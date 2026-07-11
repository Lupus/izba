# hack/dogfood/gui/test_run_gui_journeys.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import FakeDriver
from gui.run_gui_journeys import run_gui_journey, select_gui_journeys
from model import FakeModel


def _reconcile(_bin, _dir, _t, env=None):
    return {"sandboxes": ["web"], "reconcile": {}, "per_sandbox": {}}


class _DummyProc:
    """Stand-in for a _spawn_sidecar Popen in tests that stub the sidecar."""

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def _gui_main(tmp_path, journeys):
    """Write a journeys file and drive rgj.main() with the standard test argv;
    returns (rc, bundle-dict-or-None)."""
    import json as _json
    import gui.run_gui_journeys as rgj

    jf = tmp_path / "journeys.json"
    jf.write_text(_json.dumps(journeys))
    out = tmp_path / "gui-traj-0.json"
    rc = rgj.main([
        "--journeys", str(jf), "--shard", "0", "--shards", "1",
        "--izba-bin", "izba", "--sidecar-bin", "/nonexistent/sidecar",
        "--frontend-dir", str(tmp_path), "--data-dir", str(tmp_path / "d"),
        "--out", str(out), "--fake-model", "[]"])
    bundle = _json.loads(out.read_text()) if out.exists() else None
    return rc, bundle


def test_select_gui_journeys_filters_modality():
    js = [{"journey_id": "a", "modality": "gui"}, {"journey_id": "b"},
          {"journey_id": "c", "modality": "cli"}]
    assert [j["journey_id"] for j in select_gui_journeys(js)] == ["a"]


def test_run_gui_journey_happy_path_records_actions_and_state(monkeypatch):
    # Actor: click create, then done.
    model = FakeModel([{"click": "@e2"}, {"done": True}])
    # screen before each snapshot: first the create button, then the new row.
    driver = FakeDriver(snapshots=['[@e2] button "Create"',
                                   '[@e1] row "web running"',
                                   '[@e1] row "web running"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j1", "modality": "gui",
               "steps": [{"intent": "create a sandbox web",
                          "expect": "the sandbox web appears in the list"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["journey_id"] == "j1"
    assert driver.actions == [["click", "@e2"]]
    assert res["actions"][0]["command"] == "click @e2"
    # UI shows 'web', daemon shows 'web' ⇒ no ui_daemon_diff candidate.
    assert not [c for c in res["candidates"] if c["kind"] == "ui_daemon_diff"]


def test_run_gui_journey_flags_ui_daemon_diff(monkeypatch):
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j2", "modality": "gui",
               "steps": [{"intent": "look at the list", "expect": "web is listed"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    kinds = {c["kind"] for c in res["candidates"]}
    assert "ui_daemon_diff" in kinds  # daemon has 'web', UI does not


def test_run_gui_journey_screenshot_ref_recorded_on_last_action(monkeypatch, tmp_path):
    """When artifact_dir is set and the journey produces a candidate (ui_daemon_diff),
    driver.screenshot is called and the last action's screenshot_ref is set to the
    artifact-relative path <basename(artifact_dir)>/<journey_id>.png."""
    # Actor clicks once (produces one action), then done.
    model = FakeModel([{"click": "@e2"}, {"done": True}])
    # Daemon reports 'web' but UI only shows 'Sandboxes' ⇒ ui_daemon_diff fires.
    driver = FakeDriver(snapshots=['[@e2] button "Create"',
                                   '[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "ui_daemon_diff_sc", "modality": "gui",
               "steps": [{"intent": "view sandboxes", "expect": "web is listed"}]}
    artifact_dir = str(tmp_path / "artifacts")
    os.makedirs(artifact_dir, exist_ok=True)
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0,
                          artifact_dir=artifact_dir)
    # Driver must have recorded the screenshot call.
    assert driver.shots == [os.path.join(artifact_dir, "ui_daemon_diff_sc.png")]
    # The last (and only) action must carry screenshot_ref with the relative path.
    assert res["actions"]
    expected_ref = os.path.join(os.path.basename(artifact_dir), "ui_daemon_diff_sc.png")
    assert res["actions"][-1].get("screenshot_ref") == expected_ref


def test_settle_for_sandbox_returns_when_sandbox_appears(monkeypatch):
    import gui.run_gui_journeys as rgj
    calls = {"n": 0}

    def fake_recon(*a, **k):
        calls["n"] += 1
        return {"violations": [],
                "sandboxes": ([{"name": "web"}] if calls["n"] >= 2 else [])}

    monkeypatch.setattr(rgj, "_reconcile_snapshot", fake_recon)
    monkeypatch.setattr(rgj.time, "sleep", lambda s: None)  # no real waiting
    rgj._settle_for_sandbox("izba", "/tmp/x", timeout_s=10,
                            action_timeout_s=5, poll_s=0.01)
    assert calls["n"] >= 2  # polled until the sandbox registered


def test_settle_for_sandbox_times_out_without_sandbox(monkeypatch):
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": [], "sandboxes": []})
    monkeypatch.setattr(rgj.time, "sleep", lambda s: None)
    # Report-only: returns promptly on timeout, no raise, no sandbox found.
    rgj._settle_for_sandbox("izba", "/tmp/x", timeout_s=0.02,
                            action_timeout_s=5, poll_s=0.01)


def test_invoke_log_persisted_in_result(monkeypatch):
    # FakeDriver's read_invoke_log returns a canned list; the journey result
    # must carry it verbatim under "invoke_log" (the evidence behind
    # silent_failure verdicts, for the skeptic to audit later).
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "create", "ok": True},
                  {"cmd": "list", "ok": False, "error": "boom"}]
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'],
                        invoke_log=invoke_log)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j3", "modality": "gui",
               "steps": [{"intent": "look at the list", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["invoke_log"] == invoke_log


def test_console_errors_are_per_action_deltas(monkeypatch):
    # FakeDriver.read_console_errors returns a GROWING cumulative list: ["e1"]
    # after action 1, ["e1", "e2"] after action 2. Each action must record
    # only the errors NEW since the previous action, and the console oracle
    # must fire once per distinct error (2 candidates total, not 3).
    model = FakeModel([{"click": "@e1"}, {"click": "@e2"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Create"',
                                   '[@e1] button "Create"',
                                   '[@e1] button "Create"',
                                   '[@e1] button "Create"'])
    cumulative = [["e1"], ["e1", "e2"]]
    calls = {"n": 0}

    def fake_read_console_errors():
        v = cumulative[calls["n"]]
        calls["n"] += 1
        return v

    driver.read_console_errors = fake_read_console_errors
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j4", "modality": "gui",
               "steps": [{"intent": "click things", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["actions"][0]["console_errors"] == ["e1"]
    assert res["actions"][1]["console_errors"] == ["e2"]
    console_candidates = [c for c in res["candidates"] if c["kind"] == "console"]
    assert len(console_candidates) == 2


def test_model_error_reply_emits_infra_candidate(monkeypatch):
    # FakeModel scripted with an {"error": ...} reply: the journey's
    # candidates must include kind == "infra" and the journey must have no
    # actions (the step loop breaks before any driver action runs).
    model = FakeModel([{"error": "transport down"}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j5", "modality": "gui",
               "steps": [{"intent": "do something", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["actions"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "infra" in kinds


def test_reconcile_snapshot_failure_carries_error_key():
    # A dead izba binary must not masquerade as a clean {"violations": []}
    # snapshot (mirrors oracles._snapshot_reconcile's honest error shape).
    import gui.run_gui_journeys as rgj
    snap = rgj._reconcile_snapshot("/nonexistent/izba", "/tmp/x", 1)
    assert "error" in snap
    assert snap["violations"] == []
    assert snap["sandboxes"] == []


def test_sidecar_startup_failure_records_infra_candidate(monkeypatch, tmp_path):
    # A sidecar that never comes up means the journey measured NOTHING: the
    # bundle must carry a flipping infra candidate, not a silently-empty
    # (positive-looking) result.
    import gui.run_gui_journeys as rgj

    monkeypatch.setattr(rgj, "_spawn_sidecar", lambda *a, **k: _DummyProc())
    monkeypatch.setattr(rgj, "_wait_port", lambda *a, **k: False)
    journeys = {"feature": "f", "journeys": [
        {"journey_id": "dead-sidecar", "modality": "gui", "rationale": "r",
         "source": {"kind": "spec", "ref": "x"},
         "steps": [{"intent": "do", "expect": ""}]}]}
    rc, bundle = _gui_main(tmp_path, journeys)
    # 1/1 journeys degraded -> catastrophic backstop, same contract as the CLI
    # runner: a dead sidecar on every journey is a run that measured nothing.
    assert rc == rgj.EXIT_CATASTROPHIC_INFRA
    res = bundle["results"][0]
    assert res["actions"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "infra" in kinds
    assert "sidecar did not come up" in res["candidates"][0]["detail"]


def test_gui_exactly_half_degraded_is_not_catastrophic(monkeypatch, tmp_path):
    # Pin the boundary: 1 of 2 degraded is 0.5, NOT > 0.5 -> rc 0. Kills a
    # `>` -> `>=` mutation, mirrors the CLI runner's boundary test.
    import gui.run_gui_journeys as rgj

    canned = {
        "healthy": {"journey_id": "healthy",
                    "actions": [{"command": "click @e1", "exit_code": 0}],
                    "candidates": []},
        "degraded": {"journey_id": "degraded", "actions": [],
                     "candidates": [rgj._infra_candidate("degraded",
                                                         "model error")]},
    }
    monkeypatch.setattr(rgj, "_spawn_sidecar", lambda *a, **k: _DummyProc())
    monkeypatch.setattr(rgj, "_wait_port", lambda *a, **k: True)
    monkeypatch.setattr(rgj, "AgentBrowserDriver",
                        lambda *a, **k: FakeDriver(snapshots=[]))
    monkeypatch.setattr(
        rgj, "run_gui_journey",
        lambda model, driver, journey, **k: canned[journey["journey_id"]])
    journeys = {"feature": "f", "journeys": [
        {"journey_id": jid, "modality": "gui", "rationale": "r",
         "source": {"kind": "spec", "ref": "x"},
         "steps": [{"intent": "do", "expect": ""}]}
        for jid in ("healthy", "degraded")]}
    rc, bundle = _gui_main(tmp_path, journeys)
    assert rc == 0
    assert {r["journey_id"] for r in bundle["results"]} == {"healthy", "degraded"}


def test_gui_zero_attempted_journeys_is_not_catastrophic(tmp_path):
    # An all-CLI corpus sharded to the GUI runner measures nothing BY DESIGN:
    # empty `results` must not trip the backstop.
    journeys = {"feature": "f", "journeys": [
        {"journey_id": "cli-only", "rationale": "r",
         "source": {"kind": "spec", "ref": "x"},
         "steps": [{"intent": "do", "expect": ""}]}]}
    rc, bundle = _gui_main(tmp_path, journeys)
    assert rc == 0
    assert bundle["results"] == []


def test_reconcile_violations_flip_gui_journey(monkeypatch):
    # Parity with the CLI runner: a non-empty violations array in an action's
    # reconcile snapshot must emit a flipping reconcile_violation candidate.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Create"'] * 4)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(
        rgj, "_reconcile_snapshot",
        lambda *a, **k: {"violations": [{"kind": "orphan-relay", "name": "web"}],
                         "sandboxes": []})
    journey = {"journey_id": "jv", "modality": "gui",
               "steps": [{"intent": "click", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    rv = [c for c in res["candidates"] if c["kind"] == "reconcile_violation"]
    assert len(rv) == 1
    assert "orphan-relay" in rv[0]["detail"]


def test_unusable_reconciler_flags_gui_journey_as_infra(monkeypatch):
    # Parity with the CLI runner (run_journeys.py ~517-520): a journey whose
    # EVERY snapshot errored had no reconcile oracle at all and must be
    # flagged infra-degraded, not silently graded as if nothing were wrong.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Create"'] * 4)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(
        rgj, "_reconcile_snapshot",
        lambda *a, **k: {"error": "boom", "violations": [], "sandboxes": []})
    journey = {"journey_id": "jr", "modality": "gui",
               "steps": [{"intent": "click", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["actions"]
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) >= 1
    assert any("reconciler unusable" in c["detail"] for c in infra)


# ---------- Task 10: per-journey workspace + seed_files + {workspace} ----------

class _RecordingModel:
    """Like FakeModel but records, at the instant each next_command call is
    made, (a) the step['intent'] it was handed and (b) a listing of the
    workspace dir — so a test can assert BOTH that {workspace} substitution
    reached the Actor and exactly when seed_files landed relative to that
    call."""

    def __init__(self, script, workspace):
        self._script = list(script)
        self._i = 0
        self.last_cost_usd = 0.0
        self.workspace = workspace
        self.intents = []
        self.listings = []

    def next_command(self, journey, step, observations):
        self.last_cost_usd = 0.0
        self.intents.append(step.get("intent"))
        self.listings.append(
            sorted(os.listdir(self.workspace)) if os.path.isdir(self.workspace) else [])
        if self._i >= len(self._script):
            return {"done": True}
        reply = self._script[self._i]
        self._i += 1
        return reply


def test_run_gui_journey_seeds_journey_level_before_step0(tmp_path, monkeypatch):
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    workspace = tmp_path / "workspace"
    model = _RecordingModel([{"done": True}], str(workspace))
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    journey = {"journey_id": "j-seed-journey", "modality": "gui",
               "seed_files": {"izba.yml": "name: web\n"},
               "steps": [{"intent": "do nothing", "expect": ""}]}
    run_gui_journey(model, driver, journey, izba_bin="izba",
                    data_dir=str(tmp_path), max_turns=8, step_cap=10,
                    action_timeout_s=5, latency_budget_ms=30000,
                    budget={"usd": 0.0}, max_usd=2.0, workspace=str(workspace))
    # The file exists on disk...
    assert (workspace / "izba.yml").read_text() == "name: web\n"
    # ...and it was ALREADY there the very first time the model was consulted
    # (i.e. before step 0's first action, not written lazily afterwards).
    assert model.listings[0] == ["izba.yml"]


def test_run_gui_journey_step_seed_lands_before_that_step_not_earlier(tmp_path, monkeypatch):
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    workspace = tmp_path / "workspace"
    # Two steps, each done in a single next_command call.
    model = _RecordingModel([{"done": True}, {"done": True}], str(workspace))
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 3)
    journey = {"journey_id": "j-seed-step", "modality": "gui",
               "steps": [
                   {"intent": "before drift", "expect": "no file yet"},
                   {"intent": "after drift", "expect": "file present",
                    "seed_files": {"drift.txt": "drift\n"}},
               ]}
    run_gui_journey(model, driver, journey, izba_bin="izba",
                    data_dir=str(tmp_path), max_turns=8, step_cap=10,
                    action_timeout_s=5, latency_budget_ms=30000,
                    budget={"usd": 0.0}, max_usd=2.0, workspace=str(workspace))
    assert len(model.listings) == 2
    assert model.listings[0] == [], "drift.txt must not exist before step 1 seeds it"
    assert model.listings[1] == ["drift.txt"], \
        "drift.txt must be seeded before step 1's first action"
    assert (workspace / "drift.txt").read_text() == "drift\n"


def test_run_gui_journey_substitutes_workspace_token_in_intent(tmp_path, monkeypatch):
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    workspace = tmp_path / "workspace"
    model = _RecordingModel([{"click": "@e2"}, {"done": True}], str(workspace))
    driver = FakeDriver(snapshots=['[@e2] button "Create"',
                                   '[@e1] row "web running"',
                                   '[@e1] row "web running"'])
    journey = {"journey_id": "j-intent-token", "modality": "gui",
               "steps": [{"intent": "Create a sandbox with workspace {workspace}",
                          "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir=str(tmp_path), max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0, workspace=str(workspace))
    expected = f"Create a sandbox with workspace {os.path.abspath(str(workspace))}"
    # Reaches the fake Actor's next_command call...
    assert model.intents[0] == expected
    # ...and lands in the recorded trajectory action's intent too.
    assert res["actions"][0]["intent"] == expected
    assert res["workspace"] == os.path.abspath(str(workspace))


def test_run_gui_journey_core_step_no_manifest_invoke_flips_unreached_decisive(monkeypatch):
    """Critical-finding fix: a journey that DECLARES a core: true step but
    never even invoked manifest_diff verified NOTHING — it must not tally
    positive. manifest_truth_oracle is still never called (there is no
    digest to compare), but the journey must carry an `unreached_decisive`
    candidate mirroring the CLI runner's exact kind/shape convention
    (run_journeys.py's #126/PR#129 fix) so the collector flips it and the
    skeptic sees why."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    called = []
    monkeypatch.setattr(rgj, "manifest_truth_oracle",
                        lambda ctx, **k: called.append(1) or [])
    journey = {"journey_id": "j-no-manifest", "modality": "gui",
               "steps": [{"intent": "look around", "expect": "", "core": True}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert called == []  # nothing to check ⇒ never shells out / calls the oracle
    assert res["decisive_credits"] == []  # never a fabricated pass
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    unreached = [c for c in res["candidates"] if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert unreached[0]["trajectory_ref"] == {"journey_id": "j-no-manifest",
                                              "action_index": -1}
    assert "manifest_diff" in unreached[0]["detail"]


def test_run_gui_journey_non_core_no_manifest_invoke_unaffected(monkeypatch):
    """Regression: a journey WITHOUT any core: true step (fallback-to-last-
    step decisive index) that never touches the Manifest tab keeps the
    original Task-11 behavior exactly — no unreached_decisive, no infra, no
    decisive_credits. Only journeys that explicitly declare a decisive step
    opt into the new unverifiable-decisive flip."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'])
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    called = []
    monkeypatch.setattr(rgj, "manifest_truth_oracle",
                        lambda ctx, **k: called.append(1) or [])
    journey = {"journey_id": "j-non-core-no-manifest", "modality": "gui",
               "steps": [{"intent": "look around", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert called == []
    assert res["decisive_credits"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds
    assert "infra" not in kinds
    assert "functional" not in kinds


def test_run_gui_journey_decisive_manifest_mismatch_flips_negative(monkeypatch):
    """Step 3: a core: true step whose manifest_truth ground truth disagrees
    with the UI's last manifest_diff digest must emit a `functional`
    candidate tagged decisive=True — the collector's contract for flipping a
    journey negative on its decisive step (schema: `decisive` on candidate)."""
    import gui.run_gui_journeys as rgj
    from oracles import Candidate

    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    monkeypatch.setattr(
        rgj, "manifest_truth_oracle",
        lambda ctx, **k: [Candidate(
            kind="functional", detail="manifest_truth: mismatch",
            violated_expectation="drift state must match", source="izba diff",
            trajectory_ref=dict(ctx["ref"]))])
    journey = {"journey_id": "j-mt-mismatch", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "state shown",
                          "core": True}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["decisive"] is True
    assert functional[0]["detail"].startswith("manifest_truth:")
    assert res["decisive_credits"] == []  # a flip, not a credited pass


def test_run_gui_journey_decisive_manifest_match_records_credit(monkeypatch):
    """Step 3: matching ground truth grades positive AND records a
    decisive_credits audit-trail entry (schema parity with the CLI runner's
    #126/PR#129 credit mechanism) — the skeptic must be able to see the
    decisive step WAS honestly exercised, not silently skipped."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})

    def fake_mt(ctx, **k):
        # Mirrors the real oracle's side channel: a confirmed match sets
        # ctx["manifest_truth_result"] = "matched" (an empty return alone is
        # ambiguous — see gui_oracles.manifest_truth_oracle's docstring).
        ctx["manifest_truth_result"] = "matched"
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt)
    journey = {"journey_id": "j-mt-match", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "state shown",
                          "core": True}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "manifest_truth: izba diff ground truth (matched)",
    }]


def test_run_gui_journey_manifest_truth_unparseable_records_no_false_credit(monkeypatch):
    """An empty manifest_truth_oracle result is ambiguous by itself: it means
    EITHER a verified match OR that ground truth couldn't be checked at all
    (izba diff subprocess failure/timeout/unparseable output). The runner
    must only credit a decisive pass when the oracle's side channel says
    'matched' — never fabricate a credit off a bare empty return.

    Critical-finding fix: a core: true step whose ground truth was
    unparseable must not grade silently positive either — it degrades the
    journey via a flipping `infra` candidate (harness couldn't verify, not a
    product bug), same shape as every other infra candidate this runner
    emits."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})

    def fake_mt_unparseable(ctx, **k):
        ctx["manifest_truth_result"] = "unparseable"  # e.g. izba diff timed out
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt_unparseable)
    journey = {"journey_id": "j-mt-unparseable", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "state shown",
                          "core": True}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    assert res["decisive_credits"] == []  # not a fabricated pass
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "unparseable" in infra[0]["detail"]


def test_run_gui_journey_core_step_no_target_emits_infra_candidate(monkeypatch):
    """Same class as the unparseable case above: a core: true step whose
    ground truth couldn't even be targeted (missing sandbox/workspace, e.g.
    the async create never registered) must degrade via `infra`, not pass
    silently."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})

    def fake_mt_no_target(ctx, **k):
        ctx["manifest_truth_result"] = "no_target"  # e.g. no sandbox registered
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt_no_target)
    journey = {"journey_id": "j-mt-no-target", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "state shown",
                          "core": True}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    assert res["decisive_credits"] == []
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "no_target" in infra[0]["detail"]


def test_run_gui_journey_non_core_unparseable_truth_unaffected(monkeypatch):
    """Regression: a non-core (fallback-to-last-step) journey whose ground
    truth is unparseable keeps the original Task-11 behavior exactly — no
    infra candidate, no fabricated credit. Only journeys that explicitly
    declare a core: true step opt into the new unverifiable-decisive flip."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})

    def fake_mt_unparseable(ctx, **k):
        ctx["manifest_truth_result"] = "unparseable"
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt_unparseable)
    journey = {"journey_id": "j-non-core-unparseable", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "state shown"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert res["decisive_credits"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "infra" not in kinds
    assert "unreached_decisive" not in kinds
    assert "functional" not in kinds


def test_run_gui_journey_manifest_truth_ctx_carries_sandbox_from_state_evidence(monkeypatch):
    """The sandbox name/workspace passed to manifest_truth_oracle come from
    the runner's existing state_evidence (capture_state_evidence) plumbing,
    not new invoke-log arg capture — pin the exact ctx shape."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                  "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)  # sandboxes=["web"]
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    seen_ctx = {}
    def fake_mt(ctx, **k):
        seen_ctx.update(ctx)
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt)
    journey = {"journey_id": "j-mt-ctx", "modality": "gui",
               "steps": [{"intent": "view manifest diff", "expect": "", "core": True}]}
    run_gui_journey(model, driver, journey, izba_bin="izba",
                    data_dir="/tmp/x", max_turns=8, step_cap=10,
                    action_timeout_s=5, latency_budget_ms=30000,
                    budget={"usd": 0.0}, max_usd=2.0)
    assert seen_ctx["sandbox_name"] == "web"
    assert seen_ctx["invoke_log"] == invoke_log
    assert seen_ctx["izba_bin"] == "izba"
    assert seen_ctx["data_dir"] == "/tmp/x"


def test_run_gui_journey_substitutes_workspace_token_in_expect_before_dom_expect(
        tmp_path, monkeypatch):
    # {workspace} must be substituted BEFORE dom_expect's keyword extraction:
    # craft a final screen that contains the real absolute path (as the app
    # would render it), and an expect referencing {workspace} — if
    # substitution happens first, the path's distinctive token overlaps the
    # screen and no dom_expect candidate is raised.
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    workspace = tmp_path / "wsuniquemark123"
    ws_abs = os.path.abspath(str(workspace))
    model = FakeModel([{"done": True}])
    final_marks = f'[@e1] text "workspace path is {ws_abs}"'
    driver = FakeDriver(snapshots=[final_marks, final_marks])
    journey = {"journey_id": "j-expect-token", "modality": "gui",
               "steps": [{"intent": "check path",
                          "expect": "the workspace path {workspace} is shown"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir=str(tmp_path), max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0, workspace=str(workspace))
    dom_expect = [c for c in res["candidates"] if c["kind"] == "dom_expect"]
    assert dom_expect == [], \
        f"expected no dom_expect candidate once {{workspace}} is substituted: {dom_expect}"
