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
