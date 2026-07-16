# hack/dogfood/gui/test_run_gui_journeys.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import FakeDriver
from gui.run_gui_journeys import parse_args, run_gui_journey, select_gui_journeys
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


def test_max_turns_default_is_20():
    # H2 (run-3 skeptic): 14 starved multi-phase manifest journeys before
    # their decisive step (manifest-diverged-rendering never reached the
    # Manifest tab). dogfood.yml's GUI job passes no `--max-turns`, so this
    # default IS the effective CI value — pin it so a future edit can't
    # silently regress it back down.
    args = parse_args([
        "--journeys", "j.json", "--izba-bin", "izba",
        "--sidecar-bin", "sidecar", "--frontend-dir", "dist",
        "--data-dir", "/tmp/d", "--out", "out.json"])
    assert args.max_turns == 20


def test_expect_state_settle_default_is_45s():
    # Fix 1: dogfood.yml's GUI job passes no --expect-state-settle-s, so this
    # default IS the effective CI value — pin it (0 would silently regress to
    # the teardown-window false flips; the settle must stay on by default).
    args = parse_args([
        "--journeys", "j.json", "--izba-bin", "izba",
        "--sidecar-bin", "sidecar", "--frontend-dir", "dist",
        "--data-dir", "/tmp/d", "--out", "out.json"])
    assert args.expect_state_settle_s == 45.0


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


def test_daemon_spawn_failures_fold_to_one_infra_and_suppress_silent_failure(monkeypatch):
    # A daemon that can't spawn rejects every invoke identically: this must
    # not tally as one silent_failure candidate per rejected invoke (noise
    # that masks the real root cause) — it folds into a single flipping infra
    # candidate, and the matching invoke-log entries are excluded from the
    # silent_failure oracle.
    model = FakeModel([{"done": True}])
    spawn_err = ('spawning ["izba", "daemon", "run"]: '
                 'No such file or directory (os error 2)')
    invoke_log = [{"cmd": "list", "ok": False, "error": spawn_err},
                  {"cmd": "create", "ok": False, "error": spawn_err}]
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'],
                        invoke_log=invoke_log)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-spawn-fail", "modality": "gui",
               "steps": [{"intent": "look at the list", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "daemon failed to spawn" in infra[0]["detail"]
    assert "spawning [" in infra[0]["detail"]
    assert [c for c in res["candidates"] if c["kind"] == "silent_failure"] == []
    # The raw invoke_log is still persisted verbatim for the skeptic.
    assert res["invoke_log"] == invoke_log


def test_non_spawn_rejection_still_flags_silent_failure(monkeypatch):
    # Regression: only 'spawning [...]' rejections are folded — every other
    # rejected invoke keeps the normal per-entry silent_failure treatment.
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "create", "ok": False, "error": "boom"}]
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"',
                                   '[@e1] heading "Sandboxes"'],
                        invoke_log=invoke_log)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-other-fail", "modality": "gui",
               "steps": [{"intent": "look at the list", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    silent = [c for c in res["candidates"] if c["kind"] == "silent_failure"]
    assert len(silent) == 1
    assert [c for c in res["candidates"] if c["kind"] == "infra"] == []


def test_silent_failure_sees_guidance_rendered_only_between_actions(monkeypatch):
    # Live-verification FP (journey manifest-export-bootstrap-missing): the
    # FIRST manifest_diff on a no-izba.yml workspace rejects with the sentinel
    # "no izba.yml found in workspace"; ManifestTab renders the missing-
    # manifest guidance (the _ERROR_COPY_MAP-mapped copy) instead of an error
    # banner; the Actor confirms it via `read` observations; then the Export
    # click replaces it with the export outcome. The guidance therefore lives
    # ONLY in the step-opening/`read` page-text captures (page_text_history)
    # — never in a per-action capture nor the final one — and the old
    # action-captures-only union fed to silent_failure_oracle false-fired on
    # a rejection the UI had deliberately, visibly surfaced.
    model = FakeModel([{"read": True}, {"click": "@e2"}, {"done": True}])
    guidance = ("Manifest\nExport to izba.yml\n"
                "No izba.yml found in this sandbox's workspace.\n"
                "Create an izba.yml in the workspace to manage this sandbox "
                "declaratively.")
    outcome = "Manifest\nExported to /ws/izba.yml\nIn sync"
    invoke_log = [{"cmd": "manifest_diff", "ok": False,
                   "error": "no izba.yml found in workspace"}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"'] * 4,
                        invoke_log=invoke_log,
                        # opening, read (guidance visible), post-Export
                        # action capture, final — guidance gone from the
                        # last two.
                        page_texts=["Manifest tab", guidance, outcome, outcome])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-bootstrap-guidance", "modality": "gui",
               "steps": [{"intent": "export to bootstrap izba.yml", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert [c for c in res["candidates"] if c["kind"] == "silent_failure"] == []


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


def test_spawn_sidecar_prepends_izba_dir_to_path(monkeypatch, tmp_path):
    # The sidecar's DaemonClient::connect_spawning_izba resolves 'izba' via
    # PATH when there's no sibling next to its own current_exe (true for a
    # CI-built sidecar). _spawn_sidecar must therefore prepend the izba
    # binary's directory to the child's PATH so every daemon-touching invoke
    # doesn't fail with 'spawning ["izba", ...]'.
    import gui.run_gui_journeys as rgj

    izba_dir = str(tmp_path / "targetdir")
    os.makedirs(izba_dir, exist_ok=True)
    izba_bin = os.path.join(izba_dir, "izba")
    captured = {}

    class _FakePopen:
        def __init__(self, argv, env=None, **kw):
            captured["argv"] = argv
            captured["env"] = env

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(rgj.subprocess, "Popen", _FakePopen)
    rgj._spawn_sidecar("/some/sidecar-bin", izba_bin, str(tmp_path / "d"), 12345)
    assert captured["argv"] == ["/some/sidecar-bin"]
    path_entries = captured["env"]["PATH"].split(os.pathsep)
    assert path_entries[0] == izba_dir
    assert captured["env"]["IZBA_DATA_DIR"] == str(tmp_path / "d")
    assert captured["env"]["IZBA_DOGFOOD_WS_PORT"] == "12345"


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


def test_informational_reconcile_violations_recorded_but_not_flipped(monkeypatch):
    # Fix 3 (gui-handover skeptic): reconcile items the PRODUCT self-labels
    # `informational:` (orphan_volume after rm — the documented persistent-
    # volumes-survive-rm contract, reconcile.rs:145/169) must not flip a GUI
    # journey (parity with the CLI runner's _flipping_violations, H2). They
    # stay on record in the action's reconcile snapshot for the skeptic.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Remove"'] * 4)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    info = {"kind": "orphan_volume", "sandbox": None,
            "detail": "informational: named volume 'del-vol' is unreferenced "
                      "(persistent volumes survive rm)"}
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": [info], "sandboxes": []})
    journey = {"journey_id": "storage-remove-unused-volume", "modality": "gui",
               "steps": [{"intent": "remove the sandbox", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    assert [c for c in res["candidates"]
            if c["kind"] == "reconcile_violation"] == []
    # Audit trail preserved: the raw snapshot on the action still carries it.
    assert res["actions"][0]["reconcile"]["violations"] == [info]


def test_mixed_violations_flip_only_on_the_real_one(monkeypatch):
    # A real violation alongside an informational one still flips, and the
    # candidate's count/preview cover only the flipping items.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Remove"'] * 4)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    violations = [
        {"kind": "orphan_volume",
         "detail": "informational: named volume 'x' is unreferenced"},
        {"kind": "disk_live_mismatch",
         "detail": "daemon status \"running\" but disk/pid assessment is \"stopped\""},
    ]
    monkeypatch.setattr(
        rgj, "_reconcile_snapshot",
        lambda *a, **k: {"violations": violations, "sandboxes": []})
    journey = {"journey_id": "jv-mixed", "modality": "gui",
               "steps": [{"intent": "click", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    rv = [c for c in res["candidates"] if c["kind"] == "reconcile_violation"]
    assert len(rv) == 1
    assert "1 violation(s)" in rv[0]["detail"]
    assert "disk_live_mismatch" in rv[0]["detail"]
    assert "informational" not in rv[0]["detail"]


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
    step decisive index) that never touches the Manifest tab, but DOES
    exercise a real (non-ambient) invoke, keeps the original Task-11
    behavior exactly — no unreached_decisive, no infra, no decisive_credits.
    Updated for H2 (run-4 skeptic): this scenario is deliberately
    distinguished from a true lazy bail (see
    test_run_gui_journey_non_core_lazy_bail_flips_unreached_decisive) by
    giving the Actor one real click + a real `volume_list` invoke — a
    zero-invoke variant of this same journey is exactly what H2 now flips,
    so it would be dishonest to keep asserting non-flipping over an
    all-ambient invoke_log."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 3,
                        invoke_log=[{"cmd": "volume_list", "ok": True, "error": ""}])
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


_AMBIENT_ONLY_LOG = (
    [{"cmd": "list", "ok": True, "error": ""},
     {"cmd": "daemon_status", "ok": True, "error": ""}] * 45)


def test_run_gui_journey_non_core_lazy_bail_flips_unreached_decisive(monkeypatch):
    """H2 (run-4 skeptic): a non-core journey (no `core: true` step) whose
    Actor clicks once and stops, leaving an invoke_log of nothing but the
    app's ambient list/daemon_status polling, must not grade silently
    positive — reproduces run 4's `manifest-stale-token-refusal` shape
    exactly (1 action, ~90 alternating list/daemon_status entries, zero
    product invokes)."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 3,
                        invoke_log=_AMBIENT_ONLY_LOG)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "manifest-stale-token-refusal", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "click the stale sandbox row",
                          "expect": "izba.yml changed since you viewed this "
                                    "diff. Refresh and review again."}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    unreached = [c for c in res["candidates"] if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert "ambient polling" in unreached[0]["detail"]
    assert res["decisive_credits"] == []


def test_run_gui_journey_non_core_with_manifest_invokes_unaffected(monkeypatch):
    """Regression: a normal (multi-action) journey whose invoke_log carries
    real create + manifest_diff invokes beyond ambient polling must NOT be
    flipped by the H2 lazy-bail check, core or not."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = ([{"cmd": "list", "ok": True, "error": ""},
                   {"cmd": "daemon_status", "ok": True, "error": ""},
                   {"cmd": "create", "ok": True, "error": ""},
                   {"cmd": "manifest_diff", "ok": True,
                    "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}])
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"',
                                   '[@e1] heading "Manifest"'],
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-normal-non-core", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create then view manifest", "expect": ""}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds


def test_run_gui_journey_newsandbox_read_only_trajectory_not_flipped(monkeypatch):
    """Regression fixture: run 4's `newsandbox-create-disabled-hints`
    trajectory (no `core: true` step, 3 actions, invoke_log = ambient
    list/daemon_status polling PLUS one real `volume_list` read) went
    genuinely-achieved on dom_expect evidence alone (it invokes nothing
    'product' in the create/manifest_diff sense). The H2 fix must not flip
    it: `volume_list` is a real, non-ambient invoke, so
    `_has_product_invoke` is True and the lazy-bail branch never fires."""
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"click": "@e1"}, {"click": "@e2"}, {"done": True}])
    invoke_log = ([{"cmd": "list", "ok": True, "error": ""},
                   {"cmd": "daemon_status", "ok": True, "error": ""},
                   {"cmd": "volume_list", "ok": True, "error": ""},
                   {"cmd": "list", "ok": True, "error": ""},
                   {"cmd": "daemon_status", "ok": True, "error": ""}])
    driver = FakeDriver(
        snapshots=['[@e1] button "Create"'] * 4,
        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot", lambda *a, **k: {"violations": []})
    journey = {"journey_id": "newsandbox-create-disabled-hints", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "try to create without a name",
                          "expect": "Name is required."}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0)
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds


def test_has_product_invoke_true_only_beyond_ambient_polling():
    import gui.run_gui_journeys as rgj
    assert rgj._has_product_invoke([]) is False
    assert rgj._has_product_invoke(
        [{"cmd": "list"}, {"cmd": "daemon_status"}, {"cmd": "version_info"}]) is False
    assert rgj._has_product_invoke(
        [{"cmd": "list"}, {"cmd": "create"}]) is True


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


def test_manifest_yml_snapshot_taken_at_diff_time_not_post_seed(tmp_path, monkeypatch):
    """Fix 2 (manifest_truth TOCTOU): the runner snapshots the workspace
    izba.yml PER digest-carrying manifest_diff invoke — a later step's
    seed_files rewrite (the seeded-drift revert class) must not leak into the
    snapshot the ground truth will be graded against. The snapshots reach
    both the bundle (audit) and manifest_truth_oracle's ctx."""
    import gui.run_gui_journeys as rgj
    workspace = tmp_path / "workspace"
    v1 = "spec:\n  image: alpine:3.21\n"
    v2 = "spec:\n  image: alpine:3.20\n"
    # One digest-carrying manifest_diff in the (cumulative) invoke log: the
    # per-action poll after step 0's single action pairs it with v1.
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                   "digest": {"state": "repo_ahead", "deltas": 1, "weakens": 0}}]
    model = FakeModel([{"click": "@e1"}, {"done": True}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] tab "Manifest"'] * 4,
                        invoke_log=invoke_log)
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": []})
    seen_ctx = {}

    def fake_mt(ctx, **k):
        seen_ctx.update(ctx)
        ctx["manifest_truth_result"] = "matched"
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt)
    journey = {"journey_id": "manifest-seeded-drift", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "seed_files": {"izba.yml": v1},
               "steps": [
                   {"intent": "open the manifest tab", "expect": "",
                    "core": True},
                   {"intent": "after the revert", "expect": "",
                    "seed_files": {"izba.yml": v2}},
               ]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir=str(tmp_path), max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0,
                          workspace=str(workspace))
    # The snapshot is v1 (the file the UI diffed), NOT the v2 the later seed
    # rewrote — and the workspace file itself ends at v2.
    assert res["manifest_yml_snapshots"] == [v1]
    assert seen_ctx["manifest_yml_snapshots"] == [v1]
    assert (workspace / "izba.yml").read_text() == v2


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


# ---------- generalized decisive grading: expect_text / expect_state ----------
# (the product-wide GUI corpus fix: non-manifest core steps get a REAL grading
# path; every instrument-honesty flip is preserved)

def _evidence(names, recon_sandboxes):
    """A capture_state_evidence-shaped stub with a REAL reconcile shape (the
    default _reconcile stub's empty reconcile dict is structurally absent
    evidence, which expect_state honestly refuses to grade)."""
    return {"sandboxes": list(names),
            "reconcile": {"violations": [], "sandboxes": list(recon_sandboxes)},
            "per_sandbox": {}}


def _run(journey, model, driver, monkeypatch, evidence=None):
    import gui.run_gui_journeys as rgj
    ev = evidence if evidence is not None else _evidence(
        ["web"], [{"name": "web", "status_disk": "running"}])
    monkeypatch.setattr(rgj, "capture_state_evidence", lambda *a, **k: ev)
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": []})
    return run_gui_journey(model, driver, journey, izba_bin="izba",
                           data_dir="/tmp/x", max_turns=8, step_cap=10,
                           action_timeout_s=5, latency_budget_ms=30000,
                           budget={"usd": 0.0}, max_usd=2.0)


def test_core_step_passing_expect_text_grades_and_credits(monkeypatch):
    # A non-manifest core step with a matching expect_text must grade
    # genuinely: no unreached_decisive, no functional flip, and an auditable
    # decisive_credits entry (the skeptic must see the assertion WAS checked).
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] button "Create"', '[@e1] row "web running"',
                   '[@e1] row "web running"'],
        page_texts=["", "SANDBOXES · 1\nweb · running",
                    "SANDBOXES · 1\nweb · running"])
    journey = {"journey_id": "j-text-pass", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create a sandbox web",
                          "expect": "web appears running", "core": True,
                          "expect_text": "web · running"}]}
    res = _run(journey, model, driver, monkeypatch)
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds
    assert "functional" not in kinds
    assert "infra" not in kinds
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_text: 'web · running' (matched)"}]
    # H-GUI-2: the opening capture is persisted in the bundle.
    assert res["initial_observation"]["marks"] == '[@e1] button "Create"'
    assert res["initial_observation"]["page_text"] == ""


def test_core_step_failing_expect_text_flips_decisive_functional(monkeypatch):
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] button "Create"', '[@e1] row "web"',
                   '[@e1] row "web"'],
        page_texts=["", "something about web", "something about web"])
    journey = {"journey_id": "j-text-fail", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "promote", "expect": "", "core": True,
                          "expect_text": "Promoted 1 change(s)."}]}
    res = _run(journey, model, driver, monkeypatch)
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["decisive"] is True
    assert functional[0]["detail"].startswith("expect_text:")
    assert functional[0]["trajectory_ref"] == {"journey_id": "j-text-fail",
                                               "action_index": -1}
    assert res["decisive_credits"] == []
    assert not [c for c in res["candidates"]
                if c["kind"] == "unreached_decisive"]


def test_core_step_expect_text_without_any_page_text_degrades_infra(monkeypatch):
    # Zero page text captured across the whole journey: the assertion is
    # UNGRADABLE — a flipping infra candidate (harness degradation), never a
    # silent pass and never a fabricated product finding.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web"'] * 3)  # no page_texts
    journey = {"journey_id": "j-text-noev", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look", "expect": "", "core": True,
                          "expect_text": "web · running"}]}
    res = _run(journey, model, driver, monkeypatch)
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "expect_text" in infra[0]["detail"]
    assert res["decisive_credits"] == []


def test_core_step_passing_expect_state_grades_and_credits(monkeypatch):
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] button "Create"', '[@e1] row "web running"',
                   '[@e1] row "web running"'],
        page_texts=["", "web · running", "web · running"])
    journey = {"journey_id": "j-state-pass", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create web", "expect": "", "core": True,
                          "expect_state": {"sandbox": "web", "exists": True,
                                           "status": "running"}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["web"],
                                  [{"name": "web", "status_disk": "running"}]))
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds
    assert "functional" not in kinds
    assert "infra" not in kinds
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_state: sandbox 'web' (matched)"}]


def test_core_step_failing_expect_state_flips_decisive_functional(monkeypatch):
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] row "web stopped"'] * 3,
        page_texts=["web · stopped", "web · stopped", "web · stopped"])
    journey = {"journey_id": "j-state-fail", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "start web", "expect": "", "core": True,
                          "expect_state": {"sandbox": "web",
                                           "status": "running"}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["web"],
                                  [{"name": "web", "status_disk": "stopped"}]))
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["decisive"] is True
    assert functional[0]["detail"].startswith("expect_state:")
    assert res["decisive_credits"] == []


def test_core_step_expect_state_on_errored_reconcile_degrades_infra(monkeypatch):
    # Daemon truth never observed (errored end-of-journey reconcile):
    # expect_state (even `exists: false`, which an empty errored snapshot
    # would falsely satisfy) must degrade via infra, never pass.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "x"'] * 3,
                        page_texts=["x", "x", "x"])
    journey = {"journey_id": "j-state-noev", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "remove web", "expect": "", "core": True,
                          "expect_state": {"sandbox": "web",
                                           "exists": False}}]}
    ev = {"sandboxes": [],
          "reconcile": {"error": "izba died", "violations": [],
                        "sandboxes": []},
          "per_sandbox": {}}
    res = _run(journey, model, driver, monkeypatch, evidence=ev)
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "expect_state" in infra[0]["detail"]
    assert res["decisive_credits"] == []


def test_core_step_all_declared_hooks_must_pass(monkeypatch):
    # expect_text hits but expect_state diverges: the journey must still flip
    # (ALL declared hooks must pass); the text hook's credit stays on record
    # for the skeptic (it WAS checked), alongside the flipping candidate.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] row "web running"'] * 3,
        page_texts=["", "web · running", "web · running"])
    journey = {"journey_id": "j-both-hooks", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "start web", "expect": "", "core": True,
                          "expect_text": "web · running",
                          "expect_state": {"sandbox": "web",
                                           "status": "running"}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["web"],
                                  [{"name": "web", "status_disk": "stopped"}]))
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["detail"].startswith("expect_state:")
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_text: 'web · running' (matched)"}]


def test_core_step_without_hooks_flips_unreached_with_annotation_reason(monkeypatch):
    # The no-hook core step still flips (widening what is gradable, not
    # weakening the flip) and the reason now teaches the compiler what to
    # annotate.
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 2,
                        page_texts=["Sandboxes", "Sandboxes"])
    journey = {"journey_id": "j-no-hooks", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look around", "expect": "", "core": True}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence([], []))
    unreached = [c for c in res["candidates"]
                 if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert "no gradable hook" in unreached[0]["detail"]
    assert "expect_text/expect_state" in unreached[0]["detail"]
    assert "manifest_diff" in unreached[0]["detail"]
    assert res["decisive_credits"] == []


def test_zero_action_journey_passing_expect_text_on_initial_snapshot(monkeypatch):
    # H-GUI-2: an Actor that decides pure observation needs no interaction
    # produces ZERO actions — the journey start's capture (before the first
    # turn) is still page evidence: a matching expect_text grades genuinely,
    # and the bundle persists the initial observation.
    model = FakeModel([{"done": True}])
    empty_copy = "No sandboxes yet. Create one to get started."
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 2,
                        page_texts=[empty_copy, empty_copy])
    journey = {"journey_id": "app-open-empty-list", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look at the window", "expect": "",
                          "core": True,
                          "expect_text": "No sandboxes yet"}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence([], []))
    assert res["actions"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds
    assert "functional" not in kinds
    assert "infra" not in kinds
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_text: 'No sandboxes yet' (matched)"}]
    assert res["initial_observation"]["page_text"] == empty_copy


def test_zero_action_journey_failing_expect_text_reclassified_unreached(monkeypatch):
    # Fix 4 (gui-handover skeptic): an Actor that performed ZERO browser
    # actions never exercised anything — "absent from every capture" over an
    # untouched screen reads as a product failure but proves nothing about
    # the product (run: shell-tab-stopped-hint / create-invalid-volume-row,
    # both pinned strings correctly wired in the app, the actor just never
    # engaged). The journey still FLIPS — but as unreached_decisive, never a
    # functional product flip. (This test previously asserted the functional
    # flip; Fix 4 legitimately reclassifies it.)
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 2,
                        page_texts=["some other copy", "some other copy"])
    journey = {"journey_id": "app-open-empty-list-fail", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look at the window", "expect": "",
                          "core": True,
                          "expect_text": "No sandboxes yet"}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence([], []))
    assert res["actions"] == []
    assert [c for c in res["candidates"] if c["kind"] == "functional"] == []
    unreached = [c for c in res["candidates"]
                 if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert unreached[0]["detail"].startswith(
        "actor performed no actions; decisive assertion never exercised")
    assert res["decisive_credits"] == []


def test_zero_action_expect_text_hit_only_in_later_capture_not_credited(monkeypatch):
    # Fix 4 honesty edge: with zero actions the grading window is ONLY the
    # initial observation — an outcome string that appears only in a LATER
    # capture (state that changed without any actor action) must not credit
    # the decisive step; the journey is unreached, not passed.
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 2,
                        page_texts=["opening copy", "No sandboxes yet"])
    journey = {"journey_id": "zero-late-hit", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look", "expect": "", "core": True,
                          "expect_text": "No sandboxes yet"}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence([], []))
    assert res["actions"] == []
    assert res["decisive_credits"] == []
    unreached = [c for c in res["candidates"]
                 if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert "actor performed no actions" in unreached[0]["detail"]


def test_zero_action_journey_passing_expect_state_credits(monkeypatch):
    # Fix 4: a zero-action expect_state that PASSES (state needing no
    # interaction — rare) is genuine credit, same as the pure-observation
    # expect_text case.
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web running"'] * 2,
                        page_texts=["web · running", "web · running"])
    journey = {"journey_id": "zero-state-pass", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "look", "expect": "", "core": True,
                          "expect_state": {"sandbox": "web",
                                           "exists": True}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["web"],
                                  [{"name": "web", "status_disk": "running"}]))
    assert res["actions"] == []
    kinds = {c["kind"] for c in res["candidates"]}
    assert "unreached_decisive" not in kinds
    assert "functional" not in kinds
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_state: sandbox 'web' (matched)"}]


def test_zero_action_journey_failing_expect_state_reclassified_unreached(monkeypatch):
    # Fix 4: a failing expect_state on a zero-action journey — the actor
    # never attempted the interaction the state assertion presupposes —
    # flips unreached_decisive, never functional.
    model = FakeModel([{"done": True}])
    driver = FakeDriver(snapshots=['[@e1] heading "Sandboxes"'] * 2,
                        page_texts=["Sandboxes", "Sandboxes"])
    journey = {"journey_id": "zero-state-fail", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create web", "expect": "", "core": True,
                          "expect_state": {"sandbox": "web",
                                           "exists": True}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence([], []))
    assert res["actions"] == []
    assert [c for c in res["candidates"] if c["kind"] == "functional"] == []
    unreached = [c for c in res["candidates"]
                 if c["kind"] == "unreached_decisive"]
    assert len(unreached) == 1
    assert "actor performed no actions" in unreached[0]["detail"]
    assert "never attempted" in unreached[0]["detail"]
    assert res["decisive_credits"] == []


# ---------- Fix 1: expect_state settle across lifecycle teardown ----------

def _run_with_settle(journey, model, driver, monkeypatch, evidence_seq,
                     settle_s):
    """Like _run but capture_state_evidence yields evidence_seq[0] on the
    first call (the runner's end-of-journey sample) and then the LAST entry
    for every settle re-sample; time.sleep is a no-op so the poll spins."""
    import gui.run_gui_journeys as rgj
    calls = {"n": 0}

    def fake_capture(*a, **k):
        i = min(calls["n"], len(evidence_seq) - 1)
        calls["n"] += 1
        return evidence_seq[i]

    monkeypatch.setattr(rgj, "capture_state_evidence", fake_capture)
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": []})
    monkeypatch.setattr(rgj.time, "sleep", lambda s: None)
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0,
                          expect_state_settle_s=settle_s)
    return res, calls["n"]


def _stop_journey():
    return {"journey_id": "stop-sandbox-confirm", "modality": "gui",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [{"intent": "stop web", "expect": "", "core": True,
                       "expect_state": {"sandbox": "web",
                                        "status": "stopped"}}]}


def test_expect_state_transient_divergence_settles_and_credits(monkeypatch):
    # The confirmed failure mode: the first post-journey sample catches the
    # mid-ACPI-S5 teardown window ('degraded (sidecar virtiofsd:workspace
    # died)'), the settled truth is 'stopped'. The settle re-sample absorbs
    # ONLY the transient: the journey credits the decisive step, and BOTH
    # samples land in the bundle for the skeptic.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web"'] * 3,
                        page_texts=["web", "Stopping…", "web · stopped"])
    transient = _evidence(
        ["web"], [{"name": "web",
                   "status_disk": "degraded (sidecar virtiofsd:workspace died)"}])
    settled = _evidence(["web"], [{"name": "web", "status_disk": "stopped"}])
    res, n_captures = _run_with_settle(_stop_journey(), model, driver,
                                       monkeypatch, [transient, settled],
                                       settle_s=5.0)
    assert n_captures >= 2  # re-sampled at least once
    assert [c for c in res["candidates"] if c["kind"] == "functional"] == []
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_state: sandbox 'web' (matched)"}]
    # Auditability: first sample recorded alongside the settled truth.
    assert res["state_evidence_presettle"] == transient
    assert res["state_evidence"] == settled
    # Single-settle bundles keep the pre-existing shape: no per-step map.
    assert "state_evidence_settles" not in res


def test_expect_state_genuinely_wrong_settled_state_still_flips(monkeypatch):
    # Honesty: divergence that PERSISTS across the whole settle window is a
    # real product finding — it must still flip, with the settle confirmation
    # on record in the candidate detail.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web"'] * 3,
                        page_texts=["web", "Stopping…", "web"])
    wrong = _evidence(["web"], [{"name": "web", "status_disk": "running"}])
    res, n_captures = _run_with_settle(_stop_journey(), model, driver,
                                       monkeypatch, [wrong, wrong],
                                       settle_s=0.2)
    assert n_captures >= 2
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["decisive"] is True
    assert "settle re-sample" in functional[0]["detail"]
    assert "'stopped'" in functional[0]["detail"]
    assert res["decisive_credits"] == []
    # Both samples still recorded (identical here, but on record).
    assert res["state_evidence_presettle"] == wrong
    assert res["state_evidence"] == wrong


def test_expect_state_settle_disabled_flips_on_first_sample(monkeypatch):
    # settle_s=0 (the unit-test default elsewhere) keeps the old single-
    # sample behavior: no re-sample, no presettle record.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web"'] * 3,
                        page_texts=["web", "web", "web"])
    wrong = _evidence(["web"], [{"name": "web", "status_disk": "running"}])
    res, n_captures = _run_with_settle(_stop_journey(), model, driver,
                                       monkeypatch, [wrong], settle_s=0.0)
    assert n_captures == 1
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert "settle re-sample" not in functional[0]["detail"]
    assert "state_evidence_presettle" not in res


def test_expect_state_settle_audits_survive_across_multiple_core_steps(monkeypatch):
    # Greptile round: TWO core steps each trigger the settle re-sample —
    # the shared audit record must not let the second settle clobber the
    # first step's pre-settle evidence. Both per-step audits land in
    # state_evidence_settles (keyed by step index), while the
    # backward-compatible top-level pair keeps the chronological extremes
    # (presettle = the very first sample, state_evidence = the last settled).
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "web" row "api"'] * 4,
                        page_texts=["web api", "Stopping…", "stopped",
                                    "stopped"])
    journey = {"journey_id": "stop-two-sandboxes", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [
                   {"intent": "stop web", "expect": "", "core": True,
                    "expect_state": {"sandbox": "web", "status": "stopped"}},
                   {"intent": "stop api", "expect": "", "core": True,
                    "expect_state": {"sandbox": "api", "status": "stopped"}},
               ]}

    def ev(web_status, api_status):
        return _evidence(["web", "api"],
                         [{"name": "web", "status_disk": web_status},
                          {"name": "api", "status_disk": api_status}])

    transient = "degraded (sidecar virtiofsd:workspace died)"
    e1 = ev(transient, transient)   # end-of-journey sample: both mid-teardown
    e2 = ev("stopped", transient)   # step 0's settle: web settled, api not yet
    e3 = ev("stopped", "stopped")   # step 1's settle: api settled too
    res, n_captures = _run_with_settle(journey, model, driver, monkeypatch,
                                       [e1, e2, e3], settle_s=5.0)
    assert n_captures >= 3  # one end-of-journey sample + a settle per step
    assert [c for c in res["candidates"] if c["kind"] == "functional"] == []
    assert sorted(c["graded_cmd"] for c in res["decisive_credits"]) == [
        "expect_state: sandbox 'api' (matched)",
        "expect_state: sandbox 'web' (matched)"]
    # Backward-compatible pair: the chronological extremes.
    assert res["state_evidence_presettle"] == e1
    assert res["state_evidence"] == e3
    # Per-step audit: BOTH settles on record, neither clobbered.
    settles = res["state_evidence_settles"]
    assert sorted(settles) == ["0", "1"]
    assert settles["0"]["presettle"] == e1
    assert settles["0"]["settled"] == e2
    assert settles["1"]["presettle"] == e2  # step 1 graded from step 0's settled
    assert settles["1"]["settled"] == e3
    for s in settles.values():
        assert s["waited_s"] >= 0


def test_expect_state_volume_assertion_settles_uniformly(monkeypatch):
    # The Fix-1 settle applies to volume assertions too (a detach lands via
    # an async Save invoke): transiently-still-attached settles to detached
    # and credits.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "vol-demo"'] * 3,
                        page_texts=["v", "Saving…", "No volumes"])

    def ev(used_by):
        e = _evidence(["vol-demo"],
                      [{"name": "vol-demo", "status_disk": "running"}])
        e["volume_ls"] = {"argv": ["volume", "ls"], "exit_code": 0,
                          "stdout": ("NAME SIZE USED  USED BY\n"
                                     f"detach-vol 1024 10  {used_by}\n"),
                          "stderr": ""}
        return e

    journey = {"journey_id": "volumes-detach", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "detach and save", "expect": "",
                          "core": True,
                          "expect_state": {"sandbox": "vol-demo",
                                           "volume": {"name": "detach-vol",
                                                      "exists": True,
                                                      "attached_to": None}}}]}
    res, n_captures = _run_with_settle(journey, model, driver, monkeypatch,
                                       [ev("vol-demo"), ev("-")], settle_s=5.0)
    assert n_captures >= 2
    assert [c for c in res["candidates"] if c["kind"] == "functional"] == []
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_state: sandbox 'vol-demo' (matched)"}]


def test_expect_text_window_starts_at_the_core_step_not_earlier(monkeypatch):
    # The outcome string appearing ONLY in captures BEFORE the core step must
    # not credit it: "at/after the core step" is the window (the outcome of
    # step 1 can't be evidenced by step 0's screen).
    model = FakeModel([{"click": "@e1"}, {"done": True}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] row "web"'] * 4,
        page_texts=["", "OUTCOME MARKER web", "web list", "web list"])
    journey = {"journey_id": "j-window", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [
                   {"intent": "step zero", "expect": ""},
                   {"intent": "the decisive one", "expect": "", "core": True,
                    "expect_text": "OUTCOME MARKER"},
               ]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["web"],
                                  [{"name": "web", "status_disk": "running"}]))
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["detail"].startswith("expect_text:")
    assert res["decisive_credits"] == []


def test_expect_text_hit_in_final_settle_capture_counts(monkeypatch):
    # An async create can land its row only after the end-of-journey settle:
    # the FINAL capture is part of the core step's window.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] button "Create"', '[@e1] button "Create"',
                   '[@e1] row "web running"'],
        page_texts=["", "creating…", "SANDBOXES · 1\nweb · running"])
    journey = {"journey_id": "j-late-settle", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create web", "expect": "", "core": True,
                          "expect_text": "web · running"}]}
    res = _run(journey, model, driver, monkeypatch)
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_text: 'web · running' (matched)"}]


def test_manifest_diff_journey_precedence_ignores_hooks(monkeypatch):
    # A journey that DID drive manifest_diff keeps the manifest_truth path
    # exactly (its tests pin it): hooks on the core step are not graded — the
    # only decisive credit is the manifest one.
    import gui.run_gui_journeys as rgj
    model = FakeModel([{"done": True}])
    invoke_log = [{"cmd": "manifest_diff", "ok": True,
                   "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}}]
    driver = FakeDriver(snapshots=['[@e1] heading "Manifest"'] * 2,
                        page_texts=["Manifest", "Manifest"],
                        invoke_log=invoke_log)

    def fake_mt(ctx, **k):
        ctx["manifest_truth_result"] = "matched"
        return []
    monkeypatch.setattr(rgj, "manifest_truth_oracle", fake_mt)
    journey = {"journey_id": "j-mt-precedence", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "view diff", "expect": "", "core": True,
                          "expect_text": "THIS STRING IS NOWHERE"}]}
    res = _run(journey, model, driver, monkeypatch)
    # expect_text would have flipped functional if graded; precedence says no.
    assert not [c for c in res["candidates"] if c["kind"] == "functional"]
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "manifest_truth: izba diff ground truth (matched)"}]


def test_substitute_steps_workspace_covers_decisive_hooks():
    from gui.run_gui_journeys import _substitute_steps_workspace
    steps = [{"intent": "i {workspace}", "expect": "e",
              "expect_text": "exported to {workspace}/izba.yml",
              "expect_state": {"sandbox": "{workspace}", "exists": True}}]
    out = _substitute_steps_workspace(steps, "/abs/ws")
    assert out[0]["expect_text"] == "exported to /abs/ws/izba.yml"
    assert out[0]["expect_state"]["sandbox"] == "/abs/ws"
    # the caller's step objects are never mutated (shallow copies all the way)
    assert steps[0]["expect_text"] == "exported to {workspace}/izba.yml"
    assert steps[0]["expect_state"]["sandbox"] == "{workspace}"


# ---------- expect_state vocabulary widening: sandboxes_exact / port ----------

def test_step_decisive_hooks_accepts_sandboxes_exact_only_spec():
    from gui.run_gui_journeys import _step_decisive_hooks
    # No `sandbox` key needed for a pure set-level assertion — including the
    # empty list (asserts NO sandboxes).
    for exact in (["keep-demo"], []):
        _, state = _step_decisive_hooks(
            {"expect_state": {"sandboxes_exact": exact}})
        assert state == {"sandboxes_exact": exact}


def test_step_decisive_hooks_accepts_port_spec():
    from gui.run_gui_journeys import _step_decisive_hooks
    spec = {"sandbox": "web", "port": {"host": 8082, "persistent": True}}
    _, state = _step_decisive_hooks({"expect_state": spec})
    assert state == spec


def test_step_decisive_hooks_rejects_malformed_new_vocabulary():
    # A declared assertion must never be silently dropped: any half-formed
    # value invalidates the whole hook (⇒ unreached_decisive downstream).
    from gui.run_gui_journeys import _step_decisive_hooks
    bad_specs = [
        # sandboxes_exact must be a list of non-empty strings.
        {"sandboxes_exact": "keep-demo"},
        {"sandboxes_exact": [""]},
        {"sandboxes_exact": [{"name": "keep-demo"}]},
        # port needs an int host and at least one of exists/persistent.
        {"sandbox": "web", "port": {"host": 8082}},
        {"sandbox": "web", "port": {"host": "8082", "exists": True}},
        {"sandbox": "web", "port": {"host": True, "exists": True}},
        {"sandbox": "web", "port": {"exists": True}},
        # per-sandbox assertions (incl. port) still need a sandbox target.
        {"port": {"host": 8082, "exists": True}},
        {"exists": True, "sandboxes_exact": ["web"]},
    ]
    for spec in bad_specs:
        _, state = _step_decisive_hooks({"expect_state": spec})
        assert state is None, spec


def test_core_step_sandboxes_exact_false_green_class_flips(monkeypatch):
    # The D-GUI-2 replay: the journey promises 'daemon set is exactly
    # {keep-demo}' but the actor created only keep-demo and then removed it
    # (daemon truth: []). The old {drop-demo, exists: false} was trivially
    # true; sandboxes_exact must flip this decisively.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "Remove"'] * 3,
                        page_texts=["x", "x", "x"])
    journey = {"journey_id": "j-exact-fail", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "remove drop-demo only", "expect": "",
                          "core": True,
                          "expect_state": {
                              "sandboxes_exact": ["keep-demo"]}}]}
    res = _run(journey, model, driver, monkeypatch, evidence=_evidence([], []))
    functional = [c for c in res["candidates"] if c["kind"] == "functional"]
    assert len(functional) == 1
    assert functional[0]["decisive"] is True
    assert "sandboxes_exact" in functional[0]["detail"]
    assert res["decisive_credits"] == []


def test_core_step_sandboxes_exact_passing_credits(monkeypatch):
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] row "keep-demo"'] * 3,
                        page_texts=["keep-demo"] * 3)
    journey = {"journey_id": "j-exact-pass", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "remove drop-demo only", "expect": "",
                          "core": True,
                          "expect_state": {
                              "sandboxes_exact": ["keep-demo"]}}]}
    res = _run(journey, model, driver, monkeypatch,
               evidence=_evidence(["keep-demo"], [{"name": "keep-demo"}]))
    kinds = {c["kind"] for c in res["candidates"]}
    assert "functional" not in kinds
    assert "unreached_decisive" not in kinds
    assert "infra" not in kinds
    assert res["decisive_credits"] == [{
        "step_index": 0, "action_index": -1,
        "graded_cmd": "expect_state: the daemon sandbox set "
                      "(sandboxes_exact) (matched)"}]


# ---------- D-GUI-5: actor readiness gate ----------

def test_app_ready_timeout_default_is_30s():
    # dogfood.yml's GUI job passes no --app-ready-timeout-s, so this default
    # IS the effective CI value — pin it (0 would silently regress to the
    # zero-action mid-'Connecting…' class the gate exists to stop).
    args = parse_args([
        "--journeys", "j.json", "--izba-bin", "izba",
        "--sidecar-bin", "sidecar", "--frontend-dir", "dist",
        "--data-dir", "/tmp/d", "--out", "out.json"])
    assert args.app_ready_timeout_s == 30.0


def test_wait_app_ready_returns_immediately_on_ready_page():
    from gui.run_gui_journeys import _wait_app_ready
    driver = FakeDriver(page_texts=["izba\ndaemon running · v0.1.0\nAbout"])
    ready, text = _wait_app_ready(driver, timeout_s=5.0)
    assert ready is True
    assert "daemon running" in text


def test_wait_app_ready_polls_past_connecting_state():
    from gui.run_gui_journeys import _wait_app_ready
    driver = FakeDriver(page_texts=["izba\nConnecting…\nAbout",
                                    "izba\nConnecting…\nAbout",
                                    "izba\ndaemon running · v0.1.0\nAbout"])
    ready, text = _wait_app_ready(driver, timeout_s=5.0, poll_s=0.01)
    assert ready is True
    assert "daemon running" in text


def test_wait_app_ready_times_out_on_persistent_connecting():
    from gui.run_gui_journeys import _wait_app_ready
    driver = FakeDriver(page_texts=["izba\nConnecting…\nAbout"] * 50)
    ready, _ = _wait_app_ready(driver, timeout_s=0.05, poll_s=0.01)
    assert ready is False


def test_run_gui_journey_never_ready_flips_infra_and_skips_actor(monkeypatch):
    # D-GUI-5: an app stuck mid-'Connecting…' is a HARNESS degradation — one
    # flipping infra candidate, ZERO actor turns (the model is never asked),
    # and the last-seen boot page on record as the initial_observation.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(snapshots=['[@e1] button "About"'] * 5,
                        page_texts=["izba\nConnecting…\nAbout"] * 50)
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-not-ready", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create a sandbox", "expect": "",
                          "core": True, "expect_text": "web · running"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0,
                          app_ready_timeout_s=0.05)
    assert res["actions"] == []
    assert driver.actions == []  # the Actor never acted
    infra = [c for c in res["candidates"] if c["kind"] == "infra"]
    assert len(infra) == 1
    assert "daemon running" in infra[0]["detail"]
    assert "Actor was not started" in infra[0]["detail"]
    # The infra flip REPLACES the actor flail: no unreached/functional noise.
    assert {c["kind"] for c in res["candidates"]} == {"infra"}
    assert "Connecting…" in res["initial_observation"]["page_text"]
    assert res["decisive_credits"] == []


def test_run_gui_journey_ready_page_reaches_actor_and_h_gui_2(monkeypatch):
    # Once the gate sees 'daemon running', the journey proceeds normally and
    # the H-GUI-2 opening capture (initial_observation) shows the READY page.
    model = FakeModel([{"click": "@e1"}, {"done": True}])
    driver = FakeDriver(
        snapshots=['[@e1] button "New sandbox"', '[@e1] row "web running"',
                   '[@e1] row "web running"'],
        page_texts=["izba\ndaemon running · v0.1.0\nAbout",
                    "daemon running · v0.1.0\nSANDBOXES · 0",
                    "daemon running · v0.1.0\nweb · running",
                    "daemon running · v0.1.0\nweb · running"])
    import gui.run_gui_journeys as rgj
    monkeypatch.setattr(rgj, "capture_state_evidence", _reconcile)
    monkeypatch.setattr(rgj, "_reconcile_snapshot",
                        lambda *a, **k: {"violations": []})
    journey = {"journey_id": "j-ready", "modality": "gui",
               "source": {"kind": "spec", "ref": "x"},
               "steps": [{"intent": "create a sandbox web",
                          "expect": "web appears"}]}
    res = run_gui_journey(model, driver, journey, izba_bin="izba",
                          data_dir="/tmp/x", max_turns=8, step_cap=10,
                          action_timeout_s=5, latency_budget_ms=30000,
                          budget={"usd": 0.0}, max_usd=2.0,
                          app_ready_timeout_s=5.0)
    assert driver.actions == [["click", "@e1"]]
    assert not [c for c in res["candidates"] if c["kind"] == "infra"]
    # H-GUI-2: the persisted opening capture is the post-gate (READY) page.
    assert "daemon running" in res["initial_observation"]["page_text"]
    assert "Connecting" not in res["initial_observation"]["page_text"]
