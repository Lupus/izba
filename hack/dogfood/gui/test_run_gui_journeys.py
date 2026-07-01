# hack/dogfood/gui/test_run_gui_journeys.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import FakeDriver
from gui.run_gui_journeys import run_gui_journey, select_gui_journeys
from model import FakeModel


def _reconcile(_bin, _dir, _t, env=None):
    return {"sandboxes": ["web"], "reconcile": {}, "per_sandbox": {}}


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
