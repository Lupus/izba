import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_oracles import (console_oracle, dom_expect_oracle,
                             manifest_truth_oracle, parse_cli_diff_state,
                             silent_failure_oracle, ui_daemon_diff_oracle)

REF = {"journey_id": "j1", "action_index": 0}


def test_console_oracle_flags_errors():
    cs = console_oracle(["TypeError: x is undefined"], REF)
    assert len(cs) == 1 and cs[0].kind == "console"
    assert console_oracle([], REF) == []


def test_dom_expect_oracle_passes_when_keyword_present():
    assert dom_expect_oracle("the sandbox web appears in the list",
                             '[@e1] row "web running"', REF) == []


def test_dom_expect_oracle_flags_when_absent():
    cs = dom_expect_oracle("the sandbox web appears in the list",
                           '[@e1] heading "Sandboxes"', REF)
    assert len(cs) == 1 and cs[0].kind == "dom_expect"


def test_silent_failure_oracle_flags_rejected_invoke_with_no_error_surface():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    cs = silent_failure_oracle(log, '[@e1] heading "Sandboxes"', REF)
    assert len(cs) == 1 and cs[0].kind == "silent_failure"


def test_silent_failure_oracle_quiet_when_error_is_shown():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    assert silent_failure_oracle(log, '[@e1] alert "boom"', REF) == []


def test_ui_daemon_diff_flags_sandbox_missing_from_ui():
    ev = {"sandboxes": ["web"]}
    cs = ui_daemon_diff_oracle('[@e1] heading "Sandboxes"', ev, REF)
    assert len(cs) == 1 and cs[0].kind == "ui_daemon_diff"


def test_ui_daemon_diff_quiet_when_ui_shows_sandbox():
    ev = {"sandboxes": ["web"]}
    assert ui_daemon_diff_oracle('[@e1] row "web running"', ev, REF) == []


def test_ui_daemon_diff_word_boundary_run_not_suppressed_by_running():
    """Sandbox named 'run' must still be flagged when the UI only shows 'running'
    (substring match would silently pass it; word-boundary must reject it)."""
    ev = {"sandboxes": ["run"]}
    cs = ui_daemon_diff_oracle('[@e1] status "running"', ev, REF)
    assert len(cs) == 1 and cs[0].kind == "ui_daemon_diff"


# ---------- manifest_truth oracle (Task 11) ----------

def _mt_ctx(ui_state, **extra):
    ctx = {
        "invoke_log": [{"cmd": "manifest_diff", "ok": True,
                        "digest": {"state": ui_state, "deltas": 0, "weakens": 0}}],
        "sandbox_name": "web", "workspace": "/tmp/ws", "izba_bin": "izba",
        "data_dir": "/tmp/d", "ref": REF,
    }
    ctx.update(extra)
    return ctx


def test_parse_cli_diff_state_maps_labels():
    assert parse_cli_diff_state("state: in sync\n") == "in_sync"
    assert parse_cli_diff_state("state: repo ahead (promotable)\n"
                                "  cpus: 2 -> 4  [restart]\n") == "repo_ahead"
    assert parse_cli_diff_state("state: managed ahead (export to capture)\n") == "managed_ahead"
    assert parse_cli_diff_state("state: diverged (repo and managed both changed)\n") == "diverged"


def test_parse_cli_diff_state_unrecognized_is_none():
    assert parse_cli_diff_state("") is None
    assert parse_cli_diff_state("no state line here\n") is None
    assert parse_cli_diff_state("state: some future label\n") is None


def test_manifest_truth_oracle_flags_state_mismatch():
    # UI says in_sync; ground truth (mocked) says repo ahead.
    def fake_run_diff(izba_bin, workspace, name, data_dir, timeout_s):
        assert (izba_bin, workspace, name) == ("izba", "/tmp/ws", "web")
        return "state: repo ahead (promotable)\n  cpus: 2 -> 4  [restart]\n"
    cs = manifest_truth_oracle(_mt_ctx("in_sync"), run_diff=fake_run_diff)
    assert len(cs) == 1
    assert cs[0].kind == "functional"
    assert cs[0].detail.startswith("manifest_truth:")
    assert cs[0].trajectory_ref == REF


def test_manifest_truth_oracle_quiet_when_states_match():
    def fake_run_diff(*a, **k):
        return "state: in sync\n"
    assert manifest_truth_oracle(_mt_ctx("in_sync"), run_diff=fake_run_diff) == []


def test_manifest_truth_oracle_silent_without_manifest_invoke():
    ctx = {"invoke_log": [{"cmd": "list", "ok": True}], "sandbox_name": "web",
          "workspace": "/tmp/ws", "izba_bin": "izba", "data_dir": "/tmp/d", "ref": REF}
    called = []
    def fake_run_diff(*a, **k):
        called.append(a)
        return "state: repo ahead (promotable)\n"
    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert called == []  # never shells out when there's nothing to check


def test_manifest_truth_oracle_silent_with_no_invoke_log_at_all():
    assert manifest_truth_oracle({}) == []


def test_manifest_truth_oracle_silent_when_ground_truth_unparseable():
    # A CLI-output-format drift must not crash the oracle — go silent.
    def fake_run_diff(*a, **k):
        return "unexpected output\n"
    assert manifest_truth_oracle(_mt_ctx("in_sync"), run_diff=fake_run_diff) == []


def test_manifest_truth_oracle_result_side_channel():
    # The caller (run_gui_journeys.py) must be able to tell "verified equal"
    # apart from "couldn't check at all" — an empty candidate list alone is
    # ambiguous between the two, so the oracle also writes
    # ctx["manifest_truth_result"] for the caller to disambiguate.
    ctx = _mt_ctx("in_sync")
    manifest_truth_oracle(ctx, run_diff=lambda *a, **k: "state: in sync\n")
    assert ctx["manifest_truth_result"] == "matched"

    ctx = _mt_ctx("in_sync")
    manifest_truth_oracle(ctx, run_diff=lambda *a, **k: "state: repo ahead (promotable)\n")
    assert ctx["manifest_truth_result"] == "mismatch"

    ctx = _mt_ctx("in_sync")
    manifest_truth_oracle(ctx, run_diff=lambda *a, **k: "garbage\n")
    assert ctx["manifest_truth_result"] == "unparseable"

    ctx = {"invoke_log": [{"cmd": "list", "ok": True}], "sandbox_name": "web",
          "workspace": "/tmp/ws", "izba_bin": "izba", "data_dir": "/tmp/d", "ref": REF}
    manifest_truth_oracle(ctx)
    assert ctx["manifest_truth_result"] == "no_digest"

    ctx = _mt_ctx("in_sync", sandbox_name=None)
    manifest_truth_oracle(ctx)
    assert ctx["manifest_truth_result"] == "no_target"


def test_manifest_truth_oracle_no_target_when_workspace_missing():
    # Complementary to the sandbox_name=None variant above: a missing
    # workspace (e.g. the GUI create invoke never resolved) must also read
    # as "couldn't check", never as a confirmed match.
    ctx = _mt_ctx("in_sync", workspace=None)
    manifest_truth_oracle(ctx)
    assert ctx["manifest_truth_result"] == "no_target"


def test_manifest_truth_oracle_silent_when_invoke_failed_ok_false():
    # real-bridge.js never attaches a digest to a rejected invoke (the
    # ok:false branch pushes {cmd, ok:false, error} with no digest key at
    # all) — pin that a bare ok:false entry with no digest is correctly
    # excluded from ground-truth comparison: no shell-out, no crash, and the
    # side channel reads "no_digest" (nothing usable was ever seen), not a
    # fabricated match.
    ctx = {"invoke_log": [{"cmd": "manifest_diff", "ok": False, "error": "boom"}],
          "sandbox_name": "web", "workspace": "/tmp/ws", "izba_bin": "izba",
          "data_dir": "/tmp/d", "ref": REF}
    called = []
    def fake_run_diff(*a, **k):
        called.append(a)
        return "state: repo ahead (promotable)\n"
    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert called == []
    assert ctx["manifest_truth_result"] == "no_digest"
