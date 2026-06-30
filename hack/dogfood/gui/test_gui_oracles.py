import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_oracles import (console_oracle, dom_expect_oracle,
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
