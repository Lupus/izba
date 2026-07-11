import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_oracles import (_has_dialog, console_oracle, dom_expect_oracle,
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


def test_dom_expect_oracle_passes_when_keyword_only_in_page_text():
    # Fix 2: a plain-<div> outcome string ("Promoted N change(s).") has no
    # accessible role/name, so the marks miss it — page_text must too be
    # searched, not just marks_text.
    assert dom_expect_oracle("promoted 1 change", '[@e1] heading "Sandboxes"',
                             REF, page_text="Promoted 1 change(s).") == []


def test_silent_failure_oracle_flags_rejected_invoke_with_no_error_surface():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    cs = silent_failure_oracle(log, '[@e1] heading "Sandboxes"', REF)
    assert len(cs) == 1 and cs[0].kind == "silent_failure"


def test_silent_failure_oracle_quiet_when_error_is_shown():
    log = [{"cmd": "create", "ok": False, "error": "boom"}]
    assert silent_failure_oracle(log, '[@e1] alert "boom"', REF) == []


def test_silent_failure_oracle_quiet_when_error_surfaced_only_in_page_text():
    # Fix 2: the stale-token/image-change gate errors render as plain text
    # nodes (mapPromoteError's friendly copy) that the a11y marks never
    # capture. page_text (document.body.innerText) does.
    log = [{"cmd": "manifest_promote",
           "ok": False,
           "error": "izba.yml changed since `izba diff`"}]
    page_text = "izba.yml changed since you viewed this diff. Refresh and review again."
    assert silent_failure_oracle(log, '[@e1] heading "Promote izba.yml changes"',
                                 REF, page_text=page_text) == []


def test_silent_failure_oracle_flags_when_neither_surface_shows_it():
    log = [{"cmd": "manifest_promote", "ok": False, "error": "boom"}]
    cs = silent_failure_oracle(log, '[@e1] heading "Sandboxes"', REF,
                               page_text="some unrelated page text")
    assert len(cs) == 1 and cs[0].kind == "silent_failure"


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


# ---------- ui_daemon_diff modal fix (Fix 1) ----------

def test_ui_daemon_diff_uses_last_non_dialog_snapshot_when_final_is_a_modal():
    # Final snapshot is captured with the Promote modal open (rail portaled
    # away); an earlier snapshot shows the sandbox in the rail.
    ev = {"sandboxes": ["web"]}
    history = [
        '[@e1] row "web running"',
        '[@e2] heading "Promote izba.yml changes"\n[@e3] dialog "Promote izba.yml changes"',
    ]
    assert ui_daemon_diff_oracle(history, ev, REF) == []


def test_ui_daemon_diff_flags_when_absent_from_all_non_dialog_snapshots():
    ev = {"sandboxes": ["web"]}
    history = [
        '[@e1] heading "Sandboxes"',
        '[@e2] dialog "Promote izba.yml changes"',
    ]
    cs = ui_daemon_diff_oracle(history, ev, REF)
    assert len(cs) == 1 and cs[0].kind == "ui_daemon_diff"


def test_ui_daemon_diff_suppressed_when_every_snapshot_has_a_dialog():
    # No reliable non-modal view exists at all: stay silent rather than
    # falsely claim the sandbox is UI-dropped.
    ev = {"sandboxes": ["web"]}
    history = ['[@e1] dialog "Promote izba.yml changes"']
    assert ui_daemon_diff_oracle(history, ev, REF) == []


def test_ui_daemon_diff_accepts_bare_string_for_backward_compat():
    ev = {"sandboxes": ["web"]}
    assert ui_daemon_diff_oracle('[@e1] row "web running"', ev, REF) == []


# ---------- ui_daemon_diff page_text fix (run-3 skeptic H1) ----------
#
# Run-3 found Fix 1 (above) ineffective for this app: agent-browser's a11y
# snapshot for the real promote dialog is `heading "Promote izba.yml
# changes"` + Cancel/Promote/Close buttons, WITHOUT a `role=dialog` mark —
# so `_has_dialog` was False for every snapshot and the "last non-dialog"
# selection degraded to "last snapshot" (the modal), reproducing the exact
# bug the fix meant to prevent (3/3 firings that run were false positives).
# These tests reproduce the skeptic's exact scenario (marks-only history
# with no `role=dialog` mark, modal masking the rail) and the corresponding
# real-negative case.

def test_ui_daemon_diff_uses_page_text_when_marks_hide_rail_behind_undetected_modal():
    # Reproduces the run-3 false positive: the final marks snapshot is the
    # real app's promote dialog rendering (heading + buttons, NO dialog-role
    # mark — `_has_dialog` alone can't see it), but `page_text` for that same
    # snapshot still carries the rail's "SANDBOXES · N / <name>" text (a
    # Radix dialog hides the rail from the a11y tree, not from
    # `document.body.innerText`; verified against a stored run-3 bundle).
    ev = {"sandboxes": ["manifest-stopped-demo"]}
    marks_history = [
        '[@e1] row "manifest-stopped-demo stopped"',
        '[@e2] heading "Promote izba.yml changes"\n'
        '[@e3] button "Cancel"\n[@e4] button "Promote"',
    ]
    page_text_history = [
        "SANDBOXES · 1\nmanifest-stopped-demo\nalpine:3.20",
        "SANDBOXES · 1\nmanifest-stopped-demo\nalpine:3.20\nPromote izba.yml changes",
    ]
    assert ui_daemon_diff_oracle(marks_history, ev, REF,
                                 page_text_history=page_text_history) == []


def test_ui_daemon_diff_flags_when_sandbox_absent_from_both_marks_and_page_text():
    ev = {"sandboxes": ["manifest-stopped-demo"]}
    marks_history = [
        '[@e1] heading "Sandboxes"',
        '[@e2] heading "Promote izba.yml changes"\n'
        '[@e3] button "Cancel"\n[@e4] button "Promote"',
    ]
    page_text_history = [
        "SANDBOXES · 0",
        "Promote izba.yml changes",
    ]
    cs = ui_daemon_diff_oracle(marks_history, ev, REF,
                               page_text_history=page_text_history)
    assert len(cs) == 1 and cs[0].kind == "ui_daemon_diff"


def test_ui_daemon_diff_page_text_history_shorter_than_marks_falls_back_per_index():
    # An entry beyond page_text_history's length (e.g. an older bundle that
    # only captured page_text for the final snapshot) falls back to the
    # marks-only `_has_dialog` check for that entry.
    ev = {"sandboxes": ["web"]}
    marks_history = [
        '[@e1] row "web running"',
        '[@e2] dialog "Promote izba.yml changes"',
    ]
    assert ui_daemon_diff_oracle(marks_history, ev, REF,
                                 page_text_history=[]) == []


def test_has_dialog_detects_modal_heading_and_button_cluster_without_dialog_role():
    # `_has_dialog` is still exercised as the marks-only fallback (no dead
    # code): it must recognize THIS app's actual dialog rendering (heading +
    # button cluster, no role=dialog mark), not just the spec-compliant shape.
    assert _has_dialog('[@e1] heading "Promote izba.yml changes"\n'
                       '[@e2] button "Cancel"\n[@e3] button "Promote"') is True
    # A bare heading match alone (e.g. the un-opened New-sandbox panel, which
    # also carries a "New sandbox" heading) must NOT false-positive without
    # the button cluster.
    assert _has_dialog('[@e1] heading "New sandbox"\n[@e2] textbox "Name"') is False
    assert _has_dialog('[@e1] row "web running"') is False


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
