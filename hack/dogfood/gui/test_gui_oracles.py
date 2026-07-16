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


def test_silent_failure_oracle_quiet_on_missing_manifest_guidance_copy():
    # Run-4 skeptic H1: manifest_diff_core rejects with the raw sentinel "no
    # izba.yml found in workspace" (commands.rs NO_MANIFEST_ERROR).
    # ManifestTab.tsx keys its guidance panel on that same substring but
    # RENDERS a differently-worded heading ("in this sandbox's workspace",
    # not "in workspace") — before the H1 fix, neither the raw-text nor the
    # marks/page_text checks matched, so a genuinely-rendered guidance panel
    # false-fired silent_failure. This is the exact evidence shape from run 4's
    # manifest-missing-manifest-guidance trajectory.
    log = [{"cmd": "manifest_diff", "ok": False,
           "error": "no izba.yml found in workspace"}]
    page_text = (
        "Manifest\nRefresh\nExport to izba.yml\nPromote…\n"
        "No izba.yml found in this sandbox's workspace.\n"
        "Create an izba.yml in the workspace to manage this sandbox "
        "declaratively — the manifest describes image, resources, ports, "
        "and the egress policy. Run 'izba export <name>' or use Export "
        "here once one exists.")
    assert silent_failure_oracle(log, '[@e1] heading "Manifest"', REF,
                                 page_text=page_text) == []


def test_silent_failure_oracle_flags_missing_manifest_without_guidance():
    # Counterpart to the quiet case above: the missing-manifest sentinel
    # rejection with NO guidance panel (and no other error surface) anywhere
    # in the rendered text is a GENUINE silent failure and must still flip —
    # the _ERROR_COPY_MAP entry suppresses only a visibly-rendered guidance.
    log = [{"cmd": "manifest_diff", "ok": False,
           "error": "no izba.yml found in workspace"}]
    page_text = "Manifest\nRefresh\nExport to izba.yml\nPromote…"
    cs = silent_failure_oracle(log, '[@e1] heading "Manifest"', REF,
                               page_text=page_text)
    assert len(cs) == 1 and cs[0].kind == "silent_failure"


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


# ---------- manifest_truth TOCTOU guard (Fix 2) ----------

def _ws_with_yml(tmp_path, content):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "izba.yml").write_text(content)
    return str(ws)


def test_manifest_truth_grades_snapshot_when_workspace_changed_since_diff(tmp_path):
    # The confirmed false flip: the UI's last diff saw the seeded 3.21 file
    # (repo_ahead), then the journey reverted izba.yml to match managed; the
    # post-journey ground truth over the CURRENT file says in_sync and the
    # oracle flipped a CORRECT UI. With the snapshot, ground truth runs
    # against the file the UI actually diffed — in a temp restore, never
    # mutating the journey workspace.
    snap = "spec:\n  image: alpine:3.21\n"
    live = "spec:\n  image: alpine:3.20\n"
    workspace = _ws_with_yml(tmp_path, live)
    ctx = _mt_ctx("repo_ahead", workspace=workspace,
                  manifest_yml_snapshots=[snap])
    seen = {}

    def fake_run_diff(izba_bin, ws, name, data_dir, timeout_s):
        seen["workspace"] = ws
        with open(ws + "/izba.yml") as f:
            seen["yml"] = f.read()
        # Ground truth over the snapshot agrees with the UI.
        return "state: repo ahead (promotable)\n"

    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert ctx["manifest_truth_result"] == "matched"
    assert ctx["manifest_truth_workspace_source"] == "snapshot"
    # Diffed a RESTORED temp copy carrying the snapshot content...
    assert seen["workspace"] != workspace
    assert seen["yml"] == snap
    # ...and the journey workspace itself was never mutated.
    with open(workspace + "/izba.yml") as f:
        assert f.read() == live
    # The temp restore is cleaned up.
    assert not __import__("os").path.exists(seen["workspace"])


def test_manifest_truth_genuinely_stale_ui_still_flips_via_snapshot(tmp_path):
    # Honesty: a UI that genuinely lied (digest in_sync while the file it
    # diffed was drifted) must still flip — the snapshot IS that file, so
    # ground truth over it exposes the lie.
    snap = "spec:\n  image: alpine:3.21\n"
    workspace = _ws_with_yml(tmp_path, "spec:\n  image: alpine:3.20\n")
    ctx = _mt_ctx("in_sync", workspace=workspace,
                  manifest_yml_snapshots=[snap])

    def fake_run_diff(izba_bin, ws, name, data_dir, timeout_s):
        with open(ws + "/izba.yml") as f:
            assert f.read() == snap
        return "state: repo ahead (promotable)\n"

    cs = manifest_truth_oracle(ctx, run_diff=fake_run_diff)
    assert len(cs) == 1
    assert ctx["manifest_truth_result"] == "mismatch"
    assert "as-of the UI's last manifest_diff" in cs[0].detail


def test_manifest_truth_unchanged_workspace_keeps_live_grading(tmp_path):
    same = "spec:\n  image: alpine:3.21\n"
    workspace = _ws_with_yml(tmp_path, same)
    ctx = _mt_ctx("in_sync", workspace=workspace,
                  manifest_yml_snapshots=[same])
    seen = {}

    def fake_run_diff(izba_bin, ws, name, data_dir, timeout_s):
        seen["workspace"] = ws
        return "state: in sync\n"

    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert seen["workspace"] == workspace  # the live workspace, no temp copy
    assert ctx["manifest_truth_workspace_source"] == "live"


def test_manifest_truth_without_snapshots_keeps_current_behavior(tmp_path):
    # Pre-fix bundles carry no manifest_yml_snapshots: current behavior —
    # ground truth over the live workspace, source recorded as "live".
    workspace = _ws_with_yml(tmp_path, "spec:\n  image: alpine:3.20\n")
    ctx = _mt_ctx("in_sync", workspace=workspace)
    seen = {}

    def fake_run_diff(izba_bin, ws, name, data_dir, timeout_s):
        seen["workspace"] = ws
        return "state: in sync\n"

    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert seen["workspace"] == workspace
    assert ctx["manifest_truth_workspace_source"] == "live"


def test_manifest_truth_snapshot_matches_last_digest_not_first(tmp_path):
    # Two diffs: the snapshot aligned with the LAST digest is the one graded.
    first_snap = "spec:\n  image: alpine:3.19\n"
    last_snap = "spec:\n  image: alpine:3.21\n"
    workspace = _ws_with_yml(tmp_path, "spec:\n  image: alpine:3.20\n")
    ctx = _mt_ctx("repo_ahead", workspace=workspace,
                  manifest_yml_snapshots=[first_snap, last_snap])
    ctx["invoke_log"] = [
        {"cmd": "manifest_diff", "ok": True,
         "digest": {"state": "in_sync", "deltas": 0, "weakens": 0}},
        {"cmd": "manifest_diff", "ok": True,
         "digest": {"state": "repo_ahead", "deltas": 1, "weakens": 0}},
    ]
    seen = {}

    def fake_run_diff(izba_bin, ws, name, data_dir, timeout_s):
        with open(ws + "/izba.yml") as f:
            seen["yml"] = f.read()
        return "state: repo ahead (promotable)\n"

    assert manifest_truth_oracle(ctx, run_diff=fake_run_diff) == []
    assert seen["yml"] == last_snap


# ---------- declarative decisive hooks: expect_text_oracle ----------

def test_expect_text_oracle_matched_case_insensitive():
    from gui.gui_oracles import expect_text_oracle
    verdict, found = expect_text_oracle(
        "Promoted 2 change(s).",
        ["some other screen", "banner: PROMOTED 2 CHANGE(S). done"], REF)
    assert verdict == "matched"
    assert found == []


def test_expect_text_oracle_css_uppercased_rendering_matches_title_case_pin():
    # D-GUI-3 regression pin: Rail.tsx renders `Sandboxes · {n}` under CSS
    # class `uppercase`, so page_text captures 'SANDBOXES · N'. The deep-tier
    # skeptic claimed a title-case pin 'Sandboxes · 2' "can never match" that
    # rendering — refuted: matching is case-INsensitive per the documented
    # d074d0bf semantics (both needle and haystack are lowercased), so the
    # compiler's title-case pin grades the uppercase-rendered rail correctly.
    from gui.gui_oracles import expect_text_oracle
    verdict, found = expect_text_oracle(
        "Sandboxes · 2", ["SANDBOXES · 2\nmulti-a\nmulti-b · running"], REF)
    assert verdict == "matched"
    assert found == []


def test_expect_text_oracle_mismatch_flips_functional():
    from gui.gui_oracles import expect_text_oracle
    verdict, found = expect_text_oracle(
        "Promoted 2 change(s).", ["nothing here", "still nothing"], REF,
        step_index=1, expect="promote applies the change",
        source="spec §3.2")
    assert verdict == "mismatch"
    assert len(found) == 1
    c = found[0]
    assert c.kind == "functional"
    assert "Promoted 2 change(s)." in c.detail
    assert "core step 1" in c.detail
    assert c.violated_expectation == "promote applies the change"
    assert c.source == "spec §3.2"
    assert c.trajectory_ref == REF


def test_expect_text_oracle_exact_substring_not_keyword_soup():
    # The hook is an EXACT substring, not fuzzy keywords: every individual
    # word being present must NOT count when the literal string is absent.
    from gui.gui_oracles import expect_text_oracle
    verdict, found = expect_text_oracle(
        "sandbox web is running",
        ["web sandbox status: running is shown elsewhere"], REF)
    assert verdict == "mismatch"
    assert len(found) == 1


def test_expect_text_oracle_no_evidence_when_all_captures_empty():
    # A driver that never captured any page text is a harness degradation:
    # neither a pass nor a product finding — the caller must flip via infra.
    from gui.gui_oracles import expect_text_oracle
    for window in ([], ["", "", ""]):
        verdict, found = expect_text_oracle("anything", window, REF)
        assert verdict == "no_evidence"
        assert found == []


def test_expect_text_oracle_partial_empty_captures_still_grade():
    # Empty captures are dropped; a hit in the one non-empty capture matches.
    from gui.gui_oracles import expect_text_oracle
    verdict, found = expect_text_oracle(
        "web · running", ["", "SANDBOXES · 1\nweb · running", ""], REF)
    assert verdict == "matched"
    assert found == []


# ---------- declarative decisive hooks: expect_state_oracle ----------

def _state_evidence(names, reconcile_sandboxes, error=None):
    reconcile = {"violations": [], "sandboxes": reconcile_sandboxes}
    if error is not None:
        reconcile["error"] = error
    return {"sandboxes": names, "reconcile": reconcile, "per_sandbox": {}}


def test_expect_state_oracle_exists_and_status_match():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "running"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": True, "status": "running"}, ev, REF)
    assert verdict == "matched"
    assert found == []


def test_expect_state_oracle_status_falls_back_to_status_daemon():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["web"], [{"name": "web", "status_daemon": "stopped"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "stopped"}, ev, REF)
    assert verdict == "matched"


def test_expect_state_oracle_status_mismatch_flips():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "stopped"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running"}, ev, REF, step_index=2)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert found[0].kind == "functional"
    assert "'running'" in found[0].detail and "'stopped'" in found[0].detail
    assert "core step 2" in found[0].detail


def test_expect_state_oracle_exists_false_passes_on_absent():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandbox": "gone", "exists": False}, ev, REF)
    assert verdict == "matched"
    assert found == []


def test_expect_state_oracle_exists_true_flips_on_absent():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": True}, ev, REF)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "absent" in found[0].detail


def test_expect_state_oracle_status_implies_existence():
    # status on an absent sandbox is a mismatch, never a silent skip.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running"}, ev, REF)
    assert verdict == "mismatch"
    assert "absent from daemon truth" in found[0].detail


def test_expect_state_oracle_multiple_failures_fold_into_one_candidate():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": True, "status": "running"}, ev, REF)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "exists:" in found[0].detail and "status:" in found[0].detail


def test_expect_state_oracle_errored_reconcile_is_no_evidence():
    # An errored reconcile snapshot means daemon truth was never observed —
    # `exists: false` would otherwise be a guaranteed false pass.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [], error="izba died")
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": False}, ev, REF)
    assert verdict == "no_evidence"
    assert found == []


def test_expect_state_oracle_structurally_absent_reconcile_is_no_evidence():
    # The runner's capture_state_evidence exception fallback carries an
    # empty reconcile dict (no sandboxes key, no error): still no evidence.
    from gui.gui_oracles import expect_state_oracle
    ev = {"sandboxes": [], "reconcile": {}, "per_sandbox": {}}
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": False}, ev, REF)
    assert verdict == "no_evidence"
    assert found == []


# ---------- expect_state volume vocabulary (P2 enabler) ----------

_VOL_LS_TABLE = ("NAME                       SIZE       USED  USED BY\n"
                 "detach-vol           1073741824    1048576  -\n"
                 "shared-vol           1073741824    2097152  web,api\n")


def test_parse_volume_ls_table_and_empty_sentinel():
    from gui.gui_oracles import parse_volume_ls
    assert parse_volume_ls("no persistent volumes\n") == {}
    parsed = parse_volume_ls(_VOL_LS_TABLE)
    assert parsed == {"detach-vol": [], "shared-vol": ["web", "api"]}


def test_parse_volume_ls_unrecognized_is_none():
    from gui.gui_oracles import parse_volume_ls
    assert parse_volume_ls("") is None
    assert parse_volume_ls("error: daemon unreachable\n") is None


def _vol_evidence(stdout, exit_code=0, names=("web",),
                  recon=({"name": "web", "status_disk": "running"},)):
    ev = _state_evidence(list(names), list(recon))
    ev["volume_ls"] = {"argv": ["volume", "ls"], "exit_code": exit_code,
                       "stdout": stdout, "stderr": ""}
    return ev


def test_expect_state_volume_exists_true_passes_and_false_flips():
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence(_VOL_LS_TABLE)
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "volume": {"name": "detach-vol", "exists": True}},
        ev, REF)
    assert (verdict, found) == ("matched", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "volume": {"name": "detach-vol", "exists": False}},
        ev, REF)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "volume exists:" in found[0].detail


def test_expect_state_volume_exists_false_passes_on_absent():
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence("no persistent volumes\n")
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "volume": {"name": "gone-vol", "exists": False}},
        ev, REF)
    assert (verdict, found) == ("matched", [])


def test_expect_state_volume_attached_to_sandbox():
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence(_VOL_LS_TABLE)
    verdict, found = expect_state_oracle(
        {"sandbox": "web",
         "volume": {"name": "shared-vol", "attached_to": "web"}}, ev, REF)
    assert (verdict, found) == ("matched", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web",
         "volume": {"name": "shared-vol", "attached_to": "other"}}, ev, REF)
    assert verdict == "mismatch"
    assert "volume attached_to:" in found[0].detail
    assert "'other'" in found[0].detail


def test_expect_state_volume_attached_to_null_asserts_detached_but_existing():
    # The volumes-detach cheat killer: attached_to null passes ONLY when the
    # volume exists AND is referenced by no sandbox — staged-unsaved UI text
    # can't fake `izba volume ls`.
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence(_VOL_LS_TABLE)
    verdict, found = expect_state_oracle(
        {"sandbox": "web",
         "volume": {"name": "detach-vol", "attached_to": None}}, ev, REF)
    assert (verdict, found) == ("matched", [])
    # Still attached ⇒ mismatch.
    verdict, found = expect_state_oracle(
        {"sandbox": "web",
         "volume": {"name": "shared-vol", "attached_to": None}}, ev, REF)
    assert verdict == "mismatch"
    assert "detached (null)" in found[0].detail
    # attached_to implies existence: an absent volume fails attached_to null.
    verdict, found = expect_state_oracle(
        {"sandbox": "web",
         "volume": {"name": "gone-vol", "attached_to": None}}, ev, REF)
    assert verdict == "mismatch"
    assert "absent from daemon truth" in found[0].detail


def test_expect_state_volume_composes_with_sandbox_assertions():
    # ALL declared assertions must pass: a passing volume assertion cannot
    # rescue a failing sandbox status (and vice versa) — one folded candidate.
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence(_VOL_LS_TABLE,
                       recon=[{"name": "web", "status_disk": "stopped"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": True, "status": "running",
         "volume": {"name": "detach-vol", "exists": True}}, ev, REF)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "status:" in found[0].detail
    assert "volume exists:" not in found[0].detail  # the volume half passed


def test_expect_state_volume_no_usable_evidence_is_no_evidence():
    from gui.gui_oracles import expect_state_oracle
    spec = {"sandbox": "web", "volume": {"name": "v", "exists": True}}
    # Pre-fix bundle: no volume_ls capture at all.
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "running"}])
    assert expect_state_oracle(spec, ev, REF) == ("no_evidence", [])
    # Capture failed (non-zero exit).
    assert expect_state_oracle(
        spec, _vol_evidence("", exit_code=1), REF) == ("no_evidence", [])
    # Unparseable stdout (CLI format drift must not fabricate a verdict).
    assert expect_state_oracle(
        spec, _vol_evidence("something unexpected\n"), REF) == ("no_evidence", [])


def test_expect_state_real_failure_beats_unverifiable_volume_sibling():
    # Precedence: evidence of a REAL sandbox-status divergence flips even
    # when the sibling volume assertion couldn't be checked — a harness gap
    # must not absorb a product finding.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "stopped"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running",
         "volume": {"name": "v", "exists": True}}, ev, REF)
    assert verdict == "mismatch"
    assert "status:" in found[0].detail


# ---------- expect_state.sandboxes_exact (D-GUI-2 enabler) ----------

def test_expect_state_sandboxes_exact_matches_order_insensitively():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["keep-demo", "other"],
                         [{"name": "keep-demo", "status_disk": "running"},
                          {"name": "other", "status_disk": "stopped"}])
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": ["other", "keep-demo"]}, ev, REF)
    assert (verdict, found) == ("matched", [])


def test_expect_state_sandboxes_exact_superset_in_daemon_flips():
    # The daemon holds an UNEXPECTED extra sandbox: exact-set must flip.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["keep-demo", "stray"],
                         [{"name": "keep-demo"}, {"name": "stray"}])
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": ["keep-demo"]}, ev, REF, step_index=1)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "sandboxes_exact:" in found[0].detail
    assert "unexpected ['stray']" in found[0].detail
    assert "core step 1" in found[0].detail


def test_expect_state_sandboxes_exact_missing_survivor_flips():
    # The D-GUI-2 false-green killer: the actor removed the SURVIVOR (or
    # never created it) — daemon truth [] must flip 'exactly {keep-demo}'.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": ["keep-demo"]}, ev, REF)
    assert verdict == "mismatch"
    assert "missing ['keep-demo']" in found[0].detail


def test_expect_state_sandboxes_exact_empty_list_semantics():
    from gui.gui_oracles import expect_state_oracle
    # Empty list asserts NO sandboxes: passes on an empty daemon set...
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": []}, _state_evidence([], []), REF)
    assert (verdict, found) == ("matched", [])
    # ...and flips when anything survives.
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": []},
        _state_evidence(["leftover"], [{"name": "leftover"}]), REF)
    assert verdict == "mismatch"
    assert "unexpected ['leftover']" in found[0].detail


def test_expect_state_sandboxes_exact_composes_with_status_and_volume():
    # ALL declared assertions must pass; a passing exact-set cannot rescue a
    # failing status (and vice versa) — one folded candidate.
    from gui.gui_oracles import expect_state_oracle
    ev = _vol_evidence(_VOL_LS_TABLE,
                       recon=[{"name": "web", "status_disk": "running"}])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running",
         "volume": {"name": "detach-vol", "exists": True},
         "sandboxes_exact": ["web"]}, ev, REF)
    assert (verdict, found) == ("matched", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running",
         "volume": {"name": "detach-vol", "exists": True},
         "sandboxes_exact": ["web", "ghost"]}, ev, REF)
    assert verdict == "mismatch"
    assert len(found) == 1
    assert "sandboxes_exact:" in found[0].detail
    assert "status:" not in found[0].detail  # the status half passed


def test_expect_state_sandboxes_exact_errored_reconcile_is_no_evidence():
    # Daemon truth never observed ⇒ an exact-set assertion (even the empty
    # one, which an errored snapshot would falsely satisfy) is unverifiable.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [], error="izba died")
    verdict, found = expect_state_oracle(
        {"sandboxes_exact": []}, ev, REF)
    assert (verdict, found) == ("no_evidence", [])


# ---------- expect_state.port vocabulary (D-GUI-7 enabler) ----------

def test_parse_port_ls_rules_and_empty():
    from gui.gui_oracles import parse_port_ls
    # No output at all = no active forwards (valid; there is no sentinel).
    assert parse_port_ls("") == []
    assert parse_port_ls("\n") == []
    parsed = parse_port_ls("127.0.0.1:8082 -> 80\n0.0.0.0:9000 -> 9000\n")
    assert parsed == [
        {"bind": "127.0.0.1", "host_port": 8082, "guest_port": 80},
        {"bind": "0.0.0.0", "host_port": 9000, "guest_port": 9000}]


def test_parse_port_ls_unrecognized_is_none():
    from gui.gui_oracles import parse_port_ls
    assert parse_port_ls("error: daemon unreachable\n") is None
    # One good line + one alien line: format drift must not half-parse.
    assert parse_port_ls("127.0.0.1:8082 -> 80\nTOTALLY NEW FORMAT\n") is None


def _port_evidence(port_ls_stdout, ports_persisted, exit_code=0,
                   names=("web",),
                   recon=({"name": "web", "status_disk": "running"},)):
    ev = _state_evidence(list(names), list(recon))
    ev["per_sandbox"] = {"web": {
        "port_ls": {"argv": ["port", "ls", "web"], "exit_code": exit_code,
                    "stdout": port_ls_stdout, "stderr": ""},
        "ports_persisted": ports_persisted,
    }}
    return ev


_RULE_8082 = {"bind": "127.0.0.1", "host_port": 8082, "guest_port": 80}


def test_expect_state_port_exists_true_passes_and_false_flips():
    from gui.gui_oracles import expect_state_oracle
    ev = _port_evidence("127.0.0.1:8082 -> 80\n", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "exists": True}}, ev, REF)
    assert (verdict, found) == ("matched", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "exists": False}}, ev, REF)
    assert verdict == "mismatch"
    assert "port exists:" in found[0].detail


def test_expect_state_port_exists_false_passes_after_unpublish():
    from gui.gui_oracles import expect_state_oracle
    ev = _port_evidence("", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "exists": False}}, ev, REF)
    assert (verdict, found) == ("matched", [])


def test_expect_state_port_persistent_grades_config_not_port_ls():
    # The D-GUI-7 promise: `port ls` shows the forward either way; only the
    # persisted-config capture distinguishes Make-persistent from ephemeral.
    from gui.gui_oracles import expect_state_oracle
    # Active AND persisted ⇒ persistent: true passes.
    ev = _port_evidence("127.0.0.1:8082 -> 80\n", [_RULE_8082])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "persistent": True}},
        ev, REF)
    assert (verdict, found) == ("matched", [])
    # Active but NOT persisted ⇒ persistent: true flips (the ephemeral rule
    # `port ls` alone could never distinguish).
    ev = _port_evidence("127.0.0.1:8082 -> 80\n", [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "persistent": True}},
        ev, REF)
    assert verdict == "mismatch"
    assert "port persistent:" in found[0].detail
    # ...and persistent: false passes on the same evidence.
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "persistent": False}},
        ev, REF)
    assert (verdict, found) == ("matched", [])


def test_expect_state_port_composes_exists_and_persistent():
    from gui.gui_oracles import expect_state_oracle
    ev = _port_evidence("127.0.0.1:8082 -> 80\n", [_RULE_8082])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "exists": True,
         "port": {"host": 8082, "exists": True, "persistent": True}},
        ev, REF)
    assert (verdict, found) == ("matched", [])


def test_expect_state_port_implies_sandbox_existence():
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence([], [])
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "port": {"host": 8082, "exists": True}}, ev, REF)
    assert verdict == "mismatch"
    assert "absent from daemon truth" in found[0].detail


def test_expect_state_port_no_usable_evidence_is_no_evidence():
    from gui.gui_oracles import expect_state_oracle
    exists_spec = {"sandbox": "web", "port": {"host": 8082, "exists": True}}
    persist_spec = {"sandbox": "web",
                    "port": {"host": 8082, "persistent": True}}
    # Pre-fix bundle: per_sandbox entry has no port captures at all.
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "running"}])
    ev["per_sandbox"] = {"web": {}}
    assert expect_state_oracle(exists_spec, ev, REF) == ("no_evidence", [])
    assert expect_state_oracle(persist_spec, ev, REF) == ("no_evidence", [])
    # port ls capture failed (non-zero exit) / unparseable stdout.
    assert expect_state_oracle(
        exists_spec, _port_evidence("", [], exit_code=1),
        REF) == ("no_evidence", [])
    assert expect_state_oracle(
        exists_spec, _port_evidence("weird output\n", []),
        REF) == ("no_evidence", [])
    # config.json unreadable ⇒ persisted truth unknown (None), never a pass.
    assert expect_state_oracle(
        persist_spec, _port_evidence("127.0.0.1:8082 -> 80\n", None),
        REF) == ("no_evidence", [])


def test_expect_state_real_failure_beats_unverifiable_port_sibling():
    # Same precedence rule as the volume sibling: a REAL status divergence
    # flips even when the port assertion couldn't be checked.
    from gui.gui_oracles import expect_state_oracle
    ev = _state_evidence(["web"], [{"name": "web", "status_disk": "stopped"}])
    ev["per_sandbox"] = {"web": {}}
    verdict, found = expect_state_oracle(
        {"sandbox": "web", "status": "running",
         "port": {"host": 8082, "exists": True}}, ev, REF)
    assert verdict == "mismatch"
    assert "status:" in found[0].detail
