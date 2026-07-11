"""GUI-specific deterministic oracles. Each returns oracle Candidates (the same
dataclass the CLI oracles use). Daemon-truth oracles (reconcile_seq,
capture_state_evidence) are reused from oracles.py unchanged — the daemon is
real and reachable via the izba binary against the shared IZBA_DATA_DIR."""
from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Callable, Dict, List, Optional

from oracles import Candidate  # noqa: E402

_STOP = {"the", "a", "an", "is", "are", "in", "to", "of", "and", "it", "its",
         "with", "that", "this", "appears", "shows", "should", "be", "as",
         "for", "on", "list", "view", "screen"}
_WORD_RE = re.compile(r"[a-zA-Z0-9_-]{3,}")

# Mirrors `mapPromoteError` (app/src/components/ManifestTab.tsx): substring
# token -> the friendly GUI copy the app actually renders instead of the raw
# backend error. A rejected invoke whose raw message matches one of these
# tokens surfaces to the user as the MAPPED copy, not the raw text — so
# `silent_failure_oracle` must search for both (Fix 2). Tokens are lowercase
# (matched against an already-lowercased error message); kept in sync by
# hand since the harness has no build step that imports the TS source.
_ERROR_COPY_MAP: List[tuple] = [
    ("izba.yml changed",
     "izba.yml changed since you viewed this diff. Refresh and review again."),
    ("no reviewed diff",
     "Review the diff first — open this tab's latest state, then Promote."),
    ("requires --restart",
     "This image change needs the checkbox above ticked before Promote can continue."),
]


def _mapped_error_copies(lower_msg: str) -> List[str]:
    """The GUI's mapped friendly-copy string(s) for a (lowercased) raw error
    message, per `_ERROR_COPY_MAP` — empty if no token matches (the app
    would have rendered the raw message verbatim)."""
    return [copy for token, copy in _ERROR_COPY_MAP if token in lower_msg]


def expectation_keywords(expect: str) -> List[str]:
    """Significant lowercased tokens of an expectation (stopwords dropped)."""
    return [w for w in (m.group(0).lower() for m in _WORD_RE.finditer(expect or ""))
            if w not in _STOP]


def console_oracle(console_errors: List[str], ref: Dict[str, Any]) -> List[Candidate]:
    out: List[Candidate] = []
    for e in console_errors or []:
        out.append(Candidate(
            kind="console",
            detail=f"uncaught JS error / rejection during the journey: {e[:300]}",
            violated_expectation="the UI runs without uncaught JS errors",
            source="implicit UI contract", trajectory_ref=dict(ref)))
    return out


def _has_dialog(marks_text: str) -> bool:
    """True if a rendered marks snapshot (``render_marks`` output, one
    ``[@eN] role "name"`` line per mark) contains a ``dialog``-role element.
    A Radix/shadcn ``<Dialog>`` portals its content to the end of
    ``document.body`` and the accessibility tree marks its container `role
    "dialog"`, aria-modal — when one is open, agent-browser's snapshot only
    lists that portaled subtree, so the rail/list *behind* the modal is
    invisible (not merely un-highlighted: genuinely absent from the marks).
    Case-insensitive: shrugs off a future role-casing change rather than
    silently stop detecting dialogs."""
    return bool(re.search(r'\]\s*dialog\s+"', marks_text or "", re.IGNORECASE))


def _last_non_dialog_marks(marks_history: List[str]) -> Optional[str]:
    """The last entry of ``marks_history`` (chronological, oldest-first) that
    has no dialog open, or ``None`` if every entry does (or the history is
    empty) — i.e. there is no reliable non-modal view to grade against."""
    for text in reversed(marks_history or []):
        if not _has_dialog(text):
            return text
    return None


def dom_expect_oracle(expect: str, marks_text: str, ref: Dict[str, Any],
                      page_text: str = "") -> List[Candidate]:
    """If NONE of the expectation's significant keywords appears in the final
    screen — the accessibility marks OR the raw rendered page text (Fix 2:
    plain-`<div>` outcome/error copy the marks never capture, e.g. "Promoted
    N change(s).") — the user-observable outcome is missing. Conservative
    (needs zero overlap across BOTH surfaces) to stay low-noise — the
    skeptic adjudicates borderline cases."""
    kws = expectation_keywords(expect)
    if not kws:
        return []
    hay = ((marks_text or "") + "\n" + (page_text or "")).lower()
    if any(re.search(rf'\b{re.escape(k)}\b', hay) for k in kws):
        return []
    return [Candidate(
        kind="dom_expect",
        detail=f"none of {kws!r} present in the final screen",
        violated_expectation=expect, source="journey step",
        trajectory_ref=dict(ref))]


def silent_failure_oracle(invoke_log: List[Dict[str, Any]], marks_text: str,
                          ref: Dict[str, Any],
                          page_text: str = "") -> List[Candidate]:
    """A backend invoke that rejected but left no visible error surface (no
    'alert'/'error'/the error text, in EITHER the accessibility marks or the
    raw rendered page text) = the user wasn't told.

    Fix 2 (run-2 skeptic): the app renders promote/create error copy as plain
    `<div>` text (e.g. "izba.yml changed since you viewed this diff. Refresh
    and review again." — `mapPromoteError`'s friendly copy in
    `ManifestTab.tsx`), which agent-browser's accessibility snapshot never
    captures (no role/name). ``page_text`` is `document.body.innerText`
    (`driver.read_page_text`), which does. ``page_text`` is expected to be the
    UNION of every action's captured page text across the whole journey (see
    run_gui_journeys.py), not just the final one — the harness has no
    timestamp/index correlation between a specific `invoke_log` rejection and
    a specific action, so rather than risk a false positive from an
    under-scoped window, this checks the widest reasonable "at-or-after the
    rejection" approximation: the error's own raw text (or its 40-char
    prefix), OR its `_ERROR_COPY_MAP`-mapped GUI copy (the app renders the
    MAPPED string, not the raw backend error, for known token errors —
    matching only the raw text would still false-positive on those),
    appearing ANYWHERE the journey rendered text. This trades a theoretical
    false negative (an error string that happens to also appear earlier,
    unrelated) for eliminating the false positives the skeptic found (3/3 of
    this oracle's non-spawn firings were real error copy the marks-only
    check couldn't see)."""
    hay = ((marks_text or "") + "\n" + (page_text or "")).lower()
    surfaced = ("alert" in hay) or ("error" in hay) or ("failed" in hay)
    out: List[Candidate] = []
    for e in invoke_log or []:
        if isinstance(e, dict) and e.get("ok") is False:
            msg = str(e.get("error", "")).lower()
            mapped = [c.lower() for c in _mapped_error_copies(msg)]
            if surfaced or (msg and msg[:40] in hay) or any(c in hay for c in mapped):
                continue
            out.append(Candidate(
                kind="silent_failure",
                detail=f"invoke {e.get('cmd')!r} rejected ({e.get('error')!r}) "
                       f"with no visible error surface",
                violated_expectation="a failed action tells the user it failed",
                source="implicit UI contract", trajectory_ref=dict(ref)))
    return out


def ui_daemon_diff_oracle(marks_history: Any, state_evidence: Dict[str, Any],
                          ref: Dict[str, Any]) -> List[Candidate]:
    """Differential: every sandbox the daemon reports must be visible in the
    UI. A sandbox in daemon truth but absent from the screen = the UI lies
    about / drops real state.

    Fix 1 (run-2 skeptic, all 3/3 of this oracle's firings): grading strictly
    against the journey's FINAL snapshot false-positives whenever that
    snapshot was captured with a dialog open (e.g. the promote confirm) —
    Radix/shadcn portals dialog content to the end of `document.body`, so the
    accessibility snapshot only lists the dialog subtree and the rail
    (which DOES list the sandbox, one snapshot earlier) reads as "absent".
    ``marks_history`` is the chronological list of every marks snapshot taken
    during the journey (oldest first, typically ending with the final
    post-journey capture); a bare ``str`` is also accepted (wrapped as a
    single-element history) for callers/tests that only ever have one
    snapshot. This oracle grades against the LAST entry that has no
    `dialog`-role mark (see `_has_dialog`/`_last_non_dialog_marks`) rather
    than strictly the last entry. If every snapshot in the history has a
    dialog open, there is no reliable non-modal view to grade — the oracle
    stays silent (report-only bias: never claim a sandbox is UI-dropped from
    a view we know is a portal-obscured modal)."""
    history = [marks_history] if isinstance(marks_history, str) else list(marks_history or [])
    graded = _last_non_dialog_marks(history)
    if graded is None:
        return []
    hay = graded.lower()
    out: List[Candidate] = []
    for name in (state_evidence or {}).get("sandboxes", []) or []:
        if not re.search(r'\b' + re.escape(str(name).lower()) + r'\b', hay):
            out.append(Candidate(
                kind="ui_daemon_diff",
                detail=f"daemon reports sandbox {name!r} but it is absent from the UI",
                violated_expectation="the UI reflects the daemon's actual sandboxes",
                source="daemon state-evidence", trajectory_ref=dict(ref)))
    return out


# --- manifest_truth oracle (Task 11) -----------------------------------------

# `izba diff` renders `state: <label>` (crates/izba-cli/src/commands/diff.rs
# render_deltas) — map the human label back to the GUI's DriftView enum
# vocabulary (app/src-tauri/src/views.rs drift_state_str), which is exactly
# what real-bridge.js's manifest_diff digest carries as `state`.
_CLI_LABEL_TO_STATE = {
    "in sync": "in_sync",
    "repo ahead (promotable)": "repo_ahead",
    "managed ahead (export to capture)": "managed_ahead",
    "diverged (repo and managed both changed)": "diverged",
}
_STATE_LINE_RE = re.compile(r'^state:\s*(.+?)\s*$', re.MULTILINE)

# Injectable CLI runner signature: (izba_bin, workspace, name, data_dir,
# timeout_s) -> stdout text.
RunDiff = Callable[[str, str, str, str, float], str]


def parse_cli_diff_state(stdout: str) -> Optional[str]:
    """Parse the `state: <label>` line from `izba diff` stdout and map it to
    the GUI's snake_case enum (in_sync/repo_ahead/managed_ahead/diverged).

    Best-effort: returns None if the line is absent or the label doesn't
    match a known state (a CLI output-format change must make the oracle go
    silent, never crash it)."""
    m = _STATE_LINE_RE.search(stdout or "")
    if not m:
        return None
    return _CLI_LABEL_TO_STATE.get(m.group(1).strip().lower())


def _default_run_diff(izba_bin: str, workspace: str, name: str,
                      data_dir: str, timeout_s: float) -> str:
    """Real `izba diff <workspace> --name <name>` invocation (PR #129's
    path-syntax-positional + explicit --name-override surface) against the
    shared IZBA_DATA_DIR. Report-only: any spawn/timeout error yields '' so
    the oracle stays silent rather than raising."""
    env = dict(os.environ)
    env["IZBA_DATA_DIR"] = data_dir
    try:
        p = subprocess.run([izba_bin, "diff", workspace, "--name", name],
                           capture_output=True, text=True, timeout=timeout_s, env=env)
        return p.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def manifest_truth_oracle(ctx: Dict[str, Any], *,
                          run_diff: Optional[RunDiff] = None) -> List[Candidate]:
    """Ground-truth check for the GUI's Manifest tab: compares the LAST
    `manifest_diff` invoke's digest (`{state, deltas, weakens}`, recorded by
    real-bridge.js) against what `izba diff <workspace> --name <name>`
    actually reports for the same sandbox/workspace.

    **Side-effect constraint:** `izba diff` WRITES the review token consumed
    by `izba promote` (crates/izba-cli/src/commands/diff.rs -> writes
    `manifest.review`). This oracle therefore MUST be invoked only ONCE, in
    the runner's end-of-journey grading block — never from a per-step/per-
    action hook, and never more than once per journey. Calling it mid-journey
    would refresh the review token and mask the exact stale-token behavior
    a journey may be trying to exercise (promote must refuse when the
    manifest changed since the diff was last viewed).

    Fires only when ``ctx["invoke_log"]`` contains at least one
    `manifest_diff` entry carrying a `digest` dict — a journey that never
    opened the Manifest tab produces nothing here (silent no-op), matching
    the other GUI oracles' "no evidence, no candidate" contract.

    ``ctx`` fields: ``invoke_log`` (list of invoke-log dicts),
    ``sandbox_name`` (str — the target sandbox for the ground-truth `izba
    diff` call), ``workspace`` (str — its workspace dir), ``izba_bin``,
    ``data_dir``, ``timeout_s``, ``ref`` (trajectory_ref dict). The sandbox
    name/workspace come from the runner's existing `capture_state_evidence`
    end-of-journey snapshot (a GUI journey creates/targets at most one
    sandbox) rather than adding new invoke-log argument capture — see
    run_gui_journeys.py's grading block for how ``ctx`` is assembled.

    ``run_diff`` is an injectable ``(izba_bin, workspace, name, data_dir,
    timeout_s) -> stdout`` runner (default: a real `izba diff` subprocess
    call) so tests can supply ground truth without a real binary/daemon.

    As a side channel for the caller, this also writes
    ``ctx["manifest_truth_result"]`` — an empty candidate list is ambiguous
    (it means either "verified equal" or "couldn't check at all", and a
    caller that credits every empty result as a confirmed PASS would
    fabricate a decisive-step credit on a report-only subprocess failure).
    The value is one of: ``"no_digest"`` (nothing to check — no manifest_diff
    invoke observed), ``"no_target"`` (``sandbox_name``/``workspace`` missing
    from ``ctx``), ``"unparseable"`` (`izba diff` ran but its stdout didn't
    parse — a harness/report-only failure, NOT a verified match),
    ``"matched"``, or ``"mismatch"``."""
    manifest_digests = [
        e.get("digest") for e in (ctx.get("invoke_log") or [])
        if isinstance(e, dict) and e.get("cmd") == "manifest_diff"
        and isinstance(e.get("digest"), dict)
    ]
    if not manifest_digests:
        ctx["manifest_truth_result"] = "no_digest"
        return []
    name = ctx.get("sandbox_name")
    workspace = ctx.get("workspace")
    if not name or not workspace:
        ctx["manifest_truth_result"] = "no_target"
        return []
    ui_state = manifest_digests[-1].get("state")
    runner = run_diff or _default_run_diff
    stdout = runner(ctx.get("izba_bin", "izba"), workspace, name,
                    ctx.get("data_dir", ""), float(ctx.get("timeout_s", 30.0)))
    truth_state = parse_cli_diff_state(stdout)
    if truth_state is None:
        ctx["manifest_truth_result"] = "unparseable"
        return []
    if truth_state == ui_state:
        ctx["manifest_truth_result"] = "matched"
        return []
    ctx["manifest_truth_result"] = "mismatch"
    ref = dict(ctx.get("ref") or {"journey_id": "", "action_index": -1})
    return [Candidate(
        kind="functional",
        detail=(f"manifest_truth: the UI's last manifest_diff showed state "
                f"{ui_state!r}, but `izba diff` ground truth reports "
                f"{truth_state!r} for sandbox {name!r} "
                f"(raw: {stdout.strip()[:200]!r})"),
        violated_expectation="the Manifest tab's drift state must match "
                             "izba's own computed drift state (izba diff)",
        source="contract: manifest diff ground truth",
        trajectory_ref=ref,
    )]
