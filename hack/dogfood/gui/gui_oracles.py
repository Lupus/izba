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


def dom_expect_oracle(expect: str, marks_text: str, ref: Dict[str, Any]) -> List[Candidate]:
    """If NONE of the expectation's significant keywords appears in the final
    screen, the user-observable outcome is missing. Conservative (needs zero
    overlap) to stay low-noise — the skeptic adjudicates borderline cases."""
    kws = expectation_keywords(expect)
    if not kws:
        return []
    hay = (marks_text or "").lower()
    if any(re.search(rf'\b{re.escape(k)}\b', hay) for k in kws):
        return []
    return [Candidate(
        kind="dom_expect",
        detail=f"none of {kws!r} present in the final screen",
        violated_expectation=expect, source="journey step",
        trajectory_ref=dict(ref))]


def silent_failure_oracle(invoke_log: List[Dict[str, Any]], marks_text: str,
                          ref: Dict[str, Any]) -> List[Candidate]:
    """A backend invoke that rejected but left no visible error surface (no
    'alert'/'error'/the error text) in the screen = the user wasn't told."""
    hay = (marks_text or "").lower()
    surfaced = ("alert" in hay) or ("error" in hay) or ("failed" in hay)
    out: List[Candidate] = []
    for e in invoke_log or []:
        if isinstance(e, dict) and e.get("ok") is False:
            msg = str(e.get("error", "")).lower()
            if surfaced or (msg and msg[:40] in hay):
                continue
            out.append(Candidate(
                kind="silent_failure",
                detail=f"invoke {e.get('cmd')!r} rejected ({e.get('error')!r}) "
                       f"with no visible error surface",
                violated_expectation="a failed action tells the user it failed",
                source="implicit UI contract", trajectory_ref=dict(ref)))
    return out


def ui_daemon_diff_oracle(marks_text: str, state_evidence: Dict[str, Any],
                          ref: Dict[str, Any]) -> List[Candidate]:
    """Differential: every sandbox the daemon reports must be visible in the
    final UI. A sandbox in daemon truth but absent from the screen = the UI
    lies about / drops real state."""
    hay = (marks_text or "").lower()
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
