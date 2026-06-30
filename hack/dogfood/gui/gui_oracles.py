"""GUI-specific deterministic oracles. Each returns oracle Candidates (the same
dataclass the CLI oracles use). Daemon-truth oracles (reconcile_seq,
capture_state_evidence) are reused from oracles.py unchanged — the daemon is
real and reachable via the izba binary against the shared IZBA_DATA_DIR."""
from __future__ import annotations

import re
from typing import Any, Dict, List

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
        if str(name).lower() not in hay:
            out.append(Candidate(
                kind="ui_daemon_diff",
                detail=f"daemon reports sandbox {name!r} but it is absent from the UI",
                violated_expectation="the UI reflects the daemon's actual sandboxes",
                source="daemon state-evidence", trajectory_ref=dict(ref)))
    return out
