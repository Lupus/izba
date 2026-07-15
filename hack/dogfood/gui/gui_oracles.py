"""GUI-specific deterministic oracles. Each returns oracle Candidates (the same
dataclass the CLI oracles use). Daemon-truth oracles (reconcile_seq,
capture_state_evidence) are reused from oracles.py unchanged — the daemon is
real and reachable via the izba binary against the shared IZBA_DATA_DIR."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
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
    # Run-4 skeptic H1: `manifest_diff_core` (app/src-tauri/src/commands.rs
    # NO_MANIFEST_ERROR) rejects with the raw sentinel "no izba.yml found in
    # workspace" when a workspace has no izba.yml at all. ManifestTab.tsx
    # keys its friendly guidance panel on that same substring
    # (`error.includes("no izba.yml found")`) but RENDERS a differently-
    # worded heading (MISSING_MANIFEST_HEADING) — "in this sandbox's
    # workspace" vs the raw "in workspace" — so neither the raw-text nor the
    # marks/page_text substring check in `silent_failure_oracle` matched it:
    # the guidance panel rendered correctly, but the oracle mis-fired a
    # false-positive `silent_failure` because it never learned this token's
    # mapped copy. Token is the shared substring of both the raw sentinel and
    # the rendered heading.
    ("no izba.yml found",
     "No izba.yml found in this sandbox's workspace."),
    # #131: promote's restart leg (Start/Stop) can fail AFTER the config
    # write already committed (izba-core/src/manifest/promote.rs). Both raw
    # errors carry an `izba start <name>`-flavored CLI tail that would be
    # meaningless in the GUI; ManifestTab.tsx's mapPromoteError() maps them
    # to friendly copy instead.
    ("failed to start sandbox after promote",
     "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry."),
    ("failed to stop sandbox for restart",
     "Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually."),
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


# Run-3 skeptic H1: this app's Radix/shadcn `<Dialog>` does NOT render a
# `role=dialog` mark in agent-browser's a11y snapshot — only a `heading`
# carrying the dialog's title plus its button cluster (Cancel/Promote/Close
# or Create/Cancel/Close). Matched together (never on the heading alone —
# a bare "New sandbox" heading also appears on the un-opened NewSandbox
# panel) this is still just a heuristic over ONE app's rendering, which is
# exactly why `page_text` is now the primary grading signal below and this
# is demoted to a marks-only fallback.
_MODAL_HEADING_RE = re.compile(
    r'heading\s+"(?:Promote izba\.yml changes|New sandbox)"', re.IGNORECASE)
_MODAL_BUTTON_RE = re.compile(
    r'button\s+"(?:Cancel|Promote|Close|Create)"', re.IGNORECASE)


def _has_dialog(marks_text: str) -> bool:
    """True if a rendered marks snapshot (``render_marks`` output, one
    ``[@eN] role "name"`` line per mark) has DATA evidence of an open dialog.
    Two signals: (1) an explicit ``role=dialog`` mark — the spec-compliant
    a11y-tree shape, kept for other apps'/future bundles; (2) this app's
    actual empirically-observed rendering (run-3 skeptic H1): a known modal
    heading plus its button cluster, with no ``role=dialog`` mark anywhere.
    Case-insensitive: shrugs off a future role-casing change rather than
    silently stop detecting dialogs. Even (2) is a heuristic over marks
    alone — the real fix is grading against ``page_text`` instead of relying
    on this function at all (see ``ui_daemon_diff_oracle``); this stays only
    as the fallback for snapshots that carry no page_text."""
    text = marks_text or ""
    if re.search(r'\]\s*dialog\s+"', text, re.IGNORECASE):
        return True
    return bool(_MODAL_HEADING_RE.search(text) and _MODAL_BUTTON_RE.search(text))


def _last_reliable_snapshot(marks_history: List[str],
                            page_text_history: List[str]) -> Optional[str]:
    """The union haystack (``marks + "\\n" + page_text``) of the last
    snapshot in the history that is reliable evidence of the real UI state,
    or ``None`` if none is.

    Run-2's fix tried to detect the promote/create dialog purely from the
    a11y marks (``_has_dialog``) and graded against the last snapshot that
    had none open. Run-3's skeptic found that fix ineffective for this app:
    its Radix/shadcn ``<Dialog>`` never renders a ``role=dialog`` mark, so
    every snapshot "looked" dialog-free and the LAST one — typically the
    modal itself — was graded as if it were the rail (all 3 `ui_daemon_diff`
    firings that run were false positives from exactly this).

    Fix (run-3 H1): ``page_text`` (``document.body.innerText``) is not
    subject to the same failure — a Radix dialog overlays the rail visually
    and hides it from the accessibility tree (``aria-hidden``), but does NOT
    remove its text nodes from the DOM, so ``page_text`` still contains
    "SANDBOXES · N / <name>" even while the dialog is open (verified against
    a stored run-3 trajectory bundle:
    ``manifest-promote-stopped-next-start`` action 5 onward keeps
    "SANDBOXES · 1\\nmanifest-stopped-demo" in `page_text` through the
    promote-dialog actions). So a snapshot that carries page_text is ALWAYS
    treated as reliable, regardless of what `_has_dialog` says about its
    marks. Only a snapshot with NO page_text at all (an older bundle that
    predates its per-snapshot capture) falls back to the marks-only
    `_has_dialog` heuristic — the same one run-2 shipped, now demoted from
    primary signal to fallback."""
    n = max(len(marks_history), len(page_text_history))
    for i in range(n - 1, -1, -1):
        marks_i = marks_history[i] if i < len(marks_history) else ""
        page_i = page_text_history[i] if i < len(page_text_history) else ""
        if page_i or not _has_dialog(marks_i):
            return (marks_i or "") + "\n" + (page_i or "")
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
                          ref: Dict[str, Any],
                          page_text_history: Any = None) -> List[Candidate]:
    """Differential: every sandbox the daemon reports must be visible in the
    UI. A sandbox in daemon truth but absent from the screen = the UI lies
    about / drops real state.

    Fix 1 (run-2 skeptic, all 3/3 of this oracle's firings): grading strictly
    against the journey's FINAL snapshot false-positives whenever that
    snapshot was captured with a dialog open (e.g. the promote confirm) —
    Radix/shadcn portals dialog content to the end of `document.body`, so the
    accessibility snapshot only lists the dialog subtree and the rail
    (which DOES list the sandbox, one snapshot earlier) reads as "absent".
    That fix graded against the last marks-only snapshot without a
    `dialog`-role mark — but run-3's skeptic found it INEFFECTIVE for this
    app: its dialogs never render a `role=dialog` mark at all, so every
    snapshot "looked" non-modal and the fix degraded to "grade the final
    snapshot", reproducing the exact bug it meant to fix (3/3 firings this
    run were false positives from this).

    Fix 2 (run-3 H1): grade against the UNION of marks + `page_text`
    (`document.body.innerText`) per snapshot — a Radix dialog hides the rail
    from the accessibility tree but does not remove its text from the DOM,
    so `page_text` still contains it even with the dialog open (see
    `_last_reliable_snapshot`'s docstring for the verified evidence). Any
    snapshot that carries page_text is graded directly; the marks-only
    `_has_dialog` dialog-skip only kicks in as a fallback for a snapshot with
    no page_text (older bundles predating its per-snapshot capture).

    ``marks_history`` is the chronological list of every marks snapshot taken
    during the journey (oldest first, typically ending with the final
    post-journey capture); a bare ``str`` is also accepted (wrapped as a
    single-element history) for callers/tests that only ever have one
    snapshot. ``page_text_history`` is the parallel per-snapshot
    `document.body.innerText` list (same indexing as ``marks_history``);
    omitted/``None``/shorter than ``marks_history`` degrades gracefully to
    the marks-only fallback for the missing entries. If no snapshot is
    reliable (every entry lacks page_text AND has a dialog open), the oracle
    stays silent (report-only bias: never claim a sandbox is UI-dropped from
    a view we know is a portal-obscured modal)."""
    history = [marks_history] if isinstance(marks_history, str) else list(marks_history or [])
    if page_text_history is None:
        page_history: List[str] = []
    elif isinstance(page_text_history, str):
        page_history = [page_text_history]
    else:
        page_history = list(page_text_history or [])
    graded = _last_reliable_snapshot(history, page_history)
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


# --- declarative decisive hooks (expect_text / expect_state) -----------------
#
# The GUI analog of the CLI corpus's expect_exit/expect_cmd_re: privileged,
# compiler-authored, machine-checkable assertions on a core step, so a
# NON-manifest core step (navigation/create/lifecycle/ports/volumes outcomes)
# has a REAL grading path instead of structurally flipping unreached_decisive
# ("never invoked manifest_diff"). Both return a (verdict, candidates) pair:
# verdict "matched" (verified pass), "mismatch" (candidates carry the flip),
# or "no_evidence" (the harness could not check at all — the CALLER must
# degrade the journey via infra, never read it as a pass; the same
# empty-list-is-ambiguous contract manifest_truth_oracle documents).


def expect_text_oracle(expect_text: str, page_texts: List[str],
                       ref: Dict[str, Any], *, step_index: int = 0,
                       expect: str = "", source: str = "journey step"):
    """Grade a core step's ``expect_text`` hook against captured page text.

    ``expect_text`` is an EXACT case-insensitive literal substring chosen by
    the privileged journey compiler (an outcome string, never dialog chrome —
    see the schema field's description); ``page_texts`` is the chronological
    list of ``document.body.innerText`` captures at/after the core step
    (its opening snapshot, its and later actions' captures, the final
    post-settle capture). page_text — NOT the a11y marks — is deliberately
    the only surface graded: this app's Radix dialogs and plain-<div>
    outcome copy are invisible to the accessibility snapshot
    (see ``_last_reliable_snapshot``'s verified evidence).

    Verdicts: ``"matched"`` when the substring appears in any capture;
    ``"mismatch"`` with one flipping ``functional`` candidate when every
    non-empty capture lacks it; ``"no_evidence"`` when NO capture carries any
    text at all (a driver that never captured page text is a harness
    degradation, not a product finding — the caller flips via infra).
    Truncation caveat: each capture is capped (~4 KB, marked
    ``...[truncated]``), so an outcome string cut by the cap grades as a
    miss — a false FLIP, honest direction, never a false pass."""
    texts = [t for t in (page_texts or []) if t]
    if not texts:
        return "no_evidence", []
    needle = (expect_text or "").lower()
    if any(needle in t.lower() for t in texts):
        return "matched", []
    return "mismatch", [Candidate(
        kind="functional",
        detail=(f"expect_text: {expect_text!r} absent from every page-text "
                f"capture at/after core step {step_index} "
                f"({len(texts)} capture(s) searched)"),
        violated_expectation=expect or f"expect_text: {expect_text}",
        source=source, trajectory_ref=dict(ref))]


def parse_volume_ls(stdout: str) -> Optional[Dict[str, List[str]]]:
    """Parse `izba volume ls` stdout into ``{volume_name: [referencing
    sandboxes]}`` daemon truth.

    Two known shapes (crates/izba-cli/src/commands/volume.rs `ls`): the empty
    sentinel line ``no persistent volumes``, or a header row starting with
    ``NAME`` followed by ``name size used used_by`` rows where ``used_by``
    is ``-`` (unreferenced) or a comma-joined sandbox list. Best-effort:
    returns ``None`` when the output matches neither shape — a CLI
    output-format change must make the volume grading go ``no_evidence``,
    never silently pass or fabricate a product finding."""
    text = (stdout or "").strip()
    if not text:
        return None
    lines = text.splitlines()
    if lines[0].strip() == "no persistent volumes":
        return {}
    if not lines[0].lstrip().startswith("NAME"):
        return None
    out: Dict[str, List[str]] = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue  # blank/odd line — never a data row of this format
        used_by = parts[3]
        out[parts[0]] = ([] if used_by == "-"
                         else [s for s in used_by.split(",") if s])
    return out


# `izba port ls <name>` renders one `bind:host_port -> guest_port` line per
# ACTIVE forward (crates/izba-cli/src/commands/port.rs `ls`), e.g.
# `127.0.0.1:8082 -> 80`.
_PORT_LS_LINE_RE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*->\s*(\d{1,5})$')


def parse_port_ls(stdout: str) -> Optional[List[Dict[str, Any]]]:
    """Parse `izba port ls <name>` stdout into the ACTIVE forward rules:
    ``[{"bind": str, "host_port": int, "guest_port": int}, ...]``.

    Unlike ``volume ls`` there is no empty sentinel — NO output at all is the
    valid "no active forwards" state (``[]``). Best-effort: returns ``None``
    when any non-blank line doesn't match the known shape — a CLI
    output-format change must make port grading go ``no_evidence``, never
    silently pass or fabricate a product finding."""
    rules: List[Dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _PORT_LS_LINE_RE.match(line)
        if m is None:
            return None
        rules.append({"bind": m.group(1), "host_port": int(m.group(2)),
                      "guest_port": int(m.group(3))})
    return rules


def _grade_port_assertion(pspec: Dict[str, Any],
                          sb_entry: Dict[str, Any]) -> tuple:
    """``(failure strings, unverifiable)`` for one ``expect_state.port``
    assertion graded against a sandbox's per-sandbox state evidence.

    ``exists`` grades against the ACTIVE forwards (the ``port_ls`` capture);
    ``persistent`` against the PERSISTED rules (``ports_persisted`` — the
    sandbox config.json's ``ports`` array, what `izba port publish --persist`
    / the app's Make-persistent writes). The split matters because `izba port
    ls` renders identically for an ephemeral and a persisted forward, so only
    the config capture can grade a Make-persistent promise (D-GUI-7). Either
    side's evidence being unusable makes THAT assertion unverifiable
    (``no_evidence`` at the caller) — never a silent pass."""
    host = pspec.get("host")
    failures: List[str] = []
    unverifiable = False
    if "exists" in pspec:
        cap = (sb_entry or {}).get("port_ls")
        active = (parse_port_ls(cap.get("stdout") or "")
                  if isinstance(cap, dict) and cap.get("exit_code") == 0
                  else None)
        if active is None:
            unverifiable = True
        else:
            present = any(r.get("host_port") == host for r in active)
            want = bool(pspec["exists"])
            if present != want:
                failures.append(
                    f"port exists: expected an active forward on host port "
                    f"{host} to be {'present' if want else 'absent'}, "
                    f"`izba port ls` reports it "
                    f"{'present' if present else 'absent'}")
    if "persistent" in pspec:
        persisted = (sb_entry or {}).get("ports_persisted")
        if not isinstance(persisted, list):
            unverifiable = True
        else:
            present = any(isinstance(r, dict) and r.get("host_port") == host
                          for r in persisted)
            want = bool(pspec["persistent"])
            if present != want:
                failures.append(
                    f"port persistent: expected host port {host} to be "
                    f"{'recorded' if want else 'absent'} in the sandbox's "
                    f"persisted config ports, it is "
                    f"{'recorded' if present else 'absent'}")
    return failures, unverifiable


def _usable_volume_evidence(ev: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
    """The parsed ``volume ls`` truth from a state-evidence snapshot, or
    ``None`` when it is unusable: no ``volume_ls`` capture at all (a pre-fix
    bundle), a non-zero exit (daemon unreachable), or unparseable stdout."""
    cap = ev.get("volume_ls")
    if not isinstance(cap, dict) or cap.get("exit_code") != 0:
        return None
    return parse_volume_ls(cap.get("stdout") or "")


def _grade_volume_assertion(vspec: Dict[str, Any],
                            vols: Dict[str, List[str]]) -> List[str]:
    """Failure strings for one ``expect_state.volume`` assertion graded
    against parsed ``izba volume ls`` truth (empty = all declared
    sub-assertions hold). ``attached_to`` implies existence — including
    ``attached_to: null``, which asserts DETACHED-BUT-EXISTING (the whole
    point of the volumes-detach grading: a Saved detach lands in daemon
    truth, it does not delete the persistent volume)."""
    vname = vspec.get("name")
    present = vname in vols
    failures: List[str] = []
    if "exists" in vspec:
        want = bool(vspec["exists"])
        if present != want:
            failures.append(
                f"volume exists: expected {want}, daemon reports volume "
                f"{vname!r} {'present' if present else 'absent'}")
    if "attached_to" in vspec:
        want_att = vspec["attached_to"]
        if not present:
            failures.append(
                f"volume attached_to: expected {want_att!r} but volume "
                f"{vname!r} is absent from daemon truth")
        else:
            refs = vols.get(vname) or []
            if want_att is None:
                if refs:
                    failures.append(
                        f"volume attached_to: expected detached (null), "
                        f"daemon reports {vname!r} referenced by {refs!r}")
            elif want_att not in refs:
                failures.append(
                    f"volume attached_to: expected {want_att!r}, daemon "
                    f"reports {vname!r} referenced by {refs!r}")
    return failures


def expect_state_oracle(spec: Dict[str, Any], state_evidence: Dict[str, Any],
                        ref: Dict[str, Any], *, step_index: int = 0,
                        expect: str = "", source: str = "journey step"):
    """Grade a core step's ``expect_state`` hook against daemon ground truth.

    ``spec`` is the compiler-authored assertion object
    (``{"sandbox": name?, "exists": bool?, "status": str?, "volume": {...}?,
    "port": {...}?, "sandboxes_exact": [name, ...]?}`` — schema-shaped; at
    least one assertion declared; ``sandbox`` is required for the per-sandbox
    assertions, optional for a pure ``sandboxes_exact`` spec). ``state_evidence`` is
    the runner's end-of-journey ``capture_state_evidence`` snapshot (taken
    AFTER the create-settle poll, so an async create/boot has had its bounded
    chance to register): the PRODUCT's own reconcile state + ``volume ls``
    capture, never what the UI happened to render. All declared
    sub-assertions must hold:

    - ``exists``: the named sandbox present (true) / absent (false) in the
      daemon's sandbox list;
    - ``status``: the sandbox's reconciled status (``status_disk`` falling
      back to ``status_daemon`` — the same precedence
      ``reconcile_seq_oracle`` uses) equals the given string exactly; an
      absent sandbox fails a status assertion (status implies existence);
    - ``volume``: the named persistent volume's existence/attachment per the
      ``izba volume ls`` capture (see ``_grade_volume_assertion``;
      ``attached_to: null`` = detached-but-existing);
    - ``port``: an active/persisted forward on the given host port for the
      named sandbox, per the per-sandbox ``port_ls`` capture (active truth)
      and ``ports_persisted`` config capture (persist truth — `izba port ls`
      cannot distinguish the two; see ``_grade_port_assertion``). Implies
      sandbox existence: a port assertion on an absent sandbox fails;
    - ``sandboxes_exact``: the daemon's END-OF-JOURNEY sandbox set equals
      EXACTLY the given name set, order-insensitive (an empty list asserts NO
      sandboxes). This is the multi-entity removal differential a single
      ``exists: false`` cannot express (the D-GUI-2 false-green: 'drop-demo
      absent' is trivially true when the actor never created it, while the
      surviving-set promise 'exactly {keep-demo}' went unchecked).

    Verdicts: ``"matched"``; ``"mismatch"`` with ONE flipping ``functional``
    candidate listing every failed sub-assertion; ``"no_evidence"`` when a
    declared assertion's evidence is missing — the reconcile snapshot errored
    or is structurally absent (no ``sandboxes`` key and no ``error``) for
    exists/status/port/sandboxes_exact, no usable ``volume_ls`` capture
    (pre-fix bundle / non-zero exit / unparseable) for volume, or no usable
    ``port_ls``/``ports_persisted`` capture for the declared half of a port
    assertion — the truth was never observed,
    so neither pass NOR product-bug can honestly be claimed (an errored
    snapshot would otherwise make ``exists: false`` a guaranteed false
    pass); the caller flips via infra. Precedence: a REAL failure on a
    gradable assertion beats an unverifiable sibling — evidence of
    divergence flips even when another declared assertion couldn't be
    checked."""
    ev = state_evidence or {}
    reconcile = ev.get("reconcile") or {}
    reconcile_usable = (not reconcile.get("error")
                        and "sandboxes" in reconcile)
    name = spec.get("sandbox")
    failures: List[str] = []
    unverifiable = False
    if "exists" in spec or "status" in spec:
        if not reconcile_usable:
            unverifiable = True
        else:
            names = ev.get("sandboxes") or []
            if "exists" in spec:
                want = bool(spec["exists"])
                present = name in names
                if present != want:
                    failures.append(
                        f"exists: expected {want}, daemon reports "
                        f"{'present' if present else 'absent'}")
            if "status" in spec:
                entry = next((s for s in (reconcile.get("sandboxes") or [])
                              if isinstance(s, dict) and s.get("name") == name),
                             None)
                if entry is None:
                    failures.append(f"status: expected {spec['status']!r} but "
                                    f"the sandbox is absent from daemon truth")
                else:
                    actual = entry.get("status_disk") or entry.get("status_daemon")
                    if actual != spec["status"]:
                        failures.append(f"status: expected {spec['status']!r}, "
                                        f"daemon reports {actual!r}")
    vspec = spec.get("volume")
    if isinstance(vspec, dict):
        vols = _usable_volume_evidence(ev)
        if vols is None:
            unverifiable = True
        else:
            failures.extend(_grade_volume_assertion(vspec, vols))
    pspec = spec.get("port")
    if isinstance(pspec, dict):
        if not reconcile_usable:
            unverifiable = True
        elif name not in (ev.get("sandboxes") or []):
            failures.append(
                f"port: host port {pspec.get('host')} asserted but sandbox "
                f"{name!r} is absent from daemon truth")
        else:
            pfail, punver = _grade_port_assertion(
                pspec, (ev.get("per_sandbox") or {}).get(name) or {})
            failures.extend(pfail)
            unverifiable = unverifiable or punver
    if "sandboxes_exact" in spec:
        if not reconcile_usable:
            unverifiable = True
        else:
            want = {str(n) for n in (spec.get("sandboxes_exact") or [])}
            actual = {str(n) for n in (ev.get("sandboxes") or [])}
            if actual != want:
                missing = sorted(want - actual)
                unexpected = sorted(actual - want)
                parts = [p for p in (
                    f"missing {missing!r}" if missing else "",
                    f"unexpected {unexpected!r}" if unexpected else "") if p]
                failures.append(
                    f"sandboxes_exact: expected exactly {sorted(want)!r}, "
                    f"daemon reports {sorted(actual)!r} "
                    f"({'; '.join(parts)})")
    if failures:
        label = f"sandbox {name!r}" if name else "daemon sandbox set"
        return "mismatch", [Candidate(
            kind="functional",
            detail=(f"expect_state: {label} diverges from daemon "
                    f"truth at core step {step_index}: " + "; ".join(failures)),
            violated_expectation=expect or f"expect_state: {spec!r}",
            source=source, trajectory_ref=dict(ref))]
    if unverifiable:
        return "no_evidence", []
    return "matched", []


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
# A single greedy `.*` capture, not the earlier `\s*(.+?)\s*$`: `\s` and `.`
# overlap (both match plain spaces/tabs), so the old pattern had three
# adjacent quantifiers all eligible to claim the same whitespace run —
# super-linear backtracking on a non-matching line of many trailing spaces
# (rust:S8786 / python:S8786). `parse_cli_diff_state` below already calls
# `.strip()` on the captured group, so trimming leading/trailing whitespace
# via the regex itself was redundant besides being unsafe.
_STATE_LINE_RE = re.compile(r'^state:(.*)$', re.MULTILINE)

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


def _read_file_or_none(path: str) -> Optional[str]:
    """File content as text, or ``None`` when unreadable/absent. Report-only."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _workspace_as_of_last_diff(ctx: Dict[str, Any], workspace: str,
                               n_digests: int):
    """``(workspace_to_diff, tmp_dir_or_None)`` for the TOCTOU guard.

    When ``ctx["manifest_yml_snapshots"]`` carries a snapshot for the LAST
    digest-carrying manifest_diff (index ``n_digests - 1``) and the live
    workspace izba.yml has CHANGED since, restore the snapshot into a temp
    COPY of the workspace (the whole tree is copied — the review token covers
    any referenced Dockerfile too — and the journey workspace is never
    mutated) and return it, with the temp root for the caller to clean up.
    Every other case — no snapshots (pre-fix bundle), fewer snapshots than
    digests, an unreadable snapshot (``None`` entry), an unchanged file, or a
    copy failure — keeps the current behavior: diff the live workspace."""
    snapshots = ctx.get("manifest_yml_snapshots")
    if not (isinstance(snapshots, list) and len(snapshots) >= n_digests
            and n_digests > 0):
        return workspace, None
    snap = snapshots[n_digests - 1]
    if not isinstance(snap, str):
        return workspace, None
    if _read_file_or_none(os.path.join(workspace, "izba.yml")) == snap:
        return workspace, None
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="dogfood-manifest-truth-")
        restored = os.path.join(tmp_dir, "ws")
        shutil.copytree(workspace, restored)
        with open(os.path.join(restored, "izba.yml"), "w",
                  encoding="utf-8") as f:
            f.write(snap)
        return restored, tmp_dir
    except OSError:  # report-only fallback: grade the live file as before
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return workspace, None


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

    **TOCTOU guard:** this ground truth runs POST-journey, but the UI's last
    manifest_diff digest describes the izba.yml as it was WHEN THE UI DIFFED
    IT — seeded-drift journeys legitimately edit/revert the workspace file
    mid-journey, after the UI's last diff, and grading the current file
    against the stale digest false-flips a correct UI. The runner therefore
    snapshots the workspace izba.yml content at each digest-carrying
    manifest_diff invoke (``ctx["manifest_yml_snapshots"]``, aligned with the
    digest order). When the snapshot matching the LAST digest exists and the
    live file has since changed, the diff runs against a temp copy of the
    workspace with that snapshot restored (the journey workspace is never
    mutated); an unchanged file — or a bundle with no snapshots (pre-fix) —
    keeps the current live-workspace behavior. Honesty: a UI that genuinely
    showed stale state still flips — the snapshot is the file the UI
    actually diffed, so ground truth over it exposes a lying digest exactly
    as before. The side channel ``ctx["manifest_truth_workspace_source"]``
    records ``"snapshot"``/``"live"`` for the skeptic.

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
    diff_workspace, tmp_dir = _workspace_as_of_last_diff(
        ctx, workspace, len(manifest_digests))
    ctx["manifest_truth_workspace_source"] = (
        "snapshot" if tmp_dir else "live")
    try:
        stdout = runner(ctx.get("izba_bin", "izba"), diff_workspace, name,
                        ctx.get("data_dir", ""), float(ctx.get("timeout_s", 30.0)))
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    truth_state = parse_cli_diff_state(stdout)
    if truth_state is None:
        ctx["manifest_truth_result"] = "unparseable"
        return []
    if truth_state == ui_state:
        ctx["manifest_truth_result"] = "matched"
        return []
    ctx["manifest_truth_result"] = "mismatch"
    ref = dict(ctx.get("ref") or {"journey_id": "", "action_index": -1})
    snapshot_note = (
        " (ground truth computed against the izba.yml snapshot as-of the "
        "UI's last manifest_diff — the live workspace file changed after "
        "that diff)" if tmp_dir else "")
    return [Candidate(
        kind="functional",
        detail=(f"manifest_truth: the UI's last manifest_diff showed state "
                f"{ui_state!r}, but `izba diff` ground truth reports "
                f"{truth_state!r} for sandbox {name!r} "
                f"(raw: {stdout.strip()[:200]!r})" + snapshot_note),
        violated_expectation="the Manifest tab's drift state must match "
                             "izba's own computed drift state (izba diff)",
        source="contract: manifest diff ground truth",
        trajectory_ref=ref,
    )]
