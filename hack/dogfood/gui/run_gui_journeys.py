# hack/dogfood/gui/run_gui_journeys.py
"""GUI dogfood Phase-2 runner: the Actor loop for the Tauri app, driven through
a browser via agent-browser, against a real daemon (the headless bridge
sidecar) and real microVMs.

Mirrors run_journeys.py: same caps, same report-only contract, same per-journey
data-dir isolation, same trajectory shape — only the act/observe primitives
differ. Daemon-truth oracles are reused unchanged: each browser action is
mapped into the existing Action dict, with `reconcile` = the izba __reconcile
snapshot after the action and a final capture_state_evidence pass."""
from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import FakeModel  # noqa: E402
from oracles import (  # noqa: E402
    Action as _A, capture_state_evidence, latency_oracle, reconcile_seq_oracle,
)
from run_journeys import (  # noqa: E402
    select_shard, _journey_data_dir, _write_seeds, BudgetExceeded, count_degraded,
    CATASTROPHIC_DEGRADED_FRACTION, EXIT_CATASTROPHIC_INFRA, _decisive_step_indices,
    _flipping_violations,
)
from gui.driver import (  # noqa: E402
    AgentBrowserDriver, FakeDriver, action_to_argv, render_marks,
)
from gui.gui_model import build_gui_model  # noqa: E402
from gui.gui_oracles import (  # noqa: E402
    console_oracle, dom_expect_oracle, expect_state_oracle, expect_text_oracle,
    manifest_truth_oracle, silent_failure_oracle, ui_daemon_diff_oracle,
)

DEFAULT_LATENCY_BUDGET_MS = 30_000


def log(msg: str) -> None:
    print(f"[dogfood-gui] {msg}", file=sys.stderr, flush=True)


def select_gui_journeys(journeys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [j for j in journeys if j.get("modality") == "gui"]


def _reconcile_snapshot(izba_bin: str, data_dir: str, timeout_s: float,
                        env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """`izba __reconcile --json` against the shared data dir → snapshot dict
    (always has a 'violations' key).

    Report-only, but honest (mirrors oracles._snapshot_reconcile): a FAILED
    snapshot carries an ``error`` key so a broken reconciler is distinguishable
    from a clean one — a dead izba binary must not masquerade as
    ``{"violations": []}``."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    run_env["IZBA_DATA_DIR"] = data_dir
    err = "unknown"
    try:
        p = subprocess.run([izba_bin, "__reconcile", "--json"], capture_output=True,
                           text=True, timeout=timeout_s, env=run_env)
        if p.returncode == 0 and (p.stdout or "").strip():
            snap = json.loads(p.stdout)
            if "violations" not in snap:
                snap["violations"] = []
            return snap
        err = f"exit {p.returncode}: {(p.stderr or '')[-200:]}"
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        err = repr(e)
    return {"error": err, "violations": [], "sandboxes": []}


def _settle_for_sandbox(izba_bin: str, data_dir: str, timeout_s: float,
                        action_timeout_s: float, poll_s: float = 3.0) -> None:
    """Bounded wait for an async create/VM-boot to register a sandbox before the
    final state snapshot. Polls `izba __reconcile` and returns as soon as any
    sandbox appears, or when ``timeout_s`` elapses. Report-only: never raises.
    A ``timeout_s`` of 0 returns immediately (no settle)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snap = _reconcile_snapshot(izba_bin, data_dir,
                                   min(action_timeout_s, max(poll_s, 1.0)))
        if snap.get("sandboxes"):
            return
        time.sleep(poll_s)


# D-GUI-5 (deep-tier skeptic): the app's TopBar renders exactly one
# daemon-status line (app/src/components/TopBar.tsx) — "Connecting…" while
# the headless bridge/daemon is still coming up, "daemon unreachable" when
# the connection failed, or "daemon running · vX" once ready. Two deep
# journeys recorded ZERO actions because the Actor's first observation
# caught the mid-"Connecting…" screen and the cheap actor gave up — so the
# runner gates the Actor's first turn on this ready marker.
_APP_READY_MARKER = "daemon running"


def _wait_app_ready(driver, timeout_s: float, poll_s: float = 1.0) -> tuple:
    """Bounded poll of the page text until the daemon-status line carries
    ``_APP_READY_MARKER`` (case-insensitive). Returns ``(ready,
    last_page_text)``. A persisting "Connecting…"/"daemon unreachable"
    screen is a HARNESS degradation (the bridge sidecar/daemon never came
    up), not a product finding — on timeout the caller records a flipping
    infra candidate and never starts the Actor, instead of letting it flail
    against a mid-connect screen (the D-GUI-5 zero-action class).
    Report-only: never raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        text = driver.read_page_text() or ""
        if _APP_READY_MARKER in text.lower():
            return True, text
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, text
        time.sleep(min(poll_s, remaining))


def _action_dict(intent: str, command: str, res, marks_text: str,
                 reconcile: Dict[str, Any], console_errors: List[str],
                 screenshot_ref: str = "", page_text: str = "") -> Dict[str, Any]:
    """Map a GUI action into the trajectory Action shape (+ optional GUI fields).

    ``page_text`` (Fix 2, run-2 skeptic) is `document.body.innerText` captured
    right alongside ``marks_text`` — the accessibility set-of-marks misses
    plain `<div>` text (no role/name), which is exactly how promote/create
    error and outcome copy renders (see `driver.read_page_text`,
    `gui_oracles.silent_failure_oracle`/`dom_expect_oracle`)."""
    d = {
        "intent": intent,
        "command": command,
        "exit_code": int(getattr(res, "exit_code", 0)),
        "stdout_tail": marks_text[-4000:],
        "stderr_tail": (getattr(res, "stderr", "") or "")[-4000:],
        "latency_ms": int(getattr(res, "latency_ms", 0)),
        "reconcile": reconcile,
        "snapshot": marks_text[-4000:],
        "page_text": page_text,
        "console_errors": list(console_errors or []),
    }
    if screenshot_ref:
        d["screenshot_ref"] = screenshot_ref
    return d


def _cmd_hash(journey_id: str, command: str) -> str:
    return hashlib.sha256(f"{journey_id}\0{command}".encode("utf-8")).hexdigest()


def _count_manifest_digests(invoke_log: List[Dict[str, Any]]) -> int:
    """How many digest-carrying ``manifest_diff`` invokes the log holds — the
    same filter manifest_truth_oracle applies, so the runner's per-invoke
    izba.yml snapshots (Fix 2, TOCTOU) stay index-aligned with the digest
    list the oracle grades."""
    return sum(1 for e in invoke_log or []
               if isinstance(e, dict) and e.get("cmd") == "manifest_diff"
               and isinstance(e.get("digest"), dict))


def _read_workspace_file(path: str) -> Optional[str]:
    """File content, or None when unreadable/absent. Report-only."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


# The app's ambient background polling commands (app/src/lib/ipc.ts's
# `list`/`daemonStatus`/`versionInfo`, driven by usePolling on a fixed
# interval regardless of what the Actor does) — every GUI journey's
# invoke_log carries a growing stream of these even if the Actor does
# nothing at all. They are therefore not evidence the journey exercised
# anything; see `_has_product_invoke`.
_AMBIENT_POLL_CMDS = frozenset({"list", "daemon_status", "version_info"})


def _has_product_invoke(invoke_log: List[Dict[str, Any]]) -> bool:
    """True if ``invoke_log`` contains at least one invoke beyond the app's
    ambient polling (``_AMBIENT_POLL_CMDS``) — i.e. the Actor engaged the
    app's real command surface at least once, even a read-only one (e.g.
    ``volume_list``).

    Run-4 skeptic H2: `manifest-stale-token-refusal` (no ``core: true``
    step) clicked ONE ref and stopped; its invoke_log was 90 entries of
    alternating ``list``/``daemon_status`` polling and NOTHING else — no
    `create`, no `manifest_diff`. The journey's whole point (a TOCTOU
    stale-review-token refusal) was never exercised, yet it graded positive:
    the runner's decisive-wiring above only flips a journey that DECLARES a
    `core: true` step, and this journey deliberately doesn't have one (its
    only assertion is the promote-refusal copy, which the harness cannot
    assert as a hard precondition — see the journey's `rationale`). A lazy
    1-action bail with an entirely-ambient invoke_log must not be
    indistinguishable from a journey that legitimately only reads state
    (`newsandbox-create-disabled-hints` also has no core step, but its
    invoke_log carries a real `volume_list` call — this function correctly
    returns True for it, so it is NOT flipped by the check below)."""
    return any(isinstance(e, dict) and e.get("cmd") not in _AMBIENT_POLL_CMDS
               for e in invoke_log or [])


def _is_daemon_spawn_failure(entry: Any) -> bool:
    """True for an invoke-log rejection whose error is a `DaemonClient` spawn
    failure — the ``spawning [...]`` anyhow context string
    (`procmgr::spawn_detached`, wrapped by `DaemonClient::connect_spawning_izba`)
    surfacing because the headless sidecar couldn't find/exec the `izba`
    binary. Every invoke in a journey fails identically once the daemon can't
    spawn at all, so this is ONE root cause, not one independent product
    finding per rejected invoke."""
    return (isinstance(entry, dict) and entry.get("ok") is False
            and "spawning [" in str(entry.get("error", "")))


def _infra_candidate(journey_id: str, detail: str) -> Dict[str, Any]:
    """Flipping infra candidate — same shape as the CLI runner's (a broken
    model/driver plumbing means the journey verified nothing)."""
    return {
        "kind": "infra",
        "detail": detail,
        "violated_expectation": "model/API must produce a next command",
        "source": "harness: model transport",
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


def _substitute_workspace(text: Any, workspace: str) -> Any:
    """Replace the literal ``{workspace}`` token with the journey's absolute
    workspace path. Only that one token is templated — no other substitution.
    Non-str input (or a falsy ``workspace``) passes through unchanged."""
    if not isinstance(text, str) or not workspace:
        return text
    return text.replace("{workspace}", workspace)


def _substitute_steps_workspace(steps: List[Dict[str, Any]],
                                workspace: str) -> List[Dict[str, Any]]:
    """Shallow-copy each step, substituting ``{workspace}`` in ``intent``,
    ``expect``, and the declarative decisive hooks ``expect_text`` /
    ``expect_state.sandbox`` (``seed_files`` and everything else pass through
    untouched). Done ONCE up front so both the Actor loop (which reads
    ``step['intent']`` every turn) and the end-of-journey grading (dom_expect
    on ``steps[-1]['expect']``, the hook oracles on the core step) see the
    same substituted text — the substitution must land before
    ``expectation_keywords`` tokenizes it / the hook oracles match it."""
    if not workspace:
        return steps
    out = []
    for step in steps:
        s = dict(step)
        if "intent" in s:
            s["intent"] = _substitute_workspace(s.get("intent"), workspace)
        if "expect" in s:
            s["expect"] = _substitute_workspace(s.get("expect"), workspace)
        if "expect_text" in s:
            s["expect_text"] = _substitute_workspace(s.get("expect_text"),
                                                     workspace)
        if isinstance(s.get("expect_state"), dict):
            es = dict(s["expect_state"])
            if "sandbox" in es:
                es["sandbox"] = _substitute_workspace(es.get("sandbox"),
                                                      workspace)
            s["expect_state"] = es
        out.append(s)
    return out


def _valid_volume_spec(vspec: Any) -> bool:
    """True iff ``vspec`` is a schema-shaped ``expect_state.volume`` object:
    a dict with a non-empty ``name`` and at least one of
    ``exists``/``attached_to`` declared."""
    return (isinstance(vspec, dict) and bool(vspec.get("name"))
            and ("exists" in vspec or "attached_to" in vspec))


def _valid_port_spec(pspec: Any) -> bool:
    """True iff ``pspec`` is a schema-shaped ``expect_state.port`` object: a
    dict with an integer ``host`` (bool rejected — Python bools are ints) and
    at least one of ``exists``/``persistent`` declared."""
    return (isinstance(pspec, dict)
            and isinstance(pspec.get("host"), int)
            and not isinstance(pspec.get("host"), bool)
            and ("exists" in pspec or "persistent" in pspec))


def _valid_sandboxes_exact(v: Any) -> bool:
    """True iff ``v`` is a schema-shaped ``expect_state.sandboxes_exact``
    value: a list — possibly EMPTY (asserts no sandboxes exist at all) — of
    non-empty strings."""
    return (isinstance(v, list)
            and all(isinstance(n, str) and n for n in v))


def _state_hook_label(state_hook: Dict[str, Any]) -> str:
    """Human label for an expect_state hook's target — the named sandbox for
    per-sandbox assertions, the daemon set for a pure sandboxes_exact spec."""
    name = state_hook.get("sandbox")
    return (f"sandbox {name!r}" if name
            else "the daemon sandbox set (sandboxes_exact)")


def _step_decisive_hooks(step: Dict[str, Any]) -> tuple:
    """The (expect_text, expect_state) declarative hooks a step carries, with
    malformed values normalized to absent (``None``): a hook the schema would
    reject (non-str/empty expect_text; expect_state carrying a per-sandbox
    assertion — ``exists``/``status``/``volume``/``port`` — without a
    ``sandbox`` target, without at least one assertion among those plus
    ``sandboxes_exact``, or with a half-formed ``volume``/``port``/
    ``sandboxes_exact`` value — a declared assertion must never be silently
    dropped) is NOT gradable and must fall through to the
    unreached_decisive flip — never a silent pass on a half-formed
    assertion."""
    text = step.get("expect_text")
    if not (isinstance(text, str) and text):
        text = None
    state = step.get("expect_state")
    if not isinstance(state, dict):
        state = None
    else:
        per_sandbox = [k for k in ("exists", "status", "volume", "port")
                       if k in state]
        if per_sandbox and not state.get("sandbox"):
            state = None  # per-sandbox assertions need a sandbox target
        elif not per_sandbox and "sandboxes_exact" not in state:
            state = None  # no assertion declared at all
        elif "volume" in state and not _valid_volume_spec(state.get("volume")):
            state = None
        elif "port" in state and not _valid_port_spec(state.get("port")):
            state = None
        elif ("sandboxes_exact" in state
              and not _valid_sandboxes_exact(state.get("sandboxes_exact"))):
            state = None
    return text, state


def _apply_hook_verdict(verdict: str, found: List[Any], *, hook: str,
                        no_evidence_detail: str, journey_id: str,
                        step_idx: int, candidates: List[Dict[str, Any]],
                        decisive_credits: List[Dict[str, Any]]) -> None:
    """Fold one hook oracle's ``(verdict, candidates)`` into the journey per
    the instrument-honesty contract: ``matched`` ⇒ an auditable
    decisive_credits entry (the skeptic must see the decisive assertion WAS
    checked, mirroring the manifest_truth credit shape); ``mismatch`` ⇒ the
    oracle's ``functional`` candidate(s) tagged ``decisive`` (the collector's
    flip contract); ``no_evidence`` ⇒ a flipping ``infra`` candidate
    (couldn't verify — harness degradation, not a product bug, and NEVER a
    silent pass)."""
    if verdict == "matched":
        decisive_credits.append({
            "step_index": step_idx, "action_index": -1,
            "graded_cmd": f"{hook} (matched)",
        })
        return
    if verdict == "no_evidence":
        candidates.append(_infra_candidate(
            journey_id, f"{no_evidence_detail} (core decisive step {step_idx})"))
        return
    for c in found:
        cd = c.to_dict()
        cd["decisive"] = True
        candidates.append(cd)


_ZERO_ACTION_REASON = ("actor performed no actions; decisive assertion "
                       "never exercised")


def _zero_action_unreached(journey_id: str, step: Dict[str, Any],
                           source: str, hook_desc: str) -> Dict[str, Any]:
    """The Fix-4 reclassification candidate: a decisive hook that FAILED on a
    journey whose Actor never acted is an unreached/engagement failure (the
    swarm never attempted the interaction), NOT a product-functional flip —
    'absent from every capture' over an untouched screen reads as a product
    failure but proves nothing about the product."""
    return {
        "kind": "unreached_decisive",
        "detail": f"{_ZERO_ACTION_REASON} ({hook_desc})",
        "violated_expectation": step.get("expect", "") or hook_desc,
        "source": source,
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


def _settle_expect_state(state_hook: Dict[str, Any], first_verdict: str,
                         first_found: List[Any], *, resample_state,
                         settle_s: float, poll_s: float, ref: Dict[str, Any],
                         step_idx: int, expect: str, source: str,
                         settle_out: Dict[str, Any],
                         first_evidence: Dict[str, Any]):
    """Fix 1 (expect_state settle): confirm a failing expect_state assertion
    across a bounded re-sample window before letting it flip.

    A GUI stop/restart returns while the guest is still mid-ACPI-S5 teardown;
    the post-journey state evidence can sample the transient window where the
    VMM pid is not yet reaped but a sidecar already exited — liveness then
    honestly reports 'degraded (sidecar … died)' where the SETTLED truth is
    'stopped'/'running'. Mirrors the create-settle mechanism (bounded poll,
    report-only): re-capture the state evidence every ``poll_s`` until the
    assertion stops mismatching or ``settle_s`` elapses, and grade the
    SETTLED sample. Honesty: a genuinely-wrong settled state still flips —
    only divergence that VANISHES within the window is absorbed; and both
    the first and settled samples are recorded (``settle_out``) so the
    skeptic can audit exactly what was absorbed. Returns
    ``(verdict, found, settled_evidence)``."""
    verdict, found, evidence = first_verdict, first_found, first_evidence
    start = time.monotonic()
    deadline = start + settle_s
    resampled = False
    while time.monotonic() < deadline:
        time.sleep(poll_s)
        ev2 = resample_state()
        if ev2 is None:
            continue  # a failed re-capture is not evidence; keep polling
        resampled = True
        evidence = ev2
        verdict, found = expect_state_oracle(
            state_hook, ev2, ref, step_index=step_idx, expect=expect,
            source=source)
        if verdict != "mismatch":
            break
    if resampled:
        settle_out["first"] = first_evidence
        settle_out["settled"] = evidence
        settle_out["waited_s"] = round(time.monotonic() - start, 1)
        if verdict == "mismatch":
            for c in found:  # the flip is CONFIRMED, not a transient sample
                c.detail += (f" (confirmed across a {settle_s:g}s "
                             f"expect_state settle re-sample)")
    return verdict, found, evidence


def _grade_core_step_hooks(*, journey: Dict[str, Any], journey_id: str,
                           steps: List[Dict[str, Any]],
                           page_text_history: List[str],
                           step_hist_start: Dict[int, int],
                           state_evidence: Dict[str, Any],
                           candidates: List[Dict[str, Any]],
                           decisive_credits: List[Dict[str, Any]],
                           zero_actions: bool = False,
                           resample_state=None,
                           settle_s: float = 0.0,
                           settle_poll_s: float = 3.0,
                           settle_out: Optional[Dict[str, Any]] = None) -> None:
    """Grade every declared ``core: true`` step of a NON-manifest GUI journey
    through its declarative hooks — precedence rung 2 of the decisive wiring
    (see run_gui_journey's comment block). Mutates ``candidates`` /
    ``decisive_credits`` in place. Only called when the journey declares a
    core step and drove no manifest_diff, so ``_decisive_step_indices`` here
    yields exactly the core steps (never the fallback last step).

    Per core step:

    - no valid hook ⇒ one flipping ``unreached_decisive`` whose reason names
      the hooks (so the journey compiler learns to annotate every core step);
    - ``expect_text`` ⇒ graded over the page-text window starting at the
      step's own first capture (its "opened screen" snapshot — a
      pure-observation step's outcome is already on screen) through every
      later capture including the final post-settle one (an async
      create/boot lands its row only after the settle poll). A core step the
      Actor never entered falls back to the final capture alone — the
      outcome being observably present at journey end is still honest
      evidence, mirroring the CLI runner's satisfied-under-an-earlier-step
      crediting (_grade_decisive_from_observed);
    - ``expect_state`` ⇒ graded against the end-of-journey daemon state
      evidence (post-settle ``capture_state_evidence`` — product truth). A
      MISMATCH is first confirmed across a bounded settle re-sample
      (``settle_s``/``resample_state``, Fix 1 — see _settle_expect_state);
      only divergence that persists flips.

    ``zero_actions`` (Fix 4): a journey whose Actor performed ZERO browser
    actions never exercised anything, so hook grading applies ONLY the
    initial-observation window: an ``expect_text`` that passes THERE is
    genuine credit (pure-observation journeys — the H-GUI-2 contract), and a
    passing ``expect_state`` (state that needs no interaction — rare) is
    credited too; but a FAILING hook on a zero-action journey flips as
    ``unreached_decisive`` (the actor never attempted the interaction the
    assertion presupposes), never as a product-functional flip. No settle is
    attempted either — there is no in-flight operation to settle. The
    ``no_evidence`` ⇒ infra degradation is unchanged.

    ALL declared hooks must pass; verdict folding per _apply_hook_verdict."""
    source = journey.get("source", {}).get("ref", "journey step")
    final_hist_idx = max(len(page_text_history) - 1, 0)
    current_evidence = state_evidence
    for step_idx in sorted(_decisive_step_indices(steps)):
        s = steps[step_idx] if step_idx < len(steps) else {}
        ref = {"journey_id": journey_id, "action_index": -1}
        text_hook, state_hook = _step_decisive_hooks(s)
        if text_hook is None and state_hook is None:
            candidates.append({
                "kind": "unreached_decisive",
                "detail": (f"decisive step {step_idx} "
                           f"({s.get('intent', '')[:80]!r}) carries no "
                           f"gradable hook (expect_text/expect_state) and "
                           f"the journey drove no manifest_diff — its "
                           f"assertion was never exercised"),
                "violated_expectation": s.get("expect", "")
                                        or "decisive step must be exercised",
                "source": source,
                "trajectory_ref": dict(ref),
            })
            continue
        if text_hook is not None:
            if zero_actions:
                window = page_text_history[:1]
            else:
                start = min(step_hist_start.get(step_idx, final_hist_idx),
                            final_hist_idx)
                window = page_text_history[start:]
            verdict, found = expect_text_oracle(
                text_hook, window, ref,
                step_index=step_idx, expect=s.get("expect", ""), source=source)
            if zero_actions and verdict == "mismatch":
                candidates.append(_zero_action_unreached(
                    journey_id, s, source,
                    f"expect_text {text_hook!r} not present in the initial "
                    f"observation"))
            else:
                _apply_hook_verdict(
                    verdict, found, hook=f"expect_text: {text_hook!r}",
                    no_evidence_detail=(
                        "expect_text: no page text was ever captured to grade "
                        "the assertion against"),
                    journey_id=journey_id, step_idx=step_idx,
                    candidates=candidates, decisive_credits=decisive_credits)
        if state_hook is not None:
            verdict, found = expect_state_oracle(
                state_hook, current_evidence, ref,
                step_index=step_idx, expect=s.get("expect", ""), source=source)
            if zero_actions:
                if verdict == "mismatch":
                    candidates.append(_zero_action_unreached(
                        journey_id, s, source,
                        f"expect_state for {_state_hook_label(state_hook)} "
                        f"presupposes an "
                        f"interaction the actor never attempted"))
                    continue
            elif (verdict == "mismatch" and settle_s > 0
                    and resample_state is not None):
                verdict, found, current_evidence = _settle_expect_state(
                    state_hook, verdict, found,
                    resample_state=resample_state, settle_s=settle_s,
                    poll_s=settle_poll_s, ref=ref, step_idx=step_idx,
                    expect=s.get("expect", ""), source=source,
                    settle_out=settle_out if settle_out is not None else {},
                    first_evidence=current_evidence)
            _apply_hook_verdict(
                verdict, found,
                hook=f"expect_state: {_state_hook_label(state_hook)}",
                no_evidence_detail=(
                    "expect_state: daemon state evidence unavailable "
                    "(reconcile snapshot errored/absent, no usable "
                    "`izba volume ls` capture for a volume assertion, or no "
                    "usable port_ls/ports_persisted capture for a port "
                    "assertion), assertion unverifiable"),
                journey_id=journey_id, step_idx=step_idx,
                candidates=candidates, decisive_credits=decisive_credits)


def run_gui_journey(model, driver, journey: Dict[str, Any], *, izba_bin: str,
                    data_dir: str, max_turns: int, step_cap: int,
                    action_timeout_s: float, latency_budget_ms: int,
                    budget: Dict[str, float], max_usd: float,
                    artifact_dir: str = "",
                    create_settle_s: float = 0.0,
                    expect_state_settle_s: float = 0.0,
                    workspace: str = "",
                    app_ready_timeout_s: float = 0.0) -> Dict[str, Any]:
    """Run one GUI journey under all caps. Returns a journey_result dict.

    ``create_settle_s`` bounds an end-of-journey wait for an in-flight async
    create/VM-boot to register a sandbox in the daemon before the final
    state-evidence snapshot (the GUI ``create`` invoke resolves asynchronously,
    so a journey can otherwise end before its sandbox appears). 0 disables it
    (used by the unit tests, which mock the reconcile).

    ``expect_state_settle_s`` (Fix 1) bounds the settle re-sample window when
    a core step's ``expect_state`` assertion fails on the first post-journey
    sample: lifecycle teardown (stop/restart) and volume-save operations land
    asynchronously, so the first sample can catch a transient window (vmm pid
    unreaped, sidecar already exited ⇒ 'degraded (sidecar … died)') whose
    settled truth is the asserted state. Only divergence that persists across
    the window flips; both samples land in the bundle (``state_evidence`` =
    settled, ``state_evidence_presettle`` = first). 0 disables it (the unit
    tests' default; CI runs the parse_args default).

    ``workspace`` (Task 10) is a per-journey directory the GUI swarm can type
    a real path into (e.g. the NewSandbox form) and that mid-journey
    ``seed_files`` drift lands in — the GUI counterpart of the CLI runner's
    ``workdir``. Journey-level ``seed_files`` are written there before step 0;
    step-level ``seed_files`` immediately before that step's first action
    (same timing semantics as ``run_journeys._run_step``). The literal token
    ``{workspace}`` in a step's ``intent``/``expect`` is replaced with this
    absolute path before the Actor or the dom_expect oracle ever see it.

    ``app_ready_timeout_s`` (D-GUI-5) bounds a pre-Actor wait for the app's
    daemon-status line to reach "daemon running" (see ``_wait_app_ready``):
    an Actor whose first observation catches the mid-"Connecting…" boot
    screen tends to give up with zero actions. On timeout the journey
    returns immediately with ONE flipping infra candidate (harness
    degradation — the bridge/daemon never came up; nothing was measured) and
    the last-seen page text as its ``initial_observation``. Readiness also
    guarantees the H-GUI-2 opening capture shows the READY page. 0 disables
    it (the unit tests' default; CI runs the parse_args default)."""
    journey_id = journey.get("journey_id", "")
    actions: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    turns = 0
    console_seen = 0
    prev_reconcile: Optional[Dict[str, Any]] = None
    # Fix 1 (run-2 skeptic): every marks snapshot taken this journey, in
    # chronological order — fed to ui_daemon_diff_oracle so it can grade
    # against the last one that isn't a portal-obscured modal, instead of
    # false-positiving whenever the journey happened to end with a dialog
    # open (see gui_oracles.ui_daemon_diff_oracle's docstring).
    # Fix 2 (run-3 H1): the parallel `document.body.innerText` capture for
    # each entry above (same index) — this app's dialogs hide the rail from
    # the a11y tree but not from page_text, so the oracle prefers this union
    # over the marks-only heuristic (gui_oracles._last_reliable_snapshot).
    marks_history: List[str] = []
    page_text_history: List[str] = []
    # Index into the histories where each step's captures begin (the step's
    # own pre-turn "opened screen" snapshot is entry 0 of its window) — the
    # expect_text hook grades "at/after the core step", which needs to know
    # where that step's evidence starts. A step the Actor never entered has
    # no entry (grading then falls back to the final capture alone).
    step_hist_start: Dict[int, int] = {}
    ws_abs = os.path.abspath(workspace) if workspace else ""
    if ws_abs:
        os.makedirs(ws_abs, exist_ok=True)
    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]
    steps = _substitute_steps_workspace(steps, ws_abs)
    # D-GUI-5 readiness gate: never start the Actor against a mid-connect
    # screen. On timeout the journey verified NOTHING — one flipping infra
    # candidate (the same degradation shape as a dead sidecar), with the
    # last-seen page text on record for the skeptic.
    if app_ready_timeout_s > 0:
        ready, boot_text = _wait_app_ready(driver, app_ready_timeout_s)
        if not ready:
            log(f"{journey_id}: app not ready after {app_ready_timeout_s:g}s; "
                f"skipping the Actor")
            return {
                "journey_id": journey_id, "actions": [],
                "candidates": [_infra_candidate(
                    journey_id,
                    f"app never showed the ready daemon-status line "
                    f"({_APP_READY_MARKER!r}) within {app_ready_timeout_s:g}s "
                    f"— the Actor was not started (last page text: "
                    f"{(boot_text or '')[:200]!r})")],
                "invoke_log": driver.read_invoke_log(),
                "workspace": str(ws_abs), "decisive_credits": [],
                "initial_observation": {"marks": "",
                                        "page_text": boot_text or ""},
            }
    # Fix 2 (manifest_truth TOCTOU): the workspace izba.yml content as of
    # each digest-carrying manifest_diff invoke, in invoke order. The
    # end-of-journey `izba diff` ground truth otherwise runs against the
    # CURRENT file — which a seeded-drift step may have edited/reverted
    # AFTER the UI's last diff, making truth and UI legitimately diverge and
    # false-flipping a correct UI. Snapshots are caught up right after every
    # action, right before a step's seed write lands (closing the gap where
    # an async diff resolves between the previous action's poll and the
    # seed), and once at journey end.
    manifest_yml_snapshots: List[Optional[str]] = []

    def _snap_manifest_yml(inv: Optional[List[Dict[str, Any]]] = None) -> None:
        log_now = inv if inv is not None else driver.read_invoke_log()
        n = _count_manifest_digests(log_now)
        while len(manifest_yml_snapshots) < n:
            manifest_yml_snapshots.append(
                _read_workspace_file(os.path.join(ws_abs, "izba.yml"))
                if ws_abs else None)

    # Journey-level seed_files (precondition), written before step 0.
    _write_seeds(ws_abs, journey.get("seed_files"))
    try:
        for step_i, step in enumerate(steps):
            # Step-level seed_files (mid-journey drift) land immediately
            # before this step's first action — never inside its while loop,
            # so they're written exactly once per step regardless of turns.
            # Any manifest_diff that resolved since the last poll must be
            # snapshotted BEFORE the seed rewrites izba.yml.
            if step.get("seed_files"):
                _snap_manifest_yml()
            _write_seeds(ws_abs, step.get("seed_files"))
            step_hist_start[step_i] = len(page_text_history)
            seen: set = set()
            # Seed the Actor with the current screen so its FIRST decision sees
            # the accessibility marks (real refs to act on) rather than an empty
            # observation — otherwise it guesses a ref and burns a turn.
            marks_text = render_marks(driver.snapshot())
            marks_history.append(marks_text)
            page_text_history.append(driver.read_page_text())
            obs: List[Dict[str, Any]] = [{"action": "(opened screen)",
                                          "marks": marks_text}]
            while True:
                if len(actions) >= step_cap:
                    log(f"{journey_id}: step-cap reached"); raise StopIteration
                if turns >= max_turns:
                    log(f"{journey_id}: max-turns reached"); raise StopIteration
                if budget["usd"] >= max_usd:
                    raise BudgetExceeded()
                turns += 1
                try:
                    reply = model.next_command(journey, step, obs)
                    budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
                except Exception as e:  # report-only, but never silently green
                    log(f"{journey_id}: model error: {e!r}")
                    candidates.append(_infra_candidate(journey_id,
                                                       f"model raised: {e!r}"))
                    break
                if isinstance(reply, dict) and reply.get("error"):
                    log(f"{journey_id}: model infra error: {reply['error']}")
                    candidates.append(_infra_candidate(journey_id,
                                                       str(reply["error"])))
                    break
                if not isinstance(reply, dict) or reply.get("done"):
                    break
                if reply.get("read"):
                    marks_text = render_marks(driver.snapshot())
                    marks_history.append(marks_text)
                    page_text_history.append(driver.read_page_text())
                    obs.append({"action": "read", "marks": marks_text})
                    continue
                argv = action_to_argv(reply)
                if argv is None:
                    break
                command = " ".join(argv)
                h = _cmd_hash(journey_id, command)
                if h in seen:
                    log(f"{journey_id}: loop-dedup on {command!r}"); break
                seen.add(h)
                res = driver.act(argv)
                marks_text = render_marks(driver.snapshot())
                marks_history.append(marks_text)
                page_text = driver.read_page_text()
                page_text_history.append(page_text)
                reconcile = _reconcile_snapshot(izba_bin, data_dir, action_timeout_s)
                _snap_manifest_yml()  # Fix 2: pair new diffs with the file NOW
                all_console = driver.read_console_errors()
                console_errors = all_console[console_seen:]
                console_seen = len(all_console)
                action_index = len(actions)
                ref = {"journey_id": journey_id, "action_index": action_index}
                actions.append(_action_dict(step.get("intent", ""), command, res,
                                            marks_text, reconcile, console_errors,
                                            page_text=page_text))
                obs.append({"action": command, "marks": marks_text})
                # Per-action oracles.
                act_obj = _A(intent=step.get("intent", ""), command=command,
                             exit_code=int(res.exit_code), stdout_tail=marks_text,
                             stderr_tail="", latency_ms=int(res.latency_ms),
                             reconcile=reconcile)
                found = (latency_oracle(act_obj, latency_budget_ms)
                         + console_oracle(console_errors, ref))
                if prev_reconcile is not None:
                    found += reconcile_seq_oracle(prev_reconcile, reconcile)
                for c in found:
                    cd = c.to_dict(); cd["trajectory_ref"] = ref
                    candidates.append(cd)
                # Reconcile violations flip the journey (parity with the CLI
                # runner's _collect_candidates): declared state != reality is
                # a product finding regardless of which surface drove it.
                # Fix 3: same parity for the product's self-labeled
                # `informational:` items (e.g. orphan_volume after rm — the
                # DOCUMENTED persistent-volumes-survive-rm contract,
                # reconcile.rs prefixes the detail): they stay on record in
                # the action's reconcile snapshot (audit trail) but never
                # produce a flipping candidate; every other violation flips
                # exactly as before.
                violations = _flipping_violations(
                    (reconcile or {}).get("violations") or [])
                if violations:
                    preview = json.dumps(violations[:3])[:400]
                    candidates.append({
                        "kind": "reconcile_violation",
                        "detail": (f"izba __reconcile reported "
                                   f"{len(violations)} violation(s) after "
                                   f"{command!r}: {preview}"),
                        "violated_expectation": "reconciler must report no "
                                                "violations (declared state == "
                                                "reality)",
                        "source": "contract: disk-state invariant (__reconcile)",
                        "trajectory_ref": dict(ref),
                    })
                prev_reconcile = reconcile
    except StopIteration:
        pass
    except BudgetExceeded:
        raise

    # A journey whose EVERY snapshot errored had no reconcile oracle at all.
    if actions and all((a.get("reconcile") or {}).get("error") for a in actions):
        candidates.append(_infra_candidate(
            journey_id, "reconciler unusable: every snapshot errored"))

    # Give an in-flight async create/VM-boot time to register a sandbox before
    # grading the outcome (the GUI create invoke resolves asynchronously).
    if create_settle_s > 0:
        _settle_for_sandbox(izba_bin, data_dir, create_settle_s, action_timeout_s)
    # End-of-journey oracles: daemon truth + UI-vs-daemon + dom-expect + silent-fail.
    try:
        state_evidence = capture_state_evidence(izba_bin, data_dir, action_timeout_s,
                                                env={"IZBA_DATA_DIR": data_dir})
    except Exception as e:  # report-only
        log(f"{journey_id}: state-evidence error: {e!r}")
        state_evidence = {"sandboxes": [], "reconcile": {}, "per_sandbox": {}}
    final_marks = render_marks(driver.snapshot())
    marks_history.append(final_marks)
    final_page_text = driver.read_page_text()
    page_text_history.append(final_page_text)
    final_ref = {"journey_id": journey_id, "action_index": -1}
    invoke_log = driver.read_invoke_log()
    # Fix 2: a manifest_diff that resolved after the last per-action poll is
    # caught up here against the current file — seeds only land before a
    # step's first action, so nothing rewrote izba.yml since.
    _snap_manifest_yml(invoke_log)
    last_expect = (steps[-1].get("expect", "") if steps else "")
    # A daemon that can't spawn rejects EVERY invoke identically: fold those
    # into one flipping infra candidate (the run measured nothing, once) and
    # suppress the matching per-entry silent_failure duplicates — they are
    # one root cause, not hundreds of product findings. All other rejection
    # kinds keep the normal silent_failure treatment unchanged.
    spawn_failed = [e for e in (invoke_log or []) if _is_daemon_spawn_failure(e)]
    if spawn_failed:
        candidates.append(_infra_candidate(
            journey_id,
            f"daemon failed to spawn ({len(spawn_failed)} rejected invoke(s)); "
            f"first: {spawn_failed[0].get('error')!r}"))
    silent_failure_log = [e for e in (invoke_log or [])
                          if not _is_daemon_spawn_failure(e)]
    # Fix 2 (run-2 skeptic): silent_failure has no timestamp/index
    # correlation between a specific invoke-log rejection and a specific
    # action, so it checks the union of every action's page_text across the
    # whole journey (plus the final one) — the widest reasonable "at-or-after
    # the rejection" approximation (see gui_oracles.silent_failure_oracle's
    # docstring for the false-negative/false-positive tradeoff rationale).
    all_page_text = "\n".join(
        [a.get("page_text", "") for a in actions] + [final_page_text])
    end_found = (ui_daemon_diff_oracle(marks_history, state_evidence, final_ref,
                                       page_text_history=page_text_history)
                 + dom_expect_oracle(last_expect, final_marks, final_ref,
                                    page_text=final_page_text)
                 + silent_failure_oracle(silent_failure_log, final_marks, final_ref,
                                         page_text=all_page_text))

    # Decisive wiring (Task 11 + Critical-finding fix + product-wide
    # generalization): the decisive (core: true, else last-step) grading
    # mechanism mirrors the CLI runner's contract (run_journeys._decisive_
    # step_indices, imported unchanged: pure over `steps`, nothing CLI-shaped
    # to fake). Grading PRECEDENCE for a journey with a core step:
    #   1. journey drove manifest_diff ⇒ manifest_truth ground truth
    #      (unchanged Task-11 behavior, its tests pin it);
    #   2. else, the core step carries declarative hooks (`expect_text` /
    #      `expect_state`, compiler-authored, invisible to the Actor) ⇒
    #      grade those — ALL declared hooks must pass (see
    #      _grade_core_step_hooks). This is what gives the product-wide GUI
    #      corpus (navigation/create/lifecycle/ports/volumes outcomes, which
    #      never open the Manifest tab) a REAL grading path instead of
    #      structurally flipping unreached_decisive;
    #   3. else ⇒ unreached_decisive, exactly as before — widening what is
    #      GRADABLE, never weakening the flip: an ungradable core step still
    #      flips, with a reason that tells the compiler what to annotate.
    # A journey WITHOUT any core: true step keeps the original Task-11
    # behavior exactly: decisive wiring only activates when the journey
    # happened to invoke manifest_diff — its fallback-to-last-step decisive
    # index never gets graded otherwise. A journey that explicitly DECLARES a
    # core: true step, though, is asserting "this step's assertion must be
    # verified" — so those journeys must never grade silently positive when
    # the decisive assertion was never actually checked. The unverifiable
    # paths mirror the CLI runner's #126/PR#129 unreached_decisive fix
    # (run_journeys.py ~618-640) so the collector/skeptic see ONE convention
    # across CLI and GUI bundles: (a) no gradable route to the assertion at
    # all ⇒ flip via the exact `unreached_decisive` kind/shape; (b) ground
    # truth couldn't be computed (manifest `no_target`/`unparseable`, an
    # errored reconcile under expect_state, zero page-text captures under
    # expect_text) ⇒ flip via `infra` (harness degradation — couldn't verify
    # — not a product bug). Side-effect constraint: the manifest oracle
    # shells out to `izba diff`, which WRITES the review token, so it is
    # called exactly ONCE here, post-journey (see its docstring).
    decisive_credits: List[Dict[str, Any]] = []
    mt_found: List[Any] = []
    # Fix 1 plumbing: the settle re-sampler + its audit record. The closure
    # resolves capture_state_evidence at call time through module globals so
    # the unit tests' monkeypatch reaches it.
    settle_out: Dict[str, Any] = {}

    def _resample_state() -> Optional[Dict[str, Any]]:
        try:
            return capture_state_evidence(izba_bin, data_dir, action_timeout_s,
                                          env={"IZBA_DATA_DIR": data_dir})
        except Exception as e:  # report-only
            log(f"{journey_id}: settle re-sample error: {e!r}")
            return None

    has_core_step = any(isinstance(s, dict) and s.get("core") for s in steps)
    manifest_diff_seen = any(
        isinstance(e, dict) and e.get("cmd") == "manifest_diff"
        and isinstance(e.get("digest"), dict) for e in invoke_log)
    if manifest_diff_seen and steps:
        sandbox_name = (state_evidence.get("sandboxes") or [None])[-1]
        mt_ctx: Dict[str, Any] = {
            "invoke_log": invoke_log, "sandbox_name": sandbox_name,
            "workspace": ws_abs, "izba_bin": izba_bin, "data_dir": data_dir,
            "timeout_s": action_timeout_s, "ref": dict(final_ref),
            "manifest_yml_snapshots": list(manifest_yml_snapshots)}
        mt_found = manifest_truth_oracle(mt_ctx)
        decisive_idx = _decisive_step_indices(steps)
        mt_result = mt_ctx.get("manifest_truth_result")
        # An empty mt_found is ambiguous by itself (it means EITHER "verified
        # equal" OR "couldn't check" — a subprocess failure/timeout/unparseable
        # `izba diff` output must never be read as a confirmed pass). Only
        # ctx["manifest_truth_result"] == "matched" is an honest positive;
        # "unparseable"/"no_target" leave the decisive step ungraded when
        # there is no explicit core step (unchanged Task-11 behavior) —
        # otherwise they degrade the journey below.
        if decisive_idx and mt_result == "matched":
            # Ground truth matched what the UI showed: the decisive
            # assertion passed. Recorded as an audit-trail credit (schema
            # parity with the CLI runner's decisive_credits) even though
            # nothing flips negative — the skeptic must be able to see
            # this journey's decisive step WAS honestly exercised, not
            # silently skipped.
            decisive_credits.append({
                "step_index": min(decisive_idx),
                "action_index": final_ref["action_index"],
                "graded_cmd": "manifest_truth: izba diff ground truth (matched)",
            })
        elif has_core_step and mt_result in ("no_target", "unparseable"):
            # The harness attempted to verify the declared decisive
            # assertion but couldn't: report-only degradation, not a product
            # finding — same `infra` shape/contract as every other infra
            # candidate this runner emits (must not tally positive).
            candidates.append(_infra_candidate(
                journey_id,
                f"manifest_truth: ground truth could not be verified "
                f"({mt_result}) for a core decisive step"))
    elif has_core_step and steps:
        # No manifest_diff to ground-truth: grade each declared core step
        # through its declarative hooks (expect_text/expect_state), or flip
        # it unreached_decisive when it carries none — see the precedence
        # comment above.
        _grade_core_step_hooks(
            journey=journey, journey_id=journey_id, steps=steps,
            page_text_history=page_text_history,
            step_hist_start=step_hist_start, state_evidence=state_evidence,
            candidates=candidates, decisive_credits=decisive_credits,
            zero_actions=not actions,
            resample_state=_resample_state,
            settle_s=expect_state_settle_s,
            settle_out=settle_out)
    elif not has_core_step and steps and not _has_product_invoke(invoke_log):
        # H2 (run-4 skeptic): a NON-core journey (no declared `core: true`
        # step, so the branches above never engage) whose Actor bailed
        # before invoking anything beyond the app's ambient background
        # polling verified NOTHING — same failure mode as the declared-core
        # case above (a decisive-in-spirit assertion never exercised), just
        # without a `core: true` step to detect it via manifest_diff. Reuses
        # the exact `unreached_decisive` kind so the collector's
        # `_is_flipping` (every kind other than `latency`/non-decisive
        # `functional` flips) and `summarize_bundle.py`'s "❓ unreached"
        # grouping treat it identically to the declared-core-step-unreached
        # case: same meaning ("this journey verified nothing"), different
        # cause (no core step to miss in the first place). A journey that
        # legitimately only reads state (e.g.
        # `newsandbox-create-disabled-hints`) is unaffected: its invoke_log
        # carries a real non-ambient call (`volume_list`), so
        # `_has_product_invoke` is True and this branch never fires.
        source = journey.get("source", {}).get("ref", "journey step")
        candidates.append({
            "kind": "unreached_decisive",
            "detail": (f"invoke_log has no invoke beyond ambient polling "
                       f"({sorted(_AMBIENT_POLL_CMDS)!r}) — the Actor "
                       f"bailed before exercising anything this journey "
                       f"was meant to verify"),
            "violated_expectation": last_expect
                                    or "the journey must exercise at least "
                                       "one real product action",
            "source": source,
            "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
        })
    # Capture an annotated screenshot only if the journey produced any candidate.
    if (candidates or end_found or mt_found) and artifact_dir:
        shot = os.path.join(artifact_dir, f"{journey_id}.png")
        try:
            driver.screenshot(shot)
            if actions:
                actions[-1]["screenshot_ref"] = os.path.join(
                    os.path.basename(artifact_dir), f"{journey_id}.png")
        except Exception:
            shot = ""
    for c in end_found:
        cd = c.to_dict(); cd["trajectory_ref"] = dict(final_ref)
        candidates.append(cd)
    for c in mt_found:
        cd = c.to_dict()
        cd["trajectory_ref"] = dict(final_ref)
        cd["decisive"] = True
        candidates.append(cd)
    # H-GUI-2 (smoke-run skeptic): persist the journey's OPENING capture —
    # history entry 0 is step 0's pre-turn "opened screen" snapshot, taken
    # before the Actor's first decision — so a zero-action journey (an Actor
    # that decides pure observation needs no interaction) still carries page
    # evidence in the bundle instead of an evidence-free positive, and a
    # pure-observation expect_text has an on-record capture behind its grade.
    initial_observation = {
        "marks": marks_history[0] if marks_history else "",
        "page_text": page_text_history[0] if page_text_history else "",
    }
    result = {"journey_id": journey_id, "actions": actions,
              "candidates": candidates,
              # Fix 1: when the settle re-sampled, the SETTLED sample is the
              # truth the decisive grading used, so it becomes the journey's
              # state_evidence; the first sample stays on record below.
              "state_evidence": settle_out.get("settled", state_evidence),
              "invoke_log": invoke_log,
              "workspace": str(ws_abs), "decisive_credits": decisive_credits,
              "initial_observation": initial_observation}
    if "first" in settle_out:
        result["state_evidence_presettle"] = settle_out["first"]
    if manifest_yml_snapshots:
        result["manifest_yml_snapshots"] = manifest_yml_snapshots
    return result


# ---------- CI orchestration (static server + sidecar lifecycle) ----------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve_dir(directory: str, port: int) -> http.server.ThreadingHTTPServer:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _spawn_sidecar(sidecar_bin: str, izba_bin: str, data_dir: str, ws_port: int):
    """Spawn the headless bridge sidecar. Its `DaemonClient::connect_spawning_izba`
    resolves the `izba` binary as a sibling of its own current_exe (nothing
    there for a CI-built sidecar), then falls back to bare `izba` on PATH — so
    the sidecar's PATH must carry the directory holding ``izba_bin``, or every
    daemon-touching invoke fails with a `spawning [...]` error (see
    `_is_daemon_spawn_failure` / the runner's end-of-journey folding of those
    rejections into a single infra candidate)."""
    env = dict(os.environ)
    env["IZBA_DATA_DIR"] = data_dir
    env["IZBA_DOGFOOD_WS_PORT"] = str(ws_port)
    izba_dir = os.path.dirname(os.path.abspath(izba_bin))
    env["PATH"] = izba_dir + os.pathsep + env.get("PATH", "")
    return subprocess.Popen([sidecar_bin], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_port(port: int, timeout_s: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build_model(args):
    if args.fake_model is not None:
        return FakeModel(json.loads(args.fake_model))
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("OPENROUTER_API_KEY required (or pass --fake-model)")
    readme = _read_optional(args.readme)
    app_guide = _read_optional(args.app_guide)
    return build_gui_model(api_key, args.model, app_guide=app_guide, readme=readme)


def _read_optional(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def parse_args(argv):
    p = argparse.ArgumentParser(prog="run_gui_journeys.py")
    p.add_argument("--journeys", required=True)
    p.add_argument("--shard", type=int, default=0)
    p.add_argument("--shards", type=int, default=1)
    p.add_argument("--izba-bin", required=True)
    p.add_argument("--sidecar-bin", required=True)
    p.add_argument("--frontend-dir", required=True, help="built dogfood dist (with real-bridge.js)")
    p.add_argument("--agent-browser-bin", default="agent-browser")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--artifact-dir", default="")
    p.add_argument("--model", default="google/gemini-2.5-flash")
    # H2 (run-3 skeptic): 14 starved multi-phase manifest journeys before
    # their decisive step — `manifest-diverged-rendering` burned its whole
    # budget on the Policy-tab save and never reached the Manifest tab click.
    # No CI-arg override exists (dogfood.yml's GUI job does not pass
    # `--max-turns`), so this default IS the effective value in CI; bumped to
    # 20 to give a multi-phase journey (create + one tab's edit/save + the
    # Manifest tab's own read/act turns) enough headroom to reach its core
    # step. No per-journey override exists in the journeys schema either.
    p.add_argument("--max-turns", type=int, default=20)
    p.add_argument("--max-usd", type=float, default=2.0)
    p.add_argument("--step-cap", type=int, default=20)
    p.add_argument("--action-timeout-s", type=float, default=30.0)
    p.add_argument("--latency-budget-ms", type=int, default=DEFAULT_LATENCY_BUDGET_MS)
    p.add_argument("--create-settle-s", type=float, default=90.0,
                   help="bounded end-of-journey wait for an async create/boot to "
                        "register a sandbox before grading (0 disables)")
    p.add_argument("--expect-state-settle-s", type=float, default=45.0,
                   help="bounded settle re-sample window when a core step's "
                        "expect_state assertion fails on the first post-journey "
                        "sample (0 disables): lifecycle teardown / volume saves "
                        "land asynchronously, so a transient divergence is "
                        "re-sampled until it settles; a genuinely-wrong settled "
                        "state still flips, and both samples are recorded")
    p.add_argument("--app-ready-timeout-s", type=float, default=30.0,
                   help="bounded pre-Actor wait for the app to leave its "
                        "'Connecting…' boot state (the TopBar 'daemon "
                        "running' status line); on timeout the journey "
                        "records a flipping infra candidate instead of "
                        "letting the Actor flail against a mid-connect "
                        "screen (0 disables)")
    p.add_argument("--readme", default="README.md")
    p.add_argument("--app-guide", default="dogfood-app-guide.md")
    p.add_argument("--fake-model", default=None)
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    with open(args.journeys) as f:
        doc = json.load(f)
    feature = doc.get("feature", "")
    mine = select_shard(select_gui_journeys(doc.get("journeys", []) or []),
                        args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} gui journeys")
    os.makedirs(args.data_dir, exist_ok=True)
    if args.artifact_dir:
        os.makedirs(args.artifact_dir, exist_ok=True)
    model = build_model(args)

    http_port = _free_port()
    httpd = _serve_dir(args.frontend_dir, http_port)
    budget = {"usd": 0.0}
    results: List[Dict[str, Any]] = []
    try:
        for journey in mine:
            jid = journey.get("journey_id") or ""
            jdir = _journey_data_dir(args.data_dir, jid)
            os.makedirs(jdir, exist_ok=True)
            # Per-journey workspace (Task 10): created before the sidecar
            # spawns so it's ready the instant the Actor's first turn starts.
            workspace = os.path.join(jdir, "workspace")
            os.makedirs(workspace, exist_ok=True)
            ws_port = _free_port()
            sidecar = _spawn_sidecar(args.sidecar_bin, args.izba_bin, jdir, ws_port)
            try:
                if not _wait_port(ws_port):
                    # A dead sidecar means the journey measured NOTHING — record
                    # a flipping infra candidate so the bundle can't read as a
                    # silently-empty positive (mirrors the CLI runner's honesty).
                    log(f"{jid}: sidecar did not come up on :{ws_port}; skipping")
                    results.append({"journey_id": jid, "actions": [],
                                    "candidates": [_infra_candidate(
                                        jid, f"sidecar did not come up on "
                                             f":{ws_port}")]})
                    continue
                driver = AgentBrowserDriver(args.agent_browser_bin,
                                            http_port=http_port, ws_port=ws_port,
                                            timeout_s=args.action_timeout_s)
                driver.open(f"http://127.0.0.1:{http_port}/?ws={ws_port}")
                res = run_gui_journey(
                    model, driver, journey, izba_bin=args.izba_bin, data_dir=jdir,
                    max_turns=args.max_turns, step_cap=args.step_cap,
                    action_timeout_s=args.action_timeout_s,
                    latency_budget_ms=args.latency_budget_ms,
                    budget=budget, max_usd=args.max_usd, artifact_dir=args.artifact_dir,
                    create_settle_s=args.create_settle_s,
                    expect_state_settle_s=args.expect_state_settle_s,
                    workspace=workspace,
                    app_ready_timeout_s=args.app_ready_timeout_s)
                driver.close()
                results.append(res)
            except BudgetExceeded:
                log("budget exhausted; stopping"); break
            except Exception as e:  # report-only, but never silently green
                log(f"journey {jid!r} crashed: {e!r}")
                results.append({"journey_id": jid, "actions": [],
                                "candidates": [_infra_candidate(
                                    jid, f"journey crashed: {e!r}")]})
            finally:
                sidecar.terminate()
                try:
                    sidecar.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sidecar.kill()
    finally:
        httpd.shutdown()

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    # Same catastrophic-infra backstop as the CLI runner: when more than half
    # the attempted journeys are degraded, the run measured nothing and must
    # not read as a green void. Zero attempted journeys is NOT catastrophic
    # (an all-CLI corpus sharded to a GUI runner measures nothing by design).
    # The bundle is written first so a catastrophic run's trajectories stay
    # inspectable.
    degraded = count_degraded(results)
    catastrophic = (bool(results)
                    and degraded / len(results) > CATASTROPHIC_DEGRADED_FRACTION)
    log(f"wrote {args.out}: {len(results)} journeys ({degraded} degraded), "
        f"est. ${budget['usd']:.4f}")
    if catastrophic:
        log(f"CATASTROPHIC: {degraded}/{len(results)} gui journeys degraded "
            f"(> {CATASTROPHIC_DEGRADED_FRACTION:.0%}) — the run measured "
            f"nothing; failing the job (exit {EXIT_CATASTROPHIC_INFRA})")
        return EXIT_CATASTROPHIC_INFRA
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
