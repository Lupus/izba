"""Deterministic oracle harness for the izba dogfood Phase-2 runner.

No LLM, no network. Runs one ``izba`` command, captures the result, snapshots
``izba __reconcile --json`` after it, and applies the always-on oracles:

- ``implicit_oracle``  — scrape stdout/stderr for panic/assert/ERROR markers and
  decode the izba exit-code contract (127 -> CommandNotFound, 128+n -> Signal n).
- ``latency_oracle``   — flag actions over a human-normal time budget.
- ``functional_oracle`` — compare an action's exit against the step's expectation,
  *understanding expected-failure steps*: a refusal-expecting step that exits
  non-zero is the PASS (not a candidate), and one that exits 0 is a candidate (a
  guard that should have fired silently did not).
- ``reconcile_seq_oracle`` — *sequence* invariants the single-shot Rust
  reconciler cannot see: monotonic restart identity + legal status transitions.

Everything here is pure/stdlib so it is unit-testable anywhere (see
``test_oracles.py``). The Action/Candidate dataclasses mirror
``schema/trajectory.schema.json``.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Keep tails small enough to upload cheaply but large enough to carry a panic
# backtrace head: last 4 KB of each stream.
TAIL_BYTES = 4096


@dataclass
class Action:
    """One concrete command the Actor ran, plus the post-action reconcile snapshot."""

    intent: str
    command: str
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    latency_ms: int
    reconcile: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Candidate:
    """A possible-bug finding emitted by an oracle. Matches trajectory.schema.json."""

    kind: str  # functional | latency | implicit | reconcile_seq
    detail: str
    violated_expectation: str = ""
    source: str = ""
    trajectory_ref: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _tail(text: str, limit: int = TAIL_BYTES) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_action(
    izba_bin: str,
    argv: List[str],
    data_dir: str,
    timeout_s: float,
    intent: str = "",
    env: Optional[Dict[str, str]] = None,
) -> Action:
    """Run one ``izba`` command, then snapshot ``izba __reconcile --json``.

    Report-only: a timeout or any OS error is captured into the Action (exit_code
    set to a non-zero sentinel); this never raises.
    """
    import os

    run_env = dict(os.environ)
    run_env["IZBA_DATA_DIR"] = data_dir
    if env:
        run_env.update(env)

    # shlex.join preserves argument boundaries in the trajectory (e.g. an arg
    # with a space round-trips as one token, not several).
    command = "izba " + shlex.join(argv)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [izba_bin, *argv],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=run_env,
        )
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        exit_code = 124  # GNU timeout convention; non-zero so oracles flag it
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = ((e.stderr or "") if isinstance(e.stderr, str) else "") + \
            f"\n[harness] action timed out after {timeout_s}s"
    except OSError as e:
        exit_code = 125
        stdout = ""
        stderr = f"[harness] failed to spawn {izba_bin!r}: {e}"
    latency_ms = int((time.monotonic() - start) * 1000)

    reconcile = _snapshot_reconcile(izba_bin, data_dir, timeout_s, run_env)

    return Action(
        intent=intent,
        command=command,
        exit_code=exit_code,
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
        latency_ms=latency_ms,
        reconcile=reconcile,
    )


def _snapshot_reconcile(
    izba_bin: str, data_dir: str, timeout_s: float, env: Dict[str, str]
) -> Dict[str, Any]:
    """Best-effort ``izba __reconcile --json``. Report-only: errors -> empty snapshot."""
    import json

    try:
        proc = subprocess.run(
            [izba_bin, "__reconcile", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return {"violations": [], "sandboxes": []}


# --- Implicit oracle ---------------------------------------------------------

# panic / assert / anchored ERROR|FATAL / rust panic / sanitizer markers.
_IMPLICIT_RE = re.compile(
    # \bpanic\b so benign substrings ("no panic occurred") don't fire; the other
    # arms are already anchored (^ERROR/^FATAL line-start, the panicked phrase).
    r"\bpanic\b|assertion failed|^ERROR|^FATAL|thread '.*' panicked|AddressSanitizer",
    re.MULTILINE,
)


def implicit_oracle(action: Action) -> List[Candidate]:
    """Scrape output for crash markers; decode the izba exit-code contract."""
    out: List[Candidate] = []
    ref = {"journey_id": "", "action_index": -1}

    for stream_name, text in (("stderr", action.stderr_tail),
                              ("stdout", action.stdout_tail)):
        m = _IMPLICIT_RE.search(text)
        if m:
            out.append(Candidate(
                kind="implicit",
                detail=f"crash marker {m.group(0)!r} in {stream_name} of {action.command!r}",
                violated_expectation="izba must not panic/abort on a user command",
                source="contract: clean exit, no panics",
                trajectory_ref=dict(ref),
            ))

    code = action.exit_code
    if code == 127:
        out.append(Candidate(
            kind="implicit",
            detail=f"exit 127 (CommandNotFound) from {action.command!r}",
            violated_expectation="guest command should be found (exit != 127)",
            source="contract: exec exit-code mapping",
            trajectory_ref=dict(ref),
        ))
    elif code > 128:
        out.append(Candidate(
            kind="implicit",
            detail=f"exit {code} = Signal({code - 128}) from {action.command!r}",
            violated_expectation="command should not die from a signal",
            source="contract: exec exit-code mapping (128+n)",
            trajectory_ref=dict(ref),
        ))
    return out


# --- Functional oracle -------------------------------------------------------

# Phrases in a step's `expect` that mean the COMMAND ITSELF should fail (be
# refused/rejected), so a non-zero exit is the success case — not a divergence.
# Kept deliberately narrow (no bare "error", which appears in success expects
# like "succeeds with no error") so we don't misclassify an expect-success step.
_EXPECT_FAILURE_RE = re.compile(
    r"\brefus(?:e|es|ed|al)\b"
    r"|\breject(?:s|ed)?\b"
    r"|\bdenied\b|\bdeny\b"
    r"|non-?zero exit"
    r"|\bmust not\b|\bshould not\b"
    r"|\bnot allowed\b|\bnot permitted\b"
    r"|\billegal\b",
    re.IGNORECASE,
)


def expects_failure(expect: str) -> bool:
    """True if a step's expectation describes the command being refused/rejected,
    so a non-zero exit is the intended outcome rather than a candidate finding."""
    return bool(_EXPECT_FAILURE_RE.search(expect or ""))


def functional_oracle(
    command: str,
    exit_code: int,
    expect: str,
    source: str = "journey step",
    ref: Optional[Dict[str, Any]] = None,
) -> List[Candidate]:
    """Compare a command's exit against the step's expectation (two-sided).

    - expect describes SUCCESS but the command exited non-zero -> candidate.
    - expect describes a REFUSAL/REJECTION but the command exited 0 -> candidate
      (a guard that should have fired silently did not — a real-bug class the
      naive 'any non-zero exit' check could never see).
    - expect describes a REFUSAL and the command exited non-zero -> PASS. This is
      what kills the bulk of the false positives the old check produced on
      grammar-rejection / in-use-guard journeys (whose whole point is a refusal).
    """
    if not expect:
        return []
    ref = dict(ref or {"journey_id": "", "action_index": -1})
    if expects_failure(expect):
        if exit_code == 0:
            return [Candidate(
                kind="functional",
                detail=(f"command {command!r} unexpectedly succeeded (exit 0) "
                        f"while the step expected a refusal: {expect!r}"),
                violated_expectation=expect,
                source=source,
                trajectory_ref=ref,
            )]
        return []
    if exit_code != 0:
        return [Candidate(
            kind="functional",
            detail=(f"command {command!r} exited {exit_code} "
                    f"while step expected: {expect!r}"),
            violated_expectation=expect,
            source=source,
            trajectory_ref=ref,
        )]
    return []


# --- Latency oracle ----------------------------------------------------------


def latency_oracle(action: Action, budget_ms: int) -> List[Candidate]:
    """Flag actions slower than a human would tolerate for their class."""
    if action.latency_ms > budget_ms:
        return [Candidate(
            kind="latency",
            detail=f"{action.command!r} took {action.latency_ms} ms (budget {budget_ms} ms)",
            violated_expectation=f"action completes within {budget_ms} ms",
            source="latency budget (human-normal)",
            trajectory_ref={"journey_id": "", "action_index": -1},
        )]
    return []


# --- Reconcile sequence oracle ----------------------------------------------


def _by_name(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {s.get("name"): s for s in (snapshot or {}).get("sandboxes", []) or []}


def _alive(status: Optional[str]) -> bool:
    # Anything that is not stopped/removed/absent counts as alive.
    return status not in (None, "stopped", "removed")


def reconcile_seq_oracle(
    prev_snapshot: Dict[str, Any], cur_snapshot: Dict[str, Any]
) -> List[Candidate]:
    """Sequence invariants across two reconcile snapshots (prev -> cur).

    These are the invariants a single-shot reconciler structurally cannot see:

    - **monotonic restart identity:** if a sandbox goes stopped -> alive and its
      vmm pid is reused, its starttime MUST change (a real new process). Same
      pid + same starttime across a restart means a stale identity was trusted.
    - **legal transition:** a sandbox must not jump ``removed -> running`` (a
      removed sandbox cannot come back without a fresh create — which would
      reset its vmm identity; we approximate "fresh create" as an unchanged
      identity being illegal here).
    """
    out: List[Candidate] = []
    prev = _by_name(prev_snapshot)
    cur = _by_name(cur_snapshot)

    for name, cur_s in cur.items():
        prev_s = prev.get(name)
        if prev_s is None:
            continue
        prev_status = prev_s.get("status_disk") or prev_s.get("status_daemon")
        cur_status = cur_s.get("status_disk") or cur_s.get("status_daemon")
        prev_daemon = prev_s.get("status_daemon")

        prev_alive = _alive(prev_status)
        cur_alive = _alive(cur_status)

        prev_vmm = prev_s.get("vmm") or {}
        cur_vmm = cur_s.get("vmm") or {}

        # monotonic restart identity
        if (not prev_alive) and cur_alive and prev_vmm and cur_vmm:
            same_pid = prev_vmm.get("pid") == cur_vmm.get("pid")
            same_start = prev_vmm.get("starttime") == cur_vmm.get("starttime")
            if same_pid and same_start:
                out.append(Candidate(
                    kind="reconcile_seq",
                    detail=(f"sandbox {name!r} went {prev_status!r}->{cur_status!r} "
                            f"but reused pid {cur_vmm.get('pid')} with unchanged "
                            f"starttime {cur_vmm.get('starttime')}"),
                    violated_expectation="a restart must produce a new vmm starttime",
                    source="contract: pid+starttime liveness identity",
                    trajectory_ref={"journey_id": name, "action_index": -1},
                ))

        # legal transition: removed -> running
        if prev_daemon == "removed" and _alive(cur_s.get("status_daemon")):
            out.append(Candidate(
                kind="reconcile_seq",
                detail=(f"sandbox {name!r} transitioned removed->"
                        f"{cur_s.get('status_daemon')!r} without an intervening create"),
                violated_expectation="a removed sandbox must not become running again",
                source="contract: disk-state lifecycle",
                trajectory_ref={"journey_id": name, "action_index": -1},
            ))
    return out
