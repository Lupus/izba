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

import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Keep tails small enough to upload cheaply but large enough to carry a panic
# backtrace head: last 4 KB of each stream.
TAIL_BYTES = 4096
# Same idea for the guest serial console: enough to carry a panic/backtrace
# head, small enough to upload cheaply.
CONSOLE_TAIL_BYTES = 8192


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

    kind: str  # functional | masked_probe | latency | implicit | reconcile_seq
              # | reconcile_violation | guest_console (and runner-emitted: infra | unreached_decisive)
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


def _shell_env(izba_bin: str, data_dir: str,
               env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Environment for the Actor's shell: izba on PATH + this journey's data dir.

    The Actor is a real user at a terminal, so its commands run through ``bash``
    with ``izba`` resolvable on ``PATH`` (not a hard-coded binary path). Each
    journey gets its own ``IZBA_DATA_DIR`` so state can't leak between journeys.
    """
    import os

    run_env = dict(os.environ)
    run_env["IZBA_DATA_DIR"] = data_dir
    bindir = os.path.dirname(os.path.abspath(izba_bin))
    run_env["PATH"] = bindir + os.pathsep + run_env.get("PATH", "")
    if env:
        run_env.update(env)
    return run_env


def _read_cwd_file(cwd_file: str) -> str:
    """Return the saved cwd from ``cwd_file`` (stripped), or '' if absent/empty.

    Report-only: any read error just yields '' so the caller falls back to
    ``workdir`` — a missing cwd file is the normal first-action state, never an
    error.
    """
    try:
        with open(cwd_file, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _console_tails(data_dir: str, limit_per_sandbox: int = 2048) -> str:
    """Guest console.log tails for every sandbox under ``data_dir`` — evidence
    appended to a TIMED-OUT action's stderr so a stalled `izba start` is
    diagnosable post-hoc (H6: two 120s stalls in the 2026-07-09 run were
    environmental but undiagnosable). Capped per sandbox, and placed BEFORE
    the ``[harness] action timed out`` marker in the assembled stderr, so the
    4 KiB ``stderr_tail`` truncation (which keeps the LAST bytes) can never
    cut the marker away even with multiple sandboxes. Report-only: '' on any
    error."""
    import glob
    chunks: List[str] = []
    try:
        for path in sorted(glob.glob(os.path.join(
                data_dir, "sandboxes", "*", "logs", "console.log"))):
            name = os.path.basename(os.path.dirname(os.path.dirname(path)))
            try:
                with open(path, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - limit_per_sandbox))
                    tail = f.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            chunks.append(f"\n[harness] console.log tail ({name}):\n{tail}")
    except Exception:
        return ""
    return "".join(chunks)


def run_action(
    command: str,
    *,
    izba_bin: str,
    workdir: str,
    data_dir: str,
    timeout_s: float,
    intent: str = "",
    env: Optional[Dict[str, str]] = None,
    cwd_file: Optional[str] = None,
) -> Action:
    """Run ONE Actor command as a real shell line, then snapshot reconcile.

    The command is whatever the Actor (a user at a terminal) chose — an ``izba``
    invocation, a file-creating heredoc, a ``curl``, an ``izba exec … -- sh -c
    '…'`` — run via ``bash -c`` with ``cwd=workdir`` and ``izba`` on ``PATH``.
    This is the faithful "real user with a shell" model: the Actor can write
    files and compose pipelines, not just call one binary.

    ``cwd_file`` — when given, cwd PERSISTS across actions like a real shell: the
    command starts from the dir saved in ``cwd_file`` (falling back to ``workdir``
    when the file is absent/empty), and the resulting ``$PWD`` is written back for
    the next action. So ``mkdir X && cd X`` in one action and a command inside
    ``X`` in the next now behave as one shell session. When ``cwd_file`` is
    ``None`` (the default, and every existing caller/test) behavior is unchanged:
    each action starts fresh in ``workdir``. The command's own exit code is always
    preserved (``__rc``); the cwd write-back is best-effort.

    Report-only: a timeout or any OS error is captured into the Action (exit_code
    set to a non-zero sentinel); this never raises.
    """
    run_env = _shell_env(izba_bin, data_dir, env)

    to_run = command
    if cwd_file is not None:
        # Start from the saved cwd (or workdir if unseeded/empty), run the Actor's
        # command in a brace group so ITS exit code is what we preserve, then
        # persist $PWD for the next action. `cd workdir` stays as the subprocess
        # base so a failed START `cd` still lands somewhere sane. shlex.quote all
        # three interpolated paths so odd chars can't break out of the wrapper.
        # The brace group is terminated by a NEWLINE, not a `;`: a `;` right after
        # the command turns a valid trailing `&` (background job) into `&;` — a
        # bash syntax error — and lets a trailing `# comment` swallow the closing
        # `}`. A newline terminates the command cleanly in both cases.
        start_dir = _read_cwd_file(cwd_file) or workdir
        to_run = (
            f"cd {shlex.quote(start_dir)} 2>/dev/null || cd {shlex.quote(workdir)}; "
            f"{{ {command}\n}}; __rc=$?; "
            f"printf '%s' \"$PWD\" > {shlex.quote(cwd_file)}; exit $__rc"
        )

    start = time.monotonic()
    try:
        proc = subprocess.run(
            ["bash", "-c", to_run],
            cwd=workdir,
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
            _console_tails(data_dir) + \
            f"\n[harness] action timed out after {timeout_s}s"
    except OSError as e:
        exit_code = 125
        stdout = ""
        stderr = f"[harness] failed to run command via bash: {e}"
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
    """Best-effort ``izba __reconcile --json``.

    Report-only, but honest: a FAILED snapshot returns an ``error`` key so a
    broken reconciler is distinguishable from a clean one (previously both
    yielded the same empty shape, hiding a dead oracle)."""
    import json

    err = "unknown"
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
        err = f"exit {proc.returncode}: {(proc.stderr or '')[-200:]}"
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        err = repr(e)
    return {"error": err, "violations": [], "sandboxes": []}


def _izba_capture(izba_bin: str, argv: List[str],
                  timeout_s: float, env: Dict[str, str]) -> Dict[str, Any]:
    """Run a read-only `izba` command directly (no shell) and capture its text.

    Used for state evidence — we invoke izba ourselves (not through the Actor) so
    the snapshot is trustworthy. Report-only: errors become an `error` result
    rather than raising."""
    try:
        proc = subprocess.run(
            [izba_bin, *argv], capture_output=True, text=True,
            timeout=timeout_s, env=env,
        )
        return {"argv": argv, "exit_code": proc.returncode,
                "stdout": _tail(proc.stdout or ""), "stderr": _tail(proc.stderr or "")}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"argv": argv, "exit_code": 124, "stdout": "", "stderr": f"[harness] {e}"}


def _read_persisted_ports(data_dir: str, name: str) -> Optional[List[Any]]:
    """The sandbox's PERSISTED port-publish rules: config.json's ``ports``
    array (izba-core ``state.rs`` SandboxConfig — what `izba port publish
    --persist` / the app's Make-persistent button writes; re-applied on every
    start). `izba port ls` shows only the ACTIVE relay rules and renders
    identically for an ephemeral and a persisted forward, so this host-side
    config read is the only machine-checkable persist ground truth (the GUI
    ports-make-persistent gap, D-GUI-7). ``None`` = the file is
    unreadable/absent or ill-shaped — a ``persistent`` port assertion must
    then grade ``no_evidence``, never fabricate. Report-only."""
    import json
    try:
        with open(os.path.join(data_dir, "sandboxes", name, "config.json"),
                  encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    ports = cfg.get("ports") if isinstance(cfg, dict) else None
    return ports if isinstance(ports, list) else None


def capture_state_evidence(
    izba_bin: str, data_dir: str, timeout_s: float,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Snapshot the product's OWN authoritative state after a journey, for the
    Phase-3 trajectory-skeptic to grade outcomes against (the τ-bench "end-state" oracle).

    For an egress-firewall run the ground truth is izba's own observability — NOT
    a guest command's exit code. Per sandbox the journey created we capture
    ``izba policy show`` (effective allow-list + enforce posture) and
    ``izba netlog --summary`` (what the firewall actually allowed/denied), plus
    the lifecycle ``__reconcile`` snapshot. The top-level ``volume_ls`` capture
    (``izba volume ls``: name/size/usage + the USED-BY referencing sandboxes)
    is the daemon-truth surface behind the GUI ``expect_state.volume``
    assertion — the reconcile snapshot itself carries NO volume list (only
    informational orphan_volume violations for UNreferenced volumes), so
    attach/detach outcomes are only observable here. Per sandbox, the paired
    port-forward truth (behind the GUI ``expect_state.port`` assertion):
    ``port_ls`` (`izba port ls <name>` — the ACTIVE forwards) and
    ``ports_persisted`` (the config.json ``ports`` rules — the persist
    ground truth `port ls` cannot express; see ``_read_persisted_ports``).
    Report-only."""
    run_env = _shell_env(izba_bin, data_dir, env)
    reconcile = _snapshot_reconcile(izba_bin, data_dir, timeout_s, run_env)
    volume_ls = _izba_capture(izba_bin, ["volume", "ls"], timeout_s, run_env)
    names = [s.get("name") for s in (reconcile.get("sandboxes") or [])
             if s.get("name")]
    per_sandbox: Dict[str, Any] = {}
    for name in names:
        console_tail = ""
        try:
            console_path = os.path.join(data_dir, "sandboxes", name,
                                        "logs", "console.log")
            with open(console_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - CONSOLE_TAIL_BYTES))
                console_tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            pass  # absent console.log is the normal never-booted state
        per_sandbox[name] = {
            "policy_show": _izba_capture(izba_bin, ["policy", "show", name],
                                         timeout_s, run_env),
            "netlog": _izba_capture(izba_bin, ["netlog", name, "--summary"],
                                    timeout_s, run_env),
            "port_ls": _izba_capture(izba_bin, ["port", "ls", name],
                                     timeout_s, run_env),
            "ports_persisted": _read_persisted_ports(data_dir, name),
            "console_tail": console_tail,
        }
    return {"sandboxes": names, "reconcile": reconcile,
            "per_sandbox": per_sandbox, "volume_ls": volume_ls}


# --- Implicit oracle ---------------------------------------------------------

# panic / assert / anchored ERROR|FATAL / rust panic / sanitizer markers.
_IMPLICIT_RE = re.compile(
    # \bpanic\b so benign substrings ("no panic occurred") don't fire; the other
    # arms are already anchored (^ERROR/^FATAL line-start, the panicked phrase).
    r"\bpanic\b|assertion failed|^ERROR|^FATAL|thread '.*' panicked|AddressSanitizer",
    re.MULTILINE,
)


def implicit_oracle(action: Action, *, expect_nonzero: bool = False) -> List[Candidate]:
    """Scrape output for crash markers; decode the izba exit-code contract.

    Crash MARKERS scraped from output (panic, assertion, anchored ERROR/FATAL,
    sanitizer) always flag — they are never anticipated. The exit-code DECODE
    branch (127 -> CommandNotFound, 255 -> transport failure, 128+n -> Signal n)
    is expectation-aware: when ``expect_nonzero`` is set the step itself declared a
    non-zero/decoded exit (via ``expect_exit`` or refusal phrasing), so those codes
    are the anticipated outcome and no candidate is emitted — this is what stops a
    journey like ``exec-exit-code-contract`` (whose whole point is to observe 127
    and 128+n) from self-flipping."""
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

    # A step that anticipated a non-zero/decoded exit turns these decodes into the
    # expected result, not a crash symptom — so skip the exit-code-decode branch.
    if expect_nonzero:
        return out

    code = action.exit_code
    if code == 127:
        out.append(Candidate(
            kind="implicit",
            detail=f"exit 127 (CommandNotFound) from {action.command!r}",
            violated_expectation="guest command should be found (exit != 127)",
            source="contract: exec exit-code mapping",
            trajectory_ref=dict(ref),
        ))
    elif code == 255:
        # 255 = 128+127 can NEVER be a real signal (max signal is ~64), so the
        # generic 128+n arm below would mislabel it Signal(127). It is the
        # conventional ssh/scp/sftp exit for a transport/connection failure
        # (auth/handshake/network), so classify it as that instead — and name
        # the tool when the command is one of that family.
        tool = ""
        first = (action.command or "").strip().split()
        if first and os.path.basename(first[0]) in ("ssh", "scp", "sftp"):
            tool = f" ({os.path.basename(first[0])})"
        out.append(Candidate(
            kind="implicit",
            detail=(f"exit 255 (SSH/scp transport or connection failure) from "
                    f"{action.command!r}{tool}"),
            violated_expectation="ssh/scp transport should connect (exit != 255)",
            source="contract: ssh/scp transport exit convention",
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


def guest_console_oracle(state_evidence: Dict[str, Any],
                         ref: Dict[str, Any]) -> List[Candidate]:
    """Scan each sandbox's guest serial-console tail for crash markers.

    The guest console is the documented always-captured boot truth
    (logs/console.log), yet no oracle read it — a guest-side panic that never
    surfaced in CLI stderr was invisible. Same marker regex as the implicit
    oracle; one candidate per affected sandbox."""
    out: List[Candidate] = []
    for name, ev in (state_evidence.get("per_sandbox") or {}).items():
        tail = ev.get("console_tail") or ""
        m = _IMPLICIT_RE.search(tail)
        if m:
            out.append(Candidate(
                kind="guest_console",
                detail=(f"crash marker {m.group(0)!r} in guest console of "
                        f"sandbox {name!r}"),
                violated_expectation="guest must not panic/abort (console.log)",
                source="contract: clean guest boot/run, no panics",
                trajectory_ref=dict(ref),
            ))
    return out


def teardown_journey(izba_bin: str, data_dir: str, timeout_s: float,
                     names: List[str]) -> None:
    """Best-effort per-journey cleanup: remove this journey's sandboxes and stop
    its (data-dir-scoped) daemon so leftover VMs don't skew later journeys'
    latency/boot behavior on the shard. Hygiene, not an oracle: failures are
    logged to stderr and swallowed — teardown must never fail a journey."""
    run_env = _shell_env(izba_bin, data_dir)
    for argv in [["rm", n, "--force"] for n in names] + [["daemon", "stop"]]:
        try:
            subprocess.run([izba_bin, *argv], capture_output=True, text=True,
                           timeout=timeout_s, env=run_env)
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[dogfood] teardown {argv}: {e!r}", file=sys.stderr)


# --- Functional oracle -------------------------------------------------------

# Phrases in a step's `expect` that mean the COMMAND ITSELF should fail (be
# refused/rejected), so a non-zero exit is the success case — not a divergence.
# Kept deliberately narrow (no bare "error", which appears in success expects
# like "succeeds with no error") so we don't misclassify an expect-success step.
#
# NOTE (loop-2 redesign): this keyword oracle is intentionally NOT extended to
# adjudicate egress outcomes ("is host X blocked?"). Inferring a firewall verdict
# from a guest command's exit code is a known-weak oracle — exit 6 from `nc`/curl
# means DNS-resolution failure, not necessarily a policy block, producing both
# false positives and false negatives (see references/methodology.md, "state vs
# exit-code oracles"). Egress outcomes are judged from the product's own audit
# state (`izba netlog` / `policy show`) captured as state evidence, then graded by
# the Phase-3 skeptic — not here.
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


def step_expects_nonzero(expect: str = "", expect_exit: Any = None) -> bool:
    """True if a step's own expectation anticipates a non-zero/decoded exit.

    Used to make ``implicit_oracle``'s exit-code decode (127 / 255 / 128+n)
    expectation-aware: on a step that DECLARED a non-zero outcome those codes are
    the anticipated result, not a crash symptom. DECLARATIVE ONLY:
    ``expect_exit == "nonzero"`` or a non-zero integer means non-zero;
    ``expect_exit == 0`` still means success is expected. Unlike
    ``functional_oracle`` this deliberately does NOT fall back to the
    ``expects_failure`` phrasing inference — broad prose ("the daemon should not
    corrupt state") must never suppress the implicit decode of a real signal
    crash (Greptile P1 on PR #137); a journey that anticipates non-zero exits
    declares ``expect_exit`` explicitly.
    ``bool`` is excluded (``expect_exit: true`` is not a meaningful exit code)."""
    if expect_exit == "nonzero":
        return True
    if isinstance(expect_exit, int) and not isinstance(expect_exit, bool):
        return expect_exit != 0
    return False


# A trailing `|| <trivial-cmd>` short-circuit whose fallback arm is itself a
# trivially-succeeding command (echo/printf/true/:). The compound's overall exit
# status is then 0 even when the real probe on the left failed, so exit 0 cannot
# corroborate an expected-success step. Deliberately narrow (word-boundaried,
# no arbitrary-shell parsing) so it only fires on the unambiguous masking shape —
# and only when the trivial fallback is the FINAL clause: a `|| echo`
# mid-command (`check || echo warn; verify`) does not own the compound's exit,
# so it must not fire (Greptile P1 on PR #137).
_TRIVIAL_FALLBACK_RE = re.compile(
    r"\|\|\s*(?:(?:echo|printf)\b[^;|&]*|true\b\s*|:\s*)[\"']?\s*$"
)


def masks_success_with_trivial_fallback(command: str) -> bool:
    """True if ``command`` ends a ``||`` short-circuit with a trivially-succeeding
    fallback (echo/printf/true/:), so its overall exit 0 can hide a failed probe.

    A conservative heuristic, NOT a shell parser: it recognizes only the
    ``<probe> || <trivial>`` masking shape that silently turns a failed
    persistence/existence check into a false green (izba#78:
    ``test -f /data/hello.txt || echo "file does not exist"`` always exits 0)."""
    return bool(_TRIVIAL_FALLBACK_RE.search(command or ""))


# A trailing ``; echo $?`` (and close variants) appended to a graded command:
# the ``echo`` always exits 0, so the compound's exit status no longer reflects
# the probe on its left. Anchored at end-of-command (allowing trailing whitespace
# and quoting around ``$?``); no shell parsing — only the unambiguous trailing
# ``echo $?`` shape fires. The leading ``;`` is required so a bare ``echo $?``
# whole-command (which merely PRINTS the status without owning a probe) is left
# alone, as is any ``$?`` used mid-command.
_ECHO_STATUS_TAIL_RE = re.compile(r";\s*echo\s+[\"']?\$\?[\"']?\s*$")


def masks_exit_status_with_echo(command: str) -> bool:
    """True if ``command`` ends in a trailing ``; echo $?`` (and close variants
    ``;echo $?`` / ``; echo "$?"``), which RESETS the compound's exit status to
    the echo's own 0 — the graded exit then no longer reflects the probe.

    Unlike the ``|| <trivial>`` fallback (which only masks a FAILURE), this masks
    symmetrically: it corrupts both expected-success grading (false green) and
    expected-failure grading (a correctly-failed probe reads as exit 0, i.e. a
    false divergence). izba's ``run-rm-throwaway-propagates-exit`` was falsely
    flipped by exactly this: ``izba run --rm -- sh -c 'exit 42'; echo $?`` exits
    0 even though izba propagated 42 correctly (the ``42`` on stdout proves it)."""
    return bool(_ECHO_STATUS_TAIL_RE.search(command or ""))


def functional_oracle(
    command: str,
    exit_code: int,
    expect: str,
    source: str = "journey step",
    ref: Optional[Dict[str, Any]] = None,
    *,
    expect_exit: Any = None,
) -> List[Candidate]:
    """Compare a command's exit against the step's expectation (two-sided).

    - expect describes SUCCESS but the command exited non-zero -> candidate.
    - expect describes a REFUSAL/REJECTION but the command exited 0 -> candidate
      (a guard that should have fired silently did not — a real-bug class the
      naive 'any non-zero exit' check could never see).
    - expect describes a REFUSAL and the command exited non-zero -> PASS. This is
      what kills the bulk of the false positives the old check produced on
      grammar-rejection / in-use-guard journeys (whose whole point is a refusal).

    When ``expect_exit`` is supplied and valid it DRIVES the verdict, superseding
    the English-keyword ``expect`` heuristic entirely (the declarative escape
    hatch #111 asked for — a step can now assert an expected failure instead of
    hoping the phrasing trips ``_EXPECT_FAILURE_RE``):

    - ``"nonzero"`` -> candidate iff the command exited 0 (an expected refusal
      that silently succeeded).
    - integer ``N`` -> candidate iff the command exited != N (the assertion is a
      specific code, e.g. `izba ssh NAME -- false` must exit 1).

    An absent/invalid ``expect_exit`` falls back to the ``expect`` path unchanged.

    This is a deliberately WEAK proposer, not an outcome verdict: an exit code is
    a poor oracle for "did the user's goal happen" (a command can exit 0 without
    achieving it, or non-zero via a valid alternative path). Egress/UX outcomes
    are judged from product state by the Phase-3 skeptic; this only catches the gross
    "expected success, hard error" / "expected refusal, silent success" cases.
    """
    ref = dict(ref or {"journey_id": "", "action_index": -1})
    # A trailing `; echo $?` RESETS the compound's exit status to the echo's own
    # 0, so the graded exit no longer reflects the probe. Unlike the `|| <trivial>`
    # fallback (which only masks failure, handled in the expected-success path
    # below), this corrupts BOTH expected-success grading (false green) and
    # expected-failure grading (a correctly-failed probe reads as exit 0 -> false
    # divergence). Flag it symmetrically, before any exit-status verdict is drawn,
    # whenever a verdict WOULD be drawn (some `expect`/`expect_exit` grading applies).
    _grading = (
        expect_exit == "nonzero"
        or (isinstance(expect_exit, int) and not isinstance(expect_exit, bool))
        or bool(expect)
    )
    if _grading and masks_exit_status_with_echo(command):
        return [Candidate(
            kind="masked_probe",
            detail=(f"command {command!r} ends in a trailing '; echo $?' which "
                    f"resets the compound's exit status to 0 — the graded exit no "
                    f"longer reflects the probe, so its verdict is unverifiable"),
            violated_expectation=(
                expect or (f"expect_exit: {expect_exit}"
                           if expect_exit is not None else "")),
            source=source,
            trajectory_ref=ref,
        )]
    # Declarative assertion takes precedence over the fragile keyword heuristic.
    # `bool` is a subclass of `int`, so exclude it explicitly — `expect_exit:
    # true` is not a meaningful exit code and must not be read as `1`.
    if expect_exit == "nonzero":
        if exit_code == 0:
            return [Candidate(
                kind="functional",
                detail=(f"command {command!r} unexpectedly succeeded (exit 0) "
                        f"while the step declared expect_exit=nonzero"),
                violated_expectation=expect or "expect_exit: nonzero",
                source=source,
                trajectory_ref=ref,
            )]
        return []
    if isinstance(expect_exit, int) and not isinstance(expect_exit, bool):
        if exit_code != expect_exit:
            return [Candidate(
                kind="functional",
                detail=(f"command {command!r} exited {exit_code} "
                        f"while the step declared expect_exit={expect_exit}"),
                violated_expectation=expect or f"expect_exit: {expect_exit}",
                source=source,
                trajectory_ref=ref,
            )]
        return []
    # No (valid) declarative assertion -> the legacy English-keyword path.
    if not expect:
        return []
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
    # Expected-success path. Before crediting exit 0 as corroborating success,
    # reject an exit status that a trailing `|| <trivial>` fallback has masked:
    # the compound exits 0 regardless of whether the probe passed, so this is an
    # UNVERIFIABLE success, not a pass (izba#78 false green). Only fires on
    # expected-success steps — an expected-failure step is handled above, so a
    # legit `cmd || true` there is never flipped.
    if exit_code == 0 and masks_success_with_trivial_fallback(command):
        return [Candidate(
            kind="masked_probe",
            detail=(f"command {command!r} exited 0 but a trailing '|| <trivial>' "
                    f"fallback masks the probe's real exit status — its success "
                    f"is unverifiable, not corroborated"),
            violated_expectation=expect,
            source=source,
            trajectory_ref=ref,
        )]
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
    # An errored snapshot carries no state; comparing against it would fabricate
    # transitions. Skip (the runner separately flags an all-errored journey).
    if (prev_snapshot or {}).get("error") or (cur_snapshot or {}).get("error"):
        return []

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
