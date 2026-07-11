#!/usr/bin/env python3
"""izba dogfood Phase-2 runner: the Actor loop + caps + trajectory writer.

Loads ``journeys.json``, selects this shard's journeys (``i % shards == shard``),
and runs each journey step-by-step. For each step the Actor model proposes a
concrete ``izba`` command; the harness runs it (``oracles.run_action``), snapshots
the reconciler, applies the deterministic oracles, and asks the model for the
next command — until the step is done or a cap trips.

**Report-only, with one honesty backstop.** Any infra/subprocess error is logged
and the loop continues; the runner never raises out of the loop and always
writes a trajectory bundle that matches ``schema/trajectory.schema.json``. Exit
code is 0 regardless of findings, non-zero for a totally unrecoverable startup
error (bad args / unreadable journeys file), and **3** when more than
``CATASTROPHIC_DEGRADED_FRACTION`` (50%) of attempted journeys were
infra-degraded (zero actions, or a model/API failure) — a dead API key or a
broken transport must not silently produce an all-green run.

**Hard caps (all mandatory):**
- ``--max-turns``      — model calls per journey.
- ``--step-cap``       — actions (commands run) per journey.
- ``--max-usd``        — cumulative estimated USD for the whole run; abort when hit.
- ``--action-timeout-s`` — per-action subprocess timeout.
- loop-dedup           — a ``set`` of ``(journey_id, command)`` hashes; a repeat
                         short-circuits the journey to "done".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from model import FakeModel, OpenRouterModel  # noqa: E402
from oracles import (  # noqa: E402
    Candidate,
    capture_state_evidence,
    functional_oracle,
    guest_console_oracle,
    implicit_oracle,
    latency_oracle,
    reconcile_seq_oracle,
    run_action,
    teardown_journey,
)

# Default per-action human-normal latency budget. Sandbox lifecycle ops (boot,
# image pull) are slow, so this is generous; the per-action hard timeout is the
# real backstop. Tunable via --latency-budget-ms.
DEFAULT_LATENCY_BUDGET_MS = 30_000

# Catastrophic-infra threshold: if MORE than this fraction of attempted
# journeys are degraded (zero actions, or >=1 `infra` candidate), the run
# was not a measurement — exit 3 so the CI job fails per the "only infra
# failures fail a job" contract. At or below the threshold stays report-only
# (a transient model blip must not kill a 40-minute shard).
CATASTROPHIC_DEGRADED_FRACTION = 0.5
EXIT_CATASTROPHIC_INFRA = 3


def count_degraded(results: List[Dict[str, Any]]) -> int:
    """Journeys that measured nothing: zero actions, or >=1 infra candidate."""
    return sum(
        1 for r in results
        if not r.get("actions")
        or any(c.get("kind") == "infra" for c in r.get("candidates", []))
    )


def _infra_candidate(journey_id: str, detail: str) -> Dict[str, Any]:
    """A flipping `infra` candidate: the harness/model plumbing failed, so the
    journey verified nothing (and must not tally positive)."""
    return {
        "kind": "infra",
        "detail": detail,
        "violated_expectation": "model/API must produce a next command",
        "source": "harness: model transport",
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


def log(msg: str) -> None:
    print(f"[dogfood] {msg}", file=sys.stderr, flush=True)


def select_shard(journeys: List[Dict[str, Any]], shard: int,
                 shards: int) -> List[Dict[str, Any]]:
    """Stable modulo sharding: journey i goes to shard ``i % shards``."""
    if shards <= 1:
        return list(journeys)
    return [j for i, j in enumerate(journeys) if i % shards == shard]


def select_cli_journeys(journeys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CLI-modality journeys only — the mirror of the GUI runner's
    select_gui_journeys. A CLI shard must never run a modality:"gui" journey
    as if it were CLI (the model would type shell commands at a GUI intent)."""
    return [j for j in journeys if j.get("modality") != "gui"]


def _cmd_hash(journey_id: str, command: str) -> str:
    return hashlib.sha256(f"{journey_id}\0{command}".encode("utf-8")).hexdigest()



# A clap "Commands:" / "SUBCOMMANDS:" section header (nothing after the colon).
_CMD_SECTION_RE = re.compile(r"^(commands|subcommands):\s*$", re.IGNORECASE)
# An indented command entry: leading space then the command token.
_CMD_ENTRY_RE = re.compile(r"^\s+([a-z][a-z0-9_-]*)\b")

# H1: the default functional-grading target is the step's last PRODUCT
# invocation — a shell line that runs the izba binary (word-boundary; possibly
# after env assignments / `cd x && ` / pipes). "izba.yml" does NOT match (the
# dot fails the trailing \s|$), so file-writing heredocs stay plumbing.
_PRODUCT_CMD_RE = re.compile(r"(?:^|[\s;|&(])izba(?:\s|$)")

# Crediting an UNREACHED decisive step (H3) demands a stricter bar than
# per-step grading: the matched action must be an actual product invocation —
# `izba` in COMMAND POSITION (start of a shell segment: begin / && / || / ; /
# | / subshell, optionally after env assignments) — so a broad-but-valid
# expect_cmd_re can never credit prose like `echo izba` or a filename match.
_CREDIT_CMD_RE = re.compile(
    r"(?:^|&&|\|\||;|\||\()\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*izba\s")


def _collect_cmd_name(line: str, names: List[str]) -> None:
    """Append the command token on an indented clap entry line (skip ``help``/dups)."""
    m = _CMD_ENTRY_RE.match(line)
    if m and m.group(1) != "help" and m.group(1) not in names:
        names.append(m.group(1))


def _parse_subcommands(help_text: str) -> List[str]:
    """Extract subcommand names from a clap ``Commands:`` block in ``--help`` text.

    Returns names in declaration order, skipping the built-in ``help`` pseudo-
    command and de-duplicating. Best-effort: unknown help layouts yield ``[]``.

    The branches are mutually exclusive: a ``Commands:`` header opens the block,
    any other non-indented line (``Options:``, ``Usage: ...``) closes it, and
    indented lines while open are command entries (blank lines tolerated)."""
    names: List[str] = []
    in_cmds = False
    for line in help_text.splitlines():
        # Match the raw line (the regex is ^-anchored): a section header is a
        # non-indented "Commands:"/"SUBCOMMANDS:" line, consistent with the
        # non-indented invariant the other branches rely on.
        if _CMD_SECTION_RE.match(line):
            in_cmds = True
        elif line and not line[0].isspace():
            in_cmds = False
        elif in_cmds:
            _collect_cmd_name(line, names)
    return names


def _run_help_once(izba_bin: str, path_args: List[str], timeout_s: float,
                   deadline: float) -> Optional[str]:
    """``izba <path_args> --help`` -> stripped text, or None. Bounded by ``deadline``.

    Report-only: any spawn/timeout error returns None rather than raising."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        p = subprocess.run([izba_bin, *path_args, "--help"], capture_output=True,
                           text=True, timeout=min(timeout_s, remaining))
    except (OSError, subprocess.SubprocessError):
        return None
    text = ((p.stdout or "") + (p.stderr or "")).strip()
    return text or None


def gather_cli_help(izba_bin: str, timeout_s: float = 8.0,
                    total_timeout_s: float = 20.0) -> str:
    """Best-effort CLI help to seed the Actor so it uses real commands instead of
    guessing (start/init/list/...).

    Discovers subcommands from ``izba --help`` and recurses **one level** into
    nested command namespaces (e.g. ``volume`` -> ``volume ls/attach/...``) so the
    Actor sees real verbs and their signatures — the M3-volumes run missed
    ``izba volume attach`` precisely because only a hardcoded top-level set was
    seeded. Report-only: returns '' if top-level help is unavailable; bounded by
    an aggregate ``total_timeout_s`` so a hanging binary can't stall startup."""
    deadline = time.monotonic() + total_timeout_s
    top = _run_help_once(izba_bin, [], timeout_s, deadline)
    if not top:
        return ""
    chunks: List[str] = [f"$ izba --help\n{top}"]
    for cmd in _parse_subcommands(top):
        sub = _run_help_once(izba_bin, [cmd], timeout_s, deadline)
        if not sub:
            continue
        chunks.append(f"$ izba {cmd} --help\n{sub}")
        for nested in _parse_subcommands(sub):
            leaf = _run_help_once(izba_bin, [cmd, nested], timeout_s, deadline)
            if leaf:
                chunks.append(f"$ izba {cmd} {nested} --help\n{leaf}")
    return "\n\n".join(chunks)


_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _journey_data_dir(base: str, journey_id: str) -> str:
    """Per-journey IZBA_DATA_DIR so one journey's leftover state can't contaminate
    the next (e.g. a stray sandbox breaking a 'clean data dir' journey).

    The segment is sanitized AND suffixed with a short hash of the original id:
    stripping leading/trailing dots prevents ``..`` escaping ``base`` (path
    traversal), and the hash keeps ids that sanitize identically (e.g.
    ``"a b"`` vs ``"a-b"``) in distinct dirs rather than silently sharing state.

    The readable prefix is capped so the per-journey component stays short: the
    sandbox runtime socket (``<dir>/sandboxes/<name>/run/vsock.sock_1027``) must
    fit the ~108-byte AF_UNIX ``sun_path`` limit, and a long journey id otherwise
    pushes it over (see izba#71)."""
    journey_id = journey_id or ""  # tolerate None/empty
    safe = (_SAFE_RE.sub("-", journey_id).strip(".-") or "journey")[:16]
    short = hashlib.sha256(journey_id.encode("utf-8")).hexdigest()[:8]
    return os.path.join(base, f"{safe}-{short}")


class BudgetExceeded(Exception):
    """Raised internally to unwind to the writer when --max-usd is hit."""


def _flipping_violations(violations: List[Any]) -> List[Any]:
    """Drop the product's self-labeled `informational:` reconcile items (e.g. an
    unreferenced named volume after rm — intended behavior, reconcile.rs prefixes
    the detail). Informational items stay visible in state_evidence; only the
    rest may flip a journey (H2)."""
    out = []
    for v in violations:
        detail = v.get("detail", "") if isinstance(v, dict) else str(v)
        if not str(detail).startswith("informational:"):
            out.append(v)
    return out


def _collect_candidates(action, command, action_index, prev_reconcile,
                        latency_budget_ms, journey, step, journey_id):
    """Per-ACTION oracles -> a list of candidate dicts (with refs).

    ``implicit`` (crash markers / exit-code contract), ``latency``, and
    ``reconcile_seq`` fire on EVERY action — a panic or a signal-death anywhere in
    the journey is a finding regardless of which step it happened in. The
    ``functional`` oracle is deliberately NOT here: it is graded once per step, on
    the step's intent-bearing action (``expect_cmd_re``-selected, else the last
    izba-invoking action, else the final action), by ``_grade_step_functional`` —
    so an intermediate recovery action inside an otherwise-passing step no longer
    emits a spurious functional candidate (the #111 setup-noise false-negative)."""
    ref = {"journey_id": journey_id, "action_index": action_index}
    found = implicit_oracle(action) + latency_oracle(action, latency_budget_ms)
    if prev_reconcile is not None:
        found += reconcile_seq_oracle(prev_reconcile, action.reconcile)
    violations = _flipping_violations(
        (action.reconcile or {}).get("violations") or [])
    if violations:
        import json as _json
        found = list(found)
        preview = _json.dumps(violations[:3])[:400]
        found.append(Candidate(
            kind="reconcile_violation",
            detail=(f"izba __reconcile reported {len(violations)} violation(s) "
                    f"after {command!r}: {preview}"),
            violated_expectation="reconciler must report no violations "
                                 "(declared state == reality)",
            source="contract: disk-state invariant (__reconcile)",
        ))
    out = []
    for c in found:
        cd = c.to_dict()
        cd["trajectory_ref"] = ref
        out.append(cd)
    return out


def _decisive_step_indices(steps: List[Dict[str, Any]]) -> set:
    """The indices of a journey's DECISIVE steps.

    Decisive = every step marked ``core: true``; or, if none is marked, just the
    LAST step (the "grade the decisive (last/core) step" rule). An empty step list
    yields an empty set."""
    core = {i for i, s in enumerate(steps) if s.get("core")}
    if core:
        return core
    return {len(steps) - 1} if steps else set()


def _grade_step_functional(step, produced, journey, journey_id, decisive,
                           action_index) -> List[Dict[str, Any]]:
    """Grade the functional assertion ONCE per step, on its intent-bearing action.

    Default target is the step's last action that INVOKES the izba binary
    (falling back to the final action when none does); ``expect_cmd_re`` overrides.
    When the step declares ``expect_cmd_re`` (a regex), the target is the LAST
    action whose command matches — so a trailing verify (`izba ls`) after a correct
    refusal no longer false-fires. Invalid regexes log + fall back to the final
    action. Every candidate records ``graded_cmd`` so the skeptic sees WHAT was
    graded."""
    if not produced:
        return []
    target = produced[-1]
    target_index = action_index
    pattern = step.get("expect_cmd_re")
    if isinstance(pattern, str) and pattern:
        try:
            rx = re.compile(pattern)
            for off, a in enumerate(reversed(produced)):
                if rx.search(a.get("command", "")):
                    target = a
                    target_index = action_index - off
                    break
        except re.error as e:
            log(f"{journey_id}: invalid expect_cmd_re {pattern!r}: {e}; "
                f"grading the final action")
    else:
        # H1: without expect_cmd_re, prefer the last action that invokes the
        # product over trailing shell plumbing (seed-write heredocs, `ls`
        # peeks). Nothing izba-shaped -> the final action, as before.
        for off, a in enumerate(reversed(produced)):
            if _PRODUCT_CMD_RE.search(a.get("command", "")):
                target = a
                target_index = action_index - off
                break
    ref = {"journey_id": journey_id, "action_index": target_index}
    source = journey.get("source", {}).get("ref", "journey step")
    found = functional_oracle(
        target.get("command", ""), target.get("exit_code", 0),
        step.get("expect", ""), source, ref,
        expect_exit=step.get("expect_exit"))
    out = []
    for c in found:
        cd = c.to_dict()
        cd["trajectory_ref"] = ref
        cd["decisive"] = bool(decisive)
        cd["graded_cmd"] = target.get("command", "")
        out.append(cd)
    return out


def _next_command(model, journey, step, actions, budget, journey_id, starved):
    """One model turn -> a command string, or None to end the step.

    A model-layer failure ({"error": ...} reply, or an exception) is an INFRA
    finding, not a completion — but per-turn candidates drowned the bundle
    (H7), so failures are TALLIED into ``starved`` and the journey emits ONE
    coalesced `infra` candidate at the end (run_journey)."""
    try:
        reply = model.next_command(journey, step, actions)
        budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
    except Exception as e:  # report-only, but never silently green
        log(f"{journey_id}: model error: {e!r}; ending step")
        starved.append(f"model raised: {e!r}")
        return None
    if isinstance(reply, dict) and reply.get("error"):
        log(f"{journey_id}: model infra error: {reply['error']}; ending step")
        starved.append(str(reply["error"]))
        return None
    if not isinstance(reply, dict) or reply.get("done"):
        return None
    command = reply.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    return command


def _run_step(model, journey, step, izba_bin, data_dir, workdir, *,
              action_timeout_s,
              latency_budget_ms, budget, max_usd, max_turns, step_cap,
              journey_id, actions, candidates, ctx, decisive, cwd_file) -> bool:
    """Run one step's Actor loop. Mutates ``actions``/``candidates``/``ctx``.
    Returns True if a journey-level cap (step-cap/max-turns) tripped (caller
    should stop the whole journey). Raises BudgetExceeded on the $ cap.

    Loop-dedup (``seen``) is scoped PER STEP so a later step can legitimately
    re-issue a common verify command (e.g. ``izba ls``).

    The functional assertion is graded ONCE at step end, on the step's
    intent-bearing action (``expect_cmd_re``-selected, falling back to the final
    action ``actions[start:][-1]``): we snapshot ``start`` before the loop and
    grade what the step produced, tagging the candidate ``decisive`` per this
    step's role. Grading in a ``finally`` guarantees it also runs when a cap trips
    or a report-only error ends the step early.

    Step-level ``seed_files`` (mid-journey drift) is materialized into
    ``workdir`` here, immediately before the step's first action and after cwd
    setup (cwd already persists via ``cwd_file`` from the journey's start) —
    NOT inside the loop, so it lands exactly once per step regardless of how
    many turns/retries the step takes."""
    seen: set = set()
    start = len(actions)  # index of this step's first action; actions[start:] = its own
    _write_seeds(workdir, step.get("seed_files"))
    try:
        while True:
            if len(actions) >= step_cap:
                log(f"{journey_id}: step-cap {step_cap} reached; stopping journey")
                return True
            if ctx["turns"] >= max_turns:
                log(f"{journey_id}: max-turns {max_turns} reached; stopping journey")
                return True
            if budget["usd"] >= max_usd:
                log(f"{journey_id}: budget ${budget['usd']:.4f} >= ${max_usd}; aborting")
                raise BudgetExceeded()

            ctx["turns"] += 1
            command = _next_command(model, journey, step, actions, budget, journey_id,
                                    ctx["starved"])
            if command is None:
                return False
            h = _cmd_hash(journey_id, command)
            if h in seen:
                log(f"{journey_id}: loop-dedup hit on {command!r}; ending step")
                return False
            seen.add(h)

            try:  # report-only; run_action never raises in practice
                action = run_action(command, izba_bin=izba_bin, workdir=workdir,
                                    data_dir=data_dir, timeout_s=action_timeout_s,
                                    intent=step.get("intent", ""), cwd_file=cwd_file)
            except Exception as e:  # defensive: should not happen
                log(f"{journey_id}: run_action error: {e!r}; skipping")
                return False

            action_index = len(actions)
            actions.append(action.to_dict())
            candidates.extend(_collect_candidates(
                action, command, action_index, ctx["prev_reconcile"],
                latency_budget_ms, journey, step, journey_id))
            ctx["prev_reconcile"] = action.reconcile
    finally:
        # Grade the step's final action once, on EVERY exit path (done, dedup,
        # cap, run_action error) — except a BudgetExceeded unwind, which is
        # aborting the whole run mid-step, so a functional verdict on a
        # half-finished step would be misleading. sys.exc_info() tells us whether
        # we are leaving the block via that in-flight exception.
        if not isinstance(sys.exc_info()[1], BudgetExceeded):
            produced = actions[start:]
            candidates.extend(_grade_step_functional(
                step, produced, journey, journey_id, decisive,
                len(actions) - 1))


def _write_seeds(workdir: str, seed_files: Optional[Dict[str, Any]]) -> None:
    """Materialize a ``seed_files`` mapping (relpath -> content) into ``workdir``.

    A precondition-seeding primitive (Part E): each entry is written under
    ``workdir``, creating parent dirs. Shared by two callers: the journey-level
    ``seed_files`` (written once, before step 0) and the per-step ``seed_files``
    (written immediately before that step's first action — the mid-journey-drift
    primitive, e.g. editing ``izba.yml`` between steps to exercise the diff/promote
    reconciler). Both model an environment precondition, never the thing under
    test — see the schema field's description for the compiler rule. Traversal-
    guarded exactly like ``_journey_data_dir`` reasons about ``base`` — an
    agent-authored path must not escape the project dir:

    - reject a non-str / empty key, or a non-str content;
    - reject an absolute path or one whose ``normpath`` starts with ``..``
      (the cheap syntactic guard);
    - reject anything that, resolved, does not stay under ``workdir`` (the
      authoritative ``realpath``-prefix guard — catches symlink/edge escapes the
      syntactic check misses).

    Report-only: a rejected or failed entry is logged and skipped; this never
    raises (a seeding hiccup must not abort a journey — the journey just starts
    without that fixture, which the oracles will then observe honestly)."""
    if not isinstance(seed_files, dict):
        return
    # realpath the base once so the prefix comparison is against the resolved dir.
    base_real = os.path.realpath(workdir)
    for relpath, content in seed_files.items():
        if not isinstance(relpath, str) or not relpath.strip():
            log(f"seed_files: skipping non-str/empty key {relpath!r}")
            continue
        if not isinstance(content, str):
            log(f"seed_files: skipping {relpath!r}: content is not a string")
            continue
        norm = os.path.normpath(relpath)
        if os.path.isabs(norm) or norm == ".." or norm.startswith(".." + os.sep):
            log(f"seed_files: rejecting traversal/absolute path {relpath!r}")
            continue
        dest = os.path.join(workdir, norm)
        # Authoritative escape check: the resolved parent must stay under base.
        parent_real = os.path.realpath(os.path.dirname(dest))
        if parent_real != base_real and not parent_real.startswith(base_real + os.sep):
            log(f"seed_files: rejecting escaping path {relpath!r}")
            continue
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:  # report-only: a bad write must not kill the journey
            log(f"seed_files: failed to write {relpath!r}: {e!r}")


def _grade_decisive_from_observed(step, actions, journey, journey_id):
    """H3: a decisive step whose own pointer produced no actions may still have
    been exercised — the swarm often satisfies the assertion under an EARLIER
    step. When the step declares ``expect_cmd_re``, scan ALL journey actions for
    the LAST match and grade THAT action functionally. Returns None when the
    step has no usable ``expect_cmd_re`` or nothing matched (caller then flags
    ``unreached_decisive``); otherwise a dict with the graded candidates plus
    the crediting pointer (``action_index``/``graded_cmd``).

    A broad ``expect_cmd_re`` (e.g. a bare ``izba``) is not machine-decidable
    from breadth alone — legitimate patterns are broad too (``izba diff`` must
    match ``izba diff --name x``). So instead of trying to reject "too broad"
    patterns here, every credit is recorded verbatim by the caller into the
    journey's ``decisive_credits``: a decisive step credited from another
    step's action is a CLAIM the Phase-3 skeptic must be able to see and
    audit, including when the grade was a silent pass. Crediting DOES require
    the match to be an izba invocation in command position (``_CREDIT_CMD_RE``)
    — pattern breadth alone can no longer credit shell plumbing like
    ``echo izba`` or a filename mention."""
    pattern = step.get("expect_cmd_re")
    if not (isinstance(pattern, str) and pattern):
        return None
    try:
        rx = re.compile(pattern)
    except re.error as e:
        log(f"{journey_id}: invalid expect_cmd_re {pattern!r}: {e}")
        return None
    if rx.search(""):
        log(f"{journey_id}: expect_cmd_re {pattern!r} matches the empty string; "
            f"too broad to credit an unreached decisive step")
        return None
    for idx in range(len(actions) - 1, -1, -1):
        a = actions[idx]
        if not rx.search(a.get("command", "")):
            continue
        if not _CREDIT_CMD_RE.search(a.get("command", "")):
            continue
        ref = {"journey_id": journey_id, "action_index": idx}
        source = journey.get("source", {}).get("ref", "journey step")
        found = functional_oracle(
            a.get("command", ""), a.get("exit_code", 0),
            step.get("expect", ""), source, ref,
            expect_exit=step.get("expect_exit"))
        out = []
        for c in found:
            cd = c.to_dict()
            cd["trajectory_ref"] = ref
            cd["decisive"] = True
            cd["graded_cmd"] = a.get("command", "")
            out.append(cd)
        return {
            "step_index": None,  # caller fills the decisive step index
            "action_index": idx,
            "graded_cmd": a.get("command", ""),
            "candidates": out,
        }
    return None


def run_journey(
    model,
    journey: Dict[str, Any],
    izba_bin: str,
    data_dir: str,
    *,
    max_turns: int,
    step_cap: int,
    action_timeout_s: float,
    latency_budget_ms: int,
    budget: Dict[str, float],
    max_usd: float,
) -> Dict[str, Any]:
    """Run one journey under all caps. Returns a JourneyResult dict."""
    journey_id = journey.get("journey_id", "")
    actions: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    decisive_credits: List[Dict[str, Any]] = []
    ctx: Dict[str, Any] = {"turns": 0, "prev_reconcile": None, "starved": []}
    # The Actor's shell cwd — a real project dir, kept OUT of the izba data dir
    # so the user's files (e.g. a policy.yaml they write) don't mingle with
    # izba's internal sandbox state. izba run/cp share this as /workspace.
    workdir = os.path.join(data_dir, "proj")
    os.makedirs(workdir, exist_ok=True)
    # Materialize precondition files (Part E) into the workdir BEFORE any step, so
    # a deep journey can start at the feature's real surface (e.g. a valid izba.yml
    # already present) instead of burning its steps authoring the prerequisite.
    _write_seeds(workdir, journey.get("seed_files"))
    # One cwd file per journey so cwd persists across actions like a real shell
    # (Part D). NOT pre-created: run_action treats its absence as "start in
    # workdir", so the first action naturally begins there.
    cwd_file = os.path.join(data_dir, ".cwd")
    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]
    decisive_idx = _decisive_step_indices(steps)
    step_actions: Dict[int, int] = {}  # step index -> actions it produced
    for i, step in enumerate(steps):
        before = len(actions)
        stop = _run_step(
            model, journey, step, izba_bin, data_dir, workdir,
            action_timeout_s=action_timeout_s, latency_budget_ms=latency_budget_ms,
            budget=budget, max_usd=max_usd, max_turns=max_turns, step_cap=step_cap,
            journey_id=journey_id, actions=actions, candidates=candidates, ctx=ctx,
            decisive=(i in decisive_idx), cwd_file=cwd_file)
        step_actions[i] = len(actions) - before
        if stop:
            break
    # H7: coalesce model-starvation failures into ONE flipping infra candidate
    # (count_degraded semantics unchanged — any infra candidate degrades).
    if ctx["starved"]:
        candidates.append(_infra_candidate(
            journey_id,
            f"model starved: {len(ctx['starved'])} failed turn(s); "
            f"first: {ctx['starved'][0]}"))
    # #126: a decisive step the Actor never reached (or reached with zero
    # actions) verified NOTHING — emit a flipping candidate so the journey
    # can't tally positive on budget exhaustion before its core assertion.
    source = journey.get("source", {}).get("ref", "journey step")
    for i in sorted(decisive_idx):
        if step_actions.get(i, 0) == 0:
            s = steps[i]
            graded = _grade_decisive_from_observed(s, actions, journey, journey_id)
            if graded is not None:
                graded["step_index"] = i
                candidates.extend(graded.pop("candidates"))
                decisive_credits.append(graded)
                continue
            candidates.append({
                "kind": "unreached_decisive",
                "detail": (f"decisive step {i} ({s.get('intent', '')[:80]!r}) "
                           f"produced no actions — its assertion was never "
                           f"exercised"),
                "violated_expectation": s.get("expect", "")
                                        or "decisive step must be exercised",
                "source": source,
                "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
            })
    # A journey whose EVERY snapshot errored had no reconcile oracle at all.
    if actions and all((a.get("reconcile") or {}).get("error") for a in actions):
        candidates.append(_infra_candidate(
            journey_id, "reconciler unusable: every snapshot errored"))
    # State-based oracle: snapshot izba's OWN audit/policy/lifecycle state
    # so the Phase-3 skeptic grades the outcome from ground truth, not guest exit codes.
    try:
        state_evidence = capture_state_evidence(izba_bin, data_dir, action_timeout_s)
    except Exception as e:  # report-only: never let evidence capture fail a run
        log(f"{journey_id}: state-evidence capture error: {e!r}")
        state_evidence = {"sandboxes": [], "reconcile": {}, "per_sandbox": {}}
    for cd in guest_console_oracle(
            state_evidence, {"journey_id": journey_id, "action_index": -1}):
        d = cd.to_dict()
        candidates.append(d)
    # Hygiene: tear down this journey's sandboxes + daemon so shard N+5's
    # latency isn't skewed by N's leftover VMs. Best-effort by contract.
    try:
        teardown_journey(izba_bin, data_dir, action_timeout_s,
                         state_evidence.get("sandboxes") or [])
    except Exception as e:  # defensive: teardown_journey shouldn't raise
        log(f"{journey_id}: teardown error: {e!r}")
    return {"journey_id": journey_id, "actions": actions, "candidates": candidates,
            "state_evidence": state_evidence, "decisive_credits": decisive_credits}


def build_model(args) -> Any:
    if args.fake_model is not None:
        try:
            script = json.loads(args.fake_model)
        except ValueError as e:
            raise SystemExit(f"--fake-model is not valid JSON: {e}")
        if not isinstance(script, list):
            raise SystemExit("--fake-model must be a JSON array of replies")
        return FakeModel(script)

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("OPENROUTER_API_KEY is required for the real model "
                         "(or pass --fake-model for offline runs)")
    cli_help = gather_cli_help(args.izba_bin)
    if cli_help:
        log(f"seeded Actor with {len(cli_help)} chars of `izba --help`")
    else:
        log("WARNING: could not capture `izba --help`; Actor runs unseeded")
    readme = _read_optional(getattr(args, "readme", ""))
    if readme:
        log(f"seeded Actor with {len(readme)} chars of README ({args.readme})")
    context_pack = _read_optional(getattr(args, "context_pack", ""))
    if context_pack:
        log(f"seeded Actor with {len(context_pack)} chars of run context "
            f"({args.context_pack})")
    return OpenRouterModel(api_key, args.model, cli_help=cli_help,
                           readme=readme, context_pack=context_pack)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_journeys.py",
        description="izba dogfood Phase-2 journey-execution runner")
    p.add_argument("--journeys", required=True, help="path to journeys.json")
    p.add_argument("--shard", type=int, default=0)
    p.add_argument("--shards", type=int, default=1)
    p.add_argument("--izba-bin", required=True, help="path to the izba binary")
    p.add_argument("--data-dir", required=True, help="IZBA_DATA_DIR for this shard")
    p.add_argument("--out", required=True, help="trajectory bundle output path")
    p.add_argument("--model", default="google/gemini-2.5-flash",
                   help="OpenRouter model id (ignored with --fake-model); cheap "
                        "but tool-capable by default — deepseek-chat was too weak "
                        "to drive the shell-agent loop reliably")
    p.add_argument("--max-turns", type=int, default=12,
                   help="model calls per journey")
    p.add_argument("--max-usd", type=float, default=2.0,
                   help="cumulative estimated USD budget for the whole run")
    p.add_argument("--step-cap", type=int, default=25,
                   help="max actions (commands) per journey")
    p.add_argument("--action-timeout-s", type=float, default=120.0,
                   help="per-action subprocess timeout")
    p.add_argument("--latency-budget-ms", type=int,
                   default=DEFAULT_LATENCY_BUDGET_MS,
                   help="human-normal per-action latency budget for the oracle")
    p.add_argument("--fake-model", default=None,
                   help="JSON array of scripted replies; offline mode, no API key")
    p.add_argument("--readme", default="README.md",
                   help="product README to seed the Actor with (the docs a real "
                        "user reads); skipped if the file is absent")
    p.add_argument("--context-pack", default="dogfood-context.md",
                   help="run-specific shared notes for the Actor (guest "
                        "environment + harness conventions); skipped if absent")
    return p.parse_args(argv)


def _read_optional(path: str) -> str:
    """Read a seed file (README / context-pack), or '' if missing/unreadable.

    Report-only: a missing seed must never abort a run — it just means the Actor
    runs with a thinner surface (which is itself a fair-test condition)."""
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    with open(args.journeys) as f:
        doc = json.load(f)
    feature = doc.get("feature", "")
    all_journeys = doc.get("journeys", []) or []
    cli_journeys = select_cli_journeys(all_journeys)
    mine = select_shard(cli_journeys, args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} of {len(cli_journeys)} "
        f"cli journeys ({len(all_journeys) - len(cli_journeys)} gui excluded)")

    os.makedirs(args.data_dir, exist_ok=True)
    model = build_model(args)

    budget = {"usd": 0.0}
    results: List[Dict[str, Any]] = []
    for journey in mine:
        jid = journey.get("journey_id") or ""  # tolerate a JSON null id
        try:
            # Per-journey setup is INSIDE the report-only guard: each journey gets
            # its OWN data dir (own daemon + state) so leftover state can't
            # contaminate the next, and a setup failure (bad id, makedirs error)
            # is captured here rather than crashing the whole run.
            jdir = _journey_data_dir(args.data_dir, jid)
            os.makedirs(jdir, exist_ok=True)
            res = run_journey(
                model, journey, args.izba_bin, jdir,
                max_turns=args.max_turns, step_cap=args.step_cap,
                action_timeout_s=args.action_timeout_s,
                latency_budget_ms=args.latency_budget_ms,
                budget=budget, max_usd=args.max_usd,
            )
            results.append(res)
        except BudgetExceeded:
            log("global USD budget exhausted; stopping remaining journeys")
            break
        except Exception as e:  # report-only: never let one journey kill the run
            log(f"journey {jid!r} crashed: {e!r}; continuing")
            # Carry a flipping infra candidate so the crashed journey can't
            # read as positive in the collector/summary (the degraded tally
            # already counts it for the exit-3 decision; this keeps the
            # per-journey verdicts honest too — parity with the GUI runner).
            results.append({"journey_id": jid, "actions": [],
                            "candidates": [_infra_candidate(
                                jid, f"journey crashed: {e!r}")]})

    degraded = count_degraded(results)
    catastrophic = bool(results) and degraded / len(results) > CATASTROPHIC_DEGRADED_FRACTION

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    log(f"wrote {args.out}: {len(results)} journeys ({degraded} degraded), "
        f"est. cost ${budget['usd']:.4f}")

    try:
        import jsonschema  # optional: report-only validation
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "schema", "trajectory.schema.json")
        with open(schema_path) as f:
            jsonschema.validate(bundle, json.load(f))
    except ImportError:
        pass
    except Exception as e:
        log(f"WARNING: bundle does not validate against trajectory.schema.json: {e}")

    if catastrophic:
        log(f"CATASTROPHIC: {degraded}/{len(results)} journeys degraded "
            f"(> {CATASTROPHIC_DEGRADED_FRACTION:.0%}) — the run measured "
            f"nothing; failing the job (exit {EXIT_CATASTROPHIC_INFRA})")
        return EXIT_CATASTROPHIC_INFRA
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
