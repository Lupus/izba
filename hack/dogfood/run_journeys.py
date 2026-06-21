#!/usr/bin/env python3
"""izba dogfood Phase-2 runner: the Actor loop + caps + trajectory writer.

Loads ``journeys.json``, selects this shard's journeys (``i % shards == shard``),
and runs each journey step-by-step. For each step the Actor model proposes a
concrete ``izba`` command; the harness runs it (``oracles.run_action``), snapshots
the reconciler, applies the deterministic oracles, and asks the model for the
next command — until the step is done or a cap trips.

**Report-only.** Any infra/subprocess error is logged and the loop continues; the
runner never raises out of the loop and always writes a trajectory bundle that
matches ``schema/trajectory.schema.json``. Exit code is 0 regardless of findings;
only a totally unrecoverable startup error (bad args / unreadable journeys file)
exits non-zero.

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
    capture_state_evidence,
    functional_oracle,
    implicit_oracle,
    latency_oracle,
    reconcile_seq_oracle,
    run_action,
)

# Default per-action human-normal latency budget. Sandbox lifecycle ops (boot,
# image pull) are slow, so this is generous; the per-action hard timeout is the
# real backstop. Tunable via --latency-budget-ms.
DEFAULT_LATENCY_BUDGET_MS = 30_000


def log(msg: str) -> None:
    print(f"[dogfood] {msg}", file=sys.stderr, flush=True)


def select_shard(journeys: List[Dict[str, Any]], shard: int,
                 shards: int) -> List[Dict[str, Any]]:
    """Stable modulo sharding: journey i goes to shard ``i % shards``."""
    if shards <= 1:
        return list(journeys)
    return [j for i, j in enumerate(journeys) if i % shards == shard]


def _cmd_hash(journey_id: str, command: str) -> str:
    return hashlib.sha256(f"{journey_id}\0{command}".encode("utf-8")).hexdigest()



# A clap "Commands:" / "SUBCOMMANDS:" section header (nothing after the colon).
_CMD_SECTION_RE = re.compile(r"^(commands|subcommands):\s*$", re.IGNORECASE)
# An indented command entry: leading space then the command token.
_CMD_ENTRY_RE = re.compile(r"^\s+([a-z][a-z0-9_-]*)\b")


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


def _collect_candidates(action, command, action_index, prev_reconcile,
                        latency_budget_ms, journey, step, journey_id):
    """All oracles for one action -> a list of candidate dicts (with refs)."""
    ref = {"journey_id": journey_id, "action_index": action_index}
    found = implicit_oracle(action) + latency_oracle(action, latency_budget_ms)
    if prev_reconcile is not None:
        found += reconcile_seq_oracle(prev_reconcile, action.reconcile)
    # Functional oracle understands expected-failure steps (a refusal that
    # exits non-zero is the PASS; a refusal that exits 0 is a candidate).
    source = journey.get("source", {}).get("ref", "journey step")
    found += functional_oracle(command, action.exit_code, step.get("expect", ""),
                               source, ref)
    out = []
    for c in found:
        cd = c.to_dict()
        cd["trajectory_ref"] = ref
        out.append(cd)
    return out


def _next_command(model, journey, step, actions, budget, journey_id):
    """One model turn -> a command string, or None to end the step."""
    try:
        reply = model.next_command(journey, step, actions)
        budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
    except Exception as e:  # report-only: model failure ends the step
        log(f"{journey_id}: model error: {e!r}; ending step")
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
              journey_id, actions, candidates, ctx) -> bool:
    """Run one step's Actor loop. Mutates ``actions``/``candidates``/``ctx``.
    Returns True if a journey-level cap (step-cap/max-turns) tripped (caller
    should stop the whole journey). Raises BudgetExceeded on the $ cap.

    Loop-dedup (``seen``) is scoped PER STEP so a later step can legitimately
    re-issue a common verify command (e.g. ``izba ls``)."""
    seen: set = set()
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
        command = _next_command(model, journey, step, actions, budget, journey_id)
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
                                intent=step.get("intent", ""))
        except Exception as e:  # defensive: should not happen
            log(f"{journey_id}: run_action error: {e!r}; skipping")
            return False

        action_index = len(actions)
        actions.append(action.to_dict())
        candidates.extend(_collect_candidates(
            action, command, action_index, ctx["prev_reconcile"],
            latency_budget_ms, journey, step, journey_id))
        ctx["prev_reconcile"] = action.reconcile


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
    ctx: Dict[str, Any] = {"turns": 0, "prev_reconcile": None}
    # The Actor's shell cwd — a real project dir, kept OUT of the izba data dir
    # so the user's files (e.g. a policy.yaml they write) don't mingle with
    # izba's internal sandbox state. izba run/cp share this as /workspace.
    workdir = os.path.join(data_dir, "proj")
    os.makedirs(workdir, exist_ok=True)
    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]
    for step in steps:
        stop = _run_step(
            model, journey, step, izba_bin, data_dir, workdir,
            action_timeout_s=action_timeout_s, latency_budget_ms=latency_budget_ms,
            budget=budget, max_usd=max_usd, max_turns=max_turns, step_cap=step_cap,
            journey_id=journey_id, actions=actions, candidates=candidates, ctx=ctx)
        if stop:
            break
    # State-based oracle: snapshot izba's OWN audit/policy/lifecycle state so the
    # rubric judge grades the outcome from ground truth, not guest exit codes.
    try:
        state_evidence = capture_state_evidence(izba_bin, data_dir, action_timeout_s)
    except Exception as e:  # report-only: never let evidence capture fail a run
        log(f"{journey_id}: state-evidence capture error: {e!r}")
        state_evidence = {"sandboxes": [], "reconcile": {}, "per_sandbox": {}}
    return {"journey_id": journey_id, "actions": actions, "candidates": candidates,
            "state_evidence": state_evidence}


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
    p.add_argument("--model", default="deepseek/deepseek-chat",
                   help="OpenRouter model id (ignored with --fake-model)")
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
    mine = select_shard(all_journeys, args.shard, args.shards)
    log(f"shard {args.shard}/{args.shards}: {len(mine)} of {len(all_journeys)} journeys")

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
            results.append({"journey_id": jid, "actions": [], "candidates": []})

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    log(f"wrote {args.out}: {len(results)} journeys, "
        f"est. cost ${budget['usd']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
