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
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from model import FakeModel, OpenRouterModel  # noqa: E402
from oracles import (  # noqa: E402
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


def _argv_from_command(command: str) -> List[str]:
    """Turn a model command string into argv for izba, dropping a leading 'izba'."""
    import shlex

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if parts and parts[0] == "izba":
        parts = parts[1:]
    return parts


class BudgetExceeded(Exception):
    """Raised internally to unwind to the writer when --max-usd is hit."""


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
    prev_reconcile: Optional[Dict[str, Any]] = None
    turns = 0

    steps = journey.get("steps", []) or [{"intent": journey.get("rationale", ""),
                                          "expect": ""}]

    for step in steps:
        expect = step.get("expect", "")
        # Loop-dedup is scoped PER STEP: it stops the Actor repeating the same
        # command within a step's turn loop, without killing a later step that
        # legitimately re-issues a common verify command (e.g. `izba ls`).
        seen: set = set()
        # Inner Actor loop for this step.
        while True:
            if len(actions) >= step_cap:
                log(f"{journey_id}: step-cap {step_cap} reached; stopping journey")
                return {"journey_id": journey_id, "actions": actions,
                        "candidates": candidates}
            if turns >= max_turns:
                log(f"{journey_id}: max-turns {max_turns} reached; stopping journey")
                return {"journey_id": journey_id, "actions": actions,
                        "candidates": candidates}
            if budget["usd"] >= max_usd:
                log(f"{journey_id}: budget ${budget['usd']:.4f} >= ${max_usd}; aborting")
                raise BudgetExceeded()

            turns += 1
            try:
                reply = model.next_command(journey, step, actions)
                budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
            except Exception as e:  # report-only: model failure ends the step
                log(f"{journey_id}: model error: {e!r}; ending step")
                break

            if not isinstance(reply, dict) or reply.get("done"):
                break
            command = reply.get("command")
            if not isinstance(command, str) or not command.strip():
                break

            h = _cmd_hash(journey_id, command)
            if h in seen:
                log(f"{journey_id}: loop-dedup hit on {command!r}; ending step")
                break
            seen.add(h)

            # Run the action (report-only; run_action never raises).
            try:
                action = run_action(
                    izba_bin, _argv_from_command(command), data_dir,
                    action_timeout_s, intent=step.get("intent", ""),
                )
            except Exception as e:  # defensive: should not happen
                log(f"{journey_id}: run_action error: {e!r}; skipping")
                break

            action_index = len(actions)
            adict = action.to_dict()
            actions.append(adict)

            # Deterministic oracles.
            new_candidates = []
            new_candidates += implicit_oracle(action)
            new_candidates += latency_oracle(action, latency_budget_ms)
            if prev_reconcile is not None:
                new_candidates += reconcile_seq_oracle(prev_reconcile, action.reconcile)
            prev_reconcile = action.reconcile

            # Stamp the trajectory_ref + functional expectation onto each candidate.
            for c in new_candidates:
                cd = c.to_dict()
                cd["trajectory_ref"] = {"journey_id": journey_id,
                                        "action_index": action_index}
                candidates.append(cd)

            # Functional oracle (cheap, deterministic proxy): a non-zero exit on
            # a step that expects success is a divergence from the expectation.
            if action.exit_code != 0 and expect:
                candidates.append({
                    "kind": "functional",
                    "detail": (f"command {command!r} exited {action.exit_code} "
                               f"while step expected: {expect!r}"),
                    "violated_expectation": expect,
                    "source": journey.get("source", {}).get("ref", "journey step"),
                    "trajectory_ref": {"journey_id": journey_id,
                                       "action_index": action_index},
                })

    return {"journey_id": journey_id, "actions": actions, "candidates": candidates}


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
    return OpenRouterModel(api_key, args.model)


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
    return p.parse_args(argv)


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
        try:
            res = run_journey(
                model, journey, args.izba_bin, args.data_dir,
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
            log(f"journey {journey.get('journey_id')!r} crashed: {e!r}; continuing")
            results.append({"journey_id": journey.get("journey_id", ""),
                            "actions": [], "candidates": []})

    bundle = {"shard": args.shard, "feature": feature, "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
    log(f"wrote {args.out}: {len(results)} journeys, "
        f"est. cost ${budget['usd']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
