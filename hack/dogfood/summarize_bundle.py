#!/usr/bin/env python3
"""Render a one-bundle markdown summary for $GITHUB_STEP_SUMMARY.

Usage: summarize_bundle.py <traj.json> [...more bundles]

Mirrors the collector's flipping rule (soft = latency + non-decisive
functional; everything else flips) so the CI job summary and the Phase-3
tally agree. Pure stdlib; report-only (a malformed bundle prints a warning
row instead of failing the step)."""
from __future__ import annotations

import json
import sys


def _flips(c: dict) -> bool:
    kind = c.get("kind", "?")
    if kind == "latency":
        return False
    if kind == "functional":
        return bool(c.get("decisive"))
    return True


def summarize(paths: list[str]) -> str:
    rows = []
    tot = {"j": 0, "pos": 0, "flip": 0, "infra": 0, "unreached": 0, "soft": 0}
    for path in paths:
        try:
            with open(path) as f:
                bundle = json.load(f)
        except (OSError, ValueError) as e:
            rows.append(f"| `{path}` | ⚠ unreadable: {e} |")
            continue
        for r in bundle.get("results", []):
            tot["j"] += 1
            cands = r.get("candidates", []) or []
            kinds = [c.get("kind") for c in cands]
            n_flip = sum(1 for c in cands if _flips(c))
            tot["soft"] += len(cands) - n_flip
            verdict = "✅ positive"
            if "infra" in kinds:
                tot["infra"] += 1
                verdict = "🔌 infra"
            elif "unreached_decisive" in kinds:
                tot["unreached"] += 1
                verdict = "❓ unreached"
            elif n_flip:
                # Count flipping candidates in the header ONLY for journeys
                # whose verdict is ❌ flipped — an infra/unreached journey's
                # candidates would otherwise inflate the flipping column and
                # contradict the per-row verdicts below.
                tot["flip"] += n_flip
                verdict = "❌ flipped"
            else:
                tot["pos"] += 1
            rows.append(f"| `{r.get('journey_id')}` | {verdict} | "
                        f"{len(r.get('actions') or [])} actions | "
                        f"{n_flip} flipping / {len(cands) - n_flip} soft |")
    head = ("| journeys | positive | flipping | infra | unreached | soft |\n"
            "|---|---|---|---|---|---|\n"
            f"| {tot['j']} | {tot['pos']} | {tot['flip']} | {tot['infra']} "
            f"| {tot['unreached']} | {tot['soft']} |\n")
    return head + "\n| journey | verdict | depth | candidates |\n|---|---|---|---|\n" \
        + "\n".join(rows) + "\n"


def main(argv=None) -> int:
    args = (argv if argv is not None else sys.argv[1:])
    if not args:
        print("usage: summarize_bundle.py <traj.json>...", file=sys.stderr)
        return 2
    print(summarize(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
