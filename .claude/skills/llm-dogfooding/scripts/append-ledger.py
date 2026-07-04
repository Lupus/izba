#!/usr/bin/env python3
"""append-ledger.py — append one run's signal/noise tallies to the ledger.

Usage:
  append-ledger.py --collected collected.json [--verdict skeptic-verdict.json]
                   --feature <name> --tier <smoke|core|deep>
                   [--ledger hack/dogfood/ledger.jsonl]

One JSON line per dogfood run (Phase-4 step in the skill). The ledger is how
"iterate until signal/noise stabilizes" becomes measurable across runs:
candidate counts, precision (kept vs refuted), and depth (positives vs
unreached) over time. Report-only utility; never mutates existing lines."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--collected", required=True,
                    help="collect-trajectories.py --json output")
    ap.add_argument("--verdict", default=None,
                    help="optional skeptic-verdict.json (schema/skeptic-verdict.schema.json)")
    ap.add_argument("--feature", required=True)
    ap.add_argument("--tier", required=True)
    ap.add_argument("--ledger", default="hack/dogfood/ledger.jsonl")
    args = ap.parse_args(argv)

    with open(args.collected) as f:
        totals = json.load(f).get("totals", {})
    entry = {
        "date": datetime.date.today().isoformat(),
        "feature": args.feature,
        "tier": args.tier,
        "totals": totals,
    }
    if args.verdict:
        with open(args.verdict) as f:
            entry["skeptic"] = json.load(f).get("counts", {})
    os.makedirs(os.path.dirname(os.path.abspath(args.ledger)), exist_ok=True)
    with open(args.ledger, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    print(f"appended {args.feature}/{args.tier} to {args.ledger}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
