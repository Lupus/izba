#!/usr/bin/env python3
"""collect-trajectories.py — flatten downloaded dogfood trajectory bundles into
the skeptic's working set: NEGATIVE candidates (oracle-flagged), POSITIVE
journeys (no candidate — must be audited for cheating/unverified success), and a
signal/noise summary.

Usage: collect-trajectories.py <artifacts-dir> [--json out.json]

Bundles match hack/dogfood/schema/trajectory.schema.json:
  {shard, feature, results:[{journey_id, actions:[...], candidates:[...]}]}

The skeptic reads the JSON (or the stdout summary) alongside journeys.json and
the anchors. Positive journeys are listed precisely because a green trajectory is
a CLAIM, not a result — they need the Direction-B audit just as much as the reds.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys


def load_bundles(artifacts_dir: str) -> list[dict]:
    paths = sorted(glob.glob(os.path.join(artifacts_dir, "**", "traj-*.json"),
                             recursive=True))
    if not paths:
        sys.exit(f"no traj-*.json under {artifacts_dir!r}")
    out = []
    for p in paths:
        try:
            out.append((p, json.load(open(p))))
        except (OSError, ValueError) as e:
            print(f"WARN: skipping {p}: {e}", file=sys.stderr)
    return out


def _is_flipping(cand: dict) -> bool:
    """Does this candidate flip its journey NEGATIVE?

    Framed as the SOFT allow-list, so everything else fails LOUD (an unknown or
    future candidate kind flips rather than being silently dropped from the tally
    — the collector must never quietly lose a real finding). Exactly two classes
    are soft:

    - a ``latency`` candidate — an over-budget action is a UX finding, never the
      pass/fail of the user's goal;
    - a NON-decisive ``functional`` candidate — setup/recovery noise, i.e. a
      non-zero exit in a step that is not the journey's core / fallback-last step.

    Everything else flips: ``implicit`` (crash/panic/exit-contract) and
    ``reconcile_seq`` (lifecycle invariant) — a crash anywhere is always real; a
    ``decisive`` ``functional`` — the assertion that governs the user's goal; and
    any GUI kind (``console``/``ui_daemon_diff``/``silent_failure``/``dom_expect``)
    should this collector ever ingest GUI bundles. This is the #111 fix: setup
    noise no longer masks a satisfied core assertion, WITHOUT downgrading anything
    we don't explicitly recognize as soft."""
    kind = cand.get("kind", "?")
    if kind == "latency":
        return False
    if kind == "functional":
        return bool(cand.get("decisive"))
    return True


def collect(artifacts_dir: str) -> dict:
    negatives, soft, positives = [], [], []
    by_kind = collections.Counter()
    n_journeys = 0
    for path, bundle in load_bundles(artifacts_dir):
        shard = bundle.get("shard")
        for r in bundle.get("results", []):
            n_journeys += 1
            jid = r.get("journey_id")
            acts = r.get("actions", []) or []
            cands = r.get("candidates", []) or []
            ref = {"shard": shard, "journey_id": jid, "bundle": path}
            n_flipping = 0
            for c in cands:
                by_kind[c.get("kind", "?")] += 1  # by_kind counts ALL candidates
                row = {**ref, **{k: c.get(k) for k in
                       ("kind", "detail", "violated_expectation", "source")}}
                if _is_flipping(c):
                    n_flipping += 1
                    negatives.append(row)
                else:
                    # Carry `decisive` so the skeptic can see it was a graded-but-
                    # non-decisive functional finding (vs a latency one).
                    row["decisive"] = c.get("decisive")
                    soft.append(row)
            # Final exit + a compact trajectory the skeptic can scan.
            traj = [{"i": i, "cmd": a.get("command"), "exit": a.get("exit_code"),
                     "out": (a.get("stdout_tail") or "")[-160:],
                     "err": (a.get("stderr_tail") or "")[-160:]}
                    for i, a in enumerate(acts)]
            entry = {**ref, "n_actions": len(acts),
                     "exits": [a.get("exit_code") for a in acts],
                     "trajectory": traj}
            # A journey is POSITIVE iff it has zero FLIPPING candidates. Soft
            # candidates (non-decisive functional / latency) don't disqualify it,
            # but they are still emitted for the skeptic to audit.
            if n_flipping:
                entry["n_candidates"] = n_flipping
                entry["n_soft"] = len(cands) - n_flipping
            else:
                positives.append(entry)
    return {
        "artifacts_dir": artifacts_dir,
        "totals": {"journeys": n_journeys,
                   "candidates": sum(by_kind.values()),
                   "by_kind": dict(by_kind),
                   "flipping_candidates": len(negatives),
                   "soft_candidates": len(soft),
                   "positive_journeys": len(positives)},
        "negatives": negatives,
        "soft": soft,
        "positives": positives,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifacts_dir")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="write the full flattened set here for the skeptic")
    args = ap.parse_args(argv)

    data = collect(args.artifacts_dir)
    if args.json_out:
        json.dump(data, open(args.json_out, "w"), indent=2)

    t = data["totals"]
    print(f"== {t['journeys']} journeys | {t['candidates']} candidates "
          f"({t['by_kind']}) | {t['flipping_candidates']} flipping / "
          f"{t['soft_candidates']} soft | {t['positive_journeys']} positive "
          f"(audit for cheating) ==\n")
    print("FLIPPING candidates (journey-negative — refute each: "
          "real | intended | self-inflicted | discoverability):")
    for c in data["negatives"]:
        print(f"  [{c['kind']}] {c['journey_id']}: {(c.get('detail') or '')[:150]}")
    print("\nSOFT candidates (do NOT flip the journey — non-decisive functional / "
          "latency; still audit as UX signal):")
    for c in data["soft"]:
        print(f"  [{c['kind']}] {c['journey_id']}: {(c.get('detail') or '')[:150]}")
    print("\nPOSITIVE journeys (audit — genuinely-achieved | cheated/unverified | inconclusive):")
    for p in data["positives"]:
        print(f"  {p['journey_id']}: {p['n_actions']} actions, exits={p['exits']}")
    if args.json_out:
        print(f"\nfull set → {args.json_out} (feed to the trajectory-skeptic subagent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
