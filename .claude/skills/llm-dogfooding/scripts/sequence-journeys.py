#!/usr/bin/env python3
"""sequence-journeys.py — Phase 2 (Sequence) of LLM dogfooding.

Take the COMPLETE journeys.json produced by Phase 1 (the journey-compiler, which
aims for coverage, not order) and rearrange it into a PROGRESSIVE-EXPLORATION
plan: shallow `smoke` journeys first, then `core`, then `deep`, with deeper tiers
gated on the capabilities the earlier tiers establish.

This stage is deliberately deterministic — the *semantic* judgment (which tier a
journey belongs to, which capabilities it establishes/requires) is the
compiler's; this script only groups, orders, and surfaces the gate plan so the
orchestrator dispatches the cheapest signal first and never runs a deep journey
whose prerequisite is a known, unfixable blocker.

Usage:
    sequence-journeys.py <complete-journeys.json> [--out DIR]

Writes into DIR (default: alongside the input):
    tier-smoke.json / tier-core.json / tier-deep.json   (only non-empty tiers)
    sequence-plan.json                                   (the gate + capability plan)
and prints a human-readable plan to stdout. No network, stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

TIER_ORDER = ["smoke", "core", "deep"]
DEFAULT_TIER = "core"  # a journey with no `tier` is core coverage


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _tier_of(journey: dict) -> str:
    tier = journey.get("tier", DEFAULT_TIER)
    if tier not in TIER_ORDER:
        raise SystemExit(f"journey {journey.get('journey_id')!r}: bad tier {tier!r}")
    return tier


def build_plan(data: dict) -> dict:
    """Group journeys into ordered tiers and compute the capability graph."""
    feature = data["feature"]
    journeys = data["journeys"]

    by_tier: dict[str, list[dict]] = {t: [] for t in TIER_ORDER}
    for j in journeys:
        by_tier[_tier_of(j)].append(j)

    # capability graph: which journeys establish / require each capability
    caps: dict[str, dict[str, list[str]]] = {}
    for j in journeys:
        jid = j["journey_id"]
        for cap in j.get("establishes", []):
            caps.setdefault(cap, {"established_by": [], "required_by": []})["established_by"].append(jid)
        for cap in j.get("requires", []):
            caps.setdefault(cap, {"established_by": [], "required_by": []})["required_by"].append(jid)

    tiers = []
    for t in TIER_ORDER:
        js = by_tier[t]
        if not js:
            continue
        establishes: list[str] = []
        for j in js:
            for cap in j.get("establishes", []):
                if cap not in establishes:
                    establishes.append(cap)
        tiers.append(
            {
                "tier": t,
                "file": f"tier-{t}.json",
                "count": len(js),
                "journey_ids": [j["journey_id"] for j in js],
                "gating": [j["journey_id"] for j in js if j.get("gating")],
                "establishes": establishes,
            }
        )

    # journeys that can be deferred if a required capability ends up blocked
    deferrable = [
        {"journey_id": j["journey_id"], "tier": _tier_of(j), "requires": j["requires"]}
        for j in journeys
        if j.get("requires")
    ]

    return {
        "feature": feature,
        "tiers": tiers,
        "capabilities": caps,
        "deferrable": deferrable,
    }


def write_tier_files(data: dict, plan: dict, out_dir: str) -> None:
    by_id = {j["journey_id"]: j for j in data["journeys"]}
    for tier in plan["tiers"]:
        slice_doc = {
            "feature": data["feature"],
            "journeys": [by_id[jid] for jid in tier["journey_ids"]],
        }
        path = os.path.join(out_dir, tier["file"])
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(slice_doc, fh, indent=2)


def _print_summary(plan: dict, out_dir: str) -> None:
    print(f"== sequence plan for {plan['feature']!r} ==")
    for tier in plan["tiers"]:
        gate = f"  gating: {', '.join(tier['gating'])}" if tier["gating"] else "  gating: (none)"
        caps = f"  establishes: {', '.join(tier['establishes'])}" if tier["establishes"] else ""
        print(f"\n[{tier['tier']}] {tier['count']} journeys -> {os.path.join(out_dir, tier['file'])}")
        print(gate)
        if caps:
            print(caps)
    if plan["deferrable"]:
        print("\ndeferrable-if-blocked (journey <- required capabilities):")
        for d in plan["deferrable"]:
            print(f"  {d['journey_id']} <- {', '.join(d['requires'])}")
    print(
        "\nDispatch tiers in order; advance only when a tier's gating journeys genuinely "
        "succeed (after any in-place fix). Defer a journey whose `requires` names a "
        "capability confirmed blocked — and log it, never drop silently."
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Sequence complete journeys into progressive tiers.")
    ap.add_argument("journeys", help="path to the complete journeys.json (Phase 1 output)")
    ap.add_argument("--out", default=None, help="output dir (default: alongside the input)")
    args = ap.parse_args(argv)

    data = _load(args.journeys)
    if "journeys" not in data or "feature" not in data:
        raise SystemExit("input is not a journeys document ({feature, journeys})")

    out_dir = args.out or os.path.dirname(os.path.abspath(args.journeys))
    os.makedirs(out_dir, exist_ok=True)

    plan = build_plan(data)
    write_tier_files(data, plan, out_dir)
    with open(os.path.join(out_dir, "sequence-plan.json"), "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2)

    _print_summary(plan, out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
