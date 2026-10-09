#!/usr/bin/env python3
# hack/mutants-shard-plan.py — size the incremental mutation gate's shard
# matrices (.github/workflows/mutants.yml `plan` job) from the PR's mutant set.
#
# WHY THIS EXISTS
# The PR gate used to run fixed matrices (Linux 2 shards / 45 min, Windows 4
# shards / 60 min). A large PR's changed-line set outgrew them: PR #300 has ~640
# mutants, every shard hit its timeout, and the gate failed WITHOUT a verdict.
# The shard count now scales with the mutant count, so each shard's slice fits
# inside its job cap regardless of PR size (up to the per-platform max).
#
# HOW
# The `plan` job runs `cargo mutants --list --in-diff <3-dot diff>` (no build —
# sub-second) into a file; this script counts the non-blank lines and prints
# GITHUB_OUTPUT lines:
#   mutants=<count>
#   <plat>_shards=[0,1,...]   (compact JSON, 0-INDEXED — cargo-mutants' --shard k/n)
#   <plat>_n=<n>              (the N in every shard's `k/N` argument)
# N = clamp(ceil(count * secs_per_mutant / shard_budget_secs), min, max).
# cargo-mutants deals mutant i to shard i%N (after --no-shuffle order), so each
# shard gets ceil(count/N) mutants; the budget divides evenly, give or take one.
#
# Usage: hack/mutants-shard-plan.py <mutants-list-file> >> "$GITHUB_OUTPUT"
import dataclasses
import json
import math
import sys


@dataclasses.dataclass(frozen=True)
class Platform:
    name: str
    secs_per_mutant: int  # assumed wall clock per mutant (build + test)
    shard_budget_secs: int  # mutant work one shard may take
    min_shards: int
    max_shards: int


# Per-mutant cost, measured on PR #300's gate runs (2026-09):
#   Linux   ~37 s/mutant (27 s incremental build + 9 s test)      -> assume 40 s
#   Windows 80-145 s/mutant (build dominates; varies with crate)  -> assumed 120 s
# Re-measured on PR #328 (2026-10-09): a 20-mutant Windows shard ran past the
# 60-min job cap THREE times on slow hosted runners (sibling shards 25-33 min),
# i.e. >165 s/mutant once several mutants hit the auto-set ~62 s test timeout on
# top of a ~60 s rebuild. Windows now assumes 180 s so a shard holds ~13 mutants
# and stays inside the cap even on a degraded runner.
# Shard budget = mutant work only. It stays well under the job's timeout-minutes
# (Linux 45, Windows 60) because each shard ALSO pays cache restore, the
# cargo-mutants install, and an unmutated baseline build + test before the first
# mutant. The max caps parallel runner fan-out; past it a shard's slice exceeds
# the budget (a PR that big should be split, or the cap raised deliberately).
LINUX = Platform(name="linux", secs_per_mutant=40, shard_budget_secs=30 * 60, min_shards=2, max_shards=16)
WINDOWS = Platform(name="windows", secs_per_mutant=180, shard_budget_secs=40 * 60, min_shards=4, max_shards=36)
PLATFORMS = (LINUX, WINDOWS)


def shard_count(mutants: int, platform: Platform) -> int:
    """Shards needed so each one's mutant work fits the budget, clamped to
    [min_shards, max_shards]. Zero mutants still yields min_shards: the gate-run
    script already turns "nothing to mutate" into an empty, passing shard."""
    if mutants < 0:
        raise ValueError(f"mutant count must be >= 0, got {mutants}")
    needed = math.ceil(mutants * platform.secs_per_mutant / platform.shard_budget_secs)
    return max(platform.min_shards, min(platform.max_shards, needed))


def plan(mutants: int, platform: Platform) -> dict:
    n = shard_count(mutants, platform)
    return {"shards": list(range(n)), "n": n}


def count_mutants(list_text: str) -> int:
    """`cargo mutants --list` prints one mutant per line."""
    return sum(1 for line in list_text.splitlines() if line.strip())


def github_outputs(mutants: int, platforms=PLATFORMS) -> list:
    lines = [f"mutants={mutants}"]
    for p in platforms:
        pl = plan(mutants, p)
        lines.append(f"{p.name}_shards={json.dumps(pl['shards'], separators=(',', ':'))}")
        lines.append(f"{p.name}_n={pl['n']}")
    return lines


def main(argv, emit=print) -> int:
    if len(argv) != 1:
        print("usage: mutants-shard-plan.py <mutants-list-file>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        mutants = count_mutants(f.read())
    for line in github_outputs(mutants):
        emit(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
