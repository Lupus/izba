#!/usr/bin/env python3
# Tests for hack/mutants-shard-plan.py — sizes the PR mutation gate's shard
# matrices from the changed-line mutant count.
# Pure-Python (no cargo): exercises the planner against synthetic counts/lists.
# Run: python3 hack/mutants-shard-plan.test.py
import importlib.util
import json
import pathlib
import tempfile

_spec = importlib.util.spec_from_file_location(
    "mutants_shard_plan",
    pathlib.Path(__file__).with_name("mutants-shard-plan.py"),
)
sp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sp)

_failures = []


def check(name, cond):
    print(f"{'ok' if cond else 'FAIL'} - {name}")
    if not cond:
        _failures.append(name)


def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    return False


# A synthetic platform so the arithmetic is pinned independently of the tuned
# production constants: 10 s/mutant, 100 s budget ⇒ 10 mutants per shard.
TOY = sp.Platform(name="toy", secs_per_mutant=10, shard_budget_secs=100, min_shards=2, max_shards=5)

# --- shard_count: ceil(work / budget), clamped to [min, max] ------------------
check("zero mutants -> min shards", sp.shard_count(0, TOY) == 2)
check("one mutant -> min shards", sp.shard_count(1, TOY) == 2)
check("exactly min*per-shard -> min", sp.shard_count(20, TOY) == 2)
check("one over a shard boundary rounds UP", sp.shard_count(21, TOY) == 3)
check("exact multiple does not round up", sp.shard_count(30, TOY) == 3)
check("just under max stays under", sp.shard_count(41, TOY) == 5)
check("huge set is capped at max", sp.shard_count(10_000, TOY) == 5)
check("negative count is rejected", raises(lambda: sp.shard_count(-1, TOY), ValueError))

# --- plan: 0-indexed shard list + N ------------------------------------------
check("plan lists 0-indexed shards", sp.plan(21, TOY) == {"shards": [0, 1, 2], "n": 3})

# --- production constants: min/max and the measured PR #300 scale ------------
check("linux floor is 2", sp.shard_count(0, sp.LINUX) == 2)
check("windows floor is 4", sp.shard_count(0, sp.WINDOWS) == 4)
check("linux cap is 16", sp.shard_count(100_000, sp.LINUX) == 16)
check("windows cap is 36", sp.shard_count(100_000, sp.WINDOWS) == 36)
# 641 mutants (PR #300): linux 641*40/1800 = 14.2 -> 15; windows 641*120/2400 = 32.05 -> 33 (under the 36 cap).
check("linux 641 -> 15", sp.shard_count(641, sp.LINUX) == 15)
check("windows 641 -> 33", sp.shard_count(641, sp.WINDOWS) == 33)
# Every production budget must leave headroom under its job's timeout-minutes
# (baseline build + cache restore + install also spend wall clock).
check("linux budget < 45-min job cap", sp.LINUX.shard_budget_secs < 45 * 60)
check("windows budget < 60-min job cap", sp.WINDOWS.shard_budget_secs < 60 * 60)

# --- count_mutants: non-blank lines of a `cargo mutants --list` output --------
check(
    "count_mutants ignores blank lines",
    sp.count_mutants("a.rs:1:1: replace x\n\nb.rs:2:2: replace y\n   \n") == 2,
)
check("count_mutants of empty text is 0", sp.count_mutants("") == 0)

# --- github_outputs: the exact key=value lines the workflow consumes ----------
out = sp.github_outputs(21, [TOY])
check("github_outputs emits compact JSON shards", "toy_shards=[0,1,2]" in out)
check("github_outputs emits n", "toy_n=3" in out)
check("github_outputs emits the count", "mutants=21" in out)
check("github_outputs are one key=value per line", all("\n" not in line for line in out))
default_keys = {line.split("=", 1)[0] for line in sp.github_outputs(0)}
check(
    "default outputs cover both platforms",
    default_keys == {"mutants", "linux_shards", "linux_n", "windows_shards", "windows_n"},
)
kv = dict(line.split("=", 1) for line in sp.github_outputs(641))
for plat in ("linux", "windows"):
    check(
        f"{plat}_shards parses as JSON [0..N)",
        json.loads(kv[f"{plat}_shards"]) == list(range(int(kv[f"{plat}_n"]))),
    )

# --- main: reads a list file, prints outputs, exit 0 --------------------------
with tempfile.TemporaryDirectory() as d:
    p = pathlib.Path(d) / "list.txt"
    p.write_text("\n".join(f"x.rs:{i}:1: replace m" for i in range(641)) + "\n")
    lines = []
    rc = sp.main([str(p)], emit=lines.append)
    check("main exits 0", rc == 0)
    check("main counts the list file", "mutants=641" in lines)
    check("main emits linux_n=15", "linux_n=15" in lines)
    empty = pathlib.Path(d) / "empty.txt"
    empty.write_text("")
    lines = []
    sp.main([str(empty)], emit=lines.append)
    check("main on empty list yields floors", "linux_n=2" in lines and "windows_n=4" in lines)
check("main without args is a usage error", sp.main([], emit=lambda _l: None) == 2)

if _failures:
    print(f"\n{len(_failures)} test(s) FAILED")
    raise SystemExit(1)
print("\nall tests passed")
