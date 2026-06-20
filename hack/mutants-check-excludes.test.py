#!/usr/bin/env python3
# Tests for hack/mutants-check-excludes.py — the exclude_re drift guard.
# Pure-Python (no cargo): exercises verify() against a synthetic inventory.
# Run: python3 hack/mutants-check-excludes.test.py
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "mutants_check_excludes",
    pathlib.Path(__file__).with_name("mutants-check-excludes.py"),
)
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

# A small synthetic inventory of raw mutant names ("path:line:col: desc").
INVENTORY = [
    "crates/izba-proto/src/codec.rs:10:31: replace * with +",
    "crates/izba-proto/src/codec.rs:10:31: replace * with /",
    "crates/izba-proto/src/codec.rs:10:38: replace * with +",
    "crates/izba-proto/src/codec.rs:10:38: replace * with /",
    "crates/izba-proto/src/codec.rs:27:12: replace > with >= in write_frame",
    "crates/izba-proto/src/dns.rs:35:36: replace | with ^ in servfail",
    "crates/izba-proto/src/dns.rs:35:36: replace | with & in servfail",
    "crates/izba-proto/src/dns.rs:34:17: replace |= with &= in servfail",
    "",  # blank lines must be ignored
]

PAT_STAR = r"codec\.rs:\d+:\d+: replace \* with"
PAT_SERVFAIL = r"replace \| with \^ in servfail"

GOOD_EXPECTED = {
    PAT_STAR: {
        "reason": "size literal",
        "matches": {
            ("crates/izba-proto/src/codec.rs", "replace * with +"): 2,
            ("crates/izba-proto/src/codec.rs", "replace * with /"): 2,
        },
    },
    PAT_SERVFAIL: {
        "reason": "equivalent mutant",
        "matches": {("crates/izba-proto/src/dns.rs", "replace | with ^ in servfail"): 1},
    },
}

_failures = []


def check(name, cond):
    print(f"{'ok' if cond else 'FAIL'} - {name}")
    if not cond:
        _failures.append(name)


def errs(config_patterns, expected, inventory=INVENTORY):
    return chk.verify(inventory, config_patterns, expected)


# --- parse_mutant_name drops line/col and keeps (path, desc) -----------------
check(
    "parse_mutant_name strips line:col",
    chk.parse_mutant_name("a/b.rs:10:31: replace * with +") == ("a/b.rs", "replace * with +"),
)
check("parse_mutant_name rejects blank", chk.parse_mutant_name("   ") is None)
check("parse_mutant_name rejects malformed", chk.parse_mutant_name("no colons here") is None)

# --- happy path: every pattern matches exactly its pin -----------------------
check(
    "clean config has no errors",
    errs([PAT_STAR, PAT_SERVFAIL], GOOD_EXPECTED) == [],
)

# --- STALE: pattern matches nothing in the inventory -------------------------
stale_pat = r"codec\.rs:\d+:\d+: replace MISSING with"
stale_expected = {
    **GOOD_EXPECTED,
    stale_pat: {"reason": "x", "matches": {("crates/izba-proto/src/codec.rs", "replace MISSING with z"): 1}},
}
out = errs([PAT_STAR, PAT_SERVFAIL, stale_pat], stale_expected)
# (Assert on the pinned-mutant text, not the pattern: error messages render the
# pattern via repr(), which double-escapes the backslashes in the regex.)
check("stale pattern (matches nothing) is reported", any("STALE" in e and "MISSING" in e for e in out))

# --- OVER-BROAD: pattern matches a mutant (new desc) not in its pin -----------
broad_expected = {
    **GOOD_EXPECTED,
    # A pattern that catches both the `^` and the killable `&` servfail mutant, but
    # is pinned only to the `^` one — the `&` match must be flagged.
    r"replace \| with . in servfail": {
        "reason": "x",
        "matches": {("crates/izba-proto/src/dns.rs", "replace | with ^ in servfail"): 1},
    },
}
out = errs([PAT_STAR, r"replace \| with . in servfail"], broad_expected)
check(
    "over-broad pattern (extra desc) is reported",
    any("OVER-BROAD" in e and "replace | with & in servfail" in e for e in out),
)

# --- OVER-BROAD via COUNT: same (path,desc) appears more often than pinned ----
# Simulates a SECOND `*` added to codec.rs: identity is unchanged but the count
# rises, which a plain set would miss. Pin says 2 each; inventory has 3 of `+`.
dup_inventory = INVENTORY + ["crates/izba-proto/src/codec.rs:99:9: replace * with +"]
out = errs([PAT_STAR, PAT_SERVFAIL], GOOD_EXPECTED, inventory=dup_inventory)
check(
    "over-broad by count (duplicated operator, same identity) is reported",
    any("OVER-BROAD" in e and "replace * with +" in e for e in out),
)

# --- pinned-but-vanished: an expected mutant no longer matches ----------------
gone_inventory = [n for n in INVENTORY if "replace * with /" not in n]
out = errs([PAT_STAR, PAT_SERVFAIL], GOOD_EXPECTED, inventory=gone_inventory)
check(
    "pinned mutant that disappeared is reported (and not as stale)",
    any("no longer matches pinned" in e and "replace * with /" in e for e in out),
)

# --- config pattern with no pin ----------------------------------------------
out = errs([PAT_STAR, PAT_SERVFAIL, r"unpinned pattern"], GOOD_EXPECTED)
check("unpinned config pattern is reported", any("not pinned" in e for e in out))

# --- pin with no config pattern (orphan) -------------------------------------
out = errs([PAT_STAR], GOOD_EXPECTED)
check("orphan pin (pattern removed from config) is reported", any("no longer present" in e for e in out))

# --- invalid regex in config -------------------------------------------------
bad_expected = {**GOOD_EXPECTED, r"(unclosed": {"reason": "x", "mutants": []}}
out = errs([PAT_STAR, PAT_SERVFAIL, r"(unclosed"], bad_expected)
check("invalid regex is reported", any("not a valid regex" in e for e in out))

if _failures:
    print(f"\n{len(_failures)} test(s) FAILED")
    raise SystemExit(1)
print("\nall tests passed")
