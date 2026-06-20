#!/usr/bin/env python3
# hack/mutants-check-excludes.py — guard against silent drift of the `exclude_re`
# entries in `.cargo/mutants.toml`.
#
# WHY THIS EXISTS
# cargo-mutants suppresses individual mutants by regex matched against the mutant
# NAME ("path:line:col: description"). That is the only mechanism fine-grained
# enough to drop a single equivalent/not-worth mutant without skipping a whole
# function (an attribute can't scope below an item; see CONTRIBUTING.md). But
# cargo-mutants does NOT warn when an `exclude_re`:
#   * goes STALE  — the targeted mutant moved/renamed/vanished, so the pattern now
#     matches nothing and silently protects nothing; or
#   * goes OVER-BROAD — new code introduces a mutant the pattern also matches, so a
#     real, killable survivor is hidden from the worklist and the gate.
# Either way nobody notices. This guard makes both cases a hard CI failure.
#
# HOW
# Every `exclude_re` pattern MUST be pinned in EXPECTED below to the exact set of
# mutants it is allowed to match, identified by the line-INDEPENDENT (path,
# description) pair (line/column are intentionally excluded so ordinary edits don't
# trip the guard). The guard lists the full, unfiltered mutant inventory
# (`cargo mutants --list --no-config`) and fails if any pattern matches a set that
# differs from its pin — including the empty set (stale).
#
# WHEN YOU ADD/CHANGE AN EXCLUSION
# Update EXPECTED in the same change. The failure message prints the observed set
# so you can paste it in. Each pin also carries a one-line `reason`.
import collections
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MUTANTS_TOML = REPO_ROOT / ".cargo" / "mutants.toml"

# pattern (verbatim from .cargo/mutants.toml) -> {"reason": str, "matches": {(path, desc): count}}
# `matches` is the COMPLETE multiset the pattern may match, keyed by the
# line-INDEPENDENT (path, description) identity with its exact COUNT. The count
# matters: `16 * 1024 * 1024` has two `*`, so each `* -> +`/`* -> /` mutant occurs
# twice. Pinning the count (not just the identity) is what catches a SECOND `*`
# being added to codec.rs later — same (path, desc), so a plain set would miss it,
# but the count would jump 2 -> 3 and trip the guard.
EXPECTED = {
    r"codec\.rs:\d+:\d+: replace \* with": {
        "reason": "MAX_FRAME = 16 * 1024 * 1024 — `* -> +`/`* -> /` on a size "
        "literal admit only a tautological assert_eq. (Two `*` => count 2 each.)",
        "matches": {
            ("crates/izba-proto/src/codec.rs", "replace * with +"): 2,
            ("crates/izba-proto/src/codec.rs", "replace * with /"): 2,
        },
    },
    r"replace \| with \^ in servfail": {
        "reason": "servfail (resp[3] & 0xf0) | 0x02 — `| -> ^` is an equivalent "
        "mutant (the mask clears bit 0x02).",
        "matches": {
            ("crates/izba-proto/src/dns.rs", "replace | with ^ in servfail"): 1,
        },
    },
}


def parse_mutant_name(raw):
    """'crates/x/y.rs:21:12: replace > with >= in f' -> ('crates/x/y.rs', 'replace > with >= in f').

    Returns None for blank/unparseable lines. Line and column are dropped so the
    identity is stable across edits that shift code around.
    """
    raw = raw.rstrip("\n")
    if not raw.strip():
        return None
    head, sep, desc = raw.partition(": ")
    if not sep:
        return None
    parts = head.rsplit(":", 2)
    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
        return None
    return (parts[0], desc.strip())


def verify(inventory_names, config_patterns, expected):
    """Pure core: returns a list of human-readable error strings (empty == OK).

    inventory_names : iterable of raw "path:line:col: desc" mutant names (unfiltered).
    config_patterns : list of exclude_re patterns actually present in mutants.toml.
    expected        : the EXPECTED pin mapping.
    """
    errors = []
    config_set, expected_set = set(config_patterns), set(expected)

    for pat in sorted(config_set - expected_set):
        errors.append(
            f"exclude_re {pat!r} is in .cargo/mutants.toml but is not pinned in "
            f"mutants-check-excludes.py. Add it to EXPECTED with the exact mutants "
            f"it may match and a reason."
        )
    for pat in sorted(expected_set - config_set):
        errors.append(
            f"exclude_re {pat!r} is pinned in mutants-check-excludes.py but no "
            f"longer present in .cargo/mutants.toml. Remove the stale pin."
        )

    for pat in sorted(config_set & expected_set):
        try:
            rx = re.compile(pat)
        except re.error as exc:
            errors.append(f"exclude_re {pat!r} is not a valid regex: {exc}")
            continue
        # Match the pattern against full names, then reduce to a (path, desc)
        # multiset — the count distinguishes a duplicated operator in one file.
        matched = collections.Counter()
        for raw in inventory_names:
            if rx.search(raw):
                ident = parse_mutant_name(raw)
                if ident is not None:
                    matched[ident] += 1
        want = collections.Counter({tuple(k): v for k, v in expected[pat]["matches"].items()})

        if not matched:
            errors.append(
                f"STALE exclude_re {pat!r} matches NO mutant — it protects nothing "
                f"(the targeted mutant moved/renamed/vanished). Re-target it or "
                f"delete it. Expected to match: {dict(want)}"
            )
            continue
        # `+`/`-` on Counters keep only positive counts, giving directional diffs.
        broad = matched - want   # matched more than pinned (new/duplicated mutant)
        stale = want - matched   # pinned mutant(s) no longer present
        if broad:
            errors.append(
                f"OVER-BROAD exclude_re {pat!r} now also matches unexpected "
                f"mutant(s) {dict(broad)} — a real survivor may be silently hidden. "
                f"Narrow the pattern, or (if intended) update its pin. "
                f"Reason on file: {expected[pat]['reason']}"
            )
        if stale:
            errors.append(
                f"exclude_re {pat!r} no longer matches pinned mutant(s) "
                f"{dict(stale)} — they were caught/removed/renamed. Update the pin "
                f"in mutants-check-excludes.py."
            )
    return errors


def read_config_patterns(toml_path):
    """Extract the exclude_re list from .cargo/mutants.toml (stdlib only)."""
    try:
        import tomllib

        with open(toml_path, "rb") as f:
            return list(tomllib.load(f).get("exclude_re", []))
    except ModuleNotFoundError:
        # Python < 3.11 fallback: scrape the array literal.
        text = Path(toml_path).read_text()
        m = re.search(r"exclude_re\s*=\s*\[(.*?)\]", text, re.S)
        if not m:
            return []
        return [s.encode().decode("unicode_escape") for s in re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))]


def list_inventory():
    """Full, UNFILTERED mutant inventory via cargo-mutants (no config exclusions)."""
    proc = subprocess.run(
        ["cargo", "mutants", "--list", "--no-config"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"`cargo mutants --list --no-config` failed ({proc.returncode})")
    return proc.stdout.splitlines()


def main(argv=None):
    patterns = read_config_patterns(MUTANTS_TOML)
    inventory = list_inventory()
    errors = verify(inventory, patterns, EXPECTED)
    if errors:
        sys.stderr.write("mutants exclude_re drift detected:\n\n")
        for e in errors:
            sys.stderr.write(f"  - {e}\n")
        sys.stderr.write(
            "\nSee hack/mutants-check-excludes.py (EXPECTED) and "
            ".cargo/mutants.toml.\n"
        )
        return 1
    print(f"OK: {len(patterns)} exclude_re pattern(s) match exactly their pinned mutants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
