#!/usr/bin/env python3
# hack/mutants-report.py — merge cargo-mutants `missed.txt` survivors from one or
# more `mutants.out` directories into a JSON worklist + markdown checklist.
#
# Single source of truth for both CI pipelines:
#   --mode gate  : print a step-summary markdown to stdout; exit 1 if any survivor.
#   --mode full  : write merged JSON (--json-out) + markdown worklist (--md-out).
#
# Worklist source is `missed.txt` (one line per survivor: "path:line:col: desc").
import argparse, collections, hashlib, json, os, sys

Mutant = collections.namedtuple("Mutant", "path line col desc id_hash")


def _parse_line(raw):
    # Format: "crates/x/src/y.rs:21:12: replace > with >= in write_frame"
    raw = raw.rstrip("\n")
    if not raw.strip():
        return None
    head, _, desc = raw.partition(": ")
    parts = head.rsplit(":", 2)
    if len(parts) != 3:
        return None
    path, line, col = parts[0], parts[1], parts[2]
    try:
        line_i, col_i = int(line), int(col)
    except ValueError:
        return None
    id_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return Mutant(path, line_i, col_i, desc.strip(), id_hash)


def read_missed(out_dir):
    """Parse <out_dir>/missed.txt (out_dir is a `mutants.out` dir)."""
    fp = os.path.join(out_dir, "missed.txt")
    if not os.path.exists(fp):
        return []
    out = []
    with open(fp) as f:
        for raw in f:
            m = _parse_line(raw)
            if m:
                out.append(m)
    return out


def read_tested(out_dir):
    """Total mutants TESTED in this shard, from <out_dir>/outcomes.json.

    Lets the collect job surface how many mutants the shards actually covered, so
    a sharding partition gap (e.g. cargo-mutants' 0-vs-1-indexed --shard footgun)
    is loud in the report rather than a silent worklist truncation.
    """
    fp = os.path.join(out_dir, "outcomes.json")
    if not os.path.exists(fp):
        return 0
    try:
        with open(fp) as f:
            return int(json.load(f).get("total_mutants", 0))
    except (ValueError, OSError):
        return 0


def merge(dirs):
    seen = {}
    for d in dirs:
        for m in read_missed(d):
            if m.id_hash not in seen:
                seen[m.id_hash] = m
    out = list(seen.values())
    out.sort(key=lambda m: (m.path, m.line, m.col))
    return out


def render_markdown(mutants, tested=None):
    header = ""
    if tested is not None:
        header = f"_Tested {tested} mutant(s) across the run._\n\n"
    if not mutants:
        return header + "No surviving mutants. 🎉\n"
    by_file = collections.OrderedDict()
    for m in mutants:
        by_file.setdefault(m.path, []).append(m)
    lines = [header + f"**{len(mutants)} surviving mutant(s)** across {len(by_file)} file(s).", ""]
    for path, ms in by_file.items():
        lines.append(f"### `{path}`")
        for m in ms:
            lines.append(f"- [ ] `{m.line}:{m.col}` {m.desc} <sub>`{m.id_hash}`</sub>")
        lines.append("")
    return "\n".join(lines)


def _mutant_to_dict(m):
    return {"path": m.path, "line": m.line, "col": m.col, "desc": m.desc, "id_hash": m.id_hash}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["gate", "full"], required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    ap.add_argument("out_dirs", nargs="+", help="paths whose `mutants.out` subdir is read")
    args = ap.parse_args(argv)

    # Accept either a `mutants.out` dir directly or its parent.
    dirs = []
    for d in args.out_dirs:
        cand = d if os.path.basename(d) == "mutants.out" else os.path.join(d, "mutants.out")
        dirs.append(cand if os.path.isdir(cand) else d)

    mutants = merge(dirs)

    if args.mode == "gate":
        # Gate runs over a single dir; a tested-count header is noise here.
        sys.stdout.write(render_markdown(mutants))
        return 1 if mutants else 0

    # full mode: sum tested mutants across shards so partition gaps are visible.
    tested = sum(read_tested(d) for d in dirs)
    md = render_markdown(mutants, tested=tested)
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"count": len(mutants), "tested": tested,
                       "survivors": [_mutant_to_dict(m) for m in mutants]}, f, indent=2)
    if args.md_out:
        with open(args.md_out, "w") as f:
            f.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
