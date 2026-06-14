#!/usr/bin/env python3
"""Turn a `cargo llvm-cov report --json` file into a QA-facing coverage gap report.

The report ranks production files by **uncovered-line count, descending** — i.e.
by how many lines have no test exercising them, not by raw percentage. A small
file at 0% does not outrank a large file at 50%: the latter is where the most
untested behavior lives, so it is where adding tests buys the most coverage.

Input is the llvm-cov export JSON (`type: llvm.coverage.json.export`) that
`cargo llvm-cov report --json` emits. Output is Markdown, suitable for a CI
step summary or a committed report file.

Usage:
    coverage_report.py COVERAGE_JSON [--out FILE] [--top N] [--title TITLE]

Pure stdlib (no pip deps).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

# Path segments that mark a crate/package root, longest-match first.
_CRATE_MARKERS = (
    ("app/src-tauri/", "izba-app"),  # the Tauri backend crate (Phase 3)
)
_CRATES_RE = re.compile(r"(?:^|/)crates/([^/]+)/")
# Where to start a display-relative path, in priority order.
_REL_MARKERS = ("crates/", "app/")


class CoverageError(Exception):
    """Raised when the coverage JSON is missing, empty, or malformed."""


@dataclass
class FileStat:
    filename: str
    rel_path: str
    crate: str
    lines_count: int
    lines_covered: int
    funcs_count: int
    funcs_covered: int

    @property
    def uncovered_lines(self) -> int:
        return self.lines_count - self.lines_covered

    @property
    def uncovered_funcs(self) -> int:
        return self.funcs_count - self.funcs_covered

    @property
    def lines_percent(self) -> float:
        return 100.0 * self.lines_covered / self.lines_count if self.lines_count else 100.0


@dataclass
class CrateStat:
    crate: str
    lines_count: int
    lines_covered: int

    @property
    def lines_percent(self) -> float:
        return 100.0 * self.lines_covered / self.lines_count if self.lines_count else 100.0


@dataclass
class Totals:
    lines_count: int
    lines_covered: int
    funcs_count: int
    funcs_covered: int
    regions_count: int
    regions_covered: int

    @property
    def lines_percent(self) -> float:
        return 100.0 * self.lines_covered / self.lines_count if self.lines_count else 100.0

    @property
    def funcs_percent(self) -> float:
        return 100.0 * self.funcs_covered / self.funcs_count if self.funcs_count else 100.0

    @property
    def regions_percent(self) -> float:
        return 100.0 * self.regions_covered / self.regions_count if self.regions_count else 100.0


def derive_crate(filename: str) -> str:
    """Best-effort crate/package name from an absolute source path."""
    norm = filename.replace("\\", "/")
    for marker, name in _CRATE_MARKERS:
        if marker in norm:
            return name
    m = _CRATES_RE.search(norm)
    if m:
        return m.group(1)
    return "(other)"


def rel_path(filename: str) -> str:
    """A repo-relative display path, anchored at the first known marker."""
    norm = filename.replace("\\", "/")
    for marker in _REL_MARKERS:
        idx = norm.find(marker)
        if idx != -1:
            return norm[idx:]
    return norm.rsplit("/", 1)[-1]


def _first_data(data: dict) -> dict:
    blocks = data.get("data") or []
    if not blocks:
        raise CoverageError(
            "coverage JSON has no data blocks — did the coverage run produce results?"
        )
    return blocks[0]


def extract_files(data: dict) -> list[FileStat]:
    block = _first_data(data)
    out: list[FileStat] = []
    for f in block.get("files", []):
        try:
            name = f["filename"]
            summary = f["summary"]
            lines = summary["lines"]
            funcs = summary["functions"]
        except (KeyError, TypeError) as exc:
            raise CoverageError(f"malformed file entry in coverage JSON: {exc}") from exc
        out.append(
            FileStat(
                filename=name,
                rel_path=rel_path(name),
                crate=derive_crate(name),
                lines_count=int(lines["count"]),
                lines_covered=int(lines["covered"]),
                funcs_count=int(funcs["count"]),
                funcs_covered=int(funcs["covered"]),
            )
        )
    return out


def rank_gaps(files: list[FileStat], top: int | None = None) -> list[FileStat]:
    """Files with at least one uncovered line, worst (most uncovered) first."""
    gaps = [f for f in files if f.uncovered_lines > 0]
    gaps.sort(key=lambda f: (-f.uncovered_lines, f.lines_percent, f.rel_path))
    return gaps[:top] if top is not None else gaps


def zero_coverage_files(files: list[FileStat]) -> list[FileStat]:
    """Files with 0% line coverage and at least one line (likely untested modules)."""
    zeros = [f for f in files if f.lines_count > 0 and f.lines_covered == 0]
    zeros.sort(key=lambda f: (-f.lines_count, f.rel_path))
    return zeros


def crate_summary(files: list[FileStat]) -> list[CrateStat]:
    """Per-crate aggregate line coverage, worst-covered crate first."""
    agg: dict[str, list[int]] = {}
    for f in files:
        acc = agg.setdefault(f.crate, [0, 0])
        acc[0] += f.lines_count
        acc[1] += f.lines_covered
    crates = [CrateStat(c, n, cov) for c, (n, cov) in agg.items()]
    crates.sort(key=lambda c: (c.lines_percent, c.crate))
    return crates


def totals(data: dict) -> Totals:
    block = _first_data(data)
    t = block.get("totals")
    if not t:
        raise CoverageError("coverage JSON has no totals block")
    return Totals(
        lines_count=int(t["lines"]["count"]),
        lines_covered=int(t["lines"]["covered"]),
        funcs_count=int(t["functions"]["count"]),
        funcs_covered=int(t["functions"]["covered"]),
        regions_count=int(t["regions"]["count"]),
        regions_covered=int(t["regions"]["covered"]),
    )


def _bar(pct: float) -> str:
    filled = int(round(pct / 10.0))
    return "█" * filled + "░" * (10 - filled)


def render(data: dict, top: int = 25, title: str = "Coverage gap report") -> str:
    t = totals(data)
    files = extract_files(data)
    gaps = rank_gaps(files, top=top)
    zeros = zero_coverage_files(files)
    crates = crate_summary(files)

    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(
        f"**Overall:** {t.lines_percent:.1f}% lines "
        f"({t.lines_covered}/{t.lines_count}) · "
        f"{t.funcs_percent:.1f}% functions "
        f"({t.funcs_covered}/{t.funcs_count}) · "
        f"{t.regions_percent:.1f}% regions "
        f"({t.regions_covered}/{t.regions_count})"
    )
    lines.append("")
    lines.append("## Coverage by crate")
    lines.append("")
    lines.append("| Crate | Lines | Covered | Coverage |")
    lines.append("| --- | --: | --: | --- |")
    for c in crates:
        lines.append(
            f"| {c.crate} | {c.lines_count} | {c.lines_covered} | "
            f"`{_bar(c.lines_percent)}` {c.lines_percent:.1f}% |"
        )
    lines.append("")
    lines.append("## Coverage gaps")
    lines.append("")
    lines.append(
        "Files ranked by **uncovered-line count, descending** — the most "
        "untested behavior first. These are the highest-impact places to add "
        "tests. (A large half-covered file outranks a tiny fully-uncovered one.)"
    )
    lines.append("")
    if gaps:
        lines.append("| File | Coverage | Uncovered lines | Uncovered fns |")
        lines.append("| --- | --- | --: | --: |")
        for f in gaps:
            lines.append(
                f"| `{f.rel_path}` | {f.lines_percent:.1f}% | "
                f"{f.uncovered_lines} | {f.uncovered_funcs} |"
            )
    else:
        lines.append("_No uncovered lines — every measured file is fully covered._")
    lines.append("")
    lines.append("## Untested files (0% line coverage)")
    lines.append("")
    if zeros:
        lines.append(
            "Whole files with no test exercising any line — usually the "
            "clearest QA targets:"
        )
        lines.append("")
        for f in zeros:
            lines.append(f"- `{f.rel_path}` — {f.lines_count} lines, {f.crate}")
    else:
        lines.append("_None — every measured file has at least some coverage._")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json", help="path to `cargo llvm-cov report --json` output")
    parser.add_argument("--out", help="write Markdown here instead of stdout")
    parser.add_argument("--top", type=int, default=25, help="max files in the gap table")
    parser.add_argument("--title", default="Coverage gap report")
    args = parser.parse_args(argv)

    try:
        with open(args.json, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read coverage JSON: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: coverage JSON is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        md = render(data, top=args.top, title=args.title)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
