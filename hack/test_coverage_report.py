"""Unit tests for coverage_report.py.

Run: python3 -m unittest hack.test_coverage_report  (from repo root)
  or: cd hack && python3 -m unittest test_coverage_report
"""

import unittest

import coverage_report as cr


def _summary(count, covered):
    pct = 100.0 * covered / count if count else 100.0
    return {"count": count, "covered": covered, "percent": pct}


def _file(filename, *, lines, lcov, funcs=4, fcov=4, regions=10, rcov=10):
    return {
        "filename": filename,
        "summary": {
            "lines": _summary(lines, lcov),
            "functions": _summary(funcs, fcov),
            "regions": _summary(regions, rcov),
        },
    }


# A fixture shaped like `cargo llvm-cov report --json` (llvm.coverage.json.export).
FIXTURE = {
    "type": "llvm.coverage.json.export",
    "version": "2.0.1",
    "data": [
        {
            "files": [
                # izba-core: large, half covered -> 100 uncovered lines (biggest gap)
                _file("/work/izba/crates/izba-core/src/sandbox.rs",
                      lines=200, lcov=100, funcs=20, fcov=10),
                # izba-core: small, fully covered
                _file("/work/izba/crates/izba-core/src/paths.rs",
                      lines=30, lcov=30, funcs=5, fcov=5),
                # izba-cli: 0% covered, small -> zero-coverage callout
                _file("/work/izba/crates/izba-cli/src/commands/netlog.rs",
                      lines=40, lcov=0, funcs=6, fcov=0),
                # izba-proto: mostly covered -> 10 uncovered lines
                _file("/work/izba/crates/izba-proto/src/codec.rs",
                      lines=60, lcov=50, funcs=8, fcov=7),
            ],
            "totals": {
                "lines": _summary(330, 180),
                "functions": _summary(39, 22),
                "regions": _summary(40, 30),
            },
        }
    ],
}


class DeriveCrateTests(unittest.TestCase):
    def test_crate_from_crates_path(self):
        self.assertEqual(
            cr.derive_crate("/work/izba/crates/izba-core/src/sandbox.rs"),
            "izba-core",
        )

    def test_crate_from_app_tauri_path(self):
        self.assertEqual(
            cr.derive_crate("/work/izba/app/src-tauri/src/commands.rs"),
            "izba-app",
        )

    def test_unknown_path_falls_back(self):
        self.assertEqual(cr.derive_crate("/some/other/file.rs"), "(other)")


class RelPathTests(unittest.TestCase):
    def test_rel_path_strips_to_crates(self):
        self.assertEqual(
            cr.rel_path("/work/izba/crates/izba-core/src/sandbox.rs"),
            "crates/izba-core/src/sandbox.rs",
        )

    def test_rel_path_strips_to_app(self):
        self.assertEqual(
            cr.rel_path("/x/app/src-tauri/src/commands.rs"),
            "app/src-tauri/src/commands.rs",
        )


class ExtractFilesTests(unittest.TestCase):
    def test_extracts_all_files_with_uncovered_counts(self):
        files = cr.extract_files(FIXTURE)
        self.assertEqual(len(files), 4)
        sandbox = next(f for f in files if f.rel_path.endswith("sandbox.rs"))
        self.assertEqual(sandbox.crate, "izba-core")
        self.assertEqual(sandbox.lines_count, 200)
        self.assertEqual(sandbox.lines_covered, 100)
        self.assertEqual(sandbox.uncovered_lines, 100)
        self.assertEqual(sandbox.uncovered_funcs, 10)


class GapRankingTests(unittest.TestCase):
    def test_ranks_by_uncovered_lines_descending(self):
        files = cr.extract_files(FIXTURE)
        gaps = cr.rank_gaps(files)
        # sandbox (100 uncovered) > netlog (40) > codec (10) > paths (0)
        self.assertEqual(gaps[0].rel_path, "crates/izba-core/src/sandbox.rs")
        self.assertEqual(gaps[1].rel_path, "crates/izba-cli/src/commands/netlog.rs")
        self.assertEqual(gaps[2].rel_path, "crates/izba-proto/src/codec.rs")

    def test_fully_covered_file_excluded_from_gaps(self):
        files = cr.extract_files(FIXTURE)
        gaps = cr.rank_gaps(files)
        self.assertNotIn(
            "crates/izba-core/src/paths.rs", [g.rel_path for g in gaps]
        )

    def test_top_limits_results(self):
        files = cr.extract_files(FIXTURE)
        self.assertEqual(len(cr.rank_gaps(files, top=1)), 1)


class ZeroCoverageTests(unittest.TestCase):
    def test_lists_only_zero_percent_files(self):
        files = cr.extract_files(FIXTURE)
        zeros = cr.zero_coverage_files(files)
        self.assertEqual(
            [z.rel_path for z in zeros],
            ["crates/izba-cli/src/commands/netlog.rs"],
        )


class CrateSummaryTests(unittest.TestCase):
    def test_aggregates_per_crate_sorted_worst_first(self):
        files = cr.extract_files(FIXTURE)
        crates = cr.crate_summary(files)
        # izba-cli 0/40, izba-core 130/230, izba-proto 50/60 -> cli worst
        names = [c.crate for c in crates]
        self.assertEqual(names[0], "izba-cli")
        core = next(c for c in crates if c.crate == "izba-core")
        self.assertEqual(core.lines_count, 230)
        self.assertEqual(core.lines_covered, 130)


class TotalsTests(unittest.TestCase):
    def test_headline_totals(self):
        t = cr.totals(FIXTURE)
        self.assertEqual(t.lines_count, 330)
        self.assertEqual(t.lines_covered, 180)
        self.assertAlmostEqual(t.lines_percent, 100.0 * 180 / 330, places=3)


class RenderTests(unittest.TestCase):
    def test_render_contains_sections_and_worst_file(self):
        md = cr.render(FIXTURE, top=25)
        self.assertIn("# Coverage gap report", md)
        self.assertIn("Coverage gaps", md)
        self.assertIn("crates/izba-core/src/sandbox.rs", md)
        self.assertIn("netlog.rs", md)  # zero-coverage callout
        # ranked by uncovered-line impact, stated explicitly
        self.assertIn("uncovered", md.lower())

    def test_render_empty_data_raises(self):
        with self.assertRaises(cr.CoverageError):
            cr.render({"data": []}, top=25)


if __name__ == "__main__":
    unittest.main()
