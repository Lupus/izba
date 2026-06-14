#!/usr/bin/env bash
# Measure code coverage for the izba Rust workspace and emit a QA gap report.
#
# Runs the host unit + integration test suite under cargo-llvm-cov (source-based
# LLVM coverage), then produces, under target/coverage/:
#   - lcov.info       machine-readable, for merging / external tools
#   - coverage.json   llvm-cov export JSON, input to the gap report
#   - coverage-gaps.md  the QA-facing report (ranked by uncovered-line impact)
#   - html/           browsable HTML report (with --html)
#
# This is report-only: it never fails on low coverage, only on a genuine
# tooling/test error. It is the same path CI's coverage.yml runs.
#
# The KVM-gated integration tests self-skip unless IZBA_INTEGRATION=1 is set in
# the environment (identical to `cargo test`); set it to fold real-VM-exercised
# host paths into the numbers.
#
# Usage:
#   hack/coverage.sh [--html] [--open] [--top N] [-- <extra cargo test args>]
set -euo pipefail
cd "$(dirname "$0")/.."

# Sandbox-local toolchain, if present (matches the rest of the build).
[ -f .cargo-env ] && source .cargo-env

HTML=0
OPEN=0
TOP=25
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --html) HTML=1 ;;
    --open) HTML=1; OPEN=1 ;;
    --top) shift; TOP="$1" ;;
    --) shift; EXTRA=("$@"); break ;;
    -h|--help) sed -n '1,20p' "$0"; exit 0 ;;
    *) echo "coverage.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
  shift
done

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: cargo-llvm-cov is not installed.

Install it once with:
    rustup component add llvm-tools-preview
    cargo install cargo-llvm-cov

(See https://github.com/taiki-e/cargo-llvm-cov for details.)
EOF
  exit 1
fi

OUT="target/coverage"
mkdir -p "$OUT"

# Drop integration-test harness files and any build output from the report:
# they are not production code, so counting them as "uncovered" is noise.
IGNORE='(/tests/|/target/|/build\.rs$)'

echo "==> running tests under coverage instrumentation (IZBA_INTEGRATION=${IZBA_INTEGRATION:-unset})"
# Run the suite once, keep the raw profile data; then render each format from it
# so tests are not recompiled or re-run per output. --no-fail-fast so a single
# failing/flaky test does not abort the whole run and wipe the report — the
# report is always generated below; the test exit status is surfaced at the end
# (and CI's linux-gates job remains the authoritative test gate).
set +e
cargo llvm-cov --no-report --no-fail-fast --workspace "${EXTRA[@]}"
TEST_STATUS=$?
set -e
if [ "$TEST_STATUS" -ne 0 ]; then
  echo "WARNING: tests exited non-zero ($TEST_STATUS); coverage reflects only the tests that ran." >&2
fi

echo "==> generating lcov + json reports"
cargo llvm-cov report --lcov --output-path "$OUT/lcov.info" --ignore-filename-regex "$IGNORE"
cargo llvm-cov report --json --output-path "$OUT/coverage.json" --ignore-filename-regex "$IGNORE"

if [ "$HTML" = 1 ]; then
  echo "==> generating HTML report"
  cargo llvm-cov report --html --output-dir "$OUT/html" --ignore-filename-regex "$IGNORE"
fi

echo "==> writing QA gap report"
python3 hack/coverage_report.py "$OUT/coverage.json" --out "$OUT/coverage-gaps.md" --top "$TOP"

echo
echo "coverage artifacts in $OUT/:"
echo "  - $OUT/coverage-gaps.md  (QA gap report)"
echo "  - $OUT/lcov.info"
echo "  - $OUT/coverage.json"
# cargo-llvm-cov nests the HTML under <output-dir>/html/.
HTML_INDEX="$OUT/html/html/index.html"
[ "$HTML" = 1 ] && echo "  - $HTML_INDEX"

if [ "$OPEN" = 1 ]; then
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$HTML_INDEX" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open "$HTML_INDEX" || true
  fi
fi

# Report-only on coverage, but surface a genuine test failure so CI shows red
# (the report artifact still uploads via the workflow's `if: always()` steps).
exit "$TEST_STATUS"
