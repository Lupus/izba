#!/usr/bin/env bash
# hack/mutants-gate.sh — incremental cargo-mutants gate for a PR.
#
# Runs cargo-mutants only on the lines changed vs the merge-base of <base_ref>.
# Any surviving (uncaught) mutant on changed lines fails the gate; the author
# must add a killing test or apply `#[mutants::skip]` with justification.
# Excludes from .cargo/mutants.toml apply here too, so a diff touching only
# KVM-only code generates zero mutants and passes trivially.
#
# Usage: hack/mutants-gate.sh <base_ref>   (e.g. hack/mutants-gate.sh origin/main)
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
[[ -f .cargo-env ]] && source .cargo-env

BASE_REF="${1:?usage: mutants-gate.sh <base_ref>}"
OUT="$(mktemp -d)"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# The base ref must resolve, else the 3-dot diff below is a fatal git error that
# set -e would surface opaquely. A bare `git fetch origin <base>` only updates
# FETCH_HEAD, so the workflow must fetch into refs/remotes/origin/<base>.
if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  echo "## ⚠️ Mutation gate: base ref '$BASE_REF' does not resolve (fetch it into a ref first)" >> "$SUMMARY"
  exit 1
fi

# 3-dot diff = changes since the merge-base (what the PR actually introduces).
git diff "${BASE_REF}...HEAD" > "$OUT/pr.diff"

if [[ ! -s "$OUT/pr.diff" ]]; then
  echo "## Mutation gate: no diff vs ${BASE_REF} — skipped" >> "$SUMMARY"
  exit 0
fi

# Run the gate. cargo-mutants exits non-zero if mutants survive OR on a baseline
# failure; we distinguish those (and the "nothing to mutate" case) below.
set +e
cargo mutants --in-diff "$OUT/pr.diff" -o "$OUT/run" 2> "$OUT/stderr"
CM_RC=$?
set -e

if [[ ! -d "$OUT/run/mutants.out" ]]; then
  if [[ $CM_RC -eq 0 ]]; then
    # No mutable Rust lines in the diff (e.g. docs/CI-only change) -> clean pass.
    # cargo-mutants exits 0 and writes no mutants.out in this case.
    echo "## Mutation gate: no mutable Rust changes in the diff — passed" >> "$SUMMARY"
    exit 0
  fi
  # Non-zero exit with no output dir -> cargo-mutants never reached the testing
  # phase -> baseline/build failure.
  {
    echo "## ⚠️ Mutation gate: baseline failure (not a survivor failure)"
    echo '```'
    tail -40 "$OUT/stderr"
    echo '```'
  } >> "$SUMMARY"
  exit 1
fi

# Render survivors (exit 1 if any) via the shared reporter.
{
  echo "## Mutation gate (incremental, vs ${BASE_REF})"
  echo
} >> "$SUMMARY"
set +e
python3 hack/mutants-report.py --mode gate "$OUT/run/mutants.out" >> "$SUMMARY"
GATE_RC=$?
set -e

if [[ $GATE_RC -ne 0 ]]; then
  {
    echo
    echo "❌ Surviving mutants on changed lines. Add a killing test, or apply"
    # shellcheck disable=SC2016  # literal backtick text is intentional, no expansion wanted
    echo '`#[mutants::skip]` with a justification comment (see CONTRIBUTING.md).'
  } >> "$SUMMARY"
fi
exit $GATE_RC
