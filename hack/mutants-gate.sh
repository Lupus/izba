#!/usr/bin/env bash
# hack/mutants-gate.sh — local, single-platform incremental gate convenience
# wrapper: run the changed-line mutants for this platform and report survivors.
#
# CI uses the two halves directly (mutants-gate-run.sh per platform + the shared
# reporter as a cross-platform aggregator) so it can apply the caught-nowhere
# rule across Linux and Windows. Locally, this single-platform view is usually
# what you want while iterating.
#
# Usage: hack/mutants-gate.sh <base_ref>   (e.g. hack/mutants-gate.sh origin/main)
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_REF="${1:?usage: mutants-gate.sh <base_ref>}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT   # mutants.out can be hundreds of MB; clean up on any exit
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# Produce this platform's mutants.out (exits 1 on a baseline failure).
if ! hack/mutants-gate-run.sh "$BASE_REF" "$OUT"; then
  echo "## ⚠️ Mutation gate: baseline failure (not a survivor failure)" >> "$SUMMARY"
  exit 1
fi

{
  echo "## Mutation gate (incremental, single-platform, vs ${BASE_REF})"
  echo
} >> "$SUMMARY"
set +e
python3 hack/mutants-report.py --mode gate "$OUT/mutants.out" >> "$SUMMARY"
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
