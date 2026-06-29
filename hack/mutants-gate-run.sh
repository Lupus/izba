#!/usr/bin/env bash
# hack/mutants-gate-run.sh — per-platform half of the incremental cargo-mutants
# gate. Runs cargo-mutants on ONLY the lines changed vs <base_ref> and leaves the
# raw mutants.out in <out_dir> for the aggregator to reconcile across platforms.
#
# It does NOT decide pass/fail on survivors — the aggregator does, using the
# caught-nowhere rule (a mutant is a real gap only if NO platform caught it).
# This compensates for cargo-mutants not understanding #[cfg]: a cfg(windows)
# mutant is "missed" on Linux (cfg'd out) but "caught" on Windows.
#
# Exit 0 on a successful run (with or without survivors) or no mutable changes;
# exit 1 only on a genuine baseline/build failure.
#
# An optional <shard> ("k/n") partitions the changed-line mutant set across n
# parallel jobs (cargo-mutants assigns mutant i to shard i%n after the stable
# --no-shuffle ordering, so contiguous slow crates spread round-robin across all
# shards). The aggregator merges every shard's mutants.out with the caught-nowhere
# rule, so the partition is transparent. Omit it to run the whole set in one job.
#
# Usage: hack/mutants-gate-run.sh <base_ref> <out_dir> [<shard k/n>]
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
[[ -f .cargo-env ]] && source .cargo-env

BASE_REF="${1:?usage: mutants-gate-run.sh <base_ref> <out_dir> [<shard k/n>]}"
OUT_DIR="${2:?usage: mutants-gate-run.sh <base_ref> <out_dir> [<shard k/n>]}"
SHARD="${3:-}"
SHARD_ARGS=()
if [[ -n "$SHARD" ]]; then
  SHARD_ARGS=(--shard "$SHARD")
fi
mkdir -p "$OUT_DIR"

# Always leave a mutants.out the aggregator can read, even when nothing ran.
_empty_out() {
  mkdir -p "$OUT_DIR/mutants.out"
  : > "$OUT_DIR/mutants.out/missed.txt"
  : > "$OUT_DIR/mutants.out/caught.txt"
}

# The base ref must resolve, else the 3-dot diff is a fatal git error. A bare
# `git fetch origin <base>` only updates FETCH_HEAD, so the workflow must fetch
# into refs/remotes/origin/<base>.
if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  echo "mutants-gate-run: base ref '$BASE_REF' does not resolve" >&2
  exit 1
fi

# 3-dot diff = changes since the merge-base (what the PR actually introduces).
git diff "${BASE_REF}...HEAD" > "$OUT_DIR/pr.diff"
if [[ ! -s "$OUT_DIR/pr.diff" ]]; then
  echo "mutants-gate-run: no diff vs ${BASE_REF}"
  _empty_out
  exit 0
fi

set +e
cargo mutants --no-shuffle "${SHARD_ARGS[@]}" --in-diff "$OUT_DIR/pr.diff" -o "$OUT_DIR/run" 2> "$OUT_DIR/stderr"
CM_RC=$?
set -e

if [[ -d "$OUT_DIR/run/mutants.out" ]]; then
  cp -r "$OUT_DIR/run/mutants.out" "$OUT_DIR/mutants.out"
  exit 0
fi

# No output dir produced.
if [[ $CM_RC -eq 0 ]]; then
  # No mutable Rust lines in the diff (e.g. docs/CI-only change) -> clean pass.
  echo "mutants-gate-run: no mutable Rust changes in the diff"
  _empty_out
  exit 0
fi

# Non-zero exit with no output dir -> baseline/build failure.
echo "mutants-gate-run: baseline failure" >&2
tail -40 "$OUT_DIR/stderr" >&2 || true
exit 1
