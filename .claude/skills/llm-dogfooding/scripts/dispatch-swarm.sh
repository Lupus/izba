#!/usr/bin/env bash
# dispatch-swarm.sh — Phase 2 glue for LLM dogfooding. Validates a journeys.json,
# pushes a throwaway `dogfood-run/<feature>` branch off origin/main (NO PR),
# triggers the report-only `dogfood.yml` swarm, watches it, and downloads the
# per-shard trajectory bundles.
#
# Usage: dispatch-swarm.sh <feature> <journeys.json> [shards] [max_usd] [model]
#   defaults: shards=3  max_usd=3  model=(workflow default, cheap)
#
#   max_usd is a PER-SHARD budget cap (dogfood.yml's setup job derives the CLI
#   and GUI shard counts from `shards`/`gui_shards` + the journey set itself;
#   the GUI job auto-skips when the journey set has no modality:"gui" entries,
#   so the worst case below is shards + 3 gui shards, not shards alone).
#
# Requires network + gh auth → run UNSANDBOXED. Never opens a PR (the ci/app/
# coverage workflows ignore dogfood-run/**; dogfood.yml is workflow_dispatch only).
# Report-only: a run that finds bugs still succeeds; only infra failures fail.
set -euo pipefail

FEATURE="${1:?usage: dispatch-swarm.sh <feature> <journeys.json> [shards] [max_usd] [model]}"
JOURNEYS="${2:?usage: dispatch-swarm.sh <feature> <journeys.json> [shards] [max_usd] [model]}"
SHARDS="${3:-3}"
MAX_USD="${4:-3}"
MODEL="${5:-}"
# DOGFOOD_BRANCH lets a progressive run tag the dispatch branch per tier
# (e.g. dogfood-run/<feature>-smoke) so concurrent tiers don't clobber.
BRANCH="${DOGFOOD_BRANCH:-dogfood-run/${FEATURE}}"
# DOGFOOD_BASE is the ref the dispatch branch is cut from. Default origin/main.
# In a progressive/self-improving loop set it to the CI fixes-branch tip (e.g.
# the local HEAD that carries the in-place doc/help fixes) so the swarm reads
# the LATEST improvements and does not re-stumble on already-fixed gaps.
BASE="${DOGFOOD_BASE:-origin/main}"
SCHEMA="hack/dogfood/schema/journeys.schema.json"
OUTDIR="${DOGFOOD_OUT:-dogfood-artifacts}"

[ -f "$JOURNEYS" ] || { echo "no journeys file: $JOURNEYS" >&2; exit 1; }
[ -f "$SCHEMA" ]   || { echo "schema not found at $SCHEMA — run from the repo root" >&2; exit 1; }

echo "== validating $JOURNEYS against $SCHEMA =="
python3 - "$JOURNEYS" "$SCHEMA" <<'PY'
import json, sys
import jsonschema
data = json.load(open(sys.argv[1])); schema = json.load(open(sys.argv[2]))
jsonschema.validate(data, schema)
ids = [j["journey_id"] for j in data["journeys"]]
assert len(ids) == len(set(ids)), "duplicate journey_id"
print(f"SCHEMA OK: {len(ids)} journeys for {data['feature']!r}")
PY

echo "== pushing dispatch branch $BRANCH off $BASE (no PR) =="
# Only fetch when basing on a remote ref; a local fixes-branch tip is used as-is.
case "$BASE" in origin/*) git fetch origin "${BASE#origin/}" ;; esac
TMP_WT="$(mktemp -d)"; trap 'git worktree remove --force "$TMP_WT" 2>/dev/null || true' EXIT
git worktree add -q -B "$BRANCH" "$TMP_WT" "$BASE"
cp "$JOURNEYS" "$TMP_WT/journeys.json"
git -C "$TMP_WT" add journeys.json
git -C "$TMP_WT" commit -q -m "dogfood: journeys for ${FEATURE} (dispatch-only; not for merge)"
git -C "$TMP_WT" push -f origin "HEAD:refs/heads/${BRANCH}"

echo "== dispatching dogfood.yml (shards=$SHARDS max_usd=$MAX_USD) =="
# awk, not $(( )): max_usd is legitimately fractional (run_journeys --max-usd
# is a float) and bash integer arithmetic would abort the dispatch under
# set -e ("invalid arithmetic operator" on e.g. 2.5) AFTER the branch push.
WORST_CASE="$(awk -v u="$MAX_USD" -v s="$SHARDS" 'BEGIN{printf "%.2f", u*(s+3)}')"
echo "budget: \$${MAX_USD}/shard (worst case \$${WORST_CASE} if GUI runs)"
DISPATCH_ARGS=(--ref "$BRANCH" -f "shards=$SHARDS" -f "max_usd=$MAX_USD")
[ -n "$MODEL" ] && DISPATCH_ARGS+=(-f "model=$MODEL")
gh workflow run dogfood.yml "${DISPATCH_ARGS[@]}"

# resolve the run id (poll briefly for it to register)
RID=""
for _ in $(seq 1 10); do
  sleep 4
  RID="$(gh run list --workflow=dogfood.yml --branch "$BRANCH" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)"
  [ -n "$RID" ] && break
done
[ -n "$RID" ] || { echo "could not find dispatched run for $BRANCH" >&2; exit 1; }
echo "run id: $RID  ($(gh run view "$RID" --json url -q .url))"

echo "== watching run $RID =="
gh run watch "$RID" --exit-status || echo "(run reported non-success — inspect: likely infra, since the swarm is report-only)"

echo "== downloading trajectory bundles to $OUTDIR =="
rm -rf "$OUTDIR"; gh run download "$RID" --dir "$OUTDIR"
echo "bundles:"; find "$OUTDIR" -name '*traj-*.json' | sort
echo
echo "next: scripts/collect-trajectories.py $OUTDIR  → then dispatch the trajectory-skeptic subagent."
echo "cleanup when done: git push origin --delete $BRANCH"
