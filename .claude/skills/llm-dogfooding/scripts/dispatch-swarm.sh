#!/usr/bin/env bash
# dispatch-swarm.sh — Phase 2 glue for LLM dogfooding. Validates a journeys.json,
# pushes a throwaway `dogfood-run/<feature>` branch off origin/main (NO PR),
# triggers the report-only `dogfood.yml` swarm, watches it, and downloads the
# per-shard trajectory bundles.
#
# Usage: dispatch-swarm.sh <feature> <journeys.json> [shards] [max_usd] [model]
#   defaults: shards=3  max_usd=3  model=(workflow default, cheap)
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
BRANCH="dogfood-run/${FEATURE}"
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

echo "== pushing dispatch branch $BRANCH off origin/main (no PR) =="
git fetch origin main
TMP_WT="$(mktemp -d)"; trap 'git worktree remove --force "$TMP_WT" 2>/dev/null || true' EXIT
git worktree add -q -B "$BRANCH" "$TMP_WT" origin/main
cp "$JOURNEYS" "$TMP_WT/journeys.json"
git -C "$TMP_WT" add journeys.json
git -C "$TMP_WT" commit -q -m "dogfood: journeys for ${FEATURE} (dispatch-only; not for merge)"
git -C "$TMP_WT" push -f origin "HEAD:refs/heads/${BRANCH}"

echo "== dispatching dogfood.yml (shards=$SHARDS max_usd=$MAX_USD) =="
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
echo "bundles:"; find "$OUTDIR" -name 'traj-*.json' | sort
echo
echo "next: scripts/collect-trajectories.py $OUTDIR  → then dispatch the trajectory-skeptic subagent."
echo "cleanup when done: git push origin --delete $BRANCH"
