#!/usr/bin/env bash
# Manual GUI-dogfood smoke: build the dogfood dist + sidecar, then run ONE
# fake-model journey against a real izbad. Requires a working izba install
# (real microVMs) + agent-browser on PATH. NOT a CI gate — a dev sanity check.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT/app" && npm ci --ignore-scripts && npm run build:dogfood
cd "$ROOT/app/src-tauri" && cargo build --release --bin headless
DIST="$ROOT/app/dist"
SIDE="$ROOT/app/src-tauri/target/release/headless"
DATA="$(mktemp -d /tmp/izd-smoke.XXXX)"
# The runner exits 3 (EXIT_CATASTROPHIC_INFRA) when >50% of attempted
# journeys are degraded, after writing the trajectory bundle. This smoke
# script drives the 5-journey gui-skeleton fixture with a thin 2-reply
# fake-model script, so journeys 2-5 get zero actions and trip that backstop
# even though the bundle itself is fine — tolerate rc=3 here, but not other
# nonzero exits (those are real failures).
rc=0
python3 "$ROOT/hack/dogfood/gui/run_gui_journeys.py" \
  --journeys "$ROOT/hack/dogfood/fixtures/journeys.gui-skeleton.json" \
  --izba-bin "$(command -v izba)" \
  --sidecar-bin "$SIDE" \
  --frontend-dir "$DIST" \
  --data-dir "$DATA" \
  --out /tmp/gui-traj.json \
  --fake-model '[{"read":true},{"done":true}]' || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  exit "$rc"
fi
if [ "$rc" -eq 3 ]; then
  echo "note: runner exited 3 (catastrophic-infra backstop) — expected here, the thin fake-model script starves journeys 2-5 of actions"
fi
echo "wrote /tmp/gui-traj.json"
