#!/usr/bin/env bash
# Manual GUI-dogfood smoke: build the dogfood dist + sidecar, then run ONE
# fake-model journey against a real izbad. Requires a working izba install
# (real microVMs) + agent-browser on PATH. NOT a CI gate — a dev sanity check.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT/app" && npm ci && npm run build:dogfood
cd "$ROOT/app/src-tauri" && cargo build --release --bin headless
DIST="$ROOT/app/dist"
SIDE="$ROOT/app/src-tauri/target/release/headless"
DATA="$(mktemp -d /tmp/izd-smoke.XXXX)"
python3 "$ROOT/hack/dogfood/gui/run_gui_journeys.py" \
  --journeys "$ROOT/hack/dogfood/fixtures/journeys.gui-skeleton.json" \
  --izba-bin "$(command -v izba)" \
  --sidecar-bin "$SIDE" \
  --frontend-dir "$DIST" \
  --data-dir "$DATA" \
  --out /tmp/gui-traj.json \
  --fake-model '[{"read":true},{"done":true}]'
echo "wrote /tmp/gui-traj.json"
