#!/usr/bin/env bash
# M0 churn gate: izbad-path vsock churn must not kill the VM.
# (Exit criteria from docs/testing.md "vsock churn stressor"; the --direct
# control that DOES kill an unpatched OpenVMM is deliberately not run here.)
#
# Env:
#   IZBA_EXE      path to the izba binary            (default: izba on PATH)
#   TTYSTORM_EXE  path to the ttystorm example       (default: ttystorm on PATH)
#   IZBA_IMAGE    guest image                        (default: alpine:3.20)
#   IZBA_DATA_DIR honored by izba itself; set it to keep CI state collectable.
# Boot artifacts come from IZBA_KERNEL/IZBA_INITRAMFS or <data>/artifacts.
set -euo pipefail

IZBA_EXE="${IZBA_EXE:-izba}"
TTYSTORM_EXE="${TTYSTORM_EXE:-ttystorm}"
IZBA_IMAGE="${IZBA_IMAGE:-alpine:3.20}"
NAME="stormgate"
WS="$(mktemp -d)"

cleanup() {
    "$IZBA_EXE" rm --force "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap cleanup EXIT

echo "=== ttystorm gate: boot sandbox '$NAME' ==="
"$IZBA_EXE" run --image "$IZBA_IMAGE" --name "$NAME" "$WS" -- /bin/true

echo "=== ttystorm gate: floodfast 20 2048 ==="
"$TTYSTORM_EXE" "$NAME" floodfast 20 2048

echo "=== ttystorm gate: chop 30 256 ==="
"$TTYSTORM_EXE" "$NAME" chop 30 256

echo "=== ttystorm gate: VM survived? ==="
OUT="$("$IZBA_EXE" exec "$NAME" -- echo alive)"
if [[ "$OUT" != "alive" ]]; then
    echo "FAIL: exec after churn returned '$OUT' (VM dead or wedged)" >&2
    exit 1
fi
echo "PASS: VM alive after izbad-path churn"
