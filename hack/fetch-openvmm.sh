#!/usr/bin/env bash
# Fetch the pinned OpenVMM CI artifact (Windows x64) into dist/.
#
# OpenVMM ships no binary releases; we pin a CI run of microsoft/openvmm.
# GitHub artifacts EXPIRE (~90 days). Re-pin procedure when the download 404s:
#   1. gh run list -R microsoft/openvmm -w openvmm-ci.yaml -b main -L 5
#   2. pick the newest green run, update RUN_ID + COMMIT below
#   3. run this script, paste the printed sha256 into SHA256 below
#   4. re-run the Plan-2 validation suite before committing the new pin
#   5. upload the byte-identical openvmm.exe as the asset of a new
#      MIRROR_TAG pre-release on Lupus/izba and update MIRROR_TAG below
#
# Mirror: the upstream artifact expiring must not break every Windows build
# until someone re-pins (it did, 2026-09-29). The exact pinned binary is
# re-hosted as a release asset (releases do not expire) and used only when
# the upstream download fails. It is held to the SAME sha256 pin, so the
# mirror can never introduce a different VMM — it is a second source for the
# one vetted binary, not a second pin.
set -euo pipefail

# Pin: spike S1+ provenance (2026-06-10), branch main.
RUN_ID="27240809751"
COMMIT="7872712037c6ce3a03087a76207bd73cec9784a2"
ARTIFACT="x64-windows-openvmm"
# sha256 of openvmm.exe from this run; empty = first fetch, record it.
SHA256="96ba8f562bc267bfb9cd659ad35f451ae68d5c4b49e6c9633add46a75229c0aa"
# Lupus/izba pre-release whose `openvmm.exe` asset re-hosts this exact binary.
MIRROR_TAG="openvmm-7872712"

cd "$(dirname "$0")/.."
DIST="dist"
mkdir -p "$DIST"

command -v gh >/dev/null || { echo "error: gh CLI not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "error: gh not authenticated" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching $ARTIFACT from microsoft/openvmm run $RUN_ID (commit ${COMMIT:0:9})..."
if ! gh run download "$RUN_ID" -R microsoft/openvmm -n "$ARTIFACT" -D "$TMP"; then
    # Never fall back while recording a first pin: the mirror is only a
    # second source for an ALREADY-vetted sha256.
    [[ -n "$SHA256" ]] || { echo "error: artifact download failed and no pinned sha256 to verify a mirror against" >&2; exit 1; }
    echo "upstream artifact unavailable (likely EXPIRED); falling back to the Lupus/izba $MIRROR_TAG mirror (same sha256 pin)..."
    gh release download "$MIRROR_TAG" -R Lupus/izba -p openvmm.exe -D "$TMP" \
        || { echo "error: artifact download failed — likely EXPIRED — and the $MIRROR_TAG mirror is unavailable; see re-pin procedure in this script's header" >&2; exit 1; }
fi

EXE="$(find "$TMP" -name openvmm.exe | head -1)"
[[ -n "$EXE" ]] || { echo "error: openvmm.exe not found in artifact" >&2; exit 1; }

GOT="$(sha256sum "$EXE" | cut -d' ' -f1)"
if [[ -z "$SHA256" ]]; then
    echo "NOTE: no pinned sha256 yet — record this in fetch-openvmm.sh:"
    echo "  SHA256=\"$GOT\""
elif [[ "$GOT" != "$SHA256" ]]; then
    echo "error: sha256 mismatch: got $GOT want $SHA256" >&2
    exit 1
fi

cp "$EXE" "$DIST/openvmm.exe"
echo "OK: $DIST/openvmm.exe ($(stat -c%s "$DIST/openvmm.exe") bytes, sha256 $GOT)"
