#!/usr/bin/env bash
# Build the izba initramfs: static izba-init (+ optional static mke2fs).
#
# Usage:
#   hack/build-initramfs.sh [OUTPUT]
#   OUTPUT defaults to dist/initramfs.cpio.gz
#
# Environment:
#   IZBA_MKE2FS=/path/to/static/mke2fs  (optional)
#       If set, the binary is embedded in /sbin/mke2fs so the guest can
#       format the blank rw disk on first boot without a host-side mkfs.
set -euo pipefail

# Always run from repo root so cargo can find the workspace.
cd "$(dirname "$0")/.."

# Source the repo-local cargo/rustup if present.
# shellcheck disable=SC1091
[ -f .cargo-env ] && source .cargo-env

# Verify that cpio is available before doing anything expensive.
if ! command -v cpio >/dev/null 2>&1; then
    echo "error: 'cpio' not found — install it with:" >&2
    echo "  sudo apt-get install -y cpio" >&2
    exit 1
fi

OUTPUT="${1:-dist/initramfs.cpio.gz}"
mkdir -p "$(dirname "$OUTPUT")"

echo "Building izba-init (musl static)..."
cargo build -p izba-init --target x86_64-unknown-linux-musl --release

INIT_BIN="target/x86_64-unknown-linux-musl/release/izba-init"
if [ ! -f "$INIT_BIN" ]; then
    echo "error: expected $INIT_BIN after cargo build" >&2
    exit 1
fi

# Build the initramfs tree in a temp directory; clean up on exit.
WORK="$(mktemp -d)"
chmod 755 "$WORK"  # mktemp creates 700; initramfs root must be world-traversable
trap 'rm -rf "$WORK"' EXIT

# Minimal directory skeleton that izba-init expects to find at boot.
mkdir -p "$WORK/sbin" "$WORK/proc" "$WORK/sys" "$WORK/dev" \
         "$WORK/tmp" "$WORK/lower" "$WORK/upper" "$WORK/rootfs"

# /init must be at the root and executable.
cp "$INIT_BIN" "$WORK/init"
chmod 755 "$WORK/init"

# Optional static mke2fs — enables in-guest first-boot formatting of rw.img
# when the host-side mkfs.ext4 pre-format did not run or is unavailable.
if [ -n "${IZBA_MKE2FS:-}" ]; then
    if [ ! -f "$IZBA_MKE2FS" ]; then
        echo "error: IZBA_MKE2FS='$IZBA_MKE2FS' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_MKE2FS" "$WORK/sbin/mke2fs"
    chmod 755 "$WORK/sbin/mke2fs"
    echo "  embedded mke2fs from $IZBA_MKE2FS"
fi

# Optional static nft — required for the izbad-egress TCP REDIRECT stub.
if [ -n "${IZBA_NFT:-}" ]; then
    if [ ! -f "$IZBA_NFT" ]; then
        echo "error: IZBA_NFT='$IZBA_NFT' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_NFT" "$WORK/sbin/nft"
    chmod 755 "$WORK/sbin/nft"
    echo "  embedded nft from $IZBA_NFT"
fi

# Pack the tree into a newc cpio archive and gzip it.
#
# We include '.' (the root entry) by running find from inside WORK.  The
# leading './' is stripped from paths by cpio's own output, giving correct
# /init, /sbin/mke2fs, etc. entries without a double-slash prefix.
#
# Sorting the find output makes the archive reproducible.
echo "Packing initramfs..."
( cd "$WORK" && find . | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -9 ) > "$OUTPUT"

SIZE="$(du -sh "$OUTPUT" | cut -f1)"
echo "wrote $OUTPUT  ($SIZE)"
