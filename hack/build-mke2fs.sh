#!/usr/bin/env bash
# Build a static x86_64 mke2fs from pinned e2fsprogs sources.
#
# Usage:  hack/build-mke2fs.sh [OUTPUT]
#         OUTPUT defaults to dist/mke2fs-<version>-static-x86_64
#
# The result is the binary embedded into the initramfs via
# IZBA_MKE2FS (see build-initramfs.sh) so the guest can format a blank
# rw.img on first boot.  Source tarball is sha256-verified before use.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

VERSION=1.47.2
# sha256 from https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.2/sha256sums.asc
SHA256=08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c
URL="https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${VERSION}/e2fsprogs-${VERSION}.tar.xz"

OUTPUT="${1:-dist/mke2fs-${VERSION}-static-x86_64}"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/izba/e2fsprogs"
TARBALL="$CACHE/e2fsprogs-${VERSION}.tar.xz"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
# musl-gcc gives a truly static binary with no glibc NSS caveats.
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "error: musl-gcc not found — install it with:" >&2
    echo "  sudo apt-get install -y musl-tools" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch (cached) + verify
# ---------------------------------------------------------------------------
mkdir -p "$CACHE"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$URL"
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$TARBALL"
    echo "error: $TARBALL failed sha256 verification — removed; re-run to re-download" >&2
    exit 1
fi
echo "sha256 OK: e2fsprogs-${VERSION}.tar.xz"

# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------
SRC="$CACHE/e2fsprogs-${VERSION}"
[ -d "$SRC" ] || tar -C "$CACHE" -xf "$TARBALL"

# ---------------------------------------------------------------------------
# Configure + build
# ---------------------------------------------------------------------------
BUILD="$CACHE/build-static"
rm -rf "$BUILD" && mkdir -p "$BUILD"
cd "$BUILD"
"$SRC/configure" CC=musl-gcc CFLAGS="-O2" LDFLAGS="-static" \
    --disable-nls --disable-elf-shlibs --disable-uuidd \
    --disable-fuse2fs --disable-debugfs --disable-imager \
    --disable-resizer --disable-defrag \
    >/dev/null
make -j"$(nproc)" libs >/dev/null
make -j"$(nproc)" -C misc mke2fs >/dev/null

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
cd "$REPO_ROOT"
mkdir -p "$(dirname "$OUTPUT")"
cp "$BUILD/misc/mke2fs" "$OUTPUT"
chmod 755 "$OUTPUT"

if ! file "$OUTPUT" | grep -q "statically linked"; then
    echo "error: $OUTPUT is not statically linked" >&2
    exit 1
fi
echo "wrote $OUTPUT ($(du -sh "$OUTPUT" | cut -f1), static)"
