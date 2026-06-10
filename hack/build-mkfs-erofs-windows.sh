#!/usr/bin/env bash
# Build mkfs.erofs for Windows (native MinGW-w64, tar-mode only) plus a
# same-source Linux reference binary for the parity gate.
#
# Usage:  hack/build-mkfs-erofs-windows.sh [--linux-only]
#
# Outputs:
#   dist/mkfs.erofs.exe                          (cross build; skipped with --linux-only)
#   $CACHE/build-linux/mkfs/mkfs.erofs           (reference)
#   $CACHE/build-linux/fsck/fsck.erofs           (used by the parity script)
# where CACHE = ${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils
#
# Design: docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

VERSION=1.9.1
SHA256=a9ef5ab67c4b8d2d3e9ed71f39cd008bda653142a720d8a395a36f1110d0c432
URL="https://github.com/erofs/erofs-utils/archive/refs/tags/v${VERSION}.tar.gz"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils"
SRC_DIR="$CACHE_DIR/erofs-utils-$VERSION"
COMPAT_DIR="$REPO_ROOT/hack/mingw-compat"
PATCH_DIR="$REPO_ROOT/hack/patches/erofs-utils"
LINUX_ONLY="${1:-}"

# ---------------------------------------------------------------------------
# Dependency check (mirrors hack/build-kernel.sh)
# ---------------------------------------------------------------------------
TOOLS="curl tar make gcc autoconf automake libtoolize pkg-config"
[ "$LINUX_ONLY" = "--linux-only" ] || TOOLS="$TOOLS x86_64-w64-mingw32-gcc x86_64-w64-mingw32-objdump"
MISSING=""
for tool in $TOOLS; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    echo "error: missing tools:$MISSING" >&2
    echo "install with: sudo apt-get install -y curl tar make gcc autoconf automake libtool-bin pkg-config gcc-mingw-w64-x86-64" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch (cached) + verify + fresh extract + patch
# ---------------------------------------------------------------------------
mkdir -p "$CACHE_DIR"
TARBALL="$CACHE_DIR/erofs-utils-$VERSION.tar.gz"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$URL"
echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null

rm -rf "$SRC_DIR"
tar -xzf "$TARBALL" -C "$CACHE_DIR"

shopt -s nullglob
for p in "$PATCH_DIR"/*.patch; do
    echo "applying $(basename "$p")"
    patch -d "$SRC_DIR" -p1 --no-backup-if-mismatch < "$p"
done
shopt -u nullglob

(cd "$SRC_DIR" && ./autogen.sh) >/dev/null

# Both builds MUST use identical feature flags or the parity gate is
# meaningless: everything optional is off; izba images are uncompressed by
# design (guest kernel has no EROFS decompression) and the bundled
# xxhash.c/uuid.c fallbacks remove all library dependencies.
CONFIGURE_FLAGS=(
    --disable-lz4 --disable-lzma --disable-multithreading
    --disable-fuse --disable-s3 --disable-oci
    --without-zlib --without-libdeflate --without-libzstd --without-qpl
    --without-xxhash --without-libcurl --without-openssl --without-libxml2
    --without-json-c --without-libnl3 --without-uuid --without-selinux
)

# ---------------------------------------------------------------------------
# Linux reference build (also provides fsck.erofs for the parity script)
# ---------------------------------------------------------------------------
BUILD_LINUX="$CACHE_DIR/build-linux"
rm -rf "$BUILD_LINUX" && mkdir -p "$BUILD_LINUX"
(cd "$BUILD_LINUX" && "$SRC_DIR/configure" "${CONFIGURE_FLAGS[@]}" \
    && make -j"$(nproc)") >"$BUILD_LINUX/build.log" 2>&1 \
    || { tail -30 "$BUILD_LINUX/build.log" >&2; exit 1; }
echo "linux reference: $BUILD_LINUX/mkfs/mkfs.erofs"

[ "$LINUX_ONLY" = "--linux-only" ] && exit 0

# ---------------------------------------------------------------------------
# Windows cross build (added in Task 3)
# ---------------------------------------------------------------------------
echo "error: cross build not implemented yet" >&2
exit 1
