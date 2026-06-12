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
MISSING=""
for tool in curl sha256sum tar make file; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    echo "error: missing tools:$MISSING" >&2
    echo "install with: sudo apt-get install -y curl coreutils tar make file musl-tools" >&2
    exit 1
fi
# musl-gcc gives a truly static binary with no glibc NSS caveats.
# It comes from the musl-tools package, not a package named musl-gcc.
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "error: musl-gcc not found — install it with:" >&2
    echo "  sudo apt-get install -y musl-tools" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch (cached) + verify
# ---------------------------------------------------------------------------
mkdir -p "$CACHE"
if [ ! -f "$TARBALL" ]; then
    curl -fsSL -o "$TARBALL.part" "$URL" || { rm -f "$TARBALL.part"; exit 1; }
    mv "$TARBALL.part" "$TARBALL"
fi
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null; then
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
# musl-gcc's sysroot (/usr/include/x86_64-linux-musl) ships no Linux kernel
# headers, so files like linux/unistd.h are missing.  We append the glibc
# kernel-header paths with -idirafter (NOT -I) so they are searched last,
# after musl's own headers win — plain -I would shadow musl headers with
# glibc ones and silently produce a dynamically-linked binary.
# The kernel headers themselves come from linux-libc-dev, pulled in by
# build-essential on every Debian/Ubuntu box we care about.
"$SRC/configure" CC=musl-gcc \
    CFLAGS="-O2 -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu" \
    LDFLAGS="-static" \
    --disable-nls --disable-elf-shlibs --disable-uuidd \
    --disable-fuse2fs --disable-debugfs --disable-imager \
    --disable-resizer --disable-defrag \
    >"$BUILD/build.log" 2>&1 \
    || { tail -30 "$BUILD/build.log" >&2; echo "error: configure failed — full log: $BUILD/build.log" >&2; exit 1; }
make -j"$(nproc)" libs >>"$BUILD/build.log" 2>&1 \
    || { tail -30 "$BUILD/build.log" >&2; echo "error: make libs failed — full log: $BUILD/build.log" >&2; exit 1; }
make -j"$(nproc)" -C misc mke2fs >>"$BUILD/build.log" 2>&1 \
    || { tail -30 "$BUILD/build.log" >&2; echo "error: make mke2fs failed — full log: $BUILD/build.log" >&2; exit 1; }

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
