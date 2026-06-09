#!/usr/bin/env bash
# Build a minimal x86_64 Linux kernel for izba microVMs.
#
# Usage:
#   hack/build-kernel.sh [VERSION [OUTPUT]]
#
#   VERSION  Kernel version to build.  Defaults to 6.12.30 — a known-good
#            6.12 LTS point release.  Any recent stable (6.6+, 6.12+) works.
#   OUTPUT   Destination for the built vmlinux.
#            Defaults to dist/vmlinux (relative to the repo root).
#
# The kernel source tarball is cached in:
#   ${XDG_CACHE_HOME:-$HOME/.cache}/izba/kernel/
# so repeated runs skip the download.
#
# This script CANNOT build the kernel if a C toolchain is absent.  It checks
# for required tools first and prints the exact install command if any are
# missing.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-6.12.30}"
OUTPUT="${2:-dist/vmlinux}"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/izba/kernel"
TARBALL="linux-${VERSION}.tar.xz"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${TARBALL}"
FRAGMENT="$(pwd)/hack/kernel.config"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
MISSING=""
for tool in gcc make flex bison bc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        MISSING="$MISSING $tool"
    fi
done
# libelf is a library; check for the companion header via its dev package.
if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libelf 2>/dev/null; then
    # Fall back: check for the header directly.
    if [ ! -f /usr/include/libelf.h ] && [ ! -f /usr/include/gelf.h ]; then
        MISSING="$MISSING libelf-dev"
    fi
fi

if [ -n "$MISSING" ]; then
    echo "error: the following build dependencies are missing:$MISSING" >&2
    echo "" >&2
    echo "Install them with:" >&2
    echo "  sudo apt-get install -y build-essential flex bison bc libelf-dev" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Download + cache the tarball
# ---------------------------------------------------------------------------
mkdir -p "$CACHE_DIR"
TARBALL_PATH="$CACHE_DIR/$TARBALL"

if [ ! -f "$TARBALL_PATH" ]; then
    echo "Downloading linux-${VERSION}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fL --progress-bar -o "$TARBALL_PATH" "$TARBALL_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$TARBALL_PATH" "$TARBALL_URL"
    else
        echo "error: neither curl nor wget found" >&2
        exit 1
    fi
else
    echo "Using cached tarball: $TARBALL_PATH"
fi

# ---------------------------------------------------------------------------
# Unpack
# ---------------------------------------------------------------------------
BUILD_DIR="$CACHE_DIR/linux-${VERSION}"
if [ ! -d "$BUILD_DIR" ]; then
    echo "Unpacking..."
    tar -C "$CACHE_DIR" -xf "$TARBALL_PATH"
fi
cd "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Configure: x86_64 defconfig, then merge the izba fragment
# ---------------------------------------------------------------------------
echo "Configuring (x86_64_defconfig + izba fragment)..."
make x86_64_defconfig

# merge_config.sh -m: merge the fragment ON TOP of the existing .config
# without interactively asking about new symbols (olddefconfig handles those).
if [ ! -f scripts/kconfig/merge_config.sh ]; then
    echo "error: scripts/kconfig/merge_config.sh not found in kernel tree" >&2
    exit 1
fi
bash scripts/kconfig/merge_config.sh -m .config "$FRAGMENT"
make olddefconfig

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "Building vmlinux ($(nproc) jobs)..."
make -j"$(nproc)" vmlinux

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$(cd - && pwd)")/${OUTPUT%/*}"  # ensure dist/ exists
DEST="$(cd - && pwd)/$OUTPUT"
mkdir -p "$(dirname "$DEST")"
cp vmlinux "$DEST"

SIZE="$(du -sh "$DEST" | cut -f1)"
SHA="$(sha256sum "$DEST" | cut -d' ' -f1)"
echo ""
echo "vmlinux written to: $DEST"
echo "  size:   $SIZE"
echo "  sha256: $SHA"
echo ""
echo "Hint: export IZBA_KERNEL=$(cd - && pwd)/dist/vmlinux"
