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
TOOLS="curl tar make gcc autoconf automake libtoolize pkg-config patch"
[[ "$LINUX_ONLY" = "--linux-only" ]] || TOOLS="$TOOLS x86_64-w64-mingw32-gcc x86_64-w64-mingw32-objdump"
MISSING=""
for tool in $TOOLS; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [[ -n "$MISSING" ]]; then
    echo "error: missing tools:$MISSING" >&2
    echo "install with: sudo apt-get install -y curl tar make gcc autoconf automake libtool-bin pkg-config patch gcc-mingw-w64-x86-64" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch (cached) + verify + fresh extract + patch
# ---------------------------------------------------------------------------
mkdir -p "$CACHE_DIR"
TARBALL="$CACHE_DIR/erofs-utils-$VERSION.tar.gz"
[[ -f "$TARBALL" ]] || curl -fsSL -o "$TARBALL" "$URL"
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null; then
    rm -f "$TARBALL"
    echo "error: $TARBALL failed sha256 verification — removed; re-run to re-download" >&2
    exit 1
fi

rm -rf "$SRC_DIR"
tar -xzf "$TARBALL" -C "$CACHE_DIR"

shopt -s nullglob
for p in "$PATCH_DIR"/*.patch; do
    echo "applying $(basename "$p")"
    patch -d "$SRC_DIR" -p1 --fuzz=0 --no-backup-if-mismatch < "$p"
done
shopt -u nullglob

(cd "$SRC_DIR" && ./autogen.sh) >"$CACHE_DIR/autogen.log" 2>&1 \
    || { tail -30 "$CACHE_DIR/autogen.log" >&2; echo "full log: $CACHE_DIR/autogen.log" >&2; exit 1; }

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
    || { tail -30 "$BUILD_LINUX/build.log" >&2; echo "full log: $BUILD_LINUX/build.log" >&2; exit 1; }
echo "linux reference: $BUILD_LINUX/mkfs/mkfs.erofs"

[[ "$LINUX_ONLY" = "--linux-only" ]] && exit 0

# ---------------------------------------------------------------------------
# Windows cross build
# ---------------------------------------------------------------------------
BUILD_WIN="$CACHE_DIR/build-win32"
rm -rf "$BUILD_WIN" && mkdir -p "$BUILD_WIN"

# libtool refuses raw .o files in LIBS; hand it a static archive instead.
x86_64-w64-mingw32-gcc -O2 -D_FILE_OFFSET_BITS=64 -I"$COMPAT_DIR" \
    -c "$COMPAT_DIR/erofs_mingw.c" -o "$BUILD_WIN/erofs_mingw.o"
x86_64-w64-mingw32-ar rcs "$BUILD_WIN/liberofs_mingw.a" "$BUILD_WIN/erofs_mingw.o"

# ac_cv_c_undeclared_builtin_options: the force-included compat header drags
# in declarations that defeat autoconf's strchr probe; 'none needed' is
# correct for gcc and only AC_CHECK_DECL(memrchr) depends on it (a link-time
# failure would surface any wrong guess).
# -Werror=implicit-function-declaration: on a 64-bit target an implicitly
# declared function returning a pointer gets truncated to int — make every
# missing shim a hard compile error instead of a runtime crash.
#
# Only lib + mkfs are built: fsck/dump need dir-walk/device-node APIs that
# tar-mode never touches (the parity gate uses the Linux fsck.erofs).
(cd "$BUILD_WIN" && \
    CPPFLAGS="-I$COMPAT_DIR -include $COMPAT_DIR/erofs_mingw.h -D_FILE_OFFSET_BITS=64" \
    CFLAGS="-g -O2 -Werror=implicit-function-declaration -Werror=int-conversion -Werror=incompatible-pointer-types" \
    LIBS="-L$BUILD_WIN -lerofs_mingw" \
    ac_cv_c_undeclared_builtin_options='none needed' \
    "$SRC_DIR/configure" --host=x86_64-w64-mingw32 "${CONFIGURE_FLAGS[@]}" \
    && make -j"$(nproc)" -C lib && make -j"$(nproc)" -C mkfs) \
    >"$BUILD_WIN/build.log" 2>&1 \
    || { tail -40 "$BUILD_WIN/build.log" >&2; echo "full log: $BUILD_WIN/build.log" >&2; exit 1; }

# Multithreading-off assertion: autoconf silently ignores unknown --disable
# flags, so a future pin bump could no-op --disable-multithreading and turn
# the seek/read pread shim into a silent corruption race.  Verify config.h
# explicitly — expect the undef form; a #define means MT crept back in.
if grep -q "^#define EROFS_MT_ENABLED" "$BUILD_WIN/config.h" 2>/dev/null; then
    echo "error: EROFS_MT_ENABLED is #define'd in $BUILD_WIN/config.h" >&2
    echo "  --disable-multithreading had no effect; the pread/pwrite seek shim" >&2
    echo "  is unsafe under multithreading. Check the erofs-utils version." >&2
    exit 1
fi

# mkfs/mkfs.erofs.exe is only libtool's wrapper; the real PE lives in .libs/.
EXE="$BUILD_WIN/mkfs/.libs/mkfs.erofs.exe"
[[ -f "$EXE" ]] || EXE="$BUILD_WIN/mkfs/mkfs.erofs.exe"
[[ -f "$EXE" ]] || { echo "error: mkfs.erofs.exe not produced" >&2; exit 1; }

# Import assertion (spec §3.2): only kernel32 + msvcrt allowed.
IMPORTS="$(x86_64-w64-mingw32-objdump -p "$EXE" | awk '/DLL Name/{print tolower($3)}' | sort -u)"
BAD="$(echo "$IMPORTS" | grep -Ev '^(kernel32\.dll|msvcrt\.dll)$' || true)"
if [[ -n "$BAD" ]]; then
    echo "error: unexpected DLL imports:" >&2
    echo "$BAD" >&2
    exit 1
fi

mkdir -p dist
cp "$EXE" dist/mkfs.erofs.exe
echo "windows binary: dist/mkfs.erofs.exe (imports: $(echo "$IMPORTS" | tr '\n' ' '))"
