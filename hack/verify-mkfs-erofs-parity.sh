#!/usr/bin/env bash
# Parity gate for the Windows mkfs.erofs build: the cross-built .exe must
# produce a BYTE-IDENTICAL image to the same-source Linux reference binary.
#
# Exit codes:  0 parity proven (wine present)
#              1 divergence or build/fsck failure
#              2 Windows leg skipped (no wine) — bundle emitted to
#                dist/erofs-parity-bundle/ for hack/spike/verify-mkfs-erofs-parity.ps1
#
# Env overrides: IZBA_EROFS_CACHE (build dir), IZBA_EROFS_EXE (the .exe)
set -euo pipefail

cd "$(dirname "$0")/.."
CACHE="${IZBA_EROFS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils}"
LINUX_MKFS="$CACHE/build-linux/mkfs/mkfs.erofs"
LINUX_FSCK="$CACHE/build-linux/fsck/fsck.erofs"
EXE="${IZBA_EROFS_EXE:-dist/mkfs.erofs.exe}"
for f in "$LINUX_MKFS" "$LINUX_FSCK" "$EXE"; do
    [ -f "$f" ] || { echo "error: $f missing — run hack/build-mkfs-erofs-windows.sh first" >&2; exit 1; }
done

# Shared deterministic flags: -T0 pins timestamps, -U pins the volume UUID.
UUID=11111111-2222-3333-4444-555555555555
MKFS_FLAGS=(--tar=f -T0 -U "$UUID" --quiet)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Deterministic fixture: regular/empty/8KiB files, symlink, hardlink, nested
# dirs, mode variety — every ustar field class izba's flattened images use.
# Two batches with different uid/gid ownership (0:0 and 1000:100) so a Windows
# bug that substitutes the process uid for the ustar-header uid stays visible.
# ---------------------------------------------------------------------------
FIX="$WORK/fixture"
mkdir -p "$FIX/bin" "$FIX/deep/a/b/c"
printf 'hello erofs\n'        > "$FIX/hello.txt"
: > "$FIX/empty"
head -c 8192 /dev/zero | tr '\0' 'x' > "$FIX/bin/big8k.bin"
printf 'nested leaf\n'        > "$FIX/deep/a/b/c/leaf"
ln -s ../hello.txt              "$FIX/bin/link-to-hello"
ln "$FIX/hello.txt"             "$FIX/hardlink-hello"
chmod 755 "$FIX/bin/big8k.bin"
chmod 600 "$FIX/deep/a/b/c/leaf"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime=@0 -C "$FIX" -cf "$WORK/fixture.tar" . \
    || { echo "error: fixture tar (batch 1) failed" >&2; exit 1; }

# Batch 2: nonzero uid/gid — files land under owned/ (distinct paths avoid
# duplicate-entry ambiguity; later entries win in mkfs tar-mode anyway).
FIX2="$WORK/fixture2"
mkdir -p "$FIX2/owned"
printf 'owned file\n'  > "$FIX2/owned/owned.txt"
printf 'owned other\n' > "$FIX2/owned/other.txt"
tar --format=ustar --sort=name --owner=1000 --group=100 --numeric-owner \
    --mtime=@0 -C "$FIX2" -rf "$WORK/fixture.tar" . \
    || { echo "error: fixture tar (batch 2) failed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Reference image (Linux binary) + fsck
# ---------------------------------------------------------------------------
"$LINUX_MKFS" "${MKFS_FLAGS[@]}" "$WORK/ref.erofs" "$WORK/fixture.tar" \
    || { echo "error: Linux mkfs.erofs failed" >&2; exit 1; }
"$LINUX_FSCK" "$WORK/ref.erofs" \
    || { echo "error: Linux fsck.erofs failed" >&2; exit 1; }
REF_SHA="$(sha256sum "$WORK/ref.erofs" | cut -d' ' -f1)"
echo "reference: sha256=$REF_SHA ($(stat -c%s "$WORK/ref.erofs") bytes)"

# ---------------------------------------------------------------------------
# Windows leg: wine if available, else emit a bundle and skip
# ---------------------------------------------------------------------------
if ! command -v wine >/dev/null 2>&1; then
    BUNDLE=dist/erofs-parity-bundle
    rm -rf "$BUNDLE" && mkdir -p "$BUNDLE"
    cp "$EXE" "$BUNDLE/mkfs.erofs.exe"
    cp "$WORK/fixture.tar" "$BUNDLE/"
    echo "$REF_SHA" > "$BUNDLE/reference.sha256"
    printf '%s\n' "${MKFS_FLAGS[@]}" > "$BUNDLE/mkfs-flags.txt"
    echo "SKIP: wine not installed — bundle at $BUNDLE/;"
    echo "  run hack/spike/verify-mkfs-erofs-parity.ps1 on the Windows host."
    exit 2
fi
WINEDEBUG=-all wine "$EXE" "${MKFS_FLAGS[@]}" "$WORK/win.erofs" "$WORK/fixture.tar" \
    || { echo "error: wine mkfs.erofs.exe failed" >&2; exit 1; }
if cmp -s "$WORK/ref.erofs" "$WORK/win.erofs"; then
    echo "PASS: byte-identical images from Linux and Windows binaries"
else
    cmp "$WORK/ref.erofs" "$WORK/win.erofs" || true
    echo "FAIL: images diverge" >&2
    exit 1
fi
