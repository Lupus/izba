#!/usr/bin/env bash
# Build a static passt (user-mode networking with --vhost-user) from a pinned
# source snapshot. Ubuntu 24.04's packaged passt (0.0~git20240220) predates
# vhost-user support, which izba requires (see hack/fetch-artifacts.sh §3).
#
# Output: dist/passt-2026_05_26-static-x86_64
# Install: sudo install -m755 dist/passt-2026_05_26-static-x86_64 /usr/local/bin/passt
set -euo pipefail

cd "$(dirname "$0")/.."

TAG="2026_05_26.038c51e"
SHORT="2026_05_26"
SHA256="91df73b3d5a9bd6cac70087a5592414598d4be282e5d4f314dd03bf6d6e5e771"
URL="https://passt.top/passt/snapshot/passt-${TAG}.tar.gz"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/izba/passt"
SRC_DIR="$CACHE_DIR/passt-$TAG"
OUT="dist/passt-${SHORT}-static-x86_64"

MISSING=""
for tool in curl tar make gcc sha256sum file; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    echo "error: missing tools:$MISSING" >&2
    echo "install with: sudo apt-get install -y curl tar make gcc coreutils file" >&2
    exit 1
fi

mkdir -p "$CACHE_DIR" dist
TARBALL="$CACHE_DIR/passt-$TAG.tar.gz"
if [ ! -f "$TARBALL" ]; then
    curl -fsSL -o "$TARBALL.part" "$URL"
    mv "$TARBALL.part" "$TARBALL"
fi
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null; then
    GOT=$(sha256sum "$TARBALL" | cut -d' ' -f1)
    rm -f "$TARBALL"
    echo "error: passt tarball sha256 mismatch (got $GOT, want $SHA256); deleted" >&2
    exit 1
fi

rm -rf "$SRC_DIR"
tar -xzf "$TARBALL" -C "$CACHE_DIR"

LOG="$CACHE_DIR/build.log"
if ! make -C "$SRC_DIR" -j"$(nproc)" static >"$LOG" 2>&1; then
    echo "error: passt build failed; last 30 lines of $LOG:" >&2
    tail -30 "$LOG" >&2
    exit 1
fi

install -m755 "$SRC_DIR/passt" "$OUT"
file "$OUT" | grep -q "statically linked" || {
    echo "error: $OUT is not statically linked: $(file "$OUT")" >&2
    exit 1
}
"./$OUT" --help 2>&1 | grep -q vhost-user || {
    echo "error: built passt does not advertise --vhost-user" >&2
    exit 1
}
echo "OK: $OUT ($(stat -c%s "$OUT") bytes)"
