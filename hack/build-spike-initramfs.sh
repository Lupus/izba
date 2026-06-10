#!/usr/bin/env bash
# Build the SPIKE busybox initramfs (NOT the production izba-init one).
#
# Usage:
#   hack/build-spike-initramfs.sh OUTPUT [RC_FILE]
#   OUTPUT   e.g. dist/spike-initramfs.cpio.gz
#   RC_FILE  optional shell script embedded as /spike.rc, run by /init before
#            dropping to a shell (per-rung test payloads live in hack/spike/rc/)
#
# Environment:
#   BUSYBOX_URL  override the static-busybox download URL.
#
# Note: the docker-library/busybox dist-amd64 branch stores the rootfs tarball
# at latest/musl/amd64/rootfs.tar.gz (a plain .tar.gz containing bin/busybox
# among all applets).  The BUSYBOX_URL default reflects this actual layout.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
[ -f .cargo-env ] && source .cargo-env

OUTPUT="${1:?usage: build-spike-initramfs.sh OUTPUT [RC_FILE]}"
RC_FILE="${2:-}"
mkdir -p "$(dirname "$OUTPUT")"

# Static busybox from the docker-library dist branch (musl, amd64).
# The file latest/musl/busybox.tar.gz is a text pointer ("amd64/rootfs.tar.gz");
# the real archive lives at latest/musl/amd64/rootfs.tar.gz.
BUSYBOX_URL="${BUSYBOX_URL:-https://raw.githubusercontent.com/docker-library/busybox/dist-amd64/latest/musl/amd64/rootfs.tar.gz}"
CACHE="dist/.busybox"
if [ ! -x "$CACHE/bin/busybox" ]; then
    echo "Fetching static busybox..."
    mkdir -p "$CACHE"
    curl -fsSL "$BUSYBOX_URL" | tar -xz -C "$CACHE"
    [ -x "$CACHE/bin/busybox" ] || { echo "error: no bin/busybox in archive" >&2; exit 1; }
fi

echo "Building vsock-echo (musl static)..."
cargo build --manifest-path hack/spike/vsock-echo/Cargo.toml \
    --target x86_64-unknown-linux-musl --release

WORK="$(mktemp -d)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/proc" "$WORK/sys" "$WORK/dev" "$WORK/tmp" "$WORK/mnt"
cp "$CACHE/bin/busybox" "$WORK/bin/busybox"
cp hack/spike/vsock-echo/target/x86_64-unknown-linux-musl/release/vsock-echo \
   "$WORK/bin/vsock-echo"
chmod 755 "$WORK/bin/busybox" "$WORK/bin/vsock-echo"

cat > "$WORK/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox --install -s /bin
echo SPIKE-INIT-OK
[ -f /spike.rc ] && /bin/busybox sh /spike.rc
# Try an interactive shell; with a file-backed serial console sh may exit
# instantly on EOF — keep PID 1 alive regardless (PID 1 exit = kernel panic,
# and rung 4 needs the VM running for the host-side echo test).
/bin/busybox sh
exec /bin/busybox sleep infinity
EOF
chmod 755 "$WORK/init"

if [ -n "$RC_FILE" ]; then
    cp "$RC_FILE" "$WORK/spike.rc"
    chmod 644 "$WORK/spike.rc"
fi

echo "Packing spike initramfs..."
( cd "$WORK" && find . | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -9 ) > "$OUTPUT"
echo "wrote $OUTPUT  ($(du -sh "$OUTPUT" | cut -f1))"
