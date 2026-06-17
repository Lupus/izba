#!/usr/bin/env bash
# Assemble and build the izba .deb.
#
# Required env vars (absolute paths to already-built inputs):
#   IZBA_BIN        izba CLI binary (linux, glibc release)
#   IZBA_CH         static cloud-hypervisor binary
#   IZBA_VIRTIOFSD  static virtiofsd binary
#   IZBA_VMLINUX    kernel image
#   IZBA_INITRAMFS  initramfs.cpio.gz
#   VERSION         debian package version (e.g. 0.1.0 or 0.1.0~git<sha>)
# Optional:
#   OUT_DIR         where to write the .deb (default: dist/)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${IZBA_BIN:?}" "${IZBA_CH:?}" "${IZBA_VIRTIOFSD:?}"
: "${IZBA_VMLINUX:?}" "${IZBA_INITRAMFS:?}" "${VERSION:?}"
OUT_DIR="${OUT_DIR:-dist}"

for f in "$IZBA_BIN" "$IZBA_CH" "$IZBA_VIRTIOFSD" "$IZBA_VMLINUX" "$IZBA_INITRAMFS"; do
    [[ -f "$f" ]] || { echo "error: missing input $f" >&2; exit 1; }
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Layout (symmetric with the Windows install — see the design doc):
#   /usr/lib/izba/bin/izba
#   /usr/lib/izba/bin/libexec/{cloud-hypervisor,virtiofsd}
#   /usr/lib/izba/artifacts/{vmlinux,initramfs.cpio.gz}
#   /usr/bin/izba -> ../lib/izba/bin/izba
install -D -m 0755 "$IZBA_BIN"        "$STAGE/usr/lib/izba/bin/izba"
install -D -m 0755 "$IZBA_CH"         "$STAGE/usr/lib/izba/bin/libexec/cloud-hypervisor"
install -D -m 0755 "$IZBA_VIRTIOFSD"  "$STAGE/usr/lib/izba/bin/libexec/virtiofsd"
install -D -m 0644 "$IZBA_VMLINUX"    "$STAGE/usr/lib/izba/artifacts/vmlinux"
install -D -m 0644 "$IZBA_INITRAMFS"  "$STAGE/usr/lib/izba/artifacts/initramfs.cpio.gz"

mkdir -p "$STAGE/usr/bin"
ln -s ../lib/izba/bin/izba "$STAGE/usr/bin/izba"

mkdir -p "$STAGE/DEBIAN"
sed "s/__VERSION__/$VERSION/" packaging/debian/control.template > "$STAGE/DEBIAN/control"

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/izba_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
echo "built $DEB"
dpkg-deb --contents "$DEB"
