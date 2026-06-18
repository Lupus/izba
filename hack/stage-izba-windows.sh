#!/usr/bin/env bash
# Stage izba.exe + tools + boot artifacts onto the Windows host (from WSL).
# Layout (installer-shaped, exercises the libexec discovery path):
#   $WIN_ROOT\bin\izba.exe
#   $WIN_ROOT\bin\izba-jail-helper.exe
#   $WIN_ROOT\bin\libexec\{openvmm.exe, mkfs.erofs.exe}
#   %LOCALAPPDATA%\izba\artifacts\{vmlinux, initramfs.cpio.gz}
# Override WIN_ROOT (default /mnt/c/izba) and WIN_LOCALAPPDATA if needed.
set -euo pipefail
cd "$(dirname "$0")/.."

WIN_ROOT="${WIN_ROOT:-/mnt/c/izba}"
# %LOCALAPPDATA% as seen from WSL; derive from the Windows user if not given.
if [[ -z "${WIN_LOCALAPPDATA:-}" ]]; then
    WINUSER="$(powershell.exe -NoProfile -Command '$env:UserName' | tr -d '\r')"
    WIN_LOCALAPPDATA="/mnt/c/Users/$WINUSER/AppData/Local"
fi

IZBA_EXE="target/x86_64-pc-windows-gnu/release/izba.exe"
IZBA_JAIL_HELPER_EXE="target/x86_64-pc-windows-gnu/release/izba-jail-helper.exe"
for f in "$IZBA_EXE" "$IZBA_JAIL_HELPER_EXE" dist/openvmm.exe dist/mkfs.erofs.exe dist/vmlinux dist/initramfs.cpio.gz; do
    [[ -f "$f" ]] || { echo "error: missing $f (build/fetch it first)" >&2; exit 1; }
done

mkdir -p "$WIN_ROOT/bin/libexec" "$WIN_LOCALAPPDATA/izba/artifacts"
cp "$IZBA_EXE"               "$WIN_ROOT/bin/izba.exe"
cp "$IZBA_JAIL_HELPER_EXE"  "$WIN_ROOT/bin/izba-jail-helper.exe"
cp dist/openvmm.exe       "$WIN_ROOT/bin/libexec/openvmm.exe"
cp dist/mkfs.erofs.exe    "$WIN_ROOT/bin/libexec/mkfs.erofs.exe"
cp dist/vmlinux           "$WIN_LOCALAPPDATA/izba/artifacts/vmlinux"
cp dist/initramfs.cpio.gz "$WIN_LOCALAPPDATA/izba/artifacts/initramfs.cpio.gz"

echo "OK: staged to $WIN_ROOT (bin + libexec) and $WIN_LOCALAPPDATA/izba/artifacts"
echo "Windows-side smoke: C:\\izba\\bin\\izba.exe --help"
