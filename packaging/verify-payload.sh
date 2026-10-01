#!/usr/bin/env bash
# Assert that an installer payload carries every file a sandbox needs to boot.
#
#   packaging/verify-payload.sh deb   <izba_*.deb>   the built Debian package
#   packaging/verify-payload.sh stage <StageDir>     the Windows installer's input
#
# Why this exists (#189, #191): the USB kernel variant was added to the code and
# never to the packaging, and a fully green board shipped an installer that
# could not start a sandbox holding a device grant. Both installers take their
# boot artifacts from a directory — the .deb from build-deb.sh's stage, the
# Windows installer from `{#StageDir}\artifacts\*`, a GLOB that silently omits
# whatever is absent — so "is it in the payload" has to be asked explicitly.
#
# Exit: 0 complete; 1 incomplete (one MISSING:/EMPTY: line per problem on
# stderr, all of them, not just the first); 2 usage error / unreadable target.
set -euo pipefail

# The boot artifacts every installer ships. One line, space-separated: the
# guard test in crates/izba-core/src/artifacts.rs reads it and fails when
# `KernelVariant` grows a variant this list has not learned about.
ARTIFACTS=(vmlinux vmlinux-usb initramfs.cpio.gz kasmvnc.erofs)

usage() {
    echo "usage: $0 deb <izba_*.deb> | stage <StageDir>" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
mode="$1"
target="$2"
problems=0

problem() {
    echo "$1" >&2
    problems=$((problems + 1))
}

case "$mode" in
deb)
    [[ -f "$target" ]] || { echo "error: no such .deb: $target" >&2; exit 2; }
    listing="$(dpkg-deb --contents "$target")"
    # `<size> <path>` per entry. Field 3 is the size and field 6 the path in
    # dpkg-deb's tar-style listing; the leading `./` is dropped so paths read
    # the way build-deb.sh writes them.
    entries="$(awk '{ sub(/^\.\//, "", $6); print $3, $6 }' <<<"$listing")"
    required=(
        usr/lib/izba/bin/izba
        usr/lib/izba/bin/libexec/cloud-hypervisor
        usr/lib/izba/bin/libexec/virtiofsd
    )
    for a in "${ARTIFACTS[@]}"; do
        required+=("usr/lib/izba/artifacts/$a")
    done
    for p in "${required[@]}"; do
        # Whole-field match on the path: `vmlinux` must not be satisfied by
        # the `vmlinux-usb` entry.
        size="$(awk -v want="$p" '$2 == want { print $1; exit }' <<<"$entries")"
        if [[ -z "$size" ]]; then
            problem "MISSING: $p"
        elif [[ "$size" == 0 ]]; then
            problem "EMPTY: $p"
        fi
    done
    grep -qF './usr/bin/izba -> ../lib/izba/bin/izba' <<<"$listing" ||
        problem "MISSING: usr/bin/izba -> ../lib/izba/bin/izba (symlink)"
    ;;
stage)
    [[ -d "$target" ]] || { echo "error: no such stage dir: $target" >&2; exit 2; }
    required=(
        bin/izba.exe
        bin/izba-jail-helper.exe
        bin/izba-app.exe
        bin/libexec/openvmm.exe
        bin/libexec/mkfs.erofs.exe
    )
    for a in "${ARTIFACTS[@]}"; do
        required+=("artifacts/$a")
    done
    for p in "${required[@]}"; do
        if [[ ! -f "$target/$p" ]]; then
            problem "MISSING: $p"
        elif [[ ! -s "$target/$p" ]]; then
            problem "EMPTY: $p"
        fi
    done
    ;;
*)
    usage
    ;;
esac

if ((problems > 0)); then
    echo "error: $mode payload $target is incomplete ($problems problem(s)) — a sandbox installed from it cannot boot every configuration" >&2
    exit 1
fi
echo "payload OK: $mode $target"
