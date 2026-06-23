#!/usr/bin/env bash
# Build the izba initramfs: static izba-init (+ optional static mke2fs/nft/sshd).
#
# Usage:
#   hack/build-initramfs.sh [OUTPUT]
#   OUTPUT defaults to dist/initramfs.cpio.gz
#
# Environment:
#   IZBA_MKE2FS=/path/to/static/mke2fs  (optional)
#       If set, the binary is embedded in /sbin/mke2fs so the guest can
#       format the blank rw disk on first boot without a host-side mkfs.
#   IZBA_NFT=/path/to/static/nft  (optional, see hack/build-nft.sh)
#       If set, the binary is embedded in /sbin/nft for the egress stub's
#       TCP REDIRECT ruleset (M1 izbad-owned egress).
#   IZBA_CRUN=/path/to/static/crun  (optional, see hack/build-crun.sh)
#       If set, the binary is embedded in /sbin/crun — the OCI runtime izba
#       runs the user's workload container under inside the guest (Stance B).
#   IZBA_SSHD=/path/to/static/sshd  (optional, see hack/build-sshd.sh)
#       If set, the binary is embedded in /sbin/sshd so izba-init can launch
#       it on boot (SSH access feature).  hack/sshd_config is always copied to
#       /etc/ssh/sshd_config regardless of whether IZBA_SSHD is set.
set -euo pipefail

# Capture the script directory before any cd so $0-relative paths stay valid
# even when the script is invoked as e.g. "cd hack && ./build-initramfs.sh".
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Always run from repo root so cargo can find the workspace.
cd "$SCRIPT_DIR/.."

# Source the repo-local cargo/rustup if present.
# shellcheck disable=SC1091
[[ -f .cargo-env ]] && source .cargo-env

# Verify that cpio is available before doing anything expensive.
if ! command -v cpio >/dev/null 2>&1; then
    echo "error: 'cpio' not found — install it with:" >&2
    echo "  sudo apt-get install -y cpio" >&2
    exit 1
fi

OUTPUT="${1:-dist/initramfs.cpio.gz}"
mkdir -p "$(dirname "$OUTPUT")"

echo "Building izba-init (musl static)..."
cargo build -p izba-init --target x86_64-unknown-linux-musl --release

INIT_BIN="target/x86_64-unknown-linux-musl/release/izba-init"
if [[ ! -f "$INIT_BIN" ]]; then
    echo "error: expected $INIT_BIN after cargo build" >&2
    exit 1
fi

# Build the initramfs tree in a temp directory; clean up on exit.
WORK="$(mktemp -d)"
chmod 755 "$WORK"  # mktemp creates 700; initramfs root must be world-traversable
trap 'rm -rf "$WORK"' EXIT

# Minimal directory skeleton that izba-init expects to find at boot.
mkdir -p "$WORK/sbin" "$WORK/proc" "$WORK/sys" "$WORK/dev" \
         "$WORK/tmp" "$WORK/lower" "$WORK/upper" "$WORK/rootfs" \
         "$WORK/etc/ssh" "$WORK/run/sshd"

# /init must be at the root and executable.
cp "$INIT_BIN" "$WORK/init"
chmod 755 "$WORK/init"

# Optional static mke2fs — enables in-guest first-boot formatting of rw.img
# when the host-side mkfs.ext4 pre-format did not run or is unavailable.
if [[ -n "${IZBA_MKE2FS:-}" ]]; then
    if [[ ! -f "$IZBA_MKE2FS" ]]; then
        echo "error: IZBA_MKE2FS='$IZBA_MKE2FS' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_MKE2FS" "$WORK/sbin/mke2fs"
    chmod 755 "$WORK/sbin/mke2fs"
    echo "  embedded mke2fs from $IZBA_MKE2FS"
fi

# Optional static nft — required for the izbad-egress TCP REDIRECT stub.
if [[ -n "${IZBA_NFT:-}" ]]; then
    if [[ ! -f "$IZBA_NFT" ]]; then
        echo "error: IZBA_NFT='$IZBA_NFT' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_NFT" "$WORK/sbin/nft"
    chmod 755 "$WORK/sbin/nft"
    echo "  embedded nft from $IZBA_NFT"
fi

# Optional static crun — the OCI runtime for the in-guest workload container.
if [[ -n "${IZBA_CRUN:-}" ]]; then
    if [[ ! -f "$IZBA_CRUN" ]]; then
        echo "error: IZBA_CRUN='$IZBA_CRUN' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_CRUN" "$WORK/sbin/crun"
    chmod 755 "$WORK/sbin/crun"
    echo "  embedded crun from $IZBA_CRUN"
fi

# Always embed the static sshd_config into /etc/ssh/sshd_config.
cp "$SCRIPT_DIR/sshd_config" "$WORK/etc/ssh/sshd_config"
chmod 644 "$WORK/etc/ssh/sshd_config"

# Minimal user database for the vendored sshd. OpenSSH fatally exits at startup
# if the privilege-separation user ("sshd") is absent, and it must getpwnam the
# login user ("root"). These live in the izba-controlled initramfs root (NOT the
# OCI overlay), so they are present regardless of the project image.
#
# root's login shell is `/init` (izba-init itself), NOT `/bin/sh`: under Stance B
# the SSH session enters the crun container via `crun exec` (sshd_config's
# `ForceCommand /init __ssh-session`) instead of a `ChrootDirectory /rootfs`
# chroot. With the chroot gone, OpenSSH validates the login shell against THIS
# (initramfs) root, which has no `/bin/sh` — and refuses login ("User root not
# allowed because shell /bin/sh does not exist"). `/init` always exists here, so
# it satisfies the shell-exists check; sshd then runs the forced command as
# `/init -c "/init __ssh-session"`, which izba-init routes to its crun-exec SSH
# entry. (The redundant home `/root` need not exist — OpenSSH only warns.)
cat > "$WORK/etc/passwd" <<'PASSWD'
root:x:0:0:root:/root:/init
sshd:x:74:74:Privilege-separated SSH:/run/sshd:/sbin/nologin
PASSWD
chmod 644 "$WORK/etc/passwd"
cat > "$WORK/etc/group" <<'GROUP'
root:x:0:
sshd:x:74:
GROUP
chmod 644 "$WORK/etc/group"

# Optional static sshd — required for the SSH access feature.
#
# OpenSSH 9.8+ splits sshd into the listener (`sshd`) and a per-session worker
# (`sshd-session`); the listener re-execs the worker by its compile-time libexec
# path (/usr/libexec/sshd-session, set via build-sshd.sh's --prefix=/usr). Both
# must be embedded. build-sshd.sh emits them side by side, so we take
# sshd-session from the same directory as IZBA_SSHD.
if [[ -n "${IZBA_SSHD:-}" ]]; then
    if [[ ! -f "$IZBA_SSHD" ]]; then
        echo "error: IZBA_SSHD='$IZBA_SSHD' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_SSHD" "$WORK/sbin/sshd"
    chmod 755 "$WORK/sbin/sshd"
    echo "  embedded sshd from $IZBA_SSHD"

    sshd_session="$(dirname "$IZBA_SSHD")/sshd-session"
    if [[ ! -f "$sshd_session" ]]; then
        echo "error: sshd-session not found next to IZBA_SSHD at '$sshd_session'" >&2
        echo "       (build-sshd.sh emits sshd + sshd-session together)" >&2
        exit 1
    fi
    mkdir -p "$WORK/usr/libexec"
    cp "$sshd_session" "$WORK/usr/libexec/sshd-session"
    chmod 755 "$WORK/usr/libexec/sshd-session"
    echo "  embedded sshd-session from $sshd_session"
fi

# Pack the tree into a newc cpio archive and gzip it.
#
# We include '.' (the root entry) by running find from inside WORK.  The
# leading './' is stripped from paths by cpio's own output, giving correct
# /init, /sbin/mke2fs, etc. entries without a double-slash prefix.
#
# `--owner=0:0` forces every entry (including '/') to root:root. The build runs
# as a non-root user, so without this the unpacked initramfs root and its dirs
# are owned by the builder's uid — which the vendored sshd's StrictModes rejects
# when it walks the authorized_keys path up to '/'. A root-owned initramfs is
# also simply correct (init runs as root). Owner normalization keeps the archive
# reproducible across build users too.
#
# Sorting the find output makes the archive reproducible.
echo "Packing initramfs..."
( cd "$WORK" && find . | LC_ALL=C sort | cpio -o -H newc --quiet --owner=0:0 | gzip -9 ) > "$OUTPUT"

SIZE="$(du -sh "$OUTPUT" | cut -f1)"
echo "wrote $OUTPUT  ($SIZE)"
