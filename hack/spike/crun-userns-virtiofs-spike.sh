#!/usr/bin/env bash
# Gating spike (CH/Linux leg): crun userns + virtiofs uid-mapping.
#
# THROWAWAY harness for Pillar B of the crun-OCI-runtime design §5. It boots a
# real ≥6.12 microVM under Cloud Hypervisor with a vhost-user virtiofsd share
# (mirroring izba's actual Linux/KVM launch flags) and a MINIMAL busybox+crun
# initramfs whose /init runs the userns/idmap tests and powers off. This harness
# then parses the serial console for SPIKE-RESULT lines, prints a table, checks
# host-side ownership of the files the container created, and exits non-zero if
# any required test FAILED.
#
# It cannot boot in Claude's sandboxed Bash (no /dev/kvm there). The dispatcher
# runs it UNSANDBOXED on the real KVM host. Author/validate only here.
#
# Design ref: docs/superpowers/specs/2026-06-22-crun-oci-runtime-design.LOCAL-DRAFT.md §5
#   tests #1 (idmap mount succeeds, host file shows uid 0),
#         #3 (round-trip: container-created file owned by host uid on host),
#         #6 (Option A userns-hostID arithmetic alone — VMM-independent).
#
# Usage:
#   hack/spike/crun-userns-virtiofs-spike.sh
#
# Environment (all have defaults; fail loudly if a required artifact is absent):
#   IZBA_KERNEL     path to a >=6.12 vmlinux         (default: $DATA/artifacts/vmlinux)
#   IZBA_CH         cloud-hypervisor binary           (default: dist/bin/cloud-hypervisor → PATH)
#   IZBA_VIRTIOFSD  virtiofsd binary (>=1.13)         (default: dist/bin/virtiofsd → PATH)
#   IZBA_CRUN       static crun for the guest         (default: dist/crun)
#   IZBA_SPIKE_MEM_MB    guest memory (default 1024)
#   IZBA_SPIKE_TIMEOUT_S boot+run timeout (default 120)
#   IZBA_SPIKE_KEEP=1    keep the work dir on exit (debugging)
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root (hack/spike/ -> repo)
REPO="$PWD"
SELF_DIR="$REPO/hack/spike"

# Pinned Alpine builder digest — same as build-crun.sh / build-nft.sh, so the
# throwaway initramfs is built from the same immutable base image.
ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

DATA_DIR="${IZBA_DATA_DIR:-$HOME/.local/share/izba}"

# ---------------------------------------------------------------------------
# Resolve artifacts (env override → dist/ → PATH). Fail loudly if missing.
# ---------------------------------------------------------------------------
resolve() {  # var default_path tool_name
    local val="$1" def="$2" name="$3"
    if [[ -n "$val" ]]; then
        [[ -e "$val" ]] || { echo "error: $name='$val' does not exist" >&2; exit 1; }
        printf '%s' "$val"; return
    fi
    if [[ -e "$def" ]]; then printf '%s' "$def"; return; fi
    if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return; fi
    echo "error: $name not found (set its env var, run hack/fetch-artifacts.sh," \
         "or build it). Looked at: '$def' and PATH." >&2
    exit 1
}

KERNEL=$(resolve "${IZBA_KERNEL:-}"     "$DATA_DIR/artifacts/vmlinux"     "vmlinux")
CH=$(resolve     "${IZBA_CH:-}"         "$REPO/dist/bin/cloud-hypervisor" "cloud-hypervisor")
VIRTIOFSD=$(resolve "${IZBA_VIRTIOFSD:-}" "$REPO/dist/bin/virtiofsd"      "virtiofsd")
CRUN=$(resolve   "${IZBA_CRUN:-}"       "$REPO/dist/crun"                 "crun")

MEM_MB="${IZBA_SPIKE_MEM_MB:-1024}"
TIMEOUT_S="${IZBA_SPIKE_TIMEOUT_S:-120}"

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (the initramfs is built in an Alpine container)" >&2
    exit 1
}
[[ -e /dev/kvm ]] || echo "warning: /dev/kvm not visible — CH will fail to boot \
(expected inside Claude's sandbox; run me unsandboxed)" >&2

echo "=== crun userns + virtiofs spike (CH/Linux leg) ==="
echo "  kernel:    $KERNEL"
echo "  ch:        $CH"
echo "  virtiofsd: $VIRTIOFSD"
echo "  crun:      $CRUN"
echo "  mem:       ${MEM_MB}M   timeout: ${TIMEOUT_S}s"

# Record the pinned virtiofsd version (spec test #5 — confirm >=1.13 on CH path).
echo "  virtiofsd --version: $("$VIRTIOFSD" --version 2>&1 | head -1 || true)"

# ---------------------------------------------------------------------------
# Work dir + cleanup trap (kill CH + virtiofsd, remove sockets/dir).
# ---------------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/crun-spike.XXXXXX")"
CH_PID=""
VIOFSD_PID=""
cleanup() {
    local rc=$?
    [[ -n "$CH_PID" ]]     && kill "$CH_PID"     2>/dev/null || true
    [[ -n "$VIOFSD_PID" ]] && kill "$VIOFSD_PID" 2>/dev/null || true
    # give them a moment, then hard-kill any survivor
    sleep 1
    [[ -n "$CH_PID" ]]     && kill -9 "$CH_PID"     2>/dev/null || true
    [[ -n "$VIOFSD_PID" ]] && kill -9 "$VIOFSD_PID" 2>/dev/null || true
    if [[ "${IZBA_SPIKE_KEEP:-0}" = "1" ]]; then
        echo "kept work dir: $WORK"
    else
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

WS="$WORK/workspace"           # the host dir we share over virtiofs
RUN="$WORK/run"                # CH/virtiofsd sockets live here
CONSOLE="$WORK/console.log"
INITRAMFS="$WORK/spike-initramfs.cpio.gz"
mkdir -p "$WS" "$RUN"

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# ---------------------------------------------------------------------------
# Seed the shared workspace with host-uid-owned files (spec test #3 round-trip).
# ---------------------------------------------------------------------------
echo "host-seeded file (owner ${HOST_UID}:${HOST_GID})" > "$WS/hostfile"
echo "another"                                           > "$WS/readme.txt"
echo "  seeded $WS as ${HOST_UID}:${HOST_GID}:"
ls -lan "$WS" | sed 's/^/    /'

# ---------------------------------------------------------------------------
# Build the throwaway initramfs: busybox (Alpine) + static crun + our /init.
# Mirrors build-nft.sh's container posture (pinned Alpine digest, --owner=0:0).
# Built INSIDE the Alpine container so busybox + cpio are present and ownership
# is normalised; the host crun + init script are mounted in.
# ---------------------------------------------------------------------------
echo "Building throwaway spike initramfs (Alpine $ALPINE)..."
INIT_SH="$SELF_DIR/crun-userns-virtiofs-spike-init.sh"
[[ -f "$INIT_SH" ]] || { echo "error: $INIT_SH missing" >&2; exit 1; }

docker run --rm \
    -v "$CRUN:/in/crun:ro" \
    -v "$INIT_SH:/in/init:ro" \
    -v "$WORK:/out" \
    "$ALPINE" sh -euc '
  apk add --no-cache busybox-static cpio gzip
  root=$(mktemp -d)
  # Minimal FHS the guest /init expects.
  mkdir -p "$root"/sbin "$root"/bin "$root"/usr/bin "$root"/proc "$root"/sys \
           "$root"/dev "$root"/run "$root"/tmp "$root"/mnt
  # Static busybox provides sh + all coreutils (mount, ls, stat, sed, awk, ...).
  cp /bin/busybox.static "$root"/bin/busybox
  chmod 755 "$root"/bin/busybox
  # Install applets as symlinks so /init can call them by name on PATH.
  for app in sh mount umount ls stat sed awk cat echo mkdir sync sleep \
             poweroff reboot uname head printf env true cut chmod \
             unshare id chown zcat dmesg grep tail ln cp seq rm find; do
    ln -sf /bin/busybox "$root/bin/$app"
  done
  # Static crun where the guest /init looks for it.
  cp /in/crun "$root"/sbin/crun
  chmod 755 "$root"/sbin/crun
  # The spike /init at the archive root.
  cp /in/init "$root"/init
  chmod 755 "$root"/init
  # Reproducible, root-owned cpio (same posture as the real initramfs build).
  ( cd "$root" && find . | LC_ALL=C sort \
      | cpio -o -H newc --owner=0:0 --quiet | gzip -9 ) > /out/spike-initramfs.cpio.gz
'
[[ -s "$INITRAMFS" ]] || { echo "error: initramfs build produced nothing" >&2; exit 1; }
echo "  wrote $INITRAMFS ($(du -sh "$INITRAMFS" | cut -f1))"

# ---------------------------------------------------------------------------
# Launch virtiofsd for the workspace dir — MIRROR izba's flags
# (cloud_hypervisor.rs build_invocations): --socket-path --shared-dir
# --cache auto --sandbox none. We use --sandbox none for the spike (the
# confinement jail is orthogonal to the idmap question and namespace sandbox
# needs an unprivileged-userns knob that varies by host — see the README).
# ---------------------------------------------------------------------------
FS_SOCK="$RUN/fs-workspace.sock"
echo "Launching virtiofsd..."
"$VIRTIOFSD" \
    --socket-path "$FS_SOCK" \
    --shared-dir "$WS" \
    --cache auto \
    --sandbox none \
    > "$WORK/virtiofsd.log" 2>&1 &
VIOFSD_PID=$!

# Wait for the vhost-user socket to appear (CH connects to it at boot).
for _ in $(seq 1 60); do
    [[ -S "$FS_SOCK" ]] && break
    kill -0 "$VIOFSD_PID" 2>/dev/null || { echo "error: virtiofsd died early:" >&2; cat "$WORK/virtiofsd.log" >&2; exit 1; }
    sleep 0.1
done
[[ -S "$FS_SOCK" ]] || { echo "error: virtiofsd did not create $FS_SOCK" >&2; cat "$WORK/virtiofsd.log" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Boot cloud-hypervisor — NIC-less, shared=on, virtiofs tag=workspace, console
# to file. Mirrors izba's CH argv (cloud_hypervisor.rs). The cmdline passes the
# host uid/gid to the guest /init.
# ---------------------------------------------------------------------------
CMDLINE="console=ttyS0 init=/init spike.hostuid=${HOST_UID} spike.hostgid=${HOST_GID} spike.atmpfs=${IZBA_SPIKE_A_TMPFS:-0}"
echo "Booting cloud-hypervisor..."
"$CH" \
    --kernel "$KERNEL" \
    --initramfs "$INITRAMFS" \
    --cmdline "$CMDLINE" \
    --cpus boot=1 \
    --memory "size=${MEM_MB}M,shared=on" \
    --fs "tag=workspace,socket=${FS_SOCK}" \
    --serial "file=${CONSOLE}" \
    --console off \
    --api-socket "$RUN/ch-api.sock" \
    > "$WORK/vmm.log" 2>&1 &
CH_PID=$!

# ---------------------------------------------------------------------------
# Wait for the guest to finish (SPIKE-RESULT: DONE) or the VM to exit, up to
# the timeout. The guest powers off itself, so CH exiting is the normal path.
# ---------------------------------------------------------------------------
echo "Waiting up to ${TIMEOUT_S}s for the guest spike to finish..."
deadline=$(( $(date +%s) + TIMEOUT_S ))
while :; do
    if grep -q "SPIKE-RESULT: DONE" "$CONSOLE" 2>/dev/null; then break; fi
    if ! kill -0 "$CH_PID" 2>/dev/null; then
        echo "  cloud-hypervisor exited (guest powered off or VM died)"
        break
    fi
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
        echo "warning: timeout after ${TIMEOUT_S}s; tearing down" >&2
        break
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Parse results + host-side ownership round-trip check.
# ---------------------------------------------------------------------------
echo ""
echo "=== console.log (tail) ==="
tail -n 60 "$CONSOLE" 2>/dev/null || echo "(no console output captured)"
echo "  full console: $CONSOLE"
[[ "${IZBA_SPIKE_KEEP:-0}" = "1" ]] && echo "  (work dir kept; vmm.log + virtiofsd.log alongside)"

echo ""
echo "=== SPIKE-RESULT lines ==="
grep "SPIKE-RESULT:" "$CONSOLE" 2>/dev/null | sed 's/^/  /' || echo "  (none — boot likely failed; inspect $CONSOLE and $WORK/vmm.log)"

# Host-side round-trip ownership (spec test #3): the file the container created
# must be owned by the invoking host uid, with NO chown done by anyone.
echo ""
echo "=== host-side round-trip ownership (spec test #3) ==="
check_owner() {  # file label
    local name="$1" label="$2"
    local f="$WS/$name"
    if [[ ! -e "$f" ]]; then
        echo "  $label: MISSING ($f not created — that test did not reach the write)"
        return 1
    fi
    local own; own=$(stat -c '%u:%g' "$f")
    if [[ "$own" = "${HOST_UID}:${HOST_GID}" ]]; then
        echo "  $label: PASS  $name owned ${own} (== host ${HOST_UID}:${HOST_GID})"
        return 0
    fi
    echo "  $label: FAIL  $name owned ${own} (expected host ${HOST_UID}:${HOST_GID})"
    return 1
}
RT_A=0; RT_B=0
check_owner "created-by-A.txt" "optionA round-trip" || RT_A=1
check_owner "created-by-B.txt" "optionB round-trip" || RT_B=1

# ---------------------------------------------------------------------------
# Verdict. Required-to-pass: at least Option A (the VMM-independent fallback)
# must be green end-to-end — crun PASS + round-trip PASS. Option B is the SOTA
# target; its failure is reported loudly but, per spec, Option A alone is a
# valid floor, so we surface B separately and only HARD-fail if A fails.
# ---------------------------------------------------------------------------
crun_pass() { local opt="$1"; grep -q "SPIKE-RESULT: $opt PASS" "$CONSOLE" 2>/dev/null; }

echo ""
echo "=== verdict ==="
A_OK=0; B_OK=0
if crun_pass optionA && [[ "$RT_A" -eq 0 ]]; then A_OK=1; fi
if crun_pass optionB && [[ "$RT_B" -eq 0 ]]; then B_OK=1; fi
printf '  Option A (userns hostID, VMM-independent fallback): %s\n' \
    "$([[ "$A_OK" -eq 1 ]] && echo PASS || echo FAIL)"
printf '  Option B (idmapped virtiofs mount, SOTA primary):   %s\n' \
    "$([[ "$B_OK" -eq 1 ]] && echo PASS || echo "FAIL (decode EINVAL hint above)")"

if [[ "$A_OK" -eq 1 ]]; then
    echo "  RESULT: floor MET (Option A works). Option B status above."
    [[ "$B_OK" -eq 1 ]] && echo "  RESULT: SOTA idmap path also works — userns-by-default is unblocked on CH."
    exit 0
fi
echo "  RESULT: FAIL — Option A (the VMM-independent floor) did not pass." >&2
echo "          Inspect $CONSOLE, $WORK/vmm.log, $WORK/virtiofsd.log." >&2
exit 1
