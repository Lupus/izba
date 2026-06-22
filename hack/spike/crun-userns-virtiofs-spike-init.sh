#!/bin/sh
# Guest PID-1 for the crun userns + virtiofs uid-mapping gating spike.
#
# This is NOT izba's real init (izba-init). It is a deliberately minimal busybox
# /init whose ONLY job is to answer Pillar B of the crun-OCI-runtime design §5:
# does a user namespace + a virtiofs-backed /workspace share keep file
# ownership/writability correct? It runs the tests, prints clearly-delimited
# SPIKE-RESULT lines to the serial console, and powers off. The host harness
# (crun-userns-virtiofs-spike.sh) parses those lines.
#
# Design refs (do NOT reference any proprietary sandbox internals):
#   docs/superpowers/specs/2026-06-22-crun-oci-runtime-design.LOCAL-DRAFT.md §5
#   - Option A: userns mapping {containerID:0, hostID:<host_uid>, size:1}
#   - Option B: OCI mount "idmap" option (mount_setattr MOUNT_ATTR_IDMAP),
#               needs kernel >=6.12 + virtiofsd >=1.13 + default_permissions
#   tests 1 (idmap mount succeeds, file shows uid 0), 3 (round-trip), 6 (A alone)
#
# busybox sh; everything must be POSIX-ish and tolerate a tiny environment.

# We do NOT set -e here: a single failed test must not abort PID 1 before
# poweroff (a hung VM would wedge the harness). Each test is wrapped and the
# script always reaches poweroff via the EXIT-style trailer.
set -u

# The host uid/gid the workspace files are owned by, injected on the kernel
# cmdline as spike.hostuid=/spike.hostgid= (parsed below). Default 1000.
HOST_UID=1000
HOST_GID=1000

WS=/mnt/workspace          # virtiofs mountpoint inside the guest
TAG=workspace              # must match CH --fs tag= / the harness
BUNDLE_A=/run/bundle-a     # OCI bundle for the Option A test
BUNDLE_B=/run/bundle-b     # OCI bundle for the Option B (idmap) test

# Build a real, dedicated container rootfs (busybox), NOT the root-owned
# initramfs /. Using / as root.path makes crun "make / private" EACCES once the
# process maps to a non-root host uid (Option A). owner=0 => caller chowns it to
# match the userns mapping if needed. Returns the rootfs path on stdout.
build_rootfs() {  # $1 = dest dir
    rfs="$1"
    mkdir -p "$rfs"/bin "$rfs"/sbin "$rfs"/proc "$rfs"/sys "$rfs"/dev \
             "$rfs"/tmp "$rfs"/workspace "$rfs"/etc
    cp /bin/busybox "$rfs"/bin/busybox
    chmod 755 "$rfs"/bin/busybox
    for a in sh ls stat echo cat env printf id; do
        ln -sf busybox "$rfs/bin/$a"
    done
    # world-readable/executable so a mapped (non-root) container uid can use it.
    chmod -R a+rX "$rfs"
}

log()    { echo "SPIKE: $*"; }
result() { echo "SPIKE-RESULT: $*"; }   # "<test> PASS|FAIL <detail>"

# ---------------------------------------------------------------------------
# 0. Pseudo-filesystems + cmdline parse
# ---------------------------------------------------------------------------
setup_mounts() {
    mkdir -p /proc /sys /dev /run /tmp
    mount -t proc     proc     /proc 2>/dev/null
    mount -t sysfs    sysfs    /sys  2>/dev/null
    # devtmpfs gives us /dev/console etc. without manual mknod.
    mount -t devtmpfs devtmpfs /dev  2>/dev/null
    mount -t tmpfs    tmpfs    /run  2>/dev/null
    mount -t tmpfs    tmpfs    /tmp  2>/dev/null

    # crun needs cgroup v2 (unified hierarchy). Mount it; crun creates its own
    # sub-cgroup under it. If this fails we run crun with --cgroup-manager=disabled.
    mkdir -p /sys/fs/cgroup
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
}

parse_cmdline() {
    # /proc/cmdline is space-separated key[=value] tokens.
    for tok in $(cat /proc/cmdline 2>/dev/null); do
        case "$tok" in
            spike.hostuid=*) HOST_UID="${tok#spike.hostuid=}" ;;
            spike.hostgid=*) HOST_GID="${tok#spike.hostgid=}" ;;
            spike.atmpfs=*)  SPIKE_A_TMPFS="${tok#spike.atmpfs=}" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 1. Mount the virtiofs workspace share WITH default_permissions
#    (Option B's absence-of-it => silent EINVAL on the idmapped mount).
# ---------------------------------------------------------------------------
mount_workspace() {
    mkdir -p "$WS"
    if mount -t virtiofs -o default_permissions "$TAG" "$WS" 2>/tmp/ws.err; then
        result "virtiofs-mount PASS mounted $TAG at $WS with default_permissions"
        log "pre-userns ls -lan of $WS (numeric owners; host uid=$HOST_UID):"
        ls -lan "$WS" 2>&1 | sed 's/^/SPIKE:   /'
        return 0
    fi
    log "mount -o default_permissions failed err=$(cat /tmp/ws.err); dmesg tail:"
    dmesg 2>/dev/null | tail -8 | sed 's/^/SPIKE:   dmesg: /'
    # Retry without default_permissions purely to learn whether the option is
    # what the backend rejects (diagnostic only; idmap tests still need it).
    if mount -t virtiofs "$TAG" "$WS" 2>>/tmp/ws.err; then
        result "virtiofs-mount DEGRADED mounted only WITHOUT default_permissions \
(backend rejected the option; Option B idmap needs it) err=$(cat /tmp/ws.err)"
        return 0
    fi
    result "virtiofs-mount FAIL could not mount $TAG err=$(cat /tmp/ws.err)"
    return 1
}

# Raw kernel userns probe — isolates "kernel rejects the map" from "crun does
# something odd". Uses busybox unshare to create a userns and map root, then
# (separately) write a small uid/gid map by hand via a child that waits.
probe_userns() {
    log "raw userns probe: kernel config (if /proc/config.gz present):"
    if [ -e /proc/config.gz ]; then
        zcat /proc/config.gz 2>/dev/null | grep -E \
          'CONFIG_USER_NS|CONFIG_FUSE_FS|CONFIG_VIRTIO_FS|CONFIG_CGROUPS=' \
          | sed 's/^/SPIKE:   cfg: /'
    else
        log "  (no /proc/config.gz — kernel built without IKCONFIG_PROC)"
    fi
    # PID1's own userns map = the parent range any child userns must fit inside.
    # If this is NOT '0 0 4294967295', a child map like '0 0 65536' can EINVAL.
    log "PID1 /proc/self/uid_map: $(cat /proc/self/uid_map 2>/dev/null | tr -s ' \n' ' ')"
    log "PID1 /proc/self/gid_map: $(cat /proc/self/gid_map 2>/dev/null | tr -s ' \n' ' ')"
    # busybox unshare --user --map-root-user: maps current uid->0 (single row).
    if unshare --user --map-root-user sh -c 'echo SPIKE:   map-root-user OK uid_map=$(cat /proc/self/uid_map); id' 2>/tmp/un.err; then
        result "userns-maproot PASS busybox unshare --map-root-user works"
    else
        result "userns-maproot FAIL unshare --map-root-user err=$(cat /tmp/un.err)"
    fi
    # A multi-row / identity map needs CAP_SETUID in the parent ns (root has it).
    # Probe writing setgroups + gid_map ordering the way the kernel requires.
    log "raw userns probe done"
}

# ---------------------------------------------------------------------------
# OCI bundle helpers
# ---------------------------------------------------------------------------
# A bundle = <dir>/config.json + <dir>/rootfs/. We bind the guest initramfs
# root as the container rootfs (busybox + crun live there); the container only
# needs busybox to run the in-container probe.

# In-container probe command. Two CRITICAL constraints, both about what ends up
# as the JSON value of process.args[2]:
#   1. NO double-quote characters — we build config.json by direct string
#      interpolation (no JSON encoder in busybox), so a raw `"` would corrupt the
#      JSON. The probe is written quote-free (unquoted `echo` words; stat output
#      like "0:0" has no quotes and no shell metacharacters).
#   2. The `$(stat ...)` command substitutions MUST run INSIDE the container, not
#      when this init writes the config. So the `$` of each substitution is
#      ESCAPED (`\$(...)`) so it survives literally into the JSON string; only the
#      test label `$1` is expanded here. (Verified: the emitted args[2] still
#      contains a literal `$(stat ...)`.)
# The probe reports the in-container ownership of the host-seeded file and creates
# a fresh file for the host harness to round-trip-check after the VM exits.
probe_cmd() {  # $1 = test label (A|B)
    printf '%s' \
"set -e; cd /workspace; echo SPIKE: [$1] inside-owner-of-host-file \$(stat -c %u:%g hostfile 2>/dev/null || echo NONE); echo from-container-$1 > created-by-$1.txt; echo SPIKE: [$1] created created-by-$1.txt as \$(stat -c %u:%g created-by-$1.txt)"
}

# Emit a COMPLETE OCI config.json by direct interpolation. No sed/awk templating
# (a `\"` in a sed replacement is silently dropped — corrupts the JSON), no JSON
# encoder in busybox. All interpolated values are integers (uid/gid) or
# quote-free paths/commands, so straight interpolation yields valid JSON.
#
#   $1 = process args[2] string (quote-free; see probe_cmd)
#   $2 = process-userns uidMappings JSON array
#   $3 = process-userns gidMappings JSON array
#   $4 = the workspace mount object JSON (the only per-option difference)
#   $5 = container rootfs path
#   $6 = output config.json path
# Namespaces include user + mount/pid/uts/ipc but NOT network (vsock island).
emit_config() {
    args="$1"; uidmap="$2"; gidmap="$3"; ws_mount="$4"; rootpath="$5"; out="$6"
    cat > "$out" <<EOF
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "$args"],
    "env": ["PATH=/sbin:/usr/sbin:/bin:/usr/bin", "TERM=dumb"],
    "cwd": "/",
    "capabilities": {
      "bounding":  ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER"]
    },
    "noNewPrivileges": true
  },
  "root": { "path": "$rootpath", "readonly": false },
  "hostname": "spike",
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
      "options": ["nosuid","strictatime","mode=755","size=65536k"] },
    { "destination": "/sys", "type": "sysfs", "source": "sysfs",
      "options": ["nosuid","noexec","nodev","ro"] },
$ws_mount
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "ipc" },
      { "type": "uts" },
      { "type": "mount" },
      { "type": "user" }
    ],
    "uidMappings": $uidmap,
    "gidMappings": $gidmap
  }
}
EOF
}

# ---------------------------------------------------------------------------
# Test "optionA" — spec test #6: userns hostID arithmetic ALONE.
#   userns maps container uid 0 -> host (== guest-kernel) uid HOST_UID.
#   workspace is a PLAIN bind mount (no idmap option). Because the workspace
#   files are owned by HOST_UID and the userns maps that to container-0, the
#   files must appear as uid 0 inside, and a file the container creates must
#   land on the host owned by HOST_UID. VMM-independent fallback.
# ---------------------------------------------------------------------------
write_config_optionA() {
    mkdir -p "$BUNDLE_A"
    # Map a single-id row (container0 -> HOST_UID, the Option-A trick) plus a
    # small range so non-zero container ids stay valid. The guest runs as real
    # root (kernel uid 0), so it may map any host id freely.
    # SINGLE non-overlapping row: container 0 -> host HOST_UID. (The earlier
    # 2-row map overlapped host id HOST_UID and the kernel rejected gid_map with
    # EINVAL.) The probe runs as container uid/gid 0 and only touches files owned
    # by HOST_UID, which this single row maps to container-0 — sufficient.
    uidmap="[{\"containerID\":0,\"hostID\":${HOST_UID},\"size\":1}]"
    gidmap="[{\"containerID\":0,\"hostID\":${HOST_GID},\"size\":1}]"
    # DIAGNOSTIC: tmpfs instead of the virtiofs bind, to isolate whether crun's
    # `readlink ''` is the bind-source resolution under a non-zero-uid userns.
    if [ "${SPIKE_A_TMPFS:-0}" = "1" ]; then
        ws_mount="    { \"destination\": \"/workspace\", \"type\": \"tmpfs\", \"source\": \"tmpfs\",
      \"options\": [\"rw\",\"nosuid\"] }"
    else
        ws_mount="    { \"destination\": \"/workspace\", \"type\": \"bind\", \"source\": \"${WS}\",
      \"options\": [\"rbind\",\"rw\"] }"
    fi
    # Dedicated rootfs OWNED BY HOST_UID — because container-0 maps to host uid
    # HOST_UID, the whole container runs as HOST_UID and must own/read its rootfs.
    # (This mirrors izba's real erofs+overlay rootfs, owned by the sandbox uid.)
    rfs="$BUNDLE_A/rootfs"
    build_rootfs "$rfs"
    chown -R "${HOST_UID}:${HOST_GID}" "$rfs"
    emit_config "$(probe_cmd A)" "$uidmap" "$gidmap" "$ws_mount" "$rfs" "$BUNDLE_A/config.json"
}

# ---------------------------------------------------------------------------
# Test "optionB" — spec tests #1 + #3: OCI mount-level idmap.
#   userns maps container 0 -> guest-kernel 0 (identity; the mount does the
#   translation, not the process userns). The workspace mount carries the OCI
#   "idmap" option with explicit uidMappings/gidMappings translating the
#   host-owned files (HOST_UID) to container 0. crun applies
#   mount_setattr(MOUNT_ATTR_IDMAP). PASS = no EINVAL, file shows uid 0 inside,
#   container-created file round-trips to host as HOST_UID.
# ---------------------------------------------------------------------------
write_config_optionB() {
    mkdir -p "$BUNDLE_B"
    # Process userns is identity 0->0 over a range: the MOUNT carries the shift.
    # Identity, size 1: the container runs as real (guest-kernel) root; the
    # MOUNT carries the host_uid->0 shift. Size 1 keeps the child userns map
    # trivially inside the parent range (the size-65536 variant EINVAL'd —
    # see PID1 uid_map in the probe).
    uidmap='[{"containerID":0,"hostID":0,"size":1}]'
    gidmap='[{"containerID":0,"hostID":0,"size":1}]'
    # Mount-level idmap: containerID 0 <- hostID HOST_UID. Per the OCI
    # runtime-spec, a mount with "idmap" in options and its own uid/gidMappings
    # gets an idmapped mount; the mappings here are the MOUNT's, independent of
    # the process userns. (crun >= 1.9 understands "idmap".)
    ws_mount="    { \"destination\": \"/workspace\", \"type\": \"bind\", \"source\": \"${WS}\",
      \"options\": [\"rbind\",\"rw\",\"idmap\"],
      \"uidMappings\": [{\"containerID\":0,\"hostID\":${HOST_UID},\"size\":1}],
      \"gidMappings\": [{\"containerID\":0,\"hostID\":${HOST_GID},\"size\":1}] }"
    # Process is identity-root, so a root-owned rootfs is fine here.
    rfs="$BUNDLE_B/rootfs"
    build_rootfs "$rfs"
    emit_config "$(probe_cmd B)" "$uidmap" "$gidmap" "$ws_mount" "$rfs" "$BUNDLE_B/config.json"
}

# Run crun for a bundle id; emit PASS/FAIL with the crun exit + a decoded hint.
run_crun() {
    test="$1"; bundle="$2"
    log "[$test] config.json:"
    sed 's/^/SPIKE:   /' "$bundle/config.json"
    # --cgroup-manager: cgroupfs if we mounted cgroup2, else disabled.
    cgmgr=cgroupfs
    [ -d /sys/fs/cgroup/cgroup.controllers ] || cgmgr=disabled
    # --no-pivot: the guest root here is an initramfs (rootfs), which the kernel
    # refuses to pivot_root out of. crun then uses MS_MOVE+chroot. izba's REAL
    # init switch_roots into the erofs+overlay before the workload, so production
    # crun runs on a normal fs and won't need this — it's a spike artifact only.
    out=$(crun --debug --cgroup-manager="$cgmgr" run --no-pivot -b "$bundle" "spike-$test" 2>&1)
    rc=$?
    echo "$out" | sed 's/^/SPIKE:   crun: /'
    if [ "$rc" -eq 0 ]; then
        result "$test PASS crun-run rc=0 (verify host-side ownership of created-by-$test.txt)"
    else
        hint=""
        case "$out" in
            *"write to \`uid_map\`"*|*"write to \`gid_map\`"*|*uid_map*|*gid_map*)
                hint=" USERNS-MAP-WRITE failed (NOT the idmap mount): kernel uid/gid_map rejected" ;;
            *mount_setattr*|*MOUNT_ATTR_IDMAP*|*"idmapped"*|*"id-mapped"*)
                hint=" IDMAP-MOUNT failed (the Option B mechanism): kernel FUSE FS_ALLOW_IDMAP / virtiofsd FUSE_ALLOW_IDMAP not negotiated?" ;;
            *pivot_root*) hint=" pivot_root (initramfs cannot pivot — should be fixed by --no-pivot)" ;;
            *readlink*) hint=" readlink-empty (crun path canonicalisation — likely a mount source/dest resolution)" ;;
            *EINVAL*|*"Invalid argument"*) hint=" EINVAL (see crun debug above for the exact op)" ;;
            *cgroup*) hint=" mentions cgroup (may be incidental — read debug)" ;;
        esac
        result "$test FAIL crun-run rc=$rc$hint"
    fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
setup_mounts
parse_cmdline
log "spike start: HOST_UID=$HOST_UID HOST_GID=$HOST_GID kernel=$(uname -r)"
log "crun version: $(crun --version 2>&1 | head -1)"

probe_userns

if mount_workspace; then
    # Option A: VMM-independent fallback (test #6).
    if write_config_optionA; then
        run_crun optionA "$BUNDLE_A"
    else
        result "optionA FAIL could not write config.json"
    fi
    # Option B: SOTA idmapped mount (tests #1 + #3).
    if write_config_optionB; then
        run_crun optionB "$BUNDLE_B"
    else
        result "optionB FAIL could not write config.json"
    fi
else
    result "optionA FAIL workspace not mounted"
    result "optionB FAIL workspace not mounted"
fi

log "spike done; powering off"
result "DONE all tests attempted"
# Flush console then power off hard (no init/services to stop).
sync
poweroff -f
# If poweroff is unavailable, fall back to the magic-sysrq / reboot syscall path
# so the harness's VM never hangs.
echo o > /proc/sysrq-trigger 2>/dev/null
reboot -f 2>/dev/null
# Last resort: spin briefly then halt; the harness has a hard timeout anyway.
while true; do sleep 5; done
