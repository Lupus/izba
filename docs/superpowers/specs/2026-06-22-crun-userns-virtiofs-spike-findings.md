# Spike 0 findings — crun userns + virtiofs uid-mapping (Pillar B, CH/Linux leg)

**Date:** 2026-06-22 · **Status:** CH/Linux leg run on real KVM; OpenVMM/WHP leg
still TODO. · **Companion:** the gating spike defined in
`2026-06-22-crun-oci-runtime-design.LOCAL-DRAFT.md` §5.

**Harness:** `hack/spike/crun-userns-virtiofs-spike.sh` (+ guest `-init.sh`).
Boots a real ≥6.12 microVM under Cloud Hypervisor v42.0 with vhost-user
virtiofsd 1.13.3 (`--memory shared=on`, mirroring izba's launch), a throwaway
busybox+crun initramfs, and runs crun (`dist/crun` = static crun 1.28) against
two OCI bundles. Run unsandboxed on the WSL2 KVM host.

**Artifacts under test (all meet the design's stated floor):**
- Guest kernel: the **post-§7-delta 6.12.30** build (CI run 27963299278) — userns
  + cgroup v2 + the netfilter/bridge delta.
- virtiofsd **1.13.3** (≥1.13 — Option B/C floor per design).
- Cloud Hypervisor **v42.0**; crun **1.28** (static musl).

---

## Headline (changes the design recommendation)

| Option | Spec stance | **Spike verdict on CH + 6.12.30** |
| --- | --- | --- |
| **A** — userns `hostID`=host-uid, plain virtiofs bind (VMM-independent) | fallback / common case | **Kernel mechanism PROVEN** (userns create + maps work); a full crun round-trip is blocked in the *minimal spike* by two crun-on-initramfs rough edges (below). Validate end-to-end in izba's real overlay-root boot. |
| **B** — guest idmapped virtiofs mount (`mount_setattr(MOUNT_ATTR_IDMAP)`) | **PRIMARY (SOTA)** | **NOT VIABLE on 6.12.30.** virtio_fs rejects the prerequisite, and crun's idmap mount does **not** translate. See below. |
| **C** — virtiofsd `--translate-uid`/`--gid` (internal translation) | no-kernel-bump fallback | **AVAILABLE** — present in the pinned virtiofsd 1.13.3 (`--translate-uid`, `--translate-gid`, `--uid-map`/`--gid-map`). Not yet exercised end-to-end. |

**Net:** the design's "Primary: Option B" does **not** hold on the kernel we
actually ship. Recommended pivot: **Option A primary (VMM-independent, no kernel
idmap), Option C as the host-side fallback when single-uid arithmetic is
insufficient; Option B deferred** until a guest kernel with working virtio_fs
idmapped mounts, then re-spike.

---

## Evidence

### Kernel userns works
- `unshare --user --map-root-user` succeeds in-guest → userns creation + a
  single-row root map is fine.
- crun creates the user namespace and writes **single-extent** maps
  (`0 <host> 1`) successfully; the identity-root container (Option B's process
  ns) runs a full `/bin/sh` probe.
- PID1 `/proc/self/uid_map` is **empty** — i.e. the guest init is in the
  *initial* userns (implicit full-range identity), as expected.

### Option B — idmapped virtiofs mount is NOT functional on 6.12.30
- Guest dmesg on `mount -t virtiofs -o default_permissions …`:
  **`virtiofs: Unknown parameter 'default_permissions'`** → this kernel's
  virtio_fs parameter parser does not accept `default_permissions` at all. The
  mount only succeeds *without* it.
- With the container running (identity process userns, OCI mount `idmap` option
  + mount-level uid/gidMappings), the in-container probe reports the
  host-uid-1000 workspace file as **`65534:65534` (nobody)** and the
  container-root write fails **`Value too large for data type` (EOVERFLOW)**.
  → the idmapped mount is **not translating**; the host uid is simply unmapped.
- Conclusion: virtio_fs in 6.12.30 lacks the `FS_ALLOW_IDMAP`/`default_permissions`
  plumbing the OCI `idmap` mount needs. The design's "FUSE/virtio_fs gained idmap
  in 6.12" is true for **core FUSE** but the **virtio_fs** mount-param support
  landed later. Re-test on a newer kernel before reviving Option B.

### Option C — virtiofsd translate is available
`virtiofsd 1.13.3 --help` confirms `--translate-uid`/`--translate-gid`
(`guest`/`host`/`squash-*`/`map:` forms) and `--uid-map`/`--gid-map`
(userns-based, with `--sandbox=namespace`). `--translate-*` is **mutually
exclusive with `--posix-acl`** (documented). This is the no-kernel-bump path and
is VMM-specific to the standalone virtiofsd (CH/Linux) — **OpenVMM's bundled
virtiofs is untested (TODO).**

### Two crun-on-initramfs rough edges (Option A blockers in the *spike only*)
These appeared running crun **directly on the initramfs (rootfs)** with a
minimal busybox bundle — materially unlike izba production, where init
`switch_root`s into the erofs+overlay before any workload, so crun runs on a
normal filesystem. Flagged as **Phase-4 validation items**, not kernel verdicts:

1. **`pivot_root: Invalid argument`** — the kernel refuses to pivot_root out of
   an initramfs. Worked around with `crun run --no-pivot` (MS_MOVE+chroot).
   Production won't need it (real fs root after switch_root).
2. **`readlink \`\`: No such file or directory`** in crun child setup, triggered
   *specifically* by a **non-identity** process map (container-0 → host-1000);
   reproduces with the workspace as either a virtiofs bind **or** a plain tmpfs,
   so it is the mapping, not the share. Identity maps (Option B's ns) are
   unaffected. Needs a crun-source root-cause or validation on the real root.
3. **Range maps rejected:** a single-extent `0 0 65536` map EINVAL'd at
   `write to uid_map` while size-1 maps succeed. Root cause unconfirmed (crun
   `newuidmap` fallback w/o shadow-utils + `/etc/subuid`? a sysctl?). **This
   matters** — real OCI images use a uid *range* (e.g. `nobody`), so Option A
   needs working range maps. Re-test with izba's real flow / a crun that has the
   shadow helpers, and confirm `/etc/subuid` is not silently required.

---

## Recommendation to the design (§5)

1. **Make Option A the primary** mapping strategy (container-0 → guest/sandbox
   uid), VMM-independent, needing no guest-kernel idmap. **Default userns ON**
   remains the goal, but its go/no-go must be confirmed by an **end-to-end
   Option A round-trip in izba's real boot** (overlay rootfs, post-switch_root) —
   Phase 4, not the minimal spike.
2. **Option C (virtiofsd `--translate-uid`)** is the host-side fallback on the
   CH/Linux path when single-uid arithmetic is insufficient; remember it is
   incompatible with `--posix-acl`.
3. **Defer Option B.** Do not pin the design to guest-side idmapped virtiofs
   mounts until a kernel where `mount -t virtiofs -o default_permissions`
   is accepted and an `idmap` OCI mount actually translates. Re-run this harness
   to confirm before reviving it.
4. **Resolve the range-map (size>1) question** before committing to userns
   defaults — it gates whether real multi-uid images run under Option A.
5. **Per-VMM:** the OpenVMM/WHP leg (bundled virtiofs) is still **TODO** and may
   have a different floor; keep the fail-closed + loud per-VMM capability probe.

## How to re-run

```sh
IZBA_KERNEL=<≥6.12 vmlinux> IZBA_CH=~/.local/bin/cloud-hypervisor \
IZBA_VIRTIOFSD=~/.local/bin/virtiofsd IZBA_CRUN=$PWD/dist/crun \
IZBA_SPIKE_KEEP=1 bash hack/spike/crun-userns-virtiofs-spike.sh
```
`IZBA_SPIKE_A_TMPFS=1` swaps Option A's workspace for a tmpfs (the readlink
isolation test). Run unsandboxed (needs `/dev/kvm` + docker).
