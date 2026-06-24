# crun userns + virtiofs uid-mapping spike (Pillar B gating spike)

Throwaway harness that answers **Pillar B** of the crun-OCI-runtime design:
*with a user namespace, do files on the virtiofs `workspace` share (owned by the
host uid) stay correctly owned and writable inside the container?* This is the
gating question before defaulting userns ON for the in-guest crun container.

Authoritative spec:
`docs/superpowers/specs/2026-06-22-crun-oci-runtime-design.LOCAL-DRAFT.md` §5
(ranked Options A/B/C, per-VMM constraint, gating-spike tests 1–6).

## What it does

1. Builds a **minimal throwaway initramfs** (NOT izba's real `izba-init`) in a
   digest-pinned Alpine container: static busybox + the static `crun` from
   `dist/crun` + a small `/init` (`crun-userns-virtiofs-spike-init.sh`). A pure
   kernel + virtiofsd + crun test, decoupled from izba PID-1 complexity.
2. Seeds a host `workspace/` dir with files owned by the invoking host uid.
3. Launches **virtiofsd** for that dir and boots **cloud-hypervisor** NIC-less
   with `--memory size=...M,shared=on` and `--fs tag=workspace,...` — mirroring
   izba's real Linux/KVM launch (`crates/izba-core/src/vmm/cloud_hypervisor.rs`).
4. The guest `/init` mounts the share **with `default_permissions`**, then runs
   `crun` twice and prints `SPIKE-RESULT: <test> PASS|FAIL <detail>` to the
   serial console, then powers off.
5. The harness parses the console, checks **host-side** ownership of the files
   the container created (round-trip), prints a verdict table, and exits
   non-zero if the required floor (Option A) failed.

## Prerequisites

- A KVM host (`/dev/kvm`). **Run unsandboxed** — Claude's sandboxed Bash hides
  `/dev/kvm`; the harness warns and CH would fail to boot.
- `docker` (the throwaway initramfs is built in an Alpine container).
- **Guest kernel ≥ 6.12** vmlinux — FUSE/virtio_fs gained `FS_ALLOW_IDMAP` in
  6.12 (required for Option B). Build via `hack/build-kernel.sh` (the §7 expanded
  kernel) or point `IZBA_KERNEL` at one.
- **cloud-hypervisor** + **virtiofsd ≥ 1.13** — already sha-pinned by
  `hack/fetch-artifacts.sh` (CH v42.0, virtiofsd v1.13.3, which satisfies the
  Option B/C floor; 1.13.0 added `FUSE_ALLOW_IDMAP` + `--translate-uid`). Run
  `hack/fetch-artifacts.sh` to place them.
- **`dist/crun`** — static musl crun (build via `hack/build-crun.sh`; 1.28
  already built in this worktree).

## How the dispatcher runs it (unsandboxed)

```sh
# 1. Ensure artifacts (CH + virtiofsd; kernel/initramfs are built locally):
hack/fetch-artifacts.sh
hack/build-crun.sh                      # if dist/crun is absent

# 2. Run the spike. Defaults resolve dist/ then PATH; override as needed:
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
  hack/spike/crun-userns-virtiofs-spike.sh
```

Env knobs (all optional): `IZBA_KERNEL`, `IZBA_CH`, `IZBA_VIRTIOFSD`,
`IZBA_CRUN`, `IZBA_SPIKE_MEM_MB` (default 1024), `IZBA_SPIKE_TIMEOUT_S`
(default 120), `IZBA_SPIKE_KEEP=1` (keep the work dir + logs for debugging).

Exit code: **0** if the floor (Option A) passed (Option B status reported
separately); **non-zero** if Option A failed.

## Pass/fail interpretation (per spec tests 1, 3, 6)

| Spike test | Spec test | PASS means | FAIL means |
| --- | --- | --- | --- |
| `optionA` | #6 | userns `{containerID:0, hostID:<host_uid>, size:1}` + a **plain** bind mount → host files appear as uid 0 inside, and a container-created file lands on the host owned by `<host_uid>`. The **VMM-independent fallback**. | the single-owner-uid arithmetic doesn't round-trip — deeper than an idmap miss; inspect console. |
| `optionB` | #1 + #3 | crun applies the OCI mount **`idmap`** option (`mount_setattr(MOUNT_ATTR_IDMAP)`) with no `EINVAL`; inside, the host file shows uid 0; a container-created file round-trips to the host as `<host_uid>`. The **SOTA primary**. | typically `EINVAL` on the idmapped mount → see decoder below. |
| round-trip (host side) | #3 | the harness `stat`s `created-by-{A,B}.txt` on the host and confirms `<host_uid>:<host_gid>` with **no chown**. | wrong owner, or the file was never created (crun failed earlier). |

`optionA` is the required floor: even if a backend lacks idmap/translate, Option
A alone is a valid path for the single-owner-uid case (and it is
VMM-independent, so the OpenVMM leg can fall back to it). `optionB` passing means
the SOTA idmapped-mount path works on CH and userns-by-default is unblocked.

## Failure-mode decoder — `EINVAL` on the idmapped mount (Option B)

`EINVAL` from `crun ... run` while applying the workspace `idmap` mount is the
classic Option-B failure. Check, **in order**:

1. **`default_permissions` present on the virtiofs mount?** Its absence makes the
   kernel reject the idmapped mount with a *silent* `EINVAL` (spec §5). The guest
   `/init` mounts `-o default_permissions`; confirm the
   `SPIKE-RESULT: virtiofs-mount PASS … with default_permissions` line.
2. **Guest kernel ≥ 6.12 with FUSE idmap support?** `CONFIG_FUSE_FS=y` and the
   6.12 FUSE/virtio_fs `FS_ALLOW_IDMAP` work. `uname -r` is logged. An older
   kernel cannot do FUSE idmapped mounts at all → Option C (`--translate-uid`)
   or Option A fallback.
3. **virtiofsd ≥ 1.13 negotiating `FUSE_ALLOW_IDMAP`?** 1.13.0 added it (not
   1.12). The harness prints `virtiofsd --version`. The pinned 1.13.3 is fine.
4. **`--memory ...,shared=on`?** virtiofs DAX/shared memory must be enabled for
   the backend to serve the mount; the harness always passes it (mirrors izba).
5. **crun's `idmap` mount-option spelling.** crun ≥ 1.9 accepts `idmap` (and
   `ridmap` for recursive) in a mount's `options` with mount-level
   `uidMappings`/`gidMappings`. If a future crun changes the spelling, the
   config generator in the init script is the single place to adjust.

If only Option B fails but Option A passes, that is still a green floor — report
B's failure with the decoded cause; do not treat it as a blocker for the
single-owner-uid case.

## OpenVMM / WHP leg — DEFERRED (TODO)

<!-- TODO(dispatcher): author + run the OpenVMM/WHP .ps1 leg on the Windows host. -->

The OpenVMM/WHP leg is **not written here** — it runs later on the Windows host.
Per spec §5 the per-VMM constraint matters: **OpenVMM bundles its virtiofs
backend** (no standalone virtiofsd), so neither Option B (idmap FUSE flags) nor
Option C (`--translate-uid`) can be assumed available; its idmap/translate
capability is **unknown until measured**. The eventual
`hack/spike/crun-userns-virtiofs-spike.ps1` must:

- boot the same ≥6.12 guest + spike initramfs under OpenVMM/WHP
  (see `hack/spike/validate-izba-windows.ps1` for the OpenVMM launch pattern),
- run the **same** `/init` tests, and
- record OpenVMM's virtiofs FUSE-feature support (does it negotiate idmap at
  all?) so the per-driver capability floor is known.

If OpenVMM's backend lacks the mechanism, the fallback order (spec §5) is:
Option A's userns-`hostID` arithmetic alone (VMM-independent) → per-driver
capability flag that **fails closed + loud** on the OpenVMM path → (last resort)
contribute the knob upstream.

## Files

- `crun-userns-virtiofs-spike.sh` — the CH/Linux host harness (this is what you run).
- `crun-userns-virtiofs-spike-init.sh` — the guest PID-1 spike logic (embedded in
  the throwaway initramfs; generates the two OCI `config.json` documents).
- `README-crun-userns-virtiofs-spike.md` — this doc.
