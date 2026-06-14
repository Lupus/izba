# izba M3 — User-declared persistent volumes — Design

**Date:** 2026-06-15
**Status:** Approved design (pre-implementation)
**Topic:** Per-sandbox user-declared block-device **volumes** — the storage half
of roadmap **M3 (sized & stateful sandboxes)**. This is the mandated
disk-order **contract-change spec** that risk #5★ requires *before any M3 code*.

## 1. Goal & scope

Let a user attach extra persistent block devices to a sandbox, each formatted
and mounted at a declared path inside the guest. The motivating need is a sized,
durable `/var/lib/docker` (or any state dir) so an in-guest workload survives
stop/start — the hard prerequisite for M4's stateful mesh members.

**Resources (`cpus`/`mem_mb`) are already plumbed** end-to-end (CLI → `DaemonCreate`
→ `CreateOpts` → `SandboxConfig` → `VmSpec` → both drivers' `--memory`/processor
knobs). M3's resources half is therefore **done already**; this spec covers
**volumes only**.

### In scope (v1 of volumes)

1. **Two volume classes**, both declared inline on `izba run` / `DaemonRequest::Create`:
   - **Ephemeral (anonymous):** lives under the sandbox dir, destroyed with `izba rm`.
   - **Persistent (named):** lives under `<data>/volumes/<name>.img`, survives `rm`,
     re-attachable by name to a later sandbox.
2. **The disk-order contract change**: extend the fixed
   `[rootfs.erofs=vda, rw.img=vdb]` enumeration with user volumes (`vdc`, `vdd`, …)
   across host disk assembly, both VMM drivers, the kernel cmdline, and the guest
   mount plan — *change all ends in one milestone*.
3. **`izba volume prune`**: remove persistent volume images no longer referenced by
   any sandbox. Required for reproducible tests (a test that exercises the
   persistent path must clean up the image it leaves behind) and for basic disk
   hygiene.

### Out of scope (deferred until M4 needs them)

- The rest of the volume-object CLI: `izba volume ls` / `rm <name>` / `create` /
  `inspect`. Only `prune` ships now.
- **Resize** of an existing volume.
- **Sharing** a persistent volume between two *live* sandboxes simultaneously
  (single-writer is enforced; sequential reuse is allowed).
- **Non-ext4** filesystems / user-chosen fs.
- Resources (`cpus`/`mem_mb`) — already shipped.

## 2. Foundational decisions (locked in brainstorming)

| Decision | Choice | Rationale |
| --- | --- | --- |
| **Declaration** | Inline on `izba run` (no separate object-create step) | Matches the "postpone volume-object CLI" call; lowest surface. |
| **Class grammar** | Docker-style: **named ⇒ persistent**, **anonymous ⇒ ephemeral** | Familiar; needs no new flag; name *is* the persistence + identity signal. |
| **Ephemeral storage** | `<sandbox-dir>/volumes/<i>.img` | Lifecycle == the sandbox; reaped by the existing `rm` dir-delete. |
| **Persistent storage** | `<data>/volumes/<name>.img` | Outlives `rm`; addressable by name for re-attach. |
| **Concurrency** | Named volume is **single-writer**: at most one *live* sandbox references it | A block device has no multi-writer story; checked at create/start. |
| **Host→guest mountpoint channel** | **Kernel cmdline** `izba.volume=<guest_path>` entries, one per volume in `vdc,vdd,…` disk order | Reuses the existing cmdline-chain contract (`izba.hostname`); the disk carries no label, so order is the binding. |
| **Filesystem** | ext4, **lazy guest format** via the existing `is_blank` check | Same pattern as `rw.img`; a freshly-created image formats on first boot, an existing persistent image is left intact. |
| **Cleanup** | `izba volume prune` removes unreferenced persistent images | Reproducible tests + hygiene; full object CLI still deferred. |

## 3. Architecture

### 3.1 The disk-order contract change (the headline)

Today (load-bearing **Disk order** contract in `CLAUDE.md`):

```
[ rootfs.erofs = vda (RO),  rw.img = vdb (RW) ]
```

After M3:

```
[ rootfs.erofs = vda (RO),  rw.img = vdb (RW),  vol₀ = vdc,  vol₁ = vdd,  … ]
```

User volumes are appended **after** `rw.img`, in declaration order. The ceiling is
**24 volumes** (26 virtio-blk slots − vda − vdb); OpenVMM's `disk_port()` already
asserts `< 26`, so we validate `<= 24` user volumes at the *host* boundary with a
clear error rather than letting the driver assert.

**Ends that change (all in this milestone):**

| End | File (current) | Change |
| --- | --- | --- |
| Host disk assembly | `crates/izba-core/src/sandbox.rs` `start()` (~389) | Append one `BlockDisk{path, readonly:false}` per volume after `rw.img`. |
| Disk type | `crates/izba-core/src/vmm/spec.rs` `BlockDisk` | **Unchanged** — already `{path, readonly}`. |
| VMM trait | `crates/izba-core/src/vmm/mod.rs` `VmmDriver::launch(&VmSpec)` | **Unchanged** — already takes `Vec<BlockDisk>`. |
| CH driver | `crates/izba-core/src/vmm/cloud_hypervisor.rs` (~83) | **No logic change** — already order-driven `--disk` enumeration. Covered by tests. |
| OpenVMM driver | `crates/izba-core/src/vmm/openvmm.rs` `disk_port()`/`--pcie-root-port` (~35, ~89) | **No logic change** — already one PCIe root port per disk in order. Covered by tests. |
| Kernel cmdline | wherever `start()` builds `console=ttyS0 izba.hostname=…` | Append `izba.volume=<guest_path>` per volume, in `vdc,vdd,…` order. |
| Guest mount plan | `crates/izba-init/src/mounts.rs` `rootfs_mount_plan()` + `main.rs` boot (~84–93) | Parameterize: after overlay + virtiofs, for each cmdline `izba.volume`, format-if-blank `/dev/vd{c,d,…}` and mount at `/rootfs<guest_path>`. |

Because the trait and both drivers are already order-driven over `Vec<BlockDisk>`,
the *driver* layer needs **no behavioral change** — only the host that fills the
vector, the cmdline, and the guest that consumes it. The contract doc in
`CLAUDE.md` is updated to state the new enumeration + the cmdline binding.

### 3.2 Volume identity & storage

```
ephemeral:   <data>/sandboxes/<name>/volumes/<index>.img      (reaped on rm)
persistent:  <data>/volumes/<volname>.img                     (survives rm)
```

A new `Paths::volumes_dir()` → `<data>/volumes/`. Ephemeral images sit under the
existing sandbox dir, so the existing `rm` (delete the sandbox dir) reaps them for
free; persistent images are never touched by `rm`.

### 3.3 Data model

```rust
// crates/izba-core/src/state.rs  (and re-exported as needed)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeSpec {
    /// `Some(name)` ⇒ persistent (<data>/volumes/<name>.img);
    /// `None` ⇒ ephemeral (<sandbox>/volumes/<index>.img).
    pub name: Option<String>,
    /// Absolute guest mountpoint, e.g. `/var/lib/docker`.
    pub guest_path: PathBuf,
    /// Provisioned size in bytes (sparse).
    pub size_bytes: u64,
}
```

- Added to `SandboxConfig` as `#[serde(default)] pub volumes: Vec<VolumeSpec>` —
  back-compatible (old configs deserialize with an empty vec).
- Added to `DaemonCreate` and `CreateOpts` as `volumes: Vec<VolumeSpec>`.
- Volumes are **passive disks** — no new `RunState` pid tracking. izbad re-adopts
  them purely from `config.json` on startup, exactly as it adopts the rest of the
  sandbox from disk.

### 3.4 Lifecycle

- **create** (`sandbox::create`): for each volume, resolve its image path
  (ephemeral → sandbox dir; persistent → `volumes_dir`). Create the sparse image
  (`set_len`) and best-effort host `mkfs.ext4` **only if the image does not already
  exist** — an existing persistent image is attached as-is (no reformat, preserving
  data). Same create+format pattern as `rw.img` (`sandbox.rs` ~181–218,
  `rwdisk.rs`).
- **start**: assemble the disk vector + cmdline from `config.volumes`. Enforce
  **single-writer**: error if a referenced persistent volume is already referenced
  by another *live* sandbox (liveness via the existing pid + starttime identity).
- **rm**: unchanged — deletes the sandbox dir (ephemeral images go with it).
  Persistent images in `<data>/volumes/` are deliberately left.
- **boot** (guest): `init` reads the ordered `izba.volume` cmdline entries, and for
  the matching `/dev/vd{c,d,…}` runs the existing `ensure_formatted` (lazy ext4),
  then mounts at `/rootfs<guest_path>` after the overlay + virtiofs shares.

### 3.5 `izba volume prune`

- **New `DaemonRequest::VolumePrune`** → handler scans `<data>/volumes/*.img`,
  cross-references **every** existing sandbox `config.json`, and `unlink`s each
  image not referenced by any sandbox (running or stopped — referenced-by-config is
  the keep rule, mirroring Docker). Returns `{ removed: Vec<String>, reclaimed_bytes: u64 }`.
- **New CLI `izba volume prune`** (a `volume` subcommand namespace, leaving room for
  the deferred verbs): prints removed names + reclaimed bytes. Interactive use
  confirms before deleting; `-f/--force` skips confirmation (tests use `--force`).
- The daemon owns the scan+unlink (consistent with `rm` flowing through izbad and
  the disk-state model), so two CLIs never race on the same image.

## 4. CLI grammar

```
izba run … --volume [NAME:]GUEST_PATH:SIZE   (repeatable)
```

- `NAME` present ⇒ persistent; absent ⇒ ephemeral.
- `GUEST_PATH` absolute; **unique per sandbox**.
- `SIZE` accepts `g`/`m` suffixes (e.g. `2g`, `512m`).
- `NAME` matches `^[a-z0-9][a-z0-9_-]*$`.
- At most **24** volumes per sandbox.
- Parsing lives in a small, unit-tested `parse_volume_flag` helper so the grammar
  is testable without a VM.

`izba volume prune [-f|--force]`.

## 5. Testing

### Host unit tests (no VM, no bind, no KVM)
- `parse_volume_flag`: ephemeral vs named; size suffix parsing; rejects relative
  path, bad name, dup guest path, > 24 volumes.
- Disk-vector assembly: volumes appended after `rw.img` in declaration order
  (vdc, vdd, …); `<= 24` boundary error.
- Kernel cmdline construction: `izba.volume` entries present, ordered, one per
  volume.
- `SandboxConfig` round-trip with `volumes`; **back-compat**: a config without the
  field deserializes to an empty vec.
- Single-writer conflict detection (referenced-by-live-sandbox) with fake
  liveness.
- `mounts.rs`: volume mount-op generation from an ordered cmdline list (host-side,
  same style as the existing `rootfs_mount_plan` tests); mounts land after overlay
  + virtiofs.
- Prune selection logic: given a set of `<data>/volumes` images + a set of sandbox
  configs, returns exactly the unreferenced names (pure function over file lists,
  no unlink in the unit test).

### Integration (KVM, env-gated `IZBA_INTEGRATION=1`)
- A sandbox with **one ephemeral + one named** volume: write a sentinel file to
  each guest mountpoint; `stop`/`start`; assert both survive (data persists across
  VM restart).
- `rm` the sandbox; assert the **named** image remains in `<data>/volumes/` and the
  **ephemeral** image is gone.
- Create a **new** sandbox re-attaching the named volume; assert the sentinel
  written by the first sandbox is readable (re-attach works, no reformat).
- `izba volume prune --force` after the second sandbox is removed: assert the named
  image is reaped and reported.
- Test setup + teardown both `prune --force` so reruns are deterministic, and use a
  run-unique volume name as belt-and-suspenders.

### Windows/WHP parity
- The existing `hack/spike/validate-izba-windows.ps1` validation suite gains a
  single-volume case (create + write + stop/start + read), proving the OpenVMM
  per-disk PCIe routing carries the extra disk. Parity is the bar (roadmap
  principle #2).

### Exit criterion (roadmap M3, volumes half)
A sandbox with a sized persistent volume runs a real in-guest workload whose state
lives on the volume; data survives stop/start; the volume is re-attachable and
prunable — on **both** platforms.

## 6. Conflict-avoidance sequencing (parallel-with-the-app constraint)

The app's in-flight `feat/izba-app-p2-lifecycle` / `p3-logs-shell` branches and the
coverage branch touch the **daemon plane** (`proto.rs`, `client.rs`, `server.rs`),
`portfwd.rs`, `egress/mitm*.rs`, `build_info.rs`, `izba-cli/.../run.rs`,
`izba-init/main.rs`, and `tests/integration.rs`. To avoid churn:

1. **Land the cold-file plumbing first** — none of which those branches touch:
   `paths.rs` (`volumes_dir`), `state.rs` (`VolumeSpec` + `SandboxConfig.volumes`),
   `mounts.rs` parameterization, `sandbox.rs` disk assembly + create/format, init
   format/mount of `/dev/vd{c,d,…}`, and the `parse_volume_flag` helper.
2. **Wire the hot collision points last**, as one small additive commit:
   `DaemonCreate.volumes` + `DaemonRequest::VolumePrune` (additive enum
   variants/fields in `proto.rs`), the `server.rs` prune handler, the `run.rs`
   `--volume` flag, and the `izba volume` subcommand. These are additive — a
   mechanical rebase over the app branches, not overlapping edits.
3. `tests/integration.rs` is shared with the coverage branch; add the volume
   integration test as a **new** `#[test]` fn (append-only) to minimize conflict,
   or in a new `tests/volumes.rs` file if cleaner.

## 7. Documentation updates bundled here

- `CLAUDE.md` **Disk order** + **Cmdline chain** contracts: new enumeration
  (`vol₀=vdc…`) and the `izba.volume=<guest_path>` ordered binding.
- `docs/roadmap.md` reconciliation: mark **M2 done** (it is already merged — the
  `egress/mitm*`, `dns_snoop`, `audit`, `netlog` code is in-tree) and re-cut M3 as
  the in-flight milestone.
- `README.md` command surface: `--volume` flag + `izba volume prune`.
