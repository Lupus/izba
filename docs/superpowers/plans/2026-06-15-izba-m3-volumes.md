# izba M3 — User-declared volumes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach user-declared ephemeral/persistent block-device volumes to a sandbox, formatted ext4 and mounted at declared guest paths, plus `izba volume prune`.

**Architecture:** Volumes append to the `[erofs=vda, rw=vdb]` disk list as `vdc, vdd, …`. The host passes ordered guest mountpoints on the kernel cmdline (`izba.volumes=<p0>,<p1>`); the guest formats-if-blank and mounts each `/dev/vd{c…}` after the overlay. Named volumes persist under `<data>/volumes/`; anonymous ones live in the sandbox dir. Design: `docs/superpowers/specs/2026-06-15-izba-m3-volumes-design.md`.

**Tech Stack:** Rust (izba-core, izba-init musl, izba-cli), Cloud Hypervisor + OpenVMM drivers (both already order-driven over `Vec<BlockDisk>` — no driver change).

**Build env (worktree):** `source .cargo-env` first (worktree-local, points at the root toolchain).

**Sequencing (parallel-with-app, no churn):** Tasks 1–7 touch *cold* files no app/coverage branch touches. Tasks 8–10 are the hot collision points (`proto.rs`, `run.rs`) — additive only, landed last. Task 11 = docs. Task 12 = integration (KVM/WHP, env-gated).

---

## File structure

- **Create** `crates/izba-core/src/volume.rs` — `VolumeSpec` + flag parse + validate + size parse + cmdline encode + image-path + prune selection. One focused module both `state`, `proto`, `sandbox`, and the CLI use.
- **Modify** `crates/izba-core/src/paths.rs` — `volumes_dir()`.
- **Modify** `crates/izba-core/src/state.rs` — `SandboxConfig.volumes`.
- **Modify** `crates/izba-core/src/lib.rs` — `pub mod volume;`.
- **Modify** `crates/izba-core/src/sandbox.rs` — `CreateOpts.volumes`; create images; start disk-list + cmdline; single-writer check.
- **Modify** `crates/izba-init/src/mounts.rs` — `volume_mount_plan()`.
- **Modify** `crates/izba-init/src/main.rs` — format + mount volumes from cmdline.
- **Modify** `crates/izba-core/src/daemon/proto.rs` — `DaemonCreate.volumes`; `VolumePrune` req + `Pruned` resp.
- **Modify** `crates/izba-core/src/daemon/server.rs` — map volumes into `CreateOpts`; `VolumePrune` handler.
- **Modify** `crates/izba-cli/src/commands/run.rs` — `--volume` flag.
- **Create** `crates/izba-cli/src/commands/volume.rs` — `izba volume prune`.
- **Modify** `crates/izba-cli/src/main.rs` + `commands/mod.rs` — wire the `volume` subcommand.
- **Modify** `CLAUDE.md`, `docs/roadmap.md`, `README.md` — contracts + reconciliation.
- **Create** `crates/izba-core/tests/volumes.rs` — KVM-gated integration test.
- **Modify** `hack/spike/validate-izba-windows.ps1` — WHP volume case.

---

## Task 1: `volume` module — types, size parse, flag parse, validate

**Files:**
- Create: `crates/izba-core/src/volume.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod volume;`)

- [ ] **Step 1: Write failing tests** in `volume.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_anonymous_ephemeral() {
        let v = parse_volume_flag("/var/lib/docker:2g").unwrap();
        assert_eq!(v.name, None);
        assert_eq!(v.guest_path, PathBuf::from("/var/lib/docker"));
        assert_eq!(v.size_bytes, 2 * 1024 * 1024 * 1024);
        assert!(!v.is_persistent());
    }

    #[test]
    fn parses_named_persistent() {
        let v = parse_volume_flag("cache:/data:512m").unwrap();
        assert_eq!(v.name.as_deref(), Some("cache"));
        assert_eq!(v.guest_path, PathBuf::from("/data"));
        assert_eq!(v.size_bytes, 512 * 1024 * 1024);
        assert!(v.is_persistent());
    }

    #[test]
    fn rejects_relative_path() {
        assert!(parse_volume_flag("rel/path:1g").is_err());
    }

    #[test]
    fn rejects_bad_name() {
        assert!(parse_volume_flag("Bad_NAME:/d:1g").is_err()); // uppercase
        assert!(parse_volume_flag("-bad:/d:1g").is_err());     // leading dash
    }

    #[test]
    fn rejects_comma_in_path() {
        // commas are the cmdline list delimiter
        assert!(parse_volume_flag("/a,b:1g").is_err());
    }

    #[test]
    fn rejects_zero_size() {
        assert!(parse_volume_flag("/d:0").is_err());
    }

    #[test]
    fn size_suffixes() {
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("10m").unwrap(), 10 * (1 << 20));
        assert_eq!(parse_size("2G").unwrap(), 2 << 30);
        assert!(parse_size("").is_err());
        assert!(parse_size("5k").is_err()); // only g/m
    }

    #[test]
    fn validate_rejects_dup_guest_path() {
        let vs = vec![
            parse_volume_flag("/d:1g").unwrap(),
            parse_volume_flag("x:/d:1g").unwrap(),
        ];
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_rejects_dup_name() {
        let vs = vec![
            parse_volume_flag("c:/a:1g").unwrap(),
            parse_volume_flag("c:/b:1g").unwrap(),
        ];
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_rejects_too_many() {
        let vs: Vec<_> = (0..25)
            .map(|i| parse_volume_flag(&format!("/m{i}:1g")).unwrap())
            .collect();
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_accepts_24() {
        let vs: Vec<_> = (0..24)
            .map(|i| parse_volume_flag(&format!("/m{i}:1g")).unwrap())
            .collect();
        assert!(validate_volumes(&vs).is_ok());
    }

    #[test]
    fn cmdline_value_is_ordered_paths() {
        let vs = vec![
            parse_volume_flag("/a:1g").unwrap(),
            parse_volume_flag("c:/b:1g").unwrap(),
        ];
        assert_eq!(cmdline_value(&vs), "/a,/b");
        assert_eq!(cmdline_value(&[]), "");
    }
}
```

- [ ] **Step 2: Run, expect fail** — `source .cargo-env && cargo test -p izba-core volume:: 2>&1 | tail`. Expected: compile error (module/types absent).

- [ ] **Step 3: Implement** the module head:

```rust
//! User-declared block-device volumes: parsing, validation, and the cmdline
//! encoding that binds each volume to its `/dev/vd{c…}` slot by ORDER.
//!
//! A volume becomes an extra virtio-blk disk appended after rw.img, so the
//! Nth declared volume is the Nth extra disk (vdc, vdd, …). The guest mount
//! plan keys off declaration order via the `izba.volumes` kernel cmdline list.

use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;

/// Max user volumes per sandbox: 26 virtio-blk slots minus vda (erofs) and
/// vdb (rw). OpenVMM's `disk_port` asserts `< 26`; we validate the friendly
/// limit at the host boundary so a clear error replaces a driver panic.
pub const MAX_VOLUMES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    /// `Some` ⇒ persistent (<data>/volumes/<name>.img, survives rm);
    /// `None` ⇒ ephemeral (<sandbox>/volumes/<index>.img, reaped with rm).
    pub name: Option<String>,
    /// Absolute guest mountpoint. No commas (the cmdline list delimiter).
    pub guest_path: PathBuf,
    /// Provisioned (sparse) size in bytes.
    pub size_bytes: u64,
}

impl VolumeSpec {
    pub fn is_persistent(&self) -> bool {
        self.name.is_some()
    }

    /// Host path of this volume's backing image. `index` is the volume's
    /// position in the sandbox's volume list (only used for anonymous ones).
    pub fn image_path(&self, paths: &Paths, sandbox: &str, index: usize) -> PathBuf {
        match &self.name {
            Some(name) => paths.volume_image(name),
            None => paths
                .sandbox_dir(sandbox)
                .join("volumes")
                .join(format!("{index}.img")),
        }
    }
}

fn valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// `<g|m>`-suffixed size → bytes. Only gibi/mebi to keep the grammar tight.
pub fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('g') | Some('G') => (&s[..s.len() - 1], 1u64 << 30),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        _ => bail!("size {s:?} must end in 'g' or 'm'"),
    };
    let n: u64 = num.parse().with_context(|| format!("bad size {s:?}"))?;
    if n == 0 {
        bail!("size must be > 0");
    }
    Ok(n * mult)
}

/// Parse `[NAME:]GUEST_PATH:SIZE`. NAME present ⇒ persistent.
pub fn parse_volume_flag(s: &str) -> anyhow::Result<VolumeSpec> {
    let parts: Vec<&str> = s.split(':').collect();
    let (name, path, size) = match parts.as_slice() {
        [path, size] => (None, *path, *size),
        [name, path, size] => (Some(name.to_string()), *path, *size),
        _ => bail!("volume {s:?} must be [NAME:]GUEST_PATH:SIZE"),
    };
    if let Some(n) = &name {
        if !valid_name(n) {
            bail!("volume name {n:?} must match [a-z0-9][a-z0-9_-]*");
        }
    }
    if !path.starts_with('/') {
        bail!("volume guest path {path:?} must be absolute");
    }
    if path.contains(',') {
        bail!("volume guest path {path:?} must not contain a comma");
    }
    Ok(VolumeSpec {
        name,
        guest_path: PathBuf::from(path),
        size_bytes: parse_size(size)?,
    })
}

/// Whole-list invariants: count ceiling, unique guest paths, unique names.
pub fn validate_volumes(volumes: &[VolumeSpec]) -> anyhow::Result<()> {
    if volumes.len() > MAX_VOLUMES {
        bail!("at most {MAX_VOLUMES} volumes per sandbox (got {})", volumes.len());
    }
    let mut paths = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    for v in volumes {
        if !paths.insert(&v.guest_path) {
            bail!("duplicate volume guest path {}", v.guest_path.display());
        }
        if let Some(n) = &v.name {
            if !names.insert(n) {
                bail!("duplicate volume name {n:?}");
            }
        }
    }
    Ok(())
}

/// Ordered, comma-joined guest paths for the `izba.volumes=` cmdline key.
pub fn cmdline_value(volumes: &[VolumeSpec]) -> String {
    volumes
        .iter()
        .map(|v| v.guest_path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(",")
}
```

Add to `crates/izba-core/src/lib.rs` near the other `pub mod` lines: `pub mod volume;`.

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-core volume:: 2>&1 | tail`. Expected: all `volume::tests` PASS. (`paths.volume_image` is added in Task 2 — until then this won't compile; do Task 2's `volumes_dir`/`volume_image` first if needed, or stub. **Order Task 2 before Step 4.**)

- [ ] **Step 5: Commit** `git add crates/izba-core/src/volume.rs crates/izba-core/src/lib.rs && git commit -m "feat(core): volume spec — flag/size parse, validation, cmdline encode"`

---

## Task 2: `Paths::volumes_dir()` + `volume_image()`

**Files:** Modify `crates/izba-core/src/paths.rs`

- [ ] **Step 1: Failing test** — add to `paths.rs` tests:

```rust
#[test]
fn volume_paths_compose() {
    let p = Paths::with_root("/data/izba".into());
    assert_eq!(p.volumes_dir(), PathBuf::from("/data/izba/volumes"));
    assert_eq!(
        p.volume_image("cache"),
        PathBuf::from("/data/izba/volumes/cache.img")
    );
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core volume_paths_compose 2>&1 | tail`.

- [ ] **Step 3: Implement** in the `impl Paths` block:

```rust
/// Directory for persistent (named) volume images: `<root>/volumes`.
pub fn volumes_dir(&self) -> PathBuf {
    self.root.join("volumes")
}

/// Backing image for a persistent volume.
pub fn volume_image(&self, name: &str) -> PathBuf {
    self.volumes_dir().join(format!("{name}.img"))
}
```

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-core volume_paths_compose 2>&1 | tail`.

- [ ] **Step 5: Commit** `git add crates/izba-core/src/paths.rs && git commit -m "feat(core): Paths::volumes_dir + volume_image"`

---

## Task 3: `SandboxConfig.volumes` (back-compat serde default)

**Files:** Modify `crates/izba-core/src/state.rs`

- [ ] **Step 1: Failing test** — add to `state.rs` tests (create a `tests` mod if none; check first):

```rust
#[test]
fn config_without_volumes_defaults_empty() {
    let json = r#"{"image_digest":"sha256:x","image_ref":"img",
        "cpus":2,"mem_mb":1024,"workspace":"/w"}"#;
    let c: SandboxConfig = serde_json::from_str(json).unwrap();
    assert!(c.volumes.is_empty());
    assert!(c.ports.is_empty());
}

#[test]
fn config_roundtrips_volumes() {
    let c = SandboxConfig {
        image_digest: "sha256:x".into(),
        image_ref: "img".into(),
        cpus: 2,
        mem_mb: 1024,
        workspace: "/w".into(),
        ports: vec![],
        volumes: vec![crate::volume::VolumeSpec {
            name: Some("cache".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 30,
        }],
    };
    let s = serde_json::to_string(&c).unwrap();
    let back: SandboxConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.volumes, c.volumes);
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core config_ 2>&1 | tail`.

- [ ] **Step 3: Implement** — add the field to `SandboxConfig`:

```rust
    /// User-declared volumes (extra block devices). Defaults to empty so
    /// configs written before this feature still deserialize.
    #[serde(default)]
    pub volumes: Vec<crate::volume::VolumeSpec>,
```

- [ ] **Step 4: Run, expect pass.** (Other `SandboxConfig { … }` literals across the crate now need `volumes: vec![]` — fix compile errors as they surface; `sandbox::create` is updated in Task 5.)

- [ ] **Step 5: Commit** `git add crates/izba-core/src/state.rs && git commit -m "feat(core): SandboxConfig.volumes (serde-default for back-compat)"`

---

## Task 4: guest mount plan for volumes (`mounts.rs`)

**Files:** Modify `crates/izba-init/src/mounts.rs`

- [ ] **Step 1: Failing test** — add to `mounts.rs` tests:

```rust
#[test]
fn volume_plan_maps_order_to_vdc_onward() {
    let plan = volume_mount_plan(&["/var/lib/docker", "/data"]);
    assert_eq!(plan.len(), 2);
    assert_eq!(
        op(&plan, 0),
        ("/dev/vdc", "/rootfs/var/lib/docker", "ext4", vec![], "")
    );
    assert_eq!(op(&plan, 1), ("/dev/vdd", "/rootfs/data", "ext4", vec![], ""));
}

#[test]
fn volume_plan_empty() {
    assert!(volume_mount_plan(&[]).is_empty());
}

#[test]
fn volume_devices_match_plan() {
    assert_eq!(volume_device(0), "/dev/vdc");
    assert_eq!(volume_device(2), "/dev/vde");
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-init volume_ 2>&1 | tail`.

- [ ] **Step 3: Implement** in `mounts.rs`:

```rust
/// Guest block device for the Nth user volume: vdc, vdd, … (vda=erofs,
/// vdb=rw). Mirrors the host disk-list order and OpenVMM's `disk_port`.
pub fn volume_device(index: usize) -> String {
    format!("/dev/vd{}", (b'c' + index as u8) as char)
}

/// Mount ops for user volumes, one per guest path in declaration order.
/// Mounted under /rootfs AFTER the overlay + virtiofs shares. ext4, no
/// special flags. Targets are created by [`apply`].
pub fn volume_mount_plan(guest_paths: &[&str]) -> Vec<MountOp> {
    guest_paths
        .iter()
        .enumerate()
        .map(|(i, gp)| {
            let target = format!("/rootfs{}", gp);
            MountOp::new(&volume_device(i), &target, "ext4", &[], "")
        })
        .collect()
}
```

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-init volume_ 2>&1 | tail`.

- [ ] **Step 5: Commit** `git add crates/izba-init/src/mounts.rs && git commit -m "feat(init): volume_mount_plan — vdc+ ext4 mounts under /rootfs"`

---

## Task 5: guest boot — format + mount volumes (`izba-init/main.rs`)

**Files:** Modify `crates/izba-init/src/main.rs`

(Guest-only syscalls; the testable logic lives in Task 4. This wires it.)

- [ ] **Step 1: Implement** — after the existing `mounts::apply(&rootfs_plan[2..])` line (~102), add:

```rust
    // User volumes (vdc, vdd, …): format-if-blank then mount under /rootfs,
    // in the order the host declared them on the cmdline.
    let vols: Vec<&str> = params
        .get("izba.volumes")
        .map(|s| s.split(',').filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    for (i, _gp) in vols.iter().enumerate() {
        let dev = mounts::volume_device(i);
        rwdisk::ensure_formatted(Path::new(&dev))
            .with_context(|| format!("formatting volume {dev}"))?;
    }
    mounts::apply(&mounts::volume_mount_plan(&vols)).context("volume mounts")?;
```

- [ ] **Step 2: Build the static init** — `cargo build -p izba-init --target x86_64-unknown-linux-musl --release 2>&1 | tail`. Expected: builds clean (musl, static).

- [ ] **Step 3: Workspace test** — `cargo test -p izba-init 2>&1 | tail`. Expected: PASS.

- [ ] **Step 4: Commit** `git add crates/izba-init/src/main.rs && git commit -m "feat(init): format + mount user volumes from izba.volumes cmdline"`

---

## Task 6: `CreateOpts.volumes` + image creation in `sandbox::create`

**Files:** Modify `crates/izba-core/src/sandbox.rs`

- [ ] **Step 1: Failing test** — add to `sandbox.rs` tests (a `create` test that exercises volume image creation; use a temp `Paths`):

```rust
#[test]
fn create_provisions_volume_images() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().into());
    let opts = CreateOpts {
        image_digest: "sha256:x".into(),
        image_ref: "img".into(),
        cpus: 1,
        mem_mb: 256,
        workspace: tmp.path().into(),
        rw_size_gb: 1,
        ports: vec![],
        volumes: vec![
            crate::volume::VolumeSpec { name: None, guest_path: "/eph".into(), size_bytes: 1 << 20 },
            crate::volume::VolumeSpec { name: Some("cache".into()), guest_path: "/data".into(), size_bytes: 1 << 20 },
        ],
    };
    create(&paths, "web", &opts).unwrap();
    // ephemeral under the sandbox dir, persistent under <data>/volumes
    assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
    assert!(paths.volume_image("cache").exists());
    // config records both
    let cfg: SandboxConfig =
        load_json(&paths.sandbox_dir("web").join(CONFIG_FILE)).unwrap().unwrap();
    assert_eq!(cfg.volumes.len(), 2);
}

#[test]
fn create_keeps_existing_persistent_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().into());
    std::fs::create_dir_all(paths.volumes_dir()).unwrap();
    // pre-existing persistent image with sentinel bytes
    std::fs::write(paths.volume_image("keep"), b"SENTINEL-DATA").unwrap();
    let opts = CreateOpts {
        image_digest: "sha256:x".into(), image_ref: "img".into(),
        cpus: 1, mem_mb: 256, workspace: tmp.path().into(), rw_size_gb: 1,
        ports: vec![],
        volumes: vec![crate::volume::VolumeSpec {
            name: Some("keep".into()), guest_path: "/data".into(), size_bytes: 1 << 20 }],
    };
    create(&paths, "web", &opts).unwrap();
    // not truncated / reformatted — sentinel survives
    let data = std::fs::read(paths.volume_image("keep")).unwrap();
    assert!(data.starts_with(b"SENTINEL-DATA"));
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core create_ 2>&1 | tail`.

- [ ] **Step 3: Implement.** Add `pub volumes: Vec<crate::volume::VolumeSpec>` to `CreateOpts`. In `create()`'s `populate` closure: add `volumes: opts.volumes.clone()` to the `SandboxConfig { … }` literal; then after the rw.img block, provision each volume. Factor the existing sparse-create + best-effort mkfs into a helper and reuse it:

```rust
// (new helper near mark_sparse)
/// Create a sparse ext4-preformatted image at `path` of `size_bytes`, unless
/// it already exists (persistent volumes are reused as-is). Best-effort mkfs:
/// the guest reformats a blank image if the host has no mkfs.ext4.
fn ensure_volume_image(path: &Path, size_bytes: u64) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(()); // persistent reuse — never reformat existing data
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    mark_sparse(&f);
    f.set_len(size_bytes).with_context(|| format!("sizing {}", path.display()))?;
    drop(f);
    best_effort_mkfs(path);
    Ok(())
}
```

Extract the existing `match which::which("mkfs.ext4") { … }` body into `fn best_effort_mkfs(path: &Path)` and call it for both `rw.img` and each volume. Then in `populate`:

```rust
        for (i, v) in opts.volumes.iter().enumerate() {
            let img = v.image_path(paths, name, i);
            ensure_volume_image(&img, v.size_bytes)
                .with_context(|| format!("provisioning volume {}", v.guest_path.display()))?;
        }
```

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-core create_ 2>&1 | tail`.

- [ ] **Step 5: Commit** `git add crates/izba-core/src/sandbox.rs && git commit -m "feat(core): provision volume images in sandbox::create (reuse persistent)"`

---

## Task 7: `sandbox::start` — disk list + cmdline + single-writer check

**Files:** Modify `crates/izba-core/src/sandbox.rs`

- [ ] **Step 1: Failing tests** — add a pure helper `build_vm_disks` + `build_cmdline` so they're unit-testable without launching, and test single-writer detection:

```rust
#[test]
fn disks_append_volumes_after_rw() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().into());
    let vols = vec![
        crate::volume::VolumeSpec { name: None, guest_path: "/a".into(), size_bytes: 1<<20 },
        crate::volume::VolumeSpec { name: Some("c".into()), guest_path: "/b".into(), size_bytes: 1<<20 },
    ];
    let disks = build_vm_disks(&paths, "web", "sha256:x", &vols);
    assert_eq!(disks.len(), 4); // erofs, rw, vol0, vol1
    assert!(disks[0].readonly && !disks[1].readonly);
    assert_eq!(disks[2].path, paths.sandbox_dir("web").join("volumes/0.img"));
    assert_eq!(disks[3].path, paths.volume_image("c"));
}

#[test]
fn cmdline_includes_volumes_when_present() {
    let vols = vec![crate::volume::VolumeSpec {
        name: None, guest_path: "/a".into(), size_bytes: 1<<20 }];
    assert!(build_cmdline("web", &vols).contains("izba.volumes=/a"));
    // no key when empty
    assert!(!build_cmdline("web", &[]).contains("izba.volumes"));
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core disks_append cmdline_includes 2>&1 | tail`.

- [ ] **Step 3: Implement** the helpers and use them in `start()`:

```rust
fn build_vm_disks(
    paths: &Paths,
    name: &str,
    image_digest: &str,
    volumes: &[crate::volume::VolumeSpec],
) -> Vec<BlockDisk> {
    let mut disks = vec![
        BlockDisk { path: ImageStore::new(paths).rootfs_path(image_digest), readonly: true },
        BlockDisk { path: paths.sandbox_dir(name).join("rw.img"), readonly: false },
    ];
    for (i, v) in volumes.iter().enumerate() {
        disks.push(BlockDisk { path: v.image_path(paths, name, i), readonly: false });
    }
    disks
}

fn build_cmdline(name: &str, volumes: &[crate::volume::VolumeSpec]) -> String {
    let mut c = format!("console=ttyS0 izba.hostname={name} izba.egress=1");
    if !volumes.is_empty() {
        c.push_str(&format!(" izba.volumes={}", crate::volume::cmdline_value(volumes)));
    }
    c
}
```

In `start()`: replace the inline `cmdline` + `disks: vec![…]` with `build_cmdline(name, &config.volumes)` and `build_vm_disks(paths, name, &config.image_digest, &config.volumes)`. Before `driver.launch`, add the single-writer guard:

```rust
    // Single-writer: a persistent volume may back at most one LIVE sandbox.
    for v in config.volumes.iter().filter(|v| v.is_persistent()) {
        if let Some(holder) = persistent_volume_holder(paths, v.name.as_deref().unwrap(), name)? {
            bail!(
                "persistent volume {:?} is in use by running sandbox '{holder}'",
                v.name.as_ref().unwrap()
            );
        }
    }
```

Add `persistent_volume_holder`: iterate `list()`-style over sandbox dirs, load each `config.json`, skip `self_name`, and if a live sandbox references the same volume name, return it. Reuse the existing `liveness_of`/`list` plumbing.

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-core disks_append cmdline_includes 2>&1 | tail`.

- [ ] **Step 5: Commit** `git add crates/izba-core/src/sandbox.rs && git commit -m "feat(core): start assembles volume disks + izba.volumes cmdline + single-writer guard"`

---

## Task 8: prune selection + execution (`volume.rs` + `sandbox.rs`)

**Files:** Modify `crates/izba-core/src/volume.rs`

- [ ] **Step 1: Failing test** — pure selection over (image names, referenced names):

```rust
#[test]
fn prune_selects_unreferenced() {
    let on_disk = ["cache".to_string(), "old".to_string(), "live".to_string()];
    let referenced: std::collections::HashSet<String> =
        ["live".to_string()].into_iter().collect();
    let mut got = unreferenced_volumes(&on_disk, &referenced);
    got.sort();
    assert_eq!(got, vec!["cache".to_string(), "old".to_string()]);
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core prune_selects 2>&1 | tail`.

- [ ] **Step 3: Implement** in `volume.rs`:

```rust
use std::collections::HashSet;

/// Volume names present on disk but not referenced by any sandbox config.
pub fn unreferenced_volumes(on_disk: &[String], referenced: &HashSet<String>) -> Vec<String> {
    on_disk.iter().filter(|n| !referenced.contains(*n)).cloned().collect()
}
```

Then add the IO driver `prune_volumes(paths) -> anyhow::Result<Pruned>` in `sandbox.rs` (it needs `list`/config access): scan `paths.volumes_dir()` for `*.img` → names; collect referenced names from every sandbox `config.json`'s `volumes`; `unreferenced_volumes(...)`; `fs::remove_file` each, summing freed bytes. Return `Pruned { removed: Vec<String>, reclaimed_bytes: u64 }` (define the struct in `volume.rs`).

- [ ] **Step 4: Run, expect pass.** Add a small `sandbox.rs` test that creates two volume images + one config referencing one, calls `prune_volumes`, asserts the other is removed.

- [ ] **Step 5: Commit** `git add crates/izba-core/src/volume.rs crates/izba-core/src/sandbox.rs && git commit -m "feat(core): prune_volumes — reap volume images unreferenced by any sandbox"`

---

## Task 9: daemon proto + server (HOT — additive only)

**Files:** Modify `crates/izba-core/src/daemon/proto.rs`, `crates/izba-core/src/daemon/server.rs`

- [ ] **Step 1: Failing test** — proto round-trip in `proto.rs` tests (extend the existing request/response sample lists with the new variants) and assert `DaemonCreate` carries volumes:

```rust
#[test]
fn create_carries_volumes() {
    let c = DaemonCreate {
        name: "web".into(), image_ref: "img".into(), cpus: 2, mem_mb: 512,
        workspace: "/w".into(), rw_size_gb: 8, ports: vec![],
        volumes: vec![crate::volume::VolumeSpec {
            name: Some("c".into()), guest_path: "/d".into(), size_bytes: 1<<30 }],
    };
    let s = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<DaemonCreate>(&s).unwrap().volumes.len(), 1);
}
```

- [ ] **Step 2: Run, expect fail** — `cargo test -p izba-core create_carries_volumes 2>&1 | tail`.

- [ ] **Step 3: Implement.** Add to `DaemonCreate`:

```rust
    #[serde(default)]
    pub volumes: Vec<crate::volume::VolumeSpec>,
```

Add a `DaemonRequest` variant `VolumePrune` and a `DaemonResponse` variant:

```rust
    // DaemonRequest:
    VolumePrune,
    // DaemonResponse:
    Pruned { removed: Vec<String>, reclaimed_bytes: u64 },
```

In `server.rs`: where `DaemonRequest::Create(c)` maps to `CreateOpts`, add `volumes: c.volumes.clone()`; call `crate::volume::validate_volumes(&c.volumes)?` first. Add a `DaemonRequest::VolumePrune =>` arm calling `sandbox::prune_volumes(&paths)?` → `DaemonResponse::Pruned { … }`.

- [ ] **Step 4: Run, expect pass** — `cargo test -p izba-core 2>&1 | tail`. Update any exhaustive `match` on `DaemonRequest`/`DaemonResponse` the compiler flags.

- [ ] **Step 5: Commit** `git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs && git commit -m "feat(daemon): DaemonCreate.volumes + VolumePrune/Pruned (additive)"`

---

## Task 10: CLI — `--volume` flag + `izba volume prune` (HOT — additive only)

**Files:** Modify `crates/izba-cli/src/commands/run.rs`, `crates/izba-cli/src/main.rs`, `crates/izba-cli/src/commands/mod.rs`; Create `crates/izba-cli/src/commands/volume.rs`

- [ ] **Step 1: Read** `run.rs` to find the clap `Run`/`Create` args struct + where it builds `DaemonCreate`. Add a repeatable arg:

```rust
    /// Attach a volume: [NAME:]GUEST_PATH:SIZE (named ⇒ persistent). Repeatable.
    #[arg(long = "volume", value_name = "SPEC")]
    volumes: Vec<String>,
```

Map it: `let volumes: Vec<_> = self.volumes.iter().map(|s| izba_core::volume::parse_volume_flag(s)).collect::<anyhow::Result<_>>()?; izba_core::volume::validate_volumes(&volumes)?;` then set `volumes` on the `DaemonCreate`.

- [ ] **Step 2:** Create `commands/volume.rs`:

```rust
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum VolumeCmd {
    /// Remove persistent volume images not referenced by any sandbox.
    Prune {
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        force: bool,
    },
}

pub fn run(cmd: &VolumeCmd, client: &mut izba_core::daemon::DaemonClient) -> anyhow::Result<()> {
    match cmd {
        VolumeCmd::Prune { force } => {
            if !force && !confirm("Remove all unreferenced persistent volumes?")? {
                println!("aborted");
                return Ok(());
            }
            match client.request(izba_core::daemon::proto::DaemonRequest::VolumePrune)? {
                izba_core::daemon::proto::DaemonResponse::Pruned { removed, reclaimed_bytes } => {
                    if removed.is_empty() {
                        println!("nothing to prune");
                    } else {
                        for n in &removed { println!("removed {n}"); }
                        println!("reclaimed {reclaimed_bytes} bytes");
                    }
                    Ok(())
                }
                other => anyhow::bail!("unexpected daemon response: {other:?}"),
            }
        }
    }
}
```

(Use the existing confirm helper if one exists — grep `fn confirm`; otherwise a minimal stdin y/N reader. `client.request` signature: match the existing CLI call sites.)

- [ ] **Step 3:** Register in `main.rs` clap enum (`Volume { #[command(subcommand)] cmd: VolumeCmd }`) and dispatch; add `pub mod volume;` to `commands/mod.rs`.

- [ ] **Step 4: Build + test** — `cargo build -p izba-cli 2>&1 | tail` then `cargo test -p izba-cli 2>&1 | tail`. Expected: PASS.

- [ ] **Step 5: Commit** `git add crates/izba-cli && git commit -m "feat(cli): izba run --volume + izba volume prune"`

---

## Task 11: docs — contracts + roadmap reconciliation

**Files:** Modify `CLAUDE.md`, `docs/roadmap.md`, `README.md`

- [ ] **Step 1:** `CLAUDE.md` **Disk order** contract: state the new enumeration `[rootfs.erofs (RO)=vda, rw.img (RW)=vdb, vol₀=vdc, …]` and that user volumes append after rw in declaration order. **Cmdline chain**: add `izba.volumes=<p0>,<p1>` (ordered guest mountpoints; init formats-if-blank + mounts each `/dev/vd{c…}`).

- [ ] **Step 2:** `docs/roadmap.md`: mark **M2 — DONE** (code is in-tree: `egress/mitm*.rs`, `dns_snoop.rs`, `audit.rs`, `izba netlog`); re-cut **M3** as in-flight with the volumes slice landed (resources already shipped). Update the "Where we are" paragraph.

- [ ] **Step 3:** `README.md`: add `--volume` to the command surface + a one-line `izba volume prune`.

- [ ] **Step 4: Commit** `git add CLAUDE.md docs/roadmap.md README.md && git commit -m "docs(m3): disk-order/cmdline contracts, roadmap M2-done reconciliation, README"`

---

## Task 12: integration coverage (KVM-gated) + WHP parity case

**Files:** Create `crates/izba-core/tests/volumes.rs`; Modify `hack/spike/validate-izba-windows.ps1`

- [ ] **Step 1:** Write `tests/volumes.rs` gated like the existing integration suite (`if std::env::var("IZBA_INTEGRATION").is_err() { return; }`). Scenario: create sandbox with `--volume`-equivalent (one ephemeral `/eph`, one named `data:/data`); exec writes a sentinel into each; `stop`+`start`; exec reads both back; `rm`; assert named image remains + ephemeral gone; new sandbox re-attaches `data:/data`; exec reads the sentinel; `volume prune --force`-equivalent reaps it. Prune in setup + teardown; unique volume name per run.

- [ ] **Step 2: Run locally (unsandboxed)** — `IZBA_INTEGRATION=1 cargo test -p izba-core --test volumes -- --test-threads=1 2>&1 | tail -30`. (Needs `/dev/kvm` + artifacts; run with the Bash sandbox disabled per CLAUDE.md.) Expected: PASS.

- [ ] **Step 3:** Add a single-volume case to `validate-izba-windows.ps1` (create + write + stop/start + read). Document it; it runs on the host via `powershell.exe` and in the e2e workflow.

- [ ] **Step 4: Commit** `git add crates/izba-core/tests/volumes.rs hack/spike/validate-izba-windows.ps1 && git commit -m "test(m3): KVM volume persistence integration + WHP parity case"`

---

## Final gate (all six, before pushing)

```sh
source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

All green → squash-free, push `feat/m3-volumes`, open PR.

## Self-review notes
- **Spec coverage:** classes (T1/T6), disk-order change (T7), cmdline channel (T5/T7), guest format+mount (T4/T5), prune (T8/T9/T10), single-writer (T7), back-compat (T3), docs (T11), tests incl. WHP parity (T12). All spec sections mapped.
- **Type consistency:** `VolumeSpec{name,guest_path,size_bytes}`, `image_path(paths,name,index)`, `volume_device`/`volume_mount_plan`, `prune_volumes`→`Pruned{removed,reclaimed_bytes}`, `DaemonRequest::VolumePrune`/`DaemonResponse::Pruned` — consistent across tasks.
