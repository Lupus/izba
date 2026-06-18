# MVP-B — Ports & Volumes in the Tauri app — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire port publishing and persistent/ephemeral volume management into the Tauri desktop app (create wizard + per-sandbox Ports/Volumes tabs + a top-level Storage view), plus the small additive backend slice it needs.

**Architecture:** Backend-first. Extend `izba-core` (volume model, daemon ops), then the CLI for parity, then the Tauri `DaemonApi`/command layer, then the React UI. Every proto change is additive (`#[serde(default)]` / new enum variants); `DAEMON_PROTO_VERSION` stays `1`.

**Tech Stack:** Rust (izba-core, izba-cli, Tauri 2 `app/src-tauri`), TypeScript/React + Vite + vitest (`app/src`).

**Spec:** `docs/superpowers/specs/2026-06-18-app-ports-volumes-mvp-b-design.md`.

## Global Constraints

- Conventional commits (`feat(core): …`, `feat(app): …`); TDD — test first, watch it fail, then implement.
- Six workspace gates green before any commit touching workspace crates: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- `app/src-tauri` is OUT of the workspace — after any change to `izba-core`/`izba-proto` public types run the **app gate**: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Unit tests NEVER bind unix/vsock listeners (sandbox EPERM); use temp-dir `Paths::with_root` and `UnixStream::pair`.
- `DAEMON_PROTO_VERSION` stays `1` (all changes additive).
- SonarCloud gate: no hardcoded test IPs in non-test code; `npm ci` stays `--ignore-scripts`-safe; React props readonly where the rule applies; app frontend must keep vitest coverage (new components need tests).

---

## Phase A — Core volume model (`crates/izba-core`)

### Task A1: Stable ephemeral id on `VolumeSpec`

**Files:**
- Modify: `crates/izba-core/src/volume.rs`

**Interfaces:**
- Produces: `VolumeSpec { name, guest_path, size_bytes, eph_id: Option<u64> }`; `VolumeSpec::image_path(&self, paths: &Paths, sandbox: &str) -> PathBuf` (index param dropped); `volume::assign_eph_ids(volumes: &mut [VolumeSpec])`.

- [ ] **Step 1: Write failing tests** in `volume.rs` `mod tests`:

```rust
#[test]
fn assign_eph_ids_numbers_ephemeral_in_order() {
    let mut vs = vec![
        parse_volume_flag("cache:/data:1g").unwrap(), // persistent
        parse_volume_flag("/eph0:1g").unwrap(),        // ephemeral
        parse_volume_flag("/eph1:1g").unwrap(),        // ephemeral
    ];
    assign_eph_ids(&mut vs);
    assert_eq!(vs[0].eph_id, None); // persistent untouched
    assert_eq!(vs[1].eph_id, Some(0));
    assert_eq!(vs[2].eph_id, Some(1));
}

#[test]
fn assign_eph_ids_continues_from_max_and_preserves_existing() {
    let mut vs = vec![
        VolumeSpec { name: None, guest_path: "/a".into(), size_bytes: 1 << 30, eph_id: Some(5) },
        parse_volume_flag("/b:1g").unwrap(), // new ephemeral, eph_id None
    ];
    assign_eph_ids(&mut vs);
    assert_eq!(vs[0].eph_id, Some(5)); // preserved
    assert_eq!(vs[1].eph_id, Some(6)); // max(5)+1
}

#[test]
fn image_path_uses_eph_id_not_position() {
    let paths = Paths::with_root("/data/izba".into());
    let eph = VolumeSpec { name: None, guest_path: "/eph".into(), size_bytes: 1 << 30, eph_id: Some(3) };
    let per = parse_volume_flag("cache:/data:1g").unwrap();
    assert_eq!(eph.image_path(&paths, "web"),
        PathBuf::from("/data/izba/sandboxes/web/volumes/3.img"));
    assert_eq!(per.image_path(&paths, "web"),
        PathBuf::from("/data/izba/volumes/cache.img"));
}
```

Also update the existing `image_path_ephemeral_vs_persistent` test: drop the `index` arg, set `eph_id: Some(0)` on the ephemeral spec, call `eph.image_path(&paths, "web")` → `…/volumes/0.img`.

- [ ] **Step 2: Run tests, verify they fail to compile** (missing field/fn).

Run: `cargo test -p izba-core volume:: 2>&1 | head -20`
Expected: compile error — no field `eph_id`, no fn `assign_eph_ids`.

- [ ] **Step 3: Implement.** Add the field to `VolumeSpec`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub name: Option<String>,
    pub guest_path: PathBuf,
    pub size_bytes: u64,
    /// Stable backing id for an ephemeral image (`<sandbox>/volumes/<id>.img`),
    /// assigned once at provision time and never recomputed from list position.
    /// `None` for persistent volumes (name-keyed) and for a freshly parsed spec
    /// (the backend assigns it at create/attach).
    #[serde(default)]
    pub eph_id: Option<u64>,
}
```

Set `eph_id: None` in `parse_volume_flag`'s returned literal. Rewrite `image_path` (drop `index`):

```rust
pub fn image_path(&self, paths: &Paths, sandbox: &str) -> PathBuf {
    match &self.name {
        Some(name) => paths.volume_image(name),
        None => {
            let id = self.eph_id.expect("ephemeral volume has no eph_id; assign at provision time");
            paths.sandbox_dir(sandbox).join("volumes").join(format!("{id}.img"))
        }
    }
}
```

Add:

```rust
/// Assign stable ids to ephemeral volumes lacking one: existing ids are kept,
/// new ones continue from `max+1` (or 0). Persistent volumes are untouched.
pub fn assign_eph_ids(volumes: &mut [VolumeSpec]) {
    let mut next = volumes.iter().filter_map(|v| v.eph_id).max().map_or(0, |m| m + 1);
    for v in volumes.iter_mut() {
        if v.name.is_none() && v.eph_id.is_none() {
            v.eph_id = Some(next);
            next += 1;
        }
    }
}
```

- [ ] **Step 4: Run tests, verify pass.** Run: `cargo test -p izba-core volume::` → PASS. (Callers of `image_path` in `sandbox.rs` will now fail to compile — fixed in A2; do not run the full crate build yet.)

- [ ] **Step 5: Commit.**

```bash
git add crates/izba-core/src/volume.rs
git commit -m "feat(core): stable eph_id for ephemeral volume images"
```

### Task A2: `create` assigns ids; disk assembly keys off `eph_id`

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (`build_vm_disks` ~166, `create` ~200, tests ~916)

**Interfaces:**
- Consumes: `VolumeSpec::image_path(paths, sandbox)`, `volume::assign_eph_ids`.

- [ ] **Step 1: Write failing test** in `sandbox.rs` `mod tests`:

```rust
#[test]
fn create_assigns_eph_ids_and_persists_them() {
    let paths = test_paths(); // existing helper used by create_provisions_volume_images
    let mut o = sample_opts();
    o.volumes = vec![
        crate::volume::parse_volume_flag("cache:/data:1g").unwrap(),
        crate::volume::parse_volume_flag("/scratch:1g").unwrap(),
    ];
    create(&paths, "web", &o).unwrap();
    let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE)).unwrap().unwrap();
    assert_eq!(cfg.volumes[0].eph_id, None);       // persistent
    assert_eq!(cfg.volumes[1].eph_id, Some(0));    // first ephemeral
    assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
}
```

(Reuse whatever `test_paths()`/`sample_opts()` helpers the existing volume tests already use; match their names.)

- [ ] **Step 2: Run, verify fail to compile** (`image_path` arity) and/or assertion fail.

Run: `cargo test -p izba-core sandbox::tests::create_assigns_eph_ids 2>&1 | head -20`

- [ ] **Step 3: Implement.** In `build_vm_disks`, drop the index:

```rust
for v in volumes.iter() {
    disks.push(BlockDisk { path: v.image_path(paths, name), readonly: false });
}
```

In `create`, assign ids before building config + provisioning:

```rust
let mut volumes = opts.volumes.clone();
crate::volume::assign_eph_ids(&mut volumes);
```

Use `volumes` (not `opts.volumes`) for the `SandboxConfig { …, volumes: volumes.clone() }` and the provisioning loop:

```rust
for v in volumes.iter() {
    let img = v.image_path(paths, name);
    ensure_volume_image(&img, v.size_bytes, paths.root())
        .with_context(|| format!("provisioning volume {}", v.guest_path.display()))?;
}
```

- [ ] **Step 4: Run the crate test suite, verify pass.**

Run: `cargo test -p izba-core 2>&1 | tail -20`
Expected: all PASS (existing `create_provisions_volume_images`, `disks_append_volumes_after_rw` still green — first ephemeral keeps `0.img`).

- [ ] **Step 5: Commit.**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): assign + persist eph_id at create; disks key off it"
```

### Task A3: `list_volumes` + `VolumeInfo`

**Files:**
- Modify: `crates/izba-core/src/volume.rs` (add `VolumeInfo`), `crates/izba-core/src/sandbox.rs` (add `list_volumes`)

**Interfaces:**
- Produces: `volume::VolumeInfo { name: String, size_bytes: u64, actual_bytes: u64, referenced_by: Vec<String> }`; `sandbox::list_volumes(paths: &Paths) -> anyhow::Result<Vec<VolumeInfo>>`.
- Consumes: existing private `referenced_volume_names(paths) -> anyhow::Result<HashSet<String>>` (used by `prune_volumes`).

- [ ] **Step 1: Write failing test** in `sandbox.rs` `mod tests`:

```rust
#[test]
fn list_volumes_reports_size_and_references() {
    let paths = test_paths();
    // Persistent volume referenced by sandbox "web".
    let mut o = sample_opts();
    o.volumes = vec![crate::volume::parse_volume_flag("cache:/data:1g").unwrap()];
    create(&paths, "web", &o).unwrap();
    let got = list_volumes(&paths).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "cache");
    assert_eq!(got[0].size_bytes, 1 << 30);
    assert_eq!(got[0].referenced_by, vec!["web".to_string()]);
}
```

- [ ] **Step 2: Run, verify fail.** `cargo test -p izba-core list_volumes 2>&1 | head -20` → unresolved `list_volumes`.

- [ ] **Step 3: Implement.** Add `VolumeInfo` to `volume.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub name: String,
    pub size_bytes: u64,
    pub actual_bytes: u64,
    pub referenced_by: Vec<String>,
}
```

Add `list_volumes` to `sandbox.rs` (mirror `prune_volumes`' scan):

```rust
/// Enumerate persistent volume images under `<data>/volumes`, with declared
/// size, on-disk allocation (best-effort), and which sandbox configs use them.
pub fn list_volumes(paths: &Paths) -> anyhow::Result<Vec<crate::volume::VolumeInfo>> {
    let dir = paths.volumes_dir();
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let referenced = referenced_volume_names(paths)?;
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let fname = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = fname.strip_suffix(".img") else { continue };
        let meta = entry.metadata()?;
        let mut refs: Vec<String> = referenced_by(paths, name)?;
        refs.sort();
        out.push(crate::volume::VolumeInfo {
            name: name.to_string(),
            size_bytes: meta.len(),
            actual_bytes: allocated_bytes(&meta),
            referenced_by: refs,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
```

Add two small private helpers near `referenced_volume_names`:

```rust
/// Sandboxes whose config references persistent volume `vol`.
fn referenced_by(paths: &Paths, vol: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let dir = paths.sandboxes_dir();
    if !dir.is_dir() { return Ok(out); }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let cfg_path = entry.path().join(CONFIG_FILE);
        let Some(cfg) = load_json::<SandboxConfig>(&cfg_path)? else { continue };
        if cfg.volumes.iter().any(|v| v.name.as_deref() == Some(vol)) {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

/// On-disk allocation: blocks*512 on Unix, file length elsewhere.
fn allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    { use std::os::unix::fs::MetadataExt; meta.blocks() * 512 }
    #[cfg(not(unix))]
    { meta.len() }
}
```

(If `referenced_volume_names` already iterates configs, factor its inner loop to reuse — otherwise the two helpers above are self-contained and fine.)

- [ ] **Step 4: Run, verify pass.** `cargo test -p izba-core 2>&1 | tail -10` → PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/izba-core/src/volume.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): list_volumes + VolumeInfo (size + referenced_by)"
```

### Task A4: guarded `remove_volume`

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs`

**Interfaces:**
- Produces: `sandbox::remove_volume(paths: &Paths, name: &str) -> anyhow::Result<u64>` (returns reclaimed bytes; errors if referenced or missing).

- [ ] **Step 1: Write failing tests:**

```rust
#[test]
fn remove_volume_refuses_when_referenced() {
    let paths = test_paths();
    let mut o = sample_opts();
    o.volumes = vec![crate::volume::parse_volume_flag("cache:/data:1g").unwrap()];
    create(&paths, "web", &o).unwrap();
    let err = remove_volume(&paths, "cache").unwrap_err().to_string();
    assert!(err.contains("in use"), "got: {err}");
    assert!(paths.volume_image("cache").exists());
}

#[test]
fn remove_volume_deletes_unreferenced() {
    let paths = test_paths();
    crate::sandbox::ensure_dirs_for_test(&paths); // or std::fs::create_dir_all(paths.volumes_dir())
    crate::volume::test_make_image(&paths.volume_image("old"), 1 << 20); // helper: create a small file
    let freed = remove_volume(&paths, "old").unwrap();
    assert!(!paths.volume_image("old").exists());
    assert!(freed > 0);
}
```

For the second test, if no such helpers exist, inline: `std::fs::create_dir_all(paths.volumes_dir()).unwrap(); std::fs::write(paths.volume_image("old"), vec![0u8; 4096]).unwrap();`.

- [ ] **Step 2: Run, verify fail.** `cargo test -p izba-core remove_volume 2>&1 | head -20`.

- [ ] **Step 3: Implement:**

```rust
/// Delete a single persistent volume image. Fails closed if any sandbox config
/// references it. Returns bytes reclaimed.
pub fn remove_volume(paths: &Paths, name: &str) -> anyhow::Result<u64> {
    let refs = referenced_by(paths, name)?;
    if !refs.is_empty() {
        bail!("volume '{name}' is in use by: {}", refs.join(", "));
    }
    let img = paths.volume_image(name);
    if !img.exists() {
        bail!("no such volume '{name}'");
    }
    let bytes = fs::metadata(&img).map(|m| m.len()).unwrap_or(0);
    fs::remove_file(&img).with_context(|| format!("removing {}", img.display()))?;
    Ok(bytes)
}
```

- [ ] **Step 4: Run, verify pass.** `cargo test -p izba-core 2>&1 | tail -10`.

- [ ] **Step 5: Commit.**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): guarded remove_volume (fail-closed if referenced)"
```

### Task A5: `attach_volume` / `detach_volume`

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs`

**Interfaces:**
- Produces: `sandbox::attach_volume(paths, name: &str, spec: VolumeSpec) -> anyhow::Result<()>`; `sandbox::detach_volume(paths, name: &str, guest_path: &std::path::Path) -> anyhow::Result<()>`.
- Consumes: `volume::{validate_volumes, assign_eph_ids}`, `ensure_volume_image`.

- [ ] **Step 1: Write failing tests:**

```rust
#[test]
fn attach_volume_appends_provisions_and_persists() {
    let paths = test_paths();
    create(&paths, "web", &sample_opts()).unwrap(); // no volumes
    let spec = crate::volume::parse_volume_flag("/scratch:1g").unwrap();
    attach_volume(&paths, "web", spec).unwrap();
    let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE)).unwrap().unwrap();
    assert_eq!(cfg.volumes.len(), 1);
    assert_eq!(cfg.volumes[0].eph_id, Some(0));
    assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
}

#[test]
fn attach_volume_rejects_duplicate_guest_path() {
    let paths = test_paths();
    create(&paths, "web", &sample_opts()).unwrap();
    attach_volume(&paths, "web", crate::volume::parse_volume_flag("/data:1g").unwrap()).unwrap();
    let err = attach_volume(&paths, "web", crate::volume::parse_volume_flag("x:/data:1g").unwrap())
        .unwrap_err().to_string();
    assert!(err.contains("duplicate"), "got: {err}");
}

#[test]
fn detach_volume_removes_entry_no_file_io() {
    let paths = test_paths();
    create(&paths, "web", &sample_opts()).unwrap();
    attach_volume(&paths, "web", crate::volume::parse_volume_flag("/data:1g").unwrap()).unwrap();
    let img = paths.sandbox_dir("web").join("volumes/0.img");
    assert!(img.exists());
    detach_volume(&paths, "web", std::path::Path::new("/data")).unwrap();
    let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE)).unwrap().unwrap();
    assert!(cfg.volumes.is_empty());
    assert!(img.exists(), "detach must not delete the backing image");
}
```

- [ ] **Step 2: Run, verify fail.** `cargo test -p izba-core attach_volume 2>&1 | head -20`.

- [ ] **Step 3: Implement:**

```rust
/// Append a volume to a sandbox's config (applied on next start). Validates the
/// new set, assigns an eph_id if ephemeral, provisions the backing image.
pub fn attach_volume(paths: &Paths, name: &str, spec: crate::volume::VolumeSpec) -> anyhow::Result<()> {
    let cfg_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig = load_json(&cfg_path)?
        .with_context(|| format!("no such sandbox '{name}'"))?;
    cfg.volumes.push(spec);
    crate::volume::validate_volumes(&cfg.volumes)?;
    crate::volume::assign_eph_ids(&mut cfg.volumes);
    let v = cfg.volumes.last().unwrap();
    ensure_volume_image(&v.image_path(paths, name), v.size_bytes, paths.root())
        .with_context(|| format!("provisioning volume {}", v.guest_path.display()))?;
    save_json(&cfg_path, &cfg)?;
    Ok(())
}

/// Drop the volume mounted at `guest_path` from a sandbox's config (applied on
/// next start). No image I/O — persistent images survive; an orphaned ephemeral
/// image is reclaimed at `rm`.
pub fn detach_volume(paths: &Paths, name: &str, guest_path: &std::path::Path) -> anyhow::Result<()> {
    let cfg_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig = load_json(&cfg_path)?
        .with_context(|| format!("no such sandbox '{name}'"))?;
    let before = cfg.volumes.len();
    cfg.volumes.retain(|v| v.guest_path != guest_path);
    if cfg.volumes.len() == before {
        bail!("no volume mounted at {} in sandbox '{name}'", guest_path.display());
    }
    save_json(&cfg_path, &cfg)?;
    Ok(())
}
```

- [ ] **Step 4: Run, verify pass.** `cargo test -p izba-core 2>&1 | tail -10`.

- [ ] **Step 5: Commit.**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): attach_volume/detach_volume edit config (apply on restart)"
```

---

## Phase B — Daemon protocol + dispatch

### Task B1: proto additions + roundtrip

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs`

**Interfaces:**
- Produces: `DaemonRequest::{VolumeList, VolumeRemove{name}, VolumeAttach{name, spec}, VolumeDetach{name, guest_path}}`; `PortPublish{name, rule, persist: bool}`; `SandboxDetail.volumes: Vec<VolumeSpec>`; `DaemonResponse::Volumes{volumes: Vec<VolumeInfo>}`.

- [ ] **Step 1: Edit `PortPublish`** to add `#[serde(default)] persist: bool`, add the four new request variants (place `VolumeList`/`VolumeRemove`/`VolumeAttach`/`VolumeDetach` near `VolumePrune`), add `#[serde(default)] pub volumes: Vec<crate::volume::VolumeSpec>` to `SandboxDetail`, and add `Volumes { volumes: Vec<crate::volume::VolumeInfo> }` to `DaemonResponse`.

```rust
PortPublish { name: String, rule: PortRule, #[serde(default)] persist: bool },
VolumeList,
VolumeRemove { name: String },
VolumeAttach { name: String, spec: crate::volume::VolumeSpec },
VolumeDetach { name: String, guest_path: PathBuf },
```

- [ ] **Step 2: Extend the `request_roundtrip` and `response_roundtrip` tests** with the new variants (the test asserts `format!("{req:?}")` round-trips). Add `persist: false` to the existing `PortPublish` literal, `volumes: vec![]` to the existing `SandboxDetail` literal, and one `DaemonResponse::Volumes { volumes: vec![] }` case.

- [ ] **Step 3: Run, verify pass.**

Run: `cargo test -p izba-core daemon::proto 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add crates/izba-core/src/daemon/proto.rs
git commit -m "feat(core): proto — VolumeList/Remove/Attach/Detach, PortPublish.persist, SandboxDetail.volumes"
```

### Task B2: daemon dispatch

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (`dispatch`, ~287–435)

**Interfaces:**
- Consumes: A3/A4/A5 core fns; `relays.active`, `sandbox::control`.

- [ ] **Step 1: Write failing tests** in `server.rs` `mod tests` (use the existing daemon test scaffolding — a `Daemon` over a temp `Paths`; mirror how `VolumePrune`/`Create` are tested there). Cover:
  - `dispatch(VolumeList)` returns `Volumes` listing a created persistent volume.
  - `dispatch(VolumeAttach{..})` then `Inspect` shows the volume in `SandboxDetail.volumes`.
  - `dispatch(VolumeDetach{..})` removes it.
  - `dispatch(VolumeRemove{referenced})` returns `Error`.
  - `PortPublish{persist:true}` writes the rule into `config.ports` (load config, assert present).
  - `PortUnpublish` drops it from `config.ports`.

(If the existing test harness can't bind relays, gate the port-relay assertions on the config-file effect only — `config.ports` is what the test checks, not a live listener.)

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** new arms in `dispatch`:

```rust
DaemonRequest::VolumeList => DaemonResponse::Volumes {
    volumes: sandbox::list_volumes(&d.paths)?,
},
DaemonRequest::VolumeRemove { name } => {
    let bytes = sandbox::remove_volume(&d.paths, &name)?;
    DaemonResponse::Pruned { removed: vec![name], reclaimed_bytes: bytes }
}
DaemonRequest::VolumeAttach { name, spec } => {
    sandbox::attach_volume(&d.paths, &name, spec)?;
    DaemonResponse::Ok
}
DaemonRequest::VolumeDetach { name, guest_path } => {
    sandbox::detach_volume(&d.paths, &name, &guest_path)?;
    DaemonResponse::Ok
}
```

Replace the `PortPublish` arm (note the new `persist` binding + idempotent relay + config write):

```rust
DaemonRequest::PortPublish { name, rule, persist } => {
    drop(sandbox::control(&d.paths, &name, d.connector())?);
    // Idempotent: re-publishing an identical active rule is a no-op for the
    // relay (this is what the app's "Make persistent" button does).
    if !d.relays.active(&name).iter().any(|r| *r == rule) {
        d.relays.publish(&d.paths, &name, rule.clone())?;
    }
    relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
    if persist {
        persist_port_rule(&d.paths, &name, &rule)?;
    }
    DaemonResponse::Ok
}
```

Update the `PortUnpublish` arm to also drop from config:

```rust
DaemonRequest::PortUnpublish { name, bind, host_port } => {
    sandbox_must_exist(&d.paths, &name)?;
    d.relays.unpublish(&name, bind, host_port)?;
    relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
    unpersist_port_rule(&d.paths, &name, bind, host_port)?;
    DaemonResponse::Ok
}
```

Update the `Inspect` arm to populate `volumes`: add `volumes: config.volumes` to the `SandboxDetail { … }` it builds (the `config` is already loaded there).

Add two helpers in `server.rs` (config rewrite by `(bind, host_port)` identity):

```rust
fn persist_port_rule(paths: &Paths, name: &str, rule: &PortRule) -> anyhow::Result<()> {
    let p = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig = load_json(&p)?.with_context(|| format!("no config for '{name}'"))?;
    if !cfg.ports.iter().any(|r| r.bind == rule.bind && r.host_port == rule.host_port) {
        cfg.ports.push(rule.clone());
        save_json(&p, &cfg)?;
    }
    Ok(())
}

fn unpersist_port_rule(paths: &Paths, name: &str, bind: Ipv4Addr, host_port: u16) -> anyhow::Result<()> {
    let p = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig = load_json(&p)?.with_context(|| format!("no config for '{name}'"))?;
    let before = cfg.ports.len();
    cfg.ports.retain(|r| !(r.bind == bind && r.host_port == host_port));
    if cfg.ports.len() != before { save_json(&p, &cfg)?; }
    Ok(())
}
```

Add `use std::net::Ipv4Addr;` / `use crate::state::PortRule;` imports if not present.

- [ ] **Step 4: Run, verify pass.** `cargo test -p izba-core 2>&1 | tail -15`.

- [ ] **Step 5: Run the full six gates.** `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` must be clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/izba-core/src/daemon/server.rs
git commit -m "feat(core): daemon dispatch for volume ops + port persist/unpersist + Inspect.volumes"
```

---

## Phase C — CLI parity (`crates/izba-cli`)

### Task C1: `port publish --persist`

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (`PortCmd::Publish`), `crates/izba-cli/src/commands/port.rs`

- [ ] **Step 1:** In `main.rs`, add to `PortCmd::Publish`: `#[arg(long)] persist: bool`. Find where `PortCmd::Publish` is dispatched (search `commands::port::publish`) and thread `persist` through.

- [ ] **Step 2:** In `port.rs`, change `publish(paths, name, rule_spec, persist: bool)` and set `persist` on the `DaemonRequest::PortPublish { name, rule, persist }`. Add a unit test that the existing `parse_key` tests stay green (no new parsing). Add `#[arg]` help: "Also persist this forward to the sandbox config (survives restart)".

- [ ] **Step 3: Run** `cargo test -p izba-cli 2>&1 | tail -10` → PASS; `cargo build -p izba-cli` clean.

- [ ] **Step 4: Commit.**

```bash
git add crates/izba-cli/src/main.rs crates/izba-cli/src/commands/port.rs
git commit -m "feat(cli): izba port publish --persist"
```

### Task C2: `izba volume ls`

**Files:**
- Modify: `crates/izba-cli/src/commands/volume.rs`

- [ ] **Step 1:** Add `Ls` to `VolumeCmd`:

```rust
/// List persistent volumes (size, usage, sandboxes referencing them)
Ls,
```

- [ ] **Step 2:** Add the handler + wire it in `run`:

```rust
VolumeCmd::Ls => ls(paths),
```

```rust
fn ls(paths: &Paths) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::VolumeList, &mut |_| {})? {
        DaemonResponse::Volumes { volumes } => {
            if volumes.is_empty() {
                println!("no persistent volumes");
            } else {
                println!("{:<20} {:>10} {:>10}  USED BY", "NAME", "SIZE", "USED");
                for v in &volumes {
                    let used_by = if v.referenced_by.is_empty() { "-".to_string() } else { v.referenced_by.join(",") };
                    println!("{:<20} {:>10} {:>10}  {}", v.name, v.size_bytes, v.actual_bytes, used_by);
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}
```

- [ ] **Step 3: Run** `cargo build -p izba-cli` clean; `cargo test -p izba-cli` PASS.

- [ ] **Step 4: Commit.** `git commit -m "feat(cli): izba volume ls"`.

### Task C3: `izba volume rm`

**Files:**
- Modify: `crates/izba-cli/src/commands/volume.rs`

- [ ] **Step 1:** Add to `VolumeCmd`:

```rust
/// Remove a single persistent volume (refused if any sandbox references it)
Rm {
    /// Volume name
    name: String,
    /// Skip the confirmation prompt (does NOT bypass the in-use guard)
    #[arg(short, long)]
    force: bool,
},
```

- [ ] **Step 2:** Wire in `run` (`VolumeCmd::Rm { name, force } => rm(paths, name, *force)`) and implement:

```rust
fn rm(paths: &Paths, name: &str, force: bool) -> anyhow::Result<i32> {
    if !force && !confirm(&format!("Remove persistent volume '{name}'?"))? {
        println!("aborted");
        return Ok(0);
    }
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::VolumeRemove { name: name.to_string() }, &mut |_| {})? {
        DaemonResponse::Pruned { reclaimed_bytes, .. } => {
            println!("removed {name} (reclaimed {reclaimed_bytes} bytes)");
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}
```

- [ ] **Step 3: Run** build + test → green.
- [ ] **Step 4: Commit.** `git commit -m "feat(cli): izba volume rm (guarded)"`.

### Task C4: `izba volume attach` / `detach`

**Files:**
- Modify: `crates/izba-cli/src/commands/volume.rs`

- [ ] **Step 1:** Add to `VolumeCmd`:

```rust
/// Attach a volume to a sandbox (applied on its next restart)
Attach {
    /// Sandbox name
    name: String,
    /// [VNAME:]GUEST_PATH:SIZE
    spec: String,
},
/// Detach the volume at GUEST_PATH from a sandbox (applied on next restart)
Detach {
    /// Sandbox name
    name: String,
    /// Guest mountpoint of the volume to remove
    guest_path: String,
},
```

- [ ] **Step 2:** Wire in `run` and implement:

```rust
fn attach(paths: &Paths, name: &str, spec: &str) -> anyhow::Result<i32> {
    let spec = izba_core::volume::parse_volume_flag(spec)?;
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::VolumeAttach { name: name.to_string(), spec }, &mut |_| {})?)?;
    println!("attached (applies on next restart of '{name}')");
    Ok(0)
}

fn detach(paths: &Paths, name: &str, guest_path: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::VolumeDetach { name: name.to_string(), guest_path: guest_path.into() },
        &mut |_| {})?)?;
    println!("detached (applies on next restart of '{name}')");
    Ok(0)
}
```

(`super::expect_ok` is the helper in `commands/mod.rs`.)

- [ ] **Step 3: Run** the six gates (this is the last CLI change) — all green.
- [ ] **Step 4: Commit.** `git commit -m "feat(cli): izba volume attach/detach (apply on restart)"`.

---

## Phase D — Tauri layer (`app/src-tauri`)

> From here, the **app gate** is the relevant test command. Run `cd app/src-tauri && cargo test` after each task.

### Task D1: `DaemonApi` trait + `RealDaemon` impls

**Files:**
- Modify: `app/src-tauri/src/daemon.rs`

**Interfaces:**
- Produces (new `DaemonApi` methods): `inspect(&mut self, name) -> Result<SandboxDetail>`; `port_list(&mut self, name) -> Result<Vec<PortRule>>`; `port_publish(&mut self, name, rule: PortRule, persist: bool) -> Result<()>`; `port_unpublish(&mut self, name, bind: Ipv4Addr, host_port: u16) -> Result<()>`; `volume_list(&mut self) -> Result<Vec<VolumeInfo>>`; `volume_remove(&mut self, name) -> Result<()>`; `volume_prune(&mut self) -> Result<volume::Pruned>`; `volume_attach(&mut self, name, spec: VolumeSpec) -> Result<()>`; `volume_detach(&mut self, name, guest_path: String) -> Result<()>`.
  (`SandboxDetail`, `PortRule`, `VolumeInfo`, `VolumeSpec`, `Pruned` are the `izba_core` types.)

- [ ] **Step 1:** Add the method signatures to the `DaemonApi` trait. Use fully-qualified `izba_core::…` types in signatures (the trait already does this for egress types).

- [ ] **Step 2:** Implement them on `RealDaemon` following the existing `with_client` pattern. Examples:

```rust
fn inspect(&mut self, name: &str) -> anyhow::Result<izba_core::daemon::proto::SandboxDetail> {
    let name = name.to_string();
    self.with_client(|c| match c.request(&DaemonRequest::Inspect { name }, &mut |_| {})? {
        DaemonResponse::Inspect(d) => Ok(d),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected Inspect reply: {other:?}"),
    })
}

fn port_list(&mut self, name: &str) -> anyhow::Result<Vec<izba_core::state::PortRule>> {
    let name = name.to_string();
    self.with_client(|c| match c.request(&DaemonRequest::PortList { name }, &mut |_| {})? {
        DaemonResponse::Ports { rules } => Ok(rules),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected PortList reply: {other:?}"),
    })
}

fn port_publish(&mut self, name: &str, rule: izba_core::state::PortRule, persist: bool) -> anyhow::Result<()> {
    let name = name.to_string();
    self.with_client(|c| expect_ok(c.request(&DaemonRequest::PortPublish { name, rule, persist }, &mut |_| {})?))
}

fn port_unpublish(&mut self, name: &str, bind: std::net::Ipv4Addr, host_port: u16) -> anyhow::Result<()> {
    let name = name.to_string();
    self.with_client(|c| expect_ok(c.request(&DaemonRequest::PortUnpublish { name, bind, host_port }, &mut |_| {})?))
}

fn volume_list(&mut self) -> anyhow::Result<Vec<izba_core::volume::VolumeInfo>> {
    self.with_client(|c| match c.request(&DaemonRequest::VolumeList, &mut |_| {})? {
        DaemonResponse::Volumes { volumes } => Ok(volumes),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected VolumeList reply: {other:?}"),
    })
}

fn volume_remove(&mut self, name: &str) -> anyhow::Result<()> {
    let name = name.to_string();
    self.with_client(|c| expect_ok(c.request(&DaemonRequest::VolumeRemove { name }, &mut |_| {})?))
}

fn volume_prune(&mut self) -> anyhow::Result<izba_core::volume::Pruned> {
    self.with_client(|c| match c.request(&DaemonRequest::VolumePrune, &mut |_| {})? {
        DaemonResponse::Pruned { removed, reclaimed_bytes } => Ok(izba_core::volume::Pruned { removed, reclaimed_bytes }),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected VolumePrune reply: {other:?}"),
    })
}

fn volume_attach(&mut self, name: &str, spec: izba_core::volume::VolumeSpec) -> anyhow::Result<()> {
    let name = name.to_string();
    self.with_client(|c| expect_ok(c.request(&DaemonRequest::VolumeAttach { name, spec }, &mut |_| {})?))
}

fn volume_detach(&mut self, name: &str, guest_path: String) -> anyhow::Result<()> {
    let name = name.to_string();
    self.with_client(|c| expect_ok(c.request(&DaemonRequest::VolumeDetach { name, guest_path: guest_path.into() }, &mut |_| {})?))
}
```

- [ ] **Step 3: Run** `cd app/src-tauri && cargo build` — fails only because `FakeDaemon` doesn't implement the new methods yet (fixed in D2). Do not commit until D2.

### Task D2: `FakeDaemon` state + impls

**Files:**
- Modify: `app/src-tauri/src/fake.rs`

- [ ] **Step 1:** Add fields to `FakeDaemon` for observable state: `pub ports: Vec<izba_core::state::PortRule>`, `pub volumes: Vec<izba_core::volume::VolumeInfo>`, `pub detail_volumes: Vec<izba_core::volume::VolumeSpec>`. Default them (e.g. `ports: vec![]`, one sample volume `cache` referenced by `web`, `detail_volumes: vec![]`).

- [ ] **Step 2:** Implement the new trait methods recording into `calls` and returning canned/echoed state. Examples:

```rust
fn inspect(&mut self, name: &str) -> anyhow::Result<izba_core::daemon::proto::SandboxDetail> {
    Ok(izba_core::daemon::proto::SandboxDetail {
        name: name.to_string(), image_ref: "ubuntu:24.04".into(), image_digest: "sha256:x".into(),
        cpus: 2, mem_mb: 4096, workspace: "/ws".into(), status: "running".into(),
        ports: self.ports.clone(), volumes: self.detail_volumes.clone(),
    })
}
fn port_list(&mut self, _name: &str) -> anyhow::Result<Vec<izba_core::state::PortRule>> { Ok(self.ports.clone()) }
fn port_publish(&mut self, name: &str, rule: izba_core::state::PortRule, persist: bool) -> anyhow::Result<()> {
    self.calls.push(format!("publish:{name}:{}:{}:{persist}", rule.host_port, rule.guest_port));
    self.ports.push(rule); Ok(())
}
fn port_unpublish(&mut self, name: &str, bind: std::net::Ipv4Addr, host_port: u16) -> anyhow::Result<()> {
    self.calls.push(format!("unpublish:{name}:{bind}:{host_port}"));
    self.ports.retain(|r| !(r.bind == bind && r.host_port == host_port)); Ok(())
}
fn volume_list(&mut self) -> anyhow::Result<Vec<izba_core::volume::VolumeInfo>> { Ok(self.volumes.clone()) }
fn volume_remove(&mut self, name: &str) -> anyhow::Result<()> { self.calls.push(format!("vrm:{name}")); Ok(()) }
fn volume_prune(&mut self) -> anyhow::Result<izba_core::volume::Pruned> {
    self.calls.push("vprune".into());
    Ok(izba_core::volume::Pruned { removed: vec!["old".into()], reclaimed_bytes: 1024 })
}
fn volume_attach(&mut self, name: &str, spec: izba_core::volume::VolumeSpec) -> anyhow::Result<()> {
    self.calls.push(format!("vattach:{name}:{}", spec.guest_path.display())); Ok(())
}
fn volume_detach(&mut self, name: &str, guest_path: String) -> anyhow::Result<()> {
    self.calls.push(format!("vdetach:{name}:{guest_path}")); Ok(())
}
```

- [ ] **Step 3: Run** `cd app/src-tauri && cargo test 2>&1 | tail -10` → PASS (existing tests compile + green).

- [ ] **Step 4: Commit** (D1 + D2 together).

```bash
git add app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs
git commit -m "feat(app): DaemonApi + Real/Fake impls for port & volume ops"
```

### Task D3: views + command cores + Tauri command registration

**Files:**
- Modify: `app/src-tauri/src/views.rs`, `app/src-tauri/src/commands.rs`, `app/src-tauri/src/lib.rs`

**Interfaces:**
- Produces serializable view structs: `PortRuleView { bind: String, host_port: u16, guest_port: u16 }`, `VolumeSpecView { name: Option<String>, guest_path: String, size_bytes: u64, eph_id: Option<u64> }`, `VolumeInfoView { name, size_bytes, actual_bytes, referenced_by }`, `SandboxDetailView { name, image, status, ports: Vec<PortRuleView>, volumes: Vec<VolumeSpecView> }`. Command cores: `inspect_core`, `port_list_core`, `port_publish_core`, `port_unpublish_core`, `volume_list_core`, `volume_remove_core`, `volume_prune_core`, `volume_attach_core`, `volume_detach_core`.

- [ ] **Step 1: `views.rs`** — add `volumes: Vec<String>` to `CreateOpts` (with a doc comment) and parse it in `into_daemon_create` (mirror the `ports` parse + `validate_volumes`):

```rust
/// Repeatable `[NAME:]GUEST_PATH:SIZE` volume specs (blank entries ignored).
#[serde(default)]
pub volumes: Vec<String>,
```

```rust
let volumes = self.volumes.iter().map(|s| s.trim()).filter(|s| !s.is_empty())
    .map(izba_core::volume::parse_volume_flag).collect::<anyhow::Result<Vec<_>>>()?;
izba_core::volume::validate_volumes(&volumes)?;
// …in the returned DaemonCreate: volumes,   (drop the hardcoded Vec::new())
```

Update the two existing `CreateOpts` literals in `views.rs` tests + `commands.rs` test helper + `newSandbox`-adjacent tests to add `volumes: vec![]`. Add a test:

```rust
#[test]
fn create_opts_parses_volumes() {
    let mut o = /* existing helper */;
    o.volumes = vec!["cache:/data:1g".into(), "  ".into()];
    let dc = o.into_daemon_create().unwrap();
    assert_eq!(dc.volumes.len(), 1);
    assert_eq!(dc.volumes[0].name.as_deref(), Some("cache"));
}
```

Add the view structs + `From` conversions (`PortRuleView::from(PortRule)` stringifies `bind`; `VolumeSpecView`/`VolumeInfoView` map directly; `SandboxDetailView::from(SandboxDetail)`).

- [ ] **Step 2: `commands.rs`** — add `*_core` wrappers (mirror `policy_*_core`), each mapping `anyhow::Error` → `String` and converting core types → view types. Add tests using `FakeDaemon` asserting `d.calls` (e.g. `port_publish_core(&mut d, "web", "8080", "80", false)` records `publish:web:8080:80:false`). The core takes string host/guest ports and builds a `PortRule` via `izba_core::portfwd::parse_rule` (reuse the wizard-style `[bind:]host:guest` assembly) — keep the signature `port_publish_core(d, name, rule_spec: &str, persist: bool)` for a single parse path.

- [ ] **Step 3: `lib.rs`** — add `#[tauri::command] async fn` wrappers for each (mirror `policy_*`, all via `run_action`), and register them in `generate_handler![…]`. Names: `inspect`, `port_list`, `port_publish`, `port_unpublish`, `volume_list`, `volume_remove`, `volume_prune`, `volume_attach`, `volume_detach`.

- [ ] **Step 4: Run** `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` — all green.

- [ ] **Step 5: Commit.**

```bash
git add app/src-tauri/src/views.rs app/src-tauri/src/commands.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): views + command cores + tauri commands for ports & volumes"
```

### Task D4: opener plugin (Open in browser)

**Files:**
- Modify: `app/src-tauri/Cargo.toml`, `app/src-tauri/src/lib.rs`, `app/src-tauri/capabilities/default.json` (or the capabilities file the project uses), `app/package.json`

- [ ] **Step 1:** Add `tauri-plugin-opener = "2"` to `app/src-tauri/Cargo.toml`; register `.plugin(tauri_plugin_opener::init())` in `lib.rs` (next to `tauri_plugin_dialog`). Add `@tauri-apps/plugin-opener` to `app/package.json` deps (match the dialog plugin's version line).

- [ ] **Step 2:** Grant the opener capability. Inspect the existing capabilities JSON (where `dialog:*` is allowed) and add `"opener:allow-open-url"` (and `"opener:default"` if the project's pattern needs it). Scope the URL permission to `http://127.0.0.1:*` / `http://localhost:*` if the schema supports it; otherwise allow the default and rely on the frontend only ever passing a localhost URL.

- [ ] **Step 3: Run** `cd app && npm ci && npm run build && (cd src-tauri && cargo build)` — green. (No unit test; verified in the E2E devbuild.)

- [ ] **Step 4: Commit.**

```bash
git add app/src-tauri/Cargo.toml app/src-tauri/src/lib.rs app/src-tauri/capabilities/ app/package.json app/package-lock.json
git commit -m "feat(app): add opener plugin for forwarded-port open-in-browser"
```

---

## Phase E — Frontend (`app/src`)

> Test command: `cd app && npx vitest run`. Mirror existing component style (`NewSandbox.tsx`, `PolicyEditor.tsx`) for markup/Tailwind classes; the code below specifies the non-obvious logic and the test assertions.

### Task E1: types + ipc bindings

**Files:**
- Modify: `app/src/lib/types.ts`, `app/src/lib/ipc.ts`

- [ ] **Step 1:** Add to `types.ts`:

```ts
export interface PortRule { bind: string; host_port: number; guest_port: number; }
export interface VolumeSpec { name: string | null; guest_path: string; size_bytes: number; eph_id?: number | null; }
export interface VolumeInfo { name: string; size_bytes: number; actual_bytes: number; referenced_by: string[]; }
export interface SandboxDetail {
  name: string; image: string; status: string;
  ports: PortRule[]; volumes: VolumeSpec[];
}
```

Add `volumes: string[]` to `CreateOpts`.

- [ ] **Step 2:** Add to the `api` object in `ipc.ts`:

```ts
inspect: (name: string) => invoke<SandboxDetail>("inspect", { name }),
portList: (name: string) => invoke<PortRule[]>("port_list", { name }),
portPublish: (name: string, rule: string, persist: boolean) =>
  invoke<void>("port_publish", { name, rule, persist }),
portUnpublish: (name: string, bind: string, hostPort: number) =>
  invoke<void>("port_unpublish", { name, bind, hostPort }),
volumeList: () => invoke<VolumeInfo[]>("volume_list"),
volumeRemove: (name: string) => invoke<void>("volume_remove", { name }),
volumePrune: () => invoke<{ removed: string[]; reclaimed_bytes: number }>("volume_prune"),
volumeAttach: (name: string, spec: string) => invoke<void>("volume_attach", { name, spec }),
volumeDetach: (name: string, guestPath: string) => invoke<void>("volume_detach", { name, guestPath }),
```

(Confirm the Tauri arg names match the Rust command params — Tauri uses camelCase JS → snake_case Rust by default; pass `hostPort`/`guestPath` and name the Rust params `host_port`/`guest_path`. Verify against how `remove(name, force)` already works.)

- [ ] **Step 3: Commit.** `git commit -m "feat(app): frontend types + ipc bindings for ports & volumes"` (no standalone test; exercised by E2–E5).

### Task E2: wizard Volumes section

**Files:**
- Modify: `app/src/components/NewSandbox.tsx`
- Test: `app/src/test/newSandbox.test.tsx`

**Interfaces:**
- Consumes: existing wizard validators (`isValidPort`, `portGrid` etc. at module scope in `NewSandbox.tsx`). Add volume validators.

- [ ] **Step 1: Write failing tests** in `newSandbox.test.tsx` (mirror existing port-row tests):
  - Adding a volume row with name `cache`, path `/data`, size `1g` and submitting calls `api.create` with `volumes: ["cache:/data:1g"]`.
  - An invalid row (path `data` without leading `/`, or size `1x`) blocks Create and shows a warning.
  - A row with empty name emits an ephemeral spec `"/scratch:1g"` (no leading name).
  - A fully-blank volume row is ignored on submit.

- [ ] **Step 2: Run** `cd app && npx vitest run newSandbox` → FAIL.

- [ ] **Step 3: Implement.** Add a `VolumeRow { name: string; path: string; size: string }` state array + `setVolume/addVolume/removeVolume` mirroring the port handlers. Add validators at module scope:

```ts
const isValidVolName = (s: string) => s === "" || /^[a-z0-9][a-z0-9_-]*$/.test(s);
const isValidVolPath = (s: string) => s.startsWith("/") && !s.includes(",");
const isValidVolSize = (s: string) => /^\d+[gmGM]$/.test(s);
const isBlankVolRow = (r: VolumeRow) => !r.name.trim() && !r.path.trim() && !r.size.trim();
const isValidVolRow = (r: VolumeRow) =>
  isValidVolName(r.name.trim()) && isValidVolPath(r.path.trim()) && isValidVolSize(r.size.trim());
```

Render a "Volumes" section mirroring the Ports section markup (column headers Name / Guest path / Size; per-field red border via the existing `cell(bad)` helper; an "ephemeral"/"persistent" tag derived from `r.name.trim() === "" ? "ephemeral" : "persistent"`; a `+ Add volume` button; a warning line when any non-blank row is invalid). Compute `volumesInvalid` like `portsInvalid`. In `submit`, build:

```ts
volumes: volumes.filter((r) => !isBlankVolRow(r)).map((r) =>
  `${r.name.trim() ? `${r.name.trim()}:` : ""}${r.path.trim()}:${r.size.trim()}`),
```

Add `volumesInvalid` to the `canCreate` guard (Create disabled while invalid).

- [ ] **Step 4: Run** `npx vitest run newSandbox` → PASS.

- [ ] **Step 5: Commit.** `git commit -m "feat(app): wizard volumes section"`.

### Task E3: Ports tab

**Files:**
- Create: `app/src/components/PortsTab.tsx`
- Test: `app/src/test/portsTab.test.tsx`
- Modify: `app/src/components/Detail.tsx`

**Interfaces:**
- Props: `{ sandbox: SandboxView }`. Uses `api.inspect` (persisted `ports`) + `api.portList` (live relays) to classify, `api.portPublish`/`api.portUnpublish`, and `openUrl` from `@tauri-apps/plugin-opener`.

- [ ] **Step 1: Write failing tests** (`portsTab.test.tsx`, mock `../lib/ipc` and `@tauri-apps/plugin-opener`):
  - Renders forwards from `portList`; a forward present in `portList` but absent from `inspect().ports` shows an "active until restart" badge + a "Make persistent" button.
  - Clicking "Make persistent" calls `api.portPublish(name, "127.0.0.1:8080:80", true)`.
  - Clicking the open-in-browser control calls `openUrl("http://127.0.0.1:8080")`.
  - Clicking remove (×) calls `api.portUnpublish(name, "127.0.0.1", 8080)`.
  - The add-forward form is disabled when the sandbox is stopped.

- [ ] **Step 2: Run** `npx vitest run portsTab` → FAIL.

- [ ] **Step 3: Implement** `PortsTab.tsx`. Core logic:

```ts
const running = sandbox.state.kind !== "stopped";
// classify: a live rule is "persisted" iff an identical (bind,host_port,guest_port) is in inspect().ports
const persistedKey = (r: PortRule) => `${r.bind}:${r.host_port}:${r.guest_port}`;
// load both on mount / on `running` change:
const [live, setLive] = useState<PortRule[]>([]);
const [persisted, setPersisted] = useState<PortRule[]>([]);
// rows = union; for a row, isPersisted = persisted.some(p => persistedKey(p)===persistedKey(r))
```

Each row renders `${bind}:${host_port} → ${guest_port}`, an Open-in-browser button (`onClick={() => void openUrl(\`http://127.0.0.1:${r.host_port}\`)}`, `aria-label={\`Open port ${r.host_port} in browser\`}`), a "Make persistent" button when `!isPersisted` (`onClick` → `api.portPublish(sandbox.name, persistedKey(r), true)` then reload), and a remove ×. An add-forward sub-form (bind/host/guest inputs reusing the wizard validators — import or duplicate the small `isValidPort`/`isValidBind` checks; prefer extracting them to `app/src/lib/portvalidate.ts` and importing in both NewSandbox and PortsTab if clean) that calls `api.portPublish(name, "bind:host:guest", false)` and is disabled unless `running`.

After any mutation, re-fetch `portList`+`inspect` to refresh classification.

- [ ] **Step 4:** In `Detail.tsx`, add `"ports"` to the `Tab` union + the `tabs` array (label "Ports", placed after Overview), and render `{tab === "ports" && <PortsTab sandbox={sandbox} />}`.

- [ ] **Step 5: Run** `npx vitest run portsTab` and the existing `detail` test → PASS.

- [ ] **Step 6: Commit.** `git commit -m "feat(app): Ports tab — live/persisted forwards, make-persistent, open-in-browser"`.

### Task E4: Volumes tab

**Files:**
- Create: `app/src/components/VolumesTab.tsx`
- Test: `app/src/test/volumesTab.test.tsx`
- Modify: `app/src/components/Detail.tsx`

**Interfaces:**
- Props: `{ sandbox: SandboxView; onChanged: () => void }`. Uses `api.inspect` (seed `volumes`), `api.volumeAttach`/`api.volumeDetach`, `api.restart`.

- [ ] **Step 1: Write failing tests:**
  - Seeds rows from `inspect().volumes` (named row shows "persistent", null-name row shows "ephemeral").
  - Adding a row + clicking Save calls `api.volumeAttach(name, "cache:/data:1g")`.
  - Removing a seeded row + Save calls `api.volumeDetach(name, "/data")`.
  - While the editor is dirty, the "applies on next restart" banner is visible; a "Restart now" button calls `api.restart(name)` and is shown only when running.

- [ ] **Step 2: Run** `npx vitest run volumesTab` → FAIL.

- [ ] **Step 3: Implement** `VolumesTab.tsx`. Seed from `api.inspect(name)`; keep an editable `rows` array + a `dirty` flag (mirror `PolicyEditor`'s `saved`/edit pattern). Reuse the wizard volume validators (extract to `app/src/lib/volumevalidate.ts` and import in both NewSandbox and VolumesTab to stay DRY). On Save, diff against the seeded set: for each added valid row call `volumeAttach(name, spec)`; for each removed seeded row call `volumeDetach(name, guest_path)`; then re-`inspect` and clear `dirty`. Show the restart banner when `dirty`, with `Restart now` (`api.restart`) gated on `running`. Each persistent row shows a one-line single-writer caveat.

- [ ] **Step 4:** In `Detail.tsx`, add `"volumes"` to the `Tab` union + tabs array (label "Volumes"), render `{tab === "volumes" && <VolumesTab sandbox={sandbox} onChanged={onChanged} />}`.

- [ ] **Step 5: Run** `npx vitest run volumesTab` + `detail` → PASS.

- [ ] **Step 6: Commit.** `git commit -m "feat(app): Volumes tab — edit + apply on restart"`.

### Task E5: Storage view + Rail/App wiring

**Files:**
- Create: `app/src/components/StorageView.tsx`
- Test: `app/src/test/storageView.test.tsx`
- Modify: `app/src/components/Rail.tsx`, `app/src/App.tsx`

**Interfaces:**
- `StorageView` props: none (calls `api.volumeList`/`api.volumeRemove`/`api.volumePrune`).
- `Rail` gains a `view`/`onView` selection so the main area can switch between the sandbox Detail and Storage.

- [ ] **Step 1: Write failing tests** (`storageView.test.tsx`):
  - Renders volumes from `api.volumeList`; a volume with non-empty `referenced_by` shows in-use chips and a **disabled** Delete; an unreferenced one's Delete is enabled.
  - Clicking Delete on an unreferenced volume (through the confirm) calls `api.volumeRemove(name)`.
  - Clicking "Prune unused" (through the confirm) calls `api.volumePrune` and shows the reclaimed bytes.

- [ ] **Step 2: Run** `npx vitest run storageView` → FAIL.

- [ ] **Step 3: Implement** `StorageView.tsx` (a table mirroring `PolicyEditor`/`NetlogView` styling; reuse `ConfirmDialog`). For each row: name, size (format bytes), used, `referenced_by` chips; Delete disabled (with `title="in use by …"`) when referenced; `volumeRemove` then refresh on confirm. A "Prune unused" button → `volumePrune` confirm → show `removed`/`reclaimed_bytes`.

- [ ] **Step 4: Wire navigation.** Add a top-level destination. In `App.tsx`, add `const [view, setView] = useState<"sandboxes" | "storage">("sandboxes")`; pass `view`/`onView={setView}` to `Rail`; render `{view === "storage" ? <StorageView /> : <Detail sandbox={current} onChanged={refresh} />}`. In `Rail.tsx`, add a "Storage" nav button above or below the Sandboxes group (mirror the existing button styling, `aria-pressed={view === "storage"}`); selecting it calls `onView("storage")`, and selecting a sandbox calls `onSelect(name)` + `onView("sandboxes")`. Keep `Rail`'s existing props; add `view`/`onView`. Update the existing `app.test.tsx` if it asserts Rail's prop shape.

- [ ] **Step 5: Run** `npx vitest run` (whole suite) → PASS.

- [ ] **Step 6: Commit.** `git commit -m "feat(app): Storage view + Rail navigation"`.

---

## Phase F — Verification & delivery

### Task F1: full local gate sweep

- [ ] **Step 1:** Workspace gates (from repo root):

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

- [ ] **Step 2:** App gate:

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

- [ ] **Step 3:** Fix any failures inline (re-run the relevant gate). Commit fixes with `fix(...)` messages.

### Task F2: push, PR, CI, SonarCloud/Greptile gate, devbuild

- [ ] **Step 1:** Confirm branch (not `main`), rebase on `origin/main` if behind, push the feature branch.
- [ ] **Step 2:** Open/refresh the PR (body ends with the Claude Code attribution trailer). Start CI; in parallel dispatch the devbuild: `bash hack/devbuild.sh` (unsandboxed). Record the exact main-checkout `dist/local/<UTC-ts>-<sha>/` path.
- [ ] **Step 3:** Drive the **SonarCloud** + **Greptile** gates to green: address Sonar findings (coverage on new frontend components, no hardcoded non-test IPs, readonly props) and resolve Greptile review comments (use the `greploop` skill to iterate to a clean score).
- [ ] **Step 4:** When ALL checks (ci.yml gates, App CI, SonarCloud, Greptile, e2e if it runs) are green, report to the owner: summary, PR link, the exact `dist/local/<ts>-<sha>/` path + ready-to-paste install commands (Linux `sudo dpkg -i …izba_*.deb` + `…izba-app_*.deb`; Windows installer via the documented `Start-Process` UNC double-backslash form).
- [ ] **Step 5:** Manual E2E verification flows from the spec §"Verification": ports (publish → make persistent → restart survives → open in browser) and volumes (attach + restart-now mounts; detach keeps others intact; Storage in-use guard + delete + prune).

---

## Self-Review (completed during planning)

- **Spec coverage:** VolumeList (A3/B1/B2/C2/D), VolumeRemove guard (A4/B/C3/D/E5), VolumeAttach/Detach + apply-on-restart (A5/B2/C4/D/E4), stable eph_id (A1/A2), `--persist` + idempotent + config-drop (B2/C1/E3), SandboxDetail.volumes (B1/B2/D/E4), Open-in-browser (D4/E3), wizard volumes (E2), IA Ports/Volumes tabs + Storage view (E3/E4/E5), CLI parity (C1–C4), gates + devbuild (F). All covered.
- **Placeholders:** none — every code step carries concrete code; frontend steps that defer markup to "mirror existing component" still specify the exact logic, handlers, and test assertions.
- **Type consistency:** `eph_id: Option<u64>` and `image_path(paths, sandbox)` used uniformly A1→A5/B; `VolumeInfo`/`VolumeSpec`/`PortRule` thread unchanged through proto→Tauri→TS; `persist: bool` consistent CLI/proto/daemon/app; ipc arg names (`hostPort`/`guestPath`) flagged for Tauri camel/snake matching in E1.
