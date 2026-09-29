# Sandbox save/load Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `izba save` / `izba load` move 1..N sandboxes (disks, volumes, image, optional workspace) between hosts, byte-identical and verified, any OS ↔ any OS.

**Architecture:** A pure `izba-core::bundle` library writes/reads a zstd-compressed tar (`.izba`): `manifest.json` first, image/volume/sandbox files, disks as ≤4 MiB non-zero data-chunk entries, a `checksums.json` trailer. izbad exposes it as `DaemonRequest::Save`/`Load` (proto 7) with Progress frames; the CLI is a thin wrapper. Non-docker sandboxes whose workspace owner changed get an idmapped overlay upper + volumes at boot (`P = M_tgt ∘ M_src`), so disks never need rewriting.

**Tech Stack:** Rust 2021 workspace; `tar 0.4` (existing), `zstd` (new, `zstdmt` feature), `sha2`/`hex` (existing), `nix`/`windows-sys` (existing), clap CLI, izba-init (static musl) new-mount-API idmaps.

**Spec:** `docs/superpowers/specs/2026-09-29-sandbox-save-load-design.md` (read it first; §-refs below point into it).

## Global Constraints

- All six workspace gates green before every commit (see CLAUDE.md "Build & test"): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, musl `izba-init` build, windows-gnu `cargo check` + `cargo clippy` for `izba-proto izba-core izba-cli`. Source `.cargo-env` first if present.
- Touching `izba-core` public types ⇒ also run the app gate (`cd app && npm ci && npm run build && npm run test && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`).
- Unit tests never bind unix/vsock/TCP listeners (EPERM in sandboxes). Use seams.
- `DAEMON_PROTO_VERSION` becomes exactly `7`.
- Verbs are `izba save` / `izba load` (`izba export` is taken).
- Archive format version `1`; extension `.izba`; manifest entry path `manifest.json`, trailer `checksums.json`.
- Disk chunk granularity: 64 KiB zero-elision blocks, ≤ 4 MiB per chunk entry.
- Conventional commits (`feat(core): …`), TDD, every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Never `git add -A`; stage explicit paths.
- Never copy: `state.json`, `ports.json`, `lockdown.json`, `lockdown.cred`, `trust/`, `ssh/`, `oci/`, `vnc/`, `vnc.password`, `logs/console.log`, `buildout/`, `run/`.
- Loud on degradation: a failed idmap at boot fails the boot; a failed symlink on load fails the load.
- KVM suites need the Bash sandbox disabled (`/dev/kvm` is invisible inside it but works): `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 <filter>`.

## Review Focus

1. **Owner-uid change on a non-docker sandbox** (Linux 1000 → Windows 0, or 1000 → 1001): files must keep their in-container owner — Task 1 (P tests), Task 4 (KVM proof).
2. **A disk image that is fully allocated on the source** (e.g. `cp`'d without `--sparse`, or NTFS without sparse flag): archive must still be small and the target file sparse — Task 5 test `zero_blocks_are_elided_and_digest_matches_sparse_twin`.
3. **Loading into a data root that already has the same image digest / same named volume**: the target's image is kept untouched; identical volume is reused, different volume refused — Task 9 tests `existing_image_is_kept`, `identical_named_volume_is_reused`, `different_named_volume_is_refused`.
4. **A load that fails midway** (corrupt chunk, checksum mismatch, disk full): nothing half-imported remains and pre-existing state is untouched — Task 9 `rollback_*` tests.
5. **Workspace path that doesn't exist on the new OS** (`/home/u/proj` on Windows, or a path outside home): translated under the target home or an actionable `--workspace` error — Task 7 `translate_*` tests.

---

## File map

| File | Status | Responsibility |
| --- | --- | --- |
| `crates/izba-core/src/image/runtime_config.rs` | modify | `transpose_apply`, `disk_idmap_extents`, `disk_idmap_cmdline_value` |
| `crates/izba-core/src/state.rs` | modify | `SandboxConfig.disk_owner` |
| `crates/izba-core/src/sandbox.rs` | modify | start wiring (`DiskIdmap`, `build_cmdline`), `pub(crate)` helpers |
| `crates/izba-init/src/main.rs` | modify | parse `izba.diskuidmap`/`izba.diskgidmap`, idmap `/upper` + volumes |
| `crates/izba-core/src/bundle/mod.rs` | create | module root, shared consts, `Progress` sink type |
| `crates/izba-core/src/bundle/sparse.rs` | create | extents, chunk iterator, `content_digest`, chunk writer |
| `crates/izba-core/src/bundle/manifest.rs` | create | `Manifest`, `Checksums`, archive path validation |
| `crates/izba-core/src/bundle/workspace.rs` | create | workspace tar append/extract, git exec bits, path translation |
| `crates/izba-core/src/bundle/save.rs` | create | plan + write archive |
| `crates/izba-core/src/bundle/load.rs` | create | preflight, staging, verify, commit, rollback |
| `crates/izba-core/src/bundle/fsutil.rs` | create | free-space query per OS |
| `crates/izba-core/src/daemon/proto.rs` | modify | `Save`/`Load` requests, `Saved`/`Loaded` responses, proto 7 |
| `crates/izba-core/src/daemon/server.rs` | modify | `handle_save`/`handle_load` |
| `crates/izba-cli/src/main.rs`, `commands/save.rs`, `commands/load.rs`, `commands/mod.rs` | modify/create | CLI verbs |
| `crates/izba-cli/tests/daemon_e2e.rs` | modify | KVM proofs |
| `hack/spike/validate-izba-windows.ps1` | modify | Windows save/load + sparseness check |
| `CLAUDE.md`, `README.md`, `docs/security/…`, spec | modify | contracts + docs |

---

### Task 1: Disk-owner permutation P (pure, host-side)

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (next to `transpose_identity_map`, ~line 475)
- Test: same file's `mod tests`

**Interfaces:**
- Produces:
  - `pub fn transpose_apply(workload: u32, owner: u32, x: u32) -> u32`
  - `pub fn disk_idmap_extents(workload: u32, src_owner: u32, tgt_owner: u32) -> Option<Vec<oci_spec::runtime::LinuxIdMapping>>` — `None` iff P is the identity. Extents are in mount-idmap orientation (`container_id` field = DISK id, `host_id` field = PRESENTED id), cover `0..USERNS_RANGE_END`, sorted, non-overlapping.
  - `pub fn disk_idmap_cmdline_value(extents: &[LinuxIdMapping]) -> String` — `disk-presented-size` triples joined by `,` (NO fsuid-0 anchor: P is a full bijection so guest-root always has a reverse mapping).

- [ ] **Step 1: Write the failing tests**

```rust
    // ---- disk-owner permutation P = M_tgt ∘ M_src (spec §5.2) ----

    /// transpose_apply must agree with transpose_identity_map's extents
    /// (container -> guest) — the single source of truth for Option A.
    #[test]
    fn transpose_apply_agrees_with_identity_map_extents() {
        let cases = [(0, 1000), (1000, 1000), (1001, 1000), (1000, 0), (0, 0), (5, 70000)];
        for (w, o) in cases {
            let maps = transpose_identity_map(w, o);
            for x in [0u32, 1, 5, 999, 1000, 1001, 70000, 123456, USERNS_RANGE_END - 1] {
                let via_extents = maps
                    .iter()
                    .find(|m| x >= m.container_id() && x - m.container_id() < m.size())
                    .map(|m| m.host_id() + (x - m.container_id()))
                    .expect("full-range map covers x");
                assert_eq!(transpose_apply(w, o, x), via_extents, "w={w} o={o} x={x}");
            }
        }
    }

    fn apply_extents(ext: &[oci_spec::runtime::LinuxIdMapping], d: u32) -> u32 {
        ext.iter()
            .find(|m| d >= m.container_id() && d - m.container_id() < m.size())
            .map(|m| m.host_id() + (d - m.container_id()))
            .expect("P covers every id")
    }

    #[test]
    fn disk_idmap_is_none_when_owner_unchanged() {
        assert!(disk_idmap_extents(1001, 1000, 1000).is_none());
        assert!(disk_idmap_extents(0, 1000, 1000).is_none());
    }

    #[test]
    fn disk_idmap_is_none_when_both_maps_are_identity() {
        // W == O on the source and owner 0 on the target: both identity.
        assert!(disk_idmap_extents(1000, 1000, 0).is_none());
    }

    /// The invariant: for every disk id d, the container id it presents as on
    /// the target equals the container id it had on the source.
    #[test]
    fn disk_idmap_preserves_container_view() {
        let cases = [
            (1001, 1000, 1002), // uid change, non-root USER
            (0, 1000, 0),       // root USER, Linux -> Windows anchor
            (1001, 1000, 0),    // non-root USER, Linux -> Windows
            (1001, 0, 1000),    // Windows -> Linux
            (0, 0, 1000),       // root USER, Windows -> Linux
            (1000, 1001, 1000), // target owner == USER
        ];
        for (w, src, tgt) in cases {
            let ext = disk_idmap_extents(w, src, tgt).expect("non-identity case");
            for d in [0u32, 1, 999, 1000, 1001, 1002, 4242, USERNS_RANGE_END - 1] {
                let presented = apply_extents(&ext, d);
                let container_src = transpose_apply(w, src, d); // M_src self-inverse
                let container_tgt = transpose_apply(w, tgt, presented);
                assert_eq!(container_src, container_tgt, "w={w} src={src} tgt={tgt} d={d}");
            }
        }
    }

    #[test]
    fn disk_idmap_is_a_sorted_full_range_bijection() {
        let ext = disk_idmap_extents(1001, 1000, 0).unwrap();
        let mut next = 0u32;
        for m in &ext {
            assert_eq!(m.container_id(), next, "contiguous disk ranges");
            assert!(m.size() > 0);
            next = m.container_id() + m.size();
        }
        assert_eq!(next, USERNS_RANGE_END);
        let mut presented: Vec<u32> = ext.iter().filter(|m| m.size() == 1).map(|m| m.host_id()).collect();
        presented.sort();
        presented.dedup();
        assert_eq!(presented.len(), ext.iter().filter(|m| m.size() == 1).count(), "no two disk ids share a presented id");
    }

    #[test]
    fn disk_idmap_cmdline_value_renders_triples_without_anchor() {
        let ext = disk_idmap_extents(1001, 1000, 1002).unwrap();
        let v = disk_idmap_cmdline_value(&ext);
        assert!(v.starts_with("0-0-1000,"), "{v}");
        assert!(v.contains("1000-1002-1"), "disk 1000 (container 1001) -> guest 1002: {v}");
        assert!(!v.contains(&format!("{DOCKER_IDMAP_FSUID0_DISK_ID}-0-1")), "{v}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core disk_idmap transpose_apply`
Expected: compile error, `transpose_apply`/`disk_idmap_extents` not found.

- [ ] **Step 3: Implement**

```rust
/// Apply the Option A container→guest map ([`transpose_identity_map`]) to one
/// id. A transposition is its own inverse, so this is also guest→container.
/// Kept in lock-step with `transpose_identity_map` by a guard test.
pub fn transpose_apply(workload: u32, owner: u32, x: u32) -> u32 {
    if workload == owner || owner == 0 {
        x
    } else if x == workload {
        owner
    } else if x == owner {
        workload
    } else {
        x
    }
}

/// Mount idmap for a non-docker sandbox whose disks were written under
/// workspace owner `src_owner` but now boot under `tgt_owner` (save/load
/// spec §5.2): `P = M_tgt ∘ M_src⁻¹` (= `M_tgt ∘ M_src`, transpositions are
/// self-inverse). Disk id `d` presents as `P(d)`, so every file keeps the
/// container owner it had on the source. `None` iff P is the identity.
///
/// Orientation matches [`layer_idmap_cmdline_value`]: each extent's
/// `container_id` is the DISK id and `host_id` the PRESENTED id. P moves at
/// most four ids ({0, W, src, tgt}); everything else is identity, emitted as
/// the gaps between them so the map covers `0..USERNS_RANGE_END` exactly.
pub fn disk_idmap_extents(
    workload: u32,
    src_owner: u32,
    tgt_owner: u32,
) -> Option<Vec<oci_spec::runtime::LinuxIdMapping>> {
    use oci_spec::runtime::LinuxIdMappingBuilder;
    let p = |d: u32| transpose_apply(workload, tgt_owner, transpose_apply(workload, src_owner, d));
    let mut moved: Vec<u32> = [0, workload, src_owner, tgt_owner]
        .into_iter()
        .filter(|&d| d < USERNS_RANGE_END && p(d) != d)
        .collect();
    moved.sort_unstable();
    moved.dedup();
    if moved.is_empty() {
        return None;
    }
    let extent = |disk: u32, presented: u32, size: u32| {
        LinuxIdMappingBuilder::default()
            .container_id(disk)
            .host_id(presented)
            .size(size)
            .build()
            .expect("LinuxIdMapping build is infallible for u32 fields")
    };
    let mut out = Vec::with_capacity(2 * moved.len() + 1);
    let mut next = 0u32;
    for d in moved {
        if d > next {
            out.push(extent(next, next, d - next));
        }
        out.push(extent(d, p(d), 1));
        next = d + 1;
    }
    if next < USERNS_RANGE_END {
        out.push(extent(next, next, USERNS_RANGE_END - next));
    }
    Some(out)
}

/// `izba.diskuidmap=`/`izba.diskgidmap=` value: `disk-presented-size`
/// triples, same grammar izba-init's `idmap::parse_cmdline_map` reads. No
/// fsuid-0 anchor: P is a bijection over the whole range, so guest-root
/// writers (overlay copy-up, whiteouts) always have a reverse mapping.
pub fn disk_idmap_cmdline_value(extents: &[oci_spec::runtime::LinuxIdMapping]) -> String {
    extents
        .iter()
        .map(|m| format!("{}-{}-{}", m.container_id(), m.host_id(), m.size()))
        .collect::<Vec<_>>()
        .join(",")
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-core disk_idmap transpose_apply` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs
git commit -m "feat(core): disk-owner idmap permutation for moved sandboxes"
```

---

### Task 2: `SandboxConfig.disk_owner` + start emits `izba.diskuidmap/diskgidmap`

**Files:**
- Modify: `crates/izba-core/src/state.rs` (`SandboxConfig`, add field after `vnc`)
- Modify: `crates/izba-core/src/sandbox.rs` — `create` (field init `disk_owner: None`), `write_oci_bundle` (~line 783–860, returns `OciBundleOut`), `build_cmdline` (~line 258), their call site in `start_with_timeouts`, and `workspace_owner` visibility.
- Modify: every other `SandboxConfig { … }` literal (`grep -rn "SandboxConfig {" crates app/src-tauri`) — add `disk_owner: None`.
- Test: `sandbox.rs` tests (`build_cmdline` tests live there — `grep -n "fn build_cmdline_" crates/izba-core/src/sandbox.rs`), `state.rs` tests.

**Interfaces:**
- Consumes: Task 1 `disk_idmap_extents`, `disk_idmap_cmdline_value`.
- Produces:
  - `SandboxConfig.disk_owner: Option<(u32, u32)>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`)
  - `pub(crate) fn workspace_owner(workspace: &Path) -> (u32, u32)` (was private)
  - `pub(crate) fn disk_idmap_for(config: &SandboxConfig, workload: (u32, u32), host_owner: (u32, u32)) -> Option<DiskIdmap>`
  - `pub(crate) struct DiskIdmap { pub uidmap: String, pub gidmap: String }`

- [ ] **Step 1: Failing tests**

In `state.rs` tests:

```rust
    #[test]
    fn disk_owner_defaults_to_none_and_is_omitted_when_none() {
        let json = r#"{"image_digest":"sha256:x","image_ref":"a","cpus":1,"mem_mb":512,"workspace":"/w"}"#;
        let c: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.disk_owner, None);
        let out = serde_json::to_string(&c).unwrap();
        assert!(!out.contains("disk_owner"), "{out}");
        let mut c2 = c.clone();
        c2.disk_owner = Some((1000, 1000));
        let back: SandboxConfig = serde_json::from_str(&serde_json::to_string(&c2).unwrap()).unwrap();
        assert_eq!(back.disk_owner, Some((1000, 1000)));
    }
```

In `sandbox.rs` tests (use the existing test helper that builds a `SandboxConfig`; if none exists, build one via `serde_json::from_str` like above):

```rust
    fn cfg_with(disk_owner: Option<(u32, u32)>, docker: bool, builder: bool) -> SandboxConfig {
        let mut c: SandboxConfig = serde_json::from_str(
            r#"{"image_digest":"sha256:x","image_ref":"a","cpus":1,"mem_mb":512,"workspace":"/w"}"#,
        )
        .unwrap();
        c.disk_owner = disk_owner;
        c.docker = docker;
        c.builder = builder;
        c
    }

    #[test]
    fn disk_idmap_for_none_when_unset_or_same_owner() {
        assert!(disk_idmap_for(&cfg_with(None, false, false), (1001, 1001), (1000, 1000)).is_none());
        assert!(disk_idmap_for(&cfg_with(Some((1000, 1000)), false, false), (1001, 1001), (1000, 1000)).is_none());
    }

    #[test]
    fn disk_idmap_for_skips_docker_and_builder() {
        // docker: layers store container ids; builder: no userns (identity both sides).
        assert!(disk_idmap_for(&cfg_with(Some((1000, 1000)), true, false), (1001, 1001), (0, 0)).is_none());
        assert!(disk_idmap_for(&cfg_with(Some((1000, 1000)), false, true), (1001, 1001), (0, 0)).is_none());
    }

    #[test]
    fn disk_idmap_for_emits_both_legs_independently() {
        // uid leg moves (1000 -> 0), gid leg unchanged (1000 -> 1000).
        let m = disk_idmap_for(&cfg_with(Some((1000, 1000)), false, false), (1001, 1001), (0, 1000)).unwrap();
        assert!(m.uidmap.contains("1000-1001-1"), "{}", m.uidmap);
        assert_eq!(m.gidmap, format!("0-0-{}", crate::image::runtime_config::USERNS_RANGE_END));
    }

    #[test]
    fn build_cmdline_appends_disk_idmap_last() {
        let d = DiskIdmap { uidmap: "0-0-5".into(), gidmap: "0-0-6".into() };
        let c = build_cmdline("n", &[], false, false, None, true, Some(&d));
        assert!(c.ends_with(" izba.vnc=1 izba.diskuidmap=0-0-5 izba.diskgidmap=0-0-6"), "{c}");
        let c = build_cmdline("n", &[], false, false, None, false, None);
        assert!(!c.contains("diskuidmap"), "{c}");
    }
```

Note `disk_idmap_for_emits_both_legs_independently`: when only one leg moves, the other leg must still be emitted as the full-range identity (`0-0-USERNS_RANGE_END`) because init requires both keys together.

- [ ] **Step 2: Run** `cargo test -p izba-core disk_owner disk_idmap_for build_cmdline_appends` → FAIL (compile).

- [ ] **Step 3: Implement**

`state.rs`, after `pub vnc: bool,`:

```rust
    /// Save/load (spec 2026-09-29 §5.3): the workspace owner `(uid, gid)` the
    /// ids on this sandbox's disks were written under, when that differs from
    /// "whoever owns the workspace now". `None` for every sandbox created on
    /// this host (disks match the current owner; no disk idmap). Set only by
    /// `izba load`; `start` compares it to the live owner and, for non-docker
    /// non-builder sandboxes, emits `izba.diskuidmap=`/`izba.diskgidmap=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_owner: Option<(u32, u32)>,
```

`sandbox.rs`:

```rust
/// Kernel-cmdline payload for a moved sandbox's disk idmap (§5.3).
#[derive(Clone, Debug)]
pub(crate) struct DiskIdmap {
    pub uidmap: String,
    pub gidmap: String,
}

/// Decide the disk idmap for this boot. Docker mode stores container ids
/// on its (already idmapped) layers and builder VMs have no userns, so both
/// are always `None`. Otherwise `None` iff P is the identity on BOTH legs;
/// when only one leg moves, the other is emitted as the full-range identity
/// because init requires both keys together.
pub(crate) fn disk_idmap_for(
    config: &SandboxConfig,
    workload: (u32, u32),
    host_owner: (u32, u32),
) -> Option<DiskIdmap> {
    use crate::image::runtime_config::{disk_idmap_cmdline_value, disk_idmap_extents, USERNS_RANGE_END};
    let src = config.disk_owner?;
    if config.builder || config.docker_effective() {
        return None;
    }
    let u = disk_idmap_extents(workload.0, src.0, host_owner.0);
    let g = disk_idmap_extents(workload.1, src.1, host_owner.1);
    if u.is_none() && g.is_none() {
        return None;
    }
    let identity = format!("0-0-{USERNS_RANGE_END}");
    Some(DiskIdmap {
        uidmap: u.map(|e| disk_idmap_cmdline_value(&e)).unwrap_or_else(|| identity.clone()),
        gidmap: g.map(|e| disk_idmap_cmdline_value(&e)).unwrap_or(identity),
    })
}
```

- In `write_oci_bundle`, after `let spec = …generate_spec(&params)…`, compute `let disk_idmap = disk_idmap_for(config, (uid, gid), host_owner);` and add `disk_idmap: Option<DiskIdmap>` to `OciBundleOut` (update its doc comment).
- `build_cmdline` gains a final parameter `disk_idmap: Option<&DiskIdmap>`; after the VNC block append:

```rust
    // Save/load disk idmap (spec 2026-09-29 §5.3): host-authoritative like
    // every flag above; appended after VNC so no earlier flag moves.
    if let Some(d) = disk_idmap {
        c.push_str(&format!(" izba.diskuidmap={} izba.diskgidmap={}", d.uidmap, d.gidmap));
    }
```

  and update the "Appended last" comment on the VNC block to "appended after every earlier flag".
- Update every `build_cmdline(` call (the `start` site passes `bundle.disk_idmap.as_ref()`; existing tests pass `None`).
- `create`: add `disk_owner: None,` to the literal. Grep for other literals and add it there too (tests, `manifest/`, app).
- Make `workspace_owner` `pub(crate)`.

- [ ] **Step 4: Run** `cargo test -p izba-core` → PASS; then the full six gates + app gate (the app builds `SandboxConfig` literals? `grep -rn "SandboxConfig {" app/src-tauri` — fix any).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/state.rs crates/izba-core/src/sandbox.rs <any other files with SandboxConfig literals>
git commit -m "feat(core): record disk_owner and emit the disk idmap at start"
```

---

### Task 3: izba-init applies the disk idmap to `/upper` + user volumes

**Files:**
- Modify: `crates/izba-init/src/main.rs` (boot sequence ~lines 185–270, `setup_user_volumes` ~line 527)
- Modify: `crates/izba-init/src/idmap.rs` (new pure helper + tests)

**Interfaces:**
- Consumes: cmdline keys `izba.diskuidmap`, `izba.diskgidmap` (Task 2).
- Produces: `pub fn disk_maps_from_cmdline(params: &BTreeMap<String,String>, docker: bool) -> Result<Option<(Vec<IdExtent>, Vec<IdExtent>)>, String>` in `idmap.rs`.

- [ ] **Step 1: Failing tests** (`idmap.rs` tests):

```rust
    fn params(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn disk_maps_absent_is_none() {
        assert_eq!(disk_maps_from_cmdline(&params(&[]), false).unwrap(), None);
    }

    #[test]
    fn disk_maps_parse_both_legs() {
        let p = params(&[("izba.diskuidmap", "0-0-1000,1000-1001-1,1001-1000-1,1002-1002-5"), ("izba.diskgidmap", "0-0-9")]);
        let (u, g) = disk_maps_from_cmdline(&p, false).unwrap().unwrap();
        assert_eq!(u.len(), 4);
        assert_eq!(g, vec![IdExtent { disk: 0, presented: 0, size: 9 }]);
    }

    #[test]
    fn disk_maps_require_both_keys() {
        assert!(disk_maps_from_cmdline(&params(&[("izba.diskuidmap", "0-0-9")]), false).is_err());
        assert!(disk_maps_from_cmdline(&params(&[("izba.diskgidmap", "0-0-9")]), false).is_err());
    }

    #[test]
    fn disk_maps_refused_in_docker_mode() {
        let p = params(&[("izba.diskuidmap", "0-0-9"), ("izba.diskgidmap", "0-0-9")]);
        assert!(disk_maps_from_cmdline(&p, true).is_err(), "host never emits both; refuse loudly");
    }

    #[test]
    fn disk_maps_reject_garbage() {
        let p = params(&[("izba.diskuidmap", "nope"), ("izba.diskgidmap", "0-0-9")]);
        assert!(disk_maps_from_cmdline(&p, false).is_err());
    }
```

- [ ] **Step 2: Run** `cargo test -p izba-init disk_maps` → FAIL.

- [ ] **Step 3: Implement** in `idmap.rs`:

```rust
/// Parse the save/load disk idmap (`izba.diskuidmap=`/`izba.diskgidmap=`,
/// izba-core `disk_idmap_cmdline_value`). Both keys or neither; never
/// together with docker mode (its layers carry their own map). Any error
/// must fail the boot — booting with the raw disk ids would present every
/// moved file with the wrong owner.
pub fn disk_maps_from_cmdline(
    params: &std::collections::BTreeMap<String, String>,
    docker: bool,
) -> Result<Option<(Vec<IdExtent>, Vec<IdExtent>)>, String> {
    let u = params.get("izba.diskuidmap");
    let g = params.get("izba.diskgidmap");
    match (u, g) {
        (None, None) => Ok(None),
        (Some(u), Some(g)) => {
            if docker {
                return Err("izba.diskuidmap with izba.docker=1 (host bug)".into());
            }
            Ok(Some((
                parse_cmdline_map(u).map_err(|e| format!("izba.diskuidmap: {e}"))?,
                parse_cmdline_map(g).map_err(|e| format!("izba.diskgidmap: {e}"))?,
            )))
        }
        _ => Err("izba.diskuidmap and izba.diskgidmap must be given together".into()),
    }
}
```

In `main.rs`, right after `layer_maps` is computed:

```rust
    // Save/load (spec 2026-09-29 §5.3): a sandbox moved between hosts with a
    // different workspace owner presents its upper + volumes through P so
    // every file keeps its in-container owner. /lower is NOT mapped: image
    // ids are read under this host's own userns map, like a fresh create.
    let disk_maps = idmap::disk_maps_from_cmdline(&params, docker)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
```

After the docker `apply_layer_idmaps(&[/lower, /upper])` block and before `mounts::apply(&rootfs_plan[2..])`:

```rust
    if let Some((uid_map, gid_map)) = &disk_maps {
        idmap::apply_layer_idmaps(&[Path::new("/upper")], uid_map, gid_map)
            .context("idmapping the rw disk (moved sandbox; kernel must support idmapped ext4 + overlay)")?;
    }
```

Change the volume call to `setup_user_volumes(&vols, layer_maps.as_ref().or(disk_maps.as_ref()))?;` and update `setup_user_volumes`' doc/comment ("docker mode" → "docker mode or a moved sandbox's disk idmap"). Update the idmap.rs module doc with a paragraph on the disk idmap.

- [ ] **Step 4: Run** `cargo test -p izba-init` + musl build (`cargo build -p izba-init --target x86_64-unknown-linux-musl --release`) → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/idmap.rs crates/izba-init/src/main.rs
git commit -m "feat(init): apply the moved-sandbox disk idmap to the rw disk and volumes"
```

---

### Task 4: KVM proof — overlay accepts an idmapped upper (SPIKE GATE)

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (new test `disk_owner_remap_preserves_container_view`)

This is the spec §5.4 spike, landed as a permanent test. **If the sandbox fails to boot with an overlay/mount_setattr error, STOP and report to the owner with the console tail — do not proceed to Task 5+.**

- [ ] **Step 1: Write the test** (reuse `want()`, `izba()`, `assert_ok()`, `stdout_of()`, `IMAGE` from the file; mirror how `cli_surface_lifecycle` sets up `data`/`ws` tempdirs and envs — copy its setup block verbatim):

```rust
/// Save/load §5.4: a non-docker sandbox whose recorded disk_owner differs
/// from the live workspace owner boots with /upper idmapped by P, files keep
/// their in-container owner, and new writes round-trip losslessly when the
/// map is removed again.
#[test]
fn disk_owner_remap_preserves_container_view() {
    if !want() { return; }
    // <copy the data/ws tempdir + envs setup from cli_surface_lifecycle>
    let name = "remap";
    assert_ok(&izba(data, envs, &["create", "--image", IMAGE, "--name", name, &ws_s]), "create");
    assert_ok(&izba(data, envs, &["start", name]), "start 1");
    assert_ok(&izba(data, envs, &["exec", name, "--", "sh", "-c", "touch /root/before && sync"]), "touch before");
    assert_ok(&izba(data, envs, &["stop", name]), "stop 1");

    let host = izba_core::sandbox::workspace_owner_pub(&ws); // see Step 3
    let fake: (u32, u32) = (4242, 4242);
    let cfg_path = data.join("sandboxes").join(name).join("config.json");
    let mut cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg["disk_owner"] = serde_json::json!([fake.0, fake.1]);
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    let s = izba(data, envs, &["start", name]);
    assert_ok(&s, "start 2 (idmapped upper) — if this fails with an overlay/mount_setattr error the spike FAILED: stop and report");
    // alpine USER is root (W = 0). `before` was written as container 0 under
    // owner `host` => disk id transpose(0, host.0, 0). Expected container view
    // under the remap: M_tgt^-1(P(d)) == M_src^-1(d) with M_src = (0, 4242).
    use izba_core::image::runtime_config::transpose_apply;
    let d_before = transpose_apply(0, host.0, 0);
    let expect_before = transpose_apply(0, fake.0, d_before);
    let out = izba(data, envs, &["exec", name, "--", "stat", "-c", "%u", "/root/before"]);
    assert_ok(&out, "stat before");
    assert_eq!(stdout_of(&out).trim(), expect_before.to_string());

    assert_ok(&izba(data, envs, &["exec", name, "--", "sh", "-c", "touch /root/after && sync"]), "touch after");
    assert_ok(&izba(data, envs, &["stop", name]), "stop 2");
    // `after` was written as container 0 under the remap => disk id M_src(0) = transpose(0,4242,0).
    // Remove the remap: it must present as container transpose(0, host.0, that disk id).
    let mut cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg.as_object_mut().unwrap().remove("disk_owner");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    assert_ok(&izba(data, envs, &["start", name]), "start 3");
    let d_after = transpose_apply(0, fake.0, 0);
    let expect_after = transpose_apply(0, host.0, d_after);
    let out = izba(data, envs, &["exec", name, "--", "stat", "-c", "%u", "/root/after"]);
    assert_ok(&out, "stat after");
    assert_eq!(stdout_of(&out).trim(), expect_after.to_string());
    assert_ok(&izba(data, envs, &["rm", "--force", name]), "rm");
}
```

- [ ] **Step 2:** The test needs the host owner of `ws` — add a tiny public shim in `sandbox.rs`: `#[doc(hidden)] pub fn workspace_owner_pub(p: &Path) -> (u32, u32) { workspace_owner(p) }` (hidden, for e2e only). On a non-unix CI host the e2e does not run.

- [ ] **Step 3: Run it** (sandbox disabled): `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 disk_owner_remap`. Build artifacts first per docs/testing.md if the suite asks for them (init must be rebuilt: the initramfs embeds izba-init — follow docs/testing.md "rebuilding the initramfs").
Expected: PASS. If boot fails → STOP (spike failed), report.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-cli/tests/daemon_e2e.rs crates/izba-core/src/sandbox.rs
git commit -m "test(e2e): prove the moved-sandbox disk idmap preserves the container view"
```

---

### Task 5: `bundle::sparse` — extents, chunks, content digest, chunk writer

**Files:**
- Create: `crates/izba-core/src/bundle/mod.rs`, `crates/izba-core/src/bundle/sparse.rs`
- Modify: `crates/izba-core/src/lib.rs` (`pub mod bundle;`), `crates/izba-core/src/sandbox.rs` (make `mark_sparse` `pub(crate)`)

**Interfaces:**
- Produces (`bundle/mod.rs`):
  - `pub const FORMAT_VERSION: u32 = 1;`
  - `pub const ZERO_BLOCK: u64 = 64 * 1024;` `pub const MAX_CHUNK: u64 = 4 * 1024 * 1024;`
  - `pub type Progress<'a> = &'a mut dyn FnMut(String);`
- Produces (`bundle/sparse.rs`):
  - `pub fn data_extents(f: &std::fs::File, len: u64) -> std::io::Result<Vec<(u64, u64)>>` — (offset, len) of possibly-non-hole regions; falls back to `[(0, len)]`.
  - `pub struct Chunk { pub offset: u64, pub data: Vec<u8> }`
  - `pub fn for_each_chunk(path: &Path, f: impl FnMut(Chunk) -> anyhow::Result<()>) -> anyhow::Result<u64>` — calls `f` for every maximal run of non-zero 64 KiB blocks (split at `MAX_CHUNK`), in offset order; returns logical length.
  - `pub struct DigestBuilder` with `pub fn new(logical_len: u64) -> Self`, `pub fn chunk(&mut self, c: &Chunk)`, `pub fn finish(self) -> String` (hex).
  - `pub fn content_digest(path: &Path) -> anyhow::Result<String>`
  - `pub fn create_sparse(path: &Path, logical_len: u64) -> anyhow::Result<std::fs::File>`
  - `pub fn chunk_entry_name(prefix: &str, offset: u64) -> String` → `format!("{prefix}.d/{offset:016x}")`; `pub fn parse_chunk_entry(name: &str) -> Option<(&str, u64)>`

Digest definition (canonical, independent of sparseness): sha256 over `logical_len (u64 LE)` then, for each 64 KiB-aligned block that is not all zero, in offset order: `offset (u64 LE) ‖ len (u32 LE) ‖ bytes`. Since `for_each_chunk` elides exactly the all-zero blocks and chunks are unions of whole blocks, `DigestBuilder::chunk` splits each chunk back into 64 KiB blocks when hashing — so the digest does not depend on how chunks were merged.

- [ ] **Step 1: Failing tests** (`sparse.rs` `mod tests`, use `tempfile`):

```rust
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn write_at(path: &Path, len: u64, parts: &[(u64, &[u8])]) {
        let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(path).unwrap();
        f.set_len(len).unwrap();
        for (off, bytes) in parts {
            f.seek(SeekFrom::Start(*off)).unwrap();
            f.write_all(bytes).unwrap();
        }
    }

    fn collect(path: &Path) -> (u64, Vec<(u64, usize)>) {
        let mut v = Vec::new();
        let len = for_each_chunk(path, |c| { v.push((c.offset, c.data.len())); Ok(()) }).unwrap();
        (len, v)
    }

    #[test]
    fn all_hole_file_yields_no_chunks() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 10 * 1024 * 1024, &[]);
        assert_eq!(collect(&p), (10 * 1024 * 1024, vec![]));
    }

    #[test]
    fn data_blocks_become_block_aligned_chunks() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 1 << 22, &[(100, b"x"), (3 * ZERO_BLOCK + 5, b"y")]);
        assert_eq!(collect(&p).1, vec![(0, ZERO_BLOCK as usize), (3 * ZERO_BLOCK, ZERO_BLOCK as usize)]);
    }

    #[test]
    fn adjacent_blocks_merge_up_to_max_chunk() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        let big = vec![7u8; (MAX_CHUNK + ZERO_BLOCK) as usize];
        write_at(&p, MAX_CHUNK * 2, &[(0, &big)]);
        assert_eq!(collect(&p).1, vec![(0, MAX_CHUNK as usize), (MAX_CHUNK, ZERO_BLOCK as usize)]);
    }

    #[test]
    fn unaligned_tail_is_a_short_chunk() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, ZERO_BLOCK + 10, &[(ZERO_BLOCK + 3, b"z")]);
        assert_eq!(collect(&p), (ZERO_BLOCK + 10, vec![(ZERO_BLOCK, 10)]));
    }

    #[test]
    fn zero_blocks_are_elided_and_digest_matches_sparse_twin() {
        let t = tempfile::tempdir().unwrap();
        let dense = t.path().join("dense.img");
        let sparse = t.path().join("sparse.img");
        let mut content = vec![0u8; (4 * ZERO_BLOCK) as usize];
        content[(2 * ZERO_BLOCK) as usize] = 9;
        std::fs::write(&dense, &content).unwrap(); // fully allocated zeros
        write_at(&sparse, 4 * ZERO_BLOCK, &[(2 * ZERO_BLOCK, &[9])]);
        assert_eq!(collect(&dense).1, vec![(2 * ZERO_BLOCK, ZERO_BLOCK as usize)]);
        assert_eq!(content_digest(&dense).unwrap(), content_digest(&sparse).unwrap());
    }

    #[test]
    fn digest_distinguishes_length_and_content() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a"); let b = t.path().join("b"); let c = t.path().join("c");
        write_at(&a, 1 << 20, &[(5, b"q")]);
        write_at(&b, 2 << 20, &[(5, b"q")]);
        write_at(&c, 1 << 20, &[(5, b"r")]);
        let (da, db, dc) = (content_digest(&a).unwrap(), content_digest(&b).unwrap(), content_digest(&c).unwrap());
        assert_ne!(da, db); assert_ne!(da, dc);
    }

    #[test]
    fn digest_is_independent_of_chunk_merging() {
        let mut one = DigestBuilder::new(2 * ZERO_BLOCK);
        one.chunk(&Chunk { offset: 0, data: vec![1u8; (2 * ZERO_BLOCK) as usize] });
        let mut two = DigestBuilder::new(2 * ZERO_BLOCK);
        two.chunk(&Chunk { offset: 0, data: vec![1u8; ZERO_BLOCK as usize] });
        two.chunk(&Chunk { offset: ZERO_BLOCK, data: vec![1u8; ZERO_BLOCK as usize] });
        assert_eq!(one.finish(), two.finish());
    }

    #[test]
    fn create_sparse_then_write_chunks_round_trips() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        write_at(&src, 3 << 20, &[(0, b"head"), ((2 << 20) + 1, b"tail")]);
        let dst = t.path().join("dst");
        let mut f = create_sparse(&dst, 3 << 20).unwrap();
        for_each_chunk(&src, |c| {
            f.seek(SeekFrom::Start(c.offset))?;
            f.write_all(&c.data)?;
            Ok(())
        }).unwrap();
        drop(f);
        assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&dst).unwrap());
        assert_eq!(content_digest(&src).unwrap(), content_digest(&dst).unwrap());
    }

    #[test]
    fn chunk_entry_names_round_trip() {
        let n = chunk_entry_name("sandboxes/a/rw.img", 0x1_0000);
        assert_eq!(n, "sandboxes/a/rw.img.d/0000000000010000");
        assert_eq!(parse_chunk_entry(&n), Some(("sandboxes/a/rw.img", 0x1_0000)));
        assert_eq!(parse_chunk_entry("sandboxes/a/rw.img.d/xyz"), None);
        assert_eq!(parse_chunk_entry("sandboxes/a/config.json"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_extents_skip_holes() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 64 << 20, &[(32 << 20, b"x")]);
        let f = std::fs::File::open(&p).unwrap();
        let ext = data_extents(&f, 64 << 20).unwrap();
        let covered: u64 = ext.iter().map(|e| e.1).sum();
        assert!(covered < 64 << 20, "tmpfs/ext4 report holes: {ext:?}");
        assert!(ext.iter().any(|&(o, l)| o <= 32 << 20 && 32 << 20 < o + l));
    }
```

- [ ] **Step 2: Run** `cargo test -p izba-core bundle::sparse` → FAIL.

- [ ] **Step 3: Implement** `bundle/mod.rs`:

```rust
//! Sandbox save/load archives (spec docs/superpowers/specs/2026-09-29-sandbox-save-load-design.md).
//! A pure library: no daemon or CLI assumptions. `.izba` = zstd(tar):
//! `manifest.json` first, then images / named volumes / sandbox files, disks
//! as `<path>.d/<offset-hex>` data-chunk entries, `checksums.json` last.

pub mod fsutil;
pub mod load;
pub mod manifest;
pub mod save;
pub mod sparse;
pub mod workspace;

/// Archive format version written by this build; newer is refused on load.
pub const FORMAT_VERSION: u32 = 1;
/// Zero-elision granularity: an all-zero block of this size is never stored.
pub const ZERO_BLOCK: u64 = 64 * 1024;
/// Upper bound of one chunk entry's body (bounds memory per entry).
pub const MAX_CHUNK: u64 = 4 * 1024 * 1024;
/// Progress sink (daemon Progress frames / CLI stderr).
pub type Progress<'a> = &'a mut dyn FnMut(String);
```

(Create empty `load.rs`/`manifest.rs`/`save.rs`/`workspace.rs`/`fsutil.rs` with a one-line `//!` doc so the module compiles; later tasks fill them.)

`bundle/sparse.rs`:

```rust
//! Sparse-aware disk streaming: enumerate allocated extents, cut them into
//! block-aligned non-zero chunks, and a canonical content digest that is the
//! same for a sparse file and its fully-allocated twin (save/load spec §4.2).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::Context;
use sha2::{Digest, Sha256};

use super::{MAX_CHUNK, ZERO_BLOCK};

pub struct Chunk {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Possibly-non-hole regions of `f` as `(offset, len)`, ascending. Any
/// enumeration failure falls back to one full extent (always correct, just
/// slower — zero elision still keeps the archive small).
pub fn data_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    Ok(os_extents(f, len).unwrap_or_else(|_| vec![(0, len)]))
}

#[cfg(target_os = "linux")]
fn os_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    let mut out = Vec::new();
    let mut pos: i64 = 0;
    while (pos as u64) < len {
        // SAFETY: lseek on an owned, open fd.
        let data = unsafe { libc::lseek(fd, pos, libc::SEEK_DATA) };
        if data < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break; // no more data
            }
            return Err(e);
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let end = (hole as u64).min(len);
        if end > data as u64 {
            out.push((data as u64, end - data as u64));
        }
        pos = hole;
    }
    Ok(out)
}

#[cfg(windows)]
fn os_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::{FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut out = Vec::new();
    let mut start: i64 = 0;
    loop {
        let query = FILE_ALLOCATED_RANGE_BUFFER { FileOffset: start, Length: len as i64 - start };
        let mut buf = vec![FILE_ALLOCATED_RANGE_BUFFER { FileOffset: 0, Length: 0 }; 512];
        let mut returned: u32 = 0;
        // SAFETY: valid handle; in/out buffers sized as passed.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle() as _,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query as *const _ as _,
                std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                buf.as_mut_ptr() as _,
                (buf.len() * std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>()) as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let more = ok == 0
            && std::io::Error::last_os_error().raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_MORE_DATA as i32);
        if ok == 0 && !more {
            return Err(std::io::Error::last_os_error());
        }
        let n = returned as usize / std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        for r in &buf[..n] {
            out.push((r.FileOffset as u64, r.Length as u64));
        }
        if !more || n == 0 {
            break;
        }
        let last = buf[n - 1];
        start = last.FileOffset + last.Length;
    }
    Ok(out)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn os_extents(_f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    Ok(vec![(0, len)])
}

/// Stream every maximal run of non-zero `ZERO_BLOCK`-aligned blocks (split at
/// `MAX_CHUNK`) to `f`, in offset order. Returns the logical length.
pub fn for_each_chunk(
    path: &Path,
    mut f: impl FnMut(Chunk) -> anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    let extents = data_extents(&file, len)?;
    let mut pending: Option<Chunk> = None;
    let mut block = vec![0u8; ZERO_BLOCK as usize];
    for (ext_off, ext_len) in extents {
        // Align the extent outward to whole blocks.
        let mut off = ext_off - ext_off % ZERO_BLOCK;
        let end = (ext_off + ext_len).min(len);
        while off < end {
            let n = ZERO_BLOCK.min(len - off) as usize;
            file.seek(SeekFrom::Start(off))?;
            file.read_exact(&mut block[..n])
                .with_context(|| format!("reading {} @{off}", path.display()))?;
            let nonzero = block[..n].iter().any(|&b| b != 0);
            if nonzero {
                match &mut pending {
                    Some(c) if c.offset + c.data.len() as u64 == off
                        && (c.data.len() as u64 + n as u64) <= MAX_CHUNK =>
                    {
                        c.data.extend_from_slice(&block[..n])
                    }
                    _ => {
                        if let Some(c) = pending.take() {
                            f(c)?;
                        }
                        pending = Some(Chunk { offset: off, data: block[..n].to_vec() });
                    }
                }
            } else if let Some(c) = pending.take() {
                f(c)?;
            }
            off += n as u64;
        }
    }
    if let Some(c) = pending.take() {
        f(c)?;
    }
    Ok(len)
}

/// Canonical digest: sha256(len_le ‖ Σ over non-zero blocks: off_le ‖ n_le ‖ bytes).
pub struct DigestBuilder(Sha256);

impl DigestBuilder {
    pub fn new(logical_len: u64) -> Self {
        let mut h = Sha256::new();
        h.update(logical_len.to_le_bytes());
        Self(h)
    }

    /// Feed one chunk; re-split into blocks so merging never changes the digest.
    pub fn chunk(&mut self, c: &Chunk) {
        for (i, blk) in c.data.chunks(ZERO_BLOCK as usize).enumerate() {
            if blk.iter().all(|&b| b == 0) {
                continue;
            }
            let off = c.offset + (i as u64) * ZERO_BLOCK;
            self.0.update(off.to_le_bytes());
            self.0.update((blk.len() as u32).to_le_bytes());
            self.0.update(blk);
        }
    }

    pub fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

pub fn content_digest(path: &Path) -> anyhow::Result<String> {
    let len = std::fs::metadata(path)?.len();
    let mut d = DigestBuilder::new(len);
    for_each_chunk(path, |c| {
        d.chunk(&c);
        Ok(())
    })?;
    Ok(d.finish())
}

/// Create (truncating) a sparse file of `logical_len` (NTFS sparse flag set).
pub fn create_sparse(path: &Path, logical_len: u64) -> anyhow::Result<File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    crate::sandbox::mark_sparse(&f);
    f.set_len(logical_len)
        .with_context(|| format!("sizing {}", path.display()))?;
    Ok(f)
}

pub fn chunk_entry_name(prefix: &str, offset: u64) -> String {
    format!("{prefix}.d/{offset:016x}")
}

pub fn parse_chunk_entry(name: &str) -> Option<(&str, u64)> {
    let (prefix, hexoff) = name.rsplit_once(".d/")?;
    if hexoff.len() != 16 {
        return None;
    }
    Some((prefix, u64::from_str_radix(hexoff, 16).ok()?))
}
```

Add `libc = "0.2"` to izba-core `[target.'cfg(unix)'.dependencies]` if not already a direct dep (check `grep -n '^libc' crates/izba-core/Cargo.toml`); `nix` already pulls it but a direct `libc::lseek` needs the direct dep. Make `mark_sparse` in `sandbox.rs` `pub(crate)` (both cfg variants). Add `"Win32_System_Ioctl"` is already enabled; `FILE_ALLOCATED_RANGE_BUFFER` lives there.

- [ ] **Step 4: Run** `cargo test -p izba-core bundle::sparse` → PASS; windows-gnu check + clippy → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/bundle crates/izba-core/src/lib.rs crates/izba-core/src/sandbox.rs crates/izba-core/Cargo.toml Cargo.lock
git commit -m "feat(core): sparse-aware disk chunking and canonical content digest"
```

---

### Task 6: `bundle::manifest` — types and archive-path validation

**Files:**
- Create content: `crates/izba-core/src/bundle/manifest.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceOs { Linux, Windows, Other }
impl SourceOs { pub fn current() -> Self }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub izba_version: String,          // BuildInfoOwned::current().short-ish string
    pub source_os: SourceOs,
    pub created_unix_ms: u64,
    pub tags: std::collections::BTreeMap<String, String>, // tag -> digest
    pub images: Vec<String>,           // digests included
    pub named_volumes: Vec<BlobInfo>,  // path = "volumes/<name>.img"
    pub sandboxes: Vec<SandboxEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEntry {
    pub name: String,
    pub disk_owner: (u32, u32),
    pub workspace_bundled: bool,
    pub source_workspace: String,      // lossless display of the source path
    pub source_home: Option<String>,
    pub disks: Vec<BlobInfo>,          // rw.img + anonymous volumes
    pub workspace_bytes: u64,          // sum of regular-file sizes (preflight)
    #[serde(default)]
    pub locked: bool,                  // source had lockdown.json (=> "re-run izba lockdown" on load)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobInfo { pub path: String, pub logical_len: u64, pub allocated: u64 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checksums { pub files: std::collections::BTreeMap<String, String> } // archive path -> hex sha256 / content digest

pub const MANIFEST_PATH: &str = "manifest.json";
pub const CHECKSUMS_PATH: &str = "checksums.json";

pub fn check_format(m: &Manifest) -> anyhow::Result<()>;
pub fn validate_entry_path(p: &str) -> anyhow::Result<()>;
```

- [ ] **Step 1: Failing tests**

```rust
    #[test]
    fn future_format_is_refused_with_upgrade_hint() {
        let mut m = sample();
        m.format = FORMAT_VERSION + 1;
        let e = check_format(&m).unwrap_err().to_string();
        assert!(e.contains("newer izba"), "{e}");
        m.format = FORMAT_VERSION;
        check_format(&m).unwrap();
    }

    #[test]
    fn entry_paths_must_be_relative_normalized_and_known() {
        for ok in ["manifest.json", "checksums.json", "images/sha256-ab/rootfs.erofs",
                   "volumes/data.img.d/0000000000000000", "sandboxes/a/config.json",
                   "workspaces/a/src/main.rs", "workspaces/a/.git/HEAD"] {
            validate_entry_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["/etc/passwd", "../x", "sandboxes/../../x", "sandboxes/a/./b", "", "other/x",
                    "sandboxes//a", "C:/x", "sandboxes\\a", "workspaces/a/../../b"] {
            assert!(validate_entry_path(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample();
        let back: Manifest = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(back.sandboxes[0].name, "a");
        assert_eq!(back.source_os, SourceOs::Linux);
    }

    fn sample() -> Manifest {
        Manifest {
            format: FORMAT_VERSION, izba_version: "t".into(), source_os: SourceOs::Linux,
            created_unix_ms: 1, tags: Default::default(), images: vec!["sha256:ab".into()],
            named_volumes: vec![],
            sandboxes: vec![SandboxEntry { name: "a".into(), disk_owner: (1000, 1000),
                workspace_bundled: false, source_workspace: "/home/u/p".into(),
                source_home: Some("/home/u".into()), disks: vec![], workspace_bytes: 0, locked: false }],
        }
    }
```

- [ ] **Step 2: Run** `cargo test -p izba-core bundle::manifest` → FAIL.

- [ ] **Step 3: Implement.** `validate_entry_path`: reject empty, any `\\`, leading `/`, a `:` in the first component, any component that is `""`, `.` or `..`; first component must be one of `manifest.json`, `checksums.json`, `images`, `volumes`, `sandboxes`, `workspaces` (the first two only as the whole path). `check_format`: `bail!("archive format {} is newer than this izba supports ({FORMAT_VERSION}); upgrade izba on this host", m.format)` when `m.format > FORMAT_VERSION`; also refuse `0`. `SourceOs::current()` via `cfg!(target_os=…)`. `izba_version` filled by save from `crate::build_info` (use whatever `BuildInfoOwned::current()` exposes for the short version, e.g. its `describe` field — check `build_info.rs`).

- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(core): save/load archive manifest and entry-path validation`.

---

### Task 7: `bundle::workspace` — tar the tree, restore it, translate paths

**Files:**
- Create content: `crates/izba-core/src/bundle/workspace.rs`

**Interfaces:**
- Produces:
  - `pub fn append_workspace<W: std::io::Write>(tar: &mut tar::Builder<W>, root: &Path, archive_prefix: &str, exec_bits: &std::collections::HashSet<std::path::PathBuf>) -> anyhow::Result<u64>` — appends every entry under `root` (dirs, files, symlinks — never following them) at `<archive_prefix>/<rel>` with forward slashes; on Unix modes come from metadata; on Windows files are 0644 (0755 if `rel` ∈ `exec_bits`), dirs 0755. Returns bytes of regular-file content.
  - `pub fn git_exec_bits(root: &Path) -> std::collections::HashSet<std::path::PathBuf>` — runs `git -C root ls-files -s -z` if `git` is on PATH; collects paths whose mode is `100755`; empty set on any failure. Only used on Windows sources.
  - `pub fn workspace_bytes(root: &Path) -> anyhow::Result<u64>`
  - `pub fn unpack_entry<R: std::io::Read>(entry: &mut tar::Entry<R>, dest_root: &Path, rel: &Path) -> anyhow::Result<()>` — creates parents; symlink creation failure on Windows maps to an error naming Developer Mode.
  - `pub fn translate_workspace(source: &str, source_home: Option<&str>, source_os: &SourceOs, target_home: &Path) -> Option<PathBuf>` — same OS ⇒ `Some(PathBuf::from(source))`; cross-OS ⇒ if source is under `source_home` ⇒ `target_home.join(rel components)`; else `None`.
  - `pub fn is_free_target(p: &Path) -> bool` — does not exist, or is an empty dir.

- [ ] **Step 1: Failing tests**

```rust
    #[test]
    fn translate_same_os_keeps_path() {
        let p = translate_workspace("/home/u/proj", Some("/home/u"), &SourceOs::current(), Path::new("/home/v"));
        assert_eq!(p, Some(PathBuf::from("/home/u/proj")));
    }

    #[test]
    fn translate_linux_to_other_os_rebases_under_home() {
        let other = if SourceOs::current() == SourceOs::Linux { SourceOs::Windows } else { SourceOs::Linux };
        let (src, home) = match other {
            SourceOs::Windows => (r"C:\Users\u\code\proj", r"C:\Users\u"),
            _ => ("/home/u/code/proj", "/home/u"),
        };
        let t = Path::new("/target/home");
        assert_eq!(translate_workspace(src, Some(home), &other, t), Some(t.join("code").join("proj")));
    }

    #[test]
    fn translate_outside_home_needs_explicit_workspace() {
        let other = if SourceOs::current() == SourceOs::Linux { SourceOs::Windows } else { SourceOs::Linux };
        let (src, home) = match other {
            SourceOs::Windows => (r"D:\work\proj", r"C:\Users\u"),
            _ => ("/srv/proj", "/home/u"),
        };
        assert_eq!(translate_workspace(src, Some(home), &other, Path::new("/t")), None);
    }

    #[test]
    fn translate_strips_windows_verbatim_prefix() {
        if SourceOs::current() == SourceOs::Windows { return; }
        let p = translate_workspace(r"\\?\C:\Users\u\proj", Some(r"C:\Users\u"), &SourceOs::Windows, Path::new("/h"));
        assert_eq!(p, Some(PathBuf::from("/h/proj")));
    }

    #[test]
    fn is_free_target_rules() {
        let t = tempfile::tempdir().unwrap();
        assert!(is_free_target(&t.path().join("nope")));
        assert!(is_free_target(t.path()));
        std::fs::write(t.path().join("f"), b"x").unwrap();
        assert!(!is_free_target(t.path()));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_round_trips_files_modes_symlinks_and_dotfiles() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join(".git/objects")).unwrap();
        std::fs::write(src.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(src.join("run.sh"), b"#!/bin/sh").unwrap();
        std::fs::set_permissions(src.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(src.join(".git/HEAD"), b"ref").unwrap();
        symlink("run.sh", src.join("link")).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            append_workspace(&mut b, &src, "workspaces/a", &Default::default()).unwrap();
            b.finish().unwrap();
        }
        let dst = t.path().join("dst");
        let mut ar = tar::Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let p = e.path().unwrap().into_owned();
            let rel = p.strip_prefix("workspaces/a").unwrap().to_path_buf();
            if rel.as_os_str().is_empty() { continue; }
            unpack_entry(&mut e, &dst, &rel).unwrap();
        }
        assert_eq!(std::fs::read(dst.join(".env")).unwrap(), b"SECRET=1");
        assert_eq!(std::fs::read(dst.join(".git/HEAD")).unwrap(), b"ref");
        assert_eq!(std::fs::metadata(dst.join("run.sh")).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(std::fs::read_link(dst.join("link")).unwrap(), PathBuf::from("run.sh"));
    }

    #[test]
    fn unpack_refuses_to_write_through_a_symlink() {
        // An entry `link/x` after `link -> /elsewhere` must not escape dest.
        #[cfg(unix)]
        {
            let t = tempfile::tempdir().unwrap();
            let dst = t.path().join("dst");
            let outside = t.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::create_dir_all(&dst).unwrap();
            std::os::unix::fs::symlink(&outside, dst.join("link")).unwrap();
            let mut buf = Vec::new();
            {
                let mut b = tar::Builder::new(&mut buf);
                let mut h = tar::Header::new_gnu();
                h.set_size(1); h.set_mode(0o644); h.set_cksum();
                b.append_data(&mut h, "workspaces/a/link/x", &b"z"[..]).unwrap();
                b.finish().unwrap();
            }
            let mut ar = tar::Archive::new(&buf[..]);
            let mut e = ar.entries().unwrap().next().unwrap().unwrap();
            assert!(unpack_entry(&mut e, &dst, Path::new("link/x")).is_err());
            assert!(!outside.join("x").exists());
        }
    }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Key points:
  - `append_workspace`: walk with `std::fs::read_dir` recursively (sorted by name for determinism), `symlink_metadata` per entry; dirs → `Header` type Directory; symlinks → `append_link` with `read_link` target; files → `append_data` with a `File` reader (header mode from `PermissionsExt` on unix; Windows rule above). Paths joined with `/`.
  - `unpack_entry`: compute `target = dest_root.join(rel)`; walk each ancestor of `target` under `dest_root` with `symlink_metadata`; if any existing ancestor is a symlink → `bail!("refusing to write {} through a symlink", rel.display())`. Create parent dirs, then `entry.unpack(&target)` (tar crate honors type: file/dir/symlink, sets unix mode). On Windows, map an `unpack` error for a Symlink entry to `bail!("creating symlink {}: {e} — enable Windows Developer Mode (Settings → For developers) or run elevated, then re-run izba load", rel.display())`.
  - `translate_workspace`: strip a leading `\\?\` from Windows-shaped strings; split source and home by `/` or `\` depending on `source_os`; compare component-wise (case-insensitive for Windows); rebuild under `target_home` with `PathBuf::push` per component.
  - `git_exec_bits`: `which::which("git")`, then `Command::new(git).args(["-C", root, "ls-files", "-s", "-z"])`; parse records `"<mode> <sha> <stage>\t<path>\0"`.
  - Target home: callers pass `dirs`-free home: Unix `std::env::var_os("HOME")`, Windows `USERPROFILE` (same vars `paths.rs` uses).

- [ ] **Step 4: Run** → PASS (also windows-gnu clippy). **Step 5: Commit** `feat(core): workspace archiving, restore and cross-OS path translation`.

---

### Task 8: `bundle::save` — plan and write the archive

**Files:**
- Create content: `crates/izba-core/src/bundle/save.rs`
- Modify: `crates/izba-core/Cargo.toml` — add `zstd = { version = "0.13", features = ["zstdmt"] }`; run `cargo deny check` if available (license BSD-3/MIT — allowed? check `deny.toml` `allow` list; add `BSD-3-Clause` only if missing and tell the reviewer).
- Modify: `crates/izba-core/src/sandbox.rs` — expose `pub(crate) fn lock_sandbox` (already), make `persistent_volume_holder` `pub(crate)`.

**Interfaces:**
- Consumes: Tasks 5–7; `sandbox::{lock_sandbox, liveness_of, workspace_owner, persistent_volume_holder}`, `state::{load_json, SandboxConfig, CONFIG_FILE}`, `image::store::ImageStore`, `image::tags::resolve_tag`.
- Produces:

```rust
pub struct SaveOpts { pub names: Vec<String>, pub out: PathBuf, pub with_workspace: bool }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaveReport { pub path: PathBuf, pub sandboxes: Vec<String>, pub logical_bytes: u64, pub archive_bytes: u64 }
/// Caller guarantees every named sandbox is stopped (daemon stops them first for --stop).
pub fn save(paths: &Paths, connector: Connector, opts: &SaveOpts, progress: Progress) -> anyhow::Result<SaveReport>;
/// Pure planning step (testable without I/O beyond reading configs).
pub(crate) struct Plan { pub configs: Vec<(String, SandboxConfig)>, pub images: BTreeSet<String>, pub named_volumes: BTreeSet<String>, pub tags: BTreeMap<String,String> }
pub(crate) fn plan(paths: &Paths, names: &[String]) -> anyhow::Result<Plan>;
```

Entry order written: `manifest.json`; `images/<digest-dir>/<file>` for each of `rootfs.erofs`, `config.json`, `ref.txt`, `passwd`, `group` that exists (plain entries; sha256 into checksums); for each named volume: chunk entries under prefix `volumes/<name>.img` (content digest into checksums under key `volumes/<name>.img`); for each sandbox: `sandboxes/<n>/{config.json,policy.yaml,manifest.base.yaml,manifest.review}` + `sandboxes/<n>/egress-audit.jsonl` (from `logs/`) when present (sha256), chunk entries for `sandboxes/<n>/rw.img` and each anonymous volume `sandboxes/<n>/volumes/<eph_id>.img` (digest); `workspaces/<n>/…` with `--with-workspace`; `checksums.json` last. Image dir name = `paths.image_dir(digest)`'s file name (digest with `:`→`-`). Every disk also gets an empty marker entry `<prefix>.len` whose body is the 8-byte LE logical length — so an all-zero disk (no chunks) still materializes on load.

- [ ] **Step 1: Failing tests** (build fixtures with a helper that writes `sandboxes/<n>/config.json` via `save_json`, a sparse `rw.img`, an `images/<d>/rootfs.erofs` + `config.json`, and `volumes/<v>.img`; a fake `Connector` that always errors — `liveness_of` then reports Stopped when there is no `state.json`):

```rust
    #[test]
    fn plan_dedups_shared_image_and_collects_named_volumes() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[]);
        let p = plan(&paths, &["a".into(), "b".into()]).unwrap();
        assert_eq!(p.images.len(), 1);
        assert_eq!(p.named_volumes.iter().collect::<Vec<_>>(), vec!["data"]);
        drop(t);
    }

    #[test]
    fn plan_refuses_unknown_sandbox() {
        let (_t, paths) = fixture();
        assert!(plan(&paths, &["ghost".into()]).unwrap_err().to_string().contains("no such sandbox"));
    }

    #[test]
    fn save_writes_manifest_first_and_checksums_last_and_skips_host_bound_files() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        for f in ["state.json", "ports.json", "lockdown.json", "lockdown.cred"] {
            std::fs::write(paths.sandbox_dir("a").join(f), b"{}").unwrap();
        }
        std::fs::create_dir_all(paths.sandbox_dir("a").join("ssh")).unwrap();
        std::fs::write(paths.sandbox_dir("a").join("ssh/authorized_keys"), b"k").unwrap();
        let out = t.path().join("x.izba");
        save(&paths, &no_conn, &SaveOpts { names: vec!["a".into()], out: out.clone(), with_workspace: false }, &mut |_| {}).unwrap();
        let names = entry_names(&out);
        assert_eq!(names.first().unwrap(), "manifest.json");
        assert_eq!(names.last().unwrap(), "checksums.json");
        for bad in ["state.json", "ports.json", "lockdown", "ssh/"] {
            assert!(!names.iter().any(|n| n.contains(bad)), "{bad} leaked: {names:?}");
        }
        assert!(names.iter().any(|n| n == "sandboxes/a/rw.img.len"));
        assert!(!out.with_extension("izba.partial").exists());
    }

    #[test]
    fn save_refuses_a_running_sandbox() {
        // state.json with our own pid+starttime => liveness Running/Unhealthy.
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        write_live_state(&paths, "a"); // RunState with PidIdentity of std::process::id()
        let e = save(&paths, &no_conn, &SaveOpts { names: vec!["a".into()], out: t.path().join("x.izba"), with_workspace: false }, &mut |_| {}).unwrap_err();
        assert!(e.to_string().contains("stop it first"), "{e}");
    }

    #[test]
    fn save_failure_removes_partial() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:missing", &[]); // image dir absent => error mid-write
        let out = t.path().join("x.izba");
        assert!(save(&paths, &no_conn, &SaveOpts { names: vec!["a".into()], out: out.clone(), with_workspace: false }, &mut |_| {}).is_err());
        assert!(!out.exists());
        assert!(!t.path().join("x.izba.partial").exists());
    }
```

(`entry_names(path)` opens the file with `zstd::Decoder` + `tar::Archive` and collects entry paths. `write_live_state` builds a `RunState` the way the existing liveness tests in `sandbox.rs` do — reuse that helper; grep `fn .*live.*state` in sandbox.rs tests.)

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** (outline with real code for the core loop):

```rust
pub fn save(paths: &Paths, connector: Connector, opts: &SaveOpts, progress: Progress) -> anyhow::Result<SaveReport> {
    let plan = plan(paths, &opts.names)?;
    // Locks held for the whole write, then liveness re-checked under them.
    let mut _locks = Vec::new();
    for (name, _) in &plan.configs {
        _locks.push(crate::sandbox::lock_sandbox(paths, name)?);
        if crate::sandbox::liveness_of(paths, name, connector)? != crate::liveness::Liveness::Stopped {
            bail!("sandbox '{name}' is running; stop it first (or pass --stop)");
        }
    }
    for v in &plan.named_volumes {
        let owner = plan.configs.iter().find(|(_, c)| c.volumes.iter().any(|s| s.name.as_deref() == Some(v))).map(|(n, _)| n.as_str()).unwrap_or("");
        if let Some(h) = crate::sandbox::persistent_volume_holder(paths, v, owner, connector)? {
            bail!("named volume '{v}' is in use by running sandbox '{h}'; stop it first");
        }
    }
    let partial = opts.out.with_file_name(format!("{}.partial", opts.out.file_name().context("output path has no file name")?.to_string_lossy()));
    let result = write_archive(paths, &plan, opts, &partial, progress);
    match result {
        Ok(mut report) => {
            std::fs::rename(&partial, &opts.out).with_context(|| format!("renaming to {}", opts.out.display()))?;
            report.path = opts.out.clone();
            report.archive_bytes = std::fs::metadata(&opts.out)?.len();
            Ok(report)
        }
        Err(e) => { let _ = std::fs::remove_file(&partial); Err(e) }
    }
}
```

`write_archive`: `let file = File::create(partial)?; let mut enc = zstd::Encoder::new(BufWriter::new(file), 3)?; enc.include_checksum(true)?; enc.multithread(num_cpus_or(4))?;` (use `std::thread::available_parallelism`), `let mut tar = tar::Builder::new(enc); tar.mode(tar::HeaderMode::Deterministic);`. Helper fns:

```rust
fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_size(bytes.len() as u64);
    h.set_mode(0o600);
    h.set_cksum();
    tar.append_data(&mut h, path, bytes).with_context(|| format!("archiving {path}"))
}

fn append_file_hashed<W: Write>(tar: &mut tar::Builder<W>, path: &str, src: &Path, sums: &mut Checksums) -> anyhow::Result<u64> {
    let bytes_len = std::fs::metadata(src)?.len();
    let mut h = tar::Header::new_gnu();
    h.set_size(bytes_len);
    h.set_mode(0o600);
    h.set_cksum();
    let mut r = HashingReader { inner: File::open(src)?, h: Sha256::new() };
    tar.append_data(&mut h, path, &mut r).with_context(|| format!("archiving {path}"))?;
    sums.files.insert(path.to_string(), hex::encode(r.h.finalize()));
    Ok(bytes_len)
}

fn append_disk<W: Write>(tar: &mut tar::Builder<W>, prefix: &str, src: &Path, sums: &mut Checksums, progress: Progress) -> anyhow::Result<u64> {
    let len = std::fs::metadata(src)?.len();
    append_bytes(tar, &format!("{prefix}.len"), &len.to_le_bytes())?;
    let mut d = DigestBuilder::new(len);
    let mut done = 0u64;
    for_each_chunk(src, |c| {
        d.chunk(&c);
        append_bytes(tar, &chunk_entry_name(prefix, c.offset), &c.data)?;
        done += c.data.len() as u64;
        if done % (256 << 20) < c.data.len() as u64 { progress(format!("{prefix}: {} MiB", done >> 20)); }
        Ok(())
    })?;
    sums.files.insert(prefix.to_string(), d.finish());
    Ok(len)
}
```

`HashingReader` implements `Read` by delegating and `update`-ing. Manifest `disk_owner`: `config.disk_owner.unwrap_or_else(|| crate::sandbox::workspace_owner(&config.workspace))`; `source_home` from `HOME`/`USERPROFILE`; `source_workspace` = `config.workspace.to_string_lossy()`; `allocated` = Unix `MetadataExt::blocks()*512`, Windows = logical len (reuse `sandbox::allocated_bytes` at sandbox.rs:1814 — make it `pub(crate)`). Workspace: `append_workspace(&mut tar, &config.workspace, &format!("workspaces/{name}"), &exec_bits)` where `exec_bits = if cfg!(windows) { git_exec_bits(ws) } else { Default::default() }`; with `--with-workspace` and the workspace missing ⇒ `bail!("sandbox '{name}': workspace {} does not exist; save without --with-workspace", ...)`. `plan`: validate names (`validate_name`), load each config (`no such sandbox '{n}'` when missing), collect `image_digest`s, named volumes (`VolumeSpec::name`), and tags: for each config whose `image_ref` resolves via `resolve_tag` to its digest, record it. Report progress per phase ("saving sandbox 'a'", "image sha256:…").

- [ ] **Step 4: Run** → PASS + six gates. **Step 5: Commit** `feat(core): write sandbox save archives`.

---

### Task 9: `bundle::load` — preflight, staging, verify, commit, rollback

**Files:**
- Create content: `crates/izba-core/src/bundle/load.rs`, `crates/izba-core/src/bundle/fsutil.rs`

**Interfaces:**
- Consumes: Tasks 5–8; `sandbox::validate_name`, `volume::validate_volumes`, `procmgr::ensure_confinable`, `image::tags::{resolve_tag,set_tag}`, `paths::create_dir_700`.
- Produces:

```rust
pub struct LoadOpts {
    pub archive: PathBuf,
    pub select: Vec<String>,            // empty = all
    pub rename: Option<String>,          // requires exactly one selected
    pub workspace: Option<PathBuf>,      // requires exactly one selected
    pub workspace_root: Option<PathBuf>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadedSandbox { pub name: String, pub image_ref: String, pub workspace: PathBuf }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LoadReport { pub sandboxes: Vec<LoadedSandbox>, pub warnings: Vec<String>, pub redo: Vec<String> }
pub fn load(paths: &Paths, opts: &LoadOpts, progress: Progress) -> anyhow::Result<LoadReport>;

// fsutil.rs
pub fn free_bytes(dir: &Path) -> anyhow::Result<u64>;  // statvfs / GetDiskFreeSpaceExW on nearest existing ancestor
```

Seams for tests: `load_with(paths, opts, progress, hooks: &LoadHooks)` where

```rust
pub(crate) struct LoadHooks<'a> {
    pub free_bytes: &'a dyn Fn(&Path) -> anyhow::Result<u64>,
    pub target_home: PathBuf,
    pub fail_at: Option<CommitStep>,  // test-only fault injection
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStep { Images, Volumes, Workspaces, Sandboxes }
```

`load` = `load_with(paths, opts, progress, &LoadHooks { free_bytes: &fsutil::free_bytes, target_home: home_dir()?, fail_at: None })`.

Algorithm:
1. Open `zstd::Decoder` → `tar::Archive`; first entry must be `manifest.json` (else `bail!("not an izba archive (manifest.json must come first)")`); `check_format`.
2. Resolve selection (`select` ⊆ manifest names else error listing available names); apply `rename`; `validate_name` each final name; refuse existing `sandbox_dir(final)` → `bail!("sandbox '{n}' already exists here; pass --as <new-name> to load it under another name")`.
3. Resolve each workspace target: explicit `workspace` > `workspace_root.join(basename)` > `translate_workspace(...)`; `None` ⇒ `bail!("sandbox '{n}': cannot place workspace {src} on this host; pass --workspace <dir>")`. Bundled ⇒ `is_free_target` else `bail!("workspace target {p} is not empty; pass --workspace <empty-or-new dir>")`. Not bundled ⇒ target must exist as dir, else `bail!("workspace {p} does not exist; clone/copy it there or pass --workspace <dir> (or save with --with-workspace)")`. Run `ensure_confinable(target)` (after it exists: for bundled, run after commit on the created dir — error rolls back).
4. Space: `need_data = Σ allocated(selected disks + named volumes not already present + images not present)` and `need_ws = Σ workspace_bytes` grouped by the filesystem of `paths.root()` vs each workspace parent (group by the nearest existing ancestor path string; conservative: sum everything per distinct ancestor). Require `free >= need * 105 / 100` else `bail!("not enough free space on {dir}: need {need_h}, have {free_h}")`.
5. Stage dir: `paths.root().join(format!(".load-{}", std::process::id()))` (create 0700); first sweep sibling `.load-<pid>` dirs whose pid is not alive (`procmgr::pid_alive` needs starttime — just check `/proc/<pid>` existence on Linux / `OpenProcess` on Windows via a tiny helper; if uncertain, leave it). Workspace staging: `<target parent>/.izba-load-<pid>-<basename>`.
6. Stream entries: `validate_entry_path`; route by prefix:
   - `images/<d>/<f>` → skip (drain) if `ImageStore::is_complete(digest)` on target, else write to `stage/images/<d>/<f>` with sha256.
   - `<prefix>.len` → `create_sparse(stage/<prefix>, len)`; keep open files in a `HashMap<String, File>`.
   - chunk entries → seek+write into the open file for their prefix (error if `.len` not seen).
   - `sandboxes/<src>/…` of a non-selected sandbox → drain. Selected → `stage/sandboxes/<final>/<file>` (map `egress-audit.jsonl` to `logs/egress-audit.jsonl`), sha256.
   - `workspaces/<src>/<rel>` → `unpack_entry(entry, ws_stage, rel)` (bundled + selected only).
   - `checksums.json` → parse, remember; must be last (anything after → error).
   - any other path → error.
7. Verify: every staged plain file sha256 == checksums; every staged disk: `content_digest(staged) == checksums[prefix]`; missing checksum for a staged item or missing trailer ⇒ `bail!("archive is truncated or corrupt (no checksums.json)")`.
8. Named volumes present on target: `content_digest(existing) == checksums[...]` ⇒ reuse (discard staged, warning "reusing identical volume 'x'"); else `bail!("named volume '{v}' already exists here with different contents; remove or rename it first (izba volume rm {v})")`. (Checked BEFORE any commit.)
9. Rewrite each staged `config.json`: `workspace = target` (canonicalized after commit — for not-bundled it's already canonicalizable), `usb.devices[].busid_pin = None` (warn + `redo` "re-plug USB device vid:pid for '<n>'" per grant), `disk_owner = Some(manifest.disk_owner)`; validate with `validate_volumes(&cfg.volumes, cfg.vnc)`. Ports: `redo`/`warnings` entry per rule whose host port a `port_in_use` seam reports busy (seam in hooks: `port_in_use: &dyn Fn(&PortRule) -> bool`, prod = try `TcpListener::bind((rule.bind, rule.host_port))` and drop; tests pass a closure). Lockdown: on Windows always add `redo` "run `izba lockdown <n>` to re-apply Windows account confinement" when the source manifest says `source_os == Windows` — simpler and honest: add it iff the SOURCE sandbox dir had `lockdown.json` → use `SandboxEntry.locked` (Task 6 field; Task 8 sets it from `sandbox_dir.join("lockdown.json").exists()`).
10. Commit in order (each step records what it created into an `undo: Vec<PathBuf>`; `fail_at` injects an error just before the matching step): images (rename `stage/images/<d>` → `paths.image_dir(d)`; skip if exists) → named volumes (rename into `paths.volume_image(v)`) → workspaces (rename ws stage → target; if target existed as empty dir, `remove_dir` it first and record) → sandbox dirs (`create_dir_700(sandbox_dir)`, move staged files in, `create_dir_700(logs_dir)`; `claim_run_dir` is done by `start` — check `create` also calls `claim_run_dir(paths, name)`; call it here too via `pub(crate)`). Tags: `set_tag` for manifest tags whose tag is not already resolvable here. On error: remove everything in `undo` in reverse (dirs recursively), remove stage, return the error.
11. Remove stage dir; return report.

- [ ] **Step 1: Failing tests** (reuse Task 8's fixture helpers by moving them into `bundle/testutil.rs` `#[cfg(test)] pub(crate) mod testutil;`; tests build an archive with `save` from a source data root, then `load_with` into a fresh target data root):

```rust
    #[test]
    fn round_trip_is_byte_identical_and_rewrites_host_fields() {
        let src = Src::new(); // source data root with sandbox "a": rw.img data at 3 offsets, anon volume, named volume "data", image, usb grant with busid_pin, policy.yaml
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws"); std::fs::create_dir_all(&ws).unwrap();
        let rep = load_with(&tgt.paths, &LoadOpts { archive: ar, select: vec![], rename: None, workspace: Some(ws.clone()), workspace_root: None }, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes[0].name, "a");
        for (s, t) in src.disk_pairs("a", &tgt.paths) {
            assert_eq!(content_digest(&s).unwrap(), content_digest(&t).unwrap());
            assert_eq!(std::fs::read(&s).unwrap(), std::fs::read(&t).unwrap());
        }
        let cfg: SandboxConfig = load_json(&tgt.paths.sandbox_dir("a").join("config.json")).unwrap().unwrap();
        assert_eq!(cfg.workspace, ws.canonicalize().unwrap());
        assert!(cfg.usb.devices.iter().all(|g| g.busid_pin.is_none()));
        assert!(cfg.disk_owner.is_some());
        assert!(tgt.paths.sandbox_dir("a").join("policy.yaml").is_file());
        assert!(!tgt.paths.root().read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".load-")));
        assert!(rep.redo.iter().any(|r| r.contains("USB")));
    }

    #[test]
    fn existing_sandbox_name_is_refused_and_as_renames() { /* load twice; second errs with "--as"; third with rename: Some("b") succeeds */ }

    #[test]
    fn existing_image_is_kept() {
        // target already has images/<d>/rootfs.erofs with DIFFERENT bytes: after load it is unchanged.
    }

    #[test]
    fn identical_named_volume_is_reused() { /* pre-place identical volumes/data.img in target; load ok; warning mentions reusing */ }

    #[test]
    fn different_named_volume_is_refused() { /* pre-place different bytes; load errs naming 'data'; target sandbox dir absent */ }

    #[test]
    fn rollback_at_each_commit_step_leaves_target_untouched() {
        for step in [CommitStep::Images, CommitStep::Volumes, CommitStep::Workspaces, CommitStep::Sandboxes] {
            let tgt = Tgt::new();
            let before = tgt.snapshot(); // sorted list of all paths under the data root + workspace root
            let mut hooks = tgt.hooks(); hooks.fail_at = Some(step);
            assert!(load_with(&tgt.paths, &opts_bundled(&tgt), &mut |_| {}, &hooks).is_err(), "{step:?}");
            assert_eq!(tgt.snapshot(), before, "{step:?} left debris");
        }
    }

    #[test]
    fn corrupt_chunk_fails_checksum_and_leaves_nothing() { /* flip a byte inside a chunk entry body of a re-written archive (decode, mutate entry, re-encode); load errs "checksum"; snapshot unchanged */ }

    #[test]
    fn truncated_archive_without_trailer_is_refused() { /* re-encode the archive dropping checksums.json; err mentions "truncated or corrupt" */ }

    #[test]
    fn future_format_is_refused_before_writing_anything() { /* manifest.format = 99 */ }

    #[test]
    fn not_enough_space_is_refused_up_front() { /* hooks.free_bytes = |_| Ok(1) ; err mentions "not enough free space" */ }

    #[test]
    fn bundled_workspace_refuses_non_empty_target() { /* target dir with a file; err mentions "not empty" */ }

    #[test]
    fn unbundled_workspace_must_exist() { /* workspace path missing; err mentions "--workspace" */ }

    #[test]
    fn rename_with_multiple_selected_is_refused() { /* two sandboxes, rename Some; err mentions "exactly one" */ }
```

Write every `/* … */` body out in full when implementing — the comment states exactly what to build and assert; the helpers `Src`, `Tgt`, `opts_bundled`, `snapshot`, and archive re-encoding (`rewrite_archive(path, |name, bytes| -> Option<Vec<u8>>)`: decode all entries, apply the closure (None = drop), re-encode in order) live in `bundle/testutil.rs`.

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** per the algorithm. `fsutil::free_bytes`: unix `nix::sys::statvfs::statvfs(dir)` → `blocks_available() * fragment_size()` (enable nix feature `fs` if needed); windows `GetDiskFreeSpaceExW` (`Win32_Storage_FileSystem` already enabled); walk up to the nearest existing ancestor first.
- [ ] **Step 4: Run** → PASS + six gates. **Step 5: Commit** `feat(core): load sandbox archives with verification and rollback`.

---

### Task 10: Daemon `Save`/`Load` requests (proto 7)

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs`, `crates/izba-core/src/daemon/server.rs`
- Modify: `app/src-tauri` only if it exhaustively matches `DaemonRequest`/`DaemonResponse` (grep; add arms returning an error "not supported in the app yet" if so).

**Interfaces:**
- Produces:

```rust
// proto.rs
DaemonRequest::Save { names: Vec<String>, #[serde(default)] all: bool, out: PathBuf, #[serde(default)] with_workspace: bool, #[serde(default)] stop: bool },
DaemonRequest::Load { archive: PathBuf, #[serde(default)] select: Vec<String>, #[serde(default)] rename: Option<String>, #[serde(default)] workspace: Option<PathBuf>, #[serde(default)] workspace_root: Option<PathBuf> },
DaemonResponse::Saved(crate::bundle::save::SaveReport),
DaemonResponse::Loaded(crate::bundle::load::LoadReport),
pub const DAEMON_PROTO_VERSION: u32 = 7; // doc: "v7 added Save/Load (sandbox archives)."
```

- [ ] **Step 1: Failing tests** (proto.rs tests + server.rs tests using the existing fake-daemon test harness — grep `fn test_daemon(` / the helper `handle_create_*` tests use):

```rust
    #[test]
    fn proto_version_is_7() { assert_eq!(DAEMON_PROTO_VERSION, 7); }

    #[test]
    fn save_and_load_requests_round_trip() {
        let r = DaemonRequest::Save { names: vec!["a".into()], all: false, out: "/x.izba".into(), with_workspace: true, stop: false };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""type":"save""#), "{j}");
        let _: DaemonRequest = serde_json::from_str(&j).unwrap();
        let l: DaemonRequest = serde_json::from_str(r#"{"type":"load","archive":"/x.izba"}"#).unwrap();
        assert!(matches!(l, DaemonRequest::Load { select, rename: None, .. } if select.is_empty()));
    }
```

server.rs:

```rust
    #[test]
    fn save_all_expands_to_every_sandbox_and_rejects_names_plus_all() { /* dispatch Save{all:true, names:["a"]} => Error mentioning "either names or --all" */ }

    #[test]
    fn save_then_load_registers_the_sandbox_stopped() {
        // Daemon A (data root 1): create fixture sandbox on disk, dispatch Save -> Saved.
        // Daemon B (data root 2): dispatch Load -> Loaded; B.registry.summaries() contains the name with Liveness::Stopped.
    }

    #[test]
    fn save_running_without_stop_is_refused() { /* fixture with live state.json; Error contains "stop it first" */ }
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** in server.rs:

```rust
        DaemonRequest::Save { names, all, out, with_workspace, stop } => handle_save(d, names, all, out, with_workspace, stop, progress),
        DaemonRequest::Load { archive, select, rename, workspace, workspace_root } => handle_load(d, archive, select, rename, workspace, workspace_root, progress),
```

```rust
fn handle_save(d: &Arc<Daemon>, names: Vec<String>, all: bool, out: PathBuf, with_workspace: bool, stop: bool, progress: &mut dyn FnMut(String)) -> anyhow::Result<DaemonResponse> {
    if all && !names.is_empty() { bail!("give either names or --all, not both"); }
    let names = if all { sandbox::list(&d.paths, d.connector())?.into_iter().map(|i| i.name).collect() } else { names };
    if names.is_empty() { bail!("nothing to save (no sandboxes)"); }
    if !out.is_absolute() { bail!("output path must be absolute (the CLI resolves it)"); }
    if stop {
        for n in &names {
            if crate::sandbox::liveness_of(&d.paths, n, d.connector())? != Liveness::Stopped {
                progress(format!("stopping '{n}'"));
                handle_stop(d, n.clone())?;
            }
        }
    }
    let report = crate::bundle::save::save(&d.paths, d.connector(), &crate::bundle::save::SaveOpts { names, out, with_workspace }, progress)?;
    Ok(DaemonResponse::Saved(report))
}

fn handle_load(d: &Arc<Daemon>, archive: PathBuf, select: Vec<String>, rename: Option<String>, workspace: Option<PathBuf>, workspace_root: Option<PathBuf>, progress: &mut dyn FnMut(String)) -> anyhow::Result<DaemonResponse> {
    let report = crate::bundle::load::load(&d.paths, &crate::bundle::load::LoadOpts { archive, select, rename, workspace, workspace_root }, progress)?;
    for s in &report.sandboxes {
        d.registry.set(&s.name, &s.image_ref, Liveness::Stopped);
    }
    regen_ssh_config(d);
    Ok(DaemonResponse::Loaded(report))
}
```

Update CLAUDE.md's "`DAEMON_PROTO_VERSION = 6` is this: v6 added `DaemonRequest::VncSet`." sentence to v7 in Task 13 (docs), not here.

- [ ] **Step 4: Run** six gates + app gate. **Step 5: Commit** `feat(daemon): Save/Load requests for sandbox archives (proto 7)`.

---

### Task 11: CLI `izba save` / `izba load`

**Files:**
- Create: `crates/izba-cli/src/commands/save.rs`, `crates/izba-cli/src/commands/load.rs`
- Modify: `crates/izba-cli/src/main.rs` (Cmd enum + dispatch, next to `Export`), `crates/izba-cli/src/commands/mod.rs` (`pub mod save; pub mod load;`)

**Interfaces:**
- Consumes: Task 10 requests.
- Produces CLI:

```
izba save [NAME]... [--all] -o, --output <FILE> [--with-workspace] [--stop]
izba load <ARCHIVE> [NAME]... [--as <NEW>] [--workspace <DIR>] [--workspace-root <DIR>]
```

- [ ] **Step 1: Failing tests** (clap parsing tests in main.rs's existing `#[cfg(test)]` — grep for `Cli::try_parse_from` usage and mirror it; plus pure formatting tests):

```rust
    #[test]
    fn save_parses_names_all_and_flags() {
        let c = Cli::try_parse_from(["izba", "save", "a", "b", "-o", "x.izba", "--with-workspace", "--stop"]).unwrap();
        assert!(matches!(c.cmd, Cmd::Save { ref names, all: false, with_workspace: true, stop: true, .. } if names == &["a", "b"]));
        assert!(Cli::try_parse_from(["izba", "save", "--all", "-o", "x.izba"]).is_ok());
        assert!(Cli::try_parse_from(["izba", "save", "a"]).is_err(), "-o is required");
        assert!(Cli::try_parse_from(["izba", "save", "a", "--all", "-o", "x"]).is_err(), "names conflict with --all");
    }

    #[test]
    fn load_parses_selection_and_placement() {
        let c = Cli::try_parse_from(["izba", "load", "x.izba", "a", "--as", "b", "--workspace", "/w"]).unwrap();
        assert!(matches!(c.cmd, Cmd::Load { .. }));
        assert!(Cli::try_parse_from(["izba", "load", "x.izba", "--workspace", "/w", "--workspace-root", "/r"]).is_err());
    }
```

In `save.rs`: `pub(crate) fn render_save_report(r: &SaveReport) -> String` test: contains the path, "logical", and the secrets note ("may contain secrets"). In `load.rs`: `render_load_report(r)` test: lists each sandbox with its workspace, a "To redo on this host:" block only when `redo` non-empty, and "izba start <name>" hint.

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** `save::run(paths, names, all, output, with_workspace, stop)`: resolve `output` against `std::env::current_dir()` to an absolute path (`std::path::absolute`), refuse if it exists without being a file we can overwrite? (simple: refuse if exists → "output file exists; remove it or choose another path"), connect with `DaemonClient::connect_spawning_izba(paths)` like other verbs (`grep -n "connect_spawning_izba\|fn client" crates/izba-cli/src/commands/mod.rs` and reuse the shared helper), send `Save`, print progress with `eprintln!`, match `Saved(r)` → print `render_save_report`, `Error{message}` → `bail!`. `load::run` analogous; `archive`, `workspace`, `workspace_root` made absolute client-side. `#[mutants::skip]` with a reason comment on the two `run` fns (daemon-boundary glue; exercised by e2e), like `export.rs`.

- [ ] **Step 4: Run** gates. **Step 5: Commit** `feat(cli): izba save / izba load`.

---

### Task 12: KVM e2e — real save/load round trips

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs`

- [ ] **Step 1: Add `save_load_round_trip_is_byte_identical`:**
  1. Data root A + workspace `wsA` with `hello.txt` and an executable `run.sh` (0755).
  2. `izba create --image alpine:3.20 --name mv --volume data:/data:64M --volume /scratch:32M <wsA>` (check `parse_volume_flag` syntax with `grep -n "fn parse_volume_flag" -A25 crates/izba-core/src/volume.rs` and adapt).
  3. `start mv`; `exec mv -- sh -c 'echo root > /root/r && echo d > /data/d && echo s > /scratch/s && sync'`.
  4. `save mv -o <tmp>/mv.izba --with-workspace --stop`; assert exit 0 and the sandbox is stopped (`izba ls` shows stopped).
  5. Record sha256 (via `izba_core::bundle::sparse::content_digest`) of A's `rw.img`, anonymous volume image(s), `volumes/data.img`.
  6. Data root B (fresh tempdir, its own daemon via `IZBA_DATA_DIR` env as the harness does): `load <tmp>/mv.izba --as mv2 --workspace <tmp>/wsB`.
  7. Assert B's disk digests equal A's; `<tmp>/wsB/hello.txt` content; `run.sh` mode 0755.
  8. `start mv2`; `exec mv2 -- cat /root/r /data/d /scratch/s /workspace/hello.txt` == expected; `rm --force mv2`.
- [ ] **Step 2: Add `save_load_docker_mode_round_trip`** (reuse `DIND_IMAGE` setup from `docker_publish_reaches_inner_container`): create `--docker`, start, `exec -- sh -c 'docker info >/dev/null && touch /var/lib/docker/marker && sync'` (wait for engine the way that test does), save `--stop`, load into data root B, start, assert `/var/lib/docker/marker` exists and `docker info` succeeds.
- [ ] **Step 3: Run** (unsandboxed): `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 save_load` → PASS.
- [ ] **Step 4: Commit** `test(e2e): save/load round trips preserve disks, volumes and workspace`.

---

### Task 13: Windows validation, docs, contracts, follow-ups

**Files:**
- Modify: `hack/spike/validate-izba-windows.ps1` — after the existing lifecycle block: create a sandbox, write a file, `izba save <n> -o $env:TEMP\v.izba --with-workspace --stop`, `izba rm -f <n>`, `izba load $env:TEMP\v.izba --workspace <new dir>`, start, `exec cat` the file, and check the loaded `rw.img` is sparse: `(Get-Item $rw).Attributes -band [IO.FileAttributes]::SparseFile` must be non-zero; fail the script otherwise. Follow the script's existing assert/log helpers.
- Modify: `CLAUDE.md` — (a) Cmdline chain: add `[izba.diskuidmap=<d-p-n>,… izba.diskgidmap=<d-p-n>,…]` with one sentence (moved non-docker sandbox; P = M_tgt ∘ M_src; `/upper` + volumes only; fail-closed); (b) proto sentence → "`DAEMON_PROTO_VERSION = 7` … v7 added `DaemonRequest::Save`/`Load`"; (c) crate map: `bundle/` one-liner; (d) disk-state invariant: note `config.json` `disk_owner` and that `load` is a first-write like `create`.
- Modify: `README.md` command surface: `izba save` / `izba load` with a 3-line "moving to a new laptop" example.
- Modify: `docs/security/` findings/notes file (the one listing identity-layer notes; `grep -rln "F-32" docs/security`) — add a short note: disk idmap P preserves container view; only moves ids already mapped; archive is plaintext and may contain workspace secrets; lockdown never travels.
- Modify: the spec — mark status "implemented", and update §4/§5.3/§7 to match what was built (chunk entries, `.len` markers, `checksums.json` trailer, `izba.diskuidmap`/`izba.diskgidmap`, no client-disconnect abort).
- Create follow-up GitHub issues (`gh issue create -R Lupus/izba`, then `gh project item-add 1 --owner Lupus --url <url>`): GUI Save/Load; streaming `-o -` / `izba load -`; archive encryption; incremental archives.

- [ ] Run the Windows validation via interop (unsandboxed): build per docs/testing.md Windows section, then `powershell.exe -NoProfile -File hack/spike/validate-izba-windows.ps1` (use its documented invocation) → PASS.
- [ ] Manual cross-OS check: save a non-docker sandbox on WSL (`-o /mnt/c/Users/<u>/Downloads/x.izba --with-workspace`), load it with the Windows `izba.exe` via `powershell.exe`, start, `exec stat -c %u` a file written as the image USER — must equal the pre-move value. Record the result in the PR body.
- [ ] Commit `docs: save/load contracts, README, security note; windows validation`.

---

## Delivery

After Task 13: push the branch, open a ready-for-review PR (never draft), run `bash hack/devbuild.sh` (unsandboxed) in parallel, iterate until all required checks + SonarCloud + Greptile 5/5 are clean (CLAUDE.md "CI iteration"), then report PR link + `dist/local/<ts>-<sha>/` install commands.
