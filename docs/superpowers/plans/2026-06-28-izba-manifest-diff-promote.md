# izba.yml Manifest + diff/promote/export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Kubernetes-style `izba.yml` project manifest plus `izba diff` / `izba promote` / `izba export` commands that reconcile it against izba's host-only managed truth, gated so an untrusted in-guest agent can propose config but only a human can enact it.

**Architecture:** A new pure, host-testable `izba_core::manifest` module owns the schema, a canonical normalized form, the structural 3-way diff, and the host-only review/base store. CLI commands (`diff`/`promote`/`export`, plus `create` honoring the manifest) wire that pure logic to the daemon (Inspect/ReloadPolicy/Port*/Volume*/Stop/Start) and to host-callable image resolution/build. The Tauri app gets thin command wrappers + a drift view.

**Tech Stack:** Rust (workspace crates `izba-core`, `izba-cli`), `serde`/`serde_yaml`/`serde_json`, `sha2`+`hex` (already deps), clap; Tauri 2 (`app/src-tauri`, outside the workspace).

## Global Constraints

- Conventional commits (`feat(core): …`, `feat(cli): …`); TDD (test first) throughout — reviews expect it.
- All six workspace gates must be green before any commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. Run `[ -f .cargo-env ] && source .cargo-env` first.
- **No `DAEMON_PROTO_VERSION` bump.** diff/promote/export are host-side over existing RPCs (`Inspect`, `ReloadPolicy`, `PortPublish`/`PortUnpublish`, `VolumeAttach`/`VolumeDetach`, `Start`/`Stop`) and host-callable core (`image::ensure_image`, `commands::build::build_image`).
- **Trust boundary:** `manifest.base.yaml` + `manifest.review` live host-only under the sandbox dir (`paths.sandbox_dir(name)`), never inside the workspace/overlay. The in-guest agent must never read or forge them.
- **No secrets in `izba.yml`** ever (no CA/host keys). `export` renders declarative config only.
- **Fail loud on security weakening** and never silently downgrade: `diff`/`promote` flag egress-loosening deltas; `--force` and `--reset-scratch=n` print loud warnings.
- App is OUT of the workspace: when `izba-core`/`izba-proto` public types change, also run the app gate: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Unit tests never bind unix/vsock listeners (sandbox EPERM); use file/tempdir fixtures only — all `manifest` logic is pure and needs no listener.

## Spec

Authoritative spec: `docs/superpowers/specs/2026-06-28-izba-manifest-diff-promote-design.md`. Read it before starting.

## Existing types this plan consumes (verbatim signatures)

- `izba_core::state::SandboxConfig { image_digest: String, image_ref: String, cpus: u32, mem_mb: u32, workspace: PathBuf, ports: Vec<PortRule>, volumes: Vec<VolumeSpec>, builder: bool }`; `state::{CONFIG_FILE, load_json, save_json}`; `state::PortRule { bind: Ipv4Addr, host_port: u16, guest_port: u16 }`.
- `izba_core::volume::VolumeSpec { name: Option<String>, guest_path: PathBuf, size_bytes: u64, eph_id: Option<u64> }`; `volume::parse_size(&str) -> Result<u64>`; `volume::{validate_volumes, assign_eph_ids, MAX_VOLUMES}`.
- `izba_core::daemon::egress::config::{EgressPolicyConfig { enforce: bool, allow: Vec<AllowEntry>, git: Vec<GitRule> }, AllowEntry::{Host(String), Scoped{host,ports:Option<Vec<u16>>,access}}, Access::{Read, ReadWrite}, GitRule { target: GitTarget, access: Access }, GitTarget::{Repo(String), Host(String)}, POLICY_FILE }`; methods `from_yaml`, `to_yaml`, `load(dir)`, `into_policy(name)`. `AllowEntry::{host(), ports(), access()}`.
- `izba_core::image::ensure_image(paths: &Paths, image_ref: &str) -> Result<String>` (digest; pulls if needed, host-side).
- `izba_core::paths::Paths::{sandbox_dir(name)->PathBuf, run_dir(name)->PathBuf}`.
- `izba_core::daemon::proto::{DaemonRequest, DaemonResponse, DaemonCreate, SandboxDetail { name, image_ref, image_digest, cpus, mem_mb, workspace, status, ports, volumes, .. }}`; `daemon::DaemonClient::{connect(paths)->Result<Self>, request(&req,&mut cb)->Result<DaemonResponse>}`.
- CLI: `crate::SandboxOpts { image, cpus, mem, rw_size_gb, name, publish, volumes, policy }`; `commands::{build_create_request, persist_policy, parse_publish, parse_volumes, name_for, ensure_workspace, expect_ok}`; `commands::build::{build_image, BuildOpts { dockerfile: PathBuf, tag: Option<String>, context: PathBuf, build_allow: Vec<String>, cpus: u32, mem: u32 }}`.
- Tauri: `app/src-tauri/src/views.rs::CreateOpts { name, image, cpus, mem_mb, workspace, rw_size_gb, ports: Vec<String>, volumes: Vec<String> }` + `into_daemon_create()`.

## File Structure

Create (izba-core, new module — register `pub mod manifest;` in `crates/izba-core/src/lib.rs`):
- `crates/izba-core/src/manifest/mod.rs` — module root; `pub use` re-exports; high-level pure orchestration (`Reconciliation`).
- `crates/izba-core/src/manifest/quantity.rs` — k8s quantity parse/format.
- `crates/izba-core/src/manifest/schema.rs` — `Manifest`/`SandboxSpec`/… structs, serde, `apiVersion`+`kind` dispatch, `load_str`/`to_yaml`.
- `crates/izba-core/src/manifest/normalize.rs` — `Normalized` canonical form + all conversions.
- `crates/izba-core/src/manifest/diff.rs` — `FieldDelta`, `FieldClass`, `DriftState`, `diff()`, `classify()`.
- `crates/izba-core/src/manifest/store.rs` — host-only `manifest.base.yaml` + `manifest.review` read/write + `review_token`.
- `crates/izba-core/src/manifest/apply.rs` — `ApplyPlan` + `apply_to_managed()` (writes config.json + policy.yaml; computes live deltas).

Create (izba-cli, new command modules — add `pub mod {diff,promote,export};` to `crates/izba-cli/src/commands/mod.rs`):
- `crates/izba-cli/src/commands/diff.rs`, `promote.rs`, `export.rs`.

Modify:
- `crates/izba-cli/src/main.rs` — add `Diff`/`Promote`/`Export` to `Cmd`; dispatch; teach `create`/`run` to honor `izba.yml`.
- `crates/izba-cli/src/commands/create.rs` — seed `manifest.base.yaml` + review token after create.
- `app/src-tauri/src/views.rs` + `commands.rs` + `lib.rs` — `DiffView`/wrappers + create-from-manifest.

---

## Task 1: Quantity parse/format (`quantity.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/quantity.rs`
- Create (stub): `crates/izba-core/src/manifest/mod.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod manifest;`)

**Interfaces:**
- Produces: `manifest::quantity::{parse_bytes(&str)->Result<u64>, parse_mib(&str)->Result<u32>, parse_gib(&str)->Result<u64>, format(u64)->String}`.

- [ ] **Step 1: Write the failing test** (in `quantity.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gi_and_mi_to_bytes() {
        assert_eq!(parse_bytes("4Gi").unwrap(), 4u64 << 30);
        assert_eq!(parse_bytes("512Mi").unwrap(), 512u64 << 20);
        assert_eq!(parse_bytes("1Ki").unwrap(), 1024);
    }

    #[test]
    fn parse_mib_rounds_to_whole_mib() {
        assert_eq!(parse_mib("4Gi").unwrap(), 4096);
        assert_eq!(parse_mib("512Mi").unwrap(), 512);
        assert!(parse_mib("500Ki").is_err(), "sub-MiB memory is rejected");
    }

    #[test]
    fn parse_gib_requires_whole_gib() {
        assert_eq!(parse_gib("8Gi").unwrap(), 8);
        assert!(parse_gib("512Mi").is_err(), "rootDisk must be whole GiB");
    }

    #[test]
    fn format_picks_largest_exact_unit() {
        assert_eq!(format(4u64 << 30), "4Gi");
        assert_eq!(format(512u64 << 20), "512Mi");
        assert_eq!(format(0), "0");
    }

    #[test]
    fn format_then_parse_round_trips() {
        for b in [1u64 << 20, 8u64 << 30, 3u64 << 30, 700u64 << 20] {
            assert_eq!(parse_bytes(&format(b)).unwrap(), b);
        }
    }

    #[test]
    fn rejects_garbage_and_bare_numbers() {
        assert!(parse_bytes("4").is_err());
        assert!(parse_bytes("4GB").is_err()); // decimal SI not supported; Gi/Mi only
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("-1Gi").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::quantity 2>&1 | tail -20`
Expected: FAIL — module/functions not found.

- [ ] **Step 3: Write minimal implementation** (top of `quantity.rs`)

```rust
//! Kubernetes binary quantity strings (`Ki`/`Mi`/`Gi`/`Ti`) <-> bytes.
//! Only the binary (power-of-two) suffixes are accepted — izba sizes are all
//! binary, and refusing decimal SI (`GB`) avoids the 1000-vs-1024 footgun.

use anyhow::{bail, Context, Result};

const UNITS: &[(&str, u64)] = &[
    ("Ki", 1 << 10),
    ("Mi", 1 << 20),
    ("Gi", 1 << 30),
    ("Ti", 1 << 40),
];

/// Parse a binary quantity string to bytes. `"4Gi" -> 4*2^30`.
pub fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    for (suffix, mult) in UNITS {
        if let Some(num) = s.strip_suffix(suffix) {
            let n: u64 = num
                .trim()
                .parse()
                .with_context(|| format!("invalid quantity {s:?}"))?;
            return n
                .checked_mul(*mult)
                .with_context(|| format!("quantity {s:?} overflows"));
        }
    }
    bail!("quantity {s:?} must end in Ki/Mi/Gi/Ti (e.g. 4Gi, 512Mi)")
}

/// Parse to whole MiB (memory). Errors if not a whole MiB multiple.
pub fn parse_mib(s: &str) -> Result<u32> {
    let bytes = parse_bytes(s)?;
    if bytes % (1 << 20) != 0 {
        bail!("memory {s:?} must be a whole number of MiB");
    }
    u32::try_from(bytes >> 20).with_context(|| format!("memory {s:?} too large"))
}

/// Parse to whole GiB (root disk / volume sizing where GiB units are required).
pub fn parse_gib(s: &str) -> Result<u64> {
    let bytes = parse_bytes(s)?;
    if bytes % (1 << 30) != 0 {
        bail!("size {s:?} must be a whole number of GiB (e.g. 8Gi)");
    }
    Ok(bytes >> 30)
}

/// Format bytes as the largest exact binary unit. `0 -> "0"`.
pub fn format(bytes: u64) -> String {
    if bytes == 0 {
        return "0".to_string();
    }
    for (suffix, mult) in UNITS.iter().rev() {
        if bytes % *mult == 0 {
            return format!("{}{}", bytes / *mult, suffix);
        }
    }
    format!("{bytes}")
}
```

And `mod.rs` stub:

```rust
//! Project manifest (`izba.yml`): schema, canonical form, structural diff, and
//! the host-only review/base store backing `izba diff`/`promote`/`export`.

pub mod quantity;
```

And add to `crates/izba-core/src/lib.rs` (alongside the other `pub mod` lines):

```rust
pub mod manifest;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::quantity 2>&1 | tail -20`
Expected: PASS (all quantity tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/quantity.rs crates/izba-core/src/manifest/mod.rs crates/izba-core/src/lib.rs
git commit -m "feat(core): k8s binary quantity parse/format for manifest sizes"
```

---

## Task 2: Manifest schema + apiVersion/kind dispatch (`schema.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/schema.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod schema;`)

**Interfaces:**
- Consumes: `EgressPolicyConfig` (egress block is structurally identical, so reuse it directly).
- Produces:
  - `schema::{API_VERSION: &str, KIND_SANDBOX: &str}`
  - `schema::Manifest { api_version: String, kind: String, metadata: Metadata, spec: SandboxSpec }`
  - `schema::Metadata { name: Option<String>, labels: BTreeMap<String,String> }`
  - `schema::SandboxSpec { image: Option<String>, build: Option<BuildSpec>, resources: Resources, root_disk: RootDisk, volumes: Vec<VolumeMount>, ports: Vec<PortMapping>, egress: Option<EgressPolicyConfig> }`
  - `schema::Resources { cpus: u32, memory: String }`, `RootDisk { size: String }`
  - `schema::VolumeMount { name: Option<String>, mount_path: PathBuf, size: String }`
  - `schema::PortMapping { guest: u16, host: u16, bind: Option<String> }`
  - `schema::BuildSpec { context: Option<String>, dockerfile: Option<String>, tag: Option<String>, allow: Vec<String>, resources: Option<Resources> }`
  - `Manifest::{load_str(&str)->Result<Manifest>, to_yaml(&self)->String}`

- [ ] **Step 1: Write the failing test** (in `schema.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata:
  name: myapp
  labels:
    project: acme
spec:
  image: ubuntu:24.04
  resources:
    cpus: 2
    memory: 4Gi
  rootDisk:
    size: 8Gi
  volumes:
    - name: data
      mountPath: /data
      size: 8Gi
  ports:
    - guest: 80
      host: 8080
      bind: 127.0.0.1
  egress:
    enforce: true
    allow:
      - github.com
"#;

    #[test]
    fn parses_full_sample() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        assert_eq!(m.api_version, API_VERSION);
        assert_eq!(m.kind, KIND_SANDBOX);
        assert_eq!(m.metadata.name.as_deref(), Some("myapp"));
        assert_eq!(m.metadata.labels.get("project").unwrap(), "acme");
        assert_eq!(m.spec.image.as_deref(), Some("ubuntu:24.04"));
        assert_eq!(m.spec.resources.cpus, 2);
        assert_eq!(m.spec.resources.memory, "4Gi");
        assert_eq!(m.spec.root_disk.size, "8Gi");
        assert_eq!(m.spec.volumes[0].mount_path.to_str().unwrap(), "/data");
        assert_eq!(m.spec.ports[0].guest, 80);
        assert_eq!(m.spec.ports[0].bind.as_deref(), Some("127.0.0.1"));
        let eg = m.spec.egress.as_ref().unwrap();
        assert!(eg.enforce);
        assert_eq!(eg.allow.len(), 1);
    }

    #[test]
    fn rejects_unknown_api_version() {
        let y = SAMPLE.replace("izba.dev/v1alpha1", "izba.dev/v2");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("apiVersion"), "got: {err}");
        assert!(err.contains("newer izba"), "must hint upgrade: {err}");
    }

    #[test]
    fn rejects_unknown_kind() {
        let y = SAMPLE.replace("kind: Sandbox", "kind: Project");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("kind"), "got: {err}");
    }

    #[test]
    fn rejects_both_image_and_build() {
        let y = SAMPLE.replace(
            "  image: ubuntu:24.04\n",
            "  image: ubuntu:24.04\n  build:\n    context: .\n",
        );
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("image") && err.contains("build"), "got: {err}");
    }

    #[test]
    fn rejects_neither_image_nor_build() {
        let y = SAMPLE.replace("  image: ubuntu:24.04\n", "");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("image") || err.contains("build"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        // deny_unknown_fields catches typos like `cpu:` for `cpus:`.
        let y = SAMPLE.replace("    cpus: 2\n", "    cpus: 2\n    cpu: 9\n");
        assert!(Manifest::load_str(&y).is_err());
    }

    #[test]
    fn build_block_parses() {
        let y = SAMPLE.replace(
            "  image: ubuntu:24.04\n",
            "  build:\n    context: .\n    dockerfile: Dockerfile\n    allow:\n      - get.example.com\n",
        );
        let m = Manifest::load_str(&y).unwrap();
        let b = m.spec.build.as_ref().unwrap();
        assert_eq!(b.context.as_deref(), Some("."));
        assert_eq!(b.dockerfile.as_deref(), Some("Dockerfile"));
        assert_eq!(b.allow, vec!["get.example.com".to_string()]);
        assert!(m.spec.image.is_none());
    }

    #[test]
    fn to_yaml_round_trips() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let back = Manifest::load_str(&m.to_yaml()).unwrap();
        assert_eq!(back.spec.resources.memory, "4Gi");
        assert_eq!(back.metadata.name, m.metadata.name);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::schema 2>&1 | tail -20`
Expected: FAIL — types not found.

- [ ] **Step 3: Write minimal implementation** (`schema.rs`)

```rust
//! The `izba.yml` document model. k8s-style: `apiVersion`/`kind`/`metadata`/
//! `spec`. The `egress` block reuses `EgressPolicyConfig` verbatim — it is
//! structurally identical to `policy.yaml`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::daemon::egress::config::EgressPolicyConfig;

pub const API_VERSION: &str = "izba.dev/v1alpha1";
pub const KIND_SANDBOX: &str = "Sandbox";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: Metadata,
    pub spec: SandboxSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildSpec>,
    pub resources: Resources,
    #[serde(rename = "rootDisk")]
    pub root_disk: RootDisk,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeMount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressPolicyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpus: u32,
    pub memory: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootDisk {
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "mountPath")]
    pub mount_path: PathBuf,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    pub guest: u16,
    pub host: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
}

impl Manifest {
    /// Parse + validate a manifest document. Dispatches on apiVersion/kind and
    /// enforces the `image` xor `build` rule.
    pub fn load_str(s: &str) -> Result<Manifest> {
        let m: Manifest = serde_yaml::from_str(s).context("parsing izba.yml")?;
        if m.api_version != API_VERSION {
            bail!(
                "unsupported apiVersion {:?} (this izba understands {:?}); \
                 a newer izba may be needed",
                m.api_version,
                API_VERSION
            );
        }
        if m.kind != KIND_SANDBOX {
            bail!(
                "unsupported kind {:?} (this izba understands {:?})",
                m.kind,
                KIND_SANDBOX
            );
        }
        match (&m.spec.image, &m.spec.build) {
            (Some(_), Some(_)) => bail!("spec.image and spec.build are mutually exclusive"),
            (None, None) => bail!("spec must set exactly one of image or build"),
            _ => {}
        }
        Ok(m)
    }

    /// Serialize to canonical YAML.
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("Manifest serializes")
    }
}
```

Add to `mod.rs`: `pub mod schema;`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::schema 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/schema.rs crates/izba-core/src/manifest/mod.rs
git commit -m "feat(core): k8s-style izba.yml schema with apiVersion/kind dispatch"
```

---

## Task 3: Canonical normalized form + conversions (`normalize.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/normalize.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod normalize;`)

**Interfaces:**
- Consumes: Task 1 quantity, Task 2 schema, existing `SandboxConfig`, `VolumeSpec`, `PortRule`, `EgressPolicyConfig`.
- Produces:
  - `normalize::ImageSource { Ref(String), Build(schema::BuildSpec) }`
  - `normalize::Normalized { name: String, image: ImageSource, cpus: u32, mem_mb: u32, rw_size_gb: u64, volumes: Vec<VolumeSpec>, ports: Vec<PortRule>, egress: EgressPolicyConfig }` (derives `PartialEq, Eq, Clone, Debug`)
  - `Normalized::from_manifest(&Manifest, default_name: &str) -> Result<Normalized>`
  - `Normalized::from_managed(&SandboxConfig, &EgressPolicyConfig) -> Normalized`
  - `Normalized::to_manifest(&self) -> Manifest`
  - Canonical ordering applied in every constructor (volumes by `mount_path`, ports by `(bind, host_port, guest_port)`, egress allow by host, git by target debug string).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{AllowEntry, EgressPolicyConfig};
    use crate::manifest::schema::Manifest;

    const SAMPLE: &str = r#"
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata: { name: myapp }
spec:
  image: ubuntu:24.04
  resources: { cpus: 2, memory: 4Gi }
  rootDisk: { size: 8Gi }
  volumes:
    - { name: data, mountPath: /data, size: 8Gi }
  ports:
    - { guest: 80, host: 8080, bind: 127.0.0.1 }
  egress:
    enforce: true
    allow: [github.com]
"#;

    #[test]
    fn from_manifest_maps_units_and_fields() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let n = Normalized::from_manifest(&m, "fallback").unwrap();
        assert_eq!(n.name, "myapp");
        assert_eq!(n.cpus, 2);
        assert_eq!(n.mem_mb, 4096);
        assert_eq!(n.rw_size_gb, 8);
        assert_eq!(n.image, ImageSource::Ref("ubuntu:24.04".into()));
        assert_eq!(n.volumes[0].name.as_deref(), Some("data"));
        assert_eq!(n.volumes[0].size_bytes, 8u64 << 30);
        assert_eq!(n.ports[0].host_port, 8080);
        assert_eq!(n.ports[0].bind.to_string(), "127.0.0.1");
        assert!(n.egress.enforce);
    }

    #[test]
    fn from_manifest_uses_default_name_when_absent() {
        let y = SAMPLE.replace("metadata: { name: myapp }", "metadata: {}");
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "fallback").unwrap();
        assert_eq!(n.name, "fallback");
    }

    #[test]
    fn port_default_bind_is_loopback() {
        let y = SAMPLE.replace(", bind: 127.0.0.1", "");
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "f").unwrap();
        assert_eq!(n.ports[0].bind.to_string(), "127.0.0.1");
    }

    #[test]
    fn round_trips_manifest_to_normalized_to_manifest() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let n = Normalized::from_manifest(&m, "f").unwrap();
        let m2 = n.to_manifest();
        let n2 = Normalized::from_manifest(&m2, "f").unwrap();
        assert_eq!(n, n2);
    }

    #[test]
    fn from_managed_renders_ref_image_and_egress() {
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 4,
            mem_mb: 2048,
            workspace: "/w".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
        };
        let eg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("github.com".into())],
            git: vec![],
        };
        let n = Normalized::from_managed("myapp", &cfg, &eg);
        assert_eq!(n.name, "myapp");
        assert_eq!(n.cpus, 4);
        assert_eq!(n.mem_mb, 2048);
        assert_eq!(n.image, ImageSource::Ref("ubuntu:24.04".into()));
        assert!(n.egress.enforce);
    }

    #[test]
    fn canonical_order_is_stable_regardless_of_input_order() {
        let y = SAMPLE.replace(
            "    - { name: data, mountPath: /data, size: 8Gi }\n",
            "    - { name: z, mountPath: /z, size: 1Gi }\n    - { name: a, mountPath: /a, size: 1Gi }\n",
        );
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "f").unwrap();
        assert_eq!(n.volumes[0].guest_path.to_str().unwrap(), "/a");
        assert_eq!(n.volumes[1].guest_path.to_str().unwrap(), "/z");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::normalize 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`normalize.rs`)

```rust
//! The canonical comparison form. Both an `izba.yml` and the managed truth
//! (config.json + policy.yaml) normalize to `Normalized`; the structural diff
//! then compares two `Normalized` values field-by-field, order-insensitively.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::daemon::egress::config::EgressPolicyConfig;
use crate::manifest::quantity;
use crate::manifest::schema::{
    self, BuildSpec, Manifest, Metadata, PortMapping, Resources, RootDisk, SandboxSpec, VolumeMount,
};
use crate::state::{PortRule, SandboxConfig};
use crate::volume::VolumeSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    Ref(String),
    Build(BuildSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub name: String,
    pub image: ImageSource,
    pub cpus: u32,
    pub mem_mb: u32,
    pub rw_size_gb: u64,
    pub volumes: Vec<VolumeSpec>,
    pub ports: Vec<PortRule>,
    pub egress: EgressPolicyConfig,
}

fn sort_canonical(volumes: &mut [VolumeSpec], ports: &mut [PortRule], egress: &mut EgressPolicyConfig) {
    volumes.sort_by(|a, b| a.guest_path.cmp(&b.guest_path));
    ports.sort_by_key(|p| (p.bind.to_string(), p.host_port, p.guest_port));
    egress.allow.sort_by(|a, b| a.host().cmp(b.host()));
    egress.git.sort_by_key(|g| format!("{:?}", g.target));
}

impl Normalized {
    pub fn from_manifest(m: &Manifest, default_name: &str) -> Result<Normalized> {
        let s = &m.spec;
        let image = match (&s.image, &s.build) {
            (Some(r), None) => ImageSource::Ref(r.clone()),
            (None, Some(b)) => ImageSource::Build(b.clone()),
            _ => anyhow::bail!("manifest must set exactly one of image or build"),
        };
        let mut volumes = Vec::with_capacity(s.volumes.len());
        for v in &s.volumes {
            volumes.push(VolumeSpec {
                name: v.name.clone(),
                guest_path: v.mount_path.clone(),
                size_bytes: quantity::parse_bytes(&v.size)
                    .with_context(|| format!("volume {:?} size", v.mount_path))?,
                eph_id: None,
            });
        }
        let mut ports = Vec::with_capacity(s.ports.len());
        for p in &s.ports {
            let bind: Ipv4Addr = match &p.bind {
                Some(b) => b.parse().with_context(|| format!("port bind {b:?}"))?,
                None => Ipv4Addr::LOCALHOST,
            };
            ports.push(PortRule { bind, host_port: p.host, guest_port: p.guest });
        }
        let mut egress = s.egress.clone().unwrap_or_default();
        let mut n = Normalized {
            name: m.metadata.name.clone().unwrap_or_else(|| default_name.to_string()),
            image,
            cpus: s.resources.cpus,
            mem_mb: quantity::parse_mib(&s.resources.memory).context("resources.memory")?,
            rw_size_gb: quantity::parse_gib(&s.root_disk.size).context("rootDisk.size")?,
            volumes,
            ports,
            egress: std::mem::take(&mut egress),
        };
        sort_canonical(&mut n.volumes, &mut n.ports, &mut n.egress);
        Ok(n)
    }

    pub fn from_managed(name: &str, cfg: &SandboxConfig, egress: &EgressPolicyConfig) -> Normalized {
        let mut volumes = cfg.volumes.clone();
        // eph_id is a backing-store detail, not config — drop it for comparison.
        for v in &mut volumes {
            v.eph_id = None;
        }
        let mut ports = cfg.ports.clone();
        let mut egress = egress.clone();
        let mut n = Normalized {
            name: name.to_string(),
            image: ImageSource::Ref(cfg.image_ref.clone()),
            cpus: cfg.cpus,
            mem_mb: cfg.mem_mb,
            rw_size_gb: 0, // see note in to_manifest: managed config does not record rw size post-create
            volumes,
            ports,
            egress: std::mem::take(&mut egress),
        };
        sort_canonical(&mut n.volumes, &mut n.ports, &mut n.egress);
        n
    }

    pub fn to_manifest(&self) -> Manifest {
        let (image, build) = match &self.image {
            ImageSource::Ref(r) => (Some(r.clone()), None),
            ImageSource::Build(b) => (None, Some(b.clone())),
        };
        Manifest {
            api_version: schema::API_VERSION.to_string(),
            kind: schema::KIND_SANDBOX.to_string(),
            metadata: Metadata { name: Some(self.name.clone()), labels: Default::default() },
            spec: SandboxSpec {
                image,
                build,
                resources: Resources {
                    cpus: self.cpus,
                    memory: quantity::format((self.mem_mb as u64) << 20),
                },
                root_disk: RootDisk { size: quantity::format(self.rw_size_gb << 30) },
                volumes: self
                    .volumes
                    .iter()
                    .map(|v| VolumeMount {
                        name: v.name.clone(),
                        mount_path: v.guest_path.clone(),
                        size: quantity::format(v.size_bytes),
                    })
                    .collect(),
                ports: self
                    .ports
                    .iter()
                    .map(|p| PortMapping {
                        guest: p.guest_port,
                        host: p.host_port,
                        bind: Some(p.bind.to_string()),
                    })
                    .collect(),
                egress: Some(self.egress.clone()),
            },
        }
    }
}
```

> **Note on `rw_size_gb`:** `SandboxConfig` does not persist the rw scratch size after create (it sizes `rw.img` at create time only). To avoid spurious "rootDisk changed" drift on every diff, **Task 4's `diff()` ignores `rw_size_gb`** (documented there). `from_managed` sets it to `0` and `from_manifest` keeps the real value; the diff skips the field. (A follow-up may persist rw size in `SandboxConfig`; out of scope.)

Add to `mod.rs`: `pub mod normalize;`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::normalize 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/normalize.rs crates/izba-core/src/manifest/mod.rs
git commit -m "feat(core): canonical Normalized manifest form + conversions"
```

---

## Task 4: Structural diff + field class + 3-way state + weakens-egress (`diff.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/diff.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod diff;`)

**Interfaces:**
- Consumes: Task 3 `Normalized`, `ImageSource`; `EgressPolicyConfig`/`AllowEntry`/`Access`.
- Produces:
  - `diff::FieldClass { Live, Restart, Image }`
  - `diff::FieldDelta { field: String, from: String, to: String, class: FieldClass, weakens_egress: bool }`
  - `diff::DriftState { InSync, RepoAhead, ManagedAhead, Diverged }`
  - `diff::diff(from: &Normalized, to: &Normalized) -> Vec<FieldDelta>` (changes turning `from` into `to`; ignores `name` and `rw_size_gb`)
  - `diff::classify(base: &Normalized, repo: &Normalized, managed: &Normalized) -> DriftState`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{Access, AllowEntry, EgressPolicyConfig};
    use crate::manifest::normalize::{ImageSource, Normalized};
    use crate::state::PortRule;

    fn base() -> Normalized {
        Normalized {
            name: "x".into(),
            image: ImageSource::Ref("ubuntu:24.04".into()),
            cpus: 2,
            mem_mb: 4096,
            rw_size_gb: 8,
            volumes: vec![],
            ports: vec![],
            egress: EgressPolicyConfig { enforce: true, allow: vec![], git: vec![] },
        }
    }

    #[test]
    fn no_changes_is_empty() {
        assert!(diff(&base(), &base()).is_empty());
    }

    #[test]
    fn cpus_change_is_restart_class() {
        let mut to = base();
        to.cpus = 4;
        let d = diff(&base(), &to);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "cpus");
        assert_eq!(d[0].class, FieldClass::Restart);
        assert!(!d[0].weakens_egress);
    }

    #[test]
    fn image_change_is_image_class() {
        let mut to = base();
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "image");
        assert_eq!(d[0].class, FieldClass::Image);
    }

    #[test]
    fn port_change_is_live_class() {
        let mut to = base();
        to.ports = vec![PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 8080, guest_port: 80 }];
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "ports");
        assert_eq!(d[0].class, FieldClass::Live);
    }

    #[test]
    fn adding_allow_host_weakens_egress() {
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Host("evil.com".into())];
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "egress");
        assert_eq!(d[0].class, FieldClass::Live);
        assert!(d[0].weakens_egress, "adding an allowed host loosens the firewall");
    }

    #[test]
    fn disabling_enforce_weakens_egress() {
        let mut to = base();
        to.egress.enforce = false;
        assert!(diff(&base(), &to)[0].weakens_egress);
    }

    #[test]
    fn read_to_readwrite_weakens_but_readwrite_to_read_does_not() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Scoped { host: "h".into(), ports: None, access: Access::Read }];
        let mut to = from.clone();
        if let AllowEntry::Scoped { access, .. } = &mut to.egress.allow[0] {
            *access = Access::ReadWrite;
        }
        assert!(diff(&from, &to)[0].weakens_egress, "read -> read-write loosens");
        assert!(!diff(&to, &from)[0].weakens_egress, "read-write -> read tightens");
    }

    #[test]
    fn removing_an_allow_host_does_not_weaken() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Host("ok.com".into())];
        let to = base();
        let d = diff(&from, &to);
        assert!(!d[0].weakens_egress, "removing a host tightens");
    }

    #[test]
    fn classify_repo_ahead_managed_ahead_diverged_insync() {
        let b = base();
        let mut repo = base();
        repo.cpus = 4;
        let mut managed = base();
        managed.mem_mb = 8192;
        assert_eq!(classify(&b, &b, &b), DriftState::InSync);
        assert_eq!(classify(&b, &repo, &b), DriftState::RepoAhead);
        assert_eq!(classify(&b, &b, &managed), DriftState::ManagedAhead);
        assert_eq!(classify(&b, &repo, &managed), DriftState::Diverged);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::diff 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`diff.rs`)

```rust
//! Structural, order-insensitive diff between two `Normalized` configs, with a
//! field-class (Live/Restart/Image) and a `weakens_egress` flag per change, plus
//! the base/repo/managed 3-way state classifier.

use std::collections::BTreeMap;

use crate::daemon::egress::config::{Access, AllowEntry, EgressPolicyConfig};
use crate::manifest::normalize::{ImageSource, Normalized};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    Live,
    Restart,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDelta {
    pub field: String,
    pub from: String,
    pub to: String,
    pub class: FieldClass,
    pub weakens_egress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    InSync,
    RepoAhead,
    ManagedAhead,
    Diverged,
}

fn image_str(i: &ImageSource) -> String {
    match i {
        ImageSource::Ref(r) => r.clone(),
        ImageSource::Build(b) => format!("build({:?})", b.dockerfile.as_deref().unwrap_or("Dockerfile")),
    }
}

/// Build a host -> (sorted ports, access) view of an allow-list for comparison.
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<String, (Vec<u16>, Access)> {
    eg.allow
        .iter()
        .map(|e| {
            let mut ports = e.ports();
            ports.sort_unstable();
            (e.host().to_string(), (ports, e.access()))
        })
        .collect()
}

/// True if turning `from` egress into `to` egress LOOSENS the firewall:
/// disabling enforce, adding a host, adding ports to a host, widening access
/// (read -> read-write), or adding/loosening a git rule.
fn egress_weakens(from: &EgressPolicyConfig, to: &EgressPolicyConfig) -> bool {
    if from.enforce && !to.enforce {
        return true;
    }
    let (fi, ti) = (allow_index(from), allow_index(to));
    for (host, (to_ports, to_access)) in &ti {
        match fi.get(host) {
            None => return true, // new host allowed
            Some((from_ports, from_access)) => {
                if to_ports.iter().any(|p| !from_ports.contains(p)) {
                    return true; // new port on an existing host
                }
                if *from_access == Access::Read && *to_access == Access::ReadWrite {
                    return true; // widened verb
                }
            }
        }
    }
    // git: a new rule, or any rule whose access widened read -> read-write.
    let fg: BTreeMap<String, Access> =
        from.git.iter().map(|g| (format!("{:?}", g.target), g.access)).collect();
    for g in &to.git {
        let key = format!("{:?}", g.target);
        match fg.get(&key) {
            None => return true,
            Some(a) if *a == Access::Read && g.access == Access::ReadWrite => return true,
            _ => {}
        }
    }
    false
}

/// Changes that turn `from` into `to`. Ignores `name` (identity) and
/// `rw_size_gb` (not persisted in managed config; see normalize.rs note).
pub fn diff(from: &Normalized, to: &Normalized) -> Vec<FieldDelta> {
    let mut out = Vec::new();
    if from.image != to.image {
        out.push(FieldDelta {
            field: "image".into(),
            from: image_str(&from.image),
            to: image_str(&to.image),
            class: FieldClass::Image,
            weakens_egress: false,
        });
    }
    if from.cpus != to.cpus {
        out.push(FieldDelta {
            field: "cpus".into(),
            from: from.cpus.to_string(),
            to: to.cpus.to_string(),
            class: FieldClass::Restart,
            weakens_egress: false,
        });
    }
    if from.mem_mb != to.mem_mb {
        out.push(FieldDelta {
            field: "memory".into(),
            from: format!("{} MiB", from.mem_mb),
            to: format!("{} MiB", to.mem_mb),
            class: FieldClass::Restart,
            weakens_egress: false,
        });
    }
    if from.ports != to.ports {
        out.push(FieldDelta {
            field: "ports".into(),
            from: format!("{:?}", from.ports),
            to: format!("{:?}", to.ports),
            class: FieldClass::Live,
            weakens_egress: false,
        });
    }
    if from.volumes != to.volumes {
        out.push(FieldDelta {
            field: "volumes".into(),
            from: format!("{:?}", from.volumes),
            to: format!("{:?}", to.volumes),
            class: FieldClass::Live,
            weakens_egress: false,
        });
    }
    if from.egress != to.egress {
        out.push(FieldDelta {
            field: "egress".into(),
            from: from.egress.to_yaml(),
            to: to.egress.to_yaml(),
            class: FieldClass::Live,
            weakens_egress: egress_weakens(&from.egress, &to.egress),
        });
    }
    out
}

/// 3-way state. `repo`/`managed` are each compared to `base` via `diff`.
pub fn classify(base: &Normalized, repo: &Normalized, managed: &Normalized) -> DriftState {
    let repo_changed = !diff(base, repo).is_empty();
    let managed_changed = !diff(base, managed).is_empty();
    match (repo_changed, managed_changed) {
        (false, false) => DriftState::InSync,
        (true, false) => DriftState::RepoAhead,
        (false, true) => DriftState::ManagedAhead,
        (true, true) => DriftState::Diverged,
    }
}
```

Add to `mod.rs`: `pub mod diff;`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::diff 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/diff.rs crates/izba-core/src/manifest/mod.rs
git commit -m "feat(core): structural manifest diff with field-class + weakens-egress + 3-way state"
```

---

## Task 5: Host-only base + review-token store (`store.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/store.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod store;`)

**Interfaces:**
- Consumes: Task 2 `Manifest`; `sha2`, `hex`.
- Produces:
  - `store::{MANIFEST_BASE_FILE: &str = "manifest.base.yaml", MANIFEST_REVIEW_FILE: &str = "manifest.review"}`
  - `store::review_token(manifest_yaml: &str, dockerfile: Option<&str>) -> String` (sha256 hex over manifest bytes + an `0x1f` separator + dockerfile bytes)
  - `store::{write_base(dir, &Manifest)->Result<()>, read_base(dir)->Result<Option<Manifest>>}`
  - `store::{write_review(dir, token:&str)->Result<()>, read_review(dir)->Result<Option<String>>, clear_review(dir)->Result<()>}`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::Manifest;

    const M: &str = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n  resources: { cpus: 1, memory: 1Gi }\n  rootDisk: { size: 1Gi }\n";

    #[test]
    fn token_is_stable_and_input_sensitive() {
        let a = review_token("manifest-bytes", None);
        assert_eq!(a, review_token("manifest-bytes", None), "stable");
        assert_ne!(a, review_token("manifest-bytes2", None), "manifest change moves it");
        assert_ne!(a, review_token("manifest-bytes", Some("FROM x")), "dockerfile change moves it");
        assert_ne!(
            review_token("ab", Some("c")),
            review_token("a", Some("bc")),
            "separator prevents boundary collisions"
        );
    }

    #[test]
    fn base_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_base(dir.path()).unwrap().is_none());
        let m = Manifest::load_str(M).unwrap();
        write_base(dir.path(), &m).unwrap();
        let back = read_base(dir.path()).unwrap().unwrap();
        assert_eq!(back.spec.resources.cpus, 1);
    }

    #[test]
    fn review_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_review(dir.path()).unwrap().is_none());
        write_review(dir.path(), "deadbeef").unwrap();
        assert_eq!(read_review(dir.path()).unwrap().as_deref(), Some("deadbeef"));
        clear_review(dir.path()).unwrap();
        assert!(read_review(dir.path()).unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::store 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`store.rs`)

```rust
//! Host-only manifest reconciliation state, stored under the sandbox dir
//! (NEVER inside the workspace/overlay): the last-reconciled base manifest and
//! the review token gating `promote`. The in-guest agent cannot read or forge
//! these.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::manifest::schema::Manifest;

pub const MANIFEST_BASE_FILE: &str = "manifest.base.yaml";
pub const MANIFEST_REVIEW_FILE: &str = "manifest.review";

/// A review token binds the human's review to the exact bytes reviewed: the
/// manifest plus any referenced Dockerfile (also agent-writable). A 0x1f unit
/// separator keeps `("ab", "c")` distinct from `("a", "bc")`.
pub fn review_token(manifest_yaml: &str, dockerfile: Option<&str>) -> String {
    let mut h = Sha256::new();
    h.update(manifest_yaml.as_bytes());
    h.update([0x1f]);
    if let Some(df) = dockerfile {
        h.update(df.as_bytes());
    }
    hex::encode(h.finalize())
}

fn base_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_BASE_FILE)
}
fn review_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_REVIEW_FILE)
}

pub fn write_base(dir: &Path, m: &Manifest) -> Result<()> {
    let p = base_path(dir);
    std::fs::write(&p, m.to_yaml()).with_context(|| format!("writing {}", p.display()))
}

pub fn read_base(dir: &Path) -> Result<Option<Manifest>> {
    match std::fs::read_to_string(base_path(dir)) {
        Ok(s) => Ok(Some(Manifest::load_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading manifest.base.yaml"),
    }
}

pub fn write_review(dir: &Path, token: &str) -> Result<()> {
    let p = review_path(dir);
    std::fs::write(&p, token).with_context(|| format!("writing {}", p.display()))
}

pub fn read_review(dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(review_path(dir)) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading manifest.review"),
    }
}

pub fn clear_review(dir: &Path) -> Result<()> {
    match std::fs::remove_file(review_path(dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing manifest.review"),
    }
}
```

Add to `mod.rs`: `pub mod store;`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::store 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/store.rs crates/izba-core/src/manifest/mod.rs
git commit -m "feat(core): host-only manifest base + review-token store"
```

---

## Task 6: Apply-to-managed plan (`apply.rs`)

**Files:**
- Create: `crates/izba-core/src/manifest/apply.rs`
- Modify: `crates/izba-core/src/manifest/mod.rs` (add `pub mod apply;` + re-exports)

**Interfaces:**
- Consumes: Task 3 `Normalized`/`ImageSource`; `SandboxConfig`, `EgressPolicyConfig`, `PortRule`, `VolumeSpec`, `paths`, `state::{load_json,save_json,CONFIG_FILE}`.
- Produces:
  - `apply::ApplyPlan { policy_changed: bool, ports_added: Vec<PortRule>, ports_removed: Vec<PortRule>, volumes_added: Vec<VolumeSpec>, volumes_removed: Vec<PathBuf>, restart_fields: Vec<String>, image_changed: bool }`
  - `apply::plan(current: &Normalized, target: &Normalized) -> ApplyPlan` (pure delta computation; `image_digest` resolution is the CLI's job)
  - `apply::write_managed(paths, name, target: &Normalized, image_digest: &str) -> Result<()>` (writes config.json with target cpus/mem/image/ports/volumes + writes policy.yaml from target.egress)

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{AllowEntry, EgressPolicyConfig};
    use crate::manifest::normalize::{ImageSource, Normalized};
    use crate::state::{load_json, PortRule, SandboxConfig, CONFIG_FILE};
    use crate::volume::VolumeSpec;

    fn n(cpus: u32) -> Normalized {
        Normalized {
            name: "x".into(),
            image: ImageSource::Ref("ubuntu:24.04".into()),
            cpus,
            mem_mb: 4096,
            rw_size_gb: 8,
            volumes: vec![],
            ports: vec![],
            egress: EgressPolicyConfig::default(),
        }
    }

    #[test]
    fn plan_marks_restart_for_cpu_change() {
        let p = plan(&n(2), &n(4));
        assert_eq!(p.restart_fields, vec!["cpus".to_string()]);
        assert!(!p.policy_changed);
        assert!(!p.image_changed);
    }

    #[test]
    fn plan_computes_port_and_volume_deltas() {
        let mut from = n(2);
        from.ports = vec![PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 1, guest_port: 1 }];
        let mut to = n(2);
        to.ports = vec![PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 2, guest_port: 2 }];
        to.volumes = vec![VolumeSpec { name: Some("d".into()), guest_path: "/d".into(), size_bytes: 1 << 30, eph_id: None }];
        let p = plan(&from, &to);
        assert_eq!(p.ports_added.len(), 1);
        assert_eq!(p.ports_removed.len(), 1);
        assert_eq!(p.volumes_added.len(), 1);
        assert!(p.volumes_removed.is_empty());
    }

    #[test]
    fn plan_marks_policy_changed_and_image_changed() {
        let mut to = n(2);
        to.egress.allow = vec![AllowEntry::Host("h".into())];
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let p = plan(&n(2), &to);
        assert!(p.policy_changed);
        assert!(p.image_changed);
    }

    #[test]
    fn write_managed_persists_config_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path());
        std::fs::create_dir_all(paths.sandbox_dir("x")).unwrap();
        // Seed an existing config (write_managed preserves workspace + builder).
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
        };
        crate::state::save_json(&paths.sandbox_dir("x").join(CONFIG_FILE), &seed).unwrap();

        let mut target = n(8);
        target.egress.allow = vec![AllowEntry::Host("github.com".into())];
        write_managed(&paths, "x", &target, "sha256:new").unwrap();

        let cfg: SandboxConfig =
            load_json(&paths.sandbox_dir("x").join(CONFIG_FILE)).unwrap().unwrap();
        assert_eq!(cfg.cpus, 8);
        assert_eq!(cfg.image_digest, "sha256:new");
        assert_eq!(cfg.workspace.to_str().unwrap(), "/ws", "workspace preserved");
        let eg = EgressPolicyConfig::load(&paths.sandbox_dir("x")).unwrap().unwrap();
        assert!(eg.allow.iter().any(|e| e.host() == "github.com"));
    }
}
```

> If `Paths::with_root` does not exist, use whatever test constructor the rest of izba-core uses for a temp `Paths` (grep `Paths::` in existing tests, e.g. `sandbox.rs` tests, and copy that pattern).

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest::apply 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`apply.rs`)

```rust
//! Turn a target `Normalized` into (a) a delta plan the CLI enacts live via the
//! daemon and (b) the durable managed files (config.json + policy.yaml).

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::manifest::diff;
use crate::manifest::normalize::Normalized;
use crate::paths::Paths;
use crate::state::{load_json, save_json, PortRule, SandboxConfig, CONFIG_FILE};
use crate::volume::VolumeSpec;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyPlan {
    pub policy_changed: bool,
    pub ports_added: Vec<PortRule>,
    pub ports_removed: Vec<PortRule>,
    pub volumes_added: Vec<VolumeSpec>,
    pub volumes_removed: Vec<PathBuf>,
    pub restart_fields: Vec<String>,
    pub image_changed: bool,
}

/// Compute the live/restart deltas turning `current` into `target`.
pub fn plan(current: &Normalized, target: &Normalized) -> ApplyPlan {
    let mut p = ApplyPlan {
        policy_changed: current.egress != target.egress,
        image_changed: current.image != target.image,
        ..Default::default()
    };
    p.ports_added = target.ports.iter().filter(|r| !current.ports.contains(r)).cloned().collect();
    p.ports_removed = current.ports.iter().filter(|r| !target.ports.contains(r)).cloned().collect();
    p.volumes_added =
        target.volumes.iter().filter(|v| !current.volumes.contains(v)).cloned().collect();
    p.volumes_removed = current
        .volumes
        .iter()
        .filter(|v| !target.volumes.contains(v))
        .map(|v| v.guest_path.clone())
        .collect();
    for d in diff::diff(current, target) {
        if d.class == diff::FieldClass::Restart || d.class == diff::FieldClass::Image {
            p.restart_fields.push(d.field);
        }
    }
    p
}

/// Write the managed truth: config.json (cpus/mem/image/ports/volumes from
/// `target`, with `image_digest` resolved by the caller) and policy.yaml from
/// `target.egress`. Preserves `workspace` and `builder` from the existing config.
pub fn write_managed(paths: &Paths, name: &str, target: &Normalized, image_digest: &str) -> Result<()> {
    let dir = paths.sandbox_dir(name);
    let mut cfg: SandboxConfig = load_json(&dir.join(CONFIG_FILE))?
        .with_context(|| format!("no config.json for sandbox {name:?}"))?;
    cfg.cpus = target.cpus;
    cfg.mem_mb = target.mem_mb;
    cfg.image_digest = image_digest.to_string();
    if let crate::manifest::normalize::ImageSource::Ref(r) = &target.image {
        cfg.image_ref = r.clone();
    }
    cfg.ports = target.ports.clone();
    let mut volumes = target.volumes.clone();
    crate::volume::assign_eph_ids(&mut volumes);
    cfg.volumes = volumes;
    save_json(&dir.join(CONFIG_FILE), &cfg)?;
    std::fs::write(crate::daemon::egress::config::EgressPolicyConfig::path_in(&dir), target.egress.to_yaml())
        .with_context(|| format!("writing policy.yaml for {name:?}"))?;
    Ok(())
}
```

Add to `mod.rs`: `pub mod apply;` and convenience re-exports:

```rust
pub use diff::{classify, diff as diff_normalized, DriftState, FieldClass, FieldDelta};
pub use normalize::{ImageSource, Normalized};
pub use schema::Manifest;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core manifest 2>&1 | tail -25`
Expected: PASS (all `manifest::*` tests).

- [ ] **Step 5: Run the core gates and commit**

```bash
source .cargo-env 2>/dev/null
cargo clippy -p izba-core --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt --check 2>&1 | tail -5
git add crates/izba-core/src/manifest/apply.rs crates/izba-core/src/manifest/mod.rs
git commit -m "feat(core): manifest apply plan + write-managed (config.json + policy.yaml)"
```

---

## Task 7: `izba diff` command

**Files:**
- Create: `crates/izba-cli/src/commands/diff.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (add `pub mod diff;` + a shared `load_repo_manifest` helper)
- Modify: `crates/izba-cli/src/main.rs` (add `Cmd::Diff` + dispatch)
- Test: `crates/izba-cli/src/commands/diff.rs` (`#[cfg(test)]` for the pure render/load helpers)

**Interfaces:**
- Consumes: `manifest::{Manifest, Normalized, store, diff, classify, DriftState}`; `DaemonClient`; `DaemonRequest::Inspect`; `SandboxDetail`; `EgressPolicyConfig::load`.
- Produces:
  - `commands::load_repo_manifest(dir: &Path) -> Result<(Manifest, String, Option<String>)>` — returns the parsed manifest, its raw YAML bytes, and the referenced Dockerfile contents (for `build:` specs; `None` for `image:`). Located in `mod.rs` so promote/export reuse it.
  - `commands::managed_normalized(paths, name) -> Result<Normalized>` — reads config.json + policy.yaml from disk into `Normalized` (used by diff/promote/export). Reads disk directly (no daemon) so it works on a stopped sandbox.
  - `commands::diff::run(paths, dir: &Path, name_override: Option<&str>) -> Result<i32>`

- [ ] **Step 1: Write the failing test** (pure render in `diff.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::manifest::diff::{FieldClass, FieldDelta};
    use izba_core::manifest::DriftState;

    #[test]
    fn render_groups_by_class_and_flags_weakening() {
        let deltas = vec![
            FieldDelta { field: "cpus".into(), from: "2".into(), to: "4".into(), class: FieldClass::Restart, weakens_egress: false },
            FieldDelta { field: "egress".into(), from: "a".into(), to: "b".into(), class: FieldClass::Live, weakens_egress: true },
        ];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(s.contains("repo ahead") || s.contains("RepoAhead"));
        assert!(s.contains("cpus"));
        assert!(s.contains("restart"), "restart class labelled");
        assert!(s.contains("⚠"), "weakening flagged: {s}");
    }

    #[test]
    fn render_in_sync_is_terse() {
        let s = render_deltas(DriftState::InSync, &[]);
        assert!(s.to_lowercase().contains("in sync"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::diff 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

In `commands/mod.rs`, add the shared helpers:

```rust
use izba_core::manifest::{self, Manifest, Normalized};

/// Load `izba.yml` from a workspace dir, returning (manifest, raw_yaml,
/// dockerfile_contents). `dockerfile` is `Some` only for a `build:` spec.
pub(crate) fn load_repo_manifest(dir: &Path) -> anyhow::Result<(Manifest, String, Option<String>)> {
    let path = dir.join("izba.yml");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let m = Manifest::load_str(&raw)?;
    let dockerfile = match &m.spec.build {
        Some(b) => {
            let ctx = dir.join(b.context.as_deref().unwrap_or("."));
            let df = ctx.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
            Some(std::fs::read_to_string(&df).with_context(|| format!("reading {}", df.display()))?)
        }
        None => None,
    };
    Ok((m, raw, dockerfile))
}

/// Read the managed truth (config.json + policy.yaml) for `name` into a
/// `Normalized`, directly from disk (works on a stopped sandbox).
pub(crate) fn managed_normalized(
    paths: &izba_core::paths::Paths,
    name: &str,
) -> anyhow::Result<Normalized> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    use izba_core::state::{load_json, SandboxConfig, CONFIG_FILE};
    let dir = paths.sandbox_dir(name);
    let cfg: SandboxConfig = load_json(&dir.join(CONFIG_FILE))?
        .with_context(|| format!("no such sandbox: {name}"))?;
    let egress = EgressPolicyConfig::load(&dir)?.unwrap_or_default();
    Ok(Normalized::from_managed(name, &cfg, &egress))
}
```

`commands/diff.rs`:

```rust
//! `izba diff` — structural drift between `izba.yml` and the managed truth,
//! recording a review token so `promote` knows what the human saw.

use std::path::Path;

use anyhow::Result;
use izba_core::manifest::diff::{FieldClass, FieldDelta};
use izba_core::manifest::{self, store, DriftState, Normalized};
use izba_core::paths::Paths;

pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    let (m, raw, dockerfile) = super::load_repo_manifest(dir)?;
    let default_name = super::workspace_default_name(dir)?; // see note below
    let repo = Normalized::from_manifest(&m, &default_name)?;
    let name = name_override.unwrap_or(&repo.name).to_string();

    let managed = super::managed_normalized(paths, &name)?;
    let base = store::read_base(&paths.sandbox_dir(&name))?
        .map(|bm| Normalized::from_manifest(&bm, &default_name))
        .transpose()?
        .unwrap_or_else(|| managed.clone());

    let state = manifest::classify(&base, &repo, &managed);
    // The deltas the human is asked to review are repo-relative-to-managed.
    let deltas = manifest::diff_normalized(&managed, &repo);
    println!("{}", render_deltas(state, &deltas));

    // Record the review token over exactly what we showed.
    store::write_review(
        &paths.sandbox_dir(&name),
        &store::review_token(&raw, dockerfile.as_deref()),
    )?;
    Ok(0)
}

pub(crate) fn render_deltas(state: DriftState, deltas: &[FieldDelta]) -> String {
    let mut s = String::new();
    let label = match state {
        DriftState::InSync => "in sync",
        DriftState::RepoAhead => "repo ahead (promotable)",
        DriftState::ManagedAhead => "managed ahead (export to capture)",
        DriftState::Diverged => "diverged (repo and managed both changed)",
    };
    s.push_str(&format!("state: {label}\n"));
    if deltas.is_empty() {
        s.push_str("no field changes between manifest and managed truth.\n");
        return s;
    }
    for d in deltas {
        let class = match d.class {
            FieldClass::Live => "live",
            FieldClass::Restart => "restart",
            FieldClass::Image => "image (restart)",
        };
        let warn = if d.weakens_egress { "  ⚠ weakens egress" } else { "" };
        s.push_str(&format!("  {}: {} -> {}  [{}]{}\n", d.field, d.from, d.to, class, warn));
    }
    s
}
```

> Add a small `workspace_default_name(dir)` helper in `mod.rs` that mirrors `name_for` but without `SandboxOpts` (just the sanitized basename) — reuse `name::sanitize` on `dir.file_name()`.

In `main.rs`, add to `enum Cmd`:

```rust
/// Show drift between izba.yml and the managed sandbox truth
Diff {
    /// Workspace directory containing izba.yml
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Sandbox name (default: from manifest metadata.name or the dir basename)
    #[arg(long)]
    name: Option<String>,
},
```

And in the dispatch match: `Cmd::Diff { dir, name } => commands::diff::run(&paths, &dir, name.as_deref()),`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::diff 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Manual smoke + commit**

```bash
source .cargo-env 2>/dev/null
cargo build -p izba-cli 2>&1 | tail -5
git add crates/izba-cli/src/commands/diff.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/main.rs
git commit -m "feat(cli): izba diff — structural drift + review token"
```

---

## Task 8: `izba promote` command

**Files:**
- Create: `crates/izba-cli/src/commands/promote.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (`pub mod promote;`)
- Modify: `crates/izba-cli/src/main.rs` (`Cmd::Promote` + dispatch)

**Interfaces:**
- Consumes: Task 7 helpers; `manifest::{apply, store, Normalized, ImageSource}`; `image::ensure_image`; `commands::build::{build_image, BuildOpts}`; `DaemonClient` + `DaemonRequest::{ReloadPolicy, PortPublish, PortUnpublish, VolumeAttach, VolumeDetach, Stop, Start}`.
- Produces: `commands::promote::run(paths, dir, name_override, force: bool, restart: bool, reset_scratch: bool) -> Result<i32>` and a pure `gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome` helper.

- [ ] **Step 1: Write the failing test** (pure gate logic)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_a_token() {
        assert_eq!(gate(None, "tok", false), GateOutcome::NeverReviewed);
        assert_eq!(gate(None, "tok", true), GateOutcome::ForcedUnreviewed);
    }

    #[test]
    fn gate_detects_stale_review() {
        assert_eq!(gate(Some("old"), "new", false), GateOutcome::Stale);
        assert_eq!(gate(Some("old"), "new", true), GateOutcome::ForcedStale);
    }

    #[test]
    fn gate_passes_on_match() {
        assert_eq!(gate(Some("tok"), "tok", false), GateOutcome::Ok);
        assert_eq!(gate(Some("tok"), "tok", true), GateOutcome::Ok);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::promote 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`promote.rs`)

```rust
//! `izba promote` — apply izba.yml -> managed truth, gated on a prior `izba
//! diff` review. Live fields apply immediately; restart fields update
//! config.json and take effect on next start (or now with --restart).

use std::path::Path;

use anyhow::{bail, Result};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::manifest::normalize::ImageSource;
use izba_core::manifest::{apply, store, Normalized};
use izba_core::paths::Paths;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    Ok,
    NeverReviewed,
    Stale,
    ForcedUnreviewed,
    ForcedStale,
}

pub(crate) fn gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome {
    match (review, force) {
        (Some(t), _) if t == current_token => GateOutcome::Ok,
        (None, false) => GateOutcome::NeverReviewed,
        (None, true) => GateOutcome::ForcedUnreviewed,
        (Some(_), false) => GateOutcome::Stale,
        (Some(_), true) => GateOutcome::ForcedStale,
    }
}

pub fn run(
    paths: &Paths,
    dir: &Path,
    name_override: Option<&str>,
    force: bool,
    restart: bool,
    reset_scratch: bool,
) -> Result<i32> {
    let (m, raw, dockerfile) = super::load_repo_manifest(dir)?;
    let default_name = super::workspace_default_name(dir)?;
    let repo = Normalized::from_manifest(&m, &default_name)?;
    let name = name_override.unwrap_or(&repo.name).to_string();
    let dir_managed = paths.sandbox_dir(&name);

    // Review gate.
    let token = store::review_token(&raw, dockerfile.as_deref());
    match gate(store::read_review(&dir_managed)?.as_deref(), &token, force) {
        GateOutcome::Ok => {}
        GateOutcome::NeverReviewed => bail!("no reviewed diff — run `izba diff` first (or --force)"),
        GateOutcome::Stale => bail!("izba.yml changed since `izba diff` — re-run it (or --force)"),
        GateOutcome::ForcedUnreviewed => {
            eprintln!("WARNING: --force: promoting changes that were never reviewed");
        }
        GateOutcome::ForcedStale => {
            eprintln!("WARNING: --force: izba.yml changed since review — promoting UNREVIEWED changes");
        }
    }

    let managed = super::managed_normalized(paths, &name)?;
    let p = apply::plan(&managed, &repo);

    // Resolve the image digest for the target (no proto bump: host-side).
    let digest = match &repo.image {
        ImageSource::Ref(r) => izba_core::image::ensure_image(paths, r)?,
        ImageSource::Build(b) => {
            let opts = build_opts_from(dir, b);
            crate::commands::build::build_image(paths, &opts)?
        }
    };

    // Loud image-change scratch warning.
    if p.image_changed && !reset_scratch {
        eprintln!(
            "WARNING: --reset-scratch=n keeps the rw overlay built on the PREVIOUS image. \
             Packages installed (e.g. apt-get) against the old base may have missing libs / \
             wrong ABI on the new image and can render the guest UNBOOTABLE. Proceed only if \
             you understand overlay semantics."
        );
    }

    // Write managed truth (config.json + policy.yaml).
    apply::write_managed(paths, &name, &repo, &digest)?;

    // Enact live effects via the daemon.
    let mut client = DaemonClient::connect(paths)?;
    if p.policy_changed {
        send_ok(&mut client, &DaemonRequest::ReloadPolicy { name: name.clone() })?;
    }
    for r in &p.ports_removed {
        send_ok(&mut client, &DaemonRequest::PortUnpublish { name: name.clone(), bind: r.bind, host_port: r.host_port })?;
    }
    for r in &p.ports_added {
        send_ok(&mut client, &DaemonRequest::PortPublish { name: name.clone(), rule: r.clone(), persist: true })?;
    }
    for gp in &p.volumes_removed {
        send_ok(&mut client, &DaemonRequest::VolumeDetach { name: name.clone(), guest_path: gp.clone() })?;
    }
    for v in &p.volumes_added {
        send_ok(&mut client, &DaemonRequest::VolumeAttach { name: name.clone(), spec: v.clone() })?;
    }

    // Restart fields.
    if !p.restart_fields.is_empty() {
        if restart {
            send_ok(&mut client, &DaemonRequest::Stop { name: name.clone() })?;
            send_ok(&mut client, &DaemonRequest::Start { name: name.clone(), allow_unconfined: false })?;
            println!("restarted to apply: {}", p.restart_fields.join(", "));
        } else {
            println!("pending restart to apply: {} (run `izba promote --restart` or restart manually)", p.restart_fields.join(", "));
        }
    }

    // Advance the base + clear the consumed review token.
    store::write_base(&dir_managed, &m)?;
    store::clear_review(&dir_managed)?;
    println!("promoted {name}");
    Ok(0)
}

fn build_opts_from(dir: &Path, b: &izba_core::manifest::schema::BuildSpec) -> crate::commands::build::BuildOpts {
    let context = dir.join(b.context.as_deref().unwrap_or("."));
    let dockerfile = context.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
    crate::commands::build::BuildOpts {
        dockerfile,
        tag: b.tag.clone(),
        context,
        build_allow: b.allow.clone(),
        cpus: b.resources.as_ref().map(|r| r.cpus).unwrap_or(2),
        mem: b.resources.as_ref().and_then(|r| izba_core::manifest::quantity::parse_mib(&r.memory).ok()).unwrap_or(4096),
    }
}

fn send_ok(client: &mut DaemonClient, req: &DaemonRequest) -> Result<()> {
    match client.request(req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}
```

In `main.rs`, add to `enum Cmd`:

```rust
/// Apply izba.yml to the managed sandbox (requires a prior `izba diff`)
Promote {
    #[arg(default_value = ".")]
    dir: PathBuf,
    #[arg(long)]
    name: Option<String>,
    /// Promote even if the manifest was never reviewed / changed since review
    #[arg(long)]
    force: bool,
    /// Stop+start the sandbox now to apply restart-class fields (cpus/mem/image)
    #[arg(long)]
    restart: bool,
    /// On an image change, reset the rw scratch overlay onto the new base
    /// (default true). `--reset-scratch=false` keeps it (expert-only, loud).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    reset_scratch: bool,
},
```

Dispatch: `Cmd::Promote { dir, name, force, restart, reset_scratch } => commands::promote::run(&paths, &dir, name.as_deref(), force, restart, reset_scratch),`

> **`--reset-scratch` wiring:** v1 surfaces the flag and the warning; the actual overlay reset on restart is a small change in the start path keyed on a marker. If wiring the reset into `Start` is out of reach in this task, leave a `// TODO(reset-scratch): wire overlay reset into Start` ONLY as a tracked follow-up issue — do not ship a silent no-op. Simplest v1: when `image_changed && reset_scratch`, delete `rw.img` before the `Start` so it is reformatted blank (verify the start path reformats a missing rw.img; grep `rw.img` in `sandbox.rs`). Add a test that promote with an image change removes `rw.img` when `reset_scratch` and keeps it otherwise.

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::promote 2>&1 | tail -20`
Expected: PASS (gate tests).

- [ ] **Step 5: Commit**

```bash
source .cargo-env 2>/dev/null
cargo clippy -p izba-cli --all-targets -- -D warnings 2>&1 | tail -5
git add crates/izba-cli/src/commands/promote.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/main.rs
git commit -m "feat(cli): izba promote — gated apply of izba.yml to managed truth"
```

---

## Task 9: `izba export` command

**Files:**
- Create: `crates/izba-cli/src/commands/export.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (`pub mod export;`)
- Modify: `crates/izba-cli/src/main.rs` (`Cmd::Export` + dispatch)

**Interfaces:**
- Consumes: Task 7 `managed_normalized`; `Normalized::to_manifest`; `store::write_base`.
- Produces: `commands::export::run(paths, dir, name_override) -> Result<i32>` + pure `manifest_with_header(&Manifest) -> String`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::manifest::Manifest;

    #[test]
    fn export_prepends_managed_header() {
        let m = Manifest::load_str(
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n  resources: { cpus: 1, memory: 1Gi }\n  rootDisk: { size: 1Gi }\n",
        ).unwrap();
        let s = manifest_with_header(&m);
        assert!(s.starts_with("# Generated by `izba export`"), "got: {s}");
        assert!(s.contains("apiVersion: izba.dev/v1alpha1"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::export 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (`export.rs`)

```rust
//! `izba export` — write the managed truth back into izba.yml (the human then
//! commits the git diff). Inverse of promote; no review gate (the human runs it).

use std::path::Path;

use anyhow::{Context, Result};
use izba_core::manifest::{store, Manifest};
use izba_core::paths::Paths;

pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    let default_name = super::workspace_default_name(dir)?;
    // Prefer an explicit name; else the existing manifest's name; else the dir.
    let name = match name_override {
        Some(n) => n.to_string(),
        None => match super::load_repo_manifest(dir) {
            Ok((m, _, _)) => m.metadata.name.unwrap_or(default_name),
            Err(_) => default_name,
        },
    };
    let managed = super::managed_normalized(paths, &name)?;
    let manifest = managed.to_manifest();
    let path = dir.join("izba.yml");
    std::fs::write(&path, manifest_with_header(&manifest))
        .with_context(|| format!("writing {}", path.display()))?;
    // The repo now equals managed -> advance base so diff reads in-sync.
    store::write_base(&paths.sandbox_dir(&name), &manifest)?;
    store::clear_review(&paths.sandbox_dir(&name))?;
    println!("exported managed truth -> {}", path.display());
    Ok(0)
}

pub(crate) fn manifest_with_header(m: &Manifest) -> String {
    format!(
        "# Generated by `izba export` — edit and `izba diff`/`izba promote` to apply.\n{}",
        m.to_yaml()
    )
}
```

`main.rs` `Cmd`:

```rust
/// Write the managed sandbox truth back into izba.yml
Export {
    #[arg(default_value = ".")]
    dir: PathBuf,
    #[arg(long)]
    name: Option<String>,
},
```

Dispatch: `Cmd::Export { dir, name } => commands::export::run(&paths, &dir, name.as_deref()),`

- [ ] **Step 4: Run test to verify it passes**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli commands::export 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/export.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/main.rs
git commit -m "feat(cli): izba export — write managed truth back to izba.yml"
```

---

## Task 10: `izba create`/`run` honor izba.yml + seed base/review

**Files:**
- Modify: `crates/izba-cli/src/commands/create.rs` (seed base + review after create)
- Modify: `crates/izba-cli/src/commands/mod.rs` (`build_create_request` merge: if `izba.yml` present and a field was left at its clap default, take the manifest's value)
- Test: `crates/izba-cli/src/commands/create.rs` (`#[cfg(test)]` for the merge helper)

**Interfaces:**
- Consumes: `load_repo_manifest`, `Normalized::from_manifest`, `manifest::store`, `Manifest::to_yaml`.
- Produces: `commands::merge_manifest_into_opts(opts: &mut SandboxOpts, dir: &Path) -> Result<Option<Manifest>>` — if `izba.yml` exists, overlay its values onto `opts` for any field the user left at the clap default; returns the parsed manifest (so the caller can seed the base). CLI flags always win over the manifest.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_fills_defaults_but_flags_win() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("izba.yml"),
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nmetadata: { name: fromfile }\nspec:\n  image: alpine:3\n  resources: { cpus: 8, memory: 2Gi }\n  rootDisk: { size: 4Gi }\n",
        ).unwrap();

        // User left image at default but overrode cpus on the CLI.
        let mut opts = sample_opts_with_defaults(); // image="ubuntu:24.04", cpus=2 (default), name=None
        opts.cpus = 16; // simulate explicit --cpus 16
        let m = super::super::merge_manifest_into_opts(&mut opts, dir.path()).unwrap().unwrap();
        assert_eq!(opts.image, "alpine:3", "manifest fills image (was default)");
        assert_eq!(opts.cpus, 16, "explicit --cpus wins over manifest");
        assert_eq!(m.metadata.name.as_deref(), Some("fromfile"));
    }

    #[test]
    fn no_manifest_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = sample_opts_with_defaults();
        assert!(super::super::merge_manifest_into_opts(&mut opts, dir.path()).unwrap().is_none());
        assert_eq!(opts.image, "ubuntu:24.04");
    }
}
```

> Implement `sample_opts_with_defaults()` in the test by constructing `SandboxOpts` with the clap defaults (image `"ubuntu:24.04"`, cpus 2, mem 4096, rw_size_gb 8, name None, publish/volumes empty, policy None). Detecting "left at default" is done by comparing against those constants — define them as `const` in `mod.rs` and reference both from clap `default_value` and the merge.

- [ ] **Step 2: Run test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli merge_manifest 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

In `mod.rs`, add default constants + the merge:

```rust
pub(crate) const DEFAULT_IMAGE: &str = "ubuntu:24.04";
pub(crate) const DEFAULT_CPUS: u32 = 2;
pub(crate) const DEFAULT_MEM_MB: u32 = 4096;
pub(crate) const DEFAULT_RW_GB: u64 = 8;

/// Overlay an `izba.yml` (if present) onto `opts`: for each field the user left
/// at its clap default, take the manifest's value. Explicit flags always win.
pub(crate) fn merge_manifest_into_opts(
    opts: &mut crate::SandboxOpts,
    dir: &Path,
) -> anyhow::Result<Option<izba_core::manifest::Manifest>> {
    if !dir.join("izba.yml").exists() {
        return Ok(None);
    }
    let (m, _, _) = load_repo_manifest(dir)?;
    let default_name = workspace_default_name(dir)?;
    let n = izba_core::manifest::Normalized::from_manifest(&m, &default_name)?;
    if opts.image == DEFAULT_IMAGE {
        if let izba_core::manifest::ImageSource::Ref(r) = &n.image {
            opts.image = r.clone();
        }
    }
    if opts.cpus == DEFAULT_CPUS {
        opts.cpus = n.cpus;
    }
    if opts.mem == DEFAULT_MEM_MB {
        opts.mem = n.mem_mb;
    }
    if opts.rw_size_gb == DEFAULT_RW_GB && n.rw_size_gb != 0 {
        opts.rw_size_gb = n.rw_size_gb;
    }
    if opts.name.is_none() {
        opts.name = Some(n.name.clone());
    }
    // Ports/volumes/egress: only adopt from manifest when the user passed none.
    if opts.publish.is_empty() {
        opts.publish = n.ports.iter().map(|p| format!("{}:{}:{}", p.bind, p.host_port, p.guest_port)).collect();
    }
    Ok(Some(m))
}
```

Update `SandboxOpts` clap `default_value*` attributes in `main.rs` to reference the new constants (or keep literals and ensure they match exactly — add a unit test asserting equality if you keep literals).

In `create.rs::run`, after a successful `Created` and `persist_policy`, seed base + review-clear so a fresh create starts "in sync":

```rust
// Honor izba.yml + seed the manifest base so `izba diff` reads in-sync.
// (opts already merged by caller; if a manifest exists, persist it as base.)
if let Some(m) = manifest_for_base {
    use izba_core::manifest::store;
    store::write_base(&paths.sandbox_dir(&name), &m)?;
    store::clear_review(&paths.sandbox_dir(&name))?;
}
```

Wire `merge_manifest_into_opts` into both `create::run` and `run::run` BEFORE building the create request (so the manifest seeds name/image/etc.), threading the returned `Option<Manifest>` to the base-seeding block. If `--policy` was not passed but the manifest has `egress`, write it via `persist_policy_config` using `EgressPolicyConfig` from the manifest (`m.spec.egress`).

- [ ] **Step 4: Run test to verify it passes + full create/run still parse**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/create.rs crates/izba-cli/src/commands/run.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/main.rs
git commit -m "feat(cli): create/run honor izba.yml + seed manifest base"
```

---

## Task 11: Tauri app — diff/promote/export commands + create-from-manifest

**Files:**
- Modify: `app/src-tauri/src/views.rs` (add `DiffView`, `DriftStateView`, reuse `FieldDelta`-shaped struct; `CreateOpts::from_manifest`)
- Modify: `app/src-tauri/src/commands.rs` (`diff`, `promote`, `export`, `create_from_manifest` tauri commands)
- Modify: `app/src-tauri/src/lib.rs` (register the new commands in the `invoke_handler`)
- Test: `app/src-tauri/src/views.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `izba_core::manifest::{Manifest, Normalized, diff, classify, DriftState}`, the Task 7–9 host-side helpers (move the reusable bits into `izba-core` if the app cannot call `izba-cli`; the app links `izba-core` only — so the diff/promote/export ORCHESTRATION the app needs must be reachable from core OR duplicated thinly. Prefer exposing `izba_core::manifest`-level pure functions; the app composes them with `DaemonClient` like the CLI does).
- Produces: serializable `DiffView { state: String, deltas: Vec<DeltaView> }`, `DeltaView { field, from, to, class, weakens_egress }`; tauri commands `diff_sandbox`, `promote_sandbox`, `export_sandbox`, `create_from_manifest`.

> **Important architecture note:** `izba-cli`'s command modules are NOT linked by the app. The reusable, daemon-touching orchestration (load manifest, compute diff, gate, apply via daemon) used by BOTH the CLI and the app should live in `izba-core` (e.g. `izba_core::manifest::ops`), with `izba-cli` and the app as thin callers. If Tasks 7–9 put orchestration in `izba-cli`, REFACTOR the daemon-free parts (load/normalize/gate/plan) into `izba_core::manifest::ops` here and have both callers use them. Keep terminal printing in the CLI.

- [ ] **Step 1: Write the failing test** (view mapping)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::manifest::diff::{FieldClass, FieldDelta};
    use izba_core::manifest::DriftState;

    #[test]
    fn diff_view_maps_state_and_deltas() {
        let deltas = vec![FieldDelta {
            field: "egress".into(), from: "a".into(), to: "b".into(),
            class: FieldClass::Live, weakens_egress: true,
        }];
        let v = DiffView::new(DriftState::RepoAhead, &deltas);
        assert_eq!(v.state, "repo_ahead");
        assert_eq!(v.deltas[0].class, "live");
        assert!(v.deltas[0].weakens_egress);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app/src-tauri && cargo test diff_view 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`views.rs`:

```rust
use izba_core::manifest::diff::{FieldClass, FieldDelta};
use izba_core::manifest::DriftState;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaView {
    pub field: String,
    pub from: String,
    pub to: String,
    pub class: String,
    pub weakens_egress: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffView {
    pub state: String,
    pub deltas: Vec<DeltaView>,
}

impl DiffView {
    pub fn new(state: DriftState, deltas: &[FieldDelta]) -> Self {
        let state = match state {
            DriftState::InSync => "in_sync",
            DriftState::RepoAhead => "repo_ahead",
            DriftState::ManagedAhead => "managed_ahead",
            DriftState::Diverged => "diverged",
        }
        .to_string();
        let deltas = deltas
            .iter()
            .map(|d| DeltaView {
                field: d.field.clone(),
                from: d.from.clone(),
                to: d.to.clone(),
                class: match d.class {
                    FieldClass::Live => "live",
                    FieldClass::Restart => "restart",
                    FieldClass::Image => "image",
                }
                .to_string(),
                weakens_egress: d.weakens_egress,
            })
            .collect();
        Self { state, deltas }
    }
}
```

`commands.rs`: add `#[tauri::command]` wrappers `diff_sandbox(workspace: String) -> Result<DiffView, String>`, `promote_sandbox(workspace, force, restart, reset_scratch) -> Result<String,String>`, `export_sandbox(workspace) -> Result<String,String>`, `create_from_manifest(workspace) -> Result<String,String>`, each composing `izba_core::manifest::ops::*` with the app's existing `DaemonApi`/`DaemonClient` access (mirror how `create_core` connects). Register all four in `lib.rs`'s `tauri::generate_handler![...]`.

- [ ] **Step 4: Run test + app gate**

Run:
```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test 2>&1 | tail -20)
```
Expected: build + tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/views.rs app/src-tauri/src/commands.rs app/src-tauri/src/lib.rs crates/izba-core/src/manifest/
git commit -m "feat(app): manifest diff/promote/export commands + create-from-manifest"
```

---

## Task 12: Docs + full gate sweep

**Files:**
- Modify: `README.md` (manifest + diff/promote/export section)
- Modify: `CLAUDE.md` (add `izba.yml` to the "Load-bearing contracts" / state section: managed-truth vs repo-manifest trust boundary, host-only `manifest.base.yaml`+`manifest.review`)
- Verify: all gates.

- [ ] **Step 1: Write the README section**

Document: the `izba.yml` schema (copy the spec's example), the trust model in two sentences, and the `diff` -> `promote` -> `export` loop with the review gate, `--force`, `--restart`, `--reset-scratch` semantics, and the `⚠ weakens egress` flag.

- [ ] **Step 2: Update CLAUDE.md contracts**

Add a bullet under "Load-bearing contracts": `izba.yml` (repo, agent-writable in `/workspace`) is an untrusted *proposal*; the managed truth (`config.json`+`policy.yaml`) is host-only authority; `promote` is the human-gated bridge; `manifest.base.yaml`+`manifest.review` are host-only and never enter the overlay.

- [ ] **Step 3: Run ALL six workspace gates**

```bash
source .cargo-env 2>/dev/null
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -8
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release 2>&1 | tail -5
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli 2>&1 | tail -5
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings 2>&1 | tail -5
```
Expected: all green. Fix anything red before committing.

- [ ] **Step 4: Run the app gate**

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test 2>&1 | tail -10)
```
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: izba.yml manifest + diff/promote/export workflow"
```

---

## Self-Review

**1. Spec coverage:**
- §3 trust model → Task 5 (host-only store), Task 8 (gate). ✓
- §4 k8s schema → Task 2. ✓ (quantity Task 1)
- §5 on-disk base+review → Task 5. ✓
- §6 3-way reconciliation → Task 3 (normalize) + Task 4 (classify) + Task 7 (diff command). ✓
- §7 review gate (no-token/stale/force) → Task 8 `gate`. ✓
- §8 field semantics (live/restart/image, --restart, --reset-scratch) → Task 4 (class), Task 6 (plan), Task 8 (apply + restart + reset-scratch). ✓
- §9 build recipes in diff/promote (Dockerfile in review scope, rebuild→digest) → Task 5 `review_token` (dockerfile), Task 7 `load_repo_manifest` (reads Dockerfile), Task 8 (build_image on promote). ✓
- §10 security: weakens-egress flag (Task 4), --force/reset-scratch loud (Task 8), no secrets (export renders declarative only — Task 9). ✓
- §11 no proto bump: confirmed — only existing RPCs + host-side `ensure_image`/`build_image`. ✓
- §13 app surface → Task 11. ✓

**2. Placeholder scan:** The only `TODO` is the explicitly-gated reset-scratch follow-up note in Task 8, which gives a concrete v1 implementation (delete `rw.img` before Start) — not a silent no-op. No other placeholders.

**3. Type consistency:** `Normalized`, `ImageSource`, `FieldDelta`, `FieldClass`, `DriftState`, `ApplyPlan`, `GateOutcome` names are used identically across Tasks 3–11. `EgressPolicyConfig` reused verbatim as the manifest `egress` block. `review_token(manifest_yaml, dockerfile)` signature consistent in Tasks 5/7/8.

**Open risk to verify during execution:** Task 6's `Paths` temp constructor and Task 8's `rw.img` reformat-on-missing behavior must be confirmed against the actual code (grep noted in-task). Task 11 may require refactoring daemon-free orchestration into `izba_core::manifest::ops` so the app (which links core, not cli) can reuse it.
