# Docker-in-sandbox PR 2 — Docker Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement docker mode (#198, spec §§1-5,8): label/flag enablement, the userns-scoped OCI docker profile, the child-netns + veth guest datapath with prerouting nft interception, the auto `/var/lib/docker` volume, engine auto-start, and the `tcp_dial` veth fallback — ending with a real DinD KVM e2e.

**Architecture:** Host side resolves docker mode at `create` (CLI tri-state overrides the `com.docker.sandboxes.start-docker=true` image label), persists it on `SandboxConfig`, and at `start` selects the docker OCI profile + `izba.docker=1` cmdline. Guest side (izba-init) reacts: keeps the container's own netns, wires a veth pair via the vendored `/sbin/ip`, adds a prerouting nft chain, points resolv.conf at 192.168.127.1, delegates a cgroup subtree, and auto-starts `dockerd` via `crun exec`. PR 1 (merged) supplies the kernel symbols, `/sbin/ip`, `additionalGids`, and the wildcard `:15001` bind.

**Tech Stack:** Rust (izba-core, izba-init, izba-cli), nftables text rulesets, iproute2 CLI invocations, KVM e2e harnesses.

## Global Constraints

- All six workspace gates green before EVERY commit (source `.cargo-env` first): `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- izba-core public types change (SpecParams, CreateOpts, proto) → the app gate must also pass before the final push: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- **No `DAEMON_PROTO_VERSION` bump**: every wire change is an additive `#[serde(default)]` field with a `..._defaults_...` proto test (the `builder` precedent, proto.rs:468).
- Unit tests never bind listeners unconditionally (runtime-skip on `PermissionDenied`); guest-only side effects live behind `#[mutants::skip]` fns with a reason comment, with ALL branching logic extracted into host-testable pure helpers. Every rule gets a call-site test or a justified skip.
- TDD: failing test first (structural compile failure counts), then implement, then green.
- Addresses are the existing constants: init-side veth = `net::RESOLVER_IP` (192.168.127.1), container-side = `net::GUEST_IP` (192.168.127.2). Never hardcode new IPs.
- Security invariants: no capability grants outside the container's userns; `builder` (privileged) and `docker` are mutually exclusive with builder winning; fail-honest (loud console log, sandbox stays diagnosable) — never silently fall back to the shared-netns datapath.
- KVM suites + kernel/initramfs work need the Bash sandbox disabled; sandboxed pgrep/ps cannot see unsandboxed processes — verify background jobs via their log files.

---

### Task 1: Docker-mode resolution + create-path plumbing (host side)

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` (DaemonCreate ~line 45-76; tests ~line 399, 468)
- Modify: `crates/izba-core/src/daemon/server.rs` (`handle_create` ~line 433-472)
- Modify: `crates/izba-core/src/sandbox.rs` (`CreateOpts` ~line 53-65; `create()` fold ~line 355-372)
- Modify: `crates/izba-core/src/state.rs` (`SandboxConfig` ~line 21-58 + a back-compat test)
- Modify: `crates/izba-cli/src/main.rs` (`SandboxOpts` ~line 33-66), `crates/izba-cli/src/commands/mod.rs` (`build_create_request` ~line 126-147)

**Interfaces:**
- Consumes: `ImageStore::load_config(&digest)` (store.rs:40) — the config is already persisted by `ensure_image` before `handle_create` builds `CreateOpts`.
- Produces: `pub fn resolve_docker_mode(cli: Option<bool>, labels: Option<&HashMap<String, String>>) -> bool` (in `crates/izba-core/src/daemon/server.rs`, pub for tests); `DaemonCreate.docker: Option<bool>`; `CreateOpts.docker: bool`; `SandboxConfig.docker: bool`. Task 2 and Task 3 consume `SandboxConfig.docker`/`CreateOpts.docker`.

- [ ] **Step 1: Write the failing tests**

In `proto.rs` tests (next to `create_without_builder_defaults_false`):

```rust
#[test]
fn create_without_docker_defaults_none() {
    // A pre-feature client's frame has no `docker` key; it must deserialize
    // to None (= "no CLI preference, label decides") — additive field, no
    // DAEMON_PROTO_VERSION bump.
    let json = r#"{"type":"create","name":"s","image_ref":"alpine","cpus":1,"mem_mb":256,"workspace":"/w"}"#;
    let req: DaemonRequest = serde_json::from_str(json).expect("deserialize");
    match req {
        DaemonRequest::Create(c) => assert_eq!(c.docker, None),
        other => panic!("wrong variant: {other:?}"),
    }
}
```

(Adapt the JSON skeleton to the exact shape the neighboring `create_without_builder_defaults_false` test uses — copy its literal and delete the `docker` key.) Also extend the `request_roundtrip` Create literal with `docker: Some(true)`.

In `server.rs` tests:

```rust
#[test]
fn resolve_docker_mode_precedence() {
    use std::collections::HashMap;
    let on: HashMap<String, String> =
        [("com.docker.sandboxes.start-docker".to_string(), "true".to_string())].into();
    let off: HashMap<String, String> =
        [("com.docker.sandboxes.start-docker".to_string(), "false".to_string())].into();
    // CLI wins over label, both directions.
    assert!(!resolve_docker_mode(Some(false), Some(&on)));
    assert!(resolve_docker_mode(Some(true), None));
    // Label decides when CLI is silent; only the literal "true" enables.
    assert!(resolve_docker_mode(None, Some(&on)));
    assert!(!resolve_docker_mode(None, Some(&off)));
    assert!(!resolve_docker_mode(None, None));
}
```

In `state.rs` tests (next to `config_without_volumes_defaults_empty`):

```rust
#[test]
fn config_without_docker_defaults_false() {
    // Pre-docker-mode config.json on disk must load with docker=false.
    let json = r#"{"image_digest":"sha256:x","image_ref":"alpine","cpus":1,"mem_mb":256,"workspace":"/w"}"#;
    let cfg: SandboxConfig = serde_json::from_str(json).expect("deserialize");
    assert!(!cfg.docker);
}
```

(Copy the neighboring back-compat test's JSON skeleton verbatim and just assert the new field.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core create_without_docker resolve_docker_mode config_without_docker`
Expected: compile failure (missing fields/function) — structural RED.

- [ ] **Step 3: Implement**

`proto.rs` `DaemonCreate`:

```rust
/// Docker mode (#198): the CLI's explicit choice. `Some(true)` = --docker,
/// `Some(false)` = --no-docker, `None` = no preference (the image's
/// `com.docker.sandboxes.start-docker` label decides). Resolved to the
/// persisted `SandboxConfig.docker` bool by the daemon at create, where the
/// image config is in hand. Additive + serde-default → no
/// `DAEMON_PROTO_VERSION` bump.
#[serde(default)]
pub docker: Option<bool>,
```

`server.rs`:

```rust
/// The OCI image label sbx uses to mark engine-bearing images; izba honors it
/// for sbx parity (spec §1).
pub const START_DOCKER_LABEL: &str = "com.docker.sandboxes.start-docker";

/// Resolve the sandbox's docker mode: an explicit CLI choice wins; otherwise
/// the image label enables it iff its value is exactly "true"; otherwise off.
pub fn resolve_docker_mode(
    cli: Option<bool>,
    labels: Option<&std::collections::HashMap<String, String>>,
) -> bool {
    match cli {
        Some(v) => v,
        None => labels
            .and_then(|l| l.get(START_DOCKER_LABEL))
            .is_some_and(|v| v == "true"),
    }
}
```

In `handle_create`, after `let digest = (d.deps.resolve_image)(...)`:

```rust
// Docker mode is a create-time decision (spec §1): the CLI's explicit choice
// wins, else the sbx start-docker label. Builder sandboxes never get docker
// mode — the privileged builder profile skips the userns docker mode
// depends on, so the combination is contradictory; builder wins silently
// (it is set only by `izba build`, never user-visible).
let docker = if c.builder {
    false
} else {
    let cfg = crate::image::store::ImageStore::new(&d.paths)
        .load_config(&digest)
        .ok()
        .flatten();
    resolve_docker_mode(
        c.docker,
        cfg.as_ref()
            .and_then(|f| f.config.as_ref())
            .and_then(|cc| cc.labels.as_ref()),
    )
};
```

(Use the actual `ImageStore` import path already used in this file/module — check how `start` reaches it; the scout confirms `ImageStore::new(paths).load_config(&digest)` works post-`ensure_image`. A store read error resolves to label-absent, i.e. off unless `--docker` — the direction that never invents privilege.)

Then `docker` into `CreateOpts` (`sandbox.rs:53-65` — add `pub docker: bool` with a doc comment mirroring `builder`'s), fold into `SandboxConfig` in `create()` (~line 362: `docker: opts.docker`), and `state.rs`:

```rust
/// Docker mode (#198): this workload gets the docker OCI profile (own
/// netns + veth datapath, userns-scoped SYS_ADMIN/NET_ADMIN caps, cgroup
/// delegation) and the engine auto-start. Resolved at create from the CLI
/// flag / image label; `#[serde(default)]` keeps pre-feature config.json
/// loading (= false).
#[serde(default)]
pub docker: bool,
```

CLI: in `SandboxOpts` (main.rs:33-66):

```rust
/// Enable docker mode: the workload gets its own network namespace,
/// userns-scoped admin capabilities, an auto /var/lib/docker volume, and
/// the image's Docker Engine is auto-started (overrides the image label).
#[arg(long, overrides_with = "no_docker")]
docker: bool,
/// Disable docker mode even if the image carries the
/// com.docker.sandboxes.start-docker label.
#[arg(long, overrides_with = "docker")]
no_docker: bool,
```

and derive the tri-state where `build_create_request` is called: `let docker = if opts.docker { Some(true) } else if opts.no_docker { Some(false) } else { None };` — thread it through `build_create_request` as a new `docker: Option<bool>` parameter (the `allow_unconfined` threading at mod.rs:132 is the pattern), replacing the current hardcoded position next to `builder: false`. Update every `build_create_request` caller.

Also update every `CreateOpts {`/`DaemonCreate {`/`SandboxConfig {` struct literal across the workspace (tests included) — grep and add `docker: false`/`docker: None` as appropriate.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs crates/izba-core/src/sandbox.rs crates/izba-core/src/state.rs crates/izba-cli/src/main.rs crates/izba-cli/src/commands/mod.rs
git commit -m "feat(core): docker-mode flag — label auto-detect + --docker/--no-docker (#198)"
```

(Add any other files the literal-updates touched.)

---

### Task 2: Auto /var/lib/docker volume at create

**Files:**
- Modify: `crates/izba-core/src/volume.rs` (new helper + tests)
- Modify: `crates/izba-core/src/sandbox.rs` (`create()` ~line 345, before `assign_eph_ids`)

**Interfaces:**
- Consumes: `VolumeSpec { name: Option<String>, guest_path: PathBuf, size_bytes: u64, eph_id: Option<u64> }` (volume.rs:22-34); `CreateOpts.docker` from Task 1.
- Produces: `pub fn inject_docker_volume(volumes: &mut Vec<VolumeSpec>, docker: bool)` and `pub const DOCKER_VOLUME_PATH: &str = "/var/lib/docker"; pub const DOCKER_VOLUME_SIZE: u64 = 10 << 30;` in volume.rs.

- [ ] **Step 1: Write the failing tests** (volume.rs tests module)

```rust
#[test]
fn inject_docker_volume_appends_anonymous_when_absent() {
    let mut vols = vec![];
    inject_docker_volume(&mut vols, true);
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].guest_path, std::path::PathBuf::from(DOCKER_VOLUME_PATH));
    assert_eq!(vols[0].name, None, "auto volume is anonymous (ephemeral)");
    assert_eq!(vols[0].size_bytes, DOCKER_VOLUME_SIZE);
}

#[test]
fn inject_docker_volume_noop_when_docker_off() {
    let mut vols = vec![];
    inject_docker_volume(&mut vols, false);
    assert!(vols.is_empty());
}

#[test]
fn inject_docker_volume_defers_to_user_declared_path() {
    // A user-declared volume at the path (named → persistent) wins; no
    // duplicate is appended (validate_volumes would reject it anyway).
    let mut vols = vec![VolumeSpec {
        name: Some("dockerlib".into()),
        guest_path: "/var/lib/docker".into(),
        size_bytes: 2 << 30,
        eph_id: None,
    }];
    inject_docker_volume(&mut vols, true);
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].name.as_deref(), Some("dockerlib"));
}

#[test]
fn inject_docker_volume_matches_by_components_not_string() {
    // "/var/lib/docker/." and "/var/lib//docker" name the same directory; a
    // raw PathBuf == comparison would miss them and double-provision.
    for spelled in ["/var/lib/docker/", "/var/lib/docker/.", "/var/lib//docker"] {
        let mut vols = vec![VolumeSpec {
            name: None,
            guest_path: spelled.into(),
            size_bytes: 1 << 30,
            eph_id: None,
        }];
        inject_docker_volume(&mut vols, true);
        assert_eq!(vols.len(), 1, "{spelled:?} must match {DOCKER_VOLUME_PATH}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core inject_docker_volume`
Expected: compile failure (missing fn/consts).

- [ ] **Step 3: Implement**

```rust
/// Guest path of docker's storage root. overlay2 refuses an overlayfs
/// backing store and the workload rootfs IS izba's overlay, so docker mode
/// needs a real ext4 here (spec §4).
pub const DOCKER_VOLUME_PATH: &str = "/var/lib/docker";
/// Sparse size of the auto-provisioned docker volume.
pub const DOCKER_VOLUME_SIZE: u64 = 10 << 30; // 10 GiB

/// Docker mode auto-attaches an anonymous ext4 volume at
/// [`DOCKER_VOLUME_PATH`] unless the user already declared a volume there
/// (a named volume then gives persistence across `izba rm`). Component-wise
/// path comparison so `/var/lib/docker/.` and friends don't slip past the
/// dedup and double-provision.
pub fn inject_docker_volume(volumes: &mut Vec<VolumeSpec>, docker: bool) {
    if !docker {
        return;
    }
    let target: Vec<std::path::Component> =
        std::path::Path::new(DOCKER_VOLUME_PATH).components().collect();
    let declared = volumes.iter().any(|v| {
        v.guest_path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .eq(target.iter().cloned())
    });
    if !declared {
        volumes.push(VolumeSpec {
            name: None,
            guest_path: DOCKER_VOLUME_PATH.into(),
            size_bytes: DOCKER_VOLUME_SIZE,
            eph_id: None,
        });
    }
}
```

Call site in `sandbox::create()` (~line 345, BEFORE `assign_eph_ids` so the injected volume gets its `eph_id`):

```rust
let mut volumes = opts.volumes.clone();
crate::volume::inject_docker_volume(&mut volumes, opts.docker);
crate::volume::assign_eph_ids(&mut volumes);
```

- [ ] **Step 4: Run suite + mutation check**

Run: `cargo test -p izba-core volume` then (unsandboxed, backgrounded) `cargo mutants -p izba-core -f crates/izba-core/src/volume.rs --no-shuffle 2>&1 | tail -5`
Expected: tests PASS; no MISSED mutants in `inject_docker_volume` (pre-existing survivors elsewhere are out of scope — note, don't chase).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/volume.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): auto-provision an anonymous /var/lib/docker volume in docker mode (#198)"
```

---

### Task 3: OCI docker profile + start-path wiring

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (caps fn ~line 28-54; `SpecParams` ~line 556-595; `generate_spec` netns block ~line 705-723; rw-cgroup gate ~line 748-774; tests)
- Modify: `crates/izba-core/src/sandbox.rs` (`SpecParams` literal ~line 697-702 area; `build_cmdline` ~line 234-258 and its call ~line 869)

**Interfaces:**
- Consumes: `SandboxConfig.docker` (Task 1); existing `docker_default_caps()`, `LinuxNamespaceBuilder`, rw-cgroup block.
- Produces: `pub fn docker_mode_caps() -> Result<LinuxCapabilities>` (docker-default + `SysAdmin` + `NetAdmin` + `SysPtrace`); `SpecParams.docker: bool`; cmdline gains ` izba.docker=1`; the generated spec keeps a FRESH `network` namespace (no path) in docker mode. Task 4 (init) consumes `izba.docker=1`.

- [ ] **Step 1: Write the failing tests** (runtime_config.rs tests; reuse the existing minimal-params helper `base_params`, adding `docker: false` there)

```rust
#[test]
fn docker_mode_caps_is_default_plus_admin_set() {
    use oci_spec::runtime::Capability;
    let caps = docker_mode_caps().unwrap();
    let bounding = caps.bounding().clone().unwrap();
    for c in [Capability::SysAdmin, Capability::NetAdmin, Capability::SysPtrace] {
        assert!(bounding.contains(&c), "{c:?} missing from docker-mode bounding set");
    }
    // Strictly weaker than privileged: docker mode must NOT be all_caps.
    let all = all_caps().unwrap();
    assert!(bounding.len() < all.bounding().clone().unwrap().len());
    // And a superset of the docker-default set.
    let dflt = docker_default_caps().unwrap();
    for c in dflt.bounding().clone().unwrap() {
        assert!(bounding.contains(&c), "{c:?} from default set missing");
    }
}

#[test]
fn docker_mode_spec_keeps_fresh_network_namespace() {
    use oci_spec::runtime::LinuxNamespaceType;
    let img = minimal_image_config(); // reuse the existing tests' fixture helper
    let mut params = base_params(&img);
    params.docker = true;
    let spec = generate_spec(&params).unwrap();
    let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
    let net = nss.iter().find(|n| n.typ() == LinuxNamespaceType::Network)
        .expect("docker mode must keep a network namespace");
    assert!(net.path().is_none(), "fresh netns, not a joined one");
    // The userns + mappings must still be present (docker mode is NOT privileged).
    assert!(nss.iter().any(|n| n.typ() == LinuxNamespaceType::User));
    assert!(spec.linux().as_ref().unwrap().uid_mappings().is_some());
}

#[test]
fn non_docker_spec_still_drops_network_namespace() {
    use oci_spec::runtime::LinuxNamespaceType;
    let img = minimal_image_config();
    let spec = generate_spec(&base_params(&img)).unwrap();
    let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
    assert!(!nss.iter().any(|n| n.typ() == LinuxNamespaceType::Network));
}

#[test]
fn docker_mode_gets_rw_cgroup_mount() {
    let img = minimal_image_config();
    let mut params = base_params(&img);
    params.docker = true;
    let spec = generate_spec(&params).unwrap();
    let m = spec.mounts().as_ref().unwrap().iter()
        .find(|m| m.destination().to_string_lossy() == "/sys/fs/cgroup").unwrap();
    let opts = m.options().clone().unwrap();
    assert!(opts.iter().any(|o| o == "rw") && !opts.iter().any(|o| o == "ro"));
}
```

(Adapt fixture-helper names to what the existing tests actually use — the reviewer will check assertions, not helper names. Extend `spec_omits_network_namespace_keeps_others` if it conflicts.)

Cmdline test in sandbox.rs tests, next to the existing `build_cmdline` tests:

```rust
#[test]
fn cmdline_includes_docker_flag_only_when_enabled() {
    let on = build_cmdline("s", &[], false, false, true);
    assert!(on.contains(" izba.docker=1"));
    let off = build_cmdline("s", &[], false, false, false);
    assert!(!off.contains("izba.docker"));
}
```

(Match `build_cmdline`'s actual current signature/arg order — it takes name, volumes, builder, usb today; `docker` appends as the new last parameter, and existing tests get the extra `false`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core docker_mode cmdline_includes_docker`
Expected: compile failure.

- [ ] **Step 3: Implement**

`docker_mode_caps()` next to `docker_default_caps()`:

```rust
/// Docker-mode capability set (spec §2): the docker-default least-privilege
/// set plus the admin caps dockerd + nested runc need — ALL scoped inside
/// the container's user namespace (a userns SYS_ADMIN cannot mount real
/// block devices or touch init's namespaces). Strictly weaker than the
/// privileged builder profile, which drops the userns entirely.
pub fn docker_mode_caps() -> Result<LinuxCapabilities> { /* build docker_default list + SysAdmin, NetAdmin, SysPtrace, using the same builder shape as docker_default_caps() */ }
```

`SpecParams`:

```rust
/// Docker mode (spec §2-§3): fresh userns-owned network namespace instead
/// of sharing init's, the docker-mode capability set, and the rw cgroupfs
/// treatment. Mutually exclusive with `privileged` (callers guarantee it).
pub docker: bool,
```

`generate_spec` changes:
- caps selection: `let caps = if params.privileged { all_caps()? } else if params.docker { docker_mode_caps()? } else { docker_default_caps()? };`
- netns block: keep the `nss.retain(...)` drop ONLY when `!params.docker`; when docker, ensure a `Network` namespace with no path is present (the default set has one — simply don't retain-drop it). Update the block's D1 doc comment to name the docker-mode exception and the spec §3 rationale.
- rw-cgroup gate: `if params.privileged || params.docker {` with a comment naming both consumers (rootful buildkit / nested containerd+runc).

`sandbox.rs`: `docker: config.docker && !config.builder` in the `SpecParams` literal (defense in depth on top of Task 1's create-side guard — comment it), and `build_cmdline(..., config.docker)` appending ` izba.docker=1` (mirror the `izba.usb=1` block's host-authoritative comment).

Update every `SpecParams {` literal (grep — the test helper plus any others) with `docker: false`.

- [ ] **Step 4: Suite + mutation check**

Run: `cargo test -p izba-core` then (unsandboxed, backgrounded) `cargo mutants -p izba-core -f crates/izba-core/src/image/runtime_config.rs --no-shuffle 2>&1 | tail -5`
Expected: PASS; no MISSED in the new/changed lines (`docker_mode_caps`, the `||` gate, the netns branch).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): docker-mode OCI profile — own netns, userns admin caps, rw cgroupfs (#198)"
```

---

### Task 4: Guest datapath — veth, prerouting nft, resolv.conf (izba-init)

**Files:**
- Create: `crates/izba-init/src/veth.rs` (argv builders + pure helpers, host-testable; guest apply fn `#[mutants::skip]`)
- Modify: `crates/izba-init/src/egress.rs` (ruleset text fn + prerouting chain)
- Modify: `crates/izba-init/src/oci.rs` (extract container PID from `crun state` JSON)
- Modify: `crates/izba-init/src/net.rs` (docker-mode host-side configure variant)
- Modify: `crates/izba-init/src/main.rs` (read `izba.docker`, docker-mode branches: net configure, resolv.conf, nft, post-launch veth wiring)

**Interfaces:**
- Consumes: `izba.docker=1` cmdline (Task 3); `/sbin/ip` (PR 1); `net::GUEST_IP`/`net::RESOLVER_IP`; `oci::launch_container()` flow.
- Produces: `veth::commands(container_pid: u32) -> Vec<Vec<String>>` (the full `/sbin/ip` invocation plan); `veth::apply(container_pid: u32) -> io::Result<()>` (guest-only); `egress::ruleset(docker: bool) -> String` (replaces direct `NFT_RULESET` use; the const stays as the base text); `egress::apply_nft(docker: bool)`; `oci::parse_container_pid(json: &str) -> Option<u32>` and `oci::container_pid(id: &str) -> Option<u32>` (guest-only wrapper); `net::configure(docker: bool)` behavior split. Task 5 consumes `container_pid`; Task 6 consumes the docker flag plumbing pattern.

- [ ] **Step 1: Write the failing tests**

`oci.rs` tests (next to `parse_container_state` tests):

```rust
#[test]
fn parse_container_pid_extracts_integer_field() {
    let json = r#"{"ociVersion":"1.0.2","id":"izba","pid":423,"status":"running"}"#;
    assert_eq!(parse_container_pid(json), Some(423));
}

#[test]
fn parse_container_pid_absent_or_zero_is_none() {
    assert_eq!(parse_container_pid(r#"{"id":"izba","status":"stopped"}"#), None);
    // crun reports pid 0 for a stopped container — not a usable PID.
    assert_eq!(parse_container_pid(r#"{"pid":0,"status":"stopped"}"#), None);
    assert_eq!(parse_container_pid(""), None);
}
```

New `veth.rs` tests:

```rust
#[test]
fn commands_wire_both_netns_with_the_canonical_addresses() {
    let cmds = commands(423);
    let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
    // Pair created init-side, one end pushed into the container netns by PID.
    assert!(flat.iter().any(|c| c.contains("link add") && c.contains("type veth")));
    assert!(flat.iter().any(|c| c.contains("netns 423")));
    // Init side gets RESOLVER_IP, container side GUEST_IP with default route back.
    assert!(flat.iter().any(|c| c.contains(&format!("{}/24", crate::net::RESOLVER_IP))));
    assert!(flat.iter().any(|c| c.contains(&format!("{}/24", crate::net::GUEST_IP))));
    assert!(flat.iter().any(|c| c.contains("route add default via")
        && c.contains(&crate::net::RESOLVER_IP.to_string())));
    // Every command is a /sbin/ip invocation (single vendored binary).
    assert!(cmds.iter().all(|c| c[0] == IP_PATH));
    // Container-side commands enter the netns via the PID-derived /proc path.
    assert!(flat.iter().any(|c| c.contains("/proc/423/ns/net")));
}

#[test]
fn commands_bring_up_loopback_inside_container_netns() {
    let flat: Vec<String> = commands(7).iter().map(|c| c.join(" ")).collect();
    assert!(flat.iter().any(|c| c.contains("/proc/7/ns/net") && c.contains("lo") && c.contains("up")));
}
```

`egress.rs` tests:

```rust
#[test]
fn ruleset_without_docker_is_the_base_const() {
    assert_eq!(ruleset(false), NFT_RULESET);
}

#[test]
fn ruleset_with_docker_adds_prerouting_chain() {
    let r = ruleset(true);
    assert!(r.starts_with(NFT_RULESET.trim_end_matches('\n')) || r.contains("chain output"),
        "base output chain must remain");
    assert!(r.contains("type nat hook prerouting"));
    // Same interception surface as the output chain, veth-delivered.
    assert!(r.contains("tcp dport 53 redirect to :53"));
    assert!(r.contains("udp dport 53 redirect to :53"));
    assert!(r.contains(&format!("tcp dport != 53 redirect to :{REDIRECT_PORT}")));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init parse_container_pid commands_wire ruleset_with`
Expected: compile failure.

- [ ] **Step 3: Implement**

`oci.rs`: `parse_container_pid` — substring scan for `"pid"` mirroring `extract_status_field`'s technique but reading an unquoted integer; `None` for absent/0/unparseable. Guest wrapper `container_pid(id)` shells `crun state` like `container_state` does (`#[mutants::skip]` with the same guest-only reason).

`veth.rs` (new module, `mod veth;` in main.rs/lib):

```rust
//! Docker-mode veth datapath (spec §3): wire the workload container's own
//! netns to init's with a veth pair carrying the SAME addresses the shared
//! netns used (RESOLVER_IP init-side as the gateway, GUEST_IP container-
//! side), so the workload-visible network contract is unchanged while the
//! nft interception point moves structurally out of the workload's reach.

pub const IP_PATH: &str = "/sbin/ip";
pub const VETH_INIT: &str = "veth0";
pub const VETH_CTR: &str = "veth1";

/// The full /sbin/ip invocation plan. Pure — unit-tested; `apply` executes it.
/// Container-netns commands use `ip -n /proc/<pid>/ns/net` — iproute2 resolves
/// a netns argument that is a path directly, no named-netns registration
/// needed (no /var/run/netns in the initramfs).
pub fn commands(container_pid: u32) -> Vec<Vec<String>> { /* build the sequence:
    link add VETH_INIT type veth peer name VETH_CTR
    link set VETH_CTR netns <pid>
    addr add RESOLVER_IP/24 dev VETH_INIT
    link set VETH_INIT up
    -n /proc/<pid>/ns/net link set lo up
    -n /proc/<pid>/ns/net addr add GUEST_IP/24 dev VETH_CTR
    -n /proc/<pid>/ns/net link set VETH_CTR up
    -n /proc/<pid>/ns/net route add default via RESOLVER_IP
*/ }

/// Execute [`commands`] via the vendored static ip. Fail-honest: the first
/// failing command aborts with an error naming it; the caller logs loudly
/// and leaves the sandbox alive/diagnosable (spec §3 failure honesty).
// reason: shells out to /sbin/ip against live netns state — guest-only; the
// command plan is unit-tested via `commands`.
#[mutants::skip]
pub fn apply(container_pid: u32) -> std::io::Result<()> { /* loop Command::new(c[0]).args(&c[1..]).status(), error with the joined argv on failure */ }
```

NOTE for the implementer: if `ip -n <path>` turns out not to accept a /proc path in iproute2 6.12 (it accepts netns NAMES from /var/run/netns), the fallback inside `commands` is `ip netns attach izba <pid>` first (creates the named handle from the PID) and `-n izba` thereafter — adjust the unit tests' expectations to whichever form you emit; verify against the REAL vendored binary with `./dist/ip -n /proc/self/ns/net link show lo` (unsandboxed) BEFORE finalizing, and record which form works in your report.

`egress.rs`:

```rust
/// Docker-mode prerouting chain (spec §3): traffic from the workload's own
/// netns arrives over the veth and traverses prerouting, never output. Same
/// interception surface; REDIRECT rewrites the destination to the ingress
/// interface's address, which is why bind_tcp_redirect binds wildcard.
const NFT_DOCKER_PREROUTING: &str = "\
table ip izba {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 53 redirect to :53
    udp dport 53 redirect to :53
    tcp dport != 53 redirect to :15001
  }
}
";

/// The nft ruleset for this boot: base output chain, plus the prerouting
/// chain when docker mode is on.
pub fn ruleset(docker: bool) -> String { /* NFT_RULESET + optional NFT_DOCKER_PREROUTING */ }
```

and `apply_nft(docker: bool)` writes `ruleset(docker)` (keep the tmpfile + `/sbin/nft -f` shape; update the existing `apply_nft` callers/tests). Use the `REDIRECT_PORT` const in the string via the same `format!`-at-test-time technique the existing ruleset test uses (the const string may keep the literal 15001 with the test asserting via `REDIRECT_PORT`, exactly like `nft_ruleset_shape` does today).

`net.rs`: `configure(docker: bool)`:
- `false` → exactly today's behavior (lo, dummy0 + alias, default route, route_localnet).
- `true` → lo up + `enable_route_localnet()` only; no dummy0, no init-side default route (the veth pair carries RESOLVER_IP once the container starts; anything non-intercepted has no route — the structural deny, now via the missing-route topology). Update the module doc comment; keep `#[mutants::skip]` reasons accurate.

`main.rs` `run_pid1`:
- `let docker = params.get("izba.docker").map(|v| v == "1").unwrap_or(false);` next to the `izba.usb` read.
- `net::configure(docker)`; `write_resolv_conf(docker)` (nameserver = `RESOLVER_IP` when docker, `DNS_LOOPBACK` otherwise — update the fn + its doc, and the loopback-rationale comment gets a docker-mode exception note); `bring_up_egress` passes `docker` through to `apply_nft(docker)`.
- After `oci::launch_container()` (which already blocks until running): a docker-mode block:

```rust
if docker {
    match izba_init::oci::container_pid(izba_init::oci::CONTAINER_ID) {
        Some(pid) => {
            if let Err(e) = izba_init::veth::apply(pid) {
                eprintln!("izba-init: *** DOCKER-MODE VETH SETUP FAILED *** {e}; the container has no network");
            }
        }
        None => eprintln!("izba-init: *** DOCKER-MODE VETH SETUP SKIPPED *** container pid unavailable (container not running?)"),
    }
}
```

- [ ] **Step 4: Suite + mutation check**

Run: `cargo test -p izba-init` then (unsandboxed, backgrounded) `cargo mutants -p izba-init -f crates/izba-init/src/veth.rs -f crates/izba-init/src/egress.rs -f crates/izba-init/src/oci.rs --no-shuffle 2>&1 | tail -5`
Expected: PASS; no MISSED in the new pure fns.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/veth.rs crates/izba-init/src/egress.rs crates/izba-init/src/oci.rs crates/izba-init/src/net.rs crates/izba-init/src/main.rs
git commit -m "feat(init): docker-mode guest datapath — veth pair, prerouting nft, veth-gateway DNS (#198)"
```

---

### Task 5: Cgroup delegation + engine auto-start (izba-init)

**Files:**
- Create: `crates/izba-init/src/docker.rs` (delegation path/plan helpers + dockerd exec argv, host-testable; guest apply fns `#[mutants::skip]`)
- Modify: `crates/izba-init/src/main.rs` (extend the Task-4 docker-mode post-launch block)

**Interfaces:**
- Consumes: `oci::container_pid` (Task 4), `oci::crun_exec_argv` + `oci::detect_cgroup_manager` (existing), `exec.rs`'s `Command::spawn` fire-and-forget pattern.
- Produces: `docker::delegation_plan(container_cgroup: &str) -> Vec<(PathBuf, String)>` (which `cgroup.subtree_control` files get which `+controller` writes); `docker::apply_delegation(cgroup_root: &Path, container_cgroup: &str) -> io::Result<()>` (testable against a tempdir fake cgroupfs); `docker::dockerd_exec_argv(cgroup_manager: CgroupManager) -> Vec<String>`; `docker::start_engine()` (guest-only spawn).

- [ ] **Step 1: Write the failing tests** (docker.rs)

```rust
#[test]
fn delegation_plan_enables_controllers_down_the_chain() {
    // Container cgroup "/izba" ⇒ enable controllers in the root's
    // subtree_control so /izba can create controller-bearing children.
    let plan = delegation_plan("/izba");
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, std::path::PathBuf::from("cgroup.subtree_control"));
    assert_eq!(plan[0].1, "+cpu +memory +pids +io");
    // Nested container cgroup ⇒ every ancestor below the root, plus the root.
    let plan = delegation_plan("/a/b");
    let files: Vec<_> = plan.iter().map(|(p, _)| p.to_string_lossy().into_owned()).collect();
    assert_eq!(files, vec!["cgroup.subtree_control", "a/cgroup.subtree_control"]);
}

#[test]
fn apply_delegation_writes_fake_cgroupfs() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("izba")).unwrap();
    std::fs::write(root.path().join("cgroup.subtree_control"), "").unwrap();
    apply_delegation(root.path(), "/izba").unwrap();
    assert_eq!(
        std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap(),
        "+cpu +memory +pids +io"
    );
}

#[test]
fn apply_delegation_missing_file_is_reported() {
    let root = tempfile::tempdir().unwrap();
    assert!(apply_delegation(root.path(), "/izba").is_err());
}

#[test]
fn dockerd_exec_argv_runs_engine_as_root_with_honest_logging() {
    let argv = dockerd_exec_argv(crate::oci::CgroupManager::Cgroupfs);
    assert_eq!(argv[0], crate::oci::CRUN_PATH);
    let joined = argv.join(" ");
    assert!(joined.contains("exec"));
    assert!(joined.contains("--user 0:0"), "engine starts as container root");
    // The in-container command: probe for dockerd, log honestly either way.
    let cmd = argv.last().unwrap();
    assert!(cmd.contains("command -v dockerd"), "must probe before exec");
    assert!(cmd.contains(ENGINE_LOG), "stdout/err to the honest log file");
    assert!(cmd.contains("exec dockerd"), "engine replaces the probe shell");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init delegation_plan apply_delegation dockerd_exec_argv`
Expected: compile failure.

- [ ] **Step 3: Implement**

```rust
//! Docker-mode engine plumbing (spec §2 delegation + §5 auto-start).

/// In-container log for the auto-started engine — the honest record when
/// dockerd is missing or dies (no auto-restart; restart = sandbox restart).
pub const ENGINE_LOG: &str = "/var/log/izba-dockerd.log";
const CONTROLLERS: &str = "+cpu +memory +pids +io";

/// The subtree_control writes that let the container cgroup create
/// controller-bearing children: the root and every ancestor of the
/// container cgroup (exclusive of the container cgroup itself — crun/the
/// engine manage below that point). Pure; `apply_delegation` executes.
pub fn delegation_plan(container_cgroup: &str) -> Vec<(std::path::PathBuf, String)> { /* walk ancestors */ }

/// Execute the plan against `cgroup_root` (/sys/fs/cgroup in the guest; a
/// tempdir in tests). Controllers a kernel lacks make the write fail — the
/// caller treats delegation failure as loud-but-nonfatal (dockerd still
/// starts; nested limits degrade honestly).
pub fn apply_delegation(cgroup_root: &std::path::Path, container_cgroup: &str) -> std::io::Result<()> { /* write each plan entry */ }

/// `crun exec` argv that starts the engine detached-by-spawn: probe for
/// dockerd, log honestly if absent, else exec it with output to ENGINE_LOG.
pub fn dockerd_exec_argv(cgroup_manager: crate::oci::CgroupManager) -> Vec<String> {
    let script = format!(
        "mkdir -p /var/log; if command -v dockerd >/dev/null 2>&1; then exec dockerd >>{ENGINE_LOG} 2>&1; else echo 'izba: docker mode is on but the image ships no dockerd' >>{ENGINE_LOG}; fi"
    );
    crate::oci::crun_exec_argv(cgroup_manager, false, "/", &[], Some("0:0"),
        &["/bin/sh".into(), "-c".into(), script])
}

/// Spawn the engine fire-and-forget (Command::spawn is non-blocking; a dead
/// dockerd stays dead — no auto-restart philosophy).
// reason: forks a live /sbin/crun against the running container — guest-only;
// the argv is unit-tested via dockerd_exec_argv.
#[mutants::skip]
pub fn start_engine() { /* build argv with detect_cgroup_manager(), Command::new(argv[0]).args(..).spawn(), log spawn errors loudly, do not wait */ }
```

For the container cgroup path: read `/proc/<pid>/cgroup` (format `0::/<path>`) in a small pure parser `pub fn parse_cgroup_path(proc_cgroup: &str) -> Option<String>` + test (`"0::/izba\n"` → `Some("/izba")`); the guest-side glue reads the real file. Extend the main.rs docker-mode block (after veth):

```rust
let cgroup_path = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
    .and_then(|s| izba_init::docker::parse_cgroup_path(&s));
match cgroup_path {
    Some(cg) => if let Err(e) = izba_init::docker::apply_delegation(std::path::Path::new("/sys/fs/cgroup"), &cg) {
        eprintln!("izba-init: docker-mode cgroup delegation incomplete: {e} (nested container limits degraded)");
    },
    None => eprintln!("izba-init: docker-mode cgroup delegation skipped: container cgroup unknown"),
}
izba_init::docker::start_engine();
```

- [ ] **Step 4: Suite + mutation check**

Run: `cargo test -p izba-init` then (unsandboxed, backgrounded) `cargo mutants -p izba-init -f crates/izba-init/src/docker.rs --no-shuffle 2>&1 | tail -5`
Expected: PASS; no MISSED in the pure fns.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/docker.rs crates/izba-init/src/main.rs
git commit -m "feat(init): docker-mode cgroup delegation + engine auto-start (#198)"
```

---

### Task 6: `tcp_dial` veth fallback

**Files:**
- Modify: `crates/izba-init/src/server.rs` (`tcp_dial` ~line 287-339, `stream_conn` ~line 160-178, `serve_streams` signature; tests ~line 651+)
- Modify: `crates/izba-init/src/main.rs` (pass the docker flag into `serve_streams`)

**Interfaces:**
- Consumes: the `docker: bool` from cmdline (Task 4), `net::GUEST_IP`.
- Produces: `tcp_dial(conn, port, fallback: Option<Ipv4Addr>)` — dial `127.0.0.1:port` first; on any connect error with a fallback set, dial `fallback:port` before giving up; `serve_streams(..., docker: bool)` threads `docker.then_some(net::GUEST_IP)` down. sshd (init-netns loopback :22) keeps working; docker-published ports (workload netns) become reachable.

- [ ] **Step 1: Write the failing tests** (server.rs tests — follow the existing `full_connect_via_listener`-style runtime-skip pattern for listener binds)

```rust
#[test]
fn tcp_dial_falls_back_to_secondary_address() {
    // Loopback port with no listener refuses; the fallback listener on a
    // second loopback address (127.0.0.2 — still 127/8, bindable without
    // extra setup) must then receive the dial. Runtime-skip on bind EPERM.
    let l = match std::net::TcpListener::bind(("127.0.0.2", 0)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind: {e}"),
    };
    let port = l.local_addr().unwrap().port();
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let t = std::thread::spawn(move || {
        // Frame writer side: read the Response frame after dialing.
        let mut conn = a;
        izba_proto::write_frame(&mut conn, &izba_proto::StreamOpen::TcpDial { port }).unwrap();
        let resp: izba_proto::Response = izba_proto::read_frame(&mut conn).unwrap();
        matches!(resp, izba_proto::Response::Ok)
    });
    stream_conn_for_test(b, Some(std::net::Ipv4Addr::new(127, 0, 0, 2)));
    let _ = l.accept();
    assert!(t.join().unwrap());
}

#[test]
fn tcp_dial_without_fallback_reports_connect_failed() {
    // No listener anywhere, no fallback → single loopback attempt, Error frame.
    // (Adapt from the existing refused-port test at ~line 695; it changes only
    // by the new None argument.)
}
```

(The exact harness shape must follow how the existing `tcp_dial` tests drive it — the scout notes tests at server.rs:651/695 dial live loopback listeners through the frame protocol; mirror their setup precisely, including any helper they use instead of `stream_conn_for_test`. Adjust names to what exists; the load-bearing assertions are: fallback address receives the connection after loopback refuses, and no-fallback behavior is unchanged.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init tcp_dial`
Expected: compile failure (new parameter) — then adapt existing tcp_dial tests with `None`.

- [ ] **Step 3: Implement**

`tcp_dial(conn, port, fallback: Option<Ipv4Addr>)`: attempt `127.0.0.1:port` with the existing 10s cap; on `Err(first)` and `Some(ip)`, attempt `ip:port` with the same cap; only if both fail write the Error frame (message should name both attempts: `"127.0.0.1:{port}: {first}; {ip}:{port}: {second}"`). Doc comment: docker mode's workload listeners (including docker-proxy published ports) live in the container netns at GUEST_IP; init-netns services (sshd :22) stay on loopback — loopback first preserves them, the fallback reaches the workload. Thread the flag: `serve_streams` gains `docker: bool`, `stream_conn` gains `fallback: Option<Ipv4Addr>` (computed once as `docker.then_some(net::GUEST_IP)`), main.rs passes the Task-4 `docker` bool.

- [ ] **Step 4: Suite**

Run: `cargo test -p izba-init`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/server.rs crates/izba-init/src/main.rs
git commit -m "feat(init): tcp_dial falls back to the workload veth address in docker mode (#198)"
```

---

### Task 7: KVM e2e — DinD journey + netlog honesty + port reach-through

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (new docker-mode test(s); dedicated image fixture per the nginx-unprivileged precedent ~line 787-803)
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (docker `-p` + `izba port publish` reach-through test)

**Interfaces:**
- Consumes: everything from Tasks 1-6; `IZBA_INTEGRATION=1` gates; `egress-audit.jsonl` read pattern (integration.rs:1343); console.log dump-on-failure pattern (daemon_e2e.rs:514-533).
- Produces: the honest gates for docker mode. These tests are env-gated and self-skip without KVM — CI runs them in e2e.yml.

- [ ] **Step 1: Write the integration test** (TDD here = write it, watch it fail against the real VM for a real reason, then fix what it exposes)

In `integration.rs`, a `docker_mode_engine_runs_containers` test, gated like the others, using a DEDICATED pinned fixture image `docker:28-dind` (resolve the current `docker:28-dind` digest at implementation time with `docker manifest inspect docker:28-dind` or skopeo, pin `docker@sha256:...` in a const with a comment naming the tag it was resolved from — never a floating tag):

1. Create the sandbox with docker mode ON (whatever the harness's create path takes — `CreateOpts { docker: true, .. }`), 2 cpus / 2048 MB (dockerd is hungry), start it.
2. Poll-exec `docker info --format '{{.ServerVersion}}'` (as root) until it succeeds or ~60s elapses — this proves: engine auto-start ran, veth+DNS up, /var/lib/docker volume mounted (overlay2 driver working implies non-overlayfs backing — additionally assert `docker info --format '{{.Driver}}'` == `overlay2`).
3. `docker run --rm hello-world` — proves inner-container pull through the egress plane + nested runc under the delegated cgroups + userns-scoped caps suffice.
4. Read `logs/<name>/egress-audit.jsonl` (the integration.rs:1343 pattern) and assert records exist for `registry-1.docker.io` (or `auth.docker.io`) — the netlog-honesty assertion: inner-container egress is policy-visible.
5. On any failure, dump the serial console tail AND `crun exec cat /var/log/izba-dockerd.log` for diagnosis before asserting.

Also a cheap negative: `docker_mode_off_keeps_shared_netns` — boot the standard alpine fixture WITHOUT docker and assert `exec ip route`-equivalent behavior unchanged? SKIP — the entire existing suite already covers non-docker sandboxes; do not add a redundant boot. (Explicitly noting the non-goal so the implementer doesn't invent it.)

- [ ] **Step 2: Write the daemon_e2e test**

`docker_publish_reaches_inner_container`: create+start a docker-mode sandbox (CLI `--docker`, the dind fixture), wait for `docker info`, `docker run -d -p 8080:80 <tiny http image — use hello-world? no: use the dind image's own registry? Simplest honest choice: run `docker run -d -p 8080:80 nginx:alpine` pinned by digest>`, then `izba port publish 18080:8080`, then GET `127.0.0.1:18080` from the host (the daemon_e2e HTTP-probe pattern if one exists, else a plain TcpStream connect + minimal GET) and assert a response arrives — proving host → daemon relay → TcpDial loopback-miss → veth fallback → docker-proxy → inner container end-to-end. Reuse the console-dump-on-failure pattern.

- [ ] **Step 3: Build artifacts + run both suites locally** (unsandboxed, backgrounded with log polling)

The worktree already has `dist/vmlinux` (docker-capable, PR 1) and the full-embed initramfs — REBUILD the initramfs first anyway (`izba-init` changed in Tasks 4-6): musl-build izba-init, then `hack/build-initramfs.sh` with the full IZBA_* set from the Task-5a harvest + `IZBA_IP=dist/ip`. Then:
`IZBA_INTEGRATION=1 IZBA_KERNEL=$PWD/dist/vmlinux IZBA_INITRAMFS=$PWD/dist/initramfs.cpio.gz cargo test -p izba-core --test integration -- --test-threads=1`
and the same env for `cargo test -p izba-cli --test daemon_e2e -- --test-threads=1`.
Expected: everything green including the new docker tests. Iterate on real failures — this step is where the datapath earns its keep; budget for several fix→reboot cycles (veth ordering, DNS from dockerd, cgroup delegation gaps). Record every product fix made during iteration in the report.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/tests/integration.rs crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(e2e): docker-mode DinD journey — engine boot, inner pull, netlog, port reach-through (#198)"
```

(Plus separate `fix(...)` commits for anything Step 3's iteration exposed, each with its own message.)

---

### Task 8: Gates, delivery, CI iteration

**Files:** none new — the branch `worktree-docker-mode`.

- [ ] **Step 1: All six workspace gates + app gate** (Global Constraints, verbatim). Expected: green.
- [ ] **Step 2: Full local KVM reruns** of both suites (Task 7 env) — final confirmation on the exact HEAD. Expected: green.
- [ ] **Step 3: Push + PR**

```bash
git push -u origin worktree-docker-mode
gh pr create -R Lupus/izba --title "Docker mode: run Docker inside a sandbox (#198)" --body "..."
```

PR body: spec reference (§§1-5,8), what works now (label/flag, own-netns veth datapath with prerouting interception + netlog honesty, auto volume, engine auto-start, port reach-through), the security framing (userns-scoped caps, strictly weaker than builder; egress enforcement structurally unreachable), the e2e evidence, `Closes #198`. NOT draft. End with the Claude Code attribution trailer.

- [ ] **Step 4: Dispatch devbuild** (`bash hack/devbuild.sh`, unsandboxed, background) — record the exact `dist/local/<ts>-<sha>/` path.
- [ ] **Step 5: Iterate CI to CLEAN** — all required checks + Sonar quality gate passed + Greptile satisfied (greploop if needed); rerun known infra flakes; `DIRTY` mergeState = rebase, never quota.
- [ ] **Step 6: Report** — summary, PR link, devbuild path + `sudo dpkg -i` command, and the manual smoke-test recipe (`izba run docker/sandbox-templates:shell-docker`, then `docker run hello-world` inside — label auto-detect exercised manually since CI e2e uses the dind fixture).
