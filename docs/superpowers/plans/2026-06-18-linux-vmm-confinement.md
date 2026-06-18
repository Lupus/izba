# Linux host-side VMM confinement (MVP-C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Launch cloud-hypervisor + virtiofsd confined on Linux (explicit seccomp, Landlock, virtiofsd sandbox, best-effort rlimits), fail-closed, reusing the Windows jailer's existing `--allow-unconfined`/`ConfinementStatus` plumbing.

**Architecture:** New `procmgr::jail_linux` probes host capabilities (userns/Landlock/seccomp) and builds a `ConfinementPlan` (which flags + the achieved `ConfinementStatus`). The cloud-hypervisor driver consumes the plan: it injects flags into the virtiofsd/CH argv, spawns with `setrlimit`, fails closed when the floor (`seccomp + virtiofsd-sandbox + Landlock`) is unmet and `--allow-unconfined` was not passed, and records the status on the handle. No daemon-proto, CLI, or state.json changes — that plumbing already exists.

**Tech Stack:** Rust, `nix` 0.29 (+ `resource`, `sched` features), `nix::libc` raw syscall for the Landlock ABI probe, cloud-hypervisor v42.0, virtiofsd v1.13.3.

## Global Constraints

- All six workspace gates must stay green: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- `izba-core` MUST compile for `x86_64-pc-windows-gnu`: all new Linux-specific code is `#[cfg(target_os = "linux")]` with a non-Linux compile-parity fallback.
- Conventional commits (`feat(core): …`, `docs(security): …`). TDD: failing test first.
- Never silently downgrade security: fail closed by default; `--allow-unconfined` is the only opt-out and must be loud (the status/CLI surfacing already exists).
- Unit tests never bind real listeners; pure-logic tests only (no KVM) for everything except Task 7.

---

### Task 1: `ConfinementStatus::confined` constructor

A Linux-honest `Restricted` constructor (the existing `applied()` hardcodes Windows token text).

**Files:**
- Modify: `crates/izba-core/src/procmgr/confine.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `ConfinementStatus::confined(reason: &str) -> ConfinementStatus` (mode `ConfinementMode::Restricted`, `reason` verbatim).

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `confine.rs`:

```rust
#[test]
fn confined_constructor_is_restricted_with_verbatim_reason() {
    let s = ConfinementStatus::confined("seccomp+landlock+virtiofs:namespace");
    assert_eq!(s.mode, ConfinementMode::Restricted);
    assert_eq!(s.reason, "seccomp+landlock+virtiofs:namespace");
    assert!(s.summary().starts_with("confined: "));
    assert!(s.is_confined());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-core --lib confined_constructor`
Expected: FAIL — `no function or associated item named 'confined'`.

- [ ] **Step 3: Implement** — add to `impl ConfinementStatus` (next to `degraded`):

```rust
    /// Restricted confinement with a caller-supplied reason. Used by the Linux
    /// realisation, whose reason text (layer list) differs from the Windows
    /// token-shaped `applied()`.
    pub fn confined(reason: &str) -> Self {
        Self {
            mode: ConfinementMode::Restricted,
            reason: reason.to_string(),
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-core --lib confined_constructor`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/procmgr/confine.rs
git commit -m "feat(core): add ConfinementStatus::confined for non-Windows realisations"
```

---

### Task 2: `jail_linux` capability probe

Detect userns / Landlock / seccomp on the host. Linux-gated with a non-Linux stub.

**Files:**
- Create: `crates/izba-core/src/procmgr/jail_linux.rs`
- Modify: `crates/izba-core/src/procmgr/mod.rs` (module decl + re-export)
- Modify: `crates/izba-core/Cargo.toml` (add `resource`, `sched` to the unix `nix` features)
- Test: in `jail_linux.rs`

**Interfaces:**
- Produces: `pub struct Capabilities { pub userns: bool, pub landlock: bool, pub seccomp: bool }` and `Capabilities::probe() -> Capabilities`.

- [ ] **Step 1: Add nix features.** In `crates/izba-core/Cargo.toml`, change the unix nix line to:

```toml
nix = { version = "0.29", features = ["process", "signal", "resource", "sched"] }
```

- [ ] **Step 2: Declare the module.** In `crates/izba-core/src/procmgr/mod.rs`, after the `confine` block add:

```rust
#[cfg(target_os = "linux")]
pub mod jail_linux;
```

- [ ] **Step 3: Write the failing test** — create `crates/izba-core/src/procmgr/jail_linux.rs` with only:

```rust
//! Linux host-side confinement mechanism for the cloud-hypervisor driver:
//! capability probing and the fail-closed confinement plan. The cross-platform
//! status surface lives in `confine.rs`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_self_consistent_and_total() {
        // Must not panic in any environment; seccomp is universally available on
        // a seccomp-capable kernel, so it is true wherever the test suite runs.
        let caps = Capabilities::probe();
        assert!(caps.seccomp, "seccomp filter mode is expected on CI/dev hosts");
        // userns/landlock are environment-dependent; just assert they are read
        // without panicking (booleans already are).
        let _ = (caps.userns, caps.landlock);
    }
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cargo test -p izba-core --lib jail_linux::tests::probe_is_self_consistent`
Expected: FAIL — `cannot find type 'Capabilities'`.

- [ ] **Step 5: Implement the probe.** Prepend to `jail_linux.rs` (above the test module):

```rust
use nix::libc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub userns: bool,
    pub landlock: bool,
    pub seccomp: bool,
}

impl Capabilities {
    pub fn probe() -> Self {
        Self {
            userns: probe_userns(),
            landlock: probe_landlock(),
            seccomp: probe_seccomp(),
        }
    }
}

/// Fork a child that attempts `unshare(CLONE_NEWUSER)`; the child exits 0 on
/// success. This is the only reliable cross-distro signal — reading
/// `user.max_user_namespaces` alone misses AppArmor/seccomp gating.
fn probe_userns() -> bool {
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    // SAFETY: the child does no allocation before _exit; it only calls unshare
    // and _exit, both async-signal-safe.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = if unshare(CloneFlags::CLONE_NEWUSER).is_ok() { 0 } else { 1 };
            unsafe { libc::_exit(code) };
        }
        Ok(ForkResult::Parent { child }) => {
            matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
        }
        Err(_) => false,
    }
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
/// the ABI version (>=1) when the LSM is active, or -1/ENOSYS/EOPNOTSUPP when it
/// is absent. The canonical capability probe.
fn probe_landlock() -> bool {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    // SAFETY: a pure capability query; NULL attr + 0 size + the VERSION flag is
    // the documented no-op probe form and creates no ruleset fd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    ret >= 1
}

/// `prctl(PR_GET_SECCOMP)` succeeds on any seccomp-capable kernel (returns the
/// current mode, 0 when unconfined). Failure means no seccomp support.
fn probe_seccomp() -> bool {
    // SAFETY: PR_GET_SECCOMP takes no pointer args; pure query.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
}
```

- [ ] **Step 6: Add the non-Linux compile-parity stub.** In `crates/izba-core/src/procmgr/mod.rs`, after the `#[cfg(target_os = "linux")] pub mod jail_linux;` line add:

```rust
/// Non-Linux compile parity: cloud-hypervisor only runs on Linux, but
/// `izba-core` is cross-checked for `x86_64-pc-windows-gnu`. The CH driver
/// references these names; on non-Linux they report no capabilities.
#[cfg(not(target_os = "linux"))]
pub mod jail_linux {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Capabilities {
        pub userns: bool,
        pub landlock: bool,
        pub seccomp: bool,
    }
    impl Capabilities {
        pub fn probe() -> Self {
            Self { userns: false, landlock: false, seccomp: false }
        }
    }
}
```

- [ ] **Step 7: Run test + cross-check**

Run: `cargo test -p izba-core --lib jail_linux`
Expected: PASS.
Run: `cargo check --target x86_64-pc-windows-gnu -p izba-core`
Expected: compiles.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-core/src/procmgr/jail_linux.rs crates/izba-core/src/procmgr/mod.rs crates/izba-core/Cargo.toml Cargo.lock
git commit -m "feat(core): probe host userns/Landlock/seccomp capabilities (jail_linux)"
```

---

### Task 3: `jail_linux::plan` — floor logic + plan types

Compute the confinement plan: which flags, fail-closed decision, achieved status.

**Files:**
- Modify: `crates/izba-core/src/procmgr/jail_linux.rs` (+ the non-Linux stub in `mod.rs`)
- Test: in `jail_linux.rs`

**Interfaces:**
- Consumes: `Capabilities` (Task 2), `ConfinementStatus::{confined,degraded}` (Task 1).
- Produces:
  - `pub enum VirtiofsdSandbox { Namespace, Chroot, None }` with `pub fn as_arg(&self) -> &'static str` (`"namespace"`/`"chroot"`/`"none"`).
  - `pub struct ResourceLimits { pub address_space: Option<u64>, pub nofile: Option<u64>, pub nproc: Option<u64> }` with `pub fn for_vmm(mem_mb: u64) -> Self`.
  - `pub struct ConfinementPlan { pub virtiofsd_sandbox: VirtiofsdSandbox, pub ch_seccomp: bool, pub ch_landlock: bool, pub rlimits: ResourceLimits, pub status: crate::procmgr::ConfinementStatus }`.
  - `pub fn plan(caps: &Capabilities, allow_unconfined: bool, mem_mb: u64) -> anyhow::Result<ConfinementPlan>`.

- [ ] **Step 1: Write the failing tests** — add to the `tests` module:

```rust
use crate::procmgr::ConfinementMode;

fn caps(userns: bool, landlock: bool, seccomp: bool) -> Capabilities {
    Capabilities { userns, landlock, seccomp }
}

#[test]
fn full_floor_yields_restricted_with_namespace() {
    let p = plan(&caps(true, true, true), false, 2048).unwrap();
    assert_eq!(p.virtiofsd_sandbox, VirtiofsdSandbox::Namespace);
    assert!(p.ch_seccomp && p.ch_landlock);
    assert_eq!(p.status.mode, ConfinementMode::Restricted);
    assert!(p.status.reason.contains("seccomp"));
    assert!(p.status.reason.contains("landlock"));
    assert!(p.status.reason.contains("namespace"));
}

#[test]
fn missing_landlock_fails_closed_with_actionable_error() {
    let err = plan(&caps(true, false, true), false, 2048).unwrap_err().to_string();
    assert!(err.to_lowercase().contains("landlock"), "names the failed leg: {err}");
    assert!(err.contains("--allow-unconfined"), "names the override: {err}");
}

#[test]
fn allow_unconfined_downgrades_to_none_not_error() {
    let p = plan(&caps(true, false, true), true, 2048).unwrap();
    assert_eq!(p.status.mode, ConfinementMode::None);
    // Best-effort flags still set for whatever was available.
    assert!(p.ch_seccomp);
    assert!(!p.ch_landlock);
}

#[test]
fn no_userns_falls_back_then_fails_floor() {
    // No userns and (in test) no chroot capability => sandbox None => floor fails.
    let err = plan(&caps(false, true, true), false, 2048).unwrap_err().to_string();
    assert!(err.to_lowercase().contains("virtiofs"), "names the sandbox leg: {err}");
}

#[test]
fn rlimits_scale_with_mem() {
    let small = ResourceLimits::for_vmm(1024);
    let big = ResourceLimits::for_vmm(8192);
    assert!(big.address_space.unwrap() > small.address_space.unwrap());
    assert!(small.nofile.is_some() && small.nproc.is_some());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib jail_linux`
Expected: FAIL — `cannot find function 'plan'` / types missing.

- [ ] **Step 3: Implement.** Add to `jail_linux.rs` (above the test module):

```rust
use crate::procmgr::ConfinementStatus;
use anyhow::bail;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtiofsdSandbox {
    Namespace,
    Chroot,
    None,
}

impl VirtiofsdSandbox {
    pub fn as_arg(&self) -> &'static str {
        match self {
            VirtiofsdSandbox::Namespace => "namespace",
            VirtiofsdSandbox::Chroot => "chroot",
            VirtiofsdSandbox::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub address_space: Option<u64>,
    pub nofile: Option<u64>,
    pub nproc: Option<u64>,
}

impl ResourceLimits {
    /// Best-effort ceilings (F-28). address_space covers guest RAM plus generous
    /// headroom for CH's own mappings, virtiofs DAX window, and stacks.
    pub fn for_vmm(mem_mb: u64) -> Self {
        const MIB: u64 = 1024 * 1024;
        let headroom_mb = 2048; // CH mappings + DAX + slack
        Self {
            address_space: Some((mem_mb + headroom_mb) * MIB),
            nofile: Some(4096),
            nproc: Some(256),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfinementPlan {
    pub virtiofsd_sandbox: VirtiofsdSandbox,
    pub ch_seccomp: bool,
    pub ch_landlock: bool,
    pub rlimits: ResourceLimits,
    pub status: ConfinementStatus,
}

/// `CAP_SYS_CHROOT` is required for `virtiofsd --sandbox chroot`; an
/// unprivileged user only holds it inside a userns. Outside one this returns
/// false, so a no-userns host fails the virtiofsd floor leg (fail closed).
fn has_chroot_cap() -> bool {
    // Probed cheaply: an effective-cap query would need libcap; instead infer
    // from euid (root has it) — the common privileged-host case. Unprivileged
    // hosts rely on the namespace path.
    nix::unistd::geteuid().is_root()
}

pub fn plan(
    caps: &Capabilities,
    allow_unconfined: bool,
    mem_mb: u64,
) -> anyhow::Result<ConfinementPlan> {
    let sandbox = if caps.userns {
        VirtiofsdSandbox::Namespace
    } else if has_chroot_cap() {
        VirtiofsdSandbox::Chroot
    } else {
        VirtiofsdSandbox::None
    };

    // Floor legs.
    let mut missing: Vec<&str> = Vec::new();
    if !caps.seccomp {
        missing.push("seccomp");
    }
    if !caps.landlock {
        missing.push("Landlock LSM");
    }
    if sandbox == VirtiofsdSandbox::None {
        missing.push("virtiofsd sandbox (needs unprivileged userns or CAP_SYS_CHROOT)");
    }

    let rlimits = ResourceLimits::for_vmm(mem_mb);
    let flags = ConfinementPlan {
        virtiofsd_sandbox: sandbox,
        ch_seccomp: caps.seccomp,
        ch_landlock: caps.landlock,
        rlimits,
        status: ConfinementStatus::degraded("placeholder"), // overwritten below
    };

    if missing.is_empty() {
        let reason = format!(
            "seccomp+landlock+virtiofs:{}+rlimits",
            sandbox.as_arg()
        );
        return Ok(ConfinementPlan {
            status: ConfinementStatus::confined(&reason),
            ..flags
        });
    }

    if !allow_unconfined {
        bail!(
            "host-side VMM confinement floor not met: missing {}. \
             Enable the Landlock LSM (CONFIG_SECURITY_LANDLOCK + boot param \
             lsm=...,landlock) and/or unprivileged user namespaces, \
             or pass --allow-unconfined to launch without confinement (NOT recommended).",
            missing.join(", ")
        );
    }

    // Opted out: report None honestly, listing what DID apply.
    let mut applied: Vec<&str> = Vec::new();
    if caps.seccomp {
        applied.push("seccomp");
    }
    if caps.landlock {
        applied.push("landlock");
    }
    if sandbox != VirtiofsdSandbox::None {
        applied.push("virtiofs-sandbox");
    }
    let detail = if applied.is_empty() {
        "no host-side confinement available".to_string()
    } else {
        format!("--allow-unconfined: floor waived (best-effort: {})", applied.join("+"))
    };
    Ok(ConfinementPlan {
        status: ConfinementStatus::degraded(&detail),
        ..flags
    })
}
```

- [ ] **Step 4: Mirror the new public types in the non-Linux stub.** In `mod.rs`'s `#[cfg(not(target_os = "linux"))] pub mod jail_linux` block, add minimal definitions so the CH driver compiles cross-target:

```rust
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VirtiofsdSandbox { Namespace, Chroot, None }
    impl VirtiofsdSandbox {
        pub fn as_arg(&self) -> &'static str {
            match self {
                VirtiofsdSandbox::Namespace => "namespace",
                VirtiofsdSandbox::Chroot => "chroot",
                VirtiofsdSandbox::None => "none",
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ResourceLimits {
        pub address_space: Option<u64>,
        pub nofile: Option<u64>,
        pub nproc: Option<u64>,
    }
    impl ResourceLimits {
        pub fn for_vmm(_mem_mb: u64) -> Self {
            Self { address_space: None, nofile: None, nproc: None }
        }
    }
    #[derive(Debug, Clone)]
    pub struct ConfinementPlan {
        pub virtiofsd_sandbox: VirtiofsdSandbox,
        pub ch_seccomp: bool,
        pub ch_landlock: bool,
        pub rlimits: ResourceLimits,
        pub status: crate::procmgr::ConfinementStatus,
    }
    pub fn plan(
        _caps: &Capabilities,
        _allow_unconfined: bool,
        _mem_mb: u64,
    ) -> anyhow::Result<ConfinementPlan> {
        Ok(ConfinementPlan {
            virtiofsd_sandbox: VirtiofsdSandbox::None,
            ch_seccomp: false,
            ch_landlock: false,
            rlimits: ResourceLimits::for_vmm(0),
            status: crate::procmgr::ConfinementStatus::degraded(
                "host-side VMM confinement unsupported on this platform",
            ),
        })
    }
```

- [ ] **Step 5: Run tests + both clippy gates**

Run: `cargo test -p izba-core --lib jail_linux`
Expected: PASS (all 6 tests).
Run: `cargo clippy -p izba-core --all-targets -- -D warnings` and `cargo clippy --target x86_64-pc-windows-gnu -p izba-core --all-targets -- -D warnings`
Expected: zero warnings both.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/procmgr/jail_linux.rs crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(core): jail_linux confinement plan with fail-closed floor (F-06/F-07/F-27)"
```

---

### Task 4: rlimits at spawn (`spawn_detached_with_limits`)

Best-effort `setrlimit` in the existing `pre_exec` closure (F-28).

**Files:**
- Modify: `crates/izba-core/src/procmgr/unix.rs`
- Modify: `crates/izba-core/src/procmgr/mod.rs` (re-export)
- Test: in `unix.rs`

**Interfaces:**
- Consumes: `ResourceLimits` (Task 3).
- Produces: `pub fn spawn_detached_with_limits(cmd: &CommandSpec, log: &Path, limits: &crate::procmgr::jail_linux::ResourceLimits) -> anyhow::Result<PidIdentity>`.

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `unix.rs` (follow the existing `spawn_detached` test pattern that runs `/bin/true` / a real command and checks identity):

```rust
#[test]
fn spawn_with_limits_runs_and_returns_identity() {
    use crate::procmgr::jail_linux::ResourceLimits;
    let log = std::env::temp_dir().join(format!("izba-rlimit-{}.log", std::process::id()));
    let cmd = CommandSpec { argv: vec!["/bin/true".to_string()] };
    let limits = ResourceLimits::for_vmm(1024);
    let id = spawn_detached_with_limits(&cmd, &log, &limits).expect("spawn ok");
    assert_ne!(id.pid, 0);
    let _ = std::fs::remove_file(&log);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib spawn_with_limits`
Expected: FAIL — function not found.

- [ ] **Step 3: Implement.** Refactor `spawn_detached` to delegate. Replace the body of `spawn_detached` with a call to the new function passing empty limits, and add the new function. The `pre_exec` closure gains setrlimit calls after `setsid`:

```rust
use crate::procmgr::jail_linux::ResourceLimits;

pub fn spawn_detached(cmd: &CommandSpec, log: &Path) -> anyhow::Result<PidIdentity> {
    spawn_detached_with_limits(cmd, log, &ResourceLimits { address_space: None, nofile: None, nproc: None })
}

/// Like `spawn_detached`, but applies best-effort `setrlimit` ceilings in the
/// child before exec (F-28). Limit failures are swallowed — they must never
/// block a launch, and the closure stays async-signal-safe (no allocation).
pub fn spawn_detached_with_limits(
    cmd: &CommandSpec,
    log: &Path,
    limits: &ResourceLimits,
) -> anyhow::Result<PidIdentity> {
    let logf = File::options()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening log {}", log.display()))?;
    let mut c = Command::new(&cmd.argv[0]);
    c.args(&cmd.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(logf.try_clone()?))
        .stderr(Stdio::from(logf));
    let limits = *limits; // Copy into the closure (ResourceLimits: Copy).
    // SAFETY: setsid(2) and setrlimit(2) are async-signal-safe; no allocation.
    unsafe {
        c.pre_exec(move || {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            apply_rlimits(&limits);
            Ok(())
        });
    }
    let child = c
        .spawn()
        .with_context(|| format!("spawning {:?}", cmd.argv))?;
    let pid = child.id();
    let starttime = proc_starttime(pid)?;
    std::mem::forget(child);
    Ok(PidIdentity { pid, starttime })
}

/// Best-effort: set each `Some` ceiling, ignoring errors (a missing limit must
/// not abort the launch). Soft = hard = requested value.
fn apply_rlimits(limits: &ResourceLimits) {
    use nix::sys::resource::{setrlimit, Resource};
    let set = |res: Resource, v: Option<u64>| {
        if let Some(v) = v {
            let _ = setrlimit(res, v, v);
        }
    };
    set(Resource::RLIMIT_AS, limits.address_space);
    set(Resource::RLIMIT_NOFILE, limits.nofile);
    set(Resource::RLIMIT_NPROC, limits.nproc);
}
```

Note: `ResourceLimits` derives `Copy` (Task 3) so the `*limits` move into the closure is valid.

- [ ] **Step 4: Re-export.** In `mod.rs`, add `spawn_detached_with_limits` to the unix re-export line:

```rust
pub use unix::{kill_pid, pid_alive, spawn_detached, spawn_detached_with_limits};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p izba-core --lib procmgr`
Expected: PASS (existing `spawn_detached` tests + the new one).

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/procmgr/unix.rs crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(core): spawn_detached_with_limits applies best-effort rlimits (F-28)"
```

---

### Task 5: inject confinement flags into the CH/virtiofsd argv

`build_invocations` consumes the plan and sets `--sandbox <mode>` + CH `--seccomp`/`--landlock`.

**Files:**
- Modify: `crates/izba-core/src/vmm/cloud_hypervisor.rs` (`build_invocations` sig + body; update its unit-test call sites at ~340/406/480/490/497)
- Test: in `cloud_hypervisor.rs`

**Interfaces:**
- Consumes: `ConfinementPlan` (Task 3).
- Produces: `pub fn build_invocations(spec: &VmSpec, tools: &VmmTools, plan: &crate::procmgr::jail_linux::ConfinementPlan) -> anyhow::Result<Invocations>`.

- [ ] **Step 1: Write the failing test** — add to the test module. Include a small helper that builds a `Restricted` plan:

```rust
fn restricted_plan() -> crate::procmgr::jail_linux::ConfinementPlan {
    use crate::procmgr::jail_linux::{ConfinementPlan, ResourceLimits, VirtiofsdSandbox};
    ConfinementPlan {
        virtiofsd_sandbox: VirtiofsdSandbox::Namespace,
        ch_seccomp: true,
        ch_landlock: true,
        rlimits: ResourceLimits::for_vmm(2048),
        status: crate::procmgr::ConfinementStatus::confined("test"),
    }
}

#[test]
fn invocations_apply_confinement_flags() {
    let spec = base_spec();
    let inv = build_invocations(&spec, &base_tools(), &restricted_plan()).unwrap();
    // virtiofsd sandbox is namespace, never "none".
    let vfsd = &inv.virtiofsd[0].argv;
    let i = vfsd.iter().position(|a| a == "--sandbox").expect("--sandbox present");
    assert_eq!(vfsd[i + 1], "namespace");
    assert!(!vfsd.contains(&"none".to_string()));
    // CH gets explicit seccomp + landlock.
    let w = i_window(&inv.vmm.argv, "--seccomp");
    assert_eq!(w, Some("true".to_string()));
    assert!(inv.vmm.argv.iter().any(|a| a == "--landlock"));
}
```

Add the helper `i_window` near the other test helpers (returns the arg after a flag):

```rust
fn i_window(argv: &[String], flag: &str) -> Option<String> {
    argv.iter().position(|a| a == flag).and_then(|i| argv.get(i + 1).cloned())
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib invocations_apply_confinement_flags`
Expected: FAIL — `build_invocations` takes 2 args, not 3.

- [ ] **Step 3: Implement.**
  1. Change the signature to add `plan: &crate::procmgr::jail_linux::ConfinementPlan`.
  2. In the virtiofsd argv builder, replace the two hardcoded lines

     ```rust
     "--sandbox".to_string(),
     "none".to_string(),
     ```

     with

     ```rust
     "--sandbox".to_string(),
     plan.virtiofsd_sandbox.as_arg().to_string(),
     ```
  3. After the `vmm.extend([...])` block that ends with `--api-socket`, before `Ok(Invocations { … })`, append CH confinement flags:

     ```rust
     if plan.ch_seccomp {
         vmm.push("--seccomp".to_string());
         vmm.push("true".to_string());
     }
     if plan.ch_landlock {
         vmm.push("--landlock".to_string());
     }
     ```
  4. Update every in-file test call site (`build_invocations(&spec, &base_tools())`) to pass `&restricted_plan()` as the third arg. Update the existing assertions at ~353/419/433 that check for `--sandbox`/`none`: they should now expect `namespace` (these tests build via `restricted_plan()`); adjust the literal `"none"` expectations to `"namespace"`.

- [ ] **Step 4: Run the full CH unit test module**

Run: `cargo test -p izba-core --lib cloud_hypervisor`
Expected: PASS (all argv tests, including the comma-rejection ones which don't depend on the plan).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/vmm/cloud_hypervisor.rs
git commit -m "feat(core): inject virtiofsd --sandbox + CH --seccomp/--landlock from plan (F-07/F-27)"
```

---

### Task 6: wire the plan into `CloudHypervisorDriver::launch` + handle

Probe → plan (fail closed) → spawn with rlimits → record status.

**Files:**
- Modify: `crates/izba-core/src/vmm/cloud_hypervisor.rs` (`launch`, the `use` line, `ChHandle`, `confinement()`)
- Test: in `cloud_hypervisor.rs` (handle accessor test)

**Interfaces:**
- Consumes: `Capabilities::probe`, `jail_linux::plan`, `spawn_detached_with_limits`, `ConfinementStatus` (Tasks 2–4), `build_invocations` (Task 5).
- Produces: `ChHandle.confinement()` returns the launch-time status; no signature change to the `VmmDriver`/`VmHandle` traits.

- [ ] **Step 1: Write the failing test** — add a handle test mirroring the OpenVMM one (`handle_accessors_report_pids_liveness_and_confinement`):

```rust
#[test]
fn ch_handle_reports_recorded_confinement() {
    let h = ChHandle {
        vsock_sock: std::path::PathBuf::from("/nonexistent/vsock.sock"),
        pids: vec![("vmm".to_string(), crate::procmgr::current_identity().unwrap())],
        confinement: crate::procmgr::ConfinementStatus::confined("seccomp+landlock+virtiofs:namespace"),
    };
    assert_eq!(h.confinement().mode, crate::procmgr::ConfinementMode::Restricted);
    assert!(h.confinement().reason.contains("landlock"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core --lib ch_handle_reports_recorded_confinement`
Expected: FAIL — `ChHandle` has no field `confinement`.

- [ ] **Step 3: Implement.**
  1. Update the `use` at the top: `use crate::procmgr::{kill_pid, pid_alive, spawn_detached_with_limits, jail_linux::Capabilities, ConfinementStatus};` (drop the now-unused `spawn_detached` if no longer referenced — keep it if other call sites in the file still use it).
  2. Add the field to the struct:

     ```rust
     struct ChHandle {
         vsock_sock: PathBuf,
         pids: Vec<(String, PidIdentity)>,
         confinement: ConfinementStatus,
     }
     ```
  3. In `launch`, near the top (after `create_dir_all(&spec.run_dir)`), build the plan and use it:

     ```rust
     let caps = Capabilities::probe();
     let plan = crate::procmgr::jail_linux::plan(&caps, spec.allow_unconfined, spec.mem_mb)
         .context("host-side VMM confinement")?;
     let inv = build_invocations(spec, &tools, &plan)?;
     ```

     (Remove the old `let inv = build_invocations(spec, &tools)?;` line at ~149.)
  4. Replace both `spawn_detached(cmd, &log)` / `spawn_detached(&inv.vmm, …)` calls with `spawn_detached_with_limits(cmd, &log, &plan.rlimits)` and `spawn_detached_with_limits(&inv.vmm, &log_dir.join("vmm.log"), &plan.rlimits)`.
  5. Set the field when building the handle:

     ```rust
     Ok(Box::new(ChHandle {
         vsock_sock: spec.run_dir.join("vsock.sock"),
         pids,
         confinement: plan.status,
     }))
     ```
  6. Replace `confinement()`'s body with `self.confinement.clone()`.

- [ ] **Step 4: Run + all six gates locally**

Run: `cargo test -p izba-core --lib cloud_hypervisor`
Expected: PASS.
Run: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli && cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/vmm/cloud_hypervisor.rs
git commit -m "feat(core): launch cloud-hypervisor confined, fail-closed (F-06-Linux)"
```

---

### Task 7: KVM integration test — confined boot + fail-closed negative

**Files:**
- Modify: `crates/izba-core/tests/integration.rs`

**Interfaces:**
- Consumes: the public sandbox/launch API used by existing integration tests; `VmHandle::confinement()`.

- [ ] **Step 1: Write the integration tests** (env-gated; follow the existing `IZBA_INTEGRATION` skip pattern in that file). Add:

```rust
#[test]
fn confined_boot_reports_restricted_when_landlock_present() {
    if std::env::var("IZBA_INTEGRATION").is_err() {
        eprintln!("skipping: IZBA_INTEGRATION not set");
        return;
    }
    // Probe first; if the host lacks Landlock, this environment can't reach
    // Restricted — skip with a clear reason rather than fail.
    let caps = izba_core::procmgr::jail_linux::Capabilities::probe();
    if !caps.landlock {
        eprintln!("skipping: host kernel has no Landlock LSM (enable CONFIG_SECURITY_LANDLOCK)");
        return;
    }
    // Boot a sandbox (reuse the existing integration helper), assert the VM is
    // alive, /workspace is usable, and confinement is Restricted.
    // <use the same boot helper the other integration tests use>
    // let sb = boot_test_sandbox(...);
    // assert_eq!(sb.handle.confinement().mode, ConfinementMode::Restricted);
}

#[test]
fn floor_failure_refuses_launch_without_allow_unconfined() {
    if std::env::var("IZBA_INTEGRATION").is_err() {
        eprintln!("skipping: IZBA_INTEGRATION not set");
        return;
    }
    // Pure-logic negative usable without KVM: a no-capability plan must error
    // and the message must name the override.
    let caps = izba_core::procmgr::jail_linux::Capabilities { userns: false, landlock: false, seccomp: false };
    let err = izba_core::procmgr::jail_linux::plan(&caps, false, 2048).unwrap_err().to_string();
    assert!(err.contains("--allow-unconfined"));
}
```

Note for the implementer: wire the first test into whatever boot helper `integration.rs` already exposes (read the file's existing tests for the exact constructor/builder and the `ConfinementMode` import path). Keep the negative test as shown — it needs no KVM.

- [ ] **Step 2: Verify it compiles + self-skips without KVM**

Run: `cargo test -p izba-core --test integration -- --test-threads=1`
Expected: tests compile; KVM-dependent test prints its skip line; the negative test PASSES.

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): confined-boot + fail-closed integration coverage"
```

---

### Task 8: docs + findings register + CI Landlock canary

**Files:**
- Modify: `docs/security/findings-2026-06-15.md` (close F-07; mitigate F-06-Linux; add F-27/F-28/F-29)
- Modify: `CLAUDE.md` (load-bearing contracts: confined Linux launch)
- Modify: `docs/testing.md` (host Landlock requirement + WSL2 enable steps)
- Modify: `.github/workflows/e2e.yml` (linux-kvm leg: assert achieved mode or pass `--allow-unconfined` with a canary)

- [ ] **Step 1: Findings register.** In `findings-2026-06-15.md`: change F-07's text to note `--sandbox none` is replaced by `namespace`/`chroot` (CLOSED by MVP-C); annotate F-06 with "Linux: mitigated by built-ins (seccomp+Landlock+sandbox), fail-closed — see 2026-06-18 spec; uid jailer deferred (F-29)". Append F-27/F-28/F-29 using the definitions from §9 of the design spec.

- [ ] **Step 2: CLAUDE.md.** In the "Load-bearing contracts" section, add a bullet: cloud-hypervisor + virtiofsd launch **confined** on Linux (explicit `--seccomp true`, `--landlock`, virtiofsd `--sandbox namespace`/`chroot`, best-effort rlimits); launch **fails closed** if the floor (seccomp+Landlock+sandbox) is unmet unless `--allow-unconfined`; achieved confinement is surfaced in `izba status`.

- [ ] **Step 3: testing.md.** Add a short subsection: Linux confinement needs the **Landlock LSM** active in the host kernel (`CONFIG_SECURITY_LANDLOCK=y` + boot `lsm=...,landlock`); verify with `cat /sys/kernel/security/lsm`. Landlock-less hosts must pass `izba run --allow-unconfined` or they fail closed.

- [ ] **Step 4: e2e.yml canary.** In the linux-kvm job, before/around the integration run, add a step that runs the `confine_probe`-style check (or `cat /sys/kernel/security/lsm`) and, if Landlock is absent, exports the flag the suite reads to pass `--allow-unconfined`; otherwise assert the suite reaches `Restricted`. Keep it a few lines; mirror the existing apparmor/userns sysctl prep already in that workflow.

- [ ] **Step 5: Final full-gate run + commit**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: green.

```bash
git add docs/security/findings-2026-06-15.md CLAUDE.md docs/testing.md .github/workflows/e2e.yml
git commit -m "docs(security): close F-07, mitigate F-06-Linux, register F-27/28/29; CI Landlock canary"
```

---

## Notes for the executor

- **App gate:** `build_invocations`'s signature changes. The `app/src-tauri` build is outside the workspace and embeds `izba-core` by path; it does **not** call `build_invocations` directly (that's internal to the driver), so it should be unaffected — but if the app build is run, confirm it's green.
- **OpenVMM (Windows) path unchanged:** this plan touches only the cloud-hypervisor driver and `not(windows)` code; the Windows jailer keeps its own `spawn_confined` path.
- **`ResourceLimits` must derive `Copy`** (Task 3) for the `pre_exec` closure move in Task 4.
