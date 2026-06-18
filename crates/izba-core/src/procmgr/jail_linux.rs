//! Linux host-side confinement mechanism for the cloud-hypervisor driver:
//! capability probing and the fail-closed confinement plan. The cross-platform
//! status surface lives in `confine.rs`.

use crate::procmgr::ConfinementStatus;

// ---------------------------------------------------------------------------
// Data types — compiled on every target so the cloud-hypervisor driver (which
// is cross-checked for `x86_64-pc-windows-gnu`) sees one definition. Only the
// capability probe and `plan()` bodies below are platform-specific.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub userns: bool,
    pub landlock: bool,
    pub seccomp: bool,
}

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
    /// F-28: host resource bounding for the VMM + virtiofsd.
    ///
    /// **No `setrlimit` is applied** — every rlimit ceiling tried here proved
    /// actively harmful to a confined launch, because `setrlimit` limits are
    /// per-process/per-real-uid, not per-sandbox, and fight the components'
    /// legitimate needs:
    /// - `RLIMIT_AS` caps virtual address space; cloud-hypervisor with
    ///   `--memory shared=on` maps the full guest RAM + virtiofs DAX window, so
    ///   any `mem`-derived ceiling OOM-kills the boot (cf. Firecracker, which
    ///   omits it too).
    /// - `RLIMIT_NPROC` is a *system-wide per-real-uid* cap on processes AND
    ///   threads. In the daemonless model the invoking user already runs many
    ///   processes (a real session was observed at 436 threads), so any usable
    ///   ceiling is already exceeded and virtiofsd's `--sandbox namespace`
    ///   sandbox-entry `fork()` dies with EAGAIN before it can create its socket.
    /// - `RLIMIT_NOFILE` would force virtiofsd below the ~1M descriptors it
    ///   raises for itself; both CH and virtiofsd already self-tune their FD
    ///   limits.
    ///
    /// The correct per-sandbox mechanism is a cgroup (pids.max / memory.max),
    /// deferred to the F-28 cgroup follow-up. The fields and `mem_mb` parameter
    /// are kept for that work; today every limit is `None` (a no-op at spawn).
    pub fn for_vmm(_mem_mb: u64) -> Self {
        Self {
            address_space: None,
            nofile: None,
            nproc: None,
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

// ---------------------------------------------------------------------------
// Capability probe — Linux uses real syscalls; every other target reports no
// capabilities (cloud-hypervisor does not run there).
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
impl Capabilities {
    pub fn probe() -> Self {
        Self {
            userns: false,
            landlock: false,
            seccomp: false,
        }
    }
}

#[cfg(target_os = "linux")]
use nix::libc;

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
fn probe_userns() -> bool {
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    // SAFETY: the child does no allocation before _exit; it only calls unshare
    // and _exit, both async-signal-safe.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = if unshare(CloneFlags::CLONE_NEWUSER).is_ok() {
                0
            } else {
                1
            };
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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
fn probe_seccomp() -> bool {
    // SAFETY: PR_GET_SECCOMP takes no pointer args; pure query.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
}

// ---------------------------------------------------------------------------
// Confinement plan — the fail-closed floor logic (Linux), plus a non-Linux stub
// that reports no confinement (cloud-hypervisor does not run there).
// ---------------------------------------------------------------------------

/// `CAP_SYS_CHROOT` is required for `virtiofsd --sandbox chroot`; an
/// unprivileged user only holds it inside a userns. Outside one this returns
/// false, so a no-userns host fails the virtiofsd floor leg (fail closed).
#[cfg(target_os = "linux")]
fn has_chroot_cap() -> bool {
    // Probed cheaply via euid (root has CAP_SYS_CHROOT) — the common
    // privileged-host case; unprivileged hosts rely on the namespace path.
    // This deliberately MISCLASSIFIES a non-root process that holds
    // CAP_SYS_CHROOT via file/ambient capabilities as lacking it (a true
    // effective-cap query would need libcap). The misclassification is
    // fail-closed-safe — such a host would be forced to `--allow-unconfined`
    // rather than silently running unconfined — and izba spawns no
    // setuid/ambient-cap path today; revisit here if that ever changes.
    // SAFETY: geteuid() is always safe; it has no side effects.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
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

    let ch_seccomp = caps.seccomp;
    let ch_landlock = caps.landlock;
    let rlimits = ResourceLimits::for_vmm(mem_mb);

    if missing.is_empty() {
        let reason = format!("seccomp+landlock+virtiofs:{}", sandbox.as_arg());
        return Ok(ConfinementPlan {
            virtiofsd_sandbox: sandbox,
            ch_seccomp,
            ch_landlock,
            rlimits,
            status: ConfinementStatus::confined(&reason),
        });
    }

    if !allow_unconfined {
        anyhow::bail!(
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
        format!(
            "--allow-unconfined: floor waived (best-effort: {})",
            applied.join("+")
        )
    };
    Ok(ConfinementPlan {
        virtiofsd_sandbox: sandbox,
        ch_seccomp,
        ch_landlock,
        rlimits,
        status: ConfinementStatus::degraded(&detail),
    })
}

/// Non-Linux compile parity: cloud-hypervisor only runs on Linux, but the CH
/// driver (and `izba-core`) are cross-checked for `x86_64-pc-windows-gnu`. This
/// stub reports no confinement and is never executed.
#[cfg(not(target_os = "linux"))]
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
        status: ConfinementStatus::degraded(
            "host-side VMM confinement unsupported on this platform",
        ),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::procmgr::ConfinementMode;

    #[test]
    fn probe_is_self_consistent_and_total() {
        // Must not panic in any environment; seccomp is universally available on
        // a seccomp-capable kernel, so it is true wherever the test suite runs.
        let caps = Capabilities::probe();
        assert!(
            caps.seccomp,
            "seccomp filter mode is expected on CI/dev hosts"
        );
        // userns/landlock are environment-dependent; just assert they are read
        // without panicking (booleans already are).
        let _ = (caps.userns, caps.landlock);
    }

    fn caps(userns: bool, landlock: bool, seccomp: bool) -> Capabilities {
        Capabilities {
            userns,
            landlock,
            seccomp,
        }
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
        let err = plan(&caps(true, false, true), false, 2048)
            .unwrap_err()
            .to_string();
        assert!(
            err.to_lowercase().contains("landlock"),
            "names the failed leg: {err}"
        );
        assert!(
            err.contains("--allow-unconfined"),
            "names the override: {err}"
        );
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
        // Running as root takes the chroot fallback (floor met) instead of failing;
        // this test only exercises the unprivileged no-userns path.
        if has_chroot_cap() {
            eprintln!("skipping: running as root, chroot fallback path taken");
            return;
        }
        let err = plan(&caps(false, true, true), false, 2048)
            .unwrap_err()
            .to_string();
        assert!(
            err.to_lowercase().contains("virtiofs"),
            "names the sandbox leg: {err}"
        );
    }

    #[test]
    fn for_vmm_applies_no_rlimits_pending_cgroups() {
        // No setrlimit ceiling is applied: per-uid/per-process rlimits break a
        // confined launch (RLIMIT_NPROC EAGAINs virtiofsd's sandbox fork,
        // RLIMIT_AS OOM-kills CH, RLIMIT_NOFILE starves virtiofsd). Resource
        // bounding is deferred to the F-28 cgroup follow-up — see for_vmm doc.
        let r = ResourceLimits::for_vmm(2048);
        assert!(r.address_space.is_none());
        assert!(r.nofile.is_none());
        assert!(r.nproc.is_none());
    }
}
