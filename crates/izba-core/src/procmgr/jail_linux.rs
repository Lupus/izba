//! Linux host-side confinement mechanism for the cloud-hypervisor driver:
//! capability probing and the fail-closed confinement plan. The cross-platform
//! status surface lives in `confine.rs`.

use crate::procmgr::ConfinementStatus;
use anyhow::bail;
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
    // SAFETY: geteuid() is always safe; it has no side effects.
    unsafe { libc::geteuid() == 0 }
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

    let ch_seccomp = caps.seccomp;
    let ch_landlock = caps.landlock;
    let rlimits = ResourceLimits::for_vmm(mem_mb);

    if missing.is_empty() {
        let reason = format!(
            "seccomp+landlock+virtiofs:{}+rlimits",
            sandbox.as_arg()
        );
        return Ok(ConfinementPlan {
            virtiofsd_sandbox: sandbox,
            ch_seccomp,
            ch_landlock,
            rlimits,
            status: ConfinementStatus::confined(&reason),
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
        virtiofsd_sandbox: sandbox,
        ch_seccomp,
        ch_landlock,
        rlimits,
        status: ConfinementStatus::degraded(&detail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procmgr::ConfinementMode;

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
        // Running as root takes the chroot fallback (floor met) instead of failing;
        // this test only exercises the unprivileged no-userns path.
        if has_chroot_cap() {
            eprintln!("skipping: running as root, chroot fallback path taken");
            return;
        }
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
}
