//! Linux host-side confinement mechanism for the cloud-hypervisor driver:
//! capability probing and the fail-closed confinement plan. The cross-platform
//! status surface lives in `confine.rs`.

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
