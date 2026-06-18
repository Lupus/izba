//! Detached process management with PID-reuse-safe identity.
//!
//! The API is platform-independent; each platform supplies the same three
//! functions. `PidIdentity.starttime` is an opaque equality token: Linux uses
//! `/proc/<pid>/stat` field 22 (clock ticks since boot), Windows uses the
//! process creation `FILETIME`. `state.json` is per-host, so the differing
//! unit never crosses platforms.

pub mod confine;
pub use confine::{
    ConfinementMode, ConfinementPolicy, ConfinementStatus, IntegrityLevel, TokenLevel,
};

#[cfg(target_os = "linux")]
pub mod jail_linux;

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

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::proc_starttime;
#[cfg(unix)]
pub use unix::{kill_pid, pid_alive, spawn_detached};

#[cfg(windows)]
mod jail_windows;
#[cfg(windows)]
pub use jail_windows::{restore_integrity_recursive, set_low_integrity_recursive, spawn_confined};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::proc_starttime;
#[cfg(windows)]
pub use windows::{kill_pid, pid_alive, spawn_detached};

/// Unix fallback so call sites can use `spawn_confined` uniformly: the Linux
/// jailer is a separate work item, so this is a plain detached spawn (the VMM
/// already runs as the invoking user). `_policy` is accepted for signature
/// parity and intentionally unused here. Reports `ConfinementMode::None`
/// honestly — the parity stub does not confine.
#[cfg(not(windows))]
pub fn spawn_confined(
    cmd: &crate::vmm::CommandSpec,
    log: &std::path::Path,
    _policy: &confine::ConfinementPolicy,
) -> anyhow::Result<(crate::state::PidIdentity, confine::ConfinementMode)> {
    Ok((spawn_detached(cmd, log)?, confine::ConfinementMode::None))
}

/// Non-Windows no-op so confined-launch call sites stay platform-uniform. Linux
/// integrity labels are a Windows MIC concept with no equivalent here; the Linux
/// jailer (a separate milestone) handles its own filesystem confinement.
#[cfg(not(windows))]
pub fn set_low_integrity_recursive(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

/// Non-Windows no-op counterpart to the integrity-restore teardown. Mirrors
/// `set_low_integrity_recursive`'s stub: there is no MIC label to undo here.
#[cfg(not(windows))]
pub fn restore_integrity_recursive(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

use crate::state::PidIdentity;

/// PID-reuse-safe identity of the current process. Alive for as long as this
/// process runs, so it is a valid `vmm_pid` for a fabricated `state.json` in
/// tests and test-support tooling.
pub fn current_identity() -> anyhow::Result<PidIdentity> {
    let pid = std::process::id();
    Ok(PidIdentity {
        pid,
        starttime: proc_starttime(pid)?,
    })
}

#[cfg(test)]
mod current_identity_tests {
    use super::*;

    #[test]
    fn current_identity_is_self_and_alive() {
        let id = current_identity().expect("current identity");
        assert_eq!(id.pid, std::process::id());
        assert!(pid_alive(&id), "the current process must read as alive");
    }
}

/// Exercises the non-Windows parity stubs so they are measured, not just
/// compiled. The Windows realisations are covered by `jail_windows.rs`'s own
/// `#[cfg(windows)]` tests (run under the Windows coverage job).
#[cfg(all(test, not(windows)))]
mod non_windows_stub_tests {
    use super::*;
    use crate::vmm::CommandSpec;

    #[test]
    fn integrity_label_helpers_are_noops() {
        // No MIC on this platform: both calls are infallible no-ops.
        let dir = std::env::temp_dir();
        set_low_integrity_recursive(&dir).expect("set_low stub returns Ok");
        restore_integrity_recursive(&dir).expect("restore stub returns Ok");
    }

    #[test]
    fn spawn_confined_delegates_to_detached_reporting_none() {
        // The parity stub spawns the process detached (no confinement) and
        // honestly reports ConfinementMode::None. `/bin/true` exits immediately.
        let log = std::env::temp_dir().join(format!(
            "izba-spawn-confined-stub-{}.log",
            std::process::id()
        ));
        let cmd = CommandSpec {
            argv: vec!["/bin/true".to_string()],
        };
        let (id, mode) = spawn_confined(&cmd, &log, &ConfinementPolicy::vmm_default())
            .expect("stub spawn succeeds");
        assert_ne!(id.pid, 0, "spawned pid must be non-zero");
        assert_eq!(
            mode,
            ConfinementMode::None,
            "the non-Windows stub never confines"
        );
        let _ = std::fs::remove_file(&log);
    }
}
