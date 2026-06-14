use crate::daemon::DaemonApi;
use crate::views::{app_build_info, DaemonStatusView, SandboxView, VersionView};

/// Core of the `list` command: maps daemon errors to a UI-friendly string.
pub fn list_core(d: &mut dyn DaemonApi) -> Result<Vec<SandboxView>, String> {
    d.list().map_err(|e| e.to_string())
}

/// Core of the `daemon_status` command.
pub fn status_core(d: &mut dyn DaemonApi) -> Result<DaemonStatusView, String> {
    d.status().map_err(|e| e.to_string())
}

/// Core of the `version_info` command: this app's build, the linked core build,
/// and the daemon's (when reachable) with a mismatch flag. An unreachable
/// daemon is not an error here — the panel just shows "not running".
pub fn version_core(d: &mut dyn DaemonApi) -> Result<VersionView, String> {
    let app = app_build_info();
    let core = izba_core::build_info::BuildInfoOwned::current();
    let (daemon, proto, mismatch) = match d.version() {
        Ok((build, proto)) => {
            let mismatch = build != app;
            (Some(build), proto, mismatch)
        }
        Err(_) => (None, 0, false),
    };
    Ok(VersionView {
        app,
        core,
        daemon,
        proto,
        mismatch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use crate::views::SbxState;

    #[test]
    fn list_core_returns_mapped_sandboxes() {
        let mut d = FakeDaemon::default();
        let out = list_core(&mut d).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "web");
        assert_eq!(out[0].state, SbxState::Running);
    }

    #[test]
    fn list_core_maps_error_to_string() {
        let mut d = FakeDaemon {
            fail_list: true,
            ..Default::default()
        };
        let err = list_core(&mut d).unwrap_err();
        assert!(err.contains("daemon unreachable"), "got: {err}");
    }

    #[test]
    fn status_core_returns_view() {
        let mut d = FakeDaemon::default();
        let s = status_core(&mut d).unwrap();
        assert_eq!(s.pid, 4242);
        assert_eq!(s.sandbox_count, 2);
    }

    #[test]
    fn status_core_maps_error_to_string() {
        let mut d = FakeDaemon {
            fail_status: true,
            ..Default::default()
        };
        let err = status_core(&mut d).unwrap_err();
        assert!(err.contains("daemon unreachable"), "got: {err}");
    }

    #[test]
    fn version_core_flags_mismatch_when_daemon_differs() {
        // The fake daemon reports a sha that cannot match the real app build.
        let mut d = FakeDaemon {
            daemon_sha: "deadbeef".into(),
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_some());
        assert!(v.mismatch);
        assert!(!v.app.git_describe.is_empty());
    }

    #[test]
    fn version_core_no_mismatch_when_daemon_absent() {
        let mut d = FakeDaemon {
            daemon_absent: true,
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_none());
        assert!(!v.mismatch);
    }
}
