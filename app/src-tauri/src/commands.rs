use crate::daemon::DaemonApi;
use crate::views::{app_build_info, CreateOpts, DaemonStatusView, SandboxView, VersionView};

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

/// Start a sandbox (may boot-wait inside the daemon).
pub fn start_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.start(name).map_err(|e| e.to_string())
}

/// Stop a sandbox.
pub fn stop_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())
}

/// Restart = stop then start (izba never auto-restarts). Stop failure aborts
/// before start so a half-restart never silently boots a stale config.
pub fn restart_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())?;
    d.start(name).map_err(|e| e.to_string())
}

/// Remove a sandbox (force skips the running-state guard).
pub fn remove_core(d: &mut dyn DaemonApi, name: &str, force: bool) -> Result<(), String> {
    d.remove(name, force).map_err(|e| e.to_string())
}

/// Create a sandbox, forwarding daemon `Progress` messages via `on_progress`.
pub fn create_core(
    d: &mut dyn DaemonApi,
    opts: CreateOpts,
    on_progress: &mut dyn FnMut(&str),
) -> Result<String, String> {
    let req = opts.into_daemon_create().map_err(|e| e.to_string())?;
    d.create(req, on_progress).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use crate::views::{CreateOpts, SbxState};

    fn create_opts() -> CreateOpts {
        CreateOpts {
            name: "new".into(),
            image: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: "/ws".into(),
            rw_size_gb: 4,
            ports: vec![],
        }
    }

    #[test]
    fn start_stop_remove_dispatch() {
        let mut d = FakeDaemon::default();
        start_core(&mut d, "web").unwrap();
        stop_core(&mut d, "web").unwrap();
        remove_core(&mut d, "web", true).unwrap();
        assert_eq!(d.calls, vec!["start:web", "stop:web", "rm:web:true"]);
    }

    #[test]
    fn restart_is_stop_then_start() {
        let mut d = FakeDaemon::default();
        restart_core(&mut d, "web").unwrap();
        assert_eq!(d.calls, vec!["stop:web", "start:web"]);
    }

    #[test]
    fn restart_does_not_start_if_stop_fails() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        assert!(restart_core(&mut d, "web").is_err());
        assert_eq!(d.calls, vec!["stop:web"]); // start not attempted
    }

    #[test]
    fn create_core_streams_and_returns_name() {
        let mut d = FakeDaemon::default();
        let mut seen = Vec::new();
        let name = create_core(&mut d, create_opts(), &mut |m| seen.push(m.to_string())).unwrap();
        assert_eq!(name, "new");
        assert_eq!(seen, vec!["pulling image", "booting"]);
    }

    #[test]
    fn create_core_maps_bad_name_to_error() {
        let mut d = FakeDaemon::default();
        let mut bad = create_opts();
        bad.name = "Bad Name".into();
        let err = create_core(&mut d, bad, &mut |_| {}).unwrap_err();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }

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
