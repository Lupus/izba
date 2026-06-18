use crate::daemon::DaemonApi;
use crate::views::{
    app_build_info, CreateOpts, DaemonStatusView, PolicyView, SandboxView, SeedEntry, VersionView,
};
use izba_core::daemon::egress::audit::EndpointSummary;
use izba_core::daemon::egress::config::{AllowEntry, GitRule};

/// Core of the `list` command: maps daemon errors to a UI-friendly string.
pub fn list_core(d: &mut dyn DaemonApi) -> Result<Vec<SandboxView>, String> {
    d.list().map_err(|e| e.to_string())
}

/// Core of the `daemon_status` command.
pub fn status_core(d: &mut dyn DaemonApi) -> Result<DaemonStatusView, String> {
    d.status().map_err(|e| e.to_string())
}

/// Core of the `read_logs` command.
pub fn read_logs_core(d: &mut dyn DaemonApi, name: &str) -> Result<String, String> {
    d.read_logs(name).map_err(|e| e.to_string())
}

/// Core of the `version_info` command: this app's build, the linked core build,
/// and the daemon's (when reachable) with a mismatch flag. An unreachable
/// daemon is not an error here — the panel just shows "not running".
pub fn version_core(d: &mut dyn DaemonApi) -> Result<VersionView, String> {
    let app = app_build_info();
    let core = izba_core::build_info::BuildInfoOwned::current();
    let (daemon, proto, mismatch) = match d.version() {
        Ok((build, proto)) => {
            // Compare the commit sha only — the same identity the About panel
            // shows. NOT git_describe: the app's build.rs enables vergen's dirty
            // flag, and its npm/dist build dirties the tree before vergen runs, so
            // the app describe gets a `-dirty` suffix the (clean) daemon build
            // lacks — a false mismatch at the identical commit. NOT the whole
            // struct either: build_timestamp/rustc always differ across the two
            // separately-built binaries.
            let mismatch = build.git_sha != app.git_sha;
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

/// Core of `read_netlog`: per-endpoint aggregated audit summaries.
pub fn read_netlog_core(d: &mut dyn DaemonApi, name: &str) -> Result<Vec<EndpointSummary>, String> {
    d.read_netlog(name).map_err(|e| e.to_string())
}

/// Core of `policy_show`: the sandbox's effective egress policy.
pub fn policy_show_core(d: &mut dyn DaemonApi, name: &str) -> Result<PolicyView, String> {
    d.policy_show(name).map_err(|e| e.to_string())
}

/// Core of `policy_allow`: authorize a host:port (auto-reloads).
pub fn policy_allow_core(
    d: &mut dyn DaemonApi,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    d.policy_allow(name, host, port).map_err(|e| e.to_string())
}

/// Core of `policy_block`: revoke a host:port (auto-reloads).
pub fn policy_block_core(
    d: &mut dyn DaemonApi,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    d.policy_block(name, host, port).map_err(|e| e.to_string())
}

/// Core of `policy_set`: replace the allow-list wholesale (auto-reloads).
pub fn policy_set_core(
    d: &mut dyn DaemonApi,
    name: &str,
    allow: Vec<AllowEntry>,
) -> Result<(), String> {
    d.policy_set(name, allow).map_err(|e| e.to_string())
}

/// Core of `policy_add_endpoints`: additively merge entries (enforce only when flag set).
pub fn policy_add_endpoints_core(
    d: &mut dyn DaemonApi,
    name: &str,
    entries: Vec<SeedEntry>,
    enforce: bool,
) -> Result<(), String> {
    d.policy_add_endpoints(name, entries, enforce)
        .map_err(|e| e.to_string())
}

/// Core of `policy_set_full`: replace allow + git rule sets (enforce untouched).
pub fn policy_set_full_core(
    d: &mut dyn DaemonApi,
    name: &str,
    allow: Vec<AllowEntry>,
    git: Vec<GitRule>,
) -> Result<(), String> {
    d.policy_set_full(name, allow, git)
        .map_err(|e| e.to_string())
}

/// Core of `policy_git_allow`: authorize a git target (auto-reloads).
pub fn policy_git_allow_core(
    d: &mut dyn DaemonApi,
    name: &str,
    target: &str,
    write: bool,
) -> Result<(), String> {
    d.policy_git_allow(name, target, write)
        .map_err(|e| e.to_string())
}

/// Core of `policy_git_block`: revoke a git target (auto-reloads).
pub fn policy_git_block_core(
    d: &mut dyn DaemonApi,
    name: &str,
    target: &str,
) -> Result<(), String> {
    d.policy_git_block(name, target).map_err(|e| e.to_string())
}

/// Core of `policy_set_enforce`: set the enforcing flag (auto-reloads).
pub fn policy_set_enforce_core(d: &mut dyn DaemonApi, name: &str, on: bool) -> Result<(), String> {
    d.policy_set_enforce(name, on).map_err(|e| e.to_string())
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
    fn version_core_no_mismatch_when_sha_matches() {
        // Same commit ⇒ same git_sha, even though the two binaries were built at
        // different instants (build_timestamp/rustc differ) and the app build may
        // be `-dirty` while the daemon is clean. The warning must NOT fire.
        let mut d = FakeDaemon {
            daemon_sha: app_build_info().git_sha,
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_some());
        assert!(!v.mismatch, "identical commit sha must not flag a mismatch");
    }

    #[test]
    fn read_logs_core_returns_text() {
        let mut d = FakeDaemon::default();
        let t = read_logs_core(&mut d, "web").unwrap();
        assert!(t.contains("boot"), "got: {t}");
    }

    #[test]
    fn read_netlog_core_returns_summaries() {
        let mut d = crate::fake::FakeDaemon::default();
        let rows = read_netlog_core(&mut d, "web").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host.as_deref(), Some("api.x.com"));
    }

    #[test]
    fn policy_edit_cores_record_calls() {
        let mut d = crate::fake::FakeDaemon::default();
        policy_allow_core(&mut d, "web", "api.x.com", 443).unwrap();
        policy_block_core(&mut d, "web", "api.x.com", 80).unwrap();
        policy_add_endpoints_core(&mut d, "web", vec![], false).unwrap();
        assert!(d.calls.iter().any(|c| c == "allow:web:api.x.com:443"));
        assert!(d.calls.iter().any(|c| c == "block:web:api.x.com:80"));
        assert!(d.calls.iter().any(|c| c.starts_with("add_endpoints:web:")));
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
