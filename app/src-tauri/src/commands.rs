use std::path::Path;

use crate::daemon::DaemonApi;
use crate::views::{
    app_build_info, CreateOpts, DaemonStatusView, DiffView, PolicyView, PortRuleView,
    SandboxDetailView, SandboxView, SeedEntry, VersionView, VolumeInfoView,
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

/// Core of `inspect`: full sandbox detail (ports + volumes) mapped to a view.
pub fn inspect_core(d: &mut dyn DaemonApi, name: &str) -> Result<SandboxDetailView, String> {
    d.inspect(name)
        .map(SandboxDetailView::from)
        .map_err(|e| e.to_string())
}

/// Core of `port_list`: active port-publish rules mapped to views.
pub fn port_list_core(d: &mut dyn DaemonApi, name: &str) -> Result<Vec<PortRuleView>, String> {
    d.port_list(name)
        .map(|rules| rules.into_iter().map(PortRuleView::from).collect())
        .map_err(|e| e.to_string())
}

/// Core of `port_publish`: parses `rule_spec` as `[BIND:]HOST:GUEST` then publishes.
pub fn port_publish_core(
    d: &mut dyn DaemonApi,
    name: &str,
    rule_spec: &str,
    persist: bool,
) -> Result<(), String> {
    let rule = izba_core::portfwd::parse_rule(rule_spec).map_err(|e| e.to_string())?;
    d.port_publish(name, rule, persist)
        .map_err(|e| e.to_string())
}

/// Core of `port_unpublish`: removes the rule identified by `(bind, host_port)`.
pub fn port_unpublish_core(
    d: &mut dyn DaemonApi,
    name: &str,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> Result<(), String> {
    d.port_unpublish(name, bind, host_port)
        .map_err(|e| e.to_string())
}

/// Core of `volume_list`: persistent volumes mapped to views.
pub fn volume_list_core(d: &mut dyn DaemonApi) -> Result<Vec<VolumeInfoView>, String> {
    d.volume_list()
        .map(|vols| vols.into_iter().map(VolumeInfoView::from).collect())
        .map_err(|e| e.to_string())
}

/// Core of `volume_remove`: remove a named persistent volume.
pub fn volume_remove_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.volume_remove(name).map_err(|e| e.to_string())
}

/// Core of `volume_prune`: prune unreferenced persistent volumes.
pub fn volume_prune_core(d: &mut dyn DaemonApi) -> Result<izba_core::volume::Pruned, String> {
    d.volume_prune().map_err(|e| e.to_string())
}

/// Core of `manifest_diff`: compute the structural diff between `workspace/izba.yml`
/// and the managed truth for sandbox `name`. Does NOT write the review token —
/// the app diff is a read-only preview; promote is a deferred follow-up.
pub fn manifest_diff_core(workspace: &str, name: &str) -> Result<DiffView, String> {
    let paths = izba_core::paths::Paths::from_env_or_default(None);
    let (state, deltas, _token) =
        izba_core::manifest::ops::compute_diff(&paths, Path::new(workspace), name)
            .map_err(|e| e.to_string())?;
    Ok(DiffView::new(state, &deltas))
}

/// Core of `manifest_export`: write the managed truth back into `workspace/izba.yml`
/// and return the path written as a string.
pub fn manifest_export_core(workspace: &str, name: &str) -> Result<String, String> {
    let paths = izba_core::paths::Paths::from_env_or_default(None);
    izba_core::manifest::ops::export(&paths, Path::new(workspace), name)
        .map(|p| p.display().to_string())
        .map_err(|e| e.to_string())
}

/// Core of `volume_attach`: attach a volume spec (parsed from `spec_str`) to sandbox `name`.
pub fn volume_attach_core(d: &mut dyn DaemonApi, name: &str, spec_str: &str) -> Result<(), String> {
    let spec = izba_core::volume::parse_volume_flag(spec_str).map_err(|e| e.to_string())?;
    d.volume_attach(name, spec).map_err(|e| e.to_string())
}

/// Core of `volume_detach`: detach the volume at `guest_path` from sandbox `name`.
pub fn volume_detach_core(
    d: &mut dyn DaemonApi,
    name: &str,
    guest_path: String,
) -> Result<(), String> {
    d.volume_detach(name, guest_path).map_err(|e| e.to_string())
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
            volumes: vec![],
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

    #[test]
    fn inspect_core_returns_mapped_view() {
        let mut d = FakeDaemon::default();
        let v = inspect_core(&mut d, "web").unwrap();
        assert_eq!(v.name, "web");
        assert_eq!(v.image, "ubuntu:24.04");
        assert_eq!(v.status, "running");
        assert!(v.ports.is_empty());
        assert!(v.volumes.is_empty());
    }

    #[test]
    fn port_list_core_returns_mapped_rules() {
        use std::net::Ipv4Addr;
        let mut d = FakeDaemon {
            ports: vec![izba_core::state::PortRule {
                bind: Ipv4Addr::new(127, 0, 0, 1),
                host_port: 8080,
                guest_port: 80,
            }],
            ..Default::default()
        };
        let rules = port_list_core(&mut d, "web").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].bind, "127.0.0.1");
        assert_eq!(rules[0].host_port, 8080);
    }

    #[test]
    fn port_publish_unpublish_core_record_calls() {
        let mut d = FakeDaemon::default();
        port_publish_core(&mut d, "web", "8080:80", false).unwrap();
        assert!(d.calls.iter().any(|c| c == "publish:web:8080:80:false"));

        let bind: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        port_unpublish_core(&mut d, "web", bind, 8080).unwrap();
        assert!(d.calls.iter().any(|c| c == "unpublish:web:127.0.0.1:8080"));
    }

    #[test]
    fn volume_list_core_returns_mapped_views() {
        let mut d = FakeDaemon::default();
        let vols = volume_list_core(&mut d).unwrap();
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].name, "cache");
        assert_eq!(vols[0].size_bytes, 1 << 30);
    }

    #[test]
    fn volume_remove_prune_core_record_calls() {
        let mut d = FakeDaemon::default();
        volume_remove_core(&mut d, "cache").unwrap();
        volume_prune_core(&mut d).unwrap();
        assert!(d.calls.iter().any(|c| c == "vrm:cache"));
        assert!(d.calls.iter().any(|c| c == "vprune"));
    }

    #[test]
    fn volume_attach_detach_core_record_calls() {
        let mut d = FakeDaemon::default();
        volume_attach_core(&mut d, "web", "cache:/data:1g").unwrap();
        volume_detach_core(&mut d, "web", "/data".into()).unwrap();
        assert!(d.calls.iter().any(|c| c == "vattach:web:/data"));
        assert!(d.calls.iter().any(|c| c == "vdetach:web:/data"));
    }
}
