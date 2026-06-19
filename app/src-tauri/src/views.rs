use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::egress::config::AllowEntry;
use izba_core::daemon::proto::DaemonCreate;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A sandbox's egress policy as the UI sees it. `enforcing` is true iff a
/// `policy.yaml` exists (an absent file = bare AllowAll sandbox; an empty
/// `allow` with `enforcing: true` = deny-all firewall).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyView {
    pub enforcing: bool,
    pub allow: Vec<AllowEntry>,
}

/// Create-sandbox options coming from the frontend wizard. Mirrors the CLI's
/// `SandboxOpts` core fields (no `--policy`: deferred to the firewall milestone).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateOpts {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: String,
    pub rw_size_gb: u64,
    /// Repeatable `[BIND:]HOST:GUEST` port specs (blank entries are ignored).
    pub ports: Vec<String>,
}

impl CreateOpts {
    /// Validate the name and parse port specs, mirroring the CLI create path
    /// (`validate_name` + `portfwd::parse_rule`). Workspace is passed through
    /// as-is — the picker yields an existing absolute path.
    pub fn into_daemon_create(self) -> anyhow::Result<DaemonCreate> {
        izba_core::sandbox::validate_name(&self.name)?;
        let ports = self
            .ports
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(izba_core::portfwd::parse_rule)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(DaemonCreate {
            name: self.name,
            image_ref: self.image,
            cpus: self.cpus,
            mem_mb: self.mem_mb,
            workspace: PathBuf::from(self.workspace),
            rw_size_gb: self.rw_size_gb,
            ports,
            // The app does not expose volume creation yet (a future "Storage"
            // tab); send none so the daemon treats it as a volume-less sandbox.
            volumes: Vec::new(),
            // The app always creates with confined intent (no unconfined toggle),
            // so the daemon runs the workspace confinement preflight and surfaces
            // an actionable error in the create dialog for an unrelabellable dir.
            allow_unconfined: false,
        })
    }
}

/// Version comparison surfaced to the About panel: this app's build, the linked
/// izba-core build, and (when reachable) the daemon's — with a mismatch flag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VersionView {
    pub app: BuildInfoOwned,
    pub core: BuildInfoOwned,
    pub daemon: Option<BuildInfoOwned>,
    pub proto: u32,
    pub mismatch: bool,
}

/// This app binary's own build metadata. The app's `build.rs` (vergen) emits
/// the `VERGEN_*`/`IZBA_PROFILE` vars into THIS crate, so they describe the app
/// — distinct from `izba_core`'s, which describes the linked library.
pub fn app_build_info() -> BuildInfoOwned {
    fn or_unknown(v: Option<&str>) -> String {
        v.unwrap_or("unknown").to_string()
    }
    BuildInfoOwned {
        pkg_version: env!("CARGO_PKG_VERSION").to_string(),
        git_describe: or_unknown(option_env!("VERGEN_GIT_DESCRIBE")),
        git_sha: or_unknown(option_env!("VERGEN_GIT_SHA")),
        commit_date: or_unknown(option_env!("VERGEN_GIT_COMMIT_DATE")),
        build_timestamp: or_unknown(option_env!("VERGEN_BUILD_TIMESTAMP")),
        rustc: or_unknown(option_env!("VERGEN_RUSTC_SEMVER")),
        target: or_unknown(option_env!("VERGEN_CARGO_TARGET_TRIPLE")),
        profile: or_unknown(option_env!("IZBA_PROFILE")),
    }
}

/// Structured sandbox state for the frontend (parsed from izba's status string).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SbxState {
    Running,
    Degraded { reason: String },
    Stopped,
}

/// Parse izba's `Liveness::describe()` string into a structured state.
/// Formats: "running" | "stopped" | "degraded (<reason>)".
///
/// NOTE: the `degraded (...)` branch strips the final ')', so a reason that
/// itself ends with ')' would lose one character. izba's reasons never do
/// (see `liveness.rs`), but keep that invariant in mind if reasons change.
pub fn parse_state(status: &str) -> SbxState {
    if status == "running" {
        SbxState::Running
    } else if status == "stopped" {
        SbxState::Stopped
    } else if let Some(reason) = status
        .strip_prefix("degraded (")
        .and_then(|s| s.strip_suffix(')'))
    {
        SbxState::Degraded {
            reason: reason.to_string(),
        }
    } else {
        // Unknown/empty status is treated as stopped rather than panicking.
        SbxState::Stopped
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxView {
    pub name: String,
    pub image: String,
    pub state: SbxState,
}

impl From<izba_core::daemon::proto::SandboxSummary> for SandboxView {
    fn from(s: izba_core::daemon::proto::SandboxSummary) -> Self {
        SandboxView {
            name: s.name,
            image: s.image_ref,
            state: parse_state(&s.status),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonStatusView {
    pub version: String,
    pub pid: u32,
    pub uptime_ms: u64,
    pub sandbox_count: usize,
}

impl From<izba_core::daemon::proto::DaemonStatus> for DaemonStatusView {
    fn from(s: izba_core::daemon::proto::DaemonStatus) -> Self {
        DaemonStatusView {
            version: s.version,
            pid: s.pid,
            uptime_ms: s.uptime_ms,
            sandbox_count: s.sandboxes.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_running_and_stopped() {
        assert_eq!(parse_state("running"), SbxState::Running);
        assert_eq!(parse_state("stopped"), SbxState::Stopped);
    }

    #[test]
    fn parses_degraded_with_reason() {
        assert_eq!(
            parse_state("degraded (sidecar virtiofsd:workspace died)"),
            SbxState::Degraded {
                reason: "sidecar virtiofsd:workspace died".into()
            }
        );
    }

    #[test]
    fn unknown_status_is_stopped() {
        assert_eq!(parse_state("weird"), SbxState::Stopped);
        assert_eq!(parse_state(""), SbxState::Stopped);
    }

    #[test]
    fn create_opts_maps_to_daemon_create() {
        let opts = CreateOpts {
            name: "web".into(),
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            rw_size_gb: 8,
            ports: vec!["127.0.0.1:8080:80".into(), "  ".into()],
        };
        let dc = opts.into_daemon_create().unwrap();
        assert_eq!(dc.name, "web");
        assert_eq!(dc.image_ref, "ubuntu:24.04");
        assert_eq!(dc.cpus, 2);
        assert_eq!(dc.mem_mb, 4096);
        assert_eq!(dc.workspace, std::path::PathBuf::from("/ws"));
        assert_eq!(dc.rw_size_gb, 8);
        assert_eq!(dc.ports.len(), 1); // blank spec dropped
        assert_eq!(dc.ports[0].host_port, 8080);
        assert_eq!(dc.ports[0].guest_port, 80);
    }

    #[test]
    fn create_opts_rejects_bad_name() {
        let opts = CreateOpts {
            name: "Bad Name".into(),
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            rw_size_gb: 8,
            ports: vec![],
        };
        let err = opts.into_daemon_create().unwrap_err().to_string();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }

    #[test]
    fn policy_view_serializes_enforcing_and_entries() {
        let v = PolicyView {
            enforcing: true,
            allow: vec![izba_core::daemon::egress::config::AllowEntry::Host(
                "api.x.com".into(),
            )],
        };
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["enforcing"], true);
        assert_eq!(j["allow"][0], "api.x.com"); // untagged: bare host → string
    }

    #[test]
    fn summary_maps_to_view() {
        let s = izba_core::daemon::proto::SandboxSummary {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            status: "running".into(),
        };
        let v: SandboxView = s.into();
        assert_eq!(
            v,
            SandboxView {
                name: "web".into(),
                image: "ubuntu:24.04".into(),
                state: SbxState::Running
            }
        );
    }
}
