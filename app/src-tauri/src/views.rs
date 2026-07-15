use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::egress::config::{Access, AllowEntry, GitRule};
use izba_core::daemon::proto::{DaemonCreate, SandboxDetail};
use izba_core::state::PortRule;
use izba_core::volume::{VolumeInfo, VolumeSpec};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single endpoint entry used by the client-side "add from traffic" dialog.
/// Serialized with `tag = "kind"` so the frontend distinguishes `http` vs `git`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SeedEntry {
    Http {
        host: String,
        port: u16,
        access: Access,
    },
    Git {
        target: String,
        access: Access,
    },
}

/// A sandbox's egress policy as the UI sees it. `enforcing` is true iff a
/// `policy.yaml` exists (an absent file = bare AllowAll sandbox; an empty
/// `allow` with `enforcing: true` = deny-all firewall).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyView {
    pub enforcing: bool,
    pub allow: Vec<AllowEntry>,
    pub git: Vec<GitRule>,
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
    /// Repeatable `[NAME:]GUEST_PATH:SIZE` volume specs (blank entries ignored).
    #[serde(default)]
    pub volumes: Vec<String>,
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
        let volumes = self
            .volumes
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(izba_core::volume::parse_volume_flag)
            .collect::<anyhow::Result<Vec<_>>>()?;
        izba_core::volume::validate_volumes(&volumes)?;
        Ok(DaemonCreate {
            name: self.name,
            image_ref: self.image,
            cpus: self.cpus,
            mem_mb: self.mem_mb,
            workspace: PathBuf::from(self.workspace),
            rw_size_gb: self.rw_size_gb,
            ports,
            volumes,
            allow_unconfined: false,
            builder: false,
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

/// A port-publish rule as the UI sees it. `bind` is stringified (e.g. "127.0.0.1").
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortRuleView {
    pub bind: String,
    pub host_port: u16,
    pub guest_port: u16,
}

impl From<PortRule> for PortRuleView {
    fn from(r: PortRule) -> Self {
        PortRuleView {
            bind: r.bind.to_string(),
            host_port: r.host_port,
            guest_port: r.guest_port,
        }
    }
}

/// A volume spec as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VolumeSpecView {
    pub name: Option<String>,
    pub guest_path: String,
    pub size_bytes: u64,
    pub eph_id: Option<u64>,
}

impl From<VolumeSpec> for VolumeSpecView {
    fn from(v: VolumeSpec) -> Self {
        VolumeSpecView {
            name: v.name,
            guest_path: v.guest_path.to_string_lossy().into_owned(),
            size_bytes: v.size_bytes,
            eph_id: v.eph_id,
        }
    }
}

/// A persistent volume record as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VolumeInfoView {
    pub name: String,
    pub size_bytes: u64,
    pub actual_bytes: u64,
    pub referenced_by: Vec<String>,
}

impl From<VolumeInfo> for VolumeInfoView {
    fn from(v: VolumeInfo) -> Self {
        VolumeInfoView {
            name: v.name,
            size_bytes: v.size_bytes,
            actual_bytes: v.actual_bytes,
            referenced_by: v.referenced_by,
        }
    }
}

/// A single field-level change between the repo manifest and the managed truth.
#[derive(Debug, Clone, Serialize)]
pub struct DeltaView {
    pub field: String,
    pub from: String,
    pub to: String,
    /// "live" | "restart" | "image"
    pub class: String,
    pub weakens_egress: bool,
}

/// Manifest diff result returned to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct DiffView {
    /// "in_sync" | "repo_ahead" | "managed_ahead" | "diverged"
    pub state: String,
    pub deltas: Vec<DeltaView>,
}

/// Map the 3-way drift state to the frontend's string tag. Shared by
/// `DiffView::new` and `PromoteView::new` so both surfaces agree on the same
/// vocabulary.
fn drift_state_str(state: izba_core::manifest::DriftState) -> &'static str {
    use izba_core::manifest::DriftState;
    match state {
        DriftState::InSync => "in_sync",
        DriftState::RepoAhead => "repo_ahead",
        DriftState::ManagedAhead => "managed_ahead",
        DriftState::Diverged => "diverged",
    }
}

/// Map one core `FieldDelta` to its frontend view. Shared by `DiffView::new`
/// and `PromoteView::new`.
fn delta_view(d: &izba_core::manifest::diff::FieldDelta) -> DeltaView {
    use izba_core::manifest::diff::FieldClass;
    DeltaView {
        field: d.field.clone(),
        from: d.from.clone(),
        to: d.to.clone(),
        class: match d.class {
            FieldClass::Live => "live".to_string(),
            FieldClass::Restart => "restart".to_string(),
            FieldClass::Image => "image".to_string(),
        },
        weakens_egress: d.weakens_egress,
    }
}

impl DiffView {
    pub fn new(
        state: izba_core::manifest::DriftState,
        deltas: &[izba_core::manifest::diff::FieldDelta],
    ) -> Self {
        DiffView {
            state: drift_state_str(state).to_string(),
            deltas: deltas.iter().map(delta_view).collect(),
        }
    }
}

/// Result of a `manifest_promote` run, mapped for the frontend. Mirrors
/// `DiffView`'s state/class vocabulary (via the shared helpers above) so the
/// promote confirmation view and the diff preview read consistently.
#[derive(Serialize, Debug)]
pub struct PromoteView {
    /// "in_sync" | "repo_ahead" | "managed_ahead" | "diverged" — the 3-way
    /// drift state computed BEFORE this run applied anything.
    pub state: String,
    pub applied: Vec<DeltaView>,
    pub needs_restart: bool,
    pub restarted: bool,
    pub stopped: bool,
    pub warnings: Vec<String>,
}

impl PromoteView {
    pub fn new(o: izba_core::manifest::promote::PromoteOutcome) -> Self {
        PromoteView {
            state: drift_state_str(o.state).to_string(),
            applied: o.applied.iter().map(delta_view).collect(),
            needs_restart: o.needs_restart,
            restarted: o.restarted,
            stopped: o.stopped,
            warnings: o.warnings,
        }
    }
}

/// Full sandbox detail for the UI (ports + volumes included).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxDetailView {
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: Vec<PortRuleView>,
    pub volumes: Vec<VolumeSpecView>,
}

impl From<SandboxDetail> for SandboxDetailView {
    fn from(d: SandboxDetail) -> Self {
        SandboxDetailView {
            name: d.name,
            image: d.image_ref,
            status: d.status,
            ports: d.ports.into_iter().map(PortRuleView::from).collect(),
            volumes: d.volumes.into_iter().map(VolumeSpecView::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_view_maps_state_and_deltas() {
        use izba_core::manifest::diff::{FieldClass, FieldDelta};
        use izba_core::manifest::DriftState;

        // InSync + empty deltas
        let v = DiffView::new(DriftState::InSync, &[]);
        assert_eq!(v.state, "in_sync");
        assert!(v.deltas.is_empty());

        // RepoAhead
        assert_eq!(
            DiffView::new(DriftState::RepoAhead, &[]).state,
            "repo_ahead"
        );
        // ManagedAhead
        assert_eq!(
            DiffView::new(DriftState::ManagedAhead, &[]).state,
            "managed_ahead"
        );
        // Diverged
        assert_eq!(DiffView::new(DriftState::Diverged, &[]).state, "diverged");

        // Delta class mapping + weakens_egress forwarding
        let deltas = vec![
            FieldDelta {
                field: "cpus".into(),
                from: "2".into(),
                to: "4".into(),
                class: FieldClass::Restart,
                weakens_egress: false,
            },
            FieldDelta {
                field: "image".into(),
                from: "ubuntu:22.04".into(),
                to: "ubuntu:24.04".into(),
                class: FieldClass::Image,
                weakens_egress: false,
            },
            FieldDelta {
                field: "egress".into(),
                from: "".into(),
                to: "allow: [evil.com]".into(),
                class: FieldClass::Live,
                weakens_egress: true,
            },
        ];
        let v = DiffView::new(DriftState::RepoAhead, &deltas);
        assert_eq!(v.state, "repo_ahead");
        assert_eq!(v.deltas.len(), 3);
        assert_eq!(v.deltas[0].field, "cpus");
        assert_eq!(v.deltas[0].class, "restart");
        assert!(!v.deltas[0].weakens_egress);
        assert_eq!(v.deltas[1].class, "image");
        assert_eq!(v.deltas[2].class, "live");
        assert!(v.deltas[2].weakens_egress);
    }

    #[test]
    fn promote_view_maps_outcome() {
        use izba_core::manifest::diff::{FieldClass, FieldDelta};
        use izba_core::manifest::promote::PromoteOutcome;
        use izba_core::manifest::DriftState;

        let outcome = PromoteOutcome {
            state: DriftState::RepoAhead,
            applied: vec![FieldDelta {
                field: "ports".into(),
                from: "".into(),
                to: "8080:80".into(),
                class: FieldClass::Live,
                weakens_egress: false,
            }],
            needs_restart: true,
            restarted: false,
            stopped: false,
            warnings: vec!["w".into()],
        };

        let v = PromoteView::new(outcome);
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["state"], "repo_ahead");
        assert_eq!(j["applied"][0]["class"], "live");
        assert_eq!(j["applied"][0]["field"], "ports");
        assert_eq!(j["warnings"], serde_json::json!(["w"]));
        assert_eq!(j["needs_restart"], true);
        assert_eq!(j["restarted"], false);
        assert_eq!(j["stopped"], false);
    }

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
            volumes: vec![],
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
            volumes: vec![],
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
            git: vec![],
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

    #[test]
    fn create_opts_parses_volumes() {
        let opts = CreateOpts {
            name: "web".into(),
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            rw_size_gb: 8,
            ports: vec![],
            volumes: vec!["cache:/data:1g".into(), "  ".into()],
        };
        let dc = opts.into_daemon_create().unwrap();
        assert_eq!(dc.volumes.len(), 1);
        assert_eq!(dc.volumes[0].name.as_deref(), Some("cache"));
    }

    #[test]
    fn port_rule_view_stringifies_bind() {
        use std::net::Ipv4Addr;
        let rule = PortRule {
            bind: Ipv4Addr::new(127, 0, 0, 1),
            host_port: 8080,
            guest_port: 80,
        };
        let v = PortRuleView::from(rule);
        assert_eq!(v.bind, "127.0.0.1");
        assert_eq!(v.host_port, 8080);
        assert_eq!(v.guest_port, 80);
    }

    #[test]
    fn volume_spec_view_maps_fields() {
        let spec = VolumeSpec {
            name: Some("cache".into()),
            guest_path: std::path::PathBuf::from("/data"),
            size_bytes: 1 << 30,
            eph_id: None,
        };
        let v = VolumeSpecView::from(spec);
        assert_eq!(v.name.as_deref(), Some("cache"));
        assert_eq!(v.guest_path, "/data");
        assert_eq!(v.size_bytes, 1 << 30);
        assert!(v.eph_id.is_none());
    }

    #[test]
    fn volume_info_view_maps_fields() {
        let info = VolumeInfo {
            name: "cache".into(),
            size_bytes: 1 << 30,
            actual_bytes: 1 << 20,
            referenced_by: vec!["web".into()],
        };
        let v = VolumeInfoView::from(info);
        assert_eq!(v.name, "cache");
        assert_eq!(v.referenced_by, vec!["web"]);
    }

    #[test]
    fn sandbox_detail_view_maps_fields() {
        use std::net::Ipv4Addr;
        let detail = izba_core::daemon::proto::SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:x".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![PortRule {
                bind: Ipv4Addr::new(127, 0, 0, 1),
                host_port: 8080,
                guest_port: 80,
            }],
            volumes: vec![],
            confinement: None,
            container: None,
            user_fallback: None,
        };
        let v = SandboxDetailView::from(detail);
        assert_eq!(v.name, "web");
        assert_eq!(v.image, "ubuntu:24.04");
        assert_eq!(v.status, "running");
        assert_eq!(v.ports.len(), 1);
        assert_eq!(v.ports[0].host_port, 8080);
        assert!(v.volumes.is_empty());
    }
}
