use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::egress::config::{Access, AllowEntry, GitRule};
use izba_core::daemon::proto::{
    DaemonCreate, HostDisk, HostResources, SandboxDetail, SandboxStats, VolumeDisk,
};
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
            // The GUI wizard has no docker-mode control yet (#198 is CLI-first);
            // None defers to the image's start-docker label, same as an
            // unset CLI flag.
            docker: None,
            // The GUI wizard has no VNC control yet (spec 2026-08-09 is
            // CLI-first); false matches an unset `--vnc` flag.
            vnc: false,
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

/// The configured usbip upstream as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbUpstreamView {
    pub host: String,
    pub port: u16,
    pub resolved: Option<String>,
    /// Stable kebab-case trust token, e.g. `own-host-loopback`.
    pub trust: String,
    /// The note for that trust class; `None` for the recommended (loopback)
    /// configuration, where silence is the honest answer.
    pub warning: Option<String>,
}

impl From<izba_core::daemon::proto::UsbUpstreamInfo> for UsbUpstreamView {
    fn from(u: izba_core::daemon::proto::UsbUpstreamInfo) -> Self {
        UsbUpstreamView {
            host: u.host,
            port: u.port,
            resolved: u.resolved,
            trust: u.trust,
            warning: u.warning,
        }
    }
}

/// One row of the upstream device inventory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbDeviceView {
    pub busid: String,
    pub device: String,
    pub description: String,
    pub shared: bool,
    pub granted_to: Vec<String>,
    pub attached_to: Option<String>,
    /// For an unshared device: the exact command a human must run elevated.
    /// izba never runs it.
    pub bind_command: Option<String>,
}

impl From<izba_core::daemon::proto::UsbDeviceInfo> for UsbDeviceView {
    fn from(d: izba_core::daemon::proto::UsbDeviceInfo) -> Self {
        UsbDeviceView {
            busid: d.busid,
            device: d.device,
            description: d.description,
            shared: d.shared,
            granted_to: d.granted_to,
            attached_to: d.attached_to,
            bind_command: d.bind_command,
        }
    }
}

/// One standing grant, with its live attachment state folded in.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbGrantView {
    pub device: String,
    pub busid_pin: Option<String>,
    pub description: String,
    pub granted_at_unix_ms: u64,
    pub attached: bool,
}

/// A sandbox's USB state as one object.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbStatusView {
    pub grants: Vec<UsbGrantView>,
    /// The sandbox holds a grant its running kernel cannot honour.
    pub restart_required: bool,
}

impl UsbStatusView {
    /// Fold the wire's parallel `attached` list into the grants it describes.
    ///
    /// Done once, here, rather than in every consumer: a UI that joins two
    /// arrays by string is a UI that will eventually join them wrong.
    pub fn new(
        grants: Vec<izba_core::daemon::proto::UsbGrantInfo>,
        attached: Vec<String>,
        restart_required: bool,
    ) -> Self {
        UsbStatusView {
            grants: grants
                .into_iter()
                .map(|g| UsbGrantView {
                    attached: attached.contains(&g.device),
                    device: g.device,
                    busid_pin: g.busid_pin,
                    description: g.description,
                    granted_at_unix_ms: g.granted_at_unix_ms,
                })
                .collect(),
            restart_required,
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
    /// Host workspace directory, rendered for humans (`display_path` strips
    /// the Windows `\\?\` verbatim prefix a canonicalized record carries).
    pub workspace: String,
    pub ports: Vec<PortRuleView>,
    pub volumes: Vec<VolumeSpecView>,
    /// In-guest workload container state token (`running`/`stopped`/…), or
    /// `None` when the sandbox is stopped, the guest was unreachable, or the
    /// daemon predates container-state reporting. The frontend renders `None`
    /// and `unknown` identically — never as a healthy status.
    pub container: Option<String>,
    /// Whether this sandbox runs in docker mode (#198).
    pub docker: bool,
    pub cpus: u32,
    pub mem_mb: u32,
    /// Host-side VMM confinement summary, or `None` when the sandbox is
    /// stopped / its state predates the field — the UI renders `None` as
    /// "unknown".
    pub confinement: Option<String>,
}

impl From<SandboxDetail> for SandboxDetailView {
    fn from(d: SandboxDetail) -> Self {
        SandboxDetailView {
            name: d.name,
            image: d.image_ref,
            status: d.status,
            workspace: izba_core::paths::display_path(std::path::Path::new(&d.workspace)),
            ports: d.ports.into_iter().map(PortRuleView::from).collect(),
            volumes: d.volumes.into_iter().map(VolumeSpecView::from).collect(),
            container: d.container.map(|c| c.as_str().to_string()),
            docker: d.docker,
            cpus: d.cpus,
            mem_mb: d.mem_mb,
            confinement: d.confinement,
        }
    }
}

/// One declared volume's disk footprint, as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VolumeDiskView {
    pub guest_path: String,
    pub allocated_bytes: u64,
    /// Whether this is the auto-provisioned docker-mode volume, so the UI can
    /// label it distinctly.
    pub docker: bool,
}

impl From<VolumeDisk> for VolumeDiskView {
    fn from(v: VolumeDisk) -> Self {
        VolumeDiskView {
            guest_path: v.guest_path,
            allocated_bytes: v.allocated_bytes,
            docker: v.docker,
        }
    }
}

/// Host-observed process resource usage for a running sandbox's VMM.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostResourcesView {
    /// CPU share over the sampling interval, in permille of one host CPU.
    /// `None` when a single sample can't yet yield a rate (first read).
    pub cpu_permille: Option<u32>,
    pub rss_kb: u64,
    pub cpus_limit: u32,
    pub mem_limit_mb: u32,
}

impl From<HostResources> for HostResourcesView {
    fn from(h: HostResources) -> Self {
        HostResourcesView {
            cpu_permille: h.cpu_permille,
            rss_kb: h.rss_kb,
            cpus_limit: h.cpus_limit,
            mem_limit_mb: h.mem_limit_mb,
        }
    }
}

/// Host-computed on-disk footprint for a sandbox.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostDiskView {
    pub rw_img_bytes: u64,
    pub volumes: Vec<VolumeDiskView>,
    pub logs_bytes: u64,
    /// The rootfs image's on-disk size. Shared by every sandbox created from
    /// the same image — do NOT sum across sandboxes.
    pub image_bytes: u64,
}

impl From<HostDisk> for HostDiskView {
    fn from(d: HostDisk) -> Self {
        HostDiskView {
            rw_img_bytes: d.rw_img_bytes,
            volumes: d.volumes.into_iter().map(VolumeDiskView::from).collect(),
            logs_bytes: d.logs_bytes,
            image_bytes: d.image_bytes,
        }
    }
}

/// One process in the guest's mini-top, as the UI sees it. `state` is the
/// kernel state char rendered as a JSON-friendly string ("R", "S", …).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessView {
    pub pid: u32,
    pub comm: String,
    pub state: String,
    pub cpu_permille: u32,
    pub rss_kb: u64,
}

impl From<izba_proto::ProcSample> for ProcessView {
    fn from(p: izba_proto::ProcSample) -> Self {
        ProcessView {
            pid: p.pid,
            comm: p.comm,
            state: p.state.to_string(),
            cpu_permille: p.cpu_permille,
            rss_kb: p.rss_kb,
        }
    }
}

/// Filesystem-level fullness of one guest mount, as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MountView {
    pub path: String,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

impl From<izba_proto::MountUsage> for MountView {
    fn from(m: izba_proto::MountUsage) -> Self {
        MountView {
            path: m.path,
            total_bytes: m.total_bytes,
            avail_bytes: m.avail_bytes,
        }
    }
}

/// Nested Docker Engine liveness, as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DockerEngineView {
    pub running: bool,
    /// When `!running`: a bounded tail of the engine log.
    pub detail: Option<String>,
}

impl From<izba_proto::DockerEngine> for DockerEngineView {
    fn from(e: izba_proto::DockerEngine) -> Self {
        DockerEngineView {
            running: e.running,
            detail: e.detail,
        }
    }
}

/// Guest-side stats payload, as the UI sees it. Everything here is
/// guest-reported and already sanitized by the daemon before it reaches this
/// struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GuestStatsView {
    /// Top processes by CPU over the sampling interval, descending.
    pub processes: Vec<ProcessView>,
    /// Total live processes in the guest.
    pub process_count: u32,
    /// Load averages × 100.
    pub load1_centi: u32,
    pub load5_centi: u32,
    pub load15_centi: u32,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub mounts: Vec<MountView>,
    /// `Some` only when the guest booted with `izba.docker=1`.
    pub docker: Option<DockerEngineView>,
    /// In-guest workload container state token, or `None`.
    pub container: Option<String>,
}

impl From<izba_proto::GuestStats> for GuestStatsView {
    fn from(g: izba_proto::GuestStats) -> Self {
        GuestStatsView {
            processes: g.processes.into_iter().map(ProcessView::from).collect(),
            process_count: g.process_count,
            load1_centi: g.load1_centi,
            load5_centi: g.load5_centi,
            load15_centi: g.load15_centi,
            mem_total_kb: g.mem_total_kb,
            mem_available_kb: g.mem_available_kb,
            mounts: g.mounts.into_iter().map(MountView::from).collect(),
            docker: g.docker.map(DockerEngineView::from),
            container: g.container.map(|c| c.as_str().to_string()),
        }
    }
}

/// Resource stats for one sandbox (#203), as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxStatsView {
    pub name: String,
    pub running: bool,
    /// Wall time since the VM process started, when running.
    pub uptime_ms: Option<u64>,
    /// Host-observed CPU/RSS + the sandbox's configured limits. `None` when
    /// not running.
    pub host: Option<HostResourcesView>,
    pub disk: HostDiskView,
    /// Sanitized guest-reported mini-top/mounts/docker-engine snapshot.
    /// `None` when the sandbox is stopped or the guest could not be reached.
    pub guest: Option<GuestStatsView>,
}

impl From<SandboxStats> for SandboxStatsView {
    fn from(s: SandboxStats) -> Self {
        SandboxStatsView {
            name: s.name,
            running: s.running,
            uptime_ms: s.uptime_ms,
            host: s.host.map(HostResourcesView::from),
            disk: HostDiskView::from(s.disk),
            guest: s.guest.map(GuestStatsView::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usb_status_view_folds_attachment_into_the_grant_it_describes() {
        let v = UsbStatusView::new(
            vec![
                izba_core::daemon::proto::UsbGrantInfo {
                    device: "0403:6001".into(),
                    busid_pin: Some("3-2".into()),
                    description: "FT232".into(),
                    granted_at_unix_ms: 7,
                },
                izba_core::daemon::proto::UsbGrantInfo {
                    device: "10c4:ea60".into(),
                    busid_pin: None,
                    description: "CP2102".into(),
                    granted_at_unix_ms: 8,
                },
            ],
            vec!["10c4:ea60".into()],
            true,
        );
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["grants"][0]["device"], "0403:6001");
        assert_eq!(j["grants"][0]["busid_pin"], "3-2");
        assert_eq!(j["grants"][0]["attached"], serde_json::json!(false));
        assert_eq!(j["grants"][1]["attached"], serde_json::json!(true));
        assert_eq!(j["restart_required"], serde_json::json!(true));
    }

    #[test]
    fn a_usb_device_view_carries_every_field_the_ui_renders() {
        let v = UsbDeviceView::from(izba_core::daemon::proto::UsbDeviceInfo {
            busid: "1-4".into(),
            device: "10c4:ea60".into(),
            description: "CP2102".into(),
            shared: false,
            granted_to: vec!["web".into()],
            attached_to: Some("api".into()),
            bind_command: Some("usbipd bind --busid 1-4".into()),
        });
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["busid"], "1-4");
        assert_eq!(j["shared"], serde_json::json!(false));
        assert_eq!(j["granted_to"], serde_json::json!(["web"]));
        assert_eq!(j["attached_to"], "api");
        // The command is the entire point of an unshared row: izba shows it
        // because it will never run it.
        assert_eq!(j["bind_command"], "usbipd bind --busid 1-4");
    }

    #[test]
    fn a_usb_upstream_view_keeps_the_trust_token_and_its_note() {
        let v = UsbUpstreamView::from(izba_core::daemon::proto::UsbUpstreamInfo {
            host: "172.20.0.1".into(),
            port: 3240,
            resolved: Some("172.20.0.1".into()),
            trust: "own-host-wsl-gateway".into(),
            warning: Some("any other WSL distro can attach the same devices".into()),
        });
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["trust"], "own-host-wsl-gateway");
        assert_eq!(
            j["warning"],
            "any other WSL distro can attach the same devices"
        );
    }

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
            container: Some(izba_proto::ContainerState::Stopped),
            user_fallback: None,
            docker: false,
        };
        let v = SandboxDetailView::from(detail);
        assert_eq!(v.name, "web");
        assert_eq!(v.image, "ubuntu:24.04");
        assert_eq!(v.status, "running");
        assert_eq!(v.workspace, "/ws");
        assert_eq!(v.ports.len(), 1);
        assert_eq!(v.ports[0].host_port, 8080);
        assert!(v.volumes.is_empty());
        assert_eq!(v.container.as_deref(), Some("stopped"));
    }

    /// A Windows workspace recorded canonicalized (`\\?\C:\...`) surfaces to
    /// the UI without the verbatim prefix — this is what the user sees on the
    /// Overview/Manifest tabs.
    #[test]
    fn sandbox_detail_view_strips_verbatim_workspace_prefix() {
        let detail = izba_core::daemon::proto::SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:x".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: r"\\?\C:\Users\u\proj".into(),
            status: "stopped".into(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: None,
            user_fallback: None,
            docker: false,
        };
        let v = SandboxDetailView::from(detail);
        assert_eq!(v.workspace, r"C:\Users\u\proj");
        assert_eq!(v.container, None);
    }

    /// `SandboxDetailView` must carry the docker/cpus/mem/confinement fields
    /// through unchanged — the Overview facelift's four-card dashboard reads
    /// them directly off this view.
    #[test]
    fn sandbox_detail_view_carries_docker_cpus_mem_confinement() {
        let detail = izba_core::daemon::proto::SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:x".into(),
            cpus: 4,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            volumes: vec![],
            confinement: Some("confined".into()),
            container: Some(izba_proto::ContainerState::Running),
            user_fallback: None,
            docker: true,
        };
        let v = SandboxDetailView::from(detail);
        assert!(v.docker);
        assert_eq!(v.cpus, 4);
        assert_eq!(v.mem_mb, 4096);
        assert_eq!(v.confinement.as_deref(), Some("confined"));
    }

    /// Full round trip of `SandboxStats` → `SandboxStatsView`, mirroring Task
    /// 4's wire fixture plus a populated `guest` half (one process, one
    /// mount, docker engine running, container running).
    #[test]
    fn sandbox_stats_view_maps_wire_type() {
        let s = SandboxStats {
            name: "web".into(),
            running: true,
            uptime_ms: Some(1234),
            host: Some(HostResources {
                cpu_permille: Some(340),
                rss_kb: 2_621_440,
                cpus_limit: 4,
                mem_limit_mb: 4096,
            }),
            disk: HostDisk {
                rw_img_bytes: 1_288_490_189,
                volumes: vec![VolumeDisk {
                    guest_path: "/var/lib/docker".into(),
                    allocated_bytes: 2_254_857_830,
                    docker: true,
                }],
                logs_bytes: 12_582_912,
                image_bytes: 933_232_640,
            },
            guest: Some(izba_proto::GuestStats {
                processes: vec![izba_proto::ProcSample {
                    pid: 42,
                    comm: "node".into(),
                    state: 'R',
                    cpu_permille: 210,
                    rss_kb: 65_536,
                }],
                process_count: 61,
                load1_centi: 42,
                load5_centi: 30,
                load15_centi: 19,
                mem_total_kb: 4 * 1024 * 1024,
                mem_available_kb: 2 * 1024 * 1024,
                mounts: vec![izba_proto::MountUsage {
                    path: "/var/lib/docker".into(),
                    total_bytes: 10 * 1024 * 1024 * 1024,
                    avail_bytes: 8 * 1024 * 1024 * 1024,
                }],
                docker: Some(izba_proto::DockerEngine {
                    running: true,
                    detail: None,
                }),
                container: Some(izba_proto::ContainerState::Running),
            }),
        };
        let v = SandboxStatsView::from(s);
        assert_eq!(v.name, "web");
        assert!(v.running);
        assert_eq!(v.uptime_ms, Some(1234));
        assert_eq!(v.host.as_ref().unwrap().cpu_permille, Some(340));
        assert_eq!(v.host.as_ref().unwrap().rss_kb, 2_621_440);
        assert_eq!(v.disk.rw_img_bytes, 1_288_490_189);
        assert!(v.disk.volumes[0].docker);
        assert_eq!(v.disk.volumes[0].guest_path, "/var/lib/docker");
        let g = v.guest.unwrap();
        assert_eq!(g.processes[0].comm, "node");
        assert_eq!(g.processes[0].state, "R");
        assert_eq!(g.process_count, 61);
        assert_eq!(g.mounts[0].path, "/var/lib/docker");
        assert!(g.docker.as_ref().unwrap().running);
        assert_eq!(g.container.as_deref(), Some("running"));
    }
}
