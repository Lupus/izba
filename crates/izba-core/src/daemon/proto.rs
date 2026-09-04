//! The CLI↔daemon wire protocol: u32-LE framed JSON via the izba-proto codec.
//!
//! Lives in izba-core (not izba-proto) deliberately: izba-proto is the
//! guest-shared protocol and must not depend on core types (`PortRule`);
//! both ends of THIS protocol are compiled from izba-core anyway.
//!
//! Connection shape: the first frame each way is `DaemonHello` ⇄
//! `DaemonResponse::HelloOk` (the server always answers with its version;
//! the client decides about mismatches). Then the connection carries
//! `DaemonRequest` → `DaemonResponse` pairs — except `OpenStream`, which on
//! `Ok` converts the connection into a raw byte splice to the guest's
//! stream port (the client sends the guest `StreamOpen` frame in-band; the
//! daemon never parses stream framing).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::build_info::BuildInfoOwned;
use crate::state::PortRule;
use izba_proto::{Request, Response};

/// Wire-protocol version exchanged in the hello frame. The CLI↔daemon
/// **compatibility** gate compares THIS (not the now-sha-bearing display
/// string), so a dev rebuild of the same protocol never churn-restarts the
/// daemon. Bump on any wire-breaking change to any daemon frame — including
/// NEW `DaemonRequest` variants: a same-version daemon that predates the
/// variant would otherwise fail the frame read instead of self-healing.
/// (v2 retro-covers `ReloadPolicy` + the `Volume*` requests that landed
/// during v1; the `Unknown` catch-all below turns any future slip into a
/// clean error instead of a dropped connection. v3 covers the `Usb*`
/// control-plane requests; v4 covers `UsbAttach`/`UsbDetach` and the guest
/// `Request` variants they forward. v5 covers `DaemonRequest::Stats` /
/// `DaemonResponse::Stats`. v6 added `DaemonRequest::VncSet`.)
pub const DAEMON_PROTO_VERSION: u32 = 6;

/// First frame on every daemon connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHello {
    /// Display string (`BuildInfo::short()`); kept for logs/diagnostics.
    pub version: String,
    /// Compatibility gate. Absent (a pre-proto client) → 0 via serde default.
    #[serde(default)]
    pub proto: u32,
}

/// Parameters of `DaemonRequest::Create` — mirrors `sandbox::CreateOpts`,
/// except the image is a ref (the daemon resolves/pulls the digest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonCreate {
    pub name: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    pub rw_size_gb: u64,
    pub ports: Vec<PortRule>,
    /// User-declared volumes. Defaults to empty so a pre-feature client frame
    /// still deserializes.
    #[serde(default)]
    pub volumes: Vec<crate::volume::VolumeSpec>,
    /// Opt out of host-side VMM confinement (mirrors `Start::allow_unconfined`).
    /// When false (the default), the daemon runs the confinement preflight on
    /// the workspace before creating anything — a workspace that cannot be
    /// relabelled (e.g. a folder at a drive root) is rejected so the sandbox is
    /// never created in an unstartable state. When true, the preflight is skipped
    /// because the VMM will not relabel the workspace. Defaults to false via
    /// serde so an older client's frame (no field) still deserializes confined.
    #[serde(default)]
    pub allow_unconfined: bool,
    /// Provision this sandbox as a throwaway in-VM build host: adds the
    /// `izba-buildout` rw share at guest `/out`. Set by `izba build`; never by
    /// `create`/`run`. Additive + serde-default → no `DAEMON_PROTO_VERSION`
    /// bump (a pre-feature client's frame deserializes to `false`).
    #[serde(default)]
    pub builder: bool,
    /// Docker mode (#198): the CLI's explicit choice. `Some(true)` = --docker,
    /// `Some(false)` = --no-docker, `None` = no preference (the image's
    /// `com.docker.sandboxes.start-docker` label decides). Resolved to the
    /// persisted `SandboxConfig.docker` bool by the daemon at create, where the
    /// image config is in hand. Additive + serde-default → no
    /// `DAEMON_PROTO_VERSION` bump.
    #[serde(default)]
    pub docker: Option<bool>,
    /// VNC display (spec 2026-08-09): plain `izba create --vnc` flag — no
    /// tri-state, no image-label precedence, nothing auto-enables VNC.
    /// Additive + serde(default) → no `DAEMON_PROTO_VERSION` bump (a
    /// pre-feature client's frame deserializes to `false`).
    #[serde(default)]
    pub vnc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonRequest {
    Create(DaemonCreate),
    Start {
        name: String,
        /// Opt out of host-side VMM confinement (NOT recommended). Defaults to
        /// false via serde so an older client's frame (no field) still
        /// deserializes and the daemon confines as usual.
        #[serde(default)]
        allow_unconfined: bool,
    },
    Stop {
        name: String,
    },
    Rm {
        name: String,
        force: bool,
    },
    List,
    Inspect {
        name: String,
    },
    /// Host-computed + guest-reported resource stats for one sandbox (#203):
    /// CPU/RSS/disk from the host side, plus a sanitized `GuestStats` round
    /// trip when the VM is up. v5.
    Stats {
        name: String,
    },
    /// Proxy one guest control RPC (vsock 1025). `Wait` may block for the
    /// workload's lifetime — the daemon handles each connection on its own
    /// thread, so this is fine.
    GuestRpc {
        name: String,
        req: Request,
    },
    PortPublish {
        name: String,
        rule: PortRule,
        /// Persist the rule to `ports.json` so it survives daemon restarts.
        /// Defaults to false via serde so older client frames still deserialize.
        #[serde(default)]
        persist: bool,
    },
    PortUnpublish {
        name: String,
        bind: Ipv4Addr,
        host_port: u16,
    },
    PortList {
        name: String,
    },
    /// Convert this connection into a raw splice to the guest stream port
    /// (vsock 1026). Must be the last frame the client sends before raw
    /// bytes; the daemon replies `Ok` or `Error`, then splices.
    OpenStream {
        name: String,
    },
    Status,
    /// Remove persistent volume images not referenced by any sandbox config.
    VolumePrune,
    /// List all named persistent volumes known to the daemon.
    VolumeList,
    /// Delete a named persistent volume image.
    VolumeRemove {
        name: String,
    },
    /// Record a volume on a sandbox's config. Takes effect on the next
    /// start — there is no hotplug; a running VM keeps its current disks.
    VolumeAttach {
        name: String,
        spec: crate::volume::VolumeSpec,
    },
    /// Remove a volume from a sandbox's config by its guest mount-point.
    /// Like `VolumeAttach`, applies on the next start (no hot-unplug).
    VolumeDetach {
        name: String,
        guest_path: PathBuf,
    },
    /// Re-read a sandbox's `policy.yaml` and hot-swap it into the live egress
    /// plane (new flows only; no VM restart).
    ReloadPolicy {
        name: String,
    },
    /// Report the configured usbip upstream and its trust classification.
    /// Answerable with the feature OFF — it is how a user asks whether it is on.
    UsbUpstreamShow,
    /// Set (or replace) the usbip upstream. `allow_remote` opts into a
    /// globally-routable address, which is otherwise refused outright.
    UsbUpstreamSet {
        host: String,
        port: u16,
        #[serde(default)]
        allow_remote: bool,
    },
    /// Enumerate what the upstream exports, annotated with existing grants.
    UsbListDevices,
    /// Grant one `vid:pid` to one sandbox. The device travels as a string so a
    /// malformed id is a clean daemon-side error rather than a frame-read
    /// failure that would drop the connection.
    UsbAllow {
        name: String,
        device: String,
        #[serde(default)]
        busid_pin: Option<String>,
    },
    /// Withdraw a grant.
    UsbRevoke {
        name: String,
        device: String,
    },
    /// List a sandbox's device grants.
    UsbStatus {
        name: String,
    },
    /// Attach an already-granted device to a running sandbox. izbad checks the
    /// grant on the host side and then forwards an `izba_proto::Request` to
    /// izba-init, which dials the USB plane and hands the socket to `vhci-hcd`.
    UsbAttach {
        name: String,
        device: String,
    },
    /// Detach a device the sandbox currently holds.
    UsbDetach {
        name: String,
        device: String,
    },
    /// Enable or disable VNC display for a sandbox (spec 2026-08-09). Takes
    /// effect on the next start — there is no hot-toggle; a running VM keeps
    /// its current desktop (or lack of one) until restarted. v6.
    VncSet {
        name: String,
        enabled: bool,
    },
    /// Graceful daemon exit. Sandboxes keep running (detached children);
    /// in-daemon port relays pause until the next daemon adopts.
    Shutdown,
    /// Catch-all for a request `type` this daemon build does not know (a
    /// newer client talking to an older daemon within the same proto
    /// version). `#[serde(other)]` makes the frame read succeed so the
    /// server can reply an honest error instead of dropping the connection
    /// mid-conversation. Never sent by a client on purpose.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSummary {
    pub name: String,
    pub image_ref: String,
    /// `Liveness::describe()` output: "running" | "degraded (…)" | "stopped".
    pub status: String,
}

/// NOTE: `Debug` is implemented BY HAND below (not derived) because
/// `vnc_url` embeds a plaintext password. Keep it that way.
#[derive(Clone, Serialize, Deserialize)]
pub struct SandboxDetail {
    pub name: String,
    pub image_ref: String,
    pub image_digest: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: String,
    pub status: String,
    pub ports: Vec<PortRule>,
    /// Volumes declared for this sandbox. Defaults to empty so frames from
    /// older daemons still deserialize.
    #[serde(default)]
    pub volumes: Vec<crate::volume::VolumeSpec>,
    /// Host-side VMM confinement summary (`ConfinementStatus::summary()`), or
    /// `None` when the sandbox is stopped / its state predates the field — the
    /// CLI renders `None` as "unknown". serde(default) keeps older frames
    /// parseable.
    #[serde(default)]
    pub confinement: Option<String>,
    /// State of the in-guest OCI workload container, probed from the live guest
    /// at inspect time. `None` when the sandbox is stopped, the guest could not
    /// be reached, or the daemon predates container-state reporting — the CLI
    /// renders `None` as "unknown". serde(default) keeps older frames parseable
    /// so a stale daemon's reply self-heals into `None` rather than erroring.
    #[serde(default)]
    pub container: Option<izba_proto::ContainerState>,
    /// Present when the image's symbolic USER could not be resolved and the
    /// workload runs as root (#114): the original declared USER string.
    /// Additive + serde(default) → no DAEMON_PROTO_VERSION bump; None →
    /// the CLI prints nothing.
    #[serde(default)]
    pub user_fallback: Option<String>,
    /// Whether this sandbox runs in docker mode (#198): own netns + veth,
    /// userns-scoped admin caps, an auto `/var/lib/docker` volume, and an
    /// auto-started Docker Engine. Surfaced by `izba status`/`inspect` per
    /// spec §1. Additive + serde(default) → no DAEMON_PROTO_VERSION bump;
    /// `false` for an older daemon's frames and for non-docker sandboxes.
    #[serde(default)]
    pub docker: bool,
    /// VNC display (spec 2026-08-09): whether this sandbox is CONFIGURED to
    /// boot with a VNC desktop. Additive + serde(default) → no
    /// DAEMON_PROTO_VERSION bump; `false` for an older daemon's frames and
    /// for non-VNC sandboxes.
    #[serde(default)]
    pub vnc: bool,
    /// Whether a VNC relay is currently live for this sandbox. Wired in a
    /// later task (Task 9's relay registry); stays at its serde default
    /// (`false`) here. Additive + serde(default) → no DAEMON_PROTO_VERSION
    /// bump.
    #[serde(default)]
    pub vnc_running: bool,
    /// The URL a human can open to reach the live VNC desktop, when one is
    /// running. Wired in a later task (Task 9); stays at its serde default
    /// (`None`) here. Additive + serde(default) → no DAEMON_PROTO_VERSION
    /// bump.
    #[serde(default)]
    pub vnc_url: Option<String>,
    /// The sandbox is running with its VNC display configuration ahead of
    /// what it actually booted (either direction — enabling OR disabling VNC
    /// on a live run both need a restart to take effect), so it must be
    /// restarted for `vnc` to take effect. Additive + serde(default) → no
    /// DAEMON_PROTO_VERSION bump.
    #[serde(default)]
    pub vnc_restart_required: bool,
}

/// Hand-written so `vnc_url` — which carries the sandbox's plaintext VNC
/// password in its userinfo — is REDACTED. `SandboxDetail` travels inside
/// `DaemonResponse`, which is `Debug`-formatted freely in daemon/CLI error
/// paths and test panics (`{other:?}`), any one of which would otherwise
/// print the live credential into a log the user never meant to share.
/// Serde is untouched: the real URL still reaches the client that asked for
/// it. Every other field is printed verbatim.
impl std::fmt::Debug for SandboxDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxDetail")
            .field("name", &self.name)
            .field("image_ref", &self.image_ref)
            .field("image_digest", &self.image_digest)
            .field("cpus", &self.cpus)
            .field("mem_mb", &self.mem_mb)
            .field("workspace", &self.workspace)
            .field("status", &self.status)
            .field("ports", &self.ports)
            .field("volumes", &self.volumes)
            .field("confinement", &self.confinement)
            .field("container", &self.container)
            .field("user_fallback", &self.user_fallback)
            .field("docker", &self.docker)
            .field("vnc", &self.vnc)
            .field("vnc_running", &self.vnc_running)
            .field("vnc_url", &self.vnc_url.as_ref().map(|_| "<redacted>"))
            .field("vnc_restart_required", &self.vnc_restart_required)
            .finish()
    }
}

/// Resource stats for one sandbox (#203), served by `DaemonRequest::Stats`.
/// `host`/`disk` are host-derived — computed by the daemon from pid/cgroup
/// and filesystem metadata — and trusted. `guest` is guest-REPORTED (a live
/// round trip to `izba-init`'s `Request::Stats`) and therefore sanitized by
/// `daemon::stats::sanitize_guest_stats` before it ever reaches this struct;
/// never trust it further.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStats {
    pub name: String,
    pub running: bool,
    /// Wall time since the VM process started, when running.
    pub uptime_ms: Option<u64>,
    /// Host-observed CPU/RSS + the sandbox's configured limits. `None` when
    /// not running (there is no VMM process to sample).
    pub host: Option<HostResources>,
    pub disk: HostDisk,
    /// Sanitized guest-reported mini-top/mounts/docker-engine snapshot.
    /// `None` when the sandbox is stopped or the guest could not be reached.
    pub guest: Option<izba_proto::GuestStats>,
}

/// Host-observed process resource usage for a running sandbox's VMM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResources {
    /// CPU share over the sampling interval, in permille of one host CPU.
    /// `None` when a single sample can't yet yield a rate (first read).
    pub cpu_permille: Option<u32>,
    pub rss_kb: u64,
    pub cpus_limit: u32,
    pub mem_limit_mb: u32,
}

/// Host-computed on-disk footprint for a sandbox. Host-derived and trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDisk {
    pub rw_img_bytes: u64,
    pub volumes: Vec<VolumeDisk>,
    pub logs_bytes: u64,
    /// The rootfs image's on-disk size. Shared by every sandbox created from
    /// the SAME image (erofs layers are content-addressed) — do NOT sum this
    /// across sandboxes into a combined footprint, it double-counts shared
    /// storage.
    pub image_bytes: u64,
}

/// One declared volume's disk footprint, keyed by guest mountpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDisk {
    pub guest_path: String,
    pub allocated_bytes: u64,
    /// Whether this is the auto-provisioned docker-mode volume
    /// (`volume::is_docker_volume_path`), so the UI can label it distinctly.
    pub docker: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Display string (`build.short()`); retained for back-compat.
    pub version: String,
    /// The daemon's wire-protocol version.
    #[serde(default)]
    pub proto: u32,
    /// The daemon's full build metadata.
    #[serde(default)]
    pub build: BuildInfoOwned,
    pub pid: u32,
    pub uptime_ms: u64,
    pub socket: String,
    pub sandboxes: Vec<SandboxSummary>,
    /// Host-installed extra CA files izbad loaded at start (`<data>/trust/extra`,
    /// #283), in load order. Empty = webpki-roots only, OR a load failure —
    /// read it together with `trust_error`. `serde(default)`: a pre-#283
    /// daemon reads as "none loaded", which is the honest answer.
    #[serde(default)]
    pub extra_ca_files: Vec<String>,
    /// Why izbad has NO extra roots and no MITM: the extra-CA load (or CA /
    /// runtime init) failed. `Some` means every enforcing sandbox's HTTP(S)
    /// is failing closed, so `izba daemon status` must say so instead of
    /// printing the "drop your CA here" hint the operator already followed.
    /// `serde(default)` for the same reason as above.
    ///
    /// The directory PATH is deliberately NOT on the wire: the CLI holds
    /// `Paths` and renders `trust_extra_dir()` itself, so an older daemon can
    /// never make it print a sentence with an empty path in it.
    #[serde(default)]
    pub trust_error: Option<String>,
}

/// The configured usbip upstream, as reported to a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbUpstreamInfo {
    pub host: String,
    pub port: u16,
    /// The address `host` currently resolves to, when it resolves at all.
    pub resolved: Option<String>,
    /// `UpstreamTrust` as a stable kebab-case token.
    pub trust: String,
    /// The human-facing note for that trust class; `None` for the recommended
    /// (loopback) configuration, where silence is the honest answer.
    pub warning: Option<String>,
}

/// One device the upstream exports — or one usbipd knows about but has not
/// shared, in which case `bind_command` says how to share it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub busid: String,
    /// Canonical `vid:pid`.
    pub device: String,
    pub description: String,
    /// Whether the upstream is currently exporting it (`OP_REP_DEVLIST`).
    pub shared: bool,
    /// Sandboxes already holding a grant for this `vid:pid`.
    #[serde(default)]
    pub granted_to: Vec<String>,
    /// The sandbox currently holding this device, when one is. Host-observed —
    /// izbad is running the splice, so it never has to ask a guest. `None` for
    /// a free device. `serde(default)`: a pre-phase-4 daemon's frame reads as
    /// "nothing attached", which is the safe direction (it never invents a
    /// holder, only fails to name one).
    #[serde(default)]
    pub attached_to: Option<String>,
    /// For an unshared device: the exact command the human must run elevated.
    #[serde(default)]
    pub bind_command: Option<String>,
}

/// One standing grant, as reported to a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbGrantInfo {
    pub device: String,
    pub busid_pin: Option<String>,
    pub description: String,
    pub granted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    HelloOk {
        version: String,
        #[serde(default)]
        proto: u32,
        #[serde(default)]
        build: BuildInfoOwned,
    },
    Ok,
    Error {
        message: String,
    },
    /// Zero or more Progress frames may precede the terminal response of a
    /// long-running request (Create pulls, Start boot-waits).
    Progress {
        message: String,
    },
    Created {
        name: String,
    },
    /// A proxied guest control RPC response. The inner `Response` is nested
    /// under a `"payload"` field to avoid a serde tag collision (both types
    /// use `"type"` as their discriminant).
    Guest {
        payload: Response,
    },
    List {
        sandboxes: Vec<SandboxSummary>,
    },
    Inspect(SandboxDetail),
    /// Result of `DaemonRequest::Stats`.
    Stats(SandboxStats),
    Ports {
        rules: Vec<PortRule>,
    },
    Status(DaemonStatus),
    /// Result of a `VolumePrune` or `VolumeRemove`: which volumes were removed
    /// and bytes freed.
    Pruned {
        removed: Vec<String>,
        reclaimed_bytes: u64,
    },
    /// Result of a `VolumeList` request.
    Volumes {
        volumes: Vec<crate::volume::VolumeInfo>,
    },
    /// Result of `UsbUpstreamShow`. `None` ⇒ USB passthrough is not configured.
    UsbUpstream {
        upstream: Option<UsbUpstreamInfo>,
    },
    /// Result of `UsbListDevices`.
    UsbDevices {
        devices: Vec<UsbDeviceInfo>,
    },
    /// Result of `UsbStatus`.
    UsbStatus {
        grants: Vec<UsbGrantInfo>,
        /// `vid:pid` of every device this sandbox is holding right now.
        #[serde(default)]
        attached: Vec<String>,
        /// The sandbox is running a kernel with no USB stack while holding at
        /// least one grant, so an attach cannot work until it restarts. Both
        /// new fields are `serde(default)` — additive on an existing variant,
        /// so `DAEMON_PROTO_VERSION` stays where it is.
        #[serde(default)]
        restart_required: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::{read_frame, write_frame, Request, Response};

    #[test]
    fn request_roundtrip() {
        for req in [
            DaemonRequest::Create(DaemonCreate {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 2,
                mem_mb: 4096,
                workspace: std::path::PathBuf::from("/ws"),
                rw_size_gb: 8,
                ports: vec![crate::state::PortRule {
                    bind: "127.0.0.1".parse().unwrap(),
                    host_port: 8080,
                    guest_port: 80,
                }],
                volumes: vec![crate::volume::VolumeSpec {
                    name: Some("cache".into()),
                    guest_path: "/data".into(),
                    size_bytes: 1 << 30,
                    eph_id: None,
                }],
                allow_unconfined: false,
                builder: true,
                docker: Some(true),
                vnc: true,
            }),
            DaemonRequest::VolumePrune,
            DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: false,
            },
            DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: true,
            },
            DaemonRequest::Stop { name: "web".into() },
            DaemonRequest::Rm {
                name: "web".into(),
                force: true,
            },
            DaemonRequest::List,
            DaemonRequest::Inspect { name: "web".into() },
            DaemonRequest::Stats { name: "web".into() },
            DaemonRequest::GuestRpc {
                name: "web".into(),
                req: Request::Health,
            },
            DaemonRequest::PortPublish {
                name: "web".into(),
                rule: crate::state::PortRule {
                    bind: "127.0.0.1".parse().unwrap(),
                    host_port: 8080,
                    guest_port: 80,
                },
                persist: false,
            },
            DaemonRequest::PortUnpublish {
                name: "web".into(),
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
            },
            DaemonRequest::PortList { name: "web".into() },
            DaemonRequest::OpenStream { name: "web".into() },
            DaemonRequest::ReloadPolicy { name: "web".into() },
            DaemonRequest::Status,
            DaemonRequest::Shutdown,
            DaemonRequest::VolumeList,
            DaemonRequest::VolumeRemove {
                name: "cache".into(),
            },
            DaemonRequest::VolumeAttach {
                name: "web".into(),
                spec: crate::volume::VolumeSpec {
                    name: Some("cache".into()),
                    guest_path: "/data".into(),
                    size_bytes: 1 << 30,
                    eph_id: None,
                },
            },
            DaemonRequest::VolumeDetach {
                name: "web".into(),
                guest_path: PathBuf::from("/data"),
            },
            DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).unwrap();
            let back: DaemonRequest = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    /// A `create` frame from a pre-`builder` client (the field absent) must
    /// deserialize to `builder: false` — additive, no proto bump.
    #[test]
    fn create_without_builder_defaults_false() {
        let json = serde_json::json!({
            "type": "create",
            "name": "web",
            "image_ref": "ubuntu:24.04",
            "cpus": 2,
            "mem_mb": 4096,
            "workspace": "/ws",
            "rw_size_gb": 8,
            "ports": [],
        });
        let req: DaemonRequest = serde_json::from_value(json).unwrap();
        let DaemonRequest::Create(c) = req else {
            panic!("expected Create");
        };
        assert!(!c.builder, "absent builder field defaults to false");
        assert!(!c.allow_unconfined);
        assert!(c.volumes.is_empty());
    }

    /// A pre-feature client's frame has no `docker` key; it must deserialize
    /// to None (= "no CLI preference, label decides") — additive field, no
    /// DAEMON_PROTO_VERSION bump.
    #[test]
    fn create_without_docker_defaults_none() {
        let json = r#"{"type":"create","name":"s","image_ref":"alpine","cpus":1,"mem_mb":256,"workspace":"/w","rw_size_gb":8,"ports":[]}"#;
        let req: DaemonRequest = serde_json::from_str(json).expect("deserialize");
        match req {
            DaemonRequest::Create(c) => assert_eq!(c.docker, None),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn response_roundtrip() {
        for resp in [
            DaemonResponse::HelloOk {
                version: "0.1.0".into(),
                proto: DAEMON_PROTO_VERSION,
                build: BuildInfoOwned::current(),
            },
            DaemonResponse::Ok,
            DaemonResponse::Error {
                message: "boom".into(),
            },
            DaemonResponse::Progress {
                message: "pulling".into(),
            },
            DaemonResponse::Created { name: "web".into() },
            DaemonResponse::Guest {
                payload: Response::Ok,
            },
            DaemonResponse::List {
                sandboxes: vec![SandboxSummary {
                    name: "web".into(),
                    image_ref: "ubuntu:24.04".into(),
                    status: "running".into(),
                }],
            },
            DaemonResponse::Inspect(SandboxDetail {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                image_digest: "sha256:abc".into(),
                cpus: 2,
                mem_mb: 4096,
                workspace: "/ws".into(),
                status: "running".into(),
                ports: vec![],
                volumes: vec![],
                confinement: Some("confined: restricted(limited)+low-il+job".into()),
                container: Some(izba_proto::ContainerState::Running),
                user_fallback: Some("node".into()),
                docker: false,
                vnc: false,
                vnc_running: false,
                vnc_url: None,
                vnc_restart_required: false,
            }),
            DaemonResponse::Ports { rules: vec![] },
            DaemonResponse::Pruned {
                removed: vec!["cache".into()],
                reclaimed_bytes: 1 << 30,
            },
            DaemonResponse::Volumes { volumes: vec![] },
            DaemonResponse::Status(DaemonStatus {
                version: "0.1.0".into(),
                proto: DAEMON_PROTO_VERSION,
                build: BuildInfoOwned::current(),
                pid: 42,
                uptime_ms: 1000,
                socket: "/x/izbad.sock".into(),
                sandboxes: vec![],
                extra_ca_files: vec![],
                trust_error: None,
            }),
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).unwrap();
            let back: DaemonResponse = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }

    /// #283: a pre-#283 daemon's Status frame (no trust fields) must still
    /// deserialize — the fields are additive and defaulted, no proto bump.
    #[test]
    fn daemon_status_trust_fields_default_when_absent() {
        let json = serde_json::json!({
            "version": "x", "pid": 1, "uptime_ms": 0, "socket": "s", "sandboxes": []
        });
        let s: DaemonStatus = serde_json::from_value(json).unwrap();
        assert!(s.extra_ca_files.is_empty());
        assert!(s.trust_error.is_none());
    }

    #[test]
    fn stable_wire_tags() {
        // Tags both sides depend on across versions (hello must stay parseable
        // by older daemons so the upgrade dance can run).
        let s = serde_json::to_string(&DaemonHello {
            version: "1".into(),
            proto: DAEMON_PROTO_VERSION,
        })
        .unwrap();
        assert!(s.contains(r#""version":"1""#), "{s}");
        let s = serde_json::to_string(&DaemonResponse::HelloOk {
            version: "1".into(),
            proto: DAEMON_PROTO_VERSION,
            build: BuildInfoOwned::current(),
        })
        .unwrap();
        assert!(s.contains(r#""type":"hello_ok""#), "{s}");
        let s = serde_json::to_string(&DaemonRequest::Shutdown).unwrap();
        assert!(s.contains(r#""type":"shutdown""#), "{s}");
        let s = serde_json::to_string(&DaemonRequest::OpenStream { name: "w".into() }).unwrap();
        assert!(s.contains(r#""type":"open_stream""#), "{s}");
        let s = serde_json::to_string(&DaemonRequest::ReloadPolicy { name: "w".into() }).unwrap();
        assert!(s.contains(r#""type":"reload_policy""#), "{s}");
    }

    #[test]
    fn old_start_without_allow_unconfined_defaults_false() {
        // A pre-confinement client's Start frame has no allow_unconfined key;
        // serde(default) must read it as false so the daemon confines.
        let json = r#"{"type":"start","name":"web"}"#;
        let back: DaemonRequest = serde_json::from_str(json).unwrap();
        match back {
            DaemonRequest::Start {
                name,
                allow_unconfined,
            } => {
                assert_eq!(name, "web");
                assert!(!allow_unconfined, "missing field must default to confine");
            }
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[test]
    fn old_create_without_allow_unconfined_defaults_false() {
        // A pre-confinement client's Create frame has no allow_unconfined key;
        // serde(default) must read it as false so the daemon runs the confinement
        // preflight (the common case) rather than silently skipping it.
        let json = r#"{"type":"create","name":"web","image_ref":"ubuntu:24.04","cpus":2,"mem_mb":4096,"workspace":"/w","rw_size_gb":8,"ports":[]}"#;
        let back: DaemonRequest = serde_json::from_str(json).unwrap();
        match back {
            DaemonRequest::Create(c) => {
                assert_eq!(c.name, "web");
                assert!(
                    !c.allow_unconfined,
                    "missing field must default to confined intent"
                );
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn old_inspect_without_container_defaults_none() {
        // A pre-Phase-7 daemon's Inspect frame had no `container` key;
        // serde(default) must read it as None (→ CLI "unknown") rather than
        // failing to deserialize, so a stale daemon self-heals on the wire.
        let json = r#"{"type":"inspect","name":"web","image_ref":"ubuntu:24.04","image_digest":"sha256:abc","cpus":2,"mem_mb":4096,"workspace":"/ws","status":"running","ports":[]}"#;
        let back: DaemonResponse = serde_json::from_str(json).unwrap();
        match back {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.container, None);
                assert_eq!(det.volumes.len(), 0);
                assert_eq!(det.confinement, None);
                assert_eq!(det.user_fallback, None);
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    /// `vnc_url` carries the sandbox's plaintext VNC password, and
    /// `SandboxDetail` is `Debug`-formatted freely (daemon/CLI error paths,
    /// test panics). The hand-written `Debug` must redact it — while serde
    /// still carries the real URL to the client that asked for it.
    #[test]
    fn debug_redacts_the_vnc_url_password() {
        let det = SandboxDetail {
            name: "desk".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 1,
            mem_mb: 512,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: None,
            user_fallback: None,
            docker: false,
            vnc: true,
            vnc_running: true,
            vnc_url: Some("http://izba:sup3rs3cr3tpassw0rd@127.0.0.1:41234/".into()),
            vnc_restart_required: false,
        };
        let rendered = format!("{det:?}");
        assert!(
            !rendered.contains("sup3rs3cr3tpassw0rd"),
            "Debug leaked the VNC password: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Other fields still print, and the WIRE form is untouched.
        assert!(rendered.contains("desk"), "{rendered}");
        assert!(
            serde_json::to_string(&det)
                .unwrap()
                .contains("sup3rs3cr3tpassw0rd"),
            "serde must still carry the real URL"
        );
        // A detail without a URL prints None, not a redaction marker.
        let plain = SandboxDetail {
            vnc_url: None,
            ..det
        };
        let rendered = format!("{plain:?}");
        assert!(rendered.contains("vnc_url: None"), "{rendered}");
    }

    #[test]
    fn inspect_container_state_roundtrips() {
        let resp = DaemonResponse::Inspect(SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 1,
            mem_mb: 512,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: Some(izba_proto::ContainerState::Stopped),
            user_fallback: None,
            docker: true,
            vnc: false,
            vnc_running: false,
            vnc_url: None,
            vnc_restart_required: false,
        });
        let json = serde_json::to_string(&resp).unwrap();
        let back: DaemonResponse = serde_json::from_str(&json).unwrap();
        match back {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.container, Some(izba_proto::ContainerState::Stopped));
                // #198: docker mode surfaces over the Inspect wire.
                assert!(det.docker, "docker flag must round-trip");
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    #[test]
    fn inspect_docker_field_defaults_false_for_older_daemon_frames() {
        // A pre-#198 daemon's Inspect frame has no `docker` key; serde(default)
        // must deserialize it to `false` (no DAEMON_PROTO_VERSION bump). Build
        // the frame from a real SandboxDetail and drop the key, so this stays
        // faithful to the derived wire shape rather than a hand-typed guess.
        let resp = DaemonResponse::Inspect(SandboxDetail {
            name: "web".into(),
            image_ref: "i".into(),
            image_digest: "d".into(),
            cpus: 1,
            mem_mb: 512,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: None,
            user_fallback: None,
            docker: true,
            vnc: false,
            vnc_running: false,
            vnc_url: None,
            vnc_restart_required: false,
        });
        // DaemonResponse is internally tagged (`#[serde(tag = "type")]`), so a
        // newtype variant flattens its struct's fields alongside `type` at the
        // top level — the `docker` key lives there, not under an "Inspect" key.
        let mut v = serde_json::to_value(&resp).unwrap();
        assert!(
            v.as_object_mut().unwrap().remove("docker").is_some(),
            "the serialized frame must have carried a docker key to remove"
        );
        let back: DaemonResponse = serde_json::from_value(v).unwrap();
        match back {
            DaemonResponse::Inspect(det) => assert!(!det.docker),
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    #[test]
    fn hello_ok_carries_proto_and_build() {
        let resp = DaemonResponse::HelloOk {
            version: "0.1.0 (9f0d480)".into(),
            proto: DAEMON_PROTO_VERSION,
            build: BuildInfoOwned::current(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: DaemonResponse = serde_json::from_str(&json).unwrap();
        match back {
            DaemonResponse::HelloOk { proto, .. } => assert_eq!(proto, DAEMON_PROTO_VERSION),
            other => panic!("expected HelloOk, got {other:?}"),
        }
    }

    #[test]
    fn usb_requests_roundtrip() {
        for req in [
            DaemonRequest::UsbUpstreamShow,
            DaemonRequest::UsbUpstreamSet {
                host: "172.24.32.1".into(),
                port: 3240,
                allow_remote: false,
            },
            DaemonRequest::UsbListDevices,
            DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: Some("3-2".into()),
            },
            DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
            DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbStatus { name: "web".into() },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).unwrap();
            let back: DaemonRequest = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn usb_responses_roundtrip() {
        for resp in [
            DaemonResponse::UsbUpstream {
                upstream: Some(UsbUpstreamInfo {
                    host: "127.0.0.1".into(),
                    port: 3240,
                    resolved: Some("127.0.0.1".into()),
                    trust: "own-host-loopback".into(),
                    warning: None,
                }),
            },
            DaemonResponse::UsbUpstream { upstream: None },
            DaemonResponse::UsbDevices {
                devices: vec![UsbDeviceInfo {
                    busid: "3-2".into(),
                    device: "0403:6001".into(),
                    description: "USB Serial Converter".into(),
                    shared: true,
                    granted_to: vec!["web".into()],
                    attached_to: Some("web".into()),
                    bind_command: None,
                }],
            },
            DaemonResponse::UsbStatus {
                grants: vec![UsbGrantInfo {
                    device: "0403:6001".into(),
                    busid_pin: None,
                    description: "USB Serial Converter".into(),
                    granted_at_unix_ms: 1_700_000_000_000,
                }],
                attached: vec!["0403:6001".into()],
                restart_required: true,
            },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).unwrap();
            let back: DaemonResponse = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn usb_wire_tags_are_stable() {
        for (req, tag) in [
            (
                DaemonRequest::UsbUpstreamShow,
                r#""type":"usb_upstream_show""#,
            ),
            (
                DaemonRequest::UsbListDevices,
                r#""type":"usb_list_devices""#,
            ),
            (
                DaemonRequest::UsbStatus { name: "w".into() },
                r#""type":"usb_status""#,
            ),
            (
                DaemonRequest::UsbRevoke {
                    name: "w".into(),
                    device: "0403:6001".into(),
                },
                r#""type":"usb_revoke""#,
            ),
        ] {
            let s = serde_json::to_string(&req).unwrap();
            assert!(s.contains(tag), "{s}");
        }
    }

    #[test]
    fn proto_version_is_bumped_for_the_new_request_variants() {
        // A same-version daemon predating these variants would fail the frame
        // read instead of self-healing via a restart, so the COMPATIBILITY gate
        // must move with them.
        assert_eq!(DAEMON_PROTO_VERSION, 6);
    }

    #[test]
    fn stats_daemon_frames_round_trip() {
        let req = DaemonRequest::Stats { name: "web".into() };
        let s = serde_json::to_string(&req).unwrap();
        let back: DaemonRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, DaemonRequest::Stats { name } if name == "web"));

        let resp = DaemonResponse::Stats(SandboxStats {
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
            guest: None,
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: DaemonResponse = serde_json::from_str(&s).unwrap();
        match back {
            DaemonResponse::Stats(st) => {
                assert!(st.disk.volumes[0].docker);
                assert_eq!(st.host.unwrap().cpu_permille, Some(340));
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn the_usb_datapath_requests_roundtrip() {
        for req in [
            DaemonRequest::UsbAttach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbDetach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ] {
            let s = serde_json::to_string(&req).unwrap();
            let back: DaemonRequest = serde_json::from_str(&s).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn a_usb_allow_without_a_pin_deserializes_unpinned() {
        // The pin is optional on the wire; its absence must mean "no pin", not
        // a frame-read failure.
        let json = r#"{"type":"usb_allow","name":"web","device":"0403:6001"}"#;
        match serde_json::from_str::<DaemonRequest>(json).unwrap() {
            DaemonRequest::UsbAllow { busid_pin, .. } => assert!(busid_pin.is_none()),
            other => panic!("expected UsbAllow, got {other:?}"),
        }
    }

    #[test]
    fn a_usb_upstream_set_without_allow_remote_defaults_to_refusing() {
        let json = r#"{"type":"usb_upstream_set","host":"h","port":3240}"#;
        match serde_json::from_str::<DaemonRequest>(json).unwrap() {
            DaemonRequest::UsbUpstreamSet { allow_remote, .. } => {
                assert!(
                    !allow_remote,
                    "a missing opt-in must never read as opted in"
                );
            }
            other => panic!("expected UsbUpstreamSet, got {other:?}"),
        }
    }

    #[test]
    fn a_pre_phase4_usb_frame_still_deserializes() {
        // Old daemon, new client. Both new facts must read as "nothing
        // attached, no restart needed" rather than failing the frame — that is
        // what keeps these additions off DAEMON_PROTO_VERSION.
        let d: UsbDeviceInfo = serde_json::from_str(
            r#"{"busid":"3-2","device":"0403:6001","description":"FT232","shared":true}"#,
        )
        .unwrap();
        assert_eq!(d.attached_to, None);

        let r: DaemonResponse =
            serde_json::from_str(r#"{"type":"usb_status","grants":[]}"#).unwrap();
        match r {
            DaemonResponse::UsbStatus {
                attached,
                restart_required,
                ..
            } => {
                assert!(attached.is_empty());
                assert!(!restart_required);
            }
            other => panic!("expected usb_status, got {other:?}"),
        }
    }

    #[test]
    fn old_hello_ok_without_proto_defaults_to_zero() {
        // An old daemon's frame had only {"type":"hello_ok","version":"x"}.
        let json = r#"{"type":"hello_ok","version":"old"}"#;
        let back: DaemonResponse = serde_json::from_str(json).unwrap();
        match back {
            DaemonResponse::HelloOk {
                proto,
                version,
                build,
            } => {
                assert_eq!(proto, 0);
                assert_eq!(version, "old");
                assert_eq!(build, BuildInfoOwned::default());
            }
            other => panic!("expected HelloOk, got {other:?}"),
        }
    }
}
