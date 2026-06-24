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
/// daemon. Bump only on a wire-breaking change to any daemon frame.
pub const DAEMON_PROTO_VERSION: u32 = 1;

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
    /// Attach a volume to a running sandbox.
    VolumeAttach {
        name: String,
        spec: crate::volume::VolumeSpec,
    },
    /// Detach a volume from a running sandbox by its guest mount-point.
    VolumeDetach {
        name: String,
        guest_path: PathBuf,
    },
    /// Re-read a sandbox's `policy.yaml` and hot-swap it into the live egress
    /// plane (new flows only; no VM restart).
    ReloadPolicy {
        name: String,
    },
    /// Graceful daemon exit. Sandboxes keep running (detached children);
    /// in-daemon port relays pause until the next daemon adopts.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSummary {
    pub name: String,
    pub image_ref: String,
    /// `Liveness::describe()` output: "running" | "degraded (…)" | "stopped".
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            }),
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).unwrap();
            let back: DaemonResponse = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
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
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
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
        });
        let json = serde_json::to_string(&resp).unwrap();
        let back: DaemonResponse = serde_json::from_str(&json).unwrap();
        match back {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.container, Some(izba_proto::ContainerState::Stopped));
            }
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
