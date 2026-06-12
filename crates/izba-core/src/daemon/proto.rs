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

use crate::state::PortRule;
use izba_proto::{Request, Response};

/// First frame on every daemon connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHello {
    pub version: String,
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
    /// Egress datapath (M1 transition knob). Defaults for old clients.
    #[serde(default)]
    pub egress: crate::state::EgressMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonRequest {
    Create(DaemonCreate),
    Start {
        name: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
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
                egress: crate::state::EgressMode::Passt,
            }),
            DaemonRequest::Start { name: "web".into() },
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
            },
            DaemonRequest::PortUnpublish {
                name: "web".into(),
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
            },
            DaemonRequest::PortList { name: "web".into() },
            DaemonRequest::OpenStream { name: "web".into() },
            DaemonRequest::Status,
            DaemonRequest::Shutdown,
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).unwrap();
            let back: DaemonRequest = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn response_roundtrip() {
        for resp in [
            DaemonResponse::HelloOk {
                version: "0.1.0".into(),
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
            }),
            DaemonResponse::Ports { rules: vec![] },
            DaemonResponse::Status(DaemonStatus {
                version: "0.1.0".into(),
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
        })
        .unwrap();
        assert!(s.contains(r#""version":"1""#), "{s}");
        let s = serde_json::to_string(&DaemonResponse::HelloOk {
            version: "1".into(),
        })
        .unwrap();
        assert!(s.contains(r#""type":"hello_ok""#), "{s}");
        let s = serde_json::to_string(&DaemonRequest::Shutdown).unwrap();
        assert!(s.contains(r#""type":"shutdown""#), "{s}");
        let s = serde_json::to_string(&DaemonRequest::OpenStream { name: "w".into() }).unwrap();
        assert!(s.contains(r#""type":"open_stream""#), "{s}");
    }
}
