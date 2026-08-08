use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
    pub tty: bool,
    pub uid: u32,
    /// Group id for the spawned process; typically matches uid.
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Health,
    Exec(ExecRequest),
    Wait {
        exec_id: u32,
    },
    Kill {
        exec_id: u32,
        signal: i32,
    },
    Resize {
        exec_id: u32,
        cols: u16,
        rows: u16,
    },
    Shutdown,
    /// Attach a granted USB device inside the guest: init dials the USB plane
    /// (see [`StreamOpen::UsbAttach`]) and hands the resulting socket to
    /// `vhci-hcd`. Attach is **host-initiated** — the human runs
    /// `izba usb attach`, izbad forwards this, and the guest never chooses
    /// which device or learns where it comes from.
    ///
    /// Refused with [`ErrorKind::UsbUnavailable`] unless the guest booted with
    /// `izba.usb=1`, which only the host can put on the kernel cmdline.
    UsbAttach {
        device: String,
    },
    /// Detach a device this guest previously attached, by the same `vid:pid`.
    UsbDetach {
        device: String,
    },
    /// Guest resource stats for the host's status surfaces: mini-top,
    /// memory, load, mount fullness, docker-engine liveness. Read-only,
    /// side-effect-free; the reply is UNTRUSTED guest data which izbad
    /// sanitizes before display. Takes ~250 ms (in-call CPU sampling).
    Stats,
}

/// State of the in-guest OCI workload container, as reported by `crun state`.
///
/// Carried as an optional field on [`HealthInfo`] so the host can report
/// honestly when the workload has exited even though the VM — and thus the
/// guest health RPC itself — is still alive. The variants mirror the OCI
/// runtime status set (`creating`/`created`/`running`/`stopped`/`paused`);
/// `Unknown` means crun could not be queried or its output was unparseable
/// and is explicitly NOT a healthy claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    Creating,
    Created,
    Running,
    Stopped,
    Paused,
    Unknown,
}

impl ContainerState {
    /// Map an OCI `state.status` value to a `ContainerState`. Any value the
    /// OCI spec (and crun) does not define maps to [`ContainerState::Unknown`].
    pub fn from_oci_status(status: &str) -> Self {
        match status {
            "creating" => ContainerState::Creating,
            "created" => ContainerState::Created,
            "running" => ContainerState::Running,
            "stopped" => ContainerState::Stopped,
            "paused" => ContainerState::Paused,
            _ => ContainerState::Unknown,
        }
    }

    /// Lowercase display token; round-trips with [`ContainerState::from_oci_status`]
    /// for every variant except `Unknown` (which has no OCI status).
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerState::Creating => "creating",
            ContainerState::Created => "created",
            ContainerState::Running => "running",
            ContainerState::Stopped => "stopped",
            ContainerState::Paused => "paused",
            ContainerState::Unknown => "unknown",
        }
    }

    /// Whether this state represents a live workload (`running`).
    pub fn is_running(self) -> bool {
        matches!(self, ContainerState::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    pub version: String,
    pub uptime_ms: u64,
    /// State of the in-guest OCI workload container, when the guest knows it.
    /// `None` when the reporting guest predates container-state reporting;
    /// `#[serde(default)]` keeps such older frames parseable, and the host
    /// renders `None` as "unknown".
    #[serde(default)]
    pub container: Option<ContainerState>,
}

/// One process in the guest's mini-top, reported by init's `/proc` scan.
/// All fields are guest-reported and therefore UNTRUSTED: the daemon
/// sanitizes `comm` and truncates the containing list before anything
/// host-side renders it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcSample {
    pub pid: u32,
    /// `/proc/<pid>/comm` — guest-controlled bytes.
    pub comm: String,
    /// Kernel state char (R/S/D/Z/T/…).
    pub state: char,
    /// CPU share over the sampling interval, in permille of ONE cpu
    /// (a multi-threaded process can exceed 1000).
    pub cpu_permille: u32,
    pub rss_kb: u64,
}

/// Filesystem-level fullness of one guest mount (statfs), under its guest
/// path (`/`, `/var/lib/docker`, …). Guest-reported, untrusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountUsage {
    pub path: String,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

/// Nested Docker Engine liveness as observed by init (a live `dockerd`
/// process in the guest's pid namespace tree). Present only when the
/// sandbox booted with `izba.docker=1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerEngine {
    pub running: bool,
    /// When `!running`: a bounded tail of the engine log, so the host can
    /// say WHY (crashed vs "image ships no dockerd"). Guest-controlled.
    pub detail: Option<String>,
}

/// Guest-side stats payload for [`Request::Stats`]. Everything here is
/// guest-reported: the host treats it as display data, never as authority.
/// CPU percentages are computed inside the call (two `/proc` samples
/// ~250 ms apart), so the RPC is stateless.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestStats {
    /// Top processes by CPU over the sampling interval, descending.
    pub processes: Vec<ProcSample>,
    /// Total live processes in the guest (all pid namespaces — init's
    /// `/proc` sees the workload container's tree too).
    pub process_count: u32,
    /// Load averages × 100 (`/proc/loadavg`).
    pub load1_centi: u32,
    pub load5_centi: u32,
    pub load15_centi: u32,
    /// `/proc/meminfo` MemTotal / MemAvailable.
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub mounts: Vec<MountUsage>,
    /// `Some` only when the guest booted with `izba.docker=1`.
    pub docker: Option<DockerEngine>,
    /// Same container state `Health` reports — lets the daemon serve both
    /// from one guest round-trip.
    pub container: Option<ContainerState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    CommandNotFound,
    ExecNotFound,
    BadRequest,
    Internal,
    /// cp: the named guest path (src or dest parent) does not exist.
    PathNotFound,
    /// port publish: init could not connect to the requested guest port.
    ConnectFailed,
    /// USB passthrough is not available in this guest: it did not boot with a
    /// USB-capable kernel (no `izba.usb=1`). Distinct from `BadRequest` because
    /// the fix is a restart of the sandbox, not a corrected call — a sandbox
    /// gains USB support at boot, when its first grant selects the USB kernel.
    UsbUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Health(HealthInfo),
    ExecStarted {
        exec_id: u32,
    },
    Wait {
        status: ExitStatus,
    },
    Ok,
    /// A device was imported for this guest. `devid` and `speed` are what
    /// `vhci-hcd` needs alongside the socket fd; izbad resolved both from the
    /// upstream's device record, so the guest never has to enumerate anything.
    UsbAttached {
        devid: u32,
        speed: u32,
    },
    Stats(GuestStats),
    Error {
        kind: ErrorKind,
        message: String,
    },
}

/// First frame on a port-1026 connection, attaching it to an exec's stream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
    Tty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAttach {
    pub exec_id: u32,
    pub kind: StreamKind,
}

/// First frame on a port-1026 connection, selecting what the connection is.
/// After this frame the connection carries raw bytes whose framing depends
/// on the variant (see each variant's doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamOpen {
    /// Attach to an exec's stdio/tty stream; raw bytes follow (both ways
    /// for `Tty`). On attach failure: one `Response::Error` frame, close.
    Attach(StreamAttach),
    /// Port-publish relay: init dials `127.0.0.1:port` inside the guest and
    /// replies one `Response` frame (`Ok` | `Error{ConnectFailed}`); on `Ok`
    /// the connection becomes a raw bidirectional byte pipe.
    TcpDial { port: u16 },
    /// cp host→guest: a raw tar stream follows; init extracts under `dest`
    /// (workload-root-relative), then replies one trailing `Response` frame.
    TarExtract { dest: String },
    /// cp guest→host: init replies one `Response` frame first (`Ok` |
    /// `Error{PathNotFound}`), then streams a tar of `src` and closes.
    TarCreate { src: String },
    /// Guest egress (vsock 1027, guest-initiated): izbad dials `addr:port`
    /// on the host and replies one `Response` frame (`Ok` |
    /// `Error{ConnectFailed}`); on `Ok` the connection becomes a raw
    /// bidirectional byte pipe. `addr` is an IP literal in M1
    /// (SO_ORIGINAL_DST); a name-carrying form is M5 scope.
    TcpConnect { addr: String, port: u16 },
    /// Guest DNS (vsock 1027, guest-initiated): DNS-over-TCP framing
    /// follows (see `crate::dns`), request/response alternating;
    /// sequential queries allowed; EOF closes.
    ///
    /// `Dns` carries a UDP-origin query: izbad caps the answer at the 512-byte
    /// non-EDNS UDP limit and sets TC=1 when it would overflow, so the guest
    /// retries over TCP (see [`StreamOpen::DnsTcp`]).
    Dns,
    /// Guest DNS over TCP (vsock 1027, guest-initiated): identical framing and
    /// dispatch to [`StreamOpen::Dns`], but the query reached the guest stub
    /// over TCP:53 (a UDP TC=1 retry, or a client that prefers TCP). izbad
    /// returns the full answer — up to the 64 KiB the 2-byte length prefix
    /// allows — instead of truncating at 512 bytes. Without this the guest can
    /// never resolve a name whose answer exceeds 512 bytes (e.g. a CDN or
    /// split-horizon record set): the UDP reply truncates and the TCP retry,
    /// lacking a path that signals "TCP", would truncate again in a loop.
    DnsTcp,
    /// Guest USB attach (vsock 1028, guest-initiated): the guest names a
    /// granted device by `vid:pid` and nothing else — never an address, never
    /// a busid. izbad resolves it against that sandbox's grants, performs the
    /// entire USB/IP op phase itself, and replies one `Response` frame
    /// ([`Response::UsbAttached`] | `Error`). On `UsbAttached` the connection
    /// becomes the raw USB/IP URB stream, which the guest hands straight to
    /// `vhci-hcd`; izbad validates every URB header travelling this way (the
    /// guest → upstream direction terminates in a privileged host service) and
    /// splices the replies opaquely.
    UsbAttach { device: String },
}

pub const CONTROL_PORT: u32 = 1025;
pub const STREAM_PORT: u32 = 1026;
/// Guest-dialed host port for egress streams; the VMM bridges it to the
/// `run/vsock.sock_1027` unix listener owned by izbad (Firecracker hybrid-
/// vsock convention, shared by Cloud Hypervisor and OpenVMM).
pub const EGRESS_PORT: u32 = 1027;
/// Guest-dialed host port for USB attach streams, bridged the same way to
/// `run/vsock.sock_1028`. izbad binds it **only** for a sandbox that holds at
/// least one device grant: with USB off there is nothing to dial, rather than
/// something that would refuse.
pub const USB_PORT: u32 = 1028;

/// Guest-side path of the vendored pause binary that izba-init bind-mounts
/// into the container (shared host↔guest contract: izba-core builds the OCI
/// `config.json` pause_argv from this; izba-init places the binary here).
pub const PAUSE_GUEST_PATH: &str = "/.izba/pause";

/// virtiofs tag of the per-sandbox OCI bundle share (`oci/config.json`).
/// The host side writes it; the guest mounts it as the OCI bundle dir for crun.
pub const OCI_TAG: &str = "izba-oci";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        for req in [
            Request::Health,
            Request::Exec(ExecRequest {
                argv: vec!["bash".into(), "-l".into()],
                env: vec![("TERM".into(), "xterm".into())],
                cwd: "/workspace".into(),
                tty: true,
                uid: 0,
                gid: 0,
            }),
            Request::Wait { exec_id: 7 },
            Request::Kill {
                exec_id: 7,
                signal: 15,
            },
            Request::Resize {
                exec_id: 7,
                cols: 80,
                rows: 24,
            },
            Request::Shutdown,
            Request::UsbAttach {
                device: "0403:6001".into(),
            },
            Request::UsbDetach {
                device: "0403:6001".into(),
            },
        ] {
            let mut buf = Vec::new();
            crate::write_frame(&mut buf, &req).unwrap();
            let back: Request = crate::read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn error_kinds_serialize_stably() {
        let r = Response::Error {
            kind: ErrorKind::ExecNotFound,
            message: "no".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("exec_not_found"), "{s}");

        let r2 = Response::Error {
            kind: ErrorKind::CommandNotFound,
            message: "not found".into(),
        };
        let s2 = serde_json::to_string(&r2).unwrap();
        assert!(s2.contains("command_not_found"), "{s2}");

        let r3 = Response::Error {
            kind: ErrorKind::BadRequest,
            message: "bad".into(),
        };
        let s3 = serde_json::to_string(&r3).unwrap();
        assert!(s3.contains("bad_request"), "{s3}");
    }

    #[test]
    fn stream_open_roundtrip_and_stable_tags() {
        for open in [
            StreamOpen::Attach(StreamAttach {
                exec_id: 7,
                kind: StreamKind::Tty,
            }),
            StreamOpen::TcpDial { port: 8000 },
            StreamOpen::TarExtract {
                dest: "/etc/app".into(),
            },
            StreamOpen::TarCreate {
                src: "data/out".into(),
            },
            StreamOpen::TcpConnect {
                addr: "93.184.216.34".into(),
                port: 443,
            },
            StreamOpen::Dns,
            StreamOpen::DnsTcp,
            StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
        ] {
            let mut buf = Vec::new();
            crate::write_frame(&mut buf, &open).unwrap();
            let back: StreamOpen = crate::read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{open:?}"), format!("{back:?}"));
        }
        // Wire tags both sides depend on.
        for (open, tag) in [
            (StreamOpen::TcpDial { port: 1 }, r#""type":"tcp_dial""#),
            (
                StreamOpen::TarExtract { dest: "d".into() },
                r#""type":"tar_extract""#,
            ),
            (
                StreamOpen::TarCreate { src: "s".into() },
                r#""type":"tar_create""#,
            ),
            (
                StreamOpen::TcpConnect {
                    addr: "1.2.3.4".into(),
                    port: 1,
                },
                r#""type":"tcp_connect""#,
            ),
            (StreamOpen::Dns, r#""type":"dns""#),
            (StreamOpen::DnsTcp, r#""type":"dns_tcp""#),
            (
                StreamOpen::UsbAttach {
                    device: "0403:6001".into(),
                },
                r#""type":"usb_attach""#,
            ),
        ] {
            let s = serde_json::to_string(&open).unwrap();
            assert!(s.contains(tag), "{s}");
        }
        let s = serde_json::to_string(&StreamOpen::Attach(StreamAttach {
            exec_id: 1,
            kind: StreamKind::Stdin,
        }))
        .unwrap();
        assert!(s.contains(r#""type":"attach""#), "{s}");
    }

    #[test]
    fn new_error_kinds_serialize_stably() {
        for (kind, tag) in [
            (ErrorKind::PathNotFound, "path_not_found"),
            (ErrorKind::ConnectFailed, "connect_failed"),
        ] {
            let s = serde_json::to_string(&Response::Error {
                kind,
                message: "m".into(),
            })
            .unwrap();
            assert!(s.contains(tag), "{s}");
        }
    }

    #[test]
    fn egress_port_is_1027() {
        assert_eq!(EGRESS_PORT, 1027);
    }

    #[test]
    fn usb_port_is_1028_and_distinct_from_every_other_plane() {
        // Each plane's port is a contract with the VMM's hybrid-vsock bridge
        // (`vsock.sock_<port>`); a collision would silently hand one plane's
        // connections to another's listener.
        assert_eq!(USB_PORT, 1028);
        for other in [CONTROL_PORT, STREAM_PORT, EGRESS_PORT] {
            assert_ne!(USB_PORT, other, "the USB plane needs its own port");
        }
    }

    #[test]
    fn usb_wire_tags_are_stable() {
        // Host and guest are built and shipped together, but a stale guest
        // initramfs against a new daemon is a real field state; these tags are
        // what keep such a pairing an honest error rather than a mis-parse.
        for (json, tag) in [
            (
                serde_json::to_string(&Request::UsbAttach {
                    device: "0403:6001".into(),
                })
                .unwrap(),
                r#""type":"usb_attach""#,
            ),
            (
                serde_json::to_string(&Request::UsbDetach {
                    device: "0403:6001".into(),
                })
                .unwrap(),
                r#""type":"usb_detach""#,
            ),
            (
                serde_json::to_string(&Response::UsbAttached {
                    devid: 196_610,
                    speed: 3,
                })
                .unwrap(),
                r#""type":"usb_attached""#,
            ),
            (
                serde_json::to_string(&Response::Error {
                    kind: ErrorKind::UsbUnavailable,
                    message: "m".into(),
                })
                .unwrap(),
                "usb_unavailable",
            ),
        ] {
            assert!(json.contains(tag), "{json}");
        }
    }

    #[test]
    fn health_container_defaults_to_none_for_old_frames() {
        // An old guest's Health frame had no `container` key; #[serde(default)]
        // must let it deserialize (None), not error — the self-heal contract.
        let json = r#"{"type":"health","version":"0.1.0","uptime_ms":7}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        match resp {
            Response::Health(h) => {
                assert_eq!(h.container, None);
                assert_eq!(h.uptime_ms, 7);
            }
            other => panic!("expected health, got {other:?}"),
        }
    }

    #[test]
    fn container_state_serializes_snake_case() {
        for (state, tag) in [
            (ContainerState::Creating, "creating"),
            (ContainerState::Created, "created"),
            (ContainerState::Running, "running"),
            (ContainerState::Stopped, "stopped"),
            (ContainerState::Paused, "paused"),
            (ContainerState::Unknown, "unknown"),
        ] {
            let s = serde_json::to_string(&state).unwrap();
            assert_eq!(s, format!("\"{tag}\""));
        }
    }

    #[test]
    fn container_state_from_oci_status_maps_known_and_unknown() {
        assert_eq!(
            ContainerState::from_oci_status("running"),
            ContainerState::Running
        );
        assert_eq!(
            ContainerState::from_oci_status("stopped"),
            ContainerState::Stopped
        );
        assert_eq!(
            ContainerState::from_oci_status("created"),
            ContainerState::Created
        );
        assert_eq!(
            ContainerState::from_oci_status("paused"),
            ContainerState::Paused
        );
        assert_eq!(
            ContainerState::from_oci_status("creating"),
            ContainerState::Creating
        );
        // Anything outside the OCI status set is honestly Unknown.
        assert_eq!(ContainerState::from_oci_status(""), ContainerState::Unknown);
        assert_eq!(
            ContainerState::from_oci_status("garbage"),
            ContainerState::Unknown
        );
    }

    #[test]
    fn container_state_as_str_matches_oci_tokens() {
        assert_eq!(ContainerState::Creating.as_str(), "creating");
        assert_eq!(ContainerState::Created.as_str(), "created");
        assert_eq!(ContainerState::Running.as_str(), "running");
        assert_eq!(ContainerState::Stopped.as_str(), "stopped");
        assert_eq!(ContainerState::Paused.as_str(), "paused");
        assert_eq!(ContainerState::Unknown.as_str(), "unknown");
        // `as_str` round-trips through `from_oci_status` for the OCI states.
        for state in [
            ContainerState::Creating,
            ContainerState::Created,
            ContainerState::Running,
            ContainerState::Stopped,
            ContainerState::Paused,
        ] {
            assert_eq!(ContainerState::from_oci_status(state.as_str()), state);
        }
    }

    #[test]
    fn container_state_is_running_only_for_running() {
        assert!(ContainerState::Running.is_running());
        for s in [
            ContainerState::Creating,
            ContainerState::Created,
            ContainerState::Stopped,
            ContainerState::Paused,
            ContainerState::Unknown,
        ] {
            assert!(!s.is_running(), "{s:?} must not count as running");
        }
    }

    #[test]
    fn response_roundtrip() {
        for resp in [
            Response::Health(HealthInfo {
                version: "0.1.0".into(),
                uptime_ms: 1234,
                container: Some(ContainerState::Running),
            }),
            Response::Health(HealthInfo {
                version: "0.1.0".into(),
                uptime_ms: 1234,
                container: None,
            }),
            Response::ExecStarted { exec_id: 42 },
            Response::UsbAttached {
                devid: 196_610,
                speed: 3,
            },
            Response::Wait {
                status: ExitStatus::Code(0),
            },
            Response::Wait {
                status: ExitStatus::Signal(15),
            },
            Response::Ok,
            Response::Error {
                kind: ErrorKind::CommandNotFound,
                message: "not found".into(),
            },
        ] {
            let mut buf = Vec::new();
            crate::write_frame(&mut buf, &resp).unwrap();
            let back: Response = crate::read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn stats_request_and_response_round_trip() {
        let req = Request::Stats;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"stats\""), "snake_case tag: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Stats));

        let resp = Response::Stats(GuestStats {
            processes: vec![ProcSample {
                pid: 812,
                comm: "node".into(),
                state: 'R',
                cpu_permille: 421,
                rss_kb: 319_488,
            }],
            process_count: 61,
            load1_centi: 42,
            load5_centi: 30,
            load15_centi: 19,
            mem_total_kb: 4_046_412,
            mem_available_kb: 2_012_004,
            mounts: vec![MountUsage {
                path: "/var/lib/docker".into(),
                total_bytes: 10 * 1024 * 1024 * 1024,
                avail_bytes: 8 * 1024 * 1024 * 1024,
            }],
            docker: Some(DockerEngine {
                running: true,
                detail: None,
            }),
            container: Some(ContainerState::Running),
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        match back {
            Response::Stats(g) => {
                assert_eq!(g.processes.len(), 1);
                assert_eq!(g.processes[0].comm, "node");
                assert_eq!(g.process_count, 61);
                assert!(g.docker.as_ref().unwrap().running);
                assert_eq!(g.container, Some(ContainerState::Running));
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn old_guest_rejects_stats_request_as_unknown_variant() {
        // A pre-stats guest deserializing `{"type":"stats"}` fails at serde —
        // its control loop replies nothing and drops the conn, which the
        // daemon maps to `guest: None`. Documented here: the request tag must
        // stay exactly "stats" so this failure mode is stable.
        let s = serde_json::to_string(&Request::Stats).unwrap();
        assert_eq!(s, r#"{"type":"stats"}"#);
    }
}
