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
    Wait { exec_id: u32 },
    Kill { exec_id: u32, signal: i32 },
    Resize { exec_id: u32, cols: u16, rows: u16 },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    pub version: String,
    pub uptime_ms: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Health(HealthInfo),
    ExecStarted { exec_id: u32 },
    Wait { status: ExitStatus },
    Ok,
    Error { kind: ErrorKind, message: String },
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
}

pub const CONTROL_PORT: u32 = 1025;
pub const STREAM_PORT: u32 = 1026;

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
    fn response_roundtrip() {
        for resp in [
            Response::Health(HealthInfo {
                version: "0.1.0".into(),
                uptime_ms: 1234,
            }),
            Response::ExecStarted { exec_id: 42 },
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
}
