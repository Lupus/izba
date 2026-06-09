use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
    pub tty: bool,
    pub uid: u32,
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
    }
}
