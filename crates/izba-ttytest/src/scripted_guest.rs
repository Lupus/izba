//! A fake "running sandbox" for driving the real `izba` binary with no VM.
//!
//! It fabricates a sandbox state dir whose `state.json` points `vmm_pid` at the
//! current (test) process — alive for the test's duration — so `izba`'s
//! liveness check passes. It then binds the hybrid-vsock Unix socket and speaks
//! the izba wire protocol: a CH-style `CONNECT <port>\n`/`OK\n` handshake per
//! connection, then either the control request loop (port 1025) or the stream
//! script (port 1026, Task 5).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{Context, Result};
use izba_proto::{
    read_frame, write_frame, ErrorKind, ExitStatus, HealthInfo, Request, Response, StreamAttach,
    CONTROL_PORT, STREAM_PORT,
};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

/// How the guest answers an `Exec` request.
#[derive(Clone, Copy)]
pub enum ExecOutcome {
    /// Reply `ExecStarted` and run the stream script.
    Started,
    /// Reply `Error { CommandNotFound }` (izba then exits 127, no stream/wait).
    CommandNotFound,
}

/// A scripted guest behaviour. `fn` pointers (not closures) keep it
/// `Send + Sync + 'static` with no boxing.
pub struct GuestScript {
    pub exec_outcome: ExecOutcome,
    /// Bytes emitted to the host as soon as the Tty stream attaches.
    pub initial_emit: Vec<u8>,
    /// If set, emit `f(cols, rows)` whenever a Resize RPC arrives.
    pub on_resize: Option<fn(u16, u16) -> Vec<u8>>,
    /// End the exec when host->guest input contains this byte (e.g. `b'q'`,
    /// `0x03` for Ctrl-C). `None` ends immediately after `initial_emit`.
    pub end_when_input_contains: Option<u8>,
    /// Status returned by the `Wait` RPC once the exec ends.
    pub final_status: ExitStatus,
}

#[derive(Default)]
struct Recorder {
    received_input: Mutex<Vec<u8>>,
    last_resize: Mutex<Option<(u16, u16)>>,
    kills: Mutex<Vec<i32>>,
}

struct Shared {
    script: GuestScript,
    rec: Recorder,
    /// Set to `Some(status)` by the stream thread when the exec ends; `Wait`
    /// blocks on this.
    done: (Mutex<Option<ExitStatus>>, Condvar),
    /// control -> stream: resize events to emit.
    resize_tx: Mutex<Option<std::sync::mpsc::Sender<(u16, u16)>>>,
    shutdown: AtomicBool,
}

pub struct ScriptedGuest {
    data_dir_keep: tempfile::TempDir,
    data_root: PathBuf,
    name: String,
    vsock: PathBuf,
    shared: Arc<Shared>,
    _accept_thread: std::thread::JoinHandle<()>,
}

impl ScriptedGuest {
    pub fn start(script: GuestScript) -> Result<Self> {
        let name = "ttytest".to_string();
        let tmp = tempfile::tempdir().context("tempdir")?;
        let data_root = tmp.path().to_path_buf();
        let paths = izba_core::paths::Paths::with_root(data_root.clone());
        let sb = paths.sandbox_dir(&name);
        let run = paths.run_dir(&name);
        // run_dir is sandbox_dir/run, so create_dir_all(&run) also creates sb.
        std::fs::create_dir_all(&run).context("create run dir")?;

        // Fabricate state.json so liveness passes: vmm_pid = current process.
        let id = izba_core::procmgr::current_identity().context("current identity")?;
        izba_core::state::save_json(
            &sb.join(izba_core::state::STATE_FILE),
            &izba_core::state::RunState {
                vmm_pid: id,
                sidecar_pids: vec![],
                started_unix_ms: 0,
            },
        )
        .context("write state.json")?;

        let vsock = run.join("vsock.sock");
        let _ = std::fs::remove_file(&vsock);
        let listener = UnixListener::bind(&vsock).context("bind vsock.sock")?;

        let shared = Arc::new(Shared {
            script,
            rec: Recorder::default(),
            done: (Mutex::new(None), Condvar::new()),
            resize_tx: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        });

        let shared_l = Arc::clone(&shared);
        let handle = std::thread::spawn(move || accept_loop(listener, shared_l));

        Ok(Self {
            data_dir_keep: tmp,
            data_root,
            name,
            vsock,
            shared,
            _accept_thread: handle,
        })
    }

    /// Pass this to the child as `IZBA_DATA_DIR`.
    pub fn data_dir(&self) -> &Path {
        &self.data_root
    }

    pub fn sandbox_name(&self) -> &str {
        &self.name
    }

    pub fn vsock_path(&self) -> PathBuf {
        self.vsock.clone()
    }

    pub fn received_input(&self) -> Vec<u8> {
        self.shared.rec.received_input.lock().unwrap().clone()
    }

    pub fn last_resize(&self) -> Option<(u16, u16)> {
        *self.shared.rec.last_resize.lock().unwrap()
    }

    pub fn kills(&self) -> Vec<i32> {
        self.shared.rec.kills.lock().unwrap().clone()
    }
}

impl Drop for ScriptedGuest {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        // Nudge the accept loop by connecting once; ignore errors.
        let _ = UnixStream::connect(&self.vsock);
        let _ = &self.data_dir_keep; // keep the tempdir until drop
    }
}

fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    // The accept thread is not joined; it exits when the shutdown flag is set
    // (via Drop's nudge connection) or when the process ends.
    for conn in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        let conn = match conn {
            Ok(c) => c,
            Err(_) => {
                if shared.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                continue;
            }
        };
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            if let Err(e) = serve_conn(conn, shared) {
                eprintln!("scripted guest conn error: {e:#}");
            }
        });
    }
}

/// Read the `CONNECT <port>\n` line byte-by-byte from `conn`, reply `OK 0\n`,
/// return the port. Reading byte-by-byte avoids consuming frame bytes that
/// immediately follow the newline (a BufReader over a clone would read ahead).
fn handshake(conn: &mut UnixStream) -> Result<u32> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = conn.read(&mut b).context("read CONNECT byte")?;
        if n == 0 {
            anyhow::bail!("EOF during CONNECT");
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 128 {
            anyhow::bail!("oversized CONNECT line");
        }
    }
    let s = String::from_utf8_lossy(&line);
    let port: u32 = s
        .trim()
        .strip_prefix("CONNECT ")
        .context("bad CONNECT line")?
        .parse()
        .context("parse port")?;
    conn.write_all(b"OK 0\n").context("write OK")?;
    Ok(port)
}

fn serve_conn(mut conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    let port = handshake(&mut conn)?;
    match port {
        CONTROL_PORT => serve_control(conn, shared),
        STREAM_PORT => serve_stream(conn, shared),
        other => anyhow::bail!("unexpected CONNECT port {other}"),
    }
}

fn serve_control(mut conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    loop {
        let req: Request = match read_frame(&mut conn) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let resp = match req {
            Request::Health => Response::Health(HealthInfo {
                version: "ttytest-guest".to_string(),
                uptime_ms: 0,
            }),
            Request::Exec(_) => match shared.script.exec_outcome {
                ExecOutcome::Started => Response::ExecStarted { exec_id: 1 },
                ExecOutcome::CommandNotFound => Response::Error {
                    kind: ErrorKind::CommandNotFound,
                    message: "ttytest: command not found".to_string(),
                },
            },
            Request::Wait { .. } => {
                let (lock, cvar) = &shared.done;
                let mut guard = lock.lock().unwrap();
                while guard.is_none() {
                    guard = cvar.wait(guard).unwrap();
                }
                Response::Wait {
                    status: guard.unwrap(),
                }
            }
            Request::Kill { signal, .. } => {
                shared.rec.kills.lock().unwrap().push(signal);
                Response::Ok
            }
            Request::Resize { cols, rows, .. } => {
                *shared.rec.last_resize.lock().unwrap() = Some((cols, rows));
                if let Some(tx) = shared.resize_tx.lock().unwrap().as_ref() {
                    let _ = tx.send((cols, rows));
                }
                Response::Ok
            }
            Request::Shutdown => {
                let _ = write_frame(&mut conn, &Response::Ok);
                shared.shutdown.store(true, Ordering::SeqCst);
                return Ok(());
            }
        };
        if write_frame(&mut conn, &resp).is_err() {
            return Ok(());
        }
    }
}

/// Stream port handler — fully implemented in Task 5. For now, accept the
/// attach frame and close so the control-plane smoke test can run.
fn serve_stream(mut conn: UnixStream, _shared: Arc<Shared>) -> Result<()> {
    let _attach: StreamAttach = match read_frame(&mut conn) {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };
    Ok(())
}
