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
    read_frame, write_frame, ErrorKind, ExitStatus, HealthInfo, Request, Response, StreamOpen,
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

        // Fabricate config.json: the daemon-first CLI's adoption pass sweeps
        // any sandbox dir without one as half-created debris, which would
        // delete this fake sandbox before exec ever reaches it.
        izba_core::state::save_json(
            &sb.join(izba_core::state::CONFIG_FILE),
            &izba_core::state::SandboxConfig {
                image_digest: "sha256:ttytest".to_string(),
                image_ref: "ttytest:fake".to_string(),
                cpus: 1,
                mem_mb: 128,
                workspace: data_root.clone(),
                ports: Vec::new(),
                egress: izba_core::state::EgressMode::Passt,
            },
        )
        .context("write config.json")?;

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

    /// Start a guest, or return `None` when this environment denies
    /// `UnixListener::bind` with `PermissionDenied`/EPERM — matching the
    /// project convention of runtime-skipping listener-bind tests in
    /// restrictive sandboxes. Panics on any other failure.
    pub fn start_or_skip(script: GuestScript) -> Option<Self> {
        match Self::start(script) {
            Ok(g) => Some(g),
            Err(e) => {
                let denied = e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                });
                if denied {
                    eprintln!("SKIP: UnixListener::bind denied in this environment: {e:#}");
                    None
                } else {
                    panic!("ScriptedGuest::start failed: {e:#}");
                }
            }
        }
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

fn serve_stream(conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    // Read the one StreamOpen frame off a clone so the original keeps its
    // remaining bytes for the reader/writer split.
    let mut attach_conn = conn.try_clone().context("clone for attach")?;
    let open: StreamOpen = match read_frame(&mut attach_conn) {
        Ok(o) => o,
        Err(_) => return Ok(()),
    };
    // The scripted guest only fakes exec streams; reject everything else
    // like a guest that doesn't implement the feature.
    let StreamOpen::Attach(_attach) = open else {
        let _ = write_frame(
            &mut attach_conn,
            &Response::Error {
                kind: ErrorKind::BadRequest,
                message: "not implemented".into(),
            },
        );
        return Ok(());
    };
    drop(attach_conn);

    // Register the resize channel so control-port Resize RPCs reach us.
    let (tx, rx) = std::sync::mpsc::channel::<(u16, u16)>();
    *shared.resize_tx.lock().unwrap() = Some(tx);

    // Reader thread: record everything the host sends.
    let mut reader = conn.try_clone().context("clone stream reader")?;
    let rec_shared = Arc::clone(&shared);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => rec_shared
                    .rec
                    .received_input
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..n]),
            }
        }
    });

    // Writer side: initial emit, then react to resizes until the end byte.
    let mut writer = conn;
    writer
        .write_all(&shared.script.initial_emit)
        .context("initial emit")?;
    writer.flush().ok();

    let end_byte = shared.script.end_when_input_contains;
    loop {
        // Emit any pending resize frames.
        while let Ok((cols, rows)) = rx.try_recv() {
            if let Some(f) = shared.script.on_resize {
                let bytes = f(cols, rows);
                let _ = writer.write_all(&bytes);
                let _ = writer.flush();
            }
        }
        // End condition.
        let ended = match end_byte {
            None => true, // end immediately after initial emit
            Some(b) => shared.rec.received_input.lock().unwrap().contains(&b),
        };
        if ended || shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Signal Wait and tear down.
    {
        let (lock, cvar) = &shared.done;
        *lock.lock().unwrap() = Some(shared.script.final_status);
        cvar.notify_all();
    }
    *shared.resize_tx.lock().unwrap() = None;
    // Shut down the socket (not just close one fd clone) so the host's output
    // pump sees EOF immediately, even though the reader_thread still holds
    // another clone of this socket end open. Without this, the host's
    // `out.join()` in `wait_tty` deadlocks: it waits for EOF which only
    // arrives when all guest socket fds are closed, but the reader_thread
    // is itself waiting for the host stdin-pump to close — which never
    // happens because that thread is left detached.
    let _ = writer.shutdown(std::net::Shutdown::Both);
    drop(writer);
    let _ = reader_thread.join();
    Ok(())
}
