//! `izba exec` — run a command inside a running sandbox.
//!
//! All connections go through izbad: control RPCs are proxied via the
//! daemon's `GuestRpc` request, streams via the `OpenStream` splice — the
//! guest-side framing is unchanged. The guest control server handles one
//! request at a time per connection and `Wait` blocks until the workload
//! exits, so `Wait` gets a dedicated second control channel while the first
//! stays free for `Resize`. Each stream (tty, or stdin/stdout/stderr) is its
//! own connection to the stream port, opened with a single `StreamAttach`
//! frame and raw bytes after that.

use crate::terminal;
use anyhow::{bail, Context};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::vmm::UdsStream;
use izba_proto::{
    write_frame, ErrorKind, ExecRequest, ExitStatus, Request, Response, StreamAttach, StreamKind,
    StreamOpen,
};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};

/// One guest control channel, proxied through izbad (`GuestRpc`). Each RPC
/// opens a fresh guest-side connection; `Wait` may block for the workload's
/// lifetime, which is why exec uses TWO of these (control + wait), exactly
/// like the pre-daemon two-connection layout.
struct GuestControl {
    client: DaemonClient,
    name: String,
}

impl GuestControl {
    fn connect(paths: &Paths, name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            client: DaemonClient::connect(paths)?,
            name: name.to_string(),
        })
    }

    fn rpc(&mut self, req: &Request) -> anyhow::Result<Response> {
        self.client.guest_rpc(&self.name, req)
    }
}

pub fn run(
    paths: &Paths,
    name: &str,
    interactive: bool,
    tty: bool,
    argv: Vec<String>,
) -> anyhow::Result<i32> {
    if tty && !terminal::stdin_is_tty() {
        anyhow::bail!("exec -t requires a terminal on stdin");
    }
    let mut control = GuestControl::connect(paths, name)?;

    let env = if tty {
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        vec![("TERM".to_string(), term)]
    } else {
        vec![]
    };
    let req = Request::Exec(ExecRequest {
        argv,
        env,
        cwd: "/workspace".to_string(),
        tty,
        uid: 0,
        gid: 0,
    });
    let exec_id = match control.rpc(&req)? {
        Response::ExecStarted { exec_id } => exec_id,
        Response::Error {
            kind: ErrorKind::CommandNotFound,
            message,
        } => {
            eprintln!("izba: {message}");
            return Ok(127);
        }
        Response::Error { kind, message } => bail!("exec failed ({kind:?}): {message}"),
        other => bail!("unexpected reply to exec: {other:?}"),
    };
    let mut wait_conn = GuestControl::connect(paths, name).context("opening wait connection")?;

    let status = if tty {
        wait_tty(paths, name, exec_id, control, &mut wait_conn)?
    } else {
        wait_plain(paths, name, exec_id, interactive, &mut wait_conn)?
    };
    Ok(match status {
        ExitStatus::Code(n) => n,
        ExitStatus::Signal(s) => 128 + s,
    })
}

fn wait_tty(
    paths: &Paths,
    name: &str,
    exec_id: u32,
    control: GuestControl,
    wait_conn: &mut GuestControl,
) -> anyhow::Result<ExitStatus> {
    let control = Arc::new(Mutex::new(control));
    resize(&control, exec_id); // size the guest pty before the program looks
    spawn_resize_watcher(Arc::clone(&control), exec_id)?;

    let stream = attach(paths, name, exec_id, StreamKind::Tty)?;
    let stream_out = stream.try_clone().context("cloning tty stream")?;

    let raw = terminal::RawGuard::new()?;
    // stdin pump never unblocks from its read; left detached, dies with us.
    std::thread::spawn(move || pump(io::stdin(), &stream));
    // Guest tty bytes go to a raw console sink: on Windows `io::stdout()`
    // rejects non-UTF-8 chunks (e.g. vim's 0xbd width-probe byte) and the
    // pump would die mid-redraw. See `terminal::console_out`.
    let out = std::thread::spawn(move || pump(stream_out, terminal::console_out()));

    let status = wait(wait_conn, exec_id);
    // The guest half-closes the stream when the child dies, so this join
    // finishes after the last output is flushed.
    let _ = out.join();
    drop(raw); // restore the terminal before anything is printed
    status
}

fn wait_plain(
    paths: &Paths,
    name: &str,
    exec_id: u32,
    interactive: bool,
    wait_conn: &mut GuestControl,
) -> anyhow::Result<ExitStatus> {
    let out_stream = attach(paths, name, exec_id, StreamKind::Stdout)?;
    let err_stream = attach(paths, name, exec_id, StreamKind::Stderr)?;
    if interactive {
        let in_stream = attach(paths, name, exec_id, StreamKind::Stdin)?;
        std::thread::spawn(move || {
            pump(io::stdin(), &in_stream);
            // Stdin EOF → half-close so the child's stdin sees EOF too.
            let _ = in_stream.shutdown(Shutdown::Write);
        });
    } else {
        // Without -i the child must still see stdin EOF rather than a pipe
        // held open forever by the guest's untaken stream: attach and
        // immediately half-close.
        let in_stream = attach(paths, name, exec_id, StreamKind::Stdin)?;
        let _ = in_stream.shutdown(Shutdown::Write);
    }
    // Raw console sinks so non-UTF-8 guest bytes don't kill the pump on
    // Windows (a console `io::stdout()` rejects them). See `terminal`.
    let out = std::thread::spawn(move || pump(out_stream, terminal::console_out()));
    let err = std::thread::spawn(move || pump(err_stream, terminal::console_err()));

    let status = wait(wait_conn, exec_id);
    let _ = out.join();
    let _ = err.join();
    status
}

fn wait(conn: &mut GuestControl, exec_id: u32) -> anyhow::Result<ExitStatus> {
    match conn.rpc(&Request::Wait { exec_id })? {
        Response::Wait { status } => Ok(status),
        Response::Error { kind, message } => bail!("wait failed ({kind:?}): {message}"),
        other => bail!("unexpected reply to wait: {other:?}"),
    }
}

/// Open a guest stream-port connection (through the daemon splice) and bind
/// it to `exec_id`'s `kind` stream.
fn attach(paths: &Paths, name: &str, exec_id: u32, kind: StreamKind) -> anyhow::Result<UdsStream> {
    let mut conn = DaemonClient::open_guest_stream(paths, name)
        .with_context(|| format!("opening {kind:?} stream"))?;
    write_frame(
        &mut conn,
        &StreamOpen::Attach(StreamAttach { exec_id, kind }),
    )?;
    Ok(conn)
}

fn pump(mut from: impl Read, mut to: impl Write) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
                let _ = to.flush();
            }
        }
    }
}

fn resize(control: &Mutex<GuestControl>, exec_id: u32) {
    let (cols, rows) = terminal::winsize();
    if let Ok(mut conn) = control.lock() {
        let _ = conn.rpc(&Request::Resize {
            exec_id,
            cols,
            rows,
        });
    }
}

/// Pushes a Resize RPC whenever the local terminal size changes.
#[cfg(unix)]
fn spawn_resize_watcher(control: Arc<Mutex<GuestControl>>, exec_id: u32) -> anyhow::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH])
        .context("installing SIGWINCH handler")?;
    std::thread::spawn(move || {
        for _ in signals.forever() {
            resize(&control, exec_id);
        }
    });
    Ok(())
}

/// Windows has no SIGWINCH: poll the console size. 200 ms is imperceptible
/// for a human dragging a window and costs one syscall per tick.
#[cfg(windows)]
fn spawn_resize_watcher(control: Arc<Mutex<GuestControl>>, exec_id: u32) -> anyhow::Result<()> {
    std::thread::spawn(move || {
        let mut last = terminal::winsize();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let now = terminal::winsize();
            if now != last {
                last = now;
                resize(&control, exec_id);
            }
        }
    });
    Ok(())
}
