//! `izba exec` — run a command inside a running sandbox.
//!
//! Connection layout: the guest control server handles one request at a time
//! per connection and `Wait` blocks until the workload exits, so `Wait` gets
//! a dedicated second control connection while the first stays free for
//! `Resize`. Each stream (tty, or stdin/stdout/stderr) is its own connection
//! to the stream port, opened with a single `StreamAttach` frame and raw
//! bytes after that.

use crate::terminal;
use anyhow::{bail, Context};
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_core::vmm::IoStream;
use izba_proto::{
    read_frame, write_frame, ErrorKind, ExecRequest, ExitStatus, Request, Response, StreamAttach,
    StreamKind,
};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

pub fn run(
    paths: &Paths,
    name: &str,
    interactive: bool,
    tty: bool,
    argv: Vec<String>,
) -> anyhow::Result<i32> {
    if tty && !terminal::is_tty(libc::STDIN_FILENO) {
        anyhow::bail!("exec -t requires a terminal on stdin");
    }
    let connector = sandbox::default_connector();
    let mut control = sandbox::control(paths, name, &connector)?;

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
    let exec_id = match rpc(&mut control, &req)? {
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
    let mut wait_conn = connector(paths, name).context("opening wait connection")?;

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
    control: Box<dyn IoStream>,
    wait_conn: &mut Box<dyn IoStream>,
) -> anyhow::Result<ExitStatus> {
    let control = Arc::new(Mutex::new(control));
    resize(&control, exec_id); // size the guest pty before the program looks
    spawn_winch(Arc::clone(&control), exec_id)?;

    let stream = attach(paths, name, exec_id, StreamKind::Tty)?;
    let stream_out = stream.try_clone().context("cloning tty stream")?;

    let raw = terminal::RawGuard::new()?;
    // stdin pump never unblocks from its read; left detached, dies with us.
    std::thread::spawn(move || pump(io::stdin(), &stream));
    let out = std::thread::spawn(move || pump(stream_out, io::stdout()));

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
    wait_conn: &mut Box<dyn IoStream>,
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
    }
    let out = std::thread::spawn(move || pump(out_stream, io::stdout()));
    let err = std::thread::spawn(move || pump(err_stream, io::stderr()));

    let status = wait(wait_conn, exec_id);
    let _ = out.join();
    let _ = err.join();
    status
}

fn rpc<S: Read + Write>(conn: &mut S, req: &Request) -> anyhow::Result<Response> {
    write_frame(conn, req)?;
    Ok(read_frame(conn)?)
}

fn wait<S: Read + Write>(conn: &mut S, exec_id: u32) -> anyhow::Result<ExitStatus> {
    match rpc(conn, &Request::Wait { exec_id })? {
        Response::Wait { status } => Ok(status),
        Response::Error { kind, message } => bail!("wait failed ({kind:?}): {message}"),
        other => bail!("unexpected reply to wait: {other:?}"),
    }
}

/// Open a stream-port connection and bind it to `exec_id`'s `kind` stream.
fn attach(paths: &Paths, name: &str, exec_id: u32, kind: StreamKind) -> anyhow::Result<UnixStream> {
    let mut conn = sandbox::default_stream_connector()(paths, name)
        .with_context(|| format!("opening {kind:?} stream"))?;
    write_frame(&mut conn, &StreamAttach { exec_id, kind })?;
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

fn resize(control: &Mutex<Box<dyn IoStream>>, exec_id: u32) {
    let (cols, rows) = terminal::winsize();
    if let Ok(mut conn) = control.lock() {
        let _ = rpc(
            &mut *conn,
            &Request::Resize {
                exec_id,
                cols,
                rows,
            },
        );
    }
}

fn spawn_winch(control: Arc<Mutex<Box<dyn IoStream>>>, exec_id: u32) -> anyhow::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH])
        .context("installing SIGWINCH handler")?;
    std::thread::spawn(move || {
        for _ in signals.forever() {
            resize(&control, exec_id);
        }
    });
    Ok(())
}
