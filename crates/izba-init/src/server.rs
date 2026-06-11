//! Control (port 1025) and stream (port 1026) servers.
//!
//! Both servers are transport-agnostic via the [`Listener`] trait so tests
//! can drive them over `UnixStream::pair()` halves; the guest binds vsock.

use crate::exec::ExecEngine;
use izba_proto::{
    read_frame, write_frame, ErrorKind, HealthInfo, Request, Response, StreamKind, StreamOpen,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

/// Process start reference for `HealthInfo::uptime_ms`. `main` touches it
/// at startup so "first access" is "process start".
pub static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Accepts bidirectional byte-stream connections. `AsRawFd` is needed so the
/// tty pump can dup the connection for its second direction.
pub trait Listener {
    type Conn: Read + Write + AsRawFd + Send + 'static;
    fn accept(&self) -> std::io::Result<Self::Conn>;
}

/// Serves control RPCs until `shutdown` is set (by a `Shutdown` request,
/// which is acknowledged with `Ok` before the flag flips).
///
/// NOTE: exiting the accept loop is best-effort — a quiet listener blocks in
/// accept() forever, so `main` watches the flag itself and never joins this
/// thread; run it as a daemon thread.
pub fn serve_control<L: Listener>(l: L, engine: Arc<ExecEngine>, shutdown: Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let conn = match l.accept() {
            Ok(c) => c,
            Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                // Brief backoff to avoid a tight spin on persistent errors
                // (e.g. EMFILE when the fd table is exhausted).
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        let engine = Arc::clone(&engine);
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || control_conn(conn, engine, shutdown));
    }
}

fn control_conn<C: Read + Write>(mut conn: C, engine: Arc<ExecEngine>, shutdown: Arc<AtomicBool>) {
    loop {
        let req: Request = match read_frame(&mut conn) {
            Ok(r) => r,
            Err(_) => return, // clean EOF or broken peer either way
        };
        let resp = match req {
            Request::Health => Response::Health(HealthInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_ms: START.elapsed().as_millis() as u64,
            }),
            Request::Exec(er) => match engine.exec(&er) {
                Ok(exec_id) => Response::ExecStarted { exec_id },
                Err((kind, message)) => Response::Error { kind, message },
            },
            // Wait may block this connection's thread for as long as the
            // workload runs; other connections are unaffected.
            Request::Wait { exec_id } => match engine.wait(exec_id) {
                Ok(status) => Response::Wait { status },
                Err((kind, message)) => Response::Error { kind, message },
            },
            Request::Kill { exec_id, signal } => match engine.kill(exec_id, signal) {
                Ok(()) => Response::Ok,
                Err((kind, message)) => Response::Error { kind, message },
            },
            Request::Resize {
                exec_id,
                cols,
                rows,
            } => match engine.resize(exec_id, cols, rows) {
                Ok(()) => Response::Ok,
                Err((kind, message)) => Response::Error { kind, message },
            },
            Request::Shutdown => {
                // Reply first so the host sees the ack, then flip the flag.
                let _ = write_frame(&mut conn, &Response::Ok);
                shutdown.store(true, Ordering::SeqCst);
                return;
            }
        };
        if write_frame(&mut conn, &resp).is_err() {
            return;
        }
    }
}

/// Serves stream attachments; never returns under normal operation
/// (run as a daemon thread). Logs and retries on accept errors.
pub fn serve_streams<L: Listener>(l: L, engine: Arc<ExecEngine>) {
    loop {
        let conn = match l.accept() {
            Ok(c) => c,
            Err(_) => {
                // Brief backoff to avoid a tight spin on persistent errors
                // (e.g. EMFILE when the fd table is exhausted).
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || stream_conn(conn, engine));
    }
}

fn stream_conn<C: Read + Write + AsRawFd + Send + 'static>(mut conn: C, engine: Arc<ExecEngine>) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return,
    };
    let attach = match open {
        StreamOpen::Attach(a) => a,
        StreamOpen::TarExtract { dest } => {
            tar_extract(&mut conn, &engine, &dest);
            return;
        }
        StreamOpen::TarCreate { src } => {
            tar_create(&mut conn, &engine, &src);
            return;
        }
        StreamOpen::TcpDial { port } => {
            tcp_dial(conn, port);
            return;
        }
    };
    let fd = match engine.take_stream(attach.exec_id, attach.kind) {
        Ok(fd) => fd,
        Err((kind, message)) => {
            // Stream conns speak raw bytes after the attach frame, except on
            // attach failure: one Error frame, then close.
            let _ = write_frame(&mut conn, &Response::Error { kind, message });
            return;
        }
    };
    match attach.kind {
        // conn → child stdin; dropping the fd on conn EOF is what delivers
        // EOF to the child's stdin — do not hold extra dups.
        StreamKind::Stdin => pump(conn, File::from(fd)),
        // child stdout/stderr → conn; conn drop at return closes it (EOF
        // for the host).
        StreamKind::Stdout | StreamKind::Stderr => pump(File::from(fd), conn),
        StreamKind::Tty => {
            let master_w = match fd.try_clone() {
                Ok(m) => m,
                Err(_) => return,
            };
            // Second handle on the connection for the outbound direction.
            let conn_w = match dup_fd(conn.as_raw_fd()) {
                Ok(d) => d,
                Err(_) => return,
            };
            // conn → master (host keystrokes).
            let reader = std::thread::spawn(move || pump(conn, File::from(master_w)));
            // master → conn (program output); EIO on the master == EOF.
            let conn_w = File::from(conn_w);
            pump(File::from(fd), &conn_w);
            // Child is gone: shut the socket down so the host sees EOF and
            // the reader thread's blocking read returns.
            unsafe { libc::shutdown(conn_w.as_raw_fd(), libc::SHUT_RDWR) };
            let _ = reader.join();
        }
    }
}

/// cp host->guest: read the tar from `conn` under the workload root, then
/// write ONE trailing `Response` status frame.
fn tar_extract<C: Read + Write>(conn: &mut C, engine: &ExecEngine, dest: &str) {
    // With no chroot (tests), resolve against `/` so absolute guest paths
    // still work; the real guest always has Some("/rootfs").
    let root = engine.root().unwrap_or_else(|| std::path::Path::new("/"));
    let resp = match crate::tarfs::extract(root, dest, conn) {
        Ok(()) => Response::Ok,
        Err((kind, message)) => Response::Error { kind, message },
    };
    let _ = write_frame(conn, &resp);
}

/// cp guest->host: resolve `src` FIRST; on failure write ONE leading
/// `Response::Error` and close (no tar bytes precede it). On success write
/// the leading `Response::Ok`, then STREAM the tar directly onto the
/// connection while walking (never buffered) and close — tar's two
/// zero-blocks are the EOF. A mid-walk I/O error just drops the connection;
/// the host sees the missing EOF and reports "transfer truncated".
fn tar_create<C: Read + Write>(conn: &mut C, engine: &ExecEngine, src: &str) {
    let root = engine.root().unwrap_or_else(|| std::path::Path::new("/"));
    let resolved = match crate::tarfs::resolve_src(root, src) {
        Ok(r) => r,
        Err((kind, message)) => {
            let _ = write_frame(conn, &Response::Error { kind, message });
            return;
        }
    };
    if write_frame(conn, &Response::Ok).is_err() {
        return;
    }
    // Stream straight onto the connection; an error here aborts mid-archive
    // (no trailing frame exists in this direction by design).
    let _ = crate::tarfs::stream_tar(&resolved, conn);
}

/// Init side of `StreamOpen::TcpDial`: dial `127.0.0.1:port` inside the guest,
/// reply one `Response` frame (`Ok` | `Error{ConnectFailed}`), and on `Ok`
/// become a raw bidirectional byte pipe.
///
/// `C` is the vsock connection (host side). On guest-socket EOF we
/// `shutdown(Write)` toward the host and drain the remaining host->guest bytes;
/// this graceful teardown is also the planned OpenVMM vsock-churn mitigation.
fn tcp_dial<C: Read + Write + AsRawFd + Send + 'static>(mut conn: C, port: u16) {
    use std::net::{Shutdown, SocketAddr, TcpStream};
    // Spec §5: 10 s dial cap. Loopback normally refuses instantly; the cap
    // guards pathological guest states (e.g. workload firewall DROP rules)
    // so a relay thread can never hang in connect forever.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let target = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
        Ok(t) => t,
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    if write_frame(&mut conn, &Response::Ok).is_err() {
        return;
    }

    // Second handles for the opposite directions.
    let conn_w = match dup_fd(conn.as_raw_fd()) {
        Ok(d) => File::from(d),
        Err(_) => return,
    };
    let target_r = match target.try_clone() {
        Ok(t) => t,
        Err(_) => return,
    };

    // host -> guest: when the host half-closes, signal the guest socket so the
    // guest service sees EOF, then this thread exits.
    let reader = std::thread::spawn(move || {
        let mut target_w = target;
        relay_pump(conn, &mut target_w);
        let _ = target_w.shutdown(Shutdown::Write);
    });

    // guest -> host: pump until the guest service closes its socket.
    let mut conn_w = conn_w;
    relay_pump(target_r, &mut conn_w);
    // Full shutdown, not SHUT_WR: Cloud Hypervisor's hybrid vsock does not
    // propagate a guest half-close to the host unix socket (the exec/tty path
    // uses SHUT_RDWR for the same reason), so a lone SHUT_WR leaves the host
    // client waiting for EOF forever. By this point the guest service has
    // closed, our final bytes are written (graceful TX — the OpenVMM churn
    // mitigation), and the inbound direction has nowhere to deliver to; the
    // full shutdown also unblocks the reader thread's pending read.
    unsafe { libc::shutdown(conn_w.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = reader.join();
}

/// Copy `r` to `w` until EOF or error. Mirrors `pump` but takes `w` by mutable
/// reference so the caller can issue a shutdown after the copy completes.
fn relay_pump(mut r: impl Read, w: &mut impl Write) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        if w.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}

fn dup_fd(fd: std::os::fd::RawFd) -> std::io::Result<OwnedFd> {
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: freshly dup'ed, owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// Copies until EOF or error. EIO is treated as EOF: that is how a pty
/// master reports "all slave ends closed".
fn pump(mut r: impl Read, mut w: impl Write) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EIO) => return,
            Err(_) => return,
        };
        if w.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::{ErrorKind, ExecRequest, ExitStatus, StreamAttach};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::sync::Mutex;

    /// Hands out pre-made socketpair halves; sandbox denies
    /// `UnixListener::bind`, so no real listener is used in tests.
    struct PairListener(Mutex<mpsc::Receiver<UnixStream>>);

    impl Listener for PairListener {
        type Conn = UnixStream;
        fn accept(&self) -> std::io::Result<UnixStream> {
            match self.0.lock().unwrap().recv() {
                Ok(s) => Ok(s),
                // Test is over (sender dropped): block forever like a quiet
                // listener instead of busy-looping; process exit reaps us.
                Err(_) => loop {
                    std::thread::park();
                },
            }
        }
    }

    struct Harness {
        control_tx: mpsc::Sender<UnixStream>,
        stream_tx: mpsc::Sender<UnixStream>,
        shutdown: Arc<AtomicBool>,
    }

    impl Harness {
        fn new() -> Self {
            let engine = Arc::new(ExecEngine::new(None));
            let shutdown = Arc::new(AtomicBool::new(false));

            let (control_tx, rx) = mpsc::channel();
            let (e, s) = (Arc::clone(&engine), Arc::clone(&shutdown));
            std::thread::spawn(move || serve_control(PairListener(Mutex::new(rx)), e, s));

            let (stream_tx, rx) = mpsc::channel();
            std::thread::spawn(move || serve_streams(PairListener(Mutex::new(rx)), engine));

            Self {
                control_tx,
                stream_tx,
                shutdown,
            }
        }

        fn control_conn(&self) -> UnixStream {
            let (mine, theirs) = UnixStream::pair().unwrap();
            self.control_tx.send(theirs).unwrap();
            mine
        }

        fn stream_conn(&self) -> UnixStream {
            let (mine, theirs) = UnixStream::pair().unwrap();
            self.stream_tx.send(theirs).unwrap();
            mine
        }
    }

    fn rpc(conn: &mut UnixStream, req: &Request) -> Response {
        write_frame(conn, req).unwrap();
        read_frame(conn).unwrap()
    }

    #[test]
    fn health_answers() {
        let h = Harness::new();
        let mut c = h.control_conn();
        match rpc(&mut c, &Request::Health) {
            Response::Health(info) => {
                assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn exec_stdio_conversation() {
        let h = Harness::new();
        let mut control = h.control_conn();

        let exec_id = match rpc(
            &mut control,
            &Request::Exec(ExecRequest {
                argv: vec!["sh".into(), "-c".into(), "read x; echo got:$x".into()],
                env: vec![],
                cwd: "/".into(),
                tty: false,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            }),
        ) {
            Response::ExecStarted { exec_id } => exec_id,
            other => panic!("unexpected: {other:?}"),
        };

        let mut stdin = h.stream_conn();
        write_frame(
            &mut stdin,
            &StreamOpen::Attach(StreamAttach {
                exec_id,
                kind: StreamKind::Stdin,
            }),
        )
        .unwrap();
        let mut stdout = h.stream_conn();
        write_frame(
            &mut stdout,
            &StreamOpen::Attach(StreamAttach {
                exec_id,
                kind: StreamKind::Stdout,
            }),
        )
        .unwrap();

        stdin.write_all(b"hi\n").unwrap();
        stdin.shutdown(std::net::Shutdown::Write).unwrap();

        let mut out = String::new();
        stdout.read_to_string(&mut out).unwrap();
        assert_eq!(out, "got:hi\n");

        match rpc(&mut control, &Request::Wait { exec_id }) {
            Response::Wait { status } => assert_eq!(status, ExitStatus::Code(0)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_exec_stream_attach() {
        let h = Harness::new();
        let mut conn = h.stream_conn();
        write_frame(
            &mut conn,
            &StreamOpen::Attach(StreamAttach {
                exec_id: 999,
                kind: StreamKind::Stdout,
            }),
        )
        .unwrap();
        match read_frame::<_, Response>(&mut conn).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::ExecNotFound),
            other => panic!("unexpected: {other:?}"),
        }
        // Server closes the conn after the error frame.
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn tar_extract_into_temp_root_then_create_back() {
        // The engine in Harness uses root=None, so tarfs operates with the
        // tempdir itself as "root". Drive a host->guest extract, then a
        // guest->host create, over socketpairs.
        use std::io::Cursor;
        let tmp = tempfile::tempdir().unwrap();
        let engine = Arc::new(ExecEngine::new(Some(tmp.path().to_path_buf())));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (stream_tx, rx) = mpsc::channel();
        {
            let e = Arc::clone(&engine);
            let _ = &shutdown;
            std::thread::spawn(move || serve_streams(PairListener(Mutex::new(rx)), e));
        }
        let stream_conn = || {
            let (mine, theirs) = UnixStream::pair().unwrap();
            stream_tx.send(theirs).unwrap();
            mine
        };

        // Pre-make the dest dir inside the root.
        std::fs::create_dir_all(tmp.path().join("dst")).unwrap();

        // --- TarExtract: send StreamOpen, then a tar rooted at the source
        // basename (`file.txt`), with dest=/dst (an existing dir → into-dir
        // rule), then expect ONE Ok frame. The entry lands at /dst/file.txt.
        let mut ext = stream_conn();
        write_frame(
            &mut ext,
            &StreamOpen::TarExtract {
                dest: "/dst".into(),
            },
        )
        .unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let data = b"payload";
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        b.append_data(&mut hdr, "file.txt", &mut &data[..]).unwrap();
        let archive = b.into_inner().unwrap();
        ext.write_all(&archive).unwrap();
        ext.shutdown(std::net::Shutdown::Write).unwrap();
        match read_frame::<_, Response>(&mut ext).unwrap() {
            Response::Ok => {}
            other => panic!("extract expected Ok, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(tmp.path().join("dst/file.txt")).unwrap(),
            b"payload"
        );

        // --- TarCreate: send StreamOpen, expect ONE leading Ok, then a tar.
        // src=/dst (a directory) → archive rooted at basename `dst`.
        let mut cre = stream_conn();
        write_frame(&mut cre, &StreamOpen::TarCreate { src: "/dst".into() }).unwrap();
        match read_frame::<_, Response>(&mut cre).unwrap() {
            Response::Ok => {}
            other => panic!("create expected leading Ok, got {other:?}"),
        }
        let mut body = Vec::new();
        cre.read_to_end(&mut body).unwrap();
        let mut found = false;
        let mut ar = tar::Archive::new(Cursor::new(&body));
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "dst/file.txt" {
                found = true;
            }
        }
        assert!(found, "created archive must contain dst/file.txt");
    }

    #[test]
    fn tar_create_missing_src_sends_leading_error() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = Arc::new(ExecEngine::new(Some(tmp.path().to_path_buf())));
        let (stream_tx, rx) = mpsc::channel();
        {
            let e = Arc::clone(&engine);
            std::thread::spawn(move || serve_streams(PairListener(Mutex::new(rx)), e));
        }
        let (mut mine, theirs) = UnixStream::pair().unwrap();
        stream_tx.send(theirs).unwrap();
        write_frame(
            &mut mine,
            &StreamOpen::TarCreate {
                src: "/nope".into(),
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut mine).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::PathNotFound),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
    }

    /// A `TcpDial` that connects to a live loopback listener must reply Ok and
    /// then pump bytes both ways. Binds a real TcpListener → runtime-skip if
    /// the sandbox denies bind.
    #[test]
    fn tcp_dial_ok_pumps_both_ways() {
        use std::net::TcpListener;
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_dial_ok_pumps_both_ways: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        // Echo server: read a line, write it back uppercased-prefixed.
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            // Half-close so our drain sees EOF.
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || tcp_dial(server, port));

        // First frame the init side sends is the Ok response.
        match read_frame::<_, Response>(&mut client).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        client.write_all(b"hi").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");

        srv.join().unwrap();
        h.join().unwrap();
    }

    /// A `TcpDial` to a refused loopback port must reply Error{ConnectFailed}
    /// and close. Port 1 is privileged/closed for an unprivileged dial; if the
    /// dial unexpectedly succeeds the assert fails loudly.
    #[test]
    fn tcp_dial_refused_reports_connect_failed() {
        // Bind-and-drop to obtain a definitely-free port, then dial it.
        use std::net::TcpListener;
        let port = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                drop(l); // nothing is listening on p now
                p
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_dial_refused_reports_connect_failed: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || tcp_dial(server, port));
        match read_frame::<_, Response>(&mut client).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::ConnectFailed),
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
        // Conn is closed after the error frame.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        h.join().unwrap();
    }

    #[test]
    fn shutdown_sets_flag_and_replies() {
        let h = Harness::new();
        let mut c = h.control_conn();
        assert!(!h.shutdown.load(Ordering::SeqCst));
        match rpc(&mut c, &Request::Shutdown) {
            Response::Ok => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert!(h.shutdown.load(Ordering::SeqCst));
        // Conn is closed after the ack.
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn kill_via_control() {
        let h = Harness::new();
        let mut c = h.control_conn();
        let exec_id = match rpc(
            &mut c,
            &Request::Exec(ExecRequest {
                argv: vec!["sleep".into(), "30".into()],
                env: vec![],
                cwd: "/".into(),
                tty: false,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            }),
        ) {
            Response::ExecStarted { exec_id } => exec_id,
            other => panic!("unexpected: {other:?}"),
        };
        match rpc(
            &mut c,
            &Request::Kill {
                exec_id,
                signal: 15,
            },
        ) {
            Response::Ok => {}
            other => panic!("unexpected: {other:?}"),
        }
        match rpc(&mut c, &Request::Wait { exec_id }) {
            Response::Wait { status } => assert_eq!(status, ExitStatus::Signal(15)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn bad_exec_reports_error_kind() {
        let h = Harness::new();
        let mut c = h.control_conn();
        match rpc(
            &mut c,
            &Request::Exec(ExecRequest {
                argv: vec!["/nonexistent/zzz".into()],
                env: vec![],
                cwd: "/".into(),
                tty: false,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            }),
        ) {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::CommandNotFound),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
