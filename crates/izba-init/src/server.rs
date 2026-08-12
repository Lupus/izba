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
use std::net::Ipv4Addr;
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
/// which sets the flag and then acknowledges with `Ok`).
///
/// NOTE: exiting the accept loop is best-effort — a quiet listener blocks in
/// accept() forever, so `main` watches the flag itself and never joins this
/// thread; run it as a daemon thread.
pub fn serve_control<L: Listener>(
    l: L,
    engine: Arc<ExecEngine>,
    usb: Arc<izba_init::usb::UsbState>,
    stats: Arc<crate::stats::StatsContext>,
    shutdown: Arc<AtomicBool>,
) {
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
        let usb = Arc::clone(&usb);
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || control_conn(conn, engine, usb, stats, shutdown));
    }
}

fn control_conn<C: Read + Write>(
    mut conn: C,
    engine: Arc<ExecEngine>,
    usb: Arc<izba_init::usb::UsbState>,
    stats: Arc<crate::stats::StatsContext>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        let req: Request = match read_frame(&mut conn) {
            Ok(r) => r,
            Err(_) => return, // clean EOF or broken peer either way
        };
        if let Request::Shutdown = req {
            // Commit the flag before acking: when the host receives Ok it
            // can immediately observe the shutdown state (the test asserts
            // this, and the real guest's PID 1 relies on it for poweroff
            // sequencing).  write_frame is on the same thread, so the
            // store strictly happens-before the socket write.
            shutdown.store(true, Ordering::SeqCst);
            let _ = write_frame(&mut conn, &Response::Ok);
            return;
        }
        let resp = dispatch_control_request(&engine, &usb, &stats, req);
        if write_frame(&mut conn, &resp).is_err() {
            return;
        }
    }
}

/// Maps a non-`Shutdown` control request to its response. `Shutdown` is handled
/// by the caller because it must ack then close the connection.
fn dispatch_control_request(
    engine: &ExecEngine,
    usb: &izba_init::usb::UsbState,
    stats: &crate::stats::StatsContext,
    req: Request,
) -> Response {
    let from_unit = |r: Result<(), (ErrorKind, String)>| match r {
        Ok(()) => Response::Ok,
        Err((kind, message)) => Response::Error { kind, message },
    };
    match req {
        Request::Health => Response::Health(HealthInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_ms: START.elapsed().as_millis() as u64,
            // Report the workload container's live state so the host can be
            // honest when the container has exited even though this guest RPC
            // (and the VM) is still up. `crun state` is queried fresh on each
            // health check; an unreachable/unparseable crun yields `Unknown`,
            // never a falsely-healthy answer. On a crun-less unit host this is
            // `Unknown`; the real value is exercised by the VM checkpoint.
            container: Some(crate::oci::container_state(crate::oci::CONTAINER_ID)),
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
        Request::Kill { exec_id, signal } => from_unit(engine.kill(exec_id, signal)),
        Request::Resize {
            exec_id,
            cols,
            rows,
        } => from_unit(engine.resize(exec_id, cols, rows)),
        // USB support is decided by the HOST, at boot, via `izba.usb=1` on the
        // kernel cmdline; `UsbState` refuses everything without it. Nothing
        // inside the guest can turn it on.
        Request::UsbAttach { device } => {
            from_unit(usb.attach_with(&device, izba_init::usb::dial_host))
        }
        Request::UsbDetach { device } => from_unit(usb.detach(&device)),
        Request::Stats => {
            let mut g = crate::stats::collect(stats);
            // Same honest container source as Health: queried fresh, Unknown
            // when crun can't answer — never a stale claim.
            g.container = Some(crate::oci::container_state(crate::oci::CONTAINER_ID));
            Response::Stats(g)
        }
        // Handled by control_conn (acks then closes the connection).
        Request::Shutdown => unreachable!("Shutdown handled by control_conn"),
    }
}

/// Serves stream attachments; never returns under normal operation
/// (run as a daemon thread). Logs and retries on accept errors.
///
/// `docker` selects the `tcp_dial` fallback address: in docker mode the
/// workload (including docker-proxy's published ports) runs in its own
/// netns at `net::GUEST_IP`, not init's loopback, so a `TcpDial` that finds
/// nothing on `127.0.0.1` needs a second try there. Computed once here
/// rather than per-connection since it never changes for the process's
/// lifetime.
/// `fs_ids`, when set (docker mode), are the fs uid/gid `TarExtract` writes
/// adopt so extracted files land as disk-0 = container-root-owned through the
/// idmapped rootfs (see idmap.rs; a plain fsuid-0 write would land on the
/// fsuid-0 anchor and present as `nobody`). `setfsuid` is per-thread, and
/// each stream runs on its own thread, so the guard cannot leak across
/// connections.
pub fn serve_streams<L: Listener>(
    l: L,
    engine: Arc<ExecEngine>,
    docker: bool,
    fs_ids: Option<(u32, u32)>,
) {
    let fallback = docker.then_some(crate::net::GUEST_IP);
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
        std::thread::spawn(move || stream_conn(conn, engine, fallback, fs_ids));
    }
}

fn stream_conn<C: Read + Write + AsRawFd + Send + 'static>(
    mut conn: C,
    engine: Arc<ExecEngine>,
    fallback: Option<Ipv4Addr>,
    fs_ids: Option<(u32, u32)>,
) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return,
    };
    let attach = match open {
        StreamOpen::Attach(a) => a,
        StreamOpen::TarExtract { dest } => {
            match fs_ids {
                Some(ids) => {
                    crate::idmap::with_fs_ids(ids, || tar_extract(&mut conn, &engine, &dest))
                }
                None => tar_extract(&mut conn, &engine, &dest),
            }
            return;
        }
        StreamOpen::TarCreate { src } => {
            tar_create(&mut conn, &engine, &src);
            return;
        }
        StreamOpen::TcpDial { port } => {
            tcp_dial(conn, port, fallback);
            return;
        }
        // Egress variants are handled by izbad on the host (vsock port 1027),
        // not by init. Reject them if they somehow arrive on port 1026.
        StreamOpen::TcpConnect { .. } | StreamOpen::Dns | StreamOpen::DnsTcp => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "egress variants are not handled by init".into(),
                },
            );
            return;
        }
        // The USB plane is izbad's (vsock port 1028) and is dialed BY init,
        // never served by it. Arriving here means something inside the guest
        // is probing planes it was not given; refuse rather than guess.
        StreamOpen::UsbAttach { .. } => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "usb_attach is not handled by init".into(),
                },
            );
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
    let resp = match izba_init::tarfs::extract(root, dest, conn) {
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
    let resolved = match izba_init::tarfs::resolve_src(root, src) {
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
    let _ = izba_init::tarfs::stream_tar(&resolved, conn);
}

/// Init side of `StreamOpen::TcpDial`: dial `127.0.0.1:port` inside the guest,
/// reply one `Response` frame (`Ok` | `Error{ConnectFailed}`), and on `Ok`
/// become a raw bidirectional byte pipe.
///
/// `C` is the vsock connection (host side). On guest-socket EOF we
/// `shutdown(Write)` toward the host and drain the remaining host->guest bytes;
/// this graceful teardown is also the planned OpenVMM vsock-churn mitigation.
///
/// `fallback`, when set (docker mode: `net::GUEST_IP`), is dialed AFTER
/// loopback refuses. Docker-mode workload listeners — including
/// docker-proxy's published ports — live in the container's own netns at
/// that address, while init-netns services (sshd on `:22`) stay on
/// loopback; trying loopback first keeps those reachable, and the fallback
/// is what makes docker-published ports reachable at all. Both attempts
/// share the 10 s cap.
fn tcp_dial<C: Read + Write + AsRawFd + Send + 'static>(
    mut conn: C,
    port: u16,
    fallback: Option<Ipv4Addr>,
) {
    use std::net::{Shutdown, SocketAddr, TcpStream};
    // Spec §5: 10 s dial cap. Loopback normally refuses instantly; the cap
    // guards pathological guest states (e.g. workload firewall DROP rules)
    // so a relay thread can never hang in connect forever.
    let timeout = std::time::Duration::from_secs(10);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let target = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(t) => t,
        Err(first) => match fallback {
            Some(ip) => {
                let fb_addr = SocketAddr::from((ip, port));
                match TcpStream::connect_timeout(&fb_addr, timeout) {
                    Ok(t) => t,
                    Err(second) => {
                        let _ = write_frame(
                            &mut conn,
                            &Response::Error {
                                kind: ErrorKind::ConnectFailed,
                                message: format!(
                                    "127.0.0.1:{port}: {first}; {ip}:{port}: {second}"
                                ),
                            },
                        );
                        return;
                    }
                }
            }
            None => {
                let _ = write_frame(
                    &mut conn,
                    &Response::Error {
                        kind: ErrorKind::ConnectFailed,
                        message: first.to_string(),
                    },
                );
                return;
            }
        },
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
pub(crate) fn relay_pump(mut r: impl Read, w: &mut impl Write) {
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

pub(crate) fn dup_fd(fd: std::os::fd::RawFd) -> std::io::Result<OwnedFd> {
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

    /// A minimal `StatsContext` for tests that don't care about `Request::Stats`
    /// itself, just that the control server is wired with SOME context: an
    /// empty (but real, so `collect`'s reads don't error mid-scan) tempdir
    /// procfs. The dir is leaked (never cleaned up) so its path stays valid
    /// for the lifetime of the harness thread it's handed to.
    fn test_stats_ctx() -> Arc<crate::stats::StatsContext> {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::create_dir_all(root.join("proc")).unwrap();
        Arc::new(crate::stats::StatsContext {
            procfs: root.join("proc"),
            rootfs: root.join("rootfs"),
            volume_paths: vec![],
            docker: false,
            engine_log: root.join("no.log"),
            clk_tck: 100,
            page_kb: 4,
        })
    }

    struct Harness {
        control_tx: mpsc::Sender<UnixStream>,
        stream_tx: mpsc::Sender<UnixStream>,
        shutdown: Arc<AtomicBool>,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_stats(test_stats_ctx())
        }

        fn with_stats(stats: Arc<crate::stats::StatsContext>) -> Self {
            // Direct-spawn engine: the server RPC-wiring tests exec real
            // binaries (sh/sleep) and assert exec/kill/resize/stream framing.
            // Production wraps execs in `crun exec`, which is absent on the test
            // host; `new_direct` spawns the request argv directly so these tests
            // exercise the server plumbing without a live crun + container.
            let engine = Arc::new(ExecEngine::new_direct(None));
            let shutdown = Arc::new(AtomicBool::new(false));

            let (control_tx, rx) = mpsc::channel();
            // USB off, the way a sandbox without device grants boots: the
            // harness proves the RPCs are wired, not that a vhci exists.
            let usb = Arc::new(izba_init::usb::UsbState::new(false));
            let (e, s) = (Arc::clone(&engine), Arc::clone(&shutdown));
            std::thread::spawn(move || {
                serve_control(PairListener(Mutex::new(rx)), e, usb, stats, s)
            });

            let (stream_tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                serve_streams(PairListener(Mutex::new(rx)), engine, false, None)
            });

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
                // The handler always reports a container state. On this
                // crun-less unit host the query fails, which is honestly
                // `Unknown` — never `None` (absent) and never a healthy claim.
                assert_eq!(info.container, Some(izba_proto::ContainerState::Unknown));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn stats_request_returns_guest_stats_with_container_state() {
        // Fake procfs with one process; StatsContext pointing at it.
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("proc").join("1");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            "1 (init) S 0 1 1 0 -1 0 0 0 0 0 2 1 0 0 20 0 1 0 3 1000 50 0\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("proc").join("meminfo"),
            "MemTotal: 500 kB\nMemAvailable: 250 kB\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("proc").join("loadavg"),
            "0.10 0.20 0.30 1/1 1\n",
        )
        .unwrap();
        let ctx = Arc::new(crate::stats::StatsContext {
            procfs: t.path().join("proc"),
            rootfs: t.path().join("rootfs"), // absent: mounts just come back empty
            volume_paths: vec![],
            docker: false,
            engine_log: t.path().join("no.log"),
            clk_tck: 100,
            page_kb: 4,
        });
        let h = Harness::with_stats(ctx);
        let mut c = h.control_conn();
        match rpc(&mut c, &Request::Stats) {
            Response::Stats(g) => {
                assert_eq!(g.process_count, 1);
                assert_eq!(g.mem_total_kb, 500);
                assert_eq!(g.load5_centi, 20);
                assert!(g.docker.is_none());
                // On a crun-less unit host container state is Unknown — but SET.
                assert!(g.container.is_some());
            }
            other => panic!("expected Stats, got {other:?}"),
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
        let engine = Arc::new(ExecEngine::new(Some(tmp.path().to_path_buf()), false));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (stream_tx, rx) = mpsc::channel();
        {
            let e = Arc::clone(&engine);
            let _ = &shutdown;
            std::thread::spawn(move || serve_streams(PairListener(Mutex::new(rx)), e, false, None));
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

    /// The docker-mode fs-id guard path: with `fs_ids` set, TarExtract must
    /// still run the extraction (under `with_fs_ids` — a no-op switch to our
    /// own euid/egid on an unprivileged host, but the ARM must execute; a
    /// deleted `Some` arm would silently fall through to the plain path in
    /// the guest and land cp writes on the fsuid-0 anchor as `nobody`).
    #[test]
    fn tar_extract_runs_under_the_docker_fs_id_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = Arc::new(ExecEngine::new(Some(tmp.path().to_path_buf()), false));
        let (stream_tx, rx) = mpsc::channel();
        let own_ids = unsafe { (libc::geteuid(), libc::getegid()) };
        {
            let e = Arc::clone(&engine);
            std::thread::spawn(move || {
                serve_streams(PairListener(Mutex::new(rx)), e, false, Some(own_ids))
            });
        }
        let (mut ext, theirs) = UnixStream::pair().unwrap();
        stream_tx.send(theirs).unwrap();
        std::fs::create_dir_all(tmp.path().join("dst")).unwrap();
        write_frame(
            &mut ext,
            &StreamOpen::TarExtract {
                dest: "/dst".into(),
            },
        )
        .unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let data = b"guarded";
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        b.append_data(&mut hdr, "g.txt", &mut &data[..]).unwrap();
        let archive = b.into_inner().unwrap();
        ext.write_all(&archive).unwrap();
        ext.shutdown(std::net::Shutdown::Write).unwrap();
        match read_frame::<_, Response>(&mut ext).unwrap() {
            Response::Ok => {}
            other => panic!("guarded extract expected Ok, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(tmp.path().join("dst/g.txt")).unwrap(),
            b"guarded"
        );
    }

    #[test]
    fn tar_create_missing_src_sends_leading_error() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = Arc::new(ExecEngine::new(Some(tmp.path().to_path_buf()), false));
        let (stream_tx, rx) = mpsc::channel();
        {
            let e = Arc::clone(&engine);
            std::thread::spawn(move || serve_streams(PairListener(Mutex::new(rx)), e, false, None));
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
        let h = std::thread::spawn(move || tcp_dial(server, port, None));

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

    /// Test-only entry into `stream_conn` bypassing `serve_streams`' Listener
    /// plumbing: builds a throwaway direct-spawn engine (never touched by a
    /// `TcpDial` frame's dispatch — it returns before any exec lookup) and
    /// drives one connection with the given fallback address, exercising the
    /// real `StreamOpen` → `tcp_dial` threading path end to end.
    fn stream_conn_for_test<C: Read + Write + AsRawFd + Send + 'static>(
        conn: C,
        fallback: Option<Ipv4Addr>,
    ) {
        let engine = Arc::new(ExecEngine::new_direct(None));
        stream_conn(conn, engine, fallback, None);
    }

    /// A `TcpDial` whose loopback attempt refuses must fall back to the
    /// docker-mode veth address (here: a second loopback address, 127.0.0.2,
    /// standing in for `net::GUEST_IP` — still 127/8 and bindable without
    /// extra setup) and succeed there.
    #[test]
    fn tcp_dial_falls_back_to_secondary_address() {
        let l = match std::net::TcpListener::bind(("127.0.0.2", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "SKIP tcp_dial_falls_back_to_secondary_address: sandbox denies bind: {e}"
                );
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let port = l.local_addr().unwrap().port();
        let (a, b) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || {
            let mut conn = a;
            write_frame(&mut conn, &StreamOpen::TcpDial { port }).unwrap();
            let resp: Response = read_frame(&mut conn).unwrap();
            // Accept the fallback dial and drop it: the relay's target-side
            // read needs that EOF to finish, and `stream_conn_for_test`
            // (below, on the test's main thread) doesn't return until the
            // relay does — accepting after it returned would deadlock.
            let (accepted, _) = l.accept().unwrap();
            drop(accepted);
            matches!(resp, Response::Ok)
        });
        stream_conn_for_test(b, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert!(t.join().unwrap());
    }

    /// With a fallback configured, when BOTH dials refuse the single
    /// `ConnectFailed` message must name both attempts — the operator needs
    /// to see that a second address was tried and what each one said.
    #[test]
    fn tcp_dial_both_attempts_fail_reports_both_addresses() {
        // Bind-and-drop on the wildcard address so the port is free on every
        // local address (both 127.0.0.1 and the 127.0.0.2 fallback).
        use std::net::TcpListener;
        let port = match TcpListener::bind(("0.0.0.0", 0)) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                drop(l); // nothing is listening on p now
                p
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "SKIP tcp_dial_both_attempts_fail_reports_both_addresses: sandbox denies bind: {e}"
                );
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let fallback = Some(Ipv4Addr::new(127, 0, 0, 2));
        let h = std::thread::spawn(move || tcp_dial(server, port, fallback));
        match read_frame::<_, Response>(&mut client).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(
                    message.contains(&format!("127.0.0.1:{port}")),
                    "message must name the loopback attempt: {message}"
                );
                assert!(
                    message.contains(&format!("127.0.0.2:{port}")),
                    "message must name the fallback attempt: {message}"
                );
            }
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
        h.join().unwrap();
    }

    /// The no-fallback dial must surface `ConnectFailed`. The free port is
    /// obtained by bind-and-drop, which is inherently racy under parallel
    /// execution: another test can bind the dropped port before our dial
    /// (observed twice in PR #215 review runs — #220), making the dial
    /// SUCCEED. A success is therefore treated as a raced port and retried
    /// with a fresh one, never asserted against.
    #[test]
    fn tcp_dial_without_fallback_reports_connect_failed() {
        use std::net::TcpListener;
        for attempt in 0..5 {
            let port = match TcpListener::bind(("127.0.0.1", 0)) {
                Ok(l) => {
                    let p = l.local_addr().unwrap().port();
                    drop(l); // nothing is listening on p now — usually
                    p
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "SKIP tcp_dial_without_fallback_reports_connect_failed: sandbox denies bind: {e}"
                    );
                    return;
                }
                Err(e) => panic!("unexpected bind failure: {e}"),
            };
            let (mut client, server) = UnixStream::pair().unwrap();
            let h = std::thread::spawn(move || tcp_dial(server, port, None));
            match read_frame::<_, Response>(&mut client).unwrap() {
                Response::Error { kind, .. } => {
                    assert_eq!(kind, ErrorKind::ConnectFailed);
                    // Conn is closed after the error frame.
                    let mut rest = Vec::new();
                    client.read_to_end(&mut rest).unwrap();
                    assert!(rest.is_empty());
                    h.join().unwrap();
                    return;
                }
                Response::Ok => {
                    // Raced: something bound the port between drop and dial.
                    // Drop our end — tcp_dial tears down on EOF — and retry.
                    eprintln!(
                        "tcp_dial deflake: port {port} was re-bound mid-test (attempt {attempt}), retrying"
                    );
                    drop(client);
                    h.join().unwrap();
                }
                other => panic!("expected ConnectFailed (or a raced Ok), got {other:?}"),
            }
        }
        panic!(
            "5 consecutive bind-and-drop ports were all re-bound by parallel \
             tests — something is systematically grabbing freed ports"
        );
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

    /// Egress variants (`Dns`/`TcpConnect`) are izbad's job on vsock 1027; if
    /// one arrives on the init stream port it must get one BadRequest frame and
    /// a closed conn, never silent acceptance.
    #[test]
    fn egress_variant_rejected_on_stream_port() {
        let h = Harness::new();
        let mut conn = h.stream_conn();
        write_frame(&mut conn, &StreamOpen::Dns).unwrap();
        match read_frame::<_, Response>(&mut conn).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("unexpected: {other:?}"),
        }
        // Server closes the conn after the single error frame.
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    /// The USB RPCs must reach `UsbState` rather than being answered inline:
    /// the harness boots USB off, so both verbs come back `UsbUnavailable`, and
    /// the message is the one only `UsbState::gate` produces.
    #[test]
    fn usb_rpcs_are_wired_to_the_usb_state_and_refuse_without_izba_usb() {
        let h = Harness::new();
        for req in [
            Request::UsbAttach {
                device: "0403:6001".into(),
            },
            Request::UsbDetach {
                device: "0403:6001".into(),
            },
        ] {
            let mut c = h.control_conn();
            match rpc(&mut c, &req) {
                Response::Error { kind, message } => {
                    assert_eq!(kind, ErrorKind::UsbUnavailable, "{req:?}");
                    assert!(message.contains("izba.usb=1"), "{req:?}: {message}");
                    assert!(
                        message.contains("restart"),
                        "the fix is a restart, and must be said: {message}"
                    );
                }
                other => panic!("{req:?} must refuse without USB, got {other:?}"),
            }
        }
    }

    /// A `UsbAttach` arriving on the STREAM port is a guest probing a plane it
    /// was not given: that variant belongs to izbad on vsock 1028, and init
    /// only ever dials it.
    #[test]
    fn usb_attach_is_rejected_on_the_stream_port() {
        let h = Harness::new();
        let mut conn = h.stream_conn();
        write_frame(
            &mut conn,
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut conn).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("unexpected: {other:?}"),
        }
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "one error frame, then closed");
    }

    /// A Resize RPC against a non-tty exec must round-trip through the control
    /// server to a BadRequest (exercises the control Resize arm + error mapping).
    #[test]
    fn resize_non_tty_via_control() {
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
            &Request::Resize {
                exec_id,
                cols: 80,
                rows: 24,
            },
        ) {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("unexpected: {other:?}"),
        }
        // Reap the sleep so the test leaves no lingering process.
        let _ = rpc(&mut c, &Request::Kill { exec_id, signal: 9 });
        let _ = rpc(&mut c, &Request::Wait { exec_id });
    }
}
