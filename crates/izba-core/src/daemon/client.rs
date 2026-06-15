//! `DaemonClient` — the CLI's (and any embedder's) handle to izbad.
//! `connect()` is the daemon-first entry point: it finds, auto-starts, or
//! auto-upgrades the daemon, performs the hello, and hands back a typed
//! RPC channel. One client = one connection; open several for concurrent
//! blocking RPCs (e.g. exec's Wait alongside Resize).

use anyhow::{bail, Context};
use std::time::{Duration, Instant};

use izba_proto::{read_frame, write_frame, Request, Response};

use crate::build_info::BuildInfoOwned;
use crate::daemon::proto::{DaemonHello, DaemonRequest, DaemonResponse, DAEMON_PROTO_VERSION};
use crate::daemon::transport;
use crate::paths::Paths;
use crate::procmgr;
use crate::vmm::{CommandSpec, UdsStream};

const SPAWN_RETRY: Duration = Duration::from_millis(100);
const SPAWN_RETRIES: u32 = 30; // ~3 s total
const GONE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonClient {
    conn: UdsStream,
    /// The daemon's display version string (`build.short()`).
    pub server_version: String,
    /// The daemon's wire-protocol version — the compatibility gate.
    pub server_proto: u32,
    /// The daemon's full build metadata (for `izba version` / the app UI).
    pub server_build: BuildInfoOwned,
}

impl DaemonClient {
    /// Connect to a running daemon. `Ok(None)` when there is none (missing
    /// socket or nothing accepting). Never auto-starts.
    pub fn connect_existing(paths: &Paths) -> anyhow::Result<Option<DaemonClient>> {
        // Check the socket file first: it is the cross-platform "is there a
        // daemon" signal (the daemon unlinks it on exit), and it sidesteps
        // WinSock's unhelpful errno mapping for dead AF_UNIX paths.
        if !paths.daemon_socket().exists() {
            return Ok(None);
        }
        match transport::connect_socket(paths) {
            Ok(s) => Ok(Some(Self::handshake(s, &transport::daemon_version())?)),
            Err(e) if connect_says_no_daemon(&e) => Ok(None),
            Err(e) => Err(e).context("connecting to the izbad socket"),
        }
    }

    /// Like [`Self::connect_existing`], but a handshake that dies mid-flight
    /// (EOF / reset / timeout) also counts as "no daemon": a daemon caught
    /// mid-idle-exit accepts from the backlog then exits before serving the
    /// hello. The spec contract is auto-restart — worst case one retry — so
    /// `connect_with` treats that as absent and takes the spawn path.
    /// `connect_existing` itself stays strict (status/stop must not spawn).
    fn connect_existing_tolerant(paths: &Paths) -> anyhow::Result<Option<DaemonClient>> {
        match Self::connect_existing(paths) {
            Ok(c) => Ok(c),
            Err(e) if is_daemon_gone(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Daemon-first connect: auto-start when absent, auto-upgrade (shutdown +
    /// respawn) on wire-protocol mismatch.
    pub fn connect(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(paths, &spawn_daemon, &transport::daemon_version())
    }

    /// Connect for embedders (the GUI) whose own `current_exe` is NOT `izba`:
    /// spawn the sibling `izba` binary's `daemon run` rather than re-exec
    /// ourselves. `izba-app` and `izba` install side by side (same dir on
    /// Windows; both on PATH via the .deb), so we resolve `izba[.exe]` next to
    /// the current executable first, then fall back to bare `izba` for the OS
    /// to resolve via PATH.
    pub fn connect_spawning_izba(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(paths, &spawn_sibling_izba, &transport::daemon_version())
    }

    /// Seam for tests: injectable spawner + client version.
    fn connect_with(
        paths: &Paths,
        spawner: &dyn Fn(&Paths) -> anyhow::Result<()>,
        my_version: &str,
    ) -> anyhow::Result<DaemonClient> {
        for attempt in 0..2 {
            let client = match Self::connect_existing_tolerant(paths)? {
                Some(c) => c,
                None => {
                    clear_stale_socket(paths)?;
                    spawner(paths)?;
                    Self::await_daemon(paths, my_version)?
                }
            };
            // Compatibility is gated on the wire PROTOCOL version, not the
            // (now sha-bearing) display string: a same-proto rebuild must not
            // churn-restart a healthy daemon. Only a proto change forces it.
            if client.server_proto == DAEMON_PROTO_VERSION {
                return Ok(client);
            }
            let server_proto = client.server_proto;
            let server_build = client.server_build.short();
            if attempt == 1 {
                bail!(
                    "daemon still speaks proto {server_proto} (CLI speaks {DAEMON_PROTO_VERSION}; \
                     daemon build {server_build}) after a restart — kill it manually: izba daemon stop"
                );
            }
            eprintln!(
                "izba: daemon proto {server_proto} != CLI {DAEMON_PROTO_VERSION} \
                 (daemon build {server_build}); restarting daemon"
            );
            client.shutdown()?;
            Self::await_gone(paths);
        }
        unreachable!("the loop returns or bails")
    }

    /// Hello exchange on a fresh connection (bounded so a wedged daemon
    /// cannot hang every CLI invocation).
    pub(crate) fn handshake(mut s: UdsStream, my_version: &str) -> anyhow::Result<DaemonClient> {
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        write_frame(
            &mut s,
            &DaemonHello {
                version: my_version.to_string(),
                proto: DAEMON_PROTO_VERSION,
            },
        )
        .context("sending hello")?;
        let resp: DaemonResponse = read_frame(&mut s).context("reading hello reply")?;
        s.set_read_timeout(None)?;
        match resp {
            DaemonResponse::HelloOk {
                version,
                proto,
                build,
            } => Ok(DaemonClient {
                conn: s,
                server_version: version,
                server_proto: proto,
                server_build: build,
            }),
            other => bail!("unexpected hello reply: {other:?}"),
        }
    }

    fn await_daemon(paths: &Paths, my_version: &str) -> anyhow::Result<DaemonClient> {
        for _ in 0..SPAWN_RETRIES {
            if let Ok(s) = transport::connect_socket(paths) {
                return Self::handshake(s, my_version);
            }
            std::thread::sleep(SPAWN_RETRY);
        }
        bail!(
            "daemon did not come up within {:?}; check {}{}",
            SPAWN_RETRY * SPAWN_RETRIES,
            paths.daemon_log().display(),
            log_tail(&paths.daemon_log(), 15)
        )
    }

    fn await_gone(paths: &Paths) {
        let deadline = Instant::now() + GONE_TIMEOUT;
        while Instant::now() < deadline {
            if transport::connect_socket(paths).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// One RPC round trip; Progress frames stream into `on_progress`.
    pub fn request(
        &mut self,
        req: &DaemonRequest,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<DaemonResponse> {
        write_frame(&mut self.conn, req).context("sending daemon request")?;
        loop {
            match read_frame::<_, DaemonResponse>(&mut self.conn)
                .context("daemon connection lost; rerun the command")?
            {
                DaemonResponse::Progress { message } => on_progress(&message),
                other => return Ok(other),
            }
        }
    }

    /// Re-read `name`'s `policy.yaml` and hot-swap it into the live egress
    /// plane (new flows only; no restart). Ok even if the sandbox is stopped.
    pub fn reload_policy(&mut self, name: &str) -> anyhow::Result<()> {
        match self.request(
            &DaemonRequest::ReloadPolicy {
                name: name.to_string(),
            },
            &mut |_| {},
        )? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected daemon reply: {other:?}"),
        }
    }

    /// Proxy one guest control RPC, unwrapping the daemon envelope.
    pub fn guest_rpc(&mut self, name: &str, req: &Request) -> anyhow::Result<Response> {
        match self.request(
            &DaemonRequest::GuestRpc {
                name: name.to_string(),
                req: req.clone(),
            },
            &mut |_| {},
        )? {
            DaemonResponse::Guest { payload } => Ok(payload),
            DaemonResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected daemon reply: {other:?}"),
        }
    }

    /// Open a raw byte stream to `name`'s guest stream port through the
    /// daemon (fresh connection; consumed by the conversion). The caller
    /// sends the guest `StreamOpen` frame on the returned stream.
    pub fn open_guest_stream(paths: &Paths, name: &str) -> anyhow::Result<UdsStream> {
        let client = Self::connect(paths)?;
        client.open_stream_on_self(name)
    }

    /// The OpenStream conversion on THIS connection (consumes it). Production
    /// callers use [`Self::open_guest_stream`]; this is for callers that must
    /// not auto-start a daemon (tests, diagnostics like ttystorm — their
    /// `current_exe` is not the izba binary, so the spawn path is wrong).
    pub fn open_stream_on_self(mut self, name: &str) -> anyhow::Result<UdsStream> {
        write_frame(
            &mut self.conn,
            &DaemonRequest::OpenStream {
                name: name.to_string(),
            },
        )
        .context("sending OpenStream")?;
        match read_frame::<_, DaemonResponse>(&mut self.conn).context("OpenStream reply")? {
            DaemonResponse::Ok => Ok(self.conn),
            DaemonResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected OpenStream reply: {other:?}"),
        }
    }

    /// Ask the daemon to exit (sandboxes keep running).
    pub fn shutdown(mut self) -> anyhow::Result<()> {
        match self.request(&DaemonRequest::Shutdown, &mut |_| {})? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected shutdown reply: {other:?}"),
        }
    }

    /// `shutdown`, then wait (bounded) until the daemon stops accepting —
    /// the Shutdown reply only means the flag is set; the accept loop needs
    /// up to one poll tick plus cleanup to actually exit. `izba daemon stop`
    /// must be synchronous so a follow-up `status` can't see a zombie.
    pub fn shutdown_and_wait(self, paths: &Paths) -> anyhow::Result<()> {
        self.shutdown()?;
        Self::await_gone(paths);
        Ok(())
    }
}

/// Does this error chain say "the daemon died under us mid-handshake"?
/// EOF/reset/timeout from the socket (raw io or wrapped in a FrameError).
/// Does this connect error mean "no daemon is listening"? Beyond the
/// portable kinds, Windows AF_UNIX surfaces raw WSA codes that std does not
/// map: connecting to a stale socket file yields WSAENETDOWN (10050) or
/// WSAEADDRNOTAVAIL (10049) instead of ConnectionRefused (observed on the
/// real Windows validation host).
fn connect_says_no_daemon(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    ) || matches!(e.raw_os_error(), Some(10050) | Some(10049))
}

fn is_daemon_gone(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let kind = match c.downcast_ref::<std::io::Error>() {
            Some(io) => Some(io.kind()),
            None => match c.downcast_ref::<izba_proto::FrameError>() {
                Some(izba_proto::FrameError::Eof) => return true,
                Some(izba_proto::FrameError::Io(io)) => Some(io.kind()),
                _ => None,
            },
        };
        matches!(
            kind,
            Some(
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::TimedOut
            )
        )
    })
}

/// Pre-spawn cleanup: if we can take the daemon flock, no daemon is alive —
/// unlink any stale socket so the fresh daemon binds cleanly. If the lock is
/// held, a daemon is starting/running and we leave everything alone (the
/// concurrent-spawn loser exits "daemon already running" and both clients
/// connect to the winner).
fn clear_stale_socket(paths: &Paths) -> anyhow::Result<()> {
    std::fs::create_dir_all(paths.daemon_dir())
        .with_context(|| format!("creating {}", paths.daemon_dir().display()))?;
    let f = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.daemon_lock())?;
    if f.try_lock().is_ok() {
        transport::remove_stale_socket(&paths.daemon_socket());
        let _ = f.unlock();
    }
    Ok(())
}

/// Spawn `izba daemon run` detached, logging to `<data>/daemon/daemon.log`.
fn spawn_daemon(paths: &Paths) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("locating the izba executable")?;
    let cmd = CommandSpec {
        argv: vec![
            exe.to_string_lossy().into_owned(),
            "daemon".to_string(),
            "run".to_string(),
        ],
    };
    procmgr::spawn_detached(&cmd, &paths.daemon_log())?;
    Ok(())
}

/// `izba` on Windows is `izba.exe`; elsewhere bare `izba`.
fn izba_exe_name() -> &'static str {
    if cfg!(windows) {
        "izba.exe"
    } else {
        "izba"
    }
}

/// Sibling `izba[.exe]` in `dir` as an absolute path, if it exists as a file.
fn resolve_izba_in(dir: &std::path::Path) -> Option<String> {
    let cand = dir.join(izba_exe_name());
    cand.is_file().then(|| cand.to_string_lossy().into_owned())
}

/// Resolve the `izba` binary to spawn: sibling of `current_exe` if present,
/// else bare `izba[.exe]` (PATH-resolved by the OS).
fn resolve_izba_binary() -> String {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(std::path::Path::parent)
        .and_then(resolve_izba_in)
        .unwrap_or_else(|| izba_exe_name().to_string())
}

/// Spawn `izba daemon run` detached (mirrors `spawn_daemon`, but targets the
/// sibling `izba` rather than `current_exe`).
fn spawn_sibling_izba(paths: &Paths) -> anyhow::Result<()> {
    let cmd = CommandSpec {
        argv: vec![
            resolve_izba_binary(),
            "daemon".to_string(),
            "run".to_string(),
        ],
    };
    procmgr::spawn_detached(&cmd, &paths.daemon_log())?;
    Ok(())
}

/// Last `n` lines of a log file, formatted for appending to an error
/// (mirrors sandbox.rs's console_tail; empty when unreadable).
fn log_tail(log: &std::path::Path, n: usize) -> String {
    let Ok(text) = std::fs::read_to_string(log) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let tail = &lines[lines.len().saturating_sub(n)..];
    format!(
        "\n--- daemon.log (last {} lines) ---\n{}",
        tail.len(),
        tail.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::*;
    use crate::vmm::UdsStream;
    use izba_proto::{read_frame, write_frame};

    /// A scripted fake daemon on the peer end of a socketpair: answers the
    /// hello with `version`, then runs `script` on the connection.
    fn fake_daemon(version: &str, script: impl FnOnce(UdsStream) + Send + 'static) -> UdsStream {
        let (client, server) = UdsStream::pair().unwrap();
        let version = version.to_string();
        std::thread::spawn(move || {
            let mut s = server;
            let _hello: DaemonHello = match read_frame(&mut s) {
                Ok(h) => h,
                Err(_) => return,
            };
            let hello_ok = DaemonResponse::HelloOk {
                version,
                proto: DAEMON_PROTO_VERSION,
                build: BuildInfoOwned::default(),
            };
            if write_frame(&mut s, &hello_ok).is_err() {
                return;
            }
            script(s);
        });
        client
    }

    #[test]
    fn handshake_matching_version() {
        let conn = fake_daemon("1.2.3", |_s| {});
        let c = DaemonClient::handshake(conn, "1.2.3").unwrap();
        assert_eq!(c.server_version, "1.2.3");
    }

    #[test]
    fn handshake_reports_server_version_on_mismatch() {
        let conn = fake_daemon("9.9.9", |_s| {});
        let c = DaemonClient::handshake(conn, "1.2.3").unwrap();
        // handshake itself succeeds; connect_with drives the upgrade dance.
        assert_eq!(c.server_version, "9.9.9");
    }

    #[test]
    fn request_skips_progress_frames() {
        let conn = fake_daemon("v", |mut s| {
            let _req: DaemonRequest = read_frame(&mut s).unwrap();
            write_frame(
                &mut s,
                &DaemonResponse::Progress {
                    message: "step 1".into(),
                },
            )
            .unwrap();
            write_frame(
                &mut s,
                &DaemonResponse::Progress {
                    message: "step 2".into(),
                },
            )
            .unwrap();
            write_frame(&mut s, &DaemonResponse::Ok).unwrap();
        });
        let mut c = DaemonClient::handshake(conn, "v").unwrap();
        let mut seen = Vec::new();
        let resp = c
            .request(&DaemonRequest::List, &mut |m| seen.push(m.to_string()))
            .unwrap();
        assert!(matches!(resp, DaemonResponse::Ok));
        assert_eq!(seen, vec!["step 1", "step 2"]);
    }

    #[test]
    fn guest_rpc_unwraps_guest_response() {
        let conn = fake_daemon("v", |mut s| {
            let req: DaemonRequest = read_frame(&mut s).unwrap();
            assert!(matches!(req, DaemonRequest::GuestRpc { .. }));
            write_frame(
                &mut s,
                &DaemonResponse::Guest {
                    payload: izba_proto::Response::Ok,
                },
            )
            .unwrap();
        });
        let mut c = DaemonClient::handshake(conn, "v").unwrap();
        let resp = c.guest_rpc("web", &izba_proto::Request::Health).unwrap();
        assert!(matches!(resp, izba_proto::Response::Ok));
    }

    #[test]
    fn guest_rpc_surfaces_daemon_errors() {
        let conn = fake_daemon("v", |mut s| {
            let _req: DaemonRequest = read_frame(&mut s).unwrap();
            write_frame(
                &mut s,
                &DaemonResponse::Error {
                    message: "sandbox 'web' is not running".into(),
                },
            )
            .unwrap();
        });
        let mut c = DaemonClient::handshake(conn, "v").unwrap();
        let err = c
            .guest_rpc("web", &izba_proto::Request::Health)
            .unwrap_err();
        assert!(err.to_string().contains("not running"), "{err:#}");
    }

    /// Scripted izbad on the REAL daemon socket: answers every hello with
    /// `version`; a Shutdown request unlinks the socket before the Ok reply
    /// (so post-shutdown connects fail like a dead daemon's) and stops the
    /// accept loop.
    fn serve_fake_daemon(
        paths: &crate::paths::Paths,
        version: &str,
        proto: u32,
    ) -> anyhow::Result<()> {
        use crate::daemon::transport;
        let listener = transport::bind_socket(paths)?;
        let version = version.to_string();
        let socket = paths.daemon_socket();
        std::thread::spawn(move || loop {
            let Ok((mut s, _peer)) = listener.accept() else {
                return;
            };
            if read_frame::<_, DaemonHello>(&mut s).is_err() {
                continue;
            }
            let hello_ok = DaemonResponse::HelloOk {
                version: version.clone(),
                proto,
                build: BuildInfoOwned::default(),
            };
            if write_frame(&mut s, &hello_ok).is_err() {
                continue;
            }
            // Serve requests until this client hangs up.
            while let Ok(req) = read_frame::<_, DaemonRequest>(&mut s) {
                if matches!(req, DaemonRequest::Shutdown) {
                    let _ = std::fs::remove_file(&socket);
                    let _ = write_frame(&mut s, &DaemonResponse::Ok);
                    return; // daemon "exits": stop accepting
                }
                let _ = write_frame(&mut s, &DaemonResponse::Ok);
            }
        });
        Ok(())
    }

    /// Probe bind permission via the real transport; returns true (and prints
    /// SKIP) when the sandbox denies bind (project convention: runtime-skip).
    fn bind_denied(paths: &crate::paths::Paths) -> bool {
        match crate::daemon::transport::bind_socket(paths) {
            Ok(l) => {
                drop(l);
                let _ = std::fs::remove_file(paths.daemon_socket());
                false
            }
            Err(e) => {
                let denied = e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                });
                if denied {
                    eprintln!("SKIP: bind denied in this environment");
                    true
                } else {
                    panic!("bind probe: {e:#}");
                }
            }
        }
    }

    /// connect_with against a real socket with no daemon: the spawner runs once
    /// and the fresh (same-proto) daemon is connected. (Reuse-without-respawn of
    /// an already-serving same-proto daemon is covered by
    /// `connect_with_keeps_daemon_on_build_only_diff`, which avoids the
    /// drop/reconnect timing that is flaky against the test fake on Windows.)
    #[test]
    fn connect_with_spawns_when_absent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        if bind_denied(&paths) {
            return;
        }
        let spawned = AtomicUsize::new(0);
        let client = DaemonClient::connect_with(
            &paths,
            &|p: &crate::paths::Paths| {
                spawned.fetch_add(1, Ordering::SeqCst);
                serve_fake_daemon(p, "v1", DAEMON_PROTO_VERSION)
            },
            "v1",
        )
        .unwrap();
        assert_eq!(spawned.load(Ordering::SeqCst), 1, "spawner ran");
        assert_eq!(client.server_proto, DAEMON_PROTO_VERSION);
        assert_eq!(client.server_version, "v1");
    }

    /// A daemon speaking an OLDER proto triggers the upgrade dance: shutdown,
    /// await_gone, respawn at the current proto.
    #[test]
    fn connect_with_restarts_on_proto_mismatch() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        if bind_denied(&paths) {
            return;
        }
        // Pre-existing daemon at proto 0 (an "old" build) already serving.
        serve_fake_daemon(&paths, "old", 0).unwrap();
        let spawned = AtomicUsize::new(0);
        let client = DaemonClient::connect_with(
            &paths,
            &|p: &crate::paths::Paths| {
                spawned.fetch_add(1, Ordering::SeqCst);
                serve_fake_daemon(p, "new", DAEMON_PROTO_VERSION)
            },
            "new",
        )
        .unwrap();
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "proto mismatch respawned"
        );
        assert_eq!(client.server_proto, DAEMON_PROTO_VERSION);
        assert_eq!(client.server_version, "new");
    }

    /// A same-proto daemon whose DISPLAY build differs (different sha) must NOT
    /// be restarted — the key behavior change from string-gating to proto-gating.
    #[test]
    fn connect_with_keeps_daemon_on_build_only_diff() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().join("izba"));
        if bind_denied(&paths) {
            return;
        }
        // Daemon at the CURRENT proto but a different display version.
        serve_fake_daemon(&paths, "0.1.0 (aaaaaaa)", DAEMON_PROTO_VERSION).unwrap();
        let spawned = AtomicUsize::new(0);
        let client = DaemonClient::connect_with(
            &paths,
            &|p: &crate::paths::Paths| {
                spawned.fetch_add(1, Ordering::SeqCst);
                serve_fake_daemon(p, "unused", DAEMON_PROTO_VERSION)
            },
            "0.1.0 (bbbbbbb)",
        )
        .unwrap();
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "no respawn on build-only diff"
        );
        assert_eq!(client.server_version, "0.1.0 (aaaaaaa)");
    }

    /// The idle-exit accept race classifier: mid-handshake EOF/reset means
    /// "daemon just exited" (retry via spawn); anything else propagates.
    #[test]
    fn daemon_gone_detection() {
        use anyhow::Context as _;
        let eof = Err::<(), _>(izba_proto::FrameError::Eof)
            .context("reading hello reply")
            .unwrap_err();
        assert!(is_daemon_gone(&eof));
        let reset = Err::<(), _>(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            .context("sending hello")
            .unwrap_err();
        assert!(is_daemon_gone(&reset));
        let denied = Err::<(), _>(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("connecting to the izbad socket")
            .unwrap_err();
        assert!(!is_daemon_gone(&denied));
    }

    #[test]
    fn resolve_izba_in_finds_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(izba_exe_name());
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(
            resolve_izba_in(dir.path()),
            Some(p.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn resolve_izba_in_absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(resolve_izba_in(dir.path()), None);
    }

    #[test]
    fn into_stream_after_open() {
        use std::io::{Read as _, Write as _};
        let conn = fake_daemon("v", |mut s| {
            let req: DaemonRequest = read_frame(&mut s).unwrap();
            assert!(matches!(req, DaemonRequest::OpenStream { .. }));
            write_frame(&mut s, &DaemonResponse::Ok).unwrap();
            // Echo one chunk raw.
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        });
        let c = DaemonClient::handshake(conn, "v").unwrap();
        let mut raw = c.open_stream_on_self("web").unwrap();
        raw.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        raw.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }
}
