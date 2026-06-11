//! `DaemonClient` — the CLI's (and any embedder's) handle to izbad.
//! `connect()` is the daemon-first entry point: it finds, auto-starts, or
//! auto-upgrades the daemon, performs the hello, and hands back a typed
//! RPC channel. One client = one connection; open several for concurrent
//! blocking RPCs (e.g. exec's Wait alongside Resize).

use anyhow::{bail, Context};
use std::time::{Duration, Instant};

use izba_proto::{read_frame, write_frame, Request, Response};

use crate::daemon::proto::{DaemonHello, DaemonRequest, DaemonResponse};
use crate::daemon::transport;
use crate::paths::Paths;
use crate::procmgr;
use crate::vmm::{CommandSpec, UdsStream};

const SPAWN_RETRY: Duration = Duration::from_millis(100);
const SPAWN_RETRIES: u32 = 30; // ~3 s total
const GONE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonClient {
    conn: UdsStream,
    pub server_version: String,
}

impl DaemonClient {
    /// Connect to a running daemon. `Ok(None)` when there is none (missing
    /// socket or nothing accepting). Never auto-starts.
    pub fn connect_existing(paths: &Paths) -> anyhow::Result<Option<DaemonClient>> {
        match transport::connect_socket(paths) {
            Ok(s) => Ok(Some(Self::handshake(s, &transport::daemon_version())?)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e).context("connecting to the izbad socket"),
        }
    }

    /// Daemon-first connect: auto-start when absent, auto-upgrade (shutdown +
    /// respawn) on version mismatch.
    pub fn connect(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(paths, &spawn_daemon, &transport::daemon_version())
    }

    /// Seam for tests: injectable spawner + client version.
    fn connect_with(
        paths: &Paths,
        spawner: &dyn Fn(&Paths) -> anyhow::Result<()>,
        my_version: &str,
    ) -> anyhow::Result<DaemonClient> {
        for attempt in 0..2 {
            let client = match Self::connect_existing(paths)? {
                Some(c) => c,
                None => {
                    clear_stale_socket(paths)?;
                    spawner(paths)?;
                    Self::await_daemon(paths, my_version)?
                }
            };
            if client.server_version == my_version {
                return Ok(client);
            }
            let server_version = client.server_version.clone();
            if attempt == 1 {
                bail!(
                    "daemon still reports version {server_version} (CLI is {my_version}) \
                     after a restart — kill it manually: izba daemon stop"
                );
            }
            eprintln!(
                "izba: daemon version {server_version} != CLI {my_version}; restarting daemon"
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
            },
        )
        .context("sending hello")?;
        let resp: DaemonResponse = read_frame(&mut s).context("reading hello reply")?;
        s.set_read_timeout(None)?;
        match resp {
            DaemonResponse::HelloOk { version } => Ok(DaemonClient {
                conn: s,
                server_version: version,
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

    /// The OpenStream conversion on THIS connection (test seam; production
    /// callers use [`Self::open_guest_stream`]).
    pub(crate) fn open_stream_on_self(mut self, name: &str) -> anyhow::Result<UdsStream> {
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
            if write_frame(&mut s, &DaemonResponse::HelloOk { version }).is_err() {
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
