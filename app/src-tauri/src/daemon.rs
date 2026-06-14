use crate::views::{DaemonStatusView, SandboxView};
use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::proto::{DaemonCreate, DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::vmm::UdsStream;
use izba_proto::{
    write_frame, ExecRequest, Request, Response, StreamAttach, StreamKind, StreamOpen,
};
use std::io::{Read, Write};
use std::net::Shutdown;

/// A live interactive shell stream into a guest. Implementations own their own
/// daemon connections (never the shared polling client).
pub trait ShellSession: Send {
    /// Write user keystrokes to the guest PTY.
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()>;
    /// Resize the guest PTY.
    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()>;
    /// Kill the shell process and tear the stream down.
    fn close(&mut self) -> anyhow::Result<()>;
}

/// Seam over izbad access so commands are unit-testable without a real daemon.
pub trait DaemonApi: Send {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>>;
    fn status(&mut self) -> anyhow::Result<DaemonStatusView>;
    /// The connected daemon's build metadata + wire-protocol version.
    fn version(&mut self) -> anyhow::Result<(BuildInfoOwned, u32)>;
    fn start(&mut self, name: &str) -> anyhow::Result<()>;
    fn stop(&mut self, name: &str) -> anyhow::Result<()>;
    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()>;
    /// Streams `Progress` messages via `on_progress`; returns the created name.
    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String>;
    /// Read the sandbox's captured console output (`logs/console.log`).
    /// Returns an empty string if the file does not exist yet.
    fn read_logs(&mut self, name: &str) -> anyhow::Result<String>;
    /// Open an interactive shell into `name`. `on_output` is invoked from a
    /// reader thread with raw PTY output; `on_exit` fires once when the shell
    /// exits or the stream closes. The returned handle drives stdin/resize/close.
    fn open_shell(
        &mut self,
        name: &str,
        on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>>;
}

/// Production `DaemonApi`: a lazily-connected `DaemonClient`. Connects via
/// `connect_spawning_izba` so a fresh install starts the sibling `izba daemon
/// run` (the app's own `current_exe` is `izba-app`, not a daemon). On any
/// send/recv error the connection is dropped so the next call reconnects (the
/// daemon idle-exits after ~5 min; polling keeps it warm but reconnect must be
/// cheap).
pub struct RealDaemon {
    paths: Paths,
    client: Option<DaemonClient>,
}

impl Default for RealDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl RealDaemon {
    pub fn new() -> Self {
        RealDaemon {
            paths: Paths::from_env_or_default(None),
            client: None,
        }
    }

    fn with_client<T>(
        &mut self,
        f: impl FnOnce(&mut DaemonClient) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if self.client.is_none() {
            self.client = Some(DaemonClient::connect_spawning_izba(&self.paths)?);
        }
        let client = self.client.as_mut().expect("just connected");
        match f(client) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.client = None; // force reconnect next call
                Err(e)
            }
        }
    }
}

impl DaemonApi for RealDaemon {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>> {
        self.with_client(|c| match c.request(&DaemonRequest::List, &mut |_| {})? {
            DaemonResponse::List { sandboxes } => {
                Ok(sandboxes.into_iter().map(SandboxView::from).collect())
            }
            DaemonResponse::Error { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected List reply: {other:?}"),
        })
    }

    fn status(&mut self) -> anyhow::Result<DaemonStatusView> {
        self.with_client(|c| match c.request(&DaemonRequest::Status, &mut |_| {})? {
            DaemonResponse::Status(s) => Ok(DaemonStatusView::from(s)),
            DaemonResponse::Error { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected Status reply: {other:?}"),
        })
    }

    fn version(&mut self) -> anyhow::Result<(BuildInfoOwned, u32)> {
        // The handshake already captured these; no extra round trip needed.
        self.with_client(|c| Ok((c.server_build.clone(), c.server_proto)))
    }

    fn start(&mut self, name: &str) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| expect_ok(c.request(&DaemonRequest::Start { name }, &mut |_| {})?))
    }

    fn stop(&mut self, name: &str) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| expect_ok(c.request(&DaemonRequest::Stop { name }, &mut |_| {})?))
    }

    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| expect_ok(c.request(&DaemonRequest::Rm { name, force }, &mut |_| {})?))
    }

    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String> {
        self.with_client(
            |c| match c.request(&DaemonRequest::Create(req), on_progress)? {
                DaemonResponse::Created { name } => Ok(name),
                DaemonResponse::Error { message } => anyhow::bail!("{message}"),
                other => anyhow::bail!("unexpected Create reply: {other:?}"),
            },
        )
    }

    fn read_logs(&mut self, name: &str) -> anyhow::Result<String> {
        let path = self.paths.logs_dir(name).join("console.log");
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    fn open_shell(
        &mut self,
        name: &str,
        mut on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>> {
        let mut control = DaemonClient::connect_spawning_izba(&self.paths)?;
        let exec_id = match control.guest_rpc(
            name,
            &Request::Exec(ExecRequest {
                argv: vec!["/bin/sh".to_string()],
                env: vec![("TERM".to_string(), "xterm-256color".to_string())],
                cwd: "/workspace".to_string(),
                tty: true,
                uid: 0,
                gid: 0,
            }),
        )? {
            Response::ExecStarted { exec_id } => exec_id,
            Response::Error { kind, message } => {
                anyhow::bail!("shell exec failed ({kind:?}): {message}")
            }
            other => anyhow::bail!("unexpected exec reply: {other:?}"),
        };
        let mut stream = DaemonClient::open_guest_stream(&self.paths, name)?;
        write_frame(
            &mut stream,
            &StreamOpen::Attach(StreamAttach {
                exec_id,
                kind: StreamKind::Tty,
            }),
        )?;
        let mut read_half = stream.try_clone()?;
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match read_half.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => on_output(buf[..n].to_vec()),
                }
            }
            on_exit();
        });
        Ok(Box::new(RealShell {
            write_half: stream,
            control,
            name: name.to_string(),
            exec_id,
            reader: Some(reader),
        }))
    }
}

/// Production `ShellSession`: a dedicated control connection (for resize/kill)
/// plus the bidirectional tty stream. A reader thread pumps guest output into
/// the `on_output` callback and fires `on_exit` on EOF.
struct RealShell {
    write_half: UdsStream,
    control: DaemonClient,
    name: String,
    exec_id: u32,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl ShellSession for RealShell {
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.write_half.write_all(data)?;
        self.write_half.flush()?;
        Ok(())
    }

    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()> {
        match self.control.guest_rpc(
            &self.name,
            &Request::Resize {
                exec_id: self.exec_id,
                cols,
                rows,
            },
        )? {
            Response::Ok => Ok(()),
            Response::Error { kind, message } => {
                anyhow::bail!("resize failed ({kind:?}): {message}")
            }
            other => anyhow::bail!("unexpected resize reply: {other:?}"),
        }
    }

    fn close(&mut self) -> anyhow::Result<()> {
        // Best-effort kill; the guest then closes the stream.
        let _ = self.control.guest_rpc(
            &self.name,
            &Request::Kill {
                exec_id: self.exec_id,
                signal: 15,
            },
        );
        // Unblock the reader thread (in case the kill RPC could not be sent).
        // shutdown(Both) is the load-bearing unblock: it forces the reader's
        // blocking read to return EOF so the join below is bounded. The Kill
        // above is best-effort (the shell may already be gone).
        let _ = self.write_half.shutdown(Shutdown::Both);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        Ok(())
    }
}

/// Map a one-shot daemon reply that should be `Ok` into `()`.
fn expect_ok(resp: DaemonResponse) -> anyhow::Result<()> {
    match resp {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}
