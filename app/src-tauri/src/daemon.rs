use crate::views::{DaemonStatusView, SandboxView};
use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::proto::{DaemonCreate, DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

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
}

/// Map a one-shot daemon reply that should be `Ok` into `()`.
fn expect_ok(resp: DaemonResponse) -> anyhow::Result<()> {
    match resp {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}
