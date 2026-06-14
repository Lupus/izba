use crate::views::{DaemonStatusView, SandboxView};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

/// Seam over izbad access so commands are unit-testable without a real daemon.
pub trait DaemonApi: Send {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>>;
    fn status(&mut self) -> anyhow::Result<DaemonStatusView>;
}

/// Production `DaemonApi`: a lazily-connected `DaemonClient`. On any send/recv
/// error the connection is dropped so the next call reconnects (the daemon
/// idle-exits after ~5 min; polling keeps it warm but reconnect must be cheap).
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
            self.client = Some(DaemonClient::connect(&self.paths)?);
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
}
