#![cfg(test)]
use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView, SbxState};

/// Scripted `DaemonApi` for unit tests — no socket, no daemon.
pub struct FakeDaemon {
    pub sandboxes: Vec<SandboxView>,
    pub status: DaemonStatusView,
    pub fail_list: bool,
}

impl Default for FakeDaemon {
    fn default() -> Self {
        FakeDaemon {
            sandboxes: vec![
                SandboxView { name: "web".into(), image: "ubuntu:24.04".into(), state: SbxState::Running },
                SandboxView { name: "db".into(), image: "postgres:16".into(), state: SbxState::Stopped },
            ],
            status: DaemonStatusView { version: "0.3.1".into(), pid: 4242, uptime_ms: 1000, sandbox_count: 2 },
            fail_list: false,
        }
    }
}

impl DaemonApi for FakeDaemon {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>> {
        if self.fail_list { anyhow::bail!("daemon unreachable"); }
        Ok(self.sandboxes.clone())
    }
    fn status(&mut self) -> anyhow::Result<DaemonStatusView> {
        Ok(self.status.clone())
    }
}
