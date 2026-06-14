#![cfg(test)]
use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView, SbxState};
use izba_core::build_info::BuildInfoOwned;

/// Scripted `DaemonApi` for unit tests — no socket, no daemon.
pub struct FakeDaemon {
    pub sandboxes: Vec<SandboxView>,
    pub status: DaemonStatusView,
    pub fail_list: bool,
    pub fail_status: bool,
    /// Short sha the fake daemon reports (lets a test force an app↔daemon diff).
    pub daemon_sha: String,
    /// When true, `version()` errors as if no daemon were reachable.
    pub daemon_absent: bool,
}

impl Default for FakeDaemon {
    fn default() -> Self {
        FakeDaemon {
            sandboxes: vec![
                SandboxView {
                    name: "web".into(),
                    image: "ubuntu:24.04".into(),
                    state: SbxState::Running,
                },
                SandboxView {
                    name: "db".into(),
                    image: "postgres:16".into(),
                    state: SbxState::Stopped,
                },
            ],
            status: DaemonStatusView {
                version: "0.3.1".into(),
                pid: 4242,
                uptime_ms: 1000,
                sandbox_count: 2,
            },
            fail_list: false,
            fail_status: false,
            daemon_sha: "feedface".into(),
            daemon_absent: false,
        }
    }
}

impl DaemonApi for FakeDaemon {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>> {
        if self.fail_list {
            anyhow::bail!("daemon unreachable");
        }
        Ok(self.sandboxes.clone())
    }
    fn status(&mut self) -> anyhow::Result<DaemonStatusView> {
        if self.fail_status {
            anyhow::bail!("daemon unreachable");
        }
        Ok(self.status.clone())
    }
    fn version(&mut self) -> anyhow::Result<(BuildInfoOwned, u32)> {
        if self.daemon_absent {
            anyhow::bail!("daemon unreachable");
        }
        let build = BuildInfoOwned {
            git_sha: self.daemon_sha.clone(),
            ..BuildInfoOwned::default()
        };
        Ok((build, 1))
    }
}
