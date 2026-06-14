#![cfg(test)]
use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView, SbxState};
use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::proto::DaemonCreate;

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
    pub fail_action: bool,
    pub calls: Vec<String>,
    pub progress: Vec<String>,
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
            fail_action: false,
            calls: Vec::new(),
            progress: vec!["pulling image".into(), "booting".into()],
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
    fn start(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("start:{name}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn stop(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("stop:{name}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()> {
        self.calls.push(format!("rm:{name}:{force}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        for m in &self.progress {
            on_progress(m);
        }
        self.calls.push(format!("create:{}", req.name));
        Ok(req.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_create() -> DaemonCreate {
        DaemonCreate {
            name: "new".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: std::path::PathBuf::from("/ws"),
            rw_size_gb: 4,
            ports: vec![],
        }
    }

    #[test]
    fn fake_records_lifecycle_calls() {
        let mut d = FakeDaemon::default();
        d.start("web").unwrap();
        d.stop("web").unwrap();
        d.remove("web", true).unwrap();
        assert_eq!(d.calls, vec!["start:web", "stop:web", "rm:web:true"]);
    }

    #[test]
    fn fake_create_streams_progress_and_returns_name() {
        let mut d = FakeDaemon::default();
        let mut seen = Vec::new();
        let name = d
            .create(sample_create(), &mut |m| seen.push(m.to_string()))
            .unwrap();
        assert_eq!(name, "new");
        assert_eq!(seen, vec!["pulling image", "booting"]);
        assert_eq!(d.calls, vec!["create:new"]);
    }

    #[test]
    fn fake_action_failure_is_surfaced() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        assert!(d.start("web").is_err());
    }
}
