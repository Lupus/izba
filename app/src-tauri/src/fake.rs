#![cfg(test)]
use crate::daemon::{DaemonApi, ShellSession};
use crate::views::{DaemonStatusView, SandboxView, SbxState};
use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::proto::DaemonCreate;
use std::sync::{Arc, Mutex};

/// Scripted `ShellSession` for unit tests. Records writes/resizes/close and
/// echoes every write back through `on_output`, so the output-event wiring is
/// observable without a real PTY.
pub struct FakeShell {
    pub writes: Arc<Mutex<Vec<Vec<u8>>>>,
    pub resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    pub closed: Arc<Mutex<bool>>,
    on_output: Box<dyn FnMut(Vec<u8>) + Send>,
}

impl ShellSession for FakeShell {
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.writes.lock().unwrap().push(data.to_vec());
        (self.on_output)(data.to_vec());
        Ok(())
    }
    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()> {
        self.resizes.lock().unwrap().push((cols, rows));
        Ok(())
    }
    fn close(&mut self) -> anyhow::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

/// Scripted `DaemonApi` for unit tests — no socket, no daemon.
pub struct FakeDaemon {
    pub sandboxes: Vec<SandboxView>,
    pub status: DaemonStatusView,
    pub fail_list: bool,
    pub fail_status: bool,
    /// Short sha the fake daemon reports (lets a test force an app↔daemon diff).
    pub daemon_sha: String,
    /// `git describe` the fake daemon reports. The mismatch check compares this
    /// against the app's describe, so a test sets it to the app's own describe
    /// to model an identical build, or to anything else to model a different one.
    pub daemon_describe: String,
    /// When true, `version()` errors as if no daemon were reachable.
    pub daemon_absent: bool,
    pub fail_action: bool,
    pub calls: Vec<String>,
    pub progress: Vec<String>,
    /// Canned console output returned by `read_logs`.
    pub logs: String,
    pub shell_writes: Arc<Mutex<Vec<Vec<u8>>>>,
    pub shell_resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    pub shell_closed: Arc<Mutex<bool>>,
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
            daemon_describe: "v0.0.0-fake-gfeedface".into(),
            daemon_absent: false,
            fail_action: false,
            calls: Vec::new(),
            progress: vec!["pulling image".into(), "booting".into()],
            logs: "boot ok\nlogin:\n".into(),
            shell_writes: Arc::new(Mutex::new(Vec::new())),
            shell_resizes: Arc::new(Mutex::new(Vec::new())),
            shell_closed: Arc::new(Mutex::new(false)),
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
            git_describe: self.daemon_describe.clone(),
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
    fn read_logs(&mut self, _name: &str) -> anyhow::Result<String> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(self.logs.clone())
    }
    fn open_shell(
        &mut self,
        _name: &str,
        mut on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        _on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        on_output(b"$ ".to_vec()); // canned prompt banner
        Ok(Box::new(FakeShell {
            writes: self.shell_writes.clone(),
            resizes: self.shell_resizes.clone(),
            closed: self.shell_closed.clone(),
            on_output,
        }))
    }
    fn read_netlog(
        &mut self,
        _name: &str,
    ) -> anyhow::Result<Vec<izba_core::daemon::egress::audit::EndpointSummary>> {
        use izba_core::daemon::egress::audit::{aggregate, AuditRecord, Tier};
        let mut r = AuditRecord::allow(
            "web",
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.x.com"),
            Tier::L7,
            "ok",
        );
        r.ts_ms = 1;
        Ok(aggregate(vec![r]))
    }
    fn policy_show(&mut self, _name: &str) -> anyhow::Result<crate::views::PolicyView> {
        Ok(crate::views::PolicyView {
            enforcing: false,
            allow: vec![],
        })
    }
    fn policy_allow(&mut self, name: &str, host: &str, port: u16) -> anyhow::Result<()> {
        self.calls.push(format!("allow:{name}:{host}:{port}"));
        Ok(())
    }
    fn policy_block(&mut self, name: &str, host: &str, port: u16) -> anyhow::Result<()> {
        self.calls.push(format!("block:{name}:{host}:{port}"));
        Ok(())
    }
    fn policy_set(
        &mut self,
        name: &str,
        allow: Vec<izba_core::daemon::egress::config::AllowEntry>,
    ) -> anyhow::Result<()> {
        self.calls.push(format!("set:{name}:{}", allow.len()));
        Ok(())
    }
    fn policy_enable_from_traffic(&mut self, name: &str) -> anyhow::Result<usize> {
        self.calls.push(format!("enable:{name}"));
        Ok(1)
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
            volumes: vec![],
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

    #[test]
    fn fake_read_logs_returns_canned_text() {
        let mut d = FakeDaemon::default();
        let logs = d.read_logs("web").unwrap();
        assert!(logs.contains("boot"), "got: {logs}");
    }

    #[test]
    fn fake_shell_echoes_and_records() {
        let mut d = FakeDaemon::default();
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let out2 = out.clone();
        let mut s = d
            .open_shell(
                "web",
                Box::new(move |b| out2.lock().unwrap().extend_from_slice(&b)),
                Box::new(|| {}),
            )
            .unwrap();
        s.write(b"ls\n").unwrap();
        s.resize(100, 40).unwrap();
        s.close().unwrap();
        assert_eq!(&d.shell_writes.lock().unwrap()[..], &[b"ls\n".to_vec()]);
        assert_eq!(d.shell_resizes.lock().unwrap()[0], (100, 40));
        assert!(*d.shell_closed.lock().unwrap());
        assert_eq!(&*out.lock().unwrap(), b"$ ls\n"); // banner + echo
    }

    #[test]
    fn fake_open_shell_surfaces_failure() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        let r = d.open_shell("web", Box::new(|_| {}), Box::new(|| {}));
        assert!(r.is_err());
    }
}
