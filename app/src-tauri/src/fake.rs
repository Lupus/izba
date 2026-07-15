#![cfg(test)]
use crate::daemon::{DaemonApi, ShellSession};
use crate::views::{DaemonStatusView, SandboxView, SbxState};
use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::egress::config::EgressPolicyConfig;
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
    /// In-memory policy state for testing git rules and enforce toggle.
    pub policy: EgressPolicyConfig,
    /// Active port-publish rules echoed by `port_list` / mutated by publish/unpublish.
    pub ports: Vec<izba_core::state::PortRule>,
    /// Persistent volume infos echoed by `volume_list`.
    pub volumes: Vec<izba_core::volume::VolumeInfo>,
    /// Volume specs echoed inside `inspect`'s detail response.
    pub detail_volumes: Vec<izba_core::volume::VolumeSpec>,
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
            logs: "boot ok\nlogin:\n".into(),
            shell_writes: Arc::new(Mutex::new(Vec::new())),
            shell_resizes: Arc::new(Mutex::new(Vec::new())),
            shell_closed: Arc::new(Mutex::new(false)),
            policy: EgressPolicyConfig::default(),
            ports: vec![],
            volumes: vec![izba_core::volume::VolumeInfo {
                name: "cache".into(),
                size_bytes: 1 << 30,
                actual_bytes: 1 << 20,
                referenced_by: vec!["web".into()],
            }],
            detail_volumes: vec![],
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
            enforcing: self.policy.enforce,
            allow: self.policy.allow.clone(),
            git: self.policy.git.clone(),
        })
    }
    fn policy_allow(&mut self, name: &str, host: &str, port: u16) -> anyhow::Result<()> {
        self.calls.push(format!("allow:{name}:{host}:{port}"));
        // Mirror the real daemon so a follow-up policy_show observes the grant.
        self.policy.allow(host, port);
        Ok(())
    }
    fn policy_block(&mut self, name: &str, host: &str, port: u16) -> anyhow::Result<()> {
        self.calls.push(format!("block:{name}:{host}:{port}"));
        // Mirror the real daemon so a follow-up policy_show observes the removal.
        self.policy.block(host, port);
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
    fn policy_add_endpoints(
        &mut self,
        name: &str,
        entries: Vec<crate::views::SeedEntry>,
        enforce: bool,
    ) -> anyhow::Result<()> {
        use crate::views::SeedEntry;
        use izba_core::daemon::egress::config::GitTarget;
        self.calls
            .push(format!("add_endpoints:{name}:{}", entries.len()));
        for e in entries {
            match e {
                SeedEntry::Http { host, port, access } => {
                    self.policy.allow(&host, port);
                    self.policy.set_host_access(&host, access);
                }
                SeedEntry::Git { target, access } => {
                    self.policy.git_allow(GitTarget::parse(&target), access);
                }
            }
        }
        if enforce {
            self.policy.set_enforce(true);
        }
        Ok(())
    }
    fn policy_set_full(
        &mut self,
        name: &str,
        allow: Vec<izba_core::daemon::egress::config::AllowEntry>,
        git: Vec<izba_core::daemon::egress::config::GitRule>,
    ) -> anyhow::Result<()> {
        self.calls.push(format!("set_full:{name}"));
        self.policy.allow = allow;
        self.policy.git = git;
        Ok(())
    }
    fn policy_git_allow(&mut self, name: &str, target: &str, write: bool) -> anyhow::Result<()> {
        use izba_core::daemon::egress::config::{Access, GitTarget};
        self.calls
            .push(format!("git_allow:{name}:{target}:{write}"));
        let gt = GitTarget::parse(target);
        let access = if write {
            Access::ReadWrite
        } else {
            Access::Read
        };
        self.policy.git_allow(gt, access);
        Ok(())
    }
    fn policy_git_block(&mut self, name: &str, target: &str) -> anyhow::Result<()> {
        use izba_core::daemon::egress::config::GitTarget;
        self.calls.push(format!("git_block:{name}:{target}"));
        let gt = GitTarget::parse(target);
        self.policy.git_block(&gt);
        Ok(())
    }
    fn policy_set_enforce(&mut self, name: &str, on: bool) -> anyhow::Result<()> {
        self.calls.push(format!("set_enforce:{name}:{on}"));
        self.policy.set_enforce(on);
        Ok(())
    }

    fn inspect(&mut self, name: &str) -> anyhow::Result<izba_core::daemon::proto::SandboxDetail> {
        Ok(izba_core::daemon::proto::SandboxDetail {
            name: name.to_string(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:x".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: self.ports.clone(),
            volumes: self.detail_volumes.clone(),
            confinement: None,
            container: None,
            user_fallback: None,
        })
    }

    fn port_list(&mut self, _name: &str) -> anyhow::Result<Vec<izba_core::state::PortRule>> {
        Ok(self.ports.clone())
    }

    fn port_publish(
        &mut self,
        name: &str,
        rule: izba_core::state::PortRule,
        persist: bool,
    ) -> anyhow::Result<()> {
        self.calls.push(format!(
            "publish:{name}:{}:{}:{persist}",
            rule.host_port, rule.guest_port
        ));
        self.ports.push(rule);
        Ok(())
    }

    fn port_unpublish(
        &mut self,
        name: &str,
        bind: std::net::Ipv4Addr,
        host_port: u16,
    ) -> anyhow::Result<()> {
        self.calls
            .push(format!("unpublish:{name}:{bind}:{host_port}"));
        self.ports
            .retain(|r| !(r.bind == bind && r.host_port == host_port));
        Ok(())
    }

    fn volume_list(&mut self) -> anyhow::Result<Vec<izba_core::volume::VolumeInfo>> {
        Ok(self.volumes.clone())
    }

    fn volume_remove(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("vrm:{name}"));
        Ok(())
    }

    fn volume_prune(&mut self) -> anyhow::Result<izba_core::volume::Pruned> {
        self.calls.push("vprune".into());
        Ok(izba_core::volume::Pruned {
            removed: vec!["old".into()],
            reclaimed_bytes: 1024,
        })
    }

    fn volume_attach(
        &mut self,
        name: &str,
        spec: izba_core::volume::VolumeSpec,
    ) -> anyhow::Result<()> {
        self.calls
            .push(format!("vattach:{name}:{}", spec.guest_path.display()));
        // Mirror the real daemon so a follow-up inspect observes the volume.
        self.detail_volumes.push(spec);
        Ok(())
    }

    fn volume_detach(&mut self, name: &str, guest_path: String) -> anyhow::Result<()> {
        self.calls.push(format!("vdetach:{name}:{guest_path}"));
        self.detail_volumes
            .retain(|s| s.guest_path != std::path::Path::new(&guest_path));
        Ok(())
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
            allow_unconfined: false,
            builder: false,
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

    #[test]
    fn fake_policy_git_allow_then_show() {
        let mut d = FakeDaemon::default();
        d.policy_set_enforce("web", true).unwrap();
        d.policy_git_allow("web", "github.com/o/a", true).unwrap();
        let view = d.policy_show("web").unwrap();
        assert!(view.enforcing);
        assert_eq!(view.git.len(), 1);
    }

    #[test]
    fn policy_add_endpoints_is_additive_and_optionally_enforces() {
        use crate::views::SeedEntry;
        use izba_core::daemon::egress::config::{Access, AllowEntry, GitRule, GitTarget};
        let mut d = FakeDaemon::default();
        // seed an existing policy with a host + a git rule, enforce off
        d.policy_set_full(
            "web",
            vec![AllowEntry::Host("existing.com".into())],
            vec![GitRule {
                target: GitTarget::Repo("github.com/o/a".into()),
                access: Access::Read,
            }],
        )
        .unwrap();
        d.policy_add_endpoints(
            "web",
            vec![SeedEntry::Http {
                host: "pypi.org".into(),
                port: 443,
                access: Access::Read,
            }],
            true,
        )
        .unwrap();
        let v = d.policy_show("web").unwrap();
        assert!(v.enforcing, "enforce flipped on");
        assert!(
            v.allow.iter().any(|e| e.host() == "existing.com"),
            "existing host kept"
        );
        assert!(
            v.allow.iter().any(|e| e.host() == "pypi.org"),
            "added host present"
        );
        assert_eq!(v.git.len(), 1, "git rule survives the add");
    }
}
