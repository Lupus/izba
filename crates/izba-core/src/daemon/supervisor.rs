//! The supervision tick: re-assess every sandbox from disk + pid identity
//! (the same `sandbox::list` the CLI used when daemonless — it also prunes
//! stale state.json and reaps orphaned sidecars), refresh the registry,
//! stop relays of stopped sandboxes, revive crashed relay threads.
//! VMs and sidecars are never auto-restarted (spec §1).

use std::time::Duration;

use crate::daemon::egress::EgressManager;
use crate::daemon::registry::Registry;
use crate::daemon::relays::RelayManager;
use crate::liveness::Liveness;
use crate::paths::Paths;
use crate::sandbox::{self, Connector};

pub fn tick(
    paths: &Paths,
    registry: &Registry,
    relays: &RelayManager,
    egress: &EgressManager,
    connector: Connector,
) {
    let infos = match sandbox::list(paths, connector) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("izbad: supervisor: list failed: {e:#}");
            return;
        }
    };
    for info in &infos {
        if info.liveness == Liveness::Stopped {
            relays.stop_all(&info.name);
            egress.stop(paths, &info.name);
        } else {
            relays.respawn_dead(paths, &info.name);
            // Idempotent: a no-op if the listener is alive, a crash-respawn
            // otherwise. Every running sandbox owns a vsock_1027 plane.
            let _ = egress.ensure_listening(paths, &info.name);
        }
    }
    registry.replace_all(infos);
}

pub fn tick_interval() -> Duration {
    interval_from(&|k| std::env::var(k).ok())
}

fn interval_from(env: &dyn Fn(&str) -> Option<String>) -> Duration {
    let ms = env("IZBA_DAEMON_TICK_MS")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::dns::UdpForwarder;
    use crate::daemon::egress::EgressManager;
    use crate::daemon::registry::Registry;
    use crate::daemon::relays::RelayManager;
    use crate::liveness::Liveness;
    use crate::sandbox::CreateOpts;
    use crate::testutil::{fake_connector, live_identity, test_paths, write_state};
    use std::sync::{Arc, Mutex};

    fn test_egress() -> EgressManager {
        use crate::daemon::egress::audit::AuditSink;
        EgressManager::new(
            Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
            None,
            AuditSink::new(crate::paths::Paths::with_root(
                std::env::temp_dir().join("izba-supervisor-audit-test"),
            )),
        )
    }

    #[test]
    fn tick_reflects_disk_state() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let opts = CreateOpts {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: ws,
            rw_size_gb: 1,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
        };
        crate::sandbox::create(&paths, "up", &opts).unwrap();
        crate::sandbox::create(&paths, "down", &opts).unwrap();
        write_state(&paths, "up", live_identity()); // "up" looks alive

        let registry = Registry::new();
        let relays = RelayManager::new();
        let egress = test_egress();
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        tick(&paths, &registry, &relays, &egress, &conn);

        assert_eq!(registry.liveness("up"), Some(Liveness::Running));
        assert_eq!(registry.liveness("down"), Some(Liveness::Stopped));
    }

    #[test]
    fn interval_env_parsing() {
        let default = |_: &str| None;
        assert_eq!(
            interval_from(&default),
            std::time::Duration::from_millis(2000)
        );
        let fast = |k: &str| (k == "IZBA_DAEMON_TICK_MS").then(|| "50".to_string());
        assert_eq!(interval_from(&fast), std::time::Duration::from_millis(50));
        let junk = |k: &str| (k == "IZBA_DAEMON_TICK_MS").then(|| "nope".to_string());
        assert_eq!(interval_from(&junk), std::time::Duration::from_millis(2000));
    }
}
