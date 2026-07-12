//! The supervision tick: re-assess every sandbox from disk + pid identity
//! (the same `sandbox::list` the CLI used when daemonless — it also prunes
//! stale state.json and reaps orphaned sidecars), refresh the registry,
//! stop relays of stopped sandboxes (except one with a `Start` in flight —
//! see [`StartsInFlight`]), revive crashed relay threads.
//! VMs and sidecars are never auto-restarted (spec §1).

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use crate::daemon::egress::EgressManager;
use crate::daemon::registry::Registry;
use crate::daemon::relays::RelayManager;
use crate::liveness::Liveness;
use crate::paths::Paths;
use crate::sandbox::{self, Connector};

/// Sandbox names with a `Start` in flight. `handle_start` holds a guard for
/// the whole listener-bind → boot → relay-republish window; the supervisor
/// tick leaves those sandboxes' relays/egress alone even though the disk
/// scan honestly reports them Stopped until state.json lands post-boot
/// (#134: without this, a tick landing mid-boot tore down the egress
/// listener the guest was mid-dial against).
#[derive(Default)]
pub struct StartsInFlight(Mutex<HashSet<String>>);

impl StartsInFlight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `name` in flight; the returned guard un-marks on drop.
    pub fn begin(&self, name: &str) -> StartGuard<'_> {
        self.0.lock().unwrap().insert(name.to_string());
        StartGuard {
            set: self,
            name: name.to_string(),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.lock().unwrap().contains(name)
    }
}

/// RAII un-mark: drops `name` out of its [`StartsInFlight`] set, on both the
/// success and error return paths of the handler that started it.
pub struct StartGuard<'a> {
    set: &'a StartsInFlight,
    name: String,
}

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.set.0.lock().unwrap().remove(&self.name);
    }
}

pub fn tick(
    paths: &Paths,
    registry: &Registry,
    relays: &RelayManager,
    egress: &EgressManager,
    connector: Connector,
    starting: &StartsInFlight,
) {
    // Snapshot BEFORE the disk scan: a handler write landing while the scan
    // is in flight must survive the coming `replace_all` (see its doc).
    let snap = registry.snapshot();
    let infos = match sandbox::list(paths, connector) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("izbad: supervisor: list failed: {e:#}");
            return;
        }
    };
    for info in &infos {
        if info.liveness == Liveness::Stopped {
            if starting.contains(&info.name) {
                // A Start is mid-boot: the disk scan honestly reports
                // Stopped until state.json lands post-boot, but this tick
                // must not tear down the listener/relays the guest is
                // dialing against right now (#134). `handle_start`'s guard
                // drops when it returns; the next tick reassesses then.
                continue;
            }
            relays.stop_all(&info.name);
            egress.stop(paths, &info.name);
        } else {
            relays.respawn_dead(paths, &info.name);
            // Idempotent: a no-op if the listener is alive, a crash-respawn
            // otherwise. Every running sandbox owns a vsock_1027 plane.
            let _ = egress.ensure_listening(paths, &info.name);
        }
    }
    registry.replace_all(snap, infos);
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
    use crate::state::PortRule;
    use crate::testutil::{fake_connector, live_identity, test_paths, write_state};
    use std::sync::{Arc, Mutex};

    /// `ensure_listening`/`publish` both bind real sockets — runtime-skip
    /// where the sandbox denies bind (house pattern, see
    /// `vsock.rs::full_connect_via_listener`).
    fn is_permission_denied(e: &anyhow::Error) -> bool {
        e.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
        })
    }

    /// Pick a free TCP port by binding to :0 and dropping the socket.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    }

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
        let starting = StartsInFlight::new();
        tick(&paths, &registry, &relays, &egress, &conn, &starting);

        assert_eq!(registry.liveness("up"), Some(Liveness::Running));
        assert_eq!(registry.liveness("down"), Some(Liveness::Stopped));
    }

    /// #134: a `Start` mid-boot has no state.json yet, so the disk scan
    /// honestly reports the sandbox Stopped. Without the starts-in-flight
    /// guard the tick would tear its egress listener and relays down while
    /// the guest is mid-boot-dial against them.
    #[test]
    fn tick_spares_egress_and_relays_of_starting_sandbox() {
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
        crate::sandbox::create(&paths, "boot", &opts).unwrap();
        // No state.json written: disk says Stopped, exactly the mid-boot
        // snapshot the guard exists for.

        let egress = test_egress();
        match egress.ensure_listening(&paths, "boot") {
            Ok(()) => {}
            Err(e) if is_permission_denied(&e) => {
                eprintln!(
                    "SKIP tick_spares_egress_and_relays_of_starting_sandbox: bind denied: {e:#}"
                );
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        let relays = RelayManager::new();
        let rule = PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: free_port(),
            guest_port: 80,
        };
        if let Err(e) = relays.publish(&paths, "boot", rule) {
            if is_permission_denied(&e) {
                eprintln!(
                    "SKIP tick_spares_egress_and_relays_of_starting_sandbox: publish denied: {e:#}"
                );
                return;
            }
            panic!("publish: {e:#}");
        }

        let registry = Registry::new();
        let starting = StartsInFlight::new();
        let _g = starting.begin("boot");
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        tick(&paths, &registry, &relays, &egress, &conn, &starting);

        assert!(
            egress.listening("boot"),
            "guard spares the mid-boot egress listener"
        );
        assert!(
            !relays.active("boot").is_empty(),
            "guard spares the mid-boot relays"
        );
    }

    /// Negative control for the above: same setup, but no guard is held —
    /// the tick must still tear a genuinely-stopped sandbox's egress/relays
    /// down. Kills the condition-negation mutant on the guard check.
    #[test]
    fn tick_stops_egress_and_relays_of_genuinely_stopped_sandbox() {
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
        crate::sandbox::create(&paths, "boot", &opts).unwrap();

        let egress = test_egress();
        match egress.ensure_listening(&paths, "boot") {
            Ok(()) => {}
            Err(e) if is_permission_denied(&e) => {
                eprintln!(
                    "SKIP tick_stops_egress_and_relays_of_genuinely_stopped_sandbox: bind denied: {e:#}"
                );
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        let relays = RelayManager::new();
        let rule = PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: free_port(),
            guest_port: 80,
        };
        if let Err(e) = relays.publish(&paths, "boot", rule) {
            if is_permission_denied(&e) {
                eprintln!(
                    "SKIP tick_stops_egress_and_relays_of_genuinely_stopped_sandbox: publish denied: {e:#}"
                );
                return;
            }
            panic!("publish: {e:#}");
        }

        let registry = Registry::new();
        let starting = StartsInFlight::new(); // nothing marked in flight
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        tick(&paths, &registry, &relays, &egress, &conn, &starting);

        assert!(
            !egress.listening("boot"),
            "unmarked stopped sandbox loses its egress listener"
        );
        assert!(
            relays.active("boot").is_empty(),
            "unmarked stopped sandbox loses its relays"
        );
    }

    #[test]
    fn start_guard_unmarks_on_drop() {
        let starting = StartsInFlight::new();
        assert!(!starting.contains("a"));
        {
            let _g = starting.begin("a");
            assert!(starting.contains("a"));
            assert!(!starting.contains("b"), "unrelated name unaffected");
        }
        assert!(!starting.contains("a"), "un-marked on drop");

        // Two concurrent guards on different names don't interfere.
        let g1 = starting.begin("a");
        let g2 = starting.begin("b");
        assert!(starting.contains("a"));
        assert!(starting.contains("b"));
        drop(g1);
        assert!(!starting.contains("a"), "dropping g1 only un-marks 'a'");
        assert!(starting.contains("b"), "'b' still held by g2");
        drop(g2);
        assert!(!starting.contains("b"));
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
