//! In-daemon port relays: one thread per published rule, owned by the
//! daemon's `RelayManager`. Replaces the pre-daemon detached
//! `izba __port-relay` processes (binding happens in the caller, so
//! port-in-use errors are synchronous — no preflight TOCTOU).
//!
//! Persistence: `ports.json` stores the ACTIVE rules as `Vec<PortRule>`.
//! The legacy schema (`Vec<PortRecord>` incl. relay pids) is migrated at
//! adoption: rules extracted, orphaned relay processes killed by the caller.

use anyhow::{bail, Context};
use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::paths::Paths;
use crate::portfwd;
use crate::state::{save_json, PidIdentity, PortRecord, PortRule, PORTS_FILE};

pub fn rules_path(paths: &Paths, name: &str) -> PathBuf {
    paths.sandbox_dir(name).join(PORTS_FILE)
}

pub fn save_rules(paths: &Paths, name: &str, rules: &[PortRule]) -> anyhow::Result<()> {
    save_json(&rules_path(paths, name), &rules.to_vec())
}

/// Load active rules; understands both schemas. Returns
/// `(rules, legacy_relay_pids)` — the caller kills the legacy pids (one-time
/// migration from the pre-daemon process-per-relay model).
pub fn load_rules_migrating(
    paths: &Paths,
    name: &str,
) -> anyhow::Result<(Vec<PortRule>, Vec<PidIdentity>)> {
    let path = rules_path(paths, name);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(e).with_context(|| format!("read {path:?}")),
    };
    if let Ok(rules) = serde_json::from_str::<Vec<PortRule>>(&raw) {
        return Ok((rules, Vec::new()));
    }
    let legacy: Vec<PortRecord> = serde_json::from_str(&raw)
        .with_context(|| format!("{path:?} matches neither ports.json schema"))?;
    let rules = legacy.iter().map(|r| r.rule.clone()).collect();
    let pids = legacy.into_iter().map(|r| r.relay).collect();
    Ok((rules, pids))
}

struct RelaySlot {
    rule: PortRule,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// All relay threads, keyed by sandbox name. Thread-safe; the daemon holds
/// one instance for its lifetime.
#[derive(Default)]
pub struct RelayManager {
    inner: Mutex<HashMap<String, Vec<RelaySlot>>>,
}

impl RelayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `(rule.bind, rule.host_port)` and start the relay thread.
    /// Synchronous error on duplicate key or bind failure.
    pub fn publish(&self, paths: &Paths, name: &str, rule: PortRule) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let slots = inner.entry(name.to_string()).or_default();
        if slots
            .iter()
            .any(|s| s.rule.bind == rule.bind && s.rule.host_port == rule.host_port)
        {
            bail!("port already published: {}:{}", rule.bind, rule.host_port);
        }
        slots.push(spawn_slot(paths, name, rule)?);
        Ok(())
    }

    pub fn unpublish(&self, name: &str, bind: Ipv4Addr, host_port: u16) -> anyhow::Result<()> {
        let slot = {
            let mut inner = self.inner.lock().unwrap();
            let Some(slots) = inner.get_mut(name) else {
                bail!("no such published port: {bind}:{host_port}");
            };
            let Some(idx) = slots
                .iter()
                .position(|s| s.rule.bind == bind && s.rule.host_port == host_port)
            else {
                bail!("no such published port: {bind}:{host_port}");
            };
            slots.remove(idx)
        }; // lock released before the (≤100 ms) join
        slot.stop.store(true, Ordering::SeqCst);
        let _ = slot.thread.join();
        Ok(())
    }

    /// The active rules for `name` (configured set; the supervisor revives
    /// crashed threads, so this is also the effective set within one tick).
    pub fn active(&self, name: &str) -> Vec<PortRule> {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|slots| slots.iter().map(|s| s.rule.clone()).collect())
            .unwrap_or_default()
    }

    /// Stop and join every relay of `name` (sandbox stop/rm, daemon exit).
    pub fn stop_all(&self, name: &str) {
        let slots = self.inner.lock().unwrap().remove(name).unwrap_or_default();
        for slot in &slots {
            slot.stop.store(true, Ordering::SeqCst);
        }
        for slot in slots {
            let _ = slot.thread.join();
        }
    }

    /// Supervisor tick: re-spawn slots whose thread exited without being
    /// asked to stop (listener error / panic). Failed rebinds stay in place
    /// and are retried next tick.
    pub fn respawn_dead(&self, paths: &Paths, name: &str) {
        let mut inner = self.inner.lock().unwrap();
        let Some(slots) = inner.get_mut(name) else {
            return;
        };
        for slot in slots.iter_mut() {
            if slot.thread.is_finished() && !slot.stop.load(Ordering::SeqCst) {
                match spawn_slot(paths, name, slot.rule.clone()) {
                    Ok(fresh) => {
                        eprintln!(
                            "izbad: respawned relay {}:{} for '{name}'",
                            slot.rule.bind, slot.rule.host_port
                        );
                        *slot = fresh;
                    }
                    Err(e) => eprintln!(
                        "izbad: relay {}:{} for '{name}' is down and rebind failed: {e:#}",
                        slot.rule.bind, slot.rule.host_port
                    ),
                }
            }
        }
    }

    /// Test hook: a slot whose thread is already finished (simulated crash).
    #[cfg(test)]
    fn insert_for_test(&self, name: &str, rule: PortRule) {
        let thread = std::thread::spawn(|| {});
        while !thread.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.inner
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(RelaySlot {
                rule,
                stop: Arc::new(AtomicBool::new(false)),
                thread,
            });
    }
}

fn spawn_slot(paths: &Paths, name: &str, rule: PortRule) -> anyhow::Result<RelaySlot> {
    let listener = TcpListener::bind((rule.bind, rule.host_port))
        .with_context(|| format!("host port {}:{} is unavailable", rule.bind, rule.host_port))?;
    let stop = Arc::new(AtomicBool::new(false));
    let vsock = paths.run_dir(name).join("vsock.sock");
    let stop2 = Arc::clone(&stop);
    let rule2 = rule.clone();
    let thread = std::thread::spawn(move || {
        if let Err(e) = portfwd::run_relay_listener(listener, &vsock, rule2.guest_port, &stop2) {
            eprintln!(
                "izbad: relay {}:{} exited: {e:#}",
                rule2.bind, rule2.host_port
            );
        }
    });
    Ok(RelaySlot { rule, stop, thread })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use crate::state::{save_json, PidIdentity, PortRecord, PortRule};

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        std::fs::create_dir_all(paths.run_dir("web")).unwrap();
        (dir, paths)
    }

    fn rule(host_port: u16) -> PortRule {
        PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port,
            guest_port: 80,
        }
    }

    #[test]
    fn load_rules_missing_file_is_empty() {
        let (_d, paths) = test_paths();
        let (rules, legacy) = load_rules_migrating(&paths, "web").unwrap();
        assert!(rules.is_empty() && legacy.is_empty());
    }

    #[test]
    fn load_rules_new_schema() {
        let (_d, paths) = test_paths();
        save_rules(&paths, "web", &[rule(8080)]).unwrap();
        let (rules, legacy) = load_rules_migrating(&paths, "web").unwrap();
        assert_eq!(rules, vec![rule(8080)]);
        assert!(legacy.is_empty());
    }

    #[test]
    fn load_rules_migrates_legacy_schema() {
        let (_d, paths) = test_paths();
        let legacy_records = vec![PortRecord {
            rule: rule(8080),
            relay: PidIdentity {
                pid: 4321,
                starttime: 777,
            },
        }];
        save_json(&rules_path(&paths, "web"), &legacy_records).unwrap();
        let (rules, legacy) = load_rules_migrating(&paths, "web").unwrap();
        assert_eq!(rules, vec![rule(8080)]);
        assert_eq!(
            legacy,
            vec![PidIdentity {
                pid: 4321,
                starttime: 777
            }]
        );
    }

    /// Binds real listeners — runtime-skip where denied.
    fn bind_works() -> bool {
        match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: TcpListener::bind denied in this environment");
                false
            }
            Err(e) => panic!("bind probe: {e}"),
        }
    }

    /// Pick a free port by binding to :0 and dropping the socket.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    }

    #[test]
    fn publish_active_unpublish_lifecycle() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let r = rule(free_port());
        mgr.publish(&paths, "web", r.clone()).unwrap();
        assert_eq!(mgr.active("web"), vec![r.clone()]);

        // Duplicate (bind, host_port) key is rejected.
        let err = mgr.publish(&paths, "web", r.clone()).unwrap_err();
        assert!(err.to_string().contains("already published"), "{err:#}");

        // The port is actually bound (second bind fails).
        assert!(std::net::TcpListener::bind((r.bind, r.host_port)).is_err());

        mgr.unpublish("web", r.bind, r.host_port).unwrap();
        assert!(mgr.active("web").is_empty());
        // Unpublish released the port (relay thread exited).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if std::net::TcpListener::bind((r.bind, r.host_port)).is_ok() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "port not released");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let err = mgr.unpublish("web", r.bind, r.host_port).unwrap_err();
        assert!(
            err.to_string().contains("no such published port"),
            "{err:#}"
        );
    }

    #[test]
    fn bind_conflict_is_synchronous_error() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let blocker = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = blocker.local_addr().unwrap().port();
        let mgr = RelayManager::new();
        let err = mgr.publish(&paths, "web", rule(port)).unwrap_err();
        assert!(err.to_string().contains("unavailable"), "{err:#}");
        assert!(mgr.active("web").is_empty());
    }

    #[test]
    fn stop_all_stops_everything() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let r1 = rule(free_port());
        let r2 = rule(free_port());
        mgr.publish(&paths, "web", r1.clone()).unwrap();
        mgr.publish(&paths, "web", r2.clone()).unwrap();
        mgr.stop_all("web");
        assert!(mgr.active("web").is_empty());
    }

    #[test]
    fn respawn_dead_revives_finished_slot() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let r = rule(free_port());
        // A slot whose thread already finished (simulated crash).
        mgr.insert_for_test("web", r.clone());
        mgr.respawn_dead(&paths, "web");
        // After respawn the port is genuinely bound again.
        assert!(std::net::TcpListener::bind((r.bind, r.host_port)).is_err());
        assert_eq!(mgr.active("web"), vec![r]);
        mgr.stop_all("web");
    }
}
