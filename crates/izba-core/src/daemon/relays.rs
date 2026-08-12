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

/// Every host port persisted as a fixed rule in ANY sandbox's `ports.json`.
///
/// The VNC relay's ephemeral allocation avoids these (#221): a kernel-chosen
/// port that matches a persisted rule would make that sandbox's next `start`
/// fail its publish and DROP the rule (pre-existing conflict behavior) — a
/// user-visible loss from a cosmetic collision. Best-effort: an unreadable
/// `ports.json` contributes nothing rather than failing the relay.
pub fn persisted_host_ports(paths: &Paths) -> std::collections::HashSet<u16> {
    let mut out = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(paths.sandboxes_dir()) else {
        return out;
    };
    for e in entries.flatten() {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Ok((rules, _)) = load_rules_migrating(paths, name) {
            out.extend(rules.iter().map(|r| r.host_port));
        }
    }
    out
}

/// Bind-with-avoidance (#221): call `bind` (kernel-chosen ephemeral port);
/// when the result lands in `avoid`, undo it via `unbind` and try again, up
/// to `attempts` total binds. Returns `(port, collided)` — if every attempt
/// collided the LAST bind is KEPT and `collided` is `true` (the caller warns
/// loudly): a colliding relay beats no display at all. Only the host-port
/// number matters, not the bind address: overlapping addresses on one port
/// conflict at bind time regardless. `attempts` is effectively clamped to at
/// least 1: the initial bind always happens.
pub fn allocate_avoiding(
    avoid: &std::collections::HashSet<u16>,
    attempts: usize,
    mut bind: impl FnMut() -> anyhow::Result<u16>,
    mut unbind: impl FnMut(u16),
) -> anyhow::Result<(u16, bool)> {
    let mut port = bind()?;
    for _ in 1..attempts {
        if !avoid.contains(&port) {
            return Ok((port, false));
        }
        unbind(port);
        port = bind()?;
    }
    Ok((port, avoid.contains(&port)))
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
    /// Test hook — see [`RelayManager::fail_next_publish_bound`].
    #[cfg(test)]
    fail_next_publish: AtomicBool,
}

impl RelayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `(rule.bind, rule.host_port)` and start the relay thread.
    /// Synchronous error on duplicate key or bind failure.
    pub fn publish(&self, paths: &Paths, name: &str, rule: PortRule) -> anyhow::Result<()> {
        // Port 0 belongs to `publish_bound` alone: `spawn_slot` rewrites a
        // zero host port from the listener, which would silently defeat the
        // duplicate-key check below (every `0` rule looks distinct, and the
        // stored rule is not the one the caller asked for). The CLI already
        // rejects `:0` in a rule spec, so this seals the library seam.
        if rule.host_port == 0 {
            bail!("host port 0 is not publishable — use publish_bound for an ephemeral relay");
        }
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

    /// Like [`publish`](Self::publish), but for a relay whose host port the
    /// KERNEL picks: pass `rule.host_port: 0` and the actually-bound port is
    /// returned AND stored (the slot keeps the REWRITTEN rule, so `active()`,
    /// the URL the daemon prints and a later `respawn_dead` rebind all agree
    /// on one real port).
    ///
    /// No duplicate-key check, unlike `publish`: an ephemeral bind can never
    /// collide with a port this manager already holds (the kernel does not
    /// hand out a bound port), and a caller passing a fixed port that IS
    /// taken gets the same synchronous "unavailable" bind error anyway.
    ///
    /// Used for the VNC relay, which lives in the daemon's SEPARATE
    /// `vnc_relays` manager precisely so it can never reach `save_rules` —
    /// it is derived per-start state, not a published port (spec
    /// 2026-08-09 §5).
    pub fn publish_bound(&self, paths: &Paths, name: &str, rule: PortRule) -> anyhow::Result<u16> {
        #[cfg(test)]
        self.take_forced_failure()?;
        let mut inner = self.inner.lock().unwrap();
        let slot = spawn_slot(paths, name, rule)?;
        let port = slot.rule.host_port;
        inner.entry(name.to_string()).or_default().push(slot);
        Ok(port)
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

    /// Test hook: make the NEXT `publish_bound` fail the way an unbindable
    /// host port would. There is no portable way to make an EPHEMERAL
    /// loopback bind fail on demand, and the fail-loud posture of the call
    /// site (`handle_start` propagates the error rather than degrading to a
    /// VNC-less sandbox) is exactly the behaviour that needs a test.
    #[cfg(test)]
    pub(crate) fn fail_next_publish_bound(&self) {
        self.fail_next_publish.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn take_forced_failure(&self) -> anyhow::Result<()> {
        if self.fail_next_publish.swap(false, Ordering::SeqCst) {
            bail!("host port 127.0.0.1:0 is unavailable (forced test failure)");
        }
        Ok(())
    }

    /// Test hook: a slot whose thread is already finished (simulated crash).
    #[cfg(test)]
    pub(crate) fn insert_for_test(&self, name: &str, rule: PortRule) {
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

fn spawn_slot(paths: &Paths, name: &str, mut rule: PortRule) -> anyhow::Result<RelaySlot> {
    let listener = TcpListener::bind((rule.bind, rule.host_port))
        .with_context(|| format!("host port {}:{} is unavailable", rule.bind, rule.host_port))?;
    // Ephemeral publish (`publish_bound`): the bind above is what decides the
    // port, so rewrite the rule with the kernel's choice BEFORE it is stored
    // — a slot left holding `0` would report a useless rule and rebind onto a
    // different port on respawn.
    if rule.host_port == 0 {
        rule.host_port = listener
            .local_addr()
            .context("reading the ephemeral relay port")?
            .port();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let vsock = crate::sandbox::live_run_dir(paths, name).join("vsock.sock");
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

    /// `publish_bound` with `host_port: 0` must report the port the KERNEL
    /// chose, and store that REWRITTEN rule — `active()` (and therefore the
    /// URL the daemon prints, and a later `respawn_dead`) must all agree on
    /// the real port, never on the `0` the caller asked for.
    #[test]
    fn publish_bound_reports_the_ephemeral_port() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let port = mgr
            .publish_bound(
                &paths,
                "web",
                PortRule {
                    bind: "127.0.0.1".parse().unwrap(),
                    host_port: 0,
                    guest_port: 6901,
                },
            )
            .unwrap();
        assert_ne!(port, 0, "an ephemeral publish must report a real port");
        assert_eq!(
            mgr.active("web"),
            vec![PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: port,
                guest_port: 6901,
            }],
            "the stored rule must carry the bound port, not the requested 0"
        );
        // The reported port is genuinely bound.
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
        mgr.stop_all("web");
    }

    /// A crashed ephemeral relay must come back on the SAME port — the URL
    /// handed to the user has to stay valid across a respawn, which only
    /// works because the slot stores the rewritten rule.
    #[test]
    fn respawn_dead_reuses_the_ephemeral_port() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let port = mgr
            .publish_bound(
                &paths,
                "web",
                PortRule {
                    bind: "127.0.0.1".parse().unwrap(),
                    host_port: 0,
                    guest_port: 6901,
                },
            )
            .unwrap();
        mgr.stop_all("web");
        // Re-insert as a "crashed" slot carrying the rewritten rule.
        mgr.insert_for_test(
            "web",
            PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: port,
                guest_port: 6901,
            },
        );
        mgr.respawn_dead(&paths, "web");
        assert_eq!(mgr.active("web").first().map(|r| r.host_port), Some(port));
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
        mgr.stop_all("web");
    }

    /// `publish` is the FIXED-port path: port 0 must be refused outright.
    /// `spawn_slot`'s rewrite would otherwise hand `publish` a stored rule the
    /// caller never asked for and make its duplicate-key check blind (every
    /// `0` rule looks distinct). No bind happens, so this needs no skip.
    #[test]
    fn publish_refuses_port_zero() {
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let err = mgr.publish(&paths, "web", rule(0)).unwrap_err();
        assert!(err.to_string().contains("not publishable"), "{err:#}");
        assert!(mgr.active("web").is_empty());
    }

    /// `publish` (the fixed-port path) must keep reporting exactly the rule
    /// it was given — the rewrite is ephemeral-only.
    #[test]
    fn publish_keeps_the_requested_fixed_port() {
        if !bind_works() {
            return;
        }
        let (_d, paths) = test_paths();
        let mgr = RelayManager::new();
        let r = rule(free_port());
        mgr.publish(&paths, "web", r.clone()).unwrap();
        assert_eq!(mgr.active("web"), vec![r]);
        mgr.stop_all("web");
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

    // ── #221: ephemeral VNC-relay allocation vs persisted fixed ports ───────

    #[test]
    fn persisted_host_ports_collects_every_sandboxs_fixed_rules() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        for s in ["a", "b", "empty"] {
            std::fs::create_dir_all(paths.sandbox_dir(s)).unwrap();
        }
        save_rules(&paths, "a", &[rule(8080), rule(8081)]).unwrap();
        save_rules(&paths, "b", &[rule(9090)]).unwrap();
        assert_eq!(
            persisted_host_ports(&paths),
            [8080, 8081, 9090].into_iter().collect()
        );
    }

    #[test]
    fn persisted_host_ports_is_empty_without_sandboxes_or_rules() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        assert!(persisted_host_ports(&paths).is_empty());
        std::fs::create_dir_all(paths.sandbox_dir("bare")).unwrap();
        assert!(persisted_host_ports(&paths).is_empty());
    }

    #[test]
    fn allocate_avoiding_rebinds_off_a_persisted_port() {
        let avoid: std::collections::HashSet<u16> = [40001].into_iter().collect();
        let ports = std::cell::RefCell::new(vec![40002u16, 40001]); // popped back-first
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &avoid,
            10,
            || Ok(ports.borrow_mut().pop().expect("bind called too often")),
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!((port, collided), (40002, false));
        assert_eq!(
            *unbound.borrow(),
            vec![40001],
            "the colliding bind must be undone before the retry"
        );
    }

    #[test]
    fn allocate_avoiding_keeps_the_last_port_when_every_attempt_collides() {
        let avoid: std::collections::HashSet<u16> = [40001].into_iter().collect();
        let binds = std::cell::RefCell::new(0usize);
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &avoid,
            3,
            || {
                *binds.borrow_mut() += 1;
                Ok(40001)
            },
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!(
            (port, collided),
            (40001, true),
            "a colliding relay beats no display at all"
        );
        assert_eq!(*binds.borrow(), 3, "exactly `attempts` binds");
        assert_eq!(
            unbound.borrow().len(),
            2,
            "every abandoned bind is undone; the kept one is not"
        );
    }

    #[test]
    fn allocate_avoiding_binds_once_when_clear_of_the_avoid_set() {
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &std::collections::HashSet::new(),
            10,
            || Ok(50000),
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!((port, collided), (50000, false));
        assert!(unbound.borrow().is_empty());
    }

    #[test]
    fn allocate_avoiding_propagates_a_bind_error() {
        let r = allocate_avoiding(
            &std::collections::HashSet::new(),
            10,
            || anyhow::bail!("forced"),
            |_p| {},
        );
        assert!(r.is_err());
    }
}
