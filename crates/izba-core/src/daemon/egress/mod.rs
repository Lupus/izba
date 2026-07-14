//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod audit;
pub mod config;
pub mod dns;
pub mod dns_snoop;
pub mod mitm;
pub mod mitm_runtime;
pub mod policy;
pub mod router;
pub mod sys_resolver;

use anyhow::Context;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use self::audit::AuditSink;
use self::dns::Resolver;
use self::dns_snoop::SnoopStore;
use self::mitm_runtime::MitmRuntime;
use self::policy::Policy;
use crate::daemon::transport::UdsListener;
use crate::paths::Paths;
use izba_proto::EGRESS_PORT;

/// Host-side unix path the VMM bridges guest-initiated vsock connections
/// to (Firecracker convention, shared by CH and OpenVMM):
/// `<vsock.sock>_<port>`.
pub fn listener_path(paths: &Paths, name: &str) -> PathBuf {
    paths
        .run_dir(name)
        .join(format!("vsock.sock_{EGRESS_PORT}"))
}

/// A swappable holder for a sandbox's live egress policy. The accept loop reads
/// it per connection via [`PolicyCell::load`], so a [`PolicyCell::store`] from a
/// reload (see [`EgressManager::apply_policy`]) takes effect on the *next*
/// connection; in-flight connections keep the `Arc` they already cloned. The
/// lock is held only for an `Arc` clone/replace, never across I/O, so a plain
/// `Mutex` is contention-free here (one accept thread per sandbox).
pub(crate) struct PolicyCell {
    inner: Mutex<Arc<dyn Policy>>,
}

impl PolicyCell {
    pub fn new(policy: Arc<dyn Policy>) -> Self {
        Self {
            inner: Mutex::new(policy),
        }
    }

    /// Snapshot the current policy (cheap `Arc` clone under a short lock).
    pub fn load(&self) -> Arc<dyn Policy> {
        Arc::clone(&self.inner.lock().unwrap())
    }

    /// Replace the policy; future `load`s see the new one.
    pub fn store(&self, policy: Arc<dyn Policy>) {
        *self.inner.lock().unwrap() = policy;
    }
}

struct EgressSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    /// The sandbox's live policy, swappable by `apply_policy`. Shared with the
    /// accept thread, which reads it per connection.
    policy: Arc<PolicyCell>,
}

/// Resolve a sandbox's egress policy from its `--policy` file, materializing
/// an explicit `enforce: false` default when no file exists yet. Fails CLOSED
/// on I/O or compile errors (deny-all enforcing policy) rather than silently
/// allowing — a present-but-broken policy is never treated as AllowAll.
fn resolve_policy(paths: &Paths, name: &str) -> Arc<dyn Policy> {
    use self::config::EgressPolicyConfig;
    let deny_all = || -> Arc<dyn Policy> {
        // An enforcing policy with an empty allow-list denies everything.
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![],
            git: vec![],
        };
        match cfg.into_policy(name) {
            Ok(p) => p,
            Err(_) => Arc::new(self::policy::AllowAll), // unreachable (embedded Rego is valid)
        }
    };
    match EgressPolicyConfig::load_or_materialize(&paths.sandbox_dir(name)) {
        Ok(cfg) => match cfg.into_policy(name) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("izbad: egress policy for '{name}' failed to compile: {e:#}; deny-all");
                deny_all()
            }
        },
        Err(e) => {
            eprintln!("izbad: reading egress policy for '{name}': {e:#}; deny-all");
            deny_all()
        }
    }
}

/// All egress listeners, keyed by sandbox name. The daemon owns one
/// instance for its lifetime; daemon restart severs live flows (decided —
/// adopt rebinds for new ones).
pub struct EgressManager {
    inner: Mutex<HashMap<String, EgressSlot>>,
    resolver: Arc<dyn Resolver>,
    /// The shared MITM runtime (tier-1 HTTP/S loopback hop). `None` ⇒ no MITM:
    /// all TCP takes the direct-dial path. The policy is sandbox-aware via
    /// `FlowDesc.sandbox`, so one runtime serves every sandbox.
    mitm: Option<Arc<MitmRuntime>>,
    /// Structured per-flow audit log (tier-2 decisions; tier-1 is audited
    /// inside the shared `MitmRuntime`). Cheap to clone into each handler.
    audit: AuditSink,
    /// DNS-snoop store (tier-2 IP→FQDN recovery). Pure runtime state, so the
    /// manager owns it rather than taking it as a dependency. One store keyed
    /// by sandbox serves every listener; the resolver path fills it and the
    /// `TcpConnect` path reads it.
    snoop: Arc<SnoopStore>,
}

impl EgressManager {
    pub fn new(
        resolver: Arc<dyn Resolver>,
        mitm: Option<Arc<MitmRuntime>>,
        audit: AuditSink,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            resolver,
            mitm,
            audit,
            snoop: Arc::new(SnoopStore::new()),
        }
    }

    /// Idempotent: bind the egress listener for `name` unless one is
    /// already alive. A finished (crashed) accept thread is rebound — this
    /// doubles as the supervisor's respawn path.
    pub fn ensure_listening(&self, paths: &Paths, name: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(slot) = inner.get(name) {
            if !slot.thread.is_finished() {
                return Ok(());
            }
            // A slot is found here only if its accept thread exited
            // unexpectedly: `stop()` always removes the slot, so it never
            // leaves a finished thread behind. Drop it and rebind below.
            inner.remove(name);
        }
        let path = listener_path(paths, name);
        // This socket is an unauthenticated outbound proxy (AllowAll until
        // M2 policy) — keep it reachable only via a 0700 run dir, the same
        // defense-in-depth the daemon control socket gets (transport.rs).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let run = paths.run_dir(name);
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", run.display()))?;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing stale {}", path.display())),
        }
        let listener = UdsListener::bind(&path)
            .with_context(|| format!("binding egress listener {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("egress listener nonblocking")?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        // Resolve THIS sandbox's policy once, when the listener is armed.
        // `load_or_materialize` writes an explicit `enforce:false` when no
        // file exists yet, then compiles it to AllowAll or RegoPolicy based
        // on the `enforce` flag. The Arc travels into the MITM runtime per
        // flow, so the shared runtime serves every sandbox's own allow-list.
        let policy = resolve_policy(paths, name);
        let cell = Arc::new(PolicyCell::new(policy));
        let cell_for_thread = Arc::clone(&cell);
        let resolver = Arc::clone(&self.resolver);
        let mitm = self.mitm.clone();
        let audit = self.audit.clone();
        let snoop = Arc::clone(&self.snoop);
        let sandbox = name.to_string();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let policy = cell_for_thread.load();
                        let resolver = Arc::clone(&resolver);
                        let mitm = mitm.clone();
                        let audit = audit.clone();
                        let snoop = Arc::clone(&snoop);
                        let sandbox = sandbox.clone();
                        std::thread::spawn(move || {
                            router::handle_conn(
                                conn,
                                &sandbox,
                                policy,
                                &*resolver,
                                mitm.as_deref(),
                                &audit,
                                &snoop,
                            )
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("izbad: egress accept for '{sandbox}': {e}");
                        return;
                    }
                }
            }
        });
        inner.insert(
            name.to_string(),
            EgressSlot {
                stop,
                thread,
                policy: cell,
            },
        );
        Ok(())
    }

    /// Stop and join the listener of `name` (sandbox stop/rm); removes the
    /// socket file so a later VMM bridge attempt fails fast. Only the accept
    /// loop is joined: in-flight connection threads are detached and finish
    /// on their own — their guest leg breaks once the VM stops.
    pub fn stop(&self, paths: &Paths, name: &str) {
        let Some(slot) = self.inner.lock().unwrap().remove(name) else {
            return;
        };
        slot.stop.store(true, Ordering::SeqCst);
        let _ = slot.thread.join();
        let _ = std::fs::remove_file(listener_path(paths, name));
    }

    pub fn listening(&self, name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|s| !s.thread.is_finished())
            .unwrap_or(false)
    }

    /// Hot-swap `name`'s live policy to an already-validated, compiled
    /// snapshot. The caller loads+compiles the policy exactly once (from
    /// `ReloadPolicy`'s dispatch handler) and hands it here to apply — this
    /// is the TOCTOU-free companion to the old re-read-by-path design: there
    /// is no second file read that could observe a different (or broken)
    /// file than the one that was validated. Takes effect on new connections
    /// only (in-flight flows keep their snapshot). No-op when `name` has no
    /// live slot — the file on disk is already what the next start will read.
    pub fn apply_policy(&self, name: &str, policy: Arc<dyn Policy>) {
        if let Some(slot) = self.inner.lock().unwrap().get(name) {
            slot.policy.store(policy);
        }
    }

    /// Test hook: a slot whose accept thread is already finished (simulated
    /// crash), so `ensure_listening` exercises its rebind path.
    #[cfg(test)]
    fn insert_for_test(&self, name: &str) {
        let thread = std::thread::spawn(|| {});
        while !thread.is_finished() {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.inner.lock().unwrap().insert(
            name.to_string(),
            EgressSlot {
                stop: Arc::new(AtomicBool::new(false)),
                thread,
                policy: Arc::new(PolicyCell::new(Arc::new(self::policy::AllowAll))),
            },
        );
    }

    #[cfg(test)]
    fn slot_enforces(&self, name: &str) -> Option<bool> {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|s| s.policy.load().enforces())
    }
}

#[cfg(test)]
mod tests {
    use super::config::EgressPolicyConfig;
    use super::policy::AllowAll;
    use super::*;
    use crate::vmm::UdsStream;
    use izba_proto::{dns as pdns, write_frame, StreamOpen};

    struct EchoResolver;
    impl Resolver for EchoResolver {
        fn handle(&self, q: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(q.to_vec())
        }
    }

    fn mgr() -> EgressManager {
        let audit = AuditSink::new(Paths::with_root(
            std::env::temp_dir().join("izba-audit-test"),
        ));
        EgressManager::new(Arc::new(EchoResolver), None, audit)
    }

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.run_dir("web")).unwrap();
        (dir, paths)
    }

    #[test]
    fn listener_path_follows_vmm_convention() {
        let paths = Paths::with_root(PathBuf::from("/data"));
        assert_eq!(
            listener_path(&paths, "web"),
            paths.run_dir("web").join("vsock.sock_1027")
        );
    }

    /// Full lifecycle against a real unix listener — runtime-skip where the
    /// sandbox denies bind (house pattern).
    #[test]
    fn ensure_listening_accepts_and_routes() {
        let (_d, paths) = test_paths();
        let m = mgr();
        match m.ensure_listening(&paths, "web") {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP ensure_listening_accepts_and_routes: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(m.listening("web"));
        // Idempotent.
        m.ensure_listening(&paths, "web").unwrap();

        // Drive one DNS exchange through the real listener.
        let mut c = UdsStream::connect(listener_path(&paths, "web")).unwrap();
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        pdns::write_dns_msg(&mut c, b"ping").unwrap();
        assert_eq!(pdns::read_dns_msg(&mut c).unwrap().unwrap(), b"ping");
        drop(c);

        m.stop(&paths, "web");
        assert!(!m.listening("web"));
        assert!(
            !listener_path(&paths, "web").exists(),
            "socket file removed on stop"
        );
    }

    #[test]
    fn stop_unknown_is_a_noop() {
        let (_d, paths) = test_paths();
        mgr().stop(&paths, "ghost");
    }

    #[test]
    fn policy_cell_loads_and_swaps() {
        let cell = PolicyCell::new(Arc::new(AllowAll));
        assert!(!cell.load().enforces(), "AllowAll is non-enforcing");

        let enforcing = EgressPolicyConfig {
            enforce: true,
            allow: vec![crate::daemon::egress::config::AllowEntry::Host(
                "api.anthropic.com".into(),
            )],
            git: vec![],
        }
        .into_policy("web")
        .unwrap();
        // into_policy now returns Arc<dyn Policy> directly — no double-wrapping.
        cell.store(enforcing);
        assert!(cell.load().enforces(), "swapped-in RegoPolicy enforces");
    }

    /// Companion to the daemon's `ReloadPolicy` dispatch: the caller loads +
    /// compiles a policy exactly once and hands the compiled snapshot to
    /// `apply_policy`, which just swaps the live slot — no re-read of
    /// `policy.yaml` happens here (that's the whole point: no TOCTOU window
    /// between validating and applying).
    #[test]
    fn apply_policy_swaps_a_live_slot() {
        let mgr = mgr(); // default policy is the bare AllowAll
        mgr.insert_for_test("web");
        assert_eq!(mgr.slot_enforces("web"), Some(false), "starts bare");

        let enforcing = EgressPolicyConfig {
            enforce: true,
            allow: vec![crate::daemon::egress::config::AllowEntry::Host(
                "api.anthropic.com".into(),
            )],
            git: vec![],
        }
        .into_policy("web")
        .unwrap();
        mgr.apply_policy("web", enforcing);

        assert_eq!(
            mgr.slot_enforces("web"),
            Some(true),
            "after apply_policy the slot enforces the compiled allow-list"
        );
    }

    #[test]
    fn apply_policy_unknown_sandbox_is_a_noop() {
        let mgr = mgr();
        let policy: Arc<dyn Policy> = Arc::new(AllowAll);
        mgr.apply_policy("ghost", policy); // must not panic
        assert_eq!(mgr.slot_enforces("ghost"), None);
    }

    /// A crashed accept thread (finished slot) is rebound by the next
    /// `ensure_listening` — the supervisor's respawn path. Runtime-skips
    /// where the sandbox denies bind.
    #[test]
    fn ensure_listening_rebinds_a_crashed_slot() {
        let (_d, paths) = test_paths();
        let m = mgr();
        m.insert_for_test("web");
        assert!(!m.listening("web"), "the seeded slot is already finished");
        match m.ensure_listening(&paths, "web") {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP ensure_listening_rebinds_a_crashed_slot: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(m.listening("web"), "rebound a fresh accept thread");
        assert!(listener_path(&paths, "web").exists(), "socket file rebound");
        m.stop(&paths, "web");
    }
}
