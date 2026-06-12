//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod dns;
pub mod policy;
pub mod router;

use anyhow::Context;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use self::dns::Resolver;
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

struct EgressSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// All egress listeners, keyed by sandbox name. The daemon owns one
/// instance for its lifetime; daemon restart severs live flows (decided —
/// adopt rebinds for new ones).
pub struct EgressManager {
    inner: Mutex<HashMap<String, EgressSlot>>,
    policy: Arc<dyn Policy>,
    resolver: Arc<dyn Resolver>,
}

impl EgressManager {
    pub fn new(policy: Arc<dyn Policy>, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            policy,
            resolver,
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
        let policy = Arc::clone(&self.policy);
        let resolver = Arc::clone(&self.resolver);
        let sandbox = name.to_string();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let policy = Arc::clone(&policy);
                        let resolver = Arc::clone(&resolver);
                        let sandbox = sandbox.clone();
                        std::thread::spawn(move || {
                            router::handle_conn(conn, &sandbox, &*policy, &*resolver)
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
        inner.insert(name.to_string(), EgressSlot { stop, thread });
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
            },
        );
    }
}

#[cfg(test)]
mod tests {
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
        EgressManager::new(Arc::new(AllowAll), Arc::new(EchoResolver))
    }

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.run_dir("web")).unwrap();
        (dir, paths)
    }

    #[test]
    fn listener_path_follows_vmm_convention() {
        let p = Paths::with_root("/data/izba".into());
        assert_eq!(
            listener_path(&p, "web"),
            PathBuf::from("/data/izba/sandboxes/web/run/vsock.sock_1027")
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
