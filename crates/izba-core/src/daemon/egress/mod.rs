//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod audit;
pub mod clienthello;
pub mod config;
pub mod dns;
pub mod dns_snoop;
pub mod inspect;
pub mod mitm;
pub mod mitm_runtime;
pub mod policy;
pub mod router;
pub mod sys_resolver;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use self::audit::AuditSink;
use self::dns::Resolver;
use self::dns_snoop::SnoopStore;
use self::mitm_runtime::MitmRuntime;
use self::policy::Policy;
use crate::daemon::peercred;
use crate::paths::Paths;
use crate::vmm::UdsStream;
use izba_proto::EGRESS_PORT;

/// Host-side unix path the VMM bridges guest-initiated vsock connections
/// to (Firecracker convention, shared by CH and OpenVMM):
/// `<run dir>/vsock.sock_<port>`. The caller supplies the run dir — the
/// start path passes the new run's dir, adoption/stop pass the LIVE dir
/// recorded in state.json (see `sandbox::live_run_dir`).
pub fn listener_path(run_dir: &Path) -> PathBuf {
    run_dir.join(format!("vsock.sock_{EGRESS_PORT}"))
}

/// What the accept loop must do with one egress connection (F-CRED-5).
///
/// This is a NAMED DECISION type on purpose, not an `Option<String>`. The gate
/// used to read `if let Some(line) = egress_peer_denial_log(..)`, which made
/// ENFORCEMENT a side effect of whether a LOG MESSAGE happened to be produced:
/// any later cosmetic edit to the logging — rate-limiting a flood, deduping a
/// repeat, staying quiet while the daemon is shutting down — would silently
/// have become an authorization bypass, and would have been reviewed as a
/// logging change. Here the message rides INSIDE `Reject`, so it can be
/// reworded, throttled or dropped entirely without the decision moving.
///
/// If you are here to touch the wording: edit the `String`. If you are here to
/// change who gets served: you are changing a trust boundary, and the register
/// entry for F-CRED-5 in `docs/security/findings-2026-06-15.md` is the place
/// that has to change with you.
enum EgressAdmission {
    /// Hand the connection to the router.
    Serve,
    /// Drop the connection; this is the daemon-log line explaining why.
    Reject(String),
}

/// Decide whether one egress connection may be served — the egress-plane twin
/// of `server::peer_denial_log`, but returning a named decision rather than an
/// `Option<String>` (see [`EgressAdmission`]). Pure, so the accept loop's
/// decision is testable without binding a listener.
///
/// The rejection line names the SANDBOX, unlike the control-plane one: a daemon
/// runs one egress listener per sandbox, so "which sandbox's outbound plane did
/// a foreign uid just try to drive" is the operator's first question.
///
/// `Allow(Unavailable)` is `Serve`, exactly like `Allow(Enforced)`: a platform
/// with no peer-credential API (Windows) never performed a rejection, so it
/// must not report one.
///
/// A `Deny` carrying `peer_uid == u32::MAX` did not identify a peer at all —
/// that value is `peercred`'s documented sentinel for "the peer-credential
/// syscall itself failed", and its own doc says a log/audit consumer must not
/// print it as a uid. Rendering it verbatim would put `uid 4294967295` in the
/// daemon log and send an operator hunting for a uid that does not exist, so
/// the line says the peer was unidentifiable instead. The DENIAL is unchanged:
/// failing closed on an unreadable credential is the entire point of that
/// sentinel.
fn egress_admission(verdict: peercred::PeerVerdict, sandbox: &str) -> EgressAdmission {
    let (peer_uid, owner_uid) = match verdict {
        peercred::PeerVerdict::Allow(_) => return EgressAdmission::Serve,
        peercred::PeerVerdict::Deny {
            peer_uid,
            owner_uid,
        } => (peer_uid, owner_uid),
    };
    let who = if peer_uid == u32::MAX {
        "an unidentifiable peer (peer-credential lookup failed)".to_string()
    } else {
        format!("uid {peer_uid}")
    };
    // "as the daemon owner", not "the VMM": that is literally what is checked
    // (see the FORWARD TRAP on `EgressManager::admit`), and an operator
    // debugging a denial needs the predicate, not an idealization of it.
    EgressAdmission::Reject(format!(
        "izbad: egress connection for '{sandbox}' from {who} rejected \
         (daemon runs as uid {owner_uid}); only a process running as the daemon \
         owner — the VMM bridging this sandbox's guest vsock — may drive a \
         sandbox's egress"
    ))
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

/// A swappable holder for a sandbox's USB egress guard, mirroring
/// [`PolicyCell`]. Read per connection so a grant or revoke takes effect on the
/// *next* flow rather than at the next VM restart — a revoked sandbox must not
/// keep paying for a denial it no longer earns, and a freshly-granted one must
/// not keep an open path to the upstream until it reboots.
pub(crate) struct UsbGuardCell {
    inner: Mutex<router::UsbGuard>,
}

impl UsbGuardCell {
    pub fn new(guard: router::UsbGuard) -> Self {
        Self {
            inner: Mutex::new(guard),
        }
    }

    pub fn load(&self) -> router::UsbGuard {
        *self.inner.lock().unwrap()
    }

    pub fn store(&self, guard: router::UsbGuard) {
        *self.inner.lock().unwrap() = guard;
    }
}

struct EgressSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    /// The sandbox's live policy, swappable by `apply_policy`. Shared with the
    /// accept thread, which reads it per connection.
    policy: Arc<PolicyCell>,
    /// The sandbox's live USB guard, swappable by `apply_usb_guard`.
    usb: Arc<UsbGuardCell>,
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
    /// The accept loop's peer gate (F-CRED-5). A bare `fn` pointer because
    /// `fn` is `Copy`: it copies into each accept thread with no `Arc`, no
    /// lifetime, and no allocation on the per-connection path.
    ///
    /// INJECTABLE ONLY so the DENIED leg can be driven through the real accept
    /// loop by a test (`a_denied_peer_is_refused_by_the_real_accept_loop`): a
    /// denied peer is by construction a peer this process cannot be, and unit
    /// tests here may not spawn one under a foreign uid. Production has
    /// exactly one admitter — [`peercred::authorize_stream`], set in
    /// [`EgressManager::new`] and pinned by
    /// `the_production_default_admitter_is_authorize_stream`. Never widen this
    /// into a constructor argument, a config key, or anything else settable at
    /// run time: an admitter that can be chosen at run time is an admitter
    /// that can be chosen to be "allow everyone", which is precisely the state
    /// F-CRED-5 exists to leave behind.
    ///
    /// FORWARD TRAP — this gate authenticates *any process running as the
    /// daemon owner*, NOT *the VMM*. Today those coincide on Linux, because
    /// izba spawns no setuid/ambient-cap path and Cloud Hypervisor inherits
    /// izbad's euid. They do NOT coincide on Windows, where MVP-D already runs
    /// the VMM under a separate `izba-spk-<name>` principal — harmless only
    /// because `enforcement_mode()` is `Unavailable` there, so nothing is
    /// compared. The obvious next Linux hardening step (running
    /// cloud-hypervisor under a per-sandbox uid, the Linux analogue of what
    /// Windows already does) would therefore break EVERY sandbox's egress the
    /// moment it lands, and would surface only as denial lines in
    /// `daemon.log`. That change needs a peer *allow-set* (owner uid plus the
    /// sandbox's VMM uid) here, in the same commit.
    admit: fn(&UdsStream) -> peercred::PeerVerdict,
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
            admit: peercred::authorize_stream,
        }
    }

    /// Test-only override of the peer gate — see the [`admit`] field's doc for
    /// why this seam exists and why it must never become reachable in
    /// production.
    ///
    /// [`admit`]: EgressManager::admit
    #[cfg(test)]
    fn set_admit(&mut self, f: fn(&UdsStream) -> peercred::PeerVerdict) {
        self.admit = f;
    }

    /// Idempotent: bind the egress listener for `name` unless one is
    /// already alive. A finished (crashed) accept thread is rebound — this
    /// doubles as the supervisor's respawn path.
    ///
    /// `run_dir` is caller-supplied: the Start RPC passes `paths.run_dir(name)`
    /// (the new run's dir — a stale `state.json` from a crashed pre-upgrade
    /// run must not drag the new bind to the legacy dir), while adoption at
    /// daemon startup and the supervisor's rebind tick pass
    /// `sandbox::live_run_dir(paths, name)` (the dir the CURRENT run actually
    /// used). `paths` is still needed to read `policy.yaml` from the sandbox
    /// dir via `resolve_policy`.
    pub fn ensure_listening(
        &self,
        paths: &Paths,
        name: &str,
        run_dir: &Path,
    ) -> anyhow::Result<()> {
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
        let path = listener_path(run_dir);
        // This socket is a full outbound proxy for the sandbox, governed by
        // that sandbox's M2 egress policy — so whoever can drive it inherits
        // the sandbox's whole allow-list. It is authenticated per connection
        // in the accept loop below (`admit`, F-CRED-5), which is the gate that
        // actually decides who may drive it.
        //
        // The 0700 run dir that `bind_sandbox_listener` (re-)asserts is now
        // DEFENSE IN DEPTH behind that check rather than the sole gate — and
        // it is unix-only, which is exactly why the peer check had to stop
        // being optional. The helper also creates the dir: it may not exist
        // yet on the adoption path (a pre-upgrade sandbox's legacy dir, or a
        // fresh Start racing the rest of `sandbox::start`'s directory setup).
        let listener = crate::daemon::transport::bind_sandbox_listener(
            paths.root(),
            run_dir,
            &path,
            "egress",
        )?;
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
        // The USB guard is resolved from this sandbox's device grants and the
        // daemon's configured upstream, and kept live by `apply_usb_guard`.
        let usb_cell = Arc::new(UsbGuardCell::new(crate::usb::guard_for(paths, name)));
        let usb_for_thread = Arc::clone(&usb_cell);
        let resolver = Arc::clone(&self.resolver);
        let mitm = self.mitm.clone();
        let audit = self.audit.clone();
        let snoop = Arc::clone(&self.snoop);
        // `fn` is `Copy`, so the gate travels into the accept thread by value.
        let admit = self.admit;
        let sandbox = name.to_string();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        // ORDERING IS LOAD-BEARING (F-CRED-5): the peer check
                        // runs AFTER `set_nonblocking` succeeds and BEFORE any
                        // per-connection work — no policy/USB-guard load, no
                        // `Arc` clone of the resolver/MITM/audit/snoop, and
                        // above all no handler thread. A foreign-uid peer must
                        // cost this daemon nothing and relay not one byte:
                        // this listener is a full outbound proxy for the
                        // sandbox, so an unauthorized local peer that got past
                        // it would inherit the sandbox's entire egress
                        // allow-list (and, once M5 lands, its credentials).
                        // Dropping `conn` closes it, so the peer sees EOF.
                        //
                        // `admit` is `peercred::authorize_stream` in every
                        // production build; it is a field only so a test can
                        // drive the DENIED leg through this very loop (see the
                        // field's doc). The decision is `EgressAdmission`, not
                        // "did we produce a log line" — reword the message
                        // freely; changing who gets `Serve`d moves a trust
                        // boundary.
                        if let EgressAdmission::Reject(line) =
                            egress_admission((admit)(&conn), &sandbox)
                        {
                            eprintln!("{line}");
                            continue;
                        }
                        let policy = cell_for_thread.load();
                        let usb = usb_for_thread.load();
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
                                usb,
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
                usb: usb_cell,
            },
        );
        Ok(())
    }

    /// Stop and join the listener of `name` (sandbox stop/rm); removes the
    /// socket file so a later VMM bridge attempt fails fast. Only the accept
    /// loop is joined: in-flight connection threads are detached and finish
    /// on their own — their guest leg breaks once the VM stops.
    ///
    /// `run_dir` is caller-supplied: it must be the LIVE dir the current run
    /// actually bound in (`sandbox::live_run_dir`), or the removal targets
    /// the wrong directory and leaves the real socket file behind.
    pub fn stop(&self, name: &str, run_dir: &Path) {
        let Some(slot) = self.inner.lock().unwrap().remove(name) else {
            return;
        };
        slot.stop.store(true, Ordering::SeqCst);
        let _ = slot.thread.join();
        let _ = std::fs::remove_file(listener_path(run_dir));
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

    /// Hot-swap `name`'s USB egress guard after a grant or revoke. Takes effect
    /// on the next connection (in-flight flows keep the guard they cloned);
    /// no-op when `name` has no live slot, since the next start recomputes it
    /// from disk anyway.
    pub fn apply_usb_guard(&self, name: &str, guard: router::UsbGuard) {
        if let Some(slot) = self.inner.lock().unwrap().get(name) {
            slot.usb.store(guard);
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
                usb: Arc::new(UsbGuardCell::new(router::UsbGuard::default())),
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

    #[cfg(test)]
    fn slot_usb_guard(&self, name: &str) -> Option<router::UsbGuard> {
        self.inner.lock().unwrap().get(name).map(|s| s.usb.load())
    }
}

#[cfg(test)]
mod tests {
    use super::config::EgressPolicyConfig;
    use super::policy::AllowAll;
    use super::*;
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
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        (dir, paths)
    }

    /// Kills a transposed `format!(peer_uid, owner_uid)` — which a bare
    /// `contains("uid 0")` / `contains("uid 1000")` pair would NOT — by
    /// pinning the semantic slots, plus the sandbox name and the verb.
    #[test]
    fn a_denial_renders_an_actionable_log_line() {
        let EgressAdmission::Reject(line) = egress_admission(
            peercred::PeerVerdict::Deny {
                peer_uid: 0,
                owner_uid: 1000,
            },
            "web",
        ) else {
            panic!("a Deny verdict must be a Reject");
        };
        assert!(line.contains("from uid 0"), "got: {line}");
        assert!(line.contains("runs as uid 1000"), "got: {line}");
        assert!(
            line.contains("'web'"),
            "the line must name the sandbox whose egress was refused; got: {line}"
        );
        assert!(
            line.contains("rejected"),
            "the line must say the connection was rejected; got: {line}"
        );
    }

    /// `peercred` documents `peer_uid: u32::MAX` as the sentinel for "the
    /// peer-credential syscall itself failed", and says a log/audit consumer
    /// must not print it as a uid. Kills the mutant that drops the sentinel
    /// branch and renders it through the ordinary `uid {peer_uid}` arm, which
    /// would emit `uid 4294967295` and send an operator hunting a uid that
    /// cannot exist.
    #[test]
    fn a_failed_credential_lookup_is_not_rendered_as_a_real_uid() {
        let EgressAdmission::Reject(line) = egress_admission(
            peercred::PeerVerdict::Deny {
                peer_uid: u32::MAX,
                owner_uid: 1000,
            },
            "web",
        ) else {
            panic!("the sentinel Deny must still be a Reject — fail-closed");
        };
        assert!(
            !line.contains("4294967295"),
            "the sentinel must never be printed as a uid; got: {line}"
        );
        assert!(
            line.contains("unidentifiable peer"),
            "the line must say the peer could not be identified; got: {line}"
        );
        assert!(
            line.contains("peer-credential lookup failed"),
            "the line must say WHY the peer is unidentifiable; got: {line}"
        );
        // The owner uid is real and still belongs in the line, and the
        // connection is still refused: fail-closed is the point of the
        // sentinel, and only its RENDERING changes.
        assert!(line.contains("runs as uid 1000"), "got: {line}");
        assert!(line.contains("rejected"), "got: {line}");
    }

    #[test]
    fn an_enforced_allow_is_served() {
        assert!(matches!(
            egress_admission(
                peercred::PeerVerdict::Allow(peercred::PeerAuth::Enforced),
                "web"
            ),
            EgressAdmission::Serve
        ));
    }

    /// A platform with no peer-credential API (Windows) reports
    /// `Allow(Unavailable)`. That is NOT an authentication, but it is also NOT
    /// a denial: rejecting it would break egress on Windows outright, and
    /// logging it as a rejection would spam the daemon log with one it never
    /// performed. The Windows residual stays "reported, never enforced".
    #[test]
    fn an_unavailable_allow_is_served_and_not_reported_as_a_denial() {
        assert!(matches!(
            egress_admission(
                peercred::PeerVerdict::Allow(peercred::PeerAuth::Unavailable),
                "web"
            ),
            EgressAdmission::Serve
        ));
    }

    /// The injection seam of FIX 1 is only as good as what it defaults to: an
    /// `EgressManager::new` that wired `admit` to an always-allow stub would
    /// leave the entire suite — including the denied-leg accept-loop test,
    /// which injects its own admitter — green while production authenticated
    /// nobody. So pin the DEFAULT itself, by address.
    ///
    /// Compared as `usize` rather than with `==` on the pointers, which is
    /// `unpredictable_function_pointer_comparisons` (deny-by-`-D warnings`).
    /// `authorize_stream` is a plain non-generic `pub fn` in this same crate,
    /// so it has one address here.
    ///
    /// Catches: `admit: peercred::authorize_stream` in `new()` rewritten to any
    /// other function. (A struct-literal field is not something cargo-mutants
    /// rewrites, which is exactly why this needs a hand-written guard.)
    #[test]
    fn the_production_default_admitter_is_authorize_stream() {
        let default_admit = mgr().admit as usize;
        let expected =
            peercred::authorize_stream as fn(&UdsStream) -> peercred::PeerVerdict as usize;
        assert_eq!(
            default_admit, expected,
            "EgressManager::new must default `admit` to peercred::authorize_stream; \
             anything else silently unauthenticates every production egress listener"
        );
    }

    #[test]
    fn listener_path_follows_vmm_convention() {
        assert_eq!(
            listener_path(Path::new("/data/run/aabbccdd")),
            PathBuf::from("/data/run/aabbccdd/vsock.sock_1027")
        );
    }

    /// Full lifecycle against a real unix listener — runtime-skip where the
    /// sandbox denies bind (house pattern).
    ///
    /// Since F-CRED-5 this is also the peer gate's POSITIVE leg, and the only
    /// test that runs the real accept loop with the DEFAULT admitter: it uses
    /// `mgr()` untouched, so `peercred::authorize_stream` judges a peer that
    /// really is us. A gate that closed on the legitimate same-uid VMM peer —
    /// or a `Serve`/`Reject` arm swapped in `egress_admission` — would stop
    /// this echo. `a_denied_peer_is_refused_by_the_real_accept_loop` is its
    /// matched negative twin.
    #[test]
    fn ensure_listening_accepts_and_routes() {
        let (_d, paths) = test_paths();
        let run_dir = paths.run_dir("web");
        let m = mgr();
        match m.ensure_listening(&paths, "web", &run_dir) {
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
        m.ensure_listening(&paths, "web", &run_dir).unwrap();

        // Drive one DNS exchange through the real listener.
        let mut c = UdsStream::connect(listener_path(&run_dir)).unwrap();
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        pdns::write_dns_msg(&mut c, b"ping").unwrap();
        assert_eq!(pdns::read_dns_msg(&mut c).unwrap().unwrap(), b"ping");
        drop(c);

        m.stop("web", &run_dir);
        assert!(!m.listening("web"));
        assert!(
            !listener_path(&run_dir).exists(),
            "socket file removed on stop"
        );
    }

    /// F-CRED-5's CALL-SITE test: the peer gate must live in the REAL accept
    /// loop, ABOVE the handler spawn, and must actually stop the connection.
    ///
    /// Modelled exactly on `ensure_listening_accepts_and_routes` — same
    /// manager, same bind-or-skip `PermissionDenied` runtime skip (the house
    /// pattern for the rare test that genuinely needs a listener), same
    /// `StreamOpen::Dns` + echo exchange. The ONLY difference is the injected
    /// always-`Deny` admitter, so the pair is matched and this test's
    /// assertion is precisely "the echo the positive leg gets must not
    /// happen".
    ///
    /// Two mutations it kills, both of which every *other* test in this crate
    /// — including the pure `egress_admission` ones — leaves green:
    ///   * moving the gate BELOW `std::thread::spawn`, so the handler runs and
    ///     answers before the connection is dropped;
    ///   * replacing the gate's `continue` with `{}`, so execution falls
    ///     straight through into the handler.
    #[test]
    fn a_denied_peer_is_refused_by_the_real_accept_loop() {
        let (_d, paths) = test_paths();
        let run_dir = paths.run_dir("web");
        let mut m = mgr();
        // A denied peer is by construction a peer this process cannot BE, and
        // a unit test may not spawn one under another uid — hence the seam.
        m.set_admit(|_| peercred::PeerVerdict::Deny {
            peer_uid: 4242,
            owner_uid: 0,
        });
        match m.ensure_listening(&paths, "web", &run_dir) {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!(
                    "SKIP a_denied_peer_is_refused_by_the_real_accept_loop: bind denied: {e:#}"
                );
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }

        let mut c = UdsStream::connect(listener_path(&run_dir)).unwrap();
        // Backstop only: a working gate closes immediately and a broken one
        // answers immediately, so this timeout exists purely so a REGRESSION
        // fails the suite instead of hanging it.
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // The writes may fail with EPIPE once the accept loop has already
        // dropped its end — that is the gate working, not a test failure.
        let _ = write_frame(&mut c, &StreamOpen::Dns);
        let _ = pdns::write_dns_msg(&mut c, b"ping");
        match pdns::read_dns_msg(&mut c) {
            // The contract the gate promises: dropping the connection closes
            // it, and the peer sees EOF without one byte of service.
            Ok(None) => {}
            Ok(Some(answer)) => panic!(
                "a DENIED peer was served: the accept loop answered {answer:?} \
                 instead of dropping the connection — the gate is missing, sits \
                 below the handler spawn, or no longer skips the handler"
            ),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                panic!("a denied peer neither was answered nor saw EOF (hung): {e}")
            }
            // A reset/broken pipe is the same refusal seen from the other end.
            Err(_) => {}
        }

        m.stop("web", &run_dir);
    }

    /// Adoption hands a LEGACY dir for pre-upgrade sandboxes; the bind must
    /// land exactly there, not in the new hashed dir. Runtime-skip where the
    /// sandbox denies bind (house pattern).
    #[test]
    fn ensure_listening_binds_in_the_dir_it_is_given() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let legacy = paths.legacy_run_dir("web");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        let mgr = mgr();
        match mgr.ensure_listening(&paths, "web", &legacy) {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP ensure_listening_binds_in_the_dir_it_is_given: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(listener_path(&legacy).exists());
        assert!(!listener_path(&paths.run_dir("web")).exists());
        mgr.stop("web", &legacy);
    }

    #[test]
    fn stop_unknown_is_a_noop() {
        let (_d, paths) = test_paths();
        mgr().stop("ghost", &paths.run_dir("ghost"));
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

    /// Revoking the last grant must reopen the sandbox's ordinary LAN access on
    /// the NEXT connection, not at its next VM restart — the same liveness
    /// contract `apply_policy` gives the egress policy.
    #[test]
    fn apply_usb_guard_swaps_a_live_slot() {
        let mgr = mgr();
        mgr.insert_for_test("web");
        assert_eq!(
            mgr.slot_usb_guard("web").map(|g| g.sandbox_usb_enabled),
            Some(false),
            "starts with no grants"
        );

        mgr.apply_usb_guard(
            "web",
            router::UsbGuard {
                sandbox_usb_enabled: true,
                upstream: Some(("127.0.0.1".parse().unwrap(), 3240)),
            },
        );
        let g = mgr.slot_usb_guard("web").expect("slot still present");
        assert!(g.sandbox_usb_enabled);
        assert_eq!(g.upstream, Some(("127.0.0.1".parse().unwrap(), 3240)));

        mgr.apply_usb_guard("web", router::UsbGuard::default());
        assert_eq!(
            mgr.slot_usb_guard("web").map(|g| g.sandbox_usb_enabled),
            Some(false),
            "a revoke must be able to relax it again"
        );
    }

    #[test]
    fn apply_usb_guard_on_an_unknown_sandbox_is_a_noop() {
        let mgr = mgr();
        mgr.apply_usb_guard("ghost", router::UsbGuard::default());
        assert!(mgr.slot_usb_guard("ghost").is_none());
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
        let run_dir = paths.run_dir("web");
        let m = mgr();
        m.insert_for_test("web");
        assert!(!m.listening("web"), "the seeded slot is already finished");
        match m.ensure_listening(&paths, "web", &run_dir) {
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
        assert!(listener_path(&run_dir).exists(), "socket file rebound");
        m.stop("web", &run_dir);
    }
}
