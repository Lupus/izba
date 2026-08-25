//! Test-only helpers shared by sandbox and daemon unit tests: a mock VMM
//! driver whose handle answers Health over a socketpair, socketpair-backed
//! fake guest connectors, and pid-identity fixtures. Never compiled into
//! release builds (`#[cfg(test)]` at the module declaration).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use izba_proto::{read_frame, write_frame, GuestStats, HealthInfo, Request, Response};

use crate::paths::Paths;
use crate::procmgr;
use crate::state::save_json;
use crate::state::{PidIdentity, RunState, STATE_FILE};
use crate::vmm::{CommandSpec, IoStream, UdsStream, VmHandle, VmSpec, VmmDriver};

// ---------------------------------------------------------------------------
// Host ports for tests that bind LATER than they choose
// ---------------------------------------------------------------------------

/// Reserve a loopback host port for a test that will bind it at some later
/// point — a relay publish, a respawn, a `handle_port_publish`.
///
/// A `bind(("127.0.0.1", 0))` probe cannot do this safely. The moment the probe
/// socket closes, the port goes back to the kernel's ephemeral pool, and any
/// other test in this binary that asks for an ephemeral port before the real
/// bind can be handed that very port. Every such test then fails on `Address
/// already in use` — a fact about the harness, never about the code under test.
/// The window is widest under `cargo llvm-cov`, where instrumentation stretches
/// the gap between choosing and binding, which is why the coverage job could go
/// red on a commit whose `cargo test` gate was green.
///
/// These ports come from a range the kernel will NEVER auto-assign, so no `:0`
/// bind anywhere in the process can collide with one, and a process-wide cursor
/// keeps two concurrent callers from choosing the same port.
///
/// Returns `None` where binding is denied outright (some sandboxes refuse
/// `bind` with EPERM), so callers runtime-skip exactly as they did before.
pub(crate) fn reserve_port() -> Option<u16> {
    let hi = auto_assign_floor();
    if hi <= RESERVED_LO {
        // The ephemeral range has been widened over our window; there is no
        // range left that the kernel cannot also hand out, so fall back to the
        // probe. Callers stay correct, they merely lose the collision guarantee.
        return probe_port();
    }
    let span = hi - RESERVED_LO;
    for _ in 0..span.min(512) {
        let n = PORT_CURSOR.fetch_add(1, Ordering::Relaxed);
        let port = RESERVED_LO + n % span;
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            // Bindable now, and unreachable by any `:0` bind — the caller may
            // safely bind it for real later.
            Ok(_) => return Some(port),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            // Held by something outside this process; walk on.
            Err(_) => continue,
        }
    }
    panic!("no free port in the reserved test window {RESERVED_LO}..{hi}");
}

/// Bottom of the reserved window. Linux's default `ip_local_port_range` starts
/// at 32768 and the Windows dynamic range at 49152, so this sits below both.
const RESERVED_LO: u16 = 20_000;

/// Ceiling used when the real auto-assign floor cannot be read.
const RESERVED_HI: u16 = 32_767;

/// Seeded from the pid, NOT from zero. Two test binaries running at once (a
/// second `cargo test`, a coverage run beside a plain one) each get their own
/// cursor, and a shared zero start would march them through 20000, 20001, …
/// in lockstep — handing both the same port and reintroducing the very
/// collision this module exists to prevent.
///
/// Note precisely what this does and does not buy, because the difference is
/// the whole reason the flake was hard to see:
///
/// - WITHIN one process the guarantee is exact. The cursor hands each caller a
///   distinct port and the range puts it beyond any `:0` bind, so no test can
///   take another's port. That is the case CI runs: `testutil` is `#[cfg(test)]`
///   in this crate, so the izba-core lib test binary is its only consumer and
///   cargo runs one of it.
/// - ACROSS processes this is a stagger, NOT a reservation. Two binaries whose
///   pid-derived offsets land close together can still probe and release the
///   same port before either really binds it, and the call sites that do not
///   retry (`reserve_port` → an immediate `PortPublish`) would fail hard on it.
///
/// Closing that last gap needs a cross-process lock, or the port held until the
/// real bind — and the port CANNOT be held here, because the code under test is
/// what creates the listener. Neither is worth it for a helper whose only
/// consumer is a single binary; concurrent manual `cargo test` runs of THIS
/// crate are the one place the residual bites.
static PORT_CURSOR: std::sync::LazyLock<std::sync::atomic::AtomicU16> =
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicU16::new(std::process::id() as u16));

/// The lowest port the kernel may pick for a `:0` bind, minus one — i.e. the
/// top of the range it will never auto-assign. Read from the live sysctl on
/// Linux so a host that has lowered `ip_local_port_range` narrows our window
/// instead of silently reintroducing the collision.
fn auto_assign_floor() -> u16 {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
        if let Some(lo) = s
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u16>().ok())
        {
            return lo.saturating_sub(1).min(RESERVED_HI);
        }
    }
    RESERVED_HI
}

/// The old probe, kept only as the fallback above.
fn probe_port() -> Option<u16> {
    match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => Some(l.local_addr().unwrap().port()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("bind probe: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Pid-identity fixtures
// ---------------------------------------------------------------------------

/// Identity of the current (test) process — alive for the test's duration.
pub(crate) fn live_identity() -> PidIdentity {
    let pid = std::process::id();
    PidIdentity {
        pid,
        starttime: procmgr::proc_starttime(pid).unwrap(),
    }
}

/// Identity that `pid_alive` rejects (starttime mismatch).
pub(crate) fn dead_identity() -> PidIdentity {
    PidIdentity {
        pid: std::process::id(),
        starttime: 1,
    }
}

/// The digest every fixture sandbox is created from (the daemon test harness
/// stubs `resolve_image` to return it, and `sandbox::tests::opts` names it).
pub(crate) const FIXTURE_IMAGE_DIGEST: &str = "sha256:abc";

pub(crate) fn test_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path().join("izba"));
    // Every fixture data root holds a COMPLETE cache entry for the canonical
    // test digest — the shape `ensure_image` guarantees for a real pull. A
    // rootfs-only entry is the pre-crun shape that silently produced a
    // container with no `PATH`, and `start` now refuses it outright (#222).
    publish_fixture_image(&paths, FIXTURE_IMAGE_DIGEST, "ubuntu:22.04");
    (dir, paths)
}

/// The `PATH` the fixture image DECLARES. Deliberately not a plausible default:
/// if it shows up in a generated bundle, it can only have come from the image
/// config, never from a guess (#222).
pub(crate) const FIXTURE_IMAGE_PATH: &str = "/image/declared/bin:/usr/bin:/bin";

/// Publish a COMPLETE image cache entry for `digest`: `rootfs.erofs` **and**
/// `config.json`.
///
/// Real registry images always carry a runtime config, so fixtures must too.
/// A rootfs-only entry is the pre-crun cache shape that silently produced a
/// container with no `PATH` (#222) — tests that boot from one are testing a
/// state `ensure_image` no longer leaves behind.
pub(crate) fn publish_fixture_image(paths: &Paths, digest: &str, image_ref: &str) {
    let store = crate::image::ImageStore::new(paths);
    if store.is_complete(digest) {
        return;
    }
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}},
            "config":{{"Env":["{FIXTURE_IMAGE_PATH}"]}}}}"#,
        FIXTURE_IMAGE_PATH = format_args!("PATH={FIXTURE_IMAGE_PATH}")
    );
    store
        .publish(digest, |staging| {
            std::fs::write(staging.join("rootfs.erofs"), b"erofs")?;
            std::fs::write(staging.join("ref.txt"), image_ref)?;
            std::fs::write(staging.join("config.json"), &config)?;
            Ok(())
        })
        .unwrap();
}

/// Spawn a real detached `sleep 30` and return its identity.
pub(crate) fn spawn_sleep(dir: &Path) -> PidIdentity {
    procmgr::spawn_detached(
        &CommandSpec {
            argv: vec!["sleep".into(), "30".into()],
        },
        &dir.join("sleep.log"),
    )
    .unwrap()
}

/// Poll until `id` is dead (or fail after 2 s).
pub(crate) fn wait_dead(id: &PidIdentity) -> bool {
    (0..40).any(|_| {
        if !procmgr::pid_alive(id) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
        !procmgr::pid_alive(id)
    })
}

pub(crate) fn write_state(paths: &Paths, name: &str, vmm: PidIdentity) {
    write_state_with_run_dir(paths, name, vmm, None);
}

/// Like [`write_state`], but lets the caller pin `RunState.run_dir`
/// explicitly — needed by tests that overwrite a real post-`Start`
/// `state.json` (which always records `Some(paths.run_dir(name))`, per
/// `record_run_state`) and must not accidentally clobber it back to the
/// legacy-adoption `None` sentinel.
pub(crate) fn write_state_with_run_dir(
    paths: &Paths,
    name: &str,
    vmm: PidIdentity,
    run_dir: Option<std::path::PathBuf>,
) {
    save_json(
        &paths.sandbox_dir(name).join(STATE_FILE),
        &RunState {
            vmm_pid: vmm,
            sidecar_pids: vec![],
            started_unix_ms: 0,
            confinement: None,
            run_dir,
            user_fallback: None,
            usb_kernel: false,
            vnc: false,
        },
    )
    .unwrap();
}

pub(crate) fn write_state_with_sidecars(
    paths: &Paths,
    name: &str,
    vmm: PidIdentity,
    sidecars: Vec<(String, PidIdentity)>,
) {
    save_json(
        &paths.sandbox_dir(name).join(STATE_FILE),
        &RunState {
            vmm_pid: vmm,
            sidecar_pids: sidecars,
            started_unix_ms: 0,
            confinement: None,
            run_dir: None,
            user_fallback: None,
            usb_kernel: false,
            vnc: false,
        },
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// MockDriver / MockHandle
// ---------------------------------------------------------------------------

pub(crate) struct MockDriver {
    pub(crate) captured: Mutex<Option<VmSpec>>,
    health_delay: Duration,
    answer_health: bool,
    omit_vmm_pid: bool,
    /// `killed` flag of the most recently launched handle.
    pub(crate) last_killed: Mutex<Option<Arc<AtomicBool>>>,
}

impl MockDriver {
    pub(crate) fn new() -> Self {
        Self::with(Duration::ZERO, true)
    }

    pub(crate) fn with(health_delay: Duration, answer_health: bool) -> Self {
        Self {
            captured: Mutex::new(None),
            health_delay,
            answer_health,
            omit_vmm_pid: false,
            last_killed: Mutex::new(None),
        }
    }

    /// A driver whose handle reports no "vmm" pid (driver bug simulation).
    pub(crate) fn without_vmm_pid() -> Self {
        Self {
            omit_vmm_pid: true,
            ..Self::new()
        }
    }
}

impl VmmDriver for MockDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>> {
        *self.captured.lock().unwrap() = Some(spec.clone());
        let killed = Arc::new(AtomicBool::new(false));
        *self.last_killed.lock().unwrap() = Some(killed.clone());
        let pids = if self.omit_vmm_pid {
            vec![]
        } else {
            vec![("vmm".to_string(), live_identity())]
        };
        Ok(Box::new(MockHandle {
            alive: Arc::new(AtomicBool::new(true)),
            killed,
            health_delay: self.health_delay,
            answer_health: self.answer_health,
            pids,
        }))
    }
}

pub(crate) struct MockHandle {
    alive: Arc<AtomicBool>,
    killed: Arc<AtomicBool>,
    health_delay: Duration,
    answer_health: bool,
    pids: Vec<(String, PidIdentity)>,
}

impl VmHandle for MockHandle {
    fn connect(&self, _port: u32) -> anyhow::Result<Box<dyn IoStream>> {
        if !self.answer_health {
            anyhow::bail!("connection refused (mock)");
        }
        let (client, server) = UdsStream::pair()?;
        let delay = self.health_delay;
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            // fake izba-init: answer ONE request then close
            let mut s = server;
            if let Ok(req) = read_frame::<_, Request>(&mut s) {
                let resp = match req {
                    Request::Health => Response::Health(HealthInfo {
                        version: "test".into(),
                        uptime_ms: 1,
                        container: None,
                    }),
                    _ => Response::Ok,
                };
                let _ = write_frame(&mut s, &resp);
            }
        });
        Ok(Box::new(client))
    }

    fn pids(&self) -> Vec<(String, PidIdentity)> {
        self.pids.clone()
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn confinement(&self) -> crate::procmgr::ConfinementStatus {
        crate::procmgr::ConfinementStatus::degraded("mock handle")
    }

    fn kill(&mut self) -> anyhow::Result<()> {
        self.alive.store(false, Ordering::SeqCst);
        self.killed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fake connectors
// ---------------------------------------------------------------------------

/// Socketpair-backed fake of izba-init for post-start invocations.
///
/// Each connection answers exactly one request. Received requests are
/// appended to `log`. When a `Shutdown` arrives and `kill_on_shutdown` is
/// set, the given process is killed — simulating the guest powering off.
pub(crate) fn fake_connector(
    log: Arc<Mutex<Vec<Request>>>,
    kill_on_shutdown: Option<PidIdentity>,
) -> impl Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> {
    move |_paths: &Paths, _name: &str| {
        let (client, server) = UdsStream::pair()?;
        let log = log.clone();
        let kill_on_shutdown = kill_on_shutdown.clone();
        std::thread::spawn(move || {
            let mut s = server;
            if let Ok(req) = read_frame::<_, Request>(&mut s) {
                let resp = match req {
                    Request::Health => Response::Health(HealthInfo {
                        version: "test".into(),
                        uptime_ms: 1,
                        // A reachable fake guest reports a live container, so
                        // tests can assert the host folds the probed state.
                        container: Some(izba_proto::ContainerState::Running),
                    }),
                    Request::Shutdown => {
                        if let Some(id) = &kill_on_shutdown {
                            let _ = procmgr::kill_pid(id);
                        }
                        Response::Ok
                    }
                    // A reachable fake guest answers Stats too, so
                    // `probe_guest_stats`/`handle_stats` tests can assert the
                    // host actually folds a real Response::Stats(GuestStats)
                    // reply (not just the None-on-failure path).
                    Request::Stats => Response::Stats(fake_guest_stats()),
                    _ => Response::Ok,
                };
                log.lock().unwrap().push(req);
                let _ = write_frame(&mut s, &resp);
            }
        });
        Ok(Box::new(client) as Box<dyn IoStream>)
    }
}

/// Connector to a guest that accepts the request but never replies —
/// simulates a wedged-but-accepting control plane.
pub(crate) fn hanging_connector() -> impl Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> {
    |_paths: &Paths, _name: &str| {
        let (client, server) = UdsStream::pair()?;
        std::thread::spawn(move || {
            let mut s = server;
            let _ = read_frame::<_, Request>(&mut s);
            // Keep the socket open so the client cannot see EOF.
            std::thread::sleep(Duration::from_secs(10));
        });
        Ok(Box::new(client) as Box<dyn IoStream>)
    }
}

/// Minimal but non-degenerate `GuestStats` fixture for `fake_connector`'s
/// `Request::Stats` reply. `process_count` is a distinguishable marker field
/// so tests can assert it survives the probe→sanitize→wire round trip.
pub(crate) fn fake_guest_stats() -> GuestStats {
    GuestStats {
        processes: vec![],
        process_count: 7,
        load1_centi: 0,
        load5_centi: 0,
        load15_centi: 0,
        mem_total_kb: 0,
        mem_available_kb: 0,
        mounts: vec![],
        docker: None,
        container: None,
    }
}

pub(crate) fn count_shutdowns(log: &Arc<Mutex<Vec<Request>>>) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|r| matches!(r, Request::Shutdown))
        .count()
}

#[cfg(test)]
mod port_tests {
    use super::*;

    #[test]
    fn a_reserved_port_is_outside_the_kernels_auto_assign_range() {
        // The whole guarantee in one assertion: if a reserved port could also
        // be handed to a `bind(:0)` somewhere else in this binary, the flake
        // this exists to kill is back.
        let who = "a_reserved_port_is_outside_the_kernels_auto_assign_range";
        if auto_assign_floor() <= RESERVED_LO {
            // This host's ephemeral range covers the whole reserved window, so
            // `reserve_port` is on its probe fallback and cannot promise this.
            // Say so rather than assert something the fallback never claimed.
            eprintln!("SKIP {who}: ephemeral range leaves no reservable window");
            return;
        }
        let Some(port) = reserve_port() else {
            eprintln!("SKIP {who}: bind denied");
            return;
        };
        assert!(
            port <= auto_assign_floor(),
            "reserved {port} is inside the auto-assign range (floor {})",
            auto_assign_floor()
        );
    }

    #[test]
    fn reserved_ports_are_never_handed_out_twice() {
        // The cursor's job. Two callers racing for the same port would put the
        // collision straight back inside our own helper.
        let Some(first) = reserve_port() else {
            eprintln!("SKIP reserved_ports_are_never_handed_out_twice: bind denied");
            return;
        };
        let mut seen = vec![first];
        for _ in 0..32 {
            let p = reserve_port().expect("bind worked a moment ago");
            assert!(!seen.contains(&p), "port {p} handed out twice");
            seen.push(p);
        }
    }
}
