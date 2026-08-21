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

pub(crate) fn test_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path().join("izba"));
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
