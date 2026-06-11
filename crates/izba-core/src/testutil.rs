//! Shared test helpers for izba-core. This module is `#[cfg(test)]` and
//! `pub(crate)` so helpers can be reused across multiple test modules without
//! duplicating private functions.

use std::sync::{Arc, Mutex};

use izba_proto::{read_frame, write_frame, HealthInfo, Request, Response};

use crate::paths::Paths;
use crate::procmgr;
use crate::state::{save_json, PidIdentity, RunState, STATE_FILE};
use crate::vmm::{IoStream, UdsStream};

/// Identity of the current (test) process — alive for the test's duration.
pub fn live_identity() -> PidIdentity {
    let pid = std::process::id();
    PidIdentity {
        pid,
        starttime: procmgr::proc_starttime(pid).unwrap(),
    }
}

pub fn test_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path().join("izba"));
    (dir, paths)
}

pub fn write_state(paths: &Paths, name: &str, vmm: PidIdentity) {
    save_json(
        &paths.sandbox_dir(name).join(STATE_FILE),
        &RunState {
            vmm_pid: vmm,
            sidecar_pids: vec![],
            started_unix_ms: 0,
        },
    )
    .unwrap();
}

/// Socketpair-backed fake of izba-init for post-start invocations.
///
/// Each connection answers exactly one request. Received requests are
/// appended to `log`. When a `Shutdown` arrives and `kill_on_shutdown` is
/// set, the given process is killed — simulating the guest powering off.
pub fn fake_connector(
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
                    }),
                    Request::Shutdown => {
                        if let Some(id) = &kill_on_shutdown {
                            let _ = procmgr::kill_pid(id);
                        }
                        Response::Ok
                    }
                    _ => Response::Ok,
                };
                log.lock().unwrap().push(req);
                let _ = write_frame(&mut s, &resp);
            }
        });
        Ok(Box::new(client) as Box<dyn IoStream>)
    }
}
