//! Read-only snapshot-consistency reconciler: cross-checks the daemon's view
//! of sandboxes against on-disk state and independent pid liveness. Never
//! mutates daemon or disk state. Pure logic + `Probes` injection so it is
//! fully unit-testable with `FakeProbes` and temp dirs. Cross-platform: pid
//! liveness comes from `crate::procmgr::pid_alive` (via `Probes`), never raw
//! `/proc` parsing, so it compiles for the windows-gnu cross gates.

use crate::daemon::proto::SandboxSummary;
use crate::liveness::{assess, Probes};
use crate::paths::Paths;
use crate::state::{load_json, PidIdentity, RunState, STATE_FILE};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    ListMismatch,
    DiskLiveMismatch,
    OrphanRelay,
    OrphanVolume,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub kind: ViolationKind,
    pub sandbox: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSnapshot {
    pub name: String,
    pub status_daemon: Option<String>,
    pub status_disk: String,
    pub vmm: Option<PidIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub violations: Vec<Violation>,
    pub sandboxes: Vec<SandboxSnapshot>,
}

/// Names of sandbox dirs on disk (sorted).
fn disk_names(paths: &Paths) -> anyhow::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let dir = paths.sandboxes_dir();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    out.insert(name.to_string());
                }
            }
        }
    }
    Ok(out)
}

pub fn reconcile(
    paths: &Paths,
    daemon_view: Option<&[SandboxSummary]>,
    probes: &dyn Probes,
) -> anyhow::Result<ReconcileReport> {
    let mut violations = Vec::new();
    let disk = disk_names(paths)?;
    let daemon: BTreeSet<String> = daemon_view
        .map(|v| v.iter().map(|s| s.name.clone()).collect())
        .unwrap_or_default();

    for name in daemon.difference(&disk) {
        violations.push(Violation {
            kind: ViolationKind::ListMismatch,
            sandbox: Some(name.clone()),
            detail: "daemon lists a sandbox with no on-disk directory".into(),
        });
    }
    for name in disk.difference(&daemon) {
        violations.push(Violation {
            kind: ViolationKind::ListMismatch,
            sandbox: Some(name.clone()),
            detail: "on-disk sandbox directory not reported by daemon list".into(),
        });
    }

    let mut sandboxes = Vec::new();
    for name in &disk {
        let state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))?;
        let disk_status = assess(state.as_ref(), probes);
        let status_disk = disk_status.describe();
        let status_daemon = daemon_view
            .and_then(|v| v.iter().find(|s| &s.name == name))
            .map(|s| s.status.clone());

        // Lenient: flag only the unambiguous alive⇄stopped disagreement.
        if let Some(d) = &status_daemon {
            let daemon_thinks_alive = d != "stopped";
            let disk_thinks_alive = !matches!(disk_status, crate::liveness::Liveness::Stopped);
            if daemon_thinks_alive != disk_thinks_alive {
                violations.push(Violation {
                    kind: ViolationKind::DiskLiveMismatch,
                    sandbox: Some(name.clone()),
                    detail: format!(
                        "daemon status {d:?} but disk/pid assessment is {status_disk:?}"
                    ),
                });
            }
        }
        sandboxes.push(SandboxSnapshot {
            name: name.clone(),
            status_daemon,
            status_disk,
            vmm: state.as_ref().map(|r| r.vmm_pid.clone()),
        });
    }

    use crate::state::{SandboxConfig, CONFIG_FILE};
    use std::collections::HashSet;

    // Orphan LEGACY relays (NEW-1): ports.json is read via the daemon's
    // schema-tolerant loader — the daemon has written `Vec<PortRule>` since the
    // thread-relay model landed, and the old strict `Vec<PortRecord>` read here
    // errored on every current-format file (false-empty snapshot). Thread
    // relays persist no pid, so relay liveness is not observable from disk;
    // the only remaining relay check is a LEGACY pre-daemon relay process that
    // survived its migration.
    for name in &disk {
        let (_rules, legacy_pids) = crate::daemon::relays::load_rules_migrating(paths, name)?;
        for pid in legacy_pids {
            if probes.pid_alive(&pid) {
                violations.push(Violation {
                    kind: ViolationKind::OrphanRelay,
                    sandbox: Some(name.clone()),
                    detail: format!(
                        "legacy relay process (pid {}) still alive; relays are daemon threads now",
                        pid.pid
                    ),
                });
            }
        }
    }

    // Orphan (unreferenced) named volume images — informational only.
    let mut referenced: HashSet<String> = HashSet::new();
    for name in &disk {
        if let Some(cfg) = load_json::<SandboxConfig>(&paths.sandbox_dir(name).join(CONFIG_FILE))? {
            for vol in cfg.volumes {
                if let Some(n) = vol.name {
                    referenced.insert(n);
                }
            }
        }
    }
    let vdir = paths.volumes_dir();
    if vdir.is_dir() {
        for entry in std::fs::read_dir(&vdir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let Some(stem) = fname.to_str().and_then(|s| s.strip_suffix(".img")) else {
                continue;
            };
            if !referenced.contains(stem) {
                violations.push(Violation {
                    kind: ViolationKind::OrphanVolume,
                    sandbox: None,
                    detail: format!(
                        "informational: named volume '{stem}' is unreferenced (persistent volumes survive rm)"
                    ),
                });
            }
        }
    }

    Ok(ReconcileReport {
        violations,
        sandboxes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::SandboxSummary;
    use crate::liveness::Probes;
    use crate::state::PidIdentity;
    use crate::testutil::{dead_identity, live_identity, test_paths, write_state};

    struct FakeProbes {
        alive: Vec<PidIdentity>,
        control: bool,
    }
    impl Probes for FakeProbes {
        fn pid_alive(&self, id: &PidIdentity) -> bool {
            self.alive.contains(id)
        }
        fn control_answers(&self) -> bool {
            self.control
        }
    }
    fn summary(name: &str, status: &str) -> SandboxSummary {
        SandboxSummary {
            name: name.into(),
            image_ref: "alpine:3.20".into(),
            status: status.into(),
        }
    }

    #[test]
    fn daemon_lists_sandbox_with_no_dir_is_list_mismatch() {
        let (_tmp, paths) = test_paths();
        // daemon claims "ghost" exists; nothing on disk
        let view = vec![summary("ghost", "running")];
        let probes = FakeProbes {
            alive: vec![],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(report.violations.iter().any(
            |v| v.kind == ViolationKind::ListMismatch && v.sandbox.as_deref() == Some("ghost")
        ));
    }

    #[test]
    fn disk_dir_not_in_daemon_list_is_list_mismatch() {
        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("orphan")).unwrap();
        let view: Vec<SandboxSummary> = vec![]; // daemon lists nothing
        let probes = FakeProbes {
            alive: vec![],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(report.violations.iter().any(
            |v| v.kind == ViolationKind::ListMismatch && v.sandbox.as_deref() == Some("orphan")
        ));
    }

    #[test]
    fn daemon_running_but_vmm_pid_dead_is_disk_live_mismatch() {
        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        write_state(&paths, "box", dead_identity()); // state.json references a dead pid
        let view = vec![summary("box", "running")]; // daemon thinks it's running
        let probes = FakeProbes {
            alive: vec![],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(report
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::DiskLiveMismatch
                && v.sandbox.as_deref() == Some("box")));
        let snap = report.sandboxes.iter().find(|s| s.name == "box").unwrap();
        assert_eq!(snap.status_daemon.as_deref(), Some("running"));
        assert_eq!(snap.status_disk, "stopped");
    }

    #[test]
    fn daemon_running_and_vmm_alive_is_clean() {
        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(
            report.violations.is_empty(),
            "unexpected: {:?}",
            report.violations
        );
    }

    /// NEW-1 (dogfood 2026-07-09): the daemon writes ports.json as the CURRENT
    /// schema (`Vec<PortRule>`, daemon/relays.rs save_rules). Reconcile used to
    /// read the legacy `Vec<PortRecord>` and errored "missing field `rule`" on
    /// every current-format file, returning a false-empty snapshot.
    #[test]
    fn current_schema_ports_json_reconciles_cleanly() {
        use crate::state::{save_json, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let rules = vec![PortRule {
            bind: Ipv4Addr::LOCALHOST,
            host_port: 8080,
            guest_port: 80,
        }];
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &rules).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes)
            .expect("current-schema ports.json must not break reconcile");
        assert!(
            report.violations.is_empty(),
            "clean current-schema state must have no violations: {:?}",
            report.violations
        );
        assert_eq!(report.sandboxes.len(), 1, "snapshot must not be empty");
    }

    /// A legacy-schema ports.json whose relay process is STILL ALIVE is an
    /// anomaly (relays are daemon threads now) — flagged as OrphanRelay.
    #[test]
    fn alive_legacy_relay_pid_is_orphan_relay() {
        use crate::state::{save_json, PortRecord, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let relay = PidIdentity {
            pid: vmm.pid + 1,
            starttime: 42,
        };
        let rec = PortRecord {
            rule: PortRule {
                bind: Ipv4Addr::LOCALHOST,
                host_port: 8080,
                guest_port: 80,
            },
            relay: relay.clone(),
        };
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &vec![rec]).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm, relay],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        let v = report
            .violations
            .iter()
            .find(|v| v.kind == ViolationKind::OrphanRelay)
            .expect("alive legacy relay must be flagged");
        assert!(v.detail.contains("legacy relay"), "got: {}", v.detail);
    }

    /// A DEAD legacy relay pid is the normal migrated state — no violation.
    /// (Replaces the deleted relay_dead_while_sandbox_running_is_orphan_relay:
    /// thread relays persist no pid, so "relay dead while sandbox alive" is
    /// no longer observable from disk.)
    #[test]
    fn dead_legacy_relay_pid_is_not_flagged() {
        use crate::state::{save_json, PortRecord, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let rec = PortRecord {
            rule: PortRule {
                bind: Ipv4Addr::LOCALHOST,
                host_port: 8080,
                guest_port: 80,
            },
            relay: dead_identity(),
        };
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &vec![rec]).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(
            !report
                .violations
                .iter()
                .any(|v| v.kind == ViolationKind::OrphanRelay),
            "dead legacy relay is the normal migrated state: {:?}",
            report.violations
        );
    }

    #[test]
    fn unreferenced_named_volume_is_informational_orphan_volume() {
        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.volumes_dir()).unwrap();
        std::fs::write(paths.volume_image("leftover"), b"x").unwrap();
        let view: Vec<SandboxSummary> = vec![];
        let probes = FakeProbes {
            alive: vec![],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        let v = report
            .violations
            .iter()
            .find(|v| v.kind == ViolationKind::OrphanVolume)
            .unwrap();
        assert!(v.detail.contains("informational"));
    }
}
