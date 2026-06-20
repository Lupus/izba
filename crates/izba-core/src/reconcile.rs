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

    // sandboxes snapshot filled in A2; empty for now keeps the type stable.
    let sandboxes = Vec::new();
    let _ = (assess, load_json::<RunState>, STATE_FILE); // referenced in A2
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
        assert!(report.violations.iter().any(|v| v.kind
            == ViolationKind::ListMismatch
            && v.sandbox.as_deref() == Some("ghost")));
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
        assert!(report.violations.iter().any(|v| v.kind
            == ViolationKind::ListMismatch
            && v.sandbox.as_deref() == Some("orphan")));
    }
}
