use crate::state::{PidIdentity, RunState};

pub trait Probes {
    /// Returns `true` iff the pid exists **and** its starttime matches.
    fn pid_alive(&self, id: &PidIdentity) -> bool;
    /// Returns `true` iff the control socket connects and the health check
    /// replies within a short timeout.
    fn control_answers(&self) -> bool;
    /// Pids of the VMM process tree rooted at `id` (the root and its worker
    /// children) that have NOT finished teardown and so still hold the
    /// sandbox's disks — see `procmgr::tree_survivors` (#319). The default is
    /// the pre-#319 reading, "the root is the whole tree, alive iff
    /// `pid_alive`", so fakes that model only pid liveness are unchanged.
    fn tree_survivors(&self, id: &PidIdentity) -> Vec<u32> {
        if self.pid_alive(id) {
            vec![id.pid]
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Liveness {
    Running,
    Degraded(String),
    Stopped,
}

impl Liveness {
    /// Human/status string shared by `izba ls` and the daemon's List/Status.
    pub fn describe(&self) -> String {
        match self {
            Liveness::Running => "running".to_string(),
            Liveness::Degraded(reason) => format!("degraded ({reason})"),
            Liveness::Stopped => "stopped".to_string(),
        }
    }
}

/// The `Degraded` reason for a VMM whose launcher is gone while a process of
/// its tree still holds the sandbox's disks (#319). Rendered inside
/// `degraded (…)`, so it must never end with `)` — the desktop app strips
/// exactly one trailing paren (`app/src-tauri/src/views.rs::parse_state`).
pub fn stuck_teardown_reason(survivors: &[u32]) -> String {
    let noun = if survivors.len() == 1 {
        "process"
    } else {
        "processes"
    };
    let pids: Vec<String> = survivors.iter().map(u32::to_string).collect();
    format!(
        "vmm {noun} {} terminated but not torn down, disks still held",
        pids.join(", ")
    )
}

/// Assess the liveness of a sandbox.
///
/// Precedence:
/// 1. `run == None`                        → Stopped
/// 2. vmm pid dead, nothing of its tree survives → Stopped
///    2b. vmm pid dead but a process of its tree still holds its resources
///    → Degraded("vmm process <pid> terminated but not torn down, disks still
///    held") (#319) — never Stopped, which would let the stale-state reaper
///    delete state.json and a later start boot against held disks
/// 3. any sidecar dead                     → Degraded("sidecar <role> died")
///    (sidecar death takes precedence over control unresponsiveness)
/// 4. control not answering                → Degraded("control plane unresponsive")
/// 5. all alive + control answers          → Running
pub fn assess(run: Option<&RunState>, probes: &dyn Probes) -> Liveness {
    let run = match run {
        None => return Liveness::Stopped,
        Some(r) => r,
    };

    if !probes.pid_alive(&run.vmm_pid) {
        let survivors = probes.tree_survivors(&run.vmm_pid);
        if survivors.is_empty() {
            return Liveness::Stopped;
        }
        return Liveness::Degraded(stuck_teardown_reason(&survivors));
    }

    for (role, id) in &run.sidecar_pids {
        if !probes.pid_alive(id) {
            return Liveness::Degraded(format!("sidecar {role} died"));
        }
    }

    if !probes.control_answers() {
        return Liveness::Degraded("control plane unresponsive".to_string());
    }

    Liveness::Running
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RunState;

    // -----------------------------------------------------------------------
    // Fake Probes
    //
    // pid_alive looks up the PidIdentity in a simple allow-list of alive pids.
    // We build the alive list when constructing FakeProbes so each test is
    // self-contained.
    // -----------------------------------------------------------------------

    struct FakeProbes {
        alive_pids: Vec<PidIdentity>,
        control: bool,
        /// What `tree_survivors` answers for ANY id — the fake models the
        /// stuck-teardown fact directly (#319).
        survivors: Vec<u32>,
    }

    impl Probes for FakeProbes {
        fn pid_alive(&self, id: &PidIdentity) -> bool {
            self.alive_pids.contains(id)
        }

        fn control_answers(&self) -> bool {
            self.control
        }

        fn tree_survivors(&self, _id: &PidIdentity) -> Vec<u32> {
            self.survivors.clone()
        }
    }

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    fn vmm_id() -> PidIdentity {
        PidIdentity {
            pid: 1,
            starttime: 100,
        }
    }

    fn sidecar_id(idx: u32) -> PidIdentity {
        PidIdentity {
            pid: 100 + idx,
            starttime: (idx + 1) as u64,
        }
    }

    fn run_with_sidecars(roles: &[&str]) -> RunState {
        RunState {
            vmm_pid: vmm_id(),
            sidecar_pids: roles
                .iter()
                .enumerate()
                .map(|(i, r)| (r.to_string(), sidecar_id(i as u32)))
                .collect(),
            started_unix_ms: 0,
            confinement: None,
            run_dir: None,
            user_fallback: None,
            usb_kernel: false,
            vnc: false,
            lockdown_account: None,
        }
    }

    // -----------------------------------------------------------------------
    // Rule 1: no RunState → Stopped
    // -----------------------------------------------------------------------
    #[test]
    fn no_run_state_is_stopped() {
        let p = FakeProbes {
            alive_pids: vec![vmm_id()],
            control: true,
            survivors: vec![],
        };
        assert_eq!(assess(None, &p), Liveness::Stopped);
    }

    // -----------------------------------------------------------------------
    // Rule 2: vmm pid dead → Stopped (regardless of sidecars / control)
    // -----------------------------------------------------------------------
    #[test]
    fn vmm_dead_is_stopped() {
        let run = run_with_sidecars(&["virtiofsd:workspace"]);
        // vmm NOT in alive list; sidecar is alive; control answers
        let p = FakeProbes {
            alive_pids: vec![sidecar_id(0)],
            control: true,
            survivors: vec![],
        };
        assert_eq!(assess(Some(&run), &p), Liveness::Stopped);
    }

    // -----------------------------------------------------------------------
    // Rule 2b (#319): vmm pid dead but a process of its tree still holds its
    // resources → Degraded, never Stopped. `Stopped` is what lets the daemon's
    // stale-state reaper delete state.json and `start` boot against the disks
    // that process still holds.
    // -----------------------------------------------------------------------
    #[test]
    fn vmm_dead_with_a_surviving_tree_is_degraded_not_stopped() {
        let run = run_with_sidecars(&[]);
        let p = FakeProbes {
            alive_pids: vec![],
            control: false,
            survivors: vec![30620],
        };
        match assess(Some(&run), &p) {
            Liveness::Degraded(reason) => {
                assert!(reason.contains("30620"), "names the pid: {reason}");
                assert!(reason.contains("disks still held"), "{reason}");
                assert!(reason.contains("not torn down"), "{reason}");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    /// The reason is rendered as `degraded (<reason>)` and the desktop app
    /// strips exactly one trailing `)` — a reason ending in `)` would lose a
    /// character. Pin it for one and for several pids.
    #[test]
    fn stuck_teardown_reason_never_ends_with_a_paren() {
        for pids in [&[30620u32][..], &[29588, 30620][..]] {
            let r = stuck_teardown_reason(pids);
            assert!(!r.ends_with(')'), "{r}");
            assert!(!r.is_empty());
        }
        assert_eq!(
            stuck_teardown_reason(&[30620]),
            "vmm process 30620 terminated but not torn down, disks still held"
        );
        assert_eq!(
            stuck_teardown_reason(&[29588, 30620]),
            "vmm processes 29588, 30620 terminated but not torn down, disks still held"
        );
    }

    /// Fakes that model only pid liveness (reconcile's, the CLI's) get the
    /// pre-#319 semantics from the trait default: the root is the whole tree.
    #[test]
    fn default_tree_survivors_is_the_root_while_alive() {
        struct PidOnly(Vec<PidIdentity>);
        impl Probes for PidOnly {
            fn pid_alive(&self, id: &PidIdentity) -> bool {
                self.0.contains(id)
            }
            fn control_answers(&self) -> bool {
                true
            }
        }
        let alive = PidOnly(vec![vmm_id()]);
        assert_eq!(alive.tree_survivors(&vmm_id()), vec![vmm_id().pid]);
        let dead = PidOnly(vec![]);
        assert!(dead.tree_survivors(&vmm_id()).is_empty());
        // And through assess: a dead root with the default is plain Stopped.
        let run = run_with_sidecars(&[]);
        assert_eq!(assess(Some(&run), &dead), Liveness::Stopped);
    }

    // -----------------------------------------------------------------------
    // Rule 3: vmm alive + all sidecars alive + control answers → Running
    // -----------------------------------------------------------------------
    #[test]
    fn all_alive_is_running() {
        let run = run_with_sidecars(&["virtiofsd:workspace", "virtiofsd:cache"]);
        let p = FakeProbes {
            alive_pids: vec![vmm_id(), sidecar_id(0), sidecar_id(1)],
            control: true,
            survivors: vec![],
        };
        assert_eq!(assess(Some(&run), &p), Liveness::Running);
    }

    // -----------------------------------------------------------------------
    // Rule 4: vmm alive + any sidecar dead → Degraded (beats control check)
    // -----------------------------------------------------------------------
    #[test]
    fn sidecar_dead_is_degraded() {
        let run = run_with_sidecars(&["virtiofsd:cache", "virtiofsd:workspace"]);
        // virtiofsd:cache alive, virtiofsd:workspace dead, control also down —
        // sidecar wins
        let p = FakeProbes {
            alive_pids: vec![vmm_id(), sidecar_id(0)],
            control: false,
            survivors: vec![],
        };
        assert_eq!(
            assess(Some(&run), &p),
            Liveness::Degraded("sidecar virtiofsd:workspace died".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Rule 5: vmm alive + sidecars alive + control not answering → Degraded
    // -----------------------------------------------------------------------
    #[test]
    fn control_unresponsive_is_degraded() {
        let run = run_with_sidecars(&["virtiofsd:workspace"]);
        let p = FakeProbes {
            alive_pids: vec![vmm_id(), sidecar_id(0)],
            control: false,
            survivors: vec![],
        };
        assert_eq!(
            assess(Some(&run), &p),
            Liveness::Degraded("control plane unresponsive".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // describe() + Clone
    // -----------------------------------------------------------------------
    #[test]
    fn describe_strings() {
        assert_eq!(Liveness::Running.describe(), "running");
        assert_eq!(
            Liveness::Degraded("sidecar virtiofsd:workspace died".into()).describe(),
            "degraded (sidecar virtiofsd:workspace died)"
        );
        assert_eq!(Liveness::Stopped.describe(), "stopped");
        // Clone is required by the daemon registry.
        let l = Liveness::Degraded("x".into());
        assert_eq!(l.clone(), l);
    }
}
