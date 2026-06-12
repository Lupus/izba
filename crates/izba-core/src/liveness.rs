use crate::state::{PidIdentity, RunState};

pub trait Probes {
    /// Returns `true` iff the pid exists **and** its starttime matches.
    fn pid_alive(&self, id: &PidIdentity) -> bool;
    /// Returns `true` iff the control socket connects and the health check
    /// replies within a short timeout.
    fn control_answers(&self) -> bool;
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

/// Assess the liveness of a sandbox.
///
/// Precedence:
/// 1. `run == None`                        → Stopped
/// 2. vmm pid dead                         → Stopped
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
        return Liveness::Stopped;
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
    }

    impl Probes for FakeProbes {
        fn pid_alive(&self, id: &PidIdentity) -> bool {
            self.alive_pids.contains(id)
        }

        fn control_answers(&self) -> bool {
            self.control
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
        };
        assert_eq!(assess(Some(&run), &p), Liveness::Stopped);
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
