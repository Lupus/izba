//! Cross-platform description of host-side process confinement and the
//! confinement actually achieved at spawn (surfaced in health). The Windows
//! realisation lives in `jail_windows.rs`; on other platforms the policy is
//! inert (the VMM already runs as the invoking user and the Linux jailer is a
//! separate work item).
use serde::{Deserialize, Serialize};

/// Restricted-token shape. Names mirror Chromium `TokenLevel` (see the design
/// reference) but only the two WHP-compatible levels are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenLevel {
    /// Restricting SIDs = {Users, Everyone, RESTRICTED, logon}; everything else
    /// deny-only. The default — tight but still opens `\Device\VidExo`.
    Limited,
    /// Adds Interactive/Local/Authenticated-Users/User to the restricting set —
    /// the fallback if a host's WHP device SD is stricter than `Limited` allows.
    RestrictedNonAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Low,
    Medium,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementPolicy {
    pub token: TokenLevel,
    pub integrity: IntegrityLevel,
    pub drop_all_privileges: bool,
    /// Best-effort resource job. NEVER kill-on-close (izba daemonless contract).
    pub job_memory_max_mb: Option<u64>,
    pub kill_on_close: bool,
    /// OpenVMM forks an `openvmm vm` worker; the child-process block must permit
    /// it, so we never set ActiveProcessLimit=1 / CHILD_PROCESS_RESTRICTED hard.
    pub allow_worker_child: bool,
}

impl ConfinementPolicy {
    /// The policy applied to the OpenVMM process. See the design spec §Decisions.
    pub fn vmm_default() -> Self {
        Self {
            token: TokenLevel::Limited,
            integrity: IntegrityLevel::Low,
            drop_all_privileges: true,
            job_memory_max_mb: None, // sized by the VMM driver from guest mem
            kill_on_close: false,
            allow_worker_child: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfinementMode {
    /// Full policy applied (restricted token + IL + job + mitigations).
    Restricted,
    /// Token/IL applied but the resource job could not be created.
    TokenOnly,
    /// No confinement — the host could not run WHP under a restricted token, or
    /// the platform has no jailer. The VMM ran as the invoking user.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementStatus {
    pub mode: ConfinementMode,
    pub reason: String,
}

impl ConfinementStatus {
    pub fn applied(p: &ConfinementPolicy) -> Self {
        let token = match p.token {
            TokenLevel::Limited => "restricted(limited)",
            TokenLevel::RestrictedNonAdmin => "restricted(non-admin)",
        };
        let il = match p.integrity {
            IntegrityLevel::Low => "low-il",
            IntegrityLevel::Medium => "medium-il",
        };
        Self {
            mode: ConfinementMode::Restricted,
            reason: format!("{token}+{il}+job"),
        }
    }
    pub fn degraded(reason: &str) -> Self {
        Self {
            mode: ConfinementMode::None,
            reason: reason.to_string(),
        }
    }
    pub fn summary(&self) -> String {
        match self.mode {
            ConfinementMode::Restricted => format!("confined: {}", self.reason),
            ConfinementMode::TokenOnly => format!("confined (token only): {}", self.reason),
            ConfinementMode::None => format!("UNCONFINED — {}", self.reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmm_default_policy_is_restricted_low_il() {
        let p = ConfinementPolicy::vmm_default();
        assert_eq!(p.token, TokenLevel::Limited);
        assert_eq!(p.integrity, IntegrityLevel::Low);
        assert!(p.drop_all_privileges);
        assert!(
            !p.kill_on_close,
            "izba contract: VMM must outlive the broker"
        );
        assert!(
            p.allow_worker_child,
            "OpenVMM spawns an `openvmm vm` worker"
        );
    }

    #[test]
    fn status_renders_human_reason() {
        let ok = ConfinementStatus::applied(&ConfinementPolicy::vmm_default());
        assert!(ok.summary().contains("restricted"));
        assert!(ok.summary().contains("low-il"));
        let none = ConfinementStatus::degraded("WHP unavailable under restricted token");
        assert_eq!(none.mode, ConfinementMode::None);
        assert!(none.summary().contains("WHP unavailable"));
    }
}
