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

/// NOTE: child-process creation is **not** blocked. OpenVMM forks an
/// `openvmm vm` worker, and the only Windows primitive for blocking children
/// (`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY =
/// PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) is all-or-nothing — it has no
/// per-child exception, so it cannot be applied without breaking the worker.
/// Children DO inherit the restricted token + Low IL (so they are deprivileged),
/// but they are not prevented from spawning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementPolicy {
    pub token: TokenLevel,
    pub integrity: IntegrityLevel,
    pub drop_all_privileges: bool,
    /// Best-effort resource job. NEVER kill-on-close (izba daemonless contract):
    /// the no-kill-on-close behavior is unconditionally baked into
    /// `create_resource_job` (Windows), so there is no policy field for it.
    pub job_memory_max_mb: Option<u64>,
}

impl ConfinementPolicy {
    /// The policy applied to the OpenVMM process. See the design spec §Decisions.
    pub fn vmm_default() -> Self {
        Self {
            token: TokenLevel::Limited,
            integrity: IntegrityLevel::Low,
            drop_all_privileges: true,
            job_memory_max_mb: None, // sized by the VMM driver from guest mem
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

/// Human description of the token confinement ACTUALLY applied. NOTE: today both
/// `TokenLevel` variants apply only `DISABLE_MAX_PRIVILEGE` (all privileges
/// dropped) and **no restricting SIDs** — see design decision 2 — so both render
/// "privileges-dropped" rather than "restricted(...)", which would overstate the
/// confinement to a reader of `izba status`. When SID shaping lands this gains
/// per-variant descriptions.
fn token_desc(_token: TokenLevel) -> &'static str {
    "privileges-dropped"
}

fn il_desc(il: IntegrityLevel) -> &'static str {
    match il {
        IntegrityLevel::Low => "low-il",
        IntegrityLevel::Medium => "medium-il",
    }
}

impl ConfinementStatus {
    pub fn applied(p: &ConfinementPolicy) -> Self {
        Self {
            mode: ConfinementMode::Restricted,
            reason: format!("{}+{}+job", token_desc(p.token), il_desc(p.integrity)),
        }
    }
    /// Token+IL boundary applied, but the best-effort resource job could not be
    /// created/assigned. Same shape as `applied()` MINUS the "+job" claim, plus
    /// a note that the job is absent — so health never overstates confinement.
    pub fn token_only(p: &ConfinementPolicy) -> Self {
        Self {
            mode: ConfinementMode::TokenOnly,
            reason: format!(
                "{}+{} (resource job unavailable)",
                token_desc(p.token),
                il_desc(p.integrity)
            ),
        }
    }
    /// Restricted confinement with a caller-supplied reason. Used by the Linux
    /// realisation, whose reason text (layer list) differs from the Windows
    /// token-shaped `applied()`.
    pub fn confined(reason: &str) -> Self {
        Self {
            mode: ConfinementMode::Restricted,
            reason: reason.to_string(),
        }
    }
    pub fn degraded(reason: &str) -> Self {
        Self {
            mode: ConfinementMode::None,
            reason: reason.to_string(),
        }
    }
    /// True when the VMM actually ran confined (token+IL applied), i.e. mode is
    /// `Restricted` or `TokenOnly` — both imply the Low-IL token, which is what
    /// required the workspace to be Low-labelled. Drives the teardown decision to
    /// restore the workspace integrity (`sandbox::restore_confined_workspace`).
    /// `None` (unconfined / no jailer) means no relabel happened, so no restore.
    pub fn is_confined(&self) -> bool {
        matches!(
            self.mode,
            ConfinementMode::Restricted | ConfinementMode::TokenOnly
        )
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
    }

    #[test]
    fn status_renders_human_reason() {
        let ok = ConfinementStatus::applied(&ConfinementPolicy::vmm_default());
        // Honest: no restricting SIDs are applied yet, so the token reads as
        // "privileges-dropped", never "restricted(...)".
        assert!(ok.summary().contains("privileges-dropped"));
        assert!(!ok.summary().contains("restricted"));
        assert!(ok.summary().contains("low-il"));
        let none = ConfinementStatus::degraded("WHP unavailable under restricted token");
        assert_eq!(none.mode, ConfinementMode::None);
        assert!(none.summary().contains("WHP unavailable"));
    }

    #[test]
    fn medium_il_renders_in_status_reason() {
        // The default policy is Low; exercise the Medium arm of `il_desc` via a
        // Medium-integrity policy so the status text reads "medium-il".
        let mut p = ConfinementPolicy::vmm_default();
        p.integrity = IntegrityLevel::Medium;
        assert!(ConfinementStatus::applied(&p).reason.contains("medium-il"));
        assert!(ConfinementStatus::token_only(&p)
            .reason
            .contains("medium-il"));
    }

    #[test]
    fn is_confined_tracks_token_il_application() {
        // Restricted + TokenOnly both applied the Low-IL token → confined → the
        // workspace was relabelled → teardown must restore it.
        assert!(ConfinementStatus::applied(&ConfinementPolicy::vmm_default()).is_confined());
        assert!(ConfinementStatus::token_only(&ConfinementPolicy::vmm_default()).is_confined());
        // Unconfined: no relabel happened, so no restore.
        assert!(!ConfinementStatus::degraded("WHP unavailable").is_confined());
    }

    #[test]
    fn token_only_status_omits_job_and_summarizes_honestly() {
        let s = ConfinementStatus::token_only(&ConfinementPolicy::vmm_default());
        assert_eq!(s.mode, ConfinementMode::TokenOnly);
        // Honest: keeps the token+IL claim but NEVER asserts the job.
        assert!(s.reason.contains("privileges-dropped"));
        assert!(s.reason.contains("low-il"));
        assert!(!s.reason.contains("+job"));
        assert!(s.reason.contains("resource job unavailable"));
        assert!(s.summary().starts_with("confined (token only):"));
    }

    #[test]
    fn confined_constructor_is_restricted_with_verbatim_reason() {
        let s = ConfinementStatus::confined("seccomp+landlock+virtiofs:namespace");
        assert_eq!(s.mode, ConfinementMode::Restricted);
        assert_eq!(s.reason, "seccomp+landlock+virtiofs:namespace");
        assert!(s.summary().starts_with("confined: "));
        assert!(s.is_confined());
    }
}
