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
    ///
    /// On Linux, `is_confined()` gates a no-op integrity restore (there is no MIC
    /// label on Linux), so `Restricted` there reflects seccomp+Landlock+sandbox,
    /// not a token.
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

/// Actionable error text for a directory that cannot be Low-integrity-relabelled
/// for a confined sandbox. The confined VMM runs at Low integrity and izba must
/// relabel every host write surface (the workspace share, scratch, writable
/// disks) to Low — which needs `WRITE_OWNER` (Full Control) on the object. A
/// folder at the **root of a drive** (e.g. `C:\name`) inherits only
/// `Authenticated Users: Modify` and grants `WRITE_OWNER` to no one (not even its
/// owner, who gets only implicit `READ_CONTROL` + `WRITE_DAC`), so the relabel is
/// denied. Surfaced both as a create-time preflight (before the sandbox is
/// written to disk) and, for sandboxes already pointing at such a dir, wrapped
/// around the start-time relabel failure.
///
/// `account` is the Windows account to grant in the remedy `icacls` command,
/// expanded by the caller (the daemon/CLI runs as the user) so the command is
/// copy-pasteable in BOTH cmd.exe and PowerShell — a `%USERNAME%` literal would
/// not expand in PowerShell and would silently grant to a non-existent principal.
///
/// Deliberately a single line (no embedded newlines): the CLI prints it to stderr
/// and the app shows it in a plain element where HTML would collapse newlines
/// anyway, so a flowing sentence reads correctly in both without per-surface CSS.
///
/// Kept here (cross-platform) so it is a single source of truth, unit-testable on
/// any host even though the denial only arises on Windows.
pub fn workspace_confinement_denied_msg(path: &std::path::Path, account: &str) -> String {
    let p = path.display();
    format!(
        "directory {p} cannot be secured for a confined sandbox: izba runs the VM at \
         Low integrity and must relabel this directory, which requires Full Control \
         (the WRITE_OWNER right) on it. A folder at the root of a drive (e.g. C:\\name) \
         does not grant this even to its owner. Two fixes: (1) use a workspace under your \
         user profile (e.g. C:\\Users\\<you>\\<project>); or (2) grant your account Full \
         Control with: icacls \"{p}\" /grant \"{account}:(OI)(CI)F\". Or create/run the \
         sandbox with --allow-unconfined to skip host-side confinement (reduced isolation)."
    )
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

    #[test]
    fn workspace_confinement_denied_msg_is_actionable() {
        let msg =
            workspace_confinement_denied_msg(std::path::Path::new(r"C:\izba-src"), r"CORP\me");
        // Names the offending path so the user knows which dir to fix.
        assert!(msg.contains(r"C:\izba-src"), "{msg}");
        // Explains the underlying access requirement (WRITE_OWNER / Full Control).
        assert!(msg.contains("Full Control"), "{msg}");
        assert!(msg.contains("WRITE_OWNER"), "{msg}");
        // Offers the two concrete remedies: relocate under the profile ...
        assert!(msg.to_lowercase().contains("profile"), "{msg}");
        // ... or grant access with a copy-pasteable icacls command on THIS path,
        // targeting the EXPANDED account so it works in cmd.exe AND PowerShell
        // (a literal `%USERNAME%` would not expand in PowerShell).
        assert!(
            msg.contains(r#"icacls "C:\izba-src" /grant "CORP\me:(OI)(CI)F""#),
            "{msg}"
        );
        assert!(
            !msg.contains("%USERNAME%"),
            "must not embed a cmd-only variable: {msg}"
        );
        // And the explicit escape hatch.
        assert!(msg.contains("--allow-unconfined"), "{msg}");
        // Single line: it renders correctly in the CLI AND the app dialog (where
        // HTML would collapse newlines) without any per-surface whitespace CSS.
        assert!(!msg.contains('\n'), "message must stay single-line: {msg}");
    }
}
