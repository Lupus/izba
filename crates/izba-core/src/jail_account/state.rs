use serde::{Deserialize, Serialize};

pub const LOCKDOWN_FILE: &str = "lockdown.json";

/// Information about a successfully locked-down sandbox account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedInfo {
    /// Windows local account name, e.g. `izba-spk-<sandbox>`.
    pub account: String,
    /// SID string, e.g. `S-1-5-21-…`.
    pub sid: String,
    /// Whether the per-sandbox outbound firewall rule (`izba-deny-<sandbox>`)
    /// is in place, blocking all traffic from this account.
    pub net_blocked: bool,
}

/// Runtime lock-down state for a sandbox's host-side VMM account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockdownState {
    /// No account has been provisioned; VMM runs as the invoking user.
    Unlocked,
    /// Account provisioned and (optionally) network-blocked.
    Locked(LockedInfo),
    /// Provisioning was attempted but something went wrong; `reason` describes
    /// the failure. The VMM should be considered NOT confined.
    Degraded { reason: String },
}

impl LockdownState {
    /// Short human-readable summary, suitable for status output.
    ///
    /// | variant | output |
    /// |---------|--------|
    /// | `Unlocked` | `"unlocked"` |
    /// | `Locked` (net_blocked=true) | `"locked(account=<a>, sid=<s>, net=blocked)"` |
    /// | `Locked` (net_blocked=false) | `"locked(account=<a>, sid=<s>, net=open)"` |
    /// | `Degraded` | `"degraded: <reason>"` |
    pub fn summary(&self) -> String {
        match self {
            LockdownState::Unlocked => "unlocked".to_string(),
            LockdownState::Locked(info) => {
                let net = if info.net_blocked { "blocked" } else { "open" };
                format!(
                    "locked(account={}, sid={}, net={})",
                    info.account, info.sid, net
                )
            }
            LockdownState::Degraded { reason } => format!("degraded: {reason}"),
        }
    }

    /// Returns `true` only when the state is `Locked`.
    pub fn is_locked(&self) -> bool {
        matches!(self, LockdownState::Locked(_))
    }
}

/// On-disk representation of the lock-down state, persisted as `lockdown.json`
/// in the sandbox directory.
///
/// `None` state means the sandbox is `Unlocked`; `Some(info)` means `Locked`.
/// `Degraded` is a transient runtime state and is never persisted.
///
/// The `#[serde(default)]` on `state` ensures that a `lockdown.json` written
/// by a future version with additional fields still deserializes correctly on
/// older builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LockdownFile {
    #[serde(default)]
    pub state: Option<LockedInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_info() -> LockedInfo {
        LockedInfo {
            account: "izba-spk-foo".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890-1001".to_string(),
            net_blocked: true,
        }
    }

    // --- serde round-trip ---

    #[test]
    fn lockdown_file_roundtrip_some() {
        let original = LockdownFile {
            state: Some(locked_info()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: LockdownFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn lockdown_file_roundtrip_none() {
        let original = LockdownFile { state: None };
        let json = serde_json::to_string(&original).unwrap();
        let back: LockdownFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn lockdown_file_default_is_none() {
        let f = LockdownFile::default();
        assert!(f.state.is_none());
    }

    /// A `lockdown.json` written before the `state` field was added (or with
    /// only unknown fields) must still deserialize without error.
    #[test]
    fn lockdown_file_missing_state_defaults_none() {
        let json = r#"{}"#;
        let f: LockdownFile = serde_json::from_str(json).unwrap();
        assert!(f.state.is_none());
    }

    // --- summary() strings ---

    #[test]
    fn summary_unlocked() {
        assert_eq!(LockdownState::Unlocked.summary(), "unlocked");
    }

    #[test]
    fn summary_locked_net_blocked() {
        let info = locked_info(); // net_blocked = true
        let state = LockdownState::Locked(info.clone());
        assert_eq!(
            state.summary(),
            format!(
                "locked(account={}, sid={}, net=blocked)",
                info.account, info.sid
            )
        );
    }

    #[test]
    fn summary_locked_net_open() {
        let mut info = locked_info();
        info.net_blocked = false;
        let state = LockdownState::Locked(info.clone());
        assert_eq!(
            state.summary(),
            format!(
                "locked(account={}, sid={}, net=open)",
                info.account, info.sid
            )
        );
    }

    #[test]
    fn summary_degraded() {
        let state = LockdownState::Degraded {
            reason: "account creation failed: access denied".to_string(),
        };
        assert_eq!(
            state.summary(),
            "degraded: account creation failed: access denied"
        );
    }

    // --- is_locked() ---

    #[test]
    fn is_locked_unlocked() {
        assert!(!LockdownState::Unlocked.is_locked());
    }

    #[test]
    fn is_locked_locked() {
        assert!(LockdownState::Locked(locked_info()).is_locked());
    }

    #[test]
    fn is_locked_degraded() {
        assert!(!LockdownState::Degraded {
            reason: "oops".to_string()
        }
        .is_locked());
    }
}
