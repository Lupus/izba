//! Egress policy seam (M1: allow-all). M2 fills in per-sandbox allow-lists
//! and the audit log; the seam exists now so the daemon grows by extension
//! instead of refactor (roadmap risk #6).

/// One egress connection attempt, as seen at the policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDesc {
    pub sandbox: String,
    /// Destination address as the guest gave it (an IP literal in M1).
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

pub trait Policy: Send + Sync {
    /// Decide AND record: implementations own their audit emission.
    fn check(&self, flow: &FlowDesc) -> Verdict;
}

/// M1 policy: everything allowed; each decision goes to stderr (the daemon
/// log), so the audit trail exists from day one.
pub struct AllowAll;

impl Policy for AllowAll {
    fn check(&self, flow: &FlowDesc) -> Verdict {
        eprintln!(
            "izbad: egress allow {} -> {}:{}",
            flow.sandbox, flow.addr, flow.port
        );
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_allows() {
        let flow = FlowDesc {
            sandbox: "web".into(),
            addr: "1.2.3.4".into(),
            port: 443,
        };
        assert_eq!(AllowAll.check(&flow), Verdict::Allow);
    }
}
