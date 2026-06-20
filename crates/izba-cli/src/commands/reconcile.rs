use izba_core::daemon::client::DaemonClient;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::liveness::Probes;
use izba_core::paths::Paths;
use izba_core::reconcile::reconcile;
use izba_core::state::PidIdentity;

/// Reconciler probes: pid liveness from procmgr; control assumed answering
/// (the reconciler flags only the unambiguous alive⇄stopped disagreement —
/// control-plane responsiveness is the runner's latency oracle, not ours).
struct PidProbes;
impl Probes for PidProbes {
    fn pid_alive(&self, id: &PidIdentity) -> bool {
        izba_core::procmgr::pid_alive(id)
    }
    fn control_answers(&self) -> bool {
        true
    }
}

pub fn run(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    // Best-effort daemon view; None if the daemon is not running.
    let daemon_view = match DaemonClient::connect_existing(paths)? {
        Some(mut client) => match client.request(&DaemonRequest::List, &mut |_| {})? {
            DaemonResponse::List { sandboxes } => Some(sandboxes),
            DaemonResponse::Error { message } => anyhow::bail!("daemon list failed: {message}"),
            other => anyhow::bail!("unexpected daemon response: {other:?}"),
        },
        None => None,
    };
    let report = reconcile(paths, daemon_view.as_deref(), &PidProbes)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for v in &report.violations {
            println!("{:?} {:?}: {}", v.kind, v.sandbox, v.detail);
        }
    }
    Ok(0)
}
