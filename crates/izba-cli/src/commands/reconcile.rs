use izba_core::daemon::client::DaemonClient;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxSummary};
use izba_core::liveness::Probes;
use izba_core::paths::Paths;
use izba_core::reconcile::reconcile_settled;
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

#[mutants::skip] // reason: drives a live daemon (List over the socket) and real sleeps; the settle/intersection decision logic is unit-tested in izba_core::reconcile.
pub fn run(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect_existing(paths)?;
    let mut fetch = || -> anyhow::Result<Option<Vec<SandboxSummary>>> {
        match client.as_mut() {
            // Best-effort daemon view; None if the daemon is not running.
            None => Ok(None),
            Some(c) => match c.request(&DaemonRequest::List, &mut |_| {})? {
                DaemonResponse::List { sandboxes } => Ok(Some(sandboxes)),
                DaemonResponse::Error { message } => anyhow::bail!("daemon list failed: {message}"),
                other => anyhow::bail!("unexpected daemon response: {other:?}"),
            },
        }
    };
    // One supervisor tick + margin: long enough for the daemon's cached
    // status to self-correct after a transition (#67).
    let settle =
        izba_core::daemon::supervisor::tick_interval() + std::time::Duration::from_millis(500);
    let report = reconcile_settled(paths, &mut fetch, &PidProbes, settle)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for v in &report.violations {
            println!("{:?} {:?}: {}", v.kind, v.sandbox, v.detail);
        }
    }
    Ok(0)
}
