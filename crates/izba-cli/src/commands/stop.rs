use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxSummary};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

/// Everything with live processes is stop-worthy: "running" and every
/// "degraded (…)" flavor. Only a fully "stopped" sandbox is skipped.
fn names_to_stop(sandboxes: &[SandboxSummary]) -> Vec<String> {
    sandboxes
        .iter()
        .filter(|sb| sb.status != "stopped")
        .map(|sb| sb.name.clone())
        .collect()
}

/// `izba stop --all`: best-effort stop of every running/degraded sandbox.
/// Keeps going past per-sandbox failures and reports them at the end, so an
/// installer calling this quiesces as much as possible in one pass.
pub fn run_all(paths: &Paths) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let sandboxes = match client.request(&DaemonRequest::List, &mut |_| {})? {
        DaemonResponse::List { sandboxes } => sandboxes,
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    };
    let names = names_to_stop(&sandboxes);
    if names.is_empty() {
        println!("no running sandboxes");
        return Ok(0);
    }
    let mut failures = Vec::new();
    for name in names {
        let stopped = client
            .request(&DaemonRequest::Stop { name: name.clone() }, &mut |_| {})
            .and_then(super::expect_ok);
        match stopped {
            Ok(()) => println!("stopped {name}"),
            Err(e) => {
                eprintln!("failed to stop {name}: {e:#}");
                failures.push(name);
            }
        }
    }
    if failures.is_empty() {
        Ok(0)
    } else {
        bail!("failed to stop: {}", failures.join(", "))
    }
}

pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let resp = client.request(
        &DaemonRequest::Stop {
            name: name.to_string(),
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::SandboxSummary;

    fn sb(name: &str, status: &str) -> SandboxSummary {
        SandboxSummary {
            name: name.into(),
            image_ref: "img".into(),
            status: status.into(),
        }
    }

    /// `stop --all` targets everything with live processes — "running" AND
    /// "degraded (…)" — and skips only fully "stopped" sandboxes.
    #[test]
    fn names_to_stop_skips_only_stopped() {
        let list = vec![
            sb("a", "running"),
            sb("b", "stopped"),
            sb("c", "degraded (vmm dead)"),
        ];
        assert_eq!(names_to_stop(&list), vec!["a", "c"]);
    }

    #[test]
    fn names_to_stop_empty_when_all_stopped() {
        let list = vec![sb("a", "stopped")];
        assert!(names_to_stop(&list).is_empty());
    }
}
