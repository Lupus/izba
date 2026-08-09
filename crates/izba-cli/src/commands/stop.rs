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

/// The `stop --all` sweep over an already-fetched sandbox list: stop every
/// running/degraded sandbox via `stop`, keep going past per-sandbox failures,
/// and report them all at the end — an installer calling this quiesces as
/// much as possible in one pass.
fn stop_all_with(
    sandboxes: Vec<SandboxSummary>,
    mut stop: impl FnMut(&str) -> anyhow::Result<()>,
) -> anyhow::Result<i32> {
    let names = names_to_stop(&sandboxes);
    if names.is_empty() {
        println!("no running sandboxes");
        return Ok(0);
    }
    let mut failures = Vec::new();
    for name in names {
        match stop(&name) {
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

/// Unwrap the daemon's `List` reply.
fn expect_list(resp: DaemonResponse) -> anyhow::Result<Vec<SandboxSummary>> {
    match resp {
        DaemonResponse::List { sandboxes } => Ok(sandboxes),
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// `izba stop --all`: best-effort stop of every running/degraded sandbox.
#[mutants::skip] // reason: drives a live daemon (List + Stop RPCs); the sweep logic is stop_all_with and expect_list, unit-tested with an injected stop fn.
pub fn run_all(paths: &Paths) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let sandboxes = expect_list(client.request(&DaemonRequest::List, &mut |_| {})?)?;
    stop_all_with(sandboxes, |name| {
        client
            .request(
                &DaemonRequest::Stop {
                    name: name.to_string(),
                },
                &mut |_| {},
            )
            .and_then(super::expect_ok)
    })
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

    #[test]
    fn stop_all_with_stops_each_and_reports_success() {
        let mut stopped = Vec::new();
        let rc = stop_all_with(vec![sb("a", "running"), sb("b", "running")], |name| {
            stopped.push(name.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(rc, 0);
        assert_eq!(stopped, vec!["a", "b"]);
    }

    #[test]
    fn stop_all_with_empty_is_success_without_stops() {
        // The closure must never run: a stopped sandbox is not stopped again.
        let rc = stop_all_with(vec![sb("a", "stopped")], |name| {
            panic!("tried to stop {name} but nothing should be stopped")
        })
        .unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    fn expect_list_unwraps_sandboxes() {
        let resp = DaemonResponse::List {
            sandboxes: vec![sb("a", "running")],
        };
        let list = expect_list(resp).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "a");
    }

    #[test]
    fn expect_list_propagates_daemon_error() {
        let err = expect_list(DaemonResponse::Error {
            message: "boom".into(),
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn expect_list_rejects_wrong_variant() {
        let err = expect_list(DaemonResponse::Ok).unwrap_err();
        assert!(err.to_string().contains("unexpected daemon reply"));
    }

    /// A failure on one sandbox must not abort the sweep — the rest still get
    /// stopped, and the error names every failed sandbox.
    #[test]
    fn stop_all_with_continues_past_failures_and_errors() {
        let mut stopped = Vec::new();
        let err = stop_all_with(
            vec![sb("a", "running"), sb("b", "running"), sb("c", "running")],
            |name| {
                if name == "b" {
                    anyhow::bail!("vmm wedged")
                }
                stopped.push(name.to_string());
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(stopped, vec!["a", "c"], "sweep continues past the failure");
        assert!(
            err.to_string().contains('b'),
            "error names the failed sandbox: {err}"
        );
    }
}
