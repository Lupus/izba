//! `izba daemon run|status|stop`. `run` is the foreground server entry the
//! auto-start machinery re-invokes detached; `status`/`stop` deliberately
//! never auto-start a daemon.

use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

pub fn run_foreground(paths: &Paths) -> anyhow::Result<i32> {
    izba_core::daemon::run_daemon(paths)?;
    Ok(0)
}

// reason: daemon-wired glue — connects to a live izbad and prints a status
// table; the whole module is intentionally untestable without a running daemon
// (exercised by the KVM-gated `daemon_e2e`, which cargo-mutants cannot run on
// hosted runners). The one mutation-worthy bit, the CONTAINER column token, is
// `ContainerState::as_str`, unit-tested in izba-proto. The `status == "stopped"`
// guard is a probe-skipping optimization (a stopped VM can't hold a live
// container; `container_state` would return None anyway).
#[mutants::skip]
pub fn status(paths: &Paths) -> anyhow::Result<i32> {
    let Some(mut client) = DaemonClient::connect_existing(paths)? else {
        println!("daemon: not running");
        return Ok(0);
    };
    match client.request(&DaemonRequest::Status, &mut |_| {})? {
        DaemonResponse::Status(s) => {
            println!(
                "daemon: running (pid {}, version {}, uptime {}s)",
                s.pid,
                s.version,
                s.uptime_ms / 1000
            );
            let cli = izba_core::build_info::BuildInfoOwned::current();
            println!("daemon build: {} (proto {})", s.build.short(), s.proto);
            println!("cli build:    {}", cli.short());
            if s.build != cli {
                println!("⚠ daemon and CLI builds differ (run `izba version` for detail)");
            }
            println!("socket: {}", s.socket);
            println!(
                "{}",
                trust_line(
                    &s,
                    &izba_core::paths::display_path(&paths.trust_extra_dir())
                )
            );
            println!("{:<24} {:<32} {:<16} CONTAINER", "NAME", "IMAGE", "STATUS");
            for sb in &s.sandboxes {
                // A stopped VM can't have a live container; skip the probe (it
                // would only fail → "unknown") so a plain `daemon status` stays
                // a cheap registry read for stopped sandboxes. For running ones,
                // probe the guest so we report the workload honestly even when
                // the VM is up but the container has exited.
                let container = if sb.status == "stopped" {
                    None
                } else {
                    client.container_state(&sb.name)
                };
                println!(
                    "{:<24} {:<32} {:<16} {}",
                    sb.name,
                    sb.image_ref,
                    sb.status,
                    container.map(|c| c.as_str()).unwrap_or("unknown"),
                );
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// The `trust:` line of `izba daemon status` (#283).
///
/// Three postures, and the ERROR one must never be rendered as either of the
/// healthy ones: when the extra-CA load (or the MITM's CA/runtime init) fails,
/// izbad has no extra roots AND no HTTPS interception, so every enforcing
/// sandbox is failing closed. Reporting that as "webpki roots only" would tell
/// the operator to install the CA they already installed while hiding the
/// outage.
///
/// `extra_dir` is rendered by the CLI from its OWN `Paths`, not read off the
/// wire: a pre-#283 daemon would otherwise leave a blank hole in the sentence.
fn trust_line(s: &izba_core::daemon::proto::DaemonStatus, extra_dir: &str) -> String {
    if let Some(err) = &s.trust_error {
        return format!(
            "⚠ trust: extra CA load FAILED — {err}; HTTPS interception is DISABLED, \
             enforcing sandboxes fail closed (fix or remove the file under {extra_dir}, \
             then `izba daemon stop` to reload)"
        );
    }
    if s.extra_ca_files.is_empty() {
        format!(
            "trust: webpki roots only (drop corporate CA certificates — \
             *.pem, *.crt, *.cer, *.der — into {extra_dir}; \
             guests pick them up on their next start, izbad after `izba daemon stop`)"
        )
    } else {
        format!(
            "trust: webpki roots + {} extra CA file(s) from {}: {} \
             (guests: on next start; izbad: reload with `izba daemon stop`)",
            s.extra_ca_files.len(),
            extra_dir,
            s.extra_ca_files.join(", ")
        )
    }
}

pub fn stop(paths: &Paths) -> anyhow::Result<i32> {
    let Some(client) = DaemonClient::connect_existing(paths)? else {
        println!("daemon: not running");
        return Ok(0);
    };
    client.shutdown_and_wait(paths)?;
    println!("daemon stopped (sandboxes keep running; port relays pause until restart)");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::DaemonStatus;

    fn status() -> DaemonStatus {
        DaemonStatus {
            version: "v".into(),
            proto: 0,
            build: izba_core::build_info::BuildInfoOwned::current(),
            pid: 1,
            uptime_ms: 0,
            socket: "/s".into(),
            sandboxes: vec![],
            extra_ca_files: vec![],
            trust_error: None,
        }
    }

    #[test]
    fn no_extra_cas_points_at_the_directory() {
        let line = trust_line(&status(), "~/.local/share/izba/trust/extra");
        assert!(line.starts_with("trust: webpki roots only"), "{line}");
        assert!(line.contains("~/.local/share/izba/trust/extra"), "{line}");
        assert!(!line.contains('⚠'), "{line}");
    }

    #[test]
    fn loaded_files_are_listed_in_order_with_the_reload_hint() {
        let mut s = status();
        s.extra_ca_files = vec!["a.crt".into(), "b.pem".into()];
        let line = trust_line(&s, "/d");
        assert!(
            line.contains("+ 2 extra CA file(s) from /d: a.crt, b.pem"),
            "{line}"
        );
        assert!(line.contains("izba daemon stop"), "{line}");
        assert!(!line.contains('⚠'), "{line}");
    }

    /// The finding this renderer exists for: a load failure must NOT render as
    /// the benign "webpki roots only" hint.
    #[test]
    fn a_load_failure_is_loud_and_names_the_fail_closed_consequence() {
        let mut s = status();
        s.trust_error = Some("extra CA file /d/corp.pem: invalid PEM".into());
        let line = trust_line(&s, "/d");
        assert!(line.starts_with("⚠ trust: extra CA load FAILED"), "{line}");
        assert!(line.contains("corp.pem"), "{line}");
        assert!(line.contains("fail closed"), "{line}");
        assert!(!line.contains("webpki roots only"), "{line}");
    }

    /// A failure wins even if a stale file list somehow accompanies it.
    #[test]
    fn a_load_failure_takes_precedence_over_a_file_list() {
        let mut s = status();
        s.extra_ca_files = vec!["a.crt".into()];
        s.trust_error = Some("boom".into());
        assert!(trust_line(&s, "/d").starts_with("⚠"), "error wins");
    }
}
