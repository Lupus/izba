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
            println!("{:<24} {:<32} STATUS", "NAME", "IMAGE");
            for sb in &s.sandboxes {
                println!("{:<24} {:<32} {}", sb.name, sb.image_ref, sb.status);
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected daemon reply: {other:?}"),
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
