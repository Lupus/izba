use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

pub fn run(paths: &Paths) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::List, &mut |_| {})? {
        DaemonResponse::List { sandboxes } => {
            println!("{:<24} {:<32} STATUS", "NAME", "IMAGE");
            for sb in sandboxes {
                println!("{:<24} {:<32} {}", sb.name, sb.image_ref, sb.status);
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}
