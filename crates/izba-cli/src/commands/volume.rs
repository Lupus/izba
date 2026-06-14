use anyhow::bail;
use clap::Subcommand;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum VolumeCmd {
    /// Remove persistent volume images not referenced by any sandbox
    Prune {
        /// Skip the confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

pub fn run(paths: &Paths, cmd: &VolumeCmd) -> anyhow::Result<i32> {
    match cmd {
        VolumeCmd::Prune { force } => prune(paths, *force),
    }
}

fn prune(paths: &Paths, force: bool) -> anyhow::Result<i32> {
    if !force && !confirm("Remove all persistent volumes not used by any sandbox?")? {
        println!("aborted");
        return Ok(0);
    }
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::VolumePrune, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Pruned {
            removed,
            reclaimed_bytes,
        } => {
            if removed.is_empty() {
                println!("nothing to prune");
            } else {
                for n in &removed {
                    println!("removed {n}");
                }
                println!("reclaimed {reclaimed_bytes} bytes");
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// Minimal y/N confirmation on stdin. Defaults to no on EOF / anything but y.
fn confirm(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{prompt} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}
