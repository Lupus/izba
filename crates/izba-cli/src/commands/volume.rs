use anyhow::bail;
use clap::Subcommand;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum VolumeCmd {
    /// List persistent volumes (size, usage, sandboxes referencing them)
    Ls,
    /// Remove persistent volume images not referenced by any sandbox
    Prune {
        /// Skip the confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
    /// Remove a single persistent volume (refused if any sandbox references it)
    Rm {
        /// Volume name
        name: String,
        /// Skip the confirmation prompt (does NOT bypass the in-use guard)
        #[arg(short, long)]
        force: bool,
    },
}

pub fn run(paths: &Paths, cmd: &VolumeCmd) -> anyhow::Result<i32> {
    match cmd {
        VolumeCmd::Ls => ls(paths),
        VolumeCmd::Prune { force } => prune(paths, *force),
        VolumeCmd::Rm { name, force } => rm(paths, name, *force),
    }
}

fn ls(paths: &Paths) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::VolumeList, &mut |_| {})? {
        DaemonResponse::Volumes { volumes } => {
            if volumes.is_empty() {
                println!("no persistent volumes");
            } else {
                println!("{:<20} {:>10} {:>10}  USED BY", "NAME", "SIZE", "USED");
                for v in &volumes {
                    let used_by = if v.referenced_by.is_empty() {
                        "-".to_string()
                    } else {
                        v.referenced_by.join(",")
                    };
                    println!(
                        "{:<20} {:>10} {:>10}  {}",
                        v.name, v.size_bytes, v.actual_bytes, used_by
                    );
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
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

fn rm(paths: &Paths, name: &str, force: bool) -> anyhow::Result<i32> {
    if !force && !confirm(&format!("Remove persistent volume '{name}'?"))? {
        println!("aborted");
        return Ok(0);
    }
    let mut client = DaemonClient::connect(paths)?;
    match client.request(
        &DaemonRequest::VolumeRemove {
            name: name.to_string(),
        },
        &mut |_| {},
    )? {
        DaemonResponse::Pruned {
            reclaimed_bytes, ..
        } => {
            println!("removed {name} (reclaimed {reclaimed_bytes} bytes)");
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
