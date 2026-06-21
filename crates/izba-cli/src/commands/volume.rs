use std::io::{BufRead, IsTerminal, Write};

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
    /// Attach a volume to a sandbox (applied on its next restart)
    Attach {
        /// Sandbox name
        name: String,
        /// [VNAME:]GUEST_PATH:SIZE — SIZE needs a `g`/`m` suffix, e.g. `10g`, `512m`
        spec: String,
    },
    /// Detach the volume at GUEST_PATH from a sandbox (applied on next restart)
    Detach {
        /// Sandbox name
        name: String,
        /// Guest mountpoint of the volume to remove
        guest_path: String,
    },
}

pub fn run(paths: &Paths, cmd: &VolumeCmd) -> anyhow::Result<i32> {
    match cmd {
        VolumeCmd::Ls => ls(paths),
        VolumeCmd::Prune { force } => prune(paths, *force),
        VolumeCmd::Rm { name, force } => rm(paths, name, *force),
        VolumeCmd::Attach { name, spec } => attach(paths, name, spec),
        VolumeCmd::Detach { name, guest_path } => detach(paths, name, guest_path),
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
    if !confirm_destructive(
        "remove all persistent volumes not used by any sandbox",
        force,
    )? {
        eprintln!("aborted");
        return Ok(1);
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
    if !confirm_destructive(&format!("remove persistent volume '{name}'"), force)? {
        eprintln!("aborted");
        return Ok(1);
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

fn attach(paths: &Paths, name: &str, spec: &str) -> anyhow::Result<i32> {
    let spec = izba_core::volume::parse_volume_flag(spec)?;
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::VolumeAttach {
            name: name.to_string(),
            spec,
        },
        &mut |_| {},
    )?)?;
    println!("attached (applies on next restart of '{name}')");
    Ok(0)
}

fn detach(paths: &Paths, name: &str, guest_path: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::VolumeDetach {
            name: name.to_string(),
            guest_path: guest_path.into(),
        },
        &mut |_| {},
    )?)?;
    println!("detached (applies on next restart of '{name}')");
    Ok(0)
}

/// Gate a destructive `volume` operation.
///
/// - `--force` ⇒ proceed without asking.
/// - interactive terminal ⇒ prompt `[y/N]`, default No.
/// - non-interactive (piped/script) without `--force` ⇒ refuse with a clear
///   error naming the flag, instead of silently aborting at exit 0. A script
///   can't answer a prompt, so we tell it the flag to pass (clig.dev: only
///   prompt when stdin is a TTY; never *require* a prompt).
///
/// Returns `Ok(true)` to proceed, `Ok(false)` if the user declined at the
/// prompt; `Err` if running non-interactively without `--force`.
fn confirm_destructive(action: &str, force: bool) -> anyhow::Result<bool> {
    confirm_with(
        action,
        force,
        std::io::stdin().is_terminal(),
        &mut std::io::stdin().lock(),
    )
}

/// Pure core of [`confirm_destructive`] with the TTY decision and input reader
/// injected, so the script-relevant branches are unit-testable without a real
/// terminal.
fn confirm_with(
    action: &str,
    force: bool,
    is_tty: bool,
    reader: &mut impl BufRead,
) -> anyhow::Result<bool> {
    if force {
        return Ok(true);
    }
    if !is_tty {
        bail!(
            "refusing to {action} without confirmation: stdin is not a terminal \
             — re-run with --force"
        );
    }
    print!("{action}? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(is_affirmative(&line))
}

/// True for an affirmative reply (`y`/`yes`, case-insensitive); anything else,
/// including empty input / EOF, is a No.
fn is_affirmative(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_proceeds_even_without_tty() {
        let mut input: &[u8] = b"";
        assert!(confirm_with("remove x", true, false, &mut input).unwrap());
    }

    #[test]
    fn non_tty_without_force_errors_naming_the_flag() {
        let mut input: &[u8] = b"";
        let err = confirm_with("remove persistent volume 'v'", false, false, &mut input)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--force"), "{err}");
        assert!(err.contains("not a terminal"), "{err}");
    }

    #[test]
    fn tty_yes_proceeds() {
        let mut yes: &[u8] = b"y\n";
        assert!(confirm_with("remove x", false, true, &mut yes).unwrap());
        let mut upper: &[u8] = b"YES\n";
        assert!(confirm_with("remove x", false, true, &mut upper).unwrap());
    }

    #[test]
    fn tty_no_or_empty_declines() {
        for raw in [&b"n\n"[..], &b"\n"[..], &b""[..]] {
            let mut input = raw;
            assert!(!confirm_with("remove x", false, true, &mut input).unwrap());
        }
    }

    #[test]
    fn is_affirmative_variants() {
        for s in ["y", "Y", "yes", " Yes ", "YES\n"] {
            assert!(is_affirmative(s), "{s:?}");
        }
        for s in ["", "n", "no", "nope", "yeah"] {
            assert!(!is_affirmative(s), "{s:?}");
        }
    }
}
