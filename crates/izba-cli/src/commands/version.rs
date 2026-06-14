//! `izba version` — detailed build info for the CLI and, when one is running,
//! the daemon it would talk to (docker-style Client/Daemon split). The bare
//! `izba --version` one-liner is handled by clap in `main.rs`.

use izba_core::build_info::{BuildInfo, BuildInfoOwned};
use izba_core::daemon::proto::DAEMON_PROTO_VERSION;
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use serde::Serialize;

/// Machine-readable payload for `izba version --json`.
#[derive(Serialize)]
pub struct VersionJson {
    pub cli: BuildInfoOwned,
    pub daemon: Option<BuildInfoOwned>,
    pub proto: u32,
    pub mismatch: bool,
}

/// Two builds differ when their full metadata differs (sha, build date, …).
pub fn builds_differ(a: &BuildInfoOwned, b: &BuildInfoOwned) -> bool {
    a != b
}

/// Best-effort daemon build: only an already-running daemon (never auto-start).
fn daemon_build(paths: &Paths) -> Option<BuildInfoOwned> {
    let client = DaemonClient::connect_existing(paths).ok().flatten()?;
    Some(client.server_build.clone())
}

pub fn run(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    let cli = BuildInfo::current().to_owned();
    let daemon = daemon_build(paths);
    let mismatch = daemon
        .as_ref()
        .map(|d| builds_differ(&cli, d))
        .unwrap_or(false);

    if json {
        let payload = VersionJson {
            cli,
            daemon,
            proto: DAEMON_PROTO_VERSION,
            mismatch,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(0);
    }

    println!("Client:\n{}", BuildInfo::current().long());
    match &daemon {
        Some(d) => {
            println!(
                "\nDaemon:\n izba {}\n git:     {}\n commit:  {} {}",
                d.pkg_version,
                d.git_describe,
                d.sha_short(),
                d.commit_date
            );
            if mismatch {
                println!("\n⚠ daemon and CLI builds differ");
            }
        }
        None => println!("\nDaemon: not running"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_payload_has_cli_and_mismatch_fields() {
        let cli = BuildInfoOwned::current();
        let payload = VersionJson {
            cli,
            daemon: None,
            proto: DAEMON_PROTO_VERSION,
            mismatch: false,
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(s.contains("\"cli\""), "{s}");
        assert!(s.contains("\"daemon\":null"), "{s}");
        assert!(s.contains("\"mismatch\":false"), "{s}");
    }

    #[test]
    fn mismatch_true_when_builds_differ() {
        let cli = BuildInfoOwned::current();
        let mut other = cli.clone();
        other.git_sha = "deadbeef0".into();
        assert!(builds_differ(&cli, &other));
        assert!(!builds_differ(&cli, &cli));
    }
}
