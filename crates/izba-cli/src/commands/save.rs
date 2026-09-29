//! `izba save` — archive sandboxes into one `.izba` file to move them to
//! another machine. Daemon-side work; this is the thin client + report.

use std::path::PathBuf;

use anyhow::{bail, Result};
use izba_core::bundle::fsutil::human_bytes;
use izba_core::bundle::save::SaveReport;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::{display_path, Paths};

#[mutants::skip] // reason: daemon-boundary glue (cwd absolutize + connect + print); exercised by the save/load e2e. The output logic is render_save_report, unit-tested.
pub fn run(
    paths: &Paths,
    names: Vec<String>,
    all: bool,
    output: PathBuf,
    with_workspace: bool,
    stop: bool,
) -> Result<i32> {
    // The daemon refuses relative paths (it has no meaningful cwd).
    let out = std::path::absolute(&output)?;
    if out.exists() {
        bail!(
            "output file {} exists; remove it or choose another path",
            out.display()
        );
    }
    let mut client = DaemonClient::connect_spawning_izba(paths)?;
    match client.request(
        &DaemonRequest::Save {
            names,
            all,
            out,
            with_workspace,
            stop,
        },
        &mut |m| eprintln!("{m}"),
    )? {
        DaemonResponse::Saved(r) => {
            println!("{}", render_save_report(&r));
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected daemon response to save: {other:?}"),
    }
}

pub(crate) fn render_save_report(r: &SaveReport) -> String {
    let mut s = format!("saved to {}\n", display_path(&r.path));
    s.push_str(&format!("sandboxes: {}\n", r.sandboxes.join(", ")));
    s.push_str(&format!(
        "{} logical -> {} archive\n",
        human_bytes(r.logical_bytes),
        human_bytes(r.archive_bytes)
    ));
    for w in &r.warnings {
        s.push_str(&format!("warning: {w}\n"));
    }
    s.push_str(
        "The archive may contain secrets from the sandbox disks and workspace \
         (e.g. .env files); treat it like a credential.",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lists_path_sizes_warnings_and_secrets_note() {
        let r = SaveReport {
            path: "/tmp/x.izba".into(),
            sandboxes: vec!["a".into(), "b".into()],
            logical_bytes: 8 << 30,
            archive_bytes: 312 << 20,
            warnings: vec!["skipped socket".into()],
        };
        let t = render_save_report(&r);
        assert!(t.contains("/tmp/x.izba"), "{t}");
        assert!(t.contains("a, b"), "{t}");
        assert!(t.contains("8.0 GiB logical"), "{t}");
        assert!(t.contains("312.0 MiB archive"), "{t}");
        assert!(t.contains("warning: skipped socket"), "{t}");
        assert!(t.contains("may contain secrets"), "{t}");
    }
}
