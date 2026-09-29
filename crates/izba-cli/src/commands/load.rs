//! `izba load` — restore sandboxes from a `.izba` archive written by
//! `izba save`. Daemon-side work; this is the thin client + report.

use std::path::PathBuf;

use anyhow::{bail, Result};
use izba_core::bundle::load::LoadReport;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::{display_path, Paths};

#[mutants::skip] // reason: daemon-boundary glue (cwd absolutize + connect + print); exercised by the save/load e2e. The output logic is render_load_report, unit-tested.
pub fn run(
    paths: &Paths,
    archive: PathBuf,
    select: Vec<String>,
    rename: Option<String>,
    workspace: Option<PathBuf>,
    workspace_root: Option<PathBuf>,
) -> Result<i32> {
    // The daemon refuses relative paths (it has no meaningful cwd).
    let abs = |p: PathBuf| std::path::absolute(p);
    let archive = abs(archive)?;
    let workspace = workspace.map(abs).transpose()?;
    let workspace_root = workspace_root.map(abs).transpose()?;
    let mut client = DaemonClient::connect_spawning_izba(paths)?;
    match client.request(
        &DaemonRequest::Load {
            archive,
            select,
            rename,
            workspace,
            workspace_root,
        },
        &mut |m| eprintln!("{m}"),
    )? {
        DaemonResponse::Loaded(r) => {
            println!("{}", render_load_report(&r));
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected daemon response to load: {other:?}"),
    }
}

pub(crate) fn render_load_report(r: &LoadReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    for s in &r.sandboxes {
        lines.push(format!(
            "loaded '{}' (workspace: {})",
            s.name,
            display_path(&s.workspace)
        ));
    }
    for w in &r.warnings {
        lines.push(format!("warning: {w}"));
    }
    if !r.redo.is_empty() {
        lines.push("To redo on this host:".to_string());
        lines.extend(r.redo.iter().map(|x| format!("  {x}")));
    }
    for s in &r.sandboxes {
        lines.push(format!("Start it with: izba start {}", s.name));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::bundle::load::LoadedSandbox;

    fn report(redo: Vec<String>) -> LoadReport {
        LoadReport {
            sandboxes: vec![LoadedSandbox {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                workspace: "/home/u/web".into(),
            }],
            warnings: vec!["port 8080 busy".into()],
            redo,
        }
    }

    #[test]
    fn report_lists_sandboxes_warnings_and_start_hint() {
        let t = render_load_report(&report(vec![]));
        assert!(t.contains("loaded 'web' (workspace: /home/u/web)"), "{t}");
        assert!(t.contains("warning: port 8080 busy"), "{t}");
        assert!(t.contains("izba start web"), "{t}");
        assert!(!t.contains("To redo on this host:"), "{t}");
    }

    #[test]
    fn redo_block_only_when_non_empty() {
        let t = render_load_report(&report(vec!["re-plug USB 1234:5678".into()]));
        assert!(t.contains("To redo on this host:"), "{t}");
        assert!(t.contains("re-plug USB 1234:5678"), "{t}");
    }
}
