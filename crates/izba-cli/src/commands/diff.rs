//! `izba diff` — structural drift between `izba.yml` and the managed truth,
//! recording a review token so `promote` knows what the human saw.

use std::path::Path;

use anyhow::Result;
use izba_core::manifest::diff::{FieldClass, FieldDelta};
use izba_core::manifest::{store, DriftState};
use izba_core::paths::Paths;

pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    // Resolve the sandbox name. Name resolution is CLI-side: workspace_default_name
    // depends on name::sanitize which lives in the CLI crate and cannot move to
    // core without creating a circular dependency.
    let (m, _, _) = super::load_repo_manifest(dir)?;
    let default_name = super::workspace_default_name(dir)?;
    let name = match name_override {
        Some(n) => n.to_string(),
        None => m.metadata.name.unwrap_or(default_name),
    };

    // Delegate the pure filesystem logic to ops (shared with the desktop app).
    let (state, deltas, token) = izba_core::manifest::ops::compute_diff(paths, dir, &name)?;
    println!("{}", render_deltas(state, &deltas));

    // Record the review token over exactly what we showed.
    store::write_review(&paths.sandbox_dir(&name), &token)?;
    Ok(0)
}

pub(crate) fn render_deltas(state: DriftState, deltas: &[FieldDelta]) -> String {
    let mut s = String::new();
    let label = match state {
        DriftState::InSync => "in sync",
        DriftState::RepoAhead => "repo ahead (promotable)",
        DriftState::ManagedAhead => "managed ahead (export to capture)",
        DriftState::Diverged => "diverged (repo and managed both changed)",
    };
    s.push_str(&format!("state: {label}\n"));
    if deltas.is_empty() {
        s.push_str("no field changes between manifest and managed truth.\n");
        return s;
    }
    for d in deltas {
        let class = match d.class {
            FieldClass::Live => "live",
            FieldClass::Restart => "restart",
            FieldClass::Image => "image (restart)",
        };
        let warn = if d.weakens_egress {
            "  ⚠ weakens egress"
        } else {
            ""
        };
        s.push_str(&format!(
            "  {}: {} -> {}  [{}]{}\n",
            d.field, d.from, d.to, class, warn
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::manifest::diff::{FieldClass, FieldDelta};
    use izba_core::manifest::DriftState;

    #[test]
    fn render_groups_by_class_and_flags_weakening() {
        let deltas = vec![
            FieldDelta {
                field: "cpus".into(),
                from: "2".into(),
                to: "4".into(),
                class: FieldClass::Restart,
                weakens_egress: false,
            },
            FieldDelta {
                field: "egress".into(),
                from: "a".into(),
                to: "b".into(),
                class: FieldClass::Live,
                weakens_egress: true,
            },
        ];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(s.contains("repo ahead") || s.contains("RepoAhead"));
        assert!(s.contains("cpus"));
        assert!(s.contains("restart"), "restart class labelled");
        assert!(s.contains('⚠'), "weakening flagged: {s}");
    }

    #[test]
    fn render_in_sync_is_terse() {
        let s = render_deltas(DriftState::InSync, &[]);
        assert!(s.to_lowercase().contains("in sync"));
    }
}
