//! `izba diff` — structural drift between `izba.yml` and the managed truth,
//! recording a review token so `promote` knows what the human saw.

use std::path::Path;

use anyhow::Result;
use izba_core::manifest::diff::{FieldClass, FieldDelta};
use izba_core::manifest::{self, store, DriftState, Normalized};
use izba_core::paths::Paths;

pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    let (m, raw, dockerfile) = super::load_repo_manifest(dir)?;
    let default_name = super::workspace_default_name(dir)?;
    let repo = Normalized::from_manifest(&m, &default_name)?;
    let name = name_override.unwrap_or(&repo.name).to_string();

    let managed = super::managed_normalized(paths, &name)?;
    let base = store::read_base(&paths.sandbox_dir(&name))?
        .map(|bm| Normalized::from_manifest(&bm, &default_name))
        .transpose()?
        .unwrap_or_else(|| managed.clone());

    let state = manifest::classify(&base, &repo, &managed);
    // The deltas the human is asked to review are repo-relative-to-managed.
    let deltas = manifest::diff_normalized(&managed, &repo);
    println!("{}", render_deltas(state, &deltas));

    // Record the review token over exactly what we showed.
    store::write_review(
        &paths.sandbox_dir(&name),
        &store::review_token(&raw, dockerfile.as_deref()),
    )?;
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
