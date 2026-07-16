//! `izba diff` — structural drift between `izba.yml` and the managed truth,
//! recording a review token so `promote` knows what the human saw.

use anyhow::{Context, Result};
use izba_core::manifest::diff::{FieldClass, FieldDelta};
use izba_core::manifest::{store, DriftState};
use izba_core::paths::Paths;

#[mutants::skip] // reason: reads managed truth from disk + writes the review token for a managed sandbox; orchestration exercised by daemon_e2e (manifest_diff_promote_live_path). The pure pieces (sandbox_ref::resolve, ops::compute_diff, render_deltas) are unit-tested separately.
pub fn run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32> {
    // #123: NAME-or-DIR positional through the shared resolver. A bare sandbox
    // name resolves to the workspace recorded in its config.json.
    let r = super::sandbox_ref::resolve(paths, target)?;
    super::sandbox_ref::check_name_override(&r, name_override)?;
    let dir = r
        .workspace
        .clone()
        .with_context(|| format!("sandbox '{}' has no recorded workspace directory", r.name))?;
    let name = match name_override {
        Some(n) => n.to_string(),
        None => r.name,
    };

    // Delegate the pure filesystem logic to ops (shared with the desktop app).
    let (state, deltas, token) = izba_core::manifest::ops::compute_diff(paths, &dir, &name)?;
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
        if d.from.contains('\n') || d.to.contains('\n') {
            // Multi-line value (egress YAML, per-line ports/volumes): the
            // inline `from -> to` form would embed raw newlines mid-sentence,
            // so render an indented from/to block instead.
            s.push_str(&format!("  {}:  [{}]{}\n", d.field, class, warn));
            s.push_str("    from:\n");
            for l in d.from.lines() {
                s.push_str(&format!("      {l}\n"));
            }
            s.push_str("    to:\n");
            for l in d.to.lines() {
                s.push_str(&format!("      {l}\n"));
            }
        } else {
            s.push_str(&format!(
                "  {}: {} -> {}  [{}]{}\n",
                d.field, d.from, d.to, class, warn
            ));
        }
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

    /// A multi-line value (egress YAML, per-line ports) renders as an indented
    /// from/to block — never inline, which would splice raw newlines into the
    /// middle of a `from -> to` sentence.
    #[test]
    fn render_multiline_value_as_indented_block() {
        let deltas = vec![FieldDelta {
            field: "ports".into(),
            from: "(none)".into(),
            to: "127.0.0.1:8080:80\n0.0.0.0:9000:90".into(),
            class: FieldClass::Live,
            weakens_egress: false,
        }];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(s.contains("  ports:  [live]\n"), "block header: {s}");
        assert!(s.contains("    from:\n      (none)\n"), "from block: {s}");
        assert!(
            s.contains("    to:\n      127.0.0.1:8080:80\n      0.0.0.0:9000:90\n"),
            "to block keeps one item per line: {s}"
        );
        assert!(
            !s.contains("-> 127.0.0.1"),
            "multi-line values must not render inline: {s}"
        );
    }
}
