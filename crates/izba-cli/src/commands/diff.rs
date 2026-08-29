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

/// The direction-aware recommendation for a drift that would WEAKEN egress,
/// with `izba.yml` ahead of the managed truth.
///
/// BYTE-SHARED with the desktop app's Manifest tab
/// (`app/src/components/ManifestTab.tsx`): the two surfaces render the exact
/// same sentence, and a test on each side pins it. Change both together —
/// a copy that drifts turns one surface's guidance into a different one's.
const WEAKENS_REPO_AHEAD: &str = "izba.yml would weaken egress relative to the current managed settings. Keep the managed settings as they are — Promote only if you intend to relax enforcement.";

/// Weakening drift with the managed truth ahead. Byte-shared with
/// `app/src/components/ManifestTab.tsx` — see [`WEAKENS_REPO_AHEAD`].
const WEAKENS_MANAGED_AHEAD: &str = "izba.yml would weaken egress relative to the current managed settings. Export to capture the managed settings into izba.yml.";

/// Weakening drift with both sides changed. Byte-shared with
/// `app/src/components/ManifestTab.tsx` — see [`WEAKENS_REPO_AHEAD`].
const WEAKENS_DIVERGED: &str = "izba.yml would weaken egress relative to the current managed settings. Export to capture the managed settings into izba.yml — or Promote only if you intend to relax enforcement.";

/// `Diverged` with an EMPTY delta list: both sides moved since the last
/// reconcile but landed on the same values, so "diverged" + "no field
/// changes" reads like a contradiction with no next step. Byte-shared with
/// `app/src/components/ManifestTab.tsx` — see [`WEAKENS_REPO_AHEAD`].
const DIVERGED_NO_DELTAS: &str = "Both izba.yml and managed settings changed since the last reconcile, but they now hold the same values — there is nothing to apply. Export to realign izba.yml and clear the drift.";

/// The `next:` recommendation for a drift report.
///
/// #241: the recommendation follows the DIRECTION of the drift, not just its
/// state. `ops::compute_diff` diffs `(managed, repo)`, so `weakens_egress`
/// means "promoting `izba.yml` would weaken egress" — the state label alone
/// would steer the reader toward the very action flagged `⚠ weakens egress`
/// two lines below. When any delta weakens egress the recommendation leads
/// with that fact and points at the managed settings instead.
///
/// The weakening strings (and the empty-delta `Diverged` one) are shared
/// verbatim with the desktop app; the rest is CLI-native wording naming the
/// `izba promote` / `izba export` subcommands.
fn recommendation(state: DriftState, deltas: &[FieldDelta]) -> &'static str {
    let weakens = deltas.iter().any(|d| d.weakens_egress);
    match (state, weakens) {
        (DriftState::RepoAhead, true) => WEAKENS_REPO_AHEAD,
        (DriftState::ManagedAhead, true) => WEAKENS_MANAGED_AHEAD,
        (DriftState::Diverged, true) => WEAKENS_DIVERGED,
        (DriftState::Diverged, false) if deltas.is_empty() => DIVERGED_NO_DELTAS,
        (DriftState::InSync, _) => "in sync — izba.yml and the managed truth match; nothing to do.",
        (DriftState::RepoAhead, false) => {
            "review the changes below, then izba promote to apply izba.yml."
        }
        (DriftState::ManagedAhead, false) => {
            "izba export to capture the managed settings into izba.yml."
        }
        (DriftState::Diverged, false) => {
            "izba promote applies izba.yml; izba export overwrites it with the managed settings."
        }
    }
}

/// Render the drift report.
///
/// #240: every delta names which side is which. `ops::compute_diff` calls
/// `diff_normalized(&managed, &repo)`, so in every `FieldDelta` `from` is the
/// LIVE MANAGED TRUTH and `to` is what `izba.yml` proposes — a direction the
/// bare `a -> b` form left the reader to guess.
///
/// The left-hand side is labelled `managed`, deliberately NOT `live`:
/// `FieldClass::Live` already renders as a `[live]` class badge in the same
/// row (it means "applies without a restart"), and the two would be
/// confusable. The desktop app's Manifest tab uses the same wording.
///
/// The orientation legend obeys the same rule and glosses `managed` as
/// `(current)` rather than `(live truth)`: an egress delta renders its
/// `[live]` class badge one line below the legend, so spending the word
/// there would reintroduce the collision the column wording exists to
/// avoid — with the two senses two lines apart, which is worse than either
/// alone.
///
/// #241: the `state:` label names WHERE the drift is, so a `next:` line
/// right below it names what to DO about it — direction-aware, because a
/// delta that weakens egress makes `promote` the wrong recommendation even
/// though the state is still "repo ahead (promotable)". See
/// [`recommendation`]. The label itself is byte-frozen (the dogfood GUI
/// oracle maps those exact strings back to drift states), so the guidance
/// had to land on a line of its own rather than inside it.
pub(crate) fn render_deltas(state: DriftState, deltas: &[FieldDelta]) -> String {
    let mut s = String::new();
    let label = match state {
        DriftState::InSync => "in sync",
        DriftState::RepoAhead => "repo ahead (promotable)",
        DriftState::ManagedAhead => "managed ahead (export to capture)",
        DriftState::Diverged => "diverged (repo and managed both changed)",
    };
    s.push_str(&format!("state: {label}\n"));
    // Two spaces after the colon so the value column aligns with `state:`.
    s.push_str(&format!("next:  {}\n", recommendation(state, deltas)));
    if deltas.is_empty() {
        s.push_str("no field changes between manifest and managed truth.\n");
        return s;
    }
    // Only when there is something to attribute — the in-sync path stays terse.
    s.push_str("showing: managed (current) -> izba.yml (proposed)\n");
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
            s.push_str("    from (managed):\n");
            for l in d.from.lines() {
                s.push_str(&format!("      {l}\n"));
            }
            s.push_str("    to (izba.yml):\n");
            for l in d.to.lines() {
                s.push_str(&format!("      {l}\n"));
            }
        } else {
            s.push_str(&format!(
                "  {}: {} (managed) -> {} (izba.yml)  [{}]{}\n",
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

    /// The legend that tells the reader which side is the live managed truth.
    const LEGEND: &str = "showing: managed (current) -> izba.yml (proposed)\n";

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

    /// #240 (a): the inline single-line form names BOTH sides — the left is the
    /// live managed truth, the right is what `izba.yml` proposes.
    #[test]
    fn render_inline_labels_managed_and_manifest_sides() {
        let deltas = vec![FieldDelta {
            field: "cpus".into(),
            from: "2".into(),
            to: "4".into(),
            class: FieldClass::Restart,
            weakens_egress: false,
        }];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(
            s.contains("  cpus: 2 (managed) -> 4 (izba.yml)  [restart]\n"),
            "inline row labels both sides: {s}"
        );
    }

    /// #240 (b): the multi-line BLOCK form labels both sides too — this is the
    /// form the acceptance criteria call out explicitly, since an unlabelled
    /// `from:`/`to:` block is where the direction is least guessable.
    #[test]
    fn render_block_labels_managed_and_manifest_sides() {
        let deltas = vec![FieldDelta {
            field: "egress".into(),
            from: "allow:\n  - github.com".into(),
            to: "allow:\n  - github.com\n  - pypi.org".into(),
            class: FieldClass::Live,
            weakens_egress: true,
        }];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(
            s.contains("    from (managed):\n"),
            "block from-heading names the managed side: {s}"
        );
        assert!(
            s.contains("    to (izba.yml):\n"),
            "block to-heading names the manifest side: {s}"
        );
    }

    /// #240 (c): the legend prints once, right after the `state:` line and
    /// before the first delta row.
    #[test]
    fn render_prints_legend_before_deltas() {
        let deltas = vec![FieldDelta {
            field: "cpus".into(),
            from: "2".into(),
            to: "4".into(),
            class: FieldClass::Restart,
            weakens_egress: false,
        }];
        let s = render_deltas(DriftState::RepoAhead, &deltas);
        assert!(s.contains(LEGEND), "legend printed: {s}");
        let legend_at = s.find(LEGEND).expect("legend present");
        let state_at = s.find("state:").expect("state line present");
        let row_at = s.find("  cpus:").expect("delta row present");
        assert!(
            state_at < legend_at && legend_at < row_at,
            "legend sits between the state line and the rows: {s}"
        );
    }

    /// #240 (d): the terse in-sync path stays terse — no legend when there is
    /// nothing to attribute.
    #[test]
    fn render_in_sync_omits_legend() {
        let s = render_deltas(DriftState::InSync, &[]);
        assert!(
            !s.contains("showing:"),
            "no legend on the empty-deltas path: {s}"
        );
        assert!(!s.contains("(managed)"), "no side labels either: {s}");
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
        assert!(
            s.contains("    from (managed):\n      (none)\n"),
            "from block: {s}"
        );
        assert!(
            s.contains("    to (izba.yml):\n      127.0.0.1:8080:80\n      0.0.0.0:9000:90\n"),
            "to block keeps one item per line: {s}"
        );
        assert!(
            !s.contains("-> 127.0.0.1"),
            "multi-line values must not render inline: {s}"
        );
    }

    // ---------------------------------------------------------------
    // #241: the `next:` recommendation line must follow the DIRECTION of
    // the drift. `ops::compute_diff` diffs `(managed, repo)`, so
    // `weakens_egress` means "promoting izba.yml would weaken egress" —
    // and a report that still steers the reader toward `promote` is
    // recommending the action it flags two lines below.
    // ---------------------------------------------------------------

    /// The `next:` line, minus its prefix — so a test can pin the exact
    /// recommendation text without re-deriving the padding.
    fn next_line(s: &str) -> String {
        s.lines()
            .find(|l| l.starts_with("next:"))
            .unwrap_or_else(|| panic!("no next: line in output: {s}"))
            .to_string()
    }

    fn weakening_delta() -> Vec<FieldDelta> {
        vec![FieldDelta {
            field: "egress".into(),
            from: "allow:\n  - github.com".into(),
            to: "allow:\n  - github.com\n  - evil.example".into(),
            class: FieldClass::Live,
            weakens_egress: true,
        }]
    }

    fn benign_delta() -> Vec<FieldDelta> {
        vec![FieldDelta {
            field: "cpus".into(),
            from: "2".into(),
            to: "4".into(),
            class: FieldClass::Restart,
            weakens_egress: false,
        }]
    }

    #[test]
    fn next_in_sync_recommends_nothing_to_do() {
        let s = render_deltas(DriftState::InSync, &[]);
        assert_eq!(
            next_line(&s),
            "next:  in sync — izba.yml and the managed truth match; nothing to do."
        );
    }

    #[test]
    fn next_repo_ahead_recommends_promote() {
        let s = render_deltas(DriftState::RepoAhead, &benign_delta());
        assert_eq!(
            next_line(&s),
            "next:  review the changes below, then izba promote to apply izba.yml."
        );
    }

    #[test]
    fn next_managed_ahead_recommends_export() {
        let s = render_deltas(DriftState::ManagedAhead, &benign_delta());
        assert_eq!(
            next_line(&s),
            "next:  izba export to capture the managed settings into izba.yml."
        );
    }

    #[test]
    fn next_diverged_names_both_directions() {
        let s = render_deltas(DriftState::Diverged, &benign_delta());
        assert_eq!(
            next_line(&s),
            "next:  izba promote applies izba.yml; izba export overwrites it with the managed settings."
        );
    }

    /// #241 core case: repo-ahead AND weakening. The report must NOT read
    /// as "then promote" — that is the action flagged `⚠ weakens egress`.
    #[test]
    fn next_repo_ahead_weakening_does_not_steer_to_promote() {
        let s = render_deltas(DriftState::RepoAhead, &weakening_delta());
        assert_eq!(
            next_line(&s),
            "next:  izba.yml would weaken egress relative to the current managed settings. \
             Keep the managed settings as they are — Promote only if you intend to relax enforcement."
        );
        assert!(
            s.contains("izba.yml would weaken egress relative to the current managed settings."),
            "weakening lead sentence present: {s}"
        );
        assert!(
            !s.contains("review the changes below, then izba promote"),
            "must not also carry the bare promote recommendation: {s}"
        );
    }

    #[test]
    fn next_managed_ahead_weakening_recommends_export() {
        let s = render_deltas(DriftState::ManagedAhead, &weakening_delta());
        assert_eq!(
            next_line(&s),
            "next:  izba.yml would weaken egress relative to the current managed settings. \
             Export to capture the managed settings into izba.yml."
        );
    }

    #[test]
    fn next_diverged_weakening_leads_with_export() {
        let s = render_deltas(DriftState::Diverged, &weakening_delta());
        assert_eq!(
            next_line(&s),
            "next:  izba.yml would weaken egress relative to the current managed settings. \
             Export to capture the managed settings into izba.yml — or Promote only if you \
             intend to relax enforcement."
        );
    }

    /// `diverged` + no deltas reads like a contradiction ("both changed" /
    /// "no field changes") with no next step. Name the resolution.
    #[test]
    fn next_diverged_with_no_deltas_recommends_export_to_realign() {
        let s = render_deltas(DriftState::Diverged, &[]);
        assert_eq!(
            next_line(&s),
            "next:  Both izba.yml and managed settings changed since the last reconcile, but \
             they now hold the same values — there is nothing to apply. Export to realign \
             izba.yml and clear the drift."
        );
        assert!(
            s.contains("no field changes between manifest and managed truth.\n"),
            "the empty-delta line is still printed: {s}"
        );
    }

    /// Ordering: `state:` then `next:` then the legend then the rows.
    #[test]
    fn next_line_sits_between_state_and_legend() {
        let s = render_deltas(DriftState::RepoAhead, &benign_delta());
        let state_at = s.find("state:").expect("state line present");
        let next_at = s.find("\nnext:").expect("next line present");
        let legend_at = s.find(LEGEND).expect("legend present");
        let row_at = s.find("  cpus:").expect("delta row present");
        assert!(
            state_at < next_at && next_at < legend_at && legend_at < row_at,
            "order is state -> next -> legend -> rows: {s}"
        );
    }

    /// GUARD: the four `state:` labels are a cross-tool contract.
    /// `hack/dogfood/gui/gui_oracles.py`'s `_CLI_LABEL_TO_STATE` maps these
    /// exact strings back to drift states, and the dogfood journey files
    /// carry `expect_stdout_re: "state: managed ahead"`. Rewording a label
    /// silently reds the dogfood gate — change both ends or neither.
    #[test]
    fn state_labels_are_byte_stable_for_the_dogfood_oracle_map() {
        for (st, want) in [
            (DriftState::InSync, "state: in sync\n"),
            (DriftState::RepoAhead, "state: repo ahead (promotable)\n"),
            (
                DriftState::ManagedAhead,
                "state: managed ahead (export to capture)\n",
            ),
            (
                DriftState::Diverged,
                "state: diverged (repo and managed both changed)\n",
            ),
        ] {
            let s = render_deltas(st, &benign_delta());
            assert!(s.starts_with(want), "label byte-stable, got: {s}");
        }
    }

    /// 97af81c4 / 607fc3c6: the word "live" may name only the `[live]`
    /// CLASS badge (applies without a restart), never a SIDE of the diff.
    /// Scoped to the header lines — a delta row legitimately carries the
    /// badge.
    #[test]
    fn header_lines_never_use_live_as_a_side_label() {
        let cases = [
            render_deltas(DriftState::InSync, &[]),
            render_deltas(DriftState::Diverged, &[]),
            render_deltas(DriftState::RepoAhead, &benign_delta()),
            render_deltas(DriftState::ManagedAhead, &weakening_delta()),
            render_deltas(DriftState::Diverged, &weakening_delta()),
        ];
        for s in &cases {
            for l in s.lines().filter(|l| {
                l.starts_with("state:") || l.starts_with("next:") || l.starts_with("showing:")
            }) {
                assert!(
                    !l.to_lowercase().contains("live"),
                    "header line names a side 'live': {l}"
                );
            }
        }
    }

    /// AC5, machine-enforced: the two surfaces must never recommend
    /// contradictory actions for identical input.
    ///
    /// The four shared strings are declared independently in two languages,
    /// so a doc comment saying "change both together" is not a gate — it is a
    /// note a future editor can miss while every test on both sides still
    /// passes. This test reads the desktop app's Manifest tab from the
    /// repository at test time and asserts each Rust const appears there
    /// VERBATIM, turning the cross-surface contract into a compile-and-run
    /// failure on `cargo test -p izba-cli` (a required gate on both
    /// platforms).
    ///
    /// The TSX side keeps each string as ONE unsplit literal for exactly this
    /// reason; a `+` concatenation would hide it from a substring check. If
    /// this test fails, the fix is to change BOTH surfaces, never to relax
    /// the assertion.
    #[test]
    fn shared_recommendation_copy_is_byte_identical_across_surfaces() {
        // `app/` is excluded from the cargo workspace, so reach it relative to
        // this crate rather than via any build-time dependency.
        let tsx_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../app/src/components/ManifestTab.tsx");
        let tsx = std::fs::read_to_string(&tsx_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", tsx_path.display()));

        for (name, shared) in [
            ("WEAKENS_REPO_AHEAD", WEAKENS_REPO_AHEAD),
            ("WEAKENS_MANAGED_AHEAD", WEAKENS_MANAGED_AHEAD),
            ("WEAKENS_DIVERGED", WEAKENS_DIVERGED),
            ("DIVERGED_NO_DELTAS", DIVERGED_NO_DELTAS),
        ] {
            assert!(
                tsx.contains(shared),
                "{name} is not present verbatim in {} — the CLI and the desktop \
                 app would recommend different things for the same drift. \
                 Expected to find:\n{shared}",
                tsx_path.display()
            );
        }
    }
}
