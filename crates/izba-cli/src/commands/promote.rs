//! `izba promote` — apply izba.yml -> managed truth, gated on a prior `izba
//! diff` review. Live fields apply immediately; restart fields update
//! config.json and take effect on next start (or now with --restart).

use std::path::Path;

use anyhow::{bail, Result};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::manifest::normalize::ImageSource;
use izba_core::manifest::{apply, diff_normalized, store, Normalized};
use izba_core::paths::Paths;
use izba_core::state::{load_json, RunState, STATE_FILE};

/// Outcome of the review gate: did the human's review token match?
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GateOutcome {
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
pub(crate) fn gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome {
    match (review, force) {
        (Some(t), _) if t == current_token => GateOutcome::Ok,
        (None, false) => GateOutcome::NeverReviewed,
        (None, true) => GateOutcome::ForcedUnreviewed,
        (Some(_), false) => GateOutcome::Stale,
        (Some(_), true) => GateOutcome::ForcedStale,
    }
}

pub fn run(
    paths: &Paths,
    dir: &Path,
    name_override: Option<&str>,
    force: bool,
    restart: bool,
    reset_scratch: bool,
) -> Result<i32> {
    let (m, raw, dockerfile) = super::load_repo_manifest(dir)?;
    let default_name = super::workspace_default_name(dir)?;
    let repo = Normalized::from_manifest(&m, &default_name)?;
    let name = name_override.unwrap_or(&repo.name).to_string();
    let dir_managed = paths.sandbox_dir(&name);

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
            eprintln!("WARNING: --force: promoting changes that were never reviewed");
        }
        GateOutcome::ForcedStale => {
            eprintln!(
                "WARNING: --force: izba.yml changed since review — promoting UNREVIEWED changes"
            );
        }
    }

    let managed = super::managed_normalized(paths, &name)?;
    let p = apply::plan(&managed, &repo);

    // Fix 2: Refuse an image-change promote without --restart. A new image
    // requires the rw scratch overlay to be reset on the new base; writing the
    // new digest to config.json without restarting leaves the guest in a state
    // where `izba start` boots the new image over an overlay built for the old
    // one — which can be UNBOOTABLE due to missing libs / wrong ABI.
    if p.image_changed && !restart {
        bail!(
            "image change requires --restart (the rw scratch overlay must be reset              on the new base; pass --restart, optionally with --reset-scratch=false              to keep the old overlay at your own risk)"
        );
    }

    // Fix 4: Warn about egress weakening BEFORE applying, even under --force,
    // so the user always sees the security implications of their change.
    {
        let weakening: Vec<_> = diff_normalized(&managed, &repo)
            .into_iter()
            .filter(|d| d.weakens_egress)
            .collect();
        if !weakening.is_empty() {
            let fields: Vec<_> = weakening.iter().map(|d| d.field.as_str()).collect();
            eprintln!("WARNING: weakens egress: {}", fields.join(", "));
        }
    }

    // Resolve the image digest for the target (host-side; no proto bump).
    let digest = match &repo.image {
        ImageSource::Ref(r) => izba_core::image::ensure_image(paths, r)?,
        ImageSource::Build(b) => {
            let opts = build_opts_from(dir, b);
            crate::commands::build::build_image(paths, &opts)?
        }
    };

    // Expert-only warning: keeping the old rw overlay on a new base can render
    // the guest UNBOOTABLE due to missing libs or ABI mismatches.
    if p.image_changed && !reset_scratch {
        eprintln!(
            "WARNING: --reset-scratch=false keeps the rw overlay built on the PREVIOUS image. \
             Packages installed (e.g. apt-get) against the old base may have missing libs / \
             wrong ABI on the new image and can render the guest UNBOOTABLE. Proceed only if \
             you understand overlay semantics."
        );
    }

    let mut client = DaemonClient::connect(paths)?;

    // Fix 5: Skip live daemon RPCs when the sandbox is not running — the
    // managed config committed below takes effect on the next `izba start`.
    // Stop/Start (the restart branch below) is a lifecycle operation, not a
    // "live RPC", so it is still driven by the --restart flag regardless.
    let is_running =
        match client.request(&DaemonRequest::Inspect { name: name.clone() }, &mut |_| {}) {
            Ok(DaemonResponse::Inspect(det)) => det.status != "stopped",
            _ => false,
        };

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
                &DaemonRequest::ReloadPolicy { name: name.clone() },
            )?;
        }
        for r in &p.ports_removed {
            send_ok(
                &mut client,
                &DaemonRequest::PortUnpublish {
                    name: name.clone(),
                    bind: r.bind,
                    host_port: r.host_port,
                },
            )?;
        }
        for r in &p.ports_added {
            send_ok(
                &mut client,
                &DaemonRequest::PortPublish {
                    name: name.clone(),
                    rule: r.clone(),
                    persist: true,
                },
            )?;
        }
        for gp in &p.volumes_removed {
            send_ok(
                &mut client,
                &DaemonRequest::VolumeDetach {
                    name: name.clone(),
                    guest_path: gp.clone(),
                },
            )?;
        }
        for v in &p.volumes_added {
            send_ok(
                &mut client,
                &DaemonRequest::VolumeAttach {
                    name: name.clone(),
                    spec: v.clone(),
                },
            )?;
        }
    } else {
        eprintln!("sandbox not running — changes apply on next start");
    }

    // Commit the durable managed truth (config.json + policy.yaml)
    // unconditionally — whether the sandbox is running or not.
    // `Stop`→`Start` below reads config.json from disk, so this must precede
    // the restart branch.
    apply::write_managed(paths, &name, &repo, &digest)?;

    // Restart-class fields (cpus, memory, image): apply now or note for later.
    if !p.restart_fields.is_empty() {
        if restart {
            // Fix 3a: Read the confinement mode BEFORE Stop — stop clears
            // state.json, so we must capture allow_unconfined before the VMM
            // is torn down. Default to false (confined, safe) when the file is
            // absent or unreadable (sandbox already stopped).
            let run_state: Option<RunState> = load_json(&paths.sandbox_dir(&name).join(STATE_FILE))
                .ok()
                .flatten();
            let allow_unconfined = run_state
                .and_then(|s| s.confinement)
                .map(|c| !c.is_confined())
                .unwrap_or(false);

            send_ok(&mut client, &DaemonRequest::Stop { name: name.clone() })?;
            // Reset the rw scratch overlay to a blank state on the new base
            // before starting, so the image change boots cleanly.
            if p.image_changed && reset_scratch {
                izba_core::sandbox::reset_rw_scratch(paths, &name)?;
            }
            // Fix 3b: Surface a helpful retry hint if Start fails after Stop —
            // the config was already committed so a plain `izba start` is safe.
            if let Err(err) = send_ok(
                &mut client,
                &DaemonRequest::Start {
                    name: name.clone(),
                    allow_unconfined,
                },
            ) {
                bail!(
                    "failed to start sandbox after promote (config already committed);                      run `izba start {name}` to retry: {err}"
                );
            }
            println!("restarted to apply: {}", p.restart_fields.join(", "));
        } else {
            println!(
                "pending restart to apply: {} (run `izba promote --restart` or restart manually)",
                p.restart_fields.join(", ")
            );
            if p.image_changed {
                println!(
                    "note: image change is pending the next restart; scratch reset \
                     (--reset-scratch) will only happen when restarted via \
                     `izba promote --restart` (cannot reset a running VM's disk)"
                );
            }
        }
    }

    // Advance the base + clear the consumed review token.
    store::write_base(&dir_managed, &m)?;
    store::clear_review(&dir_managed)?;
    println!("promoted {name}");
    Ok(0)
}

fn build_opts_from(
    dir: &Path,
    b: &izba_core::manifest::schema::BuildSpec,
) -> crate::commands::build::BuildOpts {
    let context = dir.join(b.context.as_deref().unwrap_or("."));
    let dockerfile = context.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
    crate::commands::build::BuildOpts {
        dockerfile,
        tag: b.tag.clone(),
        context,
        build_allow: b.allow.clone(),
        cpus: b.resources.as_ref().map(|r| r.cpus).unwrap_or(2),
        mem: b
            .resources
            .as_ref()
            .and_then(|r| izba_core::manifest::quantity::parse_mib(&r.memory).ok())
            .unwrap_or(4096),
    }
}

fn send_ok(client: &mut DaemonClient, req: &DaemonRequest) -> Result<()> {
    match client.request(req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
