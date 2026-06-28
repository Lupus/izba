//! `izba promote` — apply izba.yml -> managed truth, gated on a prior `izba
//! diff` review. Live fields apply immediately; restart fields update
//! config.json and take effect on next start (or now with --restart).

use std::path::Path;

use anyhow::{bail, Result};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::manifest::normalize::ImageSource;
use izba_core::manifest::{apply, store, Normalized};
use izba_core::paths::Paths;

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

    // Write managed truth (config.json + policy.yaml).
    apply::write_managed(paths, &name, &repo, &digest)?;

    // Enact live effects via the daemon.
    let mut client = DaemonClient::connect(paths)?;
    if p.policy_changed {
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

    // Restart-class fields (cpus, memory, image): apply now or note for later.
    if !p.restart_fields.is_empty() {
        if restart {
            send_ok(&mut client, &DaemonRequest::Stop { name: name.clone() })?;
            // Reset the rw scratch overlay to a blank state on the new base
            // before starting, so the image change boots cleanly.
            if p.image_changed && reset_scratch {
                izba_core::sandbox::reset_rw_scratch(paths, &name)?;
            }
            send_ok(
                &mut client,
                &DaemonRequest::Start {
                    name: name.clone(),
                    allow_unconfined: false,
                },
            )?;
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
