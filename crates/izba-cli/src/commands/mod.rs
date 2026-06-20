pub mod cp;
pub mod create;
pub mod daemon;
pub mod exec;
pub mod lockdown;
pub mod ls;
pub mod netlog;
pub mod policy;
pub mod port;
pub mod reconcile;
pub mod rm;
pub mod run;
pub mod status;
pub mod stop;
pub mod version;
pub mod volume;

use crate::name;
use crate::SandboxOpts;
use anyhow::Context;
use izba_core::state::PortRule;
use std::path::{Path, PathBuf};

/// Map a daemon reply that should be `Ok` into `Result<()>`.
pub(crate) fn expect_ok(resp: izba_core::daemon::proto::DaemonResponse) -> anyhow::Result<()> {
    use izba_core::daemon::proto::DaemonResponse;
    match resp {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected daemon reply: {other:?}"),
    }
}

/// Resolve the sandbox name for a workspace dir: `--name` wins, otherwise
/// the directory's basename, sanitized.
fn name_for(opts: &SandboxOpts, workspace: &Path) -> anyhow::Result<String> {
    if let Some(n) = &opts.name {
        izba_core::sandbox::validate_name(n)?;
        return Ok(n.clone());
    }
    let base = workspace
        .file_name()
        .with_context(|| format!("{} has no basename; pass --name", workspace.display()))?;
    name::sanitize(&base.to_string_lossy())
}

/// Create the workspace dir if missing and canonicalize it.
fn ensure_workspace(dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating workspace {}", dir.display()))?;
    dir.canonicalize()
        .with_context(|| format!("resolving workspace {}", dir.display()))
}

/// Parse the repeatable `-p/--publish` specs into PortRules.
pub fn parse_publish(specs: &[String]) -> anyhow::Result<Vec<PortRule>> {
    specs
        .iter()
        .map(|s| izba_core::portfwd::parse_rule(s))
        .collect()
}

/// Parse the repeatable `--volume` specs into VolumeSpecs and validate the set
/// (count ceiling, unique guest paths + names).
pub fn parse_volumes(specs: &[String]) -> anyhow::Result<Vec<izba_core::volume::VolumeSpec>> {
    let volumes = specs
        .iter()
        .map(|s| izba_core::volume::parse_volume_flag(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    izba_core::volume::validate_volumes(&volumes)?;
    Ok(volumes)
}

/// Assemble the daemon `Create` request from already-parsed inputs. Centralized
/// (and unit-tested) so `create` and `run` build the frame identically — in
/// particular both carry the **confinement intent**: `allow_unconfined = false`
/// (the `create` default) makes the daemon run the workspace confinement
/// preflight and reject a workspace it cannot relabel before anything is
/// created; `run --allow-unconfined` threads `true` so that preflight is skipped
/// (the VMM will not relabel the workspace).
pub(crate) fn build_create_request(
    name: String,
    opts: &SandboxOpts,
    workspace: PathBuf,
    ports: Vec<PortRule>,
    volumes: Vec<izba_core::volume::VolumeSpec>,
    allow_unconfined: bool,
) -> izba_core::daemon::proto::DaemonCreate {
    izba_core::daemon::proto::DaemonCreate {
        name,
        image_ref: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: opts.rw_size_gb,
        ports,
        volumes,
        allow_unconfined,
    }
}

/// Validate a `--policy` file and persist it into the sandbox directory as
/// `policy.yaml` (the daemon loads it when arming the sandbox's egress plane).
/// No-op when no policy was given. Must run after the sandbox dir exists.
pub(crate) fn persist_policy(
    paths: &izba_core::paths::Paths,
    name: &str,
    policy: Option<&Path>,
) -> anyhow::Result<()> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    let Some(src) = policy else {
        return Ok(());
    };
    let raw = std::fs::read_to_string(src)
        .with_context(|| format!("reading egress policy {}", src.display()))?;
    // Fail fast at create on a malformed allow-list rather than at boot.
    EgressPolicyConfig::from_yaml(&raw)
        .with_context(|| format!("invalid egress policy {}", src.display()))?;
    let dst = EgressPolicyConfig::path_in(&paths.sandbox_dir(name));
    std::fs::write(&dst, raw).with_context(|| format!("writing {}", dst.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SandboxOpts {
        SandboxOpts {
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem: 4096,
            rw_size_gb: 8,
            name: None,
            publish: vec![],
            policy: None,
            volumes: vec![],
        }
    }

    #[test]
    fn build_create_request_maps_opts_and_carries_confinement_intent() {
        let o = opts();
        let confined = build_create_request(
            "web".into(),
            &o,
            PathBuf::from("/ws"),
            vec![],
            vec![],
            false,
        );
        assert_eq!(confined.name, "web");
        assert_eq!(confined.image_ref, "ubuntu:24.04");
        assert_eq!(confined.cpus, 2);
        assert_eq!(confined.mem_mb, 4096);
        assert_eq!(confined.workspace, PathBuf::from("/ws"));
        assert_eq!(confined.rw_size_gb, 8);
        // `create` (and a plain `run`) default to confined intent, so the daemon
        // runs the workspace preflight.
        assert!(!confined.allow_unconfined);

        // `run --allow-unconfined` threads the opt-out so the preflight is skipped.
        let unconfined =
            build_create_request("web".into(), &o, PathBuf::from("/ws"), vec![], vec![], true);
        assert!(unconfined.allow_unconfined);
    }
}
