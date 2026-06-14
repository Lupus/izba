pub mod cp;
pub mod create;
pub mod daemon;
pub mod exec;
pub mod ls;
pub mod netlog;
pub mod port;
pub mod rm;
pub mod run;
pub mod stop;
pub mod version;

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
