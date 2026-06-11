pub mod cp;
pub mod create;
pub mod daemon;
pub mod exec;
pub mod ls;
pub mod port;
pub mod rm;
pub mod run;
pub mod stop;

use crate::name;
use crate::SandboxOpts;
use anyhow::Context;
use izba_core::sandbox::CreateOpts;
use izba_core::state::PortRule;
use std::path::{Path, PathBuf};

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

fn create_opts(
    opts: &SandboxOpts,
    digest: String,
    workspace: PathBuf,
    ports: Vec<PortRule>,
) -> CreateOpts {
    CreateOpts {
        image_digest: digest,
        image_ref: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: opts.rw_size_gb,
        ports,
    }
}
