use crate::{artifacts, terminal, SandboxOpts};
use izba_core::paths::Paths;
use izba_core::state::CONFIG_FILE;
use izba_core::vmm::cloud_hypervisor::CloudHypervisorDriver;
use izba_core::{image, sandbox};
use std::path::Path;

pub fn run(
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let name = resolve_or_create(paths, opts, name_or_dir)?;
    let art = artifacts::locate(paths)?;
    match sandbox::start(paths, &name, &CloudHypervisorDriver, &art) {
        Ok(()) => {}
        // `run` is idempotent: already running is exactly the state we want.
        Err(e) if e.to_string().contains("already running") => {}
        Err(e) => return Err(e),
    }
    let cmd = if cmd.is_empty() {
        vec!["/bin/sh".to_string(), "-l".to_string()]
    } else {
        cmd
    };
    let tty = terminal::is_tty(libc::STDIN_FILENO);
    super::exec::run(paths, &name, true, tty, cmd)
}

/// NAME_OR_DIR: an existing sandbox name wins; anything else is a workspace
/// directory (created if missing), with the sandbox created on first use.
fn resolve_or_create(
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
) -> anyhow::Result<String> {
    if sandbox::validate_name(name_or_dir).is_ok()
        && paths.sandbox_dir(name_or_dir).join(CONFIG_FILE).is_file()
    {
        return Ok(name_or_dir.to_string());
    }
    let workspace = super::ensure_workspace(Path::new(name_or_dir))?;
    let name = super::name_for(opts, &workspace)?;
    if !paths.sandbox_dir(&name).join(CONFIG_FILE).is_file() {
        eprintln!("pulling {}...", opts.image);
        let digest = image::ensure_image(paths, &opts.image)?;
        sandbox::create(paths, &name, &super::create_opts(opts, digest, workspace))?;
    }
    Ok(name)
}
