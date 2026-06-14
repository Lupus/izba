use crate::{terminal, SandboxOpts};
use anyhow::bail;
use izba_core::daemon::proto::{DaemonCreate, DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_core::state::CONFIG_FILE;
use std::path::Path;

pub fn run(
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let name = resolve_or_create(&mut client, paths, opts, name_or_dir)?;
    match client.request(&DaemonRequest::Start { name: name.clone() }, &mut |m| {
        eprintln!("{m}")
    })? {
        DaemonResponse::Ok => {}
        // `run` is idempotent: already running is exactly the state we want.
        DaemonResponse::Error { message } if message.contains("already running") => {}
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
    let cmd = if cmd.is_empty() {
        vec!["/bin/sh".to_string(), "-l".to_string()]
    } else {
        cmd
    };
    let tty = terminal::stdin_is_tty();
    super::exec::run(paths, &name, true, tty, cmd)
}

/// NAME_OR_DIR: an existing sandbox name wins; anything else is a workspace
/// directory (created if missing), with the sandbox created on first use.
/// Reading config.json for name resolution is the one read-only local
/// operation kept CLI-side; everything mutating goes through the daemon.
fn resolve_or_create(
    client: &mut DaemonClient,
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
) -> anyhow::Result<String> {
    if sandbox::validate_name(name_or_dir).is_ok()
        && paths.sandbox_dir(name_or_dir).join(CONFIG_FILE).is_file()
    {
        let has_non_default = opts.image != "ubuntu:24.04"
            || opts.cpus != 2
            || opts.mem != 4096
            || opts.rw_size_gb != 8
            || opts.name.is_some()
            || !opts.publish.is_empty()
            || opts.policy.is_some();
        if has_non_default {
            eprintln!(
                "warning: '{name_or_dir}' is an existing sandbox — \
                 stored config wins; --image/--cpus/--mem/--rw-size-gb/--name/--policy are ignored"
            );
        }
        return Ok(name_or_dir.to_string());
    }
    let workspace = super::ensure_workspace(Path::new(name_or_dir))?;
    let name = super::name_for(opts, &workspace)?;
    if !paths.sandbox_dir(&name).join(CONFIG_FILE).is_file() {
        let ports = super::parse_publish(&opts.publish)?;
        let req = DaemonRequest::Create(DaemonCreate {
            name: name.clone(),
            image_ref: opts.image.clone(),
            cpus: opts.cpus,
            mem_mb: opts.mem,
            workspace,
            rw_size_gb: opts.rw_size_gb,
            ports,
        });
        match client.request(&req, &mut |m| eprintln!("{m}"))? {
            DaemonResponse::Created { .. } => {}
            DaemonResponse::Error { message } => bail!(message),
            other => bail!("unexpected daemon reply: {other:?}"),
        }
        super::persist_policy(paths, &name, opts.policy.as_deref())?;
    }
    Ok(name)
}
