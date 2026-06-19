use crate::SandboxOpts;
use anyhow::bail;
use izba_core::daemon::proto::{DaemonCreate, DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use std::path::Path;

pub fn run(paths: &Paths, opts: &SandboxOpts, dir: &Path) -> anyhow::Result<i32> {
    let workspace = super::ensure_workspace(dir)?;
    let name = super::name_for(opts, &workspace)?;
    let ports = super::parse_publish(&opts.publish)?;
    let volumes = super::parse_volumes(&opts.volumes)?;
    let mut client = DaemonClient::connect(paths)?;
    let req = DaemonRequest::Create(DaemonCreate {
        name,
        image_ref: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: opts.rw_size_gb,
        ports,
        volumes,
        // `izba create` has no unconfined opt-out (that is a run/start flag), so
        // it always creates with confined intent: the daemon runs the workspace
        // confinement preflight and refuses an unrelabellable dir up front.
        allow_unconfined: false,
    });
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { name } => {
            super::persist_policy(paths, &name, opts.policy.as_deref())?;
            println!("{name}");
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}
