use crate::SandboxOpts;
use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use std::path::Path;

pub fn run(paths: &Paths, opts: &SandboxOpts, dir: &Path) -> anyhow::Result<i32> {
    let workspace = super::ensure_workspace(dir)?;
    // Honor izba.yml: overlay manifest defaults, explicit CLI flags always win.
    let mut merged = opts.clone();
    let manifest_for_base = super::merge_manifest_into_opts(&mut merged, &workspace)?;
    let name = super::name_for(&merged, &workspace)?;
    let ports = super::parse_publish(&merged.publish)?;
    let volumes = super::parse_volumes(&merged.volumes)?;
    let mut client = DaemonClient::connect(paths)?;
    // `izba create` has no unconfined opt-out (that is a run/start flag), so it
    // always creates with confined intent: the daemon runs the workspace
    // confinement preflight and refuses an unrelabellable dir up front.
    let req = DaemonRequest::Create(super::build_create_request(
        name, &merged, workspace, ports, volumes, false,
    ));
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { name } => {
            super::persist_policy(paths, &name, merged.policy.as_deref())?;
            // Seed the manifest base so `izba diff` reads in-sync right after create.
            if let Some(ref m) = manifest_for_base {
                if merged.policy.is_none() {
                    if let Some(ref eg) = m.spec.egress {
                        super::persist_policy_config(paths, &name, eg)?;
                    }
                }
                use izba_core::manifest::store;
                store::write_base(&paths.sandbox_dir(&name), m)?;
                store::clear_review(&paths.sandbox_dir(&name))?;
            }
            println!("{name}");
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use crate::SandboxOpts;

    fn sample_opts_with_defaults() -> SandboxOpts {
        SandboxOpts {
            image: super::super::DEFAULT_IMAGE.to_string(),
            cpus: super::super::DEFAULT_CPUS,
            mem: super::super::DEFAULT_MEM_MB,
            rw_size_gb: super::super::DEFAULT_RW_GB,
            name: None,
            publish: vec![],
            policy: None,
            volumes: vec![],
        }
    }

    #[test]
    fn manifest_fills_defaults_but_flags_win() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("izba.yml"),
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nmetadata: { name: fromfile }\nspec:\n  image: alpine:3\n  resources: { cpus: 8, memory: 2Gi }\n  rootDisk: { size: 4Gi }\n",
        ).unwrap();

        // User left image at default but overrode cpus on the CLI.
        let mut opts = sample_opts_with_defaults(); // image="ubuntu:24.04", cpus=2 (default), name=None
        opts.cpus = 16; // simulate explicit --cpus 16
        let m = super::super::merge_manifest_into_opts(&mut opts, dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(opts.image, "alpine:3", "manifest fills image (was default)");
        assert_eq!(opts.cpus, 16, "explicit --cpus wins over manifest");
        assert_eq!(m.metadata.name.as_deref(), Some("fromfile"));
    }

    #[test]
    fn no_manifest_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = sample_opts_with_defaults();
        assert!(
            super::super::merge_manifest_into_opts(&mut opts, dir.path())
                .unwrap()
                .is_none()
        );
        assert_eq!(opts.image, super::super::DEFAULT_IMAGE);
    }
}
