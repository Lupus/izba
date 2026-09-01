use crate::SandboxOpts;
use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[mutants::skip] // reason: connects to a live daemon (Create over the socket); e2e-only (daemon_e2e). The testable pieces (merge_manifest_into_opts, build_create_request) are unit-tested separately.
pub fn run(paths: &Paths, opts: &SandboxOpts, name_or_dir: &str) -> anyhow::Result<i32> {
    // #242: resolve BEFORE touching the filesystem. Only the path-syntax arm
    // reaches `ensure_workspace`'s `create_dir_all`, so a bare word that names
    // nothing is an error rather than a silently-created empty workspace.
    let workspace = match super::sandbox_ref::resolve_for_create(paths, name_or_dir)? {
        super::sandbox_ref::CreateTarget::Existing(name) => bail!(
            "sandbox '{name}' already exists — start it with `izba start {name}`, \
             or remove it first with `izba rm {name}`"
        ),
        super::sandbox_ref::CreateTarget::Workspace(dir) => super::ensure_workspace(&dir)?,
    };
    // Honor izba.yml: overlay manifest defaults, explicit CLI flags always win.
    let mut merged = opts.clone();
    let manifest_for_base = super::merge_manifest_into_opts(&mut merged, &workspace)?;
    let name = super::name_for(&merged, &workspace)?;
    // #242: a cwd izba.yml that is NOT the manifest being applied must never be
    // discarded silently — its `enforce:`/`protocol:` posture would go with it.
    if let Some(w) = super::sandbox_ref::cwd_manifest_ignored_warning(Some(&workspace), &name) {
        eprintln!("{w}");
    }
    let ports = super::parse_publish(&merged.publish)?;
    let volumes = super::parse_volumes(&merged.volumes, merged.vnc)?;
    // Validate --policy BEFORE the daemon Create RPC: a missing or invalid
    // file must fail here, leaving no stub sandbox registered (#139).
    let policy_raw = super::read_policy(merged.policy.as_deref())?;
    // Reject a data root too deep for the VM runtime sockets BEFORE any
    // daemon connect: a raw SUN_LEN bind failure at start time is not
    // actionable, and this must fire even before connect (the daemon socket
    // path itself may already be too long) (#71).
    izba_core::paths::ensure_socket_budget(paths, &name)?;
    // Docker mode tri-state (#198): an explicit --docker/--no-docker wins;
    // otherwise None lets the daemon fall back to the image's start-docker
    // label.
    let docker = if merged.docker {
        Some(true)
    } else if merged.no_docker {
        Some(false)
    } else {
        None
    };
    let mut client = DaemonClient::connect(paths)?;
    // `izba create` has no unconfined opt-out (that is a run/start flag), so it
    // always creates with confined intent: the daemon runs the workspace
    // confinement preflight and refuses an unrelabellable dir up front.
    let req = DaemonRequest::Create(super::build_create_request(
        name, &merged, workspace, ports, volumes, false, docker,
    ));
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { name } => {
            super::write_policy(paths, &name, policy_raw.as_deref())?;
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
            docker: false,
            no_docker: false,
            vnc: false,
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

    /// A `build:`-only manifest cannot be honored by create/run (no image ref),
    /// so `opts.image` stays at the default — but the manifest is still parsed
    /// and returned (so the base gets seeded). The user is warned on stderr.
    #[test]
    fn build_manifest_leaves_image_default_but_returns_manifest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("izba.yml"),
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nmetadata: { name: built }\nspec:\n  build: { context: . }\n  resources: { cpus: 4, memory: 2Gi }\n  rootDisk: { size: 4Gi }\n",
        ).unwrap();
        // load_repo_manifest reads the referenced Dockerfile for a `build:` spec.
        std::fs::write(dir.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let mut opts = sample_opts_with_defaults();
        let m = super::super::merge_manifest_into_opts(&mut opts, dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            opts.image,
            super::super::DEFAULT_IMAGE,
            "build: recipe cannot fill image; default stays"
        );
        // Other fields are still filled from the manifest.
        assert_eq!(opts.cpus, 4, "cpus still filled from manifest");
        assert_eq!(m.metadata.name.as_deref(), Some("built"));
    }
}
