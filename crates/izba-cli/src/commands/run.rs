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
    allow_unconfined: bool,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let name = resolve_or_create(&mut client, paths, opts, name_or_dir)?;
    if allow_unconfined {
        // Loud, BEFORE start: the user is waiving the host-side jail, so a VM
        // escape would run with their full user privileges.
        eprintln!(
            "⚠️  WARNING: --allow-unconfined set — the VMM will run WITHOUT host-side \
             confinement. A VM escape would run with your full user privileges."
        );
    }
    match client.request(
        &DaemonRequest::Start {
            name: name.clone(),
            allow_unconfined,
        },
        &mut |m| eprintln!("{m}"),
    )? {
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
    // Case A: an existing sandbox addressed directly by name.
    if sandbox::validate_name(name_or_dir).is_ok()
        && paths.sandbox_dir(name_or_dir).join(CONFIG_FILE).is_file()
    {
        reconcile_existing(paths, name_or_dir, opts)?;
        return Ok(name_or_dir.to_string());
    }
    let workspace = super::ensure_workspace(Path::new(name_or_dir))?;
    let name = super::name_for(opts, &workspace)?;
    // Case B: addressed by directory, but the sandbox already exists.
    if paths.sandbox_dir(&name).join(CONFIG_FILE).is_file() {
        reconcile_existing(paths, &name, opts)?;
        return Ok(name);
    }
    let ports = super::parse_publish(&opts.publish)?;
    let volumes = super::parse_volumes(&opts.volumes)?;
    let req = DaemonRequest::Create(DaemonCreate {
        name: name.clone(),
        image_ref: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: opts.rw_size_gb,
        ports,
        volumes,
    });
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { .. } => {}
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
    super::persist_policy(paths, &name, opts.policy.as_deref())?;
    Ok(name)
}

/// Reconcile run-time opts against an ALREADY-existing sandbox. The stored
/// config (image/cpus/mem/disk/ports) is immutable, but `--policy` IS honored:
/// re-persist it so an edited allow-list takes effect on the (re)start this
/// `run` triggers — the daemon re-reads `policy.yaml` when it arms the egress
/// plane. Anything baked at create that was passed anyway is reported ignored.
fn reconcile_existing(paths: &Paths, name: &str, opts: &SandboxOpts) -> anyhow::Result<()> {
    if opts.policy.is_some() {
        super::persist_policy(paths, name, opts.policy.as_deref())?;
        eprintln!("updated egress policy for '{name}' (takes effect on (re)start)");
    }
    let ignored = ignored_create_opts(opts);
    if !ignored.is_empty() {
        eprintln!(
            "warning: '{name}' is an existing sandbox — stored config wins; {} ignored \
             (use `izba rm {name}` to recreate)",
            ignored.join(", ")
        );
    }
    Ok(())
}

/// Create-time opts that a `run` against an existing sandbox silently ignores
/// (everything baked into the sandbox at creation). `--policy` is deliberately
/// absent — it is reconciled, not ignored — and so is `--name`, which only
/// addresses the sandbox.
fn ignored_create_opts(opts: &SandboxOpts) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    if opts.image != "ubuntu:24.04" {
        ignored.push("--image");
    }
    if opts.cpus != 2 {
        ignored.push("--cpus");
    }
    if opts.mem != 4096 {
        ignored.push("--mem");
    }
    if opts.rw_size_gb != 8 {
        ignored.push("--rw-size-gb");
    }
    if !opts.publish.is_empty() {
        ignored.push("--publish");
    }
    if !opts.volumes.is_empty() {
        ignored.push("--volume");
    }
    ignored
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::paths::Paths;

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

    /// `--policy` is reconciled (re-persisted), not ignored; `--name` only
    /// addresses the sandbox. Neither appears in the ignored-create-opts list.
    #[test]
    fn ignored_create_opts_excludes_policy_and_name() {
        let mut o = opts();
        o.cpus = 4;
        o.name = Some("fw".into());
        o.policy = Some("/tmp/p.yaml".into());
        let ig = ignored_create_opts(&o);
        assert!(ig.contains(&"--cpus"), "{ig:?}");
        assert!(
            !ig.contains(&"--policy"),
            "policy is reconciled, not ignored: {ig:?}"
        );
        assert!(!ig.contains(&"--name"), "name only addresses: {ig:?}");
    }

    #[test]
    fn ignored_create_opts_empty_for_defaults() {
        assert!(ignored_create_opts(&opts()).is_empty());
    }

    /// The reported bug: edit the policy, re-run with `--policy` against an
    /// existing sandbox — the stored allow-list must be refreshed.
    #[test]
    fn reconcile_repersists_edited_policy_on_existing_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir("fw")).unwrap();
        std::fs::write(
            paths.sandbox_dir("fw").join("policy.yaml"),
            "allow:\n  - github.com\n",
        )
        .unwrap();
        let edited = dir.path().join("edited.yaml");
        std::fs::write(&edited, "allow:\n  - github.com\n  - archive.ubuntu.com\n").unwrap();
        let mut o = opts();
        o.policy = Some(edited);

        reconcile_existing(&paths, "fw", &o).unwrap();

        let stored = std::fs::read_to_string(paths.sandbox_dir("fw").join("policy.yaml")).unwrap();
        assert!(
            stored.contains("archive.ubuntu.com"),
            "policy refreshed: {stored}"
        );
    }

    /// A `run` without `--policy` must NOT wipe an existing sandbox's policy.
    #[test]
    fn reconcile_without_policy_leaves_stored_policy_intact() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir("fw")).unwrap();
        std::fs::write(
            paths.sandbox_dir("fw").join("policy.yaml"),
            "allow:\n  - github.com\n",
        )
        .unwrap();
        reconcile_existing(&paths, "fw", &opts()).unwrap();
        let stored = std::fs::read_to_string(paths.sandbox_dir("fw").join("policy.yaml")).unwrap();
        assert_eq!(
            stored, "allow:\n  - github.com\n",
            "no --policy => unchanged"
        );
    }
}
