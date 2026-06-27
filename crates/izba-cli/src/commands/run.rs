use crate::{terminal, SandboxOpts};
use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_core::state::CONFIG_FILE;
use std::path::{Path, PathBuf};

#[mutants::skip] // reason: live daemon+VM, e2e-only
#[allow(clippy::too_many_arguments)]
pub fn run(
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
    rm: bool,
    allow_unconfined: bool,
    build: Option<PathBuf>,
    build_allow: Vec<String>,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    // When --build is given: build the image first, then run it.
    if let Some(build_path) = build {
        let image_ref = build_then_image_ref(paths, &build_path, &build_allow)?;
        // Construct a modified SandboxOpts with the built image.
        let mut run_opts = opts.clone();
        run_opts.image = image_ref;
        return run_inner(paths, &run_opts, name_or_dir, rm, allow_unconfined, cmd);
    }
    run_inner(paths, opts, name_or_dir, rm, allow_unconfined, cmd)
}

/// Resolve `--build PATH` into a local image ref that `ensure_image` can
/// satisfy from cache (no network call).
///
/// Context resolution:
/// - PATH is a directory → context = PATH, Dockerfile = `<PATH>/Dockerfile`
/// - PATH is a file (Dockerfile) → context = PATH's parent directory
///
/// The built digest is registered as a hidden local tag
/// `izba-run-build-<decimal-millis>` so the daemon's `ensure_image` short-
/// circuits the tag-is-cached branch and never touches the registry.
#[mutants::skip] // reason: live daemon+VM, e2e-only
pub(crate) fn build_then_image_ref(
    paths: &Paths,
    build_path: &Path,
    build_allow: &[String],
) -> anyhow::Result<String> {
    use super::build::{build_image, BuildOpts};
    use izba_core::image::tags::{prune_tags_with_prefix, set_tag, RUN_BUILD_TAG_PREFIX};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Sweep stale one-shot tags from prior `run --build` invocations so
    // tags.json does not grow unbounded.  This runs BEFORE registering this
    // run's tag so the current tag is never caught by the prune.
    prune_tags_with_prefix(paths, RUN_BUILD_TAG_PREFIX)?;

    let (context, dockerfile) = resolve_build_context(build_path);

    let digest = build_image(
        paths,
        &BuildOpts {
            dockerfile,
            tag: None,
            context,
            build_allow: build_allow.to_vec(),
            cpus: 2,
            mem: 4096,
        },
    )?;

    // Register a hidden local tag so ensure_image returns from cache without
    // a registry round-trip. Tag grammar: [a-z0-9][a-z0-9._-]* (no colon/slash).
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let tag = format!("izba-run-build-{millis}");
    set_tag(paths, &tag, &digest)?;
    Ok(tag)
}

/// Resolve a --build PATH into (context_dir, dockerfile_path).
///
/// - directory → (path, path/Dockerfile)
/// - file      → (parent_of_file, file)
pub(crate) fn resolve_build_context(build_path: &Path) -> (PathBuf, PathBuf) {
    if build_path.is_dir() {
        let ctx = build_path.to_path_buf();
        let df = ctx.join("Dockerfile");
        (ctx, df)
    } else {
        // It's a file (Dockerfile). Context = parent dir.
        let df = build_path.to_path_buf();
        let ctx = df
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        (ctx, df)
    }
}

#[mutants::skip] // reason: connects to a live daemon, starts the VM + execs; e2e-only (daemon_e2e)
fn run_inner(
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
    rm: bool,
    allow_unconfined: bool,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let (name, was_created) =
        resolve_or_create(&mut client, paths, opts, name_or_dir, allow_unconfined)?;
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
    let result = super::exec::run(paths, &name, true, tty, cmd);
    if rm {
        if was_created {
            // Best-effort throwaway teardown. Runs whether the command exited
            // cleanly, non-zero, or the exec itself errored — so `--rm` never
            // leaks the VM — and never masks the command's outcome: `rm::run`'s
            // own status is dropped and `result` (the command's exit code, or
            // its error) is returned. Reuses the `rm --force` path (stops if
            // running, releases any Windows lock-down account, removes ephemeral
            // resources; named volumes survive by contract).
            if let Err(e) = super::rm::run(paths, &name, true) {
                eprintln!("warning: --rm cleanup of '{name}' failed: {e:#}");
            }
        } else {
            // `run` can ATTACH to a pre-existing sandbox (resolved by name or by
            // a cwd whose sandbox already exists). Unlike `docker run` — which
            // always creates — that makes `--rm` asymmetrically destructive: it
            // would delete a sandbox (and its rw-layer data) the user already
            // had. `--rm` only reaps what THIS invocation freshly created; for
            // a pre-existing sandbox we leave it untouched and say so.
            eprintln!(
                "note: --rm had no effect — '{name}' existed before this run, so it was \
                 left in place (remove it explicitly with `izba rm {name}`)"
            );
        }
    }
    result
}

/// NAME_OR_DIR: an existing sandbox name wins; anything else is a workspace
/// directory (created if missing), with the sandbox created on first use.
/// Reading config.json for name resolution is the one read-only local
/// operation kept CLI-side; everything mutating goes through the daemon.
///
/// Returns `(name, was_created)`. `was_created` is true ONLY when this call
/// freshly minted the sandbox (neither Case A nor Case B matched) — it gates
/// `run --rm`'s teardown so attaching to a pre-existing sandbox is never
/// destructive.
#[mutants::skip] // reason: drives a live daemon (Create/persist over the socket); e2e-only
fn resolve_or_create(
    client: &mut DaemonClient,
    paths: &Paths,
    opts: &SandboxOpts,
    name_or_dir: &str,
    allow_unconfined: bool,
) -> anyhow::Result<(String, bool)> {
    // Case A: an existing sandbox addressed directly by name.
    if sandbox::validate_name(name_or_dir).is_ok()
        && paths.sandbox_dir(name_or_dir).join(CONFIG_FILE).is_file()
    {
        reconcile_existing(paths, name_or_dir, opts)?;
        return Ok((name_or_dir.to_string(), false));
    }
    let workspace = super::ensure_workspace(Path::new(name_or_dir))?;
    let name = super::name_for(opts, &workspace)?;
    // Case B: addressed by directory, but the sandbox already exists.
    if paths.sandbox_dir(&name).join(CONFIG_FILE).is_file() {
        reconcile_existing(paths, &name, opts)?;
        return Ok((name, false));
    }
    let ports = super::parse_publish(&opts.publish)?;
    let volumes = super::parse_volumes(&opts.volumes)?;
    // Carry the run's confinement intent into create: `run --allow-unconfined`
    // on a workspace that can't be relabelled must still create (the VMM will run
    // unconfined and never relabel it), so skip the create-time preflight.
    let req = DaemonRequest::Create(super::build_create_request(
        name.clone(),
        opts,
        workspace,
        ports,
        volumes,
        allow_unconfined,
    ));
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { .. } => {}
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
    super::persist_policy(paths, &name, opts.policy.as_deref())?;
    Ok((name, true))
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
    // Mutation note: the `delete !` mutant on this guard only flips whether the
    // stderr "ignored opts" warning prints — no return/state change, so it is
    // unkillable by a unit test. It is excluded by name in `.cargo/mutants.toml`
    // (pinned in `hack/mutants-check-excludes.py`); the function's policy-persist
    // mutants stay under test (covered by the `reconcile_*` tests).
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
    use crate::Cli;
    use clap::Parser;
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

    // ── resolve_build_context ─────────────────────────────────────────────────

    /// `--build ./ctx/Dockerfile` (a file): context = `./ctx`, Dockerfile = that file.
    #[test]
    fn build_context_from_dockerfile_path() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = dir.path().join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        let df = ctx.join("Dockerfile");
        std::fs::write(&df, "FROM scratch\n").unwrap();

        let (resolved_ctx, resolved_df) = resolve_build_context(&df);
        assert_eq!(
            resolved_ctx.canonicalize().unwrap(),
            ctx.canonicalize().unwrap(),
            "context should be Dockerfile's parent"
        );
        assert_eq!(resolved_df, df, "dockerfile should be the given file");
    }

    /// `--build ./ctx` (a directory): context = `./ctx`, Dockerfile = `./ctx/Dockerfile`.
    #[test]
    fn build_context_from_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = dir.path().join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();

        let (resolved_ctx, resolved_df) = resolve_build_context(&ctx);
        assert_eq!(resolved_ctx, ctx, "context should be the directory itself");
        assert_eq!(
            resolved_df,
            ctx.join("Dockerfile"),
            "dockerfile defaults to <ctx>/Dockerfile"
        );
    }

    // ── clap conflict: --build and --image are mutually exclusive ────────────

    /// clap must reject `izba run --build ./ctx --image ubuntu:24.04 .`
    #[test]
    fn clap_rejects_build_and_image_together() {
        let result =
            Cli::try_parse_from(["izba", "run", "--build", "./ctx", "--image", "ubuntu:24.04"]);
        assert!(
            result.is_err(),
            "--build and --image must conflict, but clap accepted both"
        );
    }

    /// `izba run --build ./ctx` alone (no --image) must parse successfully.
    #[test]
    fn clap_accepts_build_without_image() {
        let result = Cli::try_parse_from(["izba", "run", "--build", "./ctx"]);
        assert!(
            result.is_ok(),
            "--build without --image should be accepted: {result:?}"
        );
    }

    /// `--build-allow` is repeatable and threads through.
    #[test]
    fn clap_build_allow_repeatable() {
        use crate::Cmd;
        let cli = Cli::try_parse_from([
            "izba",
            "run",
            "--build",
            "./ctx",
            "--build-allow",
            "r1.example.com",
            "--build-allow",
            "r2.example.com",
        ])
        .unwrap();
        let Cmd::Run { build_allow, .. } = cli.cmd else {
            panic!("expected Run");
        };
        assert_eq!(
            build_allow,
            vec!["r1.example.com".to_string(), "r2.example.com".to_string()]
        );
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
