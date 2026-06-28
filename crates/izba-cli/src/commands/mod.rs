pub mod build;
pub mod cp;
pub mod create;
pub mod daemon;
pub mod diff;
pub mod exec;
pub mod export;
pub mod lockdown;
pub mod ls;
pub mod netlog;
pub mod policy;
pub mod port;
pub mod promote;
pub mod reconcile;
pub mod rm;
pub mod run;
pub mod ssh;
pub mod ssh_proxy;
pub mod start;
pub mod status;
pub mod stop;
pub mod version;
pub mod volume;

use crate::name;
use crate::SandboxOpts;
use anyhow::Context;
use izba_core::manifest::{Manifest, Normalized};
use izba_core::state::PortRule;
use std::path::{Path, PathBuf};

/// Load `izba.yml` from a workspace dir, returning (manifest, raw_yaml,
/// dockerfile_contents). `dockerfile` is `Some` only for a `build:` spec.
pub(crate) fn load_repo_manifest(dir: &Path) -> anyhow::Result<(Manifest, String, Option<String>)> {
    let path = dir.join("izba.yml");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let m = Manifest::load_str(&raw)?;
    let dockerfile = match &m.spec.build {
        Some(b) => {
            let ctx = dir.join(b.context.as_deref().unwrap_or("."));
            let df = ctx.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
            Some(
                std::fs::read_to_string(&df)
                    .with_context(|| format!("reading {}", df.display()))?,
            )
        }
        None => None,
    };
    Ok((m, raw, dockerfile))
}

/// Derive the default sandbox name from a workspace directory: the sanitized
/// basename (mirrors `name_for` but without `SandboxOpts`).
pub(crate) fn workspace_default_name(dir: &Path) -> anyhow::Result<String> {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let base = canonical
        .file_name()
        .with_context(|| format!("{} has no basename; pass --name", dir.display()))?;
    name::sanitize(&base.to_string_lossy())
}

/// Read the managed truth (config.json + policy.yaml) for `name` into a
/// `Normalized`, directly from disk (works on a stopped sandbox).
pub(crate) fn managed_normalized(
    paths: &izba_core::paths::Paths,
    name: &str,
) -> anyhow::Result<Normalized> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    use izba_core::state::{load_json, SandboxConfig, CONFIG_FILE};
    let dir = paths.sandbox_dir(name);
    let cfg: SandboxConfig =
        load_json(&dir.join(CONFIG_FILE))?.with_context(|| format!("no such sandbox: {name}"))?;
    let egress = EgressPolicyConfig::load(&dir)?.unwrap_or_default();
    Ok(Normalized::from_managed(name, &cfg, &egress))
}

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
        // `create`/`run` never provision a build host; only `izba build` does.
        builder: false,
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

/// Persist a programmatically-built egress policy as the sandbox's
/// `policy.yaml`. Unlike [`persist_policy`] (which copies a user file) this
/// serializes an in-memory [`EgressPolicyConfig`] — used by `izba build` to arm
/// the enforcing build-network allow-list. The daemon re-reads `policy.yaml`
/// when it arms the egress plane at Start, so this must run AFTER Create and
/// BEFORE Start. Must run after the sandbox dir exists.
pub(crate) fn persist_policy_config(
    paths: &izba_core::paths::Paths,
    name: &str,
    config: &izba_core::daemon::egress::config::EgressPolicyConfig,
) -> anyhow::Result<()> {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    let dst = EgressPolicyConfig::path_in(&paths.sandbox_dir(name));
    std::fs::write(&dst, config.to_yaml()).with_context(|| format!("writing {}", dst.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::egress::config::EgressPolicyConfig;
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

    /// A workspace dir with a real basename yields the sanitized basename.
    #[test]
    fn workspace_default_name_uses_sanitized_basename() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("My_Proj");
        std::fs::create_dir_all(&ws).unwrap();
        assert_eq!(workspace_default_name(&ws).unwrap(), "my_proj");
    }

    /// `Path::new(".")` must resolve to the current directory's basename rather
    /// than erroring out (the real `izba diff` default-arg path).
    #[test]
    fn workspace_default_name_resolves_dot_to_cwd_basename() {
        let cwd = std::env::current_dir().unwrap();
        let expected = name::sanitize(&cwd.file_name().unwrap().to_string_lossy()).unwrap();
        assert_eq!(workspace_default_name(Path::new(".")).unwrap(), expected);
    }

    /// Verify persist_policy_config writes a policy.yaml that round-trips.
    #[test]
    fn persist_policy_config_writes_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let name = "mybuild";

        // The sandbox dir must exist before persist_policy_config can write into it.
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let config = EgressPolicyConfig::build_network(&[]);
        persist_policy_config(&paths, name, &config).unwrap();

        // File must exist at the canonical policy path.
        let policy_path = EgressPolicyConfig::path_in(&sandbox_dir);
        assert!(
            policy_path.exists(),
            "policy.yaml should be written at {policy_path:?}"
        );

        // Must round-trip: load back and compare.
        let raw = std::fs::read_to_string(&policy_path).unwrap();
        let loaded = EgressPolicyConfig::from_yaml(&raw).unwrap();
        assert_eq!(loaded.enforce, config.enforce, "enforce must round-trip");
        assert_eq!(
            loaded.allow.len(),
            config.allow.len(),
            "allow list length must round-trip"
        );

        // Must contain the Docker Hub hosts.
        let hosts: Vec<&str> = loaded.allow.iter().map(|e| e.host()).collect();
        assert!(
            hosts.contains(&"registry-1.docker.io"),
            "registry-1.docker.io must be in allow list"
        );
        assert!(
            hosts.contains(&"auth.docker.io"),
            "auth.docker.io must be in allow list"
        );
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
