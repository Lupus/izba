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
// Consumed by Tasks 6-7 (diff/promote/export/status/stop/rm/start); until then
// nothing but this module's own tests calls it, so `-D warnings` would flag
// the whole surface as dead code.
#[allow(dead_code)]
pub mod sandbox_ref;
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

/// Read and parse `izba.yml` from `dir` WITHOUT reading the Dockerfile.  Used
/// for name-resolution / opts-merge paths where only the YAML is needed.
pub(crate) fn load_manifest_yaml(dir: &Path) -> anyhow::Result<Manifest> {
    let path = dir.join("izba.yml");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Manifest::load_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Clap default values — the single source of truth.  Both the `SandboxOpts`
/// `default_value_t` attributes in `main.rs` and the `merge_manifest_into_opts`
/// "was this field left at its default?" checks must reference these consts.
/// The resource trio re-exports the manifest schema defaults so an izba.yml
/// omitting `resources`/`rootDisk` boots identically to a bare `izba run`.
pub(crate) const DEFAULT_IMAGE: &str = "ubuntu:24.04";
pub(crate) const DEFAULT_CPUS: u32 = izba_core::manifest::schema::DEFAULT_CPUS;
pub(crate) const DEFAULT_MEM_MB: u32 = izba_core::manifest::schema::DEFAULT_MEM_MB;
pub(crate) const DEFAULT_RW_GB: u64 = izba_core::manifest::schema::DEFAULT_RW_GB;

/// Load `izba.yml` from a workspace dir, returning (manifest, raw_yaml,
/// dockerfile_contents). `dockerfile` is `Some` only for a `build:` spec.
/// Delegates to [`izba_core::manifest::ops::load_repo_manifest`].
pub(crate) fn load_repo_manifest(dir: &Path) -> anyhow::Result<(Manifest, String, Option<String>)> {
    izba_core::manifest::ops::load_repo_manifest(dir)
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
/// Delegates to [`izba_core::manifest::ops::managed_normalized`].
pub(crate) fn managed_normalized(
    paths: &izba_core::paths::Paths,
    name: &str,
) -> anyhow::Result<Normalized> {
    izba_core::manifest::ops::managed_normalized(paths, name)
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

/// Overlay an `izba.yml` (if present) onto `opts`: for each field the user left
/// at its clap default, take the manifest's value. Explicit flags always win.
/// Returns the parsed manifest so the caller can seed the manifest base after a
/// successful create.
pub(crate) fn merge_manifest_into_opts(
    opts: &mut crate::SandboxOpts,
    dir: &Path,
) -> anyhow::Result<Option<Manifest>> {
    if !dir.join("izba.yml").exists() {
        return Ok(None);
    }
    // Read only the YAML — deliberately do NOT call load_repo_manifest here.
    // load_repo_manifest reads the Dockerfile for `build:` specs, but name
    // resolution only needs the parsed YAML.  On a HEALTHY existing build-spec
    // sandbox with a deleted/cleaned Dockerfile `izba run .` would otherwise
    // fail with "reading Dockerfile: No such file" even though reconcile_existing
    // should kick in and short-circuit before any build attempt.
    let m = load_manifest_yaml(dir)?;
    // Only compute the dir-basename fallback when the manifest does not supply
    // a name; this avoids failing on a tmpdir whose basename cannot be a valid
    // sandbox name (e.g. `.tmpXXXXX` used in tests).
    let default_name = if m.metadata.name.is_none() {
        workspace_default_name(dir)?
    } else {
        String::new() // manifest name takes precedence; fallback never used
    };
    let n = Normalized::from_manifest(&m, &default_name)?;
    // Known limitation: a user explicitly passing a value equal to the clap
    // default is indistinguishable from not passing it at all — we compare
    // against the default constant rather than consulting clap's value source.
    // This is intentional simplicity (the manifest only fills genuine gaps).
    if opts.image == DEFAULT_IMAGE {
        match &n.image {
            izba_core::manifest::ImageSource::Ref(r) => opts.image = r.clone(),
            izba_core::manifest::ImageSource::Build(_) => {
                eprintln!(
                    "warning: izba.yml declares a `build:` recipe, but build-on-create \
                     is not yet supported by `izba create`/`izba run`. Booting the default \
                     image ({DEFAULT_IMAGE}). To build the declared image, run \
                     `izba run --build .` (or `izba build` then reference the tag).",
                );
            }
        }
    }
    if opts.cpus == DEFAULT_CPUS {
        opts.cpus = n.cpus;
    }
    if opts.mem == DEFAULT_MEM_MB {
        opts.mem = n.mem_mb;
    }
    if opts.rw_size_gb == DEFAULT_RW_GB && n.rw_size_gb != 0 {
        opts.rw_size_gb = n.rw_size_gb;
    }
    if opts.name.is_none() {
        opts.name = Some(n.name.clone());
    }
    // Ports: only adopt from manifest when the user passed none.
    if opts.publish.is_empty() {
        opts.publish = n
            .ports
            .iter()
            .map(|p| format!("{}:{}:{}", p.bind, p.host_port, p.guest_port))
            .collect();
    }
    // Volumes: only adopt from manifest when the user passed none.
    if opts.volumes.is_empty() {
        opts.volumes = n
            .volumes
            .iter()
            .map(|v| {
                let path = v.guest_path.to_string_lossy();
                let size = if v.size_bytes % (1 << 30) == 0 {
                    format!("{}g", v.size_bytes >> 30)
                } else {
                    format!("{}m", v.size_bytes >> 20)
                };
                match &v.name {
                    Some(name) => format!("{name}:{path}:{size}"),
                    None => format!("{path}:{size}"),
                }
            })
            .collect();
    }
    Ok(Some(m))
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

    /// Fix 4: manifest volumes are adopted into opts when the user passed none.
    #[test]
    fn merge_manifest_adopts_volumes_when_none_passed() {
        let tmp = tempfile::tempdir().unwrap();

        // Write an izba.yml with a named and an anonymous volume.
        std::fs::write(
            tmp.path().join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "spec:\n",
                "  image: ubuntu:24.04\n",
                "  resources: { cpus: 1, memory: 1Gi }\n",
                "  rootDisk: { size: 1Gi }\n",
                "  volumes:\n",
                "    - { name: data, mountPath: /data, size: 8Gi }\n",
                "    - { mountPath: /cache, size: 2Gi }\n",
            ),
        )
        .unwrap();

        // opts() has no volumes (the clap default).
        let mut o = opts();
        let ws_dir = tmp.path().join("myproject");
        std::fs::create_dir_all(&ws_dir).unwrap();

        // Rename the izba.yml to myproject/izba.yml for the lookup.
        let izba_yml = tmp.path().join("izba.yml");
        std::fs::copy(&izba_yml, ws_dir.join("izba.yml")).unwrap();

        merge_manifest_into_opts(&mut o, &ws_dir).unwrap();

        // Both volumes must be adopted as flag strings.
        assert_eq!(o.volumes.len(), 2, "two volumes should be adopted");
        // Named volume: data:/data:8g
        assert!(
            o.volumes.iter().any(|v| v == "data:/data:8g"),
            "named volume flag must be data:/data:8g; got {:?}",
            o.volumes
        );
        // Anonymous volume: /cache:2g
        assert!(
            o.volumes.iter().any(|v| v == "/cache:2g"),
            "anonymous volume flag must be /cache:2g; got {:?}",
            o.volumes
        );
    }

    /// memory + rootDisk are adopted from the manifest when opts are at their
    /// clap defaults (pins the `mem == DEFAULT` / `rw == DEFAULT && n.rw != 0`
    /// adoption guards).
    #[test]
    fn merge_manifest_adopts_mem_and_rw_when_at_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("proj");
        std::fs::create_dir_all(&ws_dir).unwrap();
        std::fs::write(
            ws_dir.join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "metadata: { name: proj }\n",
                "spec:\n",
                "  image: ubuntu:24.04\n",
                "  resources: { cpus: 1, memory: 2Gi }\n",
                "  rootDisk: { size: 16Gi }\n",
            ),
        )
        .unwrap();
        // opts() carries the clap defaults: mem == DEFAULT_MEM_MB, rw == DEFAULT_RW_GB.
        let mut o = opts();
        merge_manifest_into_opts(&mut o, &ws_dir).unwrap();
        assert_eq!(
            o.mem, 2048,
            "manifest memory (2Gi) adopted when opts at default"
        );
        assert_eq!(
            o.rw_size_gb, 16,
            "manifest rootDisk (16Gi) adopted when opts at default"
        );
    }

    /// Explicit --mem / --rw-size-gb (non-default) must NOT be overridden by the
    /// manifest (pins the `&&` and `==` halves of the adoption guards).
    #[test]
    fn merge_manifest_does_not_override_explicit_mem_and_rw() {
        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("proj");
        std::fs::create_dir_all(&ws_dir).unwrap();
        std::fs::write(
            ws_dir.join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "metadata: { name: proj }\n",
                "spec:\n",
                "  image: ubuntu:24.04\n",
                "  resources: { cpus: 1, memory: 2Gi }\n",
                "  rootDisk: { size: 16Gi }\n",
            ),
        )
        .unwrap();
        let mut o = opts();
        o.mem = 9000; // explicit, != DEFAULT_MEM_MB
        o.rw_size_gb = 20; // explicit, != DEFAULT_RW_GB
        merge_manifest_into_opts(&mut o, &ws_dir).unwrap();
        assert_eq!(o.mem, 9000, "explicit --mem must win over manifest");
        assert_eq!(
            o.rw_size_gb, 20,
            "explicit --rw-size-gb must win over manifest"
        );
    }

    /// Fix 4: an explicit --volume flag must NOT be overridden by the manifest.
    #[test]
    fn merge_manifest_does_not_override_explicit_volumes() {
        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("myproject");
        std::fs::create_dir_all(&ws_dir).unwrap();

        std::fs::write(
            ws_dir.join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "spec:\n",
                "  image: ubuntu:24.04\n",
                "  resources: { cpus: 1, memory: 1Gi }\n",
                "  rootDisk: { size: 1Gi }\n",
                "  volumes:\n",
                "    - { name: data, mountPath: /data, size: 8Gi }\n",
            ),
        )
        .unwrap();

        // User passed an explicit volume.
        let mut o = opts();
        o.volumes = vec!["/tmp/work:4g".into()];

        merge_manifest_into_opts(&mut o, &ws_dir).unwrap();

        // The explicit flag must win; manifest volume must not be added.
        assert_eq!(o.volumes, vec!["/tmp/work:4g".to_string()]);
    }

    /// Sub-GiB manifest volumes (e.g. 512Mi) must be expressed in MiB (`512m`)
    /// rather than GiB (`0g`) so that `parse_volume_flag` accepts them.
    #[test]
    fn merge_manifest_adopts_sub_gib_volumes_as_mib() {
        use izba_core::volume::parse_volume_flag;
        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("myproject");
        std::fs::create_dir_all(&ws_dir).unwrap();

        std::fs::write(
            ws_dir.join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "spec:\n",
                "  image: ubuntu:24.04\n",
                "  resources: { cpus: 1, memory: 1Gi }\n",
                "  rootDisk: { size: 1Gi }\n",
                "  volumes:\n",
                "    - { name: cache, mountPath: /cache, size: 512Mi }\n",
                "    - { mountPath: /data, size: 8Gi }\n",
            ),
        )
        .unwrap();

        let mut o = opts();
        merge_manifest_into_opts(&mut o, &ws_dir).unwrap();

        assert_eq!(o.volumes.len(), 2, "two volumes should be adopted");

        // Named 512Mi volume must be expressed as 512m (not 0g).
        let named = o
            .volumes
            .iter()
            .find(|v| v.starts_with("cache:"))
            .expect("named volume flag not found");
        assert_eq!(
            named, "cache:/cache:512m",
            "512Mi named volume must format as 512m; got {named:?}"
        );
        let named_spec = parse_volume_flag(named)
            .expect("named volume flag must be parseable by parse_volume_flag");
        assert_eq!(
            named_spec.size_bytes,
            512 << 20,
            "parsed size_bytes must be 512Mi"
        );

        // Anonymous 8Gi volume must stay as 8g.
        let anon = o
            .volumes
            .iter()
            .find(|v| v.starts_with("/data"))
            .expect("anonymous volume flag not found");
        assert_eq!(
            anon, "/data:8g",
            "8Gi anonymous volume must format as 8g; got {anon:?}"
        );
        let anon_spec = parse_volume_flag(anon)
            .expect("anonymous volume flag must be parseable by parse_volume_flag");
        assert_eq!(
            anon_spec.size_bytes,
            8 << 30,
            "parsed size_bytes must be 8Gi"
        );
    }

    /// Fix 1 (CLI): merge_manifest_into_opts with a `build:` spec must succeed
    /// even when the referenced Dockerfile does NOT exist on disk.  Name
    /// resolution / opts-merge only needs the YAML; the Dockerfile is only
    /// needed by `diff`/`promote` for the review token.
    #[test]
    fn merge_manifest_build_spec_succeeds_without_dockerfile() {
        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("myproject");
        std::fs::create_dir_all(&ws_dir).unwrap();

        // izba.yml has a build: spec, but we deliberately do NOT create the Dockerfile.
        std::fs::write(
            ws_dir.join("izba.yml"),
            concat!(
                "apiVersion: izba.dev/v1alpha1\n",
                "kind: Sandbox\n",
                "metadata: { name: myproject }\n",
                "spec:\n",
                "  build:\n",
                "    context: '.'\n",
                "    dockerfile: 'Dockerfile'\n",
                "  resources: { cpus: 2, memory: 4Gi }\n",
                "  rootDisk: { size: 8Gi }\n",
            ),
        )
        .unwrap();

        let mut o = opts();
        // Must NOT error even though Dockerfile is absent.
        let result = merge_manifest_into_opts(&mut o, &ws_dir);
        assert!(
            result.is_ok(),
            "merge_manifest_into_opts must succeed without Dockerfile: {result:?}"
        );
        // Name should be resolved from the manifest metadata.
        assert_eq!(o.name.as_deref(), Some("myproject"));
    }
}
