//! `izba build` — build an OCI image from a Dockerfile inside a throwaway,
//! daemon-managed builder VM, ingest the result, and optionally tag it.
//!
//! Daemon-first orchestration (mirrors `izba run`): the builder VM must be
//! daemon-managed because guest egress for the `FROM` base-image pull is
//! enforced by izbad per-sandbox over vsock 1027. Sequence:
//!
//!   Create (builder=true) → write enforcing build-network policy.yaml →
//!   Start (arms policy.yaml fresh) → exec the build script → ingest /out →
//!   tag → ALWAYS Rm (force).
//!
//! The persistent `izba-buildcache` volume survives `rm` by design (named
//! volumes persist) and is the incremental BuildKit cache across builds.

use anyhow::{bail, Context};
use izba_core::build::{build_script, BUILDER_IMAGE_REF};
use izba_core::daemon::egress::config::EgressPolicyConfig;
use izba_core::daemon::proto::{DaemonCreate, DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::image;
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_core::volume::VolumeSpec;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed `izba build` inputs.
pub struct BuildOpts {
    /// `-f`: Dockerfile path (default `<context>/Dockerfile`).
    pub dockerfile: PathBuf,
    /// `-t`: optional tag for the built image (validated up front).
    pub tag: Option<String>,
    /// Build context directory (becomes the `/workspace` share).
    pub context: PathBuf,
    /// `--build-allow`: extra hosts the build network may reach (registries/
    /// mirrors), on top of the Docker Hub hosts.
    pub build_allow: Vec<String>,
    pub cpus: u32,
    pub mem: u32,
}

/// 16 GiB for the persistent BuildKit cache volume.
const BUILDCACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub fn run(paths: &Paths, opts: &BuildOpts) -> anyhow::Result<i32> {
    // `izba build` only needs the exit status; all orchestration lives in
    // `build_image`. A successful build maps to exit 0.
    build_image(paths, opts)?;
    Ok(0)
}

/// Build an OCI image inside a throwaway builder VM and return its canonical
/// digest. Drives the full pipeline: validate → Create → arm build-network
/// policy → Start → run BuildKit → ingest → tag → teardown. Used directly by
/// `izba run --build` (to chain build→run) and via `run` by `izba build`.
pub fn build_image(paths: &Paths, opts: &BuildOpts) -> anyhow::Result<String> {
    // Fail fast on a bad tag BEFORE any daemon work or VM boot.
    if let Some(tag) = &opts.tag {
        image::tags::validate_tag(tag).context("invalid -t tag")?;
    }

    let context = opts
        .context
        .canonicalize()
        .with_context(|| format!("resolving build context {}", opts.context.display()))?;
    let filename = dockerfile_rel(&context, &opts.dockerfile)?;

    let name = generate_builder_name()?;
    let mut client = DaemonClient::connect(paths)?;

    // 1. Create the throwaway builder sandbox.
    let req = DaemonRequest::Create(builder_create_request(name.clone(), opts, context.clone()));
    match client.request(&req, &mut |m| eprintln!("{m}"))? {
        DaemonResponse::Created { .. } => {}
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }

    // From here on the sandbox exists on disk — tear it down no matter what.
    let result = run_build(paths, &mut client, &name, opts, &filename);
    teardown(&mut client, &name);
    result
}

/// The build proper, AFTER Create and BEFORE teardown. Persists the policy,
/// starts the VM, runs the build, ingests + tags on success, returns the digest.
fn run_build(
    paths: &Paths,
    client: &mut DaemonClient,
    name: &str,
    opts: &BuildOpts,
    filename: &str,
) -> anyhow::Result<String> {
    // 2. Arm the enforcing build-network policy BEFORE Start. The daemon reads
    // policy.yaml fresh when it binds the egress listener at Start
    // (egress::Manager::ensure_listening → resolve_policy), so writing it here
    // is sufficient — no ReloadPolicy round-trip needed.
    let policy = EgressPolicyConfig::build_network(&opts.build_allow);
    super::persist_policy_config(paths, name, &policy)?;

    // 3. Start (confined: the builder VM gets the host-side jail like any other).
    match client.request(
        &DaemonRequest::Start {
            name: name.to_string(),
            allow_unconfined: false,
        },
        &mut |m| eprintln!("{m}"),
    )? {
        DaemonResponse::Ok => {}
        DaemonResponse::Error { message } if message.contains("already running") => {}
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }

    // 4. Run the build non-interactively; exec::run returns the workload's exit
    // code (crun propagates buildctl's status).
    let script = build_script(filename);
    let code = super::exec::run(
        paths,
        name,
        false, // interactive
        false, // tty
        vec!["/bin/sh".to_string(), "-c".to_string(), script],
    )?;
    if code != 0 {
        bail!(
            "build failed (buildctl exited {code}); inspect the builder console at {}",
            paths.sandbox_dir(name).join("logs/console.log").display()
        );
    }

    // 5. Ingest the OCI archive the build wrote to the buildout share.
    let archive = sandbox::buildout_path(paths, name);
    let digest = image::ingest_oci_archive(paths, &archive)
        .with_context(|| format!("ingesting build output {}", archive.display()))?;

    // 6. Tag if requested (already validated up front).
    if let Some(tag) = &opts.tag {
        image::tags::set_tag(paths, tag, &digest)?;
        println!("Built {digest}\nTagged {tag} -> {digest}");
    } else {
        println!("Built {digest}");
    }
    Ok(digest)
}

/// Always-runs teardown: remove the throwaway sandbox (force, since it is
/// running). Best-effort — a failure here is reported but never masks the
/// build result. The persistent `izba-buildcache` volume survives by design.
fn teardown(client: &mut DaemonClient, name: &str) {
    match client.request(
        &DaemonRequest::Rm {
            name: name.to_string(),
            force: true,
        },
        &mut |m| eprintln!("{m}"),
    ) {
        Ok(DaemonResponse::Ok) => {}
        Ok(DaemonResponse::Error { message }) => {
            eprintln!("warning: failed to remove builder sandbox '{name}': {message}");
        }
        Ok(other) => eprintln!("warning: unexpected reply removing '{name}': {other:?}"),
        Err(e) => eprintln!("warning: failed to remove builder sandbox '{name}': {e:#}"),
    }
}

/// Assemble the builder `Create` request: BuildKit image, the build context as
/// the workspace, the persistent buildcache volume, builder share on, no ports,
/// confined.
fn builder_create_request(name: String, opts: &BuildOpts, workspace: PathBuf) -> DaemonCreate {
    DaemonCreate {
        name,
        image_ref: BUILDER_IMAGE_REF.to_string(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: 8,
        ports: vec![],
        volumes: vec![VolumeSpec {
            name: Some("izba-buildcache".to_string()),
            guest_path: PathBuf::from("/var/lib/buildkit"),
            size_bytes: BUILDCACHE_BYTES,
            eph_id: None,
        }],
        allow_unconfined: false,
        builder: true,
    }
}

/// A unique, valid (`sandbox::validate_name`) name for the throwaway builder:
/// `izba-build-<base36 millis>`. Lowercase alnum + dashes only.
fn generate_builder_name() -> anyhow::Result<String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = format!("izba-build-{}", to_base36(millis));
    sandbox::validate_name(&name)
        .with_context(|| format!("generated builder name '{name}' is invalid"))?;
    Ok(name)
}

/// Lowercase base36 of `n` (digits + a-z) — stays within the sandbox-name
/// grammar `[a-z0-9][a-z0-9_.-]*`.
fn to_base36(mut n: u128) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("base36 digits are ASCII")
}

/// Resolve the Dockerfile path to a name RELATIVE to the build context — the
/// `--opt filename=` BuildKit expects against the `dockerfile=/workspace` share.
/// The Dockerfile must live inside the context dir.
fn dockerfile_rel(context: &Path, dockerfile: &Path) -> anyhow::Result<String> {
    // Canonicalize the Dockerfile if it exists so the strip_prefix works even
    // when paths mix `.`/symlinks; otherwise fall back to the raw path (lets a
    // clearer "not found" surface from BuildKit rather than a host stat error).
    let df = dockerfile
        .canonicalize()
        .unwrap_or_else(|_| dockerfile.to_path_buf());
    let rel = df.strip_prefix(context).map_err(|_| {
        anyhow::anyhow!(
            "Dockerfile {} is not inside the build context {}",
            dockerfile.display(),
            context.display()
        )
    })?;
    Ok(rel.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(context: PathBuf) -> BuildOpts {
        BuildOpts {
            dockerfile: context.join("Dockerfile"),
            tag: None,
            context,
            build_allow: vec![],
            cpus: 2,
            mem: 4096,
        }
    }

    #[test]
    fn builder_create_request_shape() {
        let ws = PathBuf::from("/ctx");
        let o = opts(ws.clone());
        let req = builder_create_request("izba-build-x".into(), &o, ws.clone());
        assert!(req.builder, "builder flag set");
        assert_eq!(req.image_ref, BUILDER_IMAGE_REF);
        assert_eq!(req.workspace, ws);
        assert!(req.ports.is_empty(), "no published ports");
        assert!(!req.allow_unconfined);
        assert_eq!(req.cpus, 2);
        assert_eq!(req.mem_mb, 4096);
        assert_eq!(req.volumes.len(), 1, "one buildcache volume");
        let vol = &req.volumes[0];
        assert_eq!(vol.name.as_deref(), Some("izba-buildcache"));
        assert_eq!(vol.guest_path, PathBuf::from("/var/lib/buildkit"));
        assert_eq!(vol.size_bytes, BUILDCACHE_BYTES);
    }

    #[test]
    fn generated_builder_name_is_valid() {
        let name = generate_builder_name().unwrap();
        assert!(name.starts_with("izba-build-"));
        sandbox::validate_name(&name).expect("generated name passes validate_name");
    }

    #[test]
    fn to_base36_lowercase_alnum_only() {
        let s = to_base36(123_456_789);
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "base36 stays in name grammar: {s}"
        );
        assert_eq!(to_base36(0), "0");
        assert_eq!(to_base36(35), "z");
        assert_eq!(to_base36(36), "10");
    }

    #[test]
    fn dockerfile_rel_inside_context() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = dir.path().canonicalize().unwrap();
        std::fs::write(ctx.join("Dockerfile"), "FROM scratch\n").unwrap();
        let rel = dockerfile_rel(&ctx, &ctx.join("Dockerfile")).unwrap();
        assert_eq!(rel, "Dockerfile");
    }

    #[test]
    fn dockerfile_rel_custom_name() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = dir.path().canonicalize().unwrap();
        std::fs::write(ctx.join("Dockerfile.dev"), "FROM scratch\n").unwrap();
        let rel = dockerfile_rel(&ctx, &ctx.join("Dockerfile.dev")).unwrap();
        assert_eq!(rel, "Dockerfile.dev");
    }

    #[test]
    fn dockerfile_rel_outside_context_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = dir.path().join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        let ctx = ctx.canonicalize().unwrap();
        let err = dockerfile_rel(&ctx, Path::new("/etc/hostname")).unwrap_err();
        assert!(
            err.to_string().contains("not inside the build context"),
            "{err}"
        );
    }

    #[test]
    fn build_network_policy_yaml_includes_hub_and_extra_hosts() {
        let yaml = EgressPolicyConfig::build_network(&["registry.example.com".into()]).to_yaml();
        assert!(yaml.contains("registry-1.docker.io"), "docker hub: {yaml}");
        assert!(
            yaml.contains("registry.example.com"),
            "extra build-allow host: {yaml}"
        );
    }
}
