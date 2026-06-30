//! Daemon-free manifest reconciliation operations shared between CLI and the
//! desktop app. Each function operates on the host filesystem only — no daemon
//! RPC — and takes an already-resolved `name: &str` so callers can handle
//! name-sanitisation however they like (e.g. the CLI uses `name::sanitize`;
//! the Tauri app can do the same without pulling in CLI crates).

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::manifest::{diff, store, DriftState, Manifest, Normalized};
use crate::paths::Paths;

/// Verify that `candidate` resides inside `base`, defending against path
/// traversal via agent-controlled values (context, dockerfile fields in
/// izba.yml).
///
/// - If `candidate` exists on disk, uses `canonicalize` (resolves symlinks).
/// - If it does not exist, rejects any path with `..` components (conservative:
///   we cannot follow symlinks that do not exist yet) and performs a lexical
///   `starts_with` check against the canonicalized base.
///
/// Error messages do NOT include the escaped absolute path to avoid leaking it.
pub fn ensure_within(base: &Path, candidate: &Path) -> Result<PathBuf> {
    let canon_base = base
        .canonicalize()
        .with_context(|| format!("resolving workspace {}", base.display()))?;

    match candidate.canonicalize() {
        Ok(resolved) => {
            if !resolved.starts_with(&canon_base) {
                bail!("build context/dockerfile escapes the workspace");
            }
            Ok(resolved)
        }
        Err(_) => {
            // Path does not yet exist. Reject any `..` component up front —
            // we cannot follow symlinks that don't exist, so `..` is
            // conservative-rejected (the `ensure_within_rejects_dotdot_nonexistent`
            // test depends on this).
            for c in candidate.components() {
                if c == Component::ParentDir {
                    bail!("build context/dockerfile escapes the workspace");
                }
            }

            // Resolve the longest existing ancestor via canonicalize so BOTH
            // sides of the comparison are canonical. On Windows, canonicalize
            // returns a verbatim path (`\\?\C:\...`); without this the plain
            // `C:\...` path from `candidate` would fail `starts_with` against
            // the verbatim `canon_base`.
            let mut ancestor = candidate.to_path_buf();
            let mut tail: Vec<OsString> = Vec::new();
            let canon_ancestor = loop {
                if let Ok(p) = ancestor.canonicalize() {
                    break p;
                }
                match ancestor.file_name() {
                    Some(n) => tail.push(n.to_os_string()),
                    None => bail!("build context/dockerfile escapes the workspace"),
                }
                if !ancestor.pop() {
                    bail!("build context/dockerfile escapes the workspace");
                }
            };

            if !canon_ancestor.starts_with(&canon_base) {
                bail!("build context/dockerfile escapes the workspace");
            }

            // Re-append the non-existent tail (collected in reverse order).
            let mut resolved = canon_ancestor;
            for component in tail.into_iter().rev() {
                resolved.push(component);
            }
            if !resolved.starts_with(&canon_base) {
                bail!("build context/dockerfile escapes the workspace");
            }
            Ok(resolved)
        }
    }
}

/// Load `izba.yml` from a workspace dir, returning `(manifest, raw_yaml,
/// dockerfile_contents)`. `dockerfile` is `Some` only for a `build:` spec.
///
/// The `context` and `dockerfile` fields are agent-controlled; both are
/// verified to reside within `dir` via [`ensure_within`] before any filesystem
/// read.
pub fn load_repo_manifest(dir: &Path) -> Result<(Manifest, String, Option<String>)> {
    let path = dir.join("izba.yml");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let m = Manifest::load_str(&raw)?;
    let dockerfile = match &m.spec.build {
        Some(b) => {
            let ctx_raw = dir.join(b.context.as_deref().unwrap_or("."));
            let ctx = ensure_within(dir, &ctx_raw)?;
            let df_raw = ctx.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
            let df = ensure_within(&ctx, &df_raw)?;
            Some(
                std::fs::read_to_string(&df)
                    .with_context(|| format!("reading {}", df.display()))?,
            )
        }
        None => None,
    };
    Ok((m, raw, dockerfile))
}

/// Read the managed truth (config.json + policy.yaml) for `name` into a
/// `Normalized`, directly from disk (works on a stopped sandbox).
pub fn managed_normalized(paths: &Paths, name: &str) -> Result<Normalized> {
    crate::sandbox::validate_name(name)?;
    use crate::daemon::egress::config::EgressPolicyConfig;
    use crate::state::{load_json, SandboxConfig, CONFIG_FILE};
    let dir = paths.sandbox_dir(name);
    let cfg: SandboxConfig =
        load_json(&dir.join(CONFIG_FILE))?.with_context(|| format!("no such sandbox: {name}"))?;
    let egress = EgressPolicyConfig::load(&dir)?.unwrap_or_default();
    let mut n = Normalized::from_managed(name, &cfg, &egress);
    // Recover the scratch rw disk size so `izba export` emits a valid
    // `rootDisk.size` (not "0", which has no unit suffix and fails to parse).
    //
    // Priority order:
    //   1. cfg.rw_size_gb > 0  — persisted at create time (new sandboxes).
    //   2. rw.img file length >> 30  — back-compat for pre-existing sandboxes.
    //   3. If the file-length is also sub-GiB/zero (test images), round it up
    //      to 1 GiB so we never emit "0Gi" or the bare "0" that parse_gib
    //      rejects.  A 1 GiB rootDisk entry for a sub-GiB test image is
    //      conservative (never under-allocates on re-import).
    if cfg.rw_size_gb > 0 {
        n.rw_size_gb = cfg.rw_size_gb;
    } else {
        let rw = dir.join("rw.img");
        if let Ok(meta) = std::fs::metadata(&rw) {
            let from_file = meta.len() >> 30;
            n.rw_size_gb = if from_file > 0 {
                from_file
            } else {
                // Sub-GiB image (unusual but valid in tests / legacy setups):
                // round up to 1 GiB so to_manifest() never emits "0".
                1
            };
        }
    }
    Ok(n)
}

/// Compute the structural diff between `izba.yml` in `dir` and the managed
/// truth for `name`. Returns `(state, deltas, review_token)` where the review
/// token binds the human review to the exact manifest + Dockerfile bytes.
/// Callers are responsible for persisting the token (see [`store::write_review`]).
pub fn compute_diff(
    paths: &Paths,
    dir: &Path,
    name: &str,
) -> Result<(DriftState, Vec<diff::FieldDelta>, String)> {
    crate::sandbox::validate_name(name)?;
    let (m, raw, dockerfile) = load_repo_manifest(dir)?;
    let repo = Normalized::from_manifest(&m, name)?;
    let managed = managed_normalized(paths, name)?;
    let sandbox_dir = paths.sandbox_dir(name);
    let base = store::read_base(&sandbox_dir)?
        .map(|bm| Normalized::from_manifest(&bm, name))
        .transpose()?
        .unwrap_or_else(|| managed.clone());
    let state = super::classify(&base, &repo, &managed);
    let deltas = super::diff_normalized(&managed, &repo);
    let token = store::review_token(&raw, dockerfile.as_deref());
    Ok((state, deltas, token))
}

/// Write the managed truth for `name` back into `dir/izba.yml`, advance the
/// base, and clear the review token. Returns the path written.
/// Inverse of promote; no review gate (the caller is the human operator).
pub fn export(paths: &Paths, dir: &Path, name: &str) -> Result<PathBuf> {
    crate::sandbox::validate_name(name)?;
    let managed = managed_normalized(paths, name)?;
    let manifest = managed.to_manifest();
    let path = dir.join("izba.yml");
    std::fs::write(&path, manifest_with_header(&manifest))
        .with_context(|| format!("writing {}", path.display()))?;
    let sandbox_dir = paths.sandbox_dir(name);
    store::write_base(&sandbox_dir, &manifest)?;
    store::clear_review(&sandbox_dir)?;
    Ok(path)
}

/// Prepend the managed-export header to a YAML manifest string.
pub fn manifest_with_header(m: &Manifest) -> String {
    format!(
        "# Generated by `izba export` — edit and `izba diff`/`izba promote` to apply.\n{}",
        m.to_yaml()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;

    const MINIMAL_MANIFEST: &str = concat!(
        "apiVersion: izba.dev/v1alpha1\n",
        "kind: Sandbox\n",
        "spec:\n",
        "  image: ubuntu:24.04\n",
        "  resources: { cpus: 1, memory: 1Gi }\n",
        "  rootDisk: { size: 1Gi }\n",
    );

    #[test]
    fn load_repo_manifest_reads_izba_yml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MINIMAL_MANIFEST).unwrap();
        let (m, raw, dockerfile) = load_repo_manifest(tmp.path()).unwrap();
        assert_eq!(m.spec.resources.cpus, 1);
        assert!(raw.contains("ubuntu:24.04"));
        assert!(dockerfile.is_none());
    }

    #[test]
    fn load_repo_manifest_missing_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_repo_manifest(tmp.path()).is_err());
    }

    #[test]
    fn manifest_with_header_prepends_comment() {
        let m = Manifest::load_str(MINIMAL_MANIFEST).unwrap();
        let s = manifest_with_header(&m);
        assert!(s.starts_with("# Generated by `izba export`"), "got: {s}");
        assert!(s.contains("apiVersion: izba.dev/v1alpha1"));
    }

    #[test]
    fn managed_normalized_reads_config_json() {
        use crate::state::SandboxConfig;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let name = "testbox";
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:22.04".into(),
            cpus: 4,
            mem_mb: 2048,
            workspace: "/workspace".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        std::fs::write(
            sandbox_dir.join(crate::state::CONFIG_FILE),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        let n = managed_normalized(&paths, name).unwrap();
        assert_eq!(n.name, name);
        assert_eq!(n.cpus, 4);
        assert_eq!(n.mem_mb, 2048);
        match &n.image {
            crate::manifest::normalize::ImageSource::Ref(r) => assert_eq!(r, "ubuntu:22.04"),
            _ => panic!("expected Ref image source"),
        }
    }

    /// Fix 1: rw.img length is recovered as rw_size_gb so `izba export`
    /// emits a parseable `rootDisk.size` (not `"0"` which has no unit suffix).
    #[test]
    fn managed_normalized_recovers_rw_size_from_rw_img() {
        use crate::manifest::{quantity, schema::Manifest};
        use crate::state::SandboxConfig;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let name = "scratchbox";
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        // cfg.rw_size_gb == 0 simulates a legacy sandbox (no persisted size).
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 2048,
            workspace: "/workspace".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 0, // legacy: unknown, must recover from rw.img
        };
        std::fs::write(
            sandbox_dir.join(crate::state::CONFIG_FILE),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // Seed rw.img at exactly 8 GiB (sparse).
        let rw_path = sandbox_dir.join("rw.img");
        let f = std::fs::File::create(&rw_path).unwrap();
        f.set_len(8u64 << 30).unwrap();

        let n = managed_normalized(&paths, name).unwrap();
        assert_eq!(
            n.rw_size_gb, 8,
            "rw_size_gb must be recovered from rw.img when cfg.rw_size_gb == 0"
        );

        // to_manifest() must produce a rootDisk.size that parses without error.
        let m = n.to_manifest();
        let yaml = m.to_yaml();
        let m2 = Manifest::load_str(&yaml).expect("exported manifest must parse without error");
        let gib = quantity::parse_gib(&m2.spec.root_disk.size)
            .expect("rootDisk.size must have a valid unit suffix");
        assert_eq!(gib, 8, "rootDisk.size must round-trip to 8 GiB");
    }

    /// Fix 2 (primary): cfg.rw_size_gb > 0 must be used directly (no file read).
    #[test]
    fn managed_normalized_uses_persisted_rw_size_gb() {
        use crate::manifest::quantity;
        use crate::manifest::schema::Manifest;
        use crate::state::SandboxConfig;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let name = "persisted";
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 2048,
            workspace: "/workspace".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 16, // persisted at create time
        };
        std::fs::write(
            sandbox_dir.join(crate::state::CONFIG_FILE),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        // No rw.img at all — must NOT fall back to file-length recovery.

        let n = managed_normalized(&paths, name).unwrap();
        assert_eq!(
            n.rw_size_gb, 16,
            "rw_size_gb must come from cfg when cfg.rw_size_gb > 0"
        );
        let m = n.to_manifest();
        let yaml = m.to_yaml();
        let m2 = Manifest::load_str(&yaml).expect("exported manifest must parse");
        let gib = quantity::parse_gib(&m2.spec.root_disk.size)
            .expect("rootDisk.size must have a valid unit suffix");
        assert_eq!(gib, 16, "rootDisk.size must round-trip to 16 GiB");
    }

    /// A sub-GiB rw.img (file length >> 30 == 0) must round UP to 1 GiB, never
    /// 0 (which `to_manifest` would emit as the unparseable bare "0"). Pins the
    /// `from_file > 0` guard (a `>= 0` would pass the 0 through).
    #[test]
    fn managed_normalized_rounds_sub_gib_rw_img_up_to_one() {
        use crate::state::SandboxConfig;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let name = "subgib";
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 2048,
            workspace: "/workspace".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 0, // legacy: unknown, recover from rw.img
        };
        std::fs::write(
            sandbox_dir.join(crate::state::CONFIG_FILE),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // rw.img smaller than 1 GiB -> (len >> 30) == 0.
        let f = std::fs::File::create(sandbox_dir.join("rw.img")).unwrap();
        f.set_len(512u64 << 20).unwrap(); // 512 MiB

        let n = managed_normalized(&paths, name).unwrap();
        assert_eq!(
            n.rw_size_gb, 1,
            "a sub-GiB rw.img must round up to 1 GiB, never 0"
        );
    }

    // -- Security fix 1: validate_name at every sandbox-path chokepoint --

    /// managed_normalized must reject a traversal name before touching the fs.
    #[test]
    fn managed_normalized_rejects_traversal_name() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let err = managed_normalized(&paths, "../../etc").unwrap_err();
        assert!(
            err.to_string().contains("invalid sandbox name"),
            "expected name-validation error, got: {err}"
        );
    }

    /// compute_diff must reject a traversal name before touching the fs.
    #[test]
    fn compute_diff_rejects_traversal_name() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        std::fs::write(tmp.path().join("izba.yml"), MINIMAL_MANIFEST).unwrap();
        let err = compute_diff(&paths, tmp.path(), "../../etc").unwrap_err();
        assert!(
            err.to_string().contains("invalid sandbox name"),
            "expected name-validation error, got: {err}"
        );
    }

    /// export must reject a traversal name before touching the fs.
    #[test]
    fn export_rejects_traversal_name() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let err = export(&paths, tmp.path(), "../../etc").unwrap_err();
        assert!(
            err.to_string().contains("invalid sandbox name"),
            "expected name-validation error, got: {err}"
        );
    }

    // -- Security fix 2: ensure_within bounds build paths to workspace --

    /// A build: manifest with normal paths (context=., dockerfile=Dockerfile).
    const BUILD_MANIFEST: &str = concat!(
        "apiVersion: izba.dev/v1alpha1\n",
        "kind: Sandbox\n",
        "spec:\n",
        "  build:\n",
        "    context: '.'\n",
        "    dockerfile: 'Dockerfile'\n",
        "  resources: { cpus: 1, memory: 1Gi }\n",
        "  rootDisk: { size: 1Gi }\n",
    );

    /// load_repo_manifest with a traversal context dir must return Err.
    #[test]
    fn load_repo_manifest_rejects_traversal_context() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "spec:\n",
            "  build:\n",
            "    context: '../..'\n",
            "    dockerfile: 'x'\n",
            "  resources: { cpus: 1, memory: 1Gi }\n",
            "  rootDisk: { size: 1Gi }\n",
        );
        std::fs::write(tmp.path().join("izba.yml"), manifest).unwrap();
        let err = load_repo_manifest(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("escapes the workspace"),
            "expected traversal error, got: {err}"
        );
    }

    /// load_repo_manifest with a traversal dockerfile path must return Err.
    #[test]
    fn load_repo_manifest_rejects_traversal_dockerfile() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "spec:\n",
            "  build:\n",
            "    context: '.'\n",
            "    dockerfile: '../../../etc/shadow'\n",
            "  resources: { cpus: 1, memory: 1Gi }\n",
            "  rootDisk: { size: 1Gi }\n",
        );
        std::fs::write(tmp.path().join("izba.yml"), manifest).unwrap();
        let err = load_repo_manifest(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("escapes the workspace"),
            "expected traversal error, got: {err}"
        );
    }

    /// load_repo_manifest with normal build spec must succeed.
    #[test]
    fn load_repo_manifest_allows_normal_build_spec() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), BUILD_MANIFEST).unwrap();
        std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let (m, _, dockerfile) = load_repo_manifest(tmp.path()).unwrap();
        assert!(m.spec.build.is_some(), "build spec present");
        assert!(dockerfile.is_some(), "dockerfile contents present");
    }

    /// ensure_within: an existing path outside base is rejected.
    #[test]
    fn ensure_within_rejects_existing_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let candidate = std::env::temp_dir();
        let err = ensure_within(tmp.path(), &candidate).unwrap_err();
        assert!(
            err.to_string().contains("escapes the workspace"),
            "got: {err}"
        );
    }

    /// ensure_within: a non-existent path with `..` is rejected.
    #[test]
    fn ensure_within_rejects_dotdot_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let candidate = tmp.path().join("../evil_nonexistent_xyzzy");
        let err = ensure_within(tmp.path(), &candidate).unwrap_err();
        assert!(
            err.to_string().contains("escapes the workspace"),
            "got: {err}"
        );
    }

    /// ensure_within: a non-existent child path (no `..`) is accepted.
    #[test]
    fn ensure_within_accepts_nonexistent_child() {
        let tmp = tempfile::tempdir().unwrap();
        let candidate = tmp.path().join("subdir/Dockerfile");
        let result = ensure_within(tmp.path(), &candidate).unwrap();
        assert!(result.starts_with(tmp.path().canonicalize().unwrap()));
    }

    /// ensure_within: a deeply nested non-existent path (a/b/c.txt where `a`
    /// also doesn't exist) is accepted and the returned path starts_with the
    /// canonicalized base. This exercises the ancestor-walk on Windows where
    /// canonicalize() returns a verbatim `\\?\`-prefixed path and a plain
    /// `C:\...` candidate would otherwise fail `starts_with`.
    #[test]
    fn ensure_within_accepts_nonexistent_nested_child() {
        let tmp = tempfile::tempdir().unwrap();
        // Neither `a` nor `a/b` exist; only tmp.path() itself exists.
        let candidate = tmp.path().join("a").join("b").join("c.txt");
        let result = ensure_within(tmp.path(), &candidate).unwrap();
        let canon_base = tmp.path().canonicalize().unwrap();
        assert!(
            result.starts_with(&canon_base),
            "resolved path {result:?} must start with canon base {canon_base:?}"
        );
    }
}
