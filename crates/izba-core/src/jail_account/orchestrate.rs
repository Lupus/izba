//! Client-side lock-down orchestration: provision, unlock, GC, and state query.
//!
//! # Design
//!
//! All side-effecting operations (elevated helper invocation + DPAPI seal/unseal)
//! are hidden behind the [`LockdownBackend`] trait. [`WinBackend`] provides the
//! real Windows implementation; tests substitute a [`FakeBackend`] that runs
//! entirely in-process without elevation or DPAPI.
//!
//! # State machine
//!
//! ```text
//!  Unlocked ──lockdown()──► Locked
//!  Locked   ──unlock()───► Unlocked
//! ```
//!
//! `Cancelled` is a transient outcome: no state file is written and the sandbox
//! is left exactly as it was before `lockdown` was called.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};

use crate::jail_account::builders::{account_name, deprovision_argv, gc_argv, provision_argv};
use crate::jail_account::helper::ElevationOutcome;
use crate::jail_account::state::{LockdownFile, LockdownState, LockedInfo, LOCKDOWN_FILE};
use crate::paths::Paths;
use crate::state::{load_json, save_json, SandboxConfig, CONFIG_FILE};

// ── Trait seam ────────────────────────────────────────────────────────────────

/// Abstraction over elevation + DPAPI operations so that host-side unit tests
/// can substitute a fake without touching the OS.
pub trait LockdownBackend {
    /// Invoke the elevated helper with `argv` and return its outcome.
    fn elevate(&self, argv: &[String]) -> Result<ElevationOutcome, String>;
    /// Encrypt `plain` bytes (DPAPI-scoped to the current user on Windows).
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, String>;
    /// Decrypt a blob previously produced by [`seal`].
    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, String>;
}

// ── Windows production backend ────────────────────────────────────────────────

/// The real Windows backend: uses [`crate::jail_account::helper::run_elevated`]
/// + [`crate::jail_account::dpapi`].
#[cfg(windows)]
pub struct WinBackend;

#[cfg(windows)]
impl LockdownBackend for WinBackend {
    fn elevate(&self, argv: &[String]) -> Result<ElevationOutcome, String> {
        crate::jail_account::helper::run_elevated(argv)
    }

    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        crate::jail_account::dpapi::seal(plain)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        crate::jail_account::dpapi::unseal(blob)
    }
}

/// Non-Windows stub so that `WinBackend` compiles everywhere and its methods
/// return a clear error rather than failing at link time.
#[cfg(not(windows))]
pub struct WinBackend;

#[cfg(not(windows))]
impl LockdownBackend for WinBackend {
    fn elevate(&self, _argv: &[String]) -> Result<ElevationOutcome, String> {
        Err("windows-only".into())
    }

    fn seal(&self, _plain: &[u8]) -> Result<Vec<u8>, String> {
        Err("windows-only".into())
    }

    fn unseal(&self, _blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("windows-only".into())
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// The outcome of a [`lockdown`] call.
#[derive(Debug)]
pub enum LockdownOutcome {
    /// The sandbox was successfully locked down.
    Locked(LockedInfo),
    /// The user cancelled the UAC prompt; no state was changed.
    Cancelled,
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Compute the set of host paths the sandbox account must be able to read/write
/// (`Modify` DACL level).
///
/// Returns `[workspace, sandbox_dir]` plus the image path for every
/// **persistent** (named) volume.  Anonymous volumes live under `sandbox_dir`
/// and are therefore already covered.
///
/// This function is pure — it performs no I/O — and is therefore host-testable
/// on all platforms.
pub fn compute_grants(config: &SandboxConfig, paths: &Paths, name: &str) -> Vec<PathBuf> {
    let mut grants = vec![config.workspace.clone(), paths.sandbox_dir(name)];
    for v in &config.volumes {
        if v.is_persistent() {
            // Persistent volumes are keyed by name; `volume_image` returns
            // `<root>/volumes/<name>.img`.
            if let Some(vol_name) = &v.name {
                grants.push(paths.volume_image(vol_name));
            }
        }
    }
    grants
}

/// Compute the shared read-only artifacts the VMM opens that live OUTSIDE the
/// sandbox dir, granted at the `ReadExec` DACL level.
///
/// Returns those of `[<this image's rootfs.erofs>, artifacts_dir]` that currently
/// **exist** on disk. Granularity matters for read-confinement, so:
/// - the **erofs** is THIS sandbox's specific base-image layer (via the image
///   digest), NOT the whole `images/` dir — a compromised VMM cannot read other
///   images' base layers. It is a public OCI base layer anyway; per-sandbox data
///   lives in `rw.img`/volumes/workspace, never in the shared base erofs.
/// - `artifacts_dir` holds the **global** kernel + initramfs, identical for every
///   sandbox, so it exposes nothing sandbox-specific.
///
/// Per-sandbox **drives** are deliberately absent here: `rw.img` is inside the
/// (separately granted) sandbox dir, and named-volume images are granted
/// individually in [`compute_grants`] — so the account can never read another
/// sandbox's drives. `artifacts_dir` may be absent on hosts where kernel/initrd
/// come from elsewhere; such missing paths are filtered out so provisioning does
/// not fail.
pub fn compute_ro_grants(config: &SandboxConfig, paths: &Paths) -> Vec<PathBuf> {
    let erofs = crate::image::ImageStore::new(paths).rootfs_path(&config.image_digest);
    [erofs, paths.artifacts_dir()]
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

// ── Orchestration functions ───────────────────────────────────────────────────

/// Provision a per-sandbox Windows account, seal its credential, and persist
/// lock-down state to disk.
///
/// # Steps
///
/// 1. Load `config.json` from the sandbox directory.
/// 2. Compute grants (workspace + sandbox dir + named volume images).
/// 3. Run the elevated helper via `backend.elevate(provision_argv(…))`.
/// 4. Read the SID + credential written by the helper to temporary files.
/// 5. Seal the credential with `backend.seal` (DPAPI on Windows).
/// 6. Persist `lockdown.cred` + `lockdown.json` under the sandbox directory.
/// 7. Best-effort clean up the `.tmp` files.
///
/// Returns [`LockdownOutcome::Cancelled`] (without touching any state) if the
/// user cancels the UAC prompt.
pub fn lockdown<B: LockdownBackend>(
    backend: &B,
    paths: &Paths,
    name: &str,
) -> anyhow::Result<LockdownOutcome> {
    let sandbox_dir = paths.sandbox_dir(name);

    // --- load config ---
    let config: SandboxConfig = load_json(&sandbox_dir.join(CONFIG_FILE))
        .with_context(|| format!("loading config for sandbox {name:?}"))?
        .ok_or_else(|| anyhow!("no config.json for sandbox {name:?}"))?;

    let grants = compute_grants(&config, paths, name);
    let ro = compute_ro_grants(&config, paths);

    // --- temporary output files for the helper ---
    let sid_out = sandbox_dir.join(".lockdown.sid.tmp");
    let cred_out = sandbox_dir.join(".lockdown.cred.tmp");

    // Remove any stale tmp files from a previous failed attempt.
    let _ = std::fs::remove_file(&sid_out);
    let _ = std::fs::remove_file(&cred_out);

    // --- invoke the elevated helper ---
    let argv = provision_argv(name, &grants, &ro, &sid_out, &cred_out);
    match backend
        .elevate(&argv)
        .map_err(|e| anyhow!("elevate provision: {e}"))?
    {
        ElevationOutcome::Cancelled => return Ok(LockdownOutcome::Cancelled),
        ElevationOutcome::Failed(msg) => bail!("provision helper failed: {msg}"),
        ElevationOutcome::Ok => {}
    }

    // All remaining work runs inside a closure so that we can unconditionally
    // clean up the tmp files (including the plaintext credential) whether the
    // inner steps succeed or fail.
    let result: anyhow::Result<LockdownOutcome> = (|| {
        // --- read helper output ---
        let sid = std::fs::read_to_string(&sid_out)
            .with_context(|| format!("read sid_out {:?} (helper contract violated)", sid_out))?;
        let sid = sid.trim().to_string();

        let password = std::fs::read(&cred_out)
            .with_context(|| format!("read cred_out {:?} (helper contract violated)", cred_out))?;

        // --- seal the credential ---
        let sealed = backend
            .seal(&password)
            .map_err(|e| anyhow!("DPAPI seal: {e}"))?;

        // --- persist sealed credential ---
        let cred_path = sandbox_dir.join("lockdown.cred");
        std::fs::write(&cred_path, &sealed).with_context(|| format!("write {:?}", cred_path))?;

        // --- persist lockdown state ---
        let info = LockedInfo {
            account: account_name(name),
            sid,
            net_blocked: true,
        };
        let lockdown_path = sandbox_dir.join(LOCKDOWN_FILE);
        if let Err(e) = save_json(
            &lockdown_path,
            &LockdownFile {
                state: Some(info.clone()),
            },
        )
        .with_context(|| format!("save {:?}", lockdown_path))
        {
            // lockdown.cred was written but lockdown.json failed: remove the
            // sealed credential so the sandbox is cleanly Unlocked (json absent
            // = Unlocked is the authoritative sentinel).
            let _ = std::fs::remove_file(&cred_path);
            return Err(e);
        }

        Ok(LockdownOutcome::Locked(info))
    })();

    // Unconditionally remove tmp files (including the plaintext credential)
    // regardless of whether the inner work succeeded or failed.
    let _ = std::fs::remove_file(&sid_out);
    let _ = std::fs::remove_file(&cred_out);

    result
}

/// Deprovision the per-sandbox Windows account and clear lock-down state.
///
/// If the user cancels the UAC prompt the lock-down state is left as-is and
/// this function returns an error.
pub fn unlock<B: LockdownBackend>(backend: &B, paths: &Paths, name: &str) -> anyhow::Result<()> {
    let argv = deprovision_argv(name);
    match backend
        .elevate(&argv)
        .map_err(|e| anyhow!("elevate deprovision: {e}"))?
    {
        ElevationOutcome::Cancelled => bail!("unlock cancelled by user"),
        ElevationOutcome::Failed(msg) => bail!("deprovision helper failed: {msg}"),
        ElevationOutcome::Ok => {}
    }

    let sandbox_dir = paths.sandbox_dir(name);

    // Remove state files (idempotent — ignore not-found).
    let lockdown_path = sandbox_dir.join(LOCKDOWN_FILE);
    let cred_path = sandbox_dir.join("lockdown.cred");
    for p in [&lockdown_path, &cred_path] {
        match std::fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("remove {:?}", p)),
        }
    }

    Ok(())
}

/// Run the GC sub-command of the elevated helper to clean up orphaned accounts.
///
/// `live` is the list of sandbox names that are currently active; the helper
/// will delete any `izba-sb-*` accounts not in this list.
pub fn windows_cleanup<B: LockdownBackend>(
    backend: &B,
    paths: &Paths,
    live: &[String],
) -> anyhow::Result<()> {
    let _ = paths; // not needed for gc_argv; kept for API symmetry
    let argv = gc_argv(live);
    match backend
        .elevate(&argv)
        .map_err(|e| anyhow!("elevate gc: {e}"))?
    {
        ElevationOutcome::Cancelled => bail!("gc cancelled by user"),
        ElevationOutcome::Failed(msg) => bail!("gc helper failed: {msg}"),
        ElevationOutcome::Ok => {}
    }
    Ok(())
}

/// Read the current lock-down state from disk (read-only; for status display).
///
/// Returns `Unlocked` if `lockdown.json` does not exist or has no `state`.
pub fn lockdown_state(paths: &Paths, name: &str) -> LockdownState {
    let path = paths.sandbox_dir(name).join(LOCKDOWN_FILE);
    match load_json::<LockdownFile>(&path) {
        Ok(Some(LockdownFile { state: Some(info) })) => LockdownState::Locked(info),
        _ => LockdownState::Unlocked,
    }
}

/// Read and unseal the per-sandbox password from `lockdown.cred`.
///
/// Returns `Ok(Some(pw))` when the file exists and decrypts successfully,
/// `Ok(None)` when the file is absent (sandbox is unlocked), or `Err` on I/O
/// or decryption failure.
#[cfg(windows)]
pub fn unseal_password(
    backend: &impl LockdownBackend,
    paths: &Paths,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let cred_path = paths.sandbox_dir(name).join("lockdown.cred");
    match std::fs::read(&cred_path) {
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {:?}", cred_path)),
        Ok(blob) => {
            let plain = backend
                .unseal(&blob)
                .map_err(|e| anyhow!("DPAPI unseal: {e}"))?;
            let pw = String::from_utf8(plain).context("lockdown.cred is not valid UTF-8")?;
            Ok(Some(pw))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::jail_account::builders::account_name as jail_account_name;
    use crate::paths::Paths;
    use crate::state::{save_json as core_save_json, SandboxConfig, CONFIG_FILE};

    // ── FakeBackend ───────────────────────────────────────────────────────────

    /// Configurable fake for [`LockdownBackend`].
    ///
    /// On `Ok`, `elevate` inspects the argv to find `--sid-out` and `--cred-out`
    /// arguments and writes fake content to those files so that `lockdown` can
    /// read them back.  For `deprovision` and `gc` argv shapes there are no
    /// output files, so the write step is skipped.
    ///
    /// Set `write_tmp_files = false` to simulate a helper that returns `Ok` but
    /// does not write the output files (contract violation).
    ///
    /// Set `seal_err = Some(msg)` to make `seal` return an `Err`.
    struct FakeBackend {
        /// What `elevate` should return.
        outcome: ElevationOutcome,
        /// Whether the fake helper writes the sid/cred tmp files on `Ok`.
        write_tmp_files: bool,
        /// If `Some`, `seal` returns this error message instead of succeeding.
        seal_err: Option<String>,
        /// Captured argv from the most recent `elevate` call.
        last_argv: Arc<Mutex<Vec<String>>>,
    }

    impl FakeBackend {
        fn ok() -> Self {
            Self {
                outcome: ElevationOutcome::Ok,
                write_tmp_files: true,
                seal_err: None,
                last_argv: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn cancelled() -> Self {
            Self {
                outcome: ElevationOutcome::Cancelled,
                write_tmp_files: true,
                seal_err: None,
                last_argv: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn failed(msg: &str) -> Self {
            Self {
                outcome: ElevationOutcome::Failed(msg.to_string()),
                write_tmp_files: true,
                seal_err: None,
                last_argv: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Helper returns `Ok` but does NOT write the output files.
        fn ok_no_files() -> Self {
            Self {
                outcome: ElevationOutcome::Ok,
                write_tmp_files: false,
                seal_err: None,
                last_argv: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Helper writes the tmp files successfully, but `seal` fails.
        fn ok_seal_err(msg: &str) -> Self {
            Self {
                outcome: ElevationOutcome::Ok,
                write_tmp_files: true,
                seal_err: Some(msg.to_string()),
                last_argv: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn last_argv(&self) -> Vec<String> {
            self.last_argv.lock().unwrap().clone()
        }
    }

    impl LockdownBackend for FakeBackend {
        fn elevate(&self, argv: &[String]) -> Result<ElevationOutcome, String> {
            *self.last_argv.lock().unwrap() = argv.to_vec();

            if matches!(self.outcome, ElevationOutcome::Ok) && self.write_tmp_files {
                // If this is a provision call, write fake sid/cred tmp files.
                let mut sid_out: Option<&str> = None;
                let mut cred_out: Option<&str> = None;
                let mut i = 0;
                while i < argv.len() {
                    match argv[i].as_str() {
                        "--sid-out" if i + 1 < argv.len() => {
                            sid_out = Some(&argv[i + 1]);
                            i += 2;
                        }
                        "--cred-out" if i + 1 < argv.len() => {
                            cred_out = Some(&argv[i + 1]);
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
                if let Some(path) = sid_out {
                    std::fs::write(path, "S-1-5-21-1-2-3-1001").ok();
                }
                if let Some(path) = cred_out {
                    std::fs::write(path, b"fakepw").ok();
                }
            }

            match &self.outcome {
                ElevationOutcome::Ok => Ok(ElevationOutcome::Ok),
                ElevationOutcome::Cancelled => Ok(ElevationOutcome::Cancelled),
                ElevationOutcome::Failed(msg) => Ok(ElevationOutcome::Failed(msg.clone())),
            }
        }

        /// Identity seal: returns the plaintext unchanged, prefixed with `"sealed:"`.
        /// Returns `Err` when `seal_err` is set.
        fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
            if let Some(ref msg) = self.seal_err {
                return Err(msg.clone());
            }
            let mut v = b"sealed:".to_vec();
            v.extend_from_slice(plain);
            Ok(v)
        }

        /// Identity unseal: strips the `"sealed:"` prefix.
        fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
            blob.strip_prefix(b"sealed:")
                .map(|b| b.to_vec())
                .ok_or_else(|| "unseal: missing prefix".into())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    const SANDBOX_NAME: &str = "test-sb";

    fn make_paths(dir: &tempfile::TempDir) -> Paths {
        Paths::with_root(dir.path().to_path_buf())
    }

    fn write_config(paths: &Paths, name: &str, volumes: Vec<crate::volume::VolumeSpec>) {
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
            volumes,
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        core_save_json(&sandbox_dir.join(CONFIG_FILE), &cfg).unwrap();
    }

    // ── compute_ro_grants ─────────────────────────────────────────────────────

    fn ro_test_config() -> SandboxConfig {
        SandboxConfig {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            build: None,
            rw_size_gb: 8,
        }
    }

    fn make_erofs(paths: &Paths, cfg: &SandboxConfig) -> PathBuf {
        let erofs = crate::image::ImageStore::new(paths).rootfs_path(&cfg.image_digest);
        std::fs::create_dir_all(erofs.parent().unwrap()).unwrap();
        std::fs::write(&erofs, b"erofs").unwrap();
        erofs
    }

    #[test]
    fn compute_ro_grants_includes_this_images_erofs_not_whole_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cfg = ro_test_config();
        let erofs = make_erofs(&paths, &cfg);
        // artifacts_dir absent.

        let ro = compute_ro_grants(&cfg, &paths);
        assert!(
            ro.contains(&erofs),
            "this image's erofs must be granted: {ro:?}"
        );
        // Granularity: NOT the whole images dir, NOT the absent artifacts dir.
        assert!(
            !ro.contains(&paths.images_dir()),
            "must not grant the whole images dir: {ro:?}"
        );
        assert!(
            !ro.contains(&paths.artifacts_dir()),
            "non-existent artifacts_dir must be filtered out: {ro:?}"
        );
    }

    #[test]
    fn compute_ro_grants_adds_artifacts_dir_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cfg = ro_test_config();
        let erofs = make_erofs(&paths, &cfg);
        std::fs::create_dir_all(paths.artifacts_dir()).unwrap();

        let ro = compute_ro_grants(&cfg, &paths);
        assert!(ro.contains(&erofs));
        assert!(ro.contains(&paths.artifacts_dir()));
        assert_eq!(ro.len(), 2);
    }

    #[test]
    fn compute_ro_grants_empty_when_nothing_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Neither the erofs nor the artifacts dir created.
        let ro = compute_ro_grants(&ro_test_config(), &paths);
        assert!(ro.is_empty(), "must be empty when nothing exists: {ro:?}");
    }

    // ── compute_grants ────────────────────────────────────────────────────────

    #[test]
    fn compute_grants_includes_workspace_and_sandbox_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/my/workspace"),
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        let grants = compute_grants(&cfg, &paths, SANDBOX_NAME);
        assert!(grants.contains(&PathBuf::from("/my/workspace")));
        assert!(grants.contains(&paths.sandbox_dir(SANDBOX_NAME)));
    }

    #[test]
    fn compute_grants_includes_persistent_volume_image_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
            volumes: vec![crate::volume::VolumeSpec {
                name: Some("cache".to_string()),
                guest_path: PathBuf::from("/data"),
                size_bytes: 1 << 30,
                eph_id: None,
            }],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        let grants = compute_grants(&cfg, &paths, SANDBOX_NAME);
        assert!(grants.contains(&paths.volume_image("cache")));
    }

    #[test]
    fn compute_grants_excludes_anonymous_volume_individual_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
            volumes: vec![crate::volume::VolumeSpec {
                name: None, // anonymous
                guest_path: PathBuf::from("/ephemeral"),
                size_bytes: 1 << 20,
                eph_id: None,
            }],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        let grants = compute_grants(&cfg, &paths, SANDBOX_NAME);
        // Anonymous volumes live under sandbox_dir so only the sandbox_dir
        // entry covers them.  The individual ephemeral image path is NOT added.
        let anon_path = paths
            .sandbox_dir(SANDBOX_NAME)
            .join("volumes")
            .join("0.img");
        assert!(!grants.contains(&anon_path));
        // But sandbox_dir itself is still there.
        assert!(grants.contains(&paths.sandbox_dir(SANDBOX_NAME)));
    }

    // ── lockdown happy path ───────────────────────────────────────────────────

    #[test]
    fn lockdown_happy_path_writes_state_and_cred() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::ok();
        let outcome = lockdown(&backend, &paths, SANDBOX_NAME).unwrap();

        // Return value.
        let info = match outcome {
            LockdownOutcome::Locked(i) => i,
            LockdownOutcome::Cancelled => panic!("expected Locked"),
        };

        assert_eq!(info.account, jail_account_name(SANDBOX_NAME));
        assert_eq!(info.sid, "S-1-5-21-1-2-3-1001");
        assert!(info.net_blocked);

        // lockdown.json on disk.
        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        let lf: LockdownFile = load_json(&sandbox_dir.join(LOCKDOWN_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(lf.state.as_ref().unwrap().account, info.account);
        assert_eq!(lf.state.as_ref().unwrap().sid, "S-1-5-21-1-2-3-1001");
        assert!(lf.state.as_ref().unwrap().net_blocked);

        // lockdown.cred on disk (sealed by the fake backend).
        let cred_bytes = std::fs::read(sandbox_dir.join("lockdown.cred")).unwrap();
        // FakeBackend::seal prefixes "sealed:".
        assert!(cred_bytes.starts_with(b"sealed:"));
        // The original password was "fakepw".
        assert_eq!(&cred_bytes[b"sealed:".len()..], b"fakepw");

        // Tmp files cleaned up.
        assert!(!sandbox_dir.join(".lockdown.sid.tmp").exists());
        assert!(!sandbox_dir.join(".lockdown.cred.tmp").exists());
    }

    // ── lockdown Cancelled ────────────────────────────────────────────────────

    #[test]
    fn lockdown_cancelled_returns_cancelled_no_state_written() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::cancelled();
        let outcome = lockdown(&backend, &paths, SANDBOX_NAME).unwrap();

        assert!(matches!(outcome, LockdownOutcome::Cancelled));

        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        assert!(!sandbox_dir.join(LOCKDOWN_FILE).exists());
        assert!(!sandbox_dir.join("lockdown.cred").exists());
    }

    // ── lockdown Failed ───────────────────────────────────────────────────────

    #[test]
    fn lockdown_failed_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::failed("helper exit 1");
        let result = lockdown(&backend, &paths, SANDBOX_NAME);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("provision helper failed"), "msg: {msg}");
    }

    // ── unlock ────────────────────────────────────────────────────────────────

    #[test]
    fn unlock_removes_state_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        // First lock down.
        let backend = FakeBackend::ok();
        lockdown(&backend, &paths, SANDBOX_NAME).unwrap();

        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        assert!(sandbox_dir.join(LOCKDOWN_FILE).exists());
        assert!(sandbox_dir.join("lockdown.cred").exists());

        // Now unlock.
        let backend2 = FakeBackend::ok();
        unlock(&backend2, &paths, SANDBOX_NAME).unwrap();

        assert!(!sandbox_dir.join(LOCKDOWN_FILE).exists());
        assert!(!sandbox_dir.join("lockdown.cred").exists());
    }

    #[test]
    fn unlock_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Don't write lockdown files — call unlock on a clean sandbox.
        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let backend = FakeBackend::ok();
        // First call: nothing to remove.
        unlock(&backend, &paths, SANDBOX_NAME).unwrap();
        // Second call: still idempotent.
        unlock(&backend, &paths, SANDBOX_NAME).unwrap();
    }

    #[test]
    fn unlock_cancelled_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        std::fs::create_dir_all(paths.sandbox_dir(SANDBOX_NAME)).unwrap();

        let backend = FakeBackend::cancelled();
        let result = unlock(&backend, &paths, SANDBOX_NAME);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("cancelled"), "msg: {msg}");
    }

    // ── lockdown_state ────────────────────────────────────────────────────────

    #[test]
    fn lockdown_state_unlocked_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        std::fs::create_dir_all(paths.sandbox_dir(SANDBOX_NAME)).unwrap();

        let state = lockdown_state(&paths, SANDBOX_NAME);
        assert_eq!(state, LockdownState::Unlocked);
    }

    #[test]
    fn lockdown_state_locked_after_lockdown() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::ok();
        lockdown(&backend, &paths, SANDBOX_NAME).unwrap();

        let state = lockdown_state(&paths, SANDBOX_NAME);
        assert!(state.is_locked());
        let LockdownState::Locked(info) = state else {
            panic!("expected Locked");
        };
        assert_eq!(info.account, jail_account_name(SANDBOX_NAME));
    }

    #[test]
    fn lockdown_state_unlocked_after_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::ok();
        lockdown(&backend, &paths, SANDBOX_NAME).unwrap();
        unlock(&backend, &paths, SANDBOX_NAME).unwrap();

        let state = lockdown_state(&paths, SANDBOX_NAME);
        assert_eq!(state, LockdownState::Unlocked);
    }

    // ── windows_cleanup ───────────────────────────────────────────────────────

    #[test]
    fn windows_cleanup_passes_gc_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);

        let live = vec!["sandbox-a".to_string(), "sandbox-b".to_string()];
        let backend = FakeBackend::ok();
        windows_cleanup(&backend, &paths, &live).unwrap();

        let argv = backend.last_argv();
        let expected = gc_argv(&live);
        assert_eq!(argv, expected);
    }

    #[test]
    fn windows_cleanup_failed_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);

        let backend = FakeBackend::failed("gc failed");
        let result = windows_cleanup(&backend, &paths, &[]);
        assert!(result.is_err());
    }

    // ── Fix-3: missing output files path ─────────────────────────────────────

    /// When the elevated helper returns `Ok` but does NOT write the sid/cred
    /// tmp files (helper contract violation), `lockdown` must return `Err` AND
    /// leave no `lockdown.json` or `lockdown.cred` on disk.
    #[test]
    fn lockdown_missing_output_files_errs_and_leaves_no_state() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::ok_no_files();
        let result = lockdown(&backend, &paths, SANDBOX_NAME);
        assert!(result.is_err(), "expected Err when helper writes no output");

        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        assert!(
            !sandbox_dir.join(LOCKDOWN_FILE).exists(),
            "lockdown.json must not exist after error"
        );
        assert!(
            !sandbox_dir.join("lockdown.cred").exists(),
            "lockdown.cred must not exist after error"
        );
    }

    /// When `seal` fails the plaintext credential tmp file must NOT remain on
    /// disk (Fix-1 guarantee), and `lockdown.json`/`lockdown.cred` must not
    /// be present either.
    #[test]
    fn lockdown_seal_failure_removes_cred_tmp_and_leaves_no_state() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        write_config(&paths, SANDBOX_NAME, Vec::new());

        let backend = FakeBackend::ok_seal_err("simulated DPAPI failure");
        let result = lockdown(&backend, &paths, SANDBOX_NAME);
        assert!(result.is_err(), "expected Err when seal fails");

        let sandbox_dir = paths.sandbox_dir(SANDBOX_NAME);
        assert!(
            !sandbox_dir.join(".lockdown.cred.tmp").exists(),
            "plaintext cred tmp must be removed even on seal failure"
        );
        assert!(
            !sandbox_dir.join(".lockdown.sid.tmp").exists(),
            "sid tmp must be removed even on seal failure"
        );
        assert!(
            !sandbox_dir.join(LOCKDOWN_FILE).exists(),
            "lockdown.json must not exist after seal failure"
        );
        assert!(
            !sandbox_dir.join("lockdown.cred").exists(),
            "lockdown.cred must not exist after seal failure"
        );
    }
}
