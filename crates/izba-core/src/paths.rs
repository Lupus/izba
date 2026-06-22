use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// `override_root` wins; otherwise the per-OS default data root
    /// (Unix: `$HOME/.local/share/izba`; Windows: `%LOCALAPPDATA%\izba`).
    pub fn from_env_or_default(override_root: Option<PathBuf>) -> Self {
        if let Some(root) = override_root {
            return Self::with_root(root);
        }
        Self::with_root(default_root(&|k| std::env::var(k).ok()))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn sandboxes_dir(&self) -> PathBuf {
        self.root.join("sandboxes")
    }

    pub fn sandbox_dir(&self, name: &str) -> PathBuf {
        self.sandboxes_dir().join(name)
    }

    /// `':'` in the digest is replaced with `'-'` to keep the path safe.
    pub fn image_dir(&self, digest: &str) -> PathBuf {
        self.images_dir().join(digest.replace(':', "-"))
    }

    pub fn images_dir(&self) -> PathBuf {
        self.root.join("images")
    }

    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("run")
    }

    /// Directory for persistent (named) volume images: `<root>/volumes`.
    pub fn volumes_dir(&self) -> PathBuf {
        self.root.join("volumes")
    }

    /// Backing image for a persistent volume.
    pub fn volume_image(&self, name: &str) -> PathBuf {
        self.volumes_dir().join(format!("{name}.img"))
    }

    pub fn logs_dir(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("logs")
    }

    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    pub fn daemon_dir(&self) -> PathBuf {
        self.root.join("daemon")
    }

    pub fn daemon_socket(&self) -> PathBuf {
        self.daemon_dir().join("izbad.sock")
    }

    pub fn daemon_lock(&self) -> PathBuf {
        self.daemon_dir().join("lock")
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.daemon_dir().join("daemon.log")
    }

    /// The izba root-CA directory (`<root>/ca`): the persistent CA the MITM
    /// signs leaves with and that is baked into every guest's trust store.
    /// Holds the private key, so it is created 0700 and never shared into a VM.
    pub fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    /// Global izba SSH material (keypair, host key, managed config, known_hosts).
    pub fn ssh_dir(&self) -> PathBuf {
        self.root.join("ssh")
    }

    /// Per-sandbox dir whose contents are delivered to the guest as the
    /// `izba-ssh` virtiofs share (host key + authorized_keys).
    pub fn ssh_share_dir(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("ssh")
    }
}

/// Create `path` (and any missing ancestors) and harden the izba-owned tree to
/// `0700` on Unix: `path` itself plus every ancestor up to and including `root`
/// that did not already exist. This keeps the data root, `sandboxes/`, the
/// per-sandbox dir, `run/`, and `logs/` private to the owning user on a
/// multi-user host (matching the `ca/` and `daemon/` hardening) rather than
/// world-traversable under the process umask. A no-op chmod on Windows.
pub fn create_dir_700(path: &Path, root: &Path) -> anyhow::Result<()> {
    use anyhow::Context;

    // Ancestors (leaf-first) that don't exist yet and live inside `root` — only
    // these get chmodded, so we never touch dirs we didn't create (e.g. $HOME).
    let mut to_harden: Vec<&Path> = Vec::new();
    let mut cur = Some(path);
    while let Some(p) = cur {
        if p.exists() {
            break;
        }
        to_harden.push(p);
        if p == root {
            break;
        }
        cur = p.parent();
    }

    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in to_harden {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", p.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = to_harden;

    Ok(())
}

/// Both platform rules always compile (`cfg!`, not `#[cfg]`) so each is
/// unit-tested regardless of the build target.
fn default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    if cfg!(windows) {
        windows_default_root(env)
    } else {
        unix_default_root(env)
    }
}

fn unix_default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let home = env("HOME").unwrap_or_else(|| "/root".to_string());
    PathBuf::from(home).join(".local/share/izba")
}

fn windows_default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(lad) = env("LOCALAPPDATA") {
        return PathBuf::from(lad).join("izba");
    }
    let profile = env("USERPROFILE").unwrap_or_else(|| r"C:\".to_string());
    PathBuf::from(profile)
        .join("AppData")
        .join("Local")
        .join("izba")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_composes() {
        let p = Paths::with_root("/data/izba".into());
        assert_eq!(
            p.sandbox_dir("web"),
            PathBuf::from("/data/izba/sandboxes/web")
        );
        assert_eq!(
            p.image_dir("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc")
        );
        assert_eq!(
            p.run_dir("web"),
            PathBuf::from("/data/izba/sandboxes/web/run")
        );
        assert_eq!(
            p.logs_dir("web"),
            PathBuf::from("/data/izba/sandboxes/web/logs")
        );
        assert_eq!(
            p.daemon_socket(),
            PathBuf::from("/data/izba/daemon/izbad.sock")
        );
        assert_eq!(p.daemon_lock(), PathBuf::from("/data/izba/daemon/lock"));
        assert_eq!(
            p.daemon_log(),
            PathBuf::from("/data/izba/daemon/daemon.log")
        );
    }

    #[test]
    fn volume_paths_compose() {
        let p = Paths::with_root("/data/izba".into());
        assert_eq!(p.volumes_dir(), PathBuf::from("/data/izba/volumes"));
        assert_eq!(
            p.volume_image("cache"),
            PathBuf::from("/data/izba/volumes/cache.img")
        );
    }

    #[test]
    fn env_override() {
        let p = Paths::from_env_or_default(Some("/tmp/x".into()));
        assert_eq!(p.root(), Path::new("/tmp/x"));
    }

    #[test]
    fn default_is_under_home() {
        let p = Paths::from_env_or_default(None);
        // On Unix the default ends with `.local/share/izba`; on Windows it ends
        // with `izba` (under %LOCALAPPDATA%). Both are correct for their platform.
        if cfg!(windows) {
            assert!(p.root().ends_with("izba"), "{:?}", p.root());
        } else {
            assert!(p.root().ends_with(".local/share/izba"), "{:?}", p.root());
        }
    }

    #[test]
    fn unix_root_from_home() {
        let env = |k: &str| (k == "HOME").then(|| "/home/u".to_string());
        assert_eq!(
            unix_default_root(&env),
            PathBuf::from("/home/u/.local/share/izba")
        );
    }

    #[test]
    fn unix_root_fallback() {
        let env = |_: &str| None;
        assert_eq!(
            unix_default_root(&env),
            PathBuf::from("/root/.local/share/izba")
        );
    }

    #[test]
    fn windows_root_from_localappdata() {
        let env = |k: &str| (k == "LOCALAPPDATA").then(|| r"C:\Users\u\AppData\Local".to_string());
        assert_eq!(
            windows_default_root(&env),
            PathBuf::from(r"C:\Users\u\AppData\Local").join("izba")
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_700_hardens_path_and_created_ancestors() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("izba");
        let leaf = root.join("sandboxes").join("web").join("logs");

        create_dir_700(&leaf, &root).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // The leaf and every izba-owned ancestor up to (and including) the
        // data root must be 0700 — not world-traversable.
        assert_eq!(mode(&leaf), 0o700, "leaf");
        assert_eq!(mode(&root.join("sandboxes").join("web")), 0o700, "sandbox");
        assert_eq!(mode(&root.join("sandboxes")), 0o700, "sandboxes");
        assert_eq!(mode(&root), 0o700, "data root");
    }

    #[test]
    fn ssh_dirs_resolve_under_root() {
        let p = Paths::with_root(PathBuf::from("/data"));
        assert_eq!(p.ssh_dir(), PathBuf::from("/data/ssh"));
        assert_eq!(
            p.ssh_share_dir("foo"),
            PathBuf::from("/data/sandboxes/foo/ssh")
        );
    }

    #[test]
    fn windows_root_fallback_to_userprofile() {
        let env = |k: &str| (k == "USERPROFILE").then(|| r"C:\Users\u".to_string());
        assert_eq!(
            windows_default_root(&env),
            PathBuf::from(r"C:\Users\u")
                .join("AppData")
                .join("Local")
                .join("izba")
        );
    }
}
