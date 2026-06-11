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
    fn env_override() {
        let p = Paths::from_env_or_default(Some("/tmp/x".into()));
        assert_eq!(p.root(), Path::new("/tmp/x"));
    }

    #[test]
    fn default_is_under_home() {
        let p = Paths::from_env_or_default(None);
        assert!(p.root().ends_with(".local/share/izba"), "{:?}", p.root());
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
