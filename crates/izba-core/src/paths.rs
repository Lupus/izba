use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// `override_root` wins; otherwise defaults to `$HOME/.local/share/izba`.
    pub fn from_env_or_default(override_root: Option<PathBuf>) -> Self {
        if let Some(root) = override_root {
            return Self::with_root(root);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        Self::with_root(PathBuf::from(home).join(".local/share/izba"))
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
}
