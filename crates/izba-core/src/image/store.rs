//! Content-addressed on-disk image cache: `<images_dir>/<sanitized digest>/`.

use crate::paths::Paths;
use anyhow::{Context, Result};
use oci_client::config::ConfigFile;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ImageStore<'a> {
    paths: &'a Paths,
}

impl<'a> ImageStore<'a> {
    pub fn new(paths: &'a Paths) -> Self {
        Self { paths }
    }

    /// Path of the cached erofs rootfs for `digest`.
    pub fn rootfs_path(&self, digest: &str) -> PathBuf {
        self.paths.image_dir(digest).join("rootfs.erofs")
    }

    /// Path of the file recording which image ref produced this digest.
    pub fn ref_path(&self, digest: &str) -> PathBuf {
        self.paths.image_dir(digest).join("ref.txt")
    }

    /// Path of the cached OCI image runtime config (`config.json`) for
    /// `digest`. Holds the registry's image config blob verbatim — the source
    /// of `Entrypoint/Cmd/Env/WorkingDir/User` for crun `config.json` generation.
    pub fn config_path(&self, digest: &str) -> PathBuf {
        self.paths.image_dir(digest).join("config.json")
    }

    /// Load and parse the cached OCI runtime config for `digest`.
    ///
    /// Returns `Ok(None)` when no `config.json` is present — images cached by a
    /// pre-crun izba did not persist the config blob, so callers self-heal that
    /// case (re-persisting the config they fetched alongside the manifest).
    pub fn load_config(&self, digest: &str) -> Result<Option<ConfigFile>> {
        let path = self.config_path(digest);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
        };
        let config = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(Some(config))
    }

    /// Atomically write `json` as the cached `config.json` for an
    /// already-published `digest`. Used to self-heal images cached by a
    /// pre-crun izba: a temp file in the same dir is renamed into place, so a
    /// concurrent reader never observes a torn config (and a re-run is a
    /// harmless idempotent overwrite). The image dir must already exist.
    pub fn persist_config(&self, digest: &str, json: &[u8]) -> Result<()> {
        let dir = self.paths.image_dir(digest);
        let mut tmp = tempfile::Builder::new()
            .prefix(".config-")
            .tempfile_in(&dir)
            .with_context(|| format!("failed to stage config in {}", dir.display()))?;
        std::io::Write::write_all(&mut tmp, json).context("failed to write staged config")?;
        tmp.persist(self.config_path(digest))
            .context("failed to publish config.json")?;
        Ok(())
    }

    /// An image is cached iff its `rootfs.erofs` exists.
    pub fn is_cached(&self, digest: &str) -> bool {
        self.rootfs_path(digest).is_file()
    }

    /// Atomically publish an image dir: `build` runs against a staging
    /// directory on the same filesystem, which is renamed into place on
    /// success. On error nothing is published and staging is removed.
    /// If the digest is already cached, `build` is not invoked.
    pub fn publish(&self, digest: &str, build: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
        if self.is_cached(digest) {
            return Ok(());
        }
        let images_dir = self.paths.images_dir();
        fs::create_dir_all(&images_dir)
            .with_context(|| format!("failed to create {}", images_dir.display()))?;
        // Staging inside images_dir keeps it on the same filesystem so the
        // final rename is atomic. Dropping `staging` on error removes it.
        let staging = tempfile::Builder::new()
            .prefix(".staging-")
            .tempdir_in(&images_dir)
            .context("failed to create staging dir")?;
        build(staging.path())?;
        let final_dir = self.paths.image_dir(digest);
        let staging_path = staging.keep();
        if let Err(err) = fs::rename(&staging_path, &final_dir) {
            // Best-effort cleanup; a leaked staging dir is harmless debris.
            let _ = fs::remove_dir_all(&staging_path);
            // A concurrent builder may have published first; that is fine.
            if !final_dir.is_dir() {
                return Err(err).with_context(|| {
                    format!("failed to publish image dir {}", final_dir.display())
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const DIGEST: &str = "sha256:abc123";

    fn setup() -> (TempDir, Paths) {
        let tmp = TempDir::new().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        (tmp, paths)
    }

    fn entries(dir: &Path) -> Vec<String> {
        if !dir.exists() {
            return Vec::new();
        }
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn store_paths() {
        let paths = Paths::with_root("/data/izba".into());
        let store = ImageStore::new(&paths);
        assert_eq!(
            store.rootfs_path("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc/rootfs.erofs")
        );
        assert_eq!(
            store.ref_path("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc/ref.txt")
        );
        assert_eq!(
            store.config_path("sha256:abc"),
            PathBuf::from("/data/izba/images/sha256-abc/config.json")
        );
    }

    /// A minimal-but-valid OCI image config JSON carrying the runtime fields
    /// crun fidelity cares about (Entrypoint/Env/WorkingDir).
    const CONFIG_JSON: &str = r#"{
        "architecture": "amd64",
        "os": "linux",
        "rootfs": { "type": "layers", "diff_ids": [] },
        "config": {
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", "echo hi"],
            "Env": ["PATH=/usr/bin"],
            "WorkingDir": "/work"
        }
    }"#;

    #[test]
    fn load_config_parses_stored_config() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                fs::write(staging.join("config.json"), CONFIG_JSON)?;
                Ok(())
            })
            .unwrap();

        let cfg = store
            .load_config(DIGEST)
            .unwrap()
            .expect("config.json should be present");
        let inner = cfg.config.expect("config section present");
        assert_eq!(inner.entrypoint, Some(vec!["/bin/sh".to_string()]));
        assert_eq!(
            inner.cmd,
            Some(vec!["-c".to_string(), "echo hi".to_string()])
        );
        assert_eq!(inner.working_dir, Some("/work".to_string()));
        assert_eq!(inner.env, Some(vec!["PATH=/usr/bin".to_string()]));
    }

    #[test]
    fn load_config_is_none_for_pre_crun_cache() {
        // An image cached by a pre-crun izba: rootfs.erofs exists, no config.json.
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        assert!(store.load_config(DIGEST).unwrap().is_none());
    }

    #[test]
    fn persist_config_self_heals_pre_crun_cache() {
        // A pre-crun cached image gains a config.json without a re-pull.
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        assert!(store.load_config(DIGEST).unwrap().is_none());

        store
            .persist_config(DIGEST, CONFIG_JSON.as_bytes())
            .unwrap();

        let cfg = store
            .load_config(DIGEST)
            .unwrap()
            .expect("config persisted");
        assert_eq!(cfg.config.unwrap().working_dir, Some("/work".to_string()));
    }

    #[test]
    fn load_config_errors_on_corrupt_json() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                fs::write(staging.join("config.json"), b"{ not json")?;
                Ok(())
            })
            .unwrap();
        assert!(store.load_config(DIGEST).is_err());
    }

    #[test]
    fn load_config_propagates_non_notfound_read_errors() {
        // A read error that is NOT NotFound must surface as Err — only an
        // absent config.json is the self-heal `Ok(None)` case. Make config.json
        // a *directory* so `fs::read` fails with EISDIR (kind != NotFound).
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs")?;
                Ok(())
            })
            .unwrap();
        fs::create_dir(store.config_path(DIGEST)).unwrap();
        assert!(
            store.load_config(DIGEST).is_err(),
            "a non-NotFound read error must propagate as Err, not Ok(None)"
        );
    }

    #[test]
    fn atomic_publish() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        assert!(!store.is_cached(DIGEST));

        // Closure error: nothing published, no staging debris.
        let res = store.publish(DIGEST, |staging| {
            fs::write(staging.join("rootfs.erofs"), b"partial")?;
            anyhow::bail!("build exploded")
        });
        assert!(res.is_err());
        assert!(!store.is_cached(DIGEST));
        assert!(
            entries(&paths.images_dir()).is_empty(),
            "staging debris left behind: {:?}",
            entries(&paths.images_dir())
        );

        // Success: file ends up at the final path.
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"erofs bytes")?;
                Ok(())
            })
            .unwrap();
        assert!(store.is_cached(DIGEST));
        assert_eq!(fs::read(store.rootfs_path(DIGEST)).unwrap(), b"erofs bytes");
        assert_eq!(entries(&paths.images_dir()), vec!["sha256-abc123"]);
    }

    #[test]
    fn publish_skips_when_cached() {
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);
        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"v1")?;
                Ok(())
            })
            .unwrap();

        let mut called = false;
        store
            .publish(DIGEST, |_staging| {
                called = true;
                Ok(())
            })
            .unwrap();
        assert!(!called, "build closure ran despite cache hit");
        assert_eq!(fs::read(store.rootfs_path(DIGEST)).unwrap(), b"v1");
    }

    #[test]
    fn publish_tolerates_existing_target() {
        // Models only the losing side of a publish race: the pre-existing dir
        // here holds a marker file, not a real rootfs.erofs, so this verifies
        // staging cleanup — a real winner would have left is_cached() == true.
        let (_tmp, paths) = setup();
        let store = ImageStore::new(&paths);

        // Simulate a concurrent builder winning the race: the final dir
        // appears (non-empty, so rename will fail) while we build. It is
        // pre-created here since publish checks the cache only up front.
        let final_dir = paths.image_dir(DIGEST);
        fs::create_dir_all(&final_dir).unwrap();
        fs::write(final_dir.join("winner.txt"), b"first").unwrap();

        store
            .publish(DIGEST, |staging| {
                fs::write(staging.join("rootfs.erofs"), b"loser")?;
                Ok(())
            })
            .unwrap();

        // Winner's content untouched, loser's staging cleaned up.
        assert_eq!(fs::read(final_dir.join("winner.txt")).unwrap(), b"first");
        assert_eq!(entries(&paths.images_dir()), vec!["sha256-abc123"]);
        assert!(!final_dir.join("rootfs.erofs").exists());
    }
}
