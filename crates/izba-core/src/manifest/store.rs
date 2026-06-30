//! Host-only manifest reconciliation state, stored under the sandbox dir
//! (NEVER inside the workspace/overlay): the last-reconciled base manifest and
//! the review token gating `promote`. The in-guest agent cannot read or forge
//! these.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::manifest::schema::Manifest;

pub const MANIFEST_BASE_FILE: &str = "manifest.base.yaml";
pub const MANIFEST_REVIEW_FILE: &str = "manifest.review";

/// A review token binds the human's review to the exact bytes reviewed: the
/// manifest plus any referenced Dockerfile (also agent-writable). A 0x1f unit
/// separator keeps `("ab", "c")` distinct from `("a", "bc")`.
pub fn review_token(manifest_yaml: &str, dockerfile: Option<&str>) -> String {
    let mut h = Sha256::new();
    h.update(manifest_yaml.as_bytes());
    h.update([0x1f]);
    if let Some(df) = dockerfile {
        h.update(df.as_bytes());
    }
    hex::encode(h.finalize())
}

fn base_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_BASE_FILE)
}
fn review_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_REVIEW_FILE)
}

pub fn write_base(dir: &Path, m: &Manifest) -> Result<()> {
    let p = base_path(dir);
    std::fs::write(&p, m.to_yaml()).with_context(|| format!("writing {}", p.display()))
}

pub fn read_base(dir: &Path) -> Result<Option<Manifest>> {
    match std::fs::read_to_string(base_path(dir)) {
        Ok(s) => Ok(Some(Manifest::load_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading manifest.base.yaml"),
    }
}

pub fn write_review(dir: &Path, token: &str) -> Result<()> {
    let p = review_path(dir);
    std::fs::write(&p, token).with_context(|| format!("writing {}", p.display()))
}

pub fn read_review(dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(review_path(dir)) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading manifest.review"),
    }
}

pub fn clear_review(dir: &Path) -> Result<()> {
    match std::fs::remove_file(review_path(dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing manifest.review"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::Manifest;

    const M: &str = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n  resources: { cpus: 1, memory: 1Gi }\n  rootDisk: { size: 1Gi }\n";

    #[test]
    fn token_is_stable_and_input_sensitive() {
        let a = review_token("manifest-bytes", None);
        assert_eq!(a, review_token("manifest-bytes", None), "stable");
        assert_ne!(
            a,
            review_token("manifest-bytes2", None),
            "manifest change moves it"
        );
        assert_ne!(
            a,
            review_token("manifest-bytes", Some("FROM x")),
            "dockerfile change moves it"
        );
        assert_ne!(
            review_token("ab", Some("c")),
            review_token("a", Some("bc")),
            "separator prevents boundary collisions"
        );
    }

    #[test]
    fn base_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_base(dir.path()).unwrap().is_none());
        let m = Manifest::load_str(M).unwrap();
        write_base(dir.path(), &m).unwrap();
        let back = read_base(dir.path()).unwrap().unwrap();
        assert_eq!(back.spec.resources.cpus, 1);
    }

    /// read_base must SWALLOW only NotFound (returning Ok(None)) and PROPAGATE
    /// any other I/O error. A directory at the base path makes read_to_string
    /// fail with a non-NotFound error. Pins the `e.kind() == NotFound` guard.
    #[test]
    fn read_base_propagates_non_notfound_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(MANIFEST_BASE_FILE)).unwrap();
        assert!(
            read_base(dir.path()).is_err(),
            "a non-NotFound read error must propagate, not become Ok(None)"
        );
    }

    /// Same NotFound-only guard for read_review.
    #[test]
    fn read_review_propagates_non_notfound_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(MANIFEST_REVIEW_FILE)).unwrap();
        assert!(
            read_review(dir.path()).is_err(),
            "a non-NotFound read error must propagate, not become Ok(None)"
        );
    }

    /// clear_review is idempotent on a missing token (NotFound -> Ok) but must
    /// PROPAGATE a non-NotFound removal error. Pins both halves of the guard
    /// (`e.kind() == NotFound`).
    #[test]
    fn clear_review_idempotent_but_propagates_non_notfound_error() {
        let dir = tempfile::tempdir().unwrap();
        // Absent token: NotFound -> Ok(()).
        assert!(
            clear_review(dir.path()).is_ok(),
            "clearing an absent review token must be Ok (idempotent)"
        );
        // A directory at the review path makes remove_file fail non-NotFound.
        std::fs::create_dir(dir.path().join(MANIFEST_REVIEW_FILE)).unwrap();
        assert!(
            clear_review(dir.path()).is_err(),
            "a non-NotFound removal error must propagate"
        );
    }

    #[test]
    fn review_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_review(dir.path()).unwrap().is_none());
        write_review(dir.path(), "deadbeef").unwrap();
        assert_eq!(
            read_review(dir.path()).unwrap().as_deref(),
            Some("deadbeef")
        );
        clear_review(dir.path()).unwrap();
        assert!(read_review(dir.path()).unwrap().is_none());
    }
}
