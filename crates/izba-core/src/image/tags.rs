//! Local image tag store: a flat `BTreeMap<String, String>` (tag → "sha256:…")
//! persisted as JSON at `<data>/images/tags.json`.
//!
//! Reads are load-or-empty (missing file → empty map, NOT an error). Writes are
//! atomic: a tempfile in the same directory is renamed into place so concurrent
//! readers never observe a torn file.

use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;

/// Path of the local tag store for the given `paths`.
fn tags_path(paths: &Paths) -> std::path::PathBuf {
    paths.images_dir().join("tags.json")
}

/// Load the tag map from disk, or return an empty map if the file is absent.
fn load_tags(paths: &Paths) -> Result<BTreeMap<String, String>> {
    let path = tags_path(paths);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse tag store at {}", path.display()))
}

/// Atomically write `map` to the tag store. Creates `<data>/images/` if needed.
fn save_tags(paths: &Paths, map: &BTreeMap<String, String>) -> Result<()> {
    let images_dir = paths.images_dir();
    fs::create_dir_all(&images_dir)
        .with_context(|| format!("failed to create {}", images_dir.display()))?;
    let json = serde_json::to_vec_pretty(map).context("failed to serialise tag store")?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".tags-")
        .tempfile_in(&images_dir)
        .with_context(|| format!("failed to create temp file in {}", images_dir.display()))?;
    std::io::Write::write_all(&mut tmp, &json).context("failed to write staged tags")?;
    tmp.persist(tags_path(paths))
        .context("failed to atomically publish tags.json")?;
    Ok(())
}

/// Validate a user-supplied tag name.
///
/// Accepted grammar: `[a-z0-9][a-z0-9._-]*`, max 128 characters.
/// Rejected: empty string, leading `-` or `.`, any `:` or `/` (would collide
/// with registry refs or `oci-archive:` scheme prefixes).
pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        bail!("tag must not be empty");
    }
    if tag.len() > 128 {
        bail!("tag is too long ({} chars, max 128)", tag.len());
    }
    if tag.contains(':') {
        bail!("tag must not contain ':' (would collide with registry refs)");
    }
    if tag.contains('/') {
        bail!("tag must not contain '/' (would collide with registry refs)");
    }
    let first = tag.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        bail!("tag must start with [a-z0-9], got '{first}'");
    }
    for ch in tag.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '.' | '_' | '-') {
            bail!("tag contains invalid character '{ch}'; allowed: [a-z0-9._-]");
        }
    }
    Ok(())
}

/// Associate `tag` with `digest` in the local tag store.
///
/// Validates the tag first (see [`validate_tag`]). If the tag already exists
/// it is overwritten. The write is atomic: a temp file in `<data>/images/` is
/// renamed into place.
pub fn set_tag(paths: &Paths, tag: &str, digest: &str) -> Result<()> {
    validate_tag(tag)?;
    let mut map = load_tags(paths)?;
    map.insert(tag.to_string(), digest.to_string());
    save_tags(paths, &map)
}

/// Look up `tag` in the local tag store.
///
/// Returns `Ok(Some(digest))` when found, `Ok(None)` when the tag is unknown
/// (including when `tags.json` does not yet exist).
pub fn resolve_tag(paths: &Paths, tag: &str) -> Result<Option<String>> {
    let map = load_tags(paths)?;
    Ok(map.get(tag).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Paths) {
        let tmp = TempDir::new().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        (tmp, paths)
    }

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ── validate_tag ──────────────────────────────────────────────────────────

    #[test]
    fn validate_tag_accepts_simple_names() {
        assert!(validate_tag("myimg").is_ok());
        assert!(validate_tag("my-img_1.2").is_ok());
        assert!(validate_tag("abc123").is_ok());
        assert!(validate_tag("a").is_ok());
    }

    #[test]
    fn validate_tag_rejects_empty() {
        assert!(validate_tag("").is_err());
    }

    #[test]
    fn validate_tag_rejects_colon() {
        assert!(validate_tag("a:b").is_err());
    }

    #[test]
    fn validate_tag_rejects_slash() {
        assert!(validate_tag("a/b").is_err());
    }

    #[test]
    fn validate_tag_rejects_leading_dash() {
        assert!(validate_tag("-x").is_err());
    }

    #[test]
    fn validate_tag_rejects_leading_dot() {
        assert!(validate_tag(".x").is_err());
    }

    #[test]
    fn validate_tag_rejects_too_long() {
        let long = "a".repeat(200);
        assert!(validate_tag(&long).is_err());
    }

    #[test]
    fn validate_tag_rejects_uppercase() {
        assert!(validate_tag("MyImg").is_err());
    }

    // ── resolve_tag (missing file) ────────────────────────────────────────────

    #[test]
    fn resolve_tag_no_file_returns_none() {
        let (_tmp, paths) = setup();
        let result = resolve_tag(&paths, "nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_tag_unknown_tag_returns_none() {
        let (_tmp, paths) = setup();
        set_tag(&paths, "other", DIGEST).unwrap();
        let result = resolve_tag(&paths, "unknown").unwrap();
        assert!(result.is_none());
    }

    // ── set_tag / resolve_tag round-trip ──────────────────────────────────────

    #[test]
    fn set_then_resolve_round_trips() {
        let (_tmp, paths) = setup();
        set_tag(&paths, "myimg", DIGEST).unwrap();
        let got = resolve_tag(&paths, "myimg").unwrap();
        assert_eq!(got, Some(DIGEST.to_string()));
    }

    #[test]
    fn set_tag_overwrites_existing() {
        let (_tmp, paths) = setup();
        let digest2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        set_tag(&paths, "myimg", DIGEST).unwrap();
        set_tag(&paths, "myimg", digest2).unwrap();
        let got = resolve_tag(&paths, "myimg").unwrap();
        assert_eq!(got, Some(digest2.to_string()));
    }

    #[test]
    fn multiple_tags_coexist() {
        let (_tmp, paths) = setup();
        let d2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        set_tag(&paths, "imgone", DIGEST).unwrap();
        set_tag(&paths, "imgtwo", d2).unwrap();
        assert_eq!(
            resolve_tag(&paths, "imgone").unwrap(),
            Some(DIGEST.to_string())
        );
        assert_eq!(resolve_tag(&paths, "imgtwo").unwrap(), Some(d2.to_string()));
    }

    #[test]
    fn set_tag_rejects_invalid_tag() {
        let (_tmp, paths) = setup();
        assert!(set_tag(&paths, "a:b", DIGEST).is_err());
        // Nothing written.
        assert!(resolve_tag(&paths, "a:b").unwrap().is_none());
    }
}
