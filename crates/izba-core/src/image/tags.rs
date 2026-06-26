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

/// Prefix used by `izba run --build` for hidden one-shot local image tags.
/// These tags are pruned by [`prune_tags_with_prefix`] at the start of every
/// `run --build` invocation so the store does not grow unbounded.
pub const RUN_BUILD_TAG_PREFIX: &str = "izba-run-build-";

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
    if !matches!(first, 'a'..='z' | '0'..='9') {
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

/// Remove every tag whose name starts with `prefix` from the local tag store.
///
/// Loads the store, drops all matching entries, and atomically saves the result
/// (only writes when at least one entry was removed — a no-op on an absent or
/// already-clean store). Returns the number of entries removed.
///
/// Used by `izba run --build` to prune stale one-shot `izba-run-build-<ts>`
/// tags from prior invocations (see [`RUN_BUILD_TAG_PREFIX`]).
///
/// NOT safe against a *concurrent* `izba run --build` sharing the same `<data>`
/// dir: a parallel invocation's top-of-build prune may sweep this run's
/// freshly-registered hidden tag before the daemon's `ensure_image` resolves it
/// at Create, making that run miss the cache. Concurrent one-shot builds against
/// the same data dir are unsupported (and the load→modify→save here is itself
/// not atomic against concurrent writers).
pub fn prune_tags_with_prefix(paths: &Paths, prefix: &str) -> Result<usize> {
    let mut map = load_tags(paths)?;
    let before = map.len();
    map.retain(|k, _| !k.starts_with(prefix));
    let removed = before - map.len();
    if removed > 0 {
        save_tags(paths, &map)?;
    }
    Ok(removed)
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

    /// Mutant 57:18 (`> 128` → `>= 128`): the length boundary. Exactly 128 chars
    /// is the longest VALID tag; 129 chars is the first rejected length.
    #[test]
    fn validate_tag_length_boundary_128_ok_129_err() {
        let at_limit = "a".repeat(128);
        assert!(
            validate_tag(&at_limit).is_ok(),
            "128-char tag must be accepted (boundary)"
        );
        let over_limit = "a".repeat(129);
        assert!(
            validate_tag(&over_limit).is_err(),
            "129-char tag must be rejected"
        );
    }

    #[test]
    fn validate_tag_rejects_uppercase() {
        assert!(validate_tag("MyImg").is_err());
    }

    /// 1b: a leading uppercase char must be caught by the first-char check, not
    /// only by the per-char loop.  The error message must name the first-char
    /// constraint ("tag must start with [a-z0-9]"), not the per-char constraint.
    #[test]
    fn validate_tag_rejects_leading_uppercase() {
        let err = validate_tag("Abc").expect_err("'Abc' should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("tag must start with [a-z0-9]"),
            "expected first-char error for 'Abc', got: {msg}"
        );
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

    /// Mutant 23:19 (`e.kind() == NotFound` → `true`): a read error that is NOT
    /// NotFound (here, a DIRECTORY at the tags.json path → IsADirectory/other)
    /// must propagate as Err, never be swallowed into an empty map.
    #[test]
    fn load_tags_non_notfound_read_error_propagates() {
        let (_tmp, paths) = setup();
        let path = tags_path(&paths);
        fs::create_dir_all(&path).unwrap(); // tags.json is now a directory.
        let result = load_tags(&paths);
        assert!(
            result.is_err(),
            "a non-NotFound read error must propagate, not yield an empty map"
        );
    }

    #[test]
    fn set_tag_rejects_invalid_tag() {
        let (_tmp, paths) = setup();
        assert!(set_tag(&paths, "a:b", DIGEST).is_err());
        // Nothing written.
        assert!(resolve_tag(&paths, "a:b").unwrap().is_none());
    }

    // ── prune_tags_with_prefix ────────────────────────────────────────────────

    /// Pruning an absent store is a no-op: returns 0 and does not error.
    #[test]
    fn prune_tags_empty_store_is_noop() {
        let (_tmp, paths) = setup();
        let removed = prune_tags_with_prefix(&paths, "izba-run-build-").unwrap();
        assert_eq!(removed, 0, "no entries to prune");
        // tags.json must still be absent (no spurious write).
        assert!(
            !tags_path(&paths).exists(),
            "no file should have been created"
        );
    }

    /// Pruning removes only keys with the given prefix, leaves others intact,
    /// returns the correct count, and the persisted file reflects the removal.
    #[test]
    fn prune_tags_removes_matching_leaves_others() {
        let (_tmp, paths) = setup();
        let d2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let d3 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        // Two hidden run-build tags + one user tag.
        set_tag(&paths, "izba-run-build-111", DIGEST).unwrap();
        set_tag(&paths, "izba-run-build-222", d2).unwrap();
        set_tag(&paths, "myapp", d3).unwrap();

        let removed = prune_tags_with_prefix(&paths, "izba-run-build-").unwrap();
        assert_eq!(removed, 2, "both run-build tags should be pruned");

        // Hidden tags gone, user tag survives.
        assert!(resolve_tag(&paths, "izba-run-build-111").unwrap().is_none());
        assert!(resolve_tag(&paths, "izba-run-build-222").unwrap().is_none());
        assert_eq!(
            resolve_tag(&paths, "myapp").unwrap(),
            Some(d3.to_string()),
            "unrelated tag must survive pruning"
        );

        // Persisted file must reflect the removal.
        let on_disk = load_tags(&paths).unwrap();
        assert_eq!(on_disk.len(), 1);
        assert!(on_disk.contains_key("myapp"));
    }

    /// Pruning with a prefix that matches nothing is a no-op (returns 0).
    #[test]
    fn prune_tags_no_match_returns_zero() {
        let (_tmp, paths) = setup();
        set_tag(&paths, "myapp", DIGEST).unwrap();
        let removed = prune_tags_with_prefix(&paths, "izba-run-build-").unwrap();
        assert_eq!(removed, 0);
        // "myapp" still present.
        assert_eq!(
            resolve_tag(&paths, "myapp").unwrap(),
            Some(DIGEST.to_string())
        );
    }
}
