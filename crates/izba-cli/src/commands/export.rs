//! `izba export` — write the managed truth back into izba.yml (the human then
//! commits the git diff). Inverse of promote; no review gate (the human runs it).

use anyhow::{Context, Result};
use izba_core::paths::Paths;

#[mutants::skip] // reason: reads managed truth from disk + writes izba.yml for a managed sandbox; orchestration exercised by daemon_e2e. The pure logic (sandbox_ref::resolve, ops::export, managed_normalized, to_manifest) is unit-tested separately.
pub fn run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32> {
    // #123: NAME-or-DIR positional. For the workspace form the name comes from
    // an existing izba.yml metadata.name (malformed YAML propagates — never
    // silently exporting under the wrong name) or the dir basename; for the
    // name form the workspace comes from config.json.
    let r = super::sandbox_ref::resolve(paths, target)?;
    super::sandbox_ref::check_name_override(&r, name_override)?;
    let dir = r
        .workspace
        .clone()
        .with_context(|| format!("sandbox '{}' has no recorded workspace directory", r.name))?;
    let name = match name_override {
        Some(n) => n.to_string(),
        None => r.name,
    };
    let path = izba_core::manifest::ops::export(paths, &dir, &name)?;
    println!("exported managed truth -> {}", path.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    /// A present-but-malformed izba.yml propagates a parse error (does NOT
    /// silently fall back to the default name, which would export the wrong
    /// sandbox).
    #[test]
    fn malformed_manifest_returns_err() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        // Write a syntactically broken YAML file.
        std::fs::write(dir.join("izba.yml"), b"{ invalid: yaml: [broken").unwrap();
        // load_repo_manifest is the function the name-resolution delegates to
        // when izba.yml exists.  It must return Err on a broken file.
        let result = izba_core::manifest::ops::load_repo_manifest(dir);
        assert!(
            result.is_err(),
            "a present-but-malformed izba.yml must propagate a parse error, got Ok"
        );
    }

    /// A missing izba.yml triggers no error; the caller falls back to the
    /// directory-basename default name.
    #[test]
    fn missing_manifest_no_error() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        // No izba.yml present — load_repo_manifest must return an error (file
        // not found).  The name-resolution code checks `dir.join("izba.yml").exists()`
        // BEFORE calling load_repo_manifest, so this branch is never reached and
        // the caller silently uses the default name.
        assert!(
            !dir.join("izba.yml").exists(),
            "sanity: izba.yml must not exist in the temp dir"
        );
        // Confirm that load_repo_manifest itself would error (so the exists()
        // guard is necessary and not dead code).
        let result = izba_core::manifest::ops::load_repo_manifest(dir);
        assert!(
            result.is_err(),
            "load_repo_manifest with no izba.yml must return Err (not found)"
        );
    }
}
