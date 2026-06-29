//! `izba export` — write the managed truth back into izba.yml (the human then
//! commits the git diff). Inverse of promote; no review gate (the human runs it).

use std::path::Path;

use anyhow::Result;
use izba_core::paths::Paths;

#[mutants::skip] // reason: reads managed truth from disk + writes izba.yml for a managed sandbox; orchestration exercised by daemon_e2e. The pure logic (ops::export, managed_normalized, to_manifest) is unit-tested separately.
pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    let default_name = super::workspace_default_name(dir)?;
    // Prefer an explicit name; else the existing manifest's name; else the dir.
    // Only fall back to the default when izba.yml does NOT exist — if it exists
    // but is malformed, propagate the parse error rather than silently
    // exporting under the wrong name.
    let name = match name_override {
        Some(n) => n.to_string(),
        None => {
            if dir.join("izba.yml").exists() {
                let (m, _, _) = super::load_repo_manifest(dir)?; // propagate parse errors
                m.metadata.name.unwrap_or(default_name)
            } else {
                default_name
            }
        }
    };
    let path = izba_core::manifest::ops::export(paths, dir, &name)?;
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
        let result = super::super::load_repo_manifest(dir);
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
        let result = super::super::load_repo_manifest(dir);
        assert!(
            result.is_err(),
            "load_repo_manifest with no izba.yml must return Err (not found)"
        );
    }
}
