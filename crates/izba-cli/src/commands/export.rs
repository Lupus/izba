//! `izba export` — write the managed truth back into izba.yml (the human then
//! commits the git diff). Inverse of promote; no review gate (the human runs it).

use std::path::Path;

use anyhow::Result;
use izba_core::paths::Paths;

pub fn run(paths: &Paths, dir: &Path, name_override: Option<&str>) -> Result<i32> {
    let default_name = super::workspace_default_name(dir)?;
    // Prefer an explicit name; else the existing manifest's name; else the dir.
    let name = match name_override {
        Some(n) => n.to_string(),
        None => match super::load_repo_manifest(dir) {
            Ok((m, _, _)) => m.metadata.name.unwrap_or(default_name),
            Err(_) => default_name,
        },
    };
    let path = izba_core::manifest::ops::export(paths, dir, &name)?;
    println!("exported managed truth -> {}", path.display());
    Ok(0)
}
