//! Bundle manifest schema and archive-entry path validation. The archive is
//! untrusted input on load: every entry path is checked here before it is
//! ever joined onto a host directory.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::FORMAT_VERSION;

pub const MANIFEST_PATH: &str = "manifest.json";
pub const CHECKSUMS_PATH: &str = "checksums.json";

/// Host OS the archive was saved on (drives cross-OS load warnings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceOs {
    Linux,
    Windows,
    Other,
}

impl SourceOs {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub izba_version: String,
    pub source_os: SourceOs,
    pub created_unix_ms: u64,
    /// image tag -> digest
    pub tags: BTreeMap<String, String>,
    /// digests included in the archive
    pub images: Vec<String>,
    /// `path` = `volumes/<name>.img`
    pub named_volumes: Vec<BlobInfo>,
    pub sandboxes: Vec<SandboxEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEntry {
    pub name: String,
    pub disk_owner: (u32, u32),
    pub workspace_bundled: bool,
    /// Lossless display of the source path.
    pub source_workspace: String,
    pub source_home: Option<String>,
    /// `rw.img` + anonymous volumes.
    pub disks: Vec<BlobInfo>,
    /// Sum of regular-file sizes (load preflight).
    pub workspace_bytes: u64,
    /// Source had `lockdown.json` (=> "re-run izba lockdown" on load).
    #[serde(default)]
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobInfo {
    pub path: String,
    pub logical_len: u64,
    pub allocated: u64,
}

/// archive path -> hex sha256 / content digest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checksums {
    pub files: BTreeMap<String, String>,
}

/// Refuse an archive written by a newer (or nonsensical) format.
pub fn check_format(m: &Manifest) -> Result<()> {
    if m.format == 0 {
        bail!("archive format 0 is invalid");
    }
    if m.format > FORMAT_VERSION {
        bail!(
            "archive format {} is newer than this izba supports ({FORMAT_VERSION}); \
             upgrade izba on this host (newer izba required)",
            m.format
        );
    }
    Ok(())
}

/// Validate an archive entry path: relative, `/`-separated, normalized, and
/// rooted at a known top-level name. No `\`, no drive colon, no empty/`.`/`..`
/// components.
pub fn validate_entry_path(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("empty archive entry path");
    }
    if p.contains('\\') || p.starts_with('/') {
        bail!("unsafe archive entry path {p:?}");
    }
    let mut comps = p.split('/');
    let first = comps.next().unwrap_or("");
    if first.contains(':') {
        bail!("unsafe archive entry path {p:?}");
    }
    let mut n = 1;
    for c in p.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            bail!("unsafe archive entry path {p:?}");
        }
    }
    n += comps.count();
    match first {
        "manifest.json" | "checksums.json" if n == 1 => Ok(()),
        "images" | "volumes" | "sandboxes" | "workspaces" if n > 1 => Ok(()),
        _ => bail!("unexpected archive entry path {p:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_format_is_refused_with_upgrade_hint() {
        let mut m = sample();
        m.format = FORMAT_VERSION + 1;
        let e = check_format(&m).unwrap_err().to_string();
        assert!(e.contains("newer izba"), "{e}");
        m.format = FORMAT_VERSION;
        check_format(&m).unwrap();
        m.format = 0;
        assert!(check_format(&m).is_err());
    }

    #[test]
    fn entry_paths_must_be_relative_normalized_and_known() {
        for ok in [
            "manifest.json",
            "checksums.json",
            "images/sha256-ab/rootfs.erofs",
            "volumes/data.img.d/0000000000000000",
            "sandboxes/a/config.json",
            "workspaces/a/src/main.rs",
            "workspaces/a/.git/HEAD",
        ] {
            validate_entry_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "/etc/passwd",
            "../x",
            "sandboxes/../../x",
            "sandboxes/a/./b",
            "",
            "other/x",
            "sandboxes//a",
            "C:/x",
            "sandboxes\\a",
            "workspaces/a/../../b",
            "manifest.json/x",
            "images",
        ] {
            assert!(validate_entry_path(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample();
        let back: Manifest = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(back.sandboxes[0].name, "a");
        assert_eq!(back.source_os, SourceOs::Linux);
    }

    fn sample() -> Manifest {
        Manifest {
            format: FORMAT_VERSION,
            izba_version: "t".into(),
            source_os: SourceOs::Linux,
            created_unix_ms: 1,
            tags: Default::default(),
            images: vec!["sha256:ab".into()],
            named_volumes: vec![],
            sandboxes: vec![SandboxEntry {
                name: "a".into(),
                disk_owner: (1000, 1000),
                workspace_bundled: false,
                source_workspace: "/home/u/p".into(),
                source_home: Some("/home/u".into()),
                disks: vec![],
                workspace_bytes: 0,
                locked: false,
            }],
        }
    }
}
