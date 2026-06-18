//! User-declared block-device volumes: parsing, validation, and the cmdline
//! encoding that binds each volume to its `/dev/vd{c…}` slot by ORDER.
//!
//! A volume becomes an extra virtio-blk disk appended after rw.img, so the
//! Nth declared volume is the Nth extra disk (vdc, vdd, …). The guest mount
//! plan keys off declaration order via the `izba.volumes` kernel cmdline list.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;

/// Max user volumes per sandbox: 26 virtio-blk slots minus vda (erofs) and
/// vdb (rw). OpenVMM's `disk_port` asserts `< 26`; we validate the friendly
/// limit at the host boundary so a clear error replaces a driver panic.
pub const MAX_VOLUMES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    /// `Some` ⇒ persistent (<data>/volumes/<name>.img, survives rm);
    /// `None` ⇒ ephemeral (<sandbox>/volumes/<eph_id>.img, reaped with rm).
    pub name: Option<String>,
    /// Absolute guest mountpoint. No commas (the cmdline list delimiter).
    pub guest_path: PathBuf,
    /// Provisioned (sparse) size in bytes.
    pub size_bytes: u64,
    /// Stable backing id for an ephemeral image (`<sandbox>/volumes/<id>.img`),
    /// assigned once at provision time and never recomputed from list position.
    /// `None` for persistent volumes (name-keyed) and for a freshly parsed spec
    /// (the backend assigns it at create/attach).
    #[serde(default)]
    pub eph_id: Option<u64>,
}

impl VolumeSpec {
    pub fn is_persistent(&self) -> bool {
        self.name.is_some()
    }

    /// Host path of this volume's backing image.
    /// Ephemeral volumes use their stable `eph_id`; persistent volumes use their name.
    pub fn image_path(&self, paths: &Paths, sandbox: &str) -> PathBuf {
        match &self.name {
            Some(name) => paths.volume_image(name),
            None => {
                let id = self
                    .eph_id
                    .expect("ephemeral volume has no eph_id; assign at provision time");
                paths
                    .sandbox_dir(sandbox)
                    .join("volumes")
                    .join(format!("{id}.img"))
            }
        }
    }
}

/// Assign stable ids to ephemeral volumes lacking one: existing ids are kept,
/// new ones continue from `max+1` (or 0). Persistent volumes are untouched.
pub fn assign_eph_ids(volumes: &mut [VolumeSpec]) {
    let mut next = volumes
        .iter()
        .filter_map(|v| v.eph_id)
        .max()
        .map_or(0, |m| m + 1);
    for v in volumes.iter_mut() {
        if v.name.is_none() && v.eph_id.is_none() {
            v.eph_id = Some(next);
            next += 1;
        }
    }
}

/// Outcome of a prune: the volume names removed and the bytes reclaimed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pruned {
    pub removed: Vec<String>,
    pub reclaimed_bytes: u64,
}

/// Snapshot of a single persistent volume image: declared size, on-disk
/// allocation, and which sandbox configs reference it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub name: String,
    /// Provisioned (sparse) size in bytes — the file length.
    pub size_bytes: u64,
    /// Actual disk allocation in bytes (blocks × 512 on Unix, file length elsewhere).
    pub actual_bytes: u64,
    /// Sandbox names whose config declares this volume (sorted).
    pub referenced_by: Vec<String>,
}

fn valid_name(s: &str) -> bool {
    match s.chars().next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// `<g|m>`-suffixed size → bytes. Only gibi/mebi to keep the grammar tight.
pub fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('g') | Some('G') => (&s[..s.len() - 1], 1u64 << 30),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        _ => bail!("size {s:?} must end in 'g' or 'm'"),
    };
    let n: u64 = num.parse().with_context(|| format!("bad size {s:?}"))?;
    if n == 0 {
        bail!("size must be > 0");
    }
    Ok(n * mult)
}

/// Parse `[NAME:]GUEST_PATH:SIZE`. NAME present ⇒ persistent.
pub fn parse_volume_flag(s: &str) -> anyhow::Result<VolumeSpec> {
    let parts: Vec<&str> = s.split(':').collect();
    let (name, path, size) = match parts.as_slice() {
        [path, size] => (None, *path, *size),
        [name, path, size] => (Some(name.to_string()), *path, *size),
        _ => bail!("volume {s:?} must be [NAME:]GUEST_PATH:SIZE"),
    };
    if let Some(n) = &name {
        if !valid_name(n) {
            bail!("volume name {n:?} must match [a-z0-9][a-z0-9_-]*");
        }
    }
    if !path.starts_with('/') {
        bail!("volume guest path {path:?} must be absolute");
    }
    if path.contains(',') {
        bail!("volume guest path {path:?} must not contain a comma");
    }
    Ok(VolumeSpec {
        name,
        guest_path: PathBuf::from(path),
        size_bytes: parse_size(size)?,
        eph_id: None,
    })
}

/// Whole-list invariants: count ceiling, unique guest paths, unique names.
pub fn validate_volumes(volumes: &[VolumeSpec]) -> anyhow::Result<()> {
    if volumes.len() > MAX_VOLUMES {
        bail!(
            "at most {MAX_VOLUMES} volumes per sandbox (got {})",
            volumes.len()
        );
    }
    let mut paths = HashSet::new();
    let mut names = HashSet::new();
    for v in volumes {
        if !paths.insert(&v.guest_path) {
            bail!("duplicate volume guest path {}", v.guest_path.display());
        }
        if let Some(n) = &v.name {
            if !names.insert(n) {
                bail!("duplicate volume name {n:?}");
            }
        }
    }
    Ok(())
}

/// Ordered, comma-joined guest paths for the `izba.volumes=` cmdline key.
pub fn cmdline_value(volumes: &[VolumeSpec]) -> String {
    volumes
        .iter()
        .map(|v| v.guest_path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(",")
}

/// Volume names present on disk but not referenced by any sandbox config.
pub fn unreferenced_volumes(on_disk: &[String], referenced: &HashSet<String>) -> Vec<String> {
    on_disk
        .iter()
        .filter(|n| !referenced.contains(*n))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_anonymous_ephemeral() {
        let v = parse_volume_flag("/var/lib/docker:2g").unwrap();
        assert_eq!(v.name, None);
        assert_eq!(v.guest_path, PathBuf::from("/var/lib/docker"));
        assert_eq!(v.size_bytes, 2 * 1024 * 1024 * 1024);
        assert!(!v.is_persistent());
    }

    #[test]
    fn parses_named_persistent() {
        let v = parse_volume_flag("cache:/data:512m").unwrap();
        assert_eq!(v.name.as_deref(), Some("cache"));
        assert_eq!(v.guest_path, PathBuf::from("/data"));
        assert_eq!(v.size_bytes, 512 * 1024 * 1024);
        assert!(v.is_persistent());
    }

    #[test]
    fn rejects_relative_path() {
        assert!(parse_volume_flag("rel/path:1g").is_err());
    }

    #[test]
    fn rejects_bad_name() {
        assert!(parse_volume_flag("Bad_NAME:/d:1g").is_err()); // uppercase
        assert!(parse_volume_flag("-bad:/d:1g").is_err()); // leading dash
    }

    #[test]
    fn rejects_comma_in_path() {
        assert!(parse_volume_flag("/a,b:1g").is_err());
    }

    #[test]
    fn rejects_zero_size() {
        assert!(parse_volume_flag("/d:0").is_err());
    }

    #[test]
    fn size_suffixes() {
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("10m").unwrap(), 10 * (1 << 20));
        assert_eq!(parse_size("2G").unwrap(), 2 << 30);
        assert!(parse_size("").is_err());
        assert!(parse_size("5k").is_err()); // only g/m
    }

    #[test]
    fn validate_rejects_dup_guest_path() {
        let vs = vec![
            parse_volume_flag("/d:1g").unwrap(),
            parse_volume_flag("x:/d:1g").unwrap(),
        ];
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_rejects_dup_name() {
        let vs = vec![
            parse_volume_flag("c:/a:1g").unwrap(),
            parse_volume_flag("c:/b:1g").unwrap(),
        ];
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_rejects_too_many() {
        let vs: Vec<_> = (0..25)
            .map(|i| parse_volume_flag(&format!("/m{i}:1g")).unwrap())
            .collect();
        assert!(validate_volumes(&vs).is_err());
    }

    #[test]
    fn validate_accepts_24() {
        let vs: Vec<_> = (0..24)
            .map(|i| parse_volume_flag(&format!("/m{i}:1g")).unwrap())
            .collect();
        assert!(validate_volumes(&vs).is_ok());
    }

    #[test]
    fn cmdline_value_is_ordered_paths() {
        let vs = vec![
            parse_volume_flag("/a:1g").unwrap(),
            parse_volume_flag("c:/b:1g").unwrap(),
        ];
        assert_eq!(cmdline_value(&vs), "/a,/b");
        assert_eq!(cmdline_value(&[]), "");
    }

    #[test]
    fn image_path_ephemeral_vs_persistent() {
        let paths = Paths::with_root("/data/izba".into());
        let eph = VolumeSpec {
            name: None,
            guest_path: "/eph".into(),
            size_bytes: 1 << 30,
            eph_id: Some(0),
        };
        let per = parse_volume_flag("cache:/data:1g").unwrap();
        assert_eq!(
            eph.image_path(&paths, "web"),
            PathBuf::from("/data/izba/sandboxes/web/volumes/0.img")
        );
        assert_eq!(
            per.image_path(&paths, "web"),
            PathBuf::from("/data/izba/volumes/cache.img")
        );
    }

    #[test]
    fn assign_eph_ids_numbers_ephemeral_in_order() {
        let mut vs = vec![
            parse_volume_flag("cache:/data:1g").unwrap(), // persistent
            parse_volume_flag("/eph0:1g").unwrap(),       // ephemeral
            parse_volume_flag("/eph1:1g").unwrap(),       // ephemeral
        ];
        assign_eph_ids(&mut vs);
        assert_eq!(vs[0].eph_id, None); // persistent untouched
        assert_eq!(vs[1].eph_id, Some(0));
        assert_eq!(vs[2].eph_id, Some(1));
    }

    #[test]
    fn assign_eph_ids_continues_from_max_and_preserves_existing() {
        let mut vs = vec![
            VolumeSpec {
                name: None,
                guest_path: "/a".into(),
                size_bytes: 1 << 30,
                eph_id: Some(5),
            },
            parse_volume_flag("/b:1g").unwrap(), // new ephemeral, eph_id None
        ];
        assign_eph_ids(&mut vs);
        assert_eq!(vs[0].eph_id, Some(5)); // preserved
        assert_eq!(vs[1].eph_id, Some(6)); // max(5)+1
    }

    #[test]
    fn image_path_uses_eph_id_not_position() {
        let paths = Paths::with_root("/data/izba".into());
        let eph = VolumeSpec {
            name: None,
            guest_path: "/eph".into(),
            size_bytes: 1 << 30,
            eph_id: Some(3),
        };
        let per = parse_volume_flag("cache:/data:1g").unwrap();
        assert_eq!(
            eph.image_path(&paths, "web"),
            PathBuf::from("/data/izba/sandboxes/web/volumes/3.img")
        );
        assert_eq!(
            per.image_path(&paths, "web"),
            PathBuf::from("/data/izba/volumes/cache.img")
        );
    }

    #[test]
    fn prune_selects_unreferenced() {
        let on_disk = ["cache".to_string(), "old".to_string(), "live".to_string()];
        let referenced: HashSet<String> = ["live".to_string()].into_iter().collect();
        let mut got = unreferenced_volumes(&on_disk, &referenced);
        got.sort();
        assert_eq!(got, vec!["cache".to_string(), "old".to_string()]);
    }
}
