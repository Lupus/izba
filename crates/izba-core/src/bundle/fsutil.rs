//! Filesystem helpers for bundle save/load.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// `p` made absolute, then walked up to its nearest ancestor that exists
/// (itself if it does). Free space is a property of that ancestor's
/// filesystem, which is where a not-yet-created target will land.
pub fn nearest_existing(p: &Path) -> anyhow::Result<PathBuf> {
    let abs = std::path::absolute(p).with_context(|| format!("resolving {}", p.display()))?;
    let mut cur = abs.as_path();
    loop {
        if cur.exists() {
            return Ok(cur.to_path_buf());
        }
        cur = cur
            .parent()
            .with_context(|| format!("no existing ancestor of {}", p.display()))?;
    }
}

/// Bytes available to this user on the filesystem that holds `dir` (or would
/// hold it: the nearest existing ancestor is measured).
pub fn free_bytes(dir: &Path) -> anyhow::Result<u64> {
    let anc = nearest_existing(dir)?;
    os_free_bytes(&anc).with_context(|| format!("measuring free space on {}", anc.display()))
}

#[cfg(unix)]
fn os_free_bytes(dir: &Path) -> anyhow::Result<u64> {
    let st = nix::sys::statvfs::statvfs(dir)?;
    #[allow(clippy::unnecessary_cast)] // field widths differ across unix targets
    Ok((st.blocks_available() as u64).saturating_mul(st.fragment_size() as u64))
}

#[cfg(windows)]
fn os_free_bytes(dir: &Path) -> anyhow::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let mut avail: u64 = 0;
    // SAFETY: NUL-terminated wide path; out-pointer valid; the two optional
    // totals are null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut avail,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(avail)
}

#[cfg(not(any(unix, windows)))]
fn os_free_bytes(_dir: &Path) -> anyhow::Result<u64> {
    Ok(u64::MAX)
}

/// Human-readable byte count for messages (`1.5 GiB`, `512 B`).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_existing_walks_up_to_an_existing_dir() {
        let t = tempfile::tempdir().unwrap();
        let deep = t.path().join("a/b/c");
        assert_eq!(nearest_existing(&deep).unwrap(), t.path());
        assert_eq!(nearest_existing(t.path()).unwrap(), t.path());
    }

    #[test]
    fn free_bytes_of_a_missing_dir_measures_its_ancestor() {
        let t = tempfile::tempdir().unwrap();
        let n = free_bytes(&t.path().join("not/yet")).unwrap();
        assert!(n > 0);
    }

    #[test]
    fn human_bytes_picks_a_unit() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(3 << 29), "1.5 GiB");
        assert_eq!(human_bytes(1 << 20), "1.0 MiB");
    }
}
