//! Filesystem helpers for bundle save/load.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;

/// `Read` adapter yielding exactly `remaining` bytes of `inner`, the length a
/// tar header already declared: never reads past it (a file growing mid-read
/// — the daemon appending to egress-audit.jsonl, an IDE rewriting a
/// workspace file — is cut at that length) and errors on an early EOF (a
/// shrinking file) instead of letting the tar stream desync from its header.
/// A desynced stream would make the trailer unreachable and EVERY sandbox in
/// the archive unloadable while the save reported success.
pub(crate) struct ExactLen<R> {
    inner: R,
    remaining: u64,
}

impl<R> ExactLen<R> {
    pub(crate) fn new(inner: R, len: u64) -> Self {
        Self {
            inner,
            remaining: len,
        }
    }
}

impl<R: Read> Read for ExactLen<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let cap = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..cap])?;
        if n == 0 && cap > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "file shrank while archiving ({} bytes short)",
                    self.remaining
                ),
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

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

// reason: compiled on no platform izba builds or tests (Linux, Windows); a
// constant "unknown, assume room" answer that no CI job can execute.
#[mutants::skip]
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
        // A host that just built this test binary has far more than 1 MiB
        // free: a constant 0/1 answer, or a failed OS call read as success,
        // cannot pass this.
        assert!(n >= 1 << 20, "{n}");
    }

    #[test]
    fn exact_len_answers_an_empty_buffer_without_reading_or_failing() {
        // A zero-length read is not an early EOF, even with bytes owed.
        let mut r = ExactLen::new(&b"abc"[..], 3);
        assert_eq!(r.read(&mut []).unwrap(), 0);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn human_bytes_picks_a_unit() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(3 << 29), "1.5 GiB");
        assert_eq!(human_bytes(1 << 20), "1.0 MiB");
    }
}
