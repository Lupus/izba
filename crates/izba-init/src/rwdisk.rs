//! First-boot handling of the read-write disk (/dev/vdb).

use anyhow::Context;
use std::io::Read;
use std::path::Path;

const PROBE_LEN: usize = 64 * 1024;

/// True if the first 64 KiB of the device/file are all zeros (a short file
/// counts as blank). A fresh sparse rw.img reads as zeros; any filesystem
/// puts a superblock in that window.
pub fn is_blank(path: &Path) -> std::io::Result<bool> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; PROBE_LEN];
    let mut filled = 0;
    while filled < PROBE_LEN {
        match f.read(&mut buf[filled..])? {
            0 => break, // short file → treat missing tail as zeros
            n => filled += n,
        }
    }
    Ok(buf[..filled].iter().all(|&b| b == 0))
}

/// Formats `dev` as ext4 on first boot (when it is still blank).
pub fn ensure_formatted(dev: &Path) -> anyhow::Result<()> {
    ensure_formatted_with(dev, Path::new("/sbin/mke2fs"))
}

/// Same as [`ensure_formatted`], with the mke2fs path injectable for tests.
pub fn ensure_formatted_with(dev: &Path, mke2fs: &Path) -> anyhow::Result<()> {
    if !is_blank(dev).with_context(|| format!("probing rw disk {}", dev.display()))? {
        return Ok(());
    }
    if !mke2fs.exists() {
        anyhow::bail!(
            "rw disk is blank and initramfs has no mke2fs; \
             pre-format rw.img on the host (mkfs.ext4)"
        );
    }
    let status = std::process::Command::new(mke2fs)
        .args(["-t", "ext4", "-q"])
        .arg(dev)
        .status()
        .with_context(|| format!("running {}", mke2fs.display()))?;
    if !status.success() {
        anyhow::bail!("mke2fs failed on {}: {status}", dev.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn temp_file_with(content: impl FnOnce(&mut std::fs::File)) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        content(f.as_file_mut());
        f.as_file_mut().flush().unwrap();
        f
    }

    #[test]
    fn all_zero_file_is_blank() {
        let f = temp_file_with(|f| f.write_all(&vec![0u8; PROBE_LEN]).unwrap());
        assert!(is_blank(f.path()).unwrap());
    }

    #[test]
    fn nonzero_at_offset_is_not_blank() {
        let f = temp_file_with(|f| {
            f.write_all(&vec![0u8; PROBE_LEN]).unwrap();
            f.seek(SeekFrom::Start(1100)).unwrap();
            f.write_all(&[0x42]).unwrap();
        });
        assert!(!is_blank(f.path()).unwrap());
    }

    #[test]
    fn short_file_is_blank() {
        let f = temp_file_with(|f| f.write_all(&[0u8; 128]).unwrap());
        assert!(is_blank(f.path()).unwrap());
    }

    #[test]
    fn empty_file_is_blank() {
        let f = temp_file_with(|_| {});
        assert!(is_blank(f.path()).unwrap());
    }

    #[test]
    fn blank_disk_without_mke2fs_errors() {
        let f = temp_file_with(|f| f.write_all(&vec![0u8; PROBE_LEN]).unwrap());
        let err = ensure_formatted_with(f.path(), Path::new("/nonexistent/mke2fs"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("pre-format rw.img on the host"), "{err}");
    }

    #[test]
    fn formatted_disk_is_left_alone() {
        // Non-blank → no mke2fs needed even if the binary is missing.
        let f = temp_file_with(|f| f.write_all(b"\xeb\x3c\x90not-blank").unwrap());
        ensure_formatted_with(f.path(), Path::new("/nonexistent/mke2fs")).unwrap();
    }
}
