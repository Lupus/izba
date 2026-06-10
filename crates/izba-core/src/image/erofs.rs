//! Build an erofs image from a merged tar via `mkfs.erofs --tar=f`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
const MKFS_EROFS_EXE: &str = "mkfs.erofs.exe";
#[cfg(not(windows))]
const MKFS_EROFS_EXE: &str = "mkfs.erofs";

/// Locate `mkfs.erofs`: explicit `$IZBA_MKFS_EROFS` override, then a copy
/// bundled next to the running executable (`<exe dir>/libexec/`, Docker's
/// convention — the future Windows installer relies on this), then `$PATH`.
fn find_mkfs_erofs() -> Result<PathBuf> {
    crate::discover::find_tool("IZBA_MKFS_EROFS", MKFS_EROFS_EXE)
}

/// Convert a merged (flattened) tar file into an erofs rootfs image at `out`.
///
/// Requires erofs-utils >= 1.8 (`--tar=f` consumes a tar *file* as the
/// source, given after the image path).
pub fn build_erofs(merged_tar: &Path, out: &Path) -> Result<()> {
    let mkfs = find_mkfs_erofs()?;
    let output = Command::new(mkfs)
        .arg("--tar=f")
        .arg("-T0")
        .arg("--quiet")
        .arg(out)
        .arg(merged_tar)
        .output()
        .context("failed to run mkfs.erofs")?;
    if !output.status.success() {
        bail!(
            "mkfs.erofs failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const EROFS_MAGIC: [u8; 4] = [0xe2, 0xe1, 0xf5, 0xe0];

    #[test]
    fn erofs_smoke() {
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let dir = tempfile::TempDir::new().unwrap();
        let tar_path = dir.path().join("merged.tar");
        let out_path = dir.path().join("rootfs.erofs");

        let mut builder = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
        let data = b"hello erofs";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "hello.txt", data.as_slice())
            .unwrap();
        builder.finish().unwrap();
        drop(builder);

        build_erofs(&tar_path, &out_path).unwrap();

        let mut f = std::fs::File::open(&out_path).unwrap();
        let mut head = vec![0u8; 1028];
        f.read_exact(&mut head).unwrap();
        assert_eq!(
            &head[1024..1028],
            &EROFS_MAGIC,
            "missing erofs superblock magic"
        );
    }
}
