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
    find_mkfs_erofs_from(
        std::env::var_os("IZBA_MKFS_EROFS").map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

fn find_mkfs_erofs_from(
    env_override: Option<PathBuf>,
    current_exe: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(p) = env_override {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "IZBA_MKFS_EROFS is set to {} but no file exists there",
            p.display()
        );
    }
    if let Some(dir) = current_exe.as_deref().and_then(Path::parent) {
        let bundled = dir.join("libexec").join(MKFS_EROFS_EXE);
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    which::which(MKFS_EROFS_EXE).map_err(|_| {
        anyhow::anyhow!(
            "mkfs.erofs not found (checked $IZBA_MKFS_EROFS, <exe dir>/libexec/{MKFS_EROFS_EXE}, PATH) — install erofs-utils or set IZBA_MKFS_EROFS"
        )
    })
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
    fn resolve_env_override_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let fake = dir.path().join("my-mkfs");
        std::fs::write(&fake, b"").unwrap();
        let got = find_mkfs_erofs_from(Some(fake.clone()), None).unwrap();
        assert_eq!(got, fake);
    }

    #[test]
    fn resolve_env_override_beats_bundled() {
        // Both an env-override file and a bundled libexec file exist; the env
        // override must win.
        let override_dir = tempfile::TempDir::new().unwrap();
        let override_file = override_dir.path().join("my-mkfs-override");
        std::fs::write(&override_file, b"").unwrap();

        let exe_dir = tempfile::TempDir::new().unwrap();
        let libexec = exe_dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        let bundled = libexec.join(MKFS_EROFS_EXE);
        std::fs::write(&bundled, b"").unwrap();

        let got = find_mkfs_erofs_from(
            Some(override_file.clone()),
            Some(exe_dir.path().join("izba")),
        )
        .unwrap();
        assert_eq!(got, override_file);
    }

    #[test]
    fn resolve_env_override_missing_is_error() {
        let err =
            find_mkfs_erofs_from(Some(PathBuf::from("/nonexistent/mkfs.erofs")), None).unwrap_err();
        assert!(err.to_string().contains("IZBA_MKFS_EROFS"));
    }

    #[test]
    fn resolve_bundled_libexec_beats_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let libexec = dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        let bundled = libexec.join(MKFS_EROFS_EXE);
        std::fs::write(&bundled, b"").unwrap();
        let got = find_mkfs_erofs_from(None, Some(dir.path().join("izba"))).unwrap();
        assert_eq!(got, bundled);
    }

    #[test]
    fn resolve_falls_back_to_path() {
        // No override, no bundled copy: outcome depends on whether the host
        // has erofs-utils installed — assert both arms explicitly.
        match find_mkfs_erofs_from(None, None) {
            Ok(p) => assert!(p.to_string_lossy().contains("mkfs.erofs")),
            Err(e) => assert!(e.to_string().contains("PATH")),
        }
    }

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
