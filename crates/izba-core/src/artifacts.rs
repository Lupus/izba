//! Locating the shared boot artifacts (kernel + initramfs).

use anyhow::bail;
use std::path::{Path, PathBuf};

use crate::paths::Paths;
use crate::sandbox::Artifacts;

/// Locate boot artifacts. Resolution order:
/// 1. `$IZBA_KERNEL` + `$IZBA_INITRAMFS` overrides (both or neither).
/// 2. `<data>/artifacts/{vmlinux,initramfs.cpio.gz}` (per-user data dir).
/// 3. `<exe-dir>/../artifacts/{...}` (a self-contained package install:
///    binary at `<root>/bin/izba`, artifacts at `<root>/artifacts`).
pub fn locate(paths: &Paths) -> anyhow::Result<Artifacts> {
    let kernel = std::env::var_os("IZBA_KERNEL").map(PathBuf::from);
    let initramfs = std::env::var_os("IZBA_INITRAMFS").map(PathBuf::from);
    // current_exe may be unavailable in some sandboxed environments; None just
    // skips the exe-relative fallback below.
    let exe = std::env::current_exe().ok();
    let exe_dir = exe.as_deref().and_then(Path::parent);
    locate_from(kernel, initramfs, &paths.artifacts_dir(), exe_dir)
}

/// Pure core of [`locate`], factored for testing (no process env / current_exe).
fn locate_from(
    kernel_env: Option<PathBuf>,
    initramfs_env: Option<PathBuf>,
    data_dir: &Path,
    exe_dir: Option<&Path>,
) -> anyhow::Result<Artifacts> {
    match (kernel_env, initramfs_env) {
        (Some(kernel), Some(initramfs)) => return Ok(Artifacts { kernel, initramfs }),
        (Some(_), None) | (None, Some(_)) => {
            bail!("IZBA_KERNEL and IZBA_INITRAMFS must be set together (or neither)")
        }
        (None, None) => {}
    }

    // 2. per-user data dir, then 3. exe-relative `../artifacts`.
    let exe_relative = exe_dir
        .and_then(Path::parent)
        .map(|root| root.join("artifacts"));
    let candidates = std::iter::once(data_dir.to_path_buf()).chain(exe_relative);
    for dir in candidates {
        let kernel = dir.join("vmlinux");
        let initramfs = dir.join("initramfs.cpio.gz");
        if kernel.is_file() && initramfs.is_file() {
            return Ok(Artifacts { kernel, initramfs });
        }
    }

    bail!(
        "boot artifacts not found in {} (or next to the izba binary) — run \
         hack/fetch-artifacts.sh or set IZBA_KERNEL and IZBA_INITRAMFS",
        data_dir.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn touch(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn both_env_overrides_win() {
        let got = locate_from(
            Some(PathBuf::from("/k")),
            Some(PathBuf::from("/i")),
            Path::new("/no/data"),
            Some(Path::new("/no/exe/bin")),
        )
        .unwrap();
        assert_eq!(got.kernel, PathBuf::from("/k"));
        assert_eq!(got.initramfs, PathBuf::from("/i"));
    }

    #[test]
    fn one_env_override_is_an_error() {
        let err =
            locate_from(Some(PathBuf::from("/k")), None, Path::new("/no/data"), None).unwrap_err();
        assert!(err.to_string().contains("must be set together"));
    }

    #[test]
    fn data_dir_used_when_populated() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let got = locate_from(None, None, &data, None).unwrap();
        assert_eq!(got.kernel, data.join("vmlinux"));
        assert_eq!(got.initramfs, data.join("initramfs.cpio.gz"));
    }

    #[test]
    fn exe_relative_used_when_data_dir_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Layout: <root>/bin/izba  ->  artifacts at <root>/artifacts
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let art = tmp.path().join("artifacts");
        touch(&art, "vmlinux");
        touch(&art, "initramfs.cpio.gz");
        let empty_data = tmp.path().join("empty-data");
        let got = locate_from(None, None, &empty_data, Some(&bin)).unwrap();
        assert_eq!(got.kernel, art.join("vmlinux"));
        assert_eq!(got.initramfs, art.join("initramfs.cpio.gz"));
    }

    #[test]
    fn data_dir_wins_over_exe_relative() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let art = tmp.path().join("artifacts");
        touch(&art, "vmlinux");
        touch(&art, "initramfs.cpio.gz");
        let got = locate_from(None, None, &data, Some(&bin)).unwrap();
        assert_eq!(got.kernel, data.join("vmlinux"));
        assert_eq!(got.initramfs, data.join("initramfs.cpio.gz"));
    }

    #[test]
    fn nothing_found_is_an_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = locate_from(None, None, &tmp.path().join("nope"), None).unwrap_err();
        assert!(err.to_string().contains("boot artifacts not found"));
    }
}
