//! Locating the shared boot artifacts (kernel + initramfs).

use anyhow::bail;
use std::path::PathBuf;

use crate::paths::Paths;
use crate::sandbox::Artifacts;

/// Locate boot artifacts: `$IZBA_KERNEL`/`$IZBA_INITRAMFS` override (both or
/// nothing), else `<data>/artifacts/{vmlinux,initramfs.cpio.gz}`.
pub fn locate(paths: &Paths) -> anyhow::Result<Artifacts> {
    let kernel = std::env::var_os("IZBA_KERNEL").map(PathBuf::from);
    let initramfs = std::env::var_os("IZBA_INITRAMFS").map(PathBuf::from);
    match (kernel, initramfs) {
        (Some(kernel), Some(initramfs)) => Ok(Artifacts { kernel, initramfs }),
        (Some(_), None) | (None, Some(_)) => {
            bail!("IZBA_KERNEL and IZBA_INITRAMFS must be set together (or neither)")
        }
        (None, None) => {
            let dir = paths.artifacts_dir();
            let kernel = dir.join("vmlinux");
            let initramfs = dir.join("initramfs.cpio.gz");
            if !kernel.is_file() || !initramfs.is_file() {
                bail!(
                    "boot artifacts not found in {} — run hack/fetch-artifacts.sh \
                     or set IZBA_KERNEL and IZBA_INITRAMFS",
                    dir.display()
                );
            }
            Ok(Artifacts { kernel, initramfs })
        }
    }
}
