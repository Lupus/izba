//! Locating the shared boot artifacts (kernel + initramfs).

use anyhow::bail;
use std::path::{Path, PathBuf};

use crate::paths::Paths;
use crate::sandbox::Artifacts;

/// Which kernel image a sandbox needs.
///
/// A sandbox with device grants must boot a kernel that has `vhci-hcd`; every
/// other sandbox must boot one that physically cannot talk to a USB device
/// (design D4). Selecting the wrong image is not a degraded mode — it is either
/// an attach that mysteriously does nothing, or USB support handed to a sandbox
/// nobody granted anything to — so the two images are separate files and a
/// missing one is an error rather than a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelVariant {
    /// The default kernel: no USB support at all.
    Base,
    /// The USB-capable kernel (`vmlinux-usb`), for a sandbox holding grants.
    Usb,
}

impl KernelVariant {
    /// Every variant, so a consumer that must handle all of them (packaging
    /// checks, docs) cannot silently miss one added later.
    pub const ALL: [KernelVariant; 2] = [KernelVariant::Base, KernelVariant::Usb];

    /// Filename within an artifacts directory. Crate-visible so a start-time
    /// mismatch can name the kernel it actually located.
    pub(crate) fn image(self) -> &'static str {
        match self {
            KernelVariant::Base => "vmlinux",
            KernelVariant::Usb => "vmlinux-usb",
        }
    }

    /// Environment variable that overrides this variant's image.
    ///
    /// Separate names on purpose: the e2e suite sets both, and a run that meant
    /// to test the USB kernel must not silently pass with the base one.
    fn env(self) -> &'static str {
        match self {
            KernelVariant::Base => "IZBA_KERNEL",
            KernelVariant::Usb => "IZBA_KERNEL_USB",
        }
    }
}

/// Locate boot artifacts. Resolution order:
/// 1. `$IZBA_KERNEL` + `$IZBA_INITRAMFS` overrides (both or neither).
/// 2. `<exe-dir>/../artifacts/{vmlinux,initramfs.cpio.gz}` — the
///    version-matched bundle shipped next to the binary (`.deb`, installer).
///    This wins by default so that a package upgrade is never silently shadowed
///    by a stale data-dir left behind from earlier dev work.
/// 3. `<data>/artifacts/{...}` — per-user data dir, used as a fallback for
///    `cargo run` / dev builds that have no sibling bundle (populated by
///    `hack/fetch-artifacts.sh`).
///
/// The optional KasmVNC bundle (`kasmvnc.erofs`) follows the same order, keyed
/// off `$IZBA_KASMVNC_EROFS` — a standalone override with no pairing rule (see
/// [`locate_from_with_vnc_env`]) — and is resolved only when `vnc` is true.
pub fn locate(paths: &Paths, variant: KernelVariant, vnc: bool) -> anyhow::Result<Artifacts> {
    let kernel = std::env::var_os(variant.env()).map(PathBuf::from);
    let initramfs = std::env::var_os("IZBA_INITRAMFS").map(PathBuf::from);
    let vnc_env = std::env::var_os("IZBA_KASMVNC_EROFS").map(PathBuf::from);
    // current_exe may be unavailable in some sandboxed environments; None just
    // skips the exe-relative fallback below.
    let exe = std::env::current_exe().ok();
    let exe_dir = exe.as_deref().and_then(Path::parent);
    locate_from_with_vnc_env(
        kernel,
        initramfs,
        vnc_env,
        &paths.artifacts_dir(),
        exe_dir,
        variant,
        vnc,
    )
}

/// Pure core of [`locate`], factored for testing (no process env / current_exe).
/// Never threads a `$IZBA_KASMVNC_EROFS` override — tests that need one call
/// [`locate_from_with_vnc_env`] directly. Test-only: production always goes
/// through `locate` -> `locate_from_with_vnc_env` since it always has a real
/// (possibly absent) env value to thread.
#[cfg(test)]
fn locate_from(
    kernel_env: Option<PathBuf>,
    initramfs_env: Option<PathBuf>,
    data_dir: &Path,
    exe_dir: Option<&Path>,
    variant: KernelVariant,
    vnc: bool,
) -> anyhow::Result<Artifacts> {
    locate_from_with_vnc_env(
        kernel_env,
        initramfs_env,
        None,
        data_dir,
        exe_dir,
        variant,
        vnc,
    )
}

/// Pure core of [`locate`], with the KasmVNC bundle's env override also
/// threaded explicitly (same style as the kernel/initramfs overrides above) so
/// tests stay env-free.
#[allow(clippy::too_many_arguments)]
fn locate_from_with_vnc_env(
    kernel_env: Option<PathBuf>,
    initramfs_env: Option<PathBuf>,
    vnc_env: Option<PathBuf>,
    data_dir: &Path,
    exe_dir: Option<&Path>,
    variant: KernelVariant,
    vnc: bool,
) -> anyhow::Result<Artifacts> {
    let (kernel, initramfs) = match (kernel_env, initramfs_env) {
        (Some(kernel), Some(initramfs)) => (kernel, initramfs),
        (Some(_), None) | (None, Some(_)) => {
            bail!(
                "{} and IZBA_INITRAMFS must be set together (or neither)",
                variant.env()
            )
        }
        (None, None) => {
            // 2. exe-relative `../artifacts` (version-matched bundle), then 3. data dir.
            let exe_relative = exe_dir
                .and_then(Path::parent)
                .map(|root| root.join("artifacts"));
            let candidates = exe_relative
                .into_iter()
                .chain(std::iter::once(data_dir.to_path_buf()));
            let mut found = None;
            for dir in candidates {
                let kernel = dir.join(variant.image());
                let initramfs = dir.join("initramfs.cpio.gz");
                if kernel.is_file() && initramfs.is_file() {
                    found = Some((kernel, initramfs));
                    break;
                }
            }
            match found {
                Some(pair) => pair,
                None => {
                    if variant == KernelVariant::Usb {
                        // Never fall back to the base kernel: it has no vhci, so the
                        // sandbox would boot, accept an attach, and then quietly have
                        // no device. Say exactly what is missing and how to build it.
                        bail!(
                            "this sandbox has USB device grants, so it needs the \
                             USB-capable kernel ('{}'), which is not installed in {} or \
                             next to the izba binary — build it with \
                             `IZBA_KERNEL_EXTRA_CONFIG=hack/kernel-usb.config \
                             hack/build-kernel.sh 6.18.43 dist/vmlinux-usb`, or set \
                             IZBA_KERNEL_USB and IZBA_INITRAMFS. Revoke the grants \
                             (`izba usb revoke`) to start on the default kernel.",
                            variant.image(),
                            data_dir.display()
                        );
                    }
                    bail!(
                        "boot artifacts not found in {} (or next to the izba binary) — \
                         run hack/fetch-artifacts.sh or set IZBA_KERNEL and IZBA_INITRAMFS",
                        data_dir.display()
                    );
                }
            }
        }
    };

    let kasmvnc_erofs = if vnc {
        Some(locate_kasmvnc(vnc_env, data_dir, exe_dir)?)
    } else {
        None
    };

    Ok(Artifacts {
        variant,
        kernel,
        initramfs,
        kasmvnc_erofs,
    })
}

/// Resolve the KasmVNC bundle: `$IZBA_KASMVNC_EROFS` override (no pairing
/// rule — it is a standalone file, not a matched pair like kernel+initramfs),
/// then exe-relative `../artifacts/kasmvnc.erofs`, then `<data>/artifacts/
/// kasmvnc.erofs`. Fails closed: a VNC-enabled sandbox with no bundle must
/// never silently boot without VNC.
fn locate_kasmvnc(
    vnc_env: Option<PathBuf>,
    data_dir: &Path,
    exe_dir: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = vnc_env {
        return Ok(path);
    }

    let exe_relative = exe_dir
        .and_then(Path::parent)
        .map(|root| root.join("artifacts").join("kasmvnc.erofs"));
    let candidates = exe_relative
        .into_iter()
        .chain(std::iter::once(data_dir.join("kasmvnc.erofs")));
    for path in candidates {
        if path.is_file() {
            return Ok(path);
        }
    }

    bail!(
        "VNC is enabled for this sandbox but kasmvnc.erofs was not found in {} \
         (or next to the izba binary) — reinstall izba, run hack/build-kasmvnc-erofs.sh, \
         set IZBA_KASMVNC_EROFS, or disable VNC with `izba vnc off <name>`",
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
    fn the_usb_variant_looks_for_its_own_kernel_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "vmlinux-usb");
        touch(&data, "initramfs.cpio.gz");
        assert_eq!(
            locate_from(None, None, &data, None, KernelVariant::Usb, false)
                .unwrap()
                .kernel,
            data.join("vmlinux-usb")
        );
        assert_eq!(
            locate_from(None, None, &data, None, KernelVariant::Base, false)
                .unwrap()
                .kernel,
            data.join("vmlinux")
        );
    }

    #[test]
    fn a_usb_sandbox_without_the_usb_kernel_fails_with_a_fixable_error() {
        // Falling back to the base kernel would produce a sandbox that boots,
        // accepts an attach, and then quietly has no device — the silent
        // downgrade the project forbids. Fail, and say how to fix it.
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let err = format!(
            "{:#}",
            locate_from(None, None, &data, None, KernelVariant::Usb, false).unwrap_err()
        );
        assert!(err.contains("vmlinux-usb"), "name what is missing: {err}");
        assert!(
            err.contains("build-kernel.sh"),
            "say how to build it: {err}"
        );
        assert!(
            err.contains("izba usb revoke"),
            "and how to proceed without it: {err}"
        );
    }

    #[test]
    fn the_usb_kernel_override_is_a_separate_variable_from_the_base_one() {
        // e2e sets both. A run that meant to exercise the USB kernel must not
        // silently pass on the base one because they shared a variable.
        assert_eq!(KernelVariant::Base.env(), "IZBA_KERNEL");
        assert_eq!(KernelVariant::Usb.env(), "IZBA_KERNEL_USB");
        // And a lone override still names the variable the caller actually set.
        let err = format!(
            "{:#}",
            locate_from(
                Some(PathBuf::from("/k")),
                None,
                Path::new("/no/data"),
                None,
                KernelVariant::Usb,
                false,
            )
            .unwrap_err()
        );
        assert!(err.contains("IZBA_KERNEL_USB"), "{err}");
    }

    #[test]
    fn both_env_overrides_win() {
        let got = locate_from(
            Some(PathBuf::from("/k")),
            Some(PathBuf::from("/i")),
            Path::new("/no/data"),
            Some(Path::new("/no/exe/bin")),
            KernelVariant::Base,
            false,
        )
        .unwrap();
        assert_eq!(got.kernel, PathBuf::from("/k"));
        assert_eq!(got.initramfs, PathBuf::from("/i"));
    }

    #[test]
    fn one_env_override_is_an_error() {
        let err = locate_from(
            Some(PathBuf::from("/k")),
            None,
            Path::new("/no/data"),
            None,
            KernelVariant::Base,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be set together"));
    }

    #[test]
    fn data_dir_used_when_populated() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let got = locate_from(None, None, &data, None, KernelVariant::Base, false).unwrap();
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
        let got = locate_from(
            None,
            None,
            &empty_data,
            Some(&bin),
            KernelVariant::Base,
            false,
        )
        .unwrap();
        assert_eq!(got.kernel, art.join("vmlinux"));
        assert_eq!(got.initramfs, art.join("initramfs.cpio.gz"));
    }

    #[test]
    fn exe_relative_wins_over_data_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let art = tmp.path().join("artifacts");
        touch(&art, "vmlinux");
        touch(&art, "initramfs.cpio.gz");
        // The version-matched bundle next to the binary must win over a
        // potentially stale data dir left behind by an earlier dev build.
        let got = locate_from(None, None, &data, Some(&bin), KernelVariant::Base, false).unwrap();
        assert_eq!(got.kernel, art.join("vmlinux"));
        assert_eq!(got.initramfs, art.join("initramfs.cpio.gz"));
    }

    #[test]
    fn nothing_found_is_an_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = locate_from(
            None,
            None,
            &tmp.path().join("nope"),
            None,
            KernelVariant::Base,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("boot artifacts not found"));
    }

    #[test]
    fn a_vnc_sandbox_without_the_bundle_fails_with_a_fixable_error() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "vmlinux");
        touch(dir.path(), "initramfs.cpio.gz");
        let err = locate_from(None, None, dir.path(), None, KernelVariant::Base, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("kasmvnc.erofs"), "names the artifact: {err}");
        assert!(
            err.contains("hack/build-kasmvnc-erofs.sh"),
            "names the remedy: {err}"
        );
        assert!(err.contains("izba vnc off"), "names the way out: {err}");
    }

    #[test]
    fn the_vnc_bundle_is_found_next_to_the_kernel() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "vmlinux");
        touch(dir.path(), "initramfs.cpio.gz");
        touch(dir.path(), "kasmvnc.erofs");
        let art = locate_from(None, None, dir.path(), None, KernelVariant::Base, true).unwrap();
        assert_eq!(art.kasmvnc_erofs, Some(dir.path().join("kasmvnc.erofs")));
    }

    #[test]
    fn a_non_vnc_sandbox_never_looks_for_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "vmlinux");
        touch(dir.path(), "initramfs.cpio.gz");
        let art = locate_from(None, None, dir.path(), None, KernelVariant::Base, false).unwrap();
        assert_eq!(art.kasmvnc_erofs, None);
    }

    #[test]
    fn the_vnc_bundle_env_override_wins() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "vmlinux");
        touch(dir.path(), "initramfs.cpio.gz");
        let alt = tempfile::tempdir().unwrap();
        touch(alt.path(), "kasmvnc.erofs");
        let art = locate_from_with_vnc_env(
            None,
            None,
            Some(alt.path().join("kasmvnc.erofs")),
            dir.path(),
            None,
            KernelVariant::Base,
            true,
        )
        .unwrap();
        assert_eq!(art.kasmvnc_erofs, Some(alt.path().join("kasmvnc.erofs")));
    }

    #[test]
    fn every_kernel_variant_is_installed_by_the_debian_package() {
        // The defect this pins (#189): KernelVariant::Usb was added, artifacts
        // resolution learned to demand `vmlinux-usb`, and the packaging manifest
        // was never told — so a sandbox with grants hit a hard stop telling a
        // packaged user to go build a kernel. A test over the *enum* catches the
        // next variant too, which a hardcoded filename list would not.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let script = std::fs::read_to_string(root.join("packaging/build-deb.sh"))
            .expect("packaging/build-deb.sh must be readable from the crate");
        for v in KernelVariant::ALL {
            let dest = format!("usr/lib/izba/artifacts/{}", v.image());
            assert!(
                script.contains(&dest),
                "packaging/build-deb.sh installs no {dest}: a sandbox needing the \
                 {:?} kernel cannot start from an installed build",
                v
            );
        }
        assert!(
            script.contains("usr/lib/izba/artifacts/kasmvnc.erofs"),
            "packaging/build-deb.sh installs no usr/lib/izba/artifacts/kasmvnc.erofs: \
             a VNC-enabled sandbox cannot start from an installed build"
        );
    }
}
