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
            // The closing quote is part of the needle: `vmlinux` is a prefix of
            // `vmlinux-usb`, so a bare substring match on the base kernel would
            // be satisfied by the USB kernel's line and prove nothing.
            let dest = format!("usr/lib/izba/artifacts/{}\"", v.image());
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

    /// The repo root, from this crate's manifest dir.
    fn repo_root() -> &'static std::path::Path {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
    }

    #[test]
    fn every_kernel_variant_is_checked_by_the_payload_verifier() {
        // #191: the packaging manifests and the check over them are separate
        // files, so the verifier's list is pinned to the enum the same way the
        // .deb manifest is — the next variant fails here until the verifier
        // (and therefore every installer build) demands it.
        let script = std::fs::read_to_string(repo_root().join("packaging/verify-payload.sh"))
            .expect("packaging/verify-payload.sh must be readable from the crate");
        let list = script
            .lines()
            .find_map(|l| l.strip_prefix("ARTIFACTS=(")?.strip_suffix(')'))
            .expect("packaging/verify-payload.sh must define ARTIFACTS=(...) on one line");
        // Whole tokens, not substrings: `vmlinux` must not be satisfied by
        // `vmlinux-usb`.
        let names: Vec<&str> = list.split_whitespace().collect();
        for v in KernelVariant::ALL {
            assert!(
                names.contains(&v.image()),
                "packaging/verify-payload.sh does not require {}: an installer \
                 missing the {:?} kernel would pass verification",
                v.image(),
                v
            );
        }
        assert!(
            names.contains(&"initramfs.cpio.gz"),
            "packaging/verify-payload.sh does not require initramfs.cpio.gz"
        );
    }

    #[test]
    fn every_installer_build_runs_the_payload_verifier() {
        // A verifier with a test and no call site is the defect class this
        // feature keeps producing: the rule exists, nothing invokes it. Both
        // workflows that build installers must run it in both modes. The
        // needle is the `run:` step form on purpose: release.yml's dispatch-only
        // `smoke` job also calls the script, but from inside a `run: |` block, so
        // it is not `run:`-prefixed and (like a comment) cannot satisfy this.
        for wf in [
            ".github/workflows/release.yml",
            ".github/workflows/devbuild.yml",
        ] {
            let text = std::fs::read_to_string(repo_root().join(wf))
                .unwrap_or_else(|e| panic!("{wf} must be readable from the crate: {e}"));
            for mode in ["deb", "stage"] {
                let call = format!("run: packaging/verify-payload.sh {mode} ");
                assert!(
                    text.contains(&call),
                    "{wf} never runs `{call}…`: an installer missing a kernel \
                     would be built and uploaded unchecked"
                );
            }
        }
    }

    #[test]
    fn the_windows_installer_ships_exactly_what_the_stage_verifier_checked() {
        // `verify-payload.sh stage` checks the stage DIRECTORY, not the built
        // installer. That is only a valid proxy while izba.iss takes its boot
        // artifacts and VMM tools from that directory wholesale; a recipe
        // narrowed to named files would make the check prove nothing.
        let iss = std::fs::read_to_string(repo_root().join("packaging/windows/izba.iss"))
            .expect("packaging/windows/izba.iss must be readable from the crate");
        for glob in [r"{#StageDir}\artifacts\*", r"{#StageDir}\bin\libexec\*"] {
            assert!(
                iss.contains(glob),
                "packaging/windows/izba.iss no longer installs {glob}: the stage-dir \
                 payload check in the packaging workflows no longer describes the installer"
            );
        }
    }

    #[test]
    fn e2e_ci_attaches_a_usb_device_on_both_platforms() {
        // #191: Windows is the platform USB passthrough exists for (usbipd-win
        // lives there) and was the one platform with no e2e of it. Pin that the
        // real-VM workflow drives an attach on each: the Rust suite on KVM, the
        // PowerShell gate on WHP — fed the fake server it needs.
        let e2e = std::fs::read_to_string(repo_root().join(".github/workflows/e2e.yml"))
            .expect(".github/workflows/e2e.yml must be readable from the crate");
        assert!(
            e2e.contains("--test usb_attach_e2e"),
            "e2e.yml no longer runs the Linux/KVM USB attach suite"
        );
        assert!(
            e2e.contains("hack/ci/usb-attach-gate.ps1"),
            "e2e.yml runs no Windows/OpenVMM USB attach: the vsock-1028 plane \
             over OpenVMM's hybrid-vsock bridge would be taken on trust"
        );
        assert!(
            e2e.contains("fake-usbipd.exe"),
            "e2e.yml never hands the Windows gate a fake usbip server \
             (IZBA_FAKE_USBIPD=…\\fake-usbipd.exe)"
        );
        assert!(
            repo_root().join("hack/ci/usb-attach-gate.ps1").is_file(),
            "hack/ci/usb-attach-gate.ps1 is referenced by e2e.yml but missing"
        );
    }

    #[test]
    fn e2e_ci_builds_and_stages_the_kasmvnc_bundle() {
        // The defect this pins (Task 13): `crates/izba-cli/tests/daemon_e2e.rs`'s
        // vnc_desktop_e2e requires kasmvnc.erofs staged at the PRODUCTION
        // exe-relative discovery path (`target/artifacts/kasmvnc.erofs`) and
        // never sets IZBA_KASMVNC_EROFS — so unless CI actually builds and
        // stages the bundle, the e2e silently self-skips forever and never
        // proves the feature on a real VM (same class as the USB kernel-variant
        // packaging miss above). A cross-check over the CI YAML, mirroring
        // `every_kernel_variant_is_installed_by_the_debian_package`'s
        // file-reading pattern.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let e2e = std::fs::read_to_string(root.join(".github/workflows/e2e.yml"))
            .expect(".github/workflows/e2e.yml must be readable from the crate");
        assert!(
            e2e.contains("kasmvnc-erofs"),
            "e2e.yml has no kasmvnc-erofs artifact job/staging step: vnc_desktop_e2e \
             would self-skip on every CI run and never exercise VNC on a real VM"
        );
    }
}
