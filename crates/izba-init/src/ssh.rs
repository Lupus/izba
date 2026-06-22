// SSH constants and launch logic for the guest side of izba-ssh delivery.
//
// The izba-ssh virtiofs share delivers the SSH host key and
// authorized_keys into the guest. izba-init mounts it read-only
// at /rootfs/izba-ssh; this module copies the files into the
// sshd runtime dir and launches the vendored static sshd.

use std::path::Path;

/// virtiofs tag of the read-only SSH share izbad attaches per-sandbox.
pub const SSH_TAG: &str = "izba-ssh";

/// Post-chroot guest path of the SSH share.
/// The rootfs plan mounts it at /rootfs/izba-ssh; inside the chroot it is /izba-ssh.
#[allow(dead_code)]
pub const SSH_MOUNT: &str = "/izba-ssh";

/// Path to the vendored static sshd binary inside the initramfs.
pub const SSHD_BIN: &str = "/sbin/sshd";

/// Path to the sshd_config shipped in the initramfs.
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

/// Runtime directory for materialized SSH keys (host key, authorized_keys, pid file).
pub const RUN_DIR: &str = "/run/izba/ssh";

/// Materialize SSH keys from `share_dir` into `run_dir`.
///
/// If `<share_dir>/ssh_host_ed25519_key` is absent, returns `Ok(false)` (no SSH
/// material — skip cleanly). Otherwise creates `run_dir` (mode 0700), copies
/// the host key and authorized_keys into it (both mode 0600), and returns
/// `Ok(true)`. All filesystem side-effects are confined to `run_dir`.
pub fn materialize(share_dir: &Path, run_dir: &Path) -> std::io::Result<bool> {
    let host_key_src = share_dir.join("ssh_host_ed25519_key");
    if !host_key_src.exists() {
        return Ok(false);
    }

    // Create the runtime directory with restricted permissions (0700).
    std::fs::create_dir_all(run_dir)?;
    set_permissions(run_dir, 0o700)?;

    // Copy host key with strict permissions (0600).
    let host_key_dst = run_dir.join("ssh_host_ed25519_key");
    std::fs::copy(&host_key_src, &host_key_dst)?;
    set_permissions(&host_key_dst, 0o600)?;

    // Copy authorized_keys with strict permissions (0600). The host writes the
    // host key and authorized_keys together (write_ssh_material), so a host key
    // without authorized_keys means a partial/corrupt delivery — surface that
    // explicitly rather than letting std::fs::copy emit a bare ENOENT that
    // doesn't say which file is missing.
    let auth_keys_src = share_dir.join("authorized_keys");
    if !auth_keys_src.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "authorized_keys missing from ssh share ({}); host key present but keys incomplete",
                auth_keys_src.display()
            ),
        ));
    }
    let auth_keys_dst = run_dir.join("authorized_keys");
    std::fs::copy(&auth_keys_src, &auth_keys_dst)?;
    set_permissions(&auth_keys_dst, 0o600)?;

    Ok(true)
}

/// Returns the sshd argv: foreground (`-D`), log to stderr (`-e`), explicit config (`-f`).
pub fn sshd_argv() -> Vec<String> {
    vec![
        "-D".to_string(),
        "-e".to_string(),
        "-f".to_string(),
        SSHD_CONFIG.to_string(),
    ]
}

/// Launch the vendored sshd if SSH material was delivered.
///
/// Reads keys from `/rootfs/izba-ssh`, materializes them into `/run/izba/ssh`,
/// creates the sshd privilege-separation directory `/run/sshd` (0755,
/// best-effort — a missing privsep dir is non-fatal; sshd logs it),
/// then spawns sshd as a fire-and-forget background thread. A dead sshd is
/// non-fatal — errors are logged to the console but never panic or block boot.
pub fn launch() {
    let share_dir = Path::new("/rootfs/izba-ssh");
    let run_dir = Path::new(RUN_DIR);

    let present = match materialize(share_dir, run_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("izba-init: ssh materialize: {e}");
            return;
        }
    };

    if !present {
        // No SSH material delivered for this sandbox — skip silently.
        return;
    }

    // Normalize ownership/modes of the init-root SSH runtime directories.
    //
    // OpenSSH is strict about two things and rejects either with a fatal error
    // (privsep dir) or an auth refusal (StrictModes walking the authorized_keys
    // path): every directory must be owned by root and not group/world-writable.
    // The initramfs cpio is packed as the (non-root) build user, so a shipped
    // dir like /run carries a non-root owner; and dirs created at boot inherit
    // init's umask for their mode. init is PID 1 (uid 0), so we force the whole
    // chain to root:root with explicit modes. Best-effort — a failure here just
    // means sshd will log its own refusal.
    //   /run, /run/izba       0755 (path components, world-readable, not -writable)
    //   /run/izba/ssh         0700 (host key + authorized_keys live here)
    //   /run/sshd             0755 (sshd privilege-separation chroot dir)
    force_root_dir("/run", 0o755);
    force_root_dir("/run/izba", 0o755);
    force_root_dir(RUN_DIR, 0o700);
    force_root_dir("/run/sshd", 0o755);

    eprintln!("izba-init: starting sshd");
    std::thread::spawn(move || {
        let result = std::process::Command::new(SSHD_BIN)
            .args(sshd_argv())
            .spawn();
        match result {
            Err(e) => {
                eprintln!("izba-init: sshd spawn failed: {e}");
            }
            Ok(mut child) => match child.wait() {
                Ok(status) => eprintln!("izba-init: sshd exited: {status}"),
                Err(e) => eprintln!("izba-init: sshd wait error: {e}"),
            },
        }
    });
}

/// Set Unix permissions on a path (mode bits).
#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// No-op on non-Unix targets (Windows cross-compile gate).
#[cfg(not(unix))]
fn set_permissions(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort: ensure `path` exists and is owned by root:root with `mode`.
/// Used to normalize the init-root SSH runtime dirs against the initramfs'
/// non-root packing uid + init's umask, which OpenSSH would otherwise reject.
#[cfg(unix)]
fn force_root_dir(path: &str, mode: u32) {
    let _ = std::fs::create_dir_all(path);
    let _ = nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    );
    let _ = set_permissions(Path::new(path), mode);
}

/// No-op on non-Unix targets (Windows cross-compile gate).
#[cfg(not(unix))]
fn force_root_dir(_path: &str, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_copies_keys_and_skips_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("share");
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&share).unwrap();
        // absent → false
        assert!(!materialize(&share, &run).unwrap());
        std::fs::write(share.join("ssh_host_ed25519_key"), b"KEY").unwrap();
        std::fs::write(share.join("authorized_keys"), b"ssh-ed25519 AAAA x\n").unwrap();
        assert!(materialize(&share, &run).unwrap());
        assert_eq!(
            std::fs::read(run.join("ssh_host_ed25519_key")).unwrap(),
            b"KEY"
        );
        assert!(run.join("authorized_keys").exists());
    }

    #[cfg(unix)]
    #[test]
    fn materialized_host_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (share, run) = (tmp.path().join("s"), tmp.path().join("r"));
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(share.join("ssh_host_ed25519_key"), b"K").unwrap();
        std::fs::write(share.join("authorized_keys"), b"x\n").unwrap();
        materialize(&share, &run).unwrap();
        let m = std::fs::metadata(run.join("ssh_host_ed25519_key")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn sshd_argv_is_foreground_with_config() {
        assert_eq!(sshd_argv(), vec!["-D", "-e", "-f", "/etc/ssh/sshd_config"]);
    }
}
