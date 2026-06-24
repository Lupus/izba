// SSH constants and launch logic for the guest side of izba-ssh delivery.
//
// The izba-ssh virtiofs share delivers the SSH host key and
// authorized_keys into the guest. izba-init mounts it read-only
// at /rootfs/izba-ssh; this module copies the files into the
// sshd runtime dir and launches the vendored static sshd.

use std::path::Path;

/// Working directory used when entering the container for an SSH session.
///
/// Matches the `izba exec` interactive default (`INTERACTIVE_CWD` in
/// izba-core). izba-init cannot depend on izba-core, so the value is
/// defined here; keep both in sync when changing.
pub const SSH_SESSION_CWD: &str = "/workspace";

/// Build the `crun exec` argv for an SSH session entering the `izba`
/// container. `tty` is whether sshd gave this session a pseudo-terminal
/// (interactive login); `command` is the remote command sshd passed via the
/// restricted login shell's `-c` operand (`Some(cmd)` for `ssh host <cmd>` /
/// scp-over-exec, `None` for an interactive login shell). `term` is the
/// resolved `TERM` to forward into the container (`Some(value)` for a tty
/// session, `None` otherwise); it is forwarded as `--env TERM=<value>` ONLY
/// when `tty` is true AND `term` is `Some`, mirroring the `izba exec` server
/// path which sets `TERM` for tty execs only. This is pure: the caller
/// (`ssh_session`) resolves the actual value (the client's `TERM`, defaulting
/// to `xterm-256color`) and the default; here we only forward what we are
/// given. `trust_present` is whether the izba MITM CA bundle is present in the
/// guest; when true, all six CA-bundle env vars from
/// [`crate::trust::trust_env_pairs`] are forwarded (mirroring the `izba exec`
/// server path), gated ONLY on bundle presence and NOT on tty — a non-tty
/// `ssh host git ...` must still trust izbad's MITM leaf certs. Runs the
/// container's `/bin/sh` either interactively or as `sh -c <cmd>`, in
/// `SSH_SESSION_CWD`, as the container's configured user (no `--user`), with
/// the container image env plus the forwarded `TERM` and CA-bundle vars.
pub fn ssh_session_crun_argv(
    cgroup_manager: crate::oci::CgroupManager,
    tty: bool,
    command: Option<&str>,
    term: Option<&str>,
    trust_present: bool,
) -> Vec<String> {
    let shell_argv = match command {
        Some(cmd) => vec!["/bin/sh".to_string(), "-c".to_string(), cmd.to_string()],
        None => vec!["/bin/sh".to_string()],
    };
    // Forward TERM only for tty sessions (mirrors the exec server/CLI: pipe
    // execs get no TERM). The caller supplies the resolved value + default.
    let mut env: Vec<(String, String)> = match (tty, term) {
        (true, Some(t)) => vec![("TERM".to_string(), t.to_string())],
        _ => Vec::new(),
    };
    // Forward the MITM CA-bundle env vars when the izba CA bundle is present in
    // the guest, mirroring the `izba exec` server path (exec.rs
    // build_env_overlay). Gated ONLY on bundle presence, NOT on tty: a non-tty
    // `ssh host git ...` must also trust izbad's MITM leaf certs. The env VALUES
    // are the container-internal paths from trust_env_pairs() (valid inside
    // crun, which roots at /rootfs).
    if trust_present {
        for (k, v) in crate::trust::trust_env_pairs() {
            env.push((k.to_string(), v.to_string()));
        }
    }
    crate::oci::crun_exec_argv(
        cgroup_manager,
        tty,
        SSH_SESSION_CWD,
        &env, // env: container image env + forwarded TERM (tty only)
        None, // user: the container's configured user (no --user)
        &shell_argv,
    )
}

/// Init-visible path of the izba MITM CA bundle: `/rootfs` joined with the
/// container-internal bundle path ([`crate::trust::GUEST_CA_BUNDLE`]). The SSH
/// login shell runs in PID 1's mount namespace (sshd is launched by init; no
/// new mount ns), where the container overlay is mounted at `/rootfs` — so the
/// bundle is visible here at `/rootfs/etc/izba/ca-bundle.pem`. Pure; mirrors
/// the `oci.rs` overlay-root join pattern.
fn ssh_trust_bundle_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/rootfs").join(crate::trust::GUEST_CA_BUNDLE.trim_start_matches('/'))
}

/// Whether the izba MITM CA bundle is present in the guest (init-visible path).
// reason: filesystem existence check, exercised by the KVM/WHP e2e (no overlay
// on the host); the pure path it checks (ssh_trust_bundle_path) is unit-tested.
#[mutants::skip]
fn ssh_trust_bundle_present() -> bool {
    ssh_trust_bundle_path().is_file()
}

/// `izba-init` invoked as root's restricted login shell by sshd: enter the
/// running `izba` container via `crun exec`. `command` is `Some(cmd)` for a
/// remote command (`ssh host <cmd>` → sshd's `-c <cmd>`), `None` for an
/// interactive login shell. Never returns on success; on failure prints to
/// stderr and exits 127.
// reason: execs crun and never returns on success; covered by the KVM/WHP e2e,
// not unit tests (no live container on the host).
#[cfg(unix)]
#[mutants::skip]
pub fn ssh_session(command: Option<&str>) -> ! {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;
    let tty = nix::unistd::isatty(std::io::stdin().as_raw_fd()).unwrap_or(false);
    let cg = crate::oci::detect_cgroup_manager();
    // For an interactive (tty) login, sshd populated TERM in our environment;
    // forward the client's real TERM into the container, defaulting to
    // xterm-256color when unset (mirrors the `izba exec` CLI/server path).
    // A non-tty session (`ssh host <cmd>`) gets no TERM.
    let term: Option<String> = if tty {
        Some(std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()))
    } else {
        None
    };
    // Forward the MITM CA-bundle env vars when the izba CA bundle is present in
    // the guest (mirrors the `izba exec` server path); not gated on tty.
    let trust_present = ssh_trust_bundle_present();
    let argv = ssh_session_crun_argv(cg, tty, command, term.as_deref(), trust_present);
    let e = std::process::Command::new(&argv[0]).args(&argv[1..]).exec();
    eprintln!("izba-init: ssh-session: {e}");
    std::process::exit(127);
}

/// virtiofs tag of the read-only SSH share izbad attaches per-sandbox.
pub const SSH_TAG: &str = "izba-ssh";

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
// reason: guest-only glue — materializes keys, force-roots the runtime dirs, and
// fire-and-forget spawns the real sshd process inside the microVM. Not unit
// testable on the host (chown-to-root needs uid 0; the spawn needs the guest);
// `materialize` + `sshd_argv` are unit-tested and the whole path is covered by
// the KVM/WHP e2e.
#[mutants::skip]
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
// reason: chown-to-root side-effect glue — exercising it needs uid 0 and a real
// filesystem (the guest); covered by the KVM/WHP e2e, not host unit tests.
#[mutants::skip]
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

    // ── ssh_session_crun_argv ────────────────────────────────────────────────

    /// Find the value of the `--env` flag whose `K=V` value has key `key`,
    /// e.g. `term_env_value(argv, "TERM")` returns `Some("xterm-256color")`
    /// for an argv containing `["--env", "TERM=xterm-256color"]`. Returns
    /// `None` when no `--env` pair has that key.
    fn env_flag_value<'a>(argv: &'a [String], key: &str) -> Option<&'a str> {
        let prefix = format!("{key}=");
        argv.iter().enumerate().find_map(|(i, a)| {
            if a == "--env" {
                argv.get(i + 1)
                    .and_then(|v| v.strip_prefix(prefix.as_str()))
            } else {
                None
            }
        })
    }

    #[test]
    fn ssh_session_crun_argv_interactive_tty() {
        // tty=true, None (interactive login) → --tty present, ends with
        // ["izba", "/bin/sh"], cwd is SSH_SESSION_CWD.
        let argv =
            ssh_session_crun_argv(crate::oci::CgroupManager::Disabled, true, None, None, false);
        assert_eq!(
            argv.first().map(String::as_str),
            Some(crate::oci::CRUN_PATH)
        );
        // must contain exec subcommand
        assert!(
            argv.iter().any(|a| a == "exec"),
            "argv must contain 'exec': {argv:?}"
        );
        // --tty must be present for interactive sessions
        assert!(
            argv.iter().any(|a| a == "--tty"),
            "--tty must be present for tty=true: {argv:?}"
        );
        // --cwd + /workspace pair
        let cwd_pos = argv.iter().position(|a| a == "--cwd").expect("--cwd");
        assert_eq!(argv[cwd_pos + 1], SSH_SESSION_CWD);
        // container id followed by /bin/sh
        let id_pos = argv
            .iter()
            .position(|a| a == crate::oci::CONTAINER_ID)
            .expect("container id");
        assert_eq!(argv[id_pos + 1], "/bin/sh");
        assert_eq!(argv.len(), id_pos + 2, "interactive: only /bin/sh after id");
    }

    #[test]
    fn ssh_session_crun_argv_command_no_tty() {
        // tty=false, Some("ls -l") → NO --tty, ends with ["izba", "/bin/sh", "-c", "ls -l"]
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            false,
            Some("ls -l"),
            None,
            false,
        );
        assert_eq!(
            argv.first().map(String::as_str),
            Some(crate::oci::CRUN_PATH)
        );
        assert!(
            argv.iter().any(|a| a == "exec"),
            "argv must contain 'exec': {argv:?}"
        );
        // no --tty for pipe sessions
        assert!(
            !argv.iter().any(|a| a == "--tty"),
            "--tty must NOT be present for tty=false: {argv:?}"
        );
        // --cwd /workspace
        let cwd_pos = argv.iter().position(|a| a == "--cwd").expect("--cwd");
        assert_eq!(argv[cwd_pos + 1], SSH_SESSION_CWD);
        // container id followed by /bin/sh -c ls -l
        let id_pos = argv
            .iter()
            .position(|a| a == crate::oci::CONTAINER_ID)
            .expect("container id");
        assert_eq!(&argv[id_pos + 1..], &["/bin/sh", "-c", "ls -l"]);
    }

    #[test]
    fn ssh_session_crun_argv_starts_with_cgroup_manager_flag() {
        // Both cgroup manager variants produce a well-formed crun exec argv.
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            let argv = ssh_session_crun_argv(mgr, false, None, None, false);
            assert_eq!(argv[0], crate::oci::CRUN_PATH);
            assert!(
                argv[1].starts_with("--cgroup-manager="),
                "argv[1] must be --cgroup-manager=...: {argv:?}"
            );
            assert!(argv.iter().any(|a| a == "exec"));
        }
    }

    // ── TERM forwarding (mirrors the `izba exec` server/CLI tty contract) ─────

    #[test]
    fn ssh_session_crun_argv_tty_forwards_term() {
        // tty=true + Some("xterm-256color") → argv carries --env TERM=xterm-256color
        // (sits among the exec options, before the container id).
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            true,
            None,
            Some("xterm-256color"),
            false,
        );
        assert_eq!(
            env_flag_value(&argv, "TERM"),
            Some("xterm-256color"),
            "tty session must forward TERM: {argv:?}"
        );
        // The --env TERM pair must precede the container id positional.
        let env_pos = argv.iter().position(|a| a == "--env").expect("--env");
        let id_pos = argv
            .iter()
            .position(|a| a == crate::oci::CONTAINER_ID)
            .expect("container id");
        assert!(
            env_pos < id_pos,
            "--env must precede the container id: {argv:?}"
        );
    }

    #[test]
    fn ssh_session_crun_argv_tty_forwards_exact_term_value() {
        // A different TERM is forwarded verbatim — proves it is not hardcoded.
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Cgroupfs,
            true,
            None,
            Some("screen-256color"),
            false,
        );
        assert_eq!(env_flag_value(&argv, "TERM"), Some("screen-256color"));
    }

    #[test]
    fn ssh_session_crun_argv_tty_none_term_omits_env() {
        // tty=true but no resolved TERM → no --env TERM= fabricated here; the
        // caller (`ssh_session`) is responsible for supplying the default.
        let argv =
            ssh_session_crun_argv(crate::oci::CgroupManager::Disabled, true, None, None, false);
        assert_eq!(
            env_flag_value(&argv, "TERM"),
            None,
            "no TERM env when term is None: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--env"),
            "no --env at all when term is None: {argv:?}"
        );
    }

    #[test]
    fn ssh_session_crun_argv_no_tty_never_forwards_term() {
        // Non-tty session never gets TERM, even if a term value is passed.
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            false,
            Some("ls"),
            Some("xterm"),
            false,
        );
        assert_eq!(
            env_flag_value(&argv, "TERM"),
            None,
            "non-tty must NOT forward TERM: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--env"),
            "non-tty must have no --env: {argv:?}"
        );
    }

    // ── MITM CA-bundle (trust) forwarding (mirrors `izba exec` build_env_overlay) ─

    #[test]
    fn ssh_session_crun_argv_trust_present_forwards_all_ca_env() {
        // trust_present=true → all six CA-bundle env pairs from
        // trust_env_pairs() are forwarded, with their container-internal paths.
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            true,
            None,
            Some("xterm-256color"),
            true,
        );
        // The two key ones called out by the contract.
        assert_eq!(
            env_flag_value(&argv, "SSL_CERT_FILE"),
            Some("/etc/izba/ca-bundle.pem"),
            "SSL_CERT_FILE must point at the bundle: {argv:?}"
        );
        assert_eq!(
            env_flag_value(&argv, "NODE_EXTRA_CA_CERTS"),
            Some("/etc/izba/ca.pem"),
            "NODE_EXTRA_CA_CERTS must point at the leaf CA pem: {argv:?}"
        );
        // All six, asserted against the canonical source of truth.
        for (key, val) in crate::trust::trust_env_pairs() {
            assert_eq!(
                env_flag_value(&argv, key),
                Some(val),
                "trust env {key} must be forwarded as {val}: {argv:?}"
            );
        }
        // TERM is still forwarded alongside the trust vars.
        assert_eq!(env_flag_value(&argv, "TERM"), Some("xterm-256color"));
    }

    #[test]
    fn ssh_session_crun_argv_trust_absent_forwards_no_ca_env() {
        // trust_present=false → none of the six CA-bundle env vars are present.
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            true,
            None,
            Some("xterm-256color"),
            false,
        );
        for (key, _) in crate::trust::trust_env_pairs() {
            assert_eq!(
                env_flag_value(&argv, key),
                None,
                "trust env {key} must be absent when trust_present=false: {argv:?}"
            );
        }
    }

    #[test]
    fn ssh_session_crun_argv_trust_forwarded_on_non_tty_command() {
        // A non-tty `ssh host git fetch` (no TERM) must STILL get the trust vars:
        // trust forwarding is gated on bundle presence, NOT on tty.
        let argv = ssh_session_crun_argv(
            crate::oci::CgroupManager::Disabled,
            false,
            Some("git fetch"),
            None,
            true,
        );
        // No TERM (non-tty), but all trust vars present.
        assert_eq!(
            env_flag_value(&argv, "TERM"),
            None,
            "non-tty must not forward TERM: {argv:?}"
        );
        for (key, val) in crate::trust::trust_env_pairs() {
            assert_eq!(
                env_flag_value(&argv, key),
                Some(val),
                "trust env {key} must be forwarded even on a non-tty command: {argv:?}"
            );
        }
    }

    #[test]
    fn ssh_trust_bundle_path_is_overlay_rooted_bundle() {
        // The init-visible bundle path is /rootfs + the container-internal path.
        assert_eq!(
            ssh_trust_bundle_path(),
            Path::new("/rootfs/etc/izba/ca-bundle.pem")
        );
    }
}
