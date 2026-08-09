//! Guest-side VNC display: credential delivery + desktop auto-start.
//!
//! Three responsibilities, mirroring how `ssh.rs` and `docker.rs` split
//! theirs:
//!
//! 1. **Credentials.** The host writes a `kasmpasswd` hash line into the
//!    per-sandbox `izba-vnc` virtiofs share (`izba_core::vnc`); init mounts
//!    that share read-only at [`SHARE_MOUNT`] and [`materialize`] copies the
//!    file into init-root [`SECRETS_DIR`], which crun binds read-only into
//!    the container at the same path. The plaintext password never leaves
//!    the host.
//! 2. **Auto-start.** Once the workload container is `running`, init
//!    `crun exec`s the KasmVNC X server and a window manager inside it
//!    ([`desktop_exec_argvs`] / [`start_desktop`]) — the same
//!    fire-and-forget, no-auto-restart contract as docker mode's engine.
//! 3. **Discovery.** [`enabled_on_cmdline`] is the single predicate for
//!    "this sandbox booted with a display", used both by PID 1 and by the
//!    (separate-process) SSH login shell, which re-reads `/proc/cmdline`.
//!
//! Everything the KasmVNC session needs lives in the vendored bundle, mounted
//! from an erofs disk at [`BUNDLE_DIR`] and bound into the container at
//! [`CONTAINER_BUNDLE_DIR`] — izba-owned system material, never part of the
//! OCI image.

use std::collections::BTreeMap;
use std::path::Path;

/// virtiofs tag of the read-only VNC credential share izbad attaches
/// per-sandbox (`izba_core::vnc::VNC_SHARE_TAG`). izba-init cannot depend on
/// izba-core, so the literal is pinned on both sides by a drift test.
pub const VNC_TAG: &str = "izba-vnc";

/// Guest mountpoint of the credential share (under the overlay root, like
/// every other optional share — see `mounts::rootfs_mount_plan`).
pub const SHARE_MOUNT: &str = "/rootfs/izba-vnc";

/// Filename of the KasmVNC password-hash file, both in the share and in
/// [`SECRETS_DIR`] (`<user>:$5$kasm$<hash>:wo`, written host-side).
pub const KASMPASSWD_FILE: &str = "kasmpasswd";

/// Init-root mountpoint of the vendored KasmVNC erofs bundle.
///
/// Must equal `izba_core::image::runtime_config::VNC_BUNDLE_SHARED_DIR` — it
/// is the SOURCE of the container's read-only bundle bind. Lives OUTSIDE the
/// `/rootfs` overlay (mirroring the ssh and USB material) so the display
/// stack is never part of the OCI image and cannot be shadowed by anything
/// the workload writes.
pub const BUNDLE_DIR: &str = "/run/izba/vnc";

/// Where the bundle appears INSIDE the container (crun's bind destination,
/// `izba_core::image::runtime_config::VNC_BUNDLE_CONTAINER_DIR`). Every path
/// in [`desktop_exec_argvs`] is container-internal, so they are all rooted
/// here — not at [`BUNDLE_DIR`].
pub const CONTAINER_BUNDLE_DIR: &str = "/opt/izba-vnc";

/// Init-root directory holding the materialized `kasmpasswd`. Bound
/// read-only into the container at the SAME path
/// (`izba_core::image::runtime_config::VNC_SECRETS_{SHARED,CONTAINER}_DIR`),
/// so `-KasmPasswordFile` reads an identical string on both sides.
pub const SECRETS_DIR: &str = "/run/izba/vnc-secrets";

/// In-container log for the auto-started desktop — the honest record when
/// the X server or the window manager dies (no auto-restart, exactly like
/// `docker::ENGINE_LOG`).
pub const VNC_LOG: &str = "/var/log/izba-vnc.log";

/// The X display the session runs on; also what `izba exec`/ssh sessions get
/// as `DISPLAY` so GUI apps land on the desktop.
pub const DISPLAY: &str = ":1";

/// The guest-loopback port KasmVNC's websocket/HTTP endpoint listens on.
///
/// Must equal `izba_core::vnc::WEBSOCKET_PORT`: the host reaches it through
/// izbad's ephemeral VNC relay (`StreamOpen::TcpDial{port}`) and the inspect
/// liveness probe. Both ends move together; pinned by a drift test here and
/// in izba-core.
pub const WEBSOCKET_PORT: u16 = 6901;

/// Address the X server's VNC/websocket endpoint binds to. Loopback only:
/// the guest has no NIC, and the host reaches the port exclusively through
/// init's vsock `TcpDial` relay, which dials `127.0.0.1`.
///
/// **KNOWN GAP — docker mode + VNC is not reachable (not fixed here).** Every
/// other sandbox shares init's network namespace, so the container's
/// `127.0.0.1` IS init's and `server::tcp_dial`'s first attempt lands on this
/// listener. A docker-mode sandbox instead gives the workload its OWN netns
/// (`image/runtime_config.rs` §3), reached only over the veth pair: this
/// listener then sits on the CONTAINER's private loopback, which init cannot
/// dial, and `tcp_dial`'s docker-mode fallback to [`crate::net::GUEST_IP`]
/// finds nothing because the server is not bound there. The relay and the
/// daemon's liveness probe therefore both fail for `--docker --vnc`, which
/// izba-core does not currently refuse. Fixing it means binding the wildcard
/// address in docker mode (the container's netns is not shared with anything
/// else, so the exposure is contained) — a deliberate follow-up, since it
/// changes the listener's exposure and belongs with a docker+vnc e2e.
const LISTEN_ADDR: &str = "127.0.0.1";

/// Initial framebuffer geometry/depth. KasmVNC's dynamic resize is
/// client-driven and stays enabled, so the browser window size wins over
/// this after the first connection.
const GEOMETRY: &str = "1280x800";
const DEPTH: &str = "24";

/// The X server's unix socket for [`DISPLAY`] — what the window manager
/// waits for before connecting (see [`desktop_exec_argvs`]).
const X_SOCKET: &str = "/tmp/.X11-unix/X1";

/// The conventional system `PATH`, appended after the bundle's `bin` (see
/// [`vnc_env`]).
const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Whether the host declared a VNC display for this sandbox.
///
/// Host-authoritative like `izba.usb` / `izba.docker`: the flag rides the
/// kernel command line, which only izbad writes. The exact-`"1"` comparison
/// matters because the cmdline also carries VALUED neighbours
/// (`izba.uidmap=<triples>`, `izba.gidmap=`, `izba.volumes=…`), so a mere
/// key-presence test would be wrong for any future `izba.vnc=0`.
pub fn enabled_on_cmdline(params: &BTreeMap<String, String>) -> bool {
    params.get("izba.vnc").map(|v| v == "1").unwrap_or(false)
}

/// Materialize the KasmVNC password hash from `share_dir` into `secrets_dir`.
///
/// Mirrors [`crate::ssh::materialize`] with one deliberate difference: the
/// destination directory is created **unconditionally**, even when the share
/// carries no `kasmpasswd`. `secrets_dir` is the SOURCE of an OCI bind mount
/// authored host-side for every `vnc: true` sandbox, and crun fails a
/// container start outright when a bind source does not exist — so a missing
/// hash file must degrade to "the server rejects every login", not to "the
/// workload container never starts".
///
/// Permissions: `secrets_dir` 0755 and the hash file 0644 — deliberately
/// world-readable, unlike ssh's 0700/0600. The file holds a HASH, never the
/// plaintext, and it is read from inside the container by a process whose
/// uid does not (and must not) match init's: in docker mode guest-uid 0 is
/// not even mapped into the container's user namespace, so the "other"
/// permission bits are the only ones that can grant the read.
///
/// Returns `Ok(false)` when the share has no `kasmpasswd` (share not
/// attached / partial delivery); all filesystem side-effects stay confined
/// to `secrets_dir`.
pub fn materialize(share_dir: &Path, secrets_dir: &Path) -> std::io::Result<bool> {
    // Always present the bind source, even with nothing to put in it.
    std::fs::create_dir_all(secrets_dir)?;
    set_permissions(secrets_dir, 0o755)?;

    let src = share_dir.join(KASMPASSWD_FILE);
    if !src.exists() {
        return Ok(false);
    }
    let dst = secrets_dir.join(KASMPASSWD_FILE);
    std::fs::copy(&src, &dst)?;
    set_permissions(&dst, 0o644)?;
    Ok(true)
}

/// The container-internal environment both desktop processes run with.
///
/// Everything points into the bundle so the session never depends on the
/// image shipping X11 data of its own: `FONTCONFIG_PATH` for the bundle's
/// `fonts.conf` (which itself points at the bundle font dirs and a `/tmp`
/// cache), the XDG dirs for openbox's config/themes, and `HOME=/tmp`
/// because the image's user may have no writable home at all.
///
/// `PATH` puts the bundle's `bin` FIRST, then the standard system dirs. This
/// is the one env var that exists for the workload's benefit rather than the
/// server's: openbox's default root menu launches a terminal by NAME
/// (`x-terminal-emulator`, `xterm`), and the bundle ships `xterm` — so
/// without this the menu is dead on any image that does not carry its own
/// terminal, which is most of them. The system dirs stay after it so an
/// image's own tools still win for everything the bundle does not provide.
/// (Overriding `PATH` is safe here in a way it is NOT for `izba exec`, where
/// `build_env_overlay` deliberately leaves `PATH` to the image: these two
/// processes are izba's own, not the user's command.)
fn vnc_env() -> Vec<(String, String)> {
    vec![
        ("HOME".to_string(), "/tmp".to_string()),
        (
            "PATH".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/bin:{SYSTEM_PATH}"),
        ),
        (
            "FONTCONFIG_PATH".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/etc/fonts"),
        ),
        (
            "XDG_CONFIG_DIRS".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/etc"),
        ),
        (
            "XDG_DATA_DIRS".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/share"),
        ),
    ]
}

/// The two `crun exec` argvs that bring up the desktop, in start order:
/// the KasmVNC X server, then the window manager.
///
/// Both run as **container root** (`--user 0:0`, the dockerd precedent):
/// container-0 is a mapped, unprivileged guest uid, and running as a single
/// known user sidesteps ownership questions around the X socket, the
/// `/tmp` cache dirs and the password file.
///
/// 1. `Xkasmvnc` — flags per the design (spec 2026-08-09 §7). `-publicIP`
///    is pinned to loopback to suppress KasmVNC's WebRTC public-IP lookup,
///    which otherwise makes a real egress request; `-interface` keeps the
///    listener on loopback (the host reaches it only through init's vsock
///    relay); every data path (`-httpd`/`-fp`/`-xkbdir`) points into the
///    bundle bind.
/// 2. `openbox` — decorations/focus, with `DISPLAY` set. It **waits for the
///    X server's socket** before exec'ing: these are two fire-and-forget
///    spawns issued back-to-back, and openbox exits immediately ("cannot
///    open display") if it wins that race, leaving the session with no
///    window manager and no retry (a dead process stays dead). The wait is
///    bounded, uses whole-second `sleep` (busybox `sleep` may not accept
///    fractions), and falls through to the exec on timeout so the failure is
///    still logged honestly.
///
/// Both are wrapped in `sh -c` with output appended to [`VNC_LOG`] — the
/// same shape as `docker::dockerd_exec_argv`.
pub fn desktop_exec_argvs(cgroup_manager: crate::oci::CgroupManager) -> Vec<Vec<String>> {
    let env = vnc_env();
    // INJECTION NOTE (both format! sites below): every substitution here is a
    // compile-time constant. Anything host- or cmdline-derived must be quoted
    // or passed as argv instead — this string is handed to a container-root
    // `sh -c`.
    let server = format!(
        "mkdir -p /var/log; \
         exec {CONTAINER_BUNDLE_DIR}/bin/Xkasmvnc {DISPLAY} \
         -geometry {GEOMETRY} -depth {DEPTH} \
         -interface {LISTEN_ADDR} -websocketPort {WEBSOCKET_PORT} -publicIP {LISTEN_ADDR} \
         -KasmPasswordFile {SECRETS_DIR}/{KASMPASSWD_FILE} \
         -httpd {CONTAINER_BUNDLE_DIR}/share/kasmvnc/www \
         -fp {CONTAINER_BUNDLE_DIR}/share/fonts/X11/misc \
         -xkbdir {CONTAINER_BUNDLE_DIR}/share/xkb \
         -ac -noreset >>{VNC_LOG} 2>&1"
    );
    let wm = format!(
        "mkdir -p /var/log; \
         i=0; while [ ! -e {X_SOCKET} ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; \
         exec {CONTAINER_BUNDLE_DIR}/bin/openbox >>{VNC_LOG} 2>&1"
    );

    let mut wm_env = env.clone();
    wm_env.push(("DISPLAY".to_string(), DISPLAY.to_string()));

    vec![
        crate::oci::crun_exec_argv(
            cgroup_manager,
            false,
            "/",
            &env,
            Some("0:0"),
            &["/bin/sh".into(), "-c".into(), server],
        ),
        crate::oci::crun_exec_argv(
            cgroup_manager,
            false,
            "/",
            &wm_env,
            Some("0:0"),
            &["/bin/sh".into(), "-c".into(), wm],
        ),
    ]
}

/// Spawn the desktop fire-and-forget (`Command::spawn` is non-blocking, like
/// every exec in `exec.rs`; the caller does not wait). A dead X server or
/// window manager stays dead — no auto-restart, same policy as docker mode's
/// engine; [`VNC_LOG`] and the inspect liveness probe report it honestly.
// reason: forks a live /sbin/crun against the running container — guest-only;
// the argvs it spawns are unit-tested via desktop_exec_argvs.
#[mutants::skip]
pub fn start_desktop() {
    let cgmgr = crate::oci::detect_cgroup_manager();
    for argv in desktop_exec_argvs(cgmgr) {
        if let Err(e) = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .spawn()
        {
            eprintln!("izba-init: vnc desktop spawn failed: {e}");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── drift pins vs izba-core (the two crates cannot share a constant) ──────

    #[test]
    fn guest_paths_and_port_match_the_izba_core_literals() {
        // izba-core authors the OCI binds and the relay target; izba-init
        // mounts/serves them. Neither crate can import the other's constant,
        // so both pin the literal (izba-core side: image::runtime_config's
        // VNC_BUNDLE_SHARED_DIR / VNC_SECRETS_SHARED_DIR / VNC_BUNDLE_
        // CONTAINER_DIR and vnc::WEBSOCKET_PORT / VNC_SHARE_TAG).
        assert_eq!(BUNDLE_DIR, "/run/izba/vnc");
        assert_eq!(CONTAINER_BUNDLE_DIR, "/opt/izba-vnc");
        assert_eq!(SECRETS_DIR, "/run/izba/vnc-secrets");
        assert_eq!(WEBSOCKET_PORT, 6901);
        assert_eq!(VNC_TAG, "izba-vnc");
    }

    // ── enabled_on_cmdline ───────────────────────────────────────────────────

    #[test]
    fn vnc_is_enabled_only_by_an_exact_one() {
        let p = |s: &str| crate::cmdline::parse(s);
        assert!(enabled_on_cmdline(&p("izba.vnc=1")));
        assert!(!enabled_on_cmdline(&p("izba.vnc=0")));
        assert!(!enabled_on_cmdline(&p("izba.vnc")));
        assert!(!enabled_on_cmdline(&p("console=ttyS0")));
    }

    /// Regression guard for the post-#210 cmdline shape: `izba.vnc=1` is
    /// appended LAST, directly after the idmap triples, whose values contain
    /// `:` and `,` separators. A parser that mis-split those would swallow
    /// the flag.
    #[test]
    fn vnc_flag_parses_adjacent_to_valued_idmap_neighbours() {
        let m = crate::cmdline::parse(
            "console=ttyS0 izba.hostname=web izba.volumes=/data,/cache \
             izba.uidmap=0:2097152:1000,1000:1000:1 izba.gidmap=0:2097152:1048576 \
             izba.wsidmap=1 izba.docker=1 izba.vnc=1",
        );
        assert!(enabled_on_cmdline(&m));
        // The neighbours survive intact — proving the adjacency is real and
        // not an artifact of a truncated cmdline.
        assert_eq!(m["izba.uidmap"], "0:2097152:1000,1000:1000:1");
        assert_eq!(m["izba.wsidmap"], "1");
        assert_eq!(m["izba.volumes"], "/data,/cache");
    }

    // ── materialize ──────────────────────────────────────────────────────────

    #[test]
    fn materialize_copies_the_hash_and_reports_an_absent_share() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("share");
        let secrets = tmp.path().join("secrets");
        std::fs::create_dir_all(&share).unwrap();

        // No kasmpasswd in the share → false, and NOTHING copied.
        assert!(!materialize(&share, &secrets).unwrap());
        assert!(!secrets.join(KASMPASSWD_FILE).exists());

        std::fs::write(share.join(KASMPASSWD_FILE), b"izba:$5$kasm$abc:wo\n").unwrap();
        assert!(materialize(&share, &secrets).unwrap());
        assert_eq!(
            std::fs::read(secrets.join(KASMPASSWD_FILE)).unwrap(),
            b"izba:$5$kasm$abc:wo\n"
        );
    }

    /// The secrets dir is an OCI bind SOURCE: crun fails the whole container
    /// start when it is missing, so it must exist even when the share
    /// delivered nothing.
    #[test]
    fn materialize_creates_the_bind_source_dir_even_without_a_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("share");
        let secrets = tmp.path().join("secrets");
        std::fs::create_dir_all(&share).unwrap();
        assert!(!materialize(&share, &secrets).unwrap());
        assert!(
            secrets.is_dir(),
            "secrets dir must exist as the container's bind source"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialized_hash_is_0644_in_a_0755_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (share, secrets) = (tmp.path().join("s"), tmp.path().join("r"));
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(share.join(KASMPASSWD_FILE), b"izba:x:wo\n").unwrap();
        materialize(&share, &secrets).unwrap();
        // World-readable on purpose: the reader is container-root, whose
        // guest uid differs from init's (and is unmapped in docker mode).
        assert_eq!(
            std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(secrets.join(KASMPASSWD_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    /// `set_permissions` must be observed FORCING the mode, not merely
    /// coinciding with it: `materialized_hash_is_0644_in_a_0755_dir` above
    /// creates its source file/dir the plain way, so under a common CI/dev
    /// umask of 022 both `create_dir_all` and `std::fs::copy` already land on
    /// 0755/0644 by default — making a `replace set_permissions -> Ok(())`
    /// mutant indistinguishable from the real body. Pre-create the path with
    /// an explicit, DIFFERENT mode and assert `set_permissions` actually
    /// changes it, independent of umask or `fs::copy`'s permission-preserving
    /// behavior.
    #[cfg(unix)]
    #[test]
    fn set_permissions_forces_the_mode_regardless_of_prior_state() {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();

        let dir = tmp.path().join("d");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "precondition: dir created restrictively"
        );
        set_permissions(&dir, 0o755).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "set_permissions must force the dir mode to 0755"
        );

        let file = tmp.path().join("f");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600,
            "precondition: file created restrictively"
        );
        set_permissions(&file, 0o644).unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644,
            "set_permissions must force the file mode to 0644"
        );
    }

    // ── desktop_exec_argvs ───────────────────────────────────────────────────

    fn scripts() -> (String, String) {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs);
        assert_eq!(argvs.len(), 2, "server then window manager");
        (
            argvs[0].last().unwrap().clone(),
            argvs[1].last().unwrap().clone(),
        )
    }

    #[test]
    fn desktop_exec_argvs_runs_server_then_wm_as_root_with_honest_logging() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs);
        for argv in &argvs {
            assert_eq!(argv[0], crate::oci::CRUN_PATH);
            assert!(argv.iter().any(|a| a == "exec"), "{argv:?}");
            assert!(
                argv.windows(2).any(|w| w[0] == "--user" && w[1] == "0:0"),
                "desktop runs as container root: {argv:?}"
            );
            // Options must precede the positional container id (crun's parser).
            let id_pos = argv
                .iter()
                .position(|a| a == crate::oci::CONTAINER_ID)
                .expect("container id");
            assert!(argv.iter().position(|a| a == "--user").unwrap() < id_pos);
            assert!(
                argv.last().unwrap().contains(VNC_LOG),
                "output must land in the honest log: {argv:?}"
            );
        }
        let (server, wm) = scripts();
        assert!(
            server.contains("exec /opt/izba-vnc/bin/Xkasmvnc"),
            "{server}"
        );
        assert!(wm.contains("exec /opt/izba-vnc/bin/openbox"), "{wm}");
    }

    #[test]
    fn server_argv_pins_the_loopback_listener_and_the_relay_port() {
        let (server, _) = scripts();
        // The relay + liveness probe dial 127.0.0.1:6901 — both halves of
        // that contract are in this one string.
        assert!(
            server.contains("-interface 127.0.0.1"),
            "listener must stay on loopback: {server}"
        );
        assert!(
            server.contains(&format!("-websocketPort {WEBSOCKET_PORT}")),
            "{server}"
        );
        // -publicIP pins off KasmVNC's WebRTC public-IP lookup, which would
        // otherwise make a real egress request from the guest.
        assert!(server.contains("-publicIP 127.0.0.1"), "{server}");
    }

    #[test]
    fn server_argv_reads_the_materialized_password_file() {
        let (server, _) = scripts();
        assert!(
            server.contains("-KasmPasswordFile /run/izba/vnc-secrets/kasmpasswd"),
            "the hash file materialize() wrote is what the server authenticates against: {server}"
        );
    }

    #[test]
    fn server_argv_points_every_data_path_into_the_bundle() {
        let (server, _) = scripts();
        for want in [
            "-httpd /opt/izba-vnc/share/kasmvnc/www",
            "-fp /opt/izba-vnc/share/fonts/X11/misc",
            "-xkbdir /opt/izba-vnc/share/xkb",
        ] {
            assert!(server.contains(want), "missing {want}: {server}");
        }
        assert!(
            server.contains(&format!("-geometry {GEOMETRY}")),
            "{server}"
        );
        assert!(server.contains(&format!("-depth {DEPTH}")), "{server}");
        assert!(server.contains("-ac"), "{server}");
        assert!(server.contains("-noreset"), "{server}");
        assert!(
            server.contains(&format!("Xkasmvnc {DISPLAY} ")),
            "server must own display {DISPLAY}: {server}"
        );
    }

    #[test]
    fn window_manager_gets_display_and_waits_for_the_x_socket() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Disabled);
        let wm = &argvs[1];
        assert!(
            wm.windows(2)
                .any(|w| w[0] == "--env" && w[1] == format!("DISPLAY={DISPLAY}")),
            "window manager needs DISPLAY: {wm:?}"
        );
        let script = wm.last().unwrap();
        assert!(
            script.contains(X_SOCKET),
            "wm must wait for the X socket before exec'ing (it gets no retry): {script}"
        );
        assert!(
            script.contains("sleep 1"),
            "whole-second sleep (busybox may reject fractions): {script}"
        );
        // The SERVER must not wait for its own socket.
        assert!(!argvs[0].last().unwrap().contains(X_SOCKET));
    }

    #[test]
    fn the_server_does_not_get_display_but_both_get_the_bundle_env() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Disabled);
        let env_of = |argv: &Vec<String>, key: &str| -> Option<String> {
            let prefix = format!("{key}=");
            argv.iter().enumerate().find_map(|(i, a)| {
                (a == "--env")
                    .then(|| argv.get(i + 1))
                    .flatten()
                    .and_then(|v| v.strip_prefix(prefix.as_str()))
                    .map(str::to_string)
            })
        };
        // The X server creates the display; it must not be told to connect
        // to one (a stale DISPLAY in its env would only confuse child procs).
        assert_eq!(env_of(&argvs[0], "DISPLAY"), None);
        assert_eq!(env_of(&argvs[1], "DISPLAY"), Some(DISPLAY.to_string()));
        for argv in &argvs {
            assert_eq!(env_of(argv, "HOME"), Some("/tmp".to_string()));
            // Bundle bin FIRST so openbox's default menu (which launches a
            // terminal by NAME) finds the bundled xterm on an image that
            // ships none; system dirs still follow it.
            let path = env_of(argv, "PATH").expect("PATH must be set");
            assert!(
                path.starts_with("/opt/izba-vnc/bin:"),
                "bundle bin must come first: {path}"
            );
            assert!(path.ends_with(SYSTEM_PATH), "{path}");
            for dir in ["/usr/bin", "/bin"] {
                assert!(path.split(':').any(|p| p == dir), "missing {dir}: {path}");
            }
            assert_eq!(
                env_of(argv, "FONTCONFIG_PATH"),
                Some("/opt/izba-vnc/etc/fonts".to_string())
            );
            assert_eq!(
                env_of(argv, "XDG_CONFIG_DIRS"),
                Some("/opt/izba-vnc/etc".to_string())
            );
            assert_eq!(
                env_of(argv, "XDG_DATA_DIRS"),
                Some("/opt/izba-vnc/share".to_string())
            );
        }
    }

    #[test]
    fn desktop_exec_argvs_honours_the_cgroup_manager() {
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            for argv in desktop_exec_argvs(mgr) {
                assert_eq!(argv[1], format!("--cgroup-manager={}", mgr.as_str()));
            }
        }
    }
}
