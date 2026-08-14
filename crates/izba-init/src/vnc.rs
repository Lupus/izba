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
//!    `crun exec`s the KasmVNC X server and a window manager inside it,
//!    as the image's configured user ([`desktop_exec_argvs`] / [`start_desktop`])
//!    — the same fire-and-forget, no-auto-restart contract as docker mode's engine.
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

/// Address the X server's VNC/websocket endpoint binds to in the DEFAULT
/// (shared-netns) case. Loopback only: the guest has no NIC, and the host
/// reaches the port exclusively through init's vsock `TcpDial` relay, which
/// dials `127.0.0.1` first.
const LISTEN_ADDR: &str = "127.0.0.1";

/// Bind address in docker mode (#216, spec 2026-08-12). A docker-mode
/// sandbox gives the workload its OWN netns (`image/runtime_config.rs` §3),
/// so a loopback listener would sit on the CONTAINER's private loopback,
/// which init cannot dial. The wildcard bind makes the endpoint reachable at
/// `crate::net::GUEST_IP` over the veth pair — exactly where
/// `server::tcp_dial`'s docker-mode fallback dials after loopback refuses
/// (and init's nft output chain already exempts that address from the
/// egress REDIRECT). Binding `GUEST_IP` itself would race `veth::apply`:
/// the address exists only after crun reports `running`, the same window
/// this exec is issued in. Exposure is contained to the container netns
/// (the workload already owns the display outright via `-ac`; nested
/// containers are the same trust zone) and HTTP/ws stays behind BasicAuth.
/// The listening surface is pinned end-to-end by `vnc_docker_e2e`: `:6901`
/// is the ONLY wildcard listener (Xkasmvnc 1.5.0 opens no raw-RFB or
/// X11-TCP port — a real-VM observation, also asserted by
/// `vnc_desktop_e2e`'s listener check).
const LISTEN_ADDR_DOCKER: &str = "0.0.0.0";

/// Initial framebuffer geometry/depth. KasmVNC's dynamic resize is
/// client-driven and stays enabled, so the browser window size wins over
/// this after the first connection.
const GEOMETRY: &str = "1280x800";
const DEPTH: &str = "24";

/// The X server's unix socket for [`DISPLAY`] — what the window manager
/// waits for before connecting (see [`desktop_exec_argvs`]).
const X_SOCKET: &str = "/tmp/.X11-unix/X1";

/// The X server's lock file for [`DISPLAY`] (`/tmp/.X<n>-lock`), holding the
/// pid that owns the display. Removed together with [`X_SOCKET`] before every
/// start — see [`stale_display_cleanup_argv`].
const X_LOCK: &str = "/tmp/.X1-lock";

/// Space-separated izba-owned desktop state a pre-change (root-desktop)
/// boot may have left root-owned in the persistent overlay's `/tmp`,
/// removed by the cleanup exec on every start so the image user can
/// recreate it: the seeded lxpanel/pcmanfm/openbox/libfm profile parents
/// (`izba-session` re-seeds them from the bundle), the generated
/// Applications-menu cache, and the fontconfig cache (path pinned against
/// `hack/build-kasmvnc-erofs.sh`'s fonts.conf by a drift test). Never
/// user state — every entry is regenerated on every desktop start.
///
/// This is a hand-enumerated KNOWN-FATAL-PLUS-KNOWN-DEGRADING set, not an
/// exhaustive inventory of everything a root desktop ever wrote: after the
/// removal pass, [`desktop_dirs_prep_argv`] recreates `/tmp/.X11-unix`,
/// `/tmp/.config`, and `/tmp/.cache` as the image user's OWN directories,
/// so an UNLISTED root-owned leftover under one of them degrades SOFTLY —
/// the owning app warns or falls back (e.g. skips its cache, logs a
/// permission error) on that one unwritable subdir — rather than killing
/// the whole desktop the way the X lock or a root `/tmp/.config/lxpanel`
/// does. Only entries whose root-ownership is fatal (X's own lock/socket,
/// handled separately) or reliably breaks a specific component on every
/// upgraded sandbox belong here; anything merely cosmetic is left for the
/// user-owned parents to shrug off.
const LEGACY_ROOT_STATE: &str = "/tmp/.config/lxpanel /tmp/.config/pcmanfm /tmp/.config/libfm \
     /tmp/.cache/menus /tmp/.cache/openbox /tmp/izba-vnc-fontcache";

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
            format!("{CONTAINER_BUNDLE_DIR}/share:/usr/share:/usr/local/share"),
        ),
        (
            "GDK_PIXBUF_MODULE_FILE".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/lib/gdk-pixbuf/loaders.cache"),
        ),
        ("XDG_MENU_PREFIX".to_string(), "lxde-".to_string()),
        // GLib execs every GAppInfo launch (lxpanel's Run dialog, menu
        // items, pcmanfm open-with) through its `gio-launch-desktop`
        // helper. The helper's default location is a COMPILED-IN multiarch
        // path (`/usr/lib/x86_64-linux-gnu/glib-2.0/…` in the bookworm
        // builder) that belongs to the user's image — which need not ship
        // GLib at all — so without this override the Run dialog dies with
        // `Failed to execute child process "gio-launch-desktop"`. GLib
        // consults this env var before the compiled-in path; the bundle
        // vendors the helper (hack/build-kasmvnc-erofs.sh, drift-pinned).
        (
            "GIO_LAUNCH_DESKTOP".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/libexec/gio-launch-desktop"),
        ),
    ]
}

/// The `crun exec` argv that clears a PREVIOUS boot's X11 leftovers, run to
/// completion before either desktop process is spawned ([`start_desktop`]).
///
/// **This is what made a restarted sandbox's desktop dead on arrival.** The
/// container's `/tmp` is not a tmpfs — it lives in the sandbox's persistent
/// overlay (`rw.img`), so `/tmp/.X1-lock` and `/tmp/.X11-unix/X1` written by
/// the X server of one boot are still there on the next one. `Xkasmvnc` then
/// finds the lock, decides the display is taken and dies with
///
/// ```text
/// Fatal server error:
/// (EE) Server is already active for display 1
/// ```
///
/// X's own staleness check does not save us: it keeps the lock when the pid
/// recorded in it is still alive, and the recorded pid is a LOW one (the
/// display comes up moments after the container does), which the fresh boot's
/// pid namespace has almost certainly handed out again. The failure is
/// therefore reliable, not racy — and invisible to a fresh sandbox, which is
/// all CI ever booted.
///
/// The stale socket is the second half of the same bug: the window manager's
/// wait loop in [`desktop_exec_argvs`] treats the socket's existence as "the
/// server is up", so it would exec against a dead socket and exit with
/// "Failed to open the display".
///
/// Removing both is unconditionally safe here: init calls this exactly once,
/// right after the workload container reaches `running`, and izba's desktop
/// is the only thing that ever owns [`DISPLAY`] in that container. Running it
/// to completion (rather than folding the `rm` into the server script) is
/// what makes the ordering deterministic against the window manager's wait.
///
/// Since the desktop dropped container root (spec 2026-08-13), this exec is
/// also half of the GROUND PREPARATION for an unprivileged desktop — the
/// **remove-only** half. Root's job here is strictly deletion plus the log
/// file: it clears the root-owned desktop state a pre-change boot left in
/// the persistent overlay (without which an upgraded sandbox's desktop is
/// dead on arrival) and pre-creates [`VNC_LOG`] mode 666 (an image uid
/// cannot create files under `/var/log`). It stays `--user 0:0`
/// deliberately: root is what can delete those legacy files. The
/// **create** half — the X socket dir and `/tmp` XDG parents — runs as the
/// image user itself in [`desktop_dirs_prep_argv`], so the desktop OWNS
/// its ground and no world-writable modes are needed.
///
/// Symlink discipline: everything root does by path under the
/// workload-writable `/tmp` is `rm` — and `rm` never dereferences, so a
/// workload-planted `/tmp/.config → /etc` loses the LINK, not the target.
/// Root deliberately runs **no `chmod`/`mkdir` under `/tmp` at all**
/// (the earlier `chmod 1777` design handed the workload a root-run chmod
/// primitive it could aim by racing a symlink swap; creating the dirs as
/// the image user eliminates the primitive instead of narrowing it). The
/// one root write outside `/tmp` is the log under `/var/log`, a
/// root-owned, non-sticky directory in any conventional image, so the
/// workload user cannot plant anything there for `: >`/`chmod 666` to
/// dereference; the `[ ! -L ]` guard covers the unconventional
/// world-writable-`/var/log` image, where the residual check-to-use race
/// is accepted — in-container, single-trust-zone, and no wider than the
/// pre-change ROOT desktop. The same reasoning covers docker+VNC
/// (supported, spec 2026-08-12): everything this exec touches stays
/// inside the workload container itself.
pub fn stale_display_cleanup_argv(cgroup_manager: crate::oci::CgroupManager) -> Vec<String> {
    crate::oci::crun_exec_argv(
        cgroup_manager,
        false,
        "/",
        &[],
        Some("0:0"),
        &[
            "/bin/sh".into(),
            "-c".into(),
            // `rm -f`/`rm -rf` never fail on an absent path, so a first boot
            // is a clean no-op — the removal legs stay `;`-joined so a
            // first-boot no-op can never fail the script. Only the LOG leg
            // is load-bearing creation, so it alone is `&&`-chained: a
            // failed mkdir/create/chmod propagates as a non-zero exit, which
            // `start_desktop` reports via its "cleanup exited {st}"
            // diagnostic, rather than being swallowed the way a trailing
            // `true` would. The log is created empty iff absent (`: >` would
            // truncate an existing one) — grouped in `{ ...; }` so the `||`
            // binds only to the create-if-absent check, not to the `&&`
            // chain around it — then opened up to 666 so the unprivileged
            // desktop can append. The symlink de-linking loop keeps a
            // pre-planted link from surviving into the image user's
            // `mkdir -p` (which would silently follow it); `rm` itself never
            // dereferences, so every root-by-path step under /tmp is safe.
            format!(
                "rm -f {X_LOCK} {X_SOCKET}; \
                 rm -rf {LEGACY_ROOT_STATE}; \
                 for d in /tmp/.X11-unix /tmp/.config /tmp/.cache; do \
                 [ ! -L \"$d\" ] || rm -f \"$d\"; done; \
                 {{ [ ! -L {VNC_LOG} ] || rm -f {VNC_LOG}; }} && \
                 mkdir -p /var/log && \
                 {{ [ -e {VNC_LOG} ] || : > {VNC_LOG}; }} && \
                 chmod 666 {VNC_LOG}"
            ),
        ],
    )
}

/// The `crun exec` argv for the **create** half of the ground preparation:
/// `mkdir -p` of the X socket dir and the `/tmp` XDG parents, run as the
/// **image user** (no `--user`, same selection as [`desktop_exec_argvs`])
/// after [`stale_display_cleanup_argv`] has removed the root-owned
/// leftovers. Creating these as the desktop's own uid is what lets the
/// earlier root-run `chmod 1777` disappear: the user owns its ground
/// outright, nothing under the workload-writable `/tmp` is ever the target
/// of a root `chmod`/`mkdir`, and a workload racing a symlink into place
/// can at worst redirect ITS OWN uid's `mkdir -p` — a no-op privilege-wise,
/// since `mkdir -p` treats any existing directory (followed or not) as
/// success and creates nothing through it that the user could not create
/// directly. On an alpine-style no-`USER` image the configured user is
/// root, which simply recreates today's root-owned dirs. Awaited by
/// [`start_desktop`] before the desktop spawns, like the cleanup.
pub fn desktop_dirs_prep_argv(cgroup_manager: crate::oci::CgroupManager) -> Vec<String> {
    crate::oci::crun_exec_argv(
        cgroup_manager,
        false,
        "/",
        &[],
        None,
        &[
            "/bin/sh".into(),
            "-c".into(),
            "mkdir -p /tmp/.X11-unix /tmp/.config /tmp/.cache".into(),
        ],
    )
}

/// The two `crun exec` argvs that bring up the desktop, in start order:
/// the KasmVNC X server, then the window manager.
///
/// Both run as the **container's configured user** — the OCI spec's
/// `process.user`, which izba-core's `resolve_process_user` filled from the
/// image `USER` (uid, primary gid, supplementary groups). Passing no `--user`
/// is what selects it: crun then applies the container's own process user,
/// exactly like a default `izba exec`. An image with no `USER` (alpine) keeps
/// a root desktop; a `USER agent` image gets its desktop — and everything
/// launched from it — as `agent`, matching exec/ssh (spec 2026-08-13).
/// Ground the desktop needs but cannot create unprivileged (the X socket
/// dir, the log file, the `/tmp` XDG parents) is prepared by the root-run
/// cleanup exec ([`stale_display_cleanup_argv`]), which is awaited first.
///
/// 1. `Xkasmvnc` — flags per the design (spec 2026-08-09 §7). `-publicIP`
///    is pinned to loopback to suppress KasmVNC's WebRTC public-IP lookup,
///    which otherwise makes a real egress request; `-interface` keeps the
///    listener on loopback (the host reaches it only through init's vsock
///    relay). In docker mode the interface is the wildcard instead — see
///    [`LISTEN_ADDR_DOCKER`]. Every data path (`-httpd`/`-fp`/`-xkbdir`)
///    points into the bundle bind. Two further flags are what make the
///    *session* — not just the static page — actually work in a browser;
///    both were missing in the first cut and produced the "page loads,
///    desktop never appears, endless spinner, credential re-prompt" bug:
///    - `-SecurityTypes None`. The X server's default is `VncAuth`, which
///      authenticates the RFB stream against a **separate** legacy
///      `-rfbauth`/`PasswordFile` DES-obfuscated file. izba never writes one
///      (its credential is the `kasmpasswd` BasicAuth hash), so the server
///      offered security type 2 with no password configured: the HTTP GETs
///      all succeeded, the websocket upgraded, and the RFB handshake then
///      dead-ended — the web client sat spinning and re-prompted. Upstream's
///      `kasmvncserver` wrapper avoids this by generating an `-rfbauth` file
///      too; izba instead drops the RFB-level type, because the ONLY gate
///      that means anything here is the HTTP BasicAuth in front of the
///      websocket (which stays on — see `-KasmPasswordFile` below). It is
///      not a weakening: the listener is guest-loopback-only, the host
///      reaches it exclusively through the daemon's authenticated relay, and
///      an in-guest process already owns the display outright via `-ac`.
///    - `-BlacklistThreshold 0` (disable KasmVNC's brute-force lockout).
///      The default blacklists a source IP after 5 unauthenticated requests
///      for `BlacklistTimeout` minutes — and a browser loading this page
///      *always* trips it: HTTP basic auth is a 401-then-retry protocol, and
///      the client page fires ~30 parallel subresource requests, ~10 of
///      which reach the server before the credentials are cached. The
///      counter then locks out **everything**, since every byte arrives from
///      the same guest loopback address (the relay), and the half-loaded
///      page spins forever. Rate-limiting cannot discriminate between
///      attacker and user when all traffic shares one source IP, and there
///      is nothing to rate-limit: the password is a fresh 24-char random
///      string per `start` (`izba_core::vnc::generate_password`).
/// 2. `izba-session` (the bundled script, spec 2026-08-11) — decorations,
///    focus, taskbar and a file-manager desktop, with `DISPLAY` set. It
///    **waits for the X server's socket** before exec'ing: these are two
///    fire-and-forget spawns issued back-to-back, and the script's own
///    `openbox` exits immediately ("cannot open display") if it wins that
///    race, leaving the session with no window manager and no retry (a dead
///    process stays dead). The wait is bounded, uses whole-second `sleep`
///    (busybox `sleep` may not accept fractions), and falls through to the
///    exec on timeout so the failure is still logged honestly. Once the wait
///    clears, `izba-session` backgrounds `pcmanfm --desktop` (desktop icons +
///    file manager) and `lxpanel` (taskbar + Applications menu), then `exec`s
///    `openbox` last so it becomes THIS spawn's session leader — matching the
///    single fire-and-forget, no-auto-restart contract the rest of this
///    module documents: only openbox's death is observed here, pcmanfm/
///    lxpanel are launched and forgotten exactly like their parent.
///
/// Both are wrapped in `sh -c` with output appended to [`VNC_LOG`] — the
/// same shape as `docker::dockerd_exec_argv`.
pub fn desktop_exec_argvs(
    cgroup_manager: crate::oci::CgroupManager,
    docker: bool,
) -> Vec<Vec<String>> {
    let env = vnc_env();
    let listen = if docker {
        LISTEN_ADDR_DOCKER
    } else {
        LISTEN_ADDR
    };
    // INJECTION NOTE (both format! sites below): every substitution here is a
    // compile-time constant. Anything host- or cmdline-derived must be quoted
    // or passed as argv instead — this string is handed to a container-root
    // `sh -c`.
    let server = format!(
        "mkdir -p /var/log; \
         exec {CONTAINER_BUNDLE_DIR}/bin/Xkasmvnc {DISPLAY} \
         -geometry {GEOMETRY} -depth {DEPTH} \
         -interface {listen} -websocketPort {WEBSOCKET_PORT} -publicIP {LISTEN_ADDR} \
         -KasmPasswordFile {SECRETS_DIR}/{KASMPASSWD_FILE} \
         -SecurityTypes None -BlacklistThreshold 0 \
         -httpd {CONTAINER_BUNDLE_DIR}/share/kasmvnc/www \
         -fp {CONTAINER_BUNDLE_DIR}/share/fonts/X11/misc \
         -xkbdir {CONTAINER_BUNDLE_DIR}/share/xkb \
         -ac -noreset >>{VNC_LOG} 2>&1"
    );
    let wm = format!(
        "mkdir -p /var/log; \
         i=0; while [ ! -e {X_SOCKET} ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; \
         exec {CONTAINER_BUNDLE_DIR}/bin/izba-session >>{VNC_LOG} 2>&1"
    );

    let mut wm_env = env.clone();
    wm_env.push(("DISPLAY".to_string(), DISPLAY.to_string()));

    vec![
        crate::oci::crun_exec_argv(
            cgroup_manager,
            false,
            "/",
            &env,
            None,
            &["/bin/sh".into(), "-c".into(), server],
        ),
        crate::oci::crun_exec_argv(
            cgroup_manager,
            false,
            "/",
            &wm_env,
            None,
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
pub fn start_desktop(docker: bool) {
    let cgmgr = crate::oci::detect_cgroup_manager();
    // AWAITED, unlike the two spawns below: the window manager's wait loop
    // keys on the X socket's existence, so a leftover socket must be gone
    // BEFORE it starts looking. See `stale_display_cleanup_argv`.
    // Removal (root) first, then creation (image user): the dirs prep must
    // not run until root has cleared the legacy root-owned parents it is
    // about to recreate as its own uid.
    for (what, argv) in [
        ("stale-display cleanup", stale_display_cleanup_argv(cgmgr)),
        ("dirs prep", desktop_dirs_prep_argv(cgmgr)),
    ] {
        match std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .status()
        {
            Ok(st) if !st.success() => {
                eprintln!("izba-init: vnc {what} exited {st}");
            }
            Err(e) => eprintln!("izba-init: vnc {what} failed: {e}"),
            Ok(_) => {}
        }
    }
    for argv in desktop_exec_argvs(cgmgr, docker) {
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
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs, false);
        assert_eq!(argvs.len(), 2, "server then window manager");
        (
            argvs[0].last().unwrap().clone(),
            argvs[1].last().unwrap().clone(),
        )
    }

    // ── stale_display_cleanup_argv ───────────────────────────────────────────

    #[test]
    fn stale_display_cleanup_removes_the_previous_boots_lock_and_socket() {
        // The regression this pins: the container's /tmp is in the sandbox's
        // PERSISTENT overlay, so a second `start` finds the first boot's
        // /tmp/.X1-lock and Xkasmvnc dies with "Server is already active for
        // display 1" — a dead desktop on every restarted sandbox.
        let argv = stale_display_cleanup_argv(crate::oci::CgroupManager::Cgroupfs);
        let script = argv.last().unwrap();
        assert!(
            script.contains(&format!("rm -f {X_LOCK} {X_SOCKET}")),
            "both the lock and the socket must go: {script}"
        );
        assert!(
            script.contains("rm -f"),
            "an absent path on a first boot must not fail: {script}"
        );
        // The X socket dir is (re)created by the image user's dirs prep,
        // never by this root exec — see desktop_dirs_prep_creates_the_ground.
        assert!(
            !script.contains("mkdir -p /tmp/"),
            "root must not mkdir under the workload-writable /tmp: {script}"
        );
        assert_eq!(argv[0], crate::oci::CRUN_PATH);
        assert!(argv.iter().any(|a| a == "exec"), "{argv:?}");
        assert!(
            argv.windows(2).any(|w| w[0] == "--user" && w[1] == "0:0"),
            "cleanup runs as the same container root that owns the files: {argv:?}"
        );
        let id_pos = argv
            .iter()
            .position(|a| a == crate::oci::CONTAINER_ID)
            .expect("container id");
        assert!(argv.iter().position(|a| a == "--user").unwrap() < id_pos);
    }

    #[test]
    fn stale_display_cleanup_targets_exactly_the_display_the_server_claims() {
        // X derives both paths from the display number, so a change to
        // DISPLAY that misses either constant silently re-opens the bug.
        let n = DISPLAY.trim_start_matches(':');
        assert_eq!(X_LOCK, format!("/tmp/.X{n}-lock"));
        assert_eq!(X_SOCKET, format!("/tmp/.X11-unix/X{n}"));
        let script = stale_display_cleanup_argv(crate::oci::CgroupManager::Disabled)
            .last()
            .unwrap()
            .clone();
        let (_server, wm) = scripts();
        assert!(
            wm.contains(X_SOCKET) && script.contains(X_SOCKET),
            "the wm waits on the very socket the cleanup removes: {wm} / {script}"
        );
    }

    #[test]
    fn desktop_exec_argvs_runs_server_then_wm_as_the_image_user_with_honest_logging() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs, false);
        for argv in &argvs {
            assert_eq!(argv[0], crate::oci::CRUN_PATH);
            assert!(argv.iter().any(|a| a == "exec"), "{argv:?}");
            assert!(
                !argv.iter().any(|a| a == "--user"),
                "desktop must inherit the container's configured user (the image \
                 USER, like a default `izba exec`), never a pinned uid: {argv:?}"
            );
            let _id_pos = argv
                .iter()
                .position(|a| a == crate::oci::CONTAINER_ID)
                .expect("container id");
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
        assert!(
            wm.contains("exec /opt/izba-vnc/bin/izba-session"),
            "spawn 2 must exec the bundled session script (pcmanfm + lxpanel \
             + openbox), not bare openbox: {wm}"
        );
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

    /// Regression pin for the "page loads, desktop never appears" bug: the
    /// browser session only completes when the RFB-level security type is
    /// `None` (the default `VncAuth` needs an `-rfbauth` file izba never
    /// writes, so the handshake dead-ends after a successful websocket
    /// upgrade) AND KasmVNC's brute-force lockout is off (basic auth's
    /// 401-then-retry across ~30 parallel subresource fetches trips the
    /// 5-attempt default, and every request shares one source IP — the
    /// relay's loopback). Both were absent in the first cut, and every probe
    /// at the time stopped at a plain HTTP GET, which passes either way.
    #[test]
    fn server_argv_completes_a_browser_session_without_disabling_basic_auth() {
        let (server, _) = scripts();
        assert!(
            server.contains("-SecurityTypes None"),
            "the RFB handshake must not offer VncAuth — izba configures no \
             -rfbauth password file, so the web client would spin: {server}"
        );
        assert!(
            server.contains("-BlacklistThreshold 0"),
            "KasmVNC's brute-force lockout must be off — a single page load \
             trips it and locks out the loopback the relay dials: {server}"
        );
        // The websocket's BasicAuth gate is what replaces both, so it must
        // never be turned off in the same breath.
        assert!(
            !server.contains("-DisableBasicAuth"),
            "BasicAuth is the ONLY remaining gate in front of the desktop: {server}"
        );
        assert!(server.contains("-KasmPasswordFile"), "{server}");
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
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Disabled, false);
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
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Disabled, false);
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
            // Bundle share FIRST (its menus/icons/mime win), then the
            // image's own share dirs so GUI apps the image ships appear in
            // the Applications menu (spec 2026-08-11 §7).
            assert_eq!(
                env_of(argv, "XDG_DATA_DIRS"),
                Some("/opt/izba-vnc/share:/usr/share:/usr/local/share".to_string())
            );
            // gdk-pixbuf resolves image loaders through this cache; without
            // it GTK2 falls back to builder-image paths that don't exist.
            assert_eq!(
                env_of(argv, "GDK_PIXBUF_MODULE_FILE"),
                Some("/opt/izba-vnc/lib/gdk-pixbuf/loaders.cache".to_string())
            );
            // lxpanel's Applications menu reads lxde-applications.menu via
            // the XDG menu spec prefix.
            assert_eq!(env_of(argv, "XDG_MENU_PREFIX"), Some("lxde-".to_string()));
            // GLib launches EVERY GAppInfo command (lxpanel's Run dialog,
            // menu items, pcmanfm open-with) through its gio-launch-desktop
            // helper, resolved from a compiled-in multiarch path that
            // belongs to the user's IMAGE — which need not ship GLib at all
            // (claude-code-docker does not). Without this override the Run
            // dialog dies with `Failed to execute child process
            // "gio-launch-desktop" (No such file or directory)` on any such
            // image; GLib checks the env var before the compiled-in path.
            assert_eq!(
                env_of(argv, "GIO_LAUNCH_DESKTOP"),
                Some("/opt/izba-vnc/libexec/gio-launch-desktop".to_string())
            );
        }
    }

    /// The wm spawn's wait loop and the session script are two halves of one
    /// contract: the script assumes the X server is already up (it starts
    /// pcmanfm/lxpanel immediately), which is only true because the argv in
    /// front of it waits on the socket.
    #[test]
    fn wm_spawn_waits_for_the_socket_then_execs_the_session_script() {
        let (_server, wm) = scripts();
        assert!(
            wm.contains(X_SOCKET),
            "socket wait must precede the session: {wm}"
        );
        let wait = wm.find(X_SOCKET).unwrap();
        let exec = wm.find("exec /opt/izba-vnc/bin/izba-session").unwrap();
        assert!(wait < exec, "wait must come BEFORE the exec: {wm}");
    }

    #[test]
    fn desktop_exec_argvs_honours_the_cgroup_manager() {
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            for argv in desktop_exec_argvs(mgr, false) {
                assert_eq!(argv[1], format!("--cgroup-manager={}", mgr.as_str()));
            }
        }
    }

    // ── docker mode (#216, spec 2026-08-12) ─────────────────────────────────

    #[test]
    fn docker_mode_binds_the_wildcard_for_the_veth_fallback() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs, true);
        let server = argvs[0].last().unwrap();
        // The container owns its netns: loopback is unreachable from init,
        // and the veth address does not exist yet when this exec is issued
        // (veth::apply runs after `running`), so wildcard is the only bind
        // that cannot race. Reachability rides tcp_dial's GUEST_IP fallback.
        assert!(
            server.contains("-interface 0.0.0.0"),
            "docker mode must bind the wildcard address: {server}"
        );
        // -publicIP is NOT a bind address — it only suppresses KasmVNC's
        // WebRTC public-IP lookup — so it stays pinned to loopback.
        assert!(server.contains("-publicIP 127.0.0.1"), "{server}");
    }

    /// The desktop runs unprivileged (see `desktop_exec_argvs`), and the
    /// ground preparation is split in two: this ROOT exec removes (legacy
    /// root-owned state from pre-change boots, workload-planted symlinks)
    /// and prepares only the log under root-owned `/var/log`; the CREATE
    /// half under the workload-writable `/tmp` belongs to the image user
    /// (`desktop_dirs_prep_creates_the_ground_as_the_image_user`). Root
    /// must never `chmod`/`mkdir` by path under `/tmp` — `chmod`
    /// dereferences, so a workload racing a symlink swap would get a
    /// root-run chmod aimed at an arbitrary in-container target (the
    /// Greptile P1 on this branch's first cut).
    #[test]
    fn stale_display_cleanup_prepares_nonroot_ground() {
        let argv = stale_display_cleanup_argv(crate::oci::CgroupManager::Cgroupfs);
        let script = argv.last().unwrap();
        // Root's only footprint under /tmp is removal — `rm` never
        // dereferences a symlink, `chmod`/`mkdir` do.
        assert!(
            !script.contains("chmod 1777"),
            "no world-writable modes anywhere — the image user owns its \
             ground instead: {script}"
        );
        assert!(
            !script.contains("mkdir -p /tmp/"),
            "root must not mkdir under the workload-writable /tmp: {script}"
        );
        assert!(
            script.contains(&format!("[ -e {VNC_LOG} ] || : > {VNC_LOG}")),
            "the log must exist before an unprivileged writer appends — and an \
             existing log must NOT be truncated: {script}"
        );
        assert!(
            script.contains(&format!("chmod 666 {VNC_LOG}")),
            "any image uid must be able to append to the honest log: {script}"
        );
        assert!(
            script.contains(&format!("rm -rf {LEGACY_ROOT_STATE}")),
            "root-owned desktop state from pre-change boots must go: {script}"
        );
        // The load-bearing log leg must propagate a failure (a trailing
        // `true` would silently swallow it and start_desktop's "cleanup
        // exited {st}" diagnostic would never fire).
        assert!(
            !script.trim_end().ends_with("true"),
            "the cleanup script must not end with a masking `true` — a \
             failed ground-prep step must exit non-zero: {script}"
        );
        assert!(
            script.contains(&format!("&& chmod 666 {VNC_LOG}")),
            "the log-mode step must be &&-chained so a failure propagates: {script}"
        );
        // Pin the individual known-fatal-plus-known-degrading entries, not
        // just the joined constant, so a future trim silently dropping one
        // of them (rather than the constant changing shape entirely) is
        // still caught here.
        for path in [
            "/tmp/.config/lxpanel",
            "/tmp/.config/pcmanfm",
            "/tmp/.config/libfm",
            "/tmp/.cache/menus",
            "/tmp/.cache/openbox",
            "/tmp/izba-vnc-fontcache",
        ] {
            assert!(
                LEGACY_ROOT_STATE.contains(path),
                "LEGACY_ROOT_STATE must enumerate {path}: {LEGACY_ROOT_STATE}"
            );
        }
        // A workload-planted symlink at any dir the image user is about to
        // `mkdir -p` must be removed here (the LINK — `rm` does not
        // dereference), or the user's mkdir would silently follow it.
        let guard = "for d in /tmp/.X11-unix /tmp/.config /tmp/.cache; do \
                     [ ! -L \"$d\" ] || rm -f \"$d\"; done";
        assert!(
            script.contains(guard),
            "the dirs the image user recreates must be de-symlinked first: {script}"
        );
        assert!(
            script.contains(&format!("[ ! -L {VNC_LOG} ] || rm -f {VNC_LOG}")),
            "the log path must be de-symlinked before it is created/chmod'd: {script}"
        );
        // Still container root: it is what deletes root-owned legacy files.
        assert!(
            argv.windows(2).any(|w| w[0] == "--user" && w[1] == "0:0"),
            "cleanup must stay root — it removes root-owned leftovers: {argv:?}"
        );
    }

    /// The CREATE half of the ground prep: the X socket dir and the /tmp
    /// XDG parents are made by the image user itself — user-owned ground
    /// instead of root-chmod'd 1777 dirs, which is what eliminates the
    /// root-chmod-follows-symlink primitive outright. No `--user` = crun
    /// applies the container's configured user, exactly like the desktop
    /// spawns.
    #[test]
    fn desktop_dirs_prep_creates_the_ground_as_the_image_user() {
        let argv = desktop_dirs_prep_argv(crate::oci::CgroupManager::Cgroupfs);
        assert_eq!(argv[0], crate::oci::CRUN_PATH);
        assert!(argv.iter().any(|a| a == "exec"), "{argv:?}");
        assert!(
            !argv.iter().any(|a| a == "--user"),
            "dirs prep must run as the container's configured user — the \
             same identity that will write into them: {argv:?}"
        );
        let script = argv.last().unwrap();
        assert!(
            script.contains("mkdir -p /tmp/.X11-unix /tmp/.config /tmp/.cache"),
            "the X socket dir and XDG parents must be created: {script}"
        );
        assert!(
            !script.contains("chmod"),
            "user-owned dirs need no mode games: {script}"
        );
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            let argv = desktop_dirs_prep_argv(mgr);
            assert_eq!(argv[1], format!("--cgroup-manager={}", mgr.as_str()));
        }
    }

    /// The font cache the cleanup clears must be the path the bundle's
    /// generated fonts.conf actually uses — pinned against
    /// hack/build-kasmvnc-erofs.sh, the single place that writes it.
    #[test]
    fn legacy_font_cache_path_matches_the_bundle_fonts_conf() {
        let sh = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/build-kasmvnc-erofs.sh"
        ))
        .expect("hack/build-kasmvnc-erofs.sh readable from the workspace");
        assert!(
            sh.contains("<cachedir>/tmp/izba-vnc-fontcache</cachedir>"),
            "bundle fonts.conf cachedir moved — update LEGACY_ROOT_STATE too"
        );
        assert!(
            LEGACY_ROOT_STATE.contains("/tmp/izba-vnc-fontcache"),
            "cleanup must clear the bundle's font cache: {LEGACY_ROOT_STATE}"
        );
    }

    /// The GIO_LAUNCH_DESKTOP override in `vnc_env` names a helper the
    /// bundle build must actually stage — both ends pinned, like the font
    /// cache above. Without the helper the env var points at nothing and
    /// the Run dialog fails exactly as it did unfixed.
    #[test]
    fn gio_launch_helper_is_staged_where_vnc_env_points() {
        let sh = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/build-kasmvnc-erofs.sh"
        ))
        .expect("hack/build-kasmvnc-erofs.sh readable from the workspace");
        assert!(
            sh.contains("libexec/gio-launch-desktop"),
            "bundle build must stage the gio-launch-desktop helper at \
             libexec/ — vnc_env's GIO_LAUNCH_DESKTOP points there"
        );
        assert!(
            vnc_env().iter().any(|(k, v)| k == "GIO_LAUNCH_DESKTOP"
                && v == "/opt/izba-vnc/libexec/gio-launch-desktop"),
            "vnc_env must select the bundled helper"
        );
    }

    /// The docker argv must differ from the default argv ONLY in the
    /// `-interface` value (the `egress::output_chain(false)` guard pattern):
    /// any other divergence is silent drift between the two modes.
    #[test]
    fn docker_mode_differs_from_the_default_argv_only_in_the_interface_bind() {
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            let plain = desktop_exec_argvs(mgr, false);
            let docker = desktop_exec_argvs(mgr, true);
            assert_eq!(plain.len(), docker.len());
            for (p, d) in plain.iter().zip(docker.iter()) {
                let rewritten: Vec<String> = p
                    .iter()
                    .map(|a| a.replace("-interface 127.0.0.1", "-interface 0.0.0.0"))
                    .collect();
                assert_eq!(
                    &rewritten, d,
                    "docker argv must differ from the default only in -interface"
                );
            }
        }
    }
}
