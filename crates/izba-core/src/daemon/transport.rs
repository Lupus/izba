//! Daemon socket plumbing. AF_UNIX on both OSes: std on Unix,
//! `uds_windows` on Windows (native AF_UNIX since Win10 1803) — the same
//! strategy as the hybrid-vsock client (`vmm::UdsStream`).

use anyhow::Context;
use std::path::Path;

use crate::paths::Paths;
use crate::vmm::UdsStream;

#[cfg(unix)]
pub type UdsListener = std::os::unix::net::UnixListener;
#[cfg(windows)]
pub type UdsListener = uds_windows::UnixListener;

/// The display version string carried in the hello frame (NOT the
/// compatibility gate — that is the proto version). `IZBA_DAEMON_VERSION`
/// overrides; otherwise the rich `BuildInfo::short()` (`0.1.0 (de57bb5)`).
pub fn daemon_version() -> String {
    version_from(&|k| std::env::var(k).ok())
}

fn version_from(env: &dyn Fn(&str) -> Option<String>) -> String {
    env("IZBA_DAEMON_VERSION").unwrap_or_else(|| crate::build_info::BuildInfo::current().short())
}

/// Create `<data>/daemon/` (0700 on Unix), re-assert its Medium integrity
/// label (Windows), remove any stale socket file, bind the daemon listener
/// (socket reachable only via the 0700 dir).
pub fn bind_socket(paths: &Paths) -> anyhow::Result<UdsListener> {
    bind_socket_with(paths, crate::procmgr::restore_integrity_recursive)
}

/// [`bind_socket`] with the Medium re-assert injected, so the ordering and
/// the fail-closed refusal are host-testable (the real relabel is a Windows
/// no-op elsewhere).
///
/// Why re-assert at all (F-09, #281): on Windows `izbad.sock` is unreachable
/// from the Low-IL confined VMM ONLY because it inherits the implicit Medium
/// label (spike #248: AF_UNIX `connect()` needs write access). New starts can
/// no longer Low-label this dir (`sandbox::check_workspace_spares_control_socket`),
/// but a pre-#281 build could have — an ancestor-of-the-data-root workspace
/// start whose teardown restore was then missed leaves the dir Low, and a
/// socket bound inside it would inherit Low. Re-stamping the inheritable
/// Medium label before every bind makes the barrier hold regardless of what
/// an earlier build left behind; failing to do so refuses to serve.
fn bind_socket_with(
    paths: &Paths,
    reassert_medium: fn(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<UdsListener> {
    let dir = paths.daemon_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    reassert_medium(&dir).with_context(|| {
        format!(
            "re-asserting the Medium integrity label on the izbad control-socket dir {} \
             (F-09: a Low label there would let a confined VMM drive izbad); refusing to \
             bind the daemon socket",
            dir.display()
        )
    })?;
    let sock = paths.daemon_socket();
    remove_stale_socket(&sock);
    UdsListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))
}

/// Best-effort unlink of a leftover socket file (the caller must have
/// verified no daemon is alive — e.g. by holding the daemon flock).
pub fn remove_stale_socket(sock: &Path) {
    let _ = std::fs::remove_file(sock);
}

/// Prepare a sandbox's runtime directory and bind one of its per-sandbox
/// listeners.
///
/// The two guest-facing planes izbad binds per sandbox — egress (vsock 1027,
/// `daemon::egress`) and the USB broker (vsock 1028, `usb::broker`) — arm
/// their listeners identically: create the run dir 0700, re-assert that mode
/// in case the dir pre-existed looser (e.g. `create`'s), unlink a stale socket
/// file left by a previous run, bind, and go non-blocking so the accept loop
/// can poll its stop flag instead of parking in `accept`.
///
/// It lives here, shared, so the two planes' setup cannot drift apart. The
/// 0700 re-assert in particular is easy to lose on one side and not the other,
/// and it is **unix-only**: `paths::create_dir_700` and the chmod below are
/// both `#[cfg(unix)]`, so *this function* sets no permissions at all on
/// Windows and the sockets inherit their parent directory's DACL.
///
/// Be precise about what that does NOT say. izba does touch this directory's
/// security descriptor on Windows — it just never *hardens* it, only ever
/// widens it: `VmSpec::confined_write_surfaces` includes the run dir, so every
/// default start stamps it with an inheritable **Low** mandatory-integrity
/// label (`procmgr::jail_windows`) that the socket files inherit, without
/// which the Low-IL VMM could not write here at all; and `izba lockdown` adds
/// the run dir to `jail_account::orchestrate::compute_grants` so the
/// per-sandbox `izba-sb-<name>` account gets an inheritable Modify ACE on it.
/// Confidentiality from other local users on Windows therefore rests on the
/// inherited `%LOCALAPPDATA%` profile DACL, which izba does not author. That
/// is why each plane's own accept-time gate — not this directory — is what
/// actually decides who may drive it.
///
/// `what` names the plane in the error messages ("egress", "USB").
pub fn bind_sandbox_listener(
    root: &Path,
    run_dir: &Path,
    path: &Path,
    what: &str,
) -> anyhow::Result<UdsListener> {
    crate::paths::create_dir_700(run_dir, root)
        .with_context(|| format!("creating run dir {}", run_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", run_dir.display()))?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing stale {}", path.display())),
    }
    let listener = UdsListener::bind(path)
        .with_context(|| format!("binding {what} listener {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("{what} listener nonblocking"))?;
    Ok(listener)
}

/// Plain connect to the daemon socket (no hello).
pub fn connect_socket(paths: &Paths) -> std::io::Result<UdsStream> {
    UdsStream::connect(paths.daemon_socket())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;

    #[test]
    fn version_default_and_override() {
        let no_env = |_: &str| None;
        // Default is the rich short build string; at minimum it carries the
        // crate semver.
        assert!(version_from(&no_env).starts_with(env!("CARGO_PKG_VERSION")));
        let with_env = |k: &str| (k == "IZBA_DAEMON_VERSION").then(|| "9.9.9-test".to_string());
        assert_eq!(version_from(&with_env), "9.9.9-test");
    }

    /// Real bind — runtime-skips where sandboxes deny bind (project
    /// convention, see `full_connect_via_listener` in vsock.rs).
    #[test]
    fn bind_creates_dir_and_replaces_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.daemon_dir()).unwrap();
        std::fs::write(paths.daemon_socket(), b"stale").unwrap();
        match bind_socket(&paths) {
            Ok(_l) => assert!(paths.daemon_socket().exists()),
            Err(e) => {
                let denied = e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                });
                if denied {
                    eprintln!("SKIP: bind denied in this environment");
                    return;
                }
                panic!("bind_socket failed: {e:#}");
            }
        }
    }

    /// F-09 / #281: a daemon dir left Low-labelled by a pre-#281 build (a
    /// missed teardown restore after an ancestor-workspace start) must be
    /// re-asserted Medium BEFORE the socket is bound, and a failed re-assert
    /// must refuse the bind rather than serve a Low-reachable control plane.
    #[test]
    fn bind_refuses_when_the_medium_reassert_fails_and_never_binds() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        fn failing(_: &Path) -> anyhow::Result<()> {
            anyhow::bail!("label denied")
        }
        let err = bind_socket_with(&paths, failing).expect_err("must refuse");
        let msg = format!("{err:#}");
        assert!(msg.contains("Medium"), "{msg}");
        assert!(msg.contains("F-09"), "{msg}");
        assert!(!paths.daemon_socket().exists(), "socket must not be bound");
    }

    #[test]
    fn bind_reasserts_medium_on_the_daemon_dir_first() {
        use std::sync::Mutex;
        static SEEN: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());
        fn recording(p: &Path) -> anyhow::Result<()> {
            // the dir exists (created first) and the socket is not bound yet
            assert!(p.is_dir());
            assert!(!p.join("izbad.sock").exists());
            SEEN.lock().unwrap().push(p.to_path_buf());
            // Stop here: unit tests never bind listeners (the fail-closed
            // path is what keeps this one from reaching the bind).
            anyhow::bail!("stop before bind")
        }
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        bind_socket_with(&paths, recording).expect_err("recorder stops the bind");
        assert!(!paths.daemon_socket().exists());
        assert_eq!(*SEEN.lock().unwrap(), vec![paths.daemon_dir()]);
    }
}
