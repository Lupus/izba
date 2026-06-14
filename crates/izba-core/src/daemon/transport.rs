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

/// Create `<data>/daemon/` (0700 on Unix), remove any stale socket file,
/// bind the daemon listener (socket reachable only via the 0700 dir).
pub fn bind_socket(paths: &Paths) -> anyhow::Result<UdsListener> {
    let dir = paths.daemon_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    let sock = paths.daemon_socket();
    remove_stale_socket(&sock);
    UdsListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))
}

/// Best-effort unlink of a leftover socket file (the caller must have
/// verified no daemon is alive — e.g. by holding the daemon flock).
pub fn remove_stale_socket(sock: &Path) {
    let _ = std::fs::remove_file(sock);
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
}
