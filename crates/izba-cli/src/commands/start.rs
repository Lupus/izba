//! `izba start <name>` — boot an existing, stopped sandbox's VM without
//! exec'ing into it. Symmetric with `izba stop`. Unlike `izba run NAME` it
//! never creates a sandbox and never attaches a shell: it only flips a stopped
//! sandbox to running, after which the user reaches it via `exec`/`ssh`/ports.

use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_core::state::CONFIG_FILE;

/// Verify NAME addresses an existing sandbox, with a friendly error otherwise.
///
/// `start` (unlike `run`) does NOT create: a missing sandbox is a user error,
/// so we resolve it CLI-side and point at the verbs that *do* create, rather
/// than surfacing the daemon's lower-level "no config.json" message.
fn ensure_exists(paths: &Paths, name: &str) -> anyhow::Result<()> {
    sandbox::validate_name(name)?;
    if paths.sandbox_dir(name).join(CONFIG_FILE).is_file() {
        return Ok(());
    }
    bail!(
        "no such sandbox '{name}' — create one first with `izba create` \
         (or `izba run` to create + start + exec in one step)"
    );
}

// reason: connects to a live daemon and boots the VM; e2e-only (daemon_e2e).
// The existence-resolution branch is unit-tested via `ensure_exists`.
#[mutants::skip]
pub fn run(paths: &Paths, name: &str, allow_unconfined: bool) -> anyhow::Result<i32> {
    ensure_exists(paths, name)?;
    if allow_unconfined {
        // Loud, BEFORE start: the user is waiving the host-side jail, so a VM
        // escape would run with their full user privileges.
        eprintln!(
            "⚠️  WARNING: --allow-unconfined set — the VMM will run WITHOUT host-side \
             confinement. A VM escape would run with your full user privileges."
        );
    }
    let mut client = DaemonClient::connect(paths)?;
    match client.request(
        &DaemonRequest::Start {
            name: name.to_string(),
            allow_unconfined,
        },
        &mut |m| eprintln!("{m}"),
    )? {
        DaemonResponse::Ok => Ok(0),
        // `start` is idempotent: already running is exactly the target state.
        DaemonResponse::Error { message } if message.contains("already running") => {
            eprintln!("'{name}' is already running");
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_exists_ok_when_config_present() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        std::fs::write(paths.sandbox_dir("web").join(CONFIG_FILE), "{}").unwrap();
        assert!(ensure_exists(&paths, "web").is_ok());
    }

    #[test]
    fn ensure_exists_errors_helpfully_for_missing_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        let err = ensure_exists(&paths, "ghost").unwrap_err().to_string();
        assert!(err.contains("no such sandbox 'ghost'"), "{err}");
        // Points the user at the create-capable verbs.
        assert!(err.contains("izba create"), "{err}");
        assert!(err.contains("izba run"), "{err}");
    }

    #[test]
    fn ensure_exists_rejects_invalid_name_before_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        // An invalid name fails validation rather than the existence check.
        assert!(ensure_exists(&paths, "../escape").is_err());
    }
}
