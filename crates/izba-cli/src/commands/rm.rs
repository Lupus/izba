use izba_core::daemon::proto::DaemonRequest;
use izba_core::daemon::DaemonClient;
use izba_core::jail_account::orchestrate::{lockdown_state, unlock, WinBackend};
use izba_core::jail_account::LockdownState;
use izba_core::paths::Paths;

pub fn run(paths: &Paths, name: &str, force: bool) -> anyhow::Result<i32> {
    // Best-effort: if the sandbox is locked down, release the Windows account
    // before deleting the sandbox directory (the account must be deprovisioned
    // via the elevated helper; the state files live inside the sandbox dir).
    if matches!(lockdown_state(paths, name), LockdownState::Locked(_)) {
        if let Err(e) = unlock(&WinBackend, paths, name) {
            eprintln!(
                "izba: warning: failed to release lock-down account for '{name}': {e:#}\n\
                 The Windows account may be orphaned. Run `izba windows-cleanup` to sweep it."
            );
        }
    }

    let mut client = DaemonClient::connect(paths)?;
    let resp = client.request(
        &DaemonRequest::Rm {
            name: name.to_string(),
            force,
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    Ok(0)
}
