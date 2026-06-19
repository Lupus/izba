//! Windows preflight: can a host directory be Low-integrity-relabelled for a
//! confined sandbox? The confined VMM runs at Low integrity, so izba must relabel
//! every write surface (the workspace share, scratch, writable disks) to Low —
//! which needs `WRITE_OWNER` on the object (see `jail_windows::set_low_integrity_
//! recursive`). A folder at the root of a drive grants `WRITE_OWNER` to no one,
//! so the relabel is denied with an opaque `WIN32_ERROR 5`.
//!
//! This is the read-only "can we?" check, kept separate from `jail_windows.rs`'s
//! mutating relabel/token/spawn FFI. It backs both the create-time preflight
//! (`daemon::server::handle_create`) and the start-time guard (the OpenVMM driver
//! runs it before relabelling each surface), so a directory that cannot be
//! secured is reported up front with an actionable fix instead of a raw WIN32
//! error after the sandbox already exists.

use crate::procmgr::confine::workspace_confinement_denied_msg;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

/// `WRITE_OWNER` (winnt.h `0x0008_0000`) — the standard access right required to
/// set an object's mandatory integrity label via `SetNamedSecurityInfoW`.
/// windows-sys only exports the standard-rights constants from un-enabled
/// features, so define it locally (same pattern as `jail_windows`'s local SIDs).
const WRITE_OWNER: u32 = 0x0008_0000;

/// Can the confined (Low-IL) launch relabel `path`? Probe for `WRITE_OWNER`
/// WITHOUT mutating anything by opening a handle that requests exactly that right
/// and closing it. A directory at the **root of a drive** grants this to no one —
/// not even its owner, who gets only implicit `READ_CONTROL` + `WRITE_DAC` — so
/// the open is denied and we return the actionable
/// [`workspace_confinement_denied_msg`].
///
/// Only `ERROR_ACCESS_DENIED` means "not confinable". Any other failure (a
/// transient sharing violation, an exotic path) is NOT a reason to block the
/// sandbox, so it returns `Ok` and lets the real relabel — if it runs — speak for
/// itself.
pub fn ensure_confinable(path: &Path) -> anyhow::Result<()> {
    // SAFETY: linear FFI. The NUL-terminated UTF-16 path outlives the call, and a
    // successfully opened handle is closed before return.
    unsafe {
        let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
        path_w.push(0);
        let h = CreateFileW(
            path_w.as_ptr(),
            WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, // required to obtain a *directory* handle
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            if GetLastError() == ERROR_ACCESS_DENIED {
                anyhow::bail!(workspace_confinement_denied_msg(path, &current_account()));
            }
            // Not an access problem — don't false-block create/start.
            return Ok(());
        }
        CloseHandle(h);
    }
    Ok(())
}

/// The current Windows account (`DOMAIN\user`) to embed in the remedy `icacls`
/// command, so it is copy-pasteable as-is. The daemon/CLI runs as the user, so
/// the `USERDOMAIN`/`USERNAME` env vars name them; `icacls` accepts the
/// `DOMAIN\user` form on both domain-joined and standalone (`COMPUTER\user`)
/// hosts. Falls back to a bare username, then a placeholder, if either is unset.
fn current_account() -> String {
    match (
        std::env::var("USERDOMAIN").ok().filter(|s| !s.is_empty()),
        std::env::var("USERNAME").ok().filter(|s| !s.is_empty()),
    ) {
        (Some(domain), Some(user)) => format!("{domain}\\{user}"),
        (_, Some(user)) => user,
        _ => "<your-username>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `domain\user` of the account running the tests, for icacls grants.
    fn current_user() -> String {
        let out = std::process::Command::new("whoami")
            .output()
            .expect("run whoami");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Re-grant Full Control to `user` (so cleanup can delete) and remove `dir`.
    fn restore_and_remove(dir: &Path, user: &str) {
        let _ = std::process::Command::new("icacls")
            .arg(dir)
            .arg("/grant")
            .arg(format!("{user}:(F)"))
            .status();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Build a directory the test account OWNS but on which it lacks `WRITE_OWNER`
    /// — the exact condition of a folder at a drive root. Strip all inherited
    /// ACEs and grant the owner only Read&Execute via icacls: the owner keeps
    /// implicit `READ_CONTROL`+`WRITE_DAC` but NOT `WRITE_OWNER`, so the relabel
    /// probe is denied. Returns `None` (test skips) if the environment can't
    /// reproduce the denial — e.g. a privileged runner token that bypasses the
    /// DACL — so the suite never false-fails on an unusual account.
    fn make_non_confinable_dir(tag: &str) -> Option<std::path::PathBuf> {
        let dir = std::env::temp_dir().join(format!("izba-noown-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let user = current_user();
        let ok = std::process::Command::new("icacls")
            .arg(&dir)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:(RX)"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        // Confirm the denial actually reproduced before relying on it.
        if ensure_confinable(&dir).is_ok() {
            restore_and_remove(&dir, &user);
            return None;
        }
        Some(dir)
    }

    /// A freshly created profile-temp dir inherits Full Control (hence
    /// `WRITE_OWNER`), so the confinement preflight accepts it.
    #[test]
    fn ensure_confinable_accepts_owned_temp_dir() {
        let dir = std::env::temp_dir().join(format!("izba-confinable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        ensure_confinable(&dir).expect("a profile-temp dir must be confinable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reported bug: a workspace the user owns but cannot relabel (no
    /// `WRITE_OWNER`) must be rejected at preflight with the actionable message,
    /// not the opaque `WIN32_ERROR 5`.
    #[test]
    fn ensure_confinable_rejects_dir_without_write_owner() {
        let Some(dir) = make_non_confinable_dir("ensure") else {
            eprintln!("skipped: environment could not produce a no-WRITE_OWNER dir");
            return;
        };
        let err = ensure_confinable(&dir).expect_err("must reject a non-WRITE_OWNER dir");
        let msg = format!("{err}");
        assert!(msg.contains("Full Control"), "actionable: {msg}");
        assert!(msg.contains("icacls"), "actionable: {msg}");
        restore_and_remove(&dir, &current_user());
    }

    /// `current_account` prefers `DOMAIN\user`; the message must therefore embed
    /// an expanded account (never a `%USERNAME%` literal that PowerShell leaves
    /// unexpanded). Asserted indirectly via the produced message.
    #[test]
    fn denied_message_embeds_expanded_account_not_a_shell_variable() {
        let acct = current_account();
        let msg = workspace_confinement_denied_msg(std::path::Path::new(r"C:\izba-src"), &acct);
        assert!(msg.contains(&acct), "{msg}");
        assert!(!msg.contains("%USERNAME%"), "{msg}");
    }
}
