//! Windows sign-in screen visibility control for per-sandbox local accounts.
//!
//! The `SpecialAccounts\UserList` registry key under `HKLM\…\Winlogon` controls
//! which accounts are hidden from the interactive sign-in screen (and from the
//! Welcome screen / fast-user-switching UI). Setting a DWORD value named after
//! the account to `0` hides it; deleting the value restores normal visibility.
//!
//! On non-Windows every public function returns `Err("windows-only")`.

// ── Pure helpers (all platforms) ────────────────────────────────────────────

/// The registry key path under `HKEY_LOCAL_MACHINE` that controls account
/// visibility on the Windows sign-in screen.
///
/// Setting a DWORD value named after a local account to `0` under this key
/// hides that account from the interactive logon UI.
pub fn userlist_key_path() -> &'static str {
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
        HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_CREATE_KEY_DISPOSITION, REG_DWORD,
        REG_OPTION_NON_VOLATILE,
    };

    /// Hide `name` from the Windows sign-in screen by setting
    /// `HKLM\…\UserList\<name> = DWORD 0`.
    ///
    /// The key is created if it does not yet exist (first account on the
    /// machine). The handle is closed on all exit paths.
    pub fn hide(name: &str) -> Result<(), String> {
        // SAFETY: RegCreateKeyExW + RegSetValueExW with a NUL-terminated key
        // path and value name. All pointers point into local Vecs that outlive
        // the call; the HKEY is closed on every exit path.
        unsafe {
            let key_path_w: Vec<u16> = super::userlist_key_path()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut hkey = std::ptr::null_mut();
            let mut disposition: REG_CREATE_KEY_DISPOSITION = 0;
            let rc = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path_w.as_ptr(),
                0,                       // Reserved
                std::ptr::null_mut(),    // Class
                REG_OPTION_NON_VOLATILE, // Options
                KEY_SET_VALUE,           // samDesired
                std::ptr::null(),        // lpSecurityAttributes
                &mut hkey,
                &mut disposition,
            );
            if rc != ERROR_SUCCESS {
                return Err(format!("RegCreateKeyExW(UserList): WIN32_ERROR {rc}"));
            }

            // From here, `hkey` must be closed on every exit path.
            let result = {
                let value_name_w: Vec<u16> =
                    name.encode_utf16().chain(std::iter::once(0)).collect();
                let dword_zero: u32 = 0u32;
                let rc = RegSetValueExW(
                    hkey,
                    value_name_w.as_ptr(),
                    0, // Reserved
                    REG_DWORD,
                    &dword_zero as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as u32,
                );
                if rc != ERROR_SUCCESS {
                    Err(format!(
                        "RegSetValueExW(UserList, {name:?}): WIN32_ERROR {rc}"
                    ))
                } else {
                    Ok(())
                }
            };

            RegCloseKey(hkey);
            result
        }
    }

    /// Remove the `<name>` value from the UserList key, making the account
    /// visible on the sign-in screen again.
    ///
    /// Idempotent: if the value does not exist, or the key itself is absent,
    /// this function returns `Ok(())`.
    pub fn unhide(name: &str) -> Result<(), String> {
        // SAFETY: RegOpenKeyExW + RegDeleteValueW with NUL-terminated key/value
        // paths. All pointers are into local Vecs that outlive the call;
        // the HKEY (if opened) is closed on every exit path.
        unsafe {
            let key_path_w: Vec<u16> = super::userlist_key_path()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut hkey = std::ptr::null_mut();
            let rc = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path_w.as_ptr(),
                0,             // ulOptions
                KEY_SET_VALUE, // samDesired
                &mut hkey,
            );
            if rc == ERROR_FILE_NOT_FOUND {
                // Key does not exist — account was never hidden; treat as Ok.
                return Ok(());
            }
            if rc != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyExW(UserList): WIN32_ERROR {rc}"));
            }

            // From here, `hkey` must be closed on every exit path.
            let result = {
                let value_name_w: Vec<u16> =
                    name.encode_utf16().chain(std::iter::once(0)).collect();
                let rc = RegDeleteValueW(hkey, value_name_w.as_ptr());
                if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
                    // Success or value was never set — both are idempotent Ok.
                    Ok(())
                } else {
                    Err(format!(
                        "RegDeleteValueW(UserList, {name:?}): WIN32_ERROR {rc}"
                    ))
                }
            };

            RegCloseKey(hkey);
            result
        }
    }
}

// ── Public surface (re-export from win mod on Windows, stubs elsewhere) ──────

/// Hide `name` from the Windows sign-in screen by writing
/// `HKLM\…\UserList\<name> = DWORD 0`.
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(windows)]
pub fn hide(name: &str) -> Result<(), String> {
    win::hide(name)
}

/// Hide `name` from the Windows sign-in screen.
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(not(windows))]
pub fn hide(_name: &str) -> Result<(), String> {
    Err("windows-only".into())
}

/// Remove the `<name>` sign-in-screen suppression (idempotent).
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(windows)]
pub fn unhide(name: &str) -> Result<(), String> {
    win::unhide(name)
}

/// Remove the `<name>` sign-in-screen suppression (idempotent).
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(not(windows))]
pub fn unhide(_name: &str) -> Result<(), String> {
    Err("windows-only".into())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure key-path test (all platforms) ──────────────────────────────────

    #[test]
    fn userlist_key_path_exact() {
        assert_eq!(
            userlist_key_path(),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        );
    }

    // ── Windows FFI round-trip (elevation-gated) ─────────────────────────────

    /// Hide → unhide round-trip under the real UserList key. Skips unless the
    /// process is running elevated on Windows (registry write to HKLM requires
    /// administrator rights). Mirror of the `account_create_lookup_delete_roundtrip`
    /// elevation-probe pattern in `account.rs`.
    #[cfg(windows)]
    #[test]
    fn hide_unhide_roundtrip_userlist() {
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        };

        // Elevation probe: try to open the UserList key with write access.
        // An un-elevated process gets ERROR_ACCESS_DENIED (5u32).
        const ERROR_ACCESS_DENIED: u32 = 5;
        let key_path_w: Vec<u16> = userlist_key_path()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let probe = unsafe {
            let mut hkey = std::ptr::null_mut();
            let rc = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path_w.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            );
            if rc == ERROR_SUCCESS {
                RegCloseKey(hkey);
            }
            rc
        };

        if probe == ERROR_ACCESS_DENIED || probe == ERROR_FILE_NOT_FOUND {
            eprintln!("hide_unhide_roundtrip_userlist: not elevated or key absent, skipping");
            return;
        }

        // Use a name that is unlikely to collide with real accounts.
        let name = format!("izba-test-{}", std::process::id());

        // Ensure the value does not exist before we start.
        let _ = unhide(&name);

        // hide: must succeed and the value must exist.
        hide(&name).expect("hide should succeed when elevated");

        // Verify the DWORD value is present and equals 0.
        let found = unsafe {
            let key_path_w: Vec<u16> = userlist_key_path()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut hkey = std::ptr::null_mut();
            let rc = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path_w.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            );
            if rc != ERROR_SUCCESS {
                false
            } else {
                let value_name_w: Vec<u16> =
                    name.encode_utf16().chain(std::iter::once(0)).collect();
                let mut data: u32 = 0;
                let mut data_len: u32 = std::mem::size_of::<u32>() as u32;
                let mut reg_type: u32 = 0;
                let rc = RegQueryValueExW(
                    hkey,
                    value_name_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut reg_type,
                    &mut data as *mut u32 as *mut u8,
                    &mut data_len,
                );
                RegCloseKey(hkey);
                rc == ERROR_SUCCESS && data == 0
            }
        };
        assert!(found, "UserList value not found or non-zero after hide");

        // unhide: must succeed and be idempotent.
        unhide(&name).expect("first unhide should succeed");
        unhide(&name).expect("second unhide (absent value) should also succeed");
    }
}
