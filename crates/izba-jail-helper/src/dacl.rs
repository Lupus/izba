//! DACL manipulation for per-sandbox local accounts.
//!
//! `grant` adds an inheritable ALLOW ACE for a named account SID to an
//! existing filesystem path, preserving all prior ACEs. The new ACE is
//! `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE` so the permission flows
//! down to all files and subdirectories created within the path.
//!
//! On non-Windows every public function returns `Err("windows-only")`.

use std::path::Path;

// ── Grant level (all platforms) ──────────────────────────────────────────────

/// The level of file-system access to grant.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLevel {
    /// Read + list + execute (`GENERIC_READ | GENERIC_EXECUTE`).
    ReadExec,
    /// Read + write + execute + delete
    /// (`GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE`).
    Modify,
}

/// Non-Windows mirror type so callers compile on all platforms.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLevel {
    ReadExec,
    Modify,
}

// ── Pure access-mask helper (all platforms, unit-tested) ─────────────────────

/// Map a [`GrantLevel`] to its Win32 generic-access-rights bitmask.
///
/// The mask is passed directly to `EXPLICIT_ACCESS_W::grfAccessPermissions`.
pub fn access_mask(level: &GrantLevel) -> u32 {
    // Windows generic access rights (winnt.h). windows-sys does not re-export
    // these under their canonical names in a single always-enabled feature, so
    // we define the fixed values locally — same pattern as SE_GROUP_INTEGRITY
    // in jail_windows.rs.
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const DELETE: u32 = 0x0001_0000;

    match level {
        GrantLevel::ReadExec => GENERIC_READ | GENERIC_EXECUTE,
        GrantLevel::Modify => GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
    }
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::{access_mask, GrantLevel};
    use std::path::Path;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
        TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    };

    /// Add an inheritable ALLOW ACE for `sid` (a string SID like `"S-1-5-21-…"`)
    /// to `path`'s DACL, preserving all existing ACEs.
    ///
    /// The ACE inherits to containers and objects
    /// (`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`).
    ///
    /// Memory discipline — every `LocalAlloc`'d pointer is freed on ALL paths:
    /// - `old_sd`  — OS-allocated security descriptor from `GetNamedSecurityInfoW`
    /// - `new_acl` — OS-allocated merged ACL from `SetEntriesInAclW`
    /// - `sid`     — OS-allocated SID from `ConvertStringSidToSidW`
    pub fn grant(path: &Path, sid_str: &str, level: GrantLevel) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;

        // SAFETY: linear FFI sequence. Every LocalAlloc'd pointer is tracked and
        // freed on every exit path, including error returns. Comments at each
        // resource acquisition point document the free obligation.

        // We track three OS-allocated pointers independently so we can free each
        // on every exit path, even if acquired out-of-order errors occur.
        let mut old_sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let mut account_sid: *mut std::ffi::c_void = std::ptr::null_mut();

        let result: Result<(), String> = (|| {
            // 1. Convert the string SID to a binary SID via ConvertStringSidToSidW.
            //    The returned pointer is LocalAlloc'd; freed below as `account_sid`.
            let sid_w: Vec<u16> = sid_str.encode_utf16().chain(std::iter::once(0)).collect();

            // SAFETY: sid_w is a NUL-terminated UTF-16 string; account_sid receives
            // a LocalAlloc'd SID.
            let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut account_sid) };
            if ok == 0 {
                return Err(format!(
                    "ConvertStringSidToSidW({sid_str:?}): {}",
                    std::io::Error::last_os_error()
                ));
            }

            // 2. Read the current DACL from `path` via GetNamedSecurityInfoW.
            //    The returned `old_sd` is LocalAlloc'd; freed below.
            //    `old_dacl` points INTO `old_sd` — do NOT free it separately.
            let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
            path_w.push(0);
            let mut old_dacl: *mut ACL = std::ptr::null_mut();

            // SAFETY: path_w is NUL-terminated; old_dacl points into old_sd (same
            // allocation); old_sd receives a LocalAlloc'd security descriptor.
            let rc = unsafe {
                GetNamedSecurityInfoW(
                    path_w.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(), // owner — not needed
                    std::ptr::null_mut(), // group — not needed
                    &mut old_dacl,
                    std::ptr::null_mut(), // SACL — not needed
                    &mut old_sd,
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(format!(
                    "GetNamedSecurityInfoW({}): WIN32_ERROR {rc}",
                    path.display()
                ));
            }

            // 3. Build one EXPLICIT_ACCESS_W entry describing our new ACE.
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: access_mask(&level),
                grfAccessMode: SET_ACCESS,
                grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    // ptstrName is a union; when TrusteeForm = TRUSTEE_IS_SID it
                    // holds the SID pointer. The field is *mut u16 in windows-sys.
                    ptstrName: account_sid as *mut u16,
                },
            };

            // 4. Merge the new ACE with the existing DACL via SetEntriesInAclW.
            //    The returned `new_acl` is LocalAlloc'd; freed below.
            // SAFETY: ea outlives this call; old_dacl points into old_sd which is
            // still alive; new_acl receives a LocalAlloc'd merged ACL.
            let rc = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_acl) };
            if rc != ERROR_SUCCESS {
                return Err(format!(
                    "SetEntriesInAclW({}): WIN32_ERROR {rc}",
                    path.display()
                ));
            }

            // 5. Apply the merged DACL back to `path`.
            // SAFETY: path_w is NUL-terminated; new_acl is the merged DACL from
            // step 4, valid until LocalFree'd below.
            let rc = unsafe {
                SetNamedSecurityInfoW(
                    path_w.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(), // owner unchanged
                    std::ptr::null_mut(), // group unchanged
                    new_acl,              // the merged DACL
                    std::ptr::null_mut(), // SACL unchanged
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(format!(
                    "SetNamedSecurityInfoW({}): WIN32_ERROR {rc}",
                    path.display()
                ));
            }

            Ok(())
        })();

        // Free all OS-allocated pointers, in reverse acquisition order, on ALL
        // paths — success and error alike.
        // SAFETY: each pointer was either null-initialised (no-op LocalFree) or
        // populated by a single OS call that LocalAlloc'd it; we free each at
        // most once.
        unsafe {
            if !new_acl.is_null() {
                LocalFree(new_acl as _);
            }
            if !old_sd.is_null() {
                LocalFree(old_sd as _);
            }
            if !account_sid.is_null() {
                LocalFree(account_sid as _);
            }
        }

        result
    }
}

// ── Public surface (re-export from win mod on Windows, stubs elsewhere) ──────

/// Add an inheritable ALLOW ACE for `sid` to `path`'s DACL,
/// preserving existing ACEs.
///
/// `sid` is a string SID such as `"S-1-5-21-…"` returned by `create_account`.
#[cfg(windows)]
pub fn grant(path: &Path, sid: &str, level: GrantLevel) -> Result<(), String> {
    win::grant(path, sid, level)
}

/// Add an inheritable ALLOW ACE — stub on non-Windows.
///
/// Returns `Err("windows-only")`.
#[cfg(not(windows))]
pub fn grant(_path: &Path, _sid: &str, _level: GrantLevel) -> Result<(), String> {
    Err("windows-only".into())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure access_mask tests (all platforms) ───────────────────────────────

    #[test]
    fn access_mask_read_exec() {
        // GENERIC_READ (0x80000000) | GENERIC_EXECUTE (0x20000000)
        assert_eq!(
            access_mask(&GrantLevel::ReadExec),
            0x8000_0000 | 0x2000_0000
        );
    }

    #[test]
    fn access_mask_modify() {
        // GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE
        assert_eq!(
            access_mask(&GrantLevel::Modify),
            0x8000_0000 | 0x4000_0000 | 0x2000_0000 | 0x0001_0000
        );
    }

    #[test]
    fn access_mask_read_exec_differs_from_modify() {
        assert_ne!(
            access_mask(&GrantLevel::ReadExec),
            access_mask(&GrantLevel::Modify)
        );
    }

    // ── Windows FFI DACL grant (elevation-gated) ─────────────────────────────

    /// Grant `ReadExec` to the current user's SID on a temp dir, verify no
    /// error. We use the current user's own SID (obtained via `GetTokenInformation
    /// → ConvertSidToStringSidW`) so the test does not need a second account to
    /// be present. Skips when we cannot determine the current SID (unusual env).
    #[cfg(windows)]
    #[test]
    fn grant_read_exec_on_temp_dir() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // Build a temporary directory for the test.
        let dir = std::env::temp_dir().join(format!("izba-dacl-{}", std::process::id()));
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("grant_read_exec_on_temp_dir: cannot create temp dir, skipping");
            return;
        }

        // Obtain the current user's SID as a string.
        let current_sid = unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                eprintln!(
                    "grant_read_exec_on_temp_dir: OpenProcessToken failed, skipping: {}",
                    std::io::Error::last_os_error()
                );
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }

            // Size query.
            let mut needed: u32 = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                eprintln!("grant_read_exec_on_temp_dir: TokenUser size query failed, skipping");
                windows_sys::Win32::Foundation::CloseHandle(token);
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            );
            windows_sys::Win32::Foundation::CloseHandle(token);
            if ok == 0 {
                eprintln!("grant_read_exec_on_temp_dir: TokenUser query failed, skipping");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            // TOKEN_USER.User.Sid points into buf.
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid_ptr = tu.User.Sid;
            let mut str_ptr: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSidToStringSidW(sid_ptr, &mut str_ptr);
            if ok == 0 || str_ptr.is_null() {
                eprintln!("grant_read_exec_on_temp_dir: ConvertSidToStringSidW failed, skipping");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            let len = (0..).take_while(|&i| *str_ptr.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(str_ptr, len);
            let s = String::from_utf16(slice).unwrap_or_default();
            LocalFree(str_ptr as _);
            s
        };

        if current_sid.is_empty() {
            eprintln!("grant_read_exec_on_temp_dir: could not determine current SID, skipping");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // Call grant — must succeed (we're granting our own SID, so no elevation needed).
        let result = grant(&dir, &current_sid, GrantLevel::ReadExec);
        let _ = std::fs::remove_dir_all(&dir);
        result.expect("grant ReadExec on temp dir should succeed");
    }
}
