//! Per-sandbox local account management.
//!
//! On Windows, `create_account` provisions a dedicated standard local user
//! (via `NetUserAdd` level 1) and adds it to the built-in **Users** group
//! (S-1-5-32-545, resolved by `CreateWellKnownSid`/`LookupAccountSidW` to
//! avoid the localized group name). Returns the new account's SID string
//! (e.g. `S-1-5-21-…`) and a strong random password.
//!
//! `delete_account` removes the account via `NetUserDel`; absent account is
//! treated as success (idempotent). `delete_profile` is a best-effort stub.
//!
//! On non-Windows every public function returns `Err("windows-only")`.

// ── Password generator (all platforms) ──────────────────────────────────────

/// Minimum length enforced by `random_password` and `meets_complexity`.
pub const MIN_PW_LEN: usize = 16;

/// The four character classes Windows complexity policy checks.
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
/// Symbols that are safe in command-line invocations and JSON.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+";

/// All printable password characters (concatenation of the four classes).
const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

/// Return `true` iff `pw` satisfies Windows local-account password complexity:
/// length >= [`MIN_PW_LEN`] and at least 3 of the 4 character classes
/// (upper / lower / digit / symbol) are represented.
pub fn meets_complexity(pw: &str) -> bool {
    if pw.len() < MIN_PW_LEN {
        return false;
    }
    let b = pw.as_bytes();
    let has_upper = b.iter().any(|c| UPPER.contains(c));
    let has_lower = b.iter().any(|c| LOWER.contains(c));
    let has_digit = b.iter().any(|c| DIGITS.contains(c));
    let has_sym = b.iter().any(|c| SYMBOLS.contains(c));
    [has_upper, has_lower, has_digit, has_sym]
        .iter()
        .filter(|&&v| v)
        .count()
        >= 3
}

/// Generate a random password of exactly `len` characters (must be >= [`MIN_PW_LEN`]).
///
/// Uses the same clock+counter entropy as `confine_probe.rs` — no external
/// crate dependency. The four character classes (upper / lower / digit /
/// symbol) each seed at least one character in the output, guaranteeing
/// `meets_complexity` is always satisfied regardless of the random stream.
///
/// # Panics
///
/// Panics if `len < MIN_PW_LEN`.
pub fn random_password(len: usize) -> String {
    assert!(
        len >= MIN_PW_LEN,
        "random_password: len {len} < MIN_PW_LEN {MIN_PW_LEN}"
    );

    // We seed the first four positions with one character from each class so
    // complexity is ALWAYS satisfied, then fill the rest from the full alphabet.
    // The seeded positions are later shuffled via the same entropy stream.
    let guaranteed: &[&[u8]] = &[UPPER, LOWER, DIGITS, SYMBOLS];
    let mut bytes: Vec<u8> = Vec::with_capacity(len);

    for &class in guaranteed {
        let idx = (entropy() as usize) % class.len();
        bytes.push(class[idx]);
    }
    while bytes.len() < len {
        let idx = (entropy() as usize) % ALPHABET.len();
        bytes.push(ALPHABET[idx]);
    }

    // Fisher-Yates shuffle so the guaranteed characters are not always at
    // positions 0-3.
    for i in (1..len).rev() {
        let j = (entropy() as usize) % (i + 1);
        bytes.swap(i, j);
    }

    // SAFETY: every byte comes from printable ASCII slices.
    String::from_utf8(bytes).expect("password bytes are valid UTF-8 ASCII")
}

/// Monotonically increasing per-call entropy: a static counter folded with
/// the high-res clock. Identical to the `entropy()` in `confine_probe.rs` —
/// both live in the same binary on Windows.
fn entropy() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (n.wrapping_mul(0x9E37_79B9_7F4A_7C15))
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::random_password;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_Success, NERR_UserNotFound, NetLocalGroupAddMembers, NetUserAdd, NetUserDel,
        LOCALGROUP_MEMBERS_INFO_0, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_ACCOUNT_FLAGS,
        USER_INFO_1, USER_PRIV_USER,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountNameW, LookupAccountSidW, WinBuiltinUsersSid, PSID,
        SID_NAME_USE,
    };

    /// Password length used for all provisioned accounts.
    const PW_LEN: usize = 24;

    /// Provision a dedicated local standard user named `name`.
    ///
    /// - Creates the account via `NetUserAdd` level 1 (`USER_PRIV_USER`,
    ///   `UF_SCRIPT | UF_DONT_EXPIRE_PASSWD`).
    /// - Adds it to the built-in **Users** group (S-1-5-32-545) by resolving
    ///   the group's localized name from the well-known SID and calling
    ///   `NetLocalGroupAddMembers` level 0 with the new account's SID.
    /// - Looks up the account SID via `LookupAccountNameW` and converts it to
    ///   a string via `ConvertSidToStringSidW`.
    ///
    /// Returns `(sid_string, password)` on success.
    pub fn create_account(name: &str) -> Result<(String, String), String> {
        let password = random_password(PW_LEN);

        // Encode the account name and password as NUL-terminated UTF-16.
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let pw_w: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();

        // Build the USER_INFO_1 structure. Mutable pointers are required by
        // the API even for fields it only reads.
        // SAFETY: USER_INFO_1::default() is zeroed per the windows-sys impl;
        // the pointer fields point into our Vec<u16> buffers that outlive the
        // NetUserAdd call.
        let mut ui: USER_INFO_1 = unsafe { std::mem::zeroed() };
        ui.usri1_name = name_w.as_ptr() as *mut u16;
        ui.usri1_password = pw_w.as_ptr() as *mut u16;
        ui.usri1_priv = USER_PRIV_USER;
        ui.usri1_flags = (UF_SCRIPT | UF_DONT_EXPIRE_PASSWD) as USER_ACCOUNT_FLAGS;

        // SAFETY: pointers in ui point to valid NUL-terminated UTF-16 buffers
        // that outlive this call; parm_err output is ignored (we get the status
        // code instead).
        let status = unsafe {
            NetUserAdd(
                std::ptr::null(), // local machine
                1,                // info level 1
                &ui as *const _ as *const u8,
                std::ptr::null_mut(), // parm_err: don't care
            )
        };
        if status != NERR_Success {
            return Err(format!("NetUserAdd({name:?}): NET_API_STATUS {status}"));
        }

        // Resolve the new account's SID via LookupAccountNameW.
        let sid_string = match lookup_account_sid(name) {
            Ok(s) => s,
            Err(e) => {
                // Best-effort cleanup — ignore errors.
                let _ = delete_account(name);
                return Err(e);
            }
        };

        // Add the new account to the built-in Users group (S-1-5-32-545).
        // We look up the new account's SID again as a raw buffer so we can
        // pass it to NetLocalGroupAddMembers level 0.
        if let Err(e) = add_to_users_group(name) {
            let _ = delete_account(name);
            return Err(e);
        }

        Ok((sid_string, password))
    }

    /// Delete the local account `name` via `NetUserDel`. Absent account is
    /// treated as success (idempotent).
    pub fn delete_account(name: &str) -> Result<(), String> {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: name_w is a valid NUL-terminated UTF-16 buffer.
        let status = unsafe { NetUserDel(std::ptr::null(), name_w.as_ptr()) };
        if status == NERR_Success || status == NERR_UserNotFound {
            Ok(())
        } else {
            Err(format!("NetUserDel({name:?}): NET_API_STATUS {status}"))
        }
    }

    /// Best-effort profile deletion for `name`. Currently a stub — the
    /// orchestrator (`izba-core`) is responsible for profile cleanup via
    /// `DeleteProfileW` when it has the full profile path. This function
    /// exists so callers have a uniform interface.
    pub fn delete_profile(_name: &str) {
        // Stub: profile deletion is handled by the orchestrator.
        // A full implementation would call DeleteProfileW with the SID
        // obtained from LookupAccountNameW. Accepted for now per spec §4.
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Look up `name`'s SID with `LookupAccountNameW` and convert it to a
    /// string via `ConvertSidToStringSidW`. Returns e.g. `"S-1-5-21-…"`.
    fn lookup_account_sid(name: &str) -> Result<String, String> {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: two-phase size query + allocation; SID buffer and domain
        // buffer are sized by the first call; the second call fills them.
        unsafe {
            let mut sid_size: u32 = 0;
            let mut domain_size: u32 = 0;
            let mut sid_use: SID_NAME_USE = 0;

            // First call: size query (expects to fail with ERROR_INSUFFICIENT_BUFFER).
            LookupAccountNameW(
                std::ptr::null(),
                name_w.as_ptr(),
                std::ptr::null_mut(),
                &mut sid_size,
                std::ptr::null_mut(),
                &mut domain_size,
                &mut sid_use,
            );

            if sid_size == 0 {
                return Err(format!(
                    "LookupAccountNameW({name:?}) size query: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut sid_buf = vec![0u8; sid_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];

            let ok = LookupAccountNameW(
                std::ptr::null(),
                name_w.as_ptr(),
                sid_buf.as_mut_ptr() as PSID,
                &mut sid_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_use,
            );
            if ok == 0 {
                return Err(format!(
                    "LookupAccountNameW({name:?}): {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Convert SID to string form via ConvertSidToStringSidW.
            let mut str_sid_ptr: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSidToStringSidW(sid_buf.as_ptr() as PSID, &mut str_sid_ptr);
            if ok == 0 {
                return Err(format!(
                    "ConvertSidToStringSidW: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Read the NUL-terminated UTF-16 string, then free the LocalAlloc.
            let len = (0..).take_while(|&i| *str_sid_ptr.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(str_sid_ptr, len);
            let result = String::from_utf16(slice)
                .map_err(|e| format!("ConvertSidToStringSidW UTF-16 decode: {e}"));
            LocalFree(str_sid_ptr as _);
            result
        }
    }

    /// Add `name`'s account to the built-in Users group (S-1-5-32-545).
    ///
    /// Strategy:
    /// 1. Build the well-known Users SID via `CreateWellKnownSid`.
    /// 2. Resolve the localized group name via `LookupAccountSidW`.
    /// 3. Look up the new account's SID via `LookupAccountNameW`.
    /// 4. `NetLocalGroupAddMembers` level 0 with the account SID.
    fn add_to_users_group(name: &str) -> Result<(), String> {
        // SAFETY: linear FFI; all buffers outlive their calls; no heap escapes.
        unsafe {
            // 1. Build the well-known Users SID (S-1-5-32-545).
            let mut users_sid_size: u32 = 0;
            // Size query.
            CreateWellKnownSid(
                WinBuiltinUsersSid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut users_sid_size,
            );
            if users_sid_size == 0 {
                let e = std::io::Error::last_os_error();
                // ERROR_INSUFFICIENT_BUFFER is the expected error from the size query;
                // any other error is unexpected.
                if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    return Err(format!("CreateWellKnownSid size query: {e}"));
                }
            }
            let mut users_sid_buf = vec![0u8; users_sid_size as usize];
            let ok = CreateWellKnownSid(
                WinBuiltinUsersSid,
                std::ptr::null_mut(),
                users_sid_buf.as_mut_ptr() as PSID,
                &mut users_sid_size,
            );
            if ok == 0 {
                return Err(format!(
                    "CreateWellKnownSid(WinBuiltinUsersSid): {}",
                    std::io::Error::last_os_error()
                ));
            }

            // 2. Resolve the localized name of the Users group.
            let mut name_size: u32 = 0;
            let mut domain_size: u32 = 0;
            let mut sid_use: SID_NAME_USE = 0;
            // Size query.
            LookupAccountSidW(
                std::ptr::null(),
                users_sid_buf.as_ptr() as PSID,
                std::ptr::null_mut(),
                &mut name_size,
                std::ptr::null_mut(),
                &mut domain_size,
                &mut sid_use,
            );
            if name_size == 0 {
                return Err(format!(
                    "LookupAccountSidW(Users) size query: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut group_name_buf = vec![0u16; name_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];
            let ok = LookupAccountSidW(
                std::ptr::null(),
                users_sid_buf.as_ptr() as PSID,
                group_name_buf.as_mut_ptr(),
                &mut name_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_use,
            );
            if ok == 0 {
                return Err(format!(
                    "LookupAccountSidW(Users): {}",
                    std::io::Error::last_os_error()
                ));
            }
            // group_name_buf is already NUL-terminated by LookupAccountSidW.

            // 3. Look up the new account's SID.
            let acct_name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut acct_sid_size: u32 = 0;
            let mut acct_domain_size: u32 = 0;
            let mut acct_sid_use: SID_NAME_USE = 0;
            LookupAccountNameW(
                std::ptr::null(),
                acct_name_w.as_ptr(),
                std::ptr::null_mut(),
                &mut acct_sid_size,
                std::ptr::null_mut(),
                &mut acct_domain_size,
                &mut acct_sid_use,
            );
            if acct_sid_size == 0 {
                return Err(format!(
                    "LookupAccountNameW({name:?}) size query (for group add): {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut acct_sid_buf = vec![0u8; acct_sid_size as usize];
            let mut acct_domain_buf = vec![0u16; acct_domain_size as usize];
            let ok = LookupAccountNameW(
                std::ptr::null(),
                acct_name_w.as_ptr(),
                acct_sid_buf.as_mut_ptr() as PSID,
                &mut acct_sid_size,
                acct_domain_buf.as_mut_ptr(),
                &mut acct_domain_size,
                &mut acct_sid_use,
            );
            if ok == 0 {
                return Err(format!(
                    "LookupAccountNameW({name:?}) (for group add): {}",
                    std::io::Error::last_os_error()
                ));
            }

            // 4. Add the account SID to the Users group.
            let member = LOCALGROUP_MEMBERS_INFO_0 {
                lgrmi0_sid: acct_sid_buf.as_ptr() as PSID,
            };
            let status = NetLocalGroupAddMembers(
                std::ptr::null(),
                group_name_buf.as_ptr(),
                0, // level 0 = SID only
                &member as *const _ as *const u8,
                1, // total entries
            );
            // ERROR_MEMBER_IN_ALIAS (1378) means already a member — treat as OK.
            const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
            if status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS {
                return Err(format!(
                    "NetLocalGroupAddMembers(Users, {name:?}): NET_API_STATUS {status}"
                ));
            }
            Ok(())
        }
    }
}

// ── Public surface (re-export from win mod on Windows, stubs elsewhere) ─────

/// Provision a dedicated local account named `name`.
///
/// Returns `(sid_string, password)` on success.
#[cfg(windows)]
pub fn create_account(name: &str) -> Result<(String, String), String> {
    win::create_account(name)
}

/// Provision a dedicated local account named `name`.
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(not(windows))]
pub fn create_account(_name: &str) -> Result<(String, String), String> {
    Err("windows-only".into())
}

/// Delete the local account `name` (idempotent; absent account is Ok).
#[cfg(windows)]
pub fn delete_account(name: &str) -> Result<(), String> {
    win::delete_account(name)
}

/// Delete the local account `name`.
///
/// Returns `Err("windows-only")` on non-Windows.
#[cfg(not(windows))]
pub fn delete_account(_name: &str) -> Result<(), String> {
    Err("windows-only".into())
}

/// Best-effort profile deletion for `name`.
#[cfg(windows)]
pub fn delete_profile(name: &str) {
    win::delete_profile(name)
}

/// Best-effort profile deletion (no-op on non-Windows).
#[cfg(not(windows))]
pub fn delete_profile(_name: &str) {}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{meets_complexity, random_password, MIN_PW_LEN};

    // ── Password complexity predicate ────────────────────────────────────────

    #[test]
    fn empty_password_fails_complexity() {
        assert!(!meets_complexity(""));
    }

    #[test]
    fn short_password_fails_complexity() {
        // 15 chars with all classes — still too short.
        assert!(!meets_complexity("Abcde1234!@#$%^"));
    }

    #[test]
    fn all_upper_fails_complexity() {
        // Only one character class.
        assert!(!meets_complexity("AAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn two_classes_fails_complexity() {
        // Only upper + lower — needs >= 3 classes.
        assert!(!meets_complexity("AbAbAbAbAbAbAbAb"));
    }

    #[test]
    fn three_classes_passes_complexity() {
        // Upper + lower + digit.
        assert!(meets_complexity("AbcDefGhi1234567"));
    }

    #[test]
    fn all_four_classes_passes_complexity() {
        assert!(meets_complexity("Abcde1234!@#$AbcX"));
    }

    // ── random_password generator ────────────────────────────────────────────

    #[test]
    fn random_password_default_length_meets_complexity() {
        let pw = random_password(MIN_PW_LEN);
        assert_eq!(pw.len(), MIN_PW_LEN);
        assert!(
            meets_complexity(&pw),
            "generated password does not meet complexity: {pw:?}"
        );
    }

    #[test]
    fn random_password_24_chars() {
        let pw = random_password(24);
        assert_eq!(pw.len(), 24);
        assert!(
            meets_complexity(&pw),
            "24-char password does not meet complexity: {pw:?}"
        );
    }

    #[test]
    fn random_password_meets_complexity_many_iterations() {
        // Generate 500 passwords; every one must pass complexity.
        for i in 0..500 {
            let pw = random_password(24);
            assert!(
                meets_complexity(&pw),
                "iteration {i}: password {pw:?} failed complexity"
            );
        }
    }

    #[test]
    fn random_password_is_not_all_same_character() {
        // Statistically impossible given the alphabet, but a useful sanity check.
        let pw = random_password(24);
        let first = pw.chars().next().unwrap();
        assert!(
            !pw.chars().all(|c| c == first),
            "password is suspiciously uniform: {pw:?}"
        );
    }

    #[test]
    fn random_password_consecutive_calls_differ() {
        // Entropy is clock+counter — two consecutive calls must not collide.
        let a = random_password(24);
        let b = random_password(24);
        assert_ne!(a, b, "two consecutive passwords must differ");
    }

    #[test]
    fn random_password_contains_only_ascii_printable() {
        let pw = random_password(24);
        assert!(
            pw.is_ascii(),
            "password contains non-ASCII characters: {pw:?}"
        );
        assert!(
            pw.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            "password contains non-printable ASCII: {pw:?}"
        );
    }

    // ── Windows FFI round-trip (elevation-gated) ─────────────────────────────

    /// Create → lookup SID → delete round-trip.  Skips unless running elevated
    /// on Windows (same discipline as `full_connect_via_listener` in vsock.rs
    /// and `confine_probe`).
    #[cfg(windows)]
    #[test]
    fn account_create_lookup_delete_roundtrip() {
        use super::{create_account, delete_account};
        use windows_sys::Win32::NetworkManagement::NetManagement::NERR_Success;
        use windows_sys::Win32::NetworkManagement::NetManagement::NetUserAdd;

        // Elevation probe: try to call NetUserAdd with a deliberately-invalid
        // level (99) — an elevated process gets NERR_BadPassword or similar
        // (non-zero but NOT access-denied), while an un-elevated process gets
        // ERROR_ACCESS_DENIED (5).
        const ERROR_ACCESS_DENIED: u32 = 5;
        let probe = unsafe {
            NetUserAdd(
                std::ptr::null(),
                99,
                [0u8; 64].as_ptr(), // garbage buf, level 99 is invalid
                std::ptr::null_mut(),
            )
        };
        if probe == ERROR_ACCESS_DENIED {
            // Not elevated — skip.
            eprintln!("account_create_lookup_delete_roundtrip: not elevated, skipping");
            return;
        }

        // Use a name that is unlikely to collide with real accounts.
        let name = format!("izba-test-{}", std::process::id());

        // Ensure the account doesn't exist before we start.
        let _ = delete_account(&name);

        let (sid, password) =
            create_account(&name).expect("create_account should succeed when elevated");

        // SID must start with "S-1-5-" (local machine accounts on Windows).
        assert!(sid.starts_with("S-1-5-"), "unexpected SID format: {sid:?}");

        // Password must meet complexity.
        assert!(
            super::meets_complexity(&password),
            "returned password does not meet complexity: {password:?}"
        );

        // Delete must succeed and be idempotent.
        delete_account(&name).expect("first delete should succeed");
        delete_account(&name).expect("second delete (absent account) should also succeed");
    }
}
