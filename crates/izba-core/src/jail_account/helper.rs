//! Elevated helper invocation client.
//!
//! Resolves the `izba-jail-helper.exe` sibling binary and, on Windows,
//! launches it via `ShellExecuteExW` with the `runas` verb (triggers UAC)
//! so the helper runs with administrator privileges.
//!
//! # Design
//!
//! - `helper_path_from` is a pure function that takes the current-exe path
//!   and returns the expected sibling `izba-jail-helper.exe` path.  It is
//!   host-testable on all platforms.
//! - `helper_path` calls `std::env::current_exe()` and delegates to
//!   `helper_path_from`.
//! - `join_args` converts an argv slice to a single `lpParameters` string,
//!   quoting any argument that contains whitespace or double-quotes. Pure,
//!   all-platforms, unit-tested.
//! - `run_elevated` (Windows-only) launches the resolved helper with the
//!   given argv via `ShellExecuteExW` and waits for the process to exit.
//!
//! # UAC cancellation
//!
//! When the user clicks "No" in the UAC prompt `ShellExecuteExW` fails with
//! `ERROR_CANCELLED` (1223).  This is mapped to
//! `Ok(ElevationOutcome::Cancelled)` — the caller can surface a friendly
//! message rather than propagating a hard error.

use std::path::{Path, PathBuf};

// ── Path resolution ──────────────────────────────────────────────────────────

/// Given the path of **the current executable**, return the expected path of
/// `izba-jail-helper.exe` sitting in the same directory.
///
/// This is the pure, host-testable core.  Tests on Linux/macOS can call this
/// directly without needing to spawn anything.
pub fn helper_path_from(exe: &Path) -> PathBuf {
    let parent = exe.parent().unwrap_or(exe);
    parent.join("izba-jail-helper.exe")
}

/// Return the path of `izba-jail-helper.exe` beside the running executable.
///
/// # Errors
///
/// Returns `Err` if `std::env::current_exe()` fails (e.g. the process was
/// started without a valid `/proc/self/exe` link).
pub fn helper_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe(): {e}"))?;
    Ok(helper_path_from(&exe))
}

// ── Argument quoting ─────────────────────────────────────────────────────────

/// Join `argv` into a single `lpParameters` string suitable for
/// `ShellExecuteExW`.
///
/// Implements the MSDN `CommandLineToArgvW` quoting algorithm:
///
/// - Arguments that need no quoting (non-empty, no whitespace, no `"`) are
///   passed through verbatim.
/// - Arguments that are empty, contain ASCII whitespace, or contain a
///   double-quote are wrapped in double-quotes.  Inside a quoted argument:
///   - Each `"` is emitted as `\"` (with any immediately-preceding run of `k`
///     backslashes doubled to `2k` before the `\"`).
///   - A run of `k` backslashes at the very end of the argument (immediately
///     before the closing `"`) is doubled to `2k` so that the closing `"` is
///     not accidentally consumed by `CommandLineToArgvW`.
///
/// This matches the exact quoting rules described in the Windows documentation
/// for `CommandLineToArgvW` / `CreateProcess lpCommandLine`.
///
/// This function is pure and available on all platforms.
pub fn join_args(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let needs_quoting =
            arg.is_empty() || arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"');
        if needs_quoting {
            out.push('"');
            // Walk the argument byte-by-byte, counting consecutive backslashes.
            // Flush the pending backslash run when we hit a `"` or end-of-arg.
            let bytes = arg.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                // Count a run of backslashes.
                let bs_start = i;
                while i < bytes.len() && bytes[i] == b'\\' {
                    i += 1;
                }
                let bs_count = i - bs_start;

                if i == bytes.len() {
                    // End of argument: double all trailing backslashes so that
                    // the closing `"` we are about to emit is not consumed.
                    for _ in 0..bs_count * 2 {
                        out.push('\\');
                    }
                } else if bytes[i] == b'"' {
                    // Before an embedded quote: double the preceding backslashes
                    // and escape the quote itself.
                    for _ in 0..bs_count * 2 {
                        out.push('\\');
                    }
                    out.push('\\');
                    out.push('"');
                    i += 1;
                } else {
                    // Regular character (not a backslash or quote): emit the
                    // backslashes verbatim then the character.
                    for _ in 0..bs_count {
                        out.push('\\');
                    }
                    // SAFETY: bytes[i] is a valid byte; push it as char.
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

// ── Elevation outcome + run_elevated ────────────────────────────────────────

/// The outcome of an elevated helper invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum ElevationOutcome {
    /// The helper exited with code 0 — success.
    Ok,
    /// The user declined the UAC prompt (`ERROR_CANCELLED`).
    Cancelled,
    /// The helper exited with a nonzero code.
    Failed(String),
}

/// Launch `izba-jail-helper.exe` with `argv` under a UAC elevation prompt.
///
/// On **Windows**: uses `ShellExecuteExW` with `lpVerb = "runas"`,
/// `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC` to obtain the process
/// handle, `nShow = SW_HIDE`, then `WaitForSingleObject(INFINITE)` +
/// `GetExitCodeProcess`.
///
/// - `ShellExecuteExW` fails with `ERROR_CANCELLED` (1223) → the user
///   declined UAC → `Ok(ElevationOutcome::Cancelled)`.
/// - Helper exit code 0 → `Ok(ElevationOutcome::Ok)`.
/// - Helper exit code ≠ 0 → `Ok(ElevationOutcome::Failed("helper exit N"))`.
/// - Any other `ShellExecuteExW` failure → `Err(message)`.
///
/// On **non-Windows**: always returns `Err("windows-only")`.
#[cfg(windows)]
pub fn run_elevated(argv: &[String]) -> Result<ElevationOutcome, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let helper = helper_path().map_err(|e| format!("helper_path: {e}"))?;

    // Build NUL-terminated UTF-16 strings.
    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
    let file_w: Vec<u16> = helper
        .to_str()
        .ok_or_else(|| "helper path is not valid UTF-8".to_string())?
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let params_str = join_args(argv);
    let params_w: Vec<u16> = params_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: SHELLEXECUTEINFOW::default() zero-initialises the struct (via
    // mem::zeroed()); we then fill the required fields before calling
    // ShellExecuteExW.  The raw-pointer fields (lpVerb, lpFile, lpParameters)
    // point into local Vec<u16> buffers that remain valid for the duration of
    // the call.  hProcess is read only after a successful return.
    let mut sei = unsafe {
        let mut s = std::mem::zeroed::<SHELLEXECUTEINFOW>();
        s.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        s.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        s.lpVerb = verb_w.as_ptr();
        s.lpFile = file_w.as_ptr();
        s.lpParameters = params_w.as_ptr();
        s.nShow = SW_HIDE;
        s
    };

    // Launch with UAC elevation.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(0) as u32;
        if raw == ERROR_CANCELLED {
            return Ok(ElevationOutcome::Cancelled);
        }
        return Err(format!("ShellExecuteExW: {err}"));
    }

    // Retrieve hProcess (guaranteed valid when SEE_MASK_NOCLOSEPROCESS is set
    // and the call succeeded).
    let hprocess: HANDLE = sei.hProcess;

    // Wait for the helper to finish.
    let wait_result = unsafe { WaitForSingleObject(hprocess, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        let err = std::io::Error::last_os_error();
        unsafe { CloseHandle(hprocess) };
        return Err(format!("WaitForSingleObject: {err}"));
    }

    let mut exit_code: u32 = 0;
    let got_code = unsafe { GetExitCodeProcess(hprocess, &mut exit_code) };
    unsafe { CloseHandle(hprocess) };

    if got_code == 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("GetExitCodeProcess: {err}"));
    }

    if exit_code == 0 {
        Ok(ElevationOutcome::Ok)
    } else {
        Ok(ElevationOutcome::Failed(format!("helper exit {exit_code}")))
    }
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn run_elevated(_argv: &[String]) -> Result<ElevationOutcome, String> {
    Err("windows-only".into())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{helper_path_from, join_args, ElevationOutcome};
    use std::path::PathBuf;

    // ── helper_path_from ─────────────────────────────────────────────────────

    #[test]
    fn helper_path_from_unix_style_exe() {
        let exe = PathBuf::from("/usr/local/bin/izba");
        let got = helper_path_from(&exe);
        assert_eq!(got, PathBuf::from("/usr/local/bin/izba-jail-helper.exe"));
    }

    /// The Windows-style path test can only run on Windows, because backslash is
    /// not a path separator on Unix and PathBuf treats the whole string as a
    /// bare file name there.
    #[cfg(windows)]
    #[test]
    fn helper_path_from_windows_style_exe() {
        let exe = PathBuf::from(r"C:\Program Files\izba\izba.exe");
        let got = helper_path_from(&exe);
        assert_eq!(
            got,
            PathBuf::from(r"C:\Program Files\izba\izba-jail-helper.exe")
        );
    }

    #[test]
    fn helper_path_from_bare_exe_name() {
        // When current_exe() returns a bare name with no parent component, we
        // fall back to the exe path itself as the parent (Path::parent() → None
        // for a bare name).  The result is a sibling with no directory prefix.
        let exe = PathBuf::from("izba");
        let got = helper_path_from(&exe);
        // parent() of "izba" is "" which .join() treats as CWD-relative
        assert!(got.ends_with("izba-jail-helper.exe"));
    }

    #[test]
    fn helper_is_named_izba_jail_helper() {
        let exe = PathBuf::from("/some/dir/izba");
        let got = helper_path_from(&exe);
        assert_eq!(
            got.file_name().unwrap().to_str().unwrap(),
            "izba-jail-helper.exe"
        );
    }

    // ── join_args ────────────────────────────────────────────────────────────

    #[test]
    fn join_args_empty_slice() {
        assert_eq!(join_args(&[]), "");
    }

    #[test]
    fn join_args_single_plain() {
        let args = vec!["create-account".to_string()];
        assert_eq!(join_args(&args), "create-account");
    }

    #[test]
    fn join_args_multiple_plain() {
        let args = vec!["create-account".to_string(), "izba-sb0".to_string()];
        assert_eq!(join_args(&args), "create-account izba-sb0");
    }

    #[test]
    fn join_args_arg_with_spaces_is_quoted() {
        let args = vec!["with space".to_string()];
        assert_eq!(join_args(&args), r#""with space""#);
    }

    #[test]
    fn join_args_arg_with_tabs_is_quoted() {
        let args = vec!["with\ttab".to_string()];
        assert_eq!(join_args(&args), "\"with\ttab\"");
    }

    #[test]
    fn join_args_arg_with_internal_quote_is_escaped() {
        let args = vec!["say \"hi\"".to_string()];
        assert_eq!(join_args(&args), r#""say \"hi\"""#);
    }

    #[test]
    fn join_args_empty_arg_is_quoted() {
        let args = vec!["".to_string()];
        assert_eq!(join_args(&args), r#""""#);
    }

    #[test]
    fn join_args_mixed() {
        let args = vec![
            "create-account".to_string(),
            "name with space".to_string(),
            "plain".to_string(),
        ];
        assert_eq!(
            join_args(&args),
            r#"create-account "name with space" plain"#
        );
    }

    #[test]
    fn join_args_trailing_backslash_in_quoted_arg_is_doubled() {
        // A path with a space (forces quoting) AND a trailing backslash:
        // CommandLineToArgvW would interpret `"C:\path\"` as an unmatched open
        // quote because the `\"` sequence escapes the closing double-quote.
        // The correct encoding is `"C:\path\\"` (trailing backslash doubled).
        let args = vec!["C:\\Program Files\\izba\\x\\".to_string()];
        let result = join_args(&args);
        assert_eq!(
            result, "\"C:\\Program Files\\izba\\x\\\\\"",
            "trailing backslash must be doubled before the closing quote"
        );
        // The result must end with `\\` then `"` — i.e. the closing `"` is NOT
        // preceded by an odd number of backslashes.
        assert!(
            result.ends_with("\\\\\""),
            "closing quote must be preceded by an even number of backslashes: {result}"
        );
    }

    #[test]
    fn join_args_multiple_trailing_backslashes_doubled() {
        // Two trailing backslashes → four in the output.
        let args = vec!["path with spaces\\\\".to_string()];
        let result = join_args(&args);
        // Encoded: "path with spaces\\\\"  (2 backslashes → 4, then closing ")
        assert!(
            result.ends_with("\\\\\\\\\""),
            "two trailing backslashes must become four: {result}"
        );
    }

    #[test]
    fn join_args_backslash_before_embedded_quote_doubled() {
        // A backslash immediately before an embedded double-quote must be
        // doubled per the MSDN algorithm:  `a\"b`  must encode as  `"a\\\"b"`.
        let args = vec!["a\\\"b".to_string()];
        let result = join_args(&args);
        // The `\"` inside the argument: backslash is doubled → `\\`, quote → `\"`
        // So the full encoding is `"a\\\"b"`.
        assert_eq!(result, "\"a\\\\\\\"b\"");
    }

    #[test]
    fn join_args_no_quoting_leaves_backslashes_verbatim() {
        // An argument with backslashes but no spaces/quotes: no quoting, no doubling.
        let args = vec!["C:\\Windows\\System32\\cmd.exe".to_string()];
        assert_eq!(join_args(&args), "C:\\Windows\\System32\\cmd.exe");
    }

    // ── ElevationOutcome display/equality ────────────────────────────────────

    #[test]
    fn elevation_outcome_failed_carries_message() {
        let o = ElevationOutcome::Failed("helper exit 2".to_string());
        assert_eq!(o, ElevationOutcome::Failed("helper exit 2".to_string()));
    }

    // ── run_elevated non-Windows stub ────────────────────────────────────────

    #[cfg(not(windows))]
    #[test]
    fn run_elevated_returns_windows_only_on_non_windows() {
        use super::run_elevated;
        let result = run_elevated(&[]);
        assert_eq!(result, Err("windows-only".into()));
    }
}
