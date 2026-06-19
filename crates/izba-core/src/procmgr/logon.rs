//! Two-hop VMM launcher: izbad (unprivileged) → `CreateProcessWithLogonW` as the
//! per-sandbox account → `izba __spawn-confined-vmm` (self-confines via
//! `spawn_confined` and writes `PidIdentity` to a pidfile).
//!
//! The pure helper `inner_launcher_argv` is testable on all platforms. The
//! Windows `CreateProcessWithLogonW` body is `#[cfg(windows)]`; non-Windows
//! compiles a stub.

use crate::vmm::CommandSpec;
use std::path::Path;

/// Build the argv vector for the `izba __spawn-confined-vmm` inner launcher.
///
/// This is a PURE function: it takes all inputs by value/reference and returns
/// a `Vec<String>`.  Testable on every platform — no OS calls.
///
/// The full VMM argv is NOT passed on the command line: `CreateProcessWithLogonW`
/// caps `lpCommandLine` at 1024 characters and a real OpenVMM invocation (kernel,
/// initrd, per-disk/-share root ports, virtio-blk/-fs, vsock — ~1.5 KB) exceeds
/// that, failing with `ERROR_INVALID_PARAMETER`. Instead the argv is written to
/// `specfile` (a JSON array the account can read) and only the short path rides
/// the command line:
/// ```text
/// [ <exe>, "__spawn-confined-vmm", "--pidfile", <pidfile>, "--log", <log>,
///   "--spec", <specfile> ]
/// ```
pub fn inner_launcher_argv(exe: &Path, pidfile: &Path, log: &Path, specfile: &Path) -> Vec<String> {
    vec![
        exe.to_string_lossy().into_owned(),
        "__spawn-confined-vmm".to_string(),
        "--pidfile".to_string(),
        pidfile.to_string_lossy().into_owned(),
        "--log".to_string(),
        log.to_string_lossy().into_owned(),
        "--spec".to_string(),
        specfile.to_string_lossy().into_owned(),
    ]
}

/// Launch the VMM as the given standard local account via `CreateProcessWithLogonW`,
/// wait for the inner launcher to exit, then recover the `PidIdentity` the inner
/// launcher wrote to `pidfile`.
///
/// # Two-hop flow
///
/// 1. izbad calls this function with the account credentials and VMM spec.
/// 2. This function resolves `std::env::current_exe()` as the inner launcher.
/// 3. `CreateProcessWithLogonW(account, ".", password, LOGON_WITH_PROFILE, …)`
///    launches `izba __spawn-confined-vmm --pidfile <P> --log <L> --spec <S>`
///    as the per-sandbox account (the VMM argv is written to `<S>`, not passed
///    inline — see `inner_launcher_argv`).
/// 4. That inner `izba` process — now running AS the account — calls
///    `spawn_confined(vmm_spec, log, vmm_default())` which self-derives the
///    restricted/Low-IL token from its OWN (account) token, then writes the
///    resulting `PidIdentity` to `<P>` and exits 0.
/// 5. We wait for the inner process, check exit code, read `<P>`, return the
///    `PidIdentity`.
///
/// # Errors
///
/// Returns `Err` if:
/// - `current_exe()` fails,
/// - `CreateProcessWithLogonW` fails,
/// - the inner launcher exits nonzero,
/// - the pidfile is missing or malformed after a zero exit.
#[cfg(windows)]
pub fn spawn_confined_as_account(
    account: &str,
    password: &str,
    vmm: &CommandSpec,
    log: &Path,
    pidfile: &Path,
) -> anyhow::Result<(crate::state::PidIdentity, crate::procmgr::ConfinementMode)> {
    use anyhow::Context;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CreateProcessWithLogonW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, INFINITE, LOGON_WITH_PROFILE, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    let exe = std::env::current_exe().context("current_exe")?;

    // Write the VMM argv to a spec file in the (account-readable) run dir and pass
    // it by PATH: CreateProcessWithLogonW caps lpCommandLine at 1024 chars, which a
    // real OpenVMM invocation exceeds. The inner launcher reads it and hands it to
    // spawn_confined (CreateProcessAsUserW — no such cap).
    let specfile = pidfile.parent().unwrap_or(pidfile).join("vmm-spec.json");
    crate::state::save_json(&specfile, &vmm.argv)
        .with_context(|| format!("writing VMM spec {}", specfile.display()))?;
    let inner_argv = inner_launcher_argv(&exe, pidfile, log, &specfile);

    // Delete any stale pidfile so we cannot accidentally read stale data on failure.
    let _ = std::fs::remove_file(pidfile);

    // Build NUL-terminated UTF-16 strings.
    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let username_w = to_wide_nul(account);
    let domain_w = to_wide_nul(".");
    let password_w = to_wide_nul(password);

    // Build the command line using the existing quoted builder from jail_windows.
    let cmdline_str = crate::jail_account::helper::join_args(&inner_argv);
    // CreateProcessWithLogonW requires a MUTABLE buffer for lpCommandLine.
    let mut cmdline_w: Vec<u16> = cmdline_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // exe path as wide NUL-terminated for lpApplicationName.
    use std::os::windows::ffi::OsStrExt;
    let app_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // lpCurrentDirectory MUST be a directory the TARGET account can access.
    // CreateProcessWithLogonW launches as a DIFFERENT user; a NULL cwd inherits
    // the CALLER's working directory, which the dedicated per-sandbox account is
    // NOT ACL-granted (e.g. the caller's home under another user's profile) — the
    // logon then fails with ERROR_INVALID_PARAMETER / ERROR_INVALID_NAME. Use the
    // sandbox run dir (the pidfile's parent): the account IS granted the sandbox
    // dir (inherited) and the run dir already exists. Verified on the real host.
    let cwd = pidfile.parent().unwrap_or(pidfile);
    let cwd_w: Vec<u16> = cwd
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: linear FFI. All buffers outlive the call. pi.hProcess/hThread are
    // closed on all exit paths. We do NOT call CreateProcessAsUserW here — the
    // caller (izbad) is unprivileged and cannot build a token for the other
    // account; CreateProcessWithLogonW does the logon internally.
    let pid_identity = unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessWithLogonW(
            username_w.as_ptr(),
            domain_w.as_ptr(),
            password_w.as_ptr(),
            LOGON_WITH_PROFILE,
            app_w.as_ptr(),         // lpApplicationName (PCWSTR — const pointer)
            cmdline_w.as_mut_ptr(), // lpCommandLine (PWSTR — must be mutable)
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(), // inherit environment
            cwd_w.as_ptr(),   // run dir (account-accessible); NULL would inherit
            // the caller's cwd, which the per-sandbox account cannot access
            &si,
            &mut pi,
        );
        if ok == 0 {
            anyhow::bail!(
                "CreateProcessWithLogonW(account={account:?}): {}",
                std::io::Error::last_os_error()
            );
        }

        // Wait for the inner launcher to finish.
        let wait = WaitForSingleObject(pi.hProcess, INFINITE);
        if wait != WAIT_OBJECT_0 {
            let err = std::io::Error::last_os_error();
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            anyhow::bail!("WaitForSingleObject(inner launcher): {err}");
        }

        let mut exit_code: u32 = 0;
        let got = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hThread);

        // Read the inner-launcher's PID before closing pi.hProcess so we still
        // hold the handle (pin the PID alive) while reading starttime below.
        // (The inner launcher's VMM is a DIFFERENT process; pi.dwProcessId here
        // is the INNER LAUNCHER's pid, not the VMM's pid. We only need the
        // inner launcher's process handle alive long enough to call
        // GetExitCodeProcess — the VMM identity comes from the pidfile.)
        if got == 0 {
            let err = std::io::Error::last_os_error();
            CloseHandle(pi.hProcess);
            anyhow::bail!("GetExitCodeProcess(inner launcher): {err}");
        }
        CloseHandle(pi.hProcess);

        if exit_code != 0 {
            // Try to tail the log for a diagnostic message.
            let log_tail = std::fs::read_to_string(log)
                .unwrap_or_default()
                .lines()
                .rev()
                .take(10)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("inner launcher exited with code {exit_code}; log tail:\n{log_tail}");
        }

        // The inner launcher wrote the VMM's PidIdentity to pidfile.
        crate::state::load_json(pidfile)
            .with_context(|| format!("reading pidfile {}", pidfile.display()))?
            .with_context(|| {
                format!(
                    "pidfile {} is missing after inner launcher exit 0",
                    pidfile.display()
                )
            })?
    };

    Ok((pid_identity, crate::procmgr::ConfinementMode::Restricted))
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn spawn_confined_as_account(
    _account: &str,
    _password: &str,
    _vmm: &CommandSpec,
    _log: &Path,
    _pidfile: &Path,
) -> anyhow::Result<(crate::state::PidIdentity, crate::procmgr::ConfinementMode)> {
    anyhow::bail!("spawn_confined_as_account: windows-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn inner_launcher_argv_structure() {
        let exe = PathBuf::from("/usr/bin/izba");
        let pidfile = PathBuf::from("/tmp/sandbox/pid.json");
        let log = PathBuf::from("/tmp/sandbox/vmm.log");
        let spec = PathBuf::from("/tmp/sandbox/vmm-spec.json");

        let got = inner_launcher_argv(&exe, &pidfile, &log, &spec);

        // Fixed-length, short command line (the VMM argv is passed by file path,
        // not inline — CreateProcessWithLogonW caps lpCommandLine at 1024 chars).
        assert_eq!(
            got,
            vec![
                exe.to_string_lossy().into_owned(),
                "__spawn-confined-vmm".to_string(),
                "--pidfile".to_string(),
                pidfile.to_string_lossy().into_owned(),
                "--log".to_string(),
                log.to_string_lossy().into_owned(),
                "--spec".to_string(),
                spec.to_string_lossy().into_owned(),
            ]
        );
    }

    #[test]
    fn inner_launcher_argv_is_bounded_short() {
        // The whole point: the command line stays short regardless of the VMM
        // invocation size, so it never trips the 1024-char CreateProcessWithLogonW
        // limit. There are exactly 8 fixed elements; none carries the VMM argv.
        let got = inner_launcher_argv(
            &PathBuf::from("/usr/bin/izba"),
            &PathBuf::from("/tmp/pid.json"),
            &PathBuf::from("/tmp/vmm.log"),
            &PathBuf::from("/tmp/vmm-spec.json"),
        );
        assert_eq!(got.len(), 8);
        assert!(!got.contains(&"--".to_string()), "VMM argv is not inline");
    }

    #[test]
    fn inner_launcher_argv_contains_subcommand() {
        let got = inner_launcher_argv(
            &PathBuf::from("/bin/izba"),
            &PathBuf::from("/p"),
            &PathBuf::from("/l"),
            &PathBuf::from("/s"),
        );
        assert!(
            got.contains(&"__spawn-confined-vmm".to_string()),
            "must contain the subcommand name"
        );
        assert!(got.contains(&"--pidfile".to_string()));
        assert!(got.contains(&"--log".to_string()));
        assert!(got.contains(&"--spec".to_string()));
    }

    #[test]
    fn pidfile_roundtrip() {
        use crate::state::{load_json, save_json, PidIdentity};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pid.json");

        let original = PidIdentity {
            pid: 12345,
            starttime: 9876543210,
        };
        save_json(&path, &original).expect("save_json");

        let loaded: PidIdentity = load_json(&path).expect("load_json").expect("must exist");
        assert_eq!(loaded.pid, original.pid);
        assert_eq!(loaded.starttime, original.starttime);
    }

    #[cfg(not(windows))]
    #[test]
    fn spawn_confined_as_account_is_windows_only() {
        use crate::vmm::CommandSpec;
        let result = spawn_confined_as_account(
            "user",
            "pass",
            &CommandSpec { argv: vec![] },
            &PathBuf::from("/tmp/vmm.log"),
            &PathBuf::from("/tmp/pid.json"),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("windows-only"));
    }
}
