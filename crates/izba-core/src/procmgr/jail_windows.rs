//! Windows host-side confinement for the VMM: builds the restricted, low-
//! integrity primary token the OpenVMM process is launched under, and spawns it
//! confined via `CreateProcessAsUserW` (`spawn_confined`).
//!
//! Win32 plumbing structure adapted from OpenAI codex windows-sandbox-rs
//! (Apache-2.0); lifecycle inverted to detached spawn.
//!
//! The confinement baseline is empirically grounded: a restricted token
//! (`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`) plus a Low integrity
//! label (`SetTokenInformation(TokenIntegrityLevel)`) was proven to still open
//! the WHP device `\Device\VidExo`, so the VM can boot while the broker runs
//! deprivileged. Restricting/deny-only SID shaping per `policy.token` is a
//! follow-up — dropping privileges is the proven precondition.

use crate::procmgr::confine::{
    workspace_confinement_denied_msg, ConfinementMode, ConfinementPolicy, IntegrityLevel,
};
use crate::procmgr::windows::creation_time;
use crate::state::PidIdentity;
use crate::vmm::CommandSpec;
use anyhow::Context;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AddMandatoryAce, CreateRestrictedToken, GetLengthSid, InitializeAcl, SetTokenInformation,
    TokenIntegrityLevel, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, DISABLE_MAX_PRIVILEGE,
    LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES,
    TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
// NEVER import/use JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — izbad death/upgrade must
// not kill VMMs (izba daemonless contract).
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

/// `SE_GROUP_INTEGRITY` (winnt.h) — the SID-and-attributes flag marking a group
/// as the token's integrity label. windows-sys only exports it from the
/// `Win32_System_SystemServices` feature (not enabled here), so define the fixed
/// value locally, mirroring the `SYNCHRONIZE` pattern in `windows.rs`.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` (winnt.h) — the mandatory policy of a
/// label ACE: deny write access to anything at a higher integrity level. This
/// is the only policy bit we set; it makes the label a pure no-write-up barrier
/// (NOT no-read-up / no-execute-up), which is what a Low-labelled scratch dir
/// needs. windows-sys only exports it from the un-enabled
/// `Win32_System_SystemServices` feature, so define the fixed value locally
/// (same pattern as `SE_GROUP_INTEGRITY`). `1`.
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0001;

/// `S-1-16-4096` — the Low integrity SID, as a NUL-terminated UTF-16 literal
/// for `ConvertStringSidToSidW`. `4096 == 0x1000 == SECURITY_MANDATORY_LOW_RID`.
const LOW_INTEGRITY_SID: &str = "S-1-16-4096\0";

/// `S-1-16-8192` — the Medium integrity SID (`8192 == 0x2000 ==
/// SECURITY_MANDATORY_MEDIUM_RID`). Medium is the *default* effective IL of an
/// unlabelled object, so re-applying it as an explicit inheritable label is a
/// semantically-equivalent restore of a workspace previously lowered to Low.
const MEDIUM_INTEGRITY_SID: &str = "S-1-16-8192\0";

/// `WRITE_OWNER` (winnt.h `0x0008_0000`) — the standard access right required to
/// set an object's mandatory integrity label via `SetNamedSecurityInfoW`.
/// windows-sys only exports the standard-rights constants from un-enabled
/// features, so define it locally (same rationale as `SE_GROUP_INTEGRITY`).
const WRITE_OWNER: u32 = 0x0008_0000;

/// Preflight a confinement write surface: can the confined (Low-IL) launch
/// relabel `path`? Setting the mandatory integrity label needs `WRITE_OWNER` on
/// the object (see [`apply_inheritable_integrity_label`]); probe for exactly that
/// right WITHOUT mutating anything by opening a handle that requests `WRITE_OWNER`
/// and closing it. A directory at the **root of a drive** grants this to no one —
/// not even its owner, who gets only implicit `READ_CONTROL` + `WRITE_DAC` — so
/// the open is denied and we return the actionable
/// [`workspace_confinement_denied_msg`].
///
/// Only `ERROR_ACCESS_DENIED` means "not confinable". Any other failure (a
/// transient sharing violation, an exotic path) is NOT a reason to block the
/// sandbox, so it returns `Ok` and lets the real relabel — if it runs — speak for
/// itself. Used as a create-time preflight and, via
/// [`set_low_integrity_recursive`], as the start-time guard.
#[cfg(windows)]
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
#[cfg(windows)]
fn current_account() -> String {
    match (
        std::env::var("USERDOMAIN").ok().filter(|s| !s.is_empty()),
        std::env::var("USERNAME").ok().filter(|s| !s.is_empty()),
    ) {
        (Some(domain), Some(user)) => format!("{domain}\\{user}"),
        (None, Some(user)) => user,
        _ => "<your-username>".to_string(),
    }
}

/// Label `path` (and, via inheritance, every existing and future child) with a
/// **Low** mandatory integrity label so a Low-IL process — the confined VMM —
/// can write into it. Two distinct surfaces need this:
///
///   1. the per-sandbox scratch dir izbad created at Medium IL (`console.log`,
///      `rw.img`, the vsock socket under `run/`) — without it the VM never boots
///      (MIC no-write-up, empty console.log, 100% boot failure); and
///   2. the **virtiofs workspace share** (the user's project dir) — the guest
///      writes `/workspace` through the in-process virtiofs server, which runs
///      *inside* the Low-IL VMM, so without a Low label on the share the guest's
///      writes fail (the core izba function is dead under confinement).
///
/// The Low label is inheritable (`OBJECT_INHERIT | CONTAINER_INHERIT`).
/// Inheritance is robust for the common case: empirically, a *Medium* process
/// (the user's editor/git) doing a plain create in the labelled tree yields a
/// Low-labelled child, so the guest can still write user-created-mid-session
/// files. Residual (documented in the spec / F-06 finding, benign): a host write
/// performed by **atomic-rename-in** from *outside* the labelled tree (some
/// editors'/git's temp-then-rename save) keeps the source's non-Low label, which
/// a Low-IL guest then can't write — narrow (most tools temp within the same
/// dir, which inherits Low) and fully fixed by the dedicated-account tier.
/// Restored to ~Medium on teardown by [`restore_integrity_recursive`].
#[cfg(windows)]
pub fn set_low_integrity_recursive(path: &Path) -> anyhow::Result<()> {
    // Fail fast with an actionable message when the dir cannot be relabelled at
    // all (e.g. a workspace at a drive root): otherwise the relabel below bails
    // with an opaque `SetNamedSecurityInfoW(..): WIN32_ERROR 5`. This makes the
    // start path explain the fix for a sandbox already pointing at such a dir.
    ensure_confinable(path)?;
    apply_inheritable_integrity_label(path, LOW_INTEGRITY_SID)
}

/// Restore `path` (and its subtree, via inheritance) to a **Medium** mandatory
/// integrity label, undoing a prior [`set_low_integrity_recursive`]. Called on
/// sandbox teardown (graceful stop, force-remove, and the stale-state sweep that
/// daemon adoption runs) so the user's workspace does not keep a Low label after
/// the confined VMM is gone.
///
/// Best-effort + idempotent: re-applying Medium (the default effective IL) is
/// safe to run repeatedly, and a missed restore only leaves a *benign* Low label
/// — Medium-IL tools write *down* to it freely, so the user's workflow is
/// unaffected; the only cost is a mild integrity weakening until the next
/// teardown/adoption sweep re-asserts Medium.
///
/// This is an *approximate* restore, not a perfect one — accepted residuals,
/// all benign for the integrity boundary and cleanly closed by the future
/// dedicated-account hardening tier (which never integrity-relabels the user's
/// dir at all). Documented in the design spec / F-06 finding:
///   - It re-asserts an **explicit** Medium label where the dir likely had none
///     (unlabelled == effective Medium). Equivalent for the common case; it does
///     NOT capture+restore a pre-existing *non-default* label, so a dir that was
///     genuinely Low/sub-Medium before izba ran ends up Medium (mildly *more*
///     restrictive to Low-IL writers). Project dirs are ~always unlabelled, so
///     this is rare.
///   - Re-propagation from the root refreshes only *inherited* child ACEs; a
///     child carrying its **own explicit** Low label — e.g. files the Low-IL VMM
///     created/modified — keeps it. So after teardown the workspace can hold a
///     scattering of Low files. Benign (Medium tools write *down* to them
///     freely); the boundary is unaffected.
#[cfg(windows)]
pub fn restore_integrity_recursive(path: &Path) -> anyhow::Result<()> {
    apply_inheritable_integrity_label(path, MEDIUM_INTEGRITY_SID)
}

/// Apply `sid_str` (a NUL-terminated integrity SID literal) as an inheritable
/// `SYSTEM_MANDATORY_LABEL_ACE` (no-write-up) on `path`.
///
/// Implementation choice **(a)** (the spec's preferred, self-contained + unit-
/// testable path): build a SACL holding one `SYSTEM_MANDATORY_LABEL_ACE` flagged
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, then apply it with
/// `SetNamedSecurityInfoW(.., SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, ..)`.
/// `SetNamedSecurityInfoW` performs inheritance propagation itself: setting an
/// inheritable label on the container re-applies it to the existing subtree AND
/// it is inherited by children created later, so no manual recursion is needed.
/// izbad runs at Medium, so writing either a Low (write-down) or a Medium label
/// is always within its rights.
///
/// SAFETY: linear FFI. The label SID is `LocalAlloc`'d by
/// `ConvertStringSidToSidW` and `LocalFree`'d once `AddMandatoryAce` has copied
/// it into the ACL (on the error path we bail before the free — a one-off small
/// leak only when an OS call fails). The ACL lives in a local heap `Vec<u8>`
/// whose lifetime spans the `SetNamedSecurityInfoW` call (the OS copies it), and
/// a NUL-terminated UTF-16 path buffer likewise outlives the call.
#[cfg(windows)]
fn apply_inheritable_integrity_label(path: &Path, sid_str: &str) -> anyhow::Result<()> {
    // SAFETY: a single linear FFI sequence; every buffer handed to the OS
    // outlives the call that reads it, and the label SID is LocalFree'd after
    // the ACL copies it.
    unsafe {
        // Resolve the integrity SID.
        let sid_str: Vec<u16> = sid_str.encode_utf16().collect();
        let mut sid = std::ptr::null_mut();
        if ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) == 0 {
            anyhow::bail!(
                "ConvertStringSidToSidW(integrity label): {}",
                std::io::Error::last_os_error()
            );
        }

        // Size a SACL big enough for the ACL header + one mandatory-label ACE.
        // The ACE carries a copy of the SID, so the buffer must include the
        // SID's length; SYSTEM_MANDATORY_LABEL_ACE's fixed header is the same
        // size as ACCESS_ALLOWED_ACE's, so size generously by adding the SID
        // length to a fixed ACL+ACE overhead. 64 bytes of overhead comfortably
        // covers the ACL header (8) + the label-ACE fixed fields.
        let sid_len = GetLengthSid(sid) as usize;
        let acl_size = 64 + sid_len;
        let mut acl_buf = vec![0u8; acl_size];
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        if InitializeAcl(acl, acl_size as u32, ACL_REVISION) == 0 {
            anyhow::bail!("InitializeAcl: {}", std::io::Error::last_os_error());
        }
        // The label ACE: the requested integrity, no-write-up, inherited by
        // files (OBJECT_INHERIT) and subdirectories (CONTAINER_INHERIT) so the
        // whole subtree carries it.
        if AddMandatoryAce(
            acl,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            sid,
        ) == 0
        {
            anyhow::bail!(
                "AddMandatoryAce(integrity label): {}",
                std::io::Error::last_os_error()
            );
        }
        // AddMandatoryAce copied the SID into the ACL, so release the
        // LocalAlloc'd SID now (this fn runs per-share + per-teardown +
        // per-adoption-sweep — frequent enough that the leak should not stand).
        LocalFree(sid as _);

        // Apply the SACL as the object's mandatory label. SetNamedSecurityInfoW
        // propagates the inheritable label across the existing subtree.
        let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
        path_w.push(0);
        let rc = SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(), // owner unchanged
            std::ptr::null_mut(), // group unchanged
            std::ptr::null(),     // DACL unchanged
            acl,                  // the SACL = our label
        );
        if rc != ERROR_SUCCESS {
            anyhow::bail!(
                "SetNamedSecurityInfoW({}): WIN32_ERROR {rc}",
                path.display()
            );
        }
    }
    Ok(())
}

/// Builds the single primary token the VMM runs under: privileges dropped,
/// integrity lowered. Restricting/deny-only SID shaping per `policy.token` is a
/// follow-up (DISABLE_MAX_PRIVILEGE is the proven baseline that keeps WHP).
///
/// Used by `spawn_confined`.
///
/// SAFETY: linear FFI; base token closed always, new token closed on error.
unsafe fn build_confined_token(policy: &ConfinementPolicy) -> anyhow::Result<HANDLE> {
    let mut base: HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut base) == 0 {
        anyhow::bail!("OpenProcessToken: {}", std::io::Error::last_os_error());
    }
    let flags = if policy.drop_all_privileges {
        DISABLE_MAX_PRIVILEGE
    } else {
        0
    };
    let mut tok: HANDLE = std::ptr::null_mut();
    let ok = CreateRestrictedToken(
        base,
        flags,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        &mut tok,
    );
    CloseHandle(base);
    if ok == 0 {
        anyhow::bail!("CreateRestrictedToken: {}", std::io::Error::last_os_error());
    }
    if let Err(e) = set_integrity(tok, policy.integrity) {
        CloseHandle(tok);
        return Err(e);
    }
    Ok(tok)
}

/// Lowers the integrity level of `tok` to the policy's IL via a mandatory
/// label. Returns an error (never a silent no-op) so the caller can fail the
/// confinement attempt rather than run at the parent's integrity.
///
/// SAFETY: FFI. `ConvertStringSidToSidW` returns a `LocalAlloc`'d SID; we
/// `LocalFree` it once `SetTokenInformation` has copied the label into the token
/// (on the error path we bail before the free — a one-off small leak only when
/// the OS call itself fails).
unsafe fn set_integrity(tok: HANDLE, il: IntegrityLevel) -> anyhow::Result<()> {
    let sid_str: Vec<u16> = match il {
        IntegrityLevel::Low => "S-1-16-4096\0".encode_utf16().collect(),
        IntegrityLevel::Medium => "S-1-16-8192\0".encode_utf16().collect(),
    };
    let mut sid = std::ptr::null_mut();
    if ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) == 0 {
        anyhow::bail!(
            "ConvertStringSidToSidW: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32;
    let r = SetTokenInformation(
        tok,
        TokenIntegrityLevel,
        &mut label as *mut _ as *const _,
        size,
    );
    if r == 0 {
        anyhow::bail!(
            "SetTokenInformation(IL): {}",
            std::io::Error::last_os_error()
        );
    }
    // The token holds its own copy of the label now; release the SID.
    LocalFree(sid as _);
    Ok(())
}

/// A NAMED, best-effort resource job. CRITICAL: never KILL_ON_JOB_CLOSE — izbad
/// death/upgrade must not kill VMMs. SILENT_BREAKAWAY_OK so an adopted VMM is
/// never tied to a launcher handle. Returns the job handle (kept by the caller;
/// closing it does NOT kill members).
/// SAFETY: FFI; on error the job handle is closed.
unsafe fn create_resource_job(name_w: &[u16], mem_mb: Option<u64>) -> anyhow::Result<HANDLE> {
    let job = CreateJobObjectW(std::ptr::null(), name_w.as_ptr());
    if job.is_null() {
        anyhow::bail!("CreateJobObjectW: {}", std::io::Error::last_os_error());
    }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if let Some(mb) = mem_mb {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = (mb as usize) * 1024 * 1024;
    }
    let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    if SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &info as *const _ as *const _,
        size,
    ) == 0
    {
        CloseHandle(job);
        anyhow::bail!(
            "SetInformationJobObject: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(job)
}

// Process-creation mitigation policy bits (winnt.h). windows-sys 0.60 only
// exports the DEP_* bits (from the un-enabled `WindowsProgramming` feature) and
// nothing above bit 32, so define every bit we OR locally — same pattern as
// `SE_GROUP_INTEGRITY`. The MITIGATION_POLICY attribute value is a DWORD64 once
// any ALWAYS_ON bit at/above 32 is set, hence u64 throughout.
//
// Deliberately ABSENT (unsafe for OpenVMM): CIG (BLOCK_NON_MICROSOFT_BINARIES —
// OpenVMM is not MS-signed), ACG (PROHIBIT_DYNAMIC_CODE — the emulator may JIT),
// and win32k-disable (not proven headless-safe).
/// DEP on, permanent. `1 << 0`.
const MIT_DEP_ENABLE: u64 = 0x0000_0001;
/// Mandatory ASLR: force-relocate images. `1 << 8`.
const MIT_FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 0x0000_0001 << 8;
/// Bottom-up randomization, on. `1 << 16`.
const MIT_BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 0x0000_0001 << 16;
/// High-entropy bottom-up randomization, on. `1 << 20`.
const MIT_HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 0x0000_0001 << 20;
/// Extension-point DLLs (legacy AppInit/IME hooks) blocked. `1 << 32`.
const MIT_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 0x0000_0001 << 32;
/// Image loads prefer System32 over the application directory. `1 << 60`.
const MIT_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 0x0000_0001 << 60;

/// Creation-time mitigations safe for OpenVMM (NO CIG, NO ACG, NO win32k-disable).
fn vmm_mitigation_flags() -> u64 {
    MIT_DEP_ENABLE
        | MIT_FORCE_RELOCATE_IMAGES_ALWAYS_ON
        | MIT_BOTTOM_UP_ASLR_ALWAYS_ON
        | MIT_HIGH_ENTROPY_ASLR_ALWAYS_ON
        | MIT_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | MIT_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
}

/// Quote one argument per the `CommandLineToArgvW` rules CreateProcess parses:
/// only quote when the arg is empty or contains space/tab/quote; double embedded
/// quotes' preceding backslash runs and the trailing backslash run so the
/// closing `"` is not escaped.
fn quote_arg(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Escape the run of backslashes (each doubled) AND the quote.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Double the trailing backslash run so the closing quote stays literal.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

/// Build a NUL-terminated UTF-16 mutable command line from argv (CreateProcess
/// requires a writable buffer for `lpCommandLine`).
fn build_command_line(argv: &[String]) -> Vec<u16> {
    let mut s = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        quote_arg(a, &mut s);
    }
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Spawn `cmd` confined per `policy`, detached, stdio appended to `log`. Returns
/// the daemonless-liveness PidIdentity plus the `ConfinementMode` actually
/// achieved: `Restricted` when the best-effort resource job was created AND
/// assigned, `TokenOnly` when the token+IL boundary succeeded but the job
/// could not be applied (the honest "no +job" status). Job handle is
/// intentionally leaked (no kill-on-close) so the VMM survives the launcher.
/// FAILS CLOSED: if the confined token can't be built, returns Err (never an
/// unconfined spawn). SAFETY: linear FFI; setup handles closed; job leaked.
pub fn spawn_confined(
    cmd: &CommandSpec,
    log: &Path,
    policy: &ConfinementPolicy,
) -> anyhow::Result<(PidIdentity, ConfinementMode)> {
    if cmd.argv.is_empty() {
        anyhow::bail!("spawn_confined: empty argv");
    }
    // SAFETY: a single linear FFI sequence; each handle/allocation acquired is
    // released on every exit path (token + log + attribute list freed before
    // return; the job is intentionally leaked via mem::forget). The token is
    // built FIRST and bails on failure, so no child is ever spawned unconfined.
    unsafe {
        // FAIL CLOSED: the security boundary (restricted token + IL) is built
        // before anything else; on failure we return without spawning.
        let token = build_confined_token(policy)?;

        // From here, `token` must be closed on every exit path.
        let spawn = (|| -> anyhow::Result<(PidIdentity, ConfinementMode)> {
            // 1. Inheritable append handle to the log file (mirrors the
            //    stdout/stderr→log redirection in windows.rs spawn_detached).
            //    This is the ONLY handle made inheritable into the child.
            let mut log_w: Vec<u16> = log.as_os_str().encode_wide().collect();
            log_w.push(0);
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1, // make the log handle inheritable
            };
            // FILE_APPEND_DATA is the atomic-append access right: every write
            // goes to end-of-file regardless of the handle's file pointer, so
            // VMM logs append rather than overwrite from offset 0 (matches
            // spawn_detached's OpenOptions::append). OPEN_ALWAYS creates if
            // absent, opens otherwise.
            let hlog = CreateFileW(
                log_w.as_ptr(),
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            if hlog == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                anyhow::bail!(
                    "CreateFileW({}): {}",
                    log.display(),
                    std::io::Error::last_os_error()
                );
            }

            // From here, `hlog` must be closed on every exit path.
            let inner = (|| -> anyhow::Result<(PidIdentity, ConfinementMode)> {
                // 2. Attribute list (count=2): the inheritable-handle allow-list
                //    (exactly [hlog]) + the mitigation policy.
                let mut size: usize = 0;
                // First call computes the required size (returns 0 / ERROR_INSUFFICIENT_BUFFER).
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
                if size == 0 {
                    anyhow::bail!(
                        "InitializeProcThreadAttributeList(size): {}",
                        std::io::Error::last_os_error()
                    );
                }
                let heap = GetProcessHeap();
                if heap.is_null() {
                    anyhow::bail!("GetProcessHeap: {}", std::io::Error::last_os_error());
                }
                let attr = HeapAlloc(heap, HEAP_ZERO_MEMORY, size)
                    as windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
                if attr.is_null() {
                    anyhow::bail!("HeapAlloc(attribute list)");
                }

                // From here, `attr` must be freed (HeapFree) on every exit path,
                // and once initialized also DeleteProcThreadAttributeList'd.
                // `handles` and `mit` back pointers handed to
                // UpdateProcThreadAttribute. They are declared HERE — in the
                // scope that calls DeleteProcThreadAttributeList(attr) below —
                // so it is self-evident their backing storage outlives the
                // attribute list it is wired into, even though the OS copies the
                // values eagerly on each Update call.
                let handles: [HANDLE; 1] = [hlog];
                let mit: u64 = vmm_mitigation_flags();
                let built = (|| -> anyhow::Result<(PidIdentity, ConfinementMode)> {
                    if InitializeProcThreadAttributeList(attr, 2, 0, &mut size) == 0 {
                        anyhow::bail!(
                            "InitializeProcThreadAttributeList: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                    // From here, `attr` is initialized → must be Delete'd too.
                    let after_init = (|| -> anyhow::Result<(PidIdentity, ConfinementMode)> {
                        // 2a. HANDLE_LIST = exactly [hlog]: the only handle the
                        //     child may inherit even with bInheritHandles=TRUE.
                        if UpdateProcThreadAttribute(
                            attr,
                            0,
                            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                            handles.as_ptr() as *const _,
                            std::mem::size_of::<HANDLE>(),
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        ) == 0
                        {
                            anyhow::bail!(
                                "UpdateProcThreadAttribute(HANDLE_LIST): {}",
                                std::io::Error::last_os_error()
                            );
                        }
                        // 2b. MITIGATION_POLICY = the OpenVMM-safe DEP/ASLR set.
                        if UpdateProcThreadAttribute(
                            attr,
                            0,
                            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                            &mit as *const u64 as *const _,
                            std::mem::size_of::<u64>(),
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        ) == 0
                        {
                            anyhow::bail!(
                                "UpdateProcThreadAttribute(MITIGATION_POLICY): {}",
                                std::io::Error::last_os_error()
                            );
                        }

                        // 3. STARTUPINFOEXW: stdout+stderr=hlog, stdin left null
                        //    (the child gets no console handle), attr list attached.
                        let mut si: STARTUPINFOEXW = std::mem::zeroed();
                        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
                        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                        si.StartupInfo.hStdInput = std::ptr::null_mut();
                        si.StartupInfo.hStdOutput = hlog;
                        si.StartupInfo.hStdError = hlog;
                        si.lpAttributeList = attr;

                        // 4. Mutable, quoted UTF-16 command line.
                        let mut cmdline = build_command_line(&cmd.argv);

                        // 5. CreateProcessAsUserW under the confined token,
                        //    suspended, detached, with the extended startupinfo.
                        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
                        let ok = CreateProcessAsUserW(
                            token,
                            std::ptr::null(),
                            cmdline.as_mut_ptr(),
                            std::ptr::null(),
                            std::ptr::null(),
                            1, // bInheritHandles=TRUE — but only the HANDLE_LIST passes
                            CREATE_SUSPENDED
                                | EXTENDED_STARTUPINFO_PRESENT
                                | CREATE_NO_WINDOW
                                | CREATE_NEW_PROCESS_GROUP
                                | CREATE_UNICODE_ENVIRONMENT,
                            std::ptr::null(),
                            std::ptr::null(),
                            &si.StartupInfo,
                            &mut pi,
                        );
                        if ok == 0 {
                            anyhow::bail!(
                                "CreateProcessAsUserW({:?}): {}",
                                cmd.argv,
                                std::io::Error::last_os_error()
                            );
                        }

                        // 6. Best-effort resource job (token+IL is the boundary;
                        //    the job is only resource caps). On failure we log and
                        //    still run the confined process. Job handle is leaked
                        //    (no kill-on-close) so closing can't kill the VMM and
                        //    izbad can reopen it by name on adoption.
                        let job_name = format!("izba-vmm-{}", pi.dwProcessId);
                        let job_name_w: Vec<u16> =
                            job_name.encode_utf16().chain(std::iter::once(0)).collect();
                        // Mode reflects what the resource job ACTUALLY achieved:
                        // `Restricted` only when both create AND assign succeed;
                        // `TokenOnly` if either fails (token+IL still applied, so
                        // the boundary is intact — the status must just not claim
                        // "+job"). This drives the honest ConfinementStatus.
                        let mode = match create_resource_job(&job_name_w, policy.job_memory_max_mb)
                        {
                            Ok(job) => {
                                if AssignProcessToJobObject(job, pi.hProcess) == 0 {
                                    eprintln!(
                                        "izba: AssignProcessToJobObject({job_name}): {} — running without resource job",
                                        std::io::Error::last_os_error()
                                    );
                                    CloseHandle(job);
                                    ConfinementMode::TokenOnly
                                } else {
                                    // Leak the job handle: closing it must never
                                    // kill members, and izbad reopens by name.
                                    std::mem::forget(OwnedJobHandle(job));
                                    ConfinementMode::Restricted
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "izba: resource job for {job_name}: {e:#} — running without it"
                                );
                                ConfinementMode::TokenOnly
                            }
                        };

                        // 7. Resume the suspended child now that it is confined +
                        //    (best-effort) job-assigned. ResumeThread returns
                        //    (DWORD)-1 on failure; if we ignored that, the child
                        //    would stay SUSPENDED forever yet read as alive
                        //    (pid_alive true), so the caller's boot wait would
                        //    time out with a misleading "VM never became healthy"
                        //    instead of a confinement error — and the suspended
                        //    process would pin the VMM binary + log + token. So on
                        //    failure, terminate it (handles still open) and bail.
                        if ResumeThread(pi.hThread) == u32::MAX {
                            let err = std::io::Error::last_os_error();
                            TerminateProcess(pi.hProcess, 1);
                            CloseHandle(pi.hThread);
                            CloseHandle(pi.hProcess);
                            anyhow::bail!("ResumeThread(confined VMM): {err}");
                        }

                        // 8. Identity from the SAME FILETIME read spawn_detached
                        //    uses; pi.hProcess pins the PID until we close it.
                        let pid = pi.dwProcessId;
                        let starttime = creation_time(pi.hProcess)
                            .context("reading confined process creation time");
                        // If the identity read fails, the child is ALREADY
                        // running confined — returning Err without killing it
                        // would leave an untracked-but-confined VMM (no
                        // state.json points at it, so nothing reaps it). Kill it
                        // while pi.hProcess is still open, then surface the Err.
                        if starttime.is_err() {
                            TerminateProcess(pi.hProcess, 1);
                        }
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        Ok((
                            PidIdentity {
                                pid,
                                starttime: starttime?,
                            },
                            mode,
                        ))
                    })();
                    DeleteProcThreadAttributeList(attr);
                    after_init
                })();
                HeapFree(heap, 0, attr as *const _);
                built
            })();
            CloseHandle(hlog);
            inner
        })();

        CloseHandle(token);
        spawn
    }
}

/// RAII wrapper used only to make the "leak the job handle" intent explicit at
/// the call site (`mem::forget`); we never let it Drop, so the job handle is
/// kept open for the VMM's lifetime (no kill-on-close).
struct OwnedJobHandle(HANDLE);
impl Drop for OwnedJobHandle {
    fn drop(&mut self) {
        // SAFETY: a job handle from create_resource_job, closed at most once.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_command_line, build_confined_token, create_resource_job, ensure_confinable,
        quote_arg, restore_integrity_recursive, set_low_integrity_recursive, spawn_confined,
    };
    use crate::procmgr::confine::{ConfinementMode, ConfinementPolicy};
    use crate::procmgr::windows::kill_pid;
    use crate::vmm::CommandSpec;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, LUID};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetAce, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
        LookupPrivilegeValueW, TokenIntegrityLevel, TokenPrivileges, ACL,
        LABEL_SECURITY_INFORMATION, SYSTEM_MANDATORY_LABEL_ACE, TOKEN_MANDATORY_LABEL,
        TOKEN_PRIVILEGES,
    };
    use windows_sys::Win32::System::JobObjects::{
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };

    /// `SECURITY_MANDATORY_LOW_RID` (winnt.h) — the last sub-authority (RID) of
    /// the Low integrity SID `S-1-16-4096`. windows-sys does not export the
    /// mandatory-RID constants, so define the fixed value locally (same pattern
    /// as `SE_GROUP_INTEGRITY`). `0x1000` == 4096.
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x0000_1000;

    /// `SECURITY_MANDATORY_MEDIUM_RID` (winnt.h) — the RID of the Medium
    /// integrity SID `S-1-16-8192`. `0x2000` == 8192.
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;

    fn quoted(arg: &str) -> String {
        let mut out = String::new();
        quote_arg(arg, &mut out);
        out
    }

    fn cmdline(argv: &[&str]) -> String {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let w = build_command_line(&owned);
        // Drop the trailing NUL terminator before decoding back to a String.
        assert_eq!(w.last(), Some(&0), "command line must be NUL-terminated");
        String::from_utf16(&w[..w.len() - 1]).expect("valid utf16")
    }

    #[test]
    fn empty_arg_is_quoted() {
        assert_eq!(quoted(""), "\"\"");
    }

    #[test]
    fn simple_arg_is_unquoted() {
        assert_eq!(quoted("plain"), "plain");
    }

    #[test]
    fn arg_with_spaces_is_quoted() {
        assert_eq!(quoted("a b"), "\"a b\"");
        assert_eq!(quoted("with\ttab"), "\"with\ttab\"");
    }

    #[test]
    fn embedded_quote_is_backslash_escaped() {
        // a"b -> "a\"b"
        assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn trailing_backslashes_before_closing_quote_are_doubled() {
        // The arg `a\` has spaces? No — but force quoting via a space so the
        // closing quote follows the backslash run, which must then be doubled.
        // `a \` -> "a \\"
        assert_eq!(quoted("a \\"), "\"a \\\\\"");
        // Two trailing backslashes -> doubled to four before the closing quote.
        assert_eq!(quoted("a \\\\"), "\"a \\\\\\\\\"");
    }

    #[test]
    fn backslashes_before_embedded_quote_are_doubled_plus_one() {
        // `a\"` -> the run of 1 backslash is doubled and the quote escaped:
        // "a\\\"" (i.e. backslash backslash backslash quote inside the quotes).
        assert_eq!(quoted("a\\\""), "\"a\\\\\\\"\"");
    }

    #[test]
    fn multi_arg_command_line() {
        assert_eq!(
            cmdline(&["openvmm.exe", "--config", "a b", "plain"]),
            "openvmm.exe --config \"a b\" plain"
        );
    }

    /// The confined token must (a) carry a Low integrity label and (b) have its
    /// privileges dropped to at most `SeChangeNotifyPrivilege` (what
    /// `DISABLE_MAX_PRIVILEGE` leaves behind). NOTE: this is NOT an
    /// `IsTokenRestricted` assertion — `build_confined_token` adds no restricting
    /// SIDs, so the token is "restricted" only in the privilege/IL sense.
    #[test]
    fn build_confined_token_drops_privileges_and_lowers_integrity() {
        // SAFETY: build the token under the documented policy, then query it via
        // GetTokenInformation into correctly-sized buffers; the token is closed
        // on every exit path.
        unsafe {
            let token =
                build_confined_token(&ConfinementPolicy::vmm_default()).expect("build token");

            // --- Integrity: extract the label SID's last sub-authority (RID). ---
            let mut needed: u32 = 0;
            // First call sizes the buffer (returns FALSE / ERROR_INSUFFICIENT_BUFFER).
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
            assert!(needed > 0, "TokenIntegrityLevel size query returned 0");
            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenIntegrityLevel,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            );
            assert!(ok != 0, "GetTokenInformation(IL): {}", last_err());
            // The buffer is a TOKEN_MANDATORY_LABEL whose Label.Sid points within it.
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            assert!(!sid.is_null(), "integrity SID is null");
            let count_p = GetSidSubAuthorityCount(sid);
            assert!(!count_p.is_null(), "GetSidSubAuthorityCount null");
            let count = *count_p;
            assert!(count >= 1, "integrity SID has no sub-authorities");
            // The RID is the LAST sub-authority.
            let rid = *GetSidSubAuthority(sid, (count - 1) as u32);
            assert_eq!(
                rid, SECURITY_MANDATORY_LOW_RID,
                "integrity RID {rid:#x} != SECURITY_MANDATORY_LOW_RID"
            );

            // --- Privileges: 0, or exactly SeChangeNotifyPrivilege. ---
            let mut needed: u32 = 0;
            GetTokenInformation(token, TokenPrivileges, std::ptr::null_mut(), 0, &mut needed);
            assert!(needed > 0, "TokenPrivileges size query returned 0");
            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenPrivileges,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            );
            assert!(ok != 0, "GetTokenInformation(privs): {}", last_err());
            let privs = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
            let n = privs.PrivilegeCount;
            assert!(
                n <= 1,
                "expected <=1 privilege after DISABLE_MAX_PRIVILEGE, got {n}"
            );
            if n == 1 {
                // The single survivor must be SeChangeNotifyPrivilege.
                let want = lookup_priv_luid("SeChangeNotifyPrivilege");
                // Privileges is a flexible array; the [0] element is in-struct.
                let got = privs.Privileges[0].Luid;
                assert!(
                    got.LowPart == want.LowPart && got.HighPart == want.HighPart,
                    "the surviving privilege is not SeChangeNotifyPrivilege"
                );
            }

            CloseHandle(token);
        }
    }

    /// The resource job must be breakaway-OK, NOT kill-on-close (izba daemonless
    /// contract), and carry the requested per-job memory cap.
    #[test]
    fn create_resource_job_is_breakaway_not_kill_on_close() {
        // SAFETY: create a uniquely-named job, query its extended limits into a
        // correctly-sized struct, then close the handle.
        unsafe {
            let name = format!("izba-test-job-{}", std::process::id());
            let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let job = create_resource_job(&name_w, Some(256)).expect("create job");

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            let mut ret: u32 = 0;
            let ok = QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut ret,
            );
            assert!(ok != 0, "QueryInformationJobObject: {}", last_err());

            let flags = info.BasicLimitInformation.LimitFlags;
            assert!(
                flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0,
                "SILENT_BREAKAWAY_OK not set (flags={flags:#x})"
            );
            assert!(
                flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0,
                "KILL_ON_JOB_CLOSE must never be set (flags={flags:#x})"
            );
            assert!(
                flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0,
                "JOB_MEMORY limit flag not set (flags={flags:#x})"
            );
            assert_eq!(
                info.JobMemoryLimit,
                256 * 1024 * 1024,
                "job memory limit mismatch"
            );

            CloseHandle(job);
        }
    }

    /// The full CreateProcessAsUserW launch path: builds the confined token +
    /// integrity label + attribute list + (best-effort) job and resumes a real
    /// child (`cmd /c exit 0`). Asserts it returns a usable identity and a
    /// confinement mode; cmd exits immediately, so we do NOT assert liveness.
    /// Best-effort kill for cleanup (the process has likely already exited).
    #[test]
    fn spawn_confined_launches_and_is_trackable() {
        let cmd = CommandSpec {
            argv: vec![
                "C:\\Windows\\System32\\cmd.exe".into(),
                "/c".into(),
                "exit".into(),
                "0".into(),
            ],
        };
        let log =
            std::env::temp_dir().join(format!("izba-spawn-confined-{}.log", std::process::id()));
        let (id, mode) =
            spawn_confined(&cmd, &log, &ConfinementPolicy::vmm_default()).expect("spawn_confined");
        assert_ne!(id.pid, 0, "spawned pid must be non-zero");
        assert!(
            matches!(
                mode,
                ConfinementMode::Restricted | ConfinementMode::TokenOnly
            ),
            "mode must be Restricted or TokenOnly, got {mode:?}"
        );
        // Best-effort cleanup: cmd /c exit 0 likely already exited, so ignore errors.
        let _ = kill_pid(&id);
        let _ = std::fs::remove_file(&log);
    }

    /// Labeling a directory tree Low must produce a readable Low mandatory label
    /// (RID == SECURITY_MANDATORY_LOW_RID) on the directory itself — and, via the
    /// inheritable ACE, on a file created inside it before labeling. We read the
    /// label back through `GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)` and
    /// walk the returned SACL to the single mandatory-label ACE's SID.
    #[test]
    fn set_low_integrity_recursive_sets_low_label() {
        let dir = std::env::temp_dir().join(format!("izba-low-il-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("rw.img");
        std::fs::write(&file, b"scratch").expect("create temp file");

        set_low_integrity_recursive(&dir).expect("set Low IL");

        // The directory must carry the Low label directly; the child file must
        // carry it via OBJECT_INHERIT propagation done by SetNamedSecurityInfoW.
        assert_eq!(
            read_label_rid(&dir),
            Some(SECURITY_MANDATORY_LOW_RID),
            "directory must carry a Low integrity label"
        );
        assert_eq!(
            read_label_rid(&file),
            Some(SECURITY_MANDATORY_LOW_RID),
            "child file must inherit the Low integrity label"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Teardown restore: after lowering a tree to Low, `restore_integrity_recursive`
    /// must raise the directory AND its **inherited** child back to a **Medium**
    /// mandatory label. This is the workspace-restore path run on sandbox stop /
    /// remove / adoption sweep. (A child carrying its OWN *explicit* Low label —
    /// e.g. a file the Low-IL VMM created — is a documented benign residual that
    /// re-propagation does not clear; not asserted here. See the function doc.)
    #[test]
    fn restore_integrity_recursive_raises_back_to_medium() {
        let dir = std::env::temp_dir().join(format!("izba-restore-il-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("rw.img");
        std::fs::write(&file, b"scratch").expect("create temp file");

        set_low_integrity_recursive(&dir).expect("set Low IL");
        assert_eq!(
            read_label_rid(&dir),
            Some(SECURITY_MANDATORY_LOW_RID),
            "precondition: directory is Low before restore"
        );

        restore_integrity_recursive(&dir).expect("restore Medium IL");
        assert_eq!(
            read_label_rid(&dir),
            Some(SECURITY_MANDATORY_MEDIUM_RID),
            "directory must be restored to a Medium integrity label"
        );
        assert_eq!(
            read_label_rid(&file),
            Some(SECURITY_MANDATORY_MEDIUM_RID),
            "child file must inherit the restored Medium label"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Read `path`'s mandatory-label SID RID via the security API, or `None` if
    /// the object has no label ACE. SAFETY: queries the SACL into an OS-allocated
    /// security descriptor (freed with LocalFree), then walks to ACE 0 — the
    /// label ACE we set — and extracts its SID's last sub-authority.
    fn read_label_rid(path: &std::path::Path) -> Option<u32> {
        use std::os::windows::ffi::OsStrExt;
        unsafe {
            let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
            path_w.push(0);
            let mut sacl: *mut ACL = std::ptr::null_mut();
            let mut sd = std::ptr::null_mut();
            let rc = GetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sacl,
                &mut sd,
            );
            assert_eq!(rc, ERROR_SUCCESS, "GetNamedSecurityInfoW: WIN32_ERROR {rc}");
            let result = (|| {
                if sacl.is_null() || (*sacl).AceCount == 0 {
                    return None;
                }
                let mut ace = std::ptr::null_mut();
                if GetAce(sacl, 0, &mut ace) == 0 {
                    return None;
                }
                let label = ace as *const SYSTEM_MANDATORY_LABEL_ACE;
                // SidStart is the first DWORD of the inline SID.
                let sid = std::ptr::addr_of!((*label).SidStart) as *mut core::ffi::c_void;
                let count_p = GetSidSubAuthorityCount(sid);
                if count_p.is_null() {
                    return None;
                }
                let count = *count_p;
                if count == 0 {
                    return None;
                }
                Some(*GetSidSubAuthority(sid, (count - 1) as u32))
            })();
            if !sd.is_null() {
                LocalFree(sd as _);
            }
            result
        }
    }

    fn last_err() -> std::io::Error {
        std::io::Error::last_os_error()
    }

    /// Look up the LUID of a well-known privilege on the local system.
    /// SAFETY: `LookupPrivilegeValueW` with a NUL-terminated name + out-LUID.
    fn lookup_priv_luid(name: &str) -> LUID {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid: LUID = unsafe { std::mem::zeroed() };
        let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) };
        assert!(ok != 0, "LookupPrivilegeValueW({name}): {}", last_err());
        luid
    }

    /// `domain\user` of the account running the tests, for icacls grants.
    fn current_user() -> String {
        let out = std::process::Command::new("whoami")
            .output()
            .expect("run whoami");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Re-grant Full Control to `user` (so cleanup can delete) and remove `dir`.
    fn restore_and_remove(dir: &std::path::Path, user: &str) {
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

    /// Start-time guard: `set_low_integrity_recursive` (run per write surface at
    /// launch) must fail closed with the actionable message for an existing
    /// sandbox whose workspace can't be relabelled — not the opaque WIN32 error.
    #[test]
    fn set_low_integrity_recursive_rejects_non_confinable_dir() {
        let Some(dir) = make_non_confinable_dir("setlow") else {
            eprintln!("skipped: environment could not produce a no-WRITE_OWNER dir");
            return;
        };
        let err = set_low_integrity_recursive(&dir).expect_err("relabel must fail closed");
        assert!(format!("{err}").contains("Full Control"), "{err}");
        restore_and_remove(&dir, &current_user());
    }
}
