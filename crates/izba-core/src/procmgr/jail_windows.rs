//! Windows host-side confinement for the VMM: builds the restricted, low-
//! integrity primary token the OpenVMM process is launched under (the
//! `CreateProcessAsUserW` spawn itself lands in a later phase).
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

use crate::procmgr::confine::{ConfinementPolicy, IntegrityLevel};
use crate::procmgr::windows::creation_time;
use crate::state::PidIdentity;
use crate::vmm::CommandSpec;
use anyhow::Context;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, SetTokenInformation, TokenIntegrityLevel, DISABLE_MAX_PRIVILEGE,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
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
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

/// `SE_GROUP_INTEGRITY` (winnt.h) — the SID-and-attributes flag marking a group
/// as the token's integrity label. windows-sys only exports it from the
/// `Win32_System_SystemServices` feature (not enabled here), so define the fixed
/// value locally, mirroring the `SYNCHRONIZE` pattern in `windows.rs`.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// Builds the single primary token the VMM runs under: privileges dropped,
/// integrity lowered. Restricting/deny-only SID shaping per `policy.token` is a
/// follow-up (DISABLE_MAX_PRIVILEGE is the proven baseline that keeps WHP).
///
/// Used by `probe_confinable` and (in a later task) by `spawn_confined`.
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
/// SAFETY: FFI; the converted SID is owned by the OS allocation and intentionally
/// not freed here (process-lifetime; matches the short-lived token-build path).
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
    Ok(())
}

/// One-shot host capability probe: can a process under the VMM policy be built?
/// For now (full WHP round-trip wired in Phase 4) it returns true iff the
/// confined token can be constructed — the necessary precondition. Returns false
/// (degrade) on any failure so the launch path can fall back + report honestly.
pub fn probe_confinable(policy: &ConfinementPolicy, probe_exe: &std::path::Path) -> bool {
    let _ = probe_exe; // reserved for the Phase-4 WHP round-trip
                       // SAFETY: FFI; token closed on the success path.
    unsafe {
        match build_confined_token(policy) {
            Ok(t) => {
                CloseHandle(t);
                true
            }
            Err(_) => false,
        }
    }
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
/// the same PidIdentity the daemonless liveness model uses. Job handle is
/// intentionally leaked (no kill-on-close) so the VMM survives the launcher.
/// FAILS CLOSED: if the confined token can't be built, returns Err (never an
/// unconfined spawn). SAFETY: linear FFI; setup handles closed; job leaked.
pub fn spawn_confined(
    cmd: &CommandSpec,
    log: &Path,
    policy: &ConfinementPolicy,
) -> anyhow::Result<PidIdentity> {
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
        let spawn = (|| -> anyhow::Result<PidIdentity> {
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
            // FILE_APPEND_DATA (0x0004) within the GENERIC_WRITE umbrella;
            // OPEN_ALWAYS creates if absent, opens+seeks-to-end via append.
            let hlog = CreateFileW(
                log_w.as_ptr(),
                GENERIC_WRITE,
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
            let inner = (|| -> anyhow::Result<PidIdentity> {
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
                let built = (|| -> anyhow::Result<PidIdentity> {
                    if InitializeProcThreadAttributeList(attr, 2, 0, &mut size) == 0 {
                        anyhow::bail!(
                            "InitializeProcThreadAttributeList: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                    // From here, `attr` is initialized → must be Delete'd too.
                    let after_init = (|| -> anyhow::Result<PidIdentity> {
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
                        match create_resource_job(&job_name_w, policy.job_memory_max_mb) {
                            Ok(job) => {
                                if AssignProcessToJobObject(job, pi.hProcess) == 0 {
                                    eprintln!(
                                        "izba: AssignProcessToJobObject({job_name}): {} — running without resource job",
                                        std::io::Error::last_os_error()
                                    );
                                    CloseHandle(job);
                                } else {
                                    // Leak the job handle: closing it must never
                                    // kill members, and izbad reopens by name.
                                    std::mem::forget(OwnedJobHandle(job));
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "izba: resource job for {job_name}: {e:#} — running without it"
                                );
                            }
                        }

                        // 7. Resume the suspended child now that it is confined +
                        //    (best-effort) job-assigned.
                        ResumeThread(pi.hThread);

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
                        Ok(PidIdentity {
                            pid,
                            starttime: starttime?,
                        })
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
