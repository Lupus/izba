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
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, SetTokenInformation, TokenIntegrityLevel, DISABLE_MAX_PRIVILEGE,
    SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, SetInformationJobObject, JobObjectExtendedLimitInformation,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
// NEVER import/use JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — izbad death/upgrade must
// not kill VMMs (izba daemonless contract).
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
        anyhow::bail!(
            "CreateRestrictedToken: {}",
            std::io::Error::last_os_error()
        );
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
// Unused until Task 8 wires `spawn_confined`; the job is the resource-cap layer.
#[allow(dead_code)]
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
        anyhow::bail!("SetInformationJobObject: {}", std::io::Error::last_os_error());
    }
    Ok(job)
}
