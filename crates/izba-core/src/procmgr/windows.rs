//! Windows process management: detached spawn via creation flags, identity
//! via the process creation time, kill via `TerminateProcess`.
//!
//! Detachment notes: Windows children survive their parent's exit by default
//! (no session/SIGHUP coupling), so there is no `setsid` analog to perform —
//! `CREATE_NO_WINDOW` keeps the child off the console and
//! `CREATE_NEW_PROCESS_GROUP` detaches it from Ctrl-C delivery. We
//! deliberately do NOT use a job object: the daemonless design requires the
//! VMM to outlive the CLI.
//!
//! Aliveness: a process that exited but still has open handles keeps its PID
//! reserved (the zombie analog) — `GetExitCodeProcess` reports its exit code,
//! so the `STILL_ACTIVE` check treats it as dead, mirroring the Unix `Z`
//! state handling.

use crate::state::PidIdentity;
use crate::vmm::CommandSpec;
use anyhow::Context;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

/// `GetExitCodeProcess` sentinel for "still running" (`STATUS_PENDING`).
/// A process could in principle exit with code 259; that misread is the
/// documented Win32 caveat and is corrected by the next liveness probe.
const STILL_ACTIVE: u32 = 259;

/// Closes the handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: handle came from a successful OpenProcess and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn open_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain FFI call; a null return means no such process (or no
    // access, which for same-user izba-spawned processes means "gone").
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        None
    } else {
        Some(OwnedHandle(h))
    }
}

/// Process creation time as a single u64 (FILETIME: 100 ns ticks since 1601).
fn creation_time(h: HANDLE) -> Option<u64> {
    let mut create: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle, four valid out-pointers.
    let ok = unsafe { GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user) };
    (ok != 0).then_some(((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
}

/// Creation time of `pid` — the Windows `starttime` identity token.
/// Test-only: consumed by `sandbox.rs` unit tests forging live identities
/// (see the re-export gate in `procmgr/mod.rs`).
#[cfg(test)]
pub(crate) fn proc_starttime(pid: u32) -> anyhow::Result<u64> {
    let h = open_query(pid).with_context(|| format!("no such process: {pid}"))?;
    creation_time(h.0).context("reading process creation time")
}

/// Spawn a process detached from the current console, with stdin null and
/// stdout+stderr appended to `log`. See the module docs for the detachment
/// and identity model.
pub fn spawn_detached(cmd: &CommandSpec, log: &Path) -> anyhow::Result<PidIdentity> {
    let logf = File::options()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening log {}", log.display()))?;
    let mut c = Command::new(&cmd.argv[0]);
    c.args(&cmd.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(logf.try_clone()?))
        .stderr(Stdio::from(logf))
        .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    let child = c
        .spawn()
        .with_context(|| format!("spawning {:?}", cmd.argv))?;
    let pid = child.id();
    // Read the creation time through the Child's own handle: while `child`
    // is in scope the PID cannot be reused, and GetProcessTimes works even
    // if the process already exited.
    let starttime =
        creation_time(child.as_raw_handle() as HANDLE).context("reading process creation time")?;
    // Dropping `child` closes our handle without waiting or killing — the
    // process runs on independently (no kill-on-drop in std).
    drop(child);
    Ok(PidIdentity { pid, starttime })
}

/// Returns `true` iff the process exists, is still running (not the
/// exited-with-open-handles zombie analog), and has the recorded creation
/// time (defeats PID reuse).
pub fn pid_alive(id: &PidIdentity) -> bool {
    let Some(h) = open_query(id.pid) else {
        return false;
    };
    if creation_time(h.0) != Some(id.starttime) {
        return false;
    }
    let mut code: u32 = 0;
    // SAFETY: valid handle and out-pointer.
    let ok = unsafe { GetExitCodeProcess(h.0, &mut code) };
    ok != 0 && code == STILL_ACTIVE
}

/// Terminate the process identified by `id`, if it is still alive.
/// Idempotent: already-gone processes return `Ok(())`.
pub fn kill_pid(id: &PidIdentity) -> anyhow::Result<()> {
    if !pid_alive(id) {
        return Ok(());
    }
    // SAFETY: plain FFI call.
    let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, id.pid) };
    if h.is_null() {
        // Vanished between the aliveness check and here — already dead.
        return Ok(());
    }
    let h = OwnedHandle(h);
    // SAFETY: valid handle with PROCESS_TERMINATE access.
    let ok = unsafe { TerminateProcess(h.0, 1) };
    if ok == 0 {
        // ACCESS_DENIED can mean "already terminating": re-check before failing.
        if !pid_alive(id) {
            return Ok(());
        }
        anyhow::bail!(
            "TerminateProcess({}) failed: {}",
            id.pid,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
