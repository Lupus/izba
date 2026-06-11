//! Windows process management: detached spawn via creation flags, identity
//! via the process creation time, kill via `TerminateProcess` + a descendant
//! sweep.
//!
//! Detachment notes: Windows children survive their parent's exit by default
//! (no session/SIGHUP coupling), so there is no `setsid` analog to perform —
//! `CREATE_NO_WINDOW` keeps the child off the console and
//! `CREATE_NEW_PROCESS_GROUP` detaches it from Ctrl-C delivery. We
//! deliberately do NOT use a job object: the daemonless design requires the
//! VMM to outlive the CLI.
//!
//! Kill notes: `TerminateProcess` is not a tree kill, and OpenVMM runs the
//! actual VM in a `openvmm vm` worker child — terminating only the tracked
//! parent leaves the guest running with the disks and vsock socket held
//! (found by the Windows CLI-parity validation: `izba stop` "succeeded"
//! while the workload survived). `kill_pid` therefore also terminates every
//! live descendant of the target, validated by creation time so a recycled
//! PID is never killed by mistake.
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
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, WaitForSingleObject,
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

/// Generic `SYNCHRONIZE` access right (winnt.h) — windows-sys only exports
/// it from unrelated feature modules, so define the fixed value locally.
const SYNCHRONIZE: u32 = 0x0010_0000;

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

/// Stop our own std handles from being inherited by the spawned child.
///
/// When izba.exe itself runs in a pipeline, the shell hands it INHERITABLE
/// pipe handles. `Command::spawn` sets the child's stdio explicitly, but
/// CreateProcess with `bInheritHandles=TRUE` (which piped stdio forces)
/// duplicates EVERY other inheritable handle too — so the detached VMM ends
/// up holding the shell's pipe ends, and anything reading izba's output
/// waits for EOF until the VM dies, hours later. Best-effort: a missing
/// console handle is fine.
fn clamp_stdio_inheritance() {
    // SAFETY: adjusting a flag on our own std handles.
    unsafe {
        let _ = SetHandleInformation(
            std::io::stdin().as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        );
        let _ = SetHandleInformation(
            std::io::stdout().as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        );
        let _ = SetHandleInformation(
            std::io::stderr().as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        );
    }
}

/// Spawn a process detached from the current console, with stdin null and
/// stdout+stderr appended to `log`. See the module docs for the detachment
/// and identity model.
pub fn spawn_detached(cmd: &CommandSpec, log: &Path) -> anyhow::Result<PidIdentity> {
    clamp_stdio_inheritance();
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

/// Transitive live descendants of `root`, oldest-ancestor first.
///
/// Snapshot taken while the parent links are still meaningful; each
/// candidate must have been created at or after `root_starttime`, so a
/// recycled PID that merely happens to claim a dead parent's PID as its
/// PPID is never swept up.
fn descendants_of(root: u32, root_starttime: u64) -> Vec<u32> {
    // SAFETY: plain FFI; the snapshot handle is closed by OwnedHandle.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let snap = OwnedHandle(snap);
    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    // (pid, ppid) pairs for every live process.
    let mut table: Vec<(u32, u32)> = Vec::new();
    // SAFETY: valid snapshot handle and a properly-sized entry.
    unsafe {
        if Process32First(snap.0, &mut entry) != 0 {
            loop {
                table.push((entry.th32ProcessID, entry.th32ParentProcessID));
                if Process32Next(snap.0, &mut entry) == 0 {
                    break;
                }
            }
        }
    }
    let mut frontier = vec![root];
    let mut found = Vec::new();
    let mut i = 0;
    while i < frontier.len() {
        let parent = frontier[i];
        i += 1;
        for &(pid, ppid) in &table {
            if ppid != parent || pid == parent || frontier.contains(&pid) {
                continue;
            }
            let Some(h) = open_query(pid) else { continue };
            match creation_time(h.0) {
                Some(t) if t >= root_starttime => {
                    frontier.push(pid);
                    found.push(pid);
                }
                _ => {}
            }
        }
    }
    found
}

/// How long to wait for a terminated process to FULLY die. TerminateProcess
/// is asynchronous: the exit code is set immediately, but the process (and
/// its open handles — disk images, the vsock socket, the WHP partition)
/// lingers until kernel-side teardown finishes. Callers like `stop` rename
/// or reuse those resources right after kill, so kill must wait for the
/// handle to signal, not just for the exit code to flip.
const TERMINATION_WAIT_MS: u32 = 10_000;

/// Best-effort terminate + wait-for-full-death on a bare pid (used for the
/// descendant sweep, where there is no recorded identity beyond the
/// creation-time check already done in [`descendants_of`]).
fn terminate_quiet(pid: u32) {
    // SAFETY: plain FFI.
    let h = unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid) };
    if !h.is_null() {
        let h = OwnedHandle(h);
        // SAFETY: valid handle with PROCESS_TERMINATE | SYNCHRONIZE access.
        unsafe {
            TerminateProcess(h.0, 1);
            WaitForSingleObject(h.0, TERMINATION_WAIT_MS);
        }
    }
}

/// Terminate the process identified by `id` and every live descendant,
/// waiting for each to fully die (see [`TERMINATION_WAIT_MS`]).
/// Idempotent: already-gone processes return `Ok(())` — but the descendant
/// sweep still runs, catching workers orphaned by an earlier partial stop
/// (their PPID keeps pointing at the dead parent).
pub fn kill_pid(id: &PidIdentity) -> anyhow::Result<()> {
    // Collect descendants BEFORE terminating the root, while the snapshot
    // is cheap to interpret; the list stays valid afterwards.
    let descendants = descendants_of(id.pid, id.starttime);

    let root_result = (|| -> anyhow::Result<()> {
        if !pid_alive(id) {
            return Ok(());
        }
        // SAFETY: plain FFI call.
        let h = unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, id.pid) };
        if h.is_null() {
            // Vanished between the aliveness check and here — already dead.
            return Ok(());
        }
        let h = OwnedHandle(h);
        // SAFETY: valid handle with PROCESS_TERMINATE | SYNCHRONIZE access.
        let ok = unsafe { TerminateProcess(h.0, 1) };
        if ok == 0 {
            // ACCESS_DENIED can mean "already terminating": re-check before failing.
            if !pid_alive(id) {
                // SAFETY: still our valid handle; wait out the teardown.
                unsafe { WaitForSingleObject(h.0, TERMINATION_WAIT_MS) };
                return Ok(());
            }
            anyhow::bail!(
                "TerminateProcess({}) failed: {}",
                id.pid,
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: still our valid handle; block until full teardown (or
        // the bounded wait elapses — callers re-probe liveness anyway).
        unsafe { WaitForSingleObject(h.0, TERMINATION_WAIT_MS) };
        Ok(())
    })();

    for pid in descendants {
        terminate_quiet(pid);
    }
    root_result
}
