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
//! Aliveness vs teardown (#319): `pid_alive` asks `GetExitCodeProcess` — a
//! process that exited but whose pid is still reserved by someone's open
//! handle (the zombie analog) reads as dead, mirroring the Unix `Z` state.
//! That is the right answer for "is the guest still running", and the WRONG
//! one for "may I reuse its disks": `TerminateProcess` sets the exit code at
//! once, while the kernel-side teardown that closes the handle table (disk
//! images, the vsock sockets, the `\Device\VidExo` WHP partition) runs
//! afterwards and can hang — observed as a worker with one thread left in a
//! kernel `Wait:Executive`, all handles open, hours later. The process
//! OBJECT is signaled only when teardown completes, so `tree_survivors` uses
//! `WaitForSingleObject(h, 0)`, never the exit code, and covers the WORKER
//! children too — `openvmm.exe` runs the VM in an `openvmm vm` child, and a
//! stop that verified only the recorded launcher once reported success while
//! the worker still held `rw.img`.

use super::survivors::{filter_tree_survivors, Candidate};
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
    WAIT_OBJECT_0,
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

/// Access [`open_sync_query`] asks for: read the creation time AND ask whether
/// the process object is signaled. `PROCESS_QUERY_LIMITED_INFORMATION |
/// SYNCHRONIZE`, written as one literal: the flags are disjoint bits, so the
/// `|`→`^` mutant of the OR is semantically identical and unkillable, and
/// cargo-mutants mutates const initialisers too.
/// `access_mask_literals_match_the_flags` pins the value.
const QUERY_SYNC_ACCESS: u32 = 0x0010_1000;

/// Access [`terminate_identity`] asks for: verify the creation time, terminate,
/// and wait for full death — all through the ONE handle that pins the process.
/// `PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` as one
/// literal — same reason as [`QUERY_SYNC_ACCESS`].
const TERMINATE_IDENTITY_ACCESS: u32 = 0x0010_1001;

/// Default image file name of the only VMM izba launches on Windows: OpenVMM,
/// whose `openvmm vm` worker re-runs the same binary (`crate::vmm::openvmm`
/// locates the bundled / `PATH` copy under this name). [`tree_survivors`] and
/// [`sweep_tree_survivors`] count only descendants with the VMM's image as
/// workers — see the image guard in [`super::survivors::filter_tree_survivors`]
/// — and take that image from [`vmm_worker_image`], which follows an
/// `$IZBA_OPENVMM` override and falls back to this name.
pub const VMM_IMAGE_NAME: &str = "openvmm.exe";

/// Environment override the OpenVMM driver resolves its binary by
/// (`crate::discover::find_tool`).
const OPENVMM_ENV: &str = "IZBA_OPENVMM";

/// Image name of this host's VMM worker, as [`tree_survivors`] expects it:
/// the file name of `$IZBA_OPENVMM` when that is set, else
/// [`VMM_IMAGE_NAME`]. The override and the bundled copy are the two launch
/// paths `crate::vmm::openvmm::find_openvmm` takes (its `PATH` fallback also
/// searches for [`VMM_IMAGE_NAME`]); the worker is the same binary, so its
/// image name is this file name.
///
/// Deliberately reads the variable instead of calling `find_tool`: that
/// fails when the override names a file that no longer exists, and falling
/// back to the default name then would ignore the workers of a VMM that WAS
/// launched from it — the unsafe direction. Only the file name matters here,
/// so the override's existence is irrelevant. Residual: the variable is read
/// in THIS process at stop time; a stop run with a different `$IZBA_OPENVMM`
/// than the start that launched the VMM can still miss its workers.
fn vmm_worker_image() -> String {
    worker_image_for(std::env::var_os(OPENVMM_ENV).as_deref())
}

/// [`vmm_worker_image`] over an explicit override value: its file name,
/// lowercased, or [`VMM_IMAGE_NAME`] when there is no override or it has no
/// file name (empty, a bare root such as `C:\`, or ending in `..`).
fn worker_image_for(override_path: Option<&std::ffi::OsStr>) -> String {
    override_path
        .and_then(|p| Path::new(p).file_name())
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| VMM_IMAGE_NAME.to_string())
}

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
///
/// `pub(crate)` so the confined-spawn path in `jail_windows.rs` builds its
/// returned `PidIdentity.starttime` with the SAME FILETIME read as
/// `spawn_detached` — one identity definition for both spawn paths.
pub(crate) fn creation_time(h: HANDLE) -> Option<u64> {
    let mut create: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle, four valid out-pointers.
    let ok = unsafe { GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user) };
    (ok != 0).then_some(((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
}

/// Creation time of `pid` — the Windows `starttime` identity token.
/// Returns the creation-time token for `pid`; used by `current_identity()` and
/// by tests that forge live `PidIdentity` values.
pub fn proc_starttime(pid: u32) -> anyhow::Result<u64> {
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

/// Like `spawn_detached`, but accepts resource limit hints that are ignored on
/// Windows — resource bounds here are enforced by the job object (out of scope
/// for the Windows VMM confinement path; `ResourceLimits` is a Linux-only concern).
pub fn spawn_detached_with_limits(
    cmd: &CommandSpec,
    log: &Path,
    _limits: &crate::procmgr::jail_linux::ResourceLimits,
) -> anyhow::Result<PidIdentity> {
    spawn_detached(cmd, log)
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
    descendants_in(&process_table(), root, root_starttime)
}

/// [`descendants_of`] over an already-taken snapshot, so a caller that also
/// needs each descendant's image name reads it from the SAME snapshot the
/// walk used.
fn descendants_in(table: &[ProcEntry], root: u32, root_starttime: u64) -> Vec<u32> {
    let mut frontier = vec![root];
    let mut found = Vec::new();
    let mut i = 0;
    while i < frontier.len() {
        let parent = frontier[i];
        i += 1;
        for e in table {
            if e.ppid != parent || e.pid == parent || frontier.contains(&e.pid) {
                continue;
            }
            if is_live_descendant(e.pid, root_starttime) {
                frontier.push(e.pid);
                found.push(e.pid);
            }
        }
    }
    found
}

/// One row of a Toolhelp process snapshot.
struct ProcEntry {
    pid: u32,
    ppid: u32,
    /// `szExeFile`, lowercased: the image's bare file name (no directory).
    image: String,
}

/// Decode a NUL-terminated `szExeFile` (C `char` array) and lowercase it.
/// Non-ASCII bytes of the ANSI code page are replaced lossily — only ever
/// compared against ASCII image names.
fn exe_file_name(sz: &[i8]) -> String {
    let bytes: Vec<u8> = sz
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_lowercase()
}

/// Snapshot the live process set. Empty on failure.
fn process_table() -> Vec<ProcEntry> {
    // SAFETY: plain FFI; the snapshot handle is closed by OwnedHandle.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let snap = OwnedHandle(snap);
    // SAFETY: PROCESSENTRY32 is plain-old-data; all-zero is a valid value.
    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut table: Vec<ProcEntry> = Vec::new();
    // SAFETY: valid snapshot handle and a properly-sized entry; `szExeFile`
    // is read only after Process32First/Next filled the entry.
    unsafe {
        if Process32First(snap.0, &mut entry) != 0 {
            loop {
                table.push(ProcEntry {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    image: exe_file_name(&entry.szExeFile),
                });
                if Process32Next(snap.0, &mut entry) == 0 {
                    break;
                }
            }
        }
    }
    table
}

/// True iff `pid` is openable and was created at or after `root_starttime` —
/// so a recycled PID claiming a dead parent's PID as PPID is never swept up.
fn is_live_descendant(pid: u32, root_starttime: u64) -> bool {
    let Some(h) = open_query(pid) else {
        return false;
    };
    matches!(creation_time(h.0), Some(t) if t >= root_starttime)
}

/// How long to wait for a terminated process to FULLY die. TerminateProcess
/// is asynchronous: the exit code is set immediately, but the process (and
/// its open handles — disk images, the vsock socket, the WHP partition)
/// lingers until kernel-side teardown finishes. Callers like `stop` rename
/// or reuse those resources right after kill, so kill must wait for the
/// handle to signal, not just for the exit code to flip.
/// The wait result is deliberately NOT the verdict: `stop` asks
/// [`tree_survivors`] afterwards, which covers the worker children too.
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

/// Open `pid` for liveness queries AND synchronization (needed to ask whether
/// the process object is signaled).
fn open_sync_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain FFI call; null means no such process or no access.
    let h = unsafe { OpenProcess(QUERY_SYNC_ACCESS, 0, pid) };
    if h.is_null() {
        None
    } else {
        Some(OwnedHandle(h))
    }
}

/// True iff the process object is signaled, i.e. kernel-side teardown has
/// completed and every handle the process held is closed. A terminated
/// process whose teardown is stuck already carries an exit code but is NOT
/// signaled — that is the whole point of asking this instead of
/// `GetExitCodeProcess`.
fn is_signaled(h: HANDLE) -> bool {
    // SAFETY: valid handle opened with SYNCHRONIZE; a zero timeout never blocks.
    unsafe { WaitForSingleObject(h, 0) == WAIT_OBJECT_0 }
}

/// Pid of the `System` process, whose creation time is the current boot.
const SYSTEM_PID: u32 = 4;

/// Creation time of the current boot, read EXACTLY as the `System` process's
/// creation time — `PROCESS_QUERY_LIMITED_INFORMATION` on pid 4 is granted to
/// unprivileged users. `None` when it cannot be read; the boot guard is then
/// disabled rather than estimated (see [`super::survivors::filter_tree_survivors`]).
/// Caveat: a Fast-Startup shutdown hibernates the kernel session instead of
/// ending it, so the `System` process (and this time) survives it; a tree
/// recorded before such a power cycle is then left to the pid-holder guard.
///
/// Clock assumption: process creation times are wall-clock stamps and are NOT
/// adjusted when the clock changes. If the clock is stepped BACK by Δ after
/// boot, launchers started within Δ of boot read as pre-boot and their
/// survivors are dropped — the unsafe direction (a live tree reported as
/// stopped). The robust form (recording the boot identity in `state.json` at
/// start and comparing by equality) is tracked as #327.
fn boot_time() -> Option<u64> {
    open_query(SYSTEM_PID).and_then(|h| creation_time(h.0))
}

/// Pids of the VMM process tree rooted at `id` — the recorded root (only
/// while its creation time still matches, defeating pid reuse) and every
/// descendant per [`descendants_of`] — whose process object is NOT yet
/// signaled: still running, or terminated but stuck in teardown with its
/// handles (disk images, sockets, the WHP partition) still held (#319).
///
/// An exited process whose pid is merely reserved (someone holds a handle)
/// is signaled and therefore not a survivor. A process this user cannot open
/// reads as gone — the same blind spot [`pid_alive`] has.
///
/// Once the root is dead the PPID walk keys on its pid NUMBER, which Windows
/// may hand to an unrelated process; the descendants are therefore passed
/// through [`super::survivors::filter_tree_survivors`] with three guards:
/// only a descendant whose image is the VMM's ([`vmm_worker_image`]) can be a worker (a
/// stranger that reused the pid, spawned a child and exited leaves no holder
/// to compare against — the image is then the only tell), a root created
/// before the current boot ([`boot_time`]) has no surviving tree, and when a
/// DIFFERENT process now holds the root pid, everything created at or after
/// that holder is the holder's, not ours. The recorded root itself is matched
/// by its exact creation time and is not image-filtered.
///
/// Residual: two STALE izba sandboxes whose launcher pids were reused by each
/// other's launchers can still cross-report (both trees are `openvmm.exe`);
/// the full fix records the worker identities in `state.json` at start
/// (#329).
///
/// Cost: one Toolhelp snapshot plus one `OpenProcess` + zero-timeout wait per
/// process of the tree, plus two `OpenProcess` calls for the guards; no sleeps.
pub fn tree_survivors(id: &PidIdentity) -> Vec<u32> {
    tree_survivors_of_image(id, &vmm_worker_image())
}

/// [`tree_survivors`] with the worker image as a parameter — the seam the
/// tests drive with a `sleep.exe` worker; production passes [`vmm_worker_image`].
fn tree_survivors_of_image(id: &PidIdentity, vmm_image: &str) -> Vec<u32> {
    tree_survivor_identities(id, vmm_image)
        .into_iter()
        .map(|s| s.pid)
        .collect()
}

/// [`tree_survivors_of_image`] with each survivor's creation time kept
/// alongside its pid — the identity [`sweep_tree_survivors`] re-verifies on
/// the very handle it terminates through, so a pid Windows recycled between
/// this enumeration and the kill is never terminated.
fn tree_survivor_identities(id: &PidIdentity, vmm_image: &str) -> Vec<PidIdentity> {
    let mut out = Vec::new();
    if let Some(h) = open_sync_query(id.pid) {
        if creation_time(h.0) == Some(id.starttime) && !is_signaled(h.0) {
            out.push(id.clone());
        }
    }
    // A different process now holding the root pid: its creation time, read
    // with query-only access so a holder we may not synchronize on still
    // counts.
    let pid_holder_created = open_query(id.pid)
        .and_then(|h| creation_time(h.0))
        .filter(|&t| t != id.starttime);
    // One snapshot for both the PPID walk and the image names, so a
    // candidate's image is the one recorded for that very pid in that walk.
    let table = process_table();
    let candidates: Vec<Candidate> = descendants_in(&table, id.pid, id.starttime)
        .into_iter()
        .filter_map(|pid| {
            // Every walked pid came from `table`, and a snapshot lists a pid once.
            let image = table.iter().find(|e| e.pid == pid)?.image.clone();
            let h = open_sync_query(pid)?;
            if is_signaled(h.0) {
                return None;
            }
            // `descendants_in` already required a readable creation time.
            let created = creation_time(h.0)?;
            Some(Candidate {
                pid,
                created,
                image,
            })
        })
        .collect();
    let kept = filter_tree_survivors(
        id.starttime,
        boot_time(),
        pid_holder_created,
        vmm_image,
        &candidates,
    );
    // `descendants_of` never yields a pid twice, so mapping the kept pids back
    // onto their candidates recovers each survivor's creation time exactly.
    out.extend(
        candidates
            .iter()
            .filter(|c| kept.contains(&c.pid))
            .map(|c| PidIdentity {
                pid: c.pid,
                starttime: c.created,
            }),
    );
    out
}

/// Terminate `target` only if the process holding its pid is still the one
/// with its recorded creation time, then wait (bounded) for full death.
///
/// The identity check and the kill go through the SAME handle: an open handle
/// pins the process object, so once its creation time matches, the
/// `TerminateProcess` on that handle cannot reach a process that later reuses
/// the pid. A mismatch means a different process now holds the pid — left
/// alone. Best-effort, like [`terminate_quiet`].
fn terminate_identity(target: &PidIdentity) {
    // SAFETY: plain FFI call; a null return (gone, or no access) is handled
    // below and the non-null handle is closed exactly once by OwnedHandle.
    let h = unsafe { OpenProcess(TERMINATE_IDENTITY_ACCESS, 0, target.pid) };
    if h.is_null() {
        return;
    }
    let h = OwnedHandle(h);
    if creation_time(h.0) != Some(target.starttime) {
        return;
    }
    // SAFETY: valid handle opened with PROCESS_TERMINATE | SYNCHRONIZE, and
    // it pins the very process whose creation time was just verified.
    unsafe {
        TerminateProcess(h.0, 1);
        WaitForSingleObject(h.0, TERMINATION_WAIT_MS);
    }
}

/// Terminate every process [`tree_survivors`] reports for `id`, waiting for
/// each to fully die (bounded, see [`TERMINATION_WAIT_MS`]) — the re-sweep
/// `stop` issues when the launcher is already gone but a worker of its tree
/// is still there, possibly still running the guest (#319).
///
/// Deliberately NOT [`kill_pid`]: once the launcher is dead its sweep walks
/// PPIDs by the launcher's pid NUMBER with only the creation-time floor, so
/// if Windows has handed that pid to another process it would terminate that
/// process's children. This sweep kills exactly what `tree_survivors`
/// reports, after its image, boot-time and pid-holder guards — and carries each
/// survivor's IDENTITY, not its bare pid, to [`terminate_identity`]: the
/// bounded wait on one survivor can take seconds, long enough for a later
/// survivor to exit and its pid to be reused. Best-effort and infallible,
/// like `kill_pid`'s own descendant sweep; the caller re-probes.
pub fn sweep_tree_survivors(id: &PidIdentity) -> anyhow::Result<()> {
    sweep_tree_survivors_of_image(id, &vmm_worker_image())
}

/// [`sweep_tree_survivors`] with the worker image as a parameter — the test
/// seam, like [`tree_survivors_of_image`].
fn sweep_tree_survivors_of_image(id: &PidIdentity, vmm_image: &str) -> anyhow::Result<()> {
    for target in tree_survivor_identities(id, vmm_image) {
        terminate_identity(&target);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// The access masks are single literals so the mutation gate has no `|`
    /// to flip into an equivalent `^`; this pins them to the real flags.
    #[test]
    fn access_mask_literals_match_the_flags() {
        assert_eq!(
            QUERY_SYNC_ACCESS,
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        );
        assert_eq!(
            TERMINATE_IDENTITY_ACCESS,
            PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
        );
    }

    /// Image of the test trees' worker (Git for Windows' `sleep.exe`), passed
    /// to the `_of_image` seams in place of [`vmm_worker_image`].
    const SLEEP: &str = "sleep.exe";

    /// Serializes every test that reads or writes `$IZBA_OPENVMM` (the only
    /// env var this module's production code reads).
    static OPENVMM_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Sets (`Some`) or removes (`None`) `$IZBA_OPENVMM` while held, restoring
    /// the previous value on drop — so an assertion failure cannot leak the
    /// test's value into a later test. Holds [`OPENVMM_ENV_LOCK`].
    struct OpenvmmEnv {
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl OpenvmmEnv {
        fn set(value: Option<&str>) -> Self {
            // A test that panicked while holding the lock still restored the
            // variable in Drop, so a poisoned lock is safe to reuse.
            let lock = OPENVMM_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let prev = std::env::var_os(OPENVMM_ENV);
            match value {
                Some(v) => std::env::set_var(OPENVMM_ENV, v),
                None => std::env::remove_var(OPENVMM_ENV),
            }
            OpenvmmEnv { prev, _lock: lock }
        }
    }

    impl Drop for OpenvmmEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(OPENVMM_ENV, v),
                None => std::env::remove_var(OPENVMM_ENV),
            }
        }
    }

    /// Fix round 1 of the #328 review: the expected worker image follows the
    /// `$IZBA_OPENVMM` override the launcher resolves by — a VMM launched
    /// from a renamed binary must not have its workers ignored — and is the
    /// default name when the variable is unset.
    #[test]
    fn vmm_worker_image_follows_the_izba_openvmm_override() {
        {
            let _env = OpenvmmEnv::set(Some("C:\\x\\OpenVMM-Dev.EXE"));
            assert_eq!(vmm_worker_image(), "openvmm-dev.exe");
        }
        {
            let _env = OpenvmmEnv::set(None);
            assert_eq!(vmm_worker_image(), VMM_IMAGE_NAME);
        }
    }

    #[test]
    fn worker_image_for_falls_back_when_the_override_has_no_file_name() {
        use std::ffi::OsStr;
        assert_eq!(worker_image_for(None), VMM_IMAGE_NAME);
        assert_eq!(worker_image_for(Some(OsStr::new(""))), VMM_IMAGE_NAME);
        assert_eq!(worker_image_for(Some(OsStr::new("C:\\"))), VMM_IMAGE_NAME);
        assert_eq!(
            worker_image_for(Some(OsStr::new("D:\\vmm\\openvmm.exe"))),
            "openvmm.exe"
        );
    }

    #[test]
    fn exe_file_name_stops_at_the_nul_and_lowercases() {
        let mut sz = [0i8; 16];
        for (d, s) in sz.iter_mut().zip(b"OpenVMM.EXE\0junk") {
            *d = *s as i8;
        }
        assert_eq!(exe_file_name(&sz), "openvmm.exe");
    }

    fn log_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("izba-{tag}-{}.log", std::process::id()))
    }

    /// Poll `pred` for up to `timeout`; true if it held before the deadline.
    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if pred() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Pid of a live descendant of `root` whose image is `sleep.exe`, if any.
    /// (A console host — `conhost.exe` — may be a descendant too.)
    fn sleep_worker_of(root: &PidIdentity) -> Option<u32> {
        let table = process_table();
        descendants_in(&table, root.pid, root.starttime)
            .into_iter()
            .find(|pid| table.iter().any(|e| e.pid == *pid && e.image == SLEEP))
    }

    /// `TerminateProcess` on ONE pid with no descendant sweep (unlike
    /// `kill_pid`), so a test can orphan a worker on purpose.
    fn terminate_root_only(pid: u32) {
        // SAFETY: plain FFI; handle closed by OwnedHandle.
        let h = unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid) };
        assert!(!h.is_null(), "OpenProcess({pid}) for terminate");
        let h = OwnedHandle(h);
        // SAFETY: valid handle with PROCESS_TERMINATE | SYNCHRONIZE access.
        unsafe {
            TerminateProcess(h.0, 1);
            WaitForSingleObject(h.0, TERMINATION_WAIT_MS);
        }
    }

    /// #319: a running root is a survivor; after `kill_pid` waits out its
    /// teardown the tree is empty. (`sleep` is Git for Windows' sleep.exe,
    /// present on windows-latest — the same binary `testutil::spawn_sleep`
    /// relies on.)
    #[test]
    fn tree_survivors_lists_a_running_root_and_is_empty_after_it_fully_exits() {
        let id = spawn_detached(
            &CommandSpec {
                argv: vec!["sleep".into(), "30".into()],
            },
            &log_path("tree-root"),
        )
        .expect("spawn sleep");
        // `contains`, not equality: a console host (`conhost.exe`) may show up
        // as a descendant of the console client.
        assert!(
            tree_survivors(&id).contains(&id.pid),
            "a running root is a survivor"
        );

        kill_pid(&id).expect("kill");
        assert!(
            wait_until(Duration::from_secs(5), || tree_survivors(&id).is_empty()),
            "a terminated sleep must finish teardown and leave the tree"
        );
    }

    /// #319, the distinction the whole fix rests on: `GetExitCodeProcess` is
    /// NOT the criterion. Here the process has exited AND its pid is still
    /// reserved (our `Child` handle keeps the object alive — the "zombie
    /// analog" the module docs describe), so `open_query` still succeeds,
    /// yet the object IS signaled: not a survivor. If this ever reads as a
    /// survivor, every Windows stop would fail.
    #[test]
    fn tree_survivors_ignores_an_exited_process_whose_pid_our_handle_keeps_reserved() {
        let mut child = Command::new("C:\\Windows\\System32\\cmd.exe")
            .args(["/c", "exit", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd");
        let pid = child.id();
        let starttime = creation_time(child.as_raw_handle() as HANDLE).expect("creation time");
        child.wait().expect("wait"); // exited; `child` still holds the handle
        let id = PidIdentity { pid, starttime };

        assert!(
            open_query(pid).is_some(),
            "precondition: the pid is still reserved while we hold a handle"
        );
        assert!(!pid_alive(&id), "an exited process is not alive");
        // The pid we hold the handle for is the thing under test; a lingering
        // `conhost.exe` child of the just-exited cmd must not make this flaky.
        assert!(
            !tree_survivors(&id).contains(&id.pid),
            "an exited, signaled process is not a survivor even though its pid is reserved"
        );
        assert!(
            wait_until(Duration::from_secs(5), || tree_survivors(&id).is_empty()),
            "the whole tree must drain once any console host finishes teardown"
        );
        drop(child);
    }

    /// #319: the observed shape — the recorded launcher is gone but a worker
    /// child it spawned is still there. `cmd.exe /c sleep 30` is the
    /// launcher, `sleep` its worker; terminating ONLY cmd orphans sleep,
    /// whose PPID keeps naming the dead launcher. The tree must report the
    /// worker and not the launcher; `kill_pid`'s sweep then reaps it.
    #[test]
    fn tree_survivors_reports_an_orphaned_worker_after_its_launcher_is_gone() {
        let root = spawn_detached(
            &CommandSpec {
                argv: vec![
                    "C:\\Windows\\System32\\cmd.exe".into(),
                    "/c".into(),
                    "sleep 30".into(),
                ],
            },
            &log_path("tree-launcher"),
        )
        .expect("spawn cmd");
        // Wait for the `sleep.exe` worker specifically: a console host can be
        // a descendant long before sleep is spawned.
        assert!(
            wait_until(Duration::from_secs(5), || sleep_worker_of(&root).is_some()),
            "cmd must have spawned its sleep worker"
        );
        let worker = sleep_worker_of(&root).expect("sleep worker");

        terminate_root_only(root.pid);
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(&root)),
            "the launcher must be gone"
        );

        let survivors = tree_survivors_of_image(&root, SLEEP);
        assert!(
            !survivors.contains(&root.pid),
            "the torn-down launcher is not a survivor: {survivors:?}"
        );
        assert!(
            survivors.contains(&worker),
            "orphaned worker {worker} must be reported; got {survivors:?}"
        );

        kill_pid(&root).expect("sweep orphans");
        assert!(
            wait_until(Duration::from_secs(5), || tree_survivors_of_image(
                &root, SLEEP
            )
            .is_empty()),
            "the sweep must reap the orphaned worker"
        );
    }

    /// Spawn `cmd.exe /c sleep 30` and wait for its `sleep.exe` worker: a
    /// launcher with one real child, the shape of `openvmm.exe` + its
    /// `openvmm vm` worker.
    fn launcher_with_worker(tag: &str) -> (PidIdentity, u32) {
        let root = spawn_detached(
            &CommandSpec {
                argv: vec![
                    "C:\\Windows\\System32\\cmd.exe".into(),
                    "/c".into(),
                    "sleep 30".into(),
                ],
            },
            &log_path(tag),
        )
        .expect("spawn cmd");
        assert!(
            wait_until(Duration::from_secs(5), || sleep_worker_of(&root).is_some()),
            "cmd must have spawned its sleep worker"
        );
        let worker = sleep_worker_of(&root).expect("sleep worker");
        (root, worker)
    }

    /// 2000-01-01 00:00 UTC in FILETIME ticks (100 ns since 1601-01-01). A
    /// boot time earlier than this is a kernel lie, not a real boot — so it
    /// is the floor a plausible [`boot_time`] must clear.
    const FILETIME_2000: u64 = 125_911_584_000_000_000;

    /// Guard (a) is only as good as its input: where the boot time is
    /// readable, no process can predate it — and it is a REAL time, not a
    /// placeholder (`Some(0)`/`Some(1)` would satisfy `boot <= me` alone and
    /// silently disable the guard for every record). Opening pid 4 is NOT
    /// guaranteed for an unprivileged user (the spike recorded it failing),
    /// and production then disables the guard by design — so an unreadable
    /// boot time is a runtime skip here, not a failure.
    #[test]
    fn boot_time_is_readable_and_precedes_this_process() {
        let Some(boot) = boot_time() else {
            eprintln!(
                "skipped: pid 4 not openable by this user — boot guard disabled here by design"
            );
            return;
        };
        let me = proc_starttime(std::process::id()).expect("own creation time");
        assert!(
            boot > FILETIME_2000,
            "boot {boot} is not a plausible boot time (before 2000-01-01)"
        );
        assert!(
            boot <= me,
            "boot {boot} must not be after this process ({me})"
        );
    }

    /// #319 Fix 1 (b): a recorded launcher whose pid now belongs to a DIFFERENT
    /// process — modelled by forging an identity one tick older than the live
    /// `cmd.exe` that holds the pid — must not adopt that process's children.
    /// Before the pid-holder guard, the PPID walk reported the `sleep` child
    /// (created after the forged start time) as a surviving VMM worker,
    /// wedging the sandbox.
    #[test]
    fn tree_survivors_ignores_the_children_of_a_process_that_reused_the_launcher_pid() {
        let (holder, worker) = launcher_with_worker("tree-reused");
        let recorded = PidIdentity {
            pid: holder.pid,
            starttime: holder.starttime - 1,
        };
        let survivors = tree_survivors_of_image(&recorded, SLEEP);
        assert!(
            !survivors.contains(&worker),
            "the new pid holder's child {worker} is not ours: {survivors:?}"
        );
        assert!(
            survivors.is_empty(),
            "nothing of the new holder's tree is ours: {survivors:?}"
        );
        assert!(
            tree_survivors_of_image(&holder, SLEEP).contains(&worker),
            "control: under its real identity the worker IS a survivor"
        );
        kill_pid(&holder).expect("cleanup");
    }

    /// #319 Fix 1 (a): a record whose launcher started before the current
    /// boot has no surviving tree, whatever now claims its pid number as a
    /// parent. Modelled with a real orphaned worker whose launcher is gone,
    /// recorded with a pre-boot start time.
    ///
    /// Both branches below are the contract: where the boot time is readable
    /// the pre-boot record reports nothing; where it is not (pid 4 not
    /// openable by this user) the guard is disabled by design and the
    /// orphaned worker MUST still be reported — over-reporting is the safe
    /// direction (see `filter_tree_survivors`).
    #[test]
    fn tree_survivors_ignores_a_tree_recorded_before_the_current_boot() {
        let (root, worker) = launcher_with_worker("tree-preboot");
        terminate_root_only(root.pid);
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(&root)),
            "the launcher must be gone"
        );
        let pre_boot = PidIdentity {
            pid: root.pid,
            starttime: 1,
        };
        let survivors = tree_survivors_of_image(&pre_boot, SLEEP);
        match boot_time() {
            // The guard drops the record only because `1 < boot`; pin that the
            // boot is a real time so the test cannot pass on a placeholder.
            Some(boot) => {
                assert!(boot > FILETIME_2000, "implausible boot time {boot}");
                assert!(
                    survivors.is_empty(),
                    "a pre-boot record has no surviving tree: {survivors:?}"
                );
            }
            None => assert!(
                survivors.contains(&worker),
                "boot guard disabled (pid 4 unreadable): the orphaned worker {worker} \
                 must still be reported; got {survivors:?}"
            ),
        }
        assert!(
            tree_survivors_of_image(&root, SLEEP).contains(&worker),
            "control: the orphan IS a survivor of the real, post-boot record"
        );
        sweep_tree_survivors_of_image(&root, SLEEP).expect("sweep orphans");
    }

    /// #319 Fix 2: `stop`'s re-sweep for a launcher that is already gone
    /// reaps the orphaned, still-running worker of the real record.
    #[test]
    fn sweep_tree_survivors_reaps_an_orphaned_worker() {
        let (root, worker) = launcher_with_worker("sweep-orphan");
        terminate_root_only(root.pid);
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(&root)),
            "the launcher must be gone"
        );
        assert!(
            tree_survivors_of_image(&root, SLEEP).contains(&worker),
            "precondition"
        );

        sweep_tree_survivors_of_image(&root, SLEEP).expect("sweep");
        assert!(
            wait_until(Duration::from_secs(5), || tree_survivors_of_image(
                &root, SLEEP
            )
            .is_empty()),
            "the re-sweep must reap the orphaned worker"
        );
    }

    /// #319 Fix 2, the reason the re-sweep is not `kill_pid`: when the
    /// recorded launcher pid now belongs to a DIFFERENT process, the re-sweep
    /// must not terminate that process's children (`kill_pid`'s PPID-number
    /// sweep would).
    #[test]
    fn sweep_tree_survivors_spares_the_children_of_a_process_that_reused_the_launcher_pid() {
        let (holder, worker) = launcher_with_worker("sweep-reused");
        let recorded = PidIdentity {
            pid: holder.pid,
            starttime: holder.starttime - 1,
        };
        sweep_tree_survivors_of_image(&recorded, SLEEP).expect("sweep");
        assert!(pid_alive(&holder), "the new pid holder itself is untouched");
        assert!(
            tree_survivors_of_image(&holder, SLEEP).contains(&worker),
            "the new holder's child {worker} must still be running"
        );
        kill_pid(&holder).expect("cleanup");
    }

    /// PR #328 review (P1): the launcher dies, an unrelated program reuses
    /// its pid, spawns a child and EXITS — the pid is vacant again, so the
    /// pid-holder guard has nothing to compare against and the child is
    /// created after the recorded launcher. Modelled by an orphaned
    /// `sleep.exe` under the recorded `cmd.exe` launcher, whose pid nothing
    /// holds once cmd is gone: the PRODUCTION `tree_survivors` must report
    /// none of it (only an `openvmm.exe` can be our worker), and the
    /// production re-sweep must leave it running. The `_of_image` control
    /// proves the same tree DOES yield the worker when its image is the
    /// expected one, so the empty answer is the image filter's doing.
    #[test]
    fn production_tree_survivors_ignore_a_descendant_that_is_not_openvmm() {
        // Pin the production expectation to the default image, whatever the
        // CI job's environment says.
        let _env = OpenvmmEnv::set(None);
        assert_eq!(vmm_worker_image(), VMM_IMAGE_NAME);
        let (root, worker) = launcher_with_worker("tree-foreign-image");
        terminate_root_only(root.pid);
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(&root)),
            "the launcher must be gone"
        );
        assert!(
            tree_survivors_of_image(&root, SLEEP).contains(&worker),
            "control: with its own image named, the orphan IS reported"
        );

        let survivors = tree_survivors(&root);
        assert!(
            survivors.is_empty(),
            "no descendant that is not {VMM_IMAGE_NAME} may be reported: {survivors:?}"
        );
        sweep_tree_survivors(&root).expect("sweep");
        assert!(
            tree_survivors_of_image(&root, SLEEP).contains(&worker),
            "the production re-sweep must not terminate a non-VMM process ({worker})"
        );

        sweep_tree_survivors_of_image(&root, SLEEP).expect("cleanup");
    }
}
