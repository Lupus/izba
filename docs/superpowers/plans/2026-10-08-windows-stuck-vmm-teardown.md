# Stuck VMM Teardown Detection (#319) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a kill, `izba stop` and `izba rm` refuse — loudly and with an actionable message — while ANY process of the sandbox's VMM tree (the recorded launcher or a worker child) has not finished kernel-side teardown, `state.json` stays, and `izba status` reports the sandbox degraded instead of stopped.

**Architecture:** One new process-manager primitive, `procmgr::tree_survivors(&PidIdentity) -> Vec<u32>`, answers "which processes of the tree rooted at the recorded VMM pid still exist as un-torn-down kernel objects". On Windows that is the process object NOT being signaled (`WaitForSingleObject(h, 0) == WAIT_TIMEOUT`) — `GetExitCodeProcess` is NOT the criterion, because `TerminateProcess` sets the exit code at once while the handle table (disks, `\Device\VidExo`) is still held. On Unix it is the root alone while `pid_alive` holds (same semantics as today). The primitive enters the product through the existing `liveness::Probes` seam: `assess` turns "launcher dead + a tree survivor" into `Liveness::Degraded(..)` (so `status`, `ls`, the daemon's stale-state reaper and `start`'s already-running guard all see it for free), and `stop_locked`/`remove` gain a post-kill gate that returns one shared refusal, `disks_held_error`. Everything is unit-tested through a fake `Probes` without an unkillable process; the Windows primitive itself gets real-process tests that run in CI's `cargo test (windows)` job.

**Tech Stack:** Rust (`izba-core` `procmgr`, `liveness`, `sandbox`; `izba-cli` reconcile probes), `windows-sys` 0.60 (`WaitForSingleObject`, `WAIT_OBJECT_0`, Toolhelp), `anyhow`; PowerShell for the real-host check script; Markdown spike doc.

**Spec:** GitHub issue [#319](https://github.com/Lupus/izba/issues/319) (body is the contract; no comments). Evidence source: spike finding 8 in `docs/spikes/0002-windows-container-probe-latency.md` (PR #318, may not be on `main` yet — do NOT link to it from code; link from the new spike doc only as "PR #318").

## Global Constraints

- **No `DAEMON_PROTO_VERSION` bump, no wire change.** `Liveness` travels as `Liveness::describe()` strings (`SandboxSummary.status`); a new *reason* string inside `degraded (…)` is not a wire change.
- **The new degraded reason must NEVER end with `)`** — `app/src-tauri/src/views.rs::parse_state` strips one trailing `)`.
- **Linux semantics unchanged in the normal path:** `tree_survivors` on Unix is `[root]` iff `pid_alive(root)`, else `[]` — exactly the gate `stop_locked` applied before. The only Linux-visible change is the wording of the (already existing) "VMM survived SIGKILL" refusal.
- **A normal stop must not get measurably slower:** the Windows primitive costs one Toolhelp snapshot plus one `OpenProcess`+`WaitForSingleObject(h, 0)` per process of the tree; no new waits, no new sleeps. The graceful-then-kill flow and `TERMINATION_WAIT_MS` are untouched.
- **No new privileges:** `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)` only — the same access class `pid_alive` already needs.
- Unit tests never bind unix/vsock listeners; sandbox tests reuse `testutil::{spawn_sleep, write_state, fake_connector, …}`. Windows real-process tests are `#[cfg(windows)]` and spawn `sleep`/`cmd.exe` exactly like the existing `spawn_sleep` helper does on `windows-latest`.
- Every `cargo` command: `cd /home/kolkhovskiy/git/izba && source .cargo-env; cd -` first in the same shell (the env file lives in the MAIN checkout), with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` exported (disk is tight). If cargo cannot write the registry inside the sandbox, run `cargo fetch` once unsandboxed, then pass `--offline`.
- All six gates from CLAUDE.md must be green before each commit: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, the musl `izba-init` build, and the two `x86_64-pc-windows-gnu` cross checks (`cargo check` + `cargo clippy --all-targets … -D warnings` for `izba-proto izba-core izba-cli izba-jail-helper izba-jail-naming`). The cross clippy with `--all-targets` COMPILES the `#[cfg(windows)]` tests — use it as the local Windows gate; they EXECUTE in CI's `cargo test (windows)` job.
- Conventional commits; each body ends with `Refs #319`. Stage by explicit path, never `git add -A`.

## Review Focus

- **Retrying `stop` after a refusal** (launcher already gone, worker still stuck): the pre-#319 code took the "already stopped → cleanup" path and wiped `state.json` on the second try. Pinned by `stop_refuses_when_the_launcher_is_already_gone_but_its_worker_survives` (Task 3).
- **The daemon's stale-state reaper (`reap_stale_stopped`, runs on every `ls`/adoption)** must not delete a stuck sandbox's `state.json`: it reaps only `Liveness::Stopped`. Pinned by `vmm_dead_with_a_surviving_tree_is_degraded_not_stopped` (Task 2).
- **An exited process whose pid is merely reserved by someone's open handle** (the Windows "zombie analog", e.g. our own `Child` handle) must NOT read as a survivor, or every Windows stop would start failing. Pinned by `tree_survivors_ignores_an_exited_process_whose_pid_our_handle_keeps_reserved` (Task 1).
- **`rm` WITHOUT `--force` on a stuck sandbox** must give the disks-held explanation, not "is running (use force to remove)" — force cannot help. Pinned by both arms of `rm_refuses_with_the_disks_held_explanation_with_and_without_force` (Task 3).
- **The GUI's `degraded (<reason>)` parser** strips one trailing `)`: a reason ending in `)` would lose a character silently. Pinned by `stuck_teardown_reason_never_ends_with_a_paren` (Task 2).

---

### Task 1: `procmgr::tree_survivors` — the primitive, both platforms

**Files:**
- Modify: `crates/izba-core/src/procmgr/unix.rs` (after `kill_pid`, before `mod tests`)
- Modify: `crates/izba-core/src/procmgr/windows.rs` (module doc; after `kill_pid`; new `#[cfg(test)] mod tests` at the end)
- Modify: `crates/izba-core/src/procmgr/mod.rs:27` and `:42` (re-exports)

**Interfaces:**
- Produces: `pub fn procmgr::tree_survivors(id: &PidIdentity) -> Vec<u32>` on both platforms. Contract: pids of the process tree rooted at `id` (the root itself only if its creation time still matches `id.starttime`; descendants per `descendants_of`) whose process has NOT finished teardown — still running, or terminated with its process object not yet signaled. A process that has fully exited but whose pid is still reserved (someone holds a handle / Unix zombie) is NOT a survivor. Unprivileged-unopenable processes read as gone (same blind spot as `pid_alive`).

- [ ] **Step 1: Write the failing Unix test**

In `crates/izba-core/src/procmgr/unix.rs`, inside the existing `#[cfg(test)] mod tests`, add:

```rust
    /// #319: the Unix tree is the root alone — cloud-hypervisor spawns no worker
    /// children (virtiofsd sidecars are tracked separately) — so a survivor is
    /// exactly a root that `pid_alive` still reports. Pins that the semantics
    /// `stop_locked` relied on before #319 are unchanged on this platform.
    #[test]
    fn tree_survivors_is_the_root_while_alive_and_empty_once_dead() {
        let dir = std::env::temp_dir();
        let id = spawn_detached(
            &CommandSpec {
                argv: vec!["sleep".into(), "30".into()],
            },
            &dir.join(format!("izba-tree-survivors-{}.log", std::process::id())),
        )
        .expect("spawn sleep");
        assert_eq!(tree_survivors(&id), vec![id.pid], "a running root survives");

        kill_pid(&id).expect("kill");
        // SIGKILL is asynchronous; the parentless child is reaped by init.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while pid_alive(&id) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(tree_survivors(&id).is_empty(), "a dead root has no survivors");
    }

    /// A recycled pid (identity with a mismatching starttime) is not a survivor.
    #[test]
    fn tree_survivors_is_empty_for_a_mismatching_identity() {
        let id = PidIdentity {
            pid: std::process::id(),
            starttime: 1,
        };
        assert!(tree_survivors(&id).is_empty());
    }
```

(Check the test module's existing `use` lines: it already imports `super::*` and `CommandSpec`; add `use crate::state::PidIdentity;` only if `super::*` does not already bring it in — it does, via the file-level `use crate::state::PidIdentity;`.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p izba-core --lib procmgr::unix::tests::tree_survivors -- --nocapture`
Expected: compile error `cannot find function tree_survivors`.

- [ ] **Step 3: Implement the Unix primitive**

In `crates/izba-core/src/procmgr/unix.rs`, right after `kill_pid`:

```rust
/// Pids of the VMM process tree rooted at `id` that still hold their
/// resources (#319). On Linux the VMM (cloud-hypervisor) spawns no worker
/// children — the virtiofsd sidecars are tracked separately in
/// `RunState.sidecar_pids` — so the tree is the root alone, and it survives
/// exactly while [`pid_alive`] holds: a SIGKILLed process stuck in an
/// uninterruptible `D` sleep still owns its disk fds and IS a survivor; a `Z`
/// zombie has released them and is NOT (its pid is merely reserved).
pub fn tree_survivors(id: &PidIdentity) -> Vec<u32> {
    if pid_alive(id) {
        vec![id.pid]
    } else {
        Vec::new()
    }
}
```

- [ ] **Step 4: Export it from `mod.rs`**

Change line 27 and line 42 of `crates/izba-core/src/procmgr/mod.rs` so both platform re-export lists include `tree_survivors`:

```rust
#[cfg(unix)]
pub use unix::{kill_pid, pid_alive, spawn_detached, spawn_detached_with_limits, tree_survivors};
```

```rust
#[cfg(windows)]
pub use windows::{kill_pid, pid_alive, spawn_detached, spawn_detached_with_limits, tree_survivors};
```

- [ ] **Step 5: Run the Unix tests**

Run: `cargo test -p izba-core --lib procmgr::unix::tests::tree_survivors`
Expected: both PASS.

- [ ] **Step 6: Write the Windows tests (compile-checked locally by the cross clippy; executed by CI)**

Append to the END of `crates/izba-core/src/procmgr/windows.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

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
        assert_eq!(tree_survivors(&id), vec![id.pid]);

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
        let starttime =
            creation_time(child.as_raw_handle() as HANDLE).expect("creation time");
        child.wait().expect("wait"); // exited; `child` still holds the handle
        let id = PidIdentity { pid, starttime };

        assert!(
            open_query(pid).is_some(),
            "precondition: the pid is still reserved while we hold a handle"
        );
        assert!(!pid_alive(&id), "an exited process is not alive");
        assert!(
            tree_survivors(&id).is_empty(),
            "an exited, signaled process is not a survivor even though its pid is reserved"
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
        assert!(
            wait_until(Duration::from_secs(5), || {
                !descendants_of(root.pid, root.starttime).is_empty()
            }),
            "cmd must have spawned its sleep worker"
        );
        let workers = descendants_of(root.pid, root.starttime);

        terminate_root_only(root.pid);
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(&root)),
            "the launcher must be gone"
        );

        let survivors = tree_survivors(&root);
        assert!(
            !survivors.contains(&root.pid),
            "the torn-down launcher is not a survivor: {survivors:?}"
        );
        for w in &workers {
            assert!(
                survivors.contains(w),
                "orphaned worker {w} must be reported; got {survivors:?}"
            );
        }

        kill_pid(&root).expect("sweep orphans");
        assert!(
            wait_until(Duration::from_secs(5), || tree_survivors(&root).is_empty()),
            "the sweep must reap the orphaned worker"
        );
    }
}
```

- [ ] **Step 7: Implement the Windows primitive**

In `crates/izba-core/src/procmgr/windows.rs`:

(a) Extend the import from `windows_sys::Win32::Foundation` with `WAIT_OBJECT_0`:

```rust
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
```

(b) Replace the module-doc paragraph that begins `//! Aliveness:` with:

```rust
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
```

(c) After `kill_pid`, add:

```rust
/// Open `pid` for liveness queries AND synchronization (needed to ask whether
/// the process object is signaled).
fn open_sync_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain FFI call; null means no such process or no access.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
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

/// Pids of the VMM process tree rooted at `id` — the recorded root (only
/// while its creation time still matches, defeating pid reuse) and every
/// descendant per [`descendants_of`] — whose process object is NOT yet
/// signaled: still running, or terminated but stuck in teardown with its
/// handles (disk images, sockets, the WHP partition) still held (#319).
///
/// An exited process whose pid is merely reserved (someone holds a handle)
/// is signaled and therefore not a survivor. A process this user cannot open
/// reads as gone — the same blind spot [`pid_alive`] has. The descendant walk
/// inherits `descendants_of`'s caveat: a recycled launcher pid whose new
/// owner has children created after the recorded start time would be
/// reported too — a loud, retry-able refusal, never a silent success.
///
/// Cost: one Toolhelp snapshot plus one `OpenProcess` + zero-timeout wait per
/// process of the tree; no sleeps.
pub fn tree_survivors(id: &PidIdentity) -> Vec<u32> {
    let mut out = Vec::new();
    if let Some(h) = open_sync_query(id.pid) {
        if creation_time(h.0) == Some(id.starttime) && !is_signaled(h.0) {
            out.push(id.pid);
        }
    }
    for pid in descendants_of(id.pid, id.starttime) {
        if let Some(h) = open_sync_query(pid) {
            if !is_signaled(h.0) {
                out.push(pid);
            }
        }
    }
    out
}
```

(d) In the doc comment of `TERMINATION_WAIT_MS`, append one sentence:

```rust
/// The wait result is deliberately NOT the verdict: `stop` asks
/// [`tree_survivors`] afterwards, which covers the worker children too.
```

- [ ] **Step 8: Compile the Windows code and tests through the cross gates**

Run:
```
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli -p izba-jail-helper -p izba-jail-naming
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -p izba-jail-helper -p izba-jail-naming -- -D warnings
```
Expected: both clean. (The Windows tests execute in CI's `cargo test (windows)` job; optionally try running them here via WSL interop with `cargo test --target x86_64-pc-windows-gnu -p izba-core --lib procmgr::windows` unsandboxed — if the test runner cannot execute the `.exe`, rely on CI.)

- [ ] **Step 9: Run the host gates and commit**

Run: `cargo test -p izba-core --lib procmgr && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: green.

```bash
git add crates/izba-core/src/procmgr/unix.rs crates/izba-core/src/procmgr/windows.rs crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(procmgr): tree_survivors — which VMM processes have not finished teardown

On Windows a terminated process carries an exit code immediately, while the
kernel-side teardown that releases its handles can hang; the process object
is signaled only when that completes. tree_survivors asks exactly that, for
the recorded root and its worker children, instead of GetExitCodeProcess.
Unix keeps the root-only, pid_alive-based semantics stop relied on so far.

Refs #319

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `liveness` — a dead launcher with a surviving tree is Degraded, not Stopped

**Files:**
- Modify: `crates/izba-core/src/liveness.rs` (trait, `assess`, new `stuck_teardown_reason`, tests)

**Interfaces:**
- Consumes: nothing new (the trait default needs only `pid_alive`).
- Produces:
  - `Probes::tree_survivors(&self, id: &PidIdentity) -> Vec<u32>` with a DEFAULT body (`[id.pid]` iff `pid_alive`, else `[]`) so `reconcile.rs`'s and `izba-cli`'s fakes keep compiling.
  - `pub fn liveness::stuck_teardown_reason(survivors: &[u32]) -> String` — the `Degraded` reason (the status surface). Task 3's `stop`/`rm` refusal is a separate, longer text that also says what to do; the two deliberately share the phrase "disks still held"/"still holds the sandbox's disks" but are not one string. Shape: `vmm process 30620 terminated but not torn down, disks still held` (plural `processes 1, 2` for more than one). Never ends with `)`.
  - `assess` rule 2 split: launcher dead + no survivor → `Stopped`; launcher dead + survivors → `Degraded(stuck_teardown_reason(..))`.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-core/src/liveness.rs`, inside `mod tests`:

(a) Give `FakeProbes` a `survivors` field and implement the method; add `survivors: vec![]` to EVERY existing `FakeProbes { .. }` literal in the module (five of them):

```rust
    struct FakeProbes {
        alive_pids: Vec<PidIdentity>,
        control: bool,
        /// What `tree_survivors` answers for ANY id — the fake models the
        /// stuck-teardown fact directly (#319).
        survivors: Vec<u32>,
    }

    impl Probes for FakeProbes {
        fn pid_alive(&self, id: &PidIdentity) -> bool {
            self.alive_pids.contains(id)
        }

        fn control_answers(&self) -> bool {
            self.control
        }

        fn tree_survivors(&self, _id: &PidIdentity) -> Vec<u32> {
            self.survivors.clone()
        }
    }
```

(b) Add these tests after `vmm_dead_is_stopped`:

```rust
    // -----------------------------------------------------------------------
    // Rule 2b (#319): vmm pid dead but a process of its tree still holds its
    // resources → Degraded, never Stopped. `Stopped` is what lets the daemon's
    // stale-state reaper delete state.json and `start` boot against the disks
    // that process still holds.
    // -----------------------------------------------------------------------
    #[test]
    fn vmm_dead_with_a_surviving_tree_is_degraded_not_stopped() {
        let run = run_with_sidecars(&[]);
        let p = FakeProbes {
            alive_pids: vec![],
            control: false,
            survivors: vec![30620],
        };
        match assess(Some(&run), &p) {
            Liveness::Degraded(reason) => {
                assert!(reason.contains("30620"), "names the pid: {reason}");
                assert!(reason.contains("disks still held"), "{reason}");
                assert!(reason.contains("not torn down"), "{reason}");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    /// The reason is rendered as `degraded (<reason>)` and the desktop app
    /// strips exactly one trailing `)` — a reason ending in `)` would lose a
    /// character. Pin it for one and for several pids.
    #[test]
    fn stuck_teardown_reason_never_ends_with_a_paren() {
        for pids in [&[30620u32][..], &[29588, 30620][..]] {
            let r = stuck_teardown_reason(pids);
            assert!(!r.ends_with(')'), "{r}");
            assert!(!r.is_empty());
        }
        assert_eq!(
            stuck_teardown_reason(&[30620]),
            "vmm process 30620 terminated but not torn down, disks still held"
        );
        assert_eq!(
            stuck_teardown_reason(&[29588, 30620]),
            "vmm processes 29588, 30620 terminated but not torn down, disks still held"
        );
    }

    /// Fakes that model only pid liveness (reconcile's, the CLI's) get the
    /// pre-#319 semantics from the trait default: the root is the whole tree.
    #[test]
    fn default_tree_survivors_is_the_root_while_alive() {
        struct PidOnly(Vec<PidIdentity>);
        impl Probes for PidOnly {
            fn pid_alive(&self, id: &PidIdentity) -> bool {
                self.0.contains(id)
            }
            fn control_answers(&self) -> bool {
                true
            }
        }
        let alive = PidOnly(vec![vmm_id()]);
        assert_eq!(alive.tree_survivors(&vmm_id()), vec![vmm_id().pid]);
        let dead = PidOnly(vec![]);
        assert!(dead.tree_survivors(&vmm_id()).is_empty());
        // And through assess: a dead root with the default is plain Stopped.
        let run = run_with_sidecars(&[]);
        assert_eq!(assess(Some(&run), &dead), Liveness::Stopped);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p izba-core --lib liveness::`
Expected: compile errors (`no method tree_survivors`, `cannot find function stuck_teardown_reason`, unknown field `survivors`).

- [ ] **Step 3: Implement**

Replace the trait and `assess` in `crates/izba-core/src/liveness.rs`:

```rust
pub trait Probes {
    /// Returns `true` iff the pid exists **and** its starttime matches.
    fn pid_alive(&self, id: &PidIdentity) -> bool;
    /// Returns `true` iff the control socket connects and the health check
    /// replies within a short timeout.
    fn control_answers(&self) -> bool;
    /// Pids of the VMM process tree rooted at `id` (the root and its worker
    /// children) that have NOT finished teardown and so still hold the
    /// sandbox's disks — see `procmgr::tree_survivors` (#319). The default is
    /// the pre-#319 reading, "the root is the whole tree, alive iff
    /// `pid_alive`", so fakes that model only pid liveness are unchanged.
    fn tree_survivors(&self, id: &PidIdentity) -> Vec<u32> {
        if self.pid_alive(id) {
            vec![id.pid]
        } else {
            Vec::new()
        }
    }
}
```

```rust
/// The `Degraded` reason for a VMM whose launcher is gone while a process of
/// its tree still holds the sandbox's disks (#319). Rendered inside
/// `degraded (…)`, so it must never end with `)` — the desktop app strips
/// exactly one trailing paren (`app/src-tauri/src/views.rs::parse_state`).
pub fn stuck_teardown_reason(survivors: &[u32]) -> String {
    let noun = if survivors.len() == 1 {
        "process"
    } else {
        "processes"
    };
    let pids: Vec<String> = survivors.iter().map(u32::to_string).collect();
    format!(
        "vmm {noun} {} terminated but not torn down, disks still held",
        pids.join(", ")
    )
}

/// Assess the liveness of a sandbox.
///
/// Precedence:
/// 1. `run == None`                        → Stopped
/// 2. vmm pid dead, nothing of its tree survives → Stopped
/// 2b. vmm pid dead but a process of its tree still holds its resources
///     → Degraded("vmm process <pid> terminated but not torn down, disks still
///     held") (#319) — never Stopped, which would let the stale-state reaper
///     delete state.json and a later start boot against held disks
/// 3. any sidecar dead                     → Degraded("sidecar <role> died")
///    (sidecar death takes precedence over control unresponsiveness)
/// 4. control not answering                → Degraded("control plane unresponsive")
/// 5. all alive + control answers          → Running
pub fn assess(run: Option<&RunState>, probes: &dyn Probes) -> Liveness {
    let run = match run {
        None => return Liveness::Stopped,
        Some(r) => r,
    };

    if !probes.pid_alive(&run.vmm_pid) {
        let survivors = probes.tree_survivors(&run.vmm_pid);
        if survivors.is_empty() {
            return Liveness::Stopped;
        }
        return Liveness::Degraded(stuck_teardown_reason(&survivors));
    }

    for (role, id) in &run.sidecar_pids {
        if !probes.pid_alive(id) {
            return Liveness::Degraded(format!("sidecar {role} died"));
        }
    }

    if !probes.control_answers() {
        return Liveness::Degraded("control plane unresponsive".to_string());
    }

    Liveness::Running
}
```

- [ ] **Step 4: Run the liveness tests**

Run: `cargo test -p izba-core --lib liveness::`
Expected: all PASS (including the five pre-existing ones with `survivors: vec![]`).

- [ ] **Step 5: Gates and commit**

Run: `cargo test -p izba-core --lib && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: green (the reconcile fakes compile via the default).

```bash
git add crates/izba-core/src/liveness.rs
git commit -m "feat(liveness): a dead launcher with a surviving VMM tree reads degraded, not stopped

Probes gains tree_survivors (default: the root while pid_alive), and assess
turns 'launcher gone but a process of its tree still holds the disks' into
Degraded with a reason that names the pid. Stopped is what let the stale-state
reaper drop state.json and a later start double-boot against held disks.

Refs #319

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `stop` and `rm` refuse while the tree survives; `status` tells the truth

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` — `RealProbes` impl (~line 787), `liveness_of` (~line 1200s; `grep -n '^pub fn liveness_of'`), `stop_locked` (~line 1577), `remove` (~line 1810), tests module
- Modify: `crates/izba-cli/src/commands/reconcile.rs:11-15` (`PidProbes`)
- Modify: `CLAUDE.md` (disk-state invariant bullet)

**Interfaces:**
- Consumes: `procmgr::tree_survivors`, `liveness::stuck_teardown_reason`, `Probes::tree_survivors` (Tasks 1–2).
- Produces (all `pub(crate)` unless noted):
  - `fn liveness_of_with(paths: &Paths, name: &str, probes: &dyn Probes) -> anyhow::Result<Liveness>`; `pub fn liveness_of(..)` delegates with `RealProbes`.
  - `fn stop_locked_with(paths, name, connector: Connector, timeout: Duration, graceful: bool, probes: &dyn Probes) -> anyhow::Result<()>`; `stop_locked(..)` delegates with `RealProbes`.
  - `fn remove_with(paths, name, connector, force: bool, probes: &dyn Probes) -> anyhow::Result<()>`; `pub fn remove(..)` delegates.
  - `fn disks_held_error(name: &str, survivors: &[u32]) -> anyhow::Error` — the ONE refusal text for stop and rm.
  - `fn refuse_if_teardown_stuck(paths, name, probes) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-core/src/sandbox.rs` `mod tests`, after `rm_force_escalates_when_guest_ignores_shutdown`:

```rust
    // -----------------------------------------------------------------------
    // #319: a VMM process that was terminated but has not finished teardown
    // still holds the sandbox's disks. These fakes answer the ONE question the
    // real primitive answers from the kernel ("which pids of the tree survive")
    // with a fixed list, so the stop/rm/status contract is pinned without an
    // unkillable process. pid liveness stays REAL (the sleep below is really
    // killed), only the teardown verdict is faked.
    // -----------------------------------------------------------------------
    struct StuckTeardownProbes {
        survivors: Vec<u32>,
    }

    impl Probes for StuckTeardownProbes {
        fn pid_alive(&self, id: &crate::state::PidIdentity) -> bool {
            procmgr::pid_alive(id)
        }
        fn control_answers(&self) -> bool {
            false
        }
        fn tree_survivors(&self, _id: &crate::state::PidIdentity) -> Vec<u32> {
            self.survivors.clone()
        }
    }

    /// The observed shape: launcher alive → killed → a worker lingers.
    /// `stop` must refuse, name the pid, say the disks are held, and keep
    /// state.json so no later start can double-boot.
    #[test]
    fn stop_refuses_and_keeps_state_while_a_vmm_tree_process_survives_the_kill() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        let conn = fake_connector(Arc::new(Mutex::new(Vec::new())), None);
        let probes = StuckTeardownProbes {
            survivors: vec![30620],
        };
        let err = format!(
            "{:#}",
            stop_locked_with(&paths, "web", &conn, Duration::from_millis(300), false, &probes)
                .unwrap_err()
        );
        assert!(err.contains("30620"), "names the pid: {err}");
        assert!(err.contains("still holds the sandbox's disks"), "{err}");
        assert!(err.contains("state preserved"), "{err}");
        assert!(err.contains("izba stop web"), "says what to do: {err}");
        assert!(
            paths.sandbox_dir("web").join(STATE_FILE).exists(),
            "state.json must survive a refused stop"
        );
        assert!(wait_dead(&sleep_id), "the kill itself still happens");
    }

    /// The retry: the launcher is already gone (a previous stop killed it) but
    /// the worker still lingers. Before #319 this took the "already stopped →
    /// cleanup" path and wiped state.json. It must refuse exactly like the
    /// first attempt.
    #[test]
    fn stop_refuses_when_the_launcher_is_already_gone_but_its_worker_survives() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", dead_identity());

        let conn = fake_connector(Arc::new(Mutex::new(Vec::new())), None);
        let probes = StuckTeardownProbes {
            survivors: vec![30620],
        };
        let err = format!(
            "{:#}",
            stop_locked_with(&paths, "web", &conn, Duration::from_millis(300), true, &probes)
                .unwrap_err()
        );
        assert!(err.contains("30620") && err.contains("still holds"), "{err}");
        assert!(paths.sandbox_dir("web").join(STATE_FILE).exists());
    }

    /// With no survivor the dead-launcher path is the ordinary clean stop.
    #[test]
    fn stop_cleans_up_a_dead_launcher_when_nothing_of_its_tree_survives() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", dead_identity());

        let conn = fake_connector(Arc::new(Mutex::new(Vec::new())), None);
        let probes = StuckTeardownProbes { survivors: vec![] };
        stop_locked_with(&paths, "web", &conn, Duration::from_millis(300), true, &probes)
            .unwrap();
        assert!(!paths.sandbox_dir("web").join(STATE_FILE).exists());
    }

    /// `izba status` / `ls` must not call it stopped.
    #[test]
    fn status_reads_degraded_not_stopped_while_a_vmm_tree_process_survives() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", dead_identity());

        let probes = StuckTeardownProbes {
            survivors: vec![30620],
        };
        match liveness_of_with(&paths, "web", &probes).unwrap() {
            Liveness::Degraded(reason) => assert!(reason.contains("30620"), "{reason}"),
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    /// `rm` — forced or not — must explain, not fail on a raw rename error,
    /// and must not suggest `--force` (it cannot help). The dir stays.
    #[test]
    fn rm_refuses_with_the_disks_held_explanation_with_and_without_force() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", dead_identity());

        let conn = fake_connector(Arc::new(Mutex::new(Vec::new())), None);
        let probes = StuckTeardownProbes {
            survivors: vec![30620],
        };
        for force in [false, true] {
            let err = format!(
                "{:#}",
                remove_with(&paths, "web", &conn, force, &probes).unwrap_err()
            );
            assert!(err.contains("30620"), "force={force}: {err}");
            assert!(err.contains("still holds the sandbox's disks"), "force={force}: {err}");
            assert!(!err.contains("use force"), "force cannot help: {err}");
            assert!(!err.contains("Access is denied"), "{err}");
            assert!(paths.sandbox_dir("web").is_dir(), "dir must survive (force={force})");
            assert!(paths.sandbox_dir("web").join(STATE_FILE).exists());
        }
    }
```

Also the Windows-only rename-hint test (same module):

```rust
    /// Windows refuses to rename a directory with an open file inside and says
    /// only `Access is denied (os error 5)`. When the stuck-teardown pre-check
    /// did not fire (no state.json at all), the rename error itself must still
    /// point at the cause instead of the bare OS text.
    #[cfg(windows)]
    #[test]
    fn rm_rename_failure_names_an_open_file_as_the_likely_cause() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        let held = fs::File::create(paths.sandbox_dir("web").join("rw.img")).unwrap();

        let conn = fake_connector(Arc::new(Mutex::new(Vec::new())), None);
        let err = format!("{:#}", remove(&paths, "web", &conn, false).unwrap_err());
        assert!(err.contains("still open"), "{err}");
        assert!(err.contains("izba status web"), "{err}");
        drop(held);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p izba-core --lib sandbox::tests::stop_refuses sandbox::tests::rm_refuses sandbox::tests::status_reads`
Expected: compile errors (`stop_locked_with`, `remove_with`, `liveness_of_with` not found).

- [ ] **Step 3: Implement — `RealProbes`, `liveness_of_with`**

(a) In `impl Probes for RealProbes<'_>` add:

```rust
    fn tree_survivors(&self, id: &crate::state::PidIdentity) -> Vec<u32> {
        procmgr::tree_survivors(id)
    }
```

(b) `pub(crate) fn liveness_of` (sandbox.rs ~line 828) today loads `state.json`, builds a `RealProbes` and calls `assess`. Rewrite it as:

```rust
pub(crate) fn liveness_of(
    paths: &Paths,
    name: &str,
    connector: Connector,
) -> anyhow::Result<Liveness> {
    liveness_of_with(
        paths,
        name,
        &RealProbes {
            connector,
            paths,
            name,
        },
    )
}

/// `liveness_of` with the probes injected — the seam the stuck-teardown tests
/// use (#319); production always goes through `liveness_of`.
pub(crate) fn liveness_of_with(
    paths: &Paths,
    name: &str,
    probes: &dyn Probes,
) -> anyhow::Result<Liveness> {
    let state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))?;
    Ok(assess(state.as_ref(), probes))
}
```

- [ ] **Step 4: Implement — the shared refusal and `stop_locked_with`**

(a) Above `stop`, add:

```rust
/// The refusal `stop` and `rm` return while a process of the sandbox's VMM
/// tree has been terminated but has not finished exiting (#319): it still
/// holds the writable disk and any volumes, so state.json must stay (a later
/// start would double-boot against held disks) and nothing may be renamed
/// or deleted. One text for both verbs; `izba status` carries the same fact
/// as `degraded (…)` via `liveness::stuck_teardown_reason`.
fn disks_held_error(name: &str, survivors: &[u32]) -> anyhow::Error {
    let pids: Vec<String> = survivors.iter().map(u32::to_string).collect();
    let pids = pids.join(", ");
    let (noun, verb) = if survivors.len() == 1 {
        ("process", "has")
    } else {
        ("processes", "have")
    };
    anyhow::anyhow!(
        "sandbox '{name}': VMM {noun} {pids} {verb} been terminated but {verb} not finished exiting \
         and still holds the sandbox's disks (rw.img, volumes); state preserved so the sandbox \
         cannot be double-booted, and `izba status {name}` reports it degraded. \
         Retry `izba stop {name}` once pid {pids} has left the process list; a process stuck \
         in kernel-side teardown is released only by a host reboot."
    )
}

/// `rm` must not even attempt the rename while a terminated VMM process still
/// holds files inside the dir — Windows answers `Access is denied (os error
/// 5)` with no hint of why (#319). A sandbox without state.json has nothing
/// to check.
fn refuse_if_teardown_stuck(paths: &Paths, name: &str, probes: &dyn Probes) -> anyhow::Result<()> {
    let state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))?;
    if let Some(s) = state {
        if !probes.pid_alive(&s.vmm_pid) {
            let survivors = probes.tree_survivors(&s.vmm_pid);
            if !survivors.is_empty() {
                return Err(disks_held_error(name, &survivors));
            }
        }
    }
    Ok(())
}
```

(b) Rewrite `stop_locked` as a thin wrapper plus `stop_locked_with`. The body is today's body with three changes: `assess` and the two wait loops use `probes` instead of `procmgr::pid_alive`, and the final "survived SIGKILL" guard is replaced by a tree-wide gate that runs on BOTH paths (killed just now, or found already exited):

```rust
/// Shared stop machinery; caller must hold the sandbox lock.
///
/// When `graceful` is false the guest RPC is skipped and all pids are killed
/// outright (force-remove path).
fn stop_locked(
    paths: &Paths,
    name: &str,
    connector: Connector,
    timeout: Duration,
    graceful: bool,
) -> anyhow::Result<()> {
    stop_locked_with(
        paths,
        name,
        connector,
        timeout,
        graceful,
        &RealProbes {
            connector,
            paths,
            name,
        },
    )
}

/// `stop_locked` with the liveness probes injected — the seam the #319 tests
/// use to model a VMM whose teardown is stuck without an unkillable process.
/// `connector` is still needed for the graceful guest RPC.
fn stop_locked_with(
    paths: &Paths,
    name: &str,
    connector: Connector,
    timeout: Duration,
    graceful: bool,
    probes: &dyn Probes,
) -> anyhow::Result<()> {
    let state_path = paths.sandbox_dir(name).join(STATE_FILE);
    let state: Option<RunState> = load_json(&state_path)?;
    let state = match (assess(state.as_ref(), probes), state) {
        (Liveness::Stopped, _) | (_, None) => {
            // VMM is already dead AND nothing of its tree survives (assess
            // reads a stuck teardown as Degraded, so it never lands here);
            // sidecars (virtiofsd) usually self-exit with their vhost-user
            // peer, but not always — best-effort kill them. The VMM is gone,
            // so restore the confined workspace's integrity.
            restore_confined_workspace(paths, name);
            kill_sidecars_from_state(paths, name);
            return cleanup_runtime(paths, name);
        }
        (_, Some(s)) => s,
    };

    if graceful {
        // Best-effort: the guest may die mid-reply or hang, which is fine —
        // the bounded RPC guarantees we reach the escalation path below.
        let _ = (|| -> anyhow::Result<()> {
            let mut s = connector(paths, name)?;
            let _ = rpc(&mut s, &Request::Shutdown, CONTROL_RPC_TIMEOUT);
            Ok(())
        })();
        let deadline = Instant::now() + timeout;
        while probes.pid_alive(&state.vmm_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let any_alive = probes.pid_alive(&state.vmm_pid)
        || state
            .sidecar_pids
            .iter()
            .any(|(_, id)| probes.pid_alive(id));
    if any_alive {
        // Escalate: vmm first, then sidecars.
        procmgr::kill_pid(&state.vmm_pid)?;
        for (_, id) in &state.sidecar_pids {
            procmgr::kill_pid(id)?;
        }
        // SIGKILL is asynchronous; wait briefly so cleanup happens after death.
        let deadline = Instant::now() + Duration::from_secs(2);
        while probes.pid_alive(&state.vmm_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // The sandbox is clean only when NO process of the VMM tree survives —
    // the recorded launcher AND its worker children (#319). On Windows a
    // terminated process carries an exit code at once while the teardown
    // that releases its handles (rw.img, volumes, the WHP partition) can
    // hang; `pid_alive` would call that dead. Runs on both paths — a kill we
    // just issued, or a launcher found already exited by an earlier attempt
    // — so a RETRY never falls through to cleanup while a worker lingers.
    // A survivor keeps state.json (a later start would double-boot against
    // held disks) and the run dir, and the refusal names the pid.
    let survivors = probes.tree_survivors(&state.vmm_pid);
    if !survivors.is_empty() {
        return Err(disks_held_error(name, &survivors));
    }

    // The VMM tree is confirmed gone above; restore the confined workspace's
    // integrity before wiping state.json (after which we'd lose the "was
    // confined" signal).
    restore_confined_workspace(paths, name);
    cleanup_runtime(paths, name)
}
```

- [ ] **Step 5: Implement — `remove_with` and the rename hint**

Rewrite `remove` as a wrapper plus `remove_with`; the body is today's body with the pre-check inserted right after the lock is taken, `liveness_of` → `liveness_of_with(paths, name, probes)`, `stop_locked` → `stop_locked_with(.., probes)`, and the rename error mapped through a helper:

```rust
pub fn remove(paths: &Paths, name: &str, connector: Connector, force: bool) -> anyhow::Result<()> {
    remove_with(
        paths,
        name,
        connector,
        force,
        &RealProbes {
            connector,
            paths,
            name,
        },
    )
}

/// `remove` with the liveness probes injected (the #319 test seam).
fn remove_with(
    paths: &Paths,
    name: &str,
    connector: Connector,
    force: bool,
    probes: &dyn Probes,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        bail!("no such sandbox '{name}'");
    }
    // Rename to a sibling tombstone *while holding the lock*, so a concurrent
    // start cannot slip in between liveness check and deletion: once renamed,
    // the old name has no config.json and start fails with "no such sandbox".
    let tombstone = paths
        .sandboxes_dir()
        .join(format!("{name}.removing-{}", std::process::id()));
    {
        let _lock = lock_sandbox(paths, name)?;
        // #319: a terminated VMM process whose teardown is stuck still holds
        // files inside `dir`; neither a plain nor a forced remove can proceed,
        // and the refusal must say so rather than the rename's raw OS error.
        refuse_if_teardown_stuck(paths, name, probes)?;
        match liveness_of_with(paths, name, probes)? {
            Liveness::Stopped => {}
            _ if !force => bail!("sandbox '{name}' is running (use force to remove)"),
            _ => {
                // #78: killing a live guest outright loses page-cache writes
                // not yet flushed to the volume images. With persistent
                // volumes attached, try the graceful Shutdown (guest syncs
                // before power-off) under a short grace before escalating.
                let (grace, graceful) = if has_persistent_volumes(paths, name) {
                    (FORCE_RM_SYNC_GRACE, true)
                } else {
                    (Duration::ZERO, false)
                };
                stop_locked_with(paths, name, connector, grace, graceful, probes)?
            }
        }
        fs::rename(&dir, &tombstone).map_err(|e| rename_for_removal_error(&dir, name, e))?;
    } // release the lock (it lives beside the dir, so the rename was safe)
    // <rest of the ORIGINAL body unchanged: remove_dir_all(tombstone) warning,
    //  run_dir removal + run_dir_removal_warning, lock file removal, Ok(())>
}

/// Context for a failed tombstone rename. `PermissionDenied` on a directory
/// rename is Windows' way of saying "a file inside is open in some process"
/// — the one case `refuse_if_teardown_stuck` could not see (no state.json,
/// or a holder outside the VMM tree) — so point the user at the cause and at
/// `izba status`; every other kind keeps the plain context.
fn rename_for_removal_error(dir: &Path, name: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::Error::new(e).context(format!(
            "renaming {} for removal: a file inside it is still open in some process \
             (a VMM that has not finished exiting? check `izba status {name}` and the \
             process list)",
            dir.display()
        ))
    } else {
        anyhow::Error::new(e).context(format!("renaming {} for removal", dir.display()))
    }
}
```

(Note `remove_with` takes `validate_name` and the `dir.exists()` check from the original `remove` — move them, so `remove` is only the wrapper.)

- [ ] **Step 6: The CLI's reconcile probes use the real primitive**

In `crates/izba-cli/src/commands/reconcile.rs`, extend `impl Probes for PidProbes` with:

```rust
    fn tree_survivors(&self, id: &PidIdentity) -> Vec<u32> {
        izba_core::procmgr::tree_survivors(id)
    }
```

(so `izba reconcile`'s disk-vs-daemon comparison agrees with the daemon about a stuck sandbox being degraded rather than stopped).

- [ ] **Step 7: Run the new tests, then the whole sandbox module**

Run: `cargo test -p izba-core --lib sandbox::tests::stop_ sandbox::tests::rm_ sandbox::tests::status_reads`
Expected: new tests PASS; every pre-existing `stop_*`/`rm_*` test still PASS (their sleep really dies → no survivor → unchanged behaviour).

Run: `cargo test -p izba-core --lib`
Expected: PASS.

- [ ] **Step 8: Record the contract in `CLAUDE.md`**

In the **Disk-state invariant** bullet, after the sentence ending `…never trusted from `state.json` alone.`, insert:

```
  A stop is clean only when NO process of the VMM tree survives — the
  recorded launcher AND its worker children (`procmgr::tree_survivors`,
  #319): on Windows a `TerminateProcess`'d `openvmm.exe` carries an exit code
  at once while the kernel-side teardown that releases `rw.img`/the WHP
  partition can hang, so the verdict is "process object signaled", never
  `GetExitCodeProcess`. A survivor makes `assess` answer
  `Degraded(vmm process <pid> terminated but not torn down, disks still held)`
  — never `Stopped`, which is what lets `reap_stale_stopped` drop `state.json`
  and `start` double-boot — and `stop`/`rm` (forced or not) refuse with one
  shared message (`sandbox::disks_held_error`) that names the pid and keeps
  `state.json`.
```

- [ ] **Step 9: All six gates, then commit**

Run (in order): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`, the two `x86_64-pc-windows-gnu` checks from Global Constraints.
Expected: all green.

```bash
git add crates/izba-core/src/sandbox.rs crates/izba-cli/src/commands/reconcile.rs CLAUDE.md
git commit -m "fix(core): refuse to call a sandbox stopped while a terminated VMM process still holds its disks

stop and rm gate on procmgr::tree_survivors after the kill — the recorded
launcher AND its worker children — instead of the launcher's exit code, and
return one refusal that names the pid, says the disks are still held, keeps
state.json and tells the user what to do. The same fact reaches status/ls
through assess (Degraded, never Stopped), so the stale-state reaper no longer
wipes a stuck sandbox's state and a retry cannot fall through to cleanup.
A failed tombstone rename on PermissionDenied now points at an open file
instead of the bare OS error.

Refs #319

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Spike doc 0003, the real-host check script, runbook pointer

**Files:**
- Create: `docs/spikes/0003-windows-openvmm-worker-teardown-hang.md`
- Create: `hack/spike/stuck-vmm-teardown-check.ps1`
- Modify: `docs/testing.md` (§8, after the USB passthrough gate paragraph)

**Interfaces:** none (documentation + a standalone PowerShell script; the script calls only the public CLI).

The doc follows `docs/spikes/0001-…`'s shape (title, header line with issue + date + script link, `## Question`, `## Approach`, `## Findings`, `## Conclusion`, `## Reproduction recipe`, `## Limits`, `## Follow-on work`). The evidence below was collected on 2026-10-08 on the spike host (Windows 11 25H2, build 10.0.26200, uptime 9 d — NOT rebooted since the 2026-10-02 run), where the stuck worker from PR #318's run still exists. Task 5 appends the real-host validation of the fix to the same doc.

- [ ] **Step 1: Write the spike doc**

Create `docs/spikes/0003-windows-openvmm-worker-teardown-hang.md`:

````markdown
# 0003 — Why did a terminated OpenVMM worker never finish exiting, and why did its guest not power off?

Issue [#319](https://github.com/Lupus/izba/issues/319) · 2026-10-08 ·
script: [`hack/spike/stuck-vmm-teardown-check.ps1`](../../hack/spike/stuck-vmm-teardown-check.ps1)

## Question

Spike #249 (PR #318, finding 8) stopped a sandbox whose guest never printed
`reboot: Power down`; `izba stop` returned 0 after 20.4 s, removed `state.json`
and the run dir, and `izba status` said `stopped` — while the `openvmm vm`
worker was still present hours later with every handle open. Two questions
were left: **why did the guest not power off**, and **why does the terminated
worker never finish exiting**? And the product question #319 answers in code:
how does izba notice?

## Approach

No reproduction was attempted (one hang in twelve stops, and the stuck process
cannot be re-killed). Instead the surviving evidence on the same host was read
six days later, unelevated, from WSL over `powershell.exe` interop:

- the worker process itself (`Get-Process`, `Win32_Process`, `Win32_Thread`,
  Sysinternals `handle64 -p <pid>`);
- the spike's throwaway data root `%TEMP%\i249m`, whose sandbox dir
  `sandboxes\p249h` the failed `rm --force` left behind: `config.json`,
  `logs/console.log`, `logs/vmm.log`, `rw.img`;
- a direct sharing-mode probe of `rw.img` and a rename attempt on the dir;
- the guest-side code paths involved (`izba-init`'s shutdown sequence, the
  kernel's `kernel_power_off` ordering, `vhci_hcd`'s unlink/detach path).

## Findings

### 1. The worker is still there, exited but not torn down

| Fact | Value (2026-10-08) |
| --- | --- |
| pid / image | 30620, `…\Temp\izba249-stage\bin\libexec\openvmm.exe vm` |
| parent | 29588 (the launcher izba recorded; gone) |
| created | 2026-10-02 00:36:22; `HasExited=True`, `ExitCode`/`ExitTime` unreadable |
| threads | exactly one (tid 29052), `ThreadState=5` (Wait), `WaitReason=Executive`, 1 min 22 s CPU in total, started with the process |
| handles | 255 open |
| working set | 3.49 GB (the guest's 4 GiB RAM is still mapped) |
| host uptime | 9 d 5 h — never rebooted since |

`handle64` (unelevated, so only File handles are listed) shows the worker
holding `sandboxes\p249h\rw.img`, `images\sha256-…\rootfs.erofs`,
`logs\vmm.log`, the three virtiofs share directories `oci`, `ssh`, `trust`, and
three `C:\$Extend\$Deleted\…` entries — files that were deleted while open:
the run dir's sockets, which `stop`'s cleanup removed from under it.

The lock is real: opening `rw.img` with `FileShare.None` fails with *"being
used by another process"*; renaming the dir fails with *"Access to the path …
is denied"* — exactly the `os error 5` the spike's `rm --force` hit.

### 2. Why izba called it stopped

`stop_locked` escalated to `kill_pid`, which `TerminateProcess`d the launcher
(pid 29588, torn down fine) and swept the worker with `terminate_quiet`:
`TerminateProcess` + `WaitForSingleObject(10 s)` **whose result was
discarded**. The post-kill guard asked `pid_alive(launcher)`, i.e.
`GetExitCodeProcess`, which `TerminateProcess` satisfies immediately. The
worker — not the launcher — is what holds the disks, and nothing asked about
it. On the next `izba ls` the stale-state reaper would have found `Stopped`
and wiped `state.json` anyway. Fixed by #319: `procmgr::tree_survivors` asks
"is the process **object** signaled" (`WaitForSingleObject(h, 0)`) for the
launcher and every descendant, `assess` turns a survivor into `degraded`, and
`stop`/`rm` refuse.

### 3. Why the worker never finishes exiting (conclusion)

`TerminateProcess` queues a kernel APC to every thread; a thread blocked in a
**kernel-mode, non-alertable wait inside a driver** cannot run it and the
process cannot complete teardown until that wait returns. The one remaining
thread is in exactly such a wait (`Executive`), it is a thread that burned
1 min 22 s of CPU during a 2-minute VM lifetime — a vCPU or I/O worker, not a
housekeeping thread — and the process still holds the WHP partition handle
(`\Device\VidExo`, per the spike's elevated listing) with the guest's memory
mapped. The teardown is therefore blocked **inside the Windows Hypervisor
Platform / `vid.sys`**, on an operation of that partition that never
completes; the handle table (and so `rw.img`) is closed only after every
thread is gone. This is outside izba's control: there is no API to force a
partition to release a stuck virtual processor, and the only known release is
a host reboot. Which VID call the thread is in is not knowable unelevated (see
Limits); it is not needed for the product decision — detect and report.

### 4. Why the guest did not power off (conclusion)

The console log ends at guest time 49.3 s with seventeen
`vhci_hcd: unlink->seqnum N` / `the urb (seqnum N) was already given back`
pairs — the tail of the 40 s USB write flood through the attached
`0403:6001` device (`usb 1-1`, `cdc_acm … ttyACM0`). Nothing follows: no
`usb 1-1: USB disconnect, device number 2` (which the kernel prints at
`dev_info` level for every detach), no `reboot: Power down`.

Three facts frame it:

- `izba-init`'s shutdown is `engine.kill_all(); sync(); reboot(RB_POWER_OFF)`
  and prints nothing of its own, so console silence is expected until the
  kernel speaks.
- The kernel prints `reboot: Power down` **after** `device_shutdown()` has
  called every device's `->shutdown` (`kernel_power_off` →
  `kernel_shutdown_prepare` → `device_shutdown()` → `pr_emerg("Power down")`
  → `machine_power_off`). A hang anywhere in `device_shutdown()` produces
  exactly this silence.
- The spike script issued `izba usb detach` immediately before `izba stop`,
  and the detach's kernel-side marker is missing.

The consistent explanation: the vhci detach that preceded the stop did not
complete inside the guest — `vhci_hcd`'s port disconnect / `usb_kill_urb`
path after a traffic burst with unlinked URBs is a known hang class (the
upstream fix "usbip: give back URBs for unsent unlink requests during
cleanup", 2021, is in this 6.18 kernel, so this is a residual case, not that
exact bug) — and the power-off then blocked in `device_shutdown()` behind the
USB device, so `Power down` was never reached. The alternative, that the
detach never reached the guest and `device_shutdown()` hung on the still-
attached vhci device whose host-side splice was being torn down, has the
same common factor: **a vhci (usbip) device attached or mid-detach at
power-off after sustained traffic**. Either way it is a guest-side defect
separate from #319 — filed as a follow-up (see below). The 10 s graceful
wait then expired and the kill path in finding 2 took over.

### 5. What is NOT established

- The exact VID operation the stuck thread waits in (needs an elevated
  kernel debugger, `livekd` is installed but UAC cannot be answered over
  interop).
- Whether the hang needs the usbip traffic at all, or only the guest power-off
  failure (the eleven clean stops in the spike all powered off, every one of
  them through the kill path, because OpenVMM does not exit on guest
  power-off — #320).
- Whether the detach returned to the CLI or hung; the spike's own run log was
  not kept.

## Conclusion

- The worker hang is a Windows Hypervisor Platform / `vid.sys` teardown wait
  that `TerminateProcess` cannot interrupt; izba cannot fix it and must detect
  it. #319 makes `stop`/`rm` refuse while any process of the VMM tree is not
  yet signaled, keeps `state.json`, and shows `degraded (vmm process <pid>
  terminated but not torn down, disks still held)`.
- The guest power-off failure is a separate, guest-side defect around a vhci
  device at shutdown after traffic — follow-up filed.
- Nothing here changes a normal stop: the new check is one Toolhelp snapshot
  and a zero-timeout wait per process.

## Reproduction recipe (real-host check)

The hang itself was seen once in twelve stops and cannot be forced; this is
how to re-create the *conditions* and how to verify the *detection* on a stuck
process whenever one exists.

1. Conditions (needs `hack/fake-usbipd` and an installer-shaped stage, see
   `docs/testing.md` §8): run PR #318's `hack/spike/container-probe-windows.ps1`
   with `IZBA_USB_TRAFFIC=1` in a loop until its final check
   `all N openvmm.exe process(es) this run started are gone after 'izba stop'`
   fails. Its data root `%TEMP%\i249-<pid>` and sandbox `probe249` are what the
   check below takes as input.
2. Detection: `pwsh -NoProfile -File hack/spike/stuck-vmm-teardown-check.ps1`
   with `IZBA_EXE`, `IZBA_DATA_DIR` and `IZBA_SANDBOX` set. It lists every
   `openvmm.exe` with its exited/thread/handle state, probes `rw.img` for an
   exclusive lock, and then asserts the #319 contract through the CLI:
   `izba status` says `degraded (… not torn down, disks still held)`, `izba
   stop` exits non-zero naming the pid, `state.json` is still there, `izba rm
   --force` exits non-zero with the same explanation.
3. Validation of the fix on the 2026-10-02 survivor itself is recorded in the
   next section.

## Limits

Everything was read unelevated; kernel stacks, non-File handle types and the
exit code of the exited process were not available. The spike's run log
(`izba-probe249-<pid>` output dir) was not retained, so the detach's own
duration and output are unknown.

## Follow-on work

- Follow-up issue (guest side): *Windows/OpenVMM: guest fails to power off
  with a vhci (usbip) device attached or mid-detach after sustained traffic* —
  link added by Task 5.
- [#320](https://github.com/Lupus/izba/issues/320) — OpenVMM does not exit on
  guest power-off, so every Windows stop takes the kill path (unchanged here).
````

- [ ] **Step 2: Write the check script**

Create `hack/spike/stuck-vmm-teardown-check.ps1` (keep it Sonar-clean: `$null` on the left of comparisons, no unused variables, `Set-StrictMode`):

```powershell
# #319 -- real-host check: does izba refuse to call a sandbox stopped while a
# terminated openvmm.exe of its VMM tree has not finished teardown?
#
# Inputs (env):  IZBA_EXE       path to izba.exe under test
#                IZBA_DATA_DIR  the data root holding the sandbox
#                IZBA_SANDBOX   the sandbox name
# It never creates or starts anything. It runs `izba status`, `izba stop` and
# `izba rm --force` against the given sandbox, which is what a user would do,
# and reports PASS/FAIL per #319 acceptance criterion.
#
# Exit code: number of failed checks; 100 when a prerequisite is missing.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$exe  = $env:IZBA_EXE
$data = $env:IZBA_DATA_DIR
$name = $env:IZBA_SANDBOX
$fails = 0

function Say($text) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $text) }
function Check($what, $ok) {
    if ($ok) { Say "PASS  $what" } else { Say "FAIL  $what"; $script:fails++ }
}

foreach ($req in @(@('IZBA_EXE', $exe), @('IZBA_DATA_DIR', $data), @('IZBA_SANDBOX', $name))) {
    if ([string]::IsNullOrEmpty($req[1])) {
        [Console]::Error.WriteLine("stuck-vmm-teardown-check: set $($req[0])")
        exit 100
    }
}
if (-not (Test-Path $exe)) { [Console]::Error.WriteLine("no such izba.exe: $exe"); exit 100 }
$sandboxDir = Join-Path $data "sandboxes\$name"
if (-not (Test-Path $sandboxDir)) { [Console]::Error.WriteLine("no such sandbox dir: $sandboxDir"); exit 100 }

# Run izba with the data root under test; return rc + combined output.
function Invoke-Izba([string[]] $izbaArgs) {
    $env:IZBA_DATA_DIR = $data
    $out = & $exe @izbaArgs 2>&1 | Out-String
    return @{ rc = $LASTEXITCODE; out = $out.Trim() }
}

# --- 1. census: every openvmm.exe, and which of them are exited-but-present.
Say 'openvmm.exe processes on the host:'
$vmms = @(Get-CimInstance Win32_Process -Filter "Name='openvmm.exe'" -ErrorAction SilentlyContinue)
foreach ($p in $vmms) {
    $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
    $exited = if ($null -ne $proc) { $proc.HasExited } else { 'n/a' }
    Say ("  pid={0} ppid={1} exited={2} threads={3} handles={4} working_set_mb={5}" -f `
        $p.ProcessId, $p.ParentProcessId, $exited, $p.ThreadCount, $p.HandleCount, [int]($p.WorkingSetSize / 1MB))
}
if ($vmms.Count -eq 0) { Say '  (none)' }

# --- 2. is the writable disk exclusively held?
$rw = Join-Path $sandboxDir 'rw.img'
$held = $false
if (Test-Path $rw) {
    try {
        $fs = [System.IO.File]::Open($rw, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        $held = $true
    }
}
Say "rw.img exclusively held by another process: $held"

# --- 3. the #319 contract through the CLI.
$status = Invoke-Izba @('status', $name)
Say "izba status: rc=$($status.rc)"
Say ("  " + ($status.out -replace "`r?`n", "`n  "))
Check 'status does not report a clean stop (no bare "stopped" line)' ($status.out -notmatch '(?m)^\s*status:\s*stopped\s*$')
Check 'status reports the stuck teardown (degraded ... not torn down, disks still held)' ($status.out -match 'degraded \(vmm process(es)? [0-9, ]+ terminated but not torn down, disks still held\)')

$stop = Invoke-Izba @('stop', $name)
Say "izba stop: rc=$($stop.rc)"
Say ("  " + ($stop.out -replace "`r?`n", "`n  "))
Check 'stop exits non-zero' ($stop.rc -ne 0)
Check 'stop names a pid and says the disks are still held' ($stop.out -match 'VMM process(es)? [0-9, ]+ ha(s|ve) been terminated' -and $stop.out -match 'still holds the sandbox''s disks')
Check 'stop says what to do (retry / host reboot)' ($stop.out -match 'Retry `izba stop' -and $stop.out -match 'host reboot')
Check 'state.json is preserved after the refused stop' (Test-Path (Join-Path $sandboxDir 'state.json'))

$rm = Invoke-Izba @('rm', $name, '--force')
Say "izba rm --force: rc=$($rm.rc)"
Say ("  " + ($rm.out -replace "`r?`n", "`n  "))
Check 'rm --force exits non-zero' ($rm.rc -ne 0)
Check 'rm --force gives the same explanation, not a raw Access is denied' ($rm.out -match 'still holds the sandbox''s disks' -and $rm.out -notmatch 'Access is denied')
Check 'sandbox dir still exists after the refused rm' (Test-Path $sandboxDir)

if ($fails -eq 0) { Say 'VERDICT: izba reports the stuck teardown honestly on every surface' }
else { Say "VERDICT: $fails check(s) failed" }
exit $fails
```

- [ ] **Step 3: Runbook pointer**

In `docs/testing.md` §8, after the "USB passthrough gate" paragraph and its code block, add:

```markdown
**Stuck VMM teardown check (#319).** A `TerminateProcess`'d `openvmm.exe`
worker can hang in kernel-side teardown with the sandbox's disks still held;
izba then refuses `stop`/`rm` and shows the sandbox `degraded (vmm process
<pid> terminated but not torn down, disks still held)`. The real-host check
for that contract — and the reproduction conditions — are in
[`docs/spikes/0003-windows-openvmm-worker-teardown-hang.md`](spikes/0003-windows-openvmm-worker-teardown-hang.md):

```sh
# Windows side, against an existing data root + sandbox (creates nothing):
#   $env:IZBA_EXE = '<root>\bin\izba.exe'; $env:IZBA_DATA_DIR = '<data root>'; $env:IZBA_SANDBOX = '<name>'
#   pwsh -NoProfile -File hack/spike/stuck-vmm-teardown-check.ps1
```
```

- [ ] **Step 4: Check the script parses and the docs render**

Run (unsandboxed, PowerShell on the host parses the file without running it):
```
powershell.exe -NoProfile -Command "[void][System.Management.Automation.Language.Parser]::ParseFile('\\\\wsl.localhost\\<distro>\\<abs path>\\hack\\spike\\stuck-vmm-teardown-check.ps1', [ref]\$null, [ref]\$err); \$err | Format-List; 'errors=' + \$err.Count"
```
Expected: `errors=0`. (If the UNC path is rejected, copy the file to `/mnt/c/Users/<user>/Downloads/` and parse that path.)

Run: `grep -c '' docs/spikes/0003-windows-openvmm-worker-teardown-hang.md` (sanity: file present) and `cargo fmt --check` (no Rust touched, still green).

- [ ] **Step 5: Commit**

```bash
git add docs/spikes/0003-windows-openvmm-worker-teardown-hang.md hack/spike/stuck-vmm-teardown-check.ps1 docs/testing.md
git commit -m "docs(spike): why the OpenVMM worker hangs in teardown and why its guest never powered off (#319)

Records the surviving evidence from the 2026-10-02 run (the worker is still
present: one thread in a kernel Executive wait, rw.img exclusively held),
concludes the worker hang is a WHP/vid.sys teardown wait TerminateProcess
cannot interrupt, and the missing power-off is a guest-side vhci-at-shutdown
defect (separate follow-up). Adds the real-host check script for the #319
contract and a runbook pointer.

Refs #319

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Real-host validation on the surviving stuck process, follow-up issue, doc update

This task needs WSL→Windows interop (`powershell.exe`, `/mnt/c`) and `gh`; both run unsandboxed. It is executed by the orchestrating session, not a subagent.

**Files:**
- Modify: `docs/spikes/0003-windows-openvmm-worker-teardown-hang.md` (append `## Validation on the 2026-10-02 survivor` and fill the follow-up link)

**Interfaces:** consumes the built `izba.exe` from Tasks 1–3 and the Task 4 script.

- [ ] **Step 1: Confirm the stuck process is still there and the launcher pid was not recycled**

Run (unsandboxed):
```
powershell.exe -NoProfile -Command "Get-Process openvmm | Select Id,HasExited,StartTime,HandleCount | Format-Table -AutoSize; 'launcher 29588 present: ' + ($null -ne (Get-CimInstance Win32_Process -Filter 'ProcessId=29588'))"
```
Expected: pid 30620 listed, `HasExited=True`; `launcher 29588 present: False`. If the host was rebooted in the meantime, the survivor is gone: skip Steps 2–4, record that in the doc section instead, and keep the recipe as the real-host path.

- [ ] **Step 2: Cross-build and stage the fixed CLI next to the spike's stage**

```
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
cp -r /mnt/c/Users/kolkhovskiy/AppData/Local/Temp/izba249-stage /mnt/c/Users/kolkhovskiy/AppData/Local/Temp/izba319-stage
cp target/x86_64-pc-windows-gnu/release/izba.exe /mnt/c/Users/kolkhovskiy/AppData/Local/Temp/izba319-stage/bin/izba.exe
```

- [ ] **Step 3: Re-create the `state.json` the old build deleted, pointing at the dead launcher**

The launcher's creation time is unrecoverable; `tree_survivors` only needs `pid_alive(root)` to be false (a mismatching starttime guarantees that) and walks descendants by PPID, so a starttime of `0` is correct for this purpose. Write `/mnt/c/Users/kolkhovskiy/AppData/Local/Temp/i249m/sandboxes/p249h/state.json`:

```json
{
  "vmm_pid": { "pid": 29588, "starttime": 0 },
  "sidecar_pids": [],
  "started_unix_ms": 1790886982000,
  "usb_kernel": true,
  "vnc": false
}
```

(`confinement`, `run_dir`, `user_fallback`, `lockdown_account` are `#[serde(default)]`; `run_dir: None` means the legacy layout and is fine — the run dir has only its `owner` marker left.)

- [ ] **Step 4: Run the check script against it**

```
powershell.exe -NoProfile -Command "\$env:IZBA_EXE='C:\Users\kolkhovskiy\AppData\Local\Temp\izba319-stage\bin\izba.exe'; \$env:IZBA_DATA_DIR='C:\Users\kolkhovskiy\AppData\Local\Temp\i249m'; \$env:IZBA_SANDBOX='p249h'; pwsh -NoProfile -File '\\\\wsl.localhost\\<distro>\\<abs path>\\hack\\spike\\stuck-vmm-teardown-check.ps1'"
```
(Use `powershell.exe` for the outer hop if `pwsh` is not installed; copy the script to a Windows-local path if the UNC path is refused.)
Expected: every check `PASS`, `VERDICT: izba reports the stuck teardown honestly on every surface`; `state.json` still present afterwards. Then `izba daemon stop` for that data root:
```
powershell.exe -NoProfile -Command "\$env:IZBA_DATA_DIR='C:\Users\kolkhovskiy\AppData\Local\Temp\i249m'; & 'C:\Users\kolkhovskiy\AppData\Local\Temp\izba319-stage\bin\izba.exe' daemon stop"
```
If a check FAILS, that is a real finding about the fix: stop, apply `superpowers:systematic-debugging`, fix in Tasks 1–3's code, re-run.

- [ ] **Step 5: File the follow-up issue and link it**

From the MAIN checkout (`/home/kolkhovskiy/git/izba`), create the guest-side item with `gh issue create -R Lupus/izba` (type:bug, priority:P3, effort:M), title *"Windows/OpenVMM: guest fails to power off with a vhci (usbip) device attached or mid-detach after sustained traffic — `stop` always escalates to kill"*, body in the repo's six-section shape (What / Why / In Scope / Out of Scope / Acceptance Criteria / INVEST Notes) summarising finding 4 of the spike doc, then add it to the board: `gh project item-add 1 --owner Lupus --url <issue-url>`. Put the resulting `#N` into the doc's "Follow-on work" bullet.

- [ ] **Step 6: Append the validation section to the spike doc and commit**

Add `## Validation on the 2026-10-02 survivor` with the script's verbatim output (trimmed to the census, the three CLI results and the verdict) and the date.

```bash
git add docs/spikes/0003-windows-openvmm-worker-teardown-hang.md
git commit -m "docs(spike): validate the #319 detection against the surviving stuck worker

Refs #319

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-review notes

- **Spec coverage:** AC1 (every openvmm.exe of the tree, fully gone not just exit code) → Task 1 + Task 3 gate. AC2 (`stop` non-zero, names pid, disks held, what to do) → `disks_held_error` + `stop_refuses_*` tests. AC3 (`state.json` preserved, `status` not clean) → Task 2 `assess` + `status_reads_degraded…` + `stop_refuses_*`. AC4 (`rm` incl. `--force` same explanation) → `refuse_if_teardown_stuck` + `rm_refuses_*` + rename hint. AC5 (seam/fake regression test) → `StuckTeardownProbes`, `FakeProbes.survivors`. AC6 (recipe recorded) → Task 4 doc + script. AC7 (written conclusion + follow-up) → Task 4 findings 3–4, Task 5 issue. AC8 (not slower, flow unchanged, no privileges) → Global Constraints + no new waits in Task 3. Out of scope respected: no change to the 10 s graceful wait (#320), no Linux semantic change, no attempt to fix the WHP hang.
- **Type consistency:** `tree_survivors(&PidIdentity) -> Vec<u32>` everywhere; `stuck_teardown_reason(&[u32]) -> String`; `disks_held_error(&str, &[u32]) -> anyhow::Error`; `stop_locked_with(.., &dyn Probes)`, `remove_with(.., bool, &dyn Probes)`, `liveness_of_with(&Paths, &str, &dyn Probes)`.
- **Review Focus:** each of the five lines names its pinning test above.
