# izba Windows port, Plan 1 (Linux-side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the host-side crates compile, lint, and (where possible) unit-test for `x86_64-pc-windows-gnu`, add the OpenVmmDriver, and produce a cross-built `izba.exe` — all from Linux, no Windows host needed.

**Architecture:** Approach A from
[the design spec](../specs/2026-06-10-izba-windows-port-design.md): cfg-gated
platform splits behind unchanged public APIs. Platform decisions live in pure,
Linux-testable core functions with thin cfg wrappers. New `vmm/openvmm.rs`
driver mirrors `cloud_hypervisor.rs` (pure argv builder + driver), minus all
sidecar machinery.

**Tech Stack:** Rust (toolchain ≥1.89 for `File::try_lock`; repo uses 1.96),
`windows-sys` + `uds_windows` as Windows-only target deps, MinGW-w64 linker
for the `x86_64-pc-windows-gnu` target (already installed, along with the
rustup target).

**Gates (every task ends with ALL of these green):**

```sh
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
# New cross-target gates (this plan makes them pass incrementally; the task
# text says which packages must be green after each task):
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

Until the task that makes a package cross-green, run the cross gates only for
the packages already ported (the per-task "Cross gate" line). `izba-proto` is
cross-green from the start.

**Spike facts this plan encodes** (from
[2026-06-10-openvmm-spike-s1-findings.md](../specs/2026-06-10-openvmm-spike-s1-findings.md)):
`--hv` mandatory; `--net consomme` (not virtio-net); virtio-blk must be
PCIe-routed via per-disk `--pcie-root-port` to dodge the VPCI device-ID
collision; virtio-fs uses `pcie_port=<port>:<tag>,<path>`; vsock is
`--virtio-vsock-path <path>` with the CH-compatible CONNECT/OK handshake;
`--com1 file=` is the console log; openvmm has no sidecars.

---

### Task 1: Sandbox lock via std `File::try_lock`

Deletes the `nix` dependency from `sandbox.rs` (cross-platform std API:
`flock` on Unix, `LockFileEx` on Windows). Lock-release-on-drop semantics are
identical: std file locks are released when the `File` is closed.

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (imports + `lock_sandbox`, lines ~13, ~217-239)

- [ ] **Step 1: Confirm the existing lock test passes (baseline)**

Run: `cargo test -p izba-core flock_serializes_start`
Expected: PASS (this test is the behavioral contract for the swap).

- [ ] **Step 2: Replace the Flock implementation**

In `crates/izba-core/src/sandbox.rs`, delete the import:

```rust
use nix::fcntl::{Flock, FlockArg};
```

and replace `lock_sandbox` (keep its doc comment, adjusting the first line):

```rust
/// Take the per-sandbox exclusive lock (released when the returned `File`
/// drops — std file locks are tied to the open handle).
fn lock_sandbox(paths: &Paths, name: &str) -> anyhow::Result<File> {
    let lock_path = paths.sandbox_dir(name).join("lock");
    let f = match File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("no such sandbox '{name}'")
        }
        Err(e) => return Err(e).with_context(|| format!("opening {}", lock_path.display())),
    };
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => {
            bail!("sandbox '{name}' is busy (another operation in progress)")
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", lock_path.display()))
        }
    }
}
```

Callers bind the result as `let _lock = lock_sandbox(...)?;` and only rely on
drop — no other changes needed.

- [ ] **Step 3: Run the gates**

Run: `cargo test -p izba-core` (all, including `flock_serializes_start`),
then the full Linux gate set.
Cross gate: `cargo check --target x86_64-pc-windows-gnu -p izba-proto` (core
not yet expected to pass — procmgr/vsock still Unix-only).
Expected: all green; izba-core cross-check still fails ONLY in procmgr/vsock/vmm
(verify the sandbox.rs lock errors are gone from the output).

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "refactor(core): sandbox lock via std File::try_lock (cross-platform)"
```

---

### Task 2: Windows default data root in `paths.rs`

`%LOCALAPPDATA%\izba`, falling back to `%USERPROFILE%\AppData\Local\izba`.
Both platform rules are pure functions over an env-lookup closure, so both are
unit-tested on Linux; `cfg!(windows)` (the macro — both branches always
compile) selects at runtime.

**Files:**
- Modify: `crates/izba-core/src/paths.rs`

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `paths.rs` (create the
module if absent — check the file end first):

```rust
#[test]
fn unix_root_from_home() {
    let env = |k: &str| (k == "HOME").then(|| "/home/u".to_string());
    assert_eq!(
        unix_default_root(&env),
        PathBuf::from("/home/u/.local/share/izba")
    );
}

#[test]
fn unix_root_fallback() {
    let env = |_: &str| None;
    assert_eq!(unix_default_root(&env), PathBuf::from("/root/.local/share/izba"));
}

#[test]
fn windows_root_from_localappdata() {
    let env = |k: &str| {
        (k == "LOCALAPPDATA").then(|| r"C:\Users\u\AppData\Local".to_string())
    };
    assert_eq!(
        windows_default_root(&env),
        PathBuf::from(r"C:\Users\u\AppData\Local").join("izba")
    );
}

#[test]
fn windows_root_fallback_to_userprofile() {
    let env = |k: &str| (k == "USERPROFILE").then(|| r"C:\Users\u".to_string());
    assert_eq!(
        windows_default_root(&env),
        PathBuf::from(r"C:\Users\u")
            .join("AppData")
            .join("Local")
            .join("izba")
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core paths`
Expected: FAIL — `unix_default_root` / `windows_default_root` not defined.

- [ ] **Step 3: Implement**

Replace `from_env_or_default` and add the pure functions:

```rust
/// `override_root` wins; otherwise the per-OS default data root
/// (Unix: `$HOME/.local/share/izba`; Windows: `%LOCALAPPDATA%\izba`).
pub fn from_env_or_default(override_root: Option<PathBuf>) -> Self {
    if let Some(root) = override_root {
        return Self::with_root(root);
    }
    Self::with_root(default_root(&|k| std::env::var(k).ok()))
}
```

and (file-level, near the impl):

```rust
/// Both platform rules always compile (`cfg!`, not `#[cfg]`) so each is
/// unit-tested regardless of the build target.
fn default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    if cfg!(windows) {
        windows_default_root(env)
    } else {
        unix_default_root(env)
    }
}

fn unix_default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let home = env("HOME").unwrap_or_else(|| "/root".to_string());
    PathBuf::from(home).join(".local/share/izba")
}

fn windows_default_root(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(lad) = env("LOCALAPPDATA") {
        return PathBuf::from(lad).join("izba");
    }
    let profile = env("USERPROFILE").unwrap_or_else(|| r"C:\".to_string());
    PathBuf::from(profile)
        .join("AppData")
        .join("Local")
        .join("izba")
}
```

- [ ] **Step 4: Run tests + gates**

Run: `cargo test -p izba-core paths` → PASS, then full Linux gates.
Cross gate: unchanged from Task 1.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/paths.rs
git commit -m "feat(core): Windows default data root (%LOCALAPPDATA%\\izba)"
```

---

### Task 3: procmgr platform split

`procmgr.rs` → `procmgr/` directory: `mod.rs` (shared docs + re-exports),
`unix.rs` (today's code, moved verbatim including its tests), `windows.rs`
(new). Public API unchanged: `spawn_detached`, `kill_pid`, `pid_alive`.
`PidIdentity.starttime` on Windows = process creation `FILETIME` as u64.

**Files:**
- Delete: `crates/izba-core/src/procmgr.rs` (`git mv` to `procmgr/unix.rs`)
- Create: `crates/izba-core/src/procmgr/mod.rs`
- Create: `crates/izba-core/src/procmgr/windows.rs`
- Modify: `crates/izba-core/Cargo.toml`

- [ ] **Step 1: Move the Unix implementation**

```bash
mkdir -p crates/izba-core/src/procmgr
git mv crates/izba-core/src/procmgr.rs crates/izba-core/src/procmgr/unix.rs
```

Keep `unix.rs` content byte-identical (module docs, tests and all).

- [ ] **Step 2: Create `procmgr/mod.rs`**

```rust
//! Detached process management with PID-reuse-safe identity.
//!
//! The API is platform-independent; each platform supplies the same three
//! functions. `PidIdentity.starttime` is an opaque equality token: Linux uses
//! `/proc/<pid>/stat` field 22 (clock ticks since boot), Windows uses the
//! process creation `FILETIME`. `state.json` is per-host, so the differing
//! unit never crosses platforms.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{kill_pid, pid_alive, spawn_detached};
#[cfg(unix)]
pub(crate) use unix::proc_starttime;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{kill_pid, pid_alive, spawn_detached};
```

In `unix.rs`, mark `proc_starttime` `pub(crate)` if it isn't already (it is),
and confirm `spawn_detached`, `kill_pid`, `pid_alive` are `pub`.

- [ ] **Step 3: Run Linux tests to confirm the move is invisible**

Run: `cargo test -p izba-core procmgr`
Expected: same tests pass as before the move.

- [ ] **Step 4: Add Windows target deps to `crates/izba-core/Cargo.toml`**

Move `nix` out of `[dependencies]` into a Unix-only section and add the
Windows section (note: `fs` feature dropped — Task 1 removed its last user;
keep `process`, `signal`):

```toml
[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["process", "signal"] }

[target.'cfg(windows)'.dependencies]
uds_windows = "1.1"
windows-sys = { version = "0.60", features = [
    "Win32_Foundation",
    "Win32_System_Threading",
    "Win32_System_IO",
    "Win32_System_Ioctl",
] }
```

(`uds_windows` is consumed in Task 4 and `Win32_System_IO`/`Ioctl` in Task 8;
declaring them now keeps the manifest edits in one place. If `cargo clippy`
complains about unused crates at this task, that lint is not enabled in this
repo — ignore only that; never suppress real warnings.)

- [ ] **Step 5: Write `procmgr/windows.rs`**

```rust
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
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess,
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
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
    (ok != 0).then(|| ((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
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
    let starttime = creation_time(child.as_raw_handle() as HANDLE)
        .context("reading process creation time")?;
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
```

- [ ] **Step 6: Run gates incl. the cross-check for procmgr**

Run: full Linux gates, then
`cargo check --target x86_64-pc-windows-gnu -p izba-core 2>&1 | grep error`
Expected: Linux all green; the cross-check error list no longer mentions
procmgr (remaining errors are vsock/vmm `os::unix` only).

- [ ] **Step 7: Commit**

```bash
git add crates/izba-core/src/procmgr crates/izba-core/Cargo.toml
git commit -m "feat(core): procmgr platform split — Windows detached spawn, FILETIME identity, TerminateProcess"
```

---

### Task 4: UDS platform alias (`UdsStream`)

One alias, two backings; the `IoStream` impl and every concrete-stream
signature move to it. After this task **izba-core is fully cross-green**.

**Files:**
- Modify: `crates/izba-core/src/vmm/mod.rs`
- Modify: `crates/izba-core/src/vsock.rs`
- Modify: `crates/izba-core/src/sandbox.rs` (default_stream_connector + tests)
- Modify: `crates/izba-cli/src/commands/exec.rs` (import only)

- [ ] **Step 1: Add the alias and re-point the IoStream impl in `vmm/mod.rs`**

Replace the `impl IoStream for std::os::unix::net::UnixStream` block with:

```rust
/// Platform alias for a connected AF_UNIX stream socket. Windows 10 1803+
/// supports AF_UNIX natively, but Rust std only exposes it on Unix — the
/// Windows side uses the `uds_windows` crate (same API surface: `connect`,
/// `pair`, `try_clone`, `shutdown`, read/write timeouts).
#[cfg(unix)]
pub type UdsStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type UdsStream = uds_windows::UnixStream;

impl IoStream for UdsStream {
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(t)?;
        self.set_write_timeout(t)
    }
}
```

(If `uds_windows` turns out to lack `set_read_timeout`/`set_write_timeout` —
spec risk item — wrap it in a newtype implementing them via
`winapi setsockopt SO_RCVTIMEO/SO_SNDTIMEO`; check docs.rs/uds_windows 1.1
first, the methods are expected to exist.)

- [ ] **Step 2: Switch `vsock.rs` to the alias**

Replace `use std::os::unix::net::UnixStream;` with
`use crate::vmm::UdsStream;` and rename the type in the three signatures:

```rust
pub fn hybrid_connect(socket: &Path, port: u32) -> anyhow::Result<UdsStream> {
    let s = UdsStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    hybrid_handshake(s, port)
}

fn hybrid_handshake(mut s: UdsStream, port: u32) -> anyhow::Result<UdsStream> {
```

In the tests module: replace every `UnixStream::pair()` with
`UdsStream::pair()` (`use super::*` already brings it in via the parent
import — add `use crate::vmm::UdsStream;` to the test module if needed) and
the listener in `full_connect_via_listener` keeps using
`std::os::unix::net::UnixListener` — wrap that one test in `#[cfg(unix)]`
(uds_windows has its own listener type; the cross-target test build must not
reference the std unix one).

- [ ] **Step 3: Switch `sandbox.rs`'s stream connector**

```rust
/// The production stream-port connector: hybrid-vsock through `run/vsock.sock`
/// to [`STREAM_PORT`].
///
/// Returns a concrete [`crate::vmm::UdsStream`] (not `Box<dyn IoStream>`)
/// because stream pumps need `try_clone` for the second direction and
/// `shutdown` to signal half-close — neither is expressible on the trait.
pub fn default_stream_connector(
) -> impl Fn(&Paths, &str) -> anyhow::Result<crate::vmm::UdsStream> {
```

Also update the doc comment on `default_connector` if it names the std type,
and in the `#[cfg(test)]` module replace `use std::os::unix::net::UnixStream;`
usages with the alias the same way as vsock.rs (socketpair fakes keep
working — on Unix the alias IS `UnixStream`).

- [ ] **Step 4: Switch the CLI import**

In `crates/izba-cli/src/commands/exec.rs` replace
`use std::os::unix::net::UnixStream;` with
`use izba_core::vmm::UdsStream;` and change the one signature using it:

```rust
fn attach(paths: &Paths, name: &str, exec_id: u32, kind: StreamKind) -> anyhow::Result<UdsStream> {
```

(`Shutdown` stays `std::net::Shutdown` — `uds_windows` takes the same enum.)

- [ ] **Step 5: Run gates — izba-core must now be cross-green**

Run: full Linux gates, then:
`cargo check --target x86_64-pc-windows-gnu -p izba-core` → **PASS expected**
`cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-core -- -D warnings` → PASS expected
Expected: izba-cli cross-check still fails (terminal/libc/signal-hook — Task 7).

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/vmm/mod.rs crates/izba-core/src/vsock.rs crates/izba-core/src/sandbox.rs crates/izba-cli/src/commands/exec.rs
git commit -m "feat(core): UdsStream platform alias — uds_windows backing on Windows"
```

---

### Task 5: Extract the tool-discovery helper (`discover.rs`)

The `$ENV` → `<exe dir>/libexec/` → `PATH` probe currently lives in
`image/erofs.rs`; the OpenVMM driver needs the identical logic. Extract once.

**Files:**
- Create: `crates/izba-core/src/discover.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `mod discover;`)
- Modify: `crates/izba-core/src/image/erofs.rs` (delegate)

- [ ] **Step 1: Write `discover.rs` with the tests moved from erofs.rs**

```rust
//! Locate external tool binaries: explicit env-var override, then a copy
//! bundled next to the running executable (`<exe dir>/libexec/`, Docker's
//! convention — installers rely on this), then `$PATH`.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub(crate) fn find_tool(env_var: &str, exe_name: &str) -> Result<PathBuf> {
    find_tool_from(
        env_var,
        exe_name,
        std::env::var_os(env_var).map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

fn find_tool_from(
    env_var: &str,
    exe_name: &str,
    env_override: Option<PathBuf>,
    current_exe: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(p) = env_override {
        if p.is_file() {
            return Ok(p);
        }
        bail!("{env_var} is set to {} but no file exists there", p.display());
    }
    if let Some(dir) = current_exe.as_deref().and_then(Path::parent) {
        let bundled = dir.join("libexec").join(exe_name);
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    which::which(exe_name).map_err(|_| {
        anyhow::anyhow!(
            "{exe_name} not found (checked ${env_var}, <exe dir>/libexec/{exe_name}, PATH) — \
             install it or set {env_var}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let fake = dir.path().join("my-tool");
        std::fs::write(&fake, b"").unwrap();
        let got = find_tool_from("IZBA_TOOL", "tool", Some(fake.clone()), None).unwrap();
        assert_eq!(got, fake);
    }

    #[test]
    fn env_override_beats_bundled() {
        let override_dir = tempfile::TempDir::new().unwrap();
        let override_file = override_dir.path().join("my-tool-override");
        std::fs::write(&override_file, b"").unwrap();

        let exe_dir = tempfile::TempDir::new().unwrap();
        let libexec = exe_dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        std::fs::write(libexec.join("tool"), b"").unwrap();

        let got = find_tool_from(
            "IZBA_TOOL",
            "tool",
            Some(override_file.clone()),
            Some(exe_dir.path().join("izba")),
        )
        .unwrap();
        assert_eq!(got, override_file);
    }

    #[test]
    fn env_override_missing_is_error() {
        let err = find_tool_from("IZBA_TOOL", "tool", Some(PathBuf::from("/nonexistent/x")), None)
            .unwrap_err();
        assert!(err.to_string().contains("IZBA_TOOL"));
    }

    #[test]
    fn bundled_libexec_beats_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let libexec = dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        let bundled = libexec.join("tool");
        std::fs::write(&bundled, b"").unwrap();
        let got = find_tool_from("IZBA_TOOL", "tool", None, Some(dir.path().join("izba"))).unwrap();
        assert_eq!(got, bundled);
    }

    #[test]
    fn falls_back_to_path() {
        // No override, no bundled copy: outcome depends on the host having
        // an `sh` on PATH (universally true on Linux/CI) vs a junk name.
        assert!(find_tool_from("IZBA_TOOL", "sh", None, None).is_ok());
        let err = find_tool_from("IZBA_TOOL", "definitely-not-a-real-tool-xyz", None, None)
            .unwrap_err();
        assert!(err.to_string().contains("PATH"));
    }
}
```

Add `mod discover;` to `crates/izba-core/src/lib.rs` (not `pub` — internal).

- [ ] **Step 2: Run the new tests**

Run: `cargo test -p izba-core discover`
Expected: PASS.

- [ ] **Step 3: Delegate from erofs.rs**

In `image/erofs.rs`, delete `find_mkfs_erofs_from` and the five `resolve_*`
tests (they moved, parameterized, to discover.rs), keep `MKFS_EROFS_EXE`,
and shrink the finder to:

```rust
/// Locate `mkfs.erofs`: explicit `$IZBA_MKFS_EROFS` override, then a copy
/// bundled next to the running executable (`<exe dir>/libexec/`, Docker's
/// convention — the future Windows installer relies on this), then `$PATH`.
fn find_mkfs_erofs() -> Result<PathBuf> {
    crate::discover::find_tool("IZBA_MKFS_EROFS", MKFS_EROFS_EXE)
}
```

Keep the `erofs_smoke` test untouched.

- [ ] **Step 4: Run gates**

Run: full Linux gates + the izba-core cross gates (must stay green).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/discover.rs crates/izba-core/src/lib.rs crates/izba-core/src/image/erofs.rs
git commit -m "refactor(core): extract env→libexec→PATH tool discovery, shared by mkfs.erofs"
```

---

### Task 6: OpenVmmDriver

`vmm/openvmm.rs`: pure `build_invocation` (golden-argv unit tests on Linux,
encoding the rung-7 canonical invocation) + `OpenVmmDriver`/`OpenVmmHandle`.
No sidecars; compiles on both targets (procmgr/vsock/discover are platform-split
underneath).

**Files:**
- Create: `crates/izba-core/src/vmm/openvmm.rs`
- Modify: `crates/izba-core/src/vmm/mod.rs` (add `pub mod openvmm;`)

- [ ] **Step 1: Write the failing golden-argv tests**

Create `openvmm.rs` with only the test module first (plus stub
`build_invocation` returning `CommandSpec { argv: vec![] }` so it compiles):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::spec::{BlockDisk, FsShare, VmSpec};
    use std::path::PathBuf;

    fn base_spec() -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/img/vmlinux"),
            initramfs: PathBuf::from("/img/initramfs.img"),
            cmdline: "console=ttyS0 ip=dhcp izba.hostname=box".to_string(),
            cpus: 2,
            mem_mb: 4096,
            disks: vec![
                BlockDisk {
                    path: PathBuf::from("/img/rootfs.erofs"),
                    readonly: true,
                },
                BlockDisk {
                    path: PathBuf::from("/sbx/rw.img"),
                    readonly: false,
                },
            ],
            shares: vec![FsShare {
                tag: "workspace".to_string(),
                host_path: PathBuf::from("/home/user/project"),
            }],
            net: true,
            console_log: PathBuf::from("/sbx/console.log"),
            run_dir: PathBuf::from("/sbx/run"),
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn openvmm_invocation() {
        let inv = build_invocation(&base_spec(), &PathBuf::from("/opt/openvmm"));
        assert_eq!(
            inv.argv,
            argv(&[
                "/opt/openvmm",
                "--kernel",
                "/img/vmlinux",
                "--initrd",
                "/img/initramfs.img",
                "-c",
                "console=ttyS0 ip=dhcp izba.hostname=box",
                "--hv",
                "--processors",
                "2",
                "--memory",
                "4096MB",
                "--com1",
                "file=/sbx/console.log",
                "--pcie-root-complex",
                "rc0",
                "--pcie-root-port",
                "rc0:vda",
                "--pcie-root-port",
                "rc0:vdb",
                "--pcie-root-port",
                "rc0:fs-workspace",
                "--virtio-blk",
                "file:/img/rootfs.erofs,ro,pcie_port=vda",
                "--virtio-blk",
                "file:/sbx/rw.img,pcie_port=vdb",
                "--virtio-fs",
                "pcie_port=fs-workspace:workspace,/home/user/project",
                "--net",
                "consomme",
                "--virtio-vsock-path",
                "/sbx/run/vsock.sock",
            ])
        );
    }

    #[test]
    fn openvmm_invocation_no_net() {
        let mut spec = base_spec();
        spec.net = false;
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        assert!(!inv.argv.contains(&"--net".to_string()));
        assert!(!inv.argv.contains(&"consomme".to_string()));
        // vsock stays:
        assert!(inv.argv.contains(&"--virtio-vsock-path".to_string()));
    }

    #[test]
    fn openvmm_invocation_multi_share() {
        let mut spec = base_spec();
        spec.shares.push(FsShare {
            tag: "cache".to_string(),
            host_path: PathBuf::from("/home/user/.cache/izba"),
        });
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        let joined = inv.argv.join(" ");
        assert!(joined.contains("--pcie-root-port rc0:fs-workspace"));
        assert!(joined.contains("--pcie-root-port rc0:fs-cache"));
        assert!(joined.contains("pcie_port=fs-cache:cache,/home/user/.cache/izba"));
    }

    #[test]
    fn disk_ports_follow_disk_order() {
        // The vda/vdb naming is a contract with the guest mount plan: disk 0
        // (rootfs.erofs) must enumerate first. Three disks → vda vdb vdc.
        let mut spec = base_spec();
        spec.disks.push(BlockDisk {
            path: PathBuf::from("/x/extra.img"),
            readonly: false,
        });
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        let joined = inv.argv.join(" ");
        assert!(joined.contains("file:/img/rootfs.erofs,ro,pcie_port=vda"));
        assert!(joined.contains("file:/sbx/rw.img,pcie_port=vdb"));
        assert!(joined.contains("file:/x/extra.img,pcie_port=vdc"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core openvmm`
Expected: FAIL (stub returns empty argv).

- [ ] **Step 3: Implement the module**

Full content above the test module:

```rust
//! OpenVMM backend (Windows/WHP): pure argv construction plus the
//! [`OpenVmmDriver`] that spawns `openvmm.exe`. Unlike Cloud Hypervisor
//! there are NO sidecars — the virtiofs server and consomme networking run
//! in-process inside openvmm (spike S1+ finding (c)), so launch is a single
//! detached spawn and `pids()` is just `[("vmm", id)]`.
//!
//! Flag shapes are pinned by the rung-7 canonical invocation in
//! docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md:
//! `--hv` is mandatory (VPCI vsock + netvsp need it); virtio-blk must be
//! routed via per-disk PCIe root ports (VPCI auto-routing collides device
//! IDs); networking is `--net consomme` (netvsp NIC), not virtio-net.
//! `--processors`/`--memory` are spike-unverified (defaults were used) and
//! get confirmed against `openvmm.exe --help` during Plan 2 bring-up.

use super::spec::{CommandSpec, VmSpec};
use super::{IoStream, VmHandle, VmmDriver};
use crate::procmgr::{kill_pid, pid_alive, spawn_detached};
use crate::state::PidIdentity;
use crate::vsock::hybrid_connect;
use anyhow::Context;
use std::path::{Path, PathBuf};

#[cfg(windows)]
const OPENVMM_EXE: &str = "openvmm.exe";
#[cfg(not(windows))]
const OPENVMM_EXE: &str = "openvmm";

/// Locate `openvmm`: explicit `$IZBA_OPENVMM` override, then a copy bundled
/// next to the running executable (`<exe dir>/libexec/`), then `$PATH`.
pub fn find_openvmm() -> anyhow::Result<PathBuf> {
    crate::discover::find_tool("IZBA_OPENVMM", OPENVMM_EXE)
}

/// PCIe root-port name for disk `i`: vda, vdb, … — mirrors the guest's
/// virtio-blk device names so the disk-order contract (rootfs = vda,
/// rw = vdb) stays legible end to end.
fn disk_port(i: usize) -> String {
    assert!(i < 26, "more than 26 disks is not a supported VmSpec");
    format!("vd{}", (b'a' + i as u8) as char)
}

pub fn build_invocation(spec: &VmSpec, openvmm: &Path) -> CommandSpec {
    let vsock_sock = spec.run_dir.join("vsock.sock");
    let mut argv = vec![
        openvmm.display().to_string(),
        "--kernel".to_string(),
        spec.kernel.display().to_string(),
        "--initrd".to_string(),
        spec.initramfs.display().to_string(),
        "-c".to_string(),
        spec.cmdline.clone(),
        "--hv".to_string(),
        "--processors".to_string(),
        spec.cpus.to_string(),
        "--memory".to_string(),
        format!("{}MB", spec.mem_mb),
        "--com1".to_string(),
        format!("file={}", spec.console_log.display()),
        "--pcie-root-complex".to_string(),
        "rc0".to_string(),
    ];
    for i in 0..spec.disks.len() {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:{}", disk_port(i)));
    }
    for share in &spec.shares {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:fs-{}", share.tag));
    }
    for (i, disk) in spec.disks.iter().enumerate() {
        let ro = if disk.readonly { ",ro" } else { "" };
        argv.push("--virtio-blk".to_string());
        argv.push(format!(
            "file:{}{ro},pcie_port={}",
            disk.path.display(),
            disk_port(i)
        ));
    }
    for share in &spec.shares {
        argv.push("--virtio-fs".to_string());
        argv.push(format!(
            "pcie_port=fs-{}:{},{}",
            share.tag,
            share.tag,
            share.host_path.display()
        ));
    }
    if spec.net {
        argv.push("--net".to_string());
        argv.push("consomme".to_string());
    }
    argv.push("--virtio-vsock-path".to_string());
    argv.push(vsock_sock.display().to_string());
    CommandSpec { argv }
}

/// Spawns openvmm as a single detached process.
///
/// Integration-tested on the Windows spike host (Plan 2); not unit-tested —
/// `build_invocation` carries the testable logic.
pub struct OpenVmmDriver;

impl VmmDriver for OpenVmmDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>> {
        std::fs::create_dir_all(&spec.run_dir)
            .with_context(|| format!("creating {}", spec.run_dir.display()))?;
        let log_dir = spec
            .console_log
            .parent()
            .context("console_log has no parent directory")?;
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("creating {}", log_dir.display()))?;

        let openvmm = find_openvmm()?;
        let inv = build_invocation(spec, &openvmm);

        // A crashed previous run leaves the AF_UNIX socket file behind;
        // openvmm must be able to re-bind it.
        let vsock_sock = spec.run_dir.join("vsock.sock");
        match std::fs::remove_file(&vsock_sock) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("removing stale {}", vsock_sock.display()))
            }
        }

        // Guest serial goes to spec.console_log via --com1 file=; openvmm's
        // own stdout/stderr go to a sibling vmm.log.
        let vmm_id = spawn_detached(&inv, &log_dir.join("vmm.log"))
            .context("spawning openvmm")?;

        Ok(Box::new(OpenVmmHandle {
            vsock_sock,
            vmm: ("vmm".to_string(), vmm_id),
        }))
    }
}

/// Handle to a launched openvmm VM — exactly one process, no sidecars.
struct OpenVmmHandle {
    vsock_sock: PathBuf,
    vmm: (String, PidIdentity),
}

impl VmHandle for OpenVmmHandle {
    fn connect(&self, port: u32) -> anyhow::Result<Box<dyn IoStream>> {
        let s = hybrid_connect(&self.vsock_sock, port)?;
        Ok(Box::new(s))
    }

    fn pids(&self) -> Vec<(String, PidIdentity)> {
        vec![self.vmm.clone()]
    }

    fn is_alive(&self) -> bool {
        pid_alive(&self.vmm.1)
    }

    fn kill(&mut self) -> anyhow::Result<()> {
        kill_pid(&self.vmm.1).context("killing vmm")
    }
}
```

Add to `vmm/mod.rs` next to `pub mod cloud_hypervisor;`:

```rust
pub mod openvmm;
```

- [ ] **Step 4: Run tests + gates**

Run: `cargo test -p izba-core openvmm` → PASS; full Linux gates; izba-core
cross gates (check + clippy) → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/vmm/openvmm.rs crates/izba-core/src/vmm/mod.rs
git commit -m "feat(core): OpenVmmDriver — rung-7-pinned argv builder, sidecar-free launch"
```

---

### Task 7: CLI platform work (terminal, resize, driver selection)

After this task **izba-cli is fully cross-green**.

**Files:**
- Modify: `crates/izba-cli/src/terminal.rs` (platform split)
- Modify: `crates/izba-cli/src/commands/exec.rs` (tty check, resize watcher)
- Modify: `crates/izba-cli/src/commands/run.rs` (tty check, driver selection)
- Modify: `crates/izba-cli/Cargo.toml` (platform-scope the deps)

- [ ] **Step 1: Rewrite `terminal.rs` with a platform-split `imp` module**

```rust
//! Host terminal handling: raw mode, window size, tty detection.

use std::io::IsTerminal;

/// Is stdin a terminal? (Cross-platform via std's `IsTerminal`.)
pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

pub use imp::{winsize, RawGuard};

#[cfg(unix)]
mod imp {
    use anyhow::Context;
    use nix::sys::termios::{self, SetArg, Termios};
    use std::io;

    /// Puts stdin into raw mode; restores the saved settings on drop, so the
    /// terminal recovers even on early returns and panics that unwind.
    pub struct RawGuard {
        saved: Termios,
    }

    impl RawGuard {
        pub fn new() -> anyhow::Result<Self> {
            let saved =
                termios::tcgetattr(io::stdin()).context("reading terminal attributes")?;
            let mut raw = saved.clone();
            termios::cfmakeraw(&mut raw);
            termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &raw)
                .context("setting terminal raw mode")?;
            Ok(Self { saved })
        }
    }

    impl Drop for RawGuard {
        fn drop(&mut self) {
            let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
        }
    }

    /// Current terminal size as `(cols, rows)`; falls back to 80x24 when
    /// stdout is not a terminal (or the ioctl fails).
    pub fn winsize() -> (u16, u16) {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

#[cfg(windows)]
mod imp {
    use anyhow::bail;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, SetConsoleMode,
        CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };

    /// Puts the console into raw VT mode; restores both saved modes on drop.
    ///
    /// stdin drops line/echo/Ctrl-C processing and turns on VT input (so
    /// arrow keys etc. arrive as escape sequences, matching the guest PTY);
    /// stdout turns on VT processing (so guest escape sequences render).
    pub struct RawGuard {
        stdin: HANDLE,
        stdout: HANDLE,
        saved_in: u32,
        saved_out: u32,
    }

    impl RawGuard {
        pub fn new() -> anyhow::Result<Self> {
            let stdin = io::stdin().as_raw_handle() as HANDLE;
            let stdout = io::stdout().as_raw_handle() as HANDLE;
            let mut saved_in: u32 = 0;
            let mut saved_out: u32 = 0;
            // SAFETY: plain FFI on the process's own std handles.
            unsafe {
                if GetConsoleMode(stdin, &mut saved_in) == 0 {
                    bail!("stdin is not a console");
                }
                if GetConsoleMode(stdout, &mut saved_out) == 0 {
                    bail!("stdout is not a console");
                }
                let raw_in = (saved_in
                    & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT;
                if SetConsoleMode(stdin, raw_in) == 0 {
                    bail!(
                        "setting console raw input mode: {}",
                        io::Error::last_os_error()
                    );
                }
                let raw_out = saved_out | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if SetConsoleMode(stdout, raw_out) == 0 {
                    let _ = SetConsoleMode(stdin, saved_in);
                    bail!(
                        "enabling console VT output: {}",
                        io::Error::last_os_error()
                    );
                }
            }
            Ok(Self {
                stdin,
                stdout,
                saved_in,
                saved_out,
            })
        }
    }

    impl Drop for RawGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the modes we saved on the same handles.
            unsafe {
                let _ = SetConsoleMode(self.stdin, self.saved_in);
                let _ = SetConsoleMode(self.stdout, self.saved_out);
            }
        }
    }

    /// Current console window size as `(cols, rows)`; 80x24 fallback when
    /// stdout is not a console.
    pub fn winsize() -> (u16, u16) {
        let h = io::stdout().as_raw_handle() as HANDLE;
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: valid handle and out-pointer.
        let ok = unsafe { GetConsoleScreenBufferInfo(h, &mut info) };
        if ok != 0 {
            let cols = (info.srWindow.Right - info.srWindow.Left + 1).max(0) as u16;
            let rows = (info.srWindow.Bottom - info.srWindow.Top + 1).max(0) as u16;
            if cols > 0 && rows > 0 {
                return (cols, rows);
            }
        }
        (80, 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winsize_has_fallback() {
        // Under `cargo test` stdout is a pipe, so this exercises the fallback;
        // on a real terminal it returns the actual size. Either way: nonzero.
        let (cols, rows) = winsize();
        assert!(cols > 0 && rows > 0);
    }
}
```

(The old `is_tty(RawFd)` and its `/dev/null` test are deleted — `IsTerminal`
is std and needs no test of our own.)

- [ ] **Step 2: Update the two tty-check call sites**

`commands/run.rs` line ~27: `let tty = terminal::stdin_is_tty();`
`commands/exec.rs` line ~31: `if tty && !terminal::stdin_is_tty() {`

- [ ] **Step 3: Platform-split the resize watcher in `exec.rs`**

Rename `spawn_winch` → `spawn_resize_watcher` (update the call in `wait_tty`)
and provide both bodies:

```rust
/// Pushes a Resize RPC whenever the local terminal size changes.
#[cfg(unix)]
fn spawn_resize_watcher(
    control: Arc<Mutex<Box<dyn IoStream>>>,
    exec_id: u32,
) -> anyhow::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH])
        .context("installing SIGWINCH handler")?;
    std::thread::spawn(move || {
        for _ in signals.forever() {
            resize(&control, exec_id);
        }
    });
    Ok(())
}

/// Windows has no SIGWINCH: poll the console size. 200 ms is imperceptible
/// for a human dragging a window and costs one syscall per tick.
#[cfg(windows)]
fn spawn_resize_watcher(
    control: Arc<Mutex<Box<dyn IoStream>>>,
    exec_id: u32,
) -> anyhow::Result<()> {
    std::thread::spawn(move || {
        let mut last = terminal::winsize();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let now = terminal::winsize();
            if now != last {
                last = now;
                resize(&control, exec_id);
            }
        }
    });
    Ok(())
}
```

- [ ] **Step 4: Per-OS default driver in `run.rs`**

Replace the CH import + call site:

```rust
#[cfg(unix)]
use izba_core::vmm::cloud_hypervisor::CloudHypervisorDriver as DefaultDriver;
#[cfg(windows)]
use izba_core::vmm::openvmm::OpenVmmDriver as DefaultDriver;
```

```rust
    match sandbox::start(paths, &name, &DefaultDriver, &art) {
```

- [ ] **Step 5: Platform-scope `crates/izba-cli/Cargo.toml` deps**

```toml
[dependencies]
izba-core = { path = "../izba-core" }
izba-proto = { path = "../izba-proto" }
anyhow.workspace = true
clap = { version = "4", features = ["derive"] }

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["term"] }
signal-hook = "0.3"
libc = "0.2"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.60", features = [
    "Win32_Foundation",
    "Win32_System_Console",
] }
```

- [ ] **Step 6: Run gates — izba-cli must now be cross-green**

Run: full Linux gates, then:
`cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli` → PASS
`cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings` → PASS

- [ ] **Step 7: Commit**

```bash
git add crates/izba-cli/src/terminal.rs crates/izba-cli/src/commands/exec.rs crates/izba-cli/src/commands/run.rs crates/izba-cli/Cargo.toml
git commit -m "feat(cli): Windows console raw mode, resize polling, per-OS default driver"
```

---

### Task 8: Sparse rw.img on NTFS, gates wiring, cross-built izba.exe

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (`create`, rw.img block ~line 172)
- Modify: `CLAUDE.md` (build & test section)
- Modify: `hack/README.md` (cross-build runbook section)

- [ ] **Step 1: Mark rw.img sparse before sizing**

In `sandbox::create`'s populate closure, between `File::create` and
`set_len`, insert `mark_sparse(&f);` so the block reads:

```rust
        // Sparse scratch disk: apparent size only, no blocks allocated.
        let rw = dir.join("rw.img");
        let f = File::create(&rw).with_context(|| format!("creating {}", rw.display()))?;
        mark_sparse(&f); // no-op on Unix; NTFS needs an explicit opt-in
        f.set_len(opts.rw_size_gb * 1024 * 1024 * 1024)
            .with_context(|| format!("sizing {}", rw.display()))?;
```

and add at file level (near `lock_sandbox`):

```rust
/// On NTFS, `set_len` allocates real clusters — without this, every sandbox
/// physically reserves its full rw_size_gb. Unix filesystems extend sparsely
/// by default, hence the no-op. Best-effort: failure costs disk space, not
/// correctness.
#[cfg(windows)]
fn mark_sparse(f: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned: u32 = 0;
    // SAFETY: valid file handle; no in/out buffers; null overlapped = sync.
    unsafe {
        DeviceIoControl(
            f.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
fn mark_sparse(_f: &File) {}
```

- [ ] **Step 2: Add the cross gates to `CLAUDE.md`**

In the “Build & test” fenced block, after the musl build line, add:

```sh
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

and extend the sentence below the block: all six must be green before any
commit (the cross gates need `rustup target add x86_64-pc-windows-gnu` and
the `gcc-mingw-w64-x86-64` toolchain).

- [ ] **Step 3: Add a cross-build section to `hack/README.md`**

After the mkfs.erofs-for-Windows section:

```markdown
## izba.exe (Windows host CLI)

Cross-built from WSL with the same MinGW toolchain as `mkfs.erofs.exe`:

​```sh
rustup target add x86_64-pc-windows-gnu   # once
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
# → target/x86_64-pc-windows-gnu/release/izba.exe
​```

The Windows binary discovers its tools via `$IZBA_MKFS_EROFS` /
`$IZBA_OPENVMM`, an exe-adjacent `libexec\` directory, then `PATH` — see
[the Windows-port design](../docs/superpowers/specs/2026-06-10-izba-windows-port-design.md).
```

(Remove the `​` zero-width characters — they only protect this plan's nesting.)

- [ ] **Step 4: Cross-build izba.exe (the link gate)**

```sh
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
file target/x86_64-pc-windows-gnu/release/izba.exe
```

Expected: `PE32+ executable (console) x86-64, for MS Windows`. This is the
first step that LINKS the Windows binary (check/clippy don't), so missing
symbols (e.g. ws2_32 from uds_windows) surface here.

- [ ] **Step 5: Run all gates one final time**

Full Linux set + both cross gates. Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/sandbox.rs CLAUDE.md hack/README.md
git commit -m "feat(core): sparse rw.img on NTFS; wire Windows cross gates into the runbooks"
```

---

## Self-review notes

- Spec §3.1–§3.8 all map to tasks: lock→1, paths→2, procmgr→3, UDS→4,
  discovery→5, driver→6, CLI→7, sparse+gates→8. §4 gates → task 8 + per-task
  gate lines. Nothing in spec Plan-1 scope is unassigned.
- Types referenced across tasks are defined before use (UdsStream in task 4,
  used by task 6/7; discover in task 5, used by task 6).
- `--processors`/`--memory` are deliberately encoded as-is and called out as
  Plan-2-verify (spec §3.6 + risk table) — golden tests change in one place
  if bring-up corrects them.
