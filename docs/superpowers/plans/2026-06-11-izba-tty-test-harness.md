# izba `exec -it` TTY Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the manual `izba exec -it` operator checklist with declarative `cargo test` cases that drive the real `izba` binary through a real PTY (Linux) / ConPTY (Windows), send keystrokes/resizes, and assert on the rendered screen.

**Architecture:** A new dev-support crate `izba-ttytest` provides three units: a cross-platform `TerminalSession` (portable-pty + vt100) that drives the compiled `izba` binary and scrapes the screen grid; a `ScriptedGuest` that fakes a running sandbox over a Unix-domain socket (CH hybrid-vsock handshake + framed izba protocol) so the host terminal layer can be tested with no VM; and `scenarios` encoding the checklist. Two `cargo test` tiers consume it: Tier 1 (scripted guest, no VM, both OSes) and Tier 2 (real sandbox, env-gated). Both test files are behind an opt-in `ttytests` feature so the six standard build gates are unaffected.

**Tech Stack:** Rust, `portable-pty` 0.9 (Unix PTY + Windows ConPTY), `vt100` 0.16 (screen grid), the existing `izba-proto` wire types and `izba-core` (`state`, `procmgr`, `paths`).

**Spec:** `docs/superpowers/specs/2026-06-11-izba-tty-test-harness-design.md`

**Grounding facts (verified against the codebase):**
- Proto (`crates/izba-proto/src/messages.rs`): `Request::{Health, Exec(ExecRequest), Wait{exec_id}, Kill{exec_id,signal}, Resize{exec_id,cols,rows}, Shutdown}`; `Response::{Health(HealthInfo), ExecStarted{exec_id}, Wait{status:ExitStatus}, Ok, Error{kind:ErrorKind,message}}`; `ExitStatus::{Code(i32),Signal(i32)}`; `ErrorKind::{CommandNotFound,ExecNotFound,BadRequest,Internal}`; `StreamAttach{exec_id,kind:StreamKind}`; `StreamKind::{Stdin,Stdout,Stderr,Tty}`; `CONTROL_PORT=1025`, `STREAM_PORT=1026`. Codec: `izba_proto::{read_frame, write_frame}` (length-prefixed JSON).
- Hybrid-vsock handshake (host side `crates/izba-core/src/vsock.rs`): the connector connects to one Unix socket at `run_dir(name)/vsock.sock`, writes `CONNECT <port>\n`, then reads a response line byte-by-byte and requires it to start with `OK `. The same socket path is used for both ports; the `CONNECT <port>` line selects control (1025) vs stream (1026).
- Data-root override: the CLI calls `Paths::from_env_or_default(std::env::var_os("IZBA_DATA_DIR").map(PathBuf::from))` (`crates/izba-cli/src/main.rs:118`). Setting `IZBA_DATA_DIR` on the child process redirects the entire data root — no code change needed to point `izba` at the fake sandbox.
- Liveness: `izba` loads `state.json` (`RunState{vmm_pid:PidIdentity{pid,starttime}, sidecar_pids, started_unix_ms}`) and checks the pid is alive with a matching `starttime`, then health-checks over the connector. Backing `vmm_pid` with the test process's own identity (alive for the test's duration) satisfies it.
- `izba-core` public surface used here: `izba_core::state::{RunState, PidIdentity, save_json, STATE_FILE}`, `izba_core::paths::Paths`, `izba_core::procmgr::{pid_alive, kill_pid}`. `proc_starttime` is `pub(crate)` — Task 1 adds a public `current_identity()`.
- CLI bin name is `izba` → tests use `env!("CARGO_BIN_EXE_izba")`.
- `izba-core` already depends on `uds_windows = "1.1"` for the Windows AF_UNIX path.

**Environment notes for the implementer:**
- Source the sandbox toolchain first if present: `[ -f .cargo-env ] && source .cargo-env`.
- `portable-pty`/`vt100` are not cached and crates.io is outside the command sandbox's network allowlist. The first dependency fetch (`cargo fetch` / first `cargo build`) must be run with `dangerouslyDisableSandbox: true`. Subsequent builds work sandboxed.
- The six CLAUDE.md build gates must stay green at every commit. They are:
  1. `cargo test --workspace`
  2. `cargo clippy --workspace --all-targets -- -D warnings`
  3. `cargo fmt --check`
  4. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
  5. `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
  6. `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
  Because the two new test files use `required-features = ["ttytests"]` (off by default), gates 1/2/5/6 never build the PTY harness or its dev-deps, so they remain green without cross-compiling `portable-pty`. The harness is exercised explicitly with `--features ttytests` (see Task 7).

---

## Task 1: Add `current_identity()` to izba-core

Gives external crates a PID-reuse-safe identity for the current process, so `ScriptedGuest` can fabricate a `state.json` the real binary accepts as live.

**Files:**
- Modify: `crates/izba-core/src/procmgr/mod.rs`
- Test: `crates/izba-core/src/procmgr/mod.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/izba-core/src/procmgr/mod.rs`:

```rust
#[cfg(test)]
mod current_identity_tests {
    use super::*;

    #[test]
    fn current_identity_is_self_and_alive() {
        let id = current_identity().expect("current identity");
        assert_eq!(id.pid, std::process::id());
        assert!(pid_alive(&id), "the current process must read as alive");
    }
}
```

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test -p izba-core current_identity_is_self_and_alive`
Expected: FAIL — `cannot find function current_identity in this scope`.

- [ ] **Step 3: Implement `current_identity` and a public `proc_starttime`**

In `crates/izba-core/src/procmgr/mod.rs`, change the two test-gated re-exports of `proc_starttime` to public ones and add the constructor. Replace:

```rust
#[cfg(all(unix, test))]
pub(crate) use unix::proc_starttime;
```
with
```rust
#[cfg(unix)]
pub use unix::proc_starttime;
```
and replace:
```rust
#[cfg(all(windows, test))]
pub(crate) use windows::proc_starttime;
```
with
```rust
#[cfg(windows)]
pub use windows::proc_starttime;
```

Then add (after the re-exports, before the test module):

```rust
use crate::state::PidIdentity;

/// PID-reuse-safe identity of the current process. Alive for as long as this
/// process runs, so it is a valid `vmm_pid` for a fabricated `state.json` in
/// tests and test-support tooling.
pub fn current_identity() -> anyhow::Result<PidIdentity> {
    let pid = std::process::id();
    Ok(PidIdentity {
        pid,
        starttime: proc_starttime(pid)?,
    })
}
```

If `crate::state::PidIdentity` is already imported in this file, do not duplicate the `use`.

- [ ] **Step 4: Run the test**

Run: `cargo test -p izba-core current_identity_is_self_and_alive`
Expected: PASS.

- [ ] **Step 5: Guard the gates**

Run: `cargo clippy -p izba-core --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean. (Making `proc_starttime` public removes the previous `#[cfg(test)]` gate; confirm no `unused` warnings appear in non-test builds — `current_identity` uses it unconditionally so it is now always reachable.)

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(core): expose current_identity() for liveness fabrication"
```

---

## Task 2: Scaffold the `izba-ttytest` crate

**Files:**
- Create: `crates/izba-ttytest/Cargo.toml`
- Create: `crates/izba-ttytest/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Add the crate to the workspace**

In the root `Cargo.toml`, extend `members`:

```toml
[workspace]
resolver = "2"
members = ["crates/izba-proto", "crates/izba-core", "crates/izba-cli", "crates/izba-init", "crates/izba-ttytest"]
```

- [ ] **Step 2: Create `crates/izba-ttytest/Cargo.toml`**

```toml
[package]
name = "izba-ttytest"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
izba-proto = { path = "../izba-proto" }
izba-core = { path = "../izba-core" }
anyhow.workspace = true
serde_json.workspace = true
portable-pty = "0.9"
vt100 = "0.16"
tempfile = "3"

[target.'cfg(windows)'.dependencies]
uds_windows = "1.1"

[[bin]]
name = "ttyfixture"
path = "src/bin/ttyfixture.rs"
```

- [ ] **Step 3: Create `crates/izba-ttytest/src/lib.rs`**

```rust
//! Test-support harness for izba's interactive `exec -it` terminal path.
//!
//! - [`harness`] drives the real `izba` binary through a PTY/ConPTY and scrapes
//!   the screen with a vt100 parser.
//! - [`scripted_guest`] fakes a running sandbox over a Unix-domain socket so the
//!   host terminal layer can be tested with no VM.
//! - [`scenarios`] encodes the operator checklist as reusable scenarios.
//!
//! This crate is `publish = false`; it exists only for the test tiers in
//! `crates/izba-cli/tests/`.

pub mod harness;
pub mod scenarios;
pub mod scripted_guest;
```

- [ ] **Step 4: Fetch deps and build (network — disable sandbox for this one command)**

Run with `dangerouslyDisableSandbox: true`:
`bash -lc '[ -f .cargo-env ] && source .cargo-env; cargo build -p izba-ttytest 2>&1 | tail -20'`
Expected: it resolves `portable-pty` and `vt100`, then FAILS only because `src/bin/ttyfixture.rs` and the `harness`/`scenarios`/`scripted_guest` modules don't exist yet (`file not found for module`). That proves the manifest + deps are good.

- [ ] **Step 5: Create stub module files so the crate compiles**

Create empty-but-valid stubs (filled in later tasks):
- `crates/izba-ttytest/src/harness.rs` → `//! Terminal session harness.` (one doc-comment line)
- `crates/izba-ttytest/src/scripted_guest.rs` → `//! Scripted fake guest.`
- `crates/izba-ttytest/src/scenarios.rs` → `//! Checklist scenarios.`
- `crates/izba-ttytest/src/bin/ttyfixture.rs`:

```rust
fn main() {}
```

- [ ] **Step 6: Build green**

Run (sandboxed is fine now): `cargo build -p izba-ttytest`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/izba-ttytest/Cargo.toml crates/izba-ttytest/src/lib.rs crates/izba-ttytest/src/harness.rs crates/izba-ttytest/src/scripted_guest.rs crates/izba-ttytest/src/scenarios.rs crates/izba-ttytest/src/bin/ttyfixture.rs
git commit -m "feat(ttytest): scaffold izba-ttytest dev-support crate"
```

---

## Task 3: `TerminalSession` harness + `ttyfixture`

**Files:**
- Modify: `crates/izba-ttytest/src/bin/ttyfixture.rs`
- Modify: `crates/izba-ttytest/src/harness.rs`
- Test: `crates/izba-ttytest/tests/harness_smoke.rs`

- [ ] **Step 1: Implement the cross-platform fixture program**

`crates/izba-ttytest/src/bin/ttyfixture.rs` — prints a banner, echoes input prefixed with `GOT:`, exits on `q`:

```rust
//! Tiny cross-platform fixture for the TerminalSession smoke test: print a
//! banner, echo each input chunk back prefixed with `GOT:`, and exit on `q`.
use std::io::{Read, Write};

fn main() {
    let mut out = std::io::stdout();
    let _ = out.write_all(b"TTYFIXTURE-READY\r\n");
    let _ = out.flush();

    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 64];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = out.write_all(b"GOT:");
                let _ = out.write_all(&buf[..n]);
                let _ = out.write_all(b"\r\n");
                let _ = out.flush();
                if buf[..n].contains(&b'q') {
                    break;
                }
            }
        }
    }
    let _ = out.write_all(b"TTYFIXTURE-BYE\r\n");
    let _ = out.flush();
}
```

- [ ] **Step 2: Write the failing smoke test**

`crates/izba-ttytest/tests/harness_smoke.rs`:

```rust
use izba_ttytest::harness::TerminalSession;
use portable_pty::CommandBuilder;
use std::time::Duration;

/// Self-skip when this environment cannot allocate a PTY/ConPTY.
fn pty_or_skip(cmd: CommandBuilder) -> Option<TerminalSession> {
    match TerminalSession::spawn(cmd, 80, 24) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("SKIP: cannot allocate a PTY here: {e:#}");
            None
        }
    }
}

#[test]
fn fixture_banner_echo_and_exit() {
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let Some(mut sess) = pty_or_skip(cmd) else { return };

    sess.wait_for_text("TTYFIXTURE-READY", Duration::from_secs(5))
        .expect("banner");
    sess.send_keys("hi").expect("send hi");
    sess.wait_for_text("GOT:hi", Duration::from_secs(5))
        .expect("echo");
    sess.send_keys("q").expect("send q");
    let outcome = sess.wait_exit(Duration::from_secs(5)).expect("exit");
    assert_eq!(outcome.code, Some(0));
}

#[test]
fn resize_updates_grid_dimensions() {
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let Some(sess) = pty_or_skip(cmd) else { return };
    // Resizing must not error; the fixture ignores SIGWINCH, so we only assert
    // the call succeeds and the parser tracks the new size.
    sess.resize(100, 30).expect("resize");
    assert_eq!(sess.size(), (100, 30));
}
```

- [ ] **Step 3: Run it to confirm it fails to compile**

Run: `cargo test -p izba-ttytest --test harness_smoke`
Expected: FAIL — `TerminalSession` / methods not found.

- [ ] **Step 4: Implement `TerminalSession`**

`crates/izba-ttytest/src/harness.rs`:

```rust
//! Drives the real `izba` (or any) binary through a PTY/ConPTY and scrapes the
//! rendered screen with a vt100 parser.
//!
//! ConPTY renders asynchronously and runs its own reflow, so assertions are
//! always made against the parsed grid (never raw master bytes), and
//! [`TerminalSession::wait_stable`] polls until the grid quiesces.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

/// Outcome of the child process exiting.
pub struct ExitOutcome {
    pub code: Option<i32>,
}

pub struct TerminalSession {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    parser: Arc<Mutex<vt100::Parser>>,
    child: Box<dyn Child + Send + Sync>,
    cols: u16,
    rows: u16,
    _reader: std::thread::JoinHandle<()>,
}

impl TerminalSession {
    /// Open a PTY/ConPTY of `cols`x`rows`, spawn `cmd` on the slave, and start a
    /// background thread feeding master output into a vt100 parser.
    pub fn spawn(cmd: CommandBuilder, cols: u16, rows: u16) -> Result<Self> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty")?;
        let child = pair.slave.spawn_command(cmd).context("spawn on pty slave")?;
        // Drop the slave handle so the master sees EOF when the child exits.
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().context("clone reader")?;
        let writer = pair.master.take_writer().context("take writer")?;
        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));

        let sink = Arc::clone(&parser);
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink.lock().unwrap().process(&buf[..n]),
                }
            }
        });

        Ok(Self {
            master: pair.master,
            writer,
            parser,
            child,
            cols,
            rows,
            _reader: reader_thread,
        })
    }

    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes).context("write to pty")?;
        self.writer.flush().context("flush pty")?;
        Ok(())
    }

    pub fn send_keys(&mut self, s: &str) -> Result<()> {
        self.send_bytes(s.as_bytes())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("resize pty")?;
        self.parser.lock().unwrap().set_size(rows, cols);
        Ok(())
    }

    /// The size the parser currently tracks, as `(cols, rows)`.
    pub fn size(&self) -> (u16, u16) {
        let s = self.parser.lock().unwrap();
        let (rows, cols) = s.screen().size();
        (cols, rows)
    }

    pub fn screen_text(&self) -> String {
        self.parser.lock().unwrap().screen().contents()
    }

    pub fn screen_contains(&self, needle: &str) -> bool {
        self.screen_text().contains(needle)
    }

    /// Text of one cell (row, col), or None if out of range.
    pub fn cell(&self, row: u16, col: u16) -> Option<String> {
        self.parser
            .lock()
            .unwrap()
            .screen()
            .cell(row, col)
            .map(|c| c.contents())
    }

    pub fn wait_for_text(&self, needle: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.screen_contains(needle) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!(
            "timed out after {timeout:?} waiting for {needle:?}; screen was:\n{}",
            self.screen_text()
        );
    }

    /// Poll until the grid stops changing for `idle` (the ConPTY quiescence
    /// gate). Use before snapshotting after sending input.
    pub fn wait_stable(&self, idle: Duration, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut last = self.screen_text();
        let mut stable_since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let now = self.screen_text();
            if now != last {
                last = now;
                stable_since = Instant::now();
            } else if stable_since.elapsed() >= idle {
                return Ok(());
            }
            if start.elapsed() > timeout {
                bail!("screen not stable within {timeout:?}");
            }
        }
    }

    pub fn is_child_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Result<ExitOutcome> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().context("try_wait")? {
                return Ok(ExitOutcome {
                    code: Some(status.exit_code() as i32),
                });
            }
            if start.elapsed() > timeout {
                bail!("child did not exit within {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
```

Note on API specifics to verify against the resolved `portable-pty` 0.9 and `vt100` 0.16 during implementation: `Child::try_wait() -> io::Result<Option<ExitStatus>>` and `ExitStatus::exit_code() -> u32`; `vt100::Parser::{new, process, set_size, screen}`, `Screen::{contents, size, cell}` and `Cell::contents`. If `Screen::size()` returns `(rows, cols)`, keep the `(cols, rows)` swap in `size()` as written. If a method name differs slightly in the resolved version, adjust the call but keep the public signatures of `TerminalSession` exactly as above (later tasks depend on them).

- [ ] **Step 5: Run the smoke test**

Run: `cargo test -p izba-ttytest --test harness_smoke`
Expected: PASS (or self-SKIP printout if the environment denies PTY allocation; in this WSL2 dev environment a PTY is available, so expect PASS).

- [ ] **Step 6: Guard gates 2 and 3**

Run: `cargo clippy -p izba-ttytest --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/izba-ttytest/src/bin/ttyfixture.rs crates/izba-ttytest/src/harness.rs crates/izba-ttytest/tests/harness_smoke.rs
git commit -m "feat(ttytest): TerminalSession PTY/ConPTY harness with smoke test"
```

---

## Task 4: `ScriptedGuest` — sandbox fabrication, listener, handshake, control RPC

**Files:**
- Modify: `crates/izba-ttytest/src/scripted_guest.rs`
- Test: `crates/izba-ttytest/tests/guest_smoke.rs`

This task delivers the guest's control plane: a fabricated live sandbox dir, the Unix-socket listener, the CH hybrid handshake, and the control-port (1025) request loop. The stream port (1026) and the script engine come in Task 5; for now a 1026 connection is accepted and immediately closed.

- [ ] **Step 1: Write the failing smoke test**

`crates/izba-ttytest/tests/guest_smoke.rs`:

```rust
use izba_proto::{read_frame, write_frame, Request, Response, CONTROL_PORT};
use izba_ttytest::scripted_guest::{ExecOutcome, GuestScript, ScriptedGuest};
use izba_proto::ExitStatus;
use std::io::{Read, Write};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

/// Perform the CH hybrid handshake to `port` on the guest's vsock.sock.
fn connect(sock: &std::path::Path, port: u32) -> UnixStream {
    let mut s = UnixStream::connect(sock).expect("connect vsock.sock");
    s.write_all(format!("CONNECT {port}\n").as_bytes()).unwrap();
    // Read the OK line byte-by-byte (matches the host's reader).
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).unwrap();
        assert_ne!(n, 0, "EOF before OK line");
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    assert!(
        String::from_utf8_lossy(&line).starts_with("OK "),
        "handshake not OK: {:?}",
        String::from_utf8_lossy(&line)
    );
    s
}

#[test]
fn answers_handshake_and_health() {
    let script = GuestScript {
        exec_outcome: ExecOutcome::Started,
        initial_emit: Vec::new(),
        on_resize: None,
        end_when_input_contains: None,
        final_status: ExitStatus::Code(0),
    };
    let guest = ScriptedGuest::start(script).expect("start guest");

    let sock = guest.data_dir().join(format!(
        ".local/share/izba/sandboxes/{}/run/vsock.sock",
        guest.sandbox_name()
    ));
    // The exact path is an internal detail; prefer the helper:
    let sock = guest.vsock_path();
    let _ = sock; // silence if unused in your edit

    let mut conn = connect(&guest.vsock_path(), CONTROL_PORT);
    write_frame(&mut conn, &Request::Health).unwrap();
    match read_frame::<_, Response>(&mut conn).unwrap() {
        Response::Health(info) => assert!(!info.version.is_empty()),
        other => panic!("unexpected: {other:?}"),
    }
    drop(conn);
    drop(guest);
    // Give the listener a moment to drop without hanging the test.
    std::thread::sleep(Duration::from_millis(50));
}
```

(When implementing, drop the redundant `sock` lines above; they are illustrative. The real assertion uses `guest.vsock_path()`.)

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test -p izba-ttytest --test guest_smoke`
Expected: FAIL — `ScriptedGuest`/`GuestScript` not found.

- [ ] **Step 3: Implement the guest control plane**

`crates/izba-ttytest/src/scripted_guest.rs`:

```rust
//! A fake "running sandbox" for driving the real `izba` binary with no VM.
//!
//! It fabricates a sandbox state dir whose `state.json` points `vmm_pid` at the
//! current (test) process — alive for the test's duration — so `izba`'s
//! liveness check passes. It then binds the hybrid-vsock Unix socket and speaks
//! the izba wire protocol: a CH-style `CONNECT <port>\n`/`OK\n` handshake per
//! connection, then either the control request loop (port 1025) or the stream
//! script (port 1026, Task 5).

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use izba_proto::{
    read_frame, write_frame, ErrorKind, ExitStatus, HealthInfo, Request, Response, StreamAttach,
    CONTROL_PORT, STREAM_PORT,
};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

/// How the guest answers an `Exec` request.
#[derive(Clone, Copy)]
pub enum ExecOutcome {
    /// Reply `ExecStarted` and run the stream script.
    Started,
    /// Reply `Error { CommandNotFound }` (izba then exits 127, no stream/wait).
    CommandNotFound,
}

/// A scripted guest behaviour. `fn` pointers (not closures) keep it
/// `Send + Sync + 'static` with no boxing.
pub struct GuestScript {
    pub exec_outcome: ExecOutcome,
    /// Bytes emitted to the host as soon as the Tty stream attaches.
    pub initial_emit: Vec<u8>,
    /// If set, emit `f(cols, rows)` whenever a Resize RPC arrives.
    pub on_resize: Option<fn(u16, u16) -> Vec<u8>>,
    /// End the exec when host→guest input contains this byte (e.g. `b'q'`,
    /// `0x03` for Ctrl-C). `None` ends immediately after `initial_emit`.
    pub end_when_input_contains: Option<u8>,
    /// Status returned by the `Wait` RPC once the exec ends.
    pub final_status: ExitStatus,
}

#[derive(Default)]
struct Recorder {
    received_input: Mutex<Vec<u8>>,
    last_resize: Mutex<Option<(u16, u16)>>,
    kills: Mutex<Vec<i32>>,
}

struct Shared {
    script: GuestScript,
    rec: Recorder,
    /// Set to `Some(status)` by the stream thread when the exec ends; `Wait`
    /// blocks on this.
    done: (Mutex<Option<ExitStatus>>, Condvar),
    /// control → stream: resize events to emit.
    resize_tx: Mutex<Option<std::sync::mpsc::Sender<(u16, u16)>>>,
    shutdown: AtomicBool,
}

pub struct ScriptedGuest {
    data_dir_keep: tempfile::TempDir,
    data_root: PathBuf,
    name: String,
    vsock: PathBuf,
    shared: Arc<Shared>,
    _listener: std::thread::JoinHandle<()>,
}

impl ScriptedGuest {
    pub fn start(script: GuestScript) -> Result<Self> {
        let name = "ttytest".to_string();
        let tmp = tempfile::tempdir().context("tempdir")?;
        // The CLI resolves IZBA_DATA_DIR as the data ROOT directly
        // (Paths::with_root), so vsock.sock lives at <root>/sandboxes/<name>/run.
        let data_root = tmp.path().to_path_buf();
        let paths = izba_core::paths::Paths::with_root(data_root.clone());
        let sb = paths.sandbox_dir(&name);
        let run = paths.run_dir(&name);
        std::fs::create_dir_all(&run).context("create run dir")?;

        // Fabricate state.json so liveness passes: vmm_pid = current process.
        let id = izba_core::procmgr::current_identity().context("current identity")?;
        izba_core::state::save_json(
            &sb.join(izba_core::state::STATE_FILE),
            &izba_core::state::RunState {
                vmm_pid: id,
                sidecar_pids: vec![],
                started_unix_ms: 0,
            },
        )
        .context("write state.json")?;

        let vsock = run.join("vsock.sock");
        // On Windows AF_UNIX, a stale path must not exist.
        let _ = std::fs::remove_file(&vsock);
        let listener = UnixListener::bind(&vsock).context("bind vsock.sock")?;

        let shared = Arc::new(Shared {
            script,
            rec: Recorder::default(),
            done: (Mutex::new(None), Condvar::new()),
            resize_tx: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        });

        let shared_l = Arc::clone(&shared);
        let handle = std::thread::spawn(move || accept_loop(listener, shared_l));

        Ok(Self {
            data_dir_keep: tmp,
            data_root,
            name,
            vsock,
            shared,
            _listener: handle,
        })
    }

    /// Pass this to the child as `IZBA_DATA_DIR`.
    pub fn data_dir(&self) -> &Path {
        &self.data_root
    }
    pub fn sandbox_name(&self) -> &str {
        &self.name
    }
    pub fn vsock_path(&self) -> PathBuf {
        self.vsock.clone()
    }
    pub fn received_input(&self) -> Vec<u8> {
        self.shared.rec.received_input.lock().unwrap().clone()
    }
    pub fn last_resize(&self) -> Option<(u16, u16)> {
        *self.shared.rec.last_resize.lock().unwrap()
    }
    pub fn kills(&self) -> Vec<i32> {
        self.shared.rec.kills.lock().unwrap().clone()
    }
}

impl Drop for ScriptedGuest {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        // Nudge the accept loop by connecting once; ignore errors.
        let _ = UnixStream::connect(&self.vsock);
        let _ = &self.data_dir_keep; // keep the tempdir until drop
    }
}

fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    for conn in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        let Ok(conn) = conn else { continue };
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            if let Err(e) = serve_conn(conn, shared) {
                eprintln!("scripted guest conn error: {e:#}");
            }
        });
    }
}

/// Read the `CONNECT <port>\n` line, reply `OK 0\n`, return the port.
fn handshake(conn: &mut UnixStream) -> Result<u32> {
    let mut reader = BufReader::new(conn.try_clone().context("clone for handshake")?);
    let mut line = String::new();
    reader.read_line(&mut line).context("read CONNECT line")?;
    let port: u32 = line
        .trim()
        .strip_prefix("CONNECT ")
        .context("bad CONNECT line")?
        .parse()
        .context("parse port")?;
    conn.write_all(b"OK 0\n").context("write OK")?;
    Ok(port)
}

fn serve_conn(mut conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    let port = handshake(&mut conn)?;
    match port {
        CONTROL_PORT => serve_control(conn, shared),
        STREAM_PORT => serve_stream(conn, shared), // implemented in Task 5
        other => anyhow::bail!("unexpected CONNECT port {other}"),
    }
}

fn serve_control(mut conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    loop {
        let req: Request = match read_frame(&mut conn) {
            Ok(r) => r,
            Err(_) => return Ok(()), // peer closed
        };
        let resp = match req {
            Request::Health => Response::Health(HealthInfo {
                version: "ttytest-guest".to_string(),
                uptime_ms: 0,
            }),
            Request::Exec(_) => match shared.script.exec_outcome {
                ExecOutcome::Started => Response::ExecStarted { exec_id: 1 },
                ExecOutcome::CommandNotFound => Response::Error {
                    kind: ErrorKind::CommandNotFound,
                    message: "ttytest: command not found".to_string(),
                },
            },
            Request::Wait { .. } => {
                let (lock, cvar) = &shared.done;
                let mut guard = lock.lock().unwrap();
                while guard.is_none() {
                    guard = cvar.wait(guard).unwrap();
                }
                Response::Wait {
                    status: guard.unwrap(),
                }
            }
            Request::Kill { signal, .. } => {
                shared.rec.kills.lock().unwrap().push(signal);
                Response::Ok
            }
            Request::Resize { cols, rows, .. } => {
                *shared.rec.last_resize.lock().unwrap() = Some((cols, rows));
                if let Some(tx) = shared.resize_tx.lock().unwrap().as_ref() {
                    let _ = tx.send((cols, rows));
                }
                Response::Ok
            }
            Request::Shutdown => {
                let _ = write_frame(&mut conn, &Response::Ok);
                shared.shutdown.store(true, Ordering::SeqCst);
                return Ok(());
            }
        };
        if write_frame(&mut conn, &resp).is_err() {
            return Ok(());
        }
    }
}

/// Stream port handler — fully implemented in Task 5. For now, accept and close
/// so the control-plane smoke test can run without the stream engine.
fn serve_stream(mut conn: UnixStream, _shared: Arc<Shared>) -> Result<()> {
    let _attach: StreamAttach = match read_frame(&mut conn) {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };
    Ok(())
}
```

Notes for the implementer:
- `Paths::with_root(root)` makes `<root>/sandboxes/<name>/run/vsock.sock` etc. Confirm `run_dir`/`sandbox_dir` join layout against `crates/izba-core/src/paths.rs`; the handshake/smoke test asserts via `guest.vsock_path()` so the literal path string in the test comment can be dropped.
- `UnixListener`/`UnixStream` are `std::os::unix::net` on Unix and `uds_windows` on Windows; both expose `connect`, `bind`, `incoming`, `try_clone`. Keep the `#[cfg]` imports.
- `read_frame`/`write_frame` take `&mut impl Read`/`&mut impl Write`; `UnixStream` implements both.

- [ ] **Step 4: Run the smoke test**

Run: `cargo test -p izba-ttytest --test guest_smoke`
Expected: PASS. (The test binds a real Unix socket. In sandboxes that deny `bind` with `EPERM`, it will error — if so, re-run this single test with `dangerouslyDisableSandbox: true`, mirroring the existing `full_connect_via_listener` runtime-skip rationale in `crates/izba-core/src/vsock.rs`.)

- [ ] **Step 5: Guard gates**

Run: `cargo clippy -p izba-ttytest --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-ttytest/src/scripted_guest.rs crates/izba-ttytest/tests/guest_smoke.rs
git commit -m "feat(ttytest): scripted guest control plane (handshake + RPC)"
```

---

## Task 5: `ScriptedGuest` — stream script engine

Implements `serve_stream`: emit `initial_emit`, continuously record host→guest input, emit `on_resize` frames when resizes arrive, and end the exec when the configured input byte is seen (signalling `Wait`).

**Files:**
- Modify: `crates/izba-ttytest/src/scripted_guest.rs`
- Test: `crates/izba-ttytest/tests/guest_stream.rs`

- [ ] **Step 1: Write the failing test**

`crates/izba-ttytest/tests/guest_stream.rs`:

```rust
use izba_proto::{
    read_frame, write_frame, ExitStatus, Request, Response, StreamAttach, StreamKind,
    CONTROL_PORT, STREAM_PORT,
};
use izba_ttytest::scripted_guest::{ExecOutcome, GuestScript, ScriptedGuest};
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

fn connect(sock: &std::path::Path, port: u32) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(format!("CONNECT {port}\n").as_bytes()).unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK "));
    s
}

#[test]
fn stream_emits_records_input_and_ends() {
    fn resized(cols: u16, rows: u16) -> Vec<u8> {
        format!("RESIZED {cols}x{rows}").into_bytes()
    }
    let script = GuestScript {
        exec_outcome: ExecOutcome::Started,
        initial_emit: b"HELLO-STREAM".to_vec(),
        on_resize: Some(resized),
        end_when_input_contains: Some(b'q'),
        final_status: ExitStatus::Code(7),
    };
    let guest = ScriptedGuest::start(script).unwrap();

    // Open the stream and read the initial emit.
    let mut stream = connect(&guest.vsock_path(), STREAM_PORT);
    write_frame(
        &mut stream,
        &StreamAttach { exec_id: 1, kind: StreamKind::Tty },
    )
    .unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("HELLO-STREAM"));

    // Drive a resize over the control port; expect a RESIZED frame on the stream.
    let mut ctrl = connect(&guest.vsock_path(), CONTROL_PORT);
    write_frame(&mut ctrl, &Request::Resize { exec_id: 1, cols: 90, rows: 20 }).unwrap();
    assert!(matches!(read_frame::<_, Response>(&mut ctrl).unwrap(), Response::Ok));
    let n = stream.read(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("RESIZED 90x20"));
    assert_eq!(guest.last_resize(), Some((90, 20)));

    // Send the end byte; the exec should end and Wait return the final status.
    stream.write_all(b"q").unwrap();
    let status = {
        let mut wait = connect(&guest.vsock_path(), CONTROL_PORT);
        write_frame(&mut wait, &Request::Wait { exec_id: 1 }).unwrap();
        match read_frame::<_, Response>(&mut wait).unwrap() {
            Response::Wait { status } => status,
            other => panic!("unexpected: {other:?}"),
        }
    };
    assert_eq!(status, ExitStatus::Code(7));

    // The input we sent was recorded.
    let recorded = guest.received_input();
    assert!(recorded.contains(&b'q'), "input not recorded: {recorded:?}");
    let _ = Duration::from_millis(0);
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `cargo test -p izba-ttytest --test guest_stream`
Expected: FAIL — the stream currently accepts and closes (no emit/record/end).

- [ ] **Step 3: Implement `serve_stream`**

Replace the placeholder `serve_stream` in `crates/izba-ttytest/src/scripted_guest.rs` with:

```rust
fn serve_stream(conn: UnixStream, shared: Arc<Shared>) -> Result<()> {
    let _attach: StreamAttach = match read_frame(&mut { conn.try_clone()? }) {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };

    // Register the resize channel so control-port Resize RPCs reach us.
    let (tx, rx) = std::sync::mpsc::channel::<(u16, u16)>();
    *shared.resize_tx.lock().unwrap() = Some(tx);

    // Reader thread: record everything the host sends.
    let mut reader = conn.try_clone().context("clone stream reader")?;
    let rec_shared = Arc::clone(&shared);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => rec_shared
                    .rec
                    .received_input
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..n]),
            }
        }
    });

    // Writer side: initial emit, then react to resizes until the end byte.
    let mut writer = conn;
    writer
        .write_all(&shared.script.initial_emit)
        .context("initial emit")?;
    writer.flush().ok();

    let end_byte = shared.script.end_when_input_contains;
    loop {
        // Emit any pending resize frames.
        while let Ok((cols, rows)) = rx.try_recv() {
            if let Some(f) = shared.script.on_resize {
                let bytes = f(cols, rows);
                let _ = writer.write_all(&bytes);
                let _ = writer.flush();
            }
        }
        // End condition.
        let ended = match end_byte {
            None => true, // end immediately after initial emit
            Some(b) => shared.rec.received_input.lock().unwrap().contains(&b),
        };
        if ended || shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Signal Wait and tear down.
    {
        let (lock, cvar) = &shared.done;
        *lock.lock().unwrap() = Some(shared.script.final_status);
        cvar.notify_all();
    }
    *shared.resize_tx.lock().unwrap() = None;
    drop(writer);
    let _ = reader_thread.join();
    Ok(())
}
```

Notes:
- `read_frame(&mut { conn.try_clone()? })` reads the attach frame from a clone so the original `conn` keeps its full byte stream for the reader/writer split. Confirm `UnixStream::try_clone()` exists on both `std` and `uds_windows` (it does); both clones share the underlying socket.
- When `end_when_input_contains` is `None`, the exec ends right after `initial_emit` (used by the exit-code scenarios). With `Some(byte)`, it ends when the host sends that byte (used by vim/arrow/Ctrl-C scenarios).

- [ ] **Step 4: Run the test**

Run: `cargo test -p izba-ttytest --test guest_stream`
Expected: PASS.

- [ ] **Step 5: Guard gates**

Run: `cargo clippy -p izba-ttytest --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-ttytest/src/scripted_guest.rs crates/izba-ttytest/tests/guest_stream.rs
git commit -m "feat(ttytest): scripted guest stream engine (emit/record/resize/end)"
```

---

## Task 6: Checklist scenarios

Encodes each checklist item as a reusable `Scenario` (the guest command argv + the `GuestScript`). Assertions live in the Tier-1 test (Task 7), which differs per item.

**Files:**
- Modify: `crates/izba-ttytest/src/scenarios.rs`
- Test: `crates/izba-ttytest/src/scenarios.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Add to `crates/izba-ttytest/src/scenarios.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::ExitStatus;

    #[test]
    fn vim_scenario_emits_probe_byte() {
        let s = vim_redraw();
        assert!(s.script.initial_emit.contains(&0xbd), "must carry the t_u7 probe byte");
        assert!(s.script.on_resize.is_some());
    }

    #[test]
    fn exit_code_scenario_carries_status() {
        let s = exit_code(42);
        assert_eq!(s.script.final_status, ExitStatus::Code(42));
        assert!(s.script.end_when_input_contains.is_none());
    }
}
```

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test -p izba-ttytest --lib scenarios`
Expected: FAIL — `vim_redraw`/`exit_code` not found.

- [ ] **Step 3: Implement the scenarios**

Prepend to `crates/izba-ttytest/src/scenarios.rs` (above the test module):

```rust
//! The `exec -it` operator checklist, encoded as reusable scenarios.

use crate::scripted_guest::{ExecOutcome, GuestScript};
use izba_proto::ExitStatus;

/// One checklist scenario: what command izba runs in the guest, plus the
/// scripted guest behaviour. Per-item assertions live in the test tier.
pub struct Scenario {
    pub name: &'static str,
    /// The guest command (the part after `--` in `izba exec -it <name> -- ...`).
    pub argv: Vec<String>,
    pub script: GuestScript,
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// vim's startup redraw, abbreviated, ending with the raw `0xbd` t_u7
/// ambiguous-width probe byte and a post-probe line. Asserting the post-probe
/// line renders is the regression guard for the Windows console byte bug.
fn vim_initial() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\x1b[2J\x1b[1;1Hline-before-probe\r\n");
    v.extend_from_slice(b"\x1b[2;1Hwidth-probe -> ");
    v.push(0xbd);
    v.extend_from_slice(b"\x1b[3;1Hline-AFTER-probe\r\n");
    v
}

fn vim_resized(cols: u16, rows: u16) -> Vec<u8> {
    format!("\x1b[2J\x1b[1;1Hresized to {cols}x{rows}\r\n").into_bytes()
}

/// vim renders fullscreen (incl. the probe byte) and repaints on resize.
pub fn vim_redraw() -> Scenario {
    Scenario {
        name: "vim_redraw",
        argv: argv(&["vi", "/workspace/x"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: vim_initial(),
            on_resize: Some(vim_resized),
            end_when_input_contains: Some(b'q'),
            final_status: ExitStatus::Code(0),
        },
    }
}

/// A shell prompt is shown and VT input (arrow keys) is delivered to the guest.
pub fn arrow_keys() -> Scenario {
    Scenario {
        name: "arrow_keys",
        argv: argv(&["/bin/sh", "-l"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: b"sh-prompt$ ".to_vec(),
            on_resize: None,
            end_when_input_contains: Some(b'q'),
            final_status: ExitStatus::Code(0),
        },
    }
}

/// Ctrl-C (0x03) reaches the guest and ends the exec via a signal; izba itself
/// must survive. The final status `Signal(2)` maps to CLI exit `130`.
pub fn ctrl_c() -> Scenario {
    Scenario {
        name: "ctrl_c",
        argv: argv(&["sleep", "100"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: b"sleeping...".to_vec(),
            on_resize: None,
            end_when_input_contains: Some(0x03),
            final_status: ExitStatus::Signal(2),
        },
    }
}

/// Exit code passthrough: the guest exits with `code`, izba returns it.
pub fn exit_code(code: i32) -> Scenario {
    Scenario {
        name: "exit_code",
        argv: argv(&["true"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: Vec::new(),
            on_resize: None,
            end_when_input_contains: None,
            final_status: ExitStatus::Code(code),
        },
    }
}

/// Command-not-found maps to CLI exit 127 (no stream/wait).
pub fn command_not_found() -> Scenario {
    Scenario {
        name: "command_not_found",
        argv: argv(&["definitely-not-a-real-binary"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::CommandNotFound,
            initial_emit: Vec::new(),
            on_resize: None,
            end_when_input_contains: None,
            final_status: ExitStatus::Code(0),
        },
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p izba-ttytest --lib scenarios`
Expected: PASS.

- [ ] **Step 5: Guard gates**

Run: `cargo clippy -p izba-ttytest --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-ttytest/src/scenarios.rs
git commit -m "feat(ttytest): encode the exec -it checklist as scenarios"
```

---

## Task 7: Tier 1 — scripted-guest cargo tests (real `izba` binary, no VM)

Drives the compiled `izba exec -it` through the harness against the scripted guest. Behind the opt-in `ttytests` feature so the standard gates don't build it.

**Files:**
- Modify: `crates/izba-cli/Cargo.toml` (dev-dep + feature + `[[test]]`)
- Create: `crates/izba-cli/tests/tty_scripted.rs`

- [ ] **Step 1: Wire the dev-dependency, feature, and gated test target**

In `crates/izba-cli/Cargo.toml` add:

```toml
[features]
# Opt-in: builds the PTY/ConPTY terminal tests (pulls portable-pty/vt100 via the
# izba-ttytest dev-dependency). Kept off by default so the six standard build
# gates never cross-compile the harness.
ttytests = []

[dev-dependencies]
izba-ttytest = { path = "../izba-ttytest" }
izba-proto = { path = "../izba-proto" }
portable-pty = "0.9"
anyhow = { workspace = true }

[[test]]
name = "tty_scripted"
required-features = ["ttytests"]

[[test]]
name = "tty_e2e"
required-features = ["ttytests"]
```

(If `izba-cli` already lists some of these dev-deps, merge rather than duplicate. The `tty_e2e` target is declared now and its file is created in Task 8; cargo tolerates the `[[test]]` entry only when the feature is off — but to keep `--features ttytests` building between Task 7 and Task 8, create a one-line placeholder `crates/izba-cli/tests/tty_e2e.rs` containing `fn main() {}`-free content: just `#[test] fn placeholder() {}`. Task 8 replaces it.)

- [ ] **Step 2: Write the Tier-1 test**

`crates/izba-cli/tests/tty_scripted.rs`:

```rust
//! Tier 1: drive the real `izba exec -it` binary through a PTY/ConPTY against a
//! scripted fake guest — no VM. Self-skips where a PTY cannot be allocated.

use izba_ttytest::harness::TerminalSession;
use izba_ttytest::scenarios::{self, Scenario};
use izba_ttytest::scripted_guest::ScriptedGuest;
use portable_pty::CommandBuilder;
use std::time::Duration;

/// Build `izba exec -it <name> -- <argv...>` pointed at the guest's data root.
fn izba_exec_cmd(guest: &ScriptedGuest, argv: &[String]) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
    cmd.arg("exec");
    cmd.arg("-it");
    cmd.arg(guest.sandbox_name());
    cmd.arg("--");
    for a in argv {
        cmd.arg(a);
    }
    cmd.env("IZBA_DATA_DIR", guest.data_dir());
    cmd.env("TERM", "xterm-256color");
    cmd
}

/// Spawn the session, self-skipping if no PTY is available here.
fn session_or_skip(guest: &ScriptedGuest, sc: &Scenario) -> Option<TerminalSession> {
    let cmd = izba_exec_cmd(guest, &sc.argv);
    match TerminalSession::spawn(cmd, 80, 24) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("SKIP {}: cannot allocate a PTY here: {e:#}", sc.name);
            None
        }
    }
}

const T: Duration = Duration::from_secs(10);

#[test]
fn vim_renders_through_the_probe_byte() {
    let sc = scenarios::vim_redraw();
    let guest = ScriptedGuest::start(scenarios::vim_redraw().script).unwrap();
    let Some(mut sess) = session_or_skip(&guest, &sc) else { return };

    // The line AFTER the 0xbd probe must render — this is the bug we fixed.
    sess.wait_for_text("line-AFTER-probe", T).expect("post-probe line");

    // Resize and confirm the guest saw it and repainted.
    sess.resize(90, 20).unwrap();
    sess.wait_for_text("resized to 90x20", T).expect("repaint");
    // (>200ms passes inside wait_for_text, covering the Windows polling watcher.)

    sess.send_keys("q").unwrap();
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(0));
    assert_eq!(guest.last_resize(), Some((90, 20)));
}

#[test]
fn arrow_keys_reach_the_guest() {
    let sc = scenarios::arrow_keys();
    let guest = ScriptedGuest::start(scenarios::arrow_keys().script).unwrap();
    let Some(mut sess) = session_or_skip(&guest, &sc) else { return };

    sess.wait_for_text("sh-prompt$", T).expect("prompt");
    sess.send_bytes(b"\x1b[A\x1b[B").unwrap(); // up, down
    sess.send_keys("q").unwrap();
    sess.wait_exit(T).expect("exit");

    let got = guest.received_input();
    assert!(
        got.windows(3).any(|w| w == b"\x1b[A"),
        "up-arrow not delivered: {got:?}"
    );
}

#[test]
fn ctrl_c_ends_exec_without_killing_izba() {
    let sc = scenarios::ctrl_c();
    let guest = ScriptedGuest::start(scenarios::ctrl_c().script).unwrap();
    let Some(mut sess) = session_or_skip(&guest, &sc) else { return };

    sess.wait_for_text("sleeping...", T).expect("running");
    assert!(sess.is_child_alive(), "izba must still be alive before Ctrl-C");
    sess.send_bytes(&[0x03]).unwrap(); // Ctrl-C

    let out = sess.wait_exit(T).expect("exit");
    // ExitStatus::Signal(2) -> CLI exit 128 + 2 = 130.
    assert_eq!(out.code, Some(130));
    assert!(guest.received_input().contains(&0x03));
}

#[test]
fn exit_code_passthrough() {
    let sc = scenarios::exit_code(42);
    let guest = ScriptedGuest::start(scenarios::exit_code(42).script).unwrap();
    let Some(mut sess) = session_or_skip(&guest, &sc) else { return };
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(42));
}

#[test]
fn command_not_found_is_127() {
    let sc = scenarios::command_not_found();
    let guest = ScriptedGuest::start(scenarios::command_not_found().script).unwrap();
    let Some(mut sess) = session_or_skip(&guest, &sc) else { return };
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(127));
}
```

Note: `Scenario` is consumed twice (once for `argv`, once for `script`) by calling the builder twice, because `GuestScript` is moved into the guest. That is intentional and cheap.

- [ ] **Step 3: Run it to confirm it fails first, then passes**

Run: `cargo test -p izba-cli --features ttytests --test tty_scripted`
Expected first run (before the binary builds cleanly or if a method is off): FAIL with a concrete error. Iterate until PASS. The test depends on the `izba` binary, which `cargo test -p izba-cli` builds automatically.

Important: if the guest's `UnixListener::bind` is denied (`EPERM`) in the command sandbox, run this with `dangerouslyDisableSandbox: true`. The `izba` child itself does not need KVM here — there is no VM.

- [ ] **Step 4: Verify the standard gates ignore the new test**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean, and it does NOT build `tty_scripted`/`tty_e2e` (they require the `ttytests` feature). Confirm by noting no `portable-pty` compilation in the output.

- [ ] **Step 5: fmt**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-cli/Cargo.toml crates/izba-cli/tests/tty_scripted.rs crates/izba-cli/tests/tty_e2e.rs Cargo.lock
git commit -m "test(cli): Tier 1 scripted-guest exec -it terminal tests"
```

---

## Task 8: Tier 2 — real-sandbox end-to-end cargo tests (env-gated)

Drives the real `izba` CLI for the full lifecycle (create → run/start → exec -it → rm) against a real VM, under the harness. Env-gated like the existing integration suite; compiles and self-skips everywhere, runs fully only on a KVM host (Linux) or the OpenVMM spike host (Windows).

**Files:**
- Replace: `crates/izba-cli/tests/tty_e2e.rs` (placeholder from Task 7)

- [ ] **Step 1: Implement the env-gated e2e test**

`crates/izba-cli/tests/tty_e2e.rs`:

```rust
//! Tier 2: drive the real `izba exec -it` against a real sandbox end-to-end.
//! Env-gated (`IZBA_TTY_E2E=1` plus real artifacts/VMM); self-skips otherwise.
//! Full runs happen on a KVM host or the OpenVMM spike host.

use izba_ttytest::harness::TerminalSession;
use portable_pty::CommandBuilder;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

struct E2eEnv {
    data_dir: PathBuf,
    image: String,
}

/// Returns `Some(env)` only when explicitly enabled and the required inputs are
/// present; prints SKIP and returns `None` otherwise.
fn want() -> Option<E2eEnv> {
    if std::env::var("IZBA_TTY_E2E").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set IZBA_TTY_E2E=1 (plus a working izba host) to run Tier 2");
        return None;
    }
    let data_dir = std::env::var_os("IZBA_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("izba-tty-e2e"));
    let image = std::env::var("IZBA_TTY_E2E_IMAGE").unwrap_or_else(|_| "alpine:3.20".to_string());
    Some(E2eEnv { data_dir, image })
}

fn izba() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_izba"));
    c.env("IZBA_DATA_DIR", std::env::var_os("IZBA_DATA_DIR").unwrap_or_default());
    c
}

const T: Duration = Duration::from_secs(30);

#[test]
fn vim_and_exit_code_end_to_end() {
    let Some(env) = want() else { return };
    let name = "ttye2e";
    // Point everything at one data dir.
    std::env::set_var("IZBA_DATA_DIR", &env.data_dir);

    // Create + start a sandbox with a throwaway workspace.
    let ws = std::env::temp_dir().join("izba-tty-e2e-ws");
    std::fs::create_dir_all(&ws).unwrap();
    let _ = izba().args(["rm", "--force", name]).status();
    let st = izba()
        .args(["create", "--image", &env.image])
        .arg(&ws)
        .args(["--name", name]) // if `create` takes a positional name instead,
        .status() // adjust to the real CLI surface during implementation.
        .expect("izba create");
    assert!(st.success(), "create failed");
    let st = izba().args(["run", name]).status();
    // `run` may attach a shell; for e2e we instead start then exec. If `run`
    // blocks, replace with the real start path. Confirm against `izba --help`.
    let _ = st;

    // Exit-code passthrough end to end.
    {
        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
        cmd.args(["exec", "-it", name, "--", "sh", "-c", "exit 42"]);
        cmd.env("IZBA_DATA_DIR", &env.data_dir);
        cmd.env("TERM", "xterm-256color");
        let mut sess = TerminalSession::spawn(cmd, 80, 24).expect("pty");
        assert_eq!(sess.wait_exit(T).unwrap().code, Some(42));
    }

    // vim renders through the probe byte on a real guest PTY (needs vim/vi in
    // the image; alpine has busybox vi).
    {
        std::fs::write(ws.join("x"), b"hello e2e\n").unwrap();
        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
        cmd.args(["exec", "-it", name, "--", "vi", "/workspace/x"]);
        cmd.env("IZBA_DATA_DIR", &env.data_dir);
        cmd.env("TERM", "xterm-256color");
        let mut sess = TerminalSession::spawn(cmd, 80, 24).expect("pty");
        sess.wait_for_text("hello e2e", T).expect("vi rendered file");
        sess.resize(100, 30).unwrap();
        sess.wait_stable(Duration::from_millis(300), T).ok();
        sess.send_keys("\x1b").unwrap(); // ESC
        sess.send_keys(":q!\r").unwrap();
        let _ = sess.wait_exit(T);
    }

    let _ = izba().args(["rm", "--force", name]).status();
}
```

The exact `create`/`run`/`start`/`rm` flags must be confirmed against the real CLI (`izba --help`, `crates/izba-cli/src/commands/`) during implementation — the structure above is correct but the precise subcommand surface (e.g. whether the sandbox name is positional vs `--name`, whether `run` blocks) must match. Adjust the lifecycle calls to the real surface; keep the harness usage identical.

- [ ] **Step 2: Confirm it compiles and self-skips**

Run: `cargo test -p izba-cli --features ttytests --test tty_e2e`
Expected: builds and prints `SKIP: set IZBA_TTY_E2E=1 ...`, test passes (no-op). (Full execution requires a real VM and is run on the KVM/spike host: `IZBA_TTY_E2E=1 IZBA_DATA_DIR=... cargo test -p izba-cli --features ttytests --test tty_e2e -- --test-threads=1`.)

- [ ] **Step 3: Guard the standard gates again**

Run: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`.
Expected: clean; the e2e target is not built without the feature.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-cli/tests/tty_e2e.rs
git commit -m "test(cli): Tier 2 env-gated real-sandbox exec -it terminal tests"
```

---

## Task 9: Run all gates, document, and record

**Files:**
- Modify: `docs/testing.md` (how to run the harness)
- Modify: `README.md` (crate list) and `CLAUDE.md` (crate map)
- Modify: the memory index + project-state note (see final step)

- [ ] **Step 1: Run all six build gates**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all six green. The cross gates (5,6) must NOT attempt to build `portable-pty`/`vt100` (the `ttytests`-gated test targets are excluded). If gate 6 fails because it still pulls the harness dev-deps, verify the `required-features` are set on BOTH `[[test]]` entries and that `izba-ttytest` is only referenced from those two test files.

- [ ] **Step 2: Run the harness once for real (Tier 1)**

```bash
cargo test -p izba-cli --features ttytests --test tty_scripted
```
Expected: PASS on Linux (or self-SKIP if no PTY). Use `dangerouslyDisableSandbox: true` if `bind` is denied. This is the command the operator/agent runs instead of the manual checklist.

- [ ] **Step 3: Document the runbook**

Append to `docs/testing.md` a short section:

```markdown
## exec -it terminal harness

Automated replacement for the manual `exec -it` operator checklist
(`crates/izba-ttytest`, design: docs/superpowers/specs/2026-06-11-izba-tty-test-harness-design.md).

- **Tier 1 (no VM, both OSes, CI):** drives the real `izba` binary through a
  PTY/ConPTY against a scripted fake guest.
  `cargo test -p izba-cli --features ttytests --test tty_scripted`
  Self-skips where a PTY cannot be allocated.
- **Tier 2 (real sandbox, gated):** full end-to-end against KVM (Linux) or the
  OpenVMM spike host (Windows).
  `IZBA_TTY_E2E=1 IZBA_DATA_DIR=<dir> cargo test -p izba-cli --features ttytests --test tty_e2e -- --test-threads=1`

The harness is feature-gated (`ttytests`, off by default) so the six standard
build gates do not cross-compile `portable-pty`/`vt100`.
```

- [ ] **Step 4: Update the crate lists**

- `README.md` "Project layout": add `izba-ttytest/  # dev-support: PTY/ConPTY harness for exec -it tests` under `crates/`.
- `CLAUDE.md` "Crate map": add a bullet:
  `- `izba-ttytest` — dev/test-support: drives the real `izba` binary through a PTY/ConPTY (portable-pty + vt100) against a scripted fake guest or a real sandbox; the automated `exec -it` checklist. Behind the `ttytests` feature on `izba-cli`.`

- [ ] **Step 5: Commit docs**

```bash
git add docs/testing.md README.md CLAUDE.md
git commit -m "docs: document the exec -it TTY test harness"
```

- [ ] **Step 6: Update memory**

Update `/home/kolkhovskiy/.claude/projects/-home-kolkhovskiy-git-izba/memory/izba-project-state.md`: add a short paragraph that the manual `exec -it` checklist (Plan 2 Task 5) is now automated by `crates/izba-ttytest` (Tier 1 scripted-guest CI tests, both OSes, incl. the vim-0xbd regression guard; Tier 2 env-gated real-sandbox), feature-gated `ttytests`, and refresh the `MEMORY.md` one-line hook accordingly. Keep it factual and dated 2026-06-11.

---

## Self-Review (author)

- **Spec coverage:** §3 tooling → Tasks 2-3; §4.1 `TerminalSession` → Task 3; §4.1 `ScriptedGuest`/`GuestScript`/`RunningGuest` → Tasks 4-5 (model simplified to `end_when_input_contains` + `on_resize` fn-pointer, which covers every checklist item — `EmitBytes`/`ExpectInput`/`OnResizeEmit`/`EndWith` collapse into these fields); §4.1 `scenarios` → Task 6; §4.2 Tier 1 → Task 7; §4.3 Tier 2 → Task 8; §4.4 data-root redirection → grounded as `IZBA_DATA_DIR`, no code change; §5 checklist mapping → Task 7 (Tier 1) + Task 8 (Tier 2); §3.1 ConPTY quiescence (`wait_stable`) → Task 3 + used in Task 8; liveness fakery → Task 1 (`current_identity`) + Task 4. The only spec element intentionally narrowed: Tier-1 console-mode-restore assertion is left to Tier 2 (spec §5 already marks it best-effort/Tier-2); Tier 1 asserts clean exit instead.
- **Placeholder scan:** no TBD/TODO; every code step carries complete code. Two spots require confirming an external API against the resolved crate version (vt100/portable-pty method names in Task 3) and the real CLI subcommand surface (Task 8) — both are flagged explicitly with what to verify, not left vague.
- **Type consistency:** `GuestScript` fields (`exec_outcome`, `initial_emit`, `on_resize`, `end_when_input_contains`, `final_status`) are identical across Tasks 4, 5, 6, 7. `TerminalSession` method signatures are fixed in Task 3 and used unchanged in 7-8. `ExecOutcome::{Started, CommandNotFound}`, `ExitStatus::{Code, Signal}`, `Response`/`Request` variants match `crates/izba-proto/src/messages.rs` verbatim.
```
