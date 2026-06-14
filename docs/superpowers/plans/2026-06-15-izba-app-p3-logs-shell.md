# izba desktop app — P3: Logs viewer + interactive shell (xterm.js) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a **Logs** tab (live-tailing the sandbox console output) and a **Shell** tab (an interactive PTY into the guest via xterm.js) to the izba Tauri desktop app's sandbox detail view.

**Architecture:** Extend the existing `DaemonApi` trait seam (RealDaemon + FakeDaemon) with `read_logs` (one-shot disk read of `console.log`) and `open_shell` (returns a `ShellSession` handle backed by the same `Exec(tty)` + `StreamOpen::Attach{Tty}` path the CLI uses). The Tauri layer stores live shells in `AppState`, pumps guest output to the frontend over `shell-output` events (base64), and forwards keystrokes/resizes back. The frontend gets a tabbed Detail view; the Logs tab polls `read_logs`, the Shell tab drives an xterm.js terminal.

**Tech Stack:** Rust (Tauri 2, izba-core, izba-proto, base64), TypeScript/React, `@xterm/xterm` + `@xterm/addon-fit`, vitest, cargo test.

**Testing reality (read first):** App CI (`.github/workflows/app.yml`) runs frontend (`npm run build` = tsc+vite, `vitest`) + backend (`cargo fmt`/`clippy -D warnings`/`test` on `app/src-tauri`). There is **no real VM** in CI, so the real shell/logs datapath is exercised only by the `FakeDaemon`/`FakeShell` seam in unit tests and by manual validation against a live sandbox (same bar P2 met). Every task must keep all of: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (run inside `app/src-tauri`), and `npm run build` + `npm test` (run inside `app/`) green.

**Toolchain setup (worktree quirk — run before any cargo command):**
```sh
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH="$CARGO_HOME/bin:$PATH"
```
`cargo` (crates.io fetch for the new `base64` dep) and `npm install` (read-only npm cache in the sandbox → EROFS) may need the Bash sandbox disabled. The Tauri Linux system libs are already installed.

**Key facts established by exploration (do not re-derive):**
- Console output file: `paths.logs_dir(name).join("console.log")` — `Paths::logs_dir(&self, name: &str) -> PathBuf` (`crates/izba-core/src/paths.rs:47`). Plain UTF-8-ish text written by the VMM; may be absent for a never-booted sandbox.
- Interactive exec host sequence (mirrors `crates/izba-cli/src/commands/exec.rs`):
  1. `DaemonClient::connect_spawning_izba(&paths)` → control client; `client.guest_rpc(name, &Request::Exec(ExecRequest{ argv, env, cwd, tty:true, uid:0, gid:0 }))` → `Response::ExecStarted { exec_id }`.
  2. `DaemonClient::open_guest_stream(&paths, name)` → `UdsStream`; `write_frame(&mut stream, &StreamOpen::Attach(StreamAttach{ exec_id, kind: StreamKind::Tty }))`.
  3. `stream.try_clone()` → read half; spawn a thread reading raw bytes; the original half is the write (stdin) half.
  4. Resize: `control.guest_rpc(name, &Request::Resize{ exec_id, cols, rows })` → `Response::Ok`. Kill: `Request::Kill{ exec_id, signal: 15 }` → `Response::Ok`.
  5. Guest half-closes the stream when the child exits → reader `read()` returns 0.
- `ExecRequest { argv: Vec<String>, env: Vec<(String,String)>, cwd: String, tty: bool, uid: u32, gid: u32 }` (`crates/izba-proto/src/messages.rs:4`).
- `UdsStream = std::os::unix::net::UnixStream` (Unix) / `uds_windows::UnixStream` (Windows); both have `try_clone()` and `shutdown(Shutdown)` and are `Send` (`crates/izba-core/src/vmm/mod.rs:24`).
- M1 carry-forward: streams must use their OWN connection, never the shared polling `Mutex<DaemonClient>`. `open_shell` therefore creates fresh control + stream connections internally.

---

## File structure

**Backend (`app/src-tauri/`):**
- `Cargo.toml` — add `base64 = "0.22"`.
- `src/daemon.rs` — `ShellSession` trait; `DaemonApi::read_logs` + `DaemonApi::open_shell`; `RealDaemon` impls; private `RealShell`.
- `src/fake.rs` — `FakeShell`; `FakeDaemon` fields + `read_logs`/`open_shell` impls + tests.
- `src/commands.rs` — `read_logs_core` + test.
- `src/lib.rs` — `AppState.shells`; `read_logs`, `shell_open`, `shell_write`, `shell_resize`, `shell_close` commands; event payload structs; handler registration.

**Frontend (`app/`):**
- `package.json` / `package-lock.json` — add `@xterm/xterm`, `@xterm/addon-fit`.
- `src/test/setup.ts` — add a `ResizeObserver` stub for jsdom.
- `src/lib/types.ts` — `ShellOutputPayload`, `ShellExitPayload`.
- `src/lib/ipc.ts` — `readLogs`, `shellOpen`, `shellWrite`, `shellResize`, `shellClose`, `onShellOutput`, `onShellExit`, `b64ToBytes`.
- `src/components/Detail.tsx` — tabbed (Overview / Logs / Shell); Overview keeps P2 content.
- `src/components/LogsView.tsx` (create) + `src/test/logsView.test.tsx`.
- `src/components/ShellView.tsx` (create) + `src/test/shellView.test.tsx`.
- `src/test/detail.test.tsx` — extend for tab behavior (mock LogsView/ShellView).
- `src/test/ipc.test.ts` — extend for the new wrappers.

---

## Task 1: Backend — `read_logs` on the DaemonApi seam

**Files:**
- Modify: `app/src-tauri/src/daemon.rs` (trait + RealDaemon impl)
- Modify: `app/src-tauri/src/fake.rs` (field + impl + test)
- Modify: `app/src-tauri/src/commands.rs` (`read_logs_core` + test)

- [ ] **Step 1: Add the failing FakeDaemon test + field.**

In `app/src-tauri/src/fake.rs`, add a `logs` field to `FakeDaemon` (after `progress`):
```rust
    pub progress: Vec<String>,
    /// Canned console output returned by `read_logs`.
    pub logs: String,
```
In `Default`, after `progress: vec![...]`:
```rust
            progress: vec!["pulling image".into(), "booting".into()],
            logs: "boot ok\nlogin:\n".into(),
```
Add to the `impl DaemonApi for FakeDaemon` block:
```rust
    fn read_logs(&mut self, _name: &str) -> anyhow::Result<String> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(self.logs.clone())
    }
```
Add to the `tests` module in `fake.rs`:
```rust
    #[test]
    fn fake_read_logs_returns_canned_text() {
        let mut d = FakeDaemon::default();
        let logs = d.read_logs("web").unwrap();
        assert!(logs.contains("boot"), "got: {logs}");
    }
```

- [ ] **Step 2: Add the trait method (will fail to compile until RealDaemon implements it).**

In `app/src-tauri/src/daemon.rs`, add to `pub trait DaemonApi: Send`:
```rust
    /// Read the sandbox's captured console output (`logs/console.log`).
    /// Returns an empty string if the file does not exist yet.
    fn read_logs(&mut self, name: &str) -> anyhow::Result<String>;
```

- [ ] **Step 3: Implement on RealDaemon.**

In `app/src-tauri/src/daemon.rs`, add to `impl DaemonApi for RealDaemon`:
```rust
    fn read_logs(&mut self, name: &str) -> anyhow::Result<String> {
        let path = self.paths.logs_dir(name).join("console.log");
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }
```

- [ ] **Step 4: Add `read_logs_core` + test in commands.rs.**

In `app/src-tauri/src/commands.rs`, after `status_core`:
```rust
/// Core of the `read_logs` command.
pub fn read_logs_core(d: &mut dyn DaemonApi, name: &str) -> Result<String, String> {
    d.read_logs(name).map_err(|e| e.to_string())
}
```
Add to the `tests` module:
```rust
    #[test]
    fn read_logs_core_returns_text() {
        let mut d = FakeDaemon::default();
        let t = read_logs_core(&mut d, "web").unwrap();
        assert!(t.contains("boot"), "got: {t}");
    }
```

- [ ] **Step 5: Gate.**

Run (from repo root, after the toolchain exports):
```sh
cargo test --manifest-path app/src-tauri/Cargo.toml
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
```
Expected: all green; new tests pass.

- [ ] **Step 6: Commit.**
```sh
git add app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs app/src-tauri/src/commands.rs
git commit -m "feat(app): read_logs on the DaemonApi seam

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Backend — `ShellSession` + `open_shell` on the DaemonApi seam

**Files:**
- Modify: `app/src-tauri/Cargo.toml` (add `base64`)
- Modify: `app/src-tauri/src/daemon.rs` (`ShellSession` trait, `open_shell` trait method, `RealDaemon` impl, `RealShell`, imports)
- Modify: `app/src-tauri/src/fake.rs` (`FakeShell`, fields, `open_shell` impl, tests)

- [ ] **Step 1: Add the `base64` dependency.**

In `app/src-tauri/Cargo.toml`, under `[dependencies]`, add:
```toml
base64 = "0.22"
```
(`base64` is only used by `lib.rs` in Task 3, but adding it here keeps the dependency commit with the seam work. Run `cargo build --manifest-path app/src-tauri/Cargo.toml` once — may need the Bash sandbox disabled for the crates.io fetch — to regenerate `Cargo.lock`; commit the lock in Step 6.)

- [ ] **Step 2: Add the failing FakeShell test + fields.**

In `app/src-tauri/src/fake.rs`, at the top add:
```rust
use std::sync::{Arc, Mutex};
```
Add a `FakeShell` type (after the `use` lines, before `FakeDaemon`):
```rust
/// Scripted `ShellSession` for unit tests. Records writes/resizes/close and
/// echoes every write back through `on_output`, so the output-event wiring is
/// observable without a real PTY.
pub struct FakeShell {
    pub writes: Arc<Mutex<Vec<Vec<u8>>>>,
    pub resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    pub closed: Arc<Mutex<bool>>,
    on_output: Box<dyn FnMut(Vec<u8>) + Send>,
}

impl crate::daemon::ShellSession for FakeShell {
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.writes.lock().unwrap().push(data.to_vec());
        (self.on_output)(data.to_vec());
        Ok(())
    }
    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()> {
        self.resizes.lock().unwrap().push((cols, rows));
        Ok(())
    }
    fn close(&mut self) -> anyhow::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}
```
Add inspection fields to `FakeDaemon` (after `logs`):
```rust
    pub logs: String,
    pub shell_writes: Arc<Mutex<Vec<Vec<u8>>>>,
    pub shell_resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    pub shell_closed: Arc<Mutex<bool>>,
```
In `Default`, after `logs: ...`:
```rust
            logs: "boot ok\nlogin:\n".into(),
            shell_writes: Arc::new(Mutex::new(Vec::new())),
            shell_resizes: Arc::new(Mutex::new(Vec::new())),
            shell_closed: Arc::new(Mutex::new(false)),
```
Update the `use` at the top of `fake.rs` so `ShellSession` resolves (either reference it via `crate::daemon::ShellSession` as above, or add it to the existing `use crate::daemon::DaemonApi;` → `use crate::daemon::{DaemonApi, ShellSession};`). Add the `open_shell` impl to `impl DaemonApi for FakeDaemon`:
```rust
    fn open_shell(
        &mut self,
        _name: &str,
        mut on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        _on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        on_output(b"$ ".to_vec()); // canned prompt banner
        Ok(Box::new(FakeShell {
            writes: self.shell_writes.clone(),
            resizes: self.shell_resizes.clone(),
            closed: self.shell_closed.clone(),
            on_output,
        }))
    }
```
Add tests to the `tests` module in `fake.rs`:
```rust
    #[test]
    fn fake_shell_echoes_and_records() {
        let mut d = FakeDaemon::default();
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let out2 = out.clone();
        let mut s = d
            .open_shell(
                "web",
                Box::new(move |b| out2.lock().unwrap().extend_from_slice(&b)),
                Box::new(|| {}),
            )
            .unwrap();
        s.write(b"ls\n").unwrap();
        s.resize(100, 40).unwrap();
        s.close().unwrap();
        assert_eq!(&d.shell_writes.lock().unwrap()[..], &[b"ls\n".to_vec()]);
        assert_eq!(d.shell_resizes.lock().unwrap()[0], (100, 40));
        assert!(*d.shell_closed.lock().unwrap());
        assert_eq!(&*out.lock().unwrap(), b"$ ls\n"); // banner + echo
    }

    #[test]
    fn fake_open_shell_surfaces_failure() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        let r = d.open_shell("web", Box::new(|_| {}), Box::new(|| {}));
        assert!(r.is_err());
    }
```

- [ ] **Step 3: Add the `ShellSession` trait + `open_shell` trait method.**

In `app/src-tauri/src/daemon.rs`, add near the top (after the `use` lines):
```rust
/// A live interactive shell stream into a guest. Implementations own their own
/// daemon connections (never the shared polling client).
pub trait ShellSession: Send {
    /// Write user keystrokes to the guest PTY.
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()>;
    /// Resize the guest PTY.
    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()>;
    /// Kill the shell process and tear the stream down.
    fn close(&mut self) -> anyhow::Result<()>;
}
```
Add to `pub trait DaemonApi: Send`:
```rust
    /// Open an interactive shell into `name`. `on_output` is invoked from a
    /// reader thread with raw PTY output; `on_exit` fires once when the shell
    /// exits or the stream closes. The returned handle drives stdin/resize/close.
    fn open_shell(
        &mut self,
        name: &str,
        on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>>;
```

- [ ] **Step 4: Implement `open_shell` + `RealShell` on RealDaemon.**

In `app/src-tauri/src/daemon.rs`, extend the imports:
```rust
use izba_core::vmm::UdsStream;
use izba_proto::{
    write_frame, ExecRequest, Request, Response, StreamAttach, StreamKind, StreamOpen,
};
use std::io::{Read, Write};
use std::net::Shutdown;
```
Add the `RealShell` struct (after `RealDaemon`'s impls or anywhere at module scope):
```rust
/// Production `ShellSession`: a dedicated control connection (for resize/kill)
/// plus the bidirectional tty stream. A reader thread pumps guest output into
/// the `on_output` callback and fires `on_exit` on EOF.
struct RealShell {
    write_half: UdsStream,
    control: DaemonClient,
    name: String,
    exec_id: u32,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl ShellSession for RealShell {
    fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.write_half.write_all(data)?;
        self.write_half.flush()?;
        Ok(())
    }

    fn resize(&mut self, cols: u16, rows: u16) -> anyhow::Result<()> {
        match self.control.guest_rpc(
            &self.name,
            &Request::Resize {
                exec_id: self.exec_id,
                cols,
                rows,
            },
        )? {
            Response::Ok => Ok(()),
            Response::Error { kind, message } => anyhow::bail!("resize failed ({kind:?}): {message}"),
            other => anyhow::bail!("unexpected resize reply: {other:?}"),
        }
    }

    fn close(&mut self) -> anyhow::Result<()> {
        // Best-effort kill; the guest then closes the stream.
        let _ = self.control.guest_rpc(
            &self.name,
            &Request::Kill {
                exec_id: self.exec_id,
                signal: 15,
            },
        );
        // Unblock the reader thread (in case the kill RPC could not be sent).
        let _ = self.write_half.shutdown(Shutdown::Both);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        Ok(())
    }
}
```
Add the `open_shell` impl to `impl DaemonApi for RealDaemon`:
```rust
    fn open_shell(
        &mut self,
        name: &str,
        mut on_output: Box<dyn FnMut(Vec<u8>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Box<dyn ShellSession>> {
        let mut control = DaemonClient::connect_spawning_izba(&self.paths)?;
        let exec_id = match control.guest_rpc(
            name,
            &Request::Exec(ExecRequest {
                argv: vec!["/bin/sh".to_string()],
                env: vec![("TERM".to_string(), "xterm-256color".to_string())],
                cwd: "/workspace".to_string(),
                tty: true,
                uid: 0,
                gid: 0,
            }),
        )? {
            Response::ExecStarted { exec_id } => exec_id,
            Response::Error { kind, message } => anyhow::bail!("shell exec failed ({kind:?}): {message}"),
            other => anyhow::bail!("unexpected exec reply: {other:?}"),
        };
        let mut stream = DaemonClient::open_guest_stream(&self.paths, name)?;
        write_frame(
            &mut stream,
            &StreamOpen::Attach(StreamAttach {
                exec_id,
                kind: StreamKind::Tty,
            }),
        )?;
        let mut read_half = stream.try_clone()?;
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match read_half.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => on_output(buf[..n].to_vec()),
                }
            }
            on_exit();
        });
        Ok(Box::new(RealShell {
            write_half: stream,
            control,
            name: name.to_string(),
            exec_id,
            reader: Some(reader),
        }))
    }
```

- [ ] **Step 5: Gate.**
```sh
cargo build --manifest-path app/src-tauri/Cargo.toml
cargo test --manifest-path app/src-tauri/Cargo.toml
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
```
Expected: all green; `fake_shell_echoes_and_records` + `fake_open_shell_surfaces_failure` pass.

- [ ] **Step 6: Commit (include the regenerated lock).**
```sh
git add app/src-tauri/Cargo.toml app/src-tauri/Cargo.lock app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs
git commit -m "feat(app): ShellSession + open_shell on the DaemonApi seam

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Backend — Tauri commands + live-shell state + events

**Files:**
- Modify: `app/src-tauri/src/lib.rs`

This task is Tauri glue (no unit tests — the seam logic is already tested via FakeDaemon; correctness here is verified by compile + clippy + the spec/quality review). Keep it minimal and mirror the P2 command patterns.

- [ ] **Step 1: Extend AppState + imports.**

In `app/src-tauri/src/lib.rs`, update imports:
```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use daemon::{DaemonApi, RealDaemon, ShellSession};
use tauri::{Emitter, State};
use views::{CreateOpts, DaemonStatusView, SandboxView, VersionView};
```
Add the `shells` map to `AppState`:
```rust
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
    pub make_daemon: Arc<dyn Fn() -> Box<dyn DaemonApi> + Send + Sync>,
    /// Live interactive shells, keyed by sandbox name (one per sandbox).
    pub shells: Mutex<HashMap<String, Box<dyn ShellSession>>>,
}
```

- [ ] **Step 2: Add event payload structs + the commands.**

After the `create` command, add:
```rust
#[derive(Clone, serde::Serialize)]
struct ShellOutput {
    name: String,
    /// Base64-encoded raw PTY bytes (terminal output is not always UTF-8).
    data: String,
}

#[derive(Clone, serde::Serialize)]
struct ShellExit {
    name: String,
}

#[tauri::command]
async fn read_logs(state: State<'_, AppState>, name: String) -> Result<String, String> {
    run_action(&state, move |d| commands::read_logs_core(d, &name)).await
}

#[tauri::command]
async fn shell_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    // Replace any stale session for this sandbox.
    if let Ok(mut shells) = state.shells.lock() {
        if let Some(mut old) = shells.remove(&name) {
            let _ = old.close();
        }
    }
    let make = state.make_daemon.clone();
    let out_app = app.clone();
    let out_name = name.clone();
    let exit_app = app.clone();
    let exit_name = name.clone();
    let open_name = name.clone();
    let session = tauri::async_runtime::spawn_blocking(move || {
        let mut d = make();
        d.open_shell(
            &open_name,
            Box::new(move |bytes: Vec<u8>| {
                let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let _ = out_app.emit(
                    "shell-output",
                    ShellOutput {
                        name: out_name.clone(),
                        data,
                    },
                );
            }),
            Box::new(move || {
                let _ = exit_app.emit("shell-exit", ShellExit { name: exit_name });
            }),
        )
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| e.to_string())?;
    state
        .shells
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?
        .insert(name, session);
    Ok(())
}

#[tauri::command]
async fn shell_write(state: State<'_, AppState>, name: String, data: String) -> Result<(), String> {
    let mut shells = state.shells.lock().map_err(|e| format!("state poisoned: {e}"))?;
    let s = shells
        .get_mut(&name)
        .ok_or_else(|| "no active shell".to_string())?;
    s.write(data.as_bytes()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn shell_resize(
    state: State<'_, AppState>,
    name: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let mut shells = state.shells.lock().map_err(|e| format!("state poisoned: {e}"))?;
    let s = shells
        .get_mut(&name)
        .ok_or_else(|| "no active shell".to_string())?;
    s.resize(cols, rows).map_err(|e| e.to_string())
}

#[tauri::command]
async fn shell_close(state: State<'_, AppState>, name: String) -> Result<(), String> {
    let session = state
        .shells
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?
        .remove(&name);
    if let Some(mut s) = session {
        s.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}
```

- [ ] **Step 3: Register state + handlers.**

In `pub fn run()`, update the state init:
```rust
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
        make_daemon: Arc::new(|| Box::new(RealDaemon::new())),
        shells: Mutex::new(HashMap::new()),
    };
```
Add the five commands to `tauri::generate_handler![ ... ]` (after `create`):
```rust
            create,
            read_logs,
            shell_open,
            shell_write,
            shell_resize,
            shell_close
```

- [ ] **Step 4: Gate.**
```sh
cargo build --manifest-path app/src-tauri/Cargo.toml
cargo test --manifest-path app/src-tauri/Cargo.toml
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
```
Expected: all green.

- [ ] **Step 5: Commit.**
```sh
git add app/src-tauri/src/lib.rs
git commit -m "feat(app): logs + interactive shell Tauri commands and events

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Frontend — deps, types, IPC wrappers

**Files:**
- Modify: `app/package.json` + `app/package-lock.json` (add xterm)
- Modify: `app/src/test/setup.ts` (ResizeObserver stub)
- Modify: `app/src/lib/types.ts`
- Modify: `app/src/lib/ipc.ts`
- Modify: `app/src/test/ipc.test.ts`

- [ ] **Step 1: Install xterm deps.**

From `app/` (may need the Bash sandbox disabled due to the read-only npm cache):
```sh
npm install @xterm/xterm@^5.5.0 @xterm/addon-fit@^0.10.0
```
Verify both land in `dependencies` in `package.json` and that `package-lock.json` updates.

- [ ] **Step 2: ResizeObserver stub for jsdom.**

In `app/src/test/setup.ts`, append:
```ts
// jsdom has no ResizeObserver; the shell view's fit-on-resize uses one.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
if (!("ResizeObserver" in globalThis)) {
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = ResizeObserverStub;
}
```

- [ ] **Step 3: Add payload types.**

In `app/src/lib/types.ts`, append:
```ts
/** Payload of the `shell-output` event (raw PTY bytes, base64-encoded). */
export interface ShellOutputPayload {
  name: string;
  data: string;
}

/** Payload of the `shell-exit` event. */
export interface ShellExitPayload {
  name: string;
}
```

- [ ] **Step 4: Add IPC wrappers + helpers.**

In `app/src/lib/ipc.ts`, update the import and `api` object and add the event helpers:
```ts
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  SandboxView,
  DaemonStatusView,
  VersionView,
  CreateOpts,
  ShellOutputPayload,
  ShellExitPayload,
} from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
  versionInfo: () => invoke<VersionView>("version_info"),
  start: (name: string) => invoke<void>("start", { name }),
  stop: (name: string) => invoke<void>("stop", { name }),
  restart: (name: string) => invoke<void>("restart", { name }),
  remove: (name: string, force: boolean) => invoke<void>("remove", { name, force }),
  create: (opts: CreateOpts) => invoke<string>("create", { opts }),
  readLogs: (name: string) => invoke<string>("read_logs", { name }),
  shellOpen: (name: string) => invoke<void>("shell_open", { name }),
  shellWrite: (name: string, data: string) => invoke<void>("shell_write", { name, data }),
  shellResize: (name: string, cols: number, rows: number) =>
    invoke<void>("shell_resize", { name, cols, rows }),
  shellClose: (name: string) => invoke<void>("shell_close", { name }),
};

/** Decode a base64 string to raw bytes (xterm.write accepts Uint8Array). */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Subscribe to streamed create-progress messages. Returns an unlisten fn. */
export function onCreateProgress(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>("create-progress", (e) => cb(e.payload));
}

/** Subscribe to a sandbox's shell output (decoded to bytes). */
export function onShellOutput(name: string, cb: (bytes: Uint8Array) => void): Promise<UnlistenFn> {
  return listen<ShellOutputPayload>("shell-output", (e) => {
    if (e.payload.name === name) cb(b64ToBytes(e.payload.data));
  });
}

/** Subscribe to a sandbox's shell exit. */
export function onShellExit(name: string, cb: () => void): Promise<UnlistenFn> {
  return listen<ShellExitPayload>("shell-exit", (e) => {
    if (e.payload.name === name) cb();
  });
}
```
(Preserve any existing `onCreateProgress` — keep exactly one definition.)

- [ ] **Step 5: Extend ipc.test.ts.**

In `app/src/test/ipc.test.ts`, add assertions for the new wrappers, following the existing `vi.hoisted` mock pattern already in that file. Example additions inside the existing `describe`:
```ts
  it("readLogs invokes read_logs with the name", async () => {
    invoke.mockResolvedValue("logs!");
    await api.readLogs("web");
    expect(invoke).toHaveBeenCalledWith("read_logs", { name: "web" });
  });

  it("shellWrite invokes shell_write with name and data", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellWrite("web", "ls\n");
    expect(invoke).toHaveBeenCalledWith("shell_write", { name: "web", data: "ls\n" });
  });

  it("shellResize invokes shell_resize with dimensions", async () => {
    invoke.mockResolvedValue(undefined);
    await api.shellResize("web", 80, 24);
    expect(invoke).toHaveBeenCalledWith("shell_resize", { name: "web", cols: 80, rows: 24 });
  });
```
Add a `b64ToBytes` unit test:
```ts
import { b64ToBytes } from "../lib/ipc";
// ...
  it("b64ToBytes decodes base64 to bytes", () => {
    // btoa("hi") === "aGk="
    expect(Array.from(b64ToBytes("aGk="))).toEqual([104, 105]);
  });
```
(If the existing file mocks `@tauri-apps/api/event`'s `listen`, reuse that mock; otherwise the wrapper tests above only need `invoke`.)

- [ ] **Step 6: Gate.**

From `app/`:
```sh
npm run build
npm test
```
Expected: tsc + vite build OK; all vitest tests pass.

- [ ] **Step 7: Commit.**
```sh
git add app/package.json app/package-lock.json app/src/test/setup.ts app/src/lib/types.ts app/src/lib/ipc.ts app/src/test/ipc.test.ts
git commit -m "feat(app): xterm deps + logs/shell IPC wrappers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Frontend — LogsView component

**Files:**
- Create: `app/src/components/LogsView.tsx`
- Create: `app/src/test/logsView.test.tsx`

- [ ] **Step 1: Write the failing test.**

Create `app/src/test/logsView.test.tsx`:
```tsx
import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { LogsView } from "../components/LogsView";

vi.mock("../lib/ipc", () => ({
  api: { readLogs: vi.fn() },
}));

describe("LogsView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("fetches and renders console output", async () => {
    const { api } = await import("../lib/ipc");
    (api.readLogs as ReturnType<typeof vi.fn>).mockResolvedValue("hello from boot");
    render(<LogsView name="web" />);
    await waitFor(() => expect(api.readLogs).toHaveBeenCalledWith("web"));
    await screen.findByText(/hello from boot/);
  });

  it("surfaces a read error", async () => {
    const { api } = await import("../lib/ipc");
    (api.readLogs as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("nope"));
    render(<LogsView name="web" />);
    await screen.findByText(/nope/);
  });
});
```

- [ ] **Step 2: Run it to confirm it fails (component missing).**

From `app/`: `npm test -- logsView` — Expected: FAIL (cannot resolve `../components/LogsView`).

- [ ] **Step 3: Implement LogsView.**

Create `app/src/components/LogsView.tsx`:
```tsx
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/ipc";

/** Live-tailing view of a sandbox's captured console output. */
export function LogsView({ name }: { name: string }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let alive = true;
    async function tick() {
      try {
        const t = await api.readLogs(name);
        if (!alive) return;
        setText(t);
        setError(null);
      } catch (e) {
        if (!alive) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    }
    void tick();
    const id = setInterval(() => void tick(), 1500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [name]);

  // Keep the view pinned to the newest output.
  useEffect(() => {
    const el = preRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [text]);

  return (
    <div className="flex h-full flex-col">
      {error && <div className="mb-2 text-sm text-warn">{error}</div>}
      <pre
        ref={preRef}
        data-testid="log-output"
        className="flex-1 overflow-auto whitespace-pre-wrap rounded-lg bg-ink-1/5 p-3 font-mono text-xs text-ink-1"
      >
        {text || "No console output yet."}
      </pre>
    </div>
  );
}
```
(If `bg-ink-1/5`/`text-ink-1` are not in the Tailwind theme, use the nearest existing tokens used elsewhere in the app — check `Detail.tsx`, which uses `text-ink-2`, `text-ink-3`, `bg-hover`, `border-line`.)

- [ ] **Step 4: Run the test to confirm it passes.**

From `app/`: `npm test -- logsView` — Expected: PASS.

- [ ] **Step 5: Commit.**
```sh
git add app/src/components/LogsView.tsx app/src/test/logsView.test.tsx
git commit -m "feat(app): LogsView console-output tail component

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Frontend — ShellView component (xterm.js)

**Files:**
- Create: `app/src/components/ShellView.tsx`
- Create: `app/src/test/shellView.test.tsx`

- [ ] **Step 1: Write the failing test.**

Create `app/src/test/shellView.test.tsx`. Mock xterm + addon-fit + ipc; capture the `onData` callback so we can assert keystroke forwarding:
```tsx
import { render, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const term = vi.hoisted(() => ({
  open: vi.fn(),
  write: vi.fn(),
  loadAddon: vi.fn(),
  dispose: vi.fn(),
  onData: vi.fn(),
  cols: 80,
  rows: 24,
  _dataCb: null as ((d: string) => void) | null,
}));

vi.mock("@xterm/xterm", () => ({
  Terminal: vi.fn(() => {
    term.onData.mockImplementation((cb: (d: string) => void) => {
      term._dataCb = cb;
    });
    return term;
  }),
}));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: vi.fn(() => ({ fit: vi.fn() })),
}));
vi.mock("../lib/ipc", () => ({
  api: {
    shellOpen: vi.fn().mockResolvedValue(undefined),
    shellWrite: vi.fn().mockResolvedValue(undefined),
    shellResize: vi.fn().mockResolvedValue(undefined),
    shellClose: vi.fn().mockResolvedValue(undefined),
  },
  onShellOutput: vi.fn().mockResolvedValue(() => {}),
  onShellExit: vi.fn().mockResolvedValue(() => {}),
}));

import { ShellView } from "../components/ShellView";

describe("ShellView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("opens a shell on mount and subscribes to output", async () => {
    const { api, onShellOutput } = await import("../lib/ipc");
    render(<ShellView name="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalledWith("web"));
    expect(onShellOutput).toHaveBeenCalled();
  });

  it("forwards keystrokes to shellWrite", async () => {
    const { api } = await import("../lib/ipc");
    render(<ShellView name="web" />);
    await waitFor(() => expect(term.onData).toHaveBeenCalled());
    term._dataCb?.("x");
    expect(api.shellWrite).toHaveBeenCalledWith("web", "x");
  });

  it("closes the shell on unmount", async () => {
    const { api } = await import("../lib/ipc");
    const { unmount } = render(<ShellView name="web" />);
    await waitFor(() => expect(api.shellOpen).toHaveBeenCalled());
    unmount();
    expect(api.shellClose).toHaveBeenCalledWith("web");
  });
});
```

- [ ] **Step 2: Run it to confirm it fails.**

From `app/`: `npm test -- shellView` — Expected: FAIL (cannot resolve `../components/ShellView`).

- [ ] **Step 3: Implement ShellView.**

Create `app/src/components/ShellView.tsx`:
```tsx
import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, onShellOutput, onShellExit } from "../lib/ipc";

/** Interactive PTY into a guest, rendered with xterm.js. */
export function ShellView({ name }: { name: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const term = new Terminal({ fontSize: 13, cursorBlink: true });
    const fit = new FitAddon();
    term.loadAddon(fit);
    if (ref.current) {
      term.open(ref.current);
      fit.fit();
    }

    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const track = (p: Promise<() => void>) =>
      void p.then((un) => (disposed ? un() : unlisteners.push(un)));

    term.onData((d) => void api.shellWrite(name, d));

    void api.shellOpen(name).then(() => {
      void api.shellResize(name, term.cols, term.rows);
    });
    track(onShellOutput(name, (bytes) => term.write(bytes)));
    track(onShellExit(name, () => term.write("\r\n\x1b[2m[process exited]\x1b[0m\r\n")));

    const ro = new ResizeObserver(() => {
      fit.fit();
      void api.shellResize(name, term.cols, term.rows);
    });
    if (ref.current) ro.observe(ref.current);

    return () => {
      disposed = true;
      ro.disconnect();
      unlisteners.forEach((un) => un());
      void api.shellClose(name);
      term.dispose();
    };
  }, [name]);

  return <div ref={ref} className="h-full w-full" data-testid="shell-term" />;
}
```

- [ ] **Step 4: Run the test to confirm it passes.**

From `app/`: `npm test -- shellView` — Expected: PASS.

- [ ] **Step 5: Commit.**
```sh
git add app/src/components/ShellView.tsx app/src/test/shellView.test.tsx
git commit -m "feat(app): ShellView interactive xterm.js terminal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Frontend — tabbed Detail view

**Files:**
- Modify: `app/src/components/Detail.tsx`
- Modify: `app/src/test/detail.test.tsx`

- [ ] **Step 1: Extend the test (tabs + Overview still works).**

In `app/src/test/detail.test.tsx`, add mocks for the two child components at the top (so Detail tests stay isolated from xterm/polling):
```tsx
vi.mock("../components/LogsView", () => ({
  LogsView: ({ name }: { name: string }) => <div>logs-for-{name}</div>,
}));
vi.mock("../components/ShellView", () => ({
  ShellView: ({ name }: { name: string }) => <div>shell-for-{name}</div>,
}));
```
Add a new describe block:
```tsx
describe("Detail tabs", () => {
  beforeEach(() => vi.clearAllMocks());

  it("defaults to Overview and shows lifecycle actions", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    expect(screen.getByRole("button", { name: /^stop$/i })).toBeInTheDocument();
  });

  it("switches to the Logs tab", () => {
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /logs/i }));
    expect(screen.getByText("logs-for-web")).toBeInTheDocument();
  });

  it("shows the shell for a running sandbox and a hint when stopped", () => {
    const running: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    const { rerender } = render(<Detail sandbox={running} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /shell/i }));
    expect(screen.getByText("shell-for-web")).toBeInTheDocument();

    const stopped: SandboxView = { name: "db", image: "postgres:16", state: { kind: "stopped" } };
    rerender(<Detail sandbox={stopped} onChanged={noop} />);
    fireEvent.click(screen.getByRole("tab", { name: /shell/i }));
    expect(screen.getByText(/start the sandbox/i)).toBeInTheDocument();
  });
});
```
The existing `Detail` and `Detail actions` describe blocks must keep passing unchanged (header + Overview actions render by default).

- [ ] **Step 2: Run to confirm the new tests fail.**

From `app/`: `npm test -- detail` — Expected: the tab tests FAIL (no tabs yet); existing tests still pass.

- [ ] **Step 3: Refactor Detail into tabs.**

Rewrite `app/src/components/Detail.tsx`. Keep the existing header (status dot + name + image + degraded banner). Keep all current lifecycle state/handlers/buttons/confirm-dialogs as the **Overview** tab body. Add a tab bar and render Logs/Shell tabs:
```tsx
import { useEffect, useState } from "react";
import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";
import { ConfirmDialog } from "./ConfirmDialog";
import { LogsView } from "./LogsView";
import { ShellView } from "./ShellView";
import { api } from "../lib/ipc";

interface Props {
  sandbox: SandboxView | null;
  onChanged: () => void;
}

type Pending = { kind: "stop" | "remove"; name: string } | null;
type Tab = "overview" | "logs" | "shell";

export function Detail({ sandbox, onChanged }: Props) {
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  // Reset to Overview whenever the selected sandbox changes.
  useEffect(() => {
    setTab("overview");
    setError(null);
    setPending(null);
  }, [sandbox?.name]);

  if (!sandbox) {
    return <div className="grid flex-1 place-items-center text-ink-3">Select a sandbox</div>;
  }

  const running = sandbox.state.kind !== "stopped";
  const name = sandbox.name;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "logs", label: "Logs" },
    { id: "shell", label: "Shell" },
  ];

  return (
    <section className="flex flex-1 flex-col p-5">
      <div className="flex items-center gap-3 text-lg font-semibold">
        <StatusDot state={sandbox.state} /> {name}
      </div>
      <div className="mt-1 text-ink-2">{sandbox.image}</div>
      {sandbox.state.kind === "degraded" && (
        <div className="mt-3 rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-sm text-warn">
          {sandbox.state.reason}
        </div>
      )}

      <div role="tablist" className="mt-4 flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={
              "px-3 py-2 text-sm -mb-px border-b-2 " +
              (tab === t.id
                ? "border-accent font-semibold text-ink-1"
                : "border-transparent text-ink-2 hover:text-ink-1")
            }
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="mt-4 min-h-0 flex-1">
        {tab === "overview" && (
          <div>
            <div className="flex flex-wrap gap-2">
              {running ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => setPending({ kind: "stop", name })}
                  className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover disabled:opacity-50"
                >
                  Stop
                </button>
              ) : (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void act(() => api.start(name))}
                  className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white shadow-sm disabled:opacity-50"
                >
                  Start
                </button>
              )}
              <button
                type="button"
                disabled={busy}
                onClick={() => void act(() => api.restart(name))}
                className="rounded-lg border border-line px-3 py-1.5 hover:bg-hover disabled:opacity-50"
              >
                Restart
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setPending({ kind: "remove", name })}
                className="rounded-lg border border-warn/40 px-3 py-1.5 text-warn hover:bg-warn/5 disabled:opacity-50"
              >
                Remove
              </button>
            </div>
            {error && <div className="mt-3 text-sm text-warn">{error}</div>}
          </div>
        )}

        {tab === "logs" && <LogsView name={name} />}

        {tab === "shell" &&
          (running ? (
            <ShellView name={name} />
          ) : (
            <div className="text-ink-3">Start the sandbox to open a shell.</div>
          ))}
      </div>

      {pending?.kind === "stop" && (
        <ConfirmDialog
          title={`Stop ${pending.name}?`}
          message="The VM is shut down; the sandbox keeps its disk and can be started again."
          confirmLabel="Stop"
          onCancel={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            void act(() => api.stop(pending.name));
          }}
        />
      )}
      {pending?.kind === "remove" && (
        <ConfirmDialog
          title={`Remove ${pending.name}?`}
          message="This permanently deletes the sandbox and its writable disk."
          confirmLabel="Remove"
          danger
          onCancel={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            void act(() => api.remove(pending.name, false));
          }}
        />
      )}
    </section>
  );
}
```

- [ ] **Step 4: Run all frontend tests.**

From `app/`: `npm test` then `npm run build` — Expected: all pass; tsc clean. The Shell tab unmounts `ShellView` (and triggers `shellClose`) when switching away because React unmounts the conditionally-rendered child — confirm no test regressions.

- [ ] **Step 5: Commit.**
```sh
git add app/src/components/Detail.tsx app/src/test/detail.test.tsx
git commit -m "feat(app): tabbed sandbox detail (Overview / Logs / Shell)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

From repo root with toolchain exports:
```sh
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path app/src-tauri/Cargo.toml
( cd app && npm run build && npm test )
```
All five must be green — these mirror the `app.yml` CI gate. The six **core** workspace gates are untouched (app stays excluded from the cargo workspace), so they do not need re-running for this change.

**Manual validation (cannot run in CI):** against a real running sandbox, the Logs tab tails `console.log`, and the Shell tab gives an interactive `/bin/sh` (keystrokes echo, `ls` works, resizing reflows, `exit` shows `[process exited]`). Note this in the PR as manually-verified (or as a follow-up if no KVM host is available at PR time).

## Notes / deferred

- One shell per sandbox (keyed by name); opening a second replaces the first. Multi-session tabs are out of scope.
- Logs use periodic full re-fetch (1.5s) rather than incremental tailing — simple and robust for bounded console logs; revisit if logs grow large.
- Exit status code is not surfaced in the shell UI (EOF → "[process exited]"); wiring `Wait` for the numeric code is a possible follow-up.
