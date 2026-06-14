# izba Desktop App — P2 Lifecycle + Create Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add sandbox lifecycle controls (Start / Stop / Restart / Remove, with confirmation on destructive actions) and a Create-sandbox wizard (streamed progress) to the izba Tauri desktop app, extending the M1 walking skeleton.

**Architecture:** Extend the existing `DaemonApi` trait seam with `start`/`stop`/`remove`/`create` methods (unit-tested against `FakeDaemon`, no socket/KVM). `RealDaemon` maps each to a `DaemonClient` RPC. New action Tauri commands run on a **fresh daemon connection** inside `spawn_blocking` (a factory in `AppState`) so they never hold the polling `Mutex` during a slow boot-wait — honoring the M1 carry-forward note. `create` streams `Progress` frames out as `create-progress` Tauri events. The frontend gains action buttons in the Overview detail, a reusable `ConfirmDialog`, and a `NewSandbox` modal wizard.

**Tech Stack:** Rust (Tauri 2, `izba-core` path dep), React + TypeScript + Vite + Tailwind + Vitest, `@tauri-apps/plugin-dialog` for the workspace directory picker.

---

## Scope notes (read first)

- **Policy file in create is DEFERRED to P4 (firewall).** `DaemonCreate` has no policy field; the CLI persists policy separately via `persist_policy` after `Created`. P2 create covers the core fields only (name, image, cpus, mem, workspace, rw size, ports). This is called out in the design's create item but slots cleanly with the Firewall tab in P4.
- **Start progress is not surfaced in P2.** `Start` may emit boot-wait `Progress` frames; P2 ignores them (button shows a disabled "Starting…" state and refreshes on completion). Only `create` streams progress events. Surfacing start progress is a later polish.
- **Restart = Stop then Start** orchestrated in the command-core layer (izba never auto-restarts).
- **Workspace** is an existing absolute path chosen via the Tauri dialog picker (or typed); the app passes it through unchanged. The daemon validates/mounts it.

## Toolchain (worktrees have no `.cargo-env`)

Rust commands in this worktree need the main repo's toolchain on PATH:

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH="$CARGO_HOME/bin:$PATH"
```

All `cargo` commands below assume this is exported and are run from `app/src-tauri`. All `npm` commands are run from `app/`. `cargo` may need `dangerouslyDisableSandbox` for crates.io; `npm`/npmjs is allowed.

## File structure

Backend (`app/src-tauri/src/`):
- `views.rs` — **modify**: add `CreateOpts` (Deserialize) + `into_daemon_create()` (name validation + port parse).
- `daemon.rs` — **modify**: extend `DaemonApi` trait + `RealDaemon` impl with `start`/`stop`/`remove`/`create`.
- `fake.rs` — **modify**: extend `FakeDaemon` (call recording + `fail_action` + scripted progress).
- `commands.rs` — **modify**: add `start_core`/`stop_core`/`restart_core`/`remove_core`/`create_core`.
- `lib.rs` — **modify**: `AppState` gains a `make_daemon` factory; add action Tauri command wrappers + register them; emit `create-progress` events.

Frontend (`app/src/`):
- `lib/types.ts` — **modify**: add `CreateOpts`.
- `lib/ipc.ts` — **modify**: add `start`/`stop`/`restart`/`remove`/`create` + `onCreateProgress` listener.
- `components/ConfirmDialog.tsx` — **create**: reusable confirm modal.
- `components/Detail.tsx` — **modify**: action buttons + confirm gating + busy state.
- `components/NewSandbox.tsx` — **create**: create wizard modal with streamed progress.
- `components/Rail.tsx` — **modify**: enable the "＋ New sandbox" button + `onNew` callback.
- `App.tsx` — **modify**: own the modal open state + refresh-after-action wiring.
- Tests: `src/test/detail.test.tsx` (extend), `src/test/confirmDialog.test.tsx` (new), `src/test/newSandbox.test.tsx` (new).

---

## Task 1: Backend `CreateOpts` view + mapping

**Files:**
- Modify: `app/src-tauri/src/views.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `app/src-tauri/src/views.rs`:

```rust
    #[test]
    fn create_opts_maps_to_daemon_create() {
        let opts = CreateOpts {
            name: "web".into(),
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            rw_size_gb: 8,
            ports: vec!["127.0.0.1:8080:80".into(), "  ".into()],
        };
        let dc = opts.into_daemon_create().unwrap();
        assert_eq!(dc.name, "web");
        assert_eq!(dc.image_ref, "ubuntu:24.04");
        assert_eq!(dc.cpus, 2);
        assert_eq!(dc.mem_mb, 4096);
        assert_eq!(dc.workspace, std::path::PathBuf::from("/ws"));
        assert_eq!(dc.rw_size_gb, 8);
        assert_eq!(dc.ports.len(), 1); // blank spec dropped
        assert_eq!(dc.ports[0].host_port, 8080);
        assert_eq!(dc.ports[0].guest_port, 80);
    }

    #[test]
    fn create_opts_rejects_bad_name() {
        let opts = CreateOpts {
            name: "Bad Name".into(),
            image: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            rw_size_gb: 8,
            ports: vec![],
        };
        let err = opts.into_daemon_create().unwrap_err().to_string();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-app create_opts`
Expected: FAIL — `cannot find type CreateOpts`.

- [ ] **Step 3: Write minimal implementation**

Add to the top of `app/src-tauri/src/views.rs` (after the existing `use serde::Serialize;` — change it to import `Deserialize` too) and define the struct + mapping. Add near the other view structs:

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use izba_core::daemon::proto::DaemonCreate;

/// Create-sandbox options coming from the frontend wizard. Mirrors the CLI's
/// `SandboxOpts` core fields (no `--policy`: deferred to the firewall milestone).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateOpts {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: String,
    pub rw_size_gb: u64,
    /// Repeatable `[BIND:]HOST:GUEST` port specs (blank entries are ignored).
    pub ports: Vec<String>,
}

impl CreateOpts {
    /// Validate the name and parse port specs, mirroring the CLI create path
    /// (`validate_name` + `portfwd::parse_rule`). Workspace is passed through
    /// as-is — the picker yields an existing absolute path.
    pub fn into_daemon_create(self) -> anyhow::Result<DaemonCreate> {
        izba_core::sandbox::validate_name(&self.name)?;
        let ports = self
            .ports
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(izba_core::portfwd::parse_rule)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(DaemonCreate {
            name: self.name,
            image_ref: self.image,
            cpus: self.cpus,
            mem_mb: self.mem_mb,
            workspace: PathBuf::from(self.workspace),
            rw_size_gb: self.rw_size_gb,
            ports,
        })
    }
}
```

Note: remove the old `use serde::Serialize;` line so it is not duplicated.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-app create_opts`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/views.rs
git commit -m "feat(app): CreateOpts view + DaemonCreate mapping for P2 create"
```

---

## Task 2: Extend the `DaemonApi` trait + `FakeDaemon`

**Files:**
- Modify: `app/src-tauri/src/daemon.rs`
- Modify: `app/src-tauri/src/fake.rs`

- [ ] **Step 1: Write the failing test**

Add a test module at the bottom of `app/src-tauri/src/fake.rs` (the file is `#![cfg(test)]`, so a plain `mod` works):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::DaemonCreate;

    fn sample_create() -> DaemonCreate {
        DaemonCreate {
            name: "new".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: std::path::PathBuf::from("/ws"),
            rw_size_gb: 4,
            ports: vec![],
        }
    }

    #[test]
    fn fake_records_lifecycle_calls() {
        let mut d = FakeDaemon::default();
        d.start("web").unwrap();
        d.stop("web").unwrap();
        d.remove("web", true).unwrap();
        assert_eq!(d.calls, vec!["start:web", "stop:web", "rm:web:true"]);
    }

    #[test]
    fn fake_create_streams_progress_and_returns_name() {
        let mut d = FakeDaemon::default();
        let mut seen = Vec::new();
        let name = d
            .create(sample_create(), &mut |m| seen.push(m.to_string()))
            .unwrap();
        assert_eq!(name, "new");
        assert_eq!(seen, vec!["pulling image", "booting"]);
        assert_eq!(d.calls, vec!["create:new"]);
    }

    #[test]
    fn fake_action_failure_is_surfaced() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        assert!(d.start("web").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-app fake_`
Expected: FAIL — `no method named start` / missing fields.

- [ ] **Step 3: Write minimal implementation**

In `app/src-tauri/src/daemon.rs`, extend the trait (add `use izba_core::daemon::proto::DaemonCreate;` to the existing proto `use`):

```rust
pub trait DaemonApi: Send {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>>;
    fn status(&mut self) -> anyhow::Result<DaemonStatusView>;
    fn start(&mut self, name: &str) -> anyhow::Result<()>;
    fn stop(&mut self, name: &str) -> anyhow::Result<()>;
    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()>;
    /// Streams `Progress` messages via `on_progress`; returns the created name.
    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String>;
}
```

Add the `RealDaemon` impls (inside `impl DaemonApi for RealDaemon`). A small helper keeps the `Ok`/`Error` mapping DRY:

```rust
    fn start(&mut self, name: &str) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| {
            expect_ok(c.request(&DaemonRequest::Start { name }, &mut |_| {})?)
        })
    }

    fn stop(&mut self, name: &str) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| expect_ok(c.request(&DaemonRequest::Stop { name }, &mut |_| {})?))
    }

    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()> {
        let name = name.to_string();
        self.with_client(|c| {
            expect_ok(c.request(&DaemonRequest::Rm { name, force }, &mut |_| {})?)
        })
    }

    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String> {
        self.with_client(|c| match c.request(&DaemonRequest::Create(req), on_progress)? {
            DaemonResponse::Created { name } => Ok(name),
            DaemonResponse::Error { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected Create reply: {other:?}"),
        })
    }
```

Add this free function at the bottom of `daemon.rs`:

```rust
/// Map a one-shot daemon reply that should be `Ok` into `()`.
fn expect_ok(resp: DaemonResponse) -> anyhow::Result<()> {
    match resp {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}
```

In `app/src-tauri/src/fake.rs`, add the new fields to the struct + `Default`, and implement the new trait methods. Replace the struct + `Default` + `impl` accordingly:

```rust
use izba_core::daemon::proto::DaemonCreate;

pub struct FakeDaemon {
    pub sandboxes: Vec<SandboxView>,
    pub status: DaemonStatusView,
    pub fail_list: bool,
    pub fail_status: bool,
    pub fail_action: bool,
    pub calls: Vec<String>,
    pub progress: Vec<String>,
}
```

In `Default`, add after `fail_status: false,`:

```rust
            fail_action: false,
            calls: Vec::new(),
            progress: vec!["pulling image".into(), "booting".into()],
```

Add to `impl DaemonApi for FakeDaemon`:

```rust
    fn start(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("start:{name}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn stop(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("stop:{name}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn remove(&mut self, name: &str, force: bool) -> anyhow::Result<()> {
        self.calls.push(format!("rm:{name}:{force}"));
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        Ok(())
    }
    fn create(
        &mut self,
        req: DaemonCreate,
        on_progress: &mut dyn FnMut(&str),
    ) -> anyhow::Result<String> {
        if self.fail_action {
            anyhow::bail!("action failed");
        }
        for m in &self.progress {
            on_progress(m);
        }
        self.calls.push(format!("create:{}", req.name));
        Ok(req.name)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-app`
Expected: PASS (new fake tests + existing tests still green).

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs
git commit -m "feat(app): extend DaemonApi with start/stop/remove/create + fake"
```

---

## Task 3: Command-core functions

**Files:**
- Modify: `app/src-tauri/src/commands.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `app/src-tauri/src/commands.rs`:

```rust
    use crate::views::CreateOpts;

    fn create_opts() -> CreateOpts {
        CreateOpts {
            name: "new".into(),
            image: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: "/ws".into(),
            rw_size_gb: 4,
            ports: vec![],
        }
    }

    #[test]
    fn start_stop_remove_dispatch() {
        let mut d = FakeDaemon::default();
        start_core(&mut d, "web").unwrap();
        stop_core(&mut d, "web").unwrap();
        remove_core(&mut d, "web", true).unwrap();
        assert_eq!(d.calls, vec!["start:web", "stop:web", "rm:web:true"]);
    }

    #[test]
    fn restart_is_stop_then_start() {
        let mut d = FakeDaemon::default();
        restart_core(&mut d, "web").unwrap();
        assert_eq!(d.calls, vec!["stop:web", "start:web"]);
    }

    #[test]
    fn restart_does_not_start_if_stop_fails() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        assert!(restart_core(&mut d, "web").is_err());
        assert_eq!(d.calls, vec!["stop:web"]); // start not attempted
    }

    #[test]
    fn create_core_streams_and_returns_name() {
        let mut d = FakeDaemon::default();
        let mut seen = Vec::new();
        let name = create_core(&mut d, create_opts(), &mut |m| seen.push(m.to_string())).unwrap();
        assert_eq!(name, "new");
        assert_eq!(seen, vec!["pulling image", "booting"]);
    }

    #[test]
    fn create_core_maps_bad_name_to_error() {
        let mut d = FakeDaemon::default();
        let mut bad = create_opts();
        bad.name = "Bad Name".into();
        let err = create_core(&mut d, bad, &mut |_| {}).unwrap_err();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-app -- commands`
Expected: FAIL — `cannot find function start_core`.

- [ ] **Step 3: Write minimal implementation**

Add to `app/src-tauri/src/commands.rs` (top imports: add `use crate::views::CreateOpts;`):

```rust
/// Start a sandbox (may boot-wait inside the daemon).
pub fn start_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.start(name).map_err(|e| e.to_string())
}

/// Stop a sandbox.
pub fn stop_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())
}

/// Restart = stop then start (izba never auto-restarts). Stop failure aborts
/// before start so a half-restart never silently boots a stale config.
pub fn restart_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())?;
    d.start(name).map_err(|e| e.to_string())
}

/// Remove a sandbox (force skips the running-state guard).
pub fn remove_core(d: &mut dyn DaemonApi, name: &str, force: bool) -> Result<(), String> {
    d.remove(name, force).map_err(|e| e.to_string())
}

/// Create a sandbox, forwarding daemon `Progress` messages via `on_progress`.
pub fn create_core(
    d: &mut dyn DaemonApi,
    opts: CreateOpts,
    on_progress: &mut dyn FnMut(&str),
) -> Result<String, String> {
    let req = opts.into_daemon_create().map_err(|e| e.to_string())?;
    d.create(req, on_progress).map_err(|e| e.to_string())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-app -- commands`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/commands.rs
git commit -m "feat(app): lifecycle + create command-core fns (TDD)"
```

---

## Task 4: Tauri command wrappers + fresh-connection factory + events

**Files:**
- Modify: `app/src-tauri/src/lib.rs`

- [ ] **Step 1: Write the failing test**

`lib.rs` has no unit tests (Tauri harness required); the existing `list`/`daemon_status` wrappers are untested by design. Verification for this task is the **compile gate**, not a unit test. The proof is `cargo test -p izba-app` + `cargo clippy` staying green and `cargo build` succeeding.

Run (baseline, expected to FAIL after we reference not-yet-added symbols if done out of order — so this step is just the build target):

Run: `cargo build -p izba-app`
Expected after Step 3: success.

- [ ] **Step 2: Confirm the gap**

Run: `grep -c "make_daemon" app/src-tauri/src/lib.rs`
Expected: `0` (factory not present yet).

- [ ] **Step 3: Write implementation**

Replace `app/src-tauri/src/lib.rs` with:

```rust
mod commands;
mod daemon;
#[cfg(test)]
mod fake;
mod views;

use std::sync::{Arc, Mutex};

use daemon::{DaemonApi, RealDaemon};
use tauri::{Emitter, State};
use views::{CreateOpts, DaemonStatusView, SandboxView};

/// App-wide handle to izbad. `daemon` is the shared polling connection
/// (list/status). Slow/streaming actions use `make_daemon` to get their OWN
/// fresh connection inside `spawn_blocking`, so a boot-wait never blocks the
/// 2s poll (M1 carry-forward note).
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
    pub make_daemon: Arc<dyn Fn() -> Box<dyn DaemonApi> + Send + Sync>,
}

#[tauri::command]
async fn list(state: State<'_, AppState>) -> Result<Vec<SandboxView>, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::list_core(guard.as_mut())
}

#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatusView, String> {
    let mut guard = state
        .daemon
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?;
    commands::status_core(guard.as_mut())
}

/// Run a blocking action on a fresh daemon connection off the async runtime.
async fn run_action<T, F>(state: &State<'_, AppState>, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn DaemonApi) -> Result<T, String> + Send + 'static,
{
    let make = state.make_daemon.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = make();
        f(d.as_mut())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
async fn start(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::start_core(d, &name)).await
}

#[tauri::command]
async fn stop(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::stop_core(d, &name)).await
}

#[tauri::command]
async fn restart(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::restart_core(d, &name)).await
}

#[tauri::command]
async fn remove(state: State<'_, AppState>, name: String, force: bool) -> Result<(), String> {
    run_action(&state, move |d| commands::remove_core(d, &name, force)).await
}

#[tauri::command]
async fn create(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    opts: CreateOpts,
) -> Result<String, String> {
    run_action(&state, move |d| {
        commands::create_core(d, opts, &mut |m| {
            let _ = app.emit("create-progress", m.to_string());
        })
    })
    .await
}

pub fn run() {
    let state = AppState {
        daemon: Mutex::new(Box::new(RealDaemon::new())),
        make_daemon: Arc::new(|| Box::new(RealDaemon::new())),
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list,
            daemon_status,
            start,
            stop,
            restart,
            remove,
            create
        ])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
```

Add the dialog plugin to `app/src-tauri/Cargo.toml` under `[dependencies]`:

```toml
tauri-plugin-dialog = "2"
```

Add the dialog capability to `app/src-tauri/capabilities/default.json` — append to its `"permissions"` array:

```json
    "dialog:default",
    "dialog:allow-open"
```

- [ ] **Step 4: Verify build, tests, lint**

Run (from `app/src-tauri`):
```bash
cargo build -p izba-app
cargo test -p izba-app
cargo clippy -p izba-app --all-targets -- -D warnings
cargo fmt
```
Expected: build OK; all tests PASS; zero clippy warnings.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/lib.rs app/src-tauri/Cargo.toml app/src-tauri/Cargo.lock app/src-tauri/capabilities/default.json
git commit -m "feat(app): action Tauri commands on fresh conn + create-progress events + dialog plugin"
```

---

## Task 5: Frontend IPC layer + types

**Files:**
- Modify: `app/src/lib/types.ts`
- Modify: `app/src/lib/ipc.ts`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/ipc.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";

const invoke = vi.fn().mockResolvedValue(undefined);
const listen = vi.fn().mockResolvedValue(() => {});
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));

import { api, onCreateProgress } from "../lib/ipc";

describe("ipc action wrappers", () => {
  beforeEach(() => vi.clearAllMocks());

  it("start/stop/restart pass the name", async () => {
    await api.start("web");
    await api.stop("web");
    await api.restart("web");
    expect(invoke).toHaveBeenCalledWith("start", { name: "web" });
    expect(invoke).toHaveBeenCalledWith("stop", { name: "web" });
    expect(invoke).toHaveBeenCalledWith("restart", { name: "web" });
  });

  it("remove passes name + force", async () => {
    await api.remove("web", true);
    expect(invoke).toHaveBeenCalledWith("remove", { name: "web", force: true });
  });

  it("create passes opts", async () => {
    const opts = {
      name: "web",
      image: "ubuntu:24.04",
      cpus: 2,
      mem_mb: 4096,
      workspace: "/ws",
      rw_size_gb: 8,
      ports: [],
    };
    await api.create(opts);
    expect(invoke).toHaveBeenCalledWith("create", { opts });
  });

  it("onCreateProgress subscribes to the event", async () => {
    await onCreateProgress(() => {});
    expect(listen).toHaveBeenCalledWith("create-progress", expect.any(Function));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `app/`): `npm run test -- ipc`
Expected: FAIL — `api.start is not a function`.

- [ ] **Step 3: Write minimal implementation**

Add to `app/src/lib/types.ts`:

```ts
export interface CreateOpts {
  name: string;
  image: string;
  cpus: number;
  mem_mb: number;
  workspace: string;
  rw_size_gb: number;
  ports: string[];
}
```

Replace `app/src/lib/ipc.ts` with:

```ts
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { SandboxView, DaemonStatusView, CreateOpts } from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
  start: (name: string) => invoke<void>("start", { name }),
  stop: (name: string) => invoke<void>("stop", { name }),
  restart: (name: string) => invoke<void>("restart", { name }),
  remove: (name: string, force: boolean) => invoke<void>("remove", { name, force }),
  create: (opts: CreateOpts) => invoke<string>("create", { opts }),
};

/** Subscribe to streamed create-progress messages. Returns an unlisten fn. */
export function onCreateProgress(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>("create-progress", (e) => cb(e.payload));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (from `app/`): `npm run test -- ipc`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/lib/types.ts app/src/lib/ipc.ts app/src/test/ipc.test.ts
git commit -m "feat(app): frontend IPC wrappers for lifecycle + create"
```

---

## Task 6: `ConfirmDialog` component

**Files:**
- Create: `app/src/components/ConfirmDialog.tsx`
- Create: `app/src/test/confirmDialog.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/confirmDialog.test.tsx`:

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ConfirmDialog } from "../components/ConfirmDialog";

describe("ConfirmDialog", () => {
  it("renders title + message and fires onConfirm", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        title="Remove web?"
        message="This deletes the sandbox."
        confirmLabel="Remove"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByText("Remove web?")).toBeInTheDocument();
    expect(screen.getByText("This deletes the sandbox.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("fires onCancel from the Cancel button", () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog title="t" message="m" confirmLabel="Go" onConfirm={() => {}} onCancel={onCancel} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `app/`): `npm run test -- confirmDialog`
Expected: FAIL — cannot find module `ConfirmDialog`.

- [ ] **Step 3: Write minimal implementation**

Create `app/src/components/ConfirmDialog.tsx`:

```tsx
interface Props {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ title, message, confirmLabel, danger, onConfirm, onCancel }: Props) {
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/30"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div className="w-[26rem] max-w-[90vw] rounded-xl bg-white p-5 shadow-xl">
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="mt-2 text-ink-2 text-sm">{message}</p>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg px-3 py-1.5 text-ink-2 hover:bg-hover"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`rounded-lg px-3 py-1.5 font-semibold text-white shadow-sm ${
              danger ? "bg-danger" : "bg-accent"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
```

If `bg-danger` is not a defined Tailwind token, use `bg-warn` (already used in `Detail.tsx`). Check `app/tailwind.config.ts` before choosing; prefer an existing token.

- [ ] **Step 4: Run test to verify it passes**

Run (from `app/`): `npm run test -- confirmDialog`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/ConfirmDialog.tsx app/src/test/confirmDialog.test.tsx
git commit -m "feat(app): reusable ConfirmDialog for destructive actions"
```

---

## Task 7: Lifecycle action buttons in `Detail`

**Files:**
- Modify: `app/src/components/Detail.tsx`
- Modify: `app/src/test/detail.test.tsx`

- [ ] **Step 1: Write the failing test**

Append to `app/src/test/detail.test.tsx` (add the imports `fireEvent`, `waitFor`, `vi` to the existing import line; mock `ipc`):

```tsx
import { fireEvent, waitFor } from "@testing-library/react";
import { vi } from "vitest";

vi.mock("../lib/ipc", () => ({
  api: {
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    restart: vi.fn().mockResolvedValue(undefined),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

describe("Detail actions", () => {
  it("shows Start for a stopped sandbox and calls api.start", async () => {
    const { api } = await import("../lib/ipc");
    const onChanged = vi.fn();
    const sbx: SandboxView = { name: "db", image: "postgres:16", state: { kind: "stopped" } };
    render(<Detail sandbox={sbx} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /^start$/i }));
    await waitFor(() => expect(api.start).toHaveBeenCalledWith("db"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("shows Stop for a running sandbox and confirms before stopping", async () => {
    const { api } = await import("../lib/ipc");
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /^stop$/i }));
    // confirm dialog appears; click its confirm
    fireEvent.click(screen.getByRole("button", { name: /^stop$/i, hidden: false }));
    await waitFor(() => expect(api.stop).toHaveBeenCalledWith("web"));
  });

  it("Remove requires confirmation", async () => {
    const { api } = await import("../lib/ipc");
    const sbx: SandboxView = { name: "web", image: "ubuntu:24.04", state: { kind: "running" } };
    render(<Detail sandbox={sbx} onChanged={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /^remove$/i }));
    expect(api.remove).not.toHaveBeenCalled(); // not until confirmed
    fireEvent.click(screen.getByRole("button", { name: /^remove$/i }));
    await waitFor(() => expect(api.remove).toHaveBeenCalledWith("web", false));
  });
});
```

Note: the confirm-dialog button shares the action label; if the duplicate-name lookup is brittle, give the confirm button a distinct label (e.g. the dialog `confirmLabel` = "Stop") and select by dialog role first (`within(screen.getByRole("dialog"))`). Adjust the test to use `within` if needed.

- [ ] **Step 2: Run test to verify it fails**

Run (from `app/`): `npm run test -- detail`
Expected: FAIL — `Detail` has no `onChanged` prop / no action buttons.

- [ ] **Step 3: Write minimal implementation**

Replace `app/src/components/Detail.tsx`:

```tsx
import { useState } from "react";
import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";
import { ConfirmDialog } from "./ConfirmDialog";
import { api } from "../lib/ipc";

interface Props {
  sandbox: SandboxView | null;
  onChanged: () => void;
}

type Pending = { kind: "stop" | "remove"; name: string } | null;

export function Detail({ sandbox, onChanged }: Props) {
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [error, setError] = useState<string | null>(null);

  if (!sandbox) {
    return <div className="flex-1 grid place-items-center text-ink-3">Select a sandbox</div>;
  }

  const running = sandbox.state.kind !== "stopped";

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

  const name = sandbox.name;

  return (
    <section className="flex-1 p-5">
      <div className="flex items-center gap-3 text-lg font-semibold">
        <StatusDot state={sandbox.state} /> {name}
      </div>
      <div className="mt-1 text-ink-2">{sandbox.image}</div>
      {sandbox.state.kind === "degraded" && (
        <div className="mt-3 rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-warn text-sm">
          {sandbox.state.reason}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
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
            onClick={() => act(() => api.start(name))}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white shadow-sm disabled:opacity-50"
          >
            Start
          </button>
        )}
        <button
          type="button"
          disabled={busy}
          onClick={() => act(() => api.restart(name))}
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

      {error && <div className="mt-3 text-warn text-sm">{error}</div>}

      {pending?.kind === "stop" && (
        <ConfirmDialog
          title={`Stop ${pending.name}?`}
          message="The VM is shut down; the sandbox keeps its disk and can be started again."
          confirmLabel="Stop"
          onCancel={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            void act(() => api.stop(name));
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
            void act(() => api.remove(name, false));
          }}
        />
      )}
    </section>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (from `app/`): `npm run test -- detail`
Expected: PASS. If the duplicate-label selector is brittle, switch the test to `within(screen.getByRole("dialog"))` as noted.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/Detail.tsx app/src/test/detail.test.tsx
git commit -m "feat(app): lifecycle action buttons in Detail with confirm gating"
```

---

## Task 8: `NewSandbox` wizard modal

**Files:**
- Create: `app/src/components/NewSandbox.tsx`
- Create: `app/src/test/newSandbox.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/newSandbox.test.tsx`:

```tsx
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const create = vi.fn().mockResolvedValue("web");
const onCreateProgress = vi.fn().mockResolvedValue(() => {});
vi.mock("../lib/ipc", () => ({ api: { create }, onCreateProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("/picked/ws") }));

import { NewSandbox } from "../components/NewSandbox";

describe("NewSandbox", () => {
  beforeEach(() => vi.clearAllMocks());

  it("submits create with form values", async () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ name: "web", workspace: "/ws", image: "ubuntu:24.04" }),
      ),
    );
  });

  it("disables Create when name is empty", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("surfaces a create error", async () => {
    create.mockRejectedValueOnce(new Error("invalid sandbox name 'X'"));
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(screen.getByText(/invalid sandbox name/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `app/`): `npm run test -- newSandbox`
Expected: FAIL — cannot find module `NewSandbox`.

- [ ] **Step 3: Write minimal implementation**

Create `app/src/components/NewSandbox.tsx`:

```tsx
import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, onCreateProgress } from "../lib/ipc";
import type { CreateOpts } from "../lib/types";

interface Props {
  onClose: () => void;
  onCreated: (name: string) => void;
}

export function NewSandbox({ onClose, onCreated }: Props) {
  const [name, setName] = useState("");
  const [image, setImage] = useState("ubuntu:24.04");
  const [cpus, setCpus] = useState(2);
  const [memMb, setMemMb] = useState(4096);
  const [rwSizeGb, setRwSizeGb] = useState(8);
  const [workspace, setWorkspace] = useState("");
  const [portsText, setPortsText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void onCreateProgress((m) => setProgress((p) => [...p, m])).then((u) => (unlisten = u));
    return () => unlisten?.();
  }, []);

  async function pickDir() {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked === "string") {
      setWorkspace(picked);
      if (!name) {
        const base = picked.split(/[/\\]/).filter(Boolean).pop() ?? "";
        setName(base.toLowerCase().replace(/[^a-z0-9_.-]/g, "-"));
      }
    }
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setProgress([]);
    const opts: CreateOpts = {
      name,
      image,
      cpus,
      mem_mb: memMb,
      workspace,
      rw_size_gb: rwSizeGb,
      ports: portsText.split("\n").map((s) => s.trim()).filter(Boolean),
    };
    try {
      const created = await api.create(opts);
      onCreated(created);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const canCreate = name.trim().length > 0 && workspace.trim().length > 0 && !busy;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/30" role="dialog" aria-modal="true" aria-label="New sandbox">
      <div className="w-[32rem] max-w-[92vw] rounded-xl bg-white p-5 shadow-xl">
        <h2 className="text-lg font-semibold">New sandbox</h2>
        <div className="mt-4 grid gap-3 text-sm">
          <label className="grid gap-1">
            <span className="text-ink-2">Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} className="rounded-lg border border-line px-2 py-1.5" />
          </label>
          <label className="grid gap-1">
            <span className="text-ink-2">Workspace</span>
            <div className="flex gap-2">
              <input value={workspace} onChange={(e) => setWorkspace(e.target.value)} className="flex-1 rounded-lg border border-line px-2 py-1.5" />
              <button type="button" onClick={() => void pickDir()} className="rounded-lg border border-line px-3 hover:bg-hover">
                Browse…
              </button>
            </div>
          </label>
          <label className="grid gap-1">
            <span className="text-ink-2">Image</span>
            <input value={image} onChange={(e) => setImage(e.target.value)} className="rounded-lg border border-line px-2 py-1.5" />
          </label>
          <div className="grid grid-cols-3 gap-3">
            <label className="grid gap-1">
              <span className="text-ink-2">vCPUs</span>
              <input type="number" min={1} value={cpus} onChange={(e) => setCpus(+e.target.value)} className="rounded-lg border border-line px-2 py-1.5" />
            </label>
            <label className="grid gap-1">
              <span className="text-ink-2">Memory (MiB)</span>
              <input type="number" min={256} value={memMb} onChange={(e) => setMemMb(+e.target.value)} className="rounded-lg border border-line px-2 py-1.5" />
            </label>
            <label className="grid gap-1">
              <span className="text-ink-2">Disk (GiB)</span>
              <input type="number" min={1} value={rwSizeGb} onChange={(e) => setRwSizeGb(+e.target.value)} className="rounded-lg border border-line px-2 py-1.5" />
            </label>
          </div>
          <label className="grid gap-1">
            <span className="text-ink-2">Ports (one [BIND:]HOST:GUEST per line)</span>
            <textarea value={portsText} onChange={(e) => setPortsText(e.target.value)} rows={2} className="rounded-lg border border-line px-2 py-1.5 font-mono text-xs" />
          </label>
        </div>

        {progress.length > 0 && (
          <div className="mt-3 max-h-24 overflow-auto rounded-lg bg-rail p-2 font-mono text-xs text-ink-2">
            {progress.map((m, i) => (
              <div key={i}>{m}</div>
            ))}
          </div>
        )}
        {error && <div className="mt-3 text-warn text-sm">{error}</div>}

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-lg px-3 py-1.5 text-ink-2 hover:bg-hover">
            Cancel
          </button>
          <button
            type="button"
            disabled={!canCreate}
            onClick={() => void submit()}
            className="rounded-lg bg-accent px-3 py-1.5 font-semibold text-white shadow-sm disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
```

Add the npm dialog plugin (from `app/`):

```bash
npm install @tauri-apps/plugin-dialog@^2
```

- [ ] **Step 4: Run test to verify it passes**

Run (from `app/`): `npm run test -- newSandbox`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/NewSandbox.tsx app/src/test/newSandbox.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): New-sandbox wizard with dir picker + streamed progress"
```

---

## Task 9: Wire the wizard + refresh into `App` and `Rail`

**Files:**
- Modify: `app/src/App.tsx`
- Modify: `app/src/components/Rail.tsx`
- Modify: `app/src/test/rail.test.tsx`

- [ ] **Step 1: Write the failing test**

Replace `app/src/test/rail.test.tsx`'s "new sandbox button" expectation (or add) to assert the button is enabled and fires `onNew`:

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Rail } from "../components/Rail";

describe("Rail new-sandbox button", () => {
  it("is enabled and calls onNew", () => {
    const onNew = vi.fn();
    render(<Rail sandboxes={[]} selected={null} onSelect={() => {}} onNew={onNew} />);
    const btn = screen.getByRole("button", { name: /new sandbox/i });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    expect(onNew).toHaveBeenCalledOnce();
  });
});
```

Keep any existing `rail.test.tsx` cases that still apply (selection rendering); update the `Rail` render calls in them to pass `onNew={() => {}}`.

- [ ] **Step 2: Run test to verify it fails**

Run (from `app/`): `npm run test -- rail`
Expected: FAIL — `onNew` not a prop / button disabled.

- [ ] **Step 3: Write minimal implementation**

In `app/src/components/Rail.tsx`, add `onNew: () => void` to `Props` and replace the disabled button:

```tsx
interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
}
```

```tsx
      <button
        type="button"
        onClick={onNew}
        aria-label="New sandbox"
        className="mb-2 rounded-lg bg-accent text-white font-semibold py-2 shadow-sm hover:bg-accent/90"
      >
        ＋ New sandbox
      </button>
```

Replace `app/src/App.tsx`:

```tsx
import { useState } from "react";
import { usePolling } from "./lib/store";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Detail } from "./components/Detail";
import { NewSandbox } from "./components/NewSandbox";

export default function App() {
  const { sandboxes, daemon, error, refresh } = usePolling(2000);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const current = sandboxes.find((s) => s.name === selected) ?? null;

  return (
    <div className="h-full flex flex-col">
      <TopBar daemon={daemon} error={error} />
      <div className="flex flex-1 min-h-0">
        <Rail sandboxes={sandboxes} selected={selected} onSelect={setSelected} onNew={() => setCreating(true)} />
        <Detail sandbox={current} onChanged={refresh} />
      </div>
      {creating && (
        <NewSandbox
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false);
            setSelected(name);
            refresh();
          }}
        />
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (from `app/`): `npm run test`
Expected: PASS (all suites). Fix any `Rail`/`Detail` render calls in other tests that now need the new props.

- [ ] **Step 5: Commit**

```bash
git add app/src/App.tsx app/src/components/Rail.tsx app/src/test/rail.test.tsx
git commit -m "feat(app): wire New-sandbox wizard + post-action refresh into App"
```

---

## Task 10: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Frontend build + tests**

Run (from `app/`):
```bash
npm run build   # tsc + vite
npm run test
```
Expected: typecheck clean, vite build OK, all vitest suites PASS.

- [ ] **Step 2: Backend build + tests + lint + fmt**

Run (from `app/src-tauri`, toolchain exported):
```bash
cargo test -p izba-app
cargo clippy -p izba-app --all-targets -- -D warnings
cargo fmt --check
```
Expected: all PASS, zero warnings, fmt clean.

- [ ] **Step 3: Confirm core gates untouched**

`app/src-tauri` is excluded from the root workspace, so the six core gates are unaffected. Sanity check the exclusion still holds:

Run (from repo root): `grep -n "exclude" Cargo.toml`
Expected: `app/src-tauri` still listed under `[workspace] exclude` (or absent from members).

- [ ] **Step 4: Commit any fmt fixups**

```bash
git add -A app/
git commit -m "chore(app): fmt + verification fixups for P2" || echo "nothing to commit"
```

---

## Self-review checklist (done while writing)

- **Spec coverage:** lifecycle Start/Stop/Restart/Remove (Tasks 3,7) with confirm on Stop+Remove (Task 7); create wizard with workspace/image/cpus/mem/rw/ports + streamed progress (Tasks 1,4,5,8); "+ New sandbox" enabled (Task 9). Policy file + ports "open in browser" + logs/shell/firewall tabs are explicitly OUT of P2 (P3/P4).
- **Type consistency:** `CreateOpts` fields identical across `views.rs` (Rust) and `types.ts` (TS): `name/image/cpus/mem_mb/workspace/rw_size_gb/ports`. Trait method names `start/stop/remove/create` consistent across `daemon.rs`, `fake.rs`, `commands.rs`. IPC command names (`start/stop/restart/remove/create`) match Tauri `generate_handler!` registration.
- **No placeholders:** every code step has complete code; commands have expected output.
