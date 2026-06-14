# izba Desktop App — Plan 1: Walking Skeleton

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Tauri 2 desktop app shell that connects to izbad via an embedded `izba-core` and shows your real sandboxes with live status — the end-to-end integration proven before any feature work.

**Architecture:** A new `app/` subtree (React+TS+Vite+Tailwind frontend, `app/src-tauri` Rust backend) kept **outside** the root cargo workspace. The backend talks to izbad through a `DaemonApi` trait — a thin `RealDaemon` wrapping `izba_core::DaemonClient`, plus a `FakeDaemon` for unit tests (no socket `bind`, respecting the sandbox EPERM constraint). The frontend polls two Tauri commands (`list`, `daemon_status`) and renders layout A (sidebar + detail) in the light/Calm-Indigo theme.

**Tech Stack:** Tauri 2, Rust (izba-core path dep), React 18, TypeScript, Vite 5, Tailwind 3, Vitest. xterm.js arrives in a later plan.

**This is Plan 1 of a milestone series.** It produces working, launchable software on its own. Later plans (lifecycle, create, logs, shell, ports, firewall, tray) are summarized in the Roadmap at the end and will each get their own full TDD plan.

---

## File structure (this plan)

```
Cargo.toml                         # MODIFY: add app/src-tauri to [workspace].exclude
app/
├── package.json                   # CREATE: React, Vite, Tailwind, @tauri-apps/api, vitest
├── vite.config.ts                 # CREATE
├── tsconfig.json                  # CREATE
├── tailwind.config.ts             # CREATE
├── postcss.config.js              # CREATE
├── index.html                     # CREATE
├── src/
│   ├── main.tsx                   # CREATE: React entry
│   ├── App.tsx                    # CREATE: shell (TopBar + Rail + Detail)
│   ├── theme.css                  # CREATE: light theme tokens (Calm Indigo) + Tailwind directives
│   ├── lib/
│   │   ├── types.ts               # CREATE: SandboxView, DaemonStatusView, SbxState DTOs
│   │   ├── ipc.ts                 # CREATE: typed invoke() wrappers
│   │   └── store.ts               # CREATE: usePolling hook (list + status)
│   ├── components/
│   │   ├── TopBar.tsx             # CREATE
│   │   ├── Rail.tsx               # CREATE
│   │   ├── StatusDot.tsx          # CREATE
│   │   └── Detail.tsx             # CREATE (overview-only for M1)
│   └── test/
│       ├── statusDot.test.tsx     # CREATE
│       └── rail.test.tsx          # CREATE
└── src-tauri/
    ├── Cargo.toml                 # CREATE: bin+lib, izba-core path dep, tauri, serde
    ├── build.rs                   # CREATE
    ├── tauri.conf.json            # CREATE
    ├── capabilities/default.json  # CREATE
    └── src/
        ├── main.rs                # CREATE: thin shim → app_lib::run()
        ├── lib.rs                 # CREATE: Tauri builder, state, command registration
        ├── daemon.rs              # CREATE: DaemonApi trait, RealDaemon, status parser
        ├── views.rs               # CREATE: SandboxView/DaemonStatusView DTOs + From impls
        ├── commands.rs            # CREATE: list/daemon_status command core + #[tauri::command] wrappers
        └── fake.rs                # CREATE (cfg(test)): FakeDaemon
```

---

## Task 1: Scaffold the Tauri app and exclude it from the workspace

**Files:**
- Create: `app/package.json`, `app/vite.config.ts`, `app/tsconfig.json`, `app/index.html`, `app/src/main.tsx`, `app/src/App.tsx`
- Create: `app/src-tauri/Cargo.toml`, `app/src-tauri/build.rs`, `app/src-tauri/tauri.conf.json`, `app/src-tauri/capabilities/default.json`, `app/src-tauri/src/main.rs`, `app/src-tauri/src/lib.rs`
- Modify: `Cargo.toml` (root)

- [ ] **Step 1: Exclude the app backend from the root workspace**

Edit root `Cargo.toml`. The `[workspace]` table currently is:

```toml
[workspace]
resolver = "2"
members = ["crates/izba-proto", "crates/izba-core", "crates/izba-cli", "crates/izba-init", "crates/izba-ttytest"]
```

Add an `exclude` key so the nested Tauri crate is treated as a standalone crate (prevents both "package believes it's in a workspace" errors and pollution of `cargo build --workspace` + the cross-compile gates):

```toml
[workspace]
resolver = "2"
members = ["crates/izba-proto", "crates/izba-core", "crates/izba-cli", "crates/izba-init", "crates/izba-ttytest"]
exclude = ["app/src-tauri"]
```

- [ ] **Step 2: Create the frontend package manifest**

Create `app/package.json`:

```json
{
  "name": "izba-app",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "^2.0.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2.0.0",
    "@testing-library/react": "^16.0.0",
    "@testing-library/jest-dom": "^6.4.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.0",
    "autoprefixer": "^10.4.0",
    "jsdom": "^25.0.0",
    "postcss": "^8.4.0",
    "tailwindcss": "^3.4.0",
    "typescript": "^5.5.0",
    "vite": "^5.4.0",
    "vitest": "^2.1.0"
  }
}
```

- [ ] **Step 3: Create Vite + TS + Tailwind config**

Create `app/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed port and to not clear the screen.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist" },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"] },
});
```

Create `app/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2021",
    "useDefineForClassFields": true,
    "lib": ["ES2021", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "skipLibCheck": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src"]
}
```

Create `app/postcss.config.js`:

```js
export default { plugins: { tailwindcss: {}, autoprefixer: {} } };
```

Create `app/tailwind.config.ts`:

```ts
import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        accent: { DEFAULT: "#3b6fe0", weak: "#eaf0fd" },
        ink: { DEFAULT: "#1b2230", 2: "#5a6473", 3: "#8a93a3" },
        surface: "#ffffff",
        rail: "#fbfcfd",
        bg: "#f6f7f9",
        line: "#e4e7ec",
        ok: "#16a34a",
        warn: "#d97706",
        off: "#9aa3b2",
      },
    },
  },
  plugins: [],
} satisfies Config;
```

- [ ] **Step 4: Create the HTML entry and React bootstrap**

Create `app/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>izba</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

Create `app/src/theme.css`:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

:root { color-scheme: light; }
html, body, #root { height: 100%; margin: 0; }
body {
  background: theme(colors.bg);
  color: theme(colors.ink.DEFAULT);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  -webkit-font-smoothing: antialiased;
}
```

Create `app/src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./theme.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

Create a minimal `app/src/App.tsx` (replaced with the real shell in Task 5):

```tsx
export default function App() {
  return <div className="p-6 text-ink">izba — loading…</div>;
}
```

- [ ] **Step 5: Create the Tauri backend crate manifest**

Create `app/src-tauri/Cargo.toml`:

```toml
[package]
name = "izba-app"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[lib]
name = "app_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
izba-core = { path = "../../crates/izba-core" }

[features]
# default Tauri custom-protocol toggle for release builds
custom-protocol = ["tauri/custom-protocol"]
```

- [ ] **Step 6: Create the Tauri build script, config, capabilities, and entry shims**

Create `app/src-tauri/build.rs`:

```rust
fn main() {
    tauri_build::build();
}
```

Create `app/src-tauri/tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "izba",
  "version": "0.1.0",
  "identifier": "dev.izba.app",
  "build": {
    "frontendDist": "../dist",
    "devUrl": "http://localhost:1420",
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build"
  },
  "app": {
    "windows": [
      { "title": "izba", "width": 1100, "height": 720, "minWidth": 880, "minHeight": 560 }
    ],
    "security": { "csp": null }
  },
  "bundle": { "active": true, "targets": "all" }
}
```

Create `app/src-tauri/capabilities/default.json`:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "description": "Default capabilities for the izba app window",
  "windows": ["main"],
  "permissions": ["core:default"]
}
```

Create `app/src-tauri/src/main.rs`:

```rust
// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    app_lib::run();
}
```

Create `app/src-tauri/src/lib.rs` (expanded in Task 3):

```rust
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
```

- [ ] **Step 7: Install deps and verify the scaffold compiles**

Run:
```bash
cd app && npm install
cd src-tauri && cargo build
```
Expected: `npm install` completes; `cargo build` succeeds and pulls in `izba-core` (first build is slow). No workspace error.

Verify the exclusion did not break the core gates — from repo root:
```bash
cargo metadata --no-deps --format-version 1 | grep -q '"izba-app"' && echo "LEAKED INTO WORKSPACE" || echo "OK: app excluded"
```
Expected: `OK: app excluded`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml app/package.json app/vite.config.ts app/tsconfig.json app/postcss.config.js app/tailwind.config.ts app/index.html app/src/main.tsx app/src/App.tsx app/src/theme.css app/src-tauri/Cargo.toml app/src-tauri/build.rs app/src-tauri/tauri.conf.json app/src-tauri/capabilities/default.json app/src-tauri/src/main.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): scaffold Tauri 2 + React/Vite/Tailwind shell, excluded from workspace"
```

---

## Task 2: Backend — `DaemonApi` trait, status parser, and `RealDaemon`

**Files:**
- Create: `app/src-tauri/src/daemon.rs`
- Create: `app/src-tauri/src/views.rs`
- Modify: `app/src-tauri/src/lib.rs` (add `mod` declarations)

- [ ] **Step 1: Write the failing test for the status parser and view mapping**

Create `app/src-tauri/src/views.rs` with the DTOs and a `parse_state` fn, then its tests:

```rust
use serde::Serialize;

/// Structured sandbox state for the frontend (parsed from izba's status string).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SbxState {
    Running,
    Degraded { reason: String },
    Stopped,
}

/// Parse izba's `Liveness::describe()` string into a structured state.
/// Formats: "running" | "stopped" | "degraded (<reason>)".
pub fn parse_state(status: &str) -> SbxState {
    if status == "running" {
        SbxState::Running
    } else if status == "stopped" {
        SbxState::Stopped
    } else if let Some(reason) = status.strip_prefix("degraded (").and_then(|s| s.strip_suffix(')')) {
        SbxState::Degraded { reason: reason.to_string() }
    } else {
        // Unknown/empty status is treated as stopped rather than panicking.
        SbxState::Stopped
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxView {
    pub name: String,
    pub image: String,
    pub state: SbxState,
}

impl From<izba_core::daemon::proto::SandboxSummary> for SandboxView {
    fn from(s: izba_core::daemon::proto::SandboxSummary) -> Self {
        SandboxView { name: s.name, image: s.image_ref, state: parse_state(&s.status) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonStatusView {
    pub version: String,
    pub pid: u32,
    pub uptime_ms: u64,
    pub sandbox_count: usize,
}

impl From<izba_core::daemon::proto::DaemonStatus> for DaemonStatusView {
    fn from(s: izba_core::daemon::proto::DaemonStatus) -> Self {
        DaemonStatusView {
            version: s.version,
            pid: s.pid,
            uptime_ms: s.uptime_ms,
            sandbox_count: s.sandboxes.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_running_and_stopped() {
        assert_eq!(parse_state("running"), SbxState::Running);
        assert_eq!(parse_state("stopped"), SbxState::Stopped);
    }

    #[test]
    fn parses_degraded_with_reason() {
        assert_eq!(
            parse_state("degraded (sidecar virtiofsd:workspace died)"),
            SbxState::Degraded { reason: "sidecar virtiofsd:workspace died".into() }
        );
    }

    #[test]
    fn unknown_status_is_stopped() {
        assert_eq!(parse_state("weird"), SbxState::Stopped);
        assert_eq!(parse_state(""), SbxState::Stopped);
    }

    #[test]
    fn summary_maps_to_view() {
        let s = izba_core::daemon::proto::SandboxSummary {
            name: "web".into(), image_ref: "ubuntu:24.04".into(), status: "running".into(),
        };
        let v: SandboxView = s.into();
        assert_eq!(v, SandboxView { name: "web".into(), image: "ubuntu:24.04".into(), state: SbxState::Running });
    }
}
```

- [ ] **Step 2: Declare the modules so the test compiles**

Add to the top of `app/src-tauri/src/lib.rs`:

```rust
mod daemon;
mod views;
```

Create `app/src-tauri/src/daemon.rs` with just the trait for now (impl added next step):

```rust
use crate::views::{DaemonStatusView, SandboxView};

/// Seam over izbad access so commands are unit-testable without a real daemon.
pub trait DaemonApi: Send {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>>;
    fn status(&mut self) -> anyhow::Result<DaemonStatusView>;
}
```

- [ ] **Step 3: Run the test to verify it fails (then passes once compiling)**

Run:
```bash
cd app/src-tauri && cargo test views:: -- --nocapture
```
Expected first run: compile error if a field name is wrong, else the 4 tests PASS. Fix any field-name mismatch against `crates/izba-core/src/daemon/proto.rs` (`SandboxSummary { name, image_ref, status }`, `DaemonStatus { version, pid, uptime_ms, sandboxes }`).

- [ ] **Step 4: Implement `RealDaemon` wrapping `DaemonClient`**

Append to `app/src-tauri/src/daemon.rs`:

```rust
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

/// Production `DaemonApi`: a lazily-connected `DaemonClient`. On any send/recv
/// error the connection is dropped so the next call reconnects (the daemon
/// idle-exits after ~5 min; polling keeps it warm but reconnect must be cheap).
pub struct RealDaemon {
    paths: Paths,
    client: Option<DaemonClient>,
}

impl RealDaemon {
    pub fn new() -> Self {
        RealDaemon { paths: Paths::from_env_or_default(None), client: None }
    }

    fn with_client<T>(
        &mut self,
        f: impl FnOnce(&mut DaemonClient) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if self.client.is_none() {
            self.client = Some(DaemonClient::connect(&self.paths)?);
        }
        let client = self.client.as_mut().expect("just connected");
        match f(client) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.client = None; // force reconnect next call
                Err(e)
            }
        }
    }
}

impl DaemonApi for RealDaemon {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>> {
        self.with_client(|c| {
            match c.request(&DaemonRequest::List, &mut |_| {})? {
                DaemonResponse::List { sandboxes } => {
                    Ok(sandboxes.into_iter().map(SandboxView::from).collect())
                }
                DaemonResponse::Error { message } => anyhow::bail!("{message}"),
                other => anyhow::bail!("unexpected List reply: {other:?}"),
            }
        })
    }

    fn status(&mut self) -> anyhow::Result<DaemonStatusView> {
        self.with_client(|c| {
            match c.request(&DaemonRequest::Status, &mut |_| {})? {
                DaemonResponse::Status(s) => Ok(DaemonStatusView::from(s)),
                DaemonResponse::Error { message } => anyhow::bail!("{message}"),
                other => anyhow::bail!("unexpected Status reply: {other:?}"),
            }
        })
    }
}
```

- [ ] **Step 5: Verify the backend compiles with the real impl**

Run:
```bash
cd app/src-tauri && cargo test views:: && cargo build
```
Expected: tests PASS, build succeeds. If `DaemonRequest::List`/`Status` or `DaemonResponse` variants differ, reconcile against `crates/izba-core/src/daemon/proto.rs` (List is a unit variant; Status wraps `DaemonStatus`).

- [ ] **Step 6: Commit**

```bash
git add app/src-tauri/src/daemon.rs app/src-tauri/src/views.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): DaemonApi seam, status parser, and DaemonClient-backed RealDaemon"
```

---

## Task 3: Backend — `list` + `daemon_status` commands with a fake daemon

**Files:**
- Create: `app/src-tauri/src/commands.rs`
- Create: `app/src-tauri/src/fake.rs`
- Modify: `app/src-tauri/src/lib.rs`

- [ ] **Step 1: Write the failing test for command core logic against a fake**

Create `app/src-tauri/src/fake.rs`:

```rust
#![cfg(test)]
use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView, SbxState};

/// Scripted `DaemonApi` for unit tests — no socket, no daemon.
pub struct FakeDaemon {
    pub sandboxes: Vec<SandboxView>,
    pub status: DaemonStatusView,
    pub fail_list: bool,
}

impl Default for FakeDaemon {
    fn default() -> Self {
        FakeDaemon {
            sandboxes: vec![
                SandboxView { name: "web".into(), image: "ubuntu:24.04".into(), state: SbxState::Running },
                SandboxView { name: "db".into(), image: "postgres:16".into(), state: SbxState::Stopped },
            ],
            status: DaemonStatusView { version: "0.3.1".into(), pid: 4242, uptime_ms: 1000, sandbox_count: 2 },
            fail_list: false,
        }
    }
}

impl DaemonApi for FakeDaemon {
    fn list(&mut self) -> anyhow::Result<Vec<SandboxView>> {
        if self.fail_list { anyhow::bail!("daemon unreachable"); }
        Ok(self.sandboxes.clone())
    }
    fn status(&mut self) -> anyhow::Result<DaemonStatusView> {
        Ok(self.status.clone())
    }
}
```

Create `app/src-tauri/src/commands.rs` with the core fns + tests:

```rust
use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView};

/// Core of the `list` command: maps daemon errors to a UI-friendly string.
pub fn list_core(d: &mut dyn DaemonApi) -> Result<Vec<SandboxView>, String> {
    d.list().map_err(|e| e.to_string())
}

/// Core of the `daemon_status` command.
pub fn status_core(d: &mut dyn DaemonApi) -> Result<DaemonStatusView, String> {
    d.status().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use crate::views::SbxState;

    #[test]
    fn list_core_returns_mapped_sandboxes() {
        let mut d = FakeDaemon::default();
        let out = list_core(&mut d).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "web");
        assert_eq!(out[0].state, SbxState::Running);
    }

    #[test]
    fn list_core_maps_error_to_string() {
        let mut d = FakeDaemon { fail_list: true, ..Default::default() };
        let err = list_core(&mut d).unwrap_err();
        assert!(err.contains("daemon unreachable"), "got: {err}");
    }

    #[test]
    fn status_core_returns_view() {
        let mut d = FakeDaemon::default();
        let s = status_core(&mut d).unwrap();
        assert_eq!(s.pid, 4242);
        assert_eq!(s.sandbox_count, 2);
    }
}
```

- [ ] **Step 2: Wire modules and run the test to verify it fails/compiles**

Add to `app/src-tauri/src/lib.rs`:

```rust
mod commands;
#[cfg(test)]
mod fake;
```

Run:
```bash
cd app/src-tauri && cargo test commands:: -- --nocapture
```
Expected: 3 tests PASS.

- [ ] **Step 3: Add the Tauri command wrappers and managed state**

Replace `app/src-tauri/src/lib.rs` with:

```rust
mod commands;
mod daemon;
mod views;
#[cfg(test)]
mod fake;

use std::sync::Mutex;

use daemon::{DaemonApi, RealDaemon};
use views::{DaemonStatusView, SandboxView};

/// App-wide handle to izbad, guarded for the (blocking) DaemonClient.
pub struct AppState {
    pub daemon: Mutex<Box<dyn DaemonApi>>,
}

#[tauri::command]
async fn list(state: tauri::State<'_, AppState>) -> Result<Vec<SandboxView>, String> {
    let mut guard = state.daemon.lock().map_err(|_| "state poisoned".to_string())?;
    commands::list_core(guard.as_mut())
}

#[tauri::command]
async fn daemon_status(state: tauri::State<'_, AppState>) -> Result<DaemonStatusView, String> {
    let mut guard = state.daemon.lock().map_err(|_| "state poisoned".to_string())?;
    commands::status_core(guard.as_mut())
}

pub fn run() {
    let state = AppState { daemon: Mutex::new(Box::new(RealDaemon::new())) };
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![list, daemon_status])
        .run(tauri::generate_context!())
        .expect("error while running izba app");
}
```

> Note: the `DaemonClient` call is blocking. Holding the `Mutex` across the blocking call serializes daemon access (correct — one connection). Commands are `async` so Tauri runs them off the UI thread; the lock is uncontended in practice (polling cadence is ~2s).

- [ ] **Step 4: Run all backend tests and build**

Run:
```bash
cd app/src-tauri && cargo test && cargo build
```
Expected: all tests PASS, build succeeds, `generate_handler!` registers both commands.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/commands.rs app/src-tauri/src/fake.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): list + daemon_status commands with fake-daemon unit tests"
```

---

## Task 4: Frontend — typed IPC, DTO types, and the polling store

**Files:**
- Create: `app/src/lib/types.ts`
- Create: `app/src/lib/ipc.ts`
- Create: `app/src/lib/store.ts`
- Create: `app/src/test/setup.ts`

- [ ] **Step 1: Create the TS DTOs mirroring the Rust views**

Create `app/src/lib/types.ts`:

```ts
export type SbxState =
  | { kind: "running" }
  | { kind: "degraded"; reason: string }
  | { kind: "stopped" };

export interface SandboxView {
  name: string;
  image: string;
  state: SbxState;
}

export interface DaemonStatusView {
  version: string;
  pid: number;
  uptime_ms: number;
  sandbox_count: number;
}
```

- [ ] **Step 2: Create the typed invoke wrappers**

Create `app/src/lib/ipc.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";
import type { SandboxView, DaemonStatusView } from "./types";

export const api = {
  list: () => invoke<SandboxView[]>("list"),
  daemonStatus: () => invoke<DaemonStatusView>("daemon_status"),
};
```

- [ ] **Step 3: Write the failing test for the polling store**

Create `app/src/test/setup.ts`:

```ts
import "@testing-library/jest-dom";
```

Create `app/src/lib/store.test.ts`:

```ts
import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { usePolling } from "./store";

vi.mock("./ipc", () => ({
  api: {
    list: vi.fn().mockResolvedValue([{ name: "web", image: "ubuntu:24.04", state: { kind: "running" } }]),
    daemonStatus: vi.fn().mockResolvedValue({ version: "0.3.1", pid: 1, uptime_ms: 1, sandbox_count: 1 }),
  },
}));

describe("usePolling", () => {
  beforeEach(() => vi.clearAllMocks());

  it("loads sandboxes and daemon status on mount", async () => {
    const { result } = renderHook(() => usePolling(0)); // 0 = no repeat, one immediate fetch
    await waitFor(() => expect(result.current.sandboxes.length).toBe(1));
    expect(result.current.sandboxes[0].name).toBe("web");
    expect(result.current.daemon?.version).toBe("0.3.1");
    expect(result.current.error).toBeNull();
  });

  it("surfaces errors from list", async () => {
    const { api } = await import("./ipc");
    (api.list as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("daemon unreachable"));
    const { result } = renderHook(() => usePolling(0));
    await waitFor(() => expect(result.current.error).toContain("daemon unreachable"));
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

Run:
```bash
cd app && npx vitest run src/lib/store.test.ts
```
Expected: FAIL — `usePolling` not found.

- [ ] **Step 5: Implement the polling store**

Create `app/src/lib/store.ts`:

```ts
import { useEffect, useState, useCallback } from "react";
import { api } from "./ipc";
import type { SandboxView, DaemonStatusView } from "./types";

export interface PollState {
  sandboxes: SandboxView[];
  daemon: DaemonStatusView | null;
  error: string | null;
  refresh: () => void;
}

/** Polls list + daemon_status every `intervalMs` (0 = fetch once, no interval). */
export function usePolling(intervalMs = 2000): PollState {
  const [sandboxes, setSandboxes] = useState<SandboxView[]>([]);
  const [daemon, setDaemon] = useState<DaemonStatusView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const tick = useCallback(async () => {
    try {
      const [sbx, st] = await Promise.all([api.list(), api.daemonStatus()]);
      setSandboxes(sbx);
      setDaemon(st);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void tick();
    if (intervalMs <= 0) return;
    const id = setInterval(() => void tick(), intervalMs);
    return () => clearInterval(id);
  }, [tick, intervalMs]);

  return { sandboxes, daemon, error, refresh: () => void tick() };
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run:
```bash
cd app && npx vitest run src/lib/store.test.ts
```
Expected: both tests PASS.

- [ ] **Step 7: Commit**

```bash
git add app/src/lib/types.ts app/src/lib/ipc.ts app/src/lib/store.ts app/src/lib/store.test.ts app/src/test/setup.ts
git commit -m "feat(app): typed IPC wrappers + polling store (list/daemon_status)"
```

---

## Task 5: Frontend — app shell (TopBar, Rail, StatusDot, Detail)

**Files:**
- Create: `app/src/components/StatusDot.tsx`, `TopBar.tsx`, `Rail.tsx`, `Detail.tsx`
- Create: `app/src/test/statusDot.test.tsx`, `app/src/test/rail.test.tsx`
- Modify: `app/src/App.tsx`

- [ ] **Step 1: Write the failing test for StatusDot**

Create `app/src/test/statusDot.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { StatusDot } from "../components/StatusDot";

describe("StatusDot", () => {
  it("renders running with an accessible label", () => {
    render(<StatusDot state={{ kind: "running" }} />);
    expect(screen.getByLabelText("running")).toBeInTheDocument();
  });
  it("renders degraded reason in the label", () => {
    render(<StatusDot state={{ kind: "degraded", reason: "sidecar virtiofsd:workspace died" }} />);
    expect(screen.getByLabelText(/sidecar virtiofsd:workspace died/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app && npx vitest run src/test/statusDot.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement StatusDot**

Create `app/src/components/StatusDot.tsx`:

```tsx
import type { SbxState } from "../lib/types";

const COLOR: Record<SbxState["kind"], string> = {
  running: "bg-ok",
  degraded: "bg-warn",
  stopped: "bg-off",
};

export function StatusDot({ state }: { state: SbxState }) {
  const label = state.kind === "degraded" ? `degraded: ${state.reason}` : state.kind;
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-block w-2 h-2 rounded-full ${COLOR[state.kind]}`}
    />
  );
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd app && npx vitest run src/test/statusDot.test.tsx`
Expected: PASS.

- [ ] **Step 5: Write the failing test for Rail**

Create `app/src/test/rail.test.tsx`:

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Rail } from "../components/Rail";
import type { SandboxView } from "../lib/types";

const sandboxes: SandboxView[] = [
  { name: "web", image: "ubuntu:24.04", state: { kind: "running" } },
  { name: "db", image: "postgres:16", state: { kind: "stopped" } },
];

describe("Rail", () => {
  it("lists sandbox names and images", () => {
    render(<Rail sandboxes={sandboxes} selected="web" onSelect={() => {}} />);
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("postgres:16")).toBeInTheDocument();
  });

  it("calls onSelect when a sandbox is clicked", () => {
    const onSelect = vi.fn();
    render(<Rail sandboxes={sandboxes} selected="web" onSelect={onSelect} />);
    fireEvent.click(screen.getByText("db"));
    expect(onSelect).toHaveBeenCalledWith("db");
  });
});
```

- [ ] **Step 6: Run to verify it fails**

Run: `cd app && npx vitest run src/test/rail.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 7: Implement Rail, TopBar, Detail**

Create `app/src/components/Rail.tsx`:

```tsx
import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";

interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
}

export function Rail({ sandboxes, selected, onSelect }: Props) {
  return (
    <nav className="w-56 shrink-0 border-r border-line bg-rail p-3 flex flex-col gap-1">
      <button className="mb-2 rounded-lg bg-accent text-white font-semibold py-2 shadow-sm">
        ＋ New sandbox
      </button>
      <div className="px-2 pt-1 pb-1 text-[11px] uppercase tracking-wide text-ink-3 font-bold">
        Sandboxes · {sandboxes.length}
      </div>
      {sandboxes.map((s) => (
        <button
          key={s.name}
          onClick={() => onSelect(s.name)}
          className={`flex items-center gap-2 rounded-lg px-2.5 py-2 text-left hover:bg-[#eef1f5] ${
            selected === s.name ? "bg-accent-weak text-accent font-semibold" : ""
          }`}
        >
          <StatusDot state={s.state} />
          <span className="leading-tight">
            {s.name}
            <small className="block text-ink-3 font-normal text-[11.5px]">{s.image}</small>
          </span>
        </button>
      ))}
    </nav>
  );
}
```

Create `app/src/components/TopBar.tsx`:

```tsx
import type { DaemonStatusView } from "../lib/types";

export function TopBar({ daemon, error }: { daemon: DaemonStatusView | null; error: string | null }) {
  return (
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-line bg-surface">
      <div className="flex items-center gap-2 font-semibold">
        <span className="grid place-items-center w-[22px] h-[22px] rounded-md bg-accent text-white text-xs font-extrabold">
          iz
        </span>
        izba
      </div>
      <div className="text-[13px] text-ink-2 flex items-center gap-2">
        {error ? (
          <span className="text-warn">● daemon unreachable</span>
        ) : (
          <>
            <span className="inline-block w-2 h-2 rounded-full bg-ok" />
            daemon running{daemon ? ` · v${daemon.version}` : ""}
          </>
        )}
      </div>
    </header>
  );
}
```

Create `app/src/components/Detail.tsx` (overview-only for M1):

```tsx
import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";

export function Detail({ sandbox }: { sandbox: SandboxView | null }) {
  if (!sandbox) {
    return <div className="flex-1 grid place-items-center text-ink-3">Select a sandbox</div>;
  }
  return (
    <section className="flex-1 p-5">
      <div className="flex items-center gap-3 text-lg font-semibold">
        <StatusDot state={sandbox.state} /> {sandbox.name}
      </div>
      <div className="mt-1 text-ink-2">{sandbox.image}</div>
      {sandbox.state.kind === "degraded" && (
        <div className="mt-3 rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-warn text-sm">
          {sandbox.state.reason}
        </div>
      )}
      <div className="mt-4 text-ink-3 text-sm">
        Lifecycle, logs, shell, ports, and firewall tabs arrive in the next milestone.
      </div>
    </section>
  );
}
```

- [ ] **Step 8: Run to verify Rail test passes**

Run: `cd app && npx vitest run src/test/rail.test.tsx`
Expected: PASS.

- [ ] **Step 9: Assemble the shell in App.tsx**

Replace `app/src/App.tsx`:

```tsx
import { useState } from "react";
import { usePolling } from "./lib/store";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Detail } from "./components/Detail";

export default function App() {
  const { sandboxes, daemon, error } = usePolling(2000);
  const [selected, setSelected] = useState<string | null>(null);
  const current = sandboxes.find((s) => s.name === selected) ?? null;

  return (
    <div className="h-full flex flex-col">
      <TopBar daemon={daemon} error={error} />
      <div className="flex flex-1 min-h-0">
        <Rail sandboxes={sandboxes} selected={selected} onSelect={setSelected} />
        <Detail sandbox={current} />
      </div>
    </div>
  );
}
```

- [ ] **Step 10: Run the full frontend test suite + typecheck**

Run:
```bash
cd app && npx vitest run && npx tsc --noEmit
```
Expected: all tests PASS, no type errors.

- [ ] **Step 11: Commit**

```bash
git add app/src/components app/src/test/statusDot.test.tsx app/src/test/rail.test.tsx app/src/App.tsx
git commit -m "feat(app): light-theme app shell (TopBar, Rail, StatusDot, Detail)"
```

---

## Task 6: End-to-end smoke test (real daemon) + plan wrap-up

**Files:** none (verification only)

- [ ] **Step 1: Launch the app against the real izbad**

> This needs KVM/daemon access — run with the Bash sandbox disabled (per CLAUDE.md, `/dev/kvm` works here but is invisible to sandboxed Bash). Ensure at least one sandbox exists (`izba create ./somedir` or reuse an existing one).

Run:
```bash
cd app && npm run tauri dev
```
Expected: the izba window opens; the top bar shows `daemon running · v<version>`; the left rail lists your real sandboxes with correct status dots (green running / amber degraded / gray stopped); clicking a sandbox shows its overview; a degraded sandbox shows its reason inline.

- [ ] **Step 2: Verify graceful daemon-down behavior**

With the app running, stop the daemon: `izba daemon stop`. Within ~2s the top bar should switch to `● daemon unreachable` (amber) without crashing; restarting (`izba daemon status` or any `izba ls`) and waiting one poll restores the list.

- [ ] **Step 3: Confirm the core gates are untouched**

From repo root, run the existing gates to prove the app subtree didn't leak into the workspace:
```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: both succeed exactly as before (the `app/src-tauri` crate is excluded).

- [ ] **Step 4: Final commit (if any smoke-test fixes were needed)**

```bash
git add -A app
git commit -m "fix(app): walking-skeleton smoke-test adjustments" || echo "nothing to commit"
```

---

## Self-review

**Spec coverage (this plan's slice):**
- Sandbox overview + status → Tasks 2,3,5 (parser, list command, Rail/Detail). ✓
- Cross-platform daemon access via embedded izba-core → Task 2 (`RealDaemon` over `DaemonClient`). ✓
- Light theme + Calm Indigo → Task 1 (Tailwind tokens), Task 5 (components). ✓
- Backend outside workspace, gates protected → Task 1 step 1 + Task 6 step 3. ✓
- Fake-daemon unit tests, no KVM, no bind → Tasks 2,3 (`FakeDaemon`, core fns). ✓
- Polling reads (no event stream) → Task 4 (`usePolling`). ✓
- Error banner on unreachable daemon → Task 4 (error state) + Task 5 (TopBar). ✓
- Deferred to later plans (correctly NOT in this plan): lifecycle, create, logs, shell, ports, firewall, tray. ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code; every command step has an expected result.

**Type consistency:** `SbxState`/`SandboxView`/`DaemonStatusView` are defined identically in Rust (`views.rs`, `#[serde(tag="kind", rename_all="lowercase")]`) and TS (`types.ts`); `usePolling`, `api.list`/`api.daemonStatus`, and the `list`/`daemon_status` command names match across the boundary. `DaemonApi::list/status` signatures are consistent across `RealDaemon` and `FakeDaemon`.

---

## Roadmap (future plans, each its own full TDD plan)

Each milestone below produces working, testable software and will be written out in full bite-sized detail when reached:

- **Plan 2 — Lifecycle & create:** `start`/`stop`/`restart`/`rm` commands + confirm dialogs; New-sandbox wizard (`create` with streamed `Progress` events); action buttons in Detail.
- **Plan 3 — Logs & shell:** console.log viewer with follow; xterm.js terminal bound to `OpenStream` + `StreamOpen::Attach` PTY pump (stdin/stdout events + `Resize`), with the `SHUT_RDWR` teardown contract.
- **Plan 4 — Ports & firewall:** port publish/unpublish/list + "open in browser"; netlog audit stream (tail `egress-audit.jsonl`) + policy view.
- **Plan 5 — System tray & settings:** tray status + quick start/stop + show/hide; launch-on-login toggle; Settings view.
- **Plan 6 — App CI job & packaging:** add the `app` CI job (npm build + vitest + `cargo clippy` on `app/src-tauri`); platform bundling.
