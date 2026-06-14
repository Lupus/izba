# izba Desktop App — CI & Packaging (Plan 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CI gate for the Tauri desktop app, package it (Linux `.deb` + Windows installer component), and fix the app so it can launch the daemon on a clean machine.

**Architecture:** A *separate* `app.yml` workflow lints/tests the app (frontend + backend) on Linux and Windows, kept out of the six core gates. The app is renamed `izba-app` to avoid colliding with the CLI's `izba` package/binary; Tauri's deb bundler produces a standalone `izba-app` `.deb` that `Depends: izba`; the Windows GUI binary is folded into the existing Inno Setup installer as an optional component. A new public `izba-core` seam, `DaemonClient::connect_spawning_izba`, lets the GUI spawn the sibling `izba daemon run` instead of re-execing itself.

**Tech Stack:** GitHub Actions, Tauri 2 CLI, Inno Setup, Rust (`izba-core`), npm/vitest/tsc.

**Spec:** [docs/superpowers/specs/2026-06-14-izba-app-ci-packaging-design.md](../specs/2026-06-14-izba-app-ci-packaging-design.md)

---

## Environment setup (READ FIRST — every task)

This is a **git worktree**; it has no `.cargo-env`, and `cargo`/`rustup` are not
on `PATH` by default. Before running any cargo/tauri command, export the main
repo's toolchain:

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup
export CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH="$CARGO_HOME/bin:$PATH"
```

Tauri Linux system deps are already installed on this machine. `cargo`/`tauri
build` and `npm ci` may need network access to crates.io — if a command fails
with a sandbox/network error, re-run it with the sandbox disabled.

The app crate (`app/src-tauri`) is **excluded from the root cargo workspace**, so
its cargo commands must run with cwd `app/src-tauri` (or `--manifest-path
app/src-tauri/Cargo.toml`). Frontend commands run with cwd `app`.

**Commit discipline:** one commit per task, conventional-commit message, ending
with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Stage only the
files named in the task (no `git add -A`).

**Baseline sanity (run once before Task 1):**

```bash
cd app && npm ci && npm run build && npm run test
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
```
Expected: frontend 12 tests pass, tsc clean, vite build OK; backend 8 tests pass,
clippy clean. If this baseline fails, STOP and report — do not start Task 1.

---

## Task 1: App CI workflow (`app.yml`)

Adds the gate that closes the `--admin`-merge CI gap. Separate workflow so the
heavy GTK/WebKit + npm install never slows the six core gates. GitHub-hosted
runners ship Node 20, so no `setup-node` action is needed.

**Files:**
- Create: `.github/workflows/app.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/app.yml` with exactly this content:

```yaml
name: App CI

on:
  pull_request:
  push:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  app-linux:
    name: app frontend + backend (linux)
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Install Tauri system deps
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
            librsvg2-dev build-essential file libxdo-dev libssl-dev patchelf
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: app-linux
          workspaces: app/src-tauri
      - name: npm ci
        working-directory: app
        run: npm ci
      - name: frontend build (tsc typecheck + vite)
        working-directory: app
        run: npm run build
      - name: frontend tests
        working-directory: app
        run: npm run test
      - name: backend fmt
        working-directory: app/src-tauri
        run: cargo fmt --check
      - name: backend clippy
        working-directory: app/src-tauri
        run: cargo clippy --all-targets -- -D warnings
      - name: backend tests
        working-directory: app/src-tauri
        run: cargo test

  app-windows:
    name: app frontend + backend (windows)
    runs-on: windows-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: app-windows
          workspaces: app/src-tauri
      - name: npm ci
        working-directory: app
        run: npm ci
      - name: frontend build (tsc typecheck + vite)
        working-directory: app
        run: npm run build
      - name: frontend tests
        working-directory: app
        run: npm run test
      - name: backend clippy
        working-directory: app/src-tauri
        run: cargo clippy --all-targets -- -D warnings
      - name: backend tests
        working-directory: app/src-tauri
        run: cargo test
```

- [ ] **Step 2: Validate YAML syntax locally**

Run:
```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/app.yml')); print('yaml ok')"
```
Expected: `yaml ok` (no traceback).

- [ ] **Step 3: Dry-run the job commands locally**

The workflow can only fully run in CI, but its commands must pass locally first.
With the toolchain env exported:
```bash
( cd app && npm ci && npm run build && npm run test )
( cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test )
```
Expected: all green (12 frontend tests, 8 backend tests).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/app.yml
git commit -m "ci(app): add app.yml — Linux+Windows frontend/backend gate

Closes the CI gap left when M1 merged with --admin: app/src-tauri is excluded
from the cargo workspace, so the six core gates never built or tested the GUI.
Separate workflow keeps the GTK/WebKit + npm install off the core gates.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `connect_spawning_izba` seam in `izba-core`

The GUI embeds `izba-core`; `DaemonClient::connect` auto-spawns the daemon via
`std::env::current_exe()` (`client.rs:281`), which for the app is `izba-app`, not
`izba`. The existing injectable-spawner seam `connect_with` is **private**. Add a
public `connect_spawning_izba` that spawns the sibling `izba` binary, plus a
unit-testable resolver.

**Files:**
- Modify: `crates/izba-core/src/daemon/client.rs`

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in
`crates/izba-core/src/daemon/client.rs` (use the same temp-dir crate the existing
`connect_with_spawns_and_upgrades` test uses — `tempfile`):

```rust
#[test]
fn resolve_izba_in_finds_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(izba_exe_name());
    std::fs::write(&p, b"x").unwrap();
    assert_eq!(
        resolve_izba_in(dir.path()),
        Some(p.to_string_lossy().into_owned())
    );
}

#[test]
fn resolve_izba_in_absent_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(resolve_izba_in(dir.path()), None);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cargo test -p izba-core resolve_izba_in
```
Expected: FAIL — `cannot find function resolve_izba_in` / `izba_exe_name`.

- [ ] **Step 3: Implement the resolver + public seam**

In `crates/izba-core/src/daemon/client.rs`, add the public method to the
`impl DaemonClient` block, right after the existing `connect` method (which ends
at the line `Self::connect_with(paths, &spawn_daemon, &transport::daemon_version())`
followed by `}`):

```rust
    /// Connect for embedders (the GUI) whose own `current_exe` is NOT `izba`:
    /// spawn the sibling `izba` binary's `daemon run` rather than re-exec
    /// ourselves. `izba-app` and `izba` install side by side (same dir on
    /// Windows; both on PATH via the .deb), so we resolve `izba[.exe]` next to
    /// the current executable first, then fall back to bare `izba` for the OS
    /// to resolve via PATH.
    pub fn connect_spawning_izba(paths: &Paths) -> anyhow::Result<DaemonClient> {
        Self::connect_with(paths, &spawn_sibling_izba, &transport::daemon_version())
    }
```

Then add these free functions next to the existing `spawn_daemon` function
(near `client.rs:279`):

```rust
/// `izba` on Windows is `izba.exe`; elsewhere bare `izba`.
fn izba_exe_name() -> &'static str {
    if cfg!(windows) {
        "izba.exe"
    } else {
        "izba"
    }
}

/// Sibling `izba[.exe]` in `dir` as an absolute path, if it exists as a file.
fn resolve_izba_in(dir: &std::path::Path) -> Option<String> {
    let cand = dir.join(izba_exe_name());
    cand.is_file()
        .then(|| cand.to_string_lossy().into_owned())
}

/// Resolve the `izba` binary to spawn: sibling of `current_exe` if present,
/// else bare `izba[.exe]` (PATH-resolved by the OS).
fn resolve_izba_binary() -> String {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(std::path::Path::parent)
        .and_then(resolve_izba_in)
        .unwrap_or_else(|| izba_exe_name().to_string())
}

/// Spawn `izba daemon run` detached (mirrors `spawn_daemon`, but targets the
/// sibling `izba` rather than `current_exe`).
fn spawn_sibling_izba(paths: &Paths) -> anyhow::Result<()> {
    let cmd = CommandSpec {
        argv: vec![
            resolve_izba_binary(),
            "daemon".to_string(),
            "run".to_string(),
        ],
    };
    procmgr::spawn_detached(&cmd, &paths.daemon_log())?;
    Ok(())
}
```

(`CommandSpec` and `procmgr` are already imported at the top of the file:
`use crate::procmgr;` and `use crate::vmm::{CommandSpec, UdsStream};`.)

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cargo test -p izba-core resolve_izba_in
```
Expected: PASS (2 tests).

- [ ] **Step 5: Full gate for the core crate**

Run:
```bash
cargo clippy -p izba-core --all-targets -- -D warnings
cargo test -p izba-core
```
Expected: clippy clean; all `izba-core` tests pass. (Note: `connect_spawning_izba`
itself has no direct unit test — spawning a real daemon needs a binary; it is
covered by the `resolve_*` tests plus the existing `connect_with` test that
exercises the shared spawn path. Manual end-to-end is verified by the user.)

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/daemon/client.rs
git commit -m "feat(core): connect_spawning_izba seam for non-izba embedders

The GUI embeds izba-core; DaemonClient::connect auto-spawns the daemon via
current_exe(), which for the app is izba-app — wrong binary. Add a public
connect_spawning_izba that resolves and spawns the sibling izba daemon run,
with a unit-tested path resolver.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: App launches the daemon via the sibling `izba`

Switch the app's `RealDaemon` to the new seam so a freshly-installed app starts
the daemon itself.

**Files:**
- Modify: `app/src-tauri/src/daemon.rs:39`

- [ ] **Step 1: Make the change**

In `app/src-tauri/src/daemon.rs`, in `RealDaemon::with_client`, change the connect
call:

```rust
        if self.client.is_none() {
            self.client = Some(DaemonClient::connect_spawning_izba(&self.paths)?);
        }
```

(Previously `DaemonClient::connect(&self.paths)?`.) Also update the doc comment on
`RealDaemon` to reflect that it spawns the sibling `izba`, replacing the existing
first sentence:

```rust
/// Production `DaemonApi`: a lazily-connected `DaemonClient`. Connects via
/// `connect_spawning_izba` so a fresh install starts the sibling `izba daemon
/// run` (the app's own `current_exe` is `izba-app`, not a daemon). On any
/// send/recv error the connection is dropped so the next call reconnects (the
/// daemon idle-exits after ~5 min; polling keeps it warm but reconnect must be
/// cheap).
```

- [ ] **Step 2: Verify it compiles + existing tests pass**

Run (cwd `app/src-tauri`):
```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```
Expected: builds; clippy clean; 8 tests pass (the `FakeDaemon` tests never hit the
real connect path, so they are unaffected).

- [ ] **Step 3: Commit**

```bash
git add app/src-tauri/src/daemon.rs
git commit -m "fix(app): launch the daemon via the sibling izba binary

RealDaemon now connects with connect_spawning_izba so a freshly-installed app
spawns 'izba daemon run' instead of (wrongly) trying to run itself as the
daemon. Previously the app only worked if a daemon was already running.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Rename to `izba-app` + declare the `.deb` dependency

Tauri derives the deb package name and main binary name from `productName`, which
is currently `"izba"` — colliding with the CLI package/binary. Rename to
`izba-app` and configure the deb to depend on the base `izba` package.

**Files:**
- Modify: `app/src-tauri/tauri.conf.json`

- [ ] **Step 1: Edit the config**

Set `productName` and replace the `bundle` block in
`app/src-tauri/tauri.conf.json`. The window title stays `"izba"` (in
`app.windows[].title`), so only the bundle/binary identity changes. Final file:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "izba-app",
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
    "security": {
      "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    }
  },
  "bundle": {
    "active": true,
    "targets": ["deb"],
    "linux": {
      "deb": {
        "depends": ["izba"]
      }
    }
  }
}
```

- [ ] **Step 2: Build the `.deb` and verify naming + dependency**

With the toolchain env exported (and sandbox disabled if crates.io is needed):
```bash
cd app
npm ci
npm run tauri -- build --bundles deb
```
Expected: build succeeds; a `.deb` appears under
`app/src-tauri/target/release/bundle/deb/`.

Then inspect it:
```bash
DEB=$(ls app/src-tauri/target/release/bundle/deb/*.deb)
echo "$DEB"
dpkg-deb --info "$DEB" | grep -E 'Package|Version|Depends'
dpkg-deb --contents "$DEB" | grep -E 'izba-app|/usr/bin/'
```
Expected:
- filename + `Package: izba-app`
- `Depends:` line **contains `izba`** (alongside Tauri's auto webkit/gtk deps)
- contents include `./usr/bin/izba-app`
- **no** `/usr/bin/izba` (no collision with the base package)

- [ ] **Step 3: Commit (config only — do not commit build output)**

```bash
git add app/src-tauri/tauri.conf.json
git commit -m "build(app): rename productName to izba-app; deb depends on izba

Tauri derives the deb package + main binary name from productName; 'izba'
collided with the CLI package and /usr/bin/izba. Rename to izba-app and declare
Depends: izba so the base package (daemon + VM artifacts) installs first. Window
title stays 'izba'.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: GUI as an optional Windows installer component

Fold `izba-app.exe` into the existing Inno Setup installer as an optional `gui`
component (no separate MSI). Core CLI/runtime files become the fixed `cli`
component.

**Files:**
- Modify: `packaging/windows/izba.iss`

- [ ] **Step 1: Update the `.iss`**

Edit `packaging/windows/izba.iss`. Update the stage-layout comment, add a
`[Components]` section, tag the `[Files]` entries with components, add the new
GUI file, and add a Start-Menu icon. Replace the comment header's expected-layout
block and the `[Files]` section, and insert `[Components]`/`[Icons]`:

Change the expected-layout comment (lines 4-9) to add the GUI binary:
```inno
; Expected stage layout:
;   <StageDir>\bin\izba.exe
;   <StageDir>\bin\izba-app.exe          (GUI; optional component)
;   <StageDir>\bin\libexec\openvmm.exe
;   <StageDir>\bin\libexec\mkfs.erofs.exe
;   <StageDir>\artifacts\vmlinux
;   <StageDir>\artifacts\initramfs.cpio.gz
```

Add a `[Components]` section immediately before `[Files]`:
```inno
[Components]
Name: "cli"; Description: "izba CLI + microVM runtime"; Types: full custom; Flags: fixed
Name: "gui"; Description: "izba desktop app (GUI)";     Types: full
```

Replace the `[Files]` section with component-tagged entries plus the GUI binary:
```inno
[Files]
Source: "{#StageDir}\bin\izba.exe";      DestDir: "{app}\bin";         Flags: ignoreversion;                 Components: cli
Source: "{#StageDir}\bin\libexec\*";     DestDir: "{app}\bin\libexec"; Flags: ignoreversion recursesubdirs;  Components: cli
Source: "{#StageDir}\artifacts\*";       DestDir: "{app}\artifacts";   Flags: ignoreversion recursesubdirs;  Components: cli
Source: "{#StageDir}\bin\izba-app.exe";  DestDir: "{app}\bin";         Flags: ignoreversion;                 Components: gui
```

Add an `[Icons]` section immediately after `[Files]` (before `[Registry]`):
```inno
[Icons]
Name: "{group}\izba"; Filename: "{app}\bin\izba-app.exe"; Components: gui
```

Leave `[Setup]`, `[Registry]`, and `[Code]` unchanged. (`Types: full custom`
keeps the default install = everything, while letting a user uncheck the GUI.
`DisableProgramGroupPage=yes` in `[Setup]` still allows `[Icons]` to use the
default `{group}`.)

- [ ] **Step 2: Lint the `.iss` for the wiring**

There is no Inno compiler on Linux; verify the structural invariants by grep:
```bash
grep -n 'Name: "gui"' packaging/windows/izba.iss
grep -n 'izba-app.exe' packaging/windows/izba.iss
grep -c 'Components: cli' packaging/windows/izba.iss   # expect 3
grep -n 'Components: gui' packaging/windows/izba.iss   # expect 2 (Files + Icons)
```
Expected: the `gui` component is declared, `izba-app.exe` is referenced under
`gui`, all three core file lines carry `Components: cli`, and the GUI appears in
both `[Files]` and `[Icons]`. (Full compile is validated by the Release workflow
run in Task 6.)

- [ ] **Step 3: Commit**

```bash
git add packaging/windows/izba.iss
git commit -m "feat(packaging): ship the GUI as an optional Windows installer component

izba-app.exe is folded into the existing Inno Setup installer as an optional
'gui' component (core CLI/runtime become the fixed 'cli' component), plus a
Start-Menu shortcut. One installer, UI opt-in — no separate MSI.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Release wiring (build + attach the app)

Add release jobs that build the app `.deb` (Linux) and `izba-app.exe` (Windows),
feed the exe into the existing Windows installer job, and attach the `.deb` to the
GitHub Release.

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Add the app build jobs**

In `.github/workflows/release.yml`, add two new jobs after the existing
`izba-linux-bin` job (and before `package-deb`):

```yaml
  app-linux-deb:
    name: izba-app (.deb)
    needs: version
    runs-on: ubuntu-22.04
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Install Tauri system deps
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
            librsvg2-dev build-essential file libxdo-dev libssl-dev patchelf
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: app-deb
          workspaces: app/src-tauri
      - name: Build the .deb
        working-directory: app
        run: |
          npm ci
          npm run tauri -- build --bundles deb
      - name: Collect the .deb
        run: |
          mkdir -p dist
          cp app/src-tauri/target/release/bundle/deb/*.deb dist/
          ls -la dist
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-app-deb
          path: dist/*.deb
          if-no-files-found: error

  app-windows-build:
    name: izba-app.exe (windows)
    needs: version
    runs-on: windows-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: app-win-build
          workspaces: app/src-tauri
      - name: Build izba-app.exe
        working-directory: app
        run: |
          npm ci
          npm run tauri -- build --no-bundle
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-app-exe
          path: app/src-tauri/target/release/izba-app.exe
          if-no-files-found: error
```

- [ ] **Step 2: Feed `izba-app.exe` into the Windows installer**

In the existing `package-windows` job, change its `needs:` line to include the new
build job, and add a download step that stages the exe into `stage/bin/`.

Change:
```yaml
  package-windows:
    name: Build Windows installer
    needs: [version, artifacts]
```
to:
```yaml
  package-windows:
    name: Build Windows installer
    needs: [version, artifacts, app-windows-build]
```

Add this download step right after the `izba-windows-bundle` download step (the
one with `name: izba-windows-bundle` / `path: stage`), so `izba-app.exe` lands in
`stage/bin/` where the `.iss` expects it:
```yaml
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-app-exe
          path: stage/bin
```

- [ ] **Step 3: Attach the app `.deb` to the Release**

In the existing `release` job, change its `needs:` line and add a download step.

Change:
```yaml
  release:
    name: Attach to GitHub Release
    needs: [version, package-deb, package-windows]
```
to:
```yaml
  release:
    name: Attach to GitHub Release
    needs: [version, package-deb, package-windows, app-linux-deb]
```

Add this download step alongside the existing `izba-deb` / `izba-windows-installer`
downloads (into the same `rel` dir):
```yaml
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-app-deb
          path: rel
```

And add the app `.deb` glob to the `files:` list of the
`softprops/action-gh-release` step:
```yaml
          files: |
            rel/izba_*_amd64.deb
            rel/izba-app_*_amd64.deb
            rel/izba-setup-*.exe
            rel/SHA256SUMS
```
(The `SHA256SUMS` step already globs `rel/*`, so the app `.deb` is hashed
automatically.)

- [ ] **Step 4: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('yaml ok')"
```
Expected: `yaml ok`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): build + attach the desktop app to releases

Adds app-linux-deb (izba-app .deb) and app-windows-build (izba-app.exe) jobs;
the exe feeds the existing Windows installer's optional GUI component, and the
.deb is attached to the GitHub Release alongside the CLI artifacts.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

- [ ] Run the full app gate locally one more time (toolchain env exported):
```bash
( cd app && npm ci && npm run build && npm run test )
( cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test )
```
Expected: all green.

- [ ] Confirm the six **core** gates are untouched (the app is still excluded from
  the workspace):
```bash
cargo metadata --format-version 1 --no-deps | python3 -c "import json,sys; m=json.load(sys.stdin); names=[p['name'] for p in m['packages']]; assert 'izba-app' not in names, names; print('core workspace clean:', names)"
```
Expected: prints the five core crates, no `izba-app`.

- [ ] Confirm six clean commits on the branch:
```bash
git log --oneline origin/main..HEAD
```
Expected (newest first): release wiring, windows component, izba-app rename,
app spawn fix, core seam, app.yml — plus the spec commit.

- [ ] Hand off to `superpowers:finishing-a-development-branch` to push + open the PR.

---

## Notes / known limitations (documented, not bugs)

- The app `.deb` version comes from `tauri.conf.json` (`0.1.0`), not the release
  `version` job output, so a tagged release's app `.deb` may read `0.1.0` while
  the CLI `.deb` reads the tag. Aligning them (injecting the tag into
  `tauri.conf.json` during the release build) is a future nicety, out of scope.
- The Linux launcher entry's display `Name=` is `izba-app` (from `productName`).
  A prettier `Name=izba` via a `desktopTemplate` is cosmetic and deferred.
- `connect_spawning_izba` is exercised end-to-end (fresh daemon spawn) only by
  manual testing; CI covers the resolver + compile path.
