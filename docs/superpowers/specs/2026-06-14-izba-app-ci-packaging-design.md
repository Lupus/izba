# izba Desktop App — CI & Packaging (Plan 6) Design

**Date:** 2026-06-14
**Status:** Approved
**Predecessor:** [2026-06-14-izba-desktop-app-design.md](2026-06-14-izba-desktop-app-design.md) (M1 walking skeleton, merged)

## Problem

The M1 Tauri app (`app/`) was merged with CI **bypassed** (`gh pr merge --admin`):
`app/src-tauri` is excluded from the cargo workspace, and no workflow builds or
tests the app. Nothing in CI guards the GUI today. Separately, the app is not
packaged for end users, and it has a latent first-run bug: it cannot start the
daemon on a clean machine.

This sub-project closes all three gaps:

1. **CI gate** — a dedicated workflow that lints + tests the app (frontend and
   backend) on Linux and Windows, kept separate from the six core gates.
2. **Packaging** — a Linux `.deb` and Windows installer integration so the GUI
   ships to users.
3. **Daemon-spawn fix** — make the packaged app launch `izba daemon run` on
   first run instead of (wrongly) trying to run itself as the daemon.

## Decisions (locked during brainstorming)

- **No macOS** for now.
- **Linux:** a *separate* `izba-app_<ver>_amd64.deb` that `Depends: izba` (the
  base package that ships the CLI, daemon, and VM artifacts). Daemon installed
  first via the dependency.
- **Windows:** fold the GUI into the *existing* Inno Setup installer as an
  **optional component**, not a separate Tauri MSI. One installer, UI opt-in.
- **CI:** Linux **and** Windows, **always-on** (every PR + push to `main`),
  matching `ci.yml`'s trigger.
- **Include the daemon-spawn fix** so a freshly-installed app works end-to-end.
- **One branch**, clean isolated commits per logical change.

## Load-bearing facts (verified against the code)

- `DaemonClient::connect` (used by the app's `RealDaemon`,
  `app/src-tauri/src/daemon.rs:39`) auto-spawns the daemon via
  `std::env::current_exe()` (`crates/izba-core/src/daemon/client.rs:281`). For
  the GUI, `current_exe()` is `izba-app`, **not** `izba` — so on a machine with
  no running daemon it would try `izba-app daemon run` and fail. M1 only worked
  in manual testing because a daemon was already running from prior CLI use.
- The injectable-spawner seam `connect_with(paths, spawner, version)` exists but
  is **private** (`fn`, not `pub fn`). A new public seam is required.
- The base `.deb` package name is **`izba`** (`packaging/debian/control.template`).
- `tauri.conf.json` has `productName: "izba"`. Tauri's deb bundler derives the
  package name and main binary name from `productName`, which would **collide**
  with the base `izba` package and `/usr/bin/izba`. Must be renamed.
- The Cargo package and bin target are already `izba-app`
  (`app/src-tauri/Cargo.toml`).
- Existing CI conventions (`.github/workflows/ci.yml`, `release.yml`): SHA-pinned
  actions with version comments, `Swatinem/rust-cache` with a `prefix-key`,
  `actions/checkout@9f69817…`. The app `.deb` and the CLI `.deb` build on
  `ubuntu-22.04` (glibc 2.35) for forward-compatible runtime linkage.
- Tauri Linux system deps (already installed locally, must be installed in CI):
  `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`
  plus `build-essential curl wget file libxdo-dev libssl-dev patchelf`.

## Part A — App CI gate (`.github/workflows/app.yml`)

A **separate** workflow (not a job in `ci.yml`) so the six core gates stay fast
and isolated, and a heavy GTK/WebKit/node install never slows core-only CI.

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
```

**`app-linux` job** (`ubuntu-latest`):
1. `actions/checkout` (pinned SHA).
2. Install Tauri Linux system deps (apt, `--no-install-recommends`).
3. `actions/setup-node` (pinned) with Node 20 + npm cache keyed on
   `app/package-lock.json`.
4. `Swatinem/rust-cache` with `prefix-key: app-linux` and
   `workspaces: app/src-tauri` (the app is outside the root workspace).
5. `npm ci` (cwd `app`).
6. `npm run build` — runs `tsc` then `vite build` (typecheck + frontend build;
   see `app/package.json` `build` script). If `build` does not run `tsc`, add a
   `tsc --noEmit` step explicitly.
7. `npx vitest run` (cwd `app`).
8. Backend, cwd `app/src-tauri`: `cargo fmt --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`.

**`app-windows` job** (`windows-latest`):
- Same npm steps (no GTK deps — Windows uses WebView2).
- `Swatinem/rust-cache` with `prefix-key: app-windows`.
- Backend: `cargo clippy --all-targets -- -D warnings` + `cargo test` in
  `app/src-tauri` (skip `fmt --check`; one fmt gate on Linux is enough).

Timeouts: 30 min (Linux), 40 min (Windows), matching `ci.yml`.

## Part B — Packaging

### B0 — Rename to avoid the `izba` collision

In `app/src-tauri/tauri.conf.json` set `"productName": "izba-app"`. This makes
the bundled binary `izba-app`(`.exe`) and the deb package `izba-app`, both
distinct from the CLI's `izba`. The in-window title stays `"izba"` (set in
`app.windows[].title`). A nicer launcher `Name=` via a `desktopTemplate` is a
future cosmetic, out of scope here.

### B1 — Linux `.deb`

Build with Tauri's own deb bundler: `npm ci` then
`npx tauri build --bundles deb` (cwd `app`), on `ubuntu-22.04`. Tauri emits
`app/src-tauri/target/release/bundle/deb/izba-app_<ver>_amd64.deb` with the
desktop entry, icons, and auto-detected `libwebkit2gtk-4.1-0` / `libgtk-3-0`
dependencies.

Add the dependency on the base package via `tauri.conf.json`:

```json
"bundle": {
  "active": true,
  "targets": ["deb"],
  "linux": { "deb": { "depends": ["izba"] } }
}
```

(Tauri merges these with its auto-detected library deps.) The base `izba`
package provides `/usr/bin/izba` (daemon launcher) and the VM artifacts.

### B2 — Windows optional component

The GUI does **not** get a separate installer. Build just the binary with
`npx tauri build --no-bundle` (cwd `app`) on `windows-latest`, producing
`app/src-tauri/target/release/izba-app.exe` (frontend embedded; relies on the
system WebView2 runtime, present on Windows 11).

Extend `packaging/windows/izba.iss`:

```inno
[Components]
Name: "cli"; Description: "izba CLI + microVM runtime"; Types: full custom; Flags: fixed
Name: "gui"; Description: "izba desktop app (GUI)";     Types: full

[Files]
; existing CLI/runtime files gain: Components: cli
Source: "{#StageDir}\bin\izba.exe"; DestDir: "{app}\bin"; Flags: ignoreversion; Components: cli
; ... (libexec, artifacts) ... ; Components: cli
; new, optional:
Source: "{#StageDir}\bin\izba-app.exe"; DestDir: "{app}\bin"; Flags: ignoreversion; Components: gui

[Icons]
Name: "{group}\izba"; Filename: "{app}\bin\izba-app.exe"; Components: gui
```

`Types: full custom` keeps the existing default (everything) while letting a
user uncheck the GUI. The release `package-windows` job stages
`izba-app.exe` into `<StageDir>\bin\` before invoking ISCC.

### B3 — Release wiring (`.github/workflows/release.yml`)

- **`app-linux-deb`** job (`ubuntu-22.04`, needs nothing from `gate` beyond
  source): install Tauri deps + Node, `npm ci`, `npx tauri build --bundles deb`,
  rename/collect to `dist/`, `upload-artifact` name `izba-app-deb`.
- **`app-windows-build`** job (`windows-latest`): `npm ci`,
  `npx tauri build --no-bundle`, `upload-artifact` name `izba-app-exe`
  (the `izba-app.exe`).
- **`package-windows`** gains `needs: app-windows-build`, downloads
  `izba-app-exe` into `stage/bin/`, so ISCC bundles it as the `gui` component.
- **`release`** job gains `needs: app-linux-deb` and downloads + attaches
  `izba-app_*_amd64.deb` to the GitHub Release alongside the CLI artifacts; the
  SHA256SUMS step already globs the `rel/` dir.

The app `.deb` version follows the existing `version` job output.

## Part C — Daemon-spawn fix

Add a public seam to `izba-core` and use it from the app.

**`crates/izba-core/src/daemon/client.rs`:**

```rust
/// Connect for embedders (the GUI) whose own `current_exe` is NOT `izba`:
/// spawn the sibling `izba` binary's daemon rather than re-exec ourselves.
/// Resolves `izba`/`izba.exe` next to the current executable first, then PATH.
pub fn connect_spawning_izba(paths: &Paths) -> anyhow::Result<DaemonClient> {
    Self::connect_with(paths, &spawn_sibling_izba, &transport::daemon_version())
}

fn spawn_sibling_izba(paths: &Paths) -> anyhow::Result<()> {
    let exe = resolve_izba_binary();
    let cmd = CommandSpec {
        argv: vec![exe, "daemon".to_string(), "run".to_string()],
    };
    procmgr::spawn_detached(&cmd, &paths.daemon_log())?;
    Ok(())
}

/// `<dir of current_exe>/izba[.exe]` if it exists, else bare `izba`
/// (OS resolves via PATH).
fn resolve_izba_binary() -> String { /* … */ }
```

`resolve_izba_binary` is independently unit-testable (sibling-present → absolute
path; sibling-absent → `"izba"`), using a tempdir and an injected
"current exe dir" — extract a small helper
`resolve_izba_in(dir: &Path) -> String` so the test does not depend on the real
`current_exe()`.

**`app/src-tauri/src/daemon.rs`:** `RealDaemon::with_client` connects via
`DaemonClient::connect_spawning_izba(&self.paths)` instead of `connect`. The
`FakeDaemon` path and existing tests are unaffected (they never hit the seam).

This keeps all detached-spawn/logging logic inside `izba-core` (the app does not
reimplement `spawn_detached`).

## Testing strategy

- **Part A:** the workflow itself is the test; validated by a real CI run on the
  PR. Locally, the implementer runs the exact commands (`npm ci`, `npm run
  build`, `vitest run`, `cargo fmt/clippy/test` in `app/src-tauri`) to confirm
  they pass before committing.
- **Part B:** `tauri build --bundles deb` produces a `.deb` locally on Linux;
  the implementer inspects `dpkg-deb --info`/`--contents` to confirm the package
  name is `izba-app`, `Depends:` includes `izba`, and the binary is
  `/usr/bin/izba-app`. The `.iss` change is validated by the release workflow
  run (and locally if ISCC is available; otherwise by review of the component
  flags).
- **Part C:** unit test `resolve_izba_in` (both branches). The full spawn is
  covered by the existing `connect_with` test pattern in `client.rs`; add a test
  that `connect_spawning_izba` exists and compiles against the public API. End-
  to-end first-run is validated manually by the user on a clean daemon state.

## Commit plan (clean, isolated)

1. `ci(app): add app.yml — Linux+Windows lint/test gate` (Part A).
2. `feat(core): connect_spawning_izba seam for non-izba embedders` (Part C core).
3. `fix(app): launch the daemon via the sibling izba binary` (Part C app).
4. `build(app): rename productName to izba-app; deb depends on izba` (B0+B1 config).
5. `feat(packaging): izba-app .deb + GUI as optional Windows component` (B2 +
   build glue).
6. `ci(release): build + attach the desktop app to releases` (B3).

(Order chosen so each commit is independently reviewable; A first so the gate
exists before later commits, then the functional fix, then packaging.)

## Out of scope

- macOS bundling/signing.
- Code signing / notarization on any platform.
- A custom `.desktop` `Name=`/launcher polish (`desktopTemplate`).
- Auto-update / Tauri updater.
- Shipping the GUI as the *default* Windows selection beyond `Types: full`.
