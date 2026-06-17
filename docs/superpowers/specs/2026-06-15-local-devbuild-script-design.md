# Local dev build script (`hack/devbuild.sh`) — design

> **⚠️ SUPERSEDED 2026-06-16.** The local-build approach described here loaded
> the laptop (per-worktree Rust `target/` dirs on Linux *and* the Windows host,
> Tauri/npm builds ×N worktrees → disk + time blowup). `hack/devbuild.sh` was
> rewritten into a **CI dispatch + download helper**; the installer set is now
> built entirely in CI. See
> [2026-06-16-ci-dev-installer-artifacts-design.md](2026-06-16-ci-dev-installer-artifacts-design.md).
> This document is retained for history only — do **not** reintroduce the local
> heavy-build flow.

**Status:** SUPERSEDED (see banner). Originally approved 2026-06-15.

## Goal

A single script, run from a WSL2 worktree, that produces a **fresh Windows
installer (`izba-setup-*.exe`) + Linux `.deb` set (`izba_*.deb` CLI +
`izba-app_*.deb` GUI)** for fast local iteration — much faster than the
`release.yml` workflow, with **correct git version attribution** baked into
every binary, and **safe to run concurrently** with other agents on the same
WSL2 instance + Windows host.

## Why not cross-compile (rejected)

A full Windows installer cannot come from WSL2 cross-compilation: the Tauri GUI
(`izba-app.exe`) needs a native Windows (WebView2 + bundler) build; Inno Setup
(`ISCC.exe`) is Windows-only; and `izba.exe` is **MSVC source-of-truth** (a
`windows-gnu` cross build is the "works differently" divergence we're avoiding).
Instead: a **hybrid native orchestrator** — WSL2 builds Linux natively and
drives the Windows host over `powershell.exe` interop to build the Windows bits
natively (MSVC). Same machine, no CI queue.

## Architecture — five stages

1. **Identity.** Derive `VERSION` and `VERGEN_GIT_*` from the worktree git.
2. **Ensure stable artifacts** (fetch-from-CI first, cached).
3. **Build the fast bits** (`izba`, `izba-app` — both platforms).
4. **Package** (debs + Inno installer).
5. **Collect** into `dist/local/<ts>-<sha>/` + `latest` symlink + `SHA256SUMS` +
   `manifest.txt`.

### Stage 1 — Identity & git attribution (CRITICAL — the "v0.1.0 unknown" fix)

Compute from the worktree (git is available in the worktree):
```sh
SHORT=$(git rev-parse --short HEAD)
SHA=$(git rev-parse HEAD)
DESCRIBE=$(git describe --tags --always --dirty)
CDATE=$(git show -s --format=%cs HEAD)          # commit date, YYYY-MM-DD
DIRTY=$(git diff --quiet || echo '-dirty')
BASE=$(grep -m1 '^version' crates/izba-cli/Cargo.toml | cut -d'"' -f2)
VERSION="${BASE}~git${SHORT}${DIRTY:+.dirty}"   # e.g. 0.1.0~gitb7ae91f or ...f.dirty
```
`VERSION` feeds the deb/installer filenames + Inno `/DMyAppVersion`.

**Baked-in build metadata** comes from `vergen-gitcl` at compile time
(`crates/izba-core/build.rs`, `app/src-tauri/build.rs`); `build_info.rs` reads
`VERGEN_GIT_DESCRIBE`, `VERGEN_GIT_SHA`, `VERGEN_GIT_COMMIT_DATE`,
`VERGEN_BUILD_TIMESTAMP`, `VERGEN_RUSTC_SEMVER`, `VERGEN_CARGO_TARGET_TRIPLE`,
`IZBA_PROFILE` via `option_env!`.

- **Linux build runs in the worktree → git is present → vergen produces correct
  attribution natively.** No injection needed (still set `IZBA_PROFILE=release`
  via the normal `--release`).
- **Windows build runs on a git-LESS fast copy** (see Stage 3) → vergen emits
  nothing for git. Inject attribution via a generated `.cargo/config.toml`
  `[env]` table in the copy (cargo `[env]` with `force = true` sets the build
  environment that `option_env!` reads):
  ```toml
  [env]
  VERGEN_GIT_SHA = { value = "<SHA>", force = true }
  VERGEN_GIT_DESCRIBE = { value = "<DESCRIBE>", force = true }
  VERGEN_GIT_COMMIT_DATE = { value = "<CDATE>", force = true }
  ```
  **MANDATORY VERIFICATION:** after the Windows `izba.exe` builds, the script
  runs `izba.exe version` (or `--version`) and asserts the output contains
  `<SHORT>` — if not, the attribution mechanism failed and the build must abort
  with a clear error (do NOT silently ship an `unknown` build). The implementer
  must confirm this works before declaring done; if cargo `[env]` proves
  insufficient, fall back to also exporting the `VERGEN_*` vars in the
  PowerShell build environment, and re-verify.

### Stage 2 — Stable artifacts: fetch-from-CI, cached

Shared cache root: `~/.cache/izba/devbuild/` (override `IZBA_DEVBUILD_CACHE`).

**CI-built artifacts** (`vmlinux`, `initramfs.cpio.gz` with mke2fs+nft already
embedded, `mkfs.erofs.exe`):
- **Match check** against `origin/main` (after `git fetch origin main`):
  - kernel inputs clean: `git diff --quiet origin/main -- hack/kernel.config hack/build-kernel.sh`
  - initramfs inputs clean: `git diff --quiet origin/main -- crates/izba-init hack/build-initramfs.sh hack/build-mke2fs.sh hack/build-nft.sh`
- If **clean**: resolve the newest green run and download (deterministic builds ⇒
  byte-identical to what local would produce):
  ```sh
  RUN=$(gh run list --workflow=artifacts.yml --branch main --status success \
        -L1 --json databaseId,headSha -q '.[0]')
  # cache dir keyed by run id:
  CI=~/.cache/izba/devbuild/ci/<databaseId>
  # if missing: gh run download <databaseId> -n vmlinux -D $CI ; -n initramfs ; -n mkfs-erofs-windows
  ```
  Artifact names are `vmlinux`, `initramfs`, `mkfs-erofs-windows` (verify against
  `.github/workflows/_artifacts.yml` upload steps at implementation time).
- If **dirty** (you edited `kernel.config` or `izba-init`): default = **build
  locally** via the existing `hack/build-kernel.sh` / `hack/build-initramfs.sh`
  (+ `build-mke2fs.sh`/`build-nft.sh`), with a loud warning that this is the slow
  path and "push to main + let CI build" is the alternative. `--fetch-only`
  turns the dirty case into a hard error instead; `--build-heavy` forces local
  even when clean.

**Pinned third-party binaries** (cached once under
`~/.cache/izba/devbuild/pinned/`, keyed by the pin in their scripts):
- `cloud-hypervisor`, `virtiofsd` via `hack/fetch-artifacts.sh`
  (`IZBA_BIN_DIR=<pinned cache>`).
- `openvmm.exe` via `hack/fetch-openvmm.sh` (needs `gh` + the pinned RUN_ID).

All cache writes go through a per-artifact `flock` + atomic `mv` so concurrent
runs never see a half-written file.

### Stage 3 — Build the fast bits

**Linux (native, in the worktree, incremental `target/`):**
- `izba`: `cargo build --release -p izba-cli` → `target/release/izba`.
- `izba-app` deb: `cd app && npm ci && npm run tauri -- build --bundles deb`
  (needs the webkit2gtk dev stack — already installed here) →
  `app/src-tauri/target/release/bundle/deb/*.deb`. (Tauri stamps its internal
  version from `tauri.conf.json` = `0.1.0`; we rename the output file to
  `izba-app_${VERSION}_amd64.deb` for consistency — the internal control version
  staying `0.1.0` is an accepted cosmetic gap, the dir name carries the sha.)

**Windows (native MSVC, via `powershell.exe` interop):**
- A **persistent per-worktree** build dir on NTFS for incremental cargo/npm:
  `C:\Users\<winuser>\.izba-devbuild\<worktree-key>\` (WSL path
  `/mnt/c/Users/<winuser>/.izba-devbuild/<worktree-key>`), `worktree-key` = the
  worktree directory basename. `<winuser>` from `powershell.exe -c '$env:USERNAME'`.
- Sync source into it each run, preserving `target/`+`node_modules` for
  incrementality:
  `rsync -a --delete --exclude target --exclude node_modules --exclude .git
   <worktree>/{crates,app,Cargo.toml,Cargo.lock,rust-toolchain.toml} <winbuilddir>/`
  (copy the workspace-root `Cargo.toml`/`Cargo.lock`/`rust-toolchain.toml` — the
  `crates/*` inherit `edition`/`license` from the root `[workspace.package]`;
  omitting it is the failure we already hit.)
- Write the `.cargo/config.toml` `[env]` attribution block (Stage 1) into
  `<winbuilddir>/.cargo/config.toml`.
- Build via PowerShell with cwd inside the copy:
  - `izba.exe`: `cargo build --release -p izba-cli` → `target/release/izba.exe`.
  - `izba-app.exe`: `cd app; npm ci; npm run tauri -- build --no-bundle` →
    `app/src-tauri/target/release/izba-app.exe`.
- **Verify attribution** (Stage 1 mandatory check) on the built `izba.exe`.

### Stage 4 — Package

**Linux `izba_*.deb`:**
```sh
IZBA_BIN=target/release/izba \
IZBA_CH=<pinned>/cloud-hypervisor IZBA_VIRTIOFSD=<pinned>/virtiofsd \
IZBA_VMLINUX=<ci>/vmlinux IZBA_INITRAMFS=<ci>/initramfs.cpio.gz \
VERSION=$VERSION OUT_DIR=<run-out> \
  packaging/build-deb.sh
```
(`build-deb.sh` validates all five inputs exist; writes
`<run-out>/izba_${VERSION}_amd64.deb`.)

**Windows `izba-setup-*.exe`** (on the host, via interop): stage into a per-run
Windows dir, then run Inno:
```
<stage>\bin\izba.exe                      (from the Windows build copy)
<stage>\bin\izba-app.exe                  (from the Windows build copy)
<stage>\bin\libexec\openvmm.exe           (pinned cache)
<stage>\bin\libexec\mkfs.erofs.exe        (CI cache)
<stage>\artifacts\vmlinux                 (CI cache)
<stage>\artifacts\initramfs.cpio.gz       (CI cache)
```
```powershell
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" `
  "/DMyAppVersion=$VERSION" "/DStageDir=$stage" "/O$winout" `
  <copy>\packaging\windows\izba.iss
# → $winout\izba-setup-$VERSION.exe
```
Copy `izba-setup-*.exe` back into the run output dir.

### Stage 5 — Collect

```
dist/local/<UTC-ISO-ts>-<SHORT>[-dirty]/
  izba-setup-<VERSION>.exe
  izba_<VERSION>_amd64.deb
  izba-app_<VERSION>_amd64.deb
  SHA256SUMS
  manifest.txt        # VERSION, full SHA, describe, per-artifact "cache-hit | built | fetched(run <id>)"
dist/local/latest -> <that dir>     # relative symlink
```
`dist/` is gitignored. `--clean` removes `dist/local/*` except the newest
`--keep N` (default keep all; `--clean` alone wipes all but `latest`).

## Concurrency model

- **Different worktrees**: fully parallel — separate `target/`, separate
  `mktemp -d` WSL staging, separate Windows build dir (`<worktree-key>`),
  separate run output dir. Sole contention is the shared cache, guarded by
  `flock` + atomic publish.
- **Same worktree, concurrent runs**: a per-worktree `flock` on
  `~/.cache/izba/devbuild/locks/<worktree-key>.lock` serializes them (avoids
  `target/` and Windows-copy corruption). Non-blocking acquire with a clear
  "another devbuild is running in this worktree" message, or `--wait` to block.
- All `/mnt/c` writes and `powershell.exe` calls run unsandboxed (the script is
  a dev tool; document that it must run outside the agent Bash sandbox, like the
  KVM/Windows suites).

## Flags

`--windows-only` | `--linux-only` | `--no-gui` (skip izba-app both sides) |
`--refresh-{kernel,initramfs,vmm}` (force re-fetch/rebuild that artifact) |
`--build-heavy` (force local kernel/initramfs build even if clean vs main) |
`--fetch-only` (hard-error instead of local-building heavy artifacts) |
`--clean [--keep N]` | `--wait` | `-h/--help`.

## Error handling

- Windows host unreachable (`powershell.exe` fails) ⇒ Windows stages error with
  a clear message; `--linux-only` still works.
- Missing `gh` auth / expired CI artifacts ⇒ clear message pointing at
  `--build-heavy` or re-running CI.
- Inno Setup / Node missing on the host ⇒ named, actionable error.
- Any stage failure leaves no partial dir in `dist/local/` (build into a temp
  run dir, atomic-rename to the final name + repoint `latest` only on success).

## Validation (how the implementer proves it works)

Shell scripts aren't unit-tested here; validate by execution:
1. `bash hack/devbuild.sh --linux-only` → produces both debs in a dated dir;
   `dpkg-deb -I izba_*.deb` shows `Version: <VERSION>`; `izba version` from the
   built Linux binary shows the real short sha.
2. `bash hack/devbuild.sh --windows-only` → produces `izba-setup-*.exe`;
   **assert the built `izba.exe version` shows the real sha** (the attribution
   gate). 
3. Full run → all three artifacts + `SHA256SUMS` + `manifest.txt` + `latest`
   symlink; second run is materially faster (cache hits logged in `manifest.txt`).
4. Concurrency smoke: a second invocation in the same worktree is serialized
   (or refused with `--wait` guidance), not corrupting the first.

## Out of scope

Signing the installer; publishing anywhere; building the heavy artifacts in a
clever incremental way (we fetch them); cross-compilation.
