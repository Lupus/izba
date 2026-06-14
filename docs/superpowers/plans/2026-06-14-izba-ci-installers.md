# izba CI release packaging (.deb + Windows Inno installer) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce self-contained `izba_<version>_amd64.deb` and `izba-setup-<version>.exe` installers in CI on a `v*` tag, each installing a working izba (CLI + VMM + boot artifacts) with zero post-install fetch.

**Architecture:** Two small TDD'd `izba-core` changes make a clean install discoverable (exe-relative boot artifacts + `libexec`/env discovery of `cloud-hypervisor`/`virtiofsd`). Packaging recipes (`dpkg-deb` tree, Inno `.iss`) assemble symmetric `bin/` + `bin/libexec/` + `../artifacts` layouts. A reusable `_artifacts.yml` workflow (extracted from `artifacts.yml`) feeds a new `release.yml` that gates on the fast build/test gates, then packages and attaches both installers to a GitHub Release.

**Tech Stack:** Rust (izba-core), GitHub Actions (reusable workflows), `dpkg-deb`, Inno Setup (`iscc`), bash packaging scripts.

**Reference spec:** `docs/superpowers/specs/2026-06-14-izba-ci-installers-design.md`

---

## File Structure

**Modified (code):**
- `crates/izba-core/src/artifacts.rs` — add exe-relative boot-artifact fallback + tests (C1)
- `crates/izba-core/src/vmm/cloud_hypervisor.rs` — `VmmTools` resolution + threaded into `build_invocations` (C2)

**Created (packaging):**
- `packaging/debian/control.template`
- `packaging/build-deb.sh`
- `packaging/windows/izba.iss`

**Created/modified (CI):**
- `.github/workflows/_artifacts.yml` — reusable artifact builder (extracted)
- `.github/workflows/artifacts.yml` — slimmed to a thin caller
- `.github/workflows/release.yml` — new release pipeline

---

## Task 1: C1 — exe-relative boot-artifact fallback (`artifacts.rs`)

**Files:**
- Modify: `crates/izba-core/src/artifacts.rs`

- [ ] **Step 1: Write the failing tests**

Append this test module to the end of `crates/izba-core/src/artifacts.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn touch(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn both_env_overrides_win() {
        let got = locate_from(
            Some(PathBuf::from("/k")),
            Some(PathBuf::from("/i")),
            Path::new("/no/data"),
            Some(Path::new("/no/exe/bin")),
        )
        .unwrap();
        assert_eq!(got.kernel, PathBuf::from("/k"));
        assert_eq!(got.initramfs, PathBuf::from("/i"));
    }

    #[test]
    fn one_env_override_is_an_error() {
        let err = locate_from(
            Some(PathBuf::from("/k")),
            None,
            Path::new("/no/data"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be set together"));
    }

    #[test]
    fn data_dir_used_when_populated() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let got = locate_from(None, None, &data, None).unwrap();
        assert_eq!(got.kernel, data.join("vmlinux"));
        assert_eq!(got.initramfs, data.join("initramfs.cpio.gz"));
    }

    #[test]
    fn exe_relative_used_when_data_dir_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Layout: <root>/bin/izba  ->  artifacts at <root>/artifacts
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let art = tmp.path().join("artifacts");
        touch(&art, "vmlinux");
        touch(&art, "initramfs.cpio.gz");
        let empty_data = tmp.path().join("empty-data");
        let got = locate_from(None, None, &empty_data, Some(&bin)).unwrap();
        assert_eq!(got.kernel, art.join("vmlinux"));
        assert_eq!(got.initramfs, art.join("initramfs.cpio.gz"));
    }

    #[test]
    fn data_dir_wins_over_exe_relative() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        touch(&data, "vmlinux");
        touch(&data, "initramfs.cpio.gz");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let art = tmp.path().join("artifacts");
        touch(&art, "vmlinux");
        touch(&art, "initramfs.cpio.gz");
        let got = locate_from(None, None, &data, Some(&bin)).unwrap();
        assert_eq!(got.kernel, data.join("vmlinux"));
    }

    #[test]
    fn nothing_found_is_an_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = locate_from(None, None, &tmp.path().join("nope"), None).unwrap_err();
        assert!(err.to_string().contains("boot artifacts not found"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core --lib artifacts::`
Expected: FAIL — `locate_from` is not defined (compile error).

- [ ] **Step 3: Refactor `locate` into a pure `locate_from` + add the fallback**

Replace the entire body of `crates/izba-core/src/artifacts.rs` (keep the `//!` module doc on line 1) with:

```rust
//! Locating the shared boot artifacts (kernel + initramfs).

use anyhow::bail;
use std::path::{Path, PathBuf};

use crate::paths::Paths;
use crate::sandbox::Artifacts;

/// Locate boot artifacts. Resolution order:
/// 1. `$IZBA_KERNEL` + `$IZBA_INITRAMFS` overrides (both or neither).
/// 2. `<data>/artifacts/{vmlinux,initramfs.cpio.gz}` (per-user data dir).
/// 3. `<exe-dir>/../artifacts/{...}` (a self-contained package install:
///    binary at `<root>/bin/izba`, artifacts at `<root>/artifacts`).
pub fn locate(paths: &Paths) -> anyhow::Result<Artifacts> {
    let kernel = std::env::var_os("IZBA_KERNEL").map(PathBuf::from);
    let initramfs = std::env::var_os("IZBA_INITRAMFS").map(PathBuf::from);
    let exe = std::env::current_exe().ok();
    let exe_dir = exe.as_deref().and_then(Path::parent);
    locate_from(kernel, initramfs, &paths.artifacts_dir(), exe_dir)
}

/// Pure core of [`locate`], factored for testing (no process env / current_exe).
fn locate_from(
    kernel_env: Option<PathBuf>,
    initramfs_env: Option<PathBuf>,
    data_dir: &Path,
    exe_dir: Option<&Path>,
) -> anyhow::Result<Artifacts> {
    match (kernel_env, initramfs_env) {
        (Some(kernel), Some(initramfs)) => return Ok(Artifacts { kernel, initramfs }),
        (Some(_), None) | (None, Some(_)) => {
            bail!("IZBA_KERNEL and IZBA_INITRAMFS must be set together (or neither)")
        }
        (None, None) => {}
    }

    // 2. per-user data dir, then 3. exe-relative `../artifacts`.
    let exe_relative = exe_dir
        .and_then(Path::parent)
        .map(|root| root.join("artifacts"));
    let candidates = std::iter::once(data_dir.to_path_buf()).chain(exe_relative);
    for dir in candidates {
        let kernel = dir.join("vmlinux");
        let initramfs = dir.join("initramfs.cpio.gz");
        if kernel.is_file() && initramfs.is_file() {
            return Ok(Artifacts { kernel, initramfs });
        }
    }

    bail!(
        "boot artifacts not found in {} (or next to the izba binary) — run \
         hack/fetch-artifacts.sh or set IZBA_KERNEL and IZBA_INITRAMFS",
        data_dir.display()
    );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core --lib artifacts::`
Expected: PASS (6 tests).

- [ ] **Step 5: Verify no regressions + lint**

Run: `cargo test -p izba-core --lib && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/artifacts.rs
git commit -m "feat(core): exe-relative boot-artifact fallback for packaged installs

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: C2 — `libexec`/env discovery for `cloud-hypervisor` + `virtiofsd`

**Files:**
- Modify: `crates/izba-core/src/vmm/cloud_hypervisor.rs`

Threads two resolved tool paths through `build_invocations`. `find_tool` is unchanged (env override → `<exe-dir>/libexec/<name>` → `$PATH`); existing `$PATH`/dev installs keep working.

- [ ] **Step 1: Update the two existing argv tests to expect resolved paths**

In `crates/izba-core/src/vmm/cloud_hypervisor.rs`, add a `base_tools()` helper inside the `tests` module (next to `base_spec`):

```rust
    fn base_tools() -> VmmTools {
        VmmTools {
            cloud_hypervisor: PathBuf::from("/opt/izba/cloud-hypervisor"),
            virtiofsd: PathBuf::from("/opt/izba/virtiofsd"),
        }
    }
```

Then, in `ch_invocations` and `ch_invocations_multi_share`, change every
`build_invocations(&spec)` call to `build_invocations(&spec, &base_tools())`,
and in the expected `argv(&[...])` blocks replace the literal
`"virtiofsd"` (argv[0] of each virtiofsd invocation) with
`"/opt/izba/virtiofsd"` and the literal `"cloud-hypervisor"` (argv[0] of the
vmm invocation) with `"/opt/izba/cloud-hypervisor"`. There are 3 virtiofsd
argv[0] occurrences (lines ~301, ~367, ~381) and 2 cloud-hypervisor argv[0]
occurrences (lines ~316, ~396).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core --lib vmm::cloud_hypervisor`
Expected: FAIL — `VmmTools` undefined / `build_invocations` arity mismatch (compile error).

- [ ] **Step 3: Add `VmmTools` and thread it through `build_invocations`**

In `crates/izba-core/src/vmm/cloud_hypervisor.rs`:

(a) After the `Invocations` struct (around line 22), add:

```rust
/// Resolved paths to the external VMM binaries, looked up once per launch via
/// the standard discovery order (env override → `<exe-dir>/libexec/` → PATH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmTools {
    pub cloud_hypervisor: PathBuf,
    pub virtiofsd: PathBuf,
}

impl VmmTools {
    /// Resolve both binaries. Errors if either is not found.
    pub fn resolve() -> anyhow::Result<Self> {
        Ok(Self {
            cloud_hypervisor: crate::discover::find_tool(
                "IZBA_CLOUD_HYPERVISOR",
                "cloud-hypervisor",
            )?,
            virtiofsd: crate::discover::find_tool("IZBA_VIRTIOFSD", "virtiofsd")?,
        })
    }
}
```

(b) Change the signature on line 24:

```rust
pub fn build_invocations(spec: &VmSpec, tools: &VmmTools) -> Invocations {
```

(c) Replace the `virtiofsd` argv[0] (line ~35) inside the `.map(|share| ...)`:

```rust
                tools.virtiofsd.display().to_string(),
```

(d) Replace the `cloud-hypervisor` argv[0] (line ~49) in the `vmm` vec:

```rust
        tools.cloud_hypervisor.display().to_string(),
```

(e) In `launch` (around line 121), resolve tools and pass them in:

```rust
        let tools = VmmTools::resolve()?;
        let inv = build_invocations(spec, &tools);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core --lib vmm::cloud_hypervisor`
Expected: PASS.

- [ ] **Step 5: Full gates (incl. Windows cross-compile, since this module compiles for both targets)**

Run:
```bash
cargo test -p izba-core --lib
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/vmm/cloud_hypervisor.rs
git commit -m "feat(core): discover cloud-hypervisor + virtiofsd via libexec/env

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Debian package recipe (`build-deb.sh` + control template)

**Files:**
- Create: `packaging/debian/control.template`
- Create: `packaging/build-deb.sh`

- [ ] **Step 1: Write the control template**

Create `packaging/debian/control.template`:

```
Package: izba
Version: __VERSION__
Section: admin
Priority: optional
Architecture: amd64
Depends: erofs-utils, libc6
Maintainer: Konstantin Olkhovskiy <lupus@oxnull.net>
Homepage: https://github.com/Lupus/izba
Description: per-project microVM sandboxes for AI coding agents
 izba runs each project in an isolated Cloud Hypervisor microVM. This package
 bundles the izba CLI, a static cloud-hypervisor and virtiofsd, and the boot
 artifacts (kernel + initramfs) needed to launch sandboxes.
```

- [ ] **Step 2: Write `build-deb.sh`**

Create `packaging/build-deb.sh` (executable). It assembles the symmetric
`/usr/lib/izba/bin{,/libexec}` + `/usr/lib/izba/artifacts` tree, a relative
`/usr/bin/izba` symlink, and runs `dpkg-deb`. Inputs are passed as env vars so
the same script runs locally and in CI.

```bash
#!/usr/bin/env bash
# Assemble and build the izba .deb.
#
# Required env vars (absolute paths to already-built inputs):
#   IZBA_BIN        izba CLI binary (linux, glibc release)
#   IZBA_CH         static cloud-hypervisor binary
#   IZBA_VIRTIOFSD  static virtiofsd binary
#   IZBA_VMLINUX    kernel image
#   IZBA_INITRAMFS  initramfs.cpio.gz
#   VERSION         debian package version (e.g. 0.1.0 or 0.1.0~git<sha>)
# Optional:
#   OUT_DIR         where to write the .deb (default: dist/)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${IZBA_BIN:?}" "${IZBA_CH:?}" "${IZBA_VIRTIOFSD:?}"
: "${IZBA_VMLINUX:?}" "${IZBA_INITRAMFS:?}" "${VERSION:?}"
OUT_DIR="${OUT_DIR:-dist}"

for f in "$IZBA_BIN" "$IZBA_CH" "$IZBA_VIRTIOFSD" "$IZBA_VMLINUX" "$IZBA_INITRAMFS"; do
    [ -f "$f" ] || { echo "error: missing input $f" >&2; exit 1; }
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Layout (symmetric with the Windows install — see the design doc):
#   /usr/lib/izba/bin/izba
#   /usr/lib/izba/bin/libexec/{cloud-hypervisor,virtiofsd}
#   /usr/lib/izba/artifacts/{vmlinux,initramfs.cpio.gz}
#   /usr/bin/izba -> ../lib/izba/bin/izba
install -D -m 0755 "$IZBA_BIN"        "$STAGE/usr/lib/izba/bin/izba"
install -D -m 0755 "$IZBA_CH"         "$STAGE/usr/lib/izba/bin/libexec/cloud-hypervisor"
install -D -m 0755 "$IZBA_VIRTIOFSD"  "$STAGE/usr/lib/izba/bin/libexec/virtiofsd"
install -D -m 0644 "$IZBA_VMLINUX"    "$STAGE/usr/lib/izba/artifacts/vmlinux"
install -D -m 0644 "$IZBA_INITRAMFS"  "$STAGE/usr/lib/izba/artifacts/initramfs.cpio.gz"

mkdir -p "$STAGE/usr/bin"
ln -s ../lib/izba/bin/izba "$STAGE/usr/bin/izba"

mkdir -p "$STAGE/DEBIAN"
sed "s/__VERSION__/$VERSION/" packaging/debian/control.template > "$STAGE/DEBIAN/control"

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/izba_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
echo "built $DEB"
dpkg-deb --contents "$DEB"
```

- [ ] **Step 3: Make it executable**

Run: `chmod +x packaging/build-deb.sh`

- [ ] **Step 4: Smoke-test the recipe locally with stub inputs**

Run:
```bash
tmp=$(mktemp -d)
printf '#!/bin/sh\necho izba\n' > "$tmp/izba"; chmod +x "$tmp/izba"
: > "$tmp/ch"; : > "$tmp/vfsd"; : > "$tmp/vmlinux"; : > "$tmp/initramfs.cpio.gz"
IZBA_BIN="$tmp/izba" IZBA_CH="$tmp/ch" IZBA_VIRTIOFSD="$tmp/vfsd" \
  IZBA_VMLINUX="$tmp/vmlinux" IZBA_INITRAMFS="$tmp/initramfs.cpio.gz" \
  VERSION=0.0.0-test OUT_DIR="$tmp/out" packaging/build-deb.sh
dpkg-deb --info "$tmp/out/izba_0.0.0-test_amd64.deb" | grep -E 'Package|Version|Depends'
```
Expected: `built .../izba_0.0.0-test_amd64.deb`, the `--contents` lists
`./usr/lib/izba/bin/izba`, `./usr/lib/izba/bin/libexec/cloud-hypervisor`, the
symlink `./usr/bin/izba -> ../lib/izba/bin/izba`, and the artifacts; `--info`
shows `Package: izba`, `Version: 0.0.0-test`, `Depends: erofs-utils, libc6`.

(If `dpkg-deb` is absent locally, this step is verified in CI by Task 6's
`package-deb` job instead — note that and continue.)

- [ ] **Step 5: Commit**

```bash
git add packaging/debian/control.template packaging/build-deb.sh
git commit -m "feat(packaging): debian package recipe (build-deb.sh + control)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Windows Inno Setup script (`izba.iss`)

**Files:**
- Create: `packaging/windows/izba.iss`

Sources files from a prepared staging dir (`{#StageDir}`) and produces
`izba-setup-<version>.exe`, installing to `{autopf}\izba` and adding
`{app}\bin` to the system PATH.

- [ ] **Step 1: Write the `.iss`**

Create `packaging/windows/izba.iss`:

```iss
; izba Windows installer (Inno Setup).
; Build:
;   iscc /DMyAppVersion=<ver> /DStageDir=<abs path to stage> packaging\windows\izba.iss
; Expected stage layout:
;   <StageDir>\bin\izba.exe
;   <StageDir>\bin\libexec\openvmm.exe
;   <StageDir>\bin\libexec\mkfs.erofs.exe
;   <StageDir>\artifacts\vmlinux
;   <StageDir>\artifacts\initramfs.cpio.gz

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef StageDir
  #error StageDir must be defined (/DStageDir=...)
#endif

[Setup]
AppId={{B5E8F3A2-7C4D-4E1A-9B2F-1B2C3D4E5F60}
AppName=izba
AppVersion={#MyAppVersion}
AppPublisher=Konstantin Olkhovskiy
DefaultDirName={autopf}\izba
DefaultGroupName=izba
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=izba-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
ChangesEnvironment=yes

[Files]
Source: "{#StageDir}\bin\izba.exe";          DestDir: "{app}\bin";         Flags: ignoreversion
Source: "{#StageDir}\bin\libexec\*";          DestDir: "{app}\bin\libexec"; Flags: ignoreversion recursesubdirs
Source: "{#StageDir}\artifacts\*";            DestDir: "{app}\artifacts";   Flags: ignoreversion recursesubdirs

[Registry]
; Append {app}\bin to the system PATH (only if not already present).
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; \
    Check: NeedsAddPath(ExpandConstant('{app}\bin'))

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Lowercase(Param) + ';', ';' + Lowercase(OrigPath) + ';') = 0;
end;
```

- [ ] **Step 2: Validate the script parses (best-effort)**

Run (only if `iscc` is available locally; otherwise note it is validated by
Task 6's `package-windows` job and continue):
```bash
command -v iscc && iscc /Ssigntool=echo packaging/windows/izba.iss || echo "iscc not local — validated in CI"
```
Expected: either a parse run, or the "validated in CI" note.

- [ ] **Step 3: Commit**

```bash
git add packaging/windows/izba.iss
git commit -m "feat(packaging): Inno Setup installer script for Windows

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Extract reusable artifact workflow

**Files:**
- Create: `.github/workflows/_artifacts.yml`
- Modify: `.github/workflows/artifacts.yml`

- [ ] **Step 1: Create `_artifacts.yml` from the current `artifacts.yml` jobs**

Run:
```bash
cp .github/workflows/artifacts.yml .github/workflows/_artifacts.yml
```

Then in `.github/workflows/_artifacts.yml` replace the top block — everything
from `name:` down to and including the `permissions:` block (i.e. the `name`,
`on`, `concurrency`, and `permissions` keys) — with exactly:

```yaml
name: _artifacts

on:
  workflow_call:

permissions:
  contents: read
```

Leave every `jobs:` entry (kernel, mke2fs, nft, initramfs, erofs-windows,
erofs-parity, izba-windows, manifest) **unchanged**. (The `concurrency:` block
is dropped here — the caller owns concurrency.)

- [ ] **Step 2: Slim `artifacts.yml` to a thin caller**

Replace the **entire** contents of `.github/workflows/artifacts.yml` with:

```yaml
name: Artifacts

on:
  push:
    branches: [main]
    paths:
      - 'hack/**'
      - 'crates/izba-init/**'
      - 'crates/izba-cli/**'
      - 'crates/izba-core/**'
      - 'crates/izba-proto/**'
      - 'Cargo.toml'
      - 'Cargo.lock'
      - '.github/workflows/artifacts.yml'
      - '.github/workflows/_artifacts.yml'
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}

permissions:
  contents: read

jobs:
  build:
    uses: ./.github/workflows/_artifacts.yml
```

- [ ] **Step 3: Validate both workflows parse**

Run:
```bash
python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in ['.github/workflows/_artifacts.yml','.github/workflows/artifacts.yml']]; print('yaml ok')"
```
Expected: `yaml ok`.

- [ ] **Step 4: Lint with actionlint if available**

Run: `command -v actionlint && actionlint .github/workflows/_artifacts.yml .github/workflows/artifacts.yml || echo "actionlint not installed — skipping"`
Expected: clean output, or the skip note.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/_artifacts.yml .github/workflows/artifacts.yml
git commit -m "ci: extract reusable _artifacts.yml workflow

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Release pipeline (`release.yml`)

**Files:**
- Create: `.github/workflows/release.yml`

Trigger on `v*` tags + `workflow_dispatch`. Gate → build artifacts + linux bin
→ package deb + windows → attach to GitHub Release.

- [ ] **Step 1: Write `release.yml`**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ['v*']
  workflow_dispatch:

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

permissions:
  contents: write

jobs:
  version:
    name: Derive version
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.v.outputs.version }}
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - id: v
        run: |
          ref="${{ github.ref }}"
          if [[ "$ref" == refs/tags/v* ]]; then
            echo "version=${ref#refs/tags/v}" >> "$GITHUB_OUTPUT"
          else
            base=$(grep -m1 '^version' crates/izba-cli/Cargo.toml | cut -d'"' -f2)
            echo "version=${base}~git$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"
          fi

  gate:
    name: Build/test gates
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
      - run: |
          rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends musl-tools gcc-mingw-w64-x86-64
      - run: cargo test --workspace
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo fmt --check
      - run: cargo build -p izba-init --target x86_64-unknown-linux-musl --release
      - run: cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
      - run: cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings

  artifacts:
    name: Build artifacts
    needs: gate
    uses: ./.github/workflows/_artifacts.yml

  izba-linux-bin:
    name: izba (linux release binary)
    needs: gate
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: izba-linux
      - run: cargo build --release -p izba-cli
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-linux-bin
          path: target/release/izba
          if-no-files-found: error

  package-deb:
    name: Build .deb
    needs: [version, artifacts, izba-linux-bin]
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-linux-bin
          path: dl/bin
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: vmlinux
          path: dl/art
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: initramfs
          path: dl/art
      - name: Fetch pinned cloud-hypervisor + virtiofsd
        run: |
          IZBA_BIN_DIR="$PWD/dl/vmm" hack/fetch-artifacts.sh || true
          test -f dl/vmm/cloud-hypervisor
          test -f dl/vmm/virtiofsd
      - name: Build the .deb
        env:
          IZBA_BIN: ${{ github.workspace }}/dl/bin/izba
          IZBA_CH: ${{ github.workspace }}/dl/vmm/cloud-hypervisor
          IZBA_VIRTIOFSD: ${{ github.workspace }}/dl/vmm/virtiofsd
          IZBA_VMLINUX: ${{ github.workspace }}/dl/art/vmlinux
          IZBA_INITRAMFS: ${{ github.workspace }}/dl/art/initramfs.cpio.gz
          VERSION: ${{ needs.version.outputs.version }}
        run: |
          chmod +x dl/bin/izba dl/vmm/cloud-hypervisor dl/vmm/virtiofsd
          packaging/build-deb.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-deb
          path: dist/izba_*_amd64.deb
          if-no-files-found: error

  package-windows:
    name: Build Windows installer
    needs: [version, artifacts]
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-windows-bundle
          path: stage
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: vmlinux
          path: stage/artifacts
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: initramfs
          path: stage/artifacts
      - name: Fetch openvmm.exe into libexec
        shell: bash
        run: |
          hack/fetch-openvmm.sh
          mkdir -p stage/bin/libexec
          cp dist/openvmm.exe stage/bin/libexec/openvmm.exe
      - name: Build installer with Inno Setup
        shell: pwsh
        run: |
          choco install innosetup --no-progress -y
          $stage = Join-Path $env:GITHUB_WORKSPACE 'stage'
          $out = Join-Path $env:GITHUB_WORKSPACE 'dist'
          # /O overrides the .iss OutputDir (which is relative to the .iss file,
          # i.e. packaging\windows\dist) so the installer lands in repo-root dist\.
          & "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" `
            "/DMyAppVersion=${{ needs.version.outputs.version }}" `
            "/DStageDir=$stage" `
            "/O$out" `
            packaging\windows\izba.iss
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-windows-installer
          path: dist/izba-setup-*.exe
          if-no-files-found: error

  release:
    name: Attach to GitHub Release
    needs: [version, package-deb, package-windows]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-deb
          path: rel
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: izba-windows-installer
          path: rel
      - name: SHA256SUMS
        run: cd rel && sha256sum * > SHA256SUMS && cat SHA256SUMS
      - uses: softprops/action-gh-release@72f2c25fcb47643c292f7107632f7a47c1df5cd8 # v2.3.2
        with:
          files: |
            rel/izba_*_amd64.deb
            rel/izba-setup-*.exe
            rel/SHA256SUMS
```

- [ ] **Step 2: Validate it parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 3: Lint with actionlint if available**

Run: `command -v actionlint && actionlint .github/workflows/release.yml || echo "actionlint not installed — skipping"`
Expected: clean, or skip note.

- [ ] **Step 4: Verify the openvmm fetch action SHA pin matches the repo's existing pin**

Run: `grep -n "softprops/action-gh-release" .github/workflows/*.yml; grep -rn "fetch-openvmm" .github/workflows/`
Expected: confirm `softprops/action-gh-release` is either newly introduced here or matches an existing pin elsewhere; if the repo already pins a specific SHA for it, reuse that exact SHA. (If `e2e.yml` already references `fetch-openvmm.sh`, mirror its invocation.)

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: release pipeline building .deb + Windows Inno installer

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Docs + final verification

**Files:**
- Modify: `hack/README.md` (note the packaging scripts) — optional but recommended
- Modify: `README.md` install section — optional

- [ ] **Step 1: Add a packaging note to `hack/README.md`**

Append a short section under the scripts list documenting `packaging/build-deb.sh`
(env-var inputs) and `packaging/windows/izba.iss` (`iscc` with `/DStageDir`),
and that both are driven by `.github/workflows/release.yml` on `v*` tags.

- [ ] **Step 2: Run the full local gate suite one last time**

Run:
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all six green.

- [ ] **Step 3: Commit**

```bash
git add hack/README.md README.md
git commit -m "docs(packaging): document release installers + packaging scripts

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Acceptance (human, post-merge / via workflow_dispatch)

1. Trigger `release.yml` via `workflow_dispatch` (no tag) → both
   `izba-deb` and `izba-windows-installer` artifacts download successfully.
2. **Linux:** on a clean WSL2 Ubuntu, `sudo apt install ./izba_<v>_amd64.deb`
   (pulls `erofs-utils`), then `izba` boots a sandbox with **no** `IZBA_*` env
   vars set (exercises the exe-relative artifact fallback + libexec CH/virtiofsd
   discovery).
3. **Windows:** run `izba-setup-<v>.exe` on a clean host, open a new terminal,
   `izba --help` works from PATH, and a sandbox boots via OpenVMM/WHP.
4. Push a real `v0.1.0` tag → `release.yml` attaches `.deb`, `.exe`, and
   `SHA256SUMS` to the GitHub Release.
