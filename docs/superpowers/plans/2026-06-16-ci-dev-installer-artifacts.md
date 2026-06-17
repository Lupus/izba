# CI-built dev installers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the dev-installer packaging off the laptop into CI — the laptop only `gh run download`s the finished installers into `dist/local/<ts>-<sha>/`.

**Architecture:** A new dispatch-only `.github/workflows/devbuild.yml` (lean sibling of `release.yml`, reusing `_artifacts.yml`, with no test-gate dependency) builds the three installer artifacts. `hack/devbuild.sh` is rewritten from a local builder into a dispatch→watch→download helper. `release.yml`/`ci.yml` are untouched.

**Tech Stack:** GitHub Actions YAML, Bash, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-06-16-ci-dev-installer-artifacts-design.md`

---

## File structure

- **Create:** `.github/workflows/devbuild.yml` — on-demand installer build (workflow_dispatch only).
- **Rewrite:** `hack/devbuild.sh` — dispatch + watch + download helper (heavy local build deleted).
- **Modify:** `CLAUDE.md` — "Standard delivery loop" step 2.

> **Note on testing style:** This is CI/shell infra, not library code with a unit-test framework. "Tests" here are static validation (`actionlint`/YAML parse, `bash -n`, `shellcheck`, `--help` smoke) plus a final real-dispatch integration check (Task 4) run unsandboxed at delivery. There is no TDD red/green loop to fake.

---

### Task 1: New `devbuild.yml` workflow

**Files:**
- Create: `.github/workflows/devbuild.yml`

- [ ] **Step 1: Write the workflow file**

Create `.github/workflows/devbuild.yml` with exactly this content:

```yaml
name: Dev build (installers)

# On-demand installer build for manual UI/UX testing of a feature branch.
# Produces the same three artifacts as release.yml (izba-deb, izba-app-deb,
# izba-windows-installer) but cuts NO GitHub Release and runs NO test gate
# (ci.yml is the authoritative gate, so this starts packaging immediately and
# runs in parallel with the PR checks). Dispatch with:
#   gh workflow run devbuild.yml --ref <branch>
# then collect with hack/devbuild.sh. Design:
# docs/superpowers/specs/2026-06-16-ci-dev-installer-artifacts-design.md

on:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: devbuild-${{ github.ref }}
  cancel-in-progress: true

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
          base=$(grep -m1 '^version' crates/izba-cli/Cargo.toml | cut -d'"' -f2)
          echo "version=${base}~git$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"

  artifacts:
    name: Build artifacts
    uses: ./.github/workflows/_artifacts.yml

  izba-linux-bin:
    name: izba (linux release binary)
    runs-on: ubuntu-22.04
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

  app-linux-deb:
    name: izba-app (.deb)
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
    needs: [version, artifacts, app-windows-build]
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
          name: izba-app-exe
          path: stage/bin
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: vmlinux
          path: stage/artifacts
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: initramfs
          path: stage/artifacts
      - name: Fetch pinned openvmm.exe + stage into libexec
        shell: bash
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          # The pin lives in hack/fetch-openvmm.sh (single source of truth) —
          # call it directly rather than copying release.yml's cache-key pin.
          hack/fetch-openvmm.sh
          mkdir -p stage/bin/libexec
          cp dist/openvmm.exe stage/bin/libexec/openvmm.exe
      - name: Build installer with Inno Setup
        shell: pwsh
        run: |
          choco install innosetup --no-progress -y
          $stage = Join-Path $env:GITHUB_WORKSPACE 'stage'
          $out = Join-Path $env:GITHUB_WORKSPACE 'dist'
          # /O overrides the .iss OutputDir so the installer lands in repo-root dist\.
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
```

- [ ] **Step 2: Validate the YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/devbuild.yml')); print('YAML OK')"`
Expected: `YAML OK`

If `actionlint` is installed, also run: `actionlint .github/workflows/devbuild.yml`
Expected: no output (clean). (If `actionlint` is absent, skip — it is not a repo gate.)

- [ ] **Step 3: Sanity-check the action pins match the rest of the repo**

Run: `grep -hoE 'uses: [^ ]+@[0-9a-f]{40}' .github/workflows/devbuild.yml | sort -u`
Expected: every line also appears in `.github/workflows/release.yml` (same pinned SHAs — verify by eye against that file). This catches a typo'd action SHA.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/devbuild.yml
git commit -m "ci(devbuild): add dispatch-only installer build workflow

Lean sibling of release.yml: reuses _artifacts.yml, no test-gate dep, no
release/smoke, read-only token. Builds izba-deb, izba-app-deb,
izba-windows-installer for any branch on workflow_dispatch.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Rewrite `hack/devbuild.sh` as a download helper

**Files:**
- Rewrite: `hack/devbuild.sh`

- [ ] **Step 1: Replace the whole script**

Overwrite `hack/devbuild.sh` with exactly this content:

```bash
#!/usr/bin/env bash
# devbuild.sh — fetch CI-built izba installers for local manual testing.
#
# The installer set (izba_*.deb CLI, izba-app_*.deb GUI, izba-setup-*.exe) is
# built ENTIRELY in CI by .github/workflows/devbuild.yml — this script only
# dispatches that workflow on the current branch, waits for it, and downloads
# the finished installers into dist/local/<ts>-<sha>/ with paste-ready install
# commands. Nothing heavy builds on the laptop or the Windows host. Design:
# docs/superpowers/specs/2026-06-16-ci-dev-installer-artifacts-design.md
#
# IMPORTANT: run OUTSIDE the agent Bash sandbox — it calls `gh` (and, for the
# Windows install hint, `powershell.exe`), both blocked by the sandbox, exactly
# like the KVM/Windows integration suites.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

WORKFLOW="devbuild.yml"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_ts() { date -u +%H:%M:%S; }
log()   { printf '[%s] %s\n' "$(_ts)" "$*" >&2; }
stage() { printf '\n[%s] ==== %s ====\n' "$(_ts)" "$*" >&2; }
warn()  { printf '[%s] WARNING: %s\n' "$(_ts)" "$*" >&2; }
die()   { printf '[%s] ERROR: %s\n' "$(_ts)" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
REF=""
RUN_ID=""
DO_DISPATCH=1
DL_LINUX=1
DL_WINDOWS=1
DL_GUI=1
DO_CLEAN=0
KEEP_N=""

usage() {
    cat >&2 <<'EOF'
usage: hack/devbuild.sh [options]

Dispatches the CI installer build (.github/workflows/devbuild.yml) on the
current branch, waits for it, and downloads the installers into
dist/local/<ts>-<sha>/ with ready-to-paste install commands. The build runs
ENTIRELY in CI, in parallel with the PR checks — nothing heavy builds locally.
Run OUTSIDE the agent sandbox (needs gh).

Target / dispatch:
  --ref <branch>   Branch to build (default: current branch).
  --run <id>       Skip dispatch; download from this existing run id.
  --no-dispatch    Skip dispatch; download the newest run for HEAD.

Download scope (the build always produces the full set; these only pick what
to stage locally):
  --linux-only     Only the .deb set (skip the Windows installer).
  --windows-only   Only the Windows installer.
  --no-gui         Skip the izba-app GUI .deb.

Housekeeping:
  --clean [--keep N]  Prune dist/local/* keeping the newest N (default: all but
                      latest), then exit.
  -h, --help          This help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ref)          shift; REF="${1:-}"; [ -n "$REF" ] || die "--ref needs a branch" ;;
        --run)          shift; RUN_ID="${1:-}"; [ -n "$RUN_ID" ] || die "--run needs an id"; DO_DISPATCH=0 ;;
        --no-dispatch)  DO_DISPATCH=0 ;;
        --linux-only)   DL_WINDOWS=0 ;;
        --windows-only) DL_LINUX=0 ;;
        --no-gui)       DL_GUI=0 ;;
        --clean)        DO_CLEAN=1 ;;
        --keep)         shift; KEEP_N="${1:-}"; [ -n "$KEEP_N" ] || die "--keep needs N" ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage; die "unknown flag: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# --clean: prune dist/local/* (independent of a download).
# ---------------------------------------------------------------------------
prune_dist() {
    local base="$REPO_ROOT/dist/local"
    [ -d "$base" ] || { log "nothing to clean (no $base)"; return 0; }
    local latest_target=""
    [ -L "$base/latest" ] && latest_target="$(readlink "$base/latest")"
    local dirs=()
    while IFS= read -r d; do dirs+=("$d"); done < <(
        find "$base" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort -r
    )
    local keep="$KEEP_N"
    local i=0 removed=0
    for d in "${dirs[@]}"; do
        local protect=0
        if [ -n "$keep" ]; then
            [ "$i" -lt "$keep" ] && protect=1
        else
            [ "$d" = "$latest_target" ] && protect=1
        fi
        if [ "$protect" -eq 1 ]; then
            i=$((i+1))
        else
            log "clean: removing dist/local/$d"
            rm -rf "${base:?}/$d"
            removed=$((removed+1))
        fi
    done
    if [ -L "$base/latest" ] && [ ! -e "$base/latest" ]; then
        rm -f "$base/latest"
    fi
    log "clean: removed $removed run dir(s)"
}

if [ "$DO_CLEAN" -eq 1 ]; then
    stage "Clean dist/local"
    prune_dist
    exit 0
fi

# ---------------------------------------------------------------------------
# Preflight: gh present + authenticated.
# ---------------------------------------------------------------------------
command -v gh >/dev/null 2>&1 || die "gh CLI not found (needed to dispatch/download CI artifacts). Install gh."
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run 'gh auth login')."

# ---------------------------------------------------------------------------
# Stage 1 — identity
# ---------------------------------------------------------------------------
stage "Stage 1: identity"
[ -n "$REF" ] || REF="$(git rev-parse --abbrev-ref HEAD)"
[ "$REF" != "HEAD" ] || die "detached HEAD — pass --ref <branch>."
SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"
CDATE="$(git show -s --format=%cs HEAD)"
DESCRIBE="$(git describe --tags --always --dirty)"
if git diff --quiet; then DIRTY=""; else DIRTY="-dirty"; fi
BASE="$(grep -m1 '^version' crates/izba-cli/Cargo.toml | cut -d'"' -f2)"
VERSION="${BASE}~git${SHORT}"
log "ref=$REF sha=$SHA version=$VERSION"

# Warn (don't block) if the local tip isn't the pushed tip — CI builds the
# pushed ref, so an unpushed commit would build a stale tree.
if ! git rev-parse --verify --quiet "origin/$REF" >/dev/null; then
    warn "origin/$REF not found — push the branch first, else dispatch builds an old/absent ref."
elif [ "$(git rev-parse "origin/$REF")" != "$SHA" ]; then
    warn "origin/$REF != local HEAD — push the branch; CI builds the pushed tip, not your working copy."
fi

declare -A PROV

# ---------------------------------------------------------------------------
# Stage 2 — dispatch + resolve the run, then watch it.
# ---------------------------------------------------------------------------
# Pick the newest run on $REF whose headSha == our HEAD (avoids racing a
# concurrent dispatch on the same branch).
resolve_run_for_head() {
    gh run list --workflow="$WORKFLOW" --branch "$REF" \
        --json databaseId,headSha,status \
        -q "[.[] | select(.headSha==\"$SHA\")] | sort_by(.databaseId) | last | .databaseId" \
        2>/dev/null || true
}

stage "Stage 2: dispatch + resolve CI run"
if [ "$DO_DISPATCH" -eq 1 ]; then
    log "dispatching $WORKFLOW on $REF..."
    gh workflow run "$WORKFLOW" --ref "$REF" \
        || die "gh workflow run failed (is $WORKFLOW present on $REF? rebase onto main)."
    log "waiting for the dispatched run to register..."
    for _ in $(seq 1 30); do
        RUN_ID="$(resolve_run_for_head)"
        [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] && break
        sleep 3
    done
    [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] \
        || die "dispatched run for $SHA did not appear — check 'gh run list --workflow=$WORKFLOW'."
elif [ -z "$RUN_ID" ]; then
    log "resolving newest $WORKFLOW run for $SHA (no dispatch)..."
    RUN_ID="$(resolve_run_for_head)"
    [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] \
        || die "no $WORKFLOW run found for $SHA on $REF — dispatch one (drop --no-dispatch)."
fi
log "CI run: $RUN_ID"
log "watching run $RUN_ID (full installer build, ~30-40 min)..."
gh run watch "$RUN_ID" --exit-status \
    || die "run $RUN_ID failed — see: gh run view $RUN_ID --log-failed"

# ---------------------------------------------------------------------------
# Stage 3 — download the selected artifacts into a temp run dir.
# ---------------------------------------------------------------------------
stage "Stage 3: download installers"
mkdir -p "$REPO_ROOT/dist"
RUN_OUT="$(mktemp -d "$REPO_ROOT/dist/.devbuild-run.XXXXXX")"
DL_TMP="$(mktemp -d "$REPO_ROOT/dist/.devbuild-dl.XXXXXX")"
cleanup() { [ -n "${RUN_OUT:-}" ] && rm -rf "$RUN_OUT"; [ -n "${DL_TMP:-}" ] && rm -rf "$DL_TMP"; }
trap cleanup EXIT

# Download artifact NAME, find the file matching GLOB inside it, copy to RUN_OUT.
fetch_one() {
    local name="$1" glob="$2" provkey="$3"
    log "downloading artifact $name..."
    gh run download "$RUN_ID" -n "$name" -D "$DL_TMP/$name" \
        || die "failed to download artifact $name from run $RUN_ID"
    local f
    f="$(find "$DL_TMP/$name" -type f -name "$glob" | head -1)"
    [ -n "$f" ] || die "artifact $name had no file matching $glob"
    cp -f "$f" "$RUN_OUT/"
    PROV[$provkey]="fetched (run $RUN_ID)"
}

if [ "$DL_LINUX" -eq 1 ]; then
    fetch_one izba-deb 'izba_*_amd64.deb' izba-deb
    [ "$DL_GUI" -eq 1 ] && fetch_one izba-app-deb 'izba-app_*_amd64.deb' izba-app-deb
fi
if [ "$DL_WINDOWS" -eq 1 ]; then
    fetch_one izba-windows-installer 'izba-setup-*.exe' installer
fi

# ---------------------------------------------------------------------------
# Stage 4 — collect: SHA256SUMS + manifest + atomic publish + latest symlink.
# ---------------------------------------------------------------------------
stage "Stage 4: collect"
( cd "$RUN_OUT" && find . -maxdepth 1 -type f \
        ! -name SHA256SUMS ! -name manifest.txt -printf '%f\n' \
    | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS )

{
    echo "version:  $VERSION"
    echo "sha:      $SHA"
    echo "describe: $DESCRIBE"
    echo "date:     $CDATE"
    echo "ref:      $REF"
    echo "ci-run:   $RUN_ID"
    echo "built:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "artifacts:"
    for k in izba-deb izba-app-deb installer; do
        [ -n "${PROV[$k]:-}" ] && printf '  %-14s %s\n' "$k:" "${PROV[$k]}"
    done
} > "$RUN_OUT/manifest.txt"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL_NAME="${TS}-${SHORT}${DIRTY}"
FINAL_DIR="$REPO_ROOT/dist/local/$FINAL_NAME"
mkdir -p "$REPO_ROOT/dist/local"
mv "$RUN_OUT" "$FINAL_DIR"
RUN_OUT=""   # disarm cleanup for the published dir
ln -sfn "$FINAL_NAME" "$REPO_ROOT/dist/local/latest"

# ---------------------------------------------------------------------------
# Stage 5 — worktree → main-checkout copy (so the owner finds it where they
# work). Plain copy (survives the worktree being removed).
# ---------------------------------------------------------------------------
REPORT_DIR="$FINAL_DIR"
GIT_COMMON="$(git rev-parse --git-common-dir 2>/dev/null || true)"
if [ -n "$GIT_COMMON" ]; then
    MAIN_ROOT="$(cd "$GIT_COMMON/.." && pwd)"
    if [ "$MAIN_ROOT" != "$REPO_ROOT" ]; then
        mkdir -p "$MAIN_ROOT/dist/local"
        cp -a "$FINAL_DIR" "$MAIN_ROOT/dist/local/"
        REPORT_DIR="$MAIN_ROOT/dist/local/$FINAL_NAME"
        log "copied into main checkout: $REPORT_DIR"
    fi
fi

# ---------------------------------------------------------------------------
# Stage 6 — report + paste-ready install commands.
# ---------------------------------------------------------------------------
stage "DONE → $REPORT_DIR"
ls -la "$FINAL_DIR" >&2
echo "" >&2
cat "$FINAL_DIR/manifest.txt" >&2

echo "" >&2
echo "==== install commands ====" >&2
if [ "$DL_LINUX" -eq 1 ]; then
    printf '\nLinux (WSL2):\n  sudo dpkg -i "%s"/izba_*.deb\n' "$REPORT_DIR" >&2
    [ "$DL_GUI" -eq 1 ] && printf '  sudo dpkg -i "%s"/izba-app_*.deb\n' "$REPORT_DIR" >&2
fi
if [ "$DL_WINDOWS" -eq 1 ]; then
    # The exe is referenced by its real name; the zsh→powershell hop eats one
    # set of backslashes, so double every backslash of the wslpath -w output
    # AND the separator we add (printf '\\\\' emits a literal '\\').
    EXE_NAME="$(cd "$FINAL_DIR" && ls izba-setup-*.exe 2>/dev/null | head -1 || true)"
    WIN_DIR="$(wslpath -w "$REPORT_DIR" 2>/dev/null || true)"
    WIN_DIR_ESC="${WIN_DIR//\\/\\\\}"
    if [ -n "$WIN_DIR_ESC" ] && [ -n "$EXE_NAME" ]; then
        printf '\nWindows installer (via WSL interop):\n' >&2
        printf '  powershell.exe -NoProfile -Command "Start-Process -Wait '\''%s\\\\%s'\''"\n' \
            "$WIN_DIR_ESC" "$EXE_NAME" >&2
    fi
fi
echo "" >&2
```

- [ ] **Step 2: Verify bash syntax**

Run: `bash -n hack/devbuild.sh`
Expected: no output, exit 0.

- [ ] **Step 3: Lint (if shellcheck present)**

Run: `command -v shellcheck >/dev/null && shellcheck hack/devbuild.sh || echo "shellcheck absent — skipped"`
Expected: clean, OR `shellcheck absent — skipped`. (Fix any real warnings; `SC1090/SC2034`-style false positives may be annotated as the old script did.)

- [ ] **Step 4: Smoke the no-network paths**

Run: `bash hack/devbuild.sh --help`
Expected: the usage text prints; exit 0; **no `gh` call** (help returns before preflight).

Run: `bash hack/devbuild.sh --clean --keep 9999`
Expected: prints `clean: removed 0 run dir(s)` (or removes nothing meaningful); exit 0; no `gh` call.

- [ ] **Step 5: Confirm executable bit preserved**

Run: `test -x hack/devbuild.sh && echo "exec OK"`
Expected: `exec OK`. If not: `chmod +x hack/devbuild.sh`.

- [ ] **Step 6: Commit**

```bash
git add hack/devbuild.sh
git commit -m "feat(devbuild): rewrite as CI dispatch+download helper

Deletes the heavy local build (per-worktree Rust target dirs on Linux AND the
Windows host, Tauri/npm, rsync-to-/mnt/c, vergen injection). devbuild.sh now
dispatches devbuild.yml on the branch, watches it, downloads izba-deb/
izba-app-deb/izba-windows-installer into dist/local/<ts>-<sha>/, and prints
install commands. Keeps --clean, the dist/local layout, manifest/SHA256SUMS,
and the worktree->main copy.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Update CLAUDE.md delivery loop

**Files:**
- Modify: `CLAUDE.md` (the "Standard delivery loop" step 2, currently lines ~205–218)

- [ ] **Step 1: Replace step 2**

Find this block in `CLAUDE.md` (under **Standard delivery loop for a feature branch:**):

```
2. **While CI runs, bake a local dev build** for manual testing with
   `bash hack/devbuild.sh` (run unsandboxed — see [the script](hack/devbuild.sh)
   and [its design](docs/superpowers/specs/2026-06-15-local-devbuild-script-design.md)).
   It prints the exact output dir `dist/local/<UTC-ts>-<sha>/`. **Record and
   report that exact path — never `dist/local/latest`**, which a parallel
   agent's build can repoint out from under you.
   - **When built from a worktree, copy that dir into the MAIN checkout's
     `dist/local/`** so the owner (who works in the main checkout) finds it where
     they expect — a worktree's `dist/` is a separate working tree. Use a plain
     copy, not a symlink (it must survive the worktree being removed):
     `MAIN=$(git -C "$(git rev-parse --git-common-dir)/.." rev-parse --show-toplevel)`
     then `mkdir -p "$MAIN/dist/local" && cp -a dist/local/<ts>-<sha> "$MAIN/dist/local/"`.
     The copy lands outside the worktree sandbox, so run it unsandboxed. Report
     the main-checkout path as the canonical one.
```

Replace it with:

```
2. **While CI runs, dispatch the CI installer build** for manual testing:
   `bash hack/devbuild.sh` (run unsandboxed — it needs `gh`; see
   [the script](hack/devbuild.sh) and
   [its design](docs/superpowers/specs/2026-06-16-ci-dev-installer-artifacts-design.md)).
   It dispatches `.github/workflows/devbuild.yml` on the branch, watches the run,
   and downloads the finished `izba_*.deb` + `izba-app_*.deb` + `izba-setup-*.exe`
   — **the build runs entirely in CI, in parallel with the PR checks; nothing
   heavy builds on the laptop or the Windows host** (only ~150 MB of installers
   is downloaded). It needs the branch **pushed** first (CI builds the pushed
   tip), and `devbuild.yml` must exist on the branch (rebase onto `main` if it
   predates this workflow). It prints the exact output dir
   `dist/local/<UTC-ts>-<sha>/`. **Record and report that exact path — never
   `dist/local/latest`**, which a parallel run can repoint out from under you.
   - **When run from a worktree it auto-copies that dir into the MAIN checkout's
     `dist/local/`** (a worktree's `dist/` is a separate working tree) and reports
     the main-checkout path as canonical — a plain copy that survives the worktree
     being removed.
```

- [ ] **Step 2: Verify the edit landed and no stale reference remains**

Run: `grep -n '2026-06-15-local-devbuild\|bake a local dev build' CLAUDE.md`
Expected: no matches (the old design link and phrasing are gone from the delivery loop).

Run: `grep -n 'devbuild.yml\|entirely in CI' CLAUDE.md`
Expected: at least one match (the new flow is present).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude): delivery loop uses CI installer build, not local

Step 2 now dispatches devbuild.yml + downloads, replacing the laptop-loading
local hack/devbuild.sh build. Worktree->main copy is now done by the script.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: End-to-end validation (unsandboxed, at delivery)

This is the real integration check; it runs unsandboxed. **It can only run after this change merges to `main`**, because GitHub registers a `workflow_dispatch` trigger only from the workflow file on the default branch — until `devbuild.yml` is on `main`, `gh workflow run devbuild.yml` has nothing to dispatch. (Every *future* branch cut from `main` validates pre-merge as designed; only this bootstrapping branch is gated on merge.) It is not a unit test.

- [ ] **Step 1: Land the change, then run from `main` (or a fresh branch off the merged `main`)**

```bash
git push -u origin <this-branch>   # open the PR; let ci.yml/app.yml/coverage gate it
# ... after the PR merges to main:
git checkout main && git pull
```
(Per repo policy the agent may push feature branches and open/merge PRs; never push to `main` directly.)

- [ ] **Step 2: Dispatch + download via the new helper**

Run (unsandboxed): `bash hack/devbuild.sh`
Expected: it dispatches `devbuild.yml`, watches a run that goes green (~30–40 min), downloads the three artifacts, prints `DONE → <main-checkout>/dist/local/<ts>-<sha>` followed by the manifest and install commands.

- [ ] **Step 3: Verify the output dir**

Run: `ls dist/local/latest/ && cat dist/local/latest/manifest.txt`
Expected: contains `izba_*~git<sha>_amd64.deb`, `izba-app_*~git<sha>_amd64.deb`, `izba-setup-*~git<sha>.exe`, `SHA256SUMS`, `manifest.txt`; manifest shows the matching `sha:` and `ci-run:`.

- [ ] **Step 4: Verify attribution in the built CLI**

Run: `sudo dpkg -i dist/local/latest/izba_*.deb && izba version`
Expected: the version string contains `~git<short-sha>` matching the branch HEAD. (Confirms CI's in-`.git` vergen attribution worked — the thing the old local Windows path needed env injection for.)

- [ ] **Step 5: Confirm laptop did no heavy build**

Sanity: there is no new multi-GB `target/` churn from this flow and no `/mnt/c/Users/<user>/.izba-devbuild/<worktree>` directory was created. The only growth is `dist/local/<ts>-<sha>/` (~150 MB).

---

## Self-review notes

- **Spec coverage:** Part 1 (devbuild.yml) → Task 1; Part 2 (helper rewrite) → Task 2; Part 3 (CLAUDE.md) → Task 3; spec "Validation" section → Task 4. openvmm pin de-dup is in Task 1 Step 1 (the `hack/fetch-openvmm.sh`-direct step). No-`needs: gate` property is in Task 1 (jobs declare only data deps). Kept helper features (`--clean`, layout, manifest, worktree copy, scope flags) all present in Task 2.
- **Type/name consistency:** artifact names (`izba-deb`, `izba-app-deb`, `izba-windows-installer`) and file globs (`izba_*_amd64.deb`, `izba-app_*_amd64.deb`, `izba-setup-*.exe`) match between the workflow's `upload-artifact` names and the helper's `fetch_one` calls. `WORKFLOW="devbuild.yml"` matches the created filename.
- **No placeholders:** full YAML and full script bodies are inline; commands have expected output.
