#!/usr/bin/env bash
# devbuild.sh — local hybrid (WSL2 + Windows host) dev build of the izba
# installer + .deb set, with correct git version attribution and a shared,
# concurrency-safe artifact cache. Much faster than release.yml; for local
# iteration only. See docs/superpowers/specs/2026-06-15-local-devbuild-script-design.md.
#
# IMPORTANT: this is a dev tool meant to run OUTSIDE the agent Bash sandbox
# (it writes to /mnt/c, ~/.cache and calls powershell.exe / gh — all blocked
# by the agent sandbox), exactly like the KVM/Windows integration suites.
#
# Stages:
#   1. Identity & git attribution (the "v0.1.0 unknown" fix).
#   2. Ensure stable artifacts (fetch-from-CI first, cached; local fallback).
#   3. Build the fast bits (izba + izba-app, both platforms).
#   4. Package (debs + Inno installer).
#   5. Collect into dist/local/<ts>-<sha>/ + latest symlink + SHA256SUMS + manifest.txt.
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repo root and make the worktree-local rust toolchain available
# (worktrees have no .cargo-env). Honour an existing .cargo-env if present.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [ -f "$REPO_ROOT/.cargo-env" ]; then
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.cargo-env"
fi
# Worktrees keep the shared toolchain under the main checkout's .toolchain.
TOOLCHAIN_ROOT="$(git rev-parse --git-common-dir 2>/dev/null | sed 's#/\.git/\?.*##; s#/\.git$##')"
[ -z "$TOOLCHAIN_ROOT" ] && TOOLCHAIN_ROOT="$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then
    if [ -d "$TOOLCHAIN_ROOT/.toolchain/cargo/bin" ]; then
        export RUSTUP_HOME="$TOOLCHAIN_ROOT/.toolchain/rustup"
        export CARGO_HOME="$TOOLCHAIN_ROOT/.toolchain/cargo"
        export PATH="$CARGO_HOME/bin:$PATH"
    fi
fi

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
DO_LINUX=1
DO_WINDOWS=1
DO_GUI=1
REFRESH_KERNEL=0
REFRESH_INITRAMFS=0
REFRESH_VMM=0
BUILD_HEAVY=0
FETCH_ONLY=0
DO_CLEAN=0
KEEP_N=""           # empty = keep all (with --clean alone: all but latest)
WAIT_FOR_LOCK=0

usage() {
    cat >&2 <<'EOF'
usage: hack/devbuild.sh [options]

Builds a fresh izba Windows installer (izba-setup-*.exe) and Linux .deb set
(izba_*.deb CLI + izba-app_*.deb GUI) with correct git attribution baked in.
Run OUTSIDE the agent Bash sandbox (touches /mnt/c, ~/.cache, powershell.exe, gh).

Scope:
  --windows-only      Build only the Windows installer.
  --linux-only        Build only the Linux .deb set.
  --no-gui            Skip izba-app (GUI) on both sides.

Stable artifacts (vmlinux / initramfs / mkfs.erofs.exe):
  --refresh-kernel    Force re-fetch/rebuild of the kernel.
  --refresh-initramfs Force re-fetch/rebuild of the initramfs.
  --refresh-vmm       Force re-fetch of cloud-hypervisor/virtiofsd/openvmm.
  --build-heavy       Build kernel/initramfs locally even if clean vs origin/main.
  --fetch-only        Hard-error instead of local-building heavy artifacts.

Concurrency / housekeeping:
  --wait              Block on the per-worktree lock instead of failing fast.
  --clean [--keep N]  Prune dist/local/* keeping the newest N (default: all but
                      latest). Runs the prune then exits unless a build is also
                      requested.
  -h, --help          This help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --windows-only)     DO_LINUX=0 ;;
        --linux-only)       DO_WINDOWS=0 ;;
        --no-gui)           DO_GUI=0 ;;
        --refresh-kernel)   REFRESH_KERNEL=1 ;;
        --refresh-initramfs) REFRESH_INITRAMFS=1 ;;
        --refresh-vmm)      REFRESH_VMM=1 ;;
        --build-heavy)      BUILD_HEAVY=1 ;;
        --fetch-only)       FETCH_ONLY=1 ;;
        --clean)            DO_CLEAN=1 ;;
        --keep)             shift; KEEP_N="${1:-}"; [ -n "$KEEP_N" ] || die "--keep needs N" ;;
        --wait)             WAIT_FOR_LOCK=1 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  usage; die "unknown flag: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Cache + lock layout
# ---------------------------------------------------------------------------
WORKTREE_KEY="$(basename "$REPO_ROOT")"
CACHE_ROOT="${IZBA_DEVBUILD_CACHE:-$HOME/.cache/izba/devbuild}"
CI_CACHE="$CACHE_ROOT/ci"
PINNED_CACHE="$CACHE_ROOT/pinned"
LOCK_DIR="$CACHE_ROOT/locks"
mkdir -p "$CI_CACHE" "$PINNED_CACHE" "$LOCK_DIR"

# flock helper for the shared cache: serialize writes to a named resource and
# publish via atomic mv. Usage: with_cache_lock <name> <command...>
with_cache_lock() {
    local name="$1"; shift
    local lockfile="$LOCK_DIR/cache-$name.lock"
    ( flock 9; "$@" ) 9>"$lockfile"
}

# ---------------------------------------------------------------------------
# --clean: prune dist/local/* (independent of a build).
# ---------------------------------------------------------------------------
prune_dist() {
    local base="$REPO_ROOT/dist/local"
    [ -d "$base" ] || { log "nothing to clean (no $base)"; return 0; }
    local latest_target=""
    [ -L "$base/latest" ] && latest_target="$(readlink "$base/latest")"
    # Newest-first list of run dirs (exclude the 'latest' symlink itself).
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
            # --clean alone: keep only the latest target.
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
    # Drop a dangling latest symlink.
    if [ -L "$base/latest" ] && [ ! -e "$base/latest" ]; then
        rm -f "$base/latest"
    fi
    log "clean: removed $removed run dir(s)"
}

if [ "$DO_CLEAN" -eq 1 ]; then
    stage "Clean dist/local"
    prune_dist
    # --clean is housekeeping-only unless a build scope was also implied. We
    # treat --clean as "prune then exit" to match the design's intent.
    exit 0
fi

# ---------------------------------------------------------------------------
# Per-worktree lock — serialize concurrent runs in THIS worktree (protects
# target/ + the Windows build copy). Different worktrees stay fully parallel.
# ---------------------------------------------------------------------------
WT_LOCK="$LOCK_DIR/$WORKTREE_KEY.lock"
exec 8>"$WT_LOCK"
if [ "$WAIT_FOR_LOCK" -eq 1 ]; then
    log "waiting for worktree lock ($WT_LOCK)..."
    flock 8
else
    flock -n 8 || die "another devbuild is running in this worktree ($WORKTREE_KEY). Use --wait to block."
fi

START_EPOCH=$(date +%s)

# ===========================================================================
# Stage 1 — Identity & git attribution
# ===========================================================================
stage "Stage 1: identity & git attribution"
SHORT="$(git rev-parse --short HEAD)"
SHA="$(git rev-parse HEAD)"
DESCRIBE="$(git describe --tags --always --dirty)"
CDATE="$(git show -s --format=%cs HEAD)"
if git diff --quiet; then DIRTY=""; else DIRTY="-dirty"; fi
BASE="$(grep -m1 '^version' crates/izba-cli/Cargo.toml | cut -d'"' -f2)"
VERSION="${BASE}~git${SHORT}${DIRTY:+.dirty}"
log "VERSION=$VERSION  sha=$SHA  describe=$DESCRIBE  date=$CDATE"

# manifest provenance accumulator — filled per artifact, written in Stage 5.
declare -A PROV

# ===========================================================================
# Stage 2 — Stable artifacts: fetch-from-CI (cached), local fallback.
# ===========================================================================
stage "Stage 2: ensure stable artifacts"

git fetch origin main --quiet 2>/dev/null || warn "git fetch origin main failed — match check uses stale origin/main"

# Decide kernel/initramfs source: fetch when clean vs origin/main, else local.
KERNEL_CLEAN=0; INITRAMFS_CLEAN=0
git diff --quiet origin/main -- hack/kernel.config hack/build-kernel.sh && KERNEL_CLEAN=1 || true
git diff --quiet origin/main -- crates/izba-init hack/build-initramfs.sh hack/build-mke2fs.sh hack/build-nft.sh && INITRAMFS_CLEAN=1 || true

# These get filled with absolute paths to the resolved artifacts.
VMLINUX=""
INITRAMFS=""
MKFS_EROFS_WIN=""   # only needed for the Windows installer

# --- resolve the newest green artifacts.yml run on main (only if we fetch) ---
RUN_ID=""
CI_DIR=""
resolve_ci_run() {
    [ -n "$RUN_ID" ] && return 0
    command -v gh >/dev/null 2>&1 || die "gh CLI not found (needed to fetch CI artifacts). Install gh, or use --build-heavy."
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run 'gh auth login'), or use --build-heavy."
    RUN_ID="$(gh run list --workflow=artifacts.yml --branch main --status success -L1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)"
    [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] || die "no successful artifacts.yml run found on main — re-run CI or use --build-heavy."
    CI_DIR="$CI_CACHE/$RUN_ID"
    log "CI artifacts run: $RUN_ID (cache: $CI_DIR)"
}

# Download a single CI artifact NAME into the run cache, atomically, once.
# $1 = artifact name (gh), $2 = expected filename inside it, $3 = cache subpath
# Sets FETCH_PATH (absolute path to the resolved file) and LAST_FETCH_PROV
# (manifest provenance string). Runs in the CURRENT shell — no command
# substitution — so resolve_ci_run's RUN_ID/CI_DIR persist.
FETCH_PATH=""
LAST_FETCH_PROV=""
fetch_ci_artifact() {
    local name="$1" want="$2" rel="$3"
    resolve_ci_run
    local final="$CI_DIR/$rel"
    if [ -f "$final" ]; then
        log "cache-hit: $rel (run $RUN_ID)"
        LAST_FETCH_PROV="cache-hit (run $RUN_ID)"
        FETCH_PATH="$final"
        return 0
    fi
    LAST_FETCH_PROV="fetched (run $RUN_ID)"
    with_cache_lock "ci-$RUN_ID-$name" bash -c '
        set -euo pipefail
        final="$1"; name="$2"; want="$3"; run="$4"
        [ -f "$final" ] && exit 0    # another runner just published it
        mkdir -p "$(dirname "$final")"
        tmp="$(mktemp -d "${final%/*}/.dl.XXXXXX")"
        trap "rm -rf \"$tmp\"" EXIT
        echo "  fetching CI artifact \"$name\" from run $run..." >&2
        gh run download "$run" -n "$name" -D "$tmp"
        src="$(find "$tmp" -type f -name "$want" | head -1)"
        [ -n "$src" ] || { echo "  artifact $name missing $want" >&2; exit 1; }
        mkdir -p "$(dirname "$final")"
        mv -f "$src" "$final"
    ' _ "$final" "$name" "$want" "$RUN_ID"
    [ -f "$final" ] || die "failed to fetch CI artifact $name"
    FETCH_PATH="$final"
}

# Local build of kernel/initramfs into the CI-shaped cache key 'local-<sha>'.
# Slow path; only on dirty inputs (or --build-heavy / --refresh-*).
local_heavy_build() {
    [ "$FETCH_ONLY" -eq 1 ] && die "--fetch-only set but heavy artifacts are dirty vs origin/main; push to main + let CI build, or drop --fetch-only."
    warn "Building heavy artifacts LOCALLY (slow path). Alternative: push to main and let CI build them."
    local out="$CI_CACHE/local-$SHORT"
    mkdir -p "$out"
    if [ -z "$VMLINUX" ] || [ "$REFRESH_KERNEL" -eq 1 ]; then
        if [ ! -f "$out/vmlinux" ] || [ "$REFRESH_KERNEL" -eq 1 ]; then
            log "build-kernel.sh (local)..."
            hack/build-kernel.sh
            cp -f dist/vmlinux "$out/vmlinux"
        fi
        VMLINUX="$out/vmlinux"; PROV[vmlinux]="built(local)"
    fi
    if [ -z "$INITRAMFS" ] || [ "$REFRESH_INITRAMFS" -eq 1 ]; then
        if [ ! -f "$out/initramfs.cpio.gz" ] || [ "$REFRESH_INITRAMFS" -eq 1 ]; then
            log "build-mke2fs.sh + build-nft.sh + build-initramfs.sh (local)..."
            hack/build-mke2fs.sh
            hack/build-nft.sh
            local mke2fs nft
            mke2fs="$(find dist -maxdepth 1 -name 'mke2fs-*-static-x86_64' | head -1)"
            nft="dist/nft"
            [ -n "$mke2fs" ] && [ -f "$nft" ] || die "local mke2fs/nft build did not produce expected outputs"
            chmod 755 "$mke2fs" "$nft"
            IZBA_MKE2FS="$mke2fs" IZBA_NFT="$nft" hack/build-initramfs.sh
            cp -f dist/initramfs.cpio.gz "$out/initramfs.cpio.gz"
        fi
        INITRAMFS="$out/initramfs.cpio.gz"; PROV[initramfs]="built(local)"
    fi
}

# Resolve vmlinux + initramfs.
if [ "$BUILD_HEAVY" -eq 1 ] || [ "$KERNEL_CLEAN" -eq 0 ] || [ "$INITRAMFS_CLEAN" -eq 0 ]; then
    if [ "$BUILD_HEAVY" -eq 1 ]; then
        log "kernel/initramfs: --build-heavy → local build"
    else
        [ "$KERNEL_CLEAN" -eq 0 ] && warn "kernel inputs differ from origin/main → local kernel build"
        [ "$INITRAMFS_CLEAN" -eq 0 ] && warn "initramfs inputs differ from origin/main → local initramfs build"
    fi
    # For a partial-dirty case, fetch the clean half from CI first, then build the dirty half.
    if [ "$BUILD_HEAVY" -eq 0 ] && [ "$KERNEL_CLEAN" -eq 1 ] && [ "$REFRESH_KERNEL" -eq 0 ]; then
        fetch_ci_artifact vmlinux vmlinux vmlinux; VMLINUX="$FETCH_PATH"; PROV[vmlinux]="$LAST_FETCH_PROV"
    fi
    if [ "$BUILD_HEAVY" -eq 0 ] && [ "$INITRAMFS_CLEAN" -eq 1 ] && [ "$REFRESH_INITRAMFS" -eq 0 ]; then
        fetch_ci_artifact initramfs initramfs.cpio.gz initramfs.cpio.gz; INITRAMFS="$FETCH_PATH"; PROV[initramfs]="$LAST_FETCH_PROV"
    fi
    local_heavy_build
else
    log "kernel/initramfs: clean vs origin/main → fetch from CI"
    fetch_ci_artifact vmlinux vmlinux vmlinux;                         VMLINUX="$FETCH_PATH";   PROV[vmlinux]="$LAST_FETCH_PROV"
    fetch_ci_artifact initramfs initramfs.cpio.gz initramfs.cpio.gz;   INITRAMFS="$FETCH_PATH"; PROV[initramfs]="$LAST_FETCH_PROV"
fi
log "vmlinux:   $VMLINUX"
log "initramfs: $INITRAMFS"

# mkfs.erofs.exe (Windows installer only). Its erofs-utils pin is independent
# of the kernel/initramfs inputs and it has no local-build path here, so it is
# always fetched from CI (cached by run id).
if [ "$DO_WINDOWS" -eq 1 ]; then
    fetch_ci_artifact mkfs-erofs-windows mkfs.erofs.exe mkfs.erofs.exe
    MKFS_EROFS_WIN="$FETCH_PATH"
    PROV[mkfs.erofs.exe]="$LAST_FETCH_PROV"
    log "mkfs.erofs.exe: $MKFS_EROFS_WIN"
fi

# --- Pinned third-party binaries (cloud-hypervisor, virtiofsd, openvmm) ---
# Cached under pinned/, keyed by the pins inside their fetch scripts.
PINNED_BIN="$PINNED_CACHE/bin"
mkdir -p "$PINNED_BIN"
if [ "$DO_LINUX" -eq 1 ]; then
    if [ "$REFRESH_VMM" -eq 1 ] || [ ! -x "$PINNED_BIN/cloud-hypervisor" ] || [ ! -x "$PINNED_BIN/virtiofsd" ]; then
        log "ensuring pinned cloud-hypervisor + virtiofsd..."
        # fetch-artifacts.sh downloads only what's missing (and skips anything
        # already on PATH / ~/.local/bin); then we copy the resolved binaries
        # into the pinned cache for a deterministic .deb input path.
        with_cache_lock "pinned-vmm" bash -c '
            set -euo pipefail
            dest="$1"; home="$2"
            IZBA_BIN_DIR="$dest" '"$REPO_ROOT"'/hack/fetch-artifacts.sh >&2
            for b in cloud-hypervisor virtiofsd; do
                if [ -x "$dest/$b" ]; then continue; fi
                src=""
                command -v "$b" >/dev/null 2>&1 && src="$(command -v "$b")"
                [ -z "$src" ] && [ -x "$home/.local/bin/$b" ] && src="$home/.local/bin/$b"
                [ -n "$src" ] || { echo "could not locate $b after fetch" >&2; exit 1; }
                install -m0755 "$src" "$dest/$b"
            done
        ' _ "$PINNED_BIN" "$HOME" \
            || die "could not ensure cloud-hypervisor/virtiofsd (fetch-artifacts.sh). See --refresh-vmm."
        [ -x "$PINNED_BIN/cloud-hypervisor" ] || die "cloud-hypervisor not in pinned cache after fetch"
        [ -x "$PINNED_BIN/virtiofsd" ] || die "virtiofsd not in pinned cache after fetch"
        PROV[cloud-hypervisor]="pinned"; PROV[virtiofsd]="pinned"
    else
        log "cache-hit: cloud-hypervisor + virtiofsd (pinned)"
        PROV[cloud-hypervisor]="cache-hit(pinned)"; PROV[virtiofsd]="cache-hit(pinned)"
    fi
fi
OPENVMM_WIN=""
if [ "$DO_WINDOWS" -eq 1 ]; then
    OPENVMM_WIN="$PINNED_BIN/openvmm.exe"
    if [ "$REFRESH_VMM" -eq 1 ] || [ ! -f "$OPENVMM_WIN" ]; then
        log "fetching pinned openvmm.exe..."
        # fetch-openvmm.sh writes dist/openvmm.exe; publish atomically into cache.
        with_cache_lock "pinned-openvmm" bash -c '
            set -euo pipefail
            dest="$1"
            hack/fetch-openvmm.sh
            [ -f dist/openvmm.exe ] || { echo "fetch-openvmm.sh produced no dist/openvmm.exe" >&2; exit 1; }
            mv -f dist/openvmm.exe "$dest"
        ' _ "$OPENVMM_WIN" || die "fetch-openvmm.sh failed (likely expired pin — see its re-pin header), or use a fresh pin."
        PROV[openvmm.exe]="fetched(pinned)"
    else
        log "cache-hit: openvmm.exe (pinned)"
        PROV[openvmm.exe]="cache-hit(pinned)"
    fi
fi

# ===========================================================================
# Per-run temp staging — atomic-rename to dist/local/<...> only on success.
# ===========================================================================
mkdir -p "$REPO_ROOT/dist"
RUN_OUT="$(mktemp -d "$REPO_ROOT/dist/.devbuild-run.XXXXXX")"
cleanup_run() { [ -n "${RUN_OUT:-}" ] && rm -rf "$RUN_OUT"; }
trap cleanup_run EXIT

# ===========================================================================
# Stage 3 + 4 (Linux) — build izba + izba-app, package the debs.
# ===========================================================================
if [ "$DO_LINUX" -eq 1 ]; then
    stage "Stage 3: build Linux bits"
    log "cargo build --release -p izba-cli (vergen native attribution)..."
    IZBA_PROFILE=release cargo build --release -p izba-cli
    LINUX_IZBA="$REPO_ROOT/target/release/izba"
    [ -x "$LINUX_IZBA" ] || die "linux izba binary not built"

    # Correctness gate: the native worktree build must carry the real sha.
    LV="$("$LINUX_IZBA" version 2>&1 || true)"
    if printf '%s' "$LV" | grep -qF "$SHORT"; then
        log "ATTRIBUTION OK (linux): izba version contains $SHORT"
    else
        printf '%s\n' "$LV" >&2
        die "linux izba version does NOT contain $SHORT — native vergen attribution failed."
    fi
    PROV[izba-linux]="built ($SHORT)"

    stage "Stage 4: package Linux debs"
    IZBA_BIN="$LINUX_IZBA" \
    IZBA_CH="$PINNED_BIN/cloud-hypervisor" \
    IZBA_VIRTIOFSD="$PINNED_BIN/virtiofsd" \
    IZBA_VMLINUX="$VMLINUX" \
    IZBA_INITRAMFS="$INITRAMFS" \
    VERSION="$VERSION" OUT_DIR="$RUN_OUT" \
        packaging/build-deb.sh
    [ -f "$RUN_OUT/izba_${VERSION}_amd64.deb" ] || die "build-deb.sh did not produce izba_${VERSION}_amd64.deb"
    PROV[izba-deb]="built"

    if [ "$DO_GUI" -eq 1 ]; then
        log "izba-app .deb: npm ci + tauri build --bundles deb..."
        ( cd app && npm ci && npm run tauri -- build --bundles deb )
        APP_DEB="$(find app/src-tauri/target/release/bundle/deb -maxdepth 1 -name '*.deb' | head -1)"
        [ -n "$APP_DEB" ] || die "tauri did not produce an app .deb"
        # Rename to the sha-stamped filename (internal control version stays
        # 0.1.0 — accepted cosmetic gap; the dir name carries the sha).
        cp -f "$APP_DEB" "$RUN_OUT/izba-app_${VERSION}_amd64.deb"
        PROV[izba-app-deb]="built"
    fi
fi

# ===========================================================================
# Stage 3 + 4 (Windows) — build izba.exe + izba-app.exe + Inno installer.
# ===========================================================================
if [ "$DO_WINDOWS" -eq 1 ]; then
    stage "Stage 3: build Windows bits (native MSVC via powershell.exe)"
    command -v powershell.exe >/dev/null 2>&1 || die "powershell.exe not found — Windows host unreachable. Use --linux-only."

    WINUSER="$(powershell.exe -NoProfile -Command '$env:USERNAME' 2>/dev/null | tr -d '\r')"
    [ -n "$WINUSER" ] || die "could not resolve Windows username via powershell.exe"
    WIN_BUILD_WSL="/mnt/c/Users/$WINUSER/.izba-devbuild/$WORKTREE_KEY"
    mkdir -p "$WIN_BUILD_WSL"
    # Windows-native path of the same dir, for powershell cwd.
    WIN_BUILD_WIN="C:\\Users\\$WINUSER\\.izba-devbuild\\$WORKTREE_KEY"
    log "windows build dir: $WIN_BUILD_WSL"

    # Sync source, preserving target/ + node_modules for incrementality.
    # The workspace-root Cargo.toml/Cargo.lock/rust-toolchain.toml are MANDATORY
    # (crates/* inherit edition/license from [workspace.package]).
    log "rsync source into Windows build dir..."
    rsync -a --delete \
        --exclude target --exclude node_modules --exclude .git \
        crates app Cargo.toml Cargo.lock rust-toolchain.toml \
        "$WIN_BUILD_WSL/"

    # Stage 1 attribution injection: cargo [env] (force) sets the build env that
    # option_env! reads in build_info.rs — the git-less copy has no vergen git data.
    mkdir -p "$WIN_BUILD_WSL/.cargo"
    cat > "$WIN_BUILD_WSL/.cargo/config.toml" <<EOF
# Generated by hack/devbuild.sh — git attribution for the git-less Windows copy.
[env]
VERGEN_GIT_SHA = { value = "$SHA", force = true }
VERGEN_GIT_DESCRIBE = { value = "$DESCRIBE", force = true }
VERGEN_GIT_COMMIT_DATE = { value = "$CDATE", force = true }
IZBA_PROFILE = { value = "release", force = true }
EOF

    # --- Build izba.exe (MSVC). ---
    log "cargo build --release -p izba-cli (Windows)..."
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
        "Set-Location '$WIN_BUILD_WIN'; cargo build --release -p izba-cli; exit \$LASTEXITCODE" \
        || die "Windows cargo build of izba-cli failed"
    WIN_IZBA_WSL="$WIN_BUILD_WSL/target/release/izba.exe"
    [ -f "$WIN_IZBA_WSL" ] || die "izba.exe not found at $WIN_IZBA_WSL"

    # --- MANDATORY attribution gate on the built izba.exe. ---
    WIN_IZBA_WIN="$WIN_BUILD_WIN\\target\\release\\izba.exe"
    WV="$(powershell.exe -NoProfile -Command "& '$WIN_IZBA_WIN' version" 2>/dev/null | tr -d '\r' || true)"
    if printf '%s' "$WV" | grep -qF "$SHORT"; then
        log "ATTRIBUTION OK (windows): izba.exe version contains $SHORT"
    else
        printf '%s\n' "$WV" >&2
        die "windows izba.exe version does NOT contain $SHORT — cargo [env] attribution failed. See design Stage 1 fallback (export VERGEN_* in the PowerShell build env)."
    fi
    PROV[izba.exe]="built ($SHORT)"

    # --- Build izba-app.exe (Tauri, MSVC). ---
    WIN_APP_WSL=""
    if [ "$DO_GUI" -eq 1 ]; then
        log "izba-app.exe: npm ci + tauri build --no-bundle (Windows)..."
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
            "Set-Location '$WIN_BUILD_WIN\\app'; npm ci; if (\$LASTEXITCODE -ne 0) { exit \$LASTEXITCODE }; npm run tauri -- build --no-bundle; exit \$LASTEXITCODE" \
            || die "Windows izba-app.exe build failed"
        WIN_APP_WSL="$WIN_BUILD_WSL/app/src-tauri/target/release/izba-app.exe"
        [ -f "$WIN_APP_WSL" ] || die "izba-app.exe not found at $WIN_APP_WSL"
        PROV[izba-app.exe]="built"
    fi

    # ---- Stage 4 (Windows): assemble the Inno stage + build the installer. ----
    stage "Stage 4: package Windows installer"
    command -v ISCC.exe >/dev/null 2>&1 || true   # ISCC is invoked via its full path below
    STAGE_WSL="$WIN_BUILD_WSL/_stage"
    rm -rf "$STAGE_WSL"
    mkdir -p "$STAGE_WSL/bin/libexec" "$STAGE_WSL/artifacts"
    install -m0755 "$WIN_IZBA_WSL"        "$STAGE_WSL/bin/izba.exe"
    [ -n "$WIN_APP_WSL" ] && install -m0755 "$WIN_APP_WSL" "$STAGE_WSL/bin/izba-app.exe"
    install -m0755 "$OPENVMM_WIN"         "$STAGE_WSL/bin/libexec/openvmm.exe"
    install -m0755 "$MKFS_EROFS_WIN"      "$STAGE_WSL/bin/libexec/mkfs.erofs.exe"
    install -m0644 "$VMLINUX"             "$STAGE_WSL/artifacts/vmlinux"
    install -m0644 "$INITRAMFS"           "$STAGE_WSL/artifacts/initramfs.cpio.gz"

    # The .iss `gui` component pulls in bin\izba-app.exe; with --no-gui that file
    # is absent. Inno errors on a missing Source, so use a copy of the .iss that
    # drops the gui line when --no-gui. Default: ship the repo .iss as-is.
    ISS_WSL="$WIN_BUILD_WSL/_stage_izba.iss"
    if [ "$DO_GUI" -eq 1 ]; then
        cp -f "$REPO_ROOT/packaging/windows/izba.iss" "$ISS_WSL"
    else
        # Strip the gui Source + Icons lines so Inno doesn't require izba-app.exe.
        grep -v 'izba-app.exe' "$REPO_ROOT/packaging/windows/izba.iss" \
            | grep -v 'Components: gui' > "$ISS_WSL"
    fi

    STAGE_WIN="$WIN_BUILD_WIN\\_stage"
    ISS_WIN="$WIN_BUILD_WIN\\_stage_izba.iss"
    WINOUT_WSL="$WIN_BUILD_WSL/_innoout"
    rm -rf "$WINOUT_WSL"; mkdir -p "$WINOUT_WSL"
    WINOUT_WIN="$WIN_BUILD_WIN\\_innoout"

    log "running Inno Setup ISCC.exe..."
    # Resolve ISCC.exe across the per-machine, per-user (winget default), and
    # PATH locations — winget's JRSoftware.InnoSetup installs per-user under
    # %LOCALAPPDATA%\Programs, not Program Files (x86).
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        \$cands = @(
            \"\${env:ProgramFiles(x86)}\\Inno Setup 6\\ISCC.exe\",
            \"\$env:LOCALAPPDATA\\Programs\\Inno Setup 6\\ISCC.exe\",
            \"\$env:ProgramFiles\\Inno Setup 6\\ISCC.exe\"
        )
        \$iscc = \$cands | Where-Object { Test-Path \$_ } | Select-Object -First 1
        if (-not \$iscc) { \$c = Get-Command ISCC.exe -ErrorAction SilentlyContinue; if (\$c) { \$iscc = \$c.Source } }
        if (-not \$iscc) { Write-Error 'ISCC.exe (Inno Setup 6) not found. Install: winget install -e --id JRSoftware.InnoSetup'; exit 3 }
        Write-Host \"using \$iscc\"
        & \$iscc \"/DMyAppVersion=$VERSION\" \"/DStageDir=$STAGE_WIN\" \"/O$WINOUT_WIN\" \"$ISS_WIN\"
        exit \$LASTEXITCODE
    " || die "Inno Setup compile failed (install: winget install -e --id JRSoftware.InnoSetup)"

    SETUP_EXE="$(find "$WINOUT_WSL" -maxdepth 1 -name 'izba-setup-*.exe' | head -1)"
    [ -n "$SETUP_EXE" ] || die "Inno produced no izba-setup-*.exe"
    cp -f "$SETUP_EXE" "$RUN_OUT/izba-setup-${VERSION}.exe"
    PROV[installer]="built"
fi

# ===========================================================================
# Stage 5 — Collect
# ===========================================================================
stage "Stage 5: collect"

# SHA256SUMS over the produced artifacts (exclude the sums file + manifest).
( cd "$RUN_OUT" && find . -maxdepth 1 -type f \
        ! -name SHA256SUMS ! -name manifest.txt -printf '%f\n' \
    | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS )

# manifest.txt — provenance.
{
    echo "version:  $VERSION"
    echo "sha:      $SHA"
    echo "describe: $DESCRIBE"
    echo "date:     $CDATE"
    echo "built:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [ -n "$RUN_ID" ] && echo "ci-run:   $RUN_ID"
    echo ""
    echo "artifacts:"
    for k in vmlinux initramfs mkfs.erofs.exe cloud-hypervisor virtiofsd openvmm.exe \
             izba-linux izba-deb izba-app-deb izba.exe izba-app.exe installer; do
        [ -n "${PROV[$k]:-}" ] && printf '  %-18s %s\n' "$k:" "${PROV[$k]}"
    done
} > "$RUN_OUT/manifest.txt"

# Atomic publish: rename the temp run dir to its final dated name.
TS="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL_NAME="${TS}-${SHORT}${DIRTY}"
FINAL_DIR="$REPO_ROOT/dist/local/$FINAL_NAME"
mkdir -p "$REPO_ROOT/dist/local"
mv "$RUN_OUT" "$FINAL_DIR"
RUN_OUT=""   # disarm cleanup trap (it's published now)

# Repoint latest (relative symlink).
ln -sfn "$FINAL_NAME" "$REPO_ROOT/dist/local/latest"

ELAPSED=$(( $(date +%s) - START_EPOCH ))
stage "DONE in ${ELAPSED}s → dist/local/$FINAL_NAME"
ls -la "$FINAL_DIR" >&2
echo "" >&2
cat "$FINAL_DIR/manifest.txt" >&2
