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
# Arm cleanup BEFORE creating the temp dirs so a failure mid-creation can't
# leak one. The vars are pre-set empty; cleanup skips whichever isn't made yet.
RUN_OUT=""
DL_TMP=""
cleanup() { [ -n "${RUN_OUT:-}" ] && rm -rf "$RUN_OUT"; [ -n "${DL_TMP:-}" ] && rm -rf "$DL_TMP"; }
trap cleanup EXIT
RUN_OUT="$(mktemp -d "$REPO_ROOT/dist/.devbuild-run.XXXXXX")"
DL_TMP="$(mktemp -d "$REPO_ROOT/dist/.devbuild-dl.XXXXXX")"

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
