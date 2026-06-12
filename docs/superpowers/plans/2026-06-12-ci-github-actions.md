# CI: six gates + pinned artifact builds — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two GitHub Actions workflows — `ci.yml` (the six local gates + native Windows tests) and `artifacts.yml` (kernel, mke2fs, initramfs, mkfs.erofs.exe with Windows parity gate, izba.exe bundle) — with every download checksum-pinned and verified.

**Architecture:** Gates grouped by target so jobs that share compilation share a cache (linux-gates / cross-gates / windows-native). Artifacts fan out as independent jobs joined by `needs:` edges, ending in a manifest job that writes `SHA256SUMS` + `VERSIONS`. All fetches go through hack/ scripts that verify sha256 before use; workflow actions are pinned by full commit SHA.

**Tech Stack:** GitHub Actions (ubuntu-latest, windows-latest), bash, rustup/cargo (stable via `rust-toolchain.toml`), mingw-w64, musl.

**Spec:** `docs/superpowers/specs/2026-06-12-ci-github-actions-design.md`

---

## Execution policy (owner directive — read first)

- **Getting CI green takes many push→watch→fix iterations. Budget for it.**
  Do not declare failure or escalate before **10 attempts per failing job**;
  expect 10–15 total iterations across the PR as normal, not as a problem.
- **The main session steers; subagents do the work.** Dispatch a fresh
  subagent per task (and per CI-fix iteration in Task 7). The main context
  must NOT edit workflow YAML or scripts directly during the iteration loop.
- **Verify subagent claims independently.** After every subagent reports:
  (a) `git log --oneline -3` + `git diff HEAD~1` to review what it actually
  changed; (b) for CI claims, confirm with
  `gh run list --branch <branch> --limit 5` and
  `gh run view <id> --json jobs --jq '.jobs[] | {name, conclusion}'` —
  accept "CI is green" only from run conclusions you fetched yourself.
- **Diagnose from logs, not guesses:** `gh run view <id> --log-failed` is
  the input to each fix subagent's prompt.
- Pushes from this environment may need the sandbox disabled (network
  allowlist); if a push is denied, give the user the exact
  `git push` command instead and wait.

## Verified pins (authoritative, fetched 2026-06-12)

| What | Value |
| --- | --- |
| linux-6.12.30.tar.xz sha256 | `df046a48971e40ce0b2e003e7e55b6b1e7da2912120eb216d5d6c8450c9cf82e` (kernel.org sha256sums.asc; matches local cache) |
| e2fsprogs-1.47.2.tar.xz sha256 | `08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c` (kernel.org sha256sums.asc) |
| actions/checkout | `9f698171ed81b15d1823a05fc7211befd50c8ae0` # v6.0.3 |
| actions/cache | `27d5ce7f107fe9357f9df03efb73ab90386fccae` # v5.0.5 |
| actions/upload-artifact | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` # v7.0.1 |
| actions/download-artifact | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` # v8.0.1 |
| Swatinem/rust-cache | `23869a5bd66c73db3c0ac40331f3206eb23791dc` # v2.9.1 |

## File map

- Modify: `hack/build-kernel.sh` — sha256 verification of the kernel tarball
- Create: `hack/build-mke2fs.sh` — pinned static mke2fs build
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/artifacts.yml`
- Modify: `hack/README.md` — document the new script + pinning behavior

Worktree: `/home/kolkhovskiy/git/izba/.claude/worktrees/ci-github-actions`
(branch `worktree-ci-github-actions`). Toolchain env (the repo-root
`.cargo-env` uses `$PWD` and does NOT work from the worktree):

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup
export CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
```

---

### Task 1: sha256-pin the kernel tarball in `build-kernel.sh`

**Files:**
- Modify: `hack/build-kernel.sh:24-25` (pin table) and `:60-75` (verify)

- [ ] **Step 1: Add the pin and a verify-only escape hatch**

In `hack/build-kernel.sh`, after line 25 (`OUTPUT="${2:-dist/vmlinux}"`), add:

```bash
# sha256 pins for known-good tarballs.  Building any other VERSION requires
# IZBA_KERNEL_SHA256=<hash> — there is deliberately no unverified path.
declare -A KNOWN_SHA256=(
    ["6.12.30"]="df046a48971e40ce0b2e003e7e55b6b1e7da2912120eb216d5d6c8450c9cf82e"
)
EXPECTED_SHA256="${IZBA_KERNEL_SHA256:-${KNOWN_SHA256[$VERSION]:-}}"
if [ -z "$EXPECTED_SHA256" ]; then
    echo "error: no pinned sha256 for linux-${VERSION}; set IZBA_KERNEL_SHA256" >&2
    exit 1
fi
```

- [ ] **Step 2: Verify after download / on cache hit**

Replace the `else`-branch line `echo "Using cached tarball: $TARBALL_PATH"`
region: after the whole `if [ ! -f "$TARBALL_PATH" ] ... fi` block (line 75),
add:

```bash
GOT_SHA256="$(sha256sum "$TARBALL_PATH" | cut -d' ' -f1)"
if [ "$GOT_SHA256" != "$EXPECTED_SHA256" ]; then
    rm -f "$TARBALL_PATH"
    echo "error: $TARBALL sha256 mismatch — removed; re-run to re-download" >&2
    echo "  got:  $GOT_SHA256" >&2
    echo "  want: $EXPECTED_SHA256" >&2
    exit 1
fi
echo "sha256 OK: $TARBALL"
# CI smoke / tests: stop after verification, before the expensive build.
if [ "${IZBA_KERNEL_VERIFY_ONLY:-0}" = "1" ]; then
    exit 0
fi
```

- [ ] **Step 3: Negative test — corrupt tarball is rejected and deleted**

```bash
cd /home/kolkhovskiy/git/izba/.claude/worktrees/ci-github-actions
TMPCACHE=$(mktemp -d)
mkdir -p "$TMPCACHE/izba/kernel"
echo corrupt > "$TMPCACHE/izba/kernel/linux-6.12.30.tar.xz"
XDG_CACHE_HOME="$TMPCACHE" IZBA_KERNEL_VERIFY_ONLY=1 hack/build-kernel.sh; echo "exit=$?"
ls "$TMPCACHE/izba/kernel/"
```

Expected: `sha256 mismatch` error, `exit=1`, and the corrupt file is gone.

- [ ] **Step 4: Positive test — real cached tarball passes**

```bash
IZBA_KERNEL_VERIFY_ONLY=1 hack/build-kernel.sh; echo "exit=$?"
```

Expected: `sha256 OK: linux-6.12.30.tar.xz`, `exit=0` (uses the real
`~/.cache/izba/kernel/` tarball; takes ~1 s of hashing a 148 MB file).

- [ ] **Step 5: Unknown version without override is rejected**

```bash
IZBA_KERNEL_VERIFY_ONLY=1 hack/build-kernel.sh 6.12.31; echo "exit=$?"
```

Expected: `no pinned sha256 for linux-6.12.31`, `exit=1`.

- [ ] **Step 6: Commit**

```bash
git add hack/build-kernel.sh
git commit -m "feat(hack): sha256-pin the kernel tarball in build-kernel.sh"
```

---

### Task 2: `hack/build-mke2fs.sh` — pinned static mke2fs

**Files:**
- Create: `hack/build-mke2fs.sh` (mode 755)

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Build a static x86_64 mke2fs from pinned e2fsprogs sources.
#
# Usage:  hack/build-mke2fs.sh [OUTPUT]
#         OUTPUT defaults to dist/mke2fs-<version>-static-x86_64
#
# The result is the binary embedded into the initramfs via
# IZBA_MKE2FS (see build-initramfs.sh) so the guest can format a blank
# rw.img on first boot.  Source tarball is sha256-verified before use.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

VERSION=1.47.2
SHA256=08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c
URL="https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${VERSION}/e2fsprogs-${VERSION}.tar.xz"

OUTPUT="${1:-dist/mke2fs-${VERSION}-static-x86_64}"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/izba/e2fsprogs"
TARBALL="$CACHE/e2fsprogs-${VERSION}.tar.xz"

# musl-gcc gives a truly static binary with no glibc NSS caveats.
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "error: musl-gcc not found — install it with:" >&2
    echo "  sudo apt-get install -y musl-tools" >&2
    exit 1
fi

mkdir -p "$CACHE"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$URL"
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$TARBALL"
    echo "error: e2fsprogs tarball failed sha256 verification — removed; re-run" >&2
    exit 1
fi
echo "sha256 OK: e2fsprogs-${VERSION}.tar.xz"

SRC="$CACHE/e2fsprogs-${VERSION}"
[ -d "$SRC" ] || tar -C "$CACHE" -xf "$TARBALL"

BUILD="$CACHE/build-static"
rm -rf "$BUILD" && mkdir -p "$BUILD"
cd "$BUILD"
"$SRC/configure" CC=musl-gcc CFLAGS="-O2" LDFLAGS="-static" \
    --disable-nls --disable-elf-shlibs --disable-uuidd \
    --disable-fuse2fs --disable-debugfs --disable-imager \
    --disable-resizer --disable-defrag \
    >/dev/null
make -j"$(nproc)" libs >/dev/null
make -j"$(nproc)" -C misc mke2fs >/dev/null

cd "$REPO_ROOT"
mkdir -p "$(dirname "$OUTPUT")"
cp "$BUILD/misc/mke2fs" "$OUTPUT"
chmod 755 "$OUTPUT"

file "$OUTPUT" | grep -q "statically linked" || {
    echo "error: $OUTPUT is not statically linked" >&2
    exit 1
}
echo "wrote $OUTPUT ($(du -sh "$OUTPUT" | cut -f1), static)"
```

Note: if `configure`/`make` fail on a flag (these `--disable-*` names are the
best-known set), iterate on the flag list — the authority is Step 3's
functional test, not the exact flags. `make libs` then `make -C misc mke2fs`
builds only what mke2fs needs; fall back to a plain full `make` if the
partial build proves brittle.

- [ ] **Step 2: Run it**

```bash
chmod +x hack/build-mke2fs.sh
hack/build-mke2fs.sh
```

Expected: `sha256 OK`, then `wrote dist/mke2fs-1.47.2-static-x86_64 (... static)`.

- [ ] **Step 3: Functional test — it actually formats ext4**

```bash
truncate -s 64M /tmp/claude/mke2fs-test.img
dist/mke2fs-1.47.2-static-x86_64 -q -t ext4 /tmp/claude/mke2fs-test.img
file /tmp/claude/mke2fs-test.img
rm /tmp/claude/mke2fs-test.img
```

Expected: `file` reports `ext4 filesystem data`.

- [ ] **Step 4: Corruption test — bad tarball rejected**

```bash
TMPCACHE=$(mktemp -d); mkdir -p "$TMPCACHE/izba/e2fsprogs"
echo corrupt > "$TMPCACHE/izba/e2fsprogs/e2fsprogs-1.47.2.tar.xz"
XDG_CACHE_HOME="$TMPCACHE" hack/build-mke2fs.sh; echo "exit=$?"
```

Expected: `failed sha256 verification — removed`, `exit=1`.

- [ ] **Step 5: Commit**

```bash
git add hack/build-mke2fs.sh
git commit -m "feat(hack): build-mke2fs.sh — pinned static mke2fs from e2fsprogs 1.47.2"
```

---

### Task 3: `.github/workflows/ci.yml`

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: CI

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
  linux-gates:
    name: fmt + clippy + test (linux)
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: linux-gates
      - run: cargo fmt --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace

  cross-gates:
    name: musl init + windows-gnu checks
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Install cross toolchains
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends musl-tools gcc-mingw-w64-x86-64
      - run: rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: cross-gates
      - run: cargo build -p izba-init --target x86_64-unknown-linux-musl --release
      - run: cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
      - run: cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings

  windows-native:
    name: cargo test (windows)
    runs-on: windows-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: windows-native
      - run: cargo test -p izba-proto -p izba-core -p izba-cli
```

Notes for the executor:
- `rust-toolchain.toml` (channel `stable`, musl target) drives rustup on all
  runners — no toolchain action needed.
- KVM-gated tests self-skip without `IZBA_INTEGRATION=1`; unit tests that
  bind sockets runtime-skip on PermissionDenied (project test-design rule),
  so `cargo test` is runner-safe by design.
- `windows-native` builds with the MSVC host toolchain — first-ever native
  MSVC build of these crates; expect possible link/dep issues. That job is
  the most likely candidate for the Task 7 iteration budget.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "feat(ci): six-gate ci.yml — linux gates, cross gates, native Windows tests"
```

---

### Task 4: `.github/workflows/artifacts.yml`

**Files:**
- Create: `.github/workflows/artifacts.yml`

- [ ] **Step 1: Write the workflow**

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
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  kernel:
    name: vmlinux (pinned 6.12.30)
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Restore built vmlinux
        id: vmlinux
        uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
        with:
          path: dist/vmlinux
          key: vmlinux-${{ hashFiles('hack/kernel.config', 'hack/build-kernel.sh') }}
      - name: Install kernel build deps
        if: steps.vmlinux.outputs.cache-hit != 'true'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential flex bison bc libelf-dev
      - name: Build kernel
        if: steps.vmlinux.outputs.cache-hit != 'true'
        run: hack/build-kernel.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: vmlinux
          path: dist/vmlinux
          if-no-files-found: error

  mke2fs:
    name: static mke2fs (pinned e2fsprogs 1.47.2)
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends musl-tools
      - run: hack/build-mke2fs.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: mke2fs
          path: dist/mke2fs-*-static-x86_64
          if-no-files-found: error

  initramfs:
    name: initramfs (izba-init + embedded mke2fs)
    needs: mke2fs
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends musl-tools cpio
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: initramfs
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: mke2fs
          path: dist/
      - name: Build initramfs with embedded mke2fs
        run: |
          chmod 755 dist/mke2fs-*-static-x86_64
          IZBA_MKE2FS="$(echo dist/mke2fs-*-static-x86_64)" hack/build-initramfs.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: initramfs
          path: dist/initramfs.cpio.gz
          if-no-files-found: error

  erofs-windows:
    name: mkfs.erofs.exe (pinned erofs-utils 1.9.1)
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            curl tar make gcc autoconf automake libtool-bin pkg-config patch \
            gcc-mingw-w64-x86-64
      - run: hack/build-mkfs-erofs-windows.sh
      - name: Emit parity bundle (no wine — exit 2 expected)
        run: |
          set +e
          hack/verify-mkfs-erofs-parity.sh
          rc=$?
          set -e
          # 0 = parity proven here (wine present); 2 = bundle emitted for the
          # Windows leg. Anything else is a real failure.
          if [ "$rc" != 0 ] && [ "$rc" != 2 ]; then exit "$rc"; fi
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: erofs-parity-bundle
          path: dist/erofs-parity-bundle/
          if-no-files-found: error

  erofs-parity:
    name: parity proof (real Windows)
    needs: erofs-windows
    runs-on: windows-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: erofs-parity-bundle
          path: bundle
      - run: pwsh -File hack/spike/verify-mkfs-erofs-parity.ps1 bundle
      - name: Upload verified mkfs.erofs.exe
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: mkfs-erofs-windows
          path: bundle/mkfs.erofs.exe
          if-no-files-found: error

  izba-windows:
    name: izba.exe bundle (win-gnu)
    needs: erofs-parity
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64
      - run: rustup target add x86_64-pc-windows-gnu
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
        with:
          prefix-key: izba-windows
      - run: cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: mkfs-erofs-windows
          path: stage/bin/libexec
      - name: Assemble installer-shaped bundle
        # Mirrors hack/stage-izba-windows.sh layout (bin/ + bin/libexec/)
        # minus openvmm.exe, which is fetched-not-built (out of scope; see
        # the design doc) and minus boot artifacts (separate artifacts here).
        run: |
          mkdir -p stage/bin
          cp target/x86_64-pc-windows-gnu/release/izba.exe stage/bin/
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: izba-windows-bundle
          path: stage/
          if-no-files-found: error

  manifest:
    name: SHA256SUMS + provenance
    needs: [kernel, initramfs, mke2fs, erofs-parity, izba-windows]
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          path: all
      - name: Write SHA256SUMS + VERSIONS
        run: |
          cd all
          find . -type f | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
          {
            echo "commit: ${{ github.sha }}"
            echo "linux: 6.12.30"
            echo "e2fsprogs: 1.47.2"
            echo "erofs-utils: 1.9.1"
          } > VERSIONS
          cat SHA256SUMS VERSIONS
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: manifest
          path: |
            all/SHA256SUMS
            all/VERSIONS
          if-no-files-found: error
```

Notes for the executor:
- `izba-windows` deliberately `needs: erofs-parity` so the bundled
  `mkfs.erofs.exe` is the parity-proven one (promotion-after-verification).
- rustc/mingw versions for `VERSIONS`: if you want exact tool versions,
  extend the manifest step later; the pinned source versions are the
  load-bearing part.
- `hashFiles` for the vmlinux cache covers `kernel.config` + the build
  script — a sha256-pin bump or config change invalidates the cache.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/artifacts.yml
git commit -m "feat(ci): artifacts.yml — pinned kernel/mke2fs/initramfs/erofs/izba.exe + manifest"
```

---

### Task 5: lint the workflows locally

- [ ] **Step 1: Run actionlint (pinned) on both workflows**

```bash
cd /tmp/claude && mkdir -p actionlint && cd actionlint
curl -fsSL -o actionlint.tar.gz \
  https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_amd64.tar.gz
curl -fsSL -o checksums.txt \
  https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_checksums.txt
grep linux_amd64 checksums.txt | sha256sum -c -
tar xzf actionlint.tar.gz actionlint
cd /home/kolkhovskiy/git/izba/.claude/worktrees/ci-github-actions
/tmp/claude/actionlint/actionlint .github/workflows/ci.yml .github/workflows/artifacts.yml
```

Expected: no output (clean). If the sandbox blocks the GitHub release
download (redirects to objects.githubusercontent.com), retry the curl with
the sandbox disabled — it is a dev tool, verified against the release's
checksums.txt. Fix any actionlint findings before proceeding.

- [ ] **Step 2: Commit fixes (if any)**

```bash
git add .github/workflows/
git commit -m "fix(ci): actionlint findings"
```

(Skip the commit if actionlint was already clean.)

---

### Task 6: document in `hack/README.md`

**Files:**
- Modify: `hack/README.md` (Scripts section, after `build-kernel.sh`)

- [ ] **Step 1: Add the build-mke2fs.sh section and pinning notes**

After the `build-kernel.sh` section (line ~50), add:

```markdown
### `build-mke2fs.sh`

Builds a static x86_64 `mke2fs` from pinned e2fsprogs sources (musl-linked,
sha256-verified tarball). Output defaults to
`dist/mke2fs-<version>-static-x86_64` — feed it to `build-initramfs.sh` via
`IZBA_MKE2FS` to enable in-guest first-boot formatting of `rw.img`.
```

And in the `build-kernel.sh` section, append:

```markdown
The source tarball is sha256-pinned: known versions are verified against a
hash table in the script; building any other version requires
`IZBA_KERNEL_SHA256=<hash>`. `IZBA_KERNEL_VERIFY_ONLY=1` stops after
verification (used by tests).
```

- [ ] **Step 2: Commit**

```bash
git add hack/README.md
git commit -m "docs(hack): document build-mke2fs.sh and kernel tarball pinning"
```

---

### Task 7: push, open PR, iterate until CI is green

This is the steering loop — **main session steers, subagents fix** (see
Execution policy at the top: ≥10 attempts per failing job before escalating).

- [ ] **Step 1: Run the six gates locally first**

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup \
       CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo \
       PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
cargo fmt --check && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo test --workspace && \
cargo build -p izba-init --target x86_64-unknown-linux-musl --release && \
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli && \
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings && \
echo ALL-SIX-GREEN
```

Expected: `ALL-SIX-GREEN`.

- [ ] **Step 2: Push the branch (user-assisted)**

Confirm `git branch --show-current` prints `worktree-ci-github-actions`,
then give the user:

```bash
git push -u origin worktree-ci-github-actions:feat/ci-github-actions
```

(Attempt it sandbox-disabled first; hand it to the user if denied.)

- [ ] **Step 3: Open the PR (give the user this command)**

```zsh
gh pr create --head feat/ci-github-actions --title 'feat(ci): six gates + pinned artifact builds (Track T)' --body '''
## Summary
- ci.yml: linux-gates (fmt/clippy/test), cross-gates (musl init + win-gnu check/clippy), windows-native (cargo test on windows-latest)
- artifacts.yml: pinned vmlinux + static mke2fs + initramfs + mkfs.erofs.exe (with real-Windows byte-parity gate) + izba.exe bundle + SHA256SUMS/VERSIONS manifest
- build-kernel.sh: kernel tarball now sha256-pinned (df046a48…, verified against kernel.org)
- new build-mke2fs.sh: pinned e2fsprogs 1.47.2, static musl build
- every download verified before use; all actions pinned by commit SHA

Spec: docs/superpowers/specs/2026-06-12-ci-github-actions-design.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
'''
```

- [ ] **Step 4: Watch ci.yml on the PR**

```bash
gh run list --branch feat/ci-github-actions --limit 5
gh run watch <run-id> --exit-status || gh run view <run-id> --log-failed
```

- [ ] **Step 5: Smoke-run artifacts.yml from the branch**

`workflow_dispatch` works on a branch once the file exists on it:

```bash
gh workflow run artifacts.yml --ref feat/ci-github-actions
gh run list --workflow artifacts.yml --limit 3
gh run watch <run-id> --exit-status || gh run view <run-id> --log-failed
```

- [ ] **Step 6: Iterate (the patience loop)**

For each failing job: feed `gh run view <id> --log-failed` output to a fresh
fix subagent scoped to that job; review its diff; commit; push (Step 2
command, no `-u`); re-watch. Track attempts per job; only after 10 failed
attempts on the same job, stop and present the full failure history to the
user with a recommendation.

- [ ] **Step 7: Done criteria**

All ci.yml jobs green on the PR **and** an artifacts.yml dispatch run fully
green (all 7 jobs incl. `erofs-parity` and `manifest`), confirmed via
`gh run view --json jobs` by the main session — then report with run URLs.

---

## Self-review (done at plan time)

- **Spec coverage:** §1 triggers → Tasks 3/4 `on:` blocks; §2 six gates +
  windows-native → Task 3; §3 artifact fan-out + parity + manifest → Task 4;
  §4 pinning (kernel gap → Task 1, born-pinned mke2fs → Task 2, SHA-pinned
  actions → Tasks 3/4, no raw workflow downloads → all fetches in hack/
  scripts); §5 verify-CI-itself → Tasks 5 and 7. Follow-ups intentionally
  unplanned (out of scope).
- **No placeholders:** every step has complete code/commands. The two
  "iterate if flags fight back" notes (Task 2 configure flags, Task 7 loop)
  are bounded escape hatches with authoritative tests, not deferred work.
- **Consistency:** artifact names (`mke2fs`, `erofs-parity-bundle`,
  `mkfs-erofs-windows`, `izba-windows-bundle`) match between upload and
  download steps; action SHAs identical everywhere; `IZBA_KERNEL_VERIFY_ONLY`
  used consistently in Task 1 tests.
