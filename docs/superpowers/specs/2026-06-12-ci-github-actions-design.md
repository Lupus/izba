# CI for izba: GitHub Actions (Track T, first slice)

**Date:** 2026-06-12
**Status:** Approved
**Scope:** Roadmap Track T — "CI for the six gates" plus the artifact-build
story (kernel, initramfs, mke2fs, mkfs.erofs.exe, izba.exe), published as
workflow artifacts. KVM-gated integration suites stay local (roadmap
decision); promotion to tagged releases waits for M2.

## Decisions

| Question | Decision |
| --- | --- |
| Scope | Six gates + artifact builds (not KVM integration) |
| Artifact publication | `actions/upload-artifact` (90-day retention); releases at M2 |
| Triggers | ci.yml: PRs + main pushes. artifacts.yml: main pushes (path-filtered) + `workflow_dispatch` |
| Native Windows | Yes — `windows-latest` job runs unit tests for proto/core/cli |
| Workflow shape | Grouped by target: gates sharing compilation share a job + cache |
| Supply chain | Every download checksum-pinned and verified before building/promoting; actions pinned by commit SHA |

## 1. Layout & triggers

Two workflows in `.github/workflows/`:

- **`ci.yml`** — every PR and every push to `main`. Concurrency group keyed
  on workflow + ref with `cancel-in-progress: true`.
- **`artifacts.yml`** — pushes to `main` filtered to artifact-affecting
  paths (`hack/**`, `crates/izba-init/**`, `crates/izba-cli/**`,
  `crates/izba-proto/**`, `crates/izba-core/**`, `Cargo.lock`,
  `.github/workflows/artifacts.yml`) + `workflow_dispatch`. Not on PRs:
  the kernel build is too heavy for PR feedback and ci.yml already gates
  the code that feeds the artifacts.

## 2. `ci.yml` — the six gates + native Windows

Three jobs, each with `timeout-minutes` and its own `Swatinem/rust-cache`:

### `linux-gates` (ubuntu-latest)

1. `cargo fmt --check` — fails in seconds, before any build
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` — reuses clippy's target dir, near-free
   incremental cost; KVM suites self-skip without `IZBA_INTEGRATION=1`

### `cross-gates` (ubuntu-latest)

apt: `musl-tools`, `gcc-mingw-w64-x86-64`; `rustup target add
x86_64-unknown-linux-musl x86_64-pc-windows-gnu`. Then:

1. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
   (the static-init gate)
2. `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
3. `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`

### `windows-native` (windows-latest)

`cargo test -p izba-proto -p izba-core -p izba-cli` — catches
Windows-specific runtime breakage the Linux-hosted cross *check* cannot.
Integration-style tests self-skip as on any host without artifacts.

## 3. `artifacts.yml` — pinned, verified, promoted

Fan-out jobs; arrows are `needs:` edges:

```
kernel ───────────────────────────────┐
mke2fs ──→ initramfs ─────────────────┤
erofs-windows ──→ erofs-parity (win) ─┼──→ manifest ──→ upload
izba-windows ─────────────────────────┘
```

- **`kernel`**: `hack/build-kernel.sh` → `dist/vmlinux`. The *built*
  vmlinux is cached via `actions/cache` keyed on
  `hashFiles('hack/kernel.config', 'hack/build-kernel.sh')` — unchanged
  inputs skip the ~20-minute rebuild entirely. The source tarball is also
  cached (`~/.cache/izba/kernel/`).
- **`mke2fs`**: **new `hack/build-mke2fs.sh`** — pinned e2fsprogs 1.47.2
  tarball + sha256, static x86_64 build. Replaces the hand-archived
  `dist/mke2fs-1.47.2-static-x86_64` as the reproducible source of truth.
- **`initramfs`**: needs `mke2fs`; `hack/build-initramfs.sh` with
  `IZBA_MKE2FS` pointing at the fresh static binary, so the shipped
  initramfs can format a blank `rw.img` in-guest.
- **`erofs-windows`**: `hack/build-mkfs-erofs-windows.sh` →
  `dist/mkfs.erofs.exe` + Linux reference + `dist/erofs-parity-bundle/`.
- **`erofs-parity`** (windows-latest): runs
  `hack/spike/verify-mkfs-erofs-parity.ps1` on the bundle — the
  byte-identical proof, today manual, becomes a gate before the .exe is
  promoted.
- **`izba-windows`**: win-gnu release build of `izba-cli`, assembled into
  the installer-shaped `bin/` + `bin/libexec/` layout in-job (mirroring
  `hack/stage-izba-windows.sh`, which itself is WSL-interop-only —
  `powershell.exe`, `/mnt/c` — and can't run on a runner) → `izba.exe` +
  parity-proven `mkfs.erofs.exe` bundle.
- **`manifest`**: needs all of the above; writes `SHA256SUMS` over every
  produced file plus a `VERSIONS` provenance file (pinned source versions
  + commit; exact rustc/mingw tool versions deferred until needed), then
  `actions/upload-artifact` per artifact group.

Out of scope: `openvmm.exe` (fetched pinned via `fetch-openvmm.sh`, not
built; revisit if the Plan-B fork build activates),
`fetch-artifacts.sh` binaries (cloud-hypervisor/virtiofsd — not consumed
by artifact builds; see Follow-ups).

## 4. Supply-chain pinning rules

- **Fix existing gap:** `hack/build-kernel.sh` downloads the kernel
  tarball with no verification. It gains a pinned sha256 for the default
  6.12.30 tarball, verified before extraction (same pattern as
  `build-mkfs-erofs-windows.sh`: mismatch ⇒ delete + error). Overriding
  the version requires supplying the matching sha256.
- **New scripts are born pinned:** `build-mke2fs.sh` ships with version +
  sha256 from day one.
- **Actions pinned by full commit SHA** (`actions/checkout@<sha> # vX`,
  `Swatinem/rust-cache@<sha> # vX`, `actions/cache@<sha>`,
  `actions/upload-artifact@<sha>`), never floating tags.
- **No raw downloads in workflow YAML** — every fetch goes through a
  hack/ script that verifies before use, so local and CI share one
  verified code path.
- **Rust toolchain:** stays `channel = "stable"` (local convention); the
  manifest job records the pinned source versions + commit for provenance
  (exact per-run tool versions deferred until a concrete need).

## 5. Verifying the CI itself

- `actionlint` run locally on the workflow files before commit.
- The PR introducing `ci.yml` proves the six gates by running them.
- Modified `build-kernel.sh` and new `build-mke2fs.sh` are exercised
  locally (WSL2) before merge; `artifacts.yml` gets a
  `workflow_dispatch` smoke run after merge.

## Follow-ups (not this slice)

- sha256-pin `fetch-artifacts.sh` downloads (cloud-hypervisor, virtiofsd).
- KVM integration suite in CI: `ubuntu-latest` exposes `/dev/kvm`; once
  artifacts.yml is stable its outputs + `fetch-artifacts.sh` could feed an
  env-gated integration job. Deliberately deferred (roadmap: local for now).
- Release promotion (tags + prebuilt binaries) at M2, per Track T.
