# CI-built dev installers, laptop downloads only — design

**Date:** 2026-06-16
**Status:** Approved (brainstorming → spec)
**Supersedes the local-build role of:** `hack/devbuild.sh` and
[2026-06-15-local-devbuild-script-design.md](2026-06-15-local-devbuild-script-design.md)

## Problem

`hack/devbuild.sh` builds the full installer set **locally** for manual UI/UX
testing. The heavy boot artifacts (vmlinux, initramfs) were already fetched
from CI; only the *packaging* — the Rust binaries and the Tauri app for both
Linux and Windows — was built on the laptop. That local packaging is the load:

- a Rust `target/` per worktree on the Linux side (multi-GB each);
- a **second** `target/` per worktree on the Windows host, under
  `/mnt/c/Users/<user>/.izba-devbuild/<worktree>` (the rsync'd git-less copy);
- Tauri/npm builds on both sides;
- all of it multiplied by every parallel worktree.

With several worktrees building at once this exhausts disk and takes a long
time while pinning both the WSL2 instance and the Windows host.

The boot artifacts already proved the model: CI builds them, the laptop fetches
them. This design extends that to **everything** — CI packages the installers,
the laptop does nothing but `gh run download`.

## Decisions (locked during brainstorming)

1. **Trigger: on-demand dispatch.** The agent runs the build explicitly when a
   testable installer is wanted (typically right after opening the PR). Leanest
   on Windows-runner minutes; fully under agent control. *Not* auto-on-every-PR.
2. **Fully replace the local build.** No heavy build ever runs on the laptop or
   Windows host again. Accepted consequence: no offline / CI-red fallback.
3. **Dedicated lean `devbuild.yml`** that reuses the existing `_artifacts.yml`
   and has its own packaging jobs, with **no test-gate dependency**.
   `release.yml` is left untouched (zero risk to the working release path).

## Architecture

Three parts: a new CI workflow, a rewritten helper script, and a CLAUDE.md
update.

### Part 1 — `.github/workflows/devbuild.yml` (new, dispatch-only)

A lean sibling of `release.yml` that produces the three installer artifacts for
any branch and stops there — no GitHub Release, no smoke gate, read-only token.

```yaml
name: Dev build (installers)
on:
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: devbuild-${{ github.ref }}
  cancel-in-progress: true        # a re-dispatch supersedes the prior one
jobs:
  version:        # base~git<sha>, identical scheme to release.yml's non-tag path
  artifacts:      # uses: ./.github/workflows/_artifacts.yml   (UNCHANGED, reused)
  izba-linux-bin: # copied verbatim from release.yml
  app-linux-deb:  # copied verbatim from release.yml
  app-windows-build:  # copied verbatim from release.yml
  package-deb:    # needs: [version, artifacts, izba-linux-bin]  — copied
  package-windows:# needs: [version, artifacts, app-windows-build] — copied
```

Key properties:

- **No `needs: gate`.** `ci.yml` is the authoritative test gate on the PR;
  `devbuild` starts packaging immediately and runs truly in parallel with the
  PR checks. (Re-running `cargo test --workspace` here would be redundant with
  `ci.yml` and would slow time-to-delivery — that is the concrete reason this is
  a dedicated workflow rather than reusing `release.yml`, whose package jobs
  `needs: gate`.)
- **Vergen attribution needs no special handling.** Unlike the local Windows
  git-less copy (which required injecting `VERGEN_GIT_*` into the build env),
  CI builds inside a real `.git` checkout, so `izba version` carries the correct
  sha natively. The local script's whole Stage-1 attribution machinery
  disappears.
- **openvmm pin de-duplication.** `package-windows` fetches openvmm by running
  `hack/fetch-openvmm.sh` directly — that script *is* the pin's source of
  truth — instead of copying `release.yml`'s hardcoded `openvmm-run-<id>` cache
  key. The pin then lives in exactly one place. (Caching openvmm across dispatch
  runs is an optional later optimization; correctness does not depend on it.)
- **Artifacts uploaded:** `izba-deb`, `izba-app-deb`, `izba-windows-installer`
  (same artifact names release.yml uses), version-stamped `base~git<sha>`.

**Accepted cost:** ~80 lines of packaging-job YAML are shared with `release.yml`.
The two will rarely diverge; if they do, the clean follow-up is to extract a
reusable `_package.yml` that both call (the rejected Approach 3 — deferred to
avoid rewiring the working release path now).

### Part 2 — `hack/devbuild.sh` rewritten as a download helper

All heavy-build stages are deleted. Still run **outside the agent Bash sandbox**
(it needs `gh`, which the sandbox blocks). New flow:

1. **Resolve target.** Branch = current branch (or `--ref <branch>`); capture
   HEAD sha (short + full) and `git show -s --format=%cs` date for the manifest.
2. **Dispatch** (unless `--no-dispatch` / `--run <id>`):
   `gh workflow run devbuild.yml --ref <branch>`.
3. **Find the run.** Poll `gh run list --workflow=devbuild.yml --branch
   <branch> --json databaseId,headSha,status,createdAt -L 10` and select the
   newest run whose `headSha` equals the current HEAD sha. (Matching on
   `headSha` rather than "newest" avoids racing a concurrent dispatch.)
4. **Watch:** `gh run watch <id> --exit-status` (fails the script if CI fails).
5. **Download:** `gh run download <id> -n izba-deb -n izba-app-deb -n
   izba-windows-installer -D <tmpdir>`. With `--linux-only` / `--windows-only` /
   `--no-gui`, download only the corresponding subset (the build still produces
   the full set; these flags only choose what to stage locally).
6. **Collect — reuse today's Stage 5 verbatim:** stage into a temp run dir,
   atomically rename to `dist/local/<ts>-<sha>/`, write `SHA256SUMS` and
   `manifest.txt` (provenance now records the **CI run id** and per-artifact
   "fetched (run N)"), repoint the relative `latest` symlink.
7. **Worktree → main-checkout copy** (kept): when run from a worktree, copy the
   published run dir into the main checkout's `dist/local/` so the owner finds
   it where they expect (plain copy, survives worktree removal).
8. **Print install commands** — the ready-to-paste block currently documented in
   CLAUDE.md (Linux `dpkg -i`, Windows `Start-Process` via WSL interop).

**Kept:** `--clean [--keep N]` pruning, the `dist/local/<ts>-<sha>/` layout,
`latest` symlink, `SHA256SUMS` + `manifest.txt`, worktree→main copy, the
logging helpers, and the `--linux-only`/`--windows-only`/`--no-gui` scope flags
(now scoping the *download*, not a build).

**New flags:** `--ref <branch>`, `--run <id>`, `--no-dispatch`.

**Removed:** `--refresh-kernel`, `--refresh-initramfs`, `--refresh-vmm`,
`--build-heavy`, `--fetch-only`, `--wait`, and all the supporting machinery —
the shared CI/pinned caches, the flock locks, the rsync-to-`/mnt/c` Windows
build, the powershell `cargo`/`npm`/Inno invocations, and the vergen-attribution
injection + gates. The toolchain-bootstrap preamble is no longer needed (no
local cargo build).

### Part 3 — CLAUDE.md update

Rewrite the "Standard delivery loop" step 2–3 in the
**Agent autonomy & delivery workflow** section:

- Replace "While CI runs, bake a local dev build … with `bash hack/devbuild.sh`"
  with: dispatch the installer build on the branch — `hack/devbuild.sh`
  (unsandboxed) dispatches `devbuild.yml`, watches it, and downloads the
  installers into `dist/local/<ts>-<sha>/`.
- Keep the **report the exact `dist/local/<ts>-<sha>/` path (never `latest`)**
  rule, the worktree→main-checkout copy rule, and the ready-to-paste install
  commands (they are unchanged — they operate on the downloaded installers).
- Note that the build runs entirely in CI in parallel with the PR checks; the
  laptop only downloads.

## Flow (end to end)

```
agent: git push + gh pr create        ──▶ ci.yml gates run on the PR
agent: hack/devbuild.sh (unsandboxed) ──▶ gh workflow run devbuild.yml --ref <branch>
                                          (runs in parallel with ci.yml)
       └─ watch ─ download ─ dist/local/<ts>-<sha>/ + install commands
agent: report PR link + dist/local path + paste-ready install commands
```

## Trade-offs (explicit)

- **Wall-clock is not necessarily shorter** — CI still takes ~30–40 min,
  dominated by the real-Windows legs (erofs parity, izba.exe MSVC, Tauri
  Windows, Inno). But it is **laptop-free, disk-free, and parallel** with the PR
  checks. Laptop disk per testable build drops from *multi-GB `target/` dirs ×N
  worktrees ×2 platforms* to *~150 MB of installers in `dist/local/`*.
- **No offline / CI-red path** (decision 2). If CI is down there is no
  installer. Accepted.
- **First build always builds the full set** (both platforms, CLI + app).
  Per-leg scope-skipping (Linux-only → skip the slow Windows legs) would require
  conditional plumbing into `_artifacts.yml`; deferred as a future optimization.
- **Dispatching requires `devbuild.yml` to exist on the target branch.** Once
  merged to `main`, every branch cut from `main` has it. Branches created before
  the merge must rebase onto `main` first. (Validation of this very change is
  done by dispatching on its own feature branch, which carries the new file.)

## Non-goals

- Touching `release.yml`, `ci.yml`, `e2e.yml`, `coverage.yml`, or `app.yml`.
- Auto-building installers on PR push (rejected: Windows-runner cost).
- A reusable `_package.yml` refactor (deferred; revisit if the two job sets
  drift).
- Scope-skipping the heavy Windows artifact jobs for Linux-only builds
  (deferred).

## Validation

- `devbuild.yml` dispatched on this feature branch produces `izba-deb`,
  `izba-app-deb`, and `izba-windows-installer` artifacts on a green run.
- `hack/devbuild.sh` on the branch dispatches, watches, downloads, and produces
  a populated `dist/local/<ts>-<sha>/` with `SHA256SUMS` + `manifest.txt` and
  prints install commands.
- Installing `izba_*.deb` and running `izba version` shows `~git<sha>` matching
  the branch HEAD.
- `actionlint` (or the repo's existing workflow-lint path) is clean on the new
  workflow.
