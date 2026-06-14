# izba CI release packaging — `.deb` + Windows Inno installer

**Date:** 2026-06-14
**Status:** Approved design, pre-implementation
**Branch:** `worktree-ci-installers`

## Goal

Produce two **self-contained, installable** artifacts in CI so izba can be
tested as a clean-installed package on both platforms:

- `izba_<version>_amd64.deb` — installs on a clean WSL2 Ubuntu and yields a
  working `izba` with **zero** post-install network fetch.
- `izba-setup-<version>.exe` — an Inno Setup installer for Windows.

Both are built **after the fast test/build gates pass**, triggered on a `v*`
git tag (plus `workflow_dispatch` for test builds), and attached to a GitHub
Release alongside a `SHA256SUMS`.

## Decisions (locked)

1. **Bundling:** fully self-contained. Each package ships izba + its VMM +
   `mkfs.erofs` provisioning + the boot artifacts (`vmlinux`,
   `initramfs.cpio.gz`).
2. **Trigger:** `push: tags: ['v*']` + `workflow_dispatch`. Release semantics.
3. **Windows installer:** Inno Setup `.exe`.
4. **CH/virtiofsd discovery (Linux):** teach the Cloud Hypervisor driver to
   resolve `cloud-hypervisor` and `virtiofsd` via the existing `libexec`
   discovery (option B), so a self-contained package keeps every tool under
   `/usr/lib/izba` and never pollutes `/usr/bin` with generic-named binaries.

## Installed layouts

Both layouts must satisfy the existing `<exe-dir>/libexec/` tool-discovery
contract (`crates/izba-core/src/discover.rs`).

### Linux `.deb`

```
/usr/lib/izba/bin/izba                     # the CLI binary
/usr/lib/izba/bin/libexec/cloud-hypervisor # static, pinned v42.0 (bundled)
/usr/lib/izba/bin/libexec/virtiofsd        # static, pinned v1.13.3 (bundled)
/usr/lib/izba/artifacts/vmlinux            # bundled boot artifacts
/usr/lib/izba/artifacts/initramfs.cpio.gz
/usr/bin/izba -> /usr/lib/izba/bin/izba    # symlink; current_exe() reads
                                           # /proc/self/exe → resolves to the
                                           # real path → libexec is
                                           # <exe-dir>/libexec and artifacts is
                                           # <exe-dir>/../artifacts
```

The Linux binary lives under a `bin/` subdir (not directly in `/usr/lib/izba`)
so the layout is **symmetric with Windows**: on both platforms `libexec` is
`<exe-dir>/libexec` and boot artifacts are `<exe-dir>/../artifacts`.

- **`Depends: erofs-utils, libc6`.** `mkfs.erofs` has no upstream static build,
  so it is provided by the Debian-native `erofs-utils` package and located by
  `find_tool`'s `$PATH` fallback. `libc6` covers the glibc-dynamic `izba` build.
- The izba CLI binary is a normal glibc dynamic build (`cargo build --release`
  on the CI ubuntu image). It is **not** statically linked (only `izba-init`
  must stay static-musl).

### Windows (Inno Setup)

Mirrors `hack/stage-izba-windows.sh`, installing under `%ProgramFiles%\izba\`:

```
%ProgramFiles%\izba\bin\izba.exe
%ProgramFiles%\izba\bin\libexec\openvmm.exe       # fetched (hack/fetch-openvmm.sh)
%ProgramFiles%\izba\bin\libexec\mkfs.erofs.exe    # built (artifacts pipeline)
%ProgramFiles%\izba\artifacts\vmlinux
%ProgramFiles%\izba\artifacts\initramfs.cpio.gz
```

- The installer adds `%ProgramFiles%\izba\bin` to the system `PATH`.
- **`openvmm.exe` must be fetched and bundled.** The current
  `izba-windows-bundle` artifact omits it ("fetched-not-built, out of scope"),
  which makes that bundle non-functional. The Windows packaging job fetches it
  via `hack/fetch-openvmm.sh`.

## Code changes

Two small, TDD'd changes in `izba-core`. Everything else is CI workflow files
and packaging recipes.

### C1 — exe-relative boot-artifact fallback (`artifacts.rs`)

Today `artifacts::locate()` resolves boot artifacts from `$IZBA_KERNEL` /
`$IZBA_INITRAMFS`, else `<data>/artifacts/{vmlinux,initramfs.cpio.gz}`
(`~/.local/share/izba/artifacts`). A self-contained package ships the artifacts
*next to the binary*, not in the per-user data dir.

Add a third resolution step, symmetric with how `libexec` tools are found:
when the env overrides are unset **and** `<data>/artifacts` does not contain
both files, fall back to **`<exe-dir>/../artifacts`** (resolved from
`current_exe()`):

- Linux: `/usr/lib/izba/bin/izba` → `/usr/lib/izba/artifacts`
- Windows: `...\izba\bin\izba.exe` → `...\izba\artifacts`

Resolution order becomes: env overrides → `<data>/artifacts` → exe-relative
`../artifacts` → error. The `<data>/artifacts` location keeps working (so
existing dev setups and `fetch-artifacts.sh` are unaffected); the exe-relative
location is what makes a clean package install work with no env vars.

**Tests:** exe-relative dir is used when data dir is empty; data dir still wins
when populated; env overrides still win over both; both-or-neither env rule
unchanged.

### C2 — `libexec` discovery for CH + virtiofsd (`vmm/cloud_hypervisor.rs`)

`build_invocations()` currently emits the literal strings `"cloud-hypervisor"`
and `"virtiofsd"` as `argv[0]`, relying on `$PATH`. Resolve both through
`discover::find_tool` with new env overrides:

- `IZBA_CLOUD_HYPERVISOR` → `cloud-hypervisor`
- `IZBA_VIRTIOFSD` → `virtiofsd`

`find_tool` order is unchanged (env override → `<exe-dir>/libexec/<name>` →
`$PATH`), so:

- Packaged install: resolves to `/usr/lib/izba/bin/libexec/{cloud-hypervisor,virtiofsd}`.
- Dev / `fetch-artifacts.sh` install (`~/.local/bin` on PATH): resolves via
  `$PATH` exactly as before — **no behavior change for existing setups**.

**Resolution timing / testability.** `build_invocations()` is a pure function
unit-tested with exact-`argv` equality, and must stay host-testable (no real
filesystem lookups in unit tests). Approach: resolve the two tool paths once,
outside `build_invocations`, and pass them in via the `VmSpec` (or a small
`Tools { cloud_hypervisor: PathBuf, virtiofsd: PathBuf }` field). Existing
`build_invocations` tests set those fields to fixed paths and keep asserting
exact argv. A separate, thin test covers the `find_tool` resolution itself
(already covered by `discover.rs` tests — we only add env-var names).

**Cross-platform note.** This discovery path also compiles for the Windows
target (the win-gnu cross gates in `ci.yml`), but CH/virtiofsd are Linux-only;
the Windows VMM driver is OpenVMM and is unaffected. Keep the change inside the
Cloud Hypervisor driver module so it does not touch the OpenVMM path.

## CI architecture

### Reusable artifact workflow

Extract the artifact-building jobs currently in `.github/workflows/artifacts.yml`
into a reusable workflow `.github/workflows/_artifacts.yml` (`on:
workflow_call`). It builds and uploads: `vmlinux`, `initramfs`, `mke2fs`,
`nft`, `mkfs-erofs-windows` (+ real-Windows parity), and `izba-windows-bundle`.
`artifacts.yml` becomes a thin caller (preserving its current `push`/dispatch
triggers and behavior). `release.yml` is the second caller.

This keeps a single source of truth for *how* each artifact is built; the two
callers differ only in trigger and in what they do with the outputs.

### `release.yml` job graph

Trigger: `push: tags: ['v*']`, `workflow_dispatch`.

1. **`gate`** — the fast build/test gates from `ci.yml`: `cargo test
   --workspace`, `cargo clippy --workspace --all-targets -D warnings`, `cargo
   fmt --check`, the `izba-init` static-musl build, and the two win-gnu cross
   `check`/`clippy` gates. Guarantees "all tests pass" before anything is
   packaged. (The heavy real-VM `e2e.yml` remains a separate signal; a release
   tag is expected to point at a commit already green on `e2e.yml`.)
2. **`artifacts`** — `uses: ./.github/workflows/_artifacts.yml`. Provides
   `vmlinux`, `initramfs`, `mkfs-erofs-windows`, `izba-windows-bundle`.
3. **`izba-linux-bin`** — `needs: gate`. `cargo build --release -p izba-cli` on
   ubuntu (glibc); uploads `target/release/izba`.
4. **`package-deb`** — `needs: [artifacts, izba-linux-bin]`, ubuntu. Fetches the
   pinned static `cloud-hypervisor` + `virtiofsd` (reusing `hack/fetch-
   artifacts.sh` pins), downloads `vmlinux`/`initramfs`/`izba`, assembles the
   `/usr/lib/izba` tree + `DEBIAN/control` (+ `postinst` only if needed for the
   `/usr/bin` symlink), runs `dpkg-deb --build`, uploads `izba_<version>_amd64.deb`.
5. **`package-windows`** — `needs: artifacts`, windows-latest. Downloads
   `izba-windows-bundle` + `mkfs-erofs-windows` + `vmlinux`/`initramfs`, fetches
   `openvmm.exe`, runs Inno Setup (`choco install innosetup`) over
   `packaging/windows/izba.iss`, uploads `izba-setup-<version>.exe`.
6. **`release`** — `needs: [package-deb, package-windows]`. Computes
   `SHA256SUMS`, attaches `.deb` + `.exe` + `SHA256SUMS` to the GitHub Release
   via `softprops/action-gh-release` (only on the tag trigger; dispatch builds
   upload workflow artifacts instead).

### Version derivation

`<version>` comes from the tag (`v1.2.3` → `1.2.3`) on tag builds, and from
`Cargo.toml` `version` + short SHA (e.g. `0.1.0~git<sha>`) on dispatch builds.
The `.deb` `Version:` field uses the same value.

## New files

- `.github/workflows/_artifacts.yml` (reusable; extracted from `artifacts.yml`)
- `.github/workflows/release.yml`
- `packaging/debian/control.template` + optional `postinst`
- `packaging/windows/izba.iss` (Inno Setup script)
- `packaging/build-deb.sh` (assembles the tree + `dpkg-deb`, callable locally
  for testing)

## Out of scope

- arm64 / other Debian arches (amd64 only).
- apt/winget repository hosting — artifacts are attached to GitHub Releases.
- Signing (GPG-signed `.deb`, Authenticode-signed `.exe`) — deferred.
- Bundling `mkfs.erofs` on Linux as a vendored static binary — using the
  `erofs-utils` apt dependency instead.

## Testing strategy

- **C1/C2 unit tests** (host-runnable) as described above; all six standard
  build gates green.
- **`packaging/build-deb.sh`** runnable locally in WSL2; the human acceptance
  test is `sudo apt install ./izba_<v>_amd64.deb` on a clean WSL2 Ubuntu, then
  `izba` boots a sandbox with no env vars set.
- **Windows**: install the `.exe` on a clean Windows host; `izba.exe --help`
  and a sandbox boot via OpenVMM/WHP.
- CI `workflow_dispatch` produces both artifacts for download without cutting a
  release, enabling iteration before the first real `v*` tag.
