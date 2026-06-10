# Spike S1+ findings: OpenVMM on the Windows host

**Status:** in progress
**Spec:** [2026-06-10-openvmm-spike-s1-design.md](2026-06-10-openvmm-spike-s1-design.md)

## Environment

- Windows version: 10.0.26100 (Windows 11 24H2)
- OpenVMM binary provenance: CI artifact `x64-windows-openvmm` from workflow `openvmm-ci.yaml`, run id `27240809751`, branch `main`, date 2026-06-10. Artifact commit: `7872712037c6ce3a03087a76207bd73cec9784a2`. Contains `openvmm.exe` (20 MB) + `openvmm.pdb` (268 MB). No DLLs required — exe is self-contained. Staged to `C:\izba-spike\openvmm.exe`.
- Windows-side installs performed: PowerShell 7.6.2 (installed via `winget install --id Microsoft.PowerShell` during Task 3)
- S4 MSYS2 packages installed (Task 12): `pacman -S git base-devel autoconf automake libtool pkg-config mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-lz4` — installs gcc 16.1.0, lz4 1.10.0, and ~110 dependency packages (~1 GiB)

**Interop notes (affects all later tasks):**
- WSL interop (`powershell.exe`) fails inside the default Claude Code sandbox (`UtilConnectUnix: socket failed 1`). All `powershell.exe` / `/mnt/c` commands require `dangerouslyDisableSandbox: true`.
- WHP (HypervisorPlatform): `Get-WindowsOptionalFeature` requires elevation; non-admin CIM probe returned `InstallState=2` (disabled). WHP must be enabled before OpenVMM can use WHP — requires elevation + reboot. **User action needed.**
- pwsh (PowerShell 7): was missing; installed 7.6.2 via winget during this task. Confirmed working.
- gh auth: authenticated as `Lupus` on github.com (token scopes: gist, read:org, repo). Ready for artifact download in Task 4.

## Rung verdicts

| # | Rung | Verdict | Notes |
| --- | --- | --- | --- |
| 0 | acquire openvmm.exe | PASS | Artifact `x64-windows-openvmm` from CI run 27240809751; `openvmm.exe --help` runs; all 7 expected flags confirmed |
| 1 | smoke boot (their kernel) | | |
| 2 | direct-boot our vmlinux | | |
| 3 | virtio-fs share | | |
| 4 | vsock bridge | | |
| 5 | consomme networking | | |
| 6 | headless serial capture | | |
| 7 | integration preview (full izba guest) | | |
| S4 | mkfs.erofs on Windows | PARTIAL | Native `.exe` build fails due to POSIX API gaps; viable path = run mkfs.erofs in WSL2 via interop; Cygwin route untested |

## Working command lines

(exact invocations per rung as they pass — these become OpenVmmDriver fixtures)

### Rung 0 — flag inventory (from `openvmm.exe --help`, commit 7872712)

All flags match the spec design. Key notes for later rungs:

- `--kernel <FILE>` / `-k` — linux direct-boot kernel image (rung 2+)
- `--initrd <FILE>` / `-r` — initrd image (rung 2+)
- `--com1 <SERIAL>` — supports `file=<path>` (overwrites), `listen=<path>`, `stderr`, `console`, `term`, `none` (rung 6)
- `--virtio-fs <[pcie_port=PORT:]tag,root_path,[options]>` — NOTE: takes `tag,root_path` positional args as comma-separated, **no** standalone `--tag` / `--path` sub-flags; uid/gid optional (rung 3). Example: `--virtio-fs workspace,C:\path\to\workspace`
- `--virtio-vsock-path <PATH>` — "Unix socket base path" (rung 4); likely appends port suffix to the path; needs further probing in rung 4
- `--virtio-net <VIRTIO_NET>` — backends: `dio | vmnic | tap | none` (no consomme here)
- `--net <NET>` — **separate flag** with backends: `consomme | dio | tap | none`; consomme supports `hostfwd=` port-forwarding syntax (rung 5). Example: `--net consomme` or `--net consomme:hostfwd=tcp::8080-:80`
- `--pcie-root-complex <PCIE_ROOT_COMPLEX>` — needed to wire virtio devices over PCIe

## Kernel config deltas

(none yet)

## S4 details — mkfs.erofs on Windows

### Survey (Step 1)

| Source | Result |
| --- | --- |
| MSYS2 packages.msys2.org `?query=erofs` | No results — no pre-built erofs-utils package for any MSYS2 environment |
| erofs/erofs-utils GitHub releases | Source-only; latest tag v1.9.1, no binary releases for any platform |
| winget `search erofs` | No package found |
| GitHub `search repos erofs-utils windows` | No third-party Windows builds found |

**Conclusion:** must build from source. No pre-built Windows binary is publicly available; how Docker's `sbx` ships erofs tooling on Windows is not confirmed — see Path A′/C discussion below.

### Build attempt (Steps 2–3)

**Toolchain installed:** MSYS2 (fresh) + `pacman -S git base-devel autoconf automake libtool pkg-config mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-lz4` — results in gcc 16.1.0 (UCRT64) + lz4 1.10.0. lz4 pkg-config check passes (`pkg-config --modversion liblz4 → 1.10.0`).

**Complete configure invocation (copy-pasteable from the WSL side):**

```sh
/mnt/c/msys64/usr/bin/bash.exe -lc '
  export PATH=/ucrt64/bin:$PATH
  git clone https://github.com/erofs/erofs-utils.git && cd erofs-utils
  ./autogen.sh
  CPPFLAGS="-I$(pwd)/win32-shims" ./configure --disable-fuse --without-uuid
'
```

Two header shims were added under a local `win32-shims/` include directory (passed via `CPPFLAGS`) before the build step: `win32-shims/sys/uio.h` and `win32-shims/sys/ioctl.h`. These are minimal stubs to satisfy `#include` directives; the exact contents are not recorded, but each was a short stub defining the minimum required to compile past the include-not-found error. They are noted here as "two header shims added under a local include dir" — they were not sufficient to make the build succeed.

**Configure:** succeeded with `--disable-fuse --without-uuid`. lz4 detected and enabled (`checking for liblz4... yes`). One quirk: `./config.status libtool` must be run manually after configure — MSYS2's `config.status` generates the `libtool` wrapper script only when invoked explicitly (the command is buffered but not auto-run when launched from WSL interop with `-lc`).

**Build:** failed. After adding the two header shims under `win32-shims/`, build progressed past the include errors but hit a wall in `inode.c`, `io.c`, `namei.c`, and `xattr.c`. Full unique error list:

```
inode.c: S_IFLNK, S_IFSOCK, DT_* (dir-entry type constants) undeclared — MinGW stat.h omits symlink/socket support
inode.c: lstat, readlink implicit declaration — Windows has no symlinks in the POSIX sense
inode.c: getuid, getgid implicit declaration — no POSIX user/group model on Windows
inode.c: _POSIX_OPEN_MAX undeclared
inode.c: major()/minor() treated as values, not functions (MSYS2 macro mismatch)
io.c: pread, pwrite, fsync implicit declarations — pread/pwrite not in UCRT
io.c: struct stat has no st_blksize member
namei.c: S_IFLNK, S_IFSOCK, makedev undeclared
xattr.c: lstat implicit declaration; uint typedef missing
```

Root cause: erofs-utils is tightly coupled to Linux/POSIX filesystem semantics — it ingests live directory trees using `lstat`/`readlink`/`opendir`/`DT_*` and relies on POSIX inode metadata (uid/gid, symlinks, device nodes, block size). These are not shimable in a few lines; they require either substantial compat shims or a port of the directory-walk layer.

**Failure point:** `inode.c` compile (lib directory, first pass); build did not reach `mkfs/main.c`.

### Effort estimate for productizing

**Path A — Native Win32 `.exe` (full port):** ~3–5 person-days. Requires: (1) `lstat`/`readlink` shims using `GetFileAttributesEx`/`DeviceIoControl` for Windows reparse points; (2) `pread`/`pwrite` shims using `ReadFile`/`WriteFile` with `OVERLAPPED`; (3) `getuid`/`getgid` → return 0; (4) `major()`/`minor()` → 0; (5) `DT_*`/`S_IFLNK`/`S_IFSOCK` in a compat header; (6) `st_blksize` shim. Several files need patching; upstream is unlikely to accept Windows-specific `#ifdef`s without a maintained Windows CI lane. **This estimate applies to a Win32-NATIVE port only.**

**Path A′ — Cygwin build (untested):** ~0.5–1 day to attempt. Cygwin was NOT attempted within the 45-min timebox. Unlike MinGW/UCRT64, Cygwin's POSIX emulation layer provides `lstat`, `readlink`, `pread`/`pwrite`, `getuid`/`getgid`, `DT_*`, `major()`/`minor()`, and `st_blksize` — exactly the APIs that blocked the UCRT64 build. A Cygwin build is therefore a plausible route to a real Windows `.exe` at materially lower cost than the Win32-native port (Path A). The result would be a `.exe` that requires the Cygwin runtime DLL (`cygwin1.dll`), not a fully standalone Win32 binary. The parent design spec's "Docker demonstrably builds erofs-utils for Windows" hypothesis most plausibly points at a Cygwin-style POSIX layer rather than a full Win32 port, though this is unconfirmed. Estimate is rough; actual cost could be lower (configure just works) or higher (additional Cygwin-specific issues).

**Path B — WSL2 interop (recommended):** ~0.5 person-days. `mkfs.erofs` is already available as a Linux package (`apt install erofs-utils`) in WSL2. izba on Windows can invoke it via `wsl.exe mkfs.erofs ...` or run it directly in the WSL2 Linux process that already hosts the izba CLI. This is the same pattern Docker Desktop uses for Linux tooling. No porting required; the binary is stable and lz4-enabled.

**Path C — Pre-built static Linux binary bundled in the Windows release (refinement of Path B):** ~1 day. Cross-compile a static musl `mkfs.erofs` on Linux (straightforward since erofs-utils builds cleanly on Linux); embed the binary in the Windows package and invoke it via WSL2 interop. This is a refinement of Path B: the difference is shipping a pinned static binary with the izba installer instead of depending on the user's WSL distro having `erofs-utils` available via `apt`. Benefits: version control, no root needed inside the WSL distro, no dependency on the user's distro state. **This path still requires WSL2 — a static Linux ELF cannot run on native Windows without a Linux environment.** It is a distribution-quality improvement over Path B, not an elimination of the WSL2 dependency.

**Recommendation:** Use Path B for the v1 OpenVMM path — WSL2 interop is always available on any system that can run OpenVMM. Path C is a cleaner distribution story for v2 when izba ships as a standalone Windows installer, but it still requires WSL2. Path A′ (Cygwin) is worth a short investigation if a true Windows-native binary (without WSL2) is ever required, before committing to the full Win32 port effort of Path A.

### Smoke test

Not reached — build did not produce `mkfs.erofs.exe`. Image-format compatibility deferred to a later integration test once Path B or C is implemented.

## Go/no-go recommendation

(pending)
