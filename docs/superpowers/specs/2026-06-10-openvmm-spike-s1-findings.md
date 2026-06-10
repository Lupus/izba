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
- WHP (HypervisorPlatform): **functional** — empirically verified by booting a VM with openvmm.exe (guest vCPUs executed, PIO traces in openvmm output). The earlier non-admin CIM probe (`Win32_OptionalFeature` → `InstallState=2`, "disabled") was WRONG — do not trust that class for WHP state; an actual openvmm boot attempt is the reliable non-admin check (sbx working on this host was the tell). Probe boot note: the earlier whp-probe left `--com1 file=` log empty due to a shell quoting/invocation issue in that session (backslash escaping in the command string caused the `file=` argument to be malformed); the `file=` mechanism itself is confirmed working — rung 1 established this conclusively. Both `--com1 file=<path>` and `--com1 stderr` produce full serial output when the command is structured correctly via PowerShell `Start-Process`.
- pwsh (PowerShell 7): was missing; installed 7.6.2 via winget during this task. Confirmed working.
- gh auth: authenticated as `Lupus` on github.com (token scopes: gist, read:org, repo). Ready for artifact download in Task 4.

## Rung verdicts

| # | Rung | Verdict | Notes |
| --- | --- | --- | --- |
| 0 | acquire openvmm.exe | PASS | Artifact `x64-windows-openvmm` from CI run 27240809751; `openvmm.exe --help` runs; all 7 expected flags confirmed |
| 1 | smoke boot (their kernel) | PASS | openvmm-deps 0.3.0-59 kernel 6.1.172 boots to shell; `--com1 file=` and `--com1 stderr` both confirmed working; 292 lines of serial output captured |
| 2 | direct-boot our vmlinux | PASS | izba kernel 6.12.30 + spike-initramfs boots; `SPIKE-INIT-OK` confirmed at line 319 of rung2.log; no config changes needed |
| 3 | virtio-fs share | PASS | Attempt A (PCIe route) worked first try; MOUNT-OK + READ-OK (`hello-from-host`) + WRITE-OK; `guest-file.txt` visible on host; uid/gid 1000 on Windows side |
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

### Rung 1 — smoke boot (their kernel)

**Artifacts:** `openvmm-deps` release `0.3.0-59` from `microsoft/openvmm-deps`.
- Kernel: `openvmm-test-linux-6.1.x86_64.0.3.0-59.tar.gz` → extracted `vmlinux`
  (ELF 64-bit, uncompressed, `Linux version 6.1.172`, 60 MB). Staged to `C:\izba-spike\their-vmlinux`.
- Initrd: `openvmm-test-initrd.x86_64.0.3.0-59.tar.gz` → extracted `initrd`
  (gzip cpio, 1.4 MB). Staged to `C:\izba-spike\their-initrd`.

Note: the `.cargo/config.toml` in the openvmm repo (`X86_64_OPENVMM_LINUX_DIRECT_KERNEL` env var) points to `.packages/underhill-deps-private/x64/vmlinux` from the full `openvmm-deps.x86_64.tar.gz` (~165 MB, the private Underhill kernel). The `openvmm-test-linux-6.1` tarball is separate and is the OSS test kernel used by their integration test suite; it is equivalent for our smoke-boot purposes.

**Invocation (file capture mode):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after 20s
$proc = Start-Process -FilePath './openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\their-vmlinux',
                '--initrd','C:\izba-spike\their-initrd',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung1-file.log' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung1-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung1-stderr.log'
Start-Sleep -Seconds 20
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `C:\izba-spike\logs\rung1-file.log` — 18 360 bytes, 292 lines of kernel serial output. Guest booted kernel 6.1.172, ran initrd, reached interactive busybox shell (`~ # `). Log ends with `tsc: Refined TSC clocksource calibration: 2304.007 MHz` after the shell prompt.

**Invocation (stderr mode):**

```powershell
$proc = Start-Process -FilePath './openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\their-vmlinux',
                '--initrd','C:\izba-spike\their-initrd',
                '-c','console=ttyS0',
                '--com1','stderr' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung1-stderr-test-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung1-stderr-test-stderr.log'
Start-Sleep -Seconds 15
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** stderr log 34 822 bytes — openvmm PIO traces interleaved with 290 kernel serial lines. Both modes reliable.

**Whp-probe empty-log mystery — resolution:**
- Root cause: The earlier probe session used shell interpolation that malformed the `file=C:\...` argument (backslash escaping issue in the command string; the argument was passed as a single shell word rather than via `Start-Process -ArgumentList`). The `file=` mechanism itself is fully functional.
- Confirmation: our izba kernel (`vmlinux` + `spike-initramfs.cpio.gz`) also produces full serial output in both `file=` and `stderr` modes — `izba-kernel-file.log` is 20 291 bytes, 320+ kernel lines, boots to busybox shell.

### Rung 3 — virtio-fs share

**Kernel virtio transport inventory** (from `hack/kernel.config`):
- `CONFIG_VIRTIO=y`, `CONFIG_VIRTIO_PCI=y`, `CONFIG_VIRTIO_FS=y`
- `CONFIG_VIRTIO_BLK=y`, `CONFIG_VIRTIO_NET=y`, `CONFIG_VIRTIO_CONSOLE=y`, `CONFIG_VIRTIO_VSOCKETS=y`
- `CONFIG_VIRTIO_MMIO` is **not set** — MMIO transport unavailable; PCIe or PCI is the only viable route.

**Attempt A — PCIe route (PASS, first try):**

`--pcie-root-complex` + `--pcie-root-port` are required for virtio-pci visibility in direct boot (the default DSDT has no PCI bus unless you add one explicitly via these flags).

```powershell
# Run from C:\izba-spike in PowerShell; kills after 25s
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs-r3.cpio.gz',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung3.log',
                '--pcie-root-complex','rc0',
                '--pcie-root-port','rc0:ws',
                '--virtio-fs','pcie_port=ws:ws,C:\izba-spike\share' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung3-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung3-stderr.log'
Start-Sleep -Seconds 25
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `rung3.log` — 354 lines. `SPIKE-RUNG3-MOUNT-OK` + `SPIKE-RUNG3-READ-OK: hello-from-host` + `SPIKE-RUNG3-WRITE-OK` all present. Bidirectional check: `C:\izba-spike\share\guest-file.txt` created by guest, contains `guest-was-here`.

**PCIe probe lines from rung3.log (transport visibility confirmed):**
```
pci 0000:00:00.0: [1414:c030] type 01 class 0x060400 PCIe Root Port
pci 0000:01:00.0: [1af4:105a] type 00 class 0x088000 conventional PCI endpoint
virtio-pci 0000:01:00.0: enabling device (0000 -> 0002)
```
The virtio-fs device appears as virtio-pci vendor `1af4` device `105a` at `01:00.0` under the root port.

**uid/gid mapping:** Files written by the guest appear as uid/gid 1000 on the Windows/WSL side. The in-process virtiofsd server runs as the Windows user (NTFS does not store POSIX uid/gid natively; WDK's projected filesystem maps the current user to uid 1000 in the WSL metadata view). No `uid=`/`gid=` mount options were required; the default mapping was correct. No permission errors for either the read or write direction.

**Flag syntax notes:**
- `--pcie-root-complex <name>` — just the name, no extra options needed for basic use (e.g., `rc0`)
- `--pcie-root-port <rc_name>:<port_name>` — colon-separated (e.g., `rc0:ws`)
- `--virtio-fs 'pcie_port=<port_name>:<tag>,<windows_path>'` — port name prefix before the tag; `--virtio-fs-bus` not needed when using `pcie_port=`
- Attempts B/C (plain `--virtio-fs-bus pci` / `vpci` without the explicit PCIe topology) were NOT attempted — Attempt A passed cleanly on the first try.

### Rung 2 — direct-boot izba kernel

**Artifacts:** izba's own build artifacts (staged to `C:\izba-spike\` during rung-1 preparation):
- Kernel: `vmlinux` — Linux 6.12.30, built by `hack/build-kernel.sh` targeting Cloud Hypervisor, uncompressed ELF, ~60 MB.
- Initramfs: `spike-initramfs.cpio.gz` — busybox + `/init` that prints `SPIKE-INIT-OK` then drops to shell with sleep-infinity PID-1 keepalive.

**Invocation (file capture mode):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after 25s
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs.cpio.gz',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung2.log' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung2-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung2-stderr.log'
Start-Sleep -Seconds 25
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `C:\izba-spike\logs\rung2.log` — 20 330 bytes, 323 lines of kernel serial output. Linux 6.12.30 banner at line 1; `SPIKE-INIT-OK` at line 319; guest reached busybox shell. No kernel config changes were required — izba's CH-targeted kernel boots under OpenVMM direct-boot without modification.

## Kernel config deltas

None. izba's Cloud Hypervisor-targeted kernel (Linux 6.12.30, built by `hack/build-kernel.sh`) requires no configuration changes for OpenVMM direct boot. Both rungs 1 and 2 confirm this — the same `vmlinux` that boots under Cloud Hypervisor boots identically under OpenVMM.

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
