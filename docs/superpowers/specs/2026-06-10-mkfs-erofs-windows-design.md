# mkfs.erofs on Windows: native MinGW tar-mode port — design

**Date:** 2026-06-10
**Status:** implemented, merged to main 2026-06-10; §3.4 closed on real Windows 2026-06-11
**Resolves:** follow-up #2 from
[2026-06-10-openvmm-spike-s1-findings.md](2026-06-10-openvmm-spike-s1-findings.md)
(§A2 "erofs on Windows") — the erofs creation path for the future Windows/WHP
port of izba.

## 1. Problem

izba's image pipeline converts a flattened OCI tar into the read-only rootfs
via `mkfs.erofs --tar=f -T0 --quiet <out> <tar>` (`crates/izba-core/src/image/erofs.rs`).
On Windows there is no erofs-utils binary: no package in any Windows package
ecosystem, no upstream Windows port, and a naive MinGW/UCRT64 build fails on
POSIX dir-walk APIs (`lstat`, `readlink`, `opendir`/`DT_*`, `major()`/`minor()`).

The spike addendum overturned the original "WSL2 interop" recommendation with
two findings:

- **Docker ships a native MinGW-w64 `mkfs.erofs.exe`** (imports only
  `kernel32.dll` + `msvcrt.dll`) and drives it in **tar-mode**. In tar-mode
  every inode attribute comes from ustar headers, so the blocking POSIX APIs
  are never called on the real path — Docker stubbed them rather than porting
  them.
- izba's invocation is **already tar-mode and uncompressed**, so the same
  port shape applies directly.

## 2. Decision

**Native MinGW-w64 tar-mode port (Docker's route), cross-compiled from Linux.**

Alternatives considered and rejected:

| Option | Why rejected |
| --- | --- |
| Cygwin build (vendor `sekaiacg/erofs-utils` or CI-build our own) | Ships `cygwin1.dll`; a POSIX-emulation runtime dependency is explicitly unwanted |
| WSL2 interop (`wsl.exe mkfs.erofs ...`) | Adds a WSL2 runtime dependency to a native-Windows port; kept only as documented fallback if the MinGW port hits an unexpected wall |
| Pure-Rust erofs writer | Does not exist yet (all known crates are read-only); remains the tracked v2 endgame — izba's uncompressed-only usage means it is adoptable the day basic write support lands |

## 3. Design

### 3.1 Pinned source + patch series

- Upstream pin: **erofs-utils `v1.9.1`** (newest tag), fetched as a
  checksum-verified release tarball. Version bumps are a deliberate act:
  update the pin, re-run the parity gate.
- `hack/patches/erofs-utils/` holds a small numbered `.patch` series applied
  on top of the pinned tarball:
  1. build-system tweaks so `configure --host=x86_64-w64-mingw32` succeeds;
  2. a `mingw-compat` shim that **stubs** the POSIX APIs unreachable in
     tar-mode.
- Stub policy: unlike Docker's silently-warning stubs, ours **abort loudly**
  — `fprintf(stderr, "mkfs.erofs(win32): <api> reached — non-tar path is
  unsupported\n"); exit(70);`. A stub being executed means the invocation
  drifted off the tar-mode path and the output cannot be trusted; failing
  beats corrupting.

### 3.2 Build script

`hack/build-mkfs-erofs-windows.sh`:

1. fetch the pinned tarball, verify sha256;
2. apply the patch series;
3. `configure --host=x86_64-w64-mingw32` with **lz4 and zlib disabled** —
   izba images are uncompressed by design (the guest kernel carries only
   `CONFIG_EROFS_FS=y`, no decompression), so the port has zero third-party
   library dependencies to cross-compile;
4. produce `mkfs.erofs.exe` (expected imports: `kernel32.dll`,
   `msvcrt.dll` only — the script asserts this with `objdump -p | grep "DLL Name"`);
5. additionally build the **same pinned source natively for Linux**, so the
   parity gate compares two binaries built from identical code.

Toolchain: `gcc-mingw-w64-x86-64` on any Linux host (WSL2 or CI runner).

### 3.3 Parity gate (CI-compatible scripts; the repo has no CI yet)

There is no CI in this repo today, so the gate ships as scripts that a future
workflow can wrap thinly: non-interactive, exit-code-driven, paths overridable
via env vars, no network access beyond the pinned-tarball fetch in the build
script.

- `hack/verify-mkfs-erofs-parity.sh` (Linux):
  1. generate a deterministic fixture tar (fixed mtimes, sorted entries,
     covering regular files, symlinks, hardlinks, directories, mode/uid/gid
     variety);
  2. run the Linux reference binary with `--tar=f -T0 -U <fixed-uuid>` to
     produce the reference image; `fsck.erofs` it;
  3. run `mkfs.erofs.exe` on the same fixture with identical flags — under
     Wine if `wine` is on PATH; otherwise emit a verification bundle
     (fixture tar + reference sha256) and skip with a distinct exit code;
  4. **byte-compare** the two images; any divergence is a hard failure.
- `hack/spike/verify-mkfs-erofs-parity.ps1` (Windows): consume the
  verification bundle — run the `.exe` natively on the fixture, compare
  sha256 against the reference. This is the real-Windows leg of the gate and
  is what the manual end-to-end pass (§3.4) starts from.

Determinism inputs: `-T0` (timestamps), `-U <fixed-uuid>` (volume UUID),
identical source + flags. Byte-identity is the gate; if a benign
toolchain-dependent divergence is ever discovered, downgrading to
fsck+content-compare requires a documented justification in this spec.

### 3.4 Manual end-to-end gate (once)

On the Windows spike host: build the spike Alpine `rootfs.erofs` with the
Windows binary, boot the rung-7 OpenVMM stack with it, confirm all guest
mounts complete and exec round-trips. Result recorded in the findings doc.

**DEFERRED (2026-06-10):** the parity gate passed under wine (byte-identical
images vs the same-source Linux build), which was accepted as sufficient
evidence for now. Run this gate as part of the OpenVmmDriver bring-up
checklist instead — first via `hack/spike/verify-mkfs-erofs-parity.ps1` on
the real Windows host, then the rung-7 boot with a Windows-built rootfs.

**CLOSED (2026-06-11):** `verify-mkfs-erofs-parity.ps1` PASS on the spike
host (Windows 11 24H2, native pwsh, no wine): sha256
`8f21d899…ffd72345`, byte-identical to the Linux reference. The
boot-with-a-Windows-built-rootfs leg is covered by the Windows-port Plan 2
full-CLI validation (izba.exe builds its rootfs.erofs natively on Windows
through the bundled binary).

### 3.5 izba-core discovery shim

Replace the bare `which::which("mkfs.erofs")` in
`crates/izba-core/src/image/erofs.rs` with `find_mkfs_erofs()`, probe order:

1. `$IZBA_MKFS_EROFS` — explicit override (also the unit-test seam);
2. `<current_exe dir>/libexec/mkfs.erofs[.exe]` — Docker's bundling
   convention, which the future Windows installer inherits for free;
3. `PATH` via `which` (today's Linux behavior, unchanged).

The not-found error message lists every probed location. Host-testable unit
tests cover the override and fallback ordering.

## 4. Out of scope

- The rest of the Windows image pipeline (OCI pull → flatten on Windows),
  OpenVmmDriver, installer/packaging layout — later work; this design only
  guarantees the erofs tool exists and is discoverable.
- Compression support in the Windows binary (would require cross-compiling
  liblz4 and a guest kernel with decompression — neither is wanted).
- Upstreaming the patches (worth attempting later; not a dependency).

## 5. Risks

| Risk | Mitigation |
| --- | --- |
| v1.9.1 tar-mode regressions vs the field-verified v1.8.x | parity gate + fsck + manual guest boot; fall back to pinning v1.8.10 if v1.9.1 misbehaves |
| Patch series rots on upstream bumps | pin + checksums; bumps are deliberate and re-run the full gate |
| Stub reached at runtime on some input | loud abort (exit 70), never silent corruption |
| Byte-parity too strict across toolchains | documented downgrade path to fsck+content-compare (spec edit required) |
