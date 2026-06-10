# mkfs.erofs on Windows (MinGW tar-mode port) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a native Windows `mkfs.erofs.exe` (kernel32+msvcrt only, no
cygwin1.dll, no WSL2) from pinned erofs-utils v1.9.1, with CI-compatible
parity verification scripts and an izba-core discovery shim.

**Architecture:** Cross-compile erofs-utils with the Linux→Windows MinGW-w64
toolchain. Compat shims live *outside* the upstream tree in
`hack/mingw-compat/` (force-included via `-include`, linked via `LIBS=`), so
the in-tree patch series under `hack/patches/erofs-utils/` stays minimal —
only edits the compiler forces. Stubs for POSIX APIs unreachable in tar-mode
abort loudly (exit 70). A parity script proves the Windows binary produces
byte-identical images to a same-source Linux build.

**Tech Stack:** bash, GNU autotools, `gcc-mingw-w64-x86-64`, GNU `patch`,
PowerShell (verification leg), Rust (discovery shim in izba-core).

**Spec:** [docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md](../specs/2026-06-10-mkfs-erofs-windows-design.md)

**Branch:** work on top of `spike/openvmm-s1` (the spec lives there; this is
part of the same Windows-enablement bundle).

**Pinned facts (verified 2026-06-10):**

- Tarball: `https://github.com/erofs/erofs-utils/archive/refs/tags/v1.9.1.tar.gz`
- sha256: `a9ef5ab67c4b8d2d3e9ed71f39cd008bda653142a720d8a395a36f1110d0c432`
- The tag tarball has no pregenerated `configure` — `./autogen.sh` (autoconf/
  automake/libtool) is required.
- v1.9.1 compiles `vmdk.c`, `metabox.c`, `importer.c`, `diskbuf.c`
  unconditionally into liberofs; s3/oci/fuse/all compressors are behind
  configure switches and must be disabled.
- Known POSIX gaps from the spike build attempt (UCRT64, pre-v1.9 master):
  `lstat`, `readlink`, `getuid`/`getgid`, `DT_*`, `S_IFLNK`/`S_IFSOCK`,
  `major()`/`minor()`/`makedev`, `_POSIX_OPEN_MAX`, `pread`/`pwrite`/`fsync`,
  `struct stat::st_blksize`, missing `<sys/uio.h>`/`<sys/ioctl.h>`, `uint`.
- Windows-specific gotcha not in the spike list: CRT text-mode translation
  corrupts binary output — the compat layer must force `_O_BINARY` globally.
- Shared invocation for parity: `--tar=f -T0 -U 11111111-2222-3333-4444-555555555555 --quiet`
  (izba production passes `--tar=f -T0 --quiet`; the fixed `-U` is
  parity-test-only, since an unpinned volume UUID is random).

**Environment prerequisite (user-assisted, do this first):** the sandbox
cannot run `apt`. Ask the user to run:

```sh
sudo apt-get install -y autoconf automake libtool pkg-config gcc-mingw-w64-x86-64
```

`gcc`, `make`, `curl`, `tar` are already present. `wine` is optional (the
parity script skips its Windows leg without it).

---

### Task 1: izba-core discovery shim (`find_mkfs_erofs`)

**Files:**
- Modify: `crates/izba-core/src/image/erofs.rs`

Probe order per spec §3.5: `$IZBA_MKFS_EROFS` env override (set-but-missing
is a hard error, not a fallthrough) → `<exe dir>/libexec/mkfs.erofs[.exe]` →
`PATH`. The testable core is a pure function taking the env value and exe
path as parameters; the thin wrapper reads the real environment.

- [ ] **Step 1: Write the failing tests**

Append inside the existing `mod tests` in `crates/izba-core/src/image/erofs.rs`:

```rust
    #[test]
    fn resolve_env_override_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let fake = dir.path().join("my-mkfs");
        std::fs::write(&fake, b"").unwrap();
        let got = find_mkfs_erofs_from(Some(fake.clone()), None).unwrap();
        assert_eq!(got, fake);
    }

    #[test]
    fn resolve_env_override_missing_is_error() {
        let err = find_mkfs_erofs_from(
            Some(std::path::PathBuf::from("/nonexistent/mkfs.erofs")),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("IZBA_MKFS_EROFS"));
    }

    #[test]
    fn resolve_bundled_libexec_beats_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let libexec = dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        let bundled = libexec.join(MKFS_EROFS_EXE);
        std::fs::write(&bundled, b"").unwrap();
        let got = find_mkfs_erofs_from(None, Some(dir.path().join("izba"))).unwrap();
        assert_eq!(got, bundled);
    }

    #[test]
    fn resolve_falls_back_to_path() {
        // No override, no bundled copy: outcome depends on whether the host
        // has erofs-utils installed — assert both arms explicitly.
        match find_mkfs_erofs_from(None, None) {
            Ok(p) => assert!(p.to_string_lossy().contains("mkfs.erofs")),
            Err(e) => assert!(e.to_string().contains("PATH")),
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core image::erofs`
Expected: compile error — `find_mkfs_erofs_from` and `MKFS_EROFS_EXE` not found.

- [ ] **Step 3: Implement the resolver**

In `crates/izba-core/src/image/erofs.rs`, above `build_erofs`:

```rust
#[cfg(windows)]
const MKFS_EROFS_EXE: &str = "mkfs.erofs.exe";
#[cfg(not(windows))]
const MKFS_EROFS_EXE: &str = "mkfs.erofs";

/// Locate `mkfs.erofs`: explicit `$IZBA_MKFS_EROFS` override, then a copy
/// bundled next to the running executable (`<exe dir>/libexec/`, Docker's
/// convention — the future Windows installer relies on this), then `$PATH`.
fn find_mkfs_erofs() -> Result<PathBuf> {
    find_mkfs_erofs_from(
        std::env::var_os("IZBA_MKFS_EROFS").map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

fn find_mkfs_erofs_from(
    env_override: Option<PathBuf>,
    current_exe: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(p) = env_override {
        if p.is_file() {
            return Ok(p);
        }
        bail!("IZBA_MKFS_EROFS is set to {} but no file exists there", p.display());
    }
    if let Some(dir) = current_exe.as_deref().and_then(Path::parent) {
        let bundled = dir.join("libexec").join(MKFS_EROFS_EXE);
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    which::which("mkfs.erofs").map_err(|_| {
        anyhow::anyhow!(
            "mkfs.erofs not found (checked $IZBA_MKFS_EROFS, <exe dir>/libexec/{MKFS_EROFS_EXE}, PATH) — install erofs-utils or set IZBA_MKFS_EROFS"
        )
    })
}
```

Add `use std::path::PathBuf;` to the imports (`Path` is already imported).
Then switch `build_erofs` to use it — replace:

```rust
    let mkfs = which::which("mkfs.erofs")
        .map_err(|_| anyhow::anyhow!("mkfs.erofs not found — install erofs-utils"))?;
```

with:

```rust
    let mkfs = find_mkfs_erofs()?;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core image::erofs`
Expected: all `resolve_*` tests + `erofs_smoke` PASS (smoke self-skips if
erofs-utils isn't installed).

- [ ] **Step 5: Workspace gates**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: clean. (If clippy suggests `format!` inlining or similar, fix it.)

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/image/erofs.rs
git commit -m "feat(core): mkfs.erofs discovery shim — env override, bundled libexec, PATH"
```

---

### Task 2: build script — pinned fetch + Linux reference build

**Files:**
- Create: `hack/build-mkfs-erofs-windows.sh` (mode 0755)
- Create: `hack/patches/erofs-utils/series.md` (documents the patch dir; series may be empty)

The script gains its cross-compile half in Task 3; this task lands the
skeleton: dependency check, checksum-verified fetch, fresh extract + patch
application, and the same-source Linux reference build (which also produces
`fsck.erofs` for the parity gate).

- [ ] **Step 1: Write the script**

`hack/build-mkfs-erofs-windows.sh`:

```bash
#!/usr/bin/env bash
# Build mkfs.erofs for Windows (native MinGW-w64, tar-mode only) plus a
# same-source Linux reference binary for the parity gate.
#
# Usage:  hack/build-mkfs-erofs-windows.sh [--linux-only]
#
# Outputs:
#   dist/mkfs.erofs.exe                          (cross build; skipped with --linux-only)
#   $CACHE/build-linux/mkfs/mkfs.erofs           (reference)
#   $CACHE/build-linux/fsck/fsck.erofs           (used by the parity script)
# where CACHE = ${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils
#
# Design: docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

VERSION=1.9.1
SHA256=a9ef5ab67c4b8d2d3e9ed71f39cd008bda653142a720d8a395a36f1110d0c432
URL="https://github.com/erofs/erofs-utils/archive/refs/tags/v${VERSION}.tar.gz"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils"
SRC_DIR="$CACHE_DIR/erofs-utils-$VERSION"
COMPAT_DIR="$REPO_ROOT/hack/mingw-compat"
PATCH_DIR="$REPO_ROOT/hack/patches/erofs-utils"
LINUX_ONLY="${1:-}"

# ---------------------------------------------------------------------------
# Dependency check (mirrors hack/build-kernel.sh)
# ---------------------------------------------------------------------------
TOOLS="curl tar make gcc autoconf automake libtool pkg-config"
[ "$LINUX_ONLY" = "--linux-only" ] || TOOLS="$TOOLS x86_64-w64-mingw32-gcc x86_64-w64-mingw32-objdump"
MISSING=""
for tool in $TOOLS; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    echo "error: missing tools:$MISSING" >&2
    echo "install with: sudo apt-get install -y curl tar make gcc autoconf automake libtool pkg-config gcc-mingw-w64-x86-64" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch (cached) + verify + fresh extract + patch
# ---------------------------------------------------------------------------
mkdir -p "$CACHE_DIR"
TARBALL="$CACHE_DIR/erofs-utils-$VERSION.tar.gz"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$URL"
echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null

rm -rf "$SRC_DIR"
tar -xzf "$TARBALL" -C "$CACHE_DIR"

shopt -s nullglob
for p in "$PATCH_DIR"/*.patch; do
    echo "applying $(basename "$p")"
    patch -d "$SRC_DIR" -p1 --no-backup-if-mismatch < "$p"
done
shopt -u nullglob

(cd "$SRC_DIR" && ./autogen.sh) >/dev/null

# Both builds MUST use identical feature flags or the parity gate is
# meaningless: everything optional is off; izba images are uncompressed by
# design (guest kernel has no EROFS decompression) and the bundled
# xxhash.c/uuid.c fallbacks remove all library dependencies.
CONFIGURE_FLAGS=(
    --disable-lz4 --disable-lzma --disable-multithreading
    --disable-fuse --disable-s3 --disable-oci
    --without-zlib --without-libdeflate --without-libzstd --without-qpl
    --without-xxhash --without-libcurl --without-openssl --without-libxml2
    --without-json-c --without-libnl3 --without-uuid --without-selinux
)

# ---------------------------------------------------------------------------
# Linux reference build (also provides fsck.erofs for the parity script)
# ---------------------------------------------------------------------------
BUILD_LINUX="$CACHE_DIR/build-linux"
rm -rf "$BUILD_LINUX" && mkdir -p "$BUILD_LINUX"
(cd "$BUILD_LINUX" && "$SRC_DIR/configure" "${CONFIGURE_FLAGS[@]}" \
    && make -j"$(nproc)") >"$BUILD_LINUX/build.log" 2>&1 \
    || { tail -30 "$BUILD_LINUX/build.log" >&2; exit 1; }
echo "linux reference: $BUILD_LINUX/mkfs/mkfs.erofs"

[ "$LINUX_ONLY" = "--linux-only" ] && exit 0

# ---------------------------------------------------------------------------
# Windows cross build (added in Task 3)
# ---------------------------------------------------------------------------
echo "error: cross build not implemented yet" >&2
exit 1
```

- [ ] **Step 2: Create the patch-series README**

`hack/patches/erofs-utils/series.md`:

```markdown
# erofs-utils MinGW patch series

Applied in lexical order by `hack/build-mkfs-erofs-windows.sh` on top of the
pinned upstream tag (see `VERSION`/`SHA256` in that script). Patches contain
ONLY source edits the compiler forces; everything injectable from outside the
tree (POSIX shims, stubs, `_O_BINARY`) lives in `hack/mingw-compat/` instead.

Regenerate after editing the extracted source:

    cd ${XDG_CACHE_HOME:-~/.cache}/izba/erofs-utils/erofs-utils-<ver>
    git init -q && git add -A && git commit -qm vanilla   # BEFORE editing
    ... hack ...
    git diff > /path/to/izba/hack/patches/erofs-utils/0001-<topic>.patch
```

- [ ] **Step 3: Run the Linux-only path**

Run: `chmod +x hack/build-mkfs-erofs-windows.sh && hack/build-mkfs-erofs-windows.sh --linux-only`
Expected: checksum verifies, autogen+configure+make succeed, prints the
reference binary path, exit 0.

If configure rejects a flag name (e.g. `--without-json-c` vs
`--without-json_c`): run `"$SRC_DIR/configure" --help | grep -E 'json|nl3'`
and fix the flag list in the script to the exact spellings.

- [ ] **Step 4: Smoke the reference binary**

```bash
B=${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils/build-linux
T=$(mktemp -d)
mkdir "$T/root" && echo hi > "$T/root/hello.txt"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
    -C "$T/root" -cf "$T/fixture.tar" .
"$B/mkfs/mkfs.erofs" --tar=f -T0 --quiet "$T/img.erofs" "$T/fixture.tar"
"$B/fsck/fsck.erofs" "$T/img.erofs" && echo SMOKE-OK
rm -rf "$T"
```

Expected: `SMOKE-OK`.

- [ ] **Step 5: Commit**

```bash
git add hack/build-mkfs-erofs-windows.sh hack/patches/erofs-utils/series.md
git commit -m "feat(hack): erofs-utils pinned-source build script (linux reference half)"
```

---

### Task 3: MinGW compat layer + cross build to a working `.exe`

**Files:**
- Create: `hack/mingw-compat/erofs_mingw.h`
- Create: `hack/mingw-compat/erofs_mingw.c`
- Create: `hack/mingw-compat/sys/uio.h`
- Create: `hack/mingw-compat/sys/ioctl.h`
- Modify: `hack/build-mkfs-erofs-windows.sh` (replace the "not implemented" tail)
- Create: `hack/patches/erofs-utils/0001-*.patch` (only if the build loop forces in-tree edits)

This is the port itself. The compat files below cover every failure from the
spike's error list; the build loop (Step 4) then iterates on whatever v1.9.1's
new code (`vmdk.c`, `metabox.c`, `importer.c`, `diskbuf.c`, …) adds on top.

- [ ] **Step 1: Write the compat header**

`hack/mingw-compat/erofs_mingw.h`:

```c
/* Force-included (gcc -include) into every erofs-utils translation unit of
 * the x86_64-w64-mingw32 build.  This port is TAR-MODE ONLY: POSIX
 * directory-walk APIs are declared here and abort loudly in erofs_mingw.c —
 * reaching one means the invocation left the tar-mode path and the output
 * cannot be trusted.  Design: 2026-06-10-mkfs-erofs-windows-design.md §3.1 */
#ifndef EROFS_MINGW_COMPAT_H
#define EROFS_MINGW_COMPAT_H
#ifdef __MINGW32__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>

typedef unsigned int uint;

/* dir-entry type constants (dir-walk mode only; never hit in tar-mode) */
#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12

#ifndef S_IFLNK
#define S_IFLNK  0xA000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

#ifndef _POSIX_OPEN_MAX
#define _POSIX_OPEN_MAX 16
#endif

/* device numbers come from ustar headers in tar-mode; the host filesystem's
 * are meaningless on Windows */
#define makedev(maj, min) (0)
#define major(dev) (0)
#define minor(dev) (0)

/* no POSIX user/group model; tar headers carry uid/gid */
static inline int getuid(void)  { return 0; }
static inline int getgid(void)  { return 0; }
static inline int geteuid(void) { return 0; }
static inline int getegid(void) { return 0; }

/* real shims (erofs_mingw.c) — used on the image-output path */
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
int fsync(int fd);
int ftruncate(int fd, off_t length);

/* loud abort stubs (erofs_mingw.c) — dir-walk mode only */
int lstat(const char *path, struct stat *st);
ssize_t readlink(const char *path, char *buf, size_t bufsiz);

#endif /* __MINGW32__ */
#endif
```

- [ ] **Step 2: Write the compat implementation + include shims**

`hack/mingw-compat/erofs_mingw.c`:

```c
/* Companion to erofs_mingw.h — linked into the MinGW build via LIBS=. */
#include "erofs_mingw.h"
#include <fcntl.h>
#include <io.h>

/* CRT text-mode translation would corrupt the image; force binary mode for
 * every fd (mingw-w64 reads _CRT_fmode at startup). */
unsigned int _CRT_fmode = _O_BINARY;

static void die_stub(const char *api)
{
	fprintf(stderr,
		"mkfs.erofs(win32): %s reached — non-tar path is unsupported\n",
		api);
	exit(70);
}

int lstat(const char *path, struct stat *st)
{
	(void)path; (void)st;
	die_stub("lstat");
	return -1;
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
	(void)path; (void)buf; (void)bufsiz;
	die_stub("readlink");
	return -1;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	__int64 cur = _telli64(fd);
	int n;

	if (cur < 0 || _lseeki64(fd, offset, SEEK_SET) < 0)
		return -1;
	n = _read(fd, buf, (unsigned int)count);
	_lseeki64(fd, cur, SEEK_SET);
	return n;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	__int64 cur = _telli64(fd);
	int n;

	if (cur < 0 || _lseeki64(fd, offset, SEEK_SET) < 0)
		return -1;
	n = _write(fd, buf, (unsigned int)count);
	_lseeki64(fd, cur, SEEK_SET);
	return n;
}

int fsync(int fd)
{
	return _commit(fd);
}

int ftruncate(int fd, off_t length)
{
	return _chsize_s(fd, length) == 0 ? 0 : -1;
}
```

`hack/mingw-compat/sys/uio.h`:

```c
/* Minimal <sys/uio.h> for the MinGW erofs-utils build. */
#ifndef EROFS_MINGW_SYS_UIO_H
#define EROFS_MINGW_SYS_UIO_H
#include <sys/types.h>
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#endif
```

`hack/mingw-compat/sys/ioctl.h`:

```c
/* Minimal <sys/ioctl.h> for the MinGW erofs-utils build: block-device
 * ioctls never apply on Windows (output is always a regular file). */
#ifndef EROFS_MINGW_SYS_IOCTL_H
#define EROFS_MINGW_SYS_IOCTL_H
static inline int ioctl(int fd, unsigned long req, ...)
{
	(void)fd; (void)req;
	return -1;
}
#endif
```

- [ ] **Step 3: Add the cross-build half to the script**

Replace the final three lines of `hack/build-mkfs-erofs-windows.sh`
(`echo "error: cross build not implemented yet" ...; exit 1`) with:

```bash
BUILD_WIN="$CACHE_DIR/build-win32"
rm -rf "$BUILD_WIN" && mkdir -p "$BUILD_WIN"

x86_64-w64-mingw32-gcc -O2 -D_FILE_OFFSET_BITS=64 -I"$COMPAT_DIR" \
    -c "$COMPAT_DIR/erofs_mingw.c" -o "$BUILD_WIN/erofs_mingw.o"

(cd "$BUILD_WIN" && \
    CPPFLAGS="-I$COMPAT_DIR -include $COMPAT_DIR/erofs_mingw.h -D_FILE_OFFSET_BITS=64" \
    LIBS="$BUILD_WIN/erofs_mingw.o" \
    "$SRC_DIR/configure" --host=x86_64-w64-mingw32 "${CONFIGURE_FLAGS[@]}" \
    && make -j"$(nproc)") >"$BUILD_WIN/build.log" 2>&1 \
    || { tail -40 "$BUILD_WIN/build.log" >&2; exit 1; }

EXE="$BUILD_WIN/mkfs/mkfs.erofs.exe"
[ -f "$EXE" ] || EXE="$BUILD_WIN/mkfs/.libs/mkfs.erofs.exe"
[ -f "$EXE" ] || { echo "error: mkfs.erofs.exe not produced" >&2; exit 1; }

# Import assertion (spec §3.2): only kernel32 + msvcrt allowed.
IMPORTS="$(x86_64-w64-mingw32-objdump -p "$EXE" | awk '/DLL Name/{print tolower($3)}' | sort -u)"
BAD="$(echo "$IMPORTS" | grep -Ev '^(kernel32\.dll|msvcrt\.dll)$' || true)"
if [ -n "$BAD" ]; then
    echo "error: unexpected DLL imports:" >&2
    echo "$BAD" >&2
    exit 1
fi

mkdir -p dist
cp "$EXE" dist/mkfs.erofs.exe
echo "windows binary: dist/mkfs.erofs.exe (imports: $(echo "$IMPORTS" | tr '\n' ' '))"
```

- [ ] **Step 4: The build loop — iterate until the .exe links**

Run: `hack/build-mkfs-erofs-windows.sh`

Expect failures; for each, classify and fix, then re-run:

1. **Missing declaration/constant/header that is platform-plumbing** →
   extend `hack/mingw-compat/` (header for decls/macros, `.c` for
   definitions, new stub via `die_stub` if it's dir-walk/device-node-only
   functionality such as `opendir`/`readdir`, `mknod`, `chown`).
2. **Source line that cannot compile even with shims** (e.g.
   `st.st_blksize` — MinGW's `struct stat` has no such member; likely also
   `mmap` in `diskbuf.c` if reached) → edit `$SRC_DIR` and record an
   in-tree patch per `series.md`'s regeneration recipe. Keep each patch
   `#ifdef __MINGW32__`-guarded and minimal. For `st_blksize` specifically,
   substitute a 4096 fallback under the ifdef.
3. **Configure-level failure** (libtool quirks, missing AC macro) → prefer
   fixing via the script's environment; patch `configure.ac` only as a last
   resort (it forces re-running autogen).

Functions that ARE reachable in tar-mode (anything in `tar.c`, `io.c`,
`cache.c`, `super.c`, `inode.c` data paths) must get REAL implementations,
never abort stubs. When unsure whether a function is reachable, give it an
abort stub — the parity gate in Task 4 will expose a wrong guess as a loud
exit 70, never as silent corruption.

Expected end state: script exits 0 and prints
`windows binary: dist/mkfs.erofs.exe (imports: kernel32.dll msvcrt.dll )`.

- [ ] **Step 5: Re-verify the Linux half still builds from patched source**

Run: `hack/build-mkfs-erofs-windows.sh --linux-only && echo LINUX-STILL-OK`
Expected: `LINUX-STILL-OK` (patches apply before BOTH builds, so any
`#ifdef __MINGW32__` leak that breaks Linux shows up here).

- [ ] **Step 6: Commit**

```bash
git add hack/mingw-compat hack/build-mkfs-erofs-windows.sh hack/patches/erofs-utils
git commit -m "feat(hack): MinGW tar-mode cross build of mkfs.erofs — kernel32+msvcrt only"
```

(Do NOT commit `dist/` — it is gitignored, same as the kernel artifacts.)

---

### Task 4: parity verification script (Linux leg)

**Files:**
- Create: `hack/verify-mkfs-erofs-parity.sh` (mode 0755)

CI-compatible: non-interactive, env-overridable paths, exit 0 = parity
proven, exit 1 = failure, exit 2 = Windows leg skipped (no wine) with a
verification bundle emitted for the real-Windows leg (Task 5).

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Parity gate for the Windows mkfs.erofs build: the cross-built .exe must
# produce a BYTE-IDENTICAL image to the same-source Linux reference binary.
#
# Exit codes:  0 parity proven (wine present)
#              1 divergence or build/fsck failure
#              2 Windows leg skipped (no wine) — bundle emitted to
#                dist/erofs-parity-bundle/ for hack/spike/verify-mkfs-erofs-parity.ps1
#
# Env overrides: IZBA_EROFS_CACHE (build dir), IZBA_EROFS_EXE (the .exe)
set -euo pipefail

cd "$(dirname "$0")/.."
CACHE="${IZBA_EROFS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/izba/erofs-utils}"
LINUX_MKFS="$CACHE/build-linux/mkfs/mkfs.erofs"
LINUX_FSCK="$CACHE/build-linux/fsck/fsck.erofs"
EXE="${IZBA_EROFS_EXE:-dist/mkfs.erofs.exe}"
for f in "$LINUX_MKFS" "$LINUX_FSCK" "$EXE"; do
    [ -f "$f" ] || { echo "error: $f missing — run hack/build-mkfs-erofs-windows.sh first" >&2; exit 1; }
done

# Shared deterministic flags: -T0 pins timestamps, -U pins the volume UUID.
UUID=11111111-2222-3333-4444-555555555555
MKFS_FLAGS=(--tar=f -T0 -U "$UUID" --quiet)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Deterministic fixture: regular/empty/8KiB files, symlink, hardlink, nested
# dirs, mode variety — every ustar field class izba's flattened images use.
# ---------------------------------------------------------------------------
FIX="$WORK/fixture"
mkdir -p "$FIX/bin" "$FIX/deep/a/b/c"
printf 'hello erofs\n'        > "$FIX/hello.txt"
: > "$FIX/empty"
head -c 8192 /dev/zero | tr '\0' 'x' > "$FIX/bin/big8k.bin"
printf 'nested leaf\n'        > "$FIX/deep/a/b/c/leaf"
ln -s ../hello.txt              "$FIX/bin/link-to-hello"
ln "$FIX/hello.txt"             "$FIX/hardlink-hello"
chmod 755 "$FIX/bin/big8k.bin"
chmod 600 "$FIX/deep/a/b/c/leaf"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime=@0 -C "$FIX" -cf "$WORK/fixture.tar" .

# ---------------------------------------------------------------------------
# Reference image (Linux binary) + fsck
# ---------------------------------------------------------------------------
"$LINUX_MKFS" "${MKFS_FLAGS[@]}" "$WORK/ref.erofs" "$WORK/fixture.tar"
"$LINUX_FSCK" "$WORK/ref.erofs"
REF_SHA="$(sha256sum "$WORK/ref.erofs" | cut -d' ' -f1)"
echo "reference: sha256=$REF_SHA ($(stat -c%s "$WORK/ref.erofs") bytes)"

# ---------------------------------------------------------------------------
# Windows leg: wine if available, else emit a bundle and skip
# ---------------------------------------------------------------------------
if ! command -v wine >/dev/null 2>&1; then
    BUNDLE=dist/erofs-parity-bundle
    rm -rf "$BUNDLE" && mkdir -p "$BUNDLE"
    cp "$EXE" "$WORK/fixture.tar" "$BUNDLE/"
    echo "$REF_SHA" > "$BUNDLE/reference.sha256"
    printf '%s\n' "${MKFS_FLAGS[@]}" > "$BUNDLE/mkfs-flags.txt"
    echo "SKIP: wine not installed — bundle at $BUNDLE/;"
    echo "  run hack/spike/verify-mkfs-erofs-parity.ps1 on the Windows host."
    exit 2
fi
wine "$EXE" "${MKFS_FLAGS[@]}" "$WORK/win.erofs" "$WORK/fixture.tar"
if cmp -s "$WORK/ref.erofs" "$WORK/win.erofs"; then
    echo "PASS: byte-identical images from Linux and Windows binaries"
else
    cmp "$WORK/ref.erofs" "$WORK/win.erofs" || true
    echo "FAIL: images diverge" >&2
    exit 1
fi
```

- [ ] **Step 2: Run it**

Run: `chmod +x hack/verify-mkfs-erofs-parity.sh && hack/verify-mkfs-erofs-parity.sh; echo "exit=$?"`
Expected here (no wine): reference sha printed, `SKIP: wine not installed`,
`exit=2`, and `dist/erofs-parity-bundle/` contains
`mkfs.erofs.exe fixture.tar reference.sha256 mkfs-flags.txt`.

If `-U` is rejected by the `--without-uuid` build (the bundled
`lib/uuid.c` fallback should still parse it — verify): rebuild without
`--without-uuid` only if libuuid is NOT then linked into the .exe (the
import assertion catches it); otherwise drop `-U` from `MKFS_FLAGS` and pin
the UUID instead with an in-tree patch defaulting the volume UUID to zeros
under `__MINGW32__` + document in the spec. Prefer the `-U` route.

- [ ] **Step 3: Commit**

```bash
git add hack/verify-mkfs-erofs-parity.sh
git commit -m "feat(hack): erofs parity gate — byte-compare Linux vs Windows builds"
```

---

### Task 5: Windows-side verifier (PowerShell leg)

**Files:**
- Create: `hack/spike/verify-mkfs-erofs-parity.ps1`

Consumes the bundle from Task 4 on a real Windows host. This is also the
entry point for the one-time manual end-to-end gate (spec §3.4).

- [ ] **Step 1: Write the script**

```powershell
# Windows leg of the mkfs.erofs parity gate.  Copy dist/erofs-parity-bundle/
# from the WSL side, then:   pwsh -File verify-mkfs-erofs-parity.ps1 <bundle-dir>
# Exit 0 = byte parity proven on real Windows; exit 1 = divergence/error.
param([Parameter(Mandatory = $true)][string]$BundleDir)
$ErrorActionPreference = 'Stop'

$exe   = Join-Path $BundleDir 'mkfs.erofs.exe'
$tar   = Join-Path $BundleDir 'fixture.tar'
$want  = (Get-Content (Join-Path $BundleDir 'reference.sha256')).Trim()
$flags = Get-Content (Join-Path $BundleDir 'mkfs-flags.txt')
$out   = Join-Path ([System.IO.Path]::GetTempPath()) 'izba-win.erofs'
Remove-Item -Force -ErrorAction SilentlyContinue $out

& $exe @flags $out $tar
if ($LASTEXITCODE -ne 0) { Write-Error "mkfs.erofs.exe failed: $LASTEXITCODE"; exit 1 }

$got = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLower()
Remove-Item -Force $out
if ($got -eq $want) {
    Write-Host "PASS: byte-identical to the Linux reference ($got)"
    exit 0
}
Write-Error "FAIL: sha256 $got != reference $want"
exit 1
```

- [ ] **Step 2: Sanity-check syntax from WSL (no execution)**

Run: `pwsh.exe -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw 'hack/spike/verify-mkfs-erofs-parity.ps1')) > \$null; 'SYNTAX-OK'"`
(if `pwsh.exe` interop is unavailable in the sandbox, ask the user to run it)
Expected: `SYNTAX-OK`.

- [ ] **Step 3: Commit**

```bash
git add hack/spike/verify-mkfs-erofs-parity.ps1
git commit -m "feat(spike): Windows-side parity verifier for mkfs.erofs.exe"
```

---

### Task 6: documentation + final gates

**Files:**
- Modify: `hack/README.md` (new section)
- Modify: `CLAUDE.md` is NOT touched (no new contracts; discovery shim is doc-commented at the site)

- [ ] **Step 1: Document the toolchain in hack/README.md**

Append a section (match the file's existing style/heading level):

```markdown
## mkfs.erofs for Windows

`build-mkfs-erofs-windows.sh` cross-compiles pinned erofs-utils into a
native, tar-mode-only `dist/mkfs.erofs.exe` (imports: kernel32+msvcrt — no
Cygwin, no WSL2) plus a same-source Linux reference binary. Compat shims
live in `mingw-compat/`; forced in-tree edits in `patches/erofs-utils/`.
POSIX dir-walk APIs are stubbed to abort with exit 70 — the binary is only
valid for `mkfs.erofs --tar=f ...` invocations (which is all izba uses).

`verify-mkfs-erofs-parity.sh` proves the .exe byte-identical to the Linux
reference (under wine when present; otherwise it emits
`dist/erofs-parity-bundle/` for `spike/verify-mkfs-erofs-parity.ps1` on a
real Windows host — exit 2 means "run the Windows leg").

izba-core finds the binary via `$IZBA_MKFS_EROFS` → `<exe dir>/libexec/` →
`$PATH` (see `crates/izba-core/src/image/erofs.rs`).

Design: `docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md`.
```

- [ ] **Step 2: Run all workspace gates**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
```

Expected: all green.

- [ ] **Step 3: Re-run both hack scripts end-to-end**

```bash
hack/build-mkfs-erofs-windows.sh && hack/verify-mkfs-erofs-parity.sh; echo "exit=$?"
```

Expected: build exits 0 with the import line; verify prints the reference
sha and exits 0 (wine) or 2 (bundle emitted).

- [ ] **Step 4: Commit**

```bash
git add hack/README.md
git commit -m "docs(hack): mkfs.erofs-on-Windows toolchain runbook"
```

- [ ] **Step 5: Hand the manual gate to the user**

Tell the user (do not attempt from the sandbox): copy
`dist/erofs-parity-bundle/` to the Windows spike host and run
`hack/spike/verify-mkfs-erofs-parity.ps1 <bundle-dir>`; then rebuild the
spike `rootfs.erofs` with `dist/mkfs.erofs.exe` and re-run the rung-7
OpenVMM boot. Record both results in
`docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md` (§A2
follow-up #2) — that recording closes spec §3.4.
