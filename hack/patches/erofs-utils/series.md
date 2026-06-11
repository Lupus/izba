# erofs-utils MinGW patch series

Applied in lexical order by `hack/build-mkfs-erofs-windows.sh` on top of the
pinned upstream tag (see `VERSION`/`SHA256` in that script). Patches contain
ONLY source edits the compiler forces; everything injectable from outside the
tree (POSIX shims, stubs, `_O_BINARY`) lives in `hack/mingw-compat/` instead.

## Current series

- `0001-mingw-llp64-and-platform-holes.patch` — all `#ifdef __MINGW32__`-guarded
  (zero effect on the Linux reference build):
  - `err.h`/`internal.h`/`inode.c`: pointer round-trips through `unsigned long`
    (32-bit on LLP64 Windows) → `uintptr_t`; the `i_parent` tag-pointer
    truncation crashed mkfs at the first `erofs_igrab()`.
  - `io.c`/`diskbuf.c`: MinGW's `struct stat` has no `st_blksize`; use 4096,
    which matches what the Linux reference sees on ext4 (and its page size).
    Note: the Linux reference reads the host filesystem's real `st_blksize`
    while Windows pins 4096, so on a host fs reporting ≠4096 the two builds
    see different alignment inputs — benign for content parity but worth
    knowing when debugging a divergence.
  - `gzran.c`: don't include `<zlib.h>` (absent from MinGW sysroots); the
    entire file body is already `HAVE_ZLIB`-guarded.

- `0002-mingw-binary-tmpfile.patch` — `lib/diskbuf.c`, `#ifdef __MINGW32__`-
  guarded:
  - `erofs_tmpfile()`: mingw-w64's `mkstemp` opens in CRT TEXT mode (no
    `_O_BINARY`), so LF bytes are CRLF-expanded on write and `0x1a` reads
    back as EOF — silently corrupting any binary file content staged in the
    diskbuf (found on the real-Windows host: izba image builds failed with
    EIO on the first tar entry containing a `0x1a` byte). Replaced with an
    explicit `_O_BINARY | _O_TEMPORARY` open in `%TMPDIR%/%TMP%/%TEMP%`
    (delete-on-close also fixes the unlink-while-open leak — Windows cannot
    unlink open files).
  - `erofs_diskbuf_init()`: skip the stream-0 "stash inside the device fd"
    optimization — it ftruncates the output image to 2 TiB and writes at a
    1 TiB offset, which relies on sparse-file semantics; on a non-sparse
    NTFS file a successful ftruncate would make the first stash write
    zero-fill terabytes.

Regenerate after editing the extracted source:

    cd ${XDG_CACHE_HOME:-~/.cache}/izba/erofs-utils/erofs-utils-<ver>
    git init -q && git add -A && git commit -qm vanilla   # BEFORE editing
    ... hack ...
    git diff > /path/to/izba/hack/patches/erofs-utils/0001-<topic>.patch
