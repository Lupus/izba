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
  - `gzran.c`: don't include `<zlib.h>` (absent from MinGW sysroots); the
    entire file body is already `HAVE_ZLIB`-guarded.

Regenerate after editing the extracted source:

    cd ${XDG_CACHE_HOME:-~/.cache}/izba/erofs-utils/erofs-utils-<ver>
    git init -q && git add -A && git commit -qm vanilla   # BEFORE editing
    ... hack ...
    git diff > /path/to/izba/hack/patches/erofs-utils/0001-<topic>.patch
