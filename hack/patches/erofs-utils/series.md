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
