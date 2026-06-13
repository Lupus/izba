#!/usr/bin/env bash
# Build a static /sbin/nft for the izba initramfs (musl, via Alpine).
# Output: dist/nft  (use: IZBA_NFT=dist/nft hack/build-initramfs.sh)
#
# The guest egress stub (M1) uses nft to install a TCP REDIRECT ruleset that
# bends outbound connections to a local listener; nft must be statically
# linked so it runs in the minimal initramfs with no shared libraries.
#
# Every input is sha256-pinned (same posture as build-mke2fs.sh): the Alpine
# builder image by digest, and each netfilter source tarball by hash —
# verified inside the container before use, so a moved tag or a tampered
# mirror fails the build instead of silently changing the binary.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned Alpine builder — the immutable digest, not the mutable :3.22 tag.
ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

# Pinned netfilter sources (sha256 published at netfilter.org).
LIBMNL_VER=1.0.5
LIBMNL_SHA=274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525
LIBNFTNL_VER=1.2.9
LIBNFTNL_SHA=e8c216255e129f26270639fee7775265665a31b11aa920253c3e5d5d62dfc4b8
NFTABLES_VER=1.1.3
NFTABLES_SHA=9c8a64b59c90b0825e540a9b8fcb9d2d942c636f81ba50199f068fde44f34ed8

# Fixed output path: the docker mount below writes to dist/ directly.
OUT="dist/nft"
mkdir -p dist

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (build-nft.sh builds in an Alpine container)" >&2
    exit 1
}

docker run --rm \
    -e LIBMNL_VER="$LIBMNL_VER" -e LIBMNL_SHA="$LIBMNL_SHA" \
    -e LIBNFTNL_VER="$LIBNFTNL_VER" -e LIBNFTNL_SHA="$LIBNFTNL_SHA" \
    -e NFTABLES_VER="$NFTABLES_VER" -e NFTABLES_SHA="$NFTABLES_SHA" \
    -v "$PWD/dist:/out" "$ALPINE" sh -euc '
  apk add --no-cache build-base bison flex linux-headers pkgconf wget xz
  fetch() {  # url sha256
    f=$(basename "$1")
    wget -qO "$f" "$1"
    echo "$2  $f" | sha256sum -c -
  }
  fetch "https://netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VER}.tar.bz2" "$LIBMNL_SHA"
  tar xjf "libmnl-${LIBMNL_VER}.tar.bz2"
  (cd "libmnl-${LIBMNL_VER}" && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  fetch "https://netfilter.org/projects/libnftnl/files/libnftnl-${LIBNFTNL_VER}.tar.xz" "$LIBNFTNL_SHA"
  tar xJf "libnftnl-${LIBNFTNL_VER}.tar.xz"
  (cd "libnftnl-${LIBNFTNL_VER}" && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  fetch "https://netfilter.org/projects/nftables/files/nftables-${NFTABLES_VER}.tar.xz" "$NFTABLES_SHA"
  tar xJf "nftables-${NFTABLES_VER}.tar.xz"
  (cd "nftables-${NFTABLES_VER}" \
    && ./configure --with-mini-gmp --without-cli --with-json=no \
         --enable-static --disable-shared \
    && make -j"$(nproc)" LDFLAGS="-all-static" \
    && strip src/nft && cp src/nft /out/nft)
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT ($(du -sh "$OUT" | cut -f1), static, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
