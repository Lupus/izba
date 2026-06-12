#!/usr/bin/env bash
# Build a static /sbin/nft for the izba initramfs (musl, via Alpine).
# Output: dist/nft  (use: IZBA_NFT=dist/nft hack/build-initramfs.sh)
#
# The guest egress stub (M1) uses nft to install a TCP REDIRECT ruleset that
# bends outbound connections to a local listener; nft must be statically
# linked so it runs in the minimal initramfs with no shared libraries.
set -euo pipefail
cd "$(dirname "$0")/.."
# Fixed output path: the docker mount below writes to dist/ directly.
OUT="dist/nft"
mkdir -p dist

docker run --rm -v "$PWD/dist:/out" alpine:3.22 sh -euc '
  apk add --no-cache build-base bison flex linux-headers pkgconf wget xz
  wget -qO- https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2 | tar xj
  (cd libmnl-1.0.5 && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  wget -qO- https://netfilter.org/projects/libnftnl/files/libnftnl-1.2.9.tar.xz | tar xJ
  (cd libnftnl-1.2.9 && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  wget -qO- https://netfilter.org/projects/nftables/files/nftables-1.1.3.tar.xz | tar xJ
  (cd nftables-1.1.3 \
    && ./configure --with-mini-gmp --without-cli --with-json=no \
         --enable-static --disable-shared \
    && make -j"$(nproc)" LDFLAGS="-all-static" \
    && strip src/nft && cp src/nft /out/nft)
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT"
