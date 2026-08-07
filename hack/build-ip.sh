#!/usr/bin/env bash
# Build a static /sbin/ip for the izba initramfs (musl, via Alpine).
# Output: dist/ip  (use: IZBA_IP=dist/ip hack/build-initramfs.sh)
#
# Docker mode (#198) gives the workload container its own netns; izba-init
# wires it to the init netns with a veth pair, and veth creation requires
# netlink (RTM_NEWLINK) — init's net.rs is ioctl-only by design. A vendored
# static `ip` performs the link/addr/route setup in both namespaces.
#
# Same sha256-pinned posture as build-nft.sh: Alpine builder by digest,
# source tarball by the hash kernel.org publishes in sha256sums.asc.
set -euo pipefail
cd "$(dirname "$0")/.."

ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

IPROUTE2_VER=6.12.0
IPROUTE2_SHA=bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9

OUT="dist/ip"
mkdir -p dist

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (build-ip.sh builds in an Alpine container)" >&2
    exit 1
}

docker run --rm \
    -e IPROUTE2_VER="$IPROUTE2_VER" -e IPROUTE2_SHA="$IPROUTE2_SHA" \
    -v "$PWD/dist:/out" "$ALPINE" sh -euc '
  apk add --no-cache build-base bison flex linux-headers pkgconf wget xz \
      libmnl-dev libmnl-static
  wget -qO ip.tar.xz "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-${IPROUTE2_VER}.tar.xz"
  echo "$IPROUTE2_SHA  ip.tar.xz" | sha256sum -c -
  tar xJf ip.tar.xz
  cd "iproute2-${IPROUTE2_VER}"
  # configure probes optional libs (elf/bpf/cap/selinux); none are installed,
  # so the probes disable them — exactly what a minimal static ip wants.
  ./configure
  # Only lib + ip are needed (no tc/ss/bridge binaries in the initramfs).
  #
  # -include endian.h works around a musl/glibc header gap: libnetlink.h uses
  # htobe64() but only pulls in <arpa/inet.h>, which transitively exposes it
  # on glibc but not on musl (musl declares the htobe64 family in <endian.h>
  # only). Forcing the include fixes the "implicit declaration of function
  # htobe64" build failure without patching upstream source.
  make -j"$(nproc)" SUBDIRS="lib ip" LDFLAGS="-static" CCOPTS="-O2 -pipe -include endian.h"
  strip ip/ip && cp ip/ip /out/ip
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT ($(du -sh "$OUT" | cut -f1), static, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
