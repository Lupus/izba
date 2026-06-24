#!/usr/bin/env bash
# Build a static /sbin/crun for the izba initramfs (musl, via Alpine).
# Output: dist/crun  (use: IZBA_CRUN=dist/crun hack/build-initramfs.sh)
#
# crun is the OCI runtime izba runs the user's workload container under inside
# the guest (Stance B). It must be statically linked so it runs in the minimal
# initramfs with no shared libraries — same posture as the vendored nft.
#
# Every input is sha256-pinned (same posture as build-nft.sh): the Alpine
# builder image by digest, and the crun release tarball by hash — verified
# inside the container before use, so a moved tag or a tampered mirror fails
# the build instead of silently changing the binary.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned Alpine builder — the immutable digest, not the mutable :3.22 tag.
# (Same digest as build-nft.sh.)
ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

# Pinned crun release (github.com/containers/crun/releases). The release dist
# tarball ships a pre-generated ./configure (no autogen.sh / git submodules).
CRUN_VER=1.28
CRUN_SHA=eb8fe73ffe44d868b14bb94fa6c295bd57e8bf023de43b61579da826c07cc406

# Pinned json-c (crun's JSON dep since the yajl→json-c migration). Alpine ships
# no json-c-static, so build the static lib from the official release tarball —
# same from-source posture build-nft.sh uses for libmnl/libnftnl.
JSONC_VER=0.18
JSONC_SHA=876ab046479166b869afc6896d288183bbc0e5843f141200c677b3e8dfb11724

# Fixed output path: the docker mount below writes to dist/ directly.
OUT="dist/crun"
mkdir -p dist

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (build-crun.sh builds in an Alpine container)" >&2
    exit 1
}

docker run --rm \
    -e CRUN_VER="$CRUN_VER" -e CRUN_SHA="$CRUN_SHA" \
    -e JSONC_VER="$JSONC_VER" -e JSONC_SHA="$JSONC_SHA" \
    -v "$PWD/dist:/out" "$ALPINE" sh -euc '
  # Static toolchain + crun build deps. argp-standalone supplies argp on musl;
  # the *-static archives are what let crun link with no shared libraries.
  # cmake builds the static json-c (no json-c-static package on Alpine).
  apk add --no-cache \
    build-base automake autoconf libtool pkgconf python3 cmake \
    libcap-dev libcap-static libseccomp-dev libseccomp-static \
    argp-standalone linux-headers wget
  fetch() {  # url sha256
    f=$(basename "$1")
    wget -qO "$f" "$1"
    echo "$2  $f" | sha256sum -c -
  }
  # --- static json-c into /usr so crun pkg-config finds it ---
  fetch "https://s3.amazonaws.com/json-c_releases/releases/json-c-${JSONC_VER}.tar.gz" "$JSONC_SHA"
  tar xzf "json-c-${JSONC_VER}.tar.gz"
  cmake -S "json-c-${JSONC_VER}" -B jsonc-build \
      -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DDISABLE_WERROR=ON
  make -C jsonc-build -j"$(nproc)" install
  # --- crun, fully static, no systemd (no dbus/cgroup-mgr in the guest) ---
  fetch "https://github.com/containers/crun/releases/download/${CRUN_VER}/crun-${CRUN_VER}.tar.gz" "$CRUN_SHA"
  tar xzf "crun-${CRUN_VER}.tar.gz"
  cd "crun-${CRUN_VER}"
  ./configure --enable-static --disable-systemd
  # BUILT_SOURCES (git-version.h) are NOT auto-made for an explicit target like
  # `crun`, so generate it first — the tarball ships .tarball-git-version.h that
  # its rule copies into place (no git repo needed).
  make -j"$(nproc)" git-version.h
  # crun links via libtool; -static alone leaves system libs (seccomp/cap)
  # dynamic. -all-static is libtool'\''s fully-static flag (same as build-nft.sh),
  # applied at link time so it does not break configure'\''s compile probes.
  make -j"$(nproc)" crun LDFLAGS="-all-static"
  strip crun
  cp crun /out/crun
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT ($(du -sh "$OUT" | cut -f1), static, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
