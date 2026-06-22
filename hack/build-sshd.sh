#!/usr/bin/env bash
# Build a static /sbin/sshd for the izba initramfs (musl, via Alpine).
# Output: dist/sshd  (use: IZBA_SSHD=dist/sshd hack/build-initramfs.sh)
#
# The SSH access feature (Task 7) requires a static sshd binary so it can run
# inside the minimal initramfs with no shared libraries.  sshd is started by
# izba-init and listens on localhost:22 inside the guest; the host side reaches
# it via the port-relay mechanism.
#
# Every input is sha256-pinned (same posture as build-nft.sh): the Alpine
# builder image by digest, and the OpenSSH portable source tarball by hash —
# verified inside the container before use, so a moved tag or a tampered
# mirror fails the build instead of silently changing the binary.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned Alpine builder — the immutable digest, not the mutable :3.22 tag.
ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

# Pinned OpenSSH Portable source (sha256 computed from the published tarball).
OPENSSH_VER=9.9p2
OPENSSH_SHA=91aadb603e08cc285eddf965e1199d02585fa94d994d6cae5b41e1721e215673

# Fixed output path: the docker mount below writes to dist/ directly.
OUT="dist/sshd"
mkdir -p dist

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (build-sshd.sh builds in an Alpine container)" >&2
    exit 1
}

docker run --rm \
    -e OPENSSH_VER="$OPENSSH_VER" -e OPENSSH_SHA="$OPENSSH_SHA" \
    -v "$PWD/dist:/out" "$ALPINE" sh -euc '
  apk add --no-cache \
      build-base linux-headers \
      openssl-dev openssl-libs-static \
      zlib-dev zlib-static \
      autoconf automake wget

  fetch() {  # url sha256
    f=$(basename "$1")
    wget -qO "$f" "$1"
    echo "$2  $f" | sha256sum -c -
  }

  fetch "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VER}.tar.gz" \
        "$OPENSSH_SHA"
  tar xzf "openssh-${OPENSSH_VER}.tar.gz"

  cd "openssh-${OPENSSH_VER}"

  # Configure for a fully static build:
  #   --without-pam / --without-selinux   no PAM/SELinux in musl guest
  #   --with-ssl-engine=no                no ENGINE API (removed in OpenSSL 3)
  #   --with-zlib                         link zlib statically (dep present)
  #   --disable-strip                     we strip manually below
  #   --with-privsep-path=/run/sshd       izba-init creates this dir at boot
  #   --sysconfdir=/etc/ssh               where sshd looks for sshd_config
  #   LDFLAGS=-static                     musl libc → fully static link
  #
  # We pass -lresolv explicitly because the static OpenSSL pulls it in and
  # some musl toolchains need the hint to find the right archive.
  ./configure \
      --without-pam \
      --without-selinux \
      --with-ssl-engine=no \
      --with-zlib \
      --disable-strip \
      --with-privsep-path=/run/sshd \
      --sysconfdir=/etc/ssh \
      LDFLAGS="-static" \
      LIBS="-lresolv"

  make -j"$(nproc)" sshd
  strip sshd
  cp sshd /out/sshd
'

file "$OUT" | grep -q "statically linked" || {
    echo "error: $OUT is not statically linked" >&2
    file "$OUT" >&2
    exit 1
}
echo "wrote $OUT ($(du -sh "$OUT" | cut -f1), static, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
