#!/usr/bin/env bash
# Build a static sshd (+ its re-exec helper + sftp-server) for the izba
# initramfs (musl, via Alpine).  Outputs: dist/sshd, dist/sshd-session,
# dist/sftp-server
# (use: IZBA_SSHD=dist/sshd hack/build-initramfs.sh — it finds sshd-session
# and sftp-server alongside dist/sshd automatically).
#
# sftp-server is the native OpenSSH SFTP server. izba bind/copies it into the
# workload container and points `Subsystem sftp` at it (see hack/sshd_config),
# so the sftp protocol runs inside the container rather than in sshd's own
# (initramfs) namespace.
#
# The SSH access feature requires a static sshd so it can run inside the minimal
# initramfs with no shared libraries.  sshd is started by izba-init and listens
# on localhost:22 inside the guest; the host side reaches it via the port-relay
# mechanism.
#
# OpenSSH 9.8 split the monolithic sshd into a small network-facing listener
# (`sshd`, which fixed CVE-2024-6387 "regreSSHion") that re-execs a per-session
# worker `sshd-session`. The listener execs the worker by its compile-time
# libexec path, so both binaries must be vendored. We build with --prefix=/usr
# → the worker is expected at /usr/libexec/sshd-session, where
# build-initramfs.sh installs it.
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
  #   --prefix=/usr   helper re-exec path becomes /usr/libexec/sshd-{session,auth}
  ./configure \
      --prefix=/usr \
      --without-pam \
      --without-selinux \
      --with-ssl-engine=no \
      --with-zlib \
      --disable-strip \
      --with-privsep-path=/run/sshd \
      --sysconfdir=/etc/ssh \
      LDFLAGS="-static" \
      LIBS="-lresolv"

  make -j"$(nproc)" sshd sshd-session sftp-server
  for b in sshd sshd-session sftp-server; do
    strip "$b"
    cp "$b" "/out/$b"
  done
'

for b in sshd sshd-session sftp-server; do
    f="dist/$b"
    file "$f" | grep -q "statically linked" || {
        echo "error: $f is not statically linked" >&2
        file "$f" >&2
        exit 1
    }
    echo "wrote $f ($(du -sh "$f" | cut -f1), static, sha256 $(sha256sum "$f" | cut -d' ' -f1))"
done
