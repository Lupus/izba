#!/usr/bin/env bash
# SPIKE (throwaway): build a fully self-contained KasmVNC bundle that runs
# inside ANY container image (glibc, musl, shell-less), to de-risk the
# "izba ships a pre-baked VNC erofs" feature.
#
# Approach: install the upstream KasmVNC .deb + a minimal WM (openbox) + a
# test X app (xterm) in a digest-pinned Debian bookworm container, then copy
# the binaries, their full shared-library closure, the dynamic loader itself,
# and all runtime data (xkb, fonts, fontconfig, openbox config/themes, the
# KasmVNC web client) into one tree. Every ELF is patchelf'd to use the
# bundle's OWN loader at the fixed mount path /opt/izba-vnc, so the bundle
# needs nothing from the host image — not even /bin/sh.
#
# Output: dist/kasmvnc-bundle/ + dist/kasmvnc-bundle.tar.gz (+ size report).
#
# Production notes (if this graduates): pin the .deb by sha256 (done), keep
# the image digest-pinned (done), and turn the tree into an erofs instead of
# a tarball.
set -euo pipefail

KASMVNC_VERSION=1.5.0
KASMVNC_DEB="kasmvncserver_bookworm_${KASMVNC_VERSION}_amd64.deb"
KASMVNC_URL="https://github.com/kasmtech/KasmVNC/releases/download/v${KASMVNC_VERSION}/${KASMVNC_DEB}"
KASMVNC_SHA256=770fd3df51510beecc89666879d82faf411276e68c6e11df612f736b891b5f71
BUILDER_IMAGE="debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241" # bookworm-slim 2026-08

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${BUNDLE_OUT:-$HERE/../../dist/kasmvnc-bundle}"
mkdir -p "$OUT" "$OUT.cache"

if [ ! -f "$OUT.cache/$KASMVNC_DEB" ]; then
  wget -q -O "$OUT.cache/$KASMVNC_DEB" "$KASMVNC_URL"
fi
echo "$KASMVNC_SHA256  $OUT.cache/$KASMVNC_DEB" | sha256sum -c -

docker run --rm \
  -v "$OUT.cache:/cache:ro" \
  -v "$OUT:/bundle" \
  "$BUILDER_IMAGE" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  /cache/'"$KASMVNC_DEB"' \
  openbox xterm xfonts-base fonts-dejavu-core patchelf file \
  x11-xkb-utils >/dev/null

B=/bundle
rm -rf "$B"/{bin,lib,share,etc}
mkdir -p "$B"/{bin,lib,share,etc}

# --- binaries ---
BINS="/usr/bin/Xkasmvnc /usr/bin/kasmvncpasswd /usr/bin/xkbcomp /usr/bin/openbox /usr/bin/xterm"
for b in $BINS; do cp -L "$b" "$B/bin/"; done

# --- shared-library closure (iterate until fixpoint over ldd of bins+libs) ---
copy_deps() {
  ldd "$1" 2>/dev/null | awk "/=>/ {print \$3} /^\t\// {print \$1}" | while read -r so; do
    [ -f "$so" ] || continue
    base="$(basename "$so")"
    [ -f "$B/lib/$base" ] || cp -L "$so" "$B/lib/$base"
  done
}
for b in $BINS; do copy_deps "$b"; done
for _ in 1 2 3; do for so in "$B"/lib/*; do copy_deps "$so"; done; done
# the loader itself
cp -L /lib64/ld-linux-x86-64.so.2 "$B/lib/ld-linux-x86-64.so.2"

# libGL dispatch backend is dlopened, not ldd-visible; GLX is disabled at
# runtime but the server still links libGLX. Copy the mesa pieces if present.
for so in /usr/lib/x86_64-linux-gnu/libGLX_mesa.so.0 /usr/lib/x86_64-linux-gnu/libglapi.so.0; do
  [ -f "$so" ] && cp -L "$so" "$B/lib/" || true
done

# --- data ---
cp -r /usr/share/kasmvnc "$B/share/kasmvnc"          # web client + defaults
cp -r /usr/share/X11/xkb "$B/share/xkb"              # keymaps
mkdir -p "$B/share/fonts/X11"
cp -r /usr/share/fonts/X11/misc "$B/share/fonts/X11/misc"   # core fonts (xterm, server "fixed")
cp -r /usr/share/fonts/truetype "$B/share/fonts/truetype"   # dejavu for Xft apps
cp -r /etc/xdg/openbox "$B/etc/openbox" || true
mkdir -p "$B/share/themes"
for t in Clearlooks Onyx; do
  [ -d "/usr/share/themes/$t" ] && cp -r "/usr/share/themes/$t" "$B/share/themes/" || true
done

# minimal fontconfig setup pointing exclusively into the bundle
mkdir -p "$B/etc/fonts"
cat > "$B/etc/fonts/fonts.conf" <<EOF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>/opt/izba-vnc/share/fonts</dir>
  <cachedir>/tmp/izba-vnc-fontcache</cachedir>
</fontconfig>
EOF

# --- make every ELF self-locating: bundle loader + bundle rpath ---
for f in "$B"/bin/* "$B"/lib/*.so*; do
  [ "$(basename "$f")" = ld-linux-x86-64.so.2 ] && continue
  if file "$f" | grep -q "ELF 64-bit"; then
    patchelf --set-rpath /opt/izba-vnc/lib "$f" 2>/dev/null || true
    if file "$f" | grep -q "interpreter"; then
      patchelf --set-interpreter /opt/izba-vnc/lib/ld-linux-x86-64.so.2 "$f"
    fi
  fi
done

du -sh "$B"
echo "bundle contents ok"
'

tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")"
ls -lh "$OUT.tar.gz"
echo "OK: bundle at $OUT"
