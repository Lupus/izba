#!/usr/bin/env bash
# Build a self-contained KasmVNC + openbox + xterm bundle and pack it into an
# erofs image for the izba VNC display feature.
#
# Promoted from hack/spike/build-kasmvnc-bundle.sh (spike proven end-to-end
# across glibc/musl/busybox images — see hack/spike/kasmvnc-bundle-findings.md).
# Same approach: install the upstream KasmVNC .deb + a minimal WM (openbox) +
# a test X app (xterm) in a digest-pinned Debian bookworm container, copy the
# binaries, their full shared-library closure, the dynamic loader itself, and
# all runtime data (xkb, fonts, fontconfig, openbox config/themes, the
# KasmVNC web client) into one tree, patchelf every ELF to interpreter+rpath
# under /opt/izba-vnc (the fixed mount path izba-init will bind the bundle
# at), assert the result is self-contained, then pack the tree into an erofs
# image.
#
# The guest kernel builds CONFIG_EROFS_FS=y with NO EROFS_FS_ZIP* options
# (hack/kernel.config), so the image is built UNCOMPRESSED — a compressed
# erofs would not mount. Expect ~100-110 MB (vs the spike's 42 MB tar.gz).
#
# Output: dist/kasmvnc.erofs (override with KASMVNC_OUT).
set -euo pipefail

KASMVNC_VERSION=1.5.0
KASMVNC_DEB="kasmvncserver_bookworm_${KASMVNC_VERSION}_amd64.deb"
KASMVNC_URL="https://github.com/kasmtech/KasmVNC/releases/download/v${KASMVNC_VERSION}/${KASMVNC_DEB}"
KASMVNC_SHA256=770fd3df51510beecc89666879d82faf411276e68c6e11df612f736b891b5f71
BUILDER_IMAGE="debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241" # bookworm-slim 2026-08

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_FILE="${KASMVNC_OUT:-$HERE/../dist/kasmvnc.erofs}"
mkdir -p "$(dirname "$OUT_FILE")"

CACHE_DIR="$HERE/../dist/.kasmvnc-cache"
mkdir -p "$CACHE_DIR"

command -v docker >/dev/null 2>&1 || {
  echo "error: docker not found (build-kasmvnc-erofs.sh builds the bundle in a Debian container)" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE_DIR="$WORK/stage"
mkdir -p "$STAGE_DIR"

if [ ! -f "$CACHE_DIR/$KASMVNC_DEB" ]; then
  # --https-only: refuse any redirect that downgrades to http (S6506); the
  # sha256 check below is the integrity gate either way.
  wget -q --https-only -O "$CACHE_DIR/$KASMVNC_DEB" "$KASMVNC_URL"
fi
echo "$KASMVNC_SHA256  $CACHE_DIR/$KASMVNC_DEB" | sha256sum -c -

docker run --rm \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$CACHE_DIR:/cache:ro" \
  -v "$STAGE_DIR:/bundle" \
  -v "$HERE/vnc-config:/vnc-config:ro" \
  "$BUILDER_IMAGE" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  /cache/'"$KASMVNC_DEB"' \
  openbox xterm xfonts-base fonts-dejavu-core fonts-symbola patchelf file \
  x11-xkb-utils \
  pcmanfm lxpanel lxmenu-data shared-mime-info adwaita-icon-theme >/dev/null

B=/bundle
rm -rf "$B"/{bin,lib,share,etc}
mkdir -p "$B"/{bin,lib,share,etc}

# --- binaries ---
# libmenu-cache-bin ships TWO binaries and lxpanel needs both: menu-cached
# is the daemon lxpanel talks to, and menu-cache-gen is the generator that
# daemon spawns (from its own hardcoded /usr/lib/menu-cache path) to build
# the Applications menu. Shipping only the daemon yields a menu that opens
# but is permanently EMPTY, with nothing logged anywhere -- vendor both.
MENU_CACHE_BINS="$(dpkg -L libmenu-cache-bin | grep -E "/menu-cache(d|-gen)\$")"
BINS="/usr/bin/Xkasmvnc /usr/bin/kasmvncpasswd /usr/bin/xkbcomp /usr/bin/openbox /usr/bin/xterm /usr/bin/pcmanfm /usr/bin/lxpanel $MENU_CACHE_BINS"
for b in $BINS; do cp -L "$b" "$B/bin/"; done

# GLib execs every GAppInfo launch (lxpanel Run dialog, menu items, pcmanfm
# open-with) through its gio-launch-desktop helper, whose default location
# is a COMPILED-IN private glib-2.0 path that belongs to the image, not the
# bundle -- on an image without GLib the Run dialog dies with Failed to
# execute child process. Vendor the helper (libglib2.0-0 ships it; dpkg -L
# locates the private path) at libexec/ and select it via the
# GIO_LAUNCH_DESKTOP env var, which GLib consults before the compiled-in
# path (set in izba-init vnc_env, drift-pinned by a unit test there).
GIO_LAUNCH_HELPER="$(dpkg -L libglib2.0-0 | grep "/gio-launch-desktop\$")"
mkdir -p "$B/libexec"
cp -L "$GIO_LAUNCH_HELPER" "$B/libexec/gio-launch-desktop"

# --- shared-library closure (iterate until fixpoint over ldd of bins+libs) ---
copy_deps() {
  ldd "$1" 2>/dev/null | awk "/=>/ {print \$3} /^\t\// {print \$1}" | while read -r so; do
    [ -f "$so" ] || continue
    base="$(basename "$so")"
    [ -f "$B/lib/$base" ] || cp -L "$so" "$B/lib/$base"
  done
}
for b in $BINS; do copy_deps "$b"; done
copy_deps "$B/libexec/gio-launch-desktop"
for _ in 1 2 3; do for so in "$B"/lib/*; do copy_deps "$so"; done; done

# --- dlopened GTK2/libfm/lxpanel modules: invisible to ldd, copied
# explicitly, then fed BACK through copy_deps for their own closures ---
ARCH_LIB=/usr/lib/x86_64-linux-gnu
mkdir -p "$B"/lib/gdk-pixbuf/loaders "$B"/lib/libfm "$B"/lib/lxpanel/plugins
cp -L "$ARCH_LIB"/gdk-pixbuf-2.0/2.10.0/loaders/*.so "$B/lib/gdk-pixbuf/loaders/"
cp -L "$ARCH_LIB"/libfm/modules/*.so "$B/lib/libfm/"
cp -L "$ARCH_LIB"/lxpanel/plugins/*.so "$B/lib/lxpanel/plugins/" 2>/dev/null || true
for so in "$B"/lib/gdk-pixbuf/loaders/*.so "$B"/lib/libfm/*.so "$B"/lib/lxpanel/plugins/*.so; do
  [ -f "$so" ] && copy_deps "$so"
done
for _ in 1 2; do for so in "$B"/lib/*.so*; do copy_deps "$so"; done; done

# gdk-pixbuf loaders cache: paths in the cache are absolute; rewrite them
# to the bundle mount before shipping. Loaded via GDK_PIXBUF_MODULE_FILE.
# (query-loaders is a libexec-style binary, not on PATH in bookworm; it
# ships inside libgdk-pixbuf-2.0-0 itself at a fixed private path.)
GDK_PIXBUF_QUERY_LOADERS=/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders
"$GDK_PIXBUF_QUERY_LOADERS" "$B"/lib/gdk-pixbuf/loaders/*.so \
  | sed "s|$B/lib/gdk-pixbuf/loaders|/opt/izba-vnc/lib/gdk-pixbuf/loaders|" \
  > "$B/lib/gdk-pixbuf/loaders.cache"
grep -q "/opt/izba-vnc/lib/gdk-pixbuf/loaders/" "$B/lib/gdk-pixbuf/loaders.cache" || {
  echo "error: loaders.cache does not point into the bundle" >&2; exit 1; }

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
# Xft faces. DejaVu is the terminal face; Symbola is the per-glyph FALLBACK
# xterm reaches through fontconfig for what DejaVu lacks -- Miscellaneous
# Technical (U+23BF, U+23F5), Miscellaneous Symbols and Arrows, and
# monochrome emoji. A TUI drawn with those (Claude Code) otherwise renders
# them as blank boxes. Neither font covers CJK: that stays tofu, which
# would cost another ~14 MB of Unifont to close.
cp -r /usr/share/fonts/truetype "$B/share/fonts/truetype"   # dejavu + symbola for Xft apps
cp -r /etc/xdg/openbox "$B/etc/openbox" || true
mkdir -p "$B/share/themes"
for t in Clearlooks Onyx; do
  [ -d "/usr/share/themes/$t" ] && cp -r "/usr/share/themes/$t" "$B/share/themes/" || true
done

# --- desktop data ---
mkdir -p "$B"/share/icons
cp -r /usr/share/icons/hicolor "$B/share/icons/hicolor"
# Adwaita pruned to the small sizes GTK2 apps actually use (spec: <=12 MB)
mkdir -p "$B"/share/icons/Adwaita
cp /usr/share/icons/Adwaita/index.theme "$B/share/icons/Adwaita/"
for sz in 16x16 22x22 24x24 32x32 48x48; do
  [ -d "/usr/share/icons/Adwaita/$sz" ] && cp -r "/usr/share/icons/Adwaita/$sz" "$B/share/icons/Adwaita/"
done
# index.theme still lists the pruned sizes; GTK skips missing dirs, but the
# caches must be rebuilt AFTER pruning so lookups do not chase ghosts.
gtk-update-icon-cache -f -t "$B/share/icons/Adwaita" || true
gtk-update-icon-cache -f -t "$B/share/icons/hicolor" || true

cp -r /usr/share/mime "$B/share/mime"                      # shared-mime-info db
# The three compiled-in PACKAGE_DATA_DIRs of the desktop apps. Each is an
# ABSOLUTE path baked into the binary with no environment override, so the
# OCI spec binds each one over the corresponding /usr/share path
# (image/runtime_config.rs). They hold GtkBuilder .ui files, so the dialogs
# behind menu entries -- Desktop Preferences, Create New, Properties,
# Rename -- simply fail to open when they are absent, on any image that
# does not happen to ship pcmanfm itself.
cp -r /usr/share/lxpanel "$B/share/lxpanel"                # panel images + ui
cp -r /usr/share/libfm "$B/share/libfm"                    # libfm ui + terminals.list
cp -r /usr/share/pcmanfm "$B/share/pcmanfm"                # pcmanfm ui (desktop-pref)
cp -r /usr/share/desktop-directories "$B/share/desktop-directories"
mkdir -p "$B/etc/menus"
cp -r /etc/xdg/menus/. "$B/etc/menus/"                     # lxde-applications.menu

# --- izba-authored desktop configuration (hack/vnc-config) ---
cp /vnc-config/openbox/menu.xml "$B/etc/openbox/menu.xml"   # replaces the Debian default
mkdir -p "$B/etc/lxpanel" "$B/etc/pcmanfm" "$B/etc/libfm" "$B/share/applications"
cp -r /vnc-config/lxpanel/izba "$B/etc/lxpanel/izba"
cp -r /vnc-config/pcmanfm/izba "$B/etc/pcmanfm/izba"
cp /vnc-config/libfm/libfm.conf "$B/etc/libfm/libfm.conf"
# xterm defaults (UTF-8 decoding/titles, Xft face, erase key, clipboard).
# izba-init points XENVIRONMENT at this path, which is how it reaches an
# xterm launched from ANY of the desktop launchers -- see the file itself
# and the drift test in crates/izba-init/src/vnc.rs.
mkdir -p "$B/etc/X11"
cp /vnc-config/X11/Xresources "$B/etc/X11/Xresources"
cp /vnc-config/applications/xterm.desktop "$B/share/applications/xterm.desktop"
cp /vnc-config/applications/pcmanfm.desktop "$B/share/applications/pcmanfm.desktop"
install -m 0755 /vnc-config/izba-session "$B/bin/izba-session"

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

# --- ELF file list: bin/* (all binaries, including izba-session which is a
# shell script and gets skipped by the ELF-magic checks below) plus every
# nested .so under lib/, so dlopened module trees (gdk-pixbuf loaders,
# libfm, lxpanel plugins) are covered by both the patchelf pass and the
# self-containment assertion, not just the top-level lib/*.so* glob. ---
ELFS="$(find "$B"/bin "$B"/lib "$B"/libexec -type f \( -name "*.so*" -o -path "$B/bin/*" -o -path "$B/libexec/*" \))"

# --- make every ELF self-locating: bundle loader + bundle rpath ---
for f in $ELFS; do
  [ "$(basename "$f")" = ld-linux-x86-64.so.2 ] && continue
  if file "$f" | grep -q "ELF 64-bit"; then
    patchelf --set-rpath /opt/izba-vnc/lib "$f" 2>/dev/null || true
    if file "$f" | grep -q "interpreter"; then
      patchelf --set-interpreter /opt/izba-vnc/lib/ld-linux-x86-64.so.2 "$f"
    fi
  fi
done

# --- self-containment assertion: every bundled ELF (binaries AND libs) must
# resolve through the bundle rpath ONLY (loader too, for the ones that have
# one), never anything from the builder image. Covers lib/*.so* as well as
# bin/* because the patchelf pass above swallows per-file rpath failures
# (`2>/dev/null || true`) — a lib whose rpath-patch silently failed would
# otherwise ship undetected and only fail at runtime in the guest. ---
for f in $ELFS; do
  [ "$(basename "$f")" = ld-linux-x86-64.so.2 ] && continue
  file "$f" | grep -q "ELF 64-bit" || continue
  patchelf --print-rpath "$f" | grep -q "^/opt/izba-vnc/lib$" || {
    echo "error: $f rpath escapes the bundle" >&2; exit 1; }
  if file "$f" | grep -q "interpreter"; then
    patchelf --print-interpreter "$f" 2>/dev/null | grep -q "^/opt/izba-vnc/lib/ld-linux-x86-64.so.2$" || {
      echo "error: $f does not use the bundle loader" >&2; exit 1; }
  fi
done
echo "self-containment assertion: OK"

# --- content manifest: every path a later task depends on ---
for req in bin/pcmanfm bin/lxpanel bin/menu-cached bin/menu-cache-gen bin/izba-session \
           libexec/gio-launch-desktop \
           lib/gdk-pixbuf/loaders.cache etc/openbox/menu.xml \
           etc/X11/Xresources share/fonts/truetype/ancient-scripts/Symbola_hint.ttf \
           etc/lxpanel/izba/panels/panel etc/pcmanfm/izba/desktop-items-0.conf \
           etc/libfm/libfm.conf share/applications/xterm.desktop \
           share/applications/pcmanfm.desktop \
           share/icons/Adwaita/index.theme share/mime/mime.cache \
           share/lxpanel/images/my-computer.png share/libfm/terminals.list \
           share/libfm/ui/ask-rename.ui share/pcmanfm/ui/desktop-pref.ui \
           etc/menus/lxde-applications.menu \
           share/desktop-directories/lxde-menu-applications.directory; do
  [ -e "$B/$req" ] || { echo "error: bundle missing $req" >&2; exit 1; }
done
# The two dlopened module trees the OCI spec binds over the compiled-in
# multiarch dirs of liblxpanel and libfm (image/runtime_config.rs). They are
# copied by globs that tolerate an empty match, so assert they are NON-EMPTY
# here: an empty tree still binds cleanly and the failure would only show up
# as a panel with no plugins on a real boot.
# (NOTE: this whole block lives inside a single-quoted "sh -c" string --
# never use an apostrophe in a comment here, it closes the quote.)
for req in lib/lxpanel/plugins lib/libfm; do
  ls "$B/$req"/*.so >/dev/null 2>&1 || {
    echo "error: bundle module tree $req has no .so files" >&2; exit 1; }
done
grep -q obamenu "$B/etc/openbox/menu.xml" && { echo "error: stock Debian menu.xml shipped" >&2; exit 1; }
echo "bundle manifest: OK"

du -sh "$B"
echo "bundle contents ok"

# hand the staged tree (currently root-owned — this whole block ran as
# root inside the container) back to the host user so the trap below can
# remove the tempdir.
chown -R "$HOST_UID:$HOST_GID" "$B"
'

# --- pack the staged tree into an erofs image (uncompressed — the guest
# kernel has no EROFS_FS_ZIP* decompression support) ---
if command -v mkfs.erofs >/dev/null 2>&1; then
  mkfs.erofs "$OUT_FILE" "$STAGE_DIR"
else
  echo "mkfs.erofs not found on PATH — building it inside $BUILDER_IMAGE instead" >&2
  OUT_DIR="$(cd "$(dirname "$OUT_FILE")" && pwd)"
  OUT_NAME="$(basename "$OUT_FILE")"
  docker run --rm \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$STAGE_DIR:/stage:ro" \
    -v "$OUT_DIR:/out" \
    "$BUILDER_IMAGE" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends erofs-utils >/dev/null
mkfs.erofs "/out/'"$OUT_NAME"'" /stage
# this container runs as root by default, so the file it just wrote into
# the /out bind is root-owned; hand it back to the host user so a later
# re-run does not hit Permission denied overwriting dist/kasmvnc.erofs.
chown "$HOST_UID:$HOST_GID" "/out/'"$OUT_NAME"'"
'
fi

echo "wrote $OUT_FILE ($(du -sh "$OUT_FILE" | cut -f1), sha256 $(sha256sum "$OUT_FILE" | cut -d' ' -f1))"
