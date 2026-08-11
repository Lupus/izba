# VNC desktop environment v2 (LXDE-lite) — design

**Date:** 2026-08-11
**Status:** approved
**Predecessor:** [2026-08-09-vnc-display-design.md](2026-08-09-vnc-display-design.md)
(the KasmVNC plumbing this builds on — bundle, relay, auth, auto-start).

## 1. Problem

The shipped VNC desktop is bare openbox with Debian's **stock** `/etc/xdg/openbox`
config copied verbatim into the bundle. Three user-visible consequences
(reported 2026-08-11 with screenshots):

1. Right-clicking the desktop opens Debian's default root menu, whose
   "Applications" entry is a pipe-menu shelling out to `/usr/bin/obamenu` —
   not in the bundle → an openbox error dialog. Same for the `ObConf` entry
   (`obconf` missing) and "Web browser" (dead on most images).
2. No taskbar/panel of any kind: openbox alone is *only* a window manager.
   With several maximized windows there is no visible way to switch (Alt-Tab
   works but is undiscoverable and often captured by the browser hosting the
   VNC page; middle-click window list likewise undiscoverable).
3. No desktop surface at all — right-click-the-root-window is the only
   entry point, which is alien to users who have never met a bare WM.

Nobody ever *authored* a desktop configuration for this environment; v1
shipped whatever Debian's openbox package defaulted to.

## 2. Decision (user-approved 2026-08-11)

Ship a **fuller lightweight desktop** — the classic LXDE-lite trio — inside
the existing vendored bundle, with izba-authored configuration:

- **`lxpanel`** — bottom panel: Applications start-menu, per-window taskbar
  buttons (the headline fix for switching), pager, clock.
- **`pcmanfm --desktop`** — desktop layer: background, desktop icons, and a
  conventional desktop right-click menu (Open Terminal, Create New, Desktop
  Preferences). It owns root-window clicks, which retires the broken openbox
  root menu as the primary surface.
- **openbox** stays the WM, with an izba-authored `menu.xml` (fallback menu
  with only working entries) replacing Debian's.

Toolkit coherence (probed 2026-08-11 in the pinned bookworm builder image):
bookworm's `pcmanfm` 1.3.2 and `lxpanel` 0.10.1 are **both GTK2**
(`libgtk2.0-0` + `libfm-gtk4`), so this pairing is a *single*-toolkit
closure — 98 packages with `--no-install-recommends`. The rejected
alternative `pcmanfm + tint2` would have pulled GTK3 *in addition* (152
packages) and still needed a hand-rolled `.desktop` pipe-menu for an
Applications menu; `lxpanel`'s menu-cache menu does that natively.

**Accepted trade-offs:** bundle grows from ~101 MB to an expected 160–180 MB
uncompressed (erofs stays uncompressed — the guest kernel has no
`EROFS_FS_ZIP`), which flows into the installers; GTK2 is legacy but fine in
a sha-pinned, read-only, loopback-only vendored bundle (see §9 maintenance).

## 3. Non-goals

- Compositing/transparency (no `xcompmgr`/`picom`), sound, GPU accel.
- A terminal beyond `xterm` (works, already bundled; a nicer terminal is a
  separate decision).
- Wallpaper image assets — the default background is a solid color from
  config, no binary asset shipped.
- Localization; everything is English/C locale.
- Any change to the KasmVNC/auth/relay plumbing, the `docker+vnc` refusal
  (#216), or the `DAEMON_PROTO_VERSION`. This is a guest-bundle + init-argv
  change only.

## 4. Bundle changes (`hack/build-kasmvnc-erofs.sh`)

Same builder image, same install→copy-closure→patchelf→assert→mkfs pipeline;
the package set grows and a config-authoring step is added.

- **Packages added:** `pcmanfm lxpanel` (pulls `libfm4/libfm-gtk4/
  libfm-modules`, `libmenu-cache3` + `menu-cached`, `lxmenu-data`,
  `lxpanel-data`, GTK2 stack) plus `shared-mime-info` (pcmanfm needs the
  mime db) and `adwaita-icon-theme` (GTK apps without an icon theme render
  broken-image placeholders everywhere).
- **Binaries copied:** `pcmanfm`, `lxpanel`, `menu-cached` (a *libexec*
  daemon libmenu-cache spawns — see §6), plus their ldd closures through the
  existing fixpoint loop. **dlopened GTK2 modules are not ldd-visible** and
  must be copied + patchelf'd explicitly: gdk-pixbuf loaders
  (`.../gdk-pixbuf-2.0/2.10.0/loaders/*.so`), libfm modules, lxpanel plugin
  `.so`s. The existing self-containment assertion already walks
  `lib/*.so*`; module directories are added to its sweep.
- **Caches regenerated at build time, pointing into the bundle:**
  - gdk-pixbuf `loaders.cache` — regenerate with `gdk-pixbuf-query-loaders`
    and rewrite paths to `/opt/izba-vnc/...`; loaded via
    `GDK_PIXBUF_MODULE_FILE` (§7).
  - icon caches (`gtk-update-icon-cache`) for the pruned theme.
  - mime database (`update-mime-database`) into `share/mime`.
- **Icon theme pruned:** keep `index.theme`, `hicolor`, and Adwaita sizes
  16/22/24/32/48 (+ `scalable` only if librsvg is already in the closure via
  GTK; otherwise drop it and the rsvg loader). Target ≤ 12 MB of icons
  (full adwaita is ~21 MB installed).
- **Data copied:** `share/lxpanel`, `share/lxmenu-data` (XDG menu
  definitions the Applications menu is built from), `etc/xdg/pcmanfm`,
  `etc/xdg/libfm` as *bases* for the authored configs below.

### Authored configuration (new `hack/vnc-config/` directory, copied over the Debian defaults)

Checked-in files, not heredocs — reviewable and diffable:

- `openbox/menu.xml` — fallback root menu: Terminal (`xterm`), a Windows
  submenu via openbox's built-in `client-list-combined-menu`, Reconfigure,
  Restart. **No** obamenu pipe-menu, no ObConf, no web-browser entry, no
  Exit (killing the WM strands the session — the panel/desktop keep running
  with no way back short of a sandbox restart).
- `openbox/rc.xml` — Debian's default is kept (Alt-Tab et al. already
  correct) unless implementation finds a needed tweak; any change is a
  reviewed diff against the stock file.
- `lxpanel/izba/panels/panel` — bottom edge; plugins: `menu` (Applications,
  from lxmenu-data), `taskbar` (grouped window buttons), `pager`, `space`,
  `dclock`. lxpanel copies the profile from `XDG_CONFIG_DIRS` on first run;
  `HOME=/tmp` (already the session's home) makes that per-boot state.
- `pcmanfm/izba/desktop-items-0.conf` + `pcmanfm/izba/pcmanfm.conf` —
  solid-color background (dark neutral), desktop icons enabled, single-click
  off.
- `libfm/libfm.conf` — `terminal=xterm` so every "Open Terminal" surface
  works; archiver/trash left default.
- `xterm.desktop` into bundle `share/applications/` so the Applications menu
  is never empty even on a bare image.

## 5. Session orchestration (`crates/izba-init/src/vnc.rs`)

The init-side two-spawn structure is unchanged: spawn 1 is still `Xkasmvnc`;
spawn 2's argv swaps `exec {BUNDLE}/bin/openbox` for
`exec {BUNDLE}/bin/izba-session`, keeping the existing X-socket wait loop in
front. `izba-session` is a new sh script *in the bundle*:

```sh
#!/bin/sh
# izba VNC session: desktop + panel + WM. Fire-and-forget, no restarts —
# a dead component stays dead and is visible in /var/log/izba-vnc.log.
pcmanfm --desktop --profile izba &
lxpanel --profile izba &
exec openbox
```

- openbox stays the `exec`'d session leader, so the process init observes is
  still the WM — the "desktop process died" signal keeps its meaning.
- pcmanfm/lxpanel tolerate starting alongside the WM (they only need the X
  server, which the wait loop already guarantees); no second-order ordering
  is introduced.
- All three inherit the spawn's env (§7) and append to `VNC_LOG` via the
  existing `sh -c` redirection.
- The bundle path of `izba-session` joins the existing init⇄bundle drift
  test (the constants that pin `/opt/izba-vnc` layout).

## 6. `menu-cached` reachability (`crates/izba-core/src/image/runtime_config.rs`)

libmenu-cache spawns its cache daemon from a **compiled-in** libexec path
(`/usr/libexec/menu-cached` on Debian) — inside the container that path
belongs to the user's image and won't exist. Resolution order for
implementation:

1. If libmenu-cache honors an env override or falls back to `PATH` lookup
   (verify in the builder), use that — zero host-side change.
2. Otherwise, author a **file-bind** of container
   `/usr/libexec/menu-cached` → bundle `bin/menu-cached` in
   `runtime_config.rs`, exactly like the existing `xkbcomp` file-bind (the X
   server hardcodes `/usr/bin/xkbcomp`) — authored only for `vnc: true`
   sandboxes, same as every other VNC bind.

If neither works, the panel's fallback is a menu-less taskbar — the
implementation must **not** ship that silently: the e2e (§8) asserts the
Applications menu backend is alive.

## 7. Environment additions (`vnc_env()`)

- `GDK_PIXBUF_MODULE_FILE=/opt/izba-vnc/lib/gdk-pixbuf/loaders.cache`
  (exact bundle-relative path fixed at implementation).
- `XDG_DATA_DIRS` grows a **system suffix**:
  `/opt/izba-vnc/share:/usr/share:/usr/local/share` — bundle first (its
  menus/icons/mime win), then the image's own `share` dirs so GUI apps the
  image ships appear in the Applications menu automatically.
- Existing `HOME=/tmp`, `PATH` (bundle first), `FONTCONFIG_PATH`,
  `XDG_CONFIG_DIRS` are unchanged and already correct for GTK2.

## 8. Testing

- **Build script:** self-containment assertion extended to the module
  directories (§4); a size print of the final erofs (the ~180 MB expectation
  is a review checkpoint, not a hard gate).
- **KVM VNC e2e** (`daemon_e2e` VNC test): after the existing RFB proof, an
  in-sandbox liveness step — `pgrep -f lxpanel`, `pgrep -f "pcmanfm
  --desktop"`, and the §6 menu-backend check (menu-cached running *or* the
  chosen fallback mechanism proven) — repeated after the existing
  stop/start restart step (the [stale-X-lock lesson][restart]: anything
  proven only on first boot is unproven).
- **Unit/drift tests:** `izba-session` path constant pinned host-side; the
  argv-generation tests in `vnc.rs` updated for the new spawn 2.
- **GUI dogfooding** (optional follow-up, not gating): a journey asserting
  the panel is visible and window switching works via taskbar clicks.

[restart]: ../../../crates/izba-init/src/vnc.rs

## 9. Risks & maintenance

- **GTK2 sunset:** trixie moves pcmanfm to GTK3. This design pins bookworm
  (builder image is digest-pinned), so nothing breaks spontaneously; the
  bump to a GTK3 stack is a contained future change to the build script +
  configs. Recorded here so the next builder-image bump doesn't trip on it.
- **dlopen blind spots:** the pattern to watch — anything GTK loads at
  runtime (pixbuf loaders, libfm modules, panel plugins) is invisible to
  `ldd` and to the current assertion until added to its sweep. A missing
  module manifests as broken icons or a dead plugin, not a crash; the e2e
  liveness checks (§8) plus one manual visual pass on the devbuild are the
  net.
- **Size:** ~+60–80 MB in every installer. Accepted in §2; if the measured
  result lands materially above 180 MB, prune (icon sizes, locales,
  unused libfm modules) before merging rather than re-litigating the design.
