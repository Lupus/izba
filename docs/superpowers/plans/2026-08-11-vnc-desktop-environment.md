# VNC Desktop Environment v2 (LXDE-lite) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bare-openbox VNC desktop with an authored LXDE-lite session (lxpanel taskbar/menu + pcmanfm desktop + fixed openbox menu) so users get discoverable window switching, a working right-click, and an Applications menu.

**Architecture:** Everything ships inside the existing vendored `kasmvnc.erofs` bundle (same install→copy-closure→patchelf→assert→mkfs pipeline). init's second desktop spawn execs a new bundled `izba-session` script instead of `openbox` directly; one new host-side file-bind makes libmenu-cache's compiled-in `menu-cached` path resolvable. No wire/proto changes.

**Tech Stack:** Debian bookworm packages (pcmanfm 1.3.2 + lxpanel 0.10.1, both GTK2), patchelf bundling, Rust (izba-init, izba-core), KVM e2e in `daemon_e2e.rs`.

**Spec:** [docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md](../specs/2026-08-11-vnc-desktop-environment-design.md)

## Global Constraints

- erofs stays **uncompressed** (guest kernel has no `EROFS_FS_ZIP`); expected bundle ≤ ~180 MB — if materially above, prune icons/locales/modules before merging (spec §9).
- All six workspace gates green before every commit (`cargo test --workspace`, clippy `-D warnings`, `fmt --check`, static izba-init musl build, the two `x86_64-pc-windows-gnu` cross gates). Run `[ -f .cargo-env ] && source .cargo-env` first.
- KVM suites and `hack/build-kasmvnc-erofs.sh` (needs docker) must run with the Bash sandbox disabled (`/dev/kvm` is invisible inside the sandbox, not absent).
- Fire-and-forget/no-restart desktop contract unchanged; no `DAEMON_PROTO_VERSION` bump; `docker+vnc` refusal (#216) untouched.
- The e2e must keep proving PRODUCTION discovery: never set `IZBA_KASMVNC_EROFS` (the test asserts it is unset).
- Conventional commits; TDD (failing test first) for every Rust change.

---

### Task 1: Authored desktop configuration + session script (`hack/vnc-config/`)

Checked-in, reviewable config files that Task 2 copies into the bundle over Debian's stock ones. No Rust in this task.

**Files:**
- Create: `hack/vnc-config/izba-session`
- Create: `hack/vnc-config/openbox/menu.xml`
- Create: `hack/vnc-config/lxpanel/izba/config`
- Create: `hack/vnc-config/lxpanel/izba/panels/panel`
- Create: `hack/vnc-config/pcmanfm/izba/pcmanfm.conf`
- Create: `hack/vnc-config/pcmanfm/izba/desktop-items-0.conf`
- Create: `hack/vnc-config/libfm/libfm.conf`
- Create: `hack/vnc-config/applications/xterm.desktop`

**Interfaces:**
- Produces: the `hack/vnc-config/` tree Task 2 installs verbatim; the in-bundle path `/opt/izba-vnc/bin/izba-session` Task 3's argv execs; the profile name `izba` used by both `--profile` flags.

- [ ] **Step 1: Write `izba-session`**

`hack/vnc-config/izba-session`:

```sh
#!/bin/sh
# izba VNC session: desktop + panel + window manager. Fire-and-forget with
# no restarts -- a dead component stays dead and is visible in
# /var/log/izba-vnc.log (the docker-engine precedent, see izba-init vnc.rs).
#
# lxpanel and pcmanfm resolve "--profile izba" against XDG_CONFIG_HOME
# (default $HOME/.config; HOME=/tmp per vnc_env). Their fallback search for
# a default profile uses COMPILED-IN /etc/xdg + /usr/share paths that belong
# to the user's image inside the container, so relying on it would make the
# desktop image-dependent. Seed the profile deterministically instead; /tmp
# is the persistent overlay, so cp -r would keep a stale copy forever --
# refresh with rm -rf first (the profile is izba-owned, never user state).
rm -rf /tmp/.config/lxpanel/izba /tmp/.config/pcmanfm/izba
mkdir -p /tmp/.config/lxpanel /tmp/.config/pcmanfm
cp -r /opt/izba-vnc/etc/lxpanel/izba /tmp/.config/lxpanel/izba
cp -r /opt/izba-vnc/etc/pcmanfm/izba /tmp/.config/pcmanfm/izba

pcmanfm --desktop --profile izba &
lxpanel --profile izba &
exec openbox
```

- [ ] **Step 2: Write the openbox fallback menu**

`hack/vnc-config/openbox/menu.xml` (replaces Debian's stock menu whose
`obamenu` pipe-menu / `obconf` / web-browser entries error on the bundle —
the reported bug). No `Exit` entry: killing the WM strands the session.

```xml
<?xml version="1.0" encoding="utf-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="izba">
    <item label="Terminal">
      <action name="Execute"><command>xterm</command></action>
    </item>
    <!-- built-in window list: switching even if the panel is dead -->
    <menu id="client-list-combined-menu" />
    <separator />
    <item label="Reconfigure">
      <action name="Reconfigure" />
    </item>
    <item label="Restart window manager">
      <action name="Restart" />
    </item>
  </menu>
</openbox_menu>
```

(Debian's stock `rc.xml` is kept — spec §4: Alt-Tab et al. are already
correct there; only `menu.xml` is replaced.)

- [ ] **Step 3: Write the lxpanel profile**

`hack/vnc-config/lxpanel/izba/config`:

```ini
[Command]
Terminal=xterm
```

`hack/vnc-config/lxpanel/izba/panels/panel`:

```
# izba lxpanel profile: bottom panel with Applications menu, window
# taskbar, pager, clock. Field names follow lxpanel 0.10's config format.
Global {
  edge=bottom
  align=left
  margin=0
  widthtype=percent
  width=100
  height=28
  transparent=0
  autohide=0
  setdocktype=1
  setpartialstrut=1
  usefontcolor=0
  background=0
  iconsize=24
}
Plugin {
  type=menu
  Config {
    system {
    }
    separator {
    }
    item {
      command=run
    }
  }
}
Plugin {
  type=taskbar
  expand=1
  Config {
    tooltips=1
    IconsOnly=0
    ShowAllDesks=0
    UseMouseWheel=1
    UseUrgencyHint=1
    FlatButton=0
    MaxTaskWidth=200
    spacing=1
    GroupedTasks=0
  }
}
Plugin {
  type=pager
}
Plugin {
  type=dclock
  Config {
    ClockFmt=%H:%M
    BoldFont=0
    IconOnly=0
    CenterText=0
  }
}
```

- [ ] **Step 4: Write the pcmanfm profile + libfm config**

`hack/vnc-config/pcmanfm/izba/pcmanfm.conf`:

```ini
[config]
bm_open_method=0

[ui]
always_show_tabs=0
max_tab_chars=32
win_width=800
win_height=520
side_pane_mode=places
view_mode=icon
show_hidden=0
sort=name;ascending;
```

`hack/vnc-config/pcmanfm/izba/desktop-items-0.conf` (solid color, no
wallpaper asset — spec §3):

```ini
[*]
wallpaper_mode=color
wallpaper_common=1
desktop_bg=#24262b
desktop_fg=#e8e8e8
desktop_shadow=#000000
show_wm_menu=0
sort=mtime;ascending;
show_documents=0
show_trash=0
show_mounts=0
```

(`show_wm_menu=0` keeps desktop right-click on pcmanfm's own menu — the
conventional one — rather than forwarding to openbox's root menu.)

`hack/vnc-config/libfm/libfm.conf`:

```ini
[config]
terminal=xterm
single_click=0
use_trash=0

[ui]
big_icon_size=48
small_icon_size=24
pane_icon_size=24
thumbnail_size=128
```

- [ ] **Step 5: Write the xterm desktop entry**

`hack/vnc-config/applications/xterm.desktop` (so the Applications menu is
never empty even on an image shipping no `.desktop` files):

```ini
[Desktop Entry]
Type=Application
Name=Terminal (xterm)
Comment=X terminal emulator
Exec=xterm
Icon=utilities-terminal
Categories=System;TerminalEmulator;
```

- [ ] **Step 6: Validate syntax**

Run:
```bash
sh -n hack/vnc-config/izba-session
python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('hack/vnc-config/openbox/menu.xml')"
```
Expected: both exit 0, no output.

- [ ] **Step 7: Commit**

```bash
git add hack/vnc-config/
git commit -m "feat(hack): authored LXDE-lite desktop config for the VNC bundle"
```

---

### Task 2: Bundle build — packages, module closure, caches, config install

**Files:**
- Modify: `hack/build-kasmvnc-erofs.sh`

**Interfaces:**
- Consumes: `hack/vnc-config/` from Task 1 (mounted into the builder container).
- Produces: `dist/kasmvnc.erofs` containing `bin/{pcmanfm,lxpanel,menu-cached,izba-session}` (all but `izba-session` patchelf'd), `lib/gdk-pixbuf/loaders.cache` + `lib/gdk-pixbuf/loaders/*.so`, `lib/libfm/*.so`, `lib/lxpanel/plugins/*.so`, `etc/{openbox/menu.xml,lxpanel/izba/…,pcmanfm/izba/…,libfm/libfm.conf,menus/…}`, `share/{applications/xterm.desktop,lxpanel,desktop-directories,icons/{Adwaita,hicolor},mime}`. Tasks 3–5 rely on these exact in-bundle paths.

- [ ] **Step 1: Mount `hack/vnc-config` into the builder and extend the package set**

In `hack/build-kasmvnc-erofs.sh`, add a read-only bind to the main `docker run` (alongside the `/cache` mount):

```sh
  -v "$HERE/vnc-config:/vnc-config:ro" \
```

Extend the `apt-get install` line:

```sh
apt-get install -y -qq --no-install-recommends \
  /cache/'"$KASMVNC_DEB"' \
  openbox xterm xfonts-base fonts-dejavu-core patchelf file \
  x11-xkb-utils \
  pcmanfm lxpanel lxmenu-data shared-mime-info adwaita-icon-theme >/dev/null
```

- [ ] **Step 2: Add the new binaries to `BINS`**

`menu-cached` is a libexec daemon libmenu-cache spawns from a compiled-in
path; locate it with `dpkg -L` rather than guessing (bookworm ships it via
the `libmenu-cache-bin` package, expected at `/usr/libexec/menu-cached`):

```sh
MENU_CACHED="$(dpkg -L libmenu-cache-bin | grep '/menu-cached$')"
BINS="/usr/bin/Xkasmvnc /usr/bin/kasmvncpasswd /usr/bin/xkbcomp /usr/bin/openbox /usr/bin/xterm /usr/bin/pcmanfm /usr/bin/lxpanel $MENU_CACHED"
```

- [ ] **Step 3: Copy the dlopened module trees (not ldd-visible)**

After the existing closure loop (`for _ in 1 2 3; do … done`), add:

```sh
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
```

- [ ] **Step 4: Regenerate the caches with bundle paths**

```sh
# gdk-pixbuf loaders cache: paths in the cache are absolute; rewrite them
# to the bundle mount before shipping. Loaded via GDK_PIXBUF_MODULE_FILE.
gdk-pixbuf-query-loaders "$B"/lib/gdk-pixbuf/loaders/*.so \
  | sed "s|$B/lib/gdk-pixbuf/loaders|/opt/izba-vnc/lib/gdk-pixbuf/loaders|" \
  > "$B/lib/gdk-pixbuf/loaders.cache"
grep -q "/opt/izba-vnc/lib/gdk-pixbuf/loaders/" "$B/lib/gdk-pixbuf/loaders.cache" || {
  echo "error: loaders.cache does not point into the bundle" >&2; exit 1; }
```

- [ ] **Step 5: Copy icon theme (pruned), mime db, menus, panel data**

```sh
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
# caches must be rebuilt AFTER pruning so lookups don't chase ghosts.
gtk-update-icon-cache -f -t "$B/share/icons/Adwaita" || true
gtk-update-icon-cache -f -t "$B/share/icons/hicolor" || true

cp -r /usr/share/mime "$B/share/mime"                      # shared-mime-info db
cp -r /usr/share/lxpanel "$B/share/lxpanel"                # panel images/data
cp -r /usr/share/desktop-directories "$B/share/desktop-directories"
mkdir -p "$B/etc/menus"
cp -r /etc/xdg/menus/. "$B/etc/menus/"                     # lxde-applications.menu
```

- [ ] **Step 6: Install the authored configs over the Debian defaults**

After the existing `cp -r /etc/xdg/openbox "$B/etc/openbox"` line:

```sh
# --- izba-authored desktop configuration (hack/vnc-config) ---
cp /vnc-config/openbox/menu.xml "$B/etc/openbox/menu.xml"   # replaces Debian's
mkdir -p "$B/etc/lxpanel" "$B/etc/pcmanfm" "$B/etc/libfm" "$B/share/applications"
cp -r /vnc-config/lxpanel/izba "$B/etc/lxpanel/izba"
cp -r /vnc-config/pcmanfm/izba "$B/etc/pcmanfm/izba"
cp /vnc-config/libfm/libfm.conf "$B/etc/libfm/libfm.conf"
cp /vnc-config/applications/xterm.desktop "$B/share/applications/xterm.desktop"
install -m 0755 /vnc-config/izba-session "$B/bin/izba-session"
```

- [ ] **Step 7: Extend the self-containment assertion to module dirs and add a content manifest check**

Replace both `for f in "$B"/bin/* "$B"/lib/*.so*` loops' glob with a `find`
so nested module `.so`s are patchelf'd AND asserted (the second loop is the
assertion — a module that escaped the sweep would ship pointing at builder
paths and die only in the guest):

```sh
ELFS="$(find "$B"/bin "$B"/lib -type f \( -name '*.so*' -o -path "$B/bin/*" \))"
for f in $ELFS; do
  ...existing body unchanged...
done
```

(Apply to the patchelf pass and the assertion pass identically.)

Then, right before the final `du -sh`, add a manifest check naming every
path a later task depends on:

```sh
for req in bin/pcmanfm bin/lxpanel bin/menu-cached bin/izba-session \
           lib/gdk-pixbuf/loaders.cache etc/openbox/menu.xml \
           etc/lxpanel/izba/panels/panel etc/pcmanfm/izba/desktop-items-0.conf \
           etc/libfm/libfm.conf share/applications/xterm.desktop \
           share/icons/Adwaita/index.theme share/mime/mime.cache; do
  [ -e "$B/$req" ] || { echo "error: bundle missing $req" >&2; exit 1; }
done
grep -q obamenu "$B/etc/openbox/menu.xml" && { echo "error: stock Debian menu.xml shipped" >&2; exit 1; }
echo "bundle manifest: OK"
```

- [ ] **Step 8: Build and verify**

Run (sandbox disabled — needs docker):
```bash
bash hack/build-kasmvnc-erofs.sh
```
Expected: `self-containment assertion: OK`, `bundle manifest: OK`, final
size line. If the erofs lands materially above ~180 MB, prune (Adwaita
sizes, unused libfm modules) before committing — spec §9.

- [ ] **Step 9: Commit**

```bash
git add hack/build-kasmvnc-erofs.sh
git commit -m "feat(hack): LXDE-lite desktop in the kasmvnc bundle (pcmanfm, lxpanel, icons, mime, authored configs)"
```

---

### Task 3: init — session script spawn + GTK environment (`vnc.rs`)

**Files:**
- Modify: `crates/izba-init/src/vnc.rs`
- Test: same file, `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `/opt/izba-vnc/bin/izba-session` (Task 2).
- Produces: spawn 2's script `exec`s `{CONTAINER_BUNDLE_DIR}/bin/izba-session`; `vnc_env()` gains `GDK_PIXBUF_MODULE_FILE`, `XDG_MENU_PREFIX`, and a system-suffixed `XDG_DATA_DIRS`. Task 5's e2e asserts the processes this session starts.

- [ ] **Step 1: Update the failing tests first**

In `crates/izba-init/src/vnc.rs` tests:

1. In `desktop_exec_argvs_runs_server_then_wm_as_root_with_honest_logging`, change the wm assertion:

```rust
        assert!(
            wm.contains("exec /opt/izba-vnc/bin/izba-session"),
            "spawn 2 must exec the bundled session script (pcmanfm + lxpanel \
             + openbox), not bare openbox: {wm}"
        );
```

2. In `the_server_does_not_get_display_but_both_get_the_bundle_env`, replace the `XDG_DATA_DIRS` assertion and add the two new vars:

```rust
            // Bundle share FIRST (its menus/icons/mime win), then the
            // image's own share dirs so GUI apps the image ships appear in
            // the Applications menu (spec 2026-08-11 §7).
            assert_eq!(
                env_of(argv, "XDG_DATA_DIRS"),
                Some("/opt/izba-vnc/share:/usr/share:/usr/local/share".to_string())
            );
            // gdk-pixbuf resolves image loaders through this cache; without
            // it GTK2 falls back to builder-image paths that don't exist.
            assert_eq!(
                env_of(argv, "GDK_PIXBUF_MODULE_FILE"),
                Some("/opt/izba-vnc/lib/gdk-pixbuf/loaders.cache".to_string())
            );
            // lxpanel's Applications menu reads lxde-applications.menu via
            // the XDG menu spec prefix.
            assert_eq!(
                env_of(argv, "XDG_MENU_PREFIX"),
                Some("lxde-".to_string())
            );
```

3. Add a new drift-style test pinning the session-script contract:

```rust
    /// The wm spawn's wait loop and the session script are two halves of one
    /// contract: the script assumes the X server is already up (it starts
    /// pcmanfm/lxpanel immediately), which is only true because the argv in
    /// front of it waits on the socket.
    #[test]
    fn wm_spawn_waits_for_the_socket_then_execs_the_session_script() {
        let (_server, wm) = scripts();
        assert!(wm.contains(X_SOCKET), "socket wait must precede the session: {wm}");
        let wait = wm.find(X_SOCKET).unwrap();
        let exec = wm.find("exec /opt/izba-vnc/bin/izba-session").unwrap();
        assert!(wait < exec, "wait must come BEFORE the exec: {wm}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-init vnc -- --nocapture`
Expected: FAIL on the three changed/new assertions (`exec /opt/izba-vnc/bin/openbox` still present; `XDG_DATA_DIRS` mismatch; missing env vars).

- [ ] **Step 3: Implement**

In `vnc_env()` change the `XDG_DATA_DIRS` entry and append the new vars:

```rust
        (
            "XDG_DATA_DIRS".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/share:/usr/share:/usr/local/share"),
        ),
        (
            "GDK_PIXBUF_MODULE_FILE".to_string(),
            format!("{CONTAINER_BUNDLE_DIR}/lib/gdk-pixbuf/loaders.cache"),
        ),
        ("XDG_MENU_PREFIX".to_string(), "lxde-".to_string()),
```

In `desktop_exec_argvs`, change the wm script's exec target (comment updated to match — the doc comment's item 2 should now describe `izba-session`: pcmanfm --desktop + lxpanel backgrounded, openbox exec'd as session leader, all fire-and-forget):

```rust
    let wm = format!(
        "mkdir -p /var/log; \
         i=0; while [ ! -e {X_SOCKET} ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; \
         exec {CONTAINER_BUNDLE_DIR}/bin/izba-session >>{VNC_LOG} 2>&1"
    );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-init`
Expected: PASS (all, not just vnc — the module's other tests must not regress).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/vnc.rs
git commit -m "feat(init): exec the LXDE-lite izba-session script with GTK env for the VNC desktop"
```

---

### Task 4: host — `menu-cached` file-bind (`runtime_config.rs`)

libmenu-cache spawns its cache daemon from a compiled-in libexec path with no
env override; inside the container that path belongs to the user's image.
Occupy it with a single-file bind, exactly like the existing `xkbcomp` bind
(spec §6).

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (fn `add_vnc_mounts` ~line 1280, test `a_vnc_sandbox_gets_bundle_xkbcomp_and_secrets_bound_in` ~line 2112)

**Interfaces:**
- Consumes: bundle `bin/menu-cached` (Task 2) at `VNC_BUNDLE_SHARED_DIR/bin/menu-cached`.
- Produces: container path `/usr/libexec/menu-cached`, bound RO for `vnc: true` sandboxes only. Task 5's e2e asserts the daemon actually runs.

- [ ] **Step 1: Extend the failing test**

In `a_vnc_sandbox_gets_bundle_xkbcomp_and_secrets_bound_in`, after the xkbcomp assertions:

```rust
        // libmenu-cache (lxpanel's Applications menu backend) spawns its
        // daemon from a COMPILED-IN libexec path — same class as xkbcomp:
        // occupy the hardcoded path with a bundle file-bind.
        let mc = m("/usr/libexec/menu-cached").expect("menu-cached file bind");
        assert_eq!(
            mc.source().as_ref().and_then(|p| p.to_str()),
            Some("/run/izba/vnc/bin/menu-cached")
        );
        assert!(mc.options().as_ref().unwrap().iter().any(|o| o == "ro"));
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-core a_vnc_sandbox_gets_bundle -- --nocapture`
Expected: FAIL with `menu-cached file bind` panic.

- [ ] **Step 3: Implement**

In `add_vnc_mounts`, clone the xkbcomp bind block (~line 1297) with the new paths:

```rust
        spec.mounts_push(
            MountBuilder::default()
                .destination(PathBuf::from("/usr/libexec/menu-cached"))
                .typ("bind")
                .source(PathBuf::from(format!(
                    "{VNC_BUNDLE_SHARED_DIR}/bin/menu-cached"
                )))
                .options(bind_ro_options())
                .build()?,
        );
```

(Match the exact builder/option helpers the xkbcomp block uses — copy its
shape verbatim, only destination/source differ. Update `add_vnc_mounts`'s
doc comment list with a fourth bullet for it.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-core runtime_config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs
git commit -m "feat(core): bind bundle menu-cached at libmenu-cache's hardcoded libexec path"
```

---

### Task 5: e2e — desktop-component liveness, first boot AND after restart

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (the two `/proc` cmdline scans at ~lines 1928–1948 and ~2010–2030, inside `vnc_desktop_e2e`)

**Interfaces:**
- Consumes: the running session from Tasks 1–4 (`pcmanfm --desktop`, `lxpanel`, `menu-cached` processes).
- Produces: a shared `assert_desktop_procs` helper both call sites use.

- [ ] **Step 1: Factor the scan into a polling helper**

Both existing scans run once and check `["Xkasmvnc", "openbox"]`. pcmanfm/
lxpanel start in parallel with openbox and `menu-cached` is spawned lazily
by the menu plugin, so the new components need a bounded poll, not a single
snapshot. Add near `prove_desktop_session`:

```rust
/// Assert every desktop component is a live process inside the container,
/// polling briefly: pcmanfm/lxpanel start alongside openbox, and
/// menu-cached is spawned lazily by lxpanel's menu plugin, so a single
/// snapshot right after the RFB proof can race their startup.
fn assert_desktop_procs(data: &Path, name: &str, phase: &str) {
    let wants = ["Xkasmvnc", "openbox", "lxpanel", "pcmanfm", "menu-cached"];
    let no_env: &[(&str, &str)] = &[];
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut procs = String::new();
    loop {
        let o = izba(
            data,
            no_env,
            &[
                "exec",
                name,
                "--",
                "sh",
                "-c",
                // pgrep is not in busybox-alpine's default applet set.
                "for p in /proc/[0-9]*; do tr '\\0' ' ' < \"$p/cmdline\"; echo; done",
            ],
        );
        assert_ok(&o, "list container processes");
        procs = stdout_of(&o);
        if wants.iter().all(|w| procs.contains(w)) {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    for want in wants {
        assert!(
            procs.contains(want),
            "[{phase}] {want} must be running inside the container, got:\n{procs}\n{}",
            vnc_diag(data, name)
        );
    }
}
```

- [ ] **Step 2: Replace both call sites**

Replace the first-boot scan block (comment `// pgrep is not in busybox…`
through the `for want in ["Xkasmvnc", "openbox"] { … }` loop) with:

```rust
    assert_desktop_procs(&data, name, "first boot");
```

and the post-restart scan block likewise with:

```rust
    assert_desktop_procs(&data, name, "after restart");
```

Update the test's doc comment item 4 to name the full component list, and
extend item 6's restart promise to cover it.

- [ ] **Step 3: Compile-check the test**

Run: `cargo test -p izba-cli --test daemon_e2e --no-run`
Expected: compiles; without `IZBA_INTEGRATION=1` the test self-skips (real run is Task 6).

- [ ] **Step 4: Commit**

```bash
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(e2e): assert the full LXDE-lite component set, first boot and after restart"
```

---

### Task 6: Full verification — gates, bundle, real-VM e2e

**Files:** none new — this task runs everything.

- [ ] **Step 1: The six workspace gates**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all green. (No izba-core/izba-proto *public type* changed, so the app gate is not required.)

- [ ] **Step 2: Build + stage the bundle for the e2e**

Run (sandbox disabled):
```bash
bash hack/build-kasmvnc-erofs.sh
mkdir -p target/debug/artifacts
cp dist/kasmvnc.erofs target/debug/artifacts/kasmvnc.erofs
```
(`vnc_bundle_path()` resolves `<exe-dir>/../artifacts/kasmvnc.erofs`; test
exes live in `target/debug/deps`. Do NOT export `IZBA_KASMVNC_EROFS` — the
test refuses to run with it set.)

- [ ] **Step 3: Run the VNC e2e on real KVM**

Run (sandbox disabled — `/dev/kvm` is invisible inside the sandbox, not absent; needs the artifacts from docs/testing.md):
```bash
IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e vnc_desktop_e2e -- --test-threads=1 --nocapture
```
Expected: PASS, including the new `assert_desktop_procs` on both phases. Grep the output for the phase strings — a skip is not a pass (the rust-cache lesson: job-green ≠ test-ran).

- [ ] **Step 4: Manual visual pass**

```bash
cargo build -p izba-cli
# in a scratch data root:
target/debug/izba create --vnc --image debian:bookworm --name vncdesk /tmp/vncws && \
target/debug/izba start vncdesk && target/debug/izba vnc url vncdesk
```
Open the URL: verify the panel is visible (Applications menu opens, taskbar
buttons switch between two xterms, clock ticks), desktop right-click shows
pcmanfm's menu, openbox root menu (if reachable via keybinding) has no
error dialogs. Screenshot for the PR. Then `izba rm --force vncdesk`.

- [ ] **Step 5: Fix anything found, then commit fixes**

Any defect found here loops back to the owning task's file with a test
first where representable (`sh` config errors → Task 1 files + rebuild;
env/argv errors → Task 3 tests). Commit per fix, conventional message.

---

### Task 7: Docs + delivery

**Files:**
- Modify: `README.md:301-311` (the `--vnc` feature paragraph)
- Modify: `.github/workflows/e2e.yml` — **no change expected**: the
  `kasmvnc-erofs` job keys its cache on `hashFiles('hack/build-kasmvnc-erofs.sh')`,
  which Task 2 changed, so the bundle rebuilds automatically. Verify the key
  also covers `hack/vnc-config/**` — it does NOT, so extend it:
  `key: kasmvnc-erofs-${{ hashFiles('hack/build-kasmvnc-erofs.sh', 'hack/vnc-config/**') }}`.

- [ ] **Step 1: Update the README feature paragraph**

Replace "openbox + xterm" (README.md:302) with the honest new contents:

```markdown
`izba create --vnc` (or `izba vnc on <name>` on an existing sandbox, restart
required if it's running) boots with a KasmVNC remote desktop — a lightweight
LXDE-style session (openbox window manager, lxpanel taskbar with an
Applications menu and clock, pcmanfm desktop, xterm) — reachable via
`izba vnc url <name>` …
```

(Keep the rest of the paragraph verbatim.)

- [ ] **Step 2: Extend the CI cache key**

In `.github/workflows/e2e.yml`, `kasmvnc-erofs` job:

```yaml
          key: kasmvnc-erofs-${{ hashFiles('hack/build-kasmvnc-erofs.sh', 'hack/vnc-config/**') }}
```

(Without this, a config-only change would serve a stale cached bundle to the
e2e — the false-green class the dogfood reviews keep finding.)

- [ ] **Step 3: Commit**

```bash
git add README.md .github/workflows/e2e.yml
git commit -m "docs(readme),ci(e2e): describe the LXDE-lite VNC desktop; key the bundle cache on vnc-config"
```

- [ ] **Step 4: Deliver per the repo workflow**

```bash
git push -u origin worktree-vnc-desktop-env
gh pr create --title "feat(vnc): LXDE-lite desktop environment (lxpanel + pcmanfm + fixed openbox menu)" --body "..."   # ready-for-review, NEVER --draft; body ends with the Claude Code attribution trailer
bash hack/devbuild.sh   # dispatch installer build while CI runs; record the exact dist/local/<ts>-<sha>/ path
```
Then CI-iterate to fully green (all required checks + SonarCloud CLEAN;
Greptile if credits are back), and report: summary, PR link, exact
main-checkout `dist/local/<ts>-<sha>/` path + install commands.

---

## Self-Review Notes

- Spec §4 (packages, modules, caches, pruned icons, authored configs) → Tasks 1–2. §5 (session script + argv swap) → Tasks 1, 3. §6 (menu-cached bind) → Task 4. §7 (env) → Task 3. §8 (assertions, e2e both phases, size checkpoint) → Tasks 2, 5, 6. §9 size gate → Task 2 Step 8 / Task 6.
- The spec's §6 "verify an env override first" is resolved in-plan to the file-bind: libmenu-cache 1.1 has no runtime override for the daemon path (`MENUCACHE_LIBEXECDIR` is compile-time); the `dpkg -L` step in Task 2 guards the source path instead. The e2e's `menu-cached` liveness assert (Task 5) is the proof the resolution works — if it fails on the real VM, the fallback investigation happens in Task 6 Step 5 with the bind as the first suspect.
- lxpanel/pcmanfm profile-resolution risk (compiled-in fallback paths) is neutralized by `izba-session` seeding `$HOME/.config` explicitly (Task 1) — profiles never depend on lxpanel's search order.
