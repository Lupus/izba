# VNC desktop runs as the image user — design

**Date:** 2026-08-13
**Status:** approved
**Supersedes:** the "both run as container root" decision in
[2026-08-09-vnc-display-design.md](2026-08-09-vnc-display-design.md) §7 and
carried into [2026-08-11-vnc-desktop-environment-design.md](2026-08-11-vnc-desktop-environment-design.md).

## Problem

The VNC desktop — `Xkasmvnc` and the `izba-session` stack (openbox, lxpanel,
pcmanfm, menu-cached) — is `crun exec`'d with `--user 0:0`. Everything the
user does on that desktop (terminals from the panel, the file manager, any
GUI app) therefore runs as **container root**, while `izba exec` and
`ssh izba-<name>` for the same sandbox run as the image's configured `USER`
(e.g. `agent` in the claude docker image). The result: files created from the
desktop are root-owned in `/workspace`, the desktop's environment diverges
from the image author's intent, and the surface violates least privilege for
no benefit. A user who opens the desktop in the claude image reasonably
expects to be `agent`, exactly as they are over `izba exec`/ssh.

## Decision

**The desktop runs as the container's configured user** — the same
resolution `izba exec` uses when no explicit `--user` is requested: the OCI
spec's `process.user`, which `izba_core::image::runtime_config::
resolve_process_user` fills from the image `USER` (uid, primary gid, and
supplementary groups). Mechanically: `desktop_exec_argvs` passes `user: None`
to `crun_exec_argv` for both desktop spawns, so crun applies the container's
own process user.

Consequences by image shape:

- Image with `USER agent` (claude docker image): desktop runs as `agent`,
  matching `izba exec`.
- Image with no `USER` (alpine): configured user is root — behavior
  unchanged from today.
- Numeric or symbolic `USER`: whatever `resolve_process_user` already
  resolved for the container; no new resolution logic.

Rejected alternatives:

- *Hardcode a well-known user (`agent`)* — image-specific guesswork; wrong
  for every image that names its user differently.
- *A `--vnc-user` knob* — YAGNI. The right default requires no
  configuration; a knob can be added later without conflicting with this
  design.

## Ground preparation (the part root still does)

Dropping `--user 0:0` alone leaves the desktop unable to start on most
images, and dead-on-arrival on sandboxes upgraded from the root-desktop era.
The **existing stale-display cleanup exec** (`stale_display_cleanup_argv`,
already `--user 0:0`, already awaited before the desktop spawns) becomes the
single ground-preparation step. In addition to its current
`rm -f /tmp/.X1-lock /tmp/.X11-unix/X1; mkdir -p /tmp/.X11-unix` it must:

1. `chmod 1777 /tmp/.X11-unix` — a non-root X server must create the `X1`
   socket inside it (and a pre-change boot left it root-owned `0755`).
2. `mkdir -p /var/log`, create `/var/log/izba-vnc.log` if absent, and
   `chmod 666` it — both desktop spawns append to it from a uid that cannot
   create files under `/var/log`. The log **path contract is unchanged**
   (e2e diagnostics and docs keep pointing at `/var/log/izba-vnc.log`).
3. Remove izba-owned desktop state a pre-change (root) boot left behind,
   which would otherwise be unwritable/unremovable by the image user:
   `rm -rf /tmp/.config/lxpanel /tmp/.config/pcmanfm /tmp/.cache/menus
   /tmp/izba-vnc-fontcache`. All four are izba-owned by construction
   (profiles are re-seeded from the bundle by `izba-session` on every start;
   the caches are regenerated) — never user state.
4. `mkdir -p /tmp/.config /tmp/.cache` + `chmod 1777` both — `izba-session`
   and `menu-cached` (XDG dirs under `HOME=/tmp`) must create subdirs there,
   and a pre-change boot may have left them root-owned `0755`. `1777` under
   an already-`1777` `/tmp` introduces no new exposure class in a
   single-workload container.

The cleanup stays `--user 0:0` deliberately: it is what deletes root-owned
legacy files, and container-0 is a mapped unprivileged guest uid.

`hack/vnc-config/izba-session` itself is unchanged — its `rm -rf`/`cp -r`
profile refresh now operates on ground the cleanup guaranteed writable, and
the files it creates are owned by the image user.

## What does not change

- **Credentials:** `kasmpasswd` is already delivered 0644 in a 0755 dir,
  explicitly *because* the reader's uid differs from init's. Nothing moves.
- **Listener surface:** loopback-only `-interface`/`-websocketPort`,
  BasicAuth gate, `-SecurityTypes None`, `-BlacklistThreshold 0` — all
  unchanged.
- **Fire-and-forget contract:** no auto-restart; a dead desktop stays dead
  and is visible in the (path-unchanged) log.
- **docker mode:** `--docker --vnc` is refused (#216); no interaction.
- **Windows/OpenVMM:** izba-init is the only changed binary and is shared;
  no driver-specific behavior.

## Security posture

Strictly less privilege: the X server, window manager, and every process
launched from the desktop drop from container-root to the image user. No
gate weakens: the world-readable hash file and `-ac` (in-container display
access) were already the documented posture. This narrows the blast radius
of a compromised/browsing desktop session to the same identity `izba exec`
already grants.

## Testing

TDD; all six workspace gates green; KVM e2e run locally (USB post-mortem
rule: a green static board is not proof for a feature that only manifests in
a real VM).

1. **Unit (izba-init `vnc.rs`):**
   - `desktop_exec_argvs` emits **no `--user` flag** for either spawn (crun
     then applies the container's configured user) — flipping today's
     `--user 0:0` assertions.
   - `stale_display_cleanup_argv` keeps `--user 0:0` and gains pins for:
     `chmod 1777 /tmp/.X11-unix`, log pre-create + `chmod 666`, the four
     legacy `rm -rf` targets, and `chmod 1777` of `/tmp/.config` +
     `/tmp/.cache`.
2. **e2e (`daemon_e2e::vnc_desktop_e2e` + a new non-root leg):**
   - Existing alpine flow keeps proving the no-`USER` image (desktop uid 0,
     full RFB proof, restart proof).
   - New leg: sandbox created `--vnc` from `nginxinc/nginx-unprivileged`
     (digest-pinned, `USER 101` — the repo's existing non-root fixture in
     `izba-core/tests/integration.rs`), then: desktop process set live,
     `Uid:` of `Xkasmvnc` and `openbox` read from `/proc/<pid>/status` is
     101, and the credentialed HTTP + websocket/RFB proof passes — the
     desktop must *work*, not merely run, as the image user.
   - Upgrade path (root-owned leftovers) is covered by the unit pins on the
     cleanup script; no e2e boots a pre-change binary.
3. **Docs:** `vnc.rs` module/`desktop_exec_argvs` doc comments rewritten
   (the "container root / dockerd precedent" paragraph); this spec recorded;
   README's VNC section checked for root mentions.
