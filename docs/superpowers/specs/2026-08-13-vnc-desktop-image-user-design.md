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
Ground preparation is **two awaited execs** before the desktop spawns —
split so that root only ever *removes* and the image user *creates*:

1. **Remove (root — `stale_display_cleanup_argv`, `--user 0:0`).** Wipes
   the desktop's `/tmp` state wholesale — `rm -rf /tmp/.X1-lock
   /tmp/.X11-unix /tmp/.config /tmp/.cache /tmp/izba-vnc-fontcache` — and
   prepares the log: create `/var/log/izba-vnc.log` iff absent,
   `chmod 666`. The log **path contract is unchanged**. Every removed path
   is a FINAL component directly under `/tmp`: `rm` never dereferences the
   final component, and `/tmp` (the only intermediate) is not
   workload-replaceable, so root follows no symlink at the target OR on
   the way to it. Two earlier cuts each handed the workload a primitive
   (Greptile P1 ×2): a root `chmod 1777` it could aim by racing a symlink
   swap, then a leaf-path `rm -rf /tmp/.config/<name>` whose INTERMEDIATE
   a planted `/tmp/.config → <target>` would redirect. Wholesale
   final-component removal eliminates both instead of narrowing them; the
   cost is that the desktop's `HOME=/tmp` dot-dirs are ephemeral across
   restarts (izba re-seeds/regenerates everything it puts there), and the
   upgrade path degenerates to the same wipe. Root deliberately runs **no
   `chmod`/`mkdir` under `/tmp` at all**; `/var/log` is root-owned and
   non-sticky in any conventional image, so the workload cannot plant
   anything there.
2. **Create (image user — `desktop_dirs_prep_argv`, no `--user`).**
   `mkdir -p /tmp/.X11-unix /tmp/.config /tmp/.cache` as the container's
   configured user: the desktop owns its ground outright, so no
   world-writable modes exist anywhere. A workload racing a symlink into
   place can at worst redirect its OWN uid's `mkdir -p` — no privilege
   crosses. On a no-`USER` image the configured user is root, recreating
   today's root-owned dirs byte-for-byte.

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
- **docker mode:** docker+VNC is supported (#216, spec 2026-08-12) and the
  same `desktop_exec_argvs` serves it — a docker-mode sandbox's desktop
  likewise runs as the image's configured `USER` (only the bind address
  differs, `LISTEN_ADDR_DOCKER`). Everything the ground-prep exec touches
  stays inside the workload container, so the reasoning above carries over
  unchanged; `vnc_docker_e2e` re-verifies the mode.
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
