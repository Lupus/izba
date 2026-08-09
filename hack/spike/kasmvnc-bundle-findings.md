# Spike findings: self-contained KasmVNC bundle for izba sandboxes (2026-08-09)

**Question:** can izba ship a pre-baked KasmVNC display stack that runs inside
*any* workload container image (glibc, musl, minimal), so "tick VNC in sandbox
config" needs nothing from the user's image?

**Answer: YES — proven end-to-end.** `build-kasmvnc-bundle.sh` +
`test-kasmvnc-bundle.sh` in this directory; screenshots
`kasmvnc-alpine-desktop.png` / `kasmvnc-alpine-interactive.png`.

## What was proven

| Image | Result |
| --- | --- |
| `debian:bookworm-slim` (glibc) | PASS — server + web client + openbox + xterm |
| `alpine:3.22` (musl, no glibc at all) | PASS — plus browser-interactive round-trip (typed `uname -a` in Chromium via the KasmVNC websocket client; output rendered back) |
| `busybox:latest` (minimal musl) | PASS — server + web client + openbox + xterm |

The bundle (KasmVNC 1.5.0 bookworm .deb, sha-pinned + openbox + xterm +
xkb/fonts/fontconfig/themes + full ldd closure + the glibc dynamic loader
itself) is **104 MB unpacked / 42 MB tar.gz** — an erofs will land in that
range. Every ELF is `patchelf`'d to interpreter
`/opt/izba-vnc/lib/ld-linux-x86-64.so.2` + rpath `/opt/izba-vnc/lib`, so
binaries exec directly from the read-only mount with no wrapper scripts and no
loader/libs from the image. staticx was considered and rejected: it targets
single self-extracting executables at unknown paths; we have a multi-binary
suite + big data trees at a path izba controls, where patchelf gives
zero-extraction RO execution.

Processes were started exactly the way izba-init would (`crun exec` analog):
`Xkasmvnc` as one exec, `openbox` and the app as further execs into the same
container, sharing `/tmp/.X11-unix` + IPC ns (MIT-SHM safe — this is why the
server must run *in* the workload container, not init-root).

## Constraints discovered (feed these into the design)

1. **`xkbcomp` path is HARDCODED.** The X server keymap compile shells out to
   `"%s%sxkbcomp"` with compiled-in `/usr/bin` — `XKB_BINDIR` env is ignored
   by this build. Production fix: izba's `generate_spec` authors a read-only
   file bind of the bundle's `xkbcomp` at `/usr/bin/xkbcomp` (same authoring
   site as the USB `/dev/izba` bind). Proven working in the test matrix.
2. **`/bin/sh` in the image is required** — the keymap compile runs via the X
   server's `Popen`. All realistic dev images have it; a shell-less image
   would additionally need a static-sh bind (documented limitation, or ship
   busybox-sh in the bundle and bind it when absent).
3. **KasmVNC phones home for its public IP** (UDP/WebRTC negotiation) unless
   `-publicIP` is set. In izba this egress would hit sandbox policy; always
   pass `-publicIP 127.0.0.1` (done in the test) and consider disabling UDP.
4. **Flags replace the perl wrapper entirely** — no yaml, no perl deps:
   `:1 -geometry WxH -websocketPort N -interface 127.0.0.1 -DisableBasicAuth
   -SecurityTypes None -sslOnly 0 -httpd <www> -fp <fonts> -ac -noreset`.
   For production: replace `-DisableBasicAuth` with a host-generated
   `KasmPasswordFile` (kasmvncpasswd is in the bundle), and note the config
   has per-direction clipboard DLP toggles for the hostile-guest posture.
5. **`libavformat` not bundled** → "ffmpeg: Could not open libavformat.so",
   video (H.264) encoding disabled, falls back to image encodings. Works fine;
   bundle ffmpeg libs later if encoding perf matters.
6. **`/dev/shm` 64 MB oci-spec default** still needs a `generate_spec` bump
   for high resolutions (not exercised by this spike's 1280×800).

## Production mapping (from the research phase, unchanged by the spike)

- Bundle → erofs, appended as the disk AFTER all user volumes, announced via
  `izba.vnc=1` (keeps the positional `izba.volumes` contract intact); or the
  `izba-ssh`-style virtiofs share as fallback.
- `config.vnc` host-authoritative like `config.docker`/`config.usb`;
  restart-required semantics mirror the USB tab.
- Auto-start via init `crun exec` (dockerd precedent, no auto-restart);
  reachability via existing `TcpDial` + `izba port publish` (sshd precedent,
  zero proto changes); app "Display" tab = webview at the relay port.
