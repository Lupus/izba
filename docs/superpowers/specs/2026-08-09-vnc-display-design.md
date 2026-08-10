# VNC display for sandboxes (KasmVNC) — design

**Date:** 2026-08-09
**Status:** approved (PR1 backend scope; PR2 GUI sketched in §9)
**Spike:** `hack/spike/build-kasmvnc-bundle.sh` / `test-kasmvnc-bundle.sh` /
`kasmvnc-bundle-findings.md` (branch `worktree-kasmvnc-spike`) — proved a
patchelf'd self-contained KasmVNC bundle runs from a read-only mount inside
glibc, musl, and busybox containers, with a browser-interactive round-trip.

## 1. Goal & non-goals

**Goal:** a user ticks "VNC" on a sandbox and gets a reliably working,
browser-viewable desktop for the workload container — no packages in the
user's image, no agent-side setup. The human and the sandboxed agent share
the same display (VNC is multi-client), enabling visual collaboration.

**Non-goals (this design):** VMM-level display (Cloud Hypervisor upstream has
declined virtio-gpu/VNC; guest kernel deliberately has no DRM); Wayland;
GPU/H.264 acceleration; shell-less workload images (documented limitation:
the X server's keymap compile runs `xkbcomp` via `/bin/sh`); sound; per-user
multi-session.

**User decisions locked during brainstorming:** two PRs (backend, then GUI);
bundle ships inside installers; per-sandbox generated password; clipboard
bidirectional by default (deliberate convenience-over-caution call — KasmVNC's
per-direction DLP toggles remain available for a later per-session switch).

## 2. Architecture (one paragraph)

izba ships a self-contained KasmVNC bundle as a single read-only erofs
artifact. A sandbox with `config.vnc` boots with that erofs appended as the
disk after all user volumes and `izba.vnc=1` on the cmdline; init mounts it
outside the overlay and the OCI spec binds it into the workload container at
`/opt/izba-vnc`. After the container is running, init auto-starts `Xkasmvnc`
+ `openbox` inside the container (docker-engine precedent). The KasmVNC
websocket/HTTP endpoint binds guest loopback `127.0.0.1:6901`; because the
container shares init's netns, the existing `StreamOpen::TcpDial` plane
reaches it, and the daemon auto-publishes an ephemeral loopback relay on the
host. `izba vnc url` prints a credentialed URL; any browser is the client.

## 3. The artifact: `kasmvnc.erofs`

- `hack/build-kasmvnc-erofs.sh` (graduates the spike script): digest-pinned
  Debian bookworm builder image; sha256-pinned upstream KasmVNC 1.5.0 .deb
  (`770fd3df…`); adds openbox, xterm, xfonts-base, fonts-dejavu-core; copies
  binaries (`Xkasmvnc`, `kasmvncpasswd`, `xkbcomp`, `openbox`, `xterm`), the
  full ldd closure, and glibc's `ld-linux-x86-64.so.2`; patchelf's every ELF
  to interpreter `/opt/izba-vnc/lib/ld-linux-x86-64.so.2` + rpath
  `/opt/izba-vnc/lib`; bundles xkb data, X core fonts, DejaVu, a
  bundle-scoped `fonts.conf` (cache dir `/tmp`), openbox config/theme, and
  the KasmVNC web client; `mkfs.erofs` the tree. Output ~40 MB, one file.
  Self-containment is asserted (interpreter/rpath check per ELF), mirroring
  `build-sshd.sh`'s staticness assertion.
- **Why erofs, not a virtiofs share:** single immutable sha-pinned file;
  permissions/exec bits baked into the image identically on Linux and
  Windows hosts (virtiofs exec-bit semantics from a Windows host are an
  unnecessary risk for a tree of ELF binaries); read-only enforced at the
  block layer.
- **Why patchelf, not staticx:** multi-binary suite + large data trees at a
  mount path izba controls; patchelf gives zero-extraction execution off the
  RO mount. staticx targets single self-extracting executables at unknown
  paths.
- **Distribution:** built in CI, packed into the `.deb` and Windows `.exe`
  next to kernel/initramfs artifacts. `artifacts::locate` gains
  `kasmvnc_erofs` with dev-only env override `IZBA_KASMVNC_EROFS`.
- **Fail closed** (USB kernel-variant precedent, F-class lesson "a rule with
  a test and a call site without one"): `config.vnc` set and artifact
  missing ⇒ `start` fails with an actionable error naming the artifact and
  the installer/`hack` remedy. Never a silent desktop-less boot.

## 4. Guest plumbing

**Disk & cmdline (load-bearing, change all ends or none):**
`build_vm_disks` appends `kasmvnc.erofs` (RO) after the last user volume when
`config.vnc`; cmdline gains `izba.vnc=1`. Init's mapping rule: volumes
consume `vd{c…}` per `izba.volumes` as today; when `izba.vnc=1` the disk
*after* the last volume is the VNC bundle. The positional `izba.volumes`
contract is untouched; max user volumes becomes 23 while VNC is on (26 slots
− vda − vdb − vnc). Both VMM drivers change together: CH `--disk` order and
OpenVMM `disk_port(i)` both follow `build_vm_disks` order already.

**Init mounts:** erofs mounted RO at init-root `/run/izba/vnc` (outside the
`/rootfs` overlay), plus symlink `/opt/izba-vnc → /run/izba/vnc` in init's
root so the patchelf'd binaries are also runnable from init context
(`kasmvncpasswd` fallback, debugging).

**OCI spec additions** (`image/runtime_config.rs`, authored only when
`config.vnc`, dual-authoring discipline like USB's `/dev/izba` + cgroup
rules; re-verify bind interaction with the PR #210 shifted-userns/idmapped
layout during implementation):
- RO bind `/run/izba/vnc` → container `/opt/izba-vnc`.
- RO **file** bind bundle `xkbcomp` → container `/usr/bin/xkbcomp` (spike
  finding: the X server shells out to a hardcoded `/usr/bin/xkbcomp`;
  `XKB_BINDIR` is ignored). Requires image `/bin/sh` (documented limitation).
- `/dev/shm` sized up to 512 MB (oci-spec default 64 MB is too small for
  MIT-SHM at real resolutions).
- RO bind of the secrets dir (§6) for `-KasmPasswordFile`.

## 5. Config, daemon, CLI

- `SandboxConfig.vnc: bool` (`#[serde(default)]`), host-authoritative like
  `docker`/`usb`. Set at `izba create --vnc` or toggled later.
- `DaemonRequest::VncSet { name, enabled }` ⇒ **`DAEMON_PROTO_VERSION` 5→6**
  (new variant; same precedent as v5's `Stats`). CLI: `izba vnc on|off NAME`.
- `start` re-reads config after artifact selection and records the booted
  `vnc` state in `state.json` (exactly the `usb_kernel` pattern);
  `restart_required` is derived from recorded-vs-config disagreement. Any
  change to how `vnc` is chosen must update the recorded fact in the same
  commit.
- **Auto-publish:** on start of a VNC sandbox the daemon creates an ephemeral
  loopback relay (existing `RelayManager`/`TcpDial` plane — zero wire
  changes) to guest `127.0.0.1:6901`, NOT persisted in `ports.json` (it is
  derived state, recreated each start; teardown with the sandbox). Surfaced
  via `Inspect`/status as `vnc: { enabled, running, url, restart_required }`
  (additive `#[serde(default)]` fields).
- `izba vnc url NAME` prints the credentialed URL using HTTP Basic auth
  (user `izba`): `http://izba:<pass>@127.0.0.1:<relay>/`; `izba vnc open
  NAME` launches the platform browser with it. Status probes
  guest 6901 (one dial) for an honest `running/dead`; dead stays dead (no
  auto-restart, dockerd policy).
- **DISPLAY injection:** `izba exec`/ssh sessions get `DISPLAY=:1` in their
  env when the sandbox booted with VNC, so GUI apps land on the desktop.

## 6. Credentials

Per-start generated password (rotating): host generates a random secret,
stores the plaintext at `<sandbox>/vnc.password` (0600, host-only, a SIBLING
of the share dir so it never enters the guest), and delivers only the hash
via a tiny `izba-vnc` virtiofs share mirroring the proven `izba-ssh`
channel; init copies it to init-root `/run/izba/vnc-secrets` (0755 dir /
0644 file — NOT 0600: the container user's uid differs from init's, and
under docker's shifted map init-root presents as `nobody`, so world-read
bits are the delivery mechanism; the file is a crypt hash, not a secret
plaintext) and the container gets a RO bind for `-KasmPasswordFile`.

`.kasmpasswd` hash: generate host-side in Rust if the format is
implementable with available crates (verify format first — kasmvncpasswd
sources say bcrypt-style); otherwise init runs the bundled `kasmvncpasswd`
at boot to hash the shared plaintext. The plaintext never enters the
container either way; the container sees only the hash file. (Windows hosts
cannot exec the Linux `kasmvncpasswd`, so host-side hashing must be pure
Rust or the init-side fallback is used on both platforms — pick ONE path for
both, no platform fork.)

## 7. Init auto-start

At the docker-engine auto-start site (workload container `running`), when
`izba.vnc=1`:
1. `crun exec` `Xkasmvnc :1 -geometry 1280x800 -depth 24 -interface
   127.0.0.1 -websocketPort 6901 -publicIP 127.0.0.1 -KasmPasswordFile
   <bind> -SecurityTypes None -BlacklistThreshold 0 -httpd
   /opt/izba-vnc/share/kasmvnc/www -fp
   /opt/izba-vnc/share/fonts/X11/misc -xkbdir /opt/izba-vnc/share/xkb -ac
   -noreset` (+ `FONTCONFIG_PATH`, `HOME`, XDG dirs into the bundle).
   `-publicIP` pins off the WebRTC public-IP lookup (spike finding: it makes
   a real egress request otherwise). Clipboard: KasmVNC defaults are
   bidirectional-on, matching the locked decision — no flags needed; the DLP
   config path stays available.
   **`-SecurityTypes None` + `-BlacklistThreshold 0` are load-bearing** (both
   were missing in the first cut, which produced a working HTTP surface and a
   desktop that never appeared — endless spinner + credential re-prompt):
   - The X server's default `SecurityTypes=VncAuth` authenticates the RFB
     stream against a *separate* legacy `-rfbauth` DES password file. izba's
     credential is the `kasmpasswd` BasicAuth hash and it writes no rfbauth
     file (upstream's `kasmvncserver` wrapper generates one; izba invokes the
     X server directly), so the websocket upgraded and the RFB handshake then
     dead-ended. Dropping the RFB-level type is not a weakening: HTTP
     BasicAuth in front of the websocket stays the gate, the listener is
     guest-loopback-only behind the daemon relay, and an in-guest process
     already owns the display outright via `-ac`.
   - KasmVNC's brute-force lockout blacklists a source IP after 5
     unauthenticated requests. A browser trips it unaided — basic auth is
     401-then-retry and the client page fetches ~30 subresources in parallel
     — and since every byte reaches the guest from the same loopback address
     (the relay), the counter can only ever lock out the legitimate user. The
     password is a fresh 24-char random string per `start`, so there is
     nothing for a rate limiter to protect.
   Neither is observable through an HTTP GET, which is why §8's probes must
   include a websocket upgrade + RFB handshake, not just status codes.
2. `crun exec openbox` (decorations/focus; Anthropic computer-use precedent).
3. Both logged to `/var/log/izba-vnc.log`; fire-and-forget; a dead VNC
   server stays dead and is reported honestly (§5 probe).

KasmVNC's dynamic resize stays enabled (client-driven), so the browser
window size wins over the initial `-geometry`.

## 8. Testing

TDD throughout; every rule gets its test AND its call site gets one (the
USB campaign's recurring defect class).

**Host-testable units (mock level, no KVM):** artifact locate + fail-closed
refusal; disk append order incl. volumes+vnc interaction and the 23-volume
cap; cmdline authoring; OCI spec binds + `/dev/shm` override (+ absence for
non-VNC sandboxes — byte-equal spec guard like `output_chain`); init disk
mapping; password generation (per-start rotation, hash-format round-trip); relay
allocation/teardown; `VncSet` handler + proto bump; `restart_required`
derivation; DISPLAY injection.

**KVM e2e (`daemon_e2e`, env-gated as usual):**
- create `--vnc` → start → relay URL surfaces in inspect; HTTP GET without
  creds = 401; with creds = 200 + KasmVNC content markers; guest 6901
  reachable only for VNC sandboxes.
- `izba vnc on` against a running non-VNC sandbox ⇒ `restart_required`
  surfaces; restart lands the desktop.
- artifact missing ⇒ start fails with the actionable message.
- Artifact provisioning follows the **production discovery path** (no
  test-only env handoff — the exact IZBA_KERNEL_USB mistake); CI builds the
  erofs via the pinned script with an actions/cache keyed on the script
  hash.
- Windows WHP validation (`hack/spike/validate-izba-windows.ps1` flow) gains
  a VNC boot + credentialed relay-GET check, since the disk plumbing
  touches the OpenVMM driver.

**Gates:** the standard six + app gate untouched in PR1; mutation gate
covers new izba-core code; dogfood journey lands with PR2.

## 9. PR2 sketch (GUI — separate spec-lite/PR)

"Display" tab in `Detail.tsx` next to Shell: webview/iframe at the
credentialed relay URL; restart-required banner mirroring the USB tab;
`--vnc` toggle in the create dialog; `vnc` fields ride the existing inspect
payload; GUI dogfood journey. No daemon changes beyond PR1's.

## 10. Security posture

- Bundle: izba-owned, sha-pinned, RO at block layer; guest tampering is
  in-memory only (same trust domain as the workload).
- Creds: 0600 host-side, rotated per start, plaintext never in the
  container, URL credentials surfaced only to the local user.
- Relay binds `127.0.0.1` (default bind rules unchanged); everything served
  through it (pixels, web client) is untrusted guest output.
- Clipboard bidirectional-on is a **documented accepted risk** (user
  decision): a hostile guest can write the host clipboard while a VNC tab is
  connected. Revisit as a per-session toggle in PR2.
- No egress-policy interaction: the VNC plane is host-initiated inbound over
  vsock; the only outbound temptation (public-IP lookup) is pinned off and
  asserted in e2e via netlog absence if cheap.
- Manifest (`izba.yml`) does NOT get a `vnc:` field in PR1 — enabling a
  desktop stays a human action (CLI/GUI), not an agent-writable proposal;
  revisit with the promote flow if demand appears.

## 11. Risks & mitigations

| Risk | Mitigation |
| --- | --- |
| PR #210 (shifted userns / idmapped layers) moved the ground under `runtime_config.rs` | rebase first; re-verify bind uid/gid mapping + RO binds against the new layout before authoring spec changes |
| `.kasmpasswd` format not reproducible in Rust | init-side `kasmvncpasswd` fallback (one path, both platforms) |
| erofs build flakiness in CI (network fetch of .deb) | sha-pinned fetch + actions/cache; same posture as sshd/nft builds |
| KasmVNC upgrade churn | version + sha pinned in one place in the build script; bump = new erofs, no code change expected |
| Windows WHP disk-append regressions | WHP validation check in e2e.yml (§8) |
