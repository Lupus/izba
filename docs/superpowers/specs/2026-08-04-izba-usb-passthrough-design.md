# USB passthrough for izba sandboxes (usbip) — design

Status: approved 2026-08-04.
Scope: M-next feature. Touches the egress hard floor, the guest kernel artifact
set, izbad, izba-init, the CLI, and the desktop app.

## 1. Problem

An agent working on embedded firmware needs a physical device — the motivating
case is an ESP32 devkit that must be flashed and then talked to over a serial
line. izba sandboxes are NIC-less microVMs with no USB controller at all
(`hack/kernel.config:209`, "No USB controller is exposed to the guest"), so
today this workflow is impossible inside izba.

The prior art the user wants parity with is `usbipd-win`, whose `--wsl` flow
makes a Windows-host USB device appear inside a WSL2 distro. Mechanically that
flow is nothing more than the standard USB/IP protocol over TCP 3240 plus a
`vhci-hcd` attach on the Linux side, so izba can reach the same outcome without
depending on usbipd-win's tooling.

What izba must add on top of that prior art is **control**. usbipd exposes every
bound device to every client that can reach port 3240, with no authentication,
no authorization, and no encryption. izba's guest is hostile by assumption (A1),
so "the sandbox can see the USB server" must not mean "the agent can attach
whatever it likes". The human decides, per device, per sandbox.

## 2. Constraints

1. **Guest is hostile (A1).** Any byte the guest sends izbad is attacker-chosen.
2. **Disabled USB must add zero attack surface to izbad.** Not "a flag that is
   checked" — no listener, no thread, no parser, no config read.
3. **Cloud Hypervisor has no USB controller**, and neither does OpenVMM. A
   virtual-USB-controller design is not available on either driver; the device
   must arrive over a network protocol. This is why the threat surface here is a
   protocol parser rather than a device model.
4. **The guest has no udev and no module loading** (`=y`-only kernel).
5. **CLI must not wrap `usbipd-win` automagically.** Binding a device on the
   Windows host needs Administrator; izba prints the command, the human runs it.
6. **Must be thoroughly testable in CI without USB hardware.**

## 3. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **izbad owns the USB/IP op phase.** The guest sends one JSON frame carrying a *label*; izbad resolves it, dials the upstream from host-only config, and performs DEVLIST/IMPORT itself. | Zero guest-supplied usbip parsing on the host; the guest cannot enumerate the human's hardware; mirrors the M2 MITM's re-origination precedent (F-02). |
| D2 | **Dedicated vsock port 1028**, bound per-sandbox only when that sandbox holds ≥1 device grant. | Makes "disabled ⇒ no surface" structural: with no listener the VMM fails `CONNECT 1028` before any izba code runs. Needs no VMM change on either driver. |
| D3 | **`vhci-hcd` receives the vsock fd directly.** No loopback-TCP shim. | `attach_store()` validates only `socket->type != SOCK_STREAM`; there is no address-family check in the driver, and its data path is family-agnostic. Prior art: Spectrum OS runs usbip over vsock on a stock kernel. |
| D4 | **Separate `vmlinux-usb` kernel artifact**, booted only by USB-enabled sandboxes. | A universal USB kernel would give every sandbox `vhci-hcd`, which any root-in-guest process can drive with a self-made socketpair (the syzkaller external-USB bug class), and would make the §4.1 egress bypass exploitable everywhere instead of structurally impossible. |
| D5 | **Serial-class drivers only in v1**: CDC-ACM + cp210x/ch341/ftdi_sio/pl2303. No mass storage, no HID, no video/audio. | Covers the motivating case exactly. An allowlisted-but-unexpected device class finds no driver, which narrows the "USB is an exfil channel the egress firewall cannot see" residual from arbitrary storage to a serial line. |
| D6 | **Asymmetric URB validation**: parse and bound-check guest→upstream frames; splice upstream→guest opaquely. | The guest→upstream direction terminates in a privileged host service (cf. QEMU usbredir CVE-2021-3682, host code execution from a malicious redirection client) so it earns a parser. The other direction's victim is a guest kernel already assumed hostile, so parsing buys nothing. `CMD_*` frames are self-describing, so this parser is stateless; validating `RET_SUBMIT` would need seqnum→direction state because the server zeroes those fields. |
| D7 | **Grants are standing, not one-shot.** | A granted device survives replug and re-attach without a fresh human click. Revocation tears down live streams. |
| D8 | **No `spec.usb` in `izba.yml`.** | Hardware consent is machine-specific and cannot be portable; an agent-writable repo file is the wrong shape for it. Removes a class of promote-gate risk rather than mitigating it. |
| D9 | **Identity is `vid:pid`, resolved to a busid at attach time**, with an optional `busid_pin` to disambiguate identical devices. | Survives replug into another port. Ambiguity is an error, never a guess. |

## 4. Architecture

```
ESP32 ──USB──▶ Windows/Linux host
                 usbipd (TCP 3240)         ← human runs `usbipd bind` once (admin)
                        ▲
                        │ izbad dials, from HOST-ONLY config
                        │ op phase: OP_REQ_DEVLIST → identity match
                        │           OP_REQ_IMPORT  → re-verify record
                 ┌──────┴───────┐
                 │    izbad     │  ← per-device allowlist enforced HERE
                 │  UsbBroker   │  ← D6 validation on the guest→upstream leg
                 └──────▲───────┘
                        │ vsock 1028 — bound only for granted sandboxes
                        │ guest sends ONE frame: StreamOpen::UsbAttach{label}
                        │ izbad replies Response::UsbAttached{devid,speed,...}
                 ┌──────┴───────┐
                 │  izba-init   │ → write "port fd devid speed" to
                 │  (guest PID1)│   /sys/devices/platform/vhci_hcd.0/attach
                 └──────────────┘ → /dev/ttyACM0 → bridged into the container
```

Attach is **host-initiated**: the human clicks (GUI) or runs `izba usb attach`
(CLI), izbad sends `Request::UsbAttach{label}` to init over the existing control
RPC (vsock 1025), and init performs the dial. The guest never chooses the device
and never learns the upstream address. The vsock-1028 label check remains as
defence in depth for a guest that dials the port on its own.

### 4.1 The egress bypass (must ship regardless of USB)

The guest's nft ruleset redirects all non-53 TCP into the egress plane
(`crates/izba-init/src/egress.rs:322`), so an in-guest `usbip attach -r <ip>` is
mechanically ordinary izba egress. izbad's non-overridable SSRF floor covers
loopback / link-local / metadata but **deliberately not RFC1918**
(`crates/izba-core/src/daemon/egress/router.rs:99`), and a bare non-enforcing
sandbox is permissive for LAN by design (`router.rs:283`, `is_lan` at `:379`).
In WSL2 NAT mode the Windows host *is* an RFC1918 gateway, and usbipd-win's
installer opens 3240 to all local subnets.

Today this is inert: the guest kernel has no USB support, so an imported device
has no `vhci` to attach to. D4 keeps that true for sandboxes without USB. But it
must not be the only defence, and it does not help an enforcing sandbox whose
policy legitimately allows an IP that happens to run usbipd.

**Rule (approved).** The configured upstream endpoint's resolved addresses, and
TCP port 3240 generally, are denied **non-overridably** — no policy rule can
authorise them — for:

* every **enforcing** sandbox, unconditionally; and
* every **USB-enabled** sandbox (≥1 grant), enforcing or bare — otherwise the
  grant model is bypassable from inside.

A **bare, non-USB** sandbox keeps today's behaviour: LAN remains reachable,
which is the intended workflow for a user who declined a firewall, and is inert
because that sandbox boots a kernel with no `vhci-hcd`.

The deny is by **port and by address**, because a single usbipd is multi-homed
(loopback, WSL gateway, LAN IP, IPv6, IPv4-mapped and NAT64-embedded forms —
`router.rs:323` already canonicalises the latter).

### 4.2 Why the guest cannot smuggle a second import

The USB/IP op phase is strictly **one operation per TCP connection**: after a
successful `OP_REP_IMPORT` the connection is URB-only forever, with no
renegotiation path. Importing another device requires a new connection, which
passes the allowlist gate again. This is what makes splice-after-import sound,
and it is verified in the kernel protocol documentation and in both mainstream
server implementations.

## 5. Components

### 5.1 `crates/izba-proto/src/usbip/` (new) — the wire codec

Pure, no I/O, `&[u8] -> Result<_>` shaped so it is directly fuzzable.

* `op.rs` — `op_common` (8 B: version `0x0111`, code, status), `OP_REQ_DEVLIST`
  / `OP_REP_DEVLIST` (u32 count + 312-byte device records + 4 B per interface),
  `OP_REQ_IMPORT` (header + `busid[32]`), `OP_REP_IMPORT`. All fields
  **big-endian** — deliberately unlike izba's own u32-LE frames.
* `urb.rs` — the 48-byte basic/submit/unlink headers, decode + bounds only.
* Caps applied **before** any allocation: device count ≤ 256, total devlist
  reply ≤ 256 KiB, `busid`/`path` force-terminated and charset-checked,
  `transfer_buffer_length` ≤ 1 MiB (configurable), `number_of_packets` ≤ 1024,
  checked arithmetic on every `count × stride`.

### 5.2 `crates/izba-core/src/daemon/usb/` (new) — the broker

* `mod.rs` — `UsbBroker`, held as `Option<Arc<UsbBroker>>` in `DaemonDeps`
  (mirrors the MITM runtime seam); `ensure_listening(sandbox, run_dir)` binds
  `<run dir>/vsock.sock_1028` only when the sandbox holds ≥1 grant.
* `settings.rs` — `<data>/usb/settings.json` (0600): `upstream {host, port}`,
  `allow_remote_upstream`, `urb_sanity`. Corrupt/missing ⇒ safe defaults, never
  a permissive fallback (mirrors `ssh::settings::load`, inverted default).
* `trust.rs` — `UpstreamTrust` classifier (§6.2).
* `session.rs` — accept → read exactly one `StreamOpen::UsbAttach{label}` under
  a 4 KiB per-plane cap and a 5 s deadline → grant lookup → upstream dial →
  DEVLIST → identity match → IMPORT → re-verify the returned record → reply →
  splice with D6 validation on the guest→upstream leg.
* `inventory.rs` — host-side device listing: `OP_REQ_DEVLIST` against the
  upstream, optionally enriched by `usbipd.exe state` JSON over WSL interop
  (read-only verb, fixed path, timeout, capped parse, **never reachable from a
  guest RPC**).

### 5.3 `crates/izba-init/src/usb.rs` (new) — the guest client

~200 lines, no dependencies, host-testable behind a dialer seam (the
`egress.rs` pattern): dial `VMADDR_CID_HOST:1028`, write the `UsbAttach` frame,
**read the reply byte-by-byte** (a buffered read would swallow URB bytes — the
same hazard the hybrid-vsock `CONNECT` handshake already documents), parse
`/sys/devices/platform/vhci_hcd.0/status` for a free port matching the device
speed, then write `"<port> <fd> <devid> <speed>"` to `.../attach`. Detach writes
the port number to `.../detach`. Guarded by a host-authoritative `izba.usb=1`
cmdline flag: without it, init refuses every USB RPC.

### 5.4 Device visibility inside the container

The workload runs under crun with its own mount + user namespaces and a fresh
tmpfs `/dev` from the OCI default spec (`image/runtime_config.rs:608`,
namespaces at `:630`), so a node created in the guest's devtmpfs after container
start is **not** visible to the workload, and an unprivileged userns cannot
`mknod` a device for itself.

Approach: for a USB-enabled sandbox, create an empty directory before container
launch, bind it into the container at `/dev/izba` in the generated spec,
pre-authorise the serial char majors in `linux.resources.devices`, and have init
`mknod` into that shared directory after a successful attach, plus a
`/dev/ttyACM0` symlink for tool compatibility. **This area gets a spike first**
(cgroup-v2 device eBPF behaviour and userns node ownership); it is the highest
residual uncertainty in the feature.

### 5.5 Kernel artifact

New `hack/kernel-usb.config` fragment (base config + `CONFIG_USB_SUPPORT`,
`CONFIG_USB`, `CONFIG_USBIP_CORE`, `CONFIG_USBIP_VHCI_HCD`, `CONFIG_USB_ACM`,
`CONFIG_USB_SERIAL` + the four converters) producing `dist/vmlinux-usb`.
`artifacts.rs` gains a variant-aware `locate`; a USB-enabled sandbox whose
installation lacks the USB kernel fails to start with an actionable error —
never a silent boot on the non-USB kernel. The default `vmlinux` keeps its
current posture, and its "no USB support" property becomes a test.

### 5.6 Control plane

New `DaemonRequest` variants (`UsbUpstreamGet/Set`, `UsbListDevices`,
`UsbGrant`, `UsbRevoke`, `UsbAttach`, `UsbDetach`, `UsbStatus`) and a new guest
`Request::UsbAttach`/`UsbDetach` nested inside `GuestRpc`. Both are wire-breaking
for a stale daemon, so **`DAEMON_PROTO_VERSION` 2 → 3**, one bump covering all
of it. Every handler returns "usb passthrough is not configured" **before**
touching any address or label field when the feature is off. The out-of-workspace
Tauri app gate must be run on the same change.

### 5.7 Config surfaces

Daemon level, `<data>/usb/settings.json` — upstream + global toggles.
Per sandbox, `SandboxConfig.usb` (`#[serde(default)]`) —
`devices: [{label, vid, pid, busid_pin?, description, granted_at}]`. Managed
truth: host-only, never in the overlay, never in a virtiofs share, removed by
`izba rm` so a reused sandbox name cannot inherit hardware. Grants are created
**only** by an explicit host-side CLI/GUI action.

## 6. Human-facing behaviour

### 6.1 Consent

`izba usb allow <sandbox> --device 0403:6001` prints a loud banner and requires
the device id to be typed back. The banner states plainly that the agent gets
raw transfer-level access, can reflash or permanently damage the device, that
USB traffic is **not** visible to the egress firewall, that the device becomes
unavailable to the host and other sandboxes while attached, and that izba can
only verify what the usbip server reports — not that this is the physical object
in front of you. No wildcards, no class grants, no `--all`.

When a device is plugged in but not shared, izba prints the exact
`usbipd bind --busid 3-2` command for the human to run elevated. izba never
elevates and never wraps usbipd-win.

### 6.2 Upstream trust classification

Warning on "not 127.0.0.1" would be wrong on izba's primary platform, since in
WSL2 NAT mode the Windows host is an RFC1918 gateway.

| Class | Test | Behaviour |
|---|---|---|
| `OwnHostLoopback` | `127.0.0.0/8`, `::1` | No warning (recommended configuration). |
| `OwnHostWslGateway` | address == default-route gateway **and** izbad is running under WSL | Informational: "your Windows host across the WSL boundary", plus the caveat that any other WSL distro on this machine can attach the same devices. |
| `PrivateLan` | RFC1918 / ULA, not the above | Loud warning: no authentication, no encryption, anyone who can route there can attach the same devices and can read or modify the traffic. |
| `Public` | global unicast | **Refused** unless `allow_remote_upstream` is explicitly set; still warns on every attach. |

Host identity comes from `/proc/net/route`, never from `resolv.conf` — with DNS
tunnelling enabled the nameserver is `10.255.255.254`, not the host. The
resolved address is pinned at configuration time and a change is re-warned.

### 6.3 Surfaces

CLI: `izba usb upstream set|show`, `list`, `allow`, `revoke`, `attach`,
`detach`, `status`. GUI: a USB panel listing upstream devices with state
(plugged in / shared / attached elsewhere), one-click expose behind the same
consent dialog, and a copy-the-command affordance for devices that still need
`usbipd bind`.

Adding the **first** grant to a running sandbox is a restart-class change (the
kernel artifact changes); subsequent grants are live. This is surfaced honestly,
mirroring the manifest's existing Live/Restart/Image field classes.

## 7. Error handling (fail-closed, never silent)

Any parse error, cap breach, timeout, unknown label, identity mismatch after
import, ambiguous `vid:pid`, or upstream refusal ⇒ audit a Deny, close both legs
with full `SHUT_RDWR`, and surface an actionable message. Upstream death or
revocation closes the guest leg, which `vhci` reports as a device unplug. No
auto-reattach: death produces an honest state, mirroring the existing
"VMs are never auto-restarted" invariant. Attach attempts, verdicts, and
detaches are audited through the existing structured log with a new `Tier::Usb`,
so `izba netlog` and the app surface them.

## 8. Testing (TDD)

| Layer | Coverage |
|---|---|
| Unit (no sockets) | codec round-trips, cap enforcement, grant lookup, identity match, trust classifier, `UpstreamTrust` boundary cases, devlist filtering. |
| In-process | full op-phase exchange against `jiegec/usbip`'s `handler()` over `tokio::io::duplex` — a real emulated usbip server with **no listener bound**, satisfying the sandbox no-bind constraint. Dev-dependency only (its mandatory `rusb` dep links libusb and must not enter the shipped tree). |
| KVM e2e | `fake_usbipd` example binary on `127.0.0.1:0` serving a CDC-ACM handler that **echoes bulk-OUT back on bulk-IN**; the assertion is behavioural — write to `/dev/ttyACM0` in the guest, read the echo back — proving URBs flow guest vhci → vsock → izbad → TCP → server and back. |
| Negative e2e | non-granted device invisible and un-importable; upstream death ⇒ honest detach; revoke tears down a live stream. |
| Abuse cases | no listener bound when USB is off; `UsbAttach` on port 1027 ⇒ `BadRequest`; `TcpConnect{port:3240}` denied for an enforcing sandbox and for a USB-enabled bare sandbox; the default `vmlinux` has no USB support. |
| Fuzz | `usbip_op` target alongside the existing `frame`/`dns` targets in the 45 s smoke job. |

**Honest limits, to be stated in the docs:** real usbipd-win interop cannot run
in CI (it has no hardware-free mode and the runners expose no shareable
devices) — it is covered by protocol conformance plus a new section in
`hack/spike/validate-izba-windows.ps1`. Isochronous transfers and real-silicon
quirks are manual-only.

## 9. Scope boundaries (YAGNI / deferred)

Not in v1: non-serial device classes (D5); `spec.usb` in the manifest (D8);
auto-reattach on replug; a `GET_DESCRIPTOR` serial probe to strengthen device
identity (v1.1 hardening, gated behind an explicit `serial:` entry); URB-level
function filtering (e.g. "serial yes, DFU no") — granularity is the whole
device, by design; sftp-style multi-device orchestration.

## 10. New findings (for the register)

* **F-USB-1 (HIGH)** — guest bypasses the allowlist by reaching the usbip
  upstream over the generic egress plane. Live gap today, inert only because no
  guest kernel has `vhci`. Fix per §4.1.
* **F-USB-2 (HIGH)** — passthrough gives a hostile guest a byte channel into a
  privileged host service. Mitigated by D1 + D6 + stream caps; residual accepted
  and documented.
* **F-USB-3 (MEDIUM)** — device identity is upstream-asserted; the wire format
  carries **no serial number**, `vid:pid` is device-programmable, and busid can
  be recycled across a replug. Mitigated by attach-time busid resolution and
  post-import re-verification. The allowlist is a human-intent filter, not proof
  of provenance — stated verbatim in the consent banner and the docs.
* **F-USB-4 (MEDIUM, HIGH for public)** — unauthenticated, unencrypted upstream.
  Mitigated by §6.2.
* **F-USB-5 (MEDIUM, accepted)** — a hostile or MITM'd upstream attacks the
  guest USB stack (cf. CVE-2016-3955, remote OOB write from a crafted USB/IP
  length field; the syzkaller external-USB bug class). Guest compromise is not a
  sandbox escape under A1, but it costs `/workspace` confidentiality and hands a
  third party a stronger virtio-escape position — which is why the LAN warning
  names *who* is being trusted.
* **F-USB-6 (MEDIUM)** — resolved by D4: a USB-capable kernel is not shipped to
  sandboxes that did not ask for one.
* **F-USB-7 (MEDIUM, by design)** — physical blast radius of a grant: reflash,
  brick, BadUSB persistence, and an exfil channel the egress firewall cannot
  see. Narrowed by D5, gated by per-device human consent.
* **F-USB-8 (MEDIUM)** — unbounded parsing/concurrency on the new plane.
  Mitigated by §5.1 caps, per-plane frame cap, deadlines, and per-sandbox +
  global stream caps.
* **F-USB-9 (LOW)** — device-inventory disclosure. Resolved by D1: the guest
  never sees a device list.

Threat-model deltas: a new boundary row **B-USB**, a new accepted risk in §8,
and three invariants — a USB-disabled sandbox has no listener, no USB-capable
kernel and no reachable USB code path; the guest never supplies the upstream
address; no enforcing or USB-enabled sandbox may reach a usbip upstream over the
generic egress plane.
