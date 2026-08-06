# USB passthrough phase 3 — the datapath

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A granted USB serial device physically reaches the agent inside the
sandbox: `esptool --port /dev/izba/ttyACM0 flash` works, and nothing that was
not granted is reachable.

**Architecture:** izbad gains a per-sandbox vsock-1028 listener (`usb::broker`)
bound **only** when the sandbox holds ≥1 grant. The human runs `izba usb attach`;
izbad forwards `Request::UsbAttach{device}` to izba-init over the existing
control RPC (1025); init dials CID 2:1028, sends one
`StreamOpen::UsbAttach{device}` frame, and gets back the resolved
`devid`/`speed`. izbad — never the guest — speaks USB/IP: it resolves the
`vid:pid` to a busid via `OP_REQ_DEVLIST`, imports by busid on a second
connection, re-verifies the returned record against the grant, then splices,
validating every guest→upstream URB header. Init hands the raw vsock fd to
`vhci-hcd` via sysfs, then mirrors the resulting devtmpfs node into a directory
bind-mounted into the container at `/dev/izba`.

**Tech Stack:** Rust (std threads, no async on the USB path), `vsock` 0.5 crate
guest-side, Linux `vhci_hcd` sysfs interface, crun/OCI runtime spec
(`linux.resources.devices` + a bind mount), the phase-1 `izba_proto::usbip`
codec.

## Global Constraints

- **Disabled USB must add no attack surface.** With no grants: no 1028
  listener is bound, `izba.usb=1` is absent from the cmdline, init refuses every
  USB RPC, and the non-USB `vmlinux` is booted. Each of these is a test.
- **The guest never speaks USB/IP and never learns the upstream address.** It
  sends a device label; izbad does the op phase (D1, F-USB-9).
- **One USB/IP operation per TCP connection.** `OP_REQ_DEVLIST` and
  `OP_REQ_IMPORT` therefore need **two separate dials**. This is what makes
  gate-then-splice sound.
- **Guest→upstream URBs are validated; upstream→guest is opaque** (D6, already
  reasoned in `izba_proto::usbip::urb`'s module doc). Never add a stateful
  parser to the upstream→guest leg.
- **`DAEMON_PROTO_VERSION` 3 → 4**, one bump for the whole phase.
- **Serial-class only in v1**: char majors 166 (`ttyACM`) and 188 (`ttyUSB`).
  The device-cgroup allowlist makes that structural, not advisory.
- **No listener may be bound by a unit test** (house rule). Broker session
  tests use `UnixStream::pair()`; anything needing a real bind runtime-skips on
  `PermissionDenied`.
- **The heavy `usbip`/`rusb` dependency never enters the shipped tree or any
  workspace gate.** It lives in `hack/fake-usbipd`, excluded from the workspace.
- Six workspace gates + the out-of-workspace `app/src-tauri` gate must be green
  before every commit. `app/src-tauri` embeds izba-core by path and is **not**
  compiled by `cargo test --workspace`.
- Conventional commits; tests first.

---

## File structure

**New:**

| File | Responsibility |
| --- | --- |
| `crates/izba-core/src/usb/broker/mod.rs` | `UsbBroker`: per-sandbox 1028 listener lifecycle (`refresh`/`stop`/`listening`). Binds only for a granted sandbox. |
| `crates/izba-core/src/usb/broker/session.rs` | One connection: read the label, resolve+import against the upstream, reply, splice with URB validation. Pure over `Read + Write`. |
| `crates/izba-init/src/usb.rs` | Guest client: dial 1028, exchange frames, parse vhci `status`, write `attach`/`detach`, mirror the device node. |
| `hack/kernel-usb.config` | Kernel fragment re-enabling USB + `vhci-hcd` + the serial drivers. |
| `hack/fake-usbipd/` | Excluded crate: a real CDC-ACM USB/IP server (echoes bulk-OUT on bulk-IN) for the KVM e2e. |
| `crates/izba-cli/tests/usb_attach_e2e.rs` | KVM e2e: attach → write → read the echo; plus the negative and abuse cases. |

**Modified:** `izba-proto/src/messages.rs` (wire), `izba-core/src/daemon/proto.rs`
(v4 + two RPCs), `daemon/server.rs` (broker wiring + two handlers),
`daemon/supervisor.rs` (teardown), `daemon/egress/audit.rs` (`Tier::Usb`),
`izba-core/src/artifacts.rs` (kernel variant), `izba-core/src/sandbox.rs`
(cmdline + variant), `izba-core/src/image/runtime_config.rs` (bind mount +
device cgroup), `izba-init/src/{main.rs,server.rs,oci.rs}`,
`izba-cli/src/commands/usb.rs` (attach/detach), `hack/build-kernel.sh`,
`.github/workflows/{e2e.yml,_artifacts.yml}`.

---

## Task 1: The wire

**Files:**
- Modify: `crates/izba-proto/src/messages.rs`
- Modify: `crates/izba-core/src/daemon/proto.rs`

**Interfaces:**
- Produces: `izba_proto::USB_PORT: u32 = 1028`;
  `StreamOpen::UsbAttach { device: String }`;
  `Request::UsbAttach { device: String }`, `Request::UsbDetach { device: String }`;
  `Response::UsbAttached { devid: u32, speed: u32 }`;
  `ErrorKind::UsbUnavailable`; `DaemonRequest::UsbAttach { name, device }`,
  `DaemonRequest::UsbDetach { name, device }`; `DAEMON_PROTO_VERSION == 4`.

The device travels as a `String` (not a parsed `DeviceId`) so a malformed label
is a clean application-level error rather than a frame-read failure — the same
choice phase 2 made for the control plane.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-proto/src/messages.rs` tests, extend `stream_open_roundtrip_and_stable_tags`'s
arrays with `StreamOpen::UsbAttach { device: "0403:6001".into() }` /
`r#""type":"usb_attach""#`, extend `request_roundtrip`'s array with both new
`Request` variants, and add:

```rust
    #[test]
    fn usb_port_is_1028_and_distinct_from_the_other_planes() {
        assert_eq!(USB_PORT, 1028);
        for other in [CONTROL_PORT, STREAM_PORT, EGRESS_PORT] {
            assert_ne!(USB_PORT, other, "the USB plane needs its own port");
        }
    }

    #[test]
    fn usb_wire_tags_are_stable() {
        for (json, tag) in [
            (
                serde_json::to_string(&Request::UsbAttach { device: "0403:6001".into() }).unwrap(),
                "usb_attach",
            ),
            (
                serde_json::to_string(&Request::UsbDetach { device: "0403:6001".into() }).unwrap(),
                "usb_detach",
            ),
            (
                serde_json::to_string(&Response::UsbAttached { devid: 196_610, speed: 3 }).unwrap(),
                "usb_attached",
            ),
            (
                serde_json::to_string(&Response::Error {
                    kind: ErrorKind::UsbUnavailable,
                    message: "m".into(),
                })
                .unwrap(),
                "usb_unavailable",
            ),
        ] {
            assert!(json.contains(tag), "{json}");
        }
    }
```

In `crates/izba-core/src/daemon/proto.rs` tests, update the version pin to 4 and add:

```rust
    #[test]
    fn usb_attach_requests_roundtrip() {
        for req in [
            DaemonRequest::UsbAttach { name: "web".into(), device: "0403:6001".into() },
            DaemonRequest::UsbDetach { name: "web".into(), device: "0403:6001".into() },
        ] {
            let s = serde_json::to_string(&req).unwrap();
            let back: DaemonRequest = serde_json::from_str(&s).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }
```

- [ ] **Step 2: Run them and watch them fail**

`cargo test -p izba-proto -p izba-core --lib usb` — expected: does not compile
(`USB_PORT` / variants undefined).

- [ ] **Step 3: Add the variants**

`messages.rs`:

```rust
/// Guest-dialed host port for the USB attach plane; the VMM bridges it to the
/// `run/vsock.sock_1028` unix listener izbad binds **only** for a sandbox that
/// holds at least one device grant.
pub const USB_PORT: u32 = 1028;
```

On `StreamOpen`:

```rust
    /// Guest USB attach (vsock 1028, guest-initiated): the guest names a
    /// granted device (`vid:pid`) and nothing else — never an address, never a
    /// busid. izbad resolves it against the sandbox's grants, performs the
    /// whole USB/IP op phase itself, and replies one `Response` frame
    /// (`UsbAttached{devid, speed}` | `Error`). On `UsbAttached` the connection
    /// becomes the raw USB/IP URB stream the guest hands to `vhci-hcd`.
    UsbAttach { device: String },
```

On `Request` (control plane, host→guest — attach is host-initiated):

```rust
    /// Attach a granted device inside the guest: init dials the USB plane and
    /// hands the resulting fd to `vhci-hcd`. Refused with
    /// `ErrorKind::UsbUnavailable` unless the guest booted with `izba.usb=1`.
    UsbAttach { device: String },
    /// Detach a device this guest previously attached.
    UsbDetach { device: String },
```

On `Response`: `UsbAttached { devid: u32, speed: u32 },`
On `ErrorKind`:

```rust
    /// USB passthrough is not available in this guest — it did not boot with a
    /// USB-capable kernel. Distinct from `BadRequest` because the fix is a
    /// restart, not a corrected call.
    UsbUnavailable,
```

`daemon/proto.rs`: bump the constant to 4, update its doc comment to say v4
covers the guest-facing attach/detach RPCs, and add the two request variants
next to the existing six `Usb*` ones.

- [ ] **Step 4: Run the tests — expect PASS**

`cargo test -p izba-proto -p izba-core`

- [ ] **Step 5: Commit**

```bash
git add crates/izba-proto/src/messages.rs crates/izba-core/src/daemon/proto.rs
git commit -m "feat(proto): the USB attach plane and its guest RPCs"
```

---

## Task 2: The broker session (pure, no listener)

**Files:**
- Create: `crates/izba-core/src/usb/broker/session.rs`
- Create: `crates/izba-core/src/usb/broker/mod.rs` (stub declaring `session` for now)
- Modify: `crates/izba-core/src/usb/mod.rs` (`pub mod broker;`)
- Modify: `crates/izba-core/src/usb/inventory.rs` (add `read_import_reply`)

**Interfaces:**
- Consumes: `izba_proto::usbip::{encode_op_req_devlist, encode_op_req_import, decode_op_rep_import, UsbDeviceRecord, OP_COMMON_LEN, DEVICE_RECORD_LEN}`; `usb::inventory::{read_devlist_reply, UpstreamDevice}`; `usb::grants::{UsbConfig, UsbGrant, find}`; `usb::ids::DeviceId`.
- Produces:
  ```rust
  pub struct Attached { pub devid: u32, pub speed: u32, pub busid: String }
  pub fn resolve(devices: &[UpstreamDevice], grant: &UsbGrant) -> anyhow::Result<UpstreamDevice>
  pub fn import<U: Read + Write>(up: &mut U, chosen: &UpstreamDevice, grant: &UsbGrant) -> anyhow::Result<Attached>
  pub fn pump_guest_to_upstream<R: Read, W: Write>(r: R, w: W) -> anyhow::Result<()>
  pub fn devid(busnum: u32, devnum: u32) -> u32
  ```

**Why two dials:** the USB/IP op phase is one operation per connection, so
`resolve` runs on a devlist connection that is then closed, and `import` runs on
a fresh one that becomes the URB stream.

- [ ] **Step 1: Write the failing tests**

Create `crates/izba-core/src/usb/broker/session.rs` with only its `mod tests`
plus `use` lines, containing:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::grants::UsbGrant;
    use crate::usb::inventory::UpstreamDevice;

    fn dev(busid: &str, vid: u16, pid: u16) -> UpstreamDevice {
        UpstreamDevice {
            busid: busid.into(),
            id: crate::usb::DeviceId { vid, pid },
            description: "/sys/devices/x".into(),
            speed: 3,
        }
    }

    fn grant(vid: u16, pid: u16, pin: Option<&str>) -> UsbGrant {
        UsbGrant {
            device: crate::usb::DeviceId { vid, pid },
            busid_pin: pin.map(str::to_string),
            description: String::new(),
            granted_at_unix_ms: 0,
        }
    }

    #[test]
    fn resolve_picks_the_granted_device() {
        let devices = [dev("1-1", 0x1a86, 0x7523), dev("3-2", 0x0403, 0x6001)];
        let got = resolve(&devices, &grant(0x0403, 0x6001, None)).unwrap();
        assert_eq!(got.busid, "3-2");
    }

    #[test]
    fn a_device_the_upstream_does_not_export_is_a_named_refusal() {
        let err = format!(
            "{:#}",
            resolve(&[dev("1-1", 0x1a86, 0x7523)], &grant(0x0403, 0x6001, None)).unwrap_err()
        );
        assert!(err.contains("0403:6001"), "name the device: {err}");
        assert!(err.contains("usbipd bind"), "say how to fix it: {err}");
    }

    #[test]
    fn two_identical_devices_are_ambiguous_not_arbitrary() {
        // D9: picking one silently would attach hardware the human did not
        // point at. Refuse and tell them to pin a busid.
        let devices = [dev("3-2", 0x0403, 0x6001), dev("3-3", 0x0403, 0x6001)];
        let err = format!("{:#}", resolve(&devices, &grant(0x0403, 0x6001, None)).unwrap_err());
        assert!(err.contains("more than one"), "{err}");
        assert!(err.contains("--busid"), "{err}");
    }

    #[test]
    fn a_busid_pin_disambiguates_and_is_honored() {
        let devices = [dev("3-2", 0x0403, 0x6001), dev("3-3", 0x0403, 0x6001)];
        let got = resolve(&devices, &grant(0x0403, 0x6001, Some("3-3"))).unwrap();
        assert_eq!(got.busid, "3-3");
    }

    #[test]
    fn a_pin_that_names_a_port_holding_a_different_device_is_refused() {
        // F-USB-3: busids are recycled across a replug, so the pin must be
        // checked against the vid:pid, never trusted on its own.
        let devices = [dev("3-2", 0x1a86, 0x7523)];
        assert!(resolve(&devices, &grant(0x0403, 0x6001, Some("3-2"))).is_err());
    }

    #[test]
    fn devid_packs_bus_and_device_number() {
        assert_eq!(devid(3, 2), (3 << 16) | 2);
    }

    #[test]
    fn import_verifies_the_returned_record_against_the_grant() {
        // A hostile or confused upstream may hand back a different device than
        // the busid asked for; the import is only complete once izbad has
        // re-checked the record it got.
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = std::io::Cursor::new(import_reply("3-2", 0x1a86, 0x7523));
        let err = format!(
            "{:#}",
            import(&mut FakeUpstream::new(&mut up), &chosen, &grant(0x0403, 0x6001, None)).unwrap_err()
        );
        assert!(err.contains("mismatch") || err.contains("returned"), "{err}");
    }

    #[test]
    fn a_matching_import_returns_the_devid_and_speed_the_guest_needs() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = std::io::Cursor::new(import_reply("3-2", 0x0403, 0x6001));
        let got =
            import(&mut FakeUpstream::new(&mut up), &chosen, &grant(0x0403, 0x6001, None)).unwrap();
        assert_eq!(got.devid, devid(3, 2));
        assert_eq!(got.speed, 2);
        assert_eq!(got.busid, "3-2");
    }

    #[test]
    fn the_pump_forwards_a_well_formed_urb_and_its_payload() {
        let mut wire = submit_out(1, &[0xde, 0xad, 0xbe, 0xef]);
        wire.extend_from_slice(&submit_in(2, 64));
        let mut out = Vec::new();
        pump_guest_to_upstream(std::io::Cursor::new(wire.clone()), &mut out).unwrap();
        assert_eq!(out, wire, "a valid stream passes through byte-identical");
    }

    #[test]
    fn the_pump_refuses_a_guest_impersonating_the_server() {
        // RET_SUBMIT from the guest direction is never legitimate.
        let mut header = [0u8; 48];
        header[..4].copy_from_slice(&3u32.to_be_bytes());
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(header.to_vec()), &mut out).is_err());
        assert!(out.is_empty(), "nothing reaches the host service");
    }

    #[test]
    fn the_pump_stops_at_an_oversized_transfer_without_forwarding_it() {
        let mut header = [0u8; 48];
        header[..4].copy_from_slice(&1u32.to_be_bytes()); // CMD_SUBMIT
        header[24..28].copy_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(header.to_vec()), &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn a_clean_eof_between_urbs_ends_the_pump_without_an_error() {
        let wire = submit_out(1, &[1, 2, 3]);
        let mut out = Vec::new();
        pump_guest_to_upstream(std::io::Cursor::new(wire), &mut out).unwrap();
    }

    #[test]
    fn a_truncated_urb_payload_is_an_error_not_a_short_forward() {
        let mut wire = submit_out(1, &[1, 2, 3, 4]);
        wire.truncate(wire.len() - 2);
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(wire), &mut out).is_err());
    }
}
```

Plus these test helpers in the same `mod tests` (they build real wire bytes with
the phase-1 constants, so the tests pin the format, not the implementation):

```rust
    use izba_proto::usbip::{DEVICE_RECORD_LEN, OP_COMMON_LEN, OP_REP_IMPORT, USBIP_VERSION};

    /// A `Read + Write` upstream whose writes are discarded — `import` must not
    /// depend on anything it wrote coming back.
    struct FakeUpstream<'a> {
        reply: &'a mut std::io::Cursor<Vec<u8>>,
    }
    impl<'a> FakeUpstream<'a> {
        fn new(reply: &'a mut std::io::Cursor<Vec<u8>>) -> Self {
            Self { reply }
        }
    }
    impl std::io::Read for FakeUpstream<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl std::io::Write for FakeUpstream<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn import_reply(busid: &str, vid: u16, pid: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        out.extend_from_slice(&OP_REP_IMPORT.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // status: ok
        let mut b = vec![0u8; DEVICE_RECORD_LEN];
        let path = "/sys/devices/pci0000:00/usb3";
        b[..path.len()].copy_from_slice(path.as_bytes());
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        b[0x120..0x124].copy_from_slice(&3u32.to_be_bytes()); // busnum
        b[0x124..0x128].copy_from_slice(&2u32.to_be_bytes()); // devnum
        b[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes()); // speed
        b[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        b[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        out.extend_from_slice(&b);
        assert_eq!(out.len(), OP_COMMON_LEN + DEVICE_RECORD_LEN);
        out
    }

    fn urb_header(command: u32, seqnum: u32, direction: u32, len: u32) -> [u8; 48] {
        let mut h = [0u8; 48];
        h[..4].copy_from_slice(&command.to_be_bytes());
        h[4..8].copy_from_slice(&seqnum.to_be_bytes());
        h[12..16].copy_from_slice(&direction.to_be_bytes());
        h[16..20].copy_from_slice(&1u32.to_be_bytes()); // ep 1
        h[24..28].copy_from_slice(&len.to_be_bytes());
        h[32..36].copy_from_slice(&0xffff_ffffu32.to_be_bytes()); // not iso
        h
    }

    fn submit_out(seqnum: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = urb_header(1, seqnum, 0, payload.len() as u32).to_vec();
        v.extend_from_slice(payload);
        v
    }

    fn submit_in(seqnum: u32, len: u32) -> Vec<u8> {
        urb_header(1, seqnum, 1, len).to_vec()
    }
```

- [ ] **Step 2: Run and watch them fail**

`cargo test -p izba-core usb::broker` — expected: does not compile.

- [ ] **Step 3: Implement `read_import_reply` in `inventory.rs`**

```rust
/// Read one `OP_REP_IMPORT` off `reply`. Fixed-length, unlike the devlist, so
/// there is no attacker-controlled framing here at all.
///
/// The caller is responsible for having sent [`encode_op_req_import`] first.
pub fn read_import_reply<R: Read>(reply: &mut R) -> Result<UsbDeviceRecord> {
    let mut buf = vec![0u8; OP_COMMON_LEN + DEVICE_RECORD_LEN];
    reply
        .read_exact(&mut buf)
        .context("reading the import reply")?;
    decode_op_rep_import(&buf).context("decoding the import reply")
}
```

(Add `decode_op_rep_import` to the `izba_proto::usbip` import list.)

- [ ] **Step 4: Implement `session.rs`**

```rust
//! One connection on the USB plane: resolve a label to a device, import it,
//! then splice.
//!
//! The guest sends a `vid:pid` and nothing else. Everything that follows —
//! which busid that names, which host the upstream is, the whole USB/IP op
//! phase — happens here, on the host side of the boundary (D1).
//!
//! **Two dials, not one.** The USB/IP op phase is strictly one operation per
//! TCP connection: after `OP_REP_IMPORT` the connection is URB-only forever,
//! with no renegotiation path. So `resolve` runs against a devlist connection
//! that is then dropped, and `import` runs against a fresh one that becomes the
//! URB stream. That same property is what makes splicing safe: a guest cannot
//! smuggle a second import down a spliced connection, because there is no
//! second op phase to smuggle it into.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use izba_proto::usbip::{
    decode_guest_urb, encode_op_req_import, UsbDeviceRecord, URB_HEADER_LEN,
};

use crate::usb::grants::UsbGrant;
use crate::usb::inventory::{read_import_reply, UpstreamDevice};

/// What the guest needs in order to hand the socket to `vhci-hcd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub devid: u32,
    pub speed: u32,
    pub busid: String,
}

/// The kernel's device id: bus number in the high half, device number in the low.
pub fn devid(busnum: u32, devnum: u32) -> u32 {
    (busnum << 16) | (devnum & 0xffff)
}

/// Pick the one device a grant names, out of everything the upstream exports.
///
/// The grant is a `vid:pid`, which the USB/IP wire format cannot make unique —
/// it carries no serial number (F-USB-3). So two identical devices are an
/// honest ambiguity, not a coin flip: refuse and ask the human to pin a busid.
/// A pin is a *disambiguator*, never an identity: it is only honored when the
/// device sitting on that port is still the granted one, because busids are
/// recycled across a replug.
pub fn resolve(devices: &[UpstreamDevice], grant: &UsbGrant) -> Result<UpstreamDevice> {
    let mut matching: Vec<&UpstreamDevice> =
        devices.iter().filter(|d| d.id == grant.device).collect();
    if let Some(pin) = grant.busid_pin.as_deref() {
        matching.retain(|d| d.busid == pin);
        if matching.is_empty() {
            bail!(
                "no device {} on busid {pin} — the port may hold different hardware now; \
                 re-grant with the current busid, or without --busid",
                grant.device
            );
        }
    }
    match matching.len() {
        0 => bail!(
            "the usbip upstream does not export {} — plug it in and share it with \
             `usbipd bind --busid <busid>` on the USB host",
            grant.device
        ),
        1 => Ok(matching[0].clone()),
        n => bail!(
            "the upstream exports {n} devices with id {} — izba cannot tell them apart \
             (USB/IP carries no serial number); re-grant with --busid to name one",
            grant.device
        ),
    }
}

/// Import `chosen` on `up`, then re-verify what came back.
///
/// The reply is checked against the grant rather than against the request:
/// asking for a busid and being handed some other device is exactly the case
/// this exists to catch.
pub fn import<U: Read + Write>(
    up: &mut U,
    chosen: &UpstreamDevice,
    grant: &UsbGrant,
) -> Result<Attached> {
    let req = encode_op_req_import(&chosen.busid)
        .map_err(|e| anyhow!("encoding the import request: {e}"))?;
    up.write_all(&req).context("sending OP_REQ_IMPORT")?;
    up.flush().ok();
    let rec: UsbDeviceRecord = read_import_reply(up)?;
    verify(&rec, chosen, grant)?;
    Ok(Attached {
        devid: devid(rec.busnum, rec.devnum),
        speed: rec.speed,
        busid: rec.busid,
    })
}

fn verify(rec: &UsbDeviceRecord, chosen: &UpstreamDevice, grant: &UsbGrant) -> Result<()> {
    if rec.id_vendor != grant.device.vid || rec.id_product != grant.device.pid {
        bail!(
            "the upstream returned {:04x}:{:04x} for an import of {} — refusing the mismatch",
            rec.id_vendor,
            rec.id_product,
            grant.device
        );
    }
    if rec.busid != chosen.busid {
        bail!(
            "the upstream returned busid {} for an import of {} — refusing the mismatch",
            rec.busid,
            chosen.busid
        );
    }
    Ok(())
}

/// Copy the guest→upstream leg, validating every URB header on the way.
///
/// This direction terminates in a privileged host service, so it earns a
/// validator; the reverse direction is spliced opaquely (D6, see
/// `izba_proto::usbip::urb`). The payload is streamed through a fixed buffer,
/// so a header's length field bounds a *copy*, never an allocation.
///
/// Returns `Ok(())` only on a clean EOF at a header boundary. Anything else is
/// an error, and the caller closes both legs — a half-forwarded URB must never
/// reach the upstream's parser.
pub fn pump_guest_to_upstream<R: Read, W: Write>(mut r: R, mut w: W) -> Result<()> {
    let mut header = [0u8; URB_HEADER_LEN];
    let mut buf = [0u8; 32 * 1024];
    loop {
        match read_full(&mut r, &mut header)? {
            0 => return Ok(()),
            n if n < URB_HEADER_LEN => bail!("truncated URB header ({n} bytes)"),
            _ => {}
        }
        let urb = decode_guest_urb(&header).map_err(|e| anyhow!("rejecting a guest URB: {e}"))?;
        w.write_all(&header).context("forwarding a URB header")?;
        let mut left = urb.payload_len;
        while left > 0 {
            let want = left.min(buf.len());
            r.read_exact(&mut buf[..want])
                .context("reading a URB payload")?;
            w.write_all(&buf[..want])
                .context("forwarding a URB payload")?;
            left -= want;
        }
        w.flush().ok();
    }
}

/// Read until `buf` is full, returning how many bytes were read. `Ok(0)` means
/// a clean end of stream; anything between 1 and `buf.len()-1` is a truncation.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("reading from the guest"),
        }
    }
    Ok(got)
}
```

- [ ] **Step 5: Run — expect PASS**

`cargo test -p izba-core usb::` then `cargo clippy --workspace --all-targets -- -D warnings`.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/usb/broker/ crates/izba-core/src/usb/mod.rs crates/izba-core/src/usb/inventory.rs
git commit -m "feat(core): the USB broker session — resolve, import, verify, validated splice"
```

---

## Task 3: The listener, wired into the daemon

**Files:**
- Modify: `crates/izba-core/src/usb/broker/mod.rs`
- Modify: `crates/izba-core/src/daemon/server.rs` (field + 6 lifecycle sites)
- Modify: `crates/izba-core/src/daemon/supervisor.rs`
- Modify: `crates/izba-core/src/daemon/egress/audit.rs` (`Tier::Usb`)

**Interfaces:**
- Consumes: Task 2's `session::{resolve, import, pump_guest_to_upstream, Attached}`; `usb::{dialable_upstream, settings, grants}`; `crate::daemon::transport::UdsListener`; `crate::portfwd::copy_until_eof`.
- Produces:
  ```rust
  pub fn listener_path(run_dir: &Path) -> PathBuf                 // vsock.sock_1028
  pub struct UsbBroker
  impl UsbBroker {
      pub fn new(audit: AuditSink) -> Self
      pub fn refresh(&self, paths: &Paths, name: &str, run_dir: &Path) -> anyhow::Result<()>
      pub fn stop(&self, name: &str, run_dir: &Path)
      pub fn listening(&self, name: &str) -> bool
  }
  ```

`refresh` is deliberately not called `ensure_listening`: it binds **or unbinds**
according to the sandbox's current grants, so revoking the last grant closes the
plane without a restart, and a grantless sandbox never has a listener at all.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-core/src/usb/broker/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::audit::AuditSink;

    fn paths_with_grant(root: &std::path::Path, name: &str, granted: bool) -> Paths {
        let paths = Paths::with_root(root.to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir(name)).unwrap();
        let usb = if granted {
            r#"{"devices":[{"device":"0403:6001","granted_at_unix_ms":1}]}"#
        } else {
            r#"{"devices":[]}"#
        };
        std::fs::write(
            paths.sandbox_dir(name).join("config.json"),
            format!(
                r#"{{"image_digest":"sha256:x","image_ref":"i","cpus":1,"mem_mb":512,
                    "workspace":"/ws","ports":[],"volumes":[],"builder":false,
                    "rw_size_gb":0,"usb":{usb}}}"#
            ),
        )
        .unwrap();
        paths
    }

    #[test]
    fn a_sandbox_without_grants_gets_no_listener_at_all() {
        // The phase-2 promise made structural: USB off means there is nothing
        // bound for a guest to dial, not merely something that would refuse.
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_grant(tmp.path(), "web", false);
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        b.refresh(&paths, "web", &run).unwrap();
        assert!(!b.listening("web"));
        assert!(!listener_path(&run).exists(), "no socket file either");
    }

    #[test]
    fn a_granted_sandbox_gets_a_listener_and_revoking_takes_it_away() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_grant(tmp.path(), "web", true);
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        match b.refresh(&paths, "web", &run) {
            Ok(()) => {}
            Err(e) if bind_denied(&e) => {
                eprintln!("SKIP: bind denied in this environment: {e:#}");
                return;
            }
            Err(e) => panic!("refresh: {e:#}"),
        }
        assert!(b.listening("web"));
        assert!(listener_path(&run).exists());

        // Revoke the grant on disk and refresh again.
        let paths = paths_with_grant(tmp.path(), "web", false);
        b.refresh(&paths, "web", &run).unwrap();
        assert!(!b.listening("web"), "the plane closes without a restart");
        assert!(!listener_path(&run).exists());
    }

    #[test]
    fn refresh_is_idempotent_for_a_live_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_grant(tmp.path(), "web", true);
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        if b.refresh(&paths, "web", &run).is_err() {
            eprintln!("SKIP: bind denied in this environment");
            return;
        }
        b.refresh(&paths, "web", &run).unwrap();
        assert!(b.listening("web"));
    }

    #[test]
    fn the_usb_listener_is_on_1028_beside_the_egress_socket() {
        let run = std::path::Path::new("/data/run/aabbccdd");
        assert_eq!(
            listener_path(run),
            std::path::PathBuf::from("/data/run/aabbccdd/vsock.sock_1028")
        );
    }

    fn bind_denied(e: &anyhow::Error) -> bool {
        let s = format!("{e:#}");
        s.contains("Permission denied") || s.contains("Operation not permitted")
    }
}
```

In `daemon/egress/audit.rs` tests:

```rust
    #[test]
    fn the_usb_tier_serializes_and_formats() {
        assert_eq!(serde_json::to_string(&Tier::Usb).unwrap(), "\"usb\"");
        let line = format_record(&AuditRecord {
            tier: Tier::Usb,
            ..sample_record()
        });
        assert!(line.contains("usb"), "{line}");
    }
```

- [ ] **Step 2: Run and watch them fail**

`cargo test -p izba-core usb::broker` / `cargo test -p izba-core audit` — expected: does not compile.

- [ ] **Step 3: Add `Tier::Usb`**

In `audit.rs`, add the variant with a doc comment, and extend the match in
`format_record`:

```rust
    /// A USB attach decision on the vsock-1028 plane. Not a network flow: the
    /// `dest_ip`/`port` are the usbip upstream, `host` is the granted device id,
    /// and `path` is the busid it resolved to.
    Usb,
```

- [ ] **Step 4: Implement `broker/mod.rs`**

Mirror `EgressManager` exactly (same slot struct, same nonblocking accept loop
with the 100 ms `WouldBlock` sleep, same `stop`/`listening`), with these
differences:

```rust
pub fn listener_path(run_dir: &Path) -> PathBuf {
    run_dir.join(format!("vsock.sock_{USB_PORT}"))
}

    /// Bind or unbind `name`'s USB plane to match its current grants.
    ///
    /// A sandbox with no grants gets **no listener** — that is the phase-2
    /// "disabled USB adds no attack surface" promise kept structurally, and it
    /// is why this is `refresh` and not `ensure_listening`: revoking the last
    /// grant must close the plane, not leave it open until the next restart.
    pub fn refresh(&self, paths: &Paths, name: &str, run_dir: &Path) -> anyhow::Result<()> {
        let settings = crate::usb::settings::load(&paths.usb_dir());
        let granted = crate::usb::guard_for(paths, name).sandbox_usb_enabled;
        if !granted || !crate::usb::is_configured(&settings) {
            self.stop(name, run_dir);
            return Ok(());
        }
        // ... bind exactly as EgressManager::ensure_listening does ...
    }
```

Each accepted connection spawns a detached thread running:

```rust
fn handle_conn(conn: UdsStream, sandbox: &str, paths: &Paths, audit: &AuditSink) {
    // A guest that dials this plane must not be able to hold a slot open: the
    // whole handshake is deadlined, and only the post-attach splice is not.
    let _ = conn.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let open: StreamOpen = match read_frame(&mut conn) { ... };
    let StreamOpen::UsbAttach { device } = open else {
        // Anything else on this port is a guest probing a plane it was given
        // for exactly one purpose.
        reply_error(BadRequest, "only usb_attach is handled on the USB port");
        return;
    };
    // ... parse the id, look up the grant, dial twice, resolve, import ...
    // audit.record(AuditRecord { tier: Tier::Usb, .. });   // both verdicts
    // reply Response::UsbAttached { devid, speed }
    let _ = conn.set_read_timeout(None);
    // splice: guest→upstream via session::pump_guest_to_upstream (validated),
    // upstream→guest via portfwd::copy_until_eof (opaque), each in its own
    // thread, full SHUT_RDWR on either end (CH never propagates half-close).
}
```

`HANDSHAKE_TIMEOUT` = 5 s, matching `inventory::IO_TIMEOUT`.

- [ ] **Step 5: Wire it into the daemon**

Add `pub usb: UsbBroker` to `Daemon`; construct it in `Daemon::new` with the
same `AuditSink`. Then, at each of the six sites where the egress plane is
already managed, manage this one too:

| Site | Call |
| --- | --- |
| `server.rs` `handle_start` (beside `egress.ensure_listening`) | `d.usb.refresh(&d.paths, &name, &d.paths.run_dir(&name))` |
| `server.rs` `handle_start` error path | `d.usb.stop(&name, &d.paths.run_dir(&name))` |
| `server.rs` `handle_stop` / `handle_rm` | `d.usb.stop(&name, &run_dir)` (the already-resolved `live_run_dir`) |
| `server.rs` `adopt` | `d.usb.refresh(...)` with `live_run_dir` |
| `supervisor.rs` `tick` (both arms) | `refresh` on the live arm, `stop` inside `teardown_unless_starting` |
| `server.rs` `handle_usb_allow` / `handle_usb_revoke` | `d.usb.refresh(&d.paths, &name, &sandbox::live_run_dir(&d.paths, &name))` after `apply_usb_guard` |

The allow/revoke sites are what make a revoke close the plane immediately, the
same way `apply_usb_guard` already makes it close the LAN path immediately.

- [ ] **Step 6: Run the gates**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
```

- [ ] **Step 7: Commit**

```bash
git add crates/izba-core/src/usb/broker/mod.rs crates/izba-core/src/daemon/
git commit -m "feat(core): bind the USB plane only for a granted sandbox"
```

---

## Task 4: `izba usb attach` / `detach`

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (two handlers + dispatch arms)
- Modify: `crates/izba-cli/src/commands/usb.rs`
- Modify: `crates/izba-cli/tests/usb_cli.rs`

**Interfaces:**
- Consumes: `handle_guest_rpc`'s shape (`sandbox::control` + `write_frame`/`read_frame`), `usb_settings_or_refuse`, `sandbox::edit_usb_grants`'s reader half.
- Produces: `DaemonRequest::UsbAttach/UsbDetach` handlers; `UsbCmd::Attach`/`Detach`.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-core/src/daemon/server.rs` tests:

```rust
    #[test]
    fn attaching_a_device_that_was_never_granted_is_refused_before_the_guest_is_touched() {
        // The grant check is the authorization boundary; reaching the guest
        // first would make a stopped sandbox report "not running" for what is
        // really "you never consented to that device".
        let (d, _tmp) = daemon_with_usb_upstream();
        seed_sandbox(&d.paths, "web");
        let err = format!(
            "{:#}",
            dispatch_inner(
                &d,
                DaemonRequest::UsbAttach { name: "web".into(), device: "0403:6001".into() }
            )
            .unwrap_err()
        );
        assert!(err.contains("not granted"), "{err}");
        assert!(err.contains("izba usb allow"), "say how to fix it: {err}");
    }

    #[test]
    fn attaching_while_no_upstream_is_configured_refuses_on_those_terms() {
        let (d, _tmp) = daemon_without_usb();
        seed_sandbox(&d.paths, "web");
        let err = format!(
            "{:#}",
            dispatch_inner(
                &d,
                DaemonRequest::UsbAttach { name: "web".into(), device: "0403:6001".into() }
            )
            .unwrap_err()
        );
        assert!(err.contains("not configured"), "{err}");
    }

    #[test]
    fn a_malformed_device_id_never_reaches_the_grant_lookup() {
        let (d, _tmp) = daemon_with_usb_upstream();
        let err = format!(
            "{:#}",
            dispatch_inner(
                &d,
                DaemonRequest::UsbAttach { name: "web".into(), device: "403:6001".into() }
            )
            .unwrap_err()
        );
        assert!(err.contains("vid:pid"), "{err}");
    }
```

In `crates/izba-cli/tests/usb_cli.rs`:

```rust
#[test]
fn attach_and_detach_are_wired_and_refuse_an_ungranted_device() {
    let data = tempfile::tempdir().unwrap();
    seed_sandbox(data.path(), "web");
    let set = izba(data.path(), &["usb", "upstream", "set", "127.0.0.1"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    for verb in ["attach", "detach"] {
        let out = izba(data.path(), &["usb", verb, "web", "--device", "0403:6001"]);
        assert!(!out.status.success(), "{verb} must refuse an ungranted device");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("not granted"), "{verb}: {stderr}");
    }
}

#[test]
fn usb_help_lists_the_datapath_verbs() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["usb", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for sub in ["attach", "detach"] {
        assert!(text.contains(sub), "missing {sub}: {text}");
    }
}
```

- [ ] **Step 2: Run and watch them fail**

`cargo test -p izba-core daemon::server::tests::attach` and
`cargo test -p izba-cli --test usb_cli` — expected FAIL.

- [ ] **Step 3: Implement the handlers**

```rust
fn handle_usb_attach(d: &Arc<Daemon>, name: String, device: String) -> anyhow::Result<DaemonResponse> {
    forward_usb(d, name, device, true)
}

fn handle_usb_detach(d: &Arc<Daemon>, name: String, device: String) -> anyhow::Result<DaemonResponse> {
    forward_usb(d, name, device, false)
}

/// Both verbs share one shape: refuse on the host's terms first (feature off,
/// bad id, no grant), and only then talk to the guest. Ordering matters — a
/// grant check that ran after the guest RPC would report a stopped sandbox for
/// a device the user never consented to.
fn forward_usb(
    d: &Arc<Daemon>,
    name: String,
    device: String,
    attach: bool,
) -> anyhow::Result<DaemonResponse> {
    let _ = usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    let grants = sandbox::usb_grants(&d.paths, &name)?;
    if crate::usb::grants::find(&grants, id).is_none() {
        bail!("{id} is not granted to '{name}' — run `izba usb allow {name} --device {id}` first");
    }
    let req = if attach {
        izba_proto::Request::UsbAttach { device: id.to_string() }
    } else {
        izba_proto::Request::UsbDetach { device: id.to_string() }
    };
    handle_guest_rpc(d, name, req)
}
```

Add `sandbox::usb_grants(paths, name) -> anyhow::Result<UsbConfig>` (a read-only
sibling of `edit_usb_grants`, no lock needed) and the two dispatch arms.

- [ ] **Step 4: Implement the CLI verbs**

Two `UsbCmd` variants taking `<sandbox> --device <VID:PID>`; both call the
daemon and print `attached 0403:6001 to web` / `detached ...`. No consent
prompt: consent was given at `allow` time, and attach of an already-granted
device is not a new decision. `attach` prints the honest caveat once —
`the device is now unavailable to the host while attached` — because that is a
side effect on hardware outside the sandbox.

- [ ] **Step 5: Run the gates + the app gate**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/daemon/server.rs crates/izba-core/src/sandbox.rs crates/izba-cli/src/commands/usb.rs crates/izba-cli/tests/usb_cli.rs
git commit -m "feat(cli): izba usb attach/detach"
```

---

## Task 5: The guest client's pure half

**Files:**
- Create: `crates/izba-init/src/usb.rs`
- Modify: `crates/izba-init/src/lib.rs` (`pub mod usb;` — it must be host-testable)

**Interfaces:**
- Produces:
  ```rust
  pub fn parse_free_port(status: &str, speed: u32) -> Option<u32>
  pub fn attach_line(port: u32, fd: i32, devid: u32, speed: u32) -> String
  pub fn new_serial_nodes(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String>
  pub const VHCI_DIR: &str = "/sys/devices/platform/vhci_hcd.0";
  pub const SHARED_DEV_DIR: &str = "/run/izba/usb";
  ```

The vhci `status` file looks like this (one header line, then one line per port):

```
hub port sta spd dev      sockfd local_busid
hs  0000 004 000 00000000 000000 0-0
ss  0008 004 000 00000000 000000 0-0
```

`sta == 4` (`VDEV_ST_NULL`) is free. A super-speed device (`speed == 5`) needs
an `ss` port; everything else takes an `hs` port.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "\
hub port sta spd dev      sockfd local_busid
hs  0000 006 003 00030002 000005 3-2
hs  0001 004 000 00000000 000000 0-0
ss  0008 004 000 00000000 000000 0-0
";

    #[test]
    fn a_high_speed_device_takes_a_free_hs_port_skipping_the_busy_one() {
        assert_eq!(parse_free_port(STATUS, 3), Some(1));
    }

    #[test]
    fn a_super_speed_device_needs_an_ss_port() {
        // Handing a SuperSpeed device an hs port makes the kernel refuse the
        // attach with EINVAL, which would surface as an unexplained failure.
        assert_eq!(parse_free_port(STATUS, 5), Some(8));
    }

    #[test]
    fn no_free_port_is_none_not_a_guess() {
        let busy = "\
hub port sta spd dev      sockfd local_busid
hs  0000 006 003 00030002 000005 3-2
";
        assert_eq!(parse_free_port(busy, 3), None);
    }

    #[test]
    fn a_header_only_or_garbled_status_yields_no_port() {
        for s in ["", "hub port sta spd dev sockfd local_busid\n", "nonsense\n", "hs\n"] {
            assert_eq!(parse_free_port(s, 3), None, "{s:?}");
        }
    }

    #[test]
    fn the_attach_line_is_the_four_fields_the_kernel_expects() {
        assert_eq!(attach_line(1, 7, 196_610, 3), "1 7 196610 3");
    }

    #[test]
    fn only_newly_appeared_serial_nodes_are_reported() {
        // The node the attach produced is identified by diffing /dev, because
        // the kernel picks the minor and izba must not guess a name.
        let before = ["ttyS0", "ttyACM0"].iter().map(|s| s.to_string()).collect();
        let after = ["ttyS0", "ttyACM0", "ttyACM1", "sda"].iter().map(|s| s.to_string()).collect();
        assert_eq!(new_serial_nodes(&before, &after), vec!["ttyACM1".to_string()]);
    }

    #[test]
    fn a_non_serial_node_is_never_mirrored_into_the_container() {
        // v1 is serial-class only (D5). A device that lands as something else
        // must not be handed to the workload just because it appeared.
        let before = std::collections::BTreeSet::new();
        let after = ["sdb", "hidraw0", "video0"].iter().map(|s| s.to_string()).collect();
        assert!(new_serial_nodes(&before, &after).is_empty());
    }

    #[test]
    fn both_serial_families_are_recognised() {
        let before = std::collections::BTreeSet::new();
        let after = ["ttyUSB0", "ttyACM0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(new_serial_nodes(&before, &after).len(), 2);
    }
}
```

- [ ] **Step 2: Run and watch them fail**

`cargo test -p izba-init usb::` — expected: does not compile.

- [ ] **Step 3: Implement**

```rust
/// Find a free vhci port for a device of this speed.
///
/// `status` has one header line and then one line per port:
/// `hub port sta spd dev sockfd local_busid`. `sta == VDEV_ST_NULL` (4) means
/// free. The hub column matters: `vhci` keeps separate USB2 (`hs`) and USB3
/// (`ss`) port ranges and refuses a mismatched attach, so the speed picks the
/// hub rather than merely being passed along.
pub fn parse_free_port(status: &str, speed: u32) -> Option<u32> {
    const VDEV_ST_NULL: &str = "004";
    let want_hub = if speed == USB_SPEED_SUPER { "ss" } else { "hs" };
    status
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 3 && f[0] == want_hub && f[2] == VDEV_ST_NULL)
                .then(|| f[1].parse::<u32>().ok())
                .flatten()
        })
        .next()
}
```

`attach_line` is `format!("{port} {fd} {devid} {speed}")`; `new_serial_nodes`
diffs the sets and keeps names starting `ttyACM` or `ttyUSB`.

- [ ] **Step 4: Run — expect PASS**, then `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` to confirm it stays static and dependency-free.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/usb.rs crates/izba-init/src/lib.rs
git commit -m "feat(init): vhci port selection and device-node discovery"
```

---

## Task 6: The guest client's I/O half, behind the cmdline guard

**Files:**
- Modify: `crates/izba-init/src/usb.rs`
- Modify: `crates/izba-init/src/server.rs` (dispatch)
- Modify: `crates/izba-init/src/main.rs` (`izba.usb=1`, shared-dir creation)

**Interfaces:**
- Consumes: Task 1's `Request::UsbAttach/UsbDetach`, `StreamOpen::UsbAttach`, `Response::UsbAttached`, `ErrorKind::UsbUnavailable`; Task 5's pure helpers.
- Produces:
  ```rust
  pub struct UsbState { /* enabled: bool, attached: Mutex<HashMap<String, Attached>> */ }
  impl UsbState {
      pub fn new(enabled: bool) -> Self
      pub fn attach_with<S: Read + Write + AsRawFd, D: FnOnce() -> io::Result<S>>(
          &self, device: &str, dial: D) -> Result<(), (ErrorKind, String)>
      pub fn detach(&self, device: &str) -> Result<(), (ErrorKind, String)>
  }
  ```
- The dispatcher signature becomes
  `fn dispatch_control_request(engine: &ExecEngine, usb: &UsbState, req: Request) -> Response`.

**The fd hand-off is the subtle part.** After `attach_line` is written to sysfs
the *kernel* owns the socket; init must not close it, so the `S` is
`std::mem::forget`-ed (or its fd `into_raw_fd`-ed) only **after** the sysfs
write succeeds — and must be closed normally if it fails, or a failed attach
leaks a live connection into izbad for the life of the guest.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn every_usb_request_is_refused_when_the_guest_did_not_boot_with_usb() {
        // The host decides whether this guest has USB, via izba.usb=1. A guest
        // that talks itself into the plane must get nothing.
        let usb = UsbState::new(false);
        let (kind, msg) = usb
            .attach_with("0403:6001", || -> std::io::Result<std::os::unix::net::UnixStream> {
                panic!("must not dial")
            })
            .unwrap_err();
        assert_eq!(kind, ErrorKind::UsbUnavailable);
        assert!(msg.contains("izba.usb"), "{msg}");
        assert_eq!(usb.detach("0403:6001").unwrap_err().0, ErrorKind::UsbUnavailable);
    }

    #[test]
    fn attach_sends_exactly_one_frame_naming_the_device_and_nothing_else() {
        // D1: the guest may say which device; it may never say where from.
        let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut peer = theirs;
            let open: StreamOpen = izba_proto::read_frame(&mut peer).unwrap();
            let StreamOpen::UsbAttach { device } = open else {
                panic!("expected usb_attach, got {open:?}")
            };
            assert_eq!(device, "0403:6001");
            izba_proto::write_frame(&mut peer, &Response::Error {
                kind: ErrorKind::BadRequest,
                message: "no".into(),
            })
            .unwrap();
        });
        let usb = UsbState::new(true);
        let _ = usb.attach_with("0403:6001", || Ok(mine));
        h.join().unwrap();
    }

    #[test]
    fn a_refusal_from_izbad_is_reported_verbatim_not_swallowed() {
        let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut peer = theirs;
            let _: StreamOpen = izba_proto::read_frame(&mut peer).unwrap();
            izba_proto::write_frame(&mut peer, &Response::Error {
                kind: ErrorKind::BadRequest,
                message: "0403:6001 is not granted".into(),
            })
            .unwrap();
        });
        let usb = UsbState::new(true);
        let (_, msg) = usb.attach_with("0403:6001", || Ok(mine)).unwrap_err();
        assert!(msg.contains("not granted"), "{msg}");
    }

    #[test]
    fn detaching_a_device_that_was_never_attached_says_so() {
        let usb = UsbState::new(true);
        let (kind, msg) = usb.detach("0403:6001").unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        assert!(msg.contains("not attached"), "{msg}");
    }
```

And in `server.rs` tests, a dispatch-level test that `Request::UsbAttach`
reaches `UsbState` (a `UsbState::new(false)` harness returns
`UsbUnavailable`, proving the wiring without needing a vhci).

- [ ] **Step 2: Run and watch them fail.**

- [ ] **Step 3: Implement `attach_with`**

Order of operations, each step failing closed:

1. `if !self.enabled` → `UsbUnavailable`.
2. Refuse a device already in `attached` (`BadRequest`, "already attached").
3. `dial()`, write `StreamOpen::UsbAttach{device}`, `read_frame` one `Response`.
   `UsbAttached{devid,speed}` continues; `Error{kind,message}` is returned as-is;
   anything else is `Internal`.
4. Snapshot `/dev` (`before`), read `<VHCI_DIR>/status`, `parse_free_port`.
5. Write `attach_line(port, fd, devid, speed)` to `<VHCI_DIR>/attach`.
6. On success only: `into_raw_fd()` the stream so init stops owning it.
7. Poll `/dev` up to 3 s for `new_serial_nodes`; mirror the first one into
   `SHARED_DEV_DIR` with the same major/minor (`stat` + `mknod`), mode 0666.
8. Record `Attached { port, node }` and return `Ok(())`.

Mode 0666 rather than an ownership dance: the workload runs in its own user
namespace, so a uid-based grant would depend on the mapping, while the node's
*reachability* is already gated by the bind mount and the device cgroup.

`detach` writes the port number to `<VHCI_DIR>/detach`, removes the mirrored
node, and drops the entry.

- [ ] **Step 4: Wire the guard and the dispatcher**

In `main.rs`, beside the `izba.buildout` read:

```rust
    // Host-authoritative: the guest cannot talk itself into USB support.
    let usb_enabled = params.get("izba.usb").map(|v| v == "1").unwrap_or(false);
    if usb_enabled {
        let _ = std::fs::create_dir_all(usb::SHARED_DEV_DIR);
    }
    let usb = Arc::new(usb::UsbState::new(usb_enabled));
```

Thread it into `serve_control` alongside the `ExecEngine`.

- [ ] **Step 5: Gates** — workspace tests, clippy, fmt, and the musl static build.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-init/src/
git commit -m "feat(init): attach a granted device to vhci over the USB plane"
```

---

## Task 7: The USB kernel variant

**Files:**
- Create: `hack/kernel-usb.config`
- Modify: `hack/build-kernel.sh`, `hack/README.md`
- Modify: `crates/izba-core/src/artifacts.rs`, `crates/izba-core/src/sandbox.rs`, `crates/izba-core/src/daemon/server.rs`
- Modify: `.github/workflows/e2e.yml`, `.github/workflows/_artifacts.yml`

**Interfaces:**
- Produces:
  ```rust
  pub enum KernelVariant { Base, Usb }
  pub fn locate(paths: &Paths, variant: KernelVariant) -> anyhow::Result<Artifacts>
  ```
  `ArtifactsFn` becomes `Fn(&Paths, KernelVariant) -> anyhow::Result<Artifacts>`.
  `build_cmdline(name, volumes, builder, usb)` appends ` izba.usb=1`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn the_usb_variant_looks_for_its_own_kernel_image() {
        let tmp = tempfile::tempdir().unwrap();
        let art = tmp.path().join("artifacts");
        std::fs::create_dir_all(&art).unwrap();
        std::fs::write(art.join("vmlinux"), b"base").unwrap();
        std::fs::write(art.join("vmlinux-usb"), b"usb").unwrap();
        std::fs::write(art.join("initramfs.cpio.gz"), b"i").unwrap();
        let got = locate_from(None, None, tmp.path(), None, KernelVariant::Usb).unwrap();
        assert!(got.kernel.ends_with("vmlinux-usb"));
        let base = locate_from(None, None, tmp.path(), None, KernelVariant::Base).unwrap();
        assert!(base.kernel.ends_with("vmlinux"));
    }

    #[test]
    fn a_usb_sandbox_on_an_installation_without_the_usb_kernel_fails_with_a_fixable_error() {
        // Booting the non-USB kernel instead would produce a sandbox that
        // accepts an attach and then cannot see the device — the silent
        // downgrade the project forbids.
        let tmp = tempfile::tempdir().unwrap();
        let art = tmp.path().join("artifacts");
        std::fs::create_dir_all(&art).unwrap();
        std::fs::write(art.join("vmlinux"), b"base").unwrap();
        std::fs::write(art.join("initramfs.cpio.gz"), b"i").unwrap();
        let err = format!(
            "{:#}",
            locate_from(None, None, tmp.path(), None, KernelVariant::Usb).unwrap_err()
        );
        assert!(err.contains("vmlinux-usb"), "{err}");
        assert!(err.contains("USB"), "{err}");
        assert!(err.contains("build-kernel.sh"), "say how to get one: {err}");
    }

    #[test]
    fn the_usb_kernel_env_override_is_separate_from_the_base_one() {
        // e2e sets IZBA_KERNEL and IZBA_KERNEL_USB independently; one must not
        // silently satisfy the other.
        ...
    }
```

In `sandbox.rs` tests:

```rust
    #[test]
    fn the_cmdline_declares_usb_only_for_a_sandbox_that_has_grants() {
        assert!(build_cmdline("web", &[], false, true).contains("izba.usb=1"));
        assert!(!build_cmdline("web", &[], false, false).contains("izba.usb"));
    }
```

- [ ] **Step 2: Run and watch them fail.**

- [ ] **Step 3: Write the kernel fragment**

`hack/kernel-usb.config` — merged **after** `hack/kernel.config`, so it must
re-enable what the base config turns off:

```
# USB passthrough variant (dist/vmlinux-usb). Merged over hack/kernel.config,
# which disables USB entirely — a sandbox without device grants must boot a
# kernel that physically cannot talk to a USB device.
#
# vhci-hcd is the virtual host controller: it takes a socket fd and presents
# whatever is on the other end as a locally attached device. There is no module
# loader in the initramfs, so every symbol here is =y, not =m.
CONFIG_USB_SUPPORT=y
CONFIG_USB=y
CONFIG_USB_COMMON=y
CONFIG_USBIP_CORE=y
CONFIG_USBIP_VHCI_HCD=y
# Serial classes only (design D5): CDC-ACM plus the four common bridges.
CONFIG_USB_ACM=y
CONFIG_USB_SERIAL=y
CONFIG_USB_SERIAL_CP210X=y
CONFIG_USB_SERIAL_CH341=y
CONFIG_USB_SERIAL_FTDI_SIO=y
CONFIG_USB_SERIAL_PL2303=y
```

`build-kernel.sh` gains an optional extra fragment. The existing merge-verify
pass (which asserts every `=y` survived `olddefconfig`) must run over the extra
fragment too — that is what catches a symbol silently dropped for an unmet
dependency, which is exactly how a "USB kernel" without `vhci` would ship.

```sh
# hack/build-kernel.sh [VERSION [OUTPUT]]
#   IZBA_KERNEL_EXTRA_CONFIG=hack/kernel-usb.config  merge an extra fragment
```

- [ ] **Step 4: Implement variant selection**

`locate_from` takes the variant and picks the filename; the USB env override is
`IZBA_KERNEL_USB`. `handle_start` already has the `SandboxConfig` in hand
before it calls the artifacts seam:

```rust
    let variant = if config.usb.is_enabled() {
        KernelVariant::Usb
    } else {
        KernelVariant::Base
    };
    let art = (d.deps.artifacts)(&d.paths, variant)?;
```

and `sandbox::start_with_timeouts` passes `config.usb.is_enabled()` into
`build_cmdline`. Update the test fake at `server.rs`'s `DaemonDeps` builder.

- [ ] **Step 5: CI**

In `e2e.yml` and `_artifacts.yml`, add a `kernel-usb` job mirroring `kernel`,
with cache key `vmlinux-usb-${{ hashFiles('hack/kernel.config', 'hack/kernel-usb.config', 'hack/build-kernel.sh') }}` — note it hashes **both** fragments, because
the variant is the base plus the overlay and a change to either invalidates it.
Add `IZBA_KERNEL_USB` to the KVM job's env.

- [ ] **Step 6: Build it locally and prove the two kernels differ**

```bash
IZBA_KERNEL_EXTRA_CONFIG=hack/kernel-usb.config hack/build-kernel.sh 6.12.30 dist/vmlinux-usb
strings dist/vmlinux-usb | grep -qi vhci_hcd && echo "vhci present"
strings dist/vmlinux     | grep -qi vhci_hcd && echo "UNEXPECTED: base kernel has vhci"
```

- [ ] **Step 7: Commit**

```bash
git add hack/kernel-usb.config hack/build-kernel.sh hack/README.md crates/izba-core/src/artifacts.rs crates/izba-core/src/sandbox.rs crates/izba-core/src/daemon/server.rs .github/workflows/
git commit -m "feat(core): boot a USB-capable kernel only for a granted sandbox"
```

---

## Task 8: Device visibility inside the container (**spike first**)

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs`
- Modify: `crates/izba-core/src/sandbox.rs` (`SpecParams.usb`)

**This task begins with an experiment, not an edit.** The spec calls it the
highest residual uncertainty in the feature: the workload has its own mount and
user namespaces and a fresh tmpfs `/dev`, so a node created after container
start is invisible to it and an unprivileged userns cannot `mknod` one.

- [ ] **Step 1: Run the spike**

With a USB sandbox booted (Task 7) and the container running, from inside the
guest:

```sh
mkdir -p /run/izba/usb && mknod /run/izba/usb/ttyACM0 c 166 0 && chmod 666 /run/izba/usb/ttyACM0
# then, from the host:
izba exec <name> -- ls -l /dev/izba/            # is the bind visible?
izba exec <name> -- sh -c 'cat /dev/izba/ttyACM0' # EPERM ⇒ the device cgroup is filtering
```

Record three answers in the commit message: (a) does a node created **after**
container start appear through the bind mount; (b) does the cgroup device
filter block `open()`; (c) does the userns mapping make the 0666 node usable.

Expected: (a) yes — a bind mount shares the source superblock, so later files
appear; (b) yes on cgroup v2 unless the major is pre-authorised; (c) yes with
0666. **If (a) is false**, the fallback is to mount the shared dir as a tmpfs
inside the container's mount namespace and have crun's `linux.devices` create
the node — which requires knowing the major/minor before container start, and
therefore restricts attach to before-start only. Record which path was taken.

- [ ] **Step 2: Write the failing tests**

```rust
    #[test]
    fn a_usb_sandbox_gets_the_shared_device_directory_bound_in() {
        let spec = generate_spec(&usb_params(true)).unwrap();
        let m = spec
            .mounts()
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.destination() == std::path::Path::new("/dev/izba"))
            .expect("no /dev/izba mount");
        assert_eq!(m.typ().as_deref(), Some("bind"));
        assert_eq!(m.source().as_deref(), Some(std::path::Path::new("/run/izba/usb")));
        let opts = m.options().clone().unwrap_or_default();
        assert!(opts.iter().any(|o| o == "rbind"), "{opts:?}");
        assert!(opts.iter().any(|o| o == "nosuid"), "a device dir must not carry setuid: {opts:?}");
        assert!(opts.iter().any(|o| o == "noexec"), "{opts:?}");
    }

    #[test]
    fn a_sandbox_without_usb_has_no_device_directory_and_no_device_rules() {
        let spec = generate_spec(&usb_params(false)).unwrap();
        assert!(!spec.mounts().as_ref().unwrap().iter()
            .any(|m| m.destination() == std::path::Path::new("/dev/izba")));
        let devices = spec.linux().as_ref().unwrap().resources().as_ref().unwrap()
            .devices().clone().unwrap_or_default();
        assert!(devices.is_empty(), "no USB ⇒ no device allowances: {devices:?}");
    }

    #[test]
    fn only_the_serial_char_majors_are_authorised() {
        // The device cgroup is what makes "serial class only" structural rather
        // than a naming convention: a non-serial device mirrored in by mistake
        // still cannot be opened.
        let spec = generate_spec(&usb_params(true)).unwrap();
        let devices = spec.linux().as_ref().unwrap().resources().as_ref().unwrap()
            .devices().clone().unwrap();
        let majors: Vec<i64> = devices.iter().filter_map(|d| d.major()).collect();
        assert_eq!(majors, vec![166, 188], "ttyACM and ttyUSB, nothing else");
        assert!(devices.iter().all(|d| d.allow()));
        assert!(devices.iter().all(|d| d.typ() == Some(LinuxDeviceType::C)));
        assert!(
            devices.iter().all(|d| !d.access().as_deref().unwrap_or("").contains('m')),
            "the workload may read and write a device, never create one"
        );
    }
```

- [ ] **Step 3: Implement**

```rust
/// Char-device majors izba is willing to expose to a workload: CDC-ACM (166)
/// and USB serial (188). v1 is serial-class only (design D5), and encoding
/// that as a cgroup device rule makes it structural: a node of any other class
/// that somehow reached `/dev/izba` still cannot be opened.
const SERIAL_MAJORS: [i64; 2] = [166, 188];

/// Guest path of the directory izba-init mirrors attached device nodes into,
/// bind-mounted to `/dev/izba` in the container. It lives OUTSIDE the overlay
/// (init-root `/run`), mirroring how the ssh material is kept out of the OCI
/// image, and it is created before container launch so the bind has a source.
pub const USB_SHARED_DIR: &str = "/run/izba/usb";
```

`generate_spec` pushes the bind mount and the two `LinuxDeviceCgroup` entries
(`allow: true`, `type: c`, `access: "rw"`) when `params.usb`. Thread
`usb: config.usb.is_enabled()` from `write_oci_bundle`'s caller.

- [ ] **Step 4: Run the gates**, then re-run the spike commands and confirm the
generated `config.json` produces a container that can `open()` the node.

- [ ] **Step 5: Commit** (with the three spike answers in the body)

```bash
git add crates/izba-core/src/image/runtime_config.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): expose attached serial devices to the workload"
```

---

## Task 9: `fake_usbipd` and the end-to-end proof

**Files:**
- Create: `hack/fake-usbipd/{Cargo.toml,src/main.rs}`
- Modify: root `Cargo.toml` (`exclude`)
- Create: `crates/izba-cli/tests/usb_attach_e2e.rs`
- Modify: `.github/workflows/e2e.yml`

`usbip`/`rusb` link libusb and must never enter a workspace gate — including
`cargo clippy --all-targets` and the Windows cross-check, both of which build
example binaries. So the fake server is its own excluded crate, built only by
the KVM job, exactly like the `fuzz/` crates.

- [ ] **Step 1: Write the fake server**

```toml
# hack/fake-usbipd/Cargo.toml
[package]
name = "fake-usbipd"
version = "0.0.0"
edition = "2021"
publish = false

# Excluded from the izba workspace on purpose: `usbip` pulls rusb/nusb, which
# link libusb. izba's shipped tree and all six workspace gates must stay free of
# it; only the KVM e2e job builds this.
[workspace]

[dependencies]
usbip = "0.9"
tokio = { version = "1", features = ["full"] }
```

`src/main.rs` serves one CDC-ACM device (`0403:6001`, busid `1-1`) whose bulk-IN
returns whatever the last bulk-OUT wrote — an echo, which is what makes the e2e
assertion behavioural rather than a log-scrape. It prints its bound port on
stdout so the test can pick an ephemeral one.

- [ ] **Step 2: Write the e2e**

`crates/izba-cli/tests/usb_attach_e2e.rs`, gated on `IZBA_INTEGRATION=1` plus
`IZBA_FAKE_USBIPD` (the built binary) and `IZBA_KERNEL_USB`:

```rust
#[test]
fn a_granted_device_reaches_the_workload_and_carries_bytes_both_ways() {
    // The whole datapath in one assertion: the echo can only come back if URBs
    // flowed guest vhci → vsock 1028 → izbad → TCP → the server and back.
    // ... start fake_usbipd, izba usb upstream set 127.0.0.1:<port>,
    //     izba usb allow web --device 0403:6001 --confirm 0403:6001,
    //     izba create/start web, izba usb attach web --device 0403:6001,
    //     izba exec web -- sh -c 'printf hello > /dev/izba/ttyACM0; head -c5 /dev/izba/ttyACM0'
    assert_eq!(out.trim(), "hello");
}

#[test]
fn a_device_that_was_never_granted_cannot_be_attached_or_seen() {
    // ... upstream exports 1a86:7523 too; it is never granted ...
    assert!(!attach.status.success());
    assert!(stderr.contains("not granted"));
    assert!(!ls_dev_izba.contains("tty"), "nothing appears in the container");
}

#[test]
fn a_sandbox_without_grants_has_no_usb_plane_bound() {
    // The structural claim: the socket file does not exist.
    assert!(!run_dir.join("vsock.sock_1028").exists());
}

#[test]
fn the_default_kernel_cannot_do_usb_at_all() {
    // Defence in depth behind the grant check: even a guest that talked its way
    // into an attach has no vhci to attach to.
    let out = izba(&["exec", "plain", "--", "ls", "/sys/devices/platform"]);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("vhci"));
}

#[test]
fn revoking_a_grant_closes_the_plane_on_a_running_sandbox() {
    // ... izba usb revoke ... then the socket is gone and a re-attach fails ...
}

#[test]
fn upstream_death_detaches_honestly_rather_than_reconnecting() {
    // Kill fake_usbipd; the guest must see an unplug, and izba must not retry.
}
```

- [ ] **Step 3: Wire CI**

In the KVM job, before the test steps:

```yaml
      - name: Build fake usbip server (excluded crate)
        run: cargo build --locked --release --manifest-path hack/fake-usbipd/Cargo.toml
      - name: Install libusb (fake usbip server only)
        run: sudo apt-get install -y libusb-1.0-0-dev
```

and a step **"USB passthrough e2e (real vhci over vsock)"** running
`IZBA_INTEGRATION=1 cargo test -p izba-cli --test usb_attach_e2e -- --test-threads=1`
with `IZBA_FAKE_USBIPD` and `IZBA_KERNEL_USB` set.

- [ ] **Step 4: Run it locally** (unsandboxed — `/dev/kvm` works here, it is
merely invisible inside the sandboxed shell).

- [ ] **Step 5: Commit**

```bash
git add hack/fake-usbipd/ Cargo.toml crates/izba-cli/tests/usb_attach_e2e.rs .github/workflows/e2e.yml
git commit -m "test(cli): prove the USB datapath end to end against a real vhci"
```

---

## Task 10: Fuzz, docs, and the findings register

**Files:**
- Create: `crates/izba-core/fuzz/fuzz_targets/usbip_pump.rs`
- Modify: `crates/izba-core/fuzz/Cargo.toml`, `.github/workflows/ci.yml`
- Modify: `README.md`, `CLAUDE.md`, `docs/security/findings-2026-06-15.md`,
  `docs/superpowers/specs/2026-08-04-izba-usb-passthrough-design.md`

- [ ] **Step 1: Add the fuzz target**

The pump is the one new parser on a hostile-input path (guest bytes → a
privileged host service), so it earns a target; the 1028 handshake reuses the
already-fuzzed frame codec and gets none.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

// The guest→upstream URB validator: arbitrary guest bytes must never panic and
// never forward a byte past a rejected header.
fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    let _ = izba_core::usb::broker::session::pump_guest_to_upstream(
        std::io::Cursor::new(data),
        &mut out,
    );
});
```

Add the `[[bin]]` stanza and extend the ci.yml step (renaming it to name all
targets honestly — it currently says "flatten" alone).

- [ ] **Step 2: Update the docs**

- `README.md`: add `attach`/`detach` to the `izba usb` surface and one honest
  paragraph — what a granted device gives the agent, that USB traffic is not
  visible to the egress firewall, and that `/dev/izba/ttyACM0` is where it lands.
- `CLAUDE.md`: extend the crate map (`usb/broker`, `izba-init/src/usb.rs`), the
  cmdline chain (`izba.usb=1`), the vsock port list (1028), and the artifact
  list (`vmlinux-usb`).
- The design spec: a §5.2.1-style delivery note recording what phase 3 shipped
  and any deviation (notably the two-dial op phase and the `/dev/izba` path).
- `docs/security/findings-2026-06-15.md`: F-USB-2/3/5 move from "designed" to
  "mitigated, residual accepted" with the shipped control named for each;
  F-USB-6 (kernel capability) closes.

- [ ] **Step 3: Run every gate one final time**, including the app gate.

- [ ] **Step 4: Commit and open the PR**

```bash
git add -- crates/izba-core/fuzz README.md CLAUDE.md docs/
git commit -m "docs(usb): record what the datapath phase shipped"
git push -u origin feat/usb-passthrough-phase3
gh pr create --title "feat(usb): phase 3 — the datapath" --body "..."   # never --draft
```

---

## Self-review

**Spec coverage.** §5.2 broker → Tasks 2+3; §5.3 guest client → Tasks 5+6;
§5.4 device visibility → Task 8; §5.5 kernel artifact → Task 7; §5.6 control
plane (`UsbAttach`/`UsbDetach`, proto bump) → Tasks 1+4; §6.3 CLI surface →
Task 4; §7 fail-closed + `Tier::Usb` audit → Tasks 2+3; §8 testing matrix →
Tasks 2 (unit), 9 (KVM e2e, negative, abuse), 10 (fuzz).

**Two deliberate deviations from the spec**, both recorded in Task 10's
delivery note:

1. **The in-process `jiegec/usbip` + `tokio::io::duplex` layer is dropped.**
   Its purpose was a full op-phase exchange with no listener bound; Task 2's
   byte-level fake achieves that with zero dependencies, while `usbip`'s
   mandatory `rusb` would enter `cargo clippy --all-targets` and the Windows
   cross-gate. The dependency survives only where its fidelity is actually
   needed — driving a real guest kernel in the KVM e2e (Task 9).
2. **No `/dev/ttyACM0` symlink inside the container.** The OCI runtime spec has
   no symlink primitive and the container's `/dev` is a private tmpfs izba does
   not own, so the honest surface is `/dev/izba/ttyACM0`. Documented rather
   than faked.

**Placeholders.** None: every step carries the actual test or code. Task 8's
spike is an experiment with recorded outcomes and a named fallback, not a "TBD".

**Type consistency.** `Attached` is `session::Attached` (host, devid/speed/busid)
and `usb::Attached` (guest, port/node) — different types in different crates,
named for their own domain; the guest one is not on any wire. `refresh` (broker)
is deliberately not `ensure_listening` (egress), because it also unbinds.
`KernelVariant` threads through `ArtifactsFn`, `locate`, `locate_from`, and
`handle_start` with the same spelling throughout.
