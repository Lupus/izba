# USB passthrough — Phase 1: egress floor + USB/IP codec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F-USB-1 (a sandbox reaching a usbip upstream over the generic
egress plane) and land the fuzzable USB/IP wire codec that the broker will use.

**Architecture:** Two independent, purely host-side units. A `usbip_guard` pure
function extends the egress hard floor so no *enforcing* sandbox and no
*USB-enabled* sandbox can reach a usbip upstream, while a bare non-USB sandbox
keeps today's LAN behaviour. A new `izba-proto/src/usbip/` module decodes the
USB/IP op phase and URB headers with hard caps applied before any allocation.

**Tech Stack:** Rust (workspace crates `izba-proto`, `izba-core`), `cargo-fuzz`
smoke targets, `proptest`.

## Global Constraints

- All six workspace gates must be green before any commit: `cargo test
  --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo
  fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl
  --release`, and the two `x86_64-pc-windows-gnu` cross gates for
  `izba-proto`/`izba-core`/`izba-cli`.
- `source .cargo-env` first if that file exists.
- Unit tests never bind unix/vsock listeners — use `UnixStream::pair()` fakes.
- USB/IP wire fields are **big-endian**, unlike izba's own u32-LE frames.
- Protocol version is exactly `0x0111`; reject anything else.
- Caps, applied **before** allocation: devlist device count ≤ 256, total devlist
  reply ≤ 256 KiB, `transfer_buffer_length` ≤ 1 MiB, `number_of_packets` ≤ 1024,
  `busid`/`path` NUL-terminated within their fixed arrays.
- No new runtime dependencies. `jiegec/usbip` is dev-only and arrives in Phase 3.
- Conventional commits (`feat(core):`, `fix(core):`, `feat(proto):`).

---

### Task 1: USB/IP op-phase codec

**Files:**
- Create: `crates/izba-proto/src/usbip/mod.rs`
- Create: `crates/izba-proto/src/usbip/op.rs`
- Modify: `crates/izba-proto/src/lib.rs` (add `pub mod usbip;`)

**Interfaces:**
- Produces:
  - `pub const USBIP_VERSION: u16 = 0x0111;`
  - `pub const OP_REQ_DEVLIST: u16 = 0x8005;` / `OP_REP_DEVLIST: u16 = 0x0005;`
  - `pub const OP_REQ_IMPORT: u16 = 0x8003;` / `OP_REP_IMPORT: u16 = 0x0003;`
  - `pub struct UsbDeviceRecord { pub path: String, pub busid: String, pub busnum: u32, pub devnum: u32, pub speed: u32, pub id_vendor: u16, pub id_product: u16, pub bcd_device: u16, pub b_device_class: u8, pub b_device_subclass: u8, pub b_device_protocol: u8, pub b_configuration_value: u8, pub b_num_configurations: u8, pub b_num_interfaces: u8 }`
  - `pub fn encode_op_req_devlist() -> [u8; 8]`
  - `pub fn encode_op_req_import(busid: &str) -> Result<[u8; 40], UsbipError>`
  - `pub fn decode_op_rep_devlist(buf: &[u8]) -> Result<Vec<UsbDeviceRecord>, UsbipError>`
  - `pub fn decode_op_rep_import(buf: &[u8]) -> Result<UsbDeviceRecord, UsbipError>`
  - `pub enum UsbipError { BadVersion(u16), BadCode(u16), Status(u32), Truncated, TooLarge(&'static str), BadString(&'static str) }` implementing `std::error::Error`.

- [ ] **Step 1: Write the failing tests**

In `crates/izba-proto/src/usbip/op.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 312-byte device record for tests.
    fn record_bytes(busid: &str, vid: u16, pid: u16, n_iface: u8) -> Vec<u8> {
        let mut b = vec![0u8; 312];
        b[..busid.len().min(255)].copy_from_slice(busid.as_bytes()); // path
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        b[0x120..0x124].copy_from_slice(&3u32.to_be_bytes()); // busnum
        b[0x124..0x128].copy_from_slice(&2u32.to_be_bytes()); // devnum
        b[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes()); // speed = FULL
        b[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        b[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        b[0x137] = n_iface;
        b
    }

    fn rep_devlist(records: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        b.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // status OK
        b.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            b.extend_from_slice(r);
            let n_iface = r[0x137] as usize;
            b.extend(std::iter::repeat(0u8).take(n_iface * 4));
        }
        b
    }

    #[test]
    fn req_import_encodes_version_code_and_nul_padded_busid() {
        let f = encode_op_req_import("3-2").unwrap();
        assert_eq!(u16::from_be_bytes([f[0], f[1]]), USBIP_VERSION);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]), OP_REQ_IMPORT);
        assert_eq!(u32::from_be_bytes([f[4], f[5], f[6], f[7]]), 0);
        assert_eq!(&f[8..11], b"3-2");
        assert!(f[11..].iter().all(|&b| b == 0), "busid must be NUL-padded");
    }

    #[test]
    fn req_import_rejects_oversized_busid() {
        let err = encode_op_req_import(&"x".repeat(32)).unwrap_err();
        assert!(matches!(err, UsbipError::BadString(_)), "{err:?}");
    }

    #[test]
    fn rep_devlist_decodes_records_and_skips_interface_blocks() {
        let buf = rep_devlist(&[
            record_bytes("3-2", 0x0403, 0x6001, 1),
            record_bytes("3-4", 0x10c4, 0xea60, 2),
        ]);
        let devs = decode_op_rep_devlist(&buf).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].busid, "3-2");
        assert_eq!(devs[0].id_vendor, 0x0403);
        assert_eq!(devs[0].id_product, 0x6001);
        assert_eq!(devs[1].busid, "3-4");
        assert_eq!(devs[1].id_vendor, 0x10c4);
        assert_eq!(devs[1].speed, 2);
    }

    #[test]
    fn rep_devlist_rejects_wrong_version() {
        let mut buf = rep_devlist(&[record_bytes("3-2", 1, 2, 0)]);
        buf[0..2].copy_from_slice(&0x0110u16.to_be_bytes());
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::BadVersion(0x0110)
        ));
    }

    #[test]
    fn rep_devlist_rejects_nonzero_status() {
        let mut buf = rep_devlist(&[]);
        buf[4..8].copy_from_slice(&4u32.to_be_bytes()); // ST_NODEV
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::Status(4)
        ));
    }

    /// An attacker-controlled count must be rejected before any allocation.
    #[test]
    fn rep_devlist_rejects_absurd_device_count() {
        let mut buf = rep_devlist(&[]);
        buf[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::TooLarge(_)
        ));
    }

    #[test]
    fn rep_devlist_rejects_truncated_record() {
        let mut buf = rep_devlist(&[record_bytes("3-2", 1, 2, 0)]);
        buf.truncate(buf.len() - 10);
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::Truncated
        ));
    }

    /// A hostile server may fill busid[32] with no NUL terminator.
    #[test]
    fn rep_devlist_rejects_unterminated_busid() {
        let mut rec = record_bytes("3-2", 1, 2, 0);
        for b in rec[0x100..0x120].iter_mut() {
            *b = b'A';
        }
        let buf = rep_devlist(&[rec]);
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::BadString(_)
        ));
    }

    #[test]
    fn rep_import_decodes_and_reports_status_failure() {
        let mut b = Vec::new();
        b.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        b.extend_from_slice(&OP_REP_IMPORT.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        let mut rec = vec![0u8; 312];
        rec[0x108..0x10B].copy_from_slice(b"3-2"); // busid at +8 in the import layout
        rec[0x128..0x12C].copy_from_slice(&3u32.to_be_bytes()); // busnum
        rec[0x12C..0x130].copy_from_slice(&2u32.to_be_bytes()); // devnum
        rec[0x130..0x134].copy_from_slice(&2u32.to_be_bytes()); // speed
        rec[0x134..0x136].copy_from_slice(&0x0403u16.to_be_bytes());
        rec[0x136..0x138].copy_from_slice(&0x6001u16.to_be_bytes());
        b.extend_from_slice(&rec[8..]);
        let dev = decode_op_rep_import(&b).unwrap();
        assert_eq!(dev.busid, "3-2");
        assert_eq!(dev.id_vendor, 0x0403);
        assert_eq!(dev.busnum, 3);
        assert_eq!(dev.devnum, 2);

        let mut deny = b[..8].to_vec();
        deny[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            decode_op_rep_import(&deny).unwrap_err(),
            UsbipError::Status(1)
        ));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-proto usbip`
Expected: FAIL — the `usbip` module does not exist.

- [ ] **Step 3: Implement the codec**

Write `op.rs` with the constants, `UsbipError`, `UsbDeviceRecord`, and the four
functions. Implementation rules:
- Every multi-byte read is `u16::from_be_bytes` / `u32::from_be_bytes` over an
  explicitly bounds-checked slice; return `UsbipError::Truncated` rather than
  indexing past the end.
- `decode_op_rep_devlist` validates version, code, and status from the 8-byte
  `op_common`, then reads the u32 count and rejects `count > 256` **and**
  `buf.len() > 256 * 1024` with `TooLarge` before allocating the `Vec`.
- Per record: require 312 bytes remain, parse fields at the offsets used by the
  tests, then require `b_num_interfaces as usize * 4` further bytes and skip
  them, using `checked_add`/`checked_mul` for every offset advance.
- A fixed-array string is decoded by finding the first NUL; absence of a NUL
  within the array, or any byte outside printable ASCII, is
  `BadString("busid")` / `BadString("path")`.
- `decode_op_rep_import` shares the `op_common` validation, then parses the
  import record layout (busid at offset `0x108` absolute, busnum `0x128`,
  devnum `0x12C`, speed `0x130`, vid `0x134`, pid `0x136`).
- `encode_op_req_import` rejects a busid of 32 bytes or longer (no room for the
  NUL) with `BadString("busid")`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-proto usbip`
Expected: PASS, all 9 tests.

- [ ] **Step 5: Run the gates and commit**

```bash
cargo fmt && cargo clippy -p izba-proto --all-targets -- -D warnings && cargo test -p izba-proto
git add crates/izba-proto/src/usbip/ crates/izba-proto/src/lib.rs
git commit -m "feat(proto): USB/IP op-phase codec with pre-allocation caps"
```

---

### Task 2: URB header decoding for the guest→upstream leg

**Files:**
- Create: `crates/izba-proto/src/usbip/urb.rs`
- Modify: `crates/izba-proto/src/usbip/mod.rs` (add `pub mod urb;`)

**Interfaces:**
- Consumes: `UsbipError` from Task 1.
- Produces:
  - `pub const USBIP_CMD_SUBMIT: u32 = 1;` / `USBIP_CMD_UNLINK: u32 = 2;` /
    `USBIP_RET_SUBMIT: u32 = 3;` / `USBIP_RET_UNLINK: u32 = 4;`
  - `pub const URB_HEADER_LEN: usize = 48;`
  - `pub const MAX_TRANSFER_BUFFER: u32 = 1024 * 1024;`
  - `pub const MAX_ISO_PACKETS: u32 = 1024;`
  - `pub struct GuestUrb { pub command: u32, pub seqnum: u32, pub direction: u32, pub ep: u32, pub payload_len: usize }`
  - `pub fn decode_guest_urb(header: &[u8; 48]) -> Result<GuestUrb, UsbipError>`

`decode_guest_urb` is the D6 validator: it accepts **only** frames a client may
send, and computes exactly how many payload bytes follow the header, so the
broker can stream them through a bounded copy without ever sizing a buffer from
an attacker-controlled length.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn submit(direction: u32, ep: u32, len: u32, n_iso: u32) -> [u8; 48] {
        let mut h = [0u8; 48];
        h[0..4].copy_from_slice(&USBIP_CMD_SUBMIT.to_be_bytes());
        h[4..8].copy_from_slice(&7u32.to_be_bytes()); // seqnum
        h[12..16].copy_from_slice(&direction.to_be_bytes());
        h[16..20].copy_from_slice(&ep.to_be_bytes());
        h[24..28].copy_from_slice(&len.to_be_bytes());
        h[32..36].copy_from_slice(&n_iso.to_be_bytes());
        h
    }

    #[test]
    fn out_transfer_payload_is_the_buffer() {
        let u = decode_guest_urb(&submit(0, 2, 512, 0xffff_ffff)).unwrap();
        assert_eq!(u.command, USBIP_CMD_SUBMIT);
        assert_eq!(u.seqnum, 7);
        assert_eq!(u.payload_len, 512, "OUT carries its transfer buffer");
    }

    #[test]
    fn in_transfer_has_no_payload() {
        let u = decode_guest_urb(&submit(1, 2, 512, 0xffff_ffff)).unwrap();
        assert_eq!(u.payload_len, 0, "IN requests carry no buffer");
    }

    #[test]
    fn iso_adds_sixteen_bytes_per_packet_in_both_directions() {
        let out = decode_guest_urb(&submit(0, 1, 64, 4)).unwrap();
        assert_eq!(out.payload_len, 64 + 4 * 16);
        let inb = decode_guest_urb(&submit(1, 1, 64, 4)).unwrap();
        assert_eq!(inb.payload_len, 4 * 16);
    }

    #[test]
    fn unlink_is_header_only() {
        let mut h = [0u8; 48];
        h[0..4].copy_from_slice(&USBIP_CMD_UNLINK.to_be_bytes());
        assert_eq!(decode_guest_urb(&h).unwrap().payload_len, 0);
    }

    /// A guest sending a server-side reply code is a protocol violation.
    #[test]
    fn guest_may_not_send_reply_commands() {
        for cmd in [USBIP_RET_SUBMIT, USBIP_RET_UNLINK, 0, 99] {
            let mut h = [0u8; 48];
            h[0..4].copy_from_slice(&cmd.to_be_bytes());
            assert!(
                matches!(decode_guest_urb(&h).unwrap_err(), UsbipError::BadCode(_)),
                "command {cmd} must be rejected"
            );
        }
    }

    #[test]
    fn oversized_transfer_buffer_is_rejected() {
        let err = decode_guest_urb(&submit(0, 1, MAX_TRANSFER_BUFFER + 1, 0xffff_ffff)).unwrap_err();
        assert!(matches!(err, UsbipError::TooLarge(_)), "{err:?}");
    }

    #[test]
    fn absurd_iso_packet_count_is_rejected() {
        let err = decode_guest_urb(&submit(0, 1, 64, MAX_ISO_PACKETS + 1)).unwrap_err();
        assert!(matches!(err, UsbipError::TooLarge(_)), "{err:?}");
    }

    #[test]
    fn out_of_range_endpoint_and_direction_are_rejected() {
        assert!(decode_guest_urb(&submit(0, 16, 8, 0xffff_ffff)).is_err());
        assert!(decode_guest_urb(&submit(2, 1, 8, 0xffff_ffff)).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-proto urb`
Expected: FAIL — `decode_guest_urb` not found.

- [ ] **Step 3: Implement**

Parse `command`, `seqnum`, `direction`, `ep` from the basic header;
`transfer_buffer_length` at offset 24 and `number_of_packets` at offset 32.
Treat `number_of_packets == 0xffff_ffff` as "not isochronous" (the protocol's
sentinel). Reject any command other than `USBIP_CMD_SUBMIT`/`USBIP_CMD_UNLINK`
with `BadCode`, `direction > 1` or `ep > 15` with `BadCode`,
`transfer_buffer_length > MAX_TRANSFER_BUFFER` and a non-sentinel
`number_of_packets > MAX_ISO_PACKETS` with `TooLarge`. `payload_len` =
(`direction == 0` ? `transfer_buffer_length` : 0) + (iso ? `n * 16` : 0),
computed with `checked_add`/`checked_mul`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-proto urb`
Expected: PASS, all 8 tests.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -p izba-proto --all-targets -- -D warnings
git add crates/izba-proto/src/usbip/
git commit -m "feat(proto): bounded USB/IP URB header validation for the guest leg"
```

---

### Task 3: Fuzz target for the op-phase parser

**Files:**
- Create: `crates/izba-proto/fuzz/fuzz_targets/usbip_op.rs`
- Modify: `crates/izba-proto/fuzz/Cargo.toml` (add the `[[bin]]` entry)
- Modify: `.github/workflows/ci.yml` (add one line to the `fuzz-smoke` job)

**Interfaces:**
- Consumes: `decode_op_rep_devlist`, `decode_op_rep_import` from Task 1.

- [ ] **Step 1: Write the target**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both decoders take untrusted upstream bytes; neither may panic, and
    // neither may allocate proportionally to an attacker-chosen count.
    let _ = izba_proto::usbip::op::decode_op_rep_devlist(data);
    let _ = izba_proto::usbip::op::decode_op_rep_import(data);
});
```

- [ ] **Step 2: Register the binary**

Copy the existing `[[bin]]` stanza shape from the `frame` target in
`crates/izba-proto/fuzz/Cargo.toml`, changing `name` and `path` to `usbip_op`.

- [ ] **Step 3: Run it briefly to verify it builds and finds nothing**

Run: `cargo +nightly fuzz run usbip_op --target x86_64-unknown-linux-gnu -- -max_total_time=45`
Expected: completes with no crash. If it crashes, fix the decoder — a panic here
is exactly the bug class this task exists to catch.

- [ ] **Step 4: Wire it into CI**

In `.github/workflows/ci.yml`, add a line to the `fuzz-smoke` job mirroring the
existing `frame`/`dns` invocations, with `-max_total_time=45`.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-proto/fuzz .github/workflows/ci.yml
git commit -m "test(proto): fuzz the USB/IP op-phase decoder in the smoke job"
```

---

### Task 4: The usbip egress guard (F-USB-1)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (new `usbip_guard`,
  threaded into `decide_tier2` at `:263` and the pre-tier-1 floor at `:99`)
- Test: same file's `mod tests`

**Interfaces:**
- Produces:
  - `pub const USBIP_PORT: u16 = 3240;`
  - `#[derive(Clone, Copy, Debug, Default)] pub struct UsbGuard { pub sandbox_usb_enabled: bool, pub upstream: Option<(IpAddr, u16)> }`
  - `pub fn usbip_guard(guard: UsbGuard, enforcing: bool, ip: IpAddr, port: u16) -> Option<&'static str>`
  - `decide_tier2` gains a trailing `guard: UsbGuard` parameter.
- Consumes: nothing from Tasks 1–3 (independent).

Semantics, exactly as approved:

| sandbox | port 3240 (any address) | configured upstream address+port | other |
|---|---|---|---|
| enforcing | **Deny** (non-overridable) | **Deny** | unchanged |
| bare + USB-enabled | **Deny** | **Deny** | unchanged (LAN allowed) |
| bare, no USB | unchanged | unchanged | unchanged |

- [ ] **Step 1: Write the failing tests**

```rust
    /// F-USB-1: an ENFORCING sandbox must never reach a usbip upstream, even
    /// when its policy explicitly lists that IP for other purposes.
    #[test]
    fn enforcing_sandbox_cannot_reach_usbip_port_even_if_ip_is_allowed() {
        let snoop = SnoopStore::new();
        let data = r#"{"host_rules": {"10.1.0.124": {"ports": [3240, 8080], "access": "read-write"}}, "sandbox_host_rules": {}, "sandbox_git_rules": {}}"#;
        let p = RegoPolicy::with_data(data).unwrap();
        let ip: IpAddr = "10.1.0.124".parse().unwrap();

        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 3240, UsbGuard::default());
        assert_eq!(v, Verdict::Deny, "policy must not be able to open 3240");
        assert!(rule.contains("usbip"), "{rule}");

        // The same host on another port is still governed by policy alone.
        let (v, _f, _) = decide_tier2(&p, &snoop, "web", ip, 8080, UsbGuard::default());
        assert_eq!(v, Verdict::Allow);
    }

    /// A USB-enabled sandbox must not be able to bypass the device allowlist by
    /// talking to a usbip server itself — bare or not.
    #[test]
    fn usb_enabled_bare_sandbox_cannot_reach_usbip_port() {
        let snoop = SnoopStore::new();
        let guard = UsbGuard { sandbox_usb_enabled: true, upstream: None };
        let (v, _f, rule) =
            decide_tier2(&AllowAll, &snoop, "web", "192.168.1.50".parse().unwrap(), 3240, guard);
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("usbip"), "{rule}");
    }

    /// The configured upstream is denied on ITS port too, since a usbipd may be
    /// configured to listen somewhere other than 3240.
    #[test]
    fn configured_upstream_endpoint_is_denied_on_its_own_port() {
        let snoop = SnoopStore::new();
        let up: IpAddr = "172.30.96.1".parse().unwrap();
        let guard = UsbGuard { sandbox_usb_enabled: true, upstream: Some((up, 4000)) };
        let (v, _f, rule) = decide_tier2(&AllowAll, &snoop, "web", up, 4000, guard);
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("usbip"), "{rule}");

        // A different port on the same host is not implicated.
        let (v, _f, _) = decide_tier2(&AllowAll, &snoop, "web", up, 4001, guard);
        assert_eq!(v, Verdict::Allow);
    }

    /// The approved carve-out: a bare, non-USB sandbox keeps today's permissive
    /// LAN behaviour. It has no vhci-hcd, so a usbip connection is inert.
    #[test]
    fn bare_non_usb_sandbox_keeps_lan_access_on_3240() {
        let snoop = SnoopStore::new();
        let (v, _f, rule) = decide_tier2(
            &AllowAll,
            &snoop,
            "web",
            "192.168.1.50".parse().unwrap(),
            3240,
            UsbGuard::default(),
        );
        assert_eq!(v, Verdict::Allow, "bare non-USB sandbox is unchanged");
        assert_eq!(rule, "permissive");
    }

    /// The guard canonicalises IPv6-embedded IPv4 the same way the SSRF floor
    /// does, so a mapped form cannot slip past it.
    #[test]
    fn guard_canonicalises_ipv4_mapped_upstream() {
        let guard = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: Some(("172.30.96.1".parse().unwrap(), 3240)),
        };
        let mapped: IpAddr = "::ffff:172.30.96.1".parse().unwrap();
        assert!(usbip_guard(guard, false, mapped, 3240).is_some());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core usbip`
Expected: FAIL — `UsbGuard` not found, and `decide_tier2` takes 5 arguments.

- [ ] **Step 3: Implement**

Add `USBIP_PORT`, `UsbGuard`, and:

```rust
/// F-USB-1 floor: a sandbox must never reach a usbip upstream over the generic
/// egress plane, because that would import a device without passing the
/// per-device allowlist izbad enforces on the USB plane.
///
/// Applies to every ENFORCING sandbox (no policy rule may open it) and to every
/// USB-ENABLED sandbox. A bare sandbox with no USB grants is deliberately
/// unaffected: LAN is permissive by design there, and its kernel has no
/// `vhci-hcd`, so an imported device has nothing to attach to.
pub fn usbip_guard(
    guard: UsbGuard,
    enforcing: bool,
    ip: IpAddr,
    port: u16,
) -> Option<&'static str> {
    if !enforcing && !guard.sandbox_usb_enabled {
        return None;
    }
    let ip = canonical(ip); // reuse embedded_v4 like is_hard_denied/is_lan do
    if port == USBIP_PORT {
        return Some("usbip upstream (port 3240) is never reachable from a sandbox");
    }
    if let Some((up_ip, up_port)) = guard.upstream {
        if port == up_port && canonical(up_ip) == ip {
            return Some("configured usbip upstream is never reachable from a sandbox");
        }
    }
    None
}
```

Add a small `fn canonical(ip: IpAddr) -> IpAddr` that maps an IPv6-embedded
IPv4 to its v4 form via the existing `embedded_v4` helper, and returns `ip`
otherwise. Call `usbip_guard` in `decide_tier2` immediately after the
`is_hard_denied` check, returning `(Verdict::Deny, flow, reason)`. Thread
`UsbGuard` through `handle_conn`'s pre-tier-1 floor at `router.rs:99` the same
way, so the guard also covers the tier-1 path. For now `handle_conn` builds
`UsbGuard::default()`; Phase 2 populates it from the sandbox's grants and the
configured upstream.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core egress`
Expected: PASS — including the pre-existing floor and LAN tests, which must be
updated only by adding the new trailing argument, never by changing an assertion.

- [ ] **Step 5: Full gates and commit**

```bash
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add crates/izba-core/src/daemon/egress/router.rs
git commit -m "fix(core): never let an enforcing or USB-enabled sandbox reach a usbip upstream"
```

---

### Task 5: Document the guard in the security register

**Files:**
- Modify: `docs/security/README.md` (findings register: add F-USB-1 as fixed)
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (module doc mention)

- [ ] **Step 1: Add the register entry**

Add F-USB-1 to the findings table with severity HIGH, status "fixed (Phase 1)",
and a one-line statement of the carve-out: a bare sandbox with no USB grants
retains LAN access on 3240 by design, and is inert because its kernel ships no
`vhci-hcd`.

- [ ] **Step 2: Commit**

```bash
git add docs/security/README.md crates/izba-core/src/daemon/egress/router.rs
git commit -m "docs(security): register F-USB-1 and its approved carve-out"
```

---

## Follow-on plans

Phase 1 stops at a shippable boundary: the bypass is closed and the codec is
fuzzed, with no proto bump, no kernel change, and no new surface. Subsequent
phases each get their own plan document when reached:

- **Phase 2 — broker + control plane:** `daemon/usb/` (settings, trust
  classifier, session, inventory), `DAEMON_PROTO_VERSION` 2 → 3, the daemon
  RPCs, and the `izba usb` CLI. Populates the `UsbGuard` that Phase 1 leaves
  defaulted.
- **Phase 3 — datapath:** `vmlinux-usb` kernel artifact + `artifacts.rs`
  variant, `izba-init/src/usb.rs`, the container device-visibility spike and
  implementation, `fake_usbipd`, and the KVM e2e suite.
- **Phase 4 — desktop app:** `DaemonApi` methods, `FakeDaemon`, the USB panel,
  and the copy-the-command affordance for unbound devices.
