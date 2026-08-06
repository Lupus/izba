//! One connection on the USB plane: resolve a label to a device, import it,
//! then splice.
//!
//! The guest sends a `vid:pid` and nothing else. Everything that follows —
//! which busid that names, where the upstream is, the whole USB/IP op phase —
//! happens on this side of the boundary (D1). A guest cannot ask for a device
//! it was not granted, and cannot learn what else the upstream exports.
//!
//! **Two dials, not one.** The USB/IP op phase is strictly one operation per
//! TCP connection: after `OP_REP_IMPORT` the connection carries URBs forever,
//! with no renegotiation path. So [`resolve`] runs against a devlist connection
//! that is then dropped, and [`import`] runs against a fresh one that becomes
//! the URB stream. That same property is what makes splicing safe — a guest
//! cannot smuggle a second import down a spliced connection, because there is
//! no second op phase to smuggle it into.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use izba_proto::usbip::{decode_guest_urb, encode_op_req_import, UsbDeviceRecord, URB_HEADER_LEN};

use crate::usb::grants::UsbGrant;
use crate::usb::inventory::{read_import_reply, UpstreamDevice};

/// What the guest needs in order to hand the socket to `vhci-hcd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub devid: u32,
    pub speed: u32,
    pub busid: String,
}

/// The kernel's device id: bus number in the high half, device number in the
/// low half. `vhci-hcd` takes this verbatim on its `attach` line.
pub fn devid(busnum: u32, devnum: u32) -> u32 {
    (busnum << 16) | (devnum & 0xffff)
}

/// Pick the one device a grant names, out of everything the upstream exports.
///
/// A grant is a `vid:pid`, which the USB/IP wire format cannot make unique — it
/// carries no serial number (F-USB-3). Two identical devices are therefore an
/// honest ambiguity, not a coin flip: refuse, and ask the human to pin a busid.
///
/// A pin is a *disambiguator*, never an identity. It is honored only while the
/// device on that port is still the granted one, because busids are recycled
/// across a replug — trusting a pin on its own would attach whatever was
/// plugged in last.
pub fn resolve(devices: &[UpstreamDevice], grant: &UsbGrant) -> Result<UpstreamDevice> {
    let mut matching: Vec<&UpstreamDevice> =
        devices.iter().filter(|d| d.id == grant.device).collect();
    if let Some(pin) = grant.busid_pin.as_deref() {
        matching.retain(|d| d.busid == pin);
        if matching.is_empty() {
            bail!(
                "no {} on busid {pin} — that port may hold different hardware now; \
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
            "the upstream exports {n} devices with id {} and izba cannot tell them apart \
             (USB/IP carries no serial number) — re-grant with --busid to name one",
            grant.device
        ),
    }
}

/// Import `chosen` on `up`, then re-verify what came back.
///
/// The reply is checked against the **grant**, not merely against the request:
/// asking for a busid and being handed some other device is exactly the case
/// this exists to catch, and it is the last point at which izba can still
/// refuse before the guest's kernel starts driving the thing.
pub fn import<U: Read + Write>(
    up: &mut U,
    chosen: &UpstreamDevice,
    grant: &UsbGrant,
) -> Result<Attached> {
    let req =
        encode_op_req_import(&chosen.busid).map_err(|e| anyhow!("encoding the import: {e}"))?;
    up.write_all(&req).context("sending OP_REQ_IMPORT")?;
    up.flush().ok();
    let rec = read_import_reply(up)?;
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
/// validator; the reverse direction is spliced opaquely (D6 — see
/// `izba_proto::usbip::urb`, which reasons about the asymmetry). The payload is
/// streamed through a fixed buffer, so a header's length field bounds a *copy*,
/// never an allocation.
///
/// Returns `Ok(())` only on a clean end of stream at a header boundary.
/// Anything else is an error and the caller closes both legs: a half-forwarded
/// URB must never reach the upstream's parser, and neither must the bytes
/// following a header izba refused.
pub fn pump_guest_to_upstream<R: Read, W: Write>(mut r: R, mut w: W) -> Result<()> {
    let mut header = [0u8; URB_HEADER_LEN];
    let mut buf = [0u8; 32 * 1024];
    loop {
        match read_full(&mut r, &mut header)? {
            0 => return Ok(()),
            n if n < URB_HEADER_LEN => bail!("truncated URB header ({n} of {URB_HEADER_LEN})"),
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

/// Read until `buf` is full, returning how many bytes arrived. `Ok(0)` is a
/// clean end of stream; anything between 1 and `buf.len() - 1` is a truncation
/// the caller must treat as an error rather than as a smaller message.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::inventory::UpstreamDevice;
    use crate::usb::DeviceId;
    use izba_proto::usbip::{DEVICE_RECORD_LEN, OP_COMMON_LEN, OP_REP_IMPORT, USBIP_VERSION};

    fn dev(busid: &str, vid: u16, pid: u16) -> UpstreamDevice {
        UpstreamDevice {
            busid: busid.into(),
            id: DeviceId { vid, pid },
            description: "/sys/devices/x".into(),
            speed: 3,
        }
    }

    fn grant(vid: u16, pid: u16, pin: Option<&str>) -> UsbGrant {
        UsbGrant {
            device: DeviceId { vid, pid },
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
        // D9: picking one silently would attach hardware the human never
        // pointed at, and they would have no way to tell which.
        let devices = [dev("3-2", 0x0403, 0x6001), dev("3-3", 0x0403, 0x6001)];
        let err = format!(
            "{:#}",
            resolve(&devices, &grant(0x0403, 0x6001, None)).unwrap_err()
        );
        assert!(err.contains("cannot tell them apart"), "{err}");
        assert!(err.contains("--busid"), "name the way out: {err}");
    }

    #[test]
    fn a_busid_pin_disambiguates_and_is_honored() {
        let devices = [dev("3-2", 0x0403, 0x6001), dev("3-3", 0x0403, 0x6001)];
        let got = resolve(&devices, &grant(0x0403, 0x6001, Some("3-3"))).unwrap();
        assert_eq!(got.busid, "3-3");
    }

    #[test]
    fn a_pin_naming_a_port_that_now_holds_other_hardware_is_refused() {
        // F-USB-3: busids are recycled across a replug, so a pin is only ever a
        // disambiguator among devices that already match the granted vid:pid.
        let devices = [dev("3-2", 0x1a86, 0x7523)];
        let err = format!(
            "{:#}",
            resolve(&devices, &grant(0x0403, 0x6001, Some("3-2"))).unwrap_err()
        );
        assert!(err.contains("3-2"), "{err}");
    }

    #[test]
    fn resolving_against_an_empty_upstream_is_a_refusal_not_a_panic() {
        assert!(resolve(&[], &grant(0x0403, 0x6001, None)).is_err());
        assert!(resolve(&[], &grant(0x0403, 0x6001, Some("3-2"))).is_err());
    }

    #[test]
    fn devid_packs_bus_and_device_number() {
        assert_eq!(devid(3, 2), (3 << 16) | 2);
        assert_eq!(devid(1, 1), 0x0001_0001);
    }

    #[test]
    fn import_verifies_the_returned_record_against_the_grant() {
        // A hostile or confused upstream can hand back a different device than
        // the busid asked for; the import is complete only once izbad has
        // re-checked what it actually got.
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = FakeUpstream::new(import_reply("3-2", 0x1a86, 0x7523));
        let err = format!(
            "{:#}",
            import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).unwrap_err()
        );
        assert!(err.contains("1a86:7523"), "name what came back: {err}");
        assert!(err.contains("mismatch"), "{err}");
    }

    #[test]
    fn import_refuses_a_reply_for_a_different_busid() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = FakeUpstream::new(import_reply("9-9", 0x0403, 0x6001));
        let err = format!(
            "{:#}",
            import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).unwrap_err()
        );
        assert!(err.contains("9-9"), "{err}");
    }

    #[test]
    fn a_matching_import_returns_the_devid_and_speed_the_guest_needs() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = FakeUpstream::new(import_reply("3-2", 0x0403, 0x6001));
        let got = import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).unwrap();
        assert_eq!(got.devid, devid(3, 2));
        assert_eq!(got.speed, 2);
        assert_eq!(got.busid, "3-2");
    }

    #[test]
    fn import_sends_exactly_one_op_req_import_naming_the_busid() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut up = FakeUpstream::new(import_reply("3-2", 0x0403, 0x6001));
        import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).unwrap();
        let sent = up.sent;
        assert_eq!(
            sent.len(),
            OP_COMMON_LEN + 32,
            "one import request, no more"
        );
        assert_eq!(&sent[..2], &USBIP_VERSION.to_be_bytes());
        assert!(
            sent[OP_COMMON_LEN..].starts_with(b"3-2\0"),
            "the busid must be the one resolve chose: {sent:?}"
        );
    }

    #[test]
    fn an_import_reply_that_is_truncated_is_an_error() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut short = import_reply("3-2", 0x0403, 0x6001);
        short.truncate(short.len() - 1);
        let mut up = FakeUpstream::new(short);
        assert!(import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).is_err());
    }

    #[test]
    fn an_import_carrying_a_failure_status_is_refused() {
        let chosen = dev("3-2", 0x0403, 0x6001);
        let mut reply = import_reply("3-2", 0x0403, 0x6001);
        reply[4..8].copy_from_slice(&1u32.to_be_bytes());
        let mut up = FakeUpstream::new(reply);
        assert!(import(&mut up, &chosen, &grant(0x0403, 0x6001, None)).is_err());
    }

    #[test]
    fn the_pump_forwards_a_well_formed_stream_byte_identically() {
        let mut wire = submit_out(1, &[0xde, 0xad, 0xbe, 0xef]);
        wire.extend_from_slice(&submit_in(2, 64));
        wire.extend_from_slice(&unlink(3));
        let mut out = Vec::new();
        pump_guest_to_upstream(std::io::Cursor::new(wire.clone()), &mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn the_pump_refuses_a_guest_impersonating_the_server() {
        // RET_SUBMIT travels upstream→guest. A guest sending one is either
        // confused or probing; either way nothing reaches usbipd.
        let mut header = [0u8; URB_HEADER_LEN];
        header[..4].copy_from_slice(&3u32.to_be_bytes());
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(header.to_vec()), &mut out).is_err());
        assert!(out.is_empty(), "nothing reaches the host service");
    }

    #[test]
    fn the_pump_stops_at_an_oversized_transfer_without_forwarding_it() {
        // CVE-2016-3955 shape: a length field with no protocol maximum. The cap
        // must be applied before the header is forwarded, not after.
        let mut header = [0u8; URB_HEADER_LEN];
        header[..4].copy_from_slice(&1u32.to_be_bytes());
        header[24..28].copy_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());
        header[32..36].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(header.to_vec()), &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn a_rejected_header_stops_the_stream_rather_than_resynchronising() {
        // The bytes after a refused header are not a new message: they are the
        // rest of one izba declined to understand. Forwarding past them would
        // hand usbipd a frame boundary chosen by the guest.
        let mut wire = submit_out(1, &[1, 2, 3, 4]);
        let mut bad = [0u8; URB_HEADER_LEN];
        bad[..4].copy_from_slice(&99u32.to_be_bytes());
        wire.extend_from_slice(&bad);
        wire.extend_from_slice(&submit_out(2, &[5, 6, 7, 8]));
        let mut out = Vec::new();
        assert!(pump_guest_to_upstream(std::io::Cursor::new(wire), &mut out).is_err());
        assert_eq!(
            out.len(),
            URB_HEADER_LEN + 4,
            "only the first, valid URB got through"
        );
    }

    #[test]
    fn a_payload_larger_than_the_copy_buffer_is_streamed_whole() {
        // The buffer is 32 KiB and the cap is 1 MiB, so the multi-chunk path is
        // the normal one for a bulk transfer, not an edge case.
        let payload = vec![0x5au8; 100_000];
        let wire = submit_out(1, &payload);
        let mut out = Vec::new();
        pump_guest_to_upstream(std::io::Cursor::new(wire.clone()), &mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn a_clean_eof_between_urbs_ends_the_pump_without_an_error() {
        let mut out = Vec::new();
        pump_guest_to_upstream(std::io::Cursor::new(Vec::new()), &mut out).unwrap();
        pump_guest_to_upstream(std::io::Cursor::new(submit_out(1, &[1, 2, 3])), &mut out).unwrap();
    }

    #[test]
    fn a_truncated_header_or_payload_is_an_error_not_a_short_forward() {
        for cut in [1usize, 8, URB_HEADER_LEN - 1, URB_HEADER_LEN + 2] {
            let mut wire = submit_out(1, &[1, 2, 3, 4]);
            wire.truncate(cut);
            let mut out = Vec::new();
            assert!(
                pump_guest_to_upstream(std::io::Cursor::new(wire), &mut out).is_err(),
                "a stream cut at {cut} must not pass"
            );
        }
    }

    /// A `Read + Write` upstream that records what was written and replays a
    /// canned reply. `import` must not depend on anything it wrote coming back.
    struct FakeUpstream {
        reply: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl FakeUpstream {
        fn new(reply: Vec<u8>) -> Self {
            Self {
                reply: std::io::Cursor::new(reply),
                sent: Vec::new(),
            }
        }
    }

    impl Read for FakeUpstream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }

    impl Write for FakeUpstream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Build a real `OP_REP_IMPORT` from the phase-1 constants, so these tests
    /// pin the wire format rather than the implementation's idea of it.
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
        out
    }

    fn urb_header(command: u32, seqnum: u32, direction: u32, len: u32) -> [u8; URB_HEADER_LEN] {
        let mut h = [0u8; URB_HEADER_LEN];
        h[..4].copy_from_slice(&command.to_be_bytes());
        h[4..8].copy_from_slice(&seqnum.to_be_bytes());
        h[12..16].copy_from_slice(&direction.to_be_bytes());
        h[16..20].copy_from_slice(&1u32.to_be_bytes()); // endpoint 1
        h[24..28].copy_from_slice(&len.to_be_bytes());
        h[32..36].copy_from_slice(&0xffff_ffffu32.to_be_bytes()); // not isochronous
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

    fn unlink(seqnum: u32) -> Vec<u8> {
        urb_header(2, seqnum, 0, 0).to_vec()
    }
}
