//! The USB/IP "op" phase: device listing and device import.
//!
//! Exactly ONE op exchange happens per TCP connection. After a successful
//! `OP_REP_IMPORT` the connection carries URB traffic forever, with no path
//! back to the op phase and no way to import a second device. That invariant is
//! what lets izbad gate on import and then splice bytes: every further import
//! attempt needs a NEW connection, which passes the allowlist gate again.

use std::fmt;

/// Protocol version 1.1.1. Peers that send anything else are rejected outright
/// (usbipd-win is equally strict in the other direction).
pub const USBIP_VERSION: u16 = 0x0111;

pub const OP_REQ_DEVLIST: u16 = 0x8005;
pub const OP_REP_DEVLIST: u16 = 0x0005;
pub const OP_REQ_IMPORT: u16 = 0x8003;
pub const OP_REP_IMPORT: u16 = 0x0003;

/// `op_common`: version, code, status.
const OP_COMMON_LEN: usize = 8;
/// A device record in `OP_REP_DEVLIST` (interface descriptors follow it).
const DEVICE_RECORD_LEN: usize = 0x138;
const BUSID_LEN: usize = 32;
const PATH_LEN: usize = 256;
/// Bytes per interface descriptor tuple appended to a devlist record.
const INTERFACE_LEN: usize = 4;

/// Upper bound on devices in one `OP_REP_DEVLIST`, applied before allocating.
const MAX_DEVICES: u32 = 256;
/// Upper bound on a whole devlist reply, applied before allocating.
const MAX_DEVLIST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbipError {
    /// Peer announced a protocol version izba does not speak.
    BadVersion(u16),
    /// Unexpected opcode, command, or out-of-range header field.
    BadCode(u16),
    /// The peer reported a non-zero status (1 = NA, 2 = busy, 3 = dev error,
    /// 4 = no such device, 5 = other).
    Status(u32),
    /// The buffer ended before a declared field did.
    Truncated,
    /// A length or count exceeded its cap. Rejected BEFORE allocating.
    TooLarge(&'static str),
    /// A fixed-size string field was unterminated or not printable ASCII.
    BadString(&'static str),
}

impl fmt::Display for UsbipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadVersion(v) => write!(f, "unsupported usbip version {v:#06x} (want 0x0111)"),
            Self::BadCode(c) => write!(f, "unexpected usbip code/field {c:#06x}"),
            Self::Status(s) => write!(f, "usbip peer reported status {s}"),
            Self::Truncated => write!(f, "truncated usbip message"),
            Self::TooLarge(what) => write!(f, "usbip {what} exceeds its cap"),
            Self::BadString(what) => write!(f, "malformed usbip {what} string"),
        }
    }
}

impl std::error::Error for UsbipError {}

/// One device as reported by the upstream server.
///
/// Every field here is **asserted by the server and the device**, never
/// verified by izba. There is deliberately no serial number: the USB/IP wire
/// format does not carry one (it is a string descriptor, fetched separately).
/// See F-USB-3 — the allowlist is a human-intent filter, not proof of
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsbDeviceRecord {
    pub path: String,
    pub busid: String,
    pub busnum: u32,
    pub devnum: u32,
    pub speed: u32,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub b_device_class: u8,
    pub b_device_subclass: u8,
    pub b_device_protocol: u8,
    pub b_configuration_value: u8,
    pub b_num_configurations: u8,
    pub b_num_interfaces: u8,
}

/// Cursor over a peer-supplied buffer. Every read is bounds-checked; nothing
/// here can panic on a hostile input.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], UsbipError> {
        let end = self.pos.checked_add(n).ok_or(UsbipError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(UsbipError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, UsbipError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, UsbipError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, UsbipError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Decode a NUL-terminated fixed-size string field.
    ///
    /// A hostile server may fill the whole array with no terminator, or embed
    /// control characters that would corrupt logs downstream; both are refused
    /// rather than sanitised, so the value can never be used as a path, a
    /// format argument, or a log field unescaped.
    fn fixed_str(&mut self, n: usize, what: &'static str) -> Result<String, UsbipError> {
        let raw = self.take(n)?;
        let end = raw
            .iter()
            .position(|&b| b == 0)
            .ok_or(UsbipError::BadString(what))?;
        let s = &raw[..end];
        if !s.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Err(UsbipError::BadString(what));
        }
        // Printable ASCII is valid UTF-8 by construction.
        Ok(String::from_utf8_lossy(s).into_owned())
    }
}

/// Validate the 8-byte `op_common` prefix of a reply.
fn read_op_common(r: &mut Reader<'_>, expect_code: u16) -> Result<(), UsbipError> {
    let version = r.u16()?;
    if version != USBIP_VERSION {
        return Err(UsbipError::BadVersion(version));
    }
    let code = r.u16()?;
    if code != expect_code {
        return Err(UsbipError::BadCode(code));
    }
    let status = r.u32()?;
    if status != 0 {
        return Err(UsbipError::Status(status));
    }
    Ok(())
}

fn encode_op_common(code: u16) -> [u8; OP_COMMON_LEN] {
    let mut out = [0u8; OP_COMMON_LEN];
    out[0..2].copy_from_slice(&USBIP_VERSION.to_be_bytes());
    out[2..4].copy_from_slice(&code.to_be_bytes());
    // status is zero in a request
    out
}

/// `OP_REQ_DEVLIST` — ask the upstream to enumerate its exported devices.
pub fn encode_op_req_devlist() -> [u8; OP_COMMON_LEN] {
    encode_op_common(OP_REQ_DEVLIST)
}

/// `OP_REQ_IMPORT` — ask the upstream to hand over one device by busid.
pub fn encode_op_req_import(busid: &str) -> Result<[u8; OP_COMMON_LEN + BUSID_LEN], UsbipError> {
    // The field is NUL-terminated, so a 32-byte busid has no room for the
    // terminator and is refused rather than silently truncated.
    if busid.len() >= BUSID_LEN || !busid.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(UsbipError::BadString("busid"));
    }
    let mut out = [0u8; OP_COMMON_LEN + BUSID_LEN];
    out[..OP_COMMON_LEN].copy_from_slice(&encode_op_common(OP_REQ_IMPORT));
    out[OP_COMMON_LEN..OP_COMMON_LEN + busid.len()].copy_from_slice(busid.as_bytes());
    Ok(out)
}

/// Decode `OP_REP_DEVLIST`.
///
/// The device count and the per-record interface count are attacker-controlled,
/// so both the count and the total reply size are bounded before anything is
/// allocated.
pub fn decode_op_rep_devlist(buf: &[u8]) -> Result<Vec<UsbDeviceRecord>, UsbipError> {
    if buf.len() > MAX_DEVLIST_BYTES {
        return Err(UsbipError::TooLarge("devlist reply"));
    }
    let mut r = Reader::new(buf);
    read_op_common(&mut r, OP_REP_DEVLIST)?;

    let count = r.u32()?;
    if count > MAX_DEVICES {
        return Err(UsbipError::TooLarge("devlist device count"));
    }
    // Bound the allocation by what the buffer could possibly hold, not by the
    // count the peer claims.
    let feasible = buf.len() / DEVICE_RECORD_LEN + 1;
    let mut devices = Vec::with_capacity((count as usize).min(feasible));
    for _ in 0..count {
        devices.push(read_devlist_record(&mut r)?);
    }
    Ok(devices)
}

/// The 312-byte device record.
///
/// Byte-for-byte identical in `OP_REP_DEVLIST` and `OP_REP_IMPORT`; only what
/// precedes it differs (a device count vs nothing) and, in devlist, what
/// follows it (interface descriptors). Since the reader is sequential, one
/// function serves both.
fn read_device_record(r: &mut Reader<'_>) -> Result<UsbDeviceRecord, UsbipError> {
    Ok(UsbDeviceRecord {
        path: r.fixed_str(PATH_LEN, "path")?,
        busid: r.fixed_str(BUSID_LEN, "busid")?,
        busnum: r.u32()?,
        devnum: r.u32()?,
        speed: r.u32()?,
        id_vendor: r.u16()?,
        id_product: r.u16()?,
        bcd_device: r.u16()?,
        b_device_class: r.u8()?,
        b_device_subclass: r.u8()?,
        b_device_protocol: r.u8()?,
        b_configuration_value: r.u8()?,
        b_num_configurations: r.u8()?,
        b_num_interfaces: r.u8()?,
    })
}

/// One `OP_REP_DEVLIST` record, followed by its interface descriptors.
fn read_devlist_record(r: &mut Reader<'_>) -> Result<UsbDeviceRecord, UsbipError> {
    let dev = read_device_record(r)?;

    // Interface descriptors are metadata izba does not act on, but they must be
    // consumed to find the next record. b_num_interfaces is a u8, so the
    // product self-bounds at 1020 bytes.
    let skip = (dev.b_num_interfaces as usize)
        .checked_mul(INTERFACE_LEN)
        .ok_or(UsbipError::Truncated)?;
    r.take(skip)?;
    Ok(dev)
}

/// Decode `OP_REP_IMPORT`.
///
/// The import reply carries the same device record as a devlist entry, but
/// WITHOUT the trailing interface descriptors, and it begins immediately after
/// `op_common` rather than after a device count.
///
/// izbad must re-verify the returned `busid`/`vid`/`pid` against what it asked
/// for before splicing: nothing in the protocol binds the import reply to the
/// devlist entry, and a busid can be recycled onto a different device by a
/// replug between the two exchanges (F-USB-3).
pub fn decode_op_rep_import(buf: &[u8]) -> Result<UsbDeviceRecord, UsbipError> {
    let mut r = Reader::new(buf);
    read_op_common(&mut r, OP_REP_IMPORT)?;
    read_device_record(&mut r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 312-byte devlist device record.
    fn record_bytes(busid: &str, vid: u16, pid: u16, n_iface: u8) -> Vec<u8> {
        let mut b = vec![0u8; DEVICE_RECORD_LEN];
        b[..busid.len()].copy_from_slice(busid.as_bytes()); // path
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes()); // busid
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
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            b.extend_from_slice(r);
            let n_iface = r[0x137] as usize;
            b.extend(std::iter::repeat_n(0u8, n_iface * INTERFACE_LEN));
        }
        b
    }

    fn rep_import(busid: &str, vid: u16, pid: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        b.extend_from_slice(&OP_REP_IMPORT.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        let mut rec = vec![0u8; DEVICE_RECORD_LEN];
        rec[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        rec[0x120..0x124].copy_from_slice(&3u32.to_be_bytes());
        rec[0x124..0x128].copy_from_slice(&2u32.to_be_bytes());
        rec[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes());
        rec[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        rec[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        b.extend_from_slice(&rec);
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
    fn req_devlist_encodes_op_common_only() {
        let f = encode_op_req_devlist();
        assert_eq!(u16::from_be_bytes([f[0], f[1]]), USBIP_VERSION);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]), OP_REQ_DEVLIST);
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

    /// A count within the cap but far beyond what the buffer holds must not
    /// cause a large speculative allocation either.
    #[test]
    fn rep_devlist_rejects_count_exceeding_buffer() {
        let mut buf = rep_devlist(&[]);
        buf[8..12].copy_from_slice(&MAX_DEVICES.to_be_bytes());
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::Truncated
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

    /// Control characters in a server-supplied string would corrupt logs and
    /// must be refused, not sanitised.
    #[test]
    fn rep_devlist_rejects_control_characters_in_busid() {
        let mut rec = record_bytes("3-2", 1, 2, 0);
        rec[0x101] = 0x07; // BEL
        let buf = rep_devlist(&[rec]);
        assert!(matches!(
            decode_op_rep_devlist(&buf).unwrap_err(),
            UsbipError::BadString(_)
        ));
    }

    #[test]
    fn rep_devlist_accepts_empty_list() {
        assert!(decode_op_rep_devlist(&rep_devlist(&[])).unwrap().is_empty());
    }

    #[test]
    fn rep_import_decodes_the_device_record() {
        let dev = decode_op_rep_import(&rep_import("3-2", 0x0403, 0x6001)).unwrap();
        assert_eq!(dev.busid, "3-2");
        assert_eq!(dev.id_vendor, 0x0403);
        assert_eq!(dev.id_product, 0x6001);
        assert_eq!(dev.busnum, 3);
        assert_eq!(dev.devnum, 2);
        assert_eq!(dev.speed, 2);
    }

    #[test]
    fn rep_import_reports_status_failure() {
        let mut deny = rep_import("3-2", 1, 2);
        deny[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            decode_op_rep_import(&deny).unwrap_err(),
            UsbipError::Status(1)
        ));
    }

    #[test]
    fn rep_import_rejects_truncation() {
        let buf = rep_import("3-2", 1, 2);
        assert!(matches!(
            decode_op_rep_import(&buf[..buf.len() - 4]).unwrap_err(),
            UsbipError::Truncated
        ));
    }

    /// No input may panic the decoders — the property the fuzz target asserts
    /// continuously, pinned here for a few structured shapes.
    #[test]
    fn decoders_never_panic_on_arbitrary_prefixes() {
        let full = rep_devlist(&[record_bytes("3-2", 1, 2, 1)]);
        for n in 0..full.len() {
            let _ = decode_op_rep_devlist(&full[..n]);
            let _ = decode_op_rep_import(&full[..n]);
        }
    }
}
