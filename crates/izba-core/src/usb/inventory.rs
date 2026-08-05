//! Host-side device inventory: one `OP_REQ_DEVLIST` exchange with the upstream.
//!
//! This is the only thing izba asks the upstream for in the control plane, and
//! it is always host-initiated. The guest never sees a device list and never
//! learns the upstream address (D1/F-USB-9).
//!
//! **Framing vs validation.** A devlist reply is variable-length, so the reader
//! must consult the device count and each record's interface count to know
//! where the message ends. It uses those two numbers ONLY to bound its reads;
//! every value it returns comes from `decode_op_rep_devlist`, which re-validates
//! the whole buffer. So a lying count can make the read fail — it can never make
//! a bad record look good.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use izba_proto::usbip::{
    decode_op_rep_devlist, encode_op_req_devlist, UsbDeviceRecord, DEVICE_RECORD_LEN,
    INTERFACE_LEN, MAX_DEVICES, OP_COMMON_LEN,
};

use super::DeviceId;

/// One device the upstream currently exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamDevice {
    pub busid: String,
    pub id: DeviceId,
    /// The upstream's `path` field — a sysfs path, the only human-readable
    /// description the USB/IP wire format carries.
    pub description: String,
    pub speed: u32,
}

impl From<UsbDeviceRecord> for UpstreamDevice {
    fn from(r: UsbDeviceRecord) -> Self {
        Self {
            id: DeviceId {
                vid: r.id_vendor,
                pid: r.id_product,
            },
            description: r.path,
            busid: r.busid,
            speed: r.speed,
        }
    }
}

/// How long izbad waits on an upstream that accepted the connection but does
/// not answer. Short: this runs behind an interactive command.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Read one `OP_REP_DEVLIST` off `reply`.
///
/// The caller is responsible for having sent [`encode_op_req_devlist`] first;
/// this function never writes, which keeps the socket single-writer and lets
/// tests drive it from a plain `Cursor`.
pub fn read_devlist_reply<R: Read>(reply: &mut R) -> Result<Vec<UpstreamDevice>> {
    let mut buf = vec![0u8; OP_COMMON_LEN + 4];
    reply
        .read_exact(&mut buf)
        .context("reading the devlist reply header")?;

    let count = u32::from_be_bytes([
        buf[OP_COMMON_LEN],
        buf[OP_COMMON_LEN + 1],
        buf[OP_COMMON_LEN + 2],
        buf[OP_COMMON_LEN + 3],
    ]);
    if count > MAX_DEVICES {
        bail!("upstream claims {count} devices, above the {MAX_DEVICES} cap");
    }

    for _ in 0..count {
        let start = buf.len();
        buf.resize(start + DEVICE_RECORD_LEN, 0);
        reply
            .read_exact(&mut buf[start..])
            .context("reading a device record")?;
        // b_num_interfaces is the record's last byte; it is a u8, so the
        // trailing read self-bounds at 1020 bytes.
        let n_iface = buf[buf.len() - 1] as usize;
        let ifaces = buf.len();
        buf.resize(ifaces + n_iface * INTERFACE_LEN, 0);
        reply
            .read_exact(&mut buf[ifaces..])
            .context("reading interface descriptors")?;
    }

    let records = decode_op_rep_devlist(&buf).context("decoding the devlist reply")?;
    Ok(records.into_iter().map(UpstreamDevice::from).collect())
}

/// Dial `addr` and enumerate. Every phase is time-bounded so a wedged or
/// silently-accepting upstream cannot hang an interactive command.
// reason: real-socket glue — `read_devlist_reply` carries all the parsing, and
// exercising the dial/timeout wiring needs a bound listener, which the house
// unit-test constraint forbids.
#[mutants::skip]
pub fn fetch(addr: SocketAddr) -> Result<Vec<UpstreamDevice>> {
    let mut sock = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .with_context(|| format!("connecting to the usbip upstream at {addr}"))?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;
    sock.write_all(&encode_op_req_devlist())
        .context("sending OP_REQ_DEVLIST")?;
    sock.flush()?;
    read_devlist_reply(&mut sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::usbip::{OP_REP_DEVLIST, USBIP_VERSION};

    /// Build one 312-byte device record plus its interface descriptors.
    fn record(busid: &str, vid: u16, pid: u16, n_iface: u8) -> Vec<u8> {
        let mut b = vec![0u8; DEVICE_RECORD_LEN];
        let path = format!("/sys/devices/pci0000:00/usb{busid}");
        b[..path.len()].copy_from_slice(path.as_bytes());
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        b[0x120..0x124].copy_from_slice(&3u32.to_be_bytes()); // busnum
        b[0x124..0x128].copy_from_slice(&2u32.to_be_bytes()); // devnum
        b[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes()); // speed
        b[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        b[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        b[0x137] = n_iface;
        b.extend(std::iter::repeat_n(0u8, n_iface as usize * INTERFACE_LEN));
        b
    }

    fn devlist_reply(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        out.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // status
        out.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn read(bytes: Vec<u8>) -> Result<Vec<UpstreamDevice>> {
        read_devlist_reply(&mut std::io::Cursor::new(bytes))
    }

    #[test]
    fn parses_a_devlist_reply() {
        let devices = read(devlist_reply(&[
            record("3-2", 0x0403, 0x6001, 1),
            record("1-1.4", 0x1a86, 0x7523, 0),
        ]))
        .unwrap();

        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].busid, "3-2");
        assert_eq!(devices[0].id.to_string(), "0403:6001");
        assert_eq!(devices[0].speed, 2);
        assert!(devices[0].description.starts_with("/sys/devices"));
        assert_eq!(devices[1].busid, "1-1.4");
        assert_eq!(devices[1].id.to_string(), "1a86:7523");
    }

    #[test]
    fn an_empty_devlist_is_a_normal_answer_not_an_error() {
        // usbipd with nothing bound: the honest answer is "no devices", which
        // the CLI turns into the `usbipd bind` hint rather than an error.
        assert!(read(devlist_reply(&[])).unwrap().is_empty());
    }

    #[test]
    fn interface_descriptors_are_skipped_so_the_next_record_aligns() {
        // A record with the maximum interface count must not desynchronise the
        // reader — that is the framing bug that would silently mis-parse the
        // devices after it.
        let devices = read(devlist_reply(&[
            record("3-2", 0x0403, 0x6001, 255),
            record("3-3", 0x1a86, 0x7523, 0),
        ]))
        .unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].busid, "3-3");
        assert_eq!(devices[1].id.to_string(), "1a86:7523");
    }

    #[test]
    fn a_claimed_device_count_beyond_the_cap_is_refused_before_reading_it() {
        // The count is upstream-controlled; it must bound the read, not be
        // trusted by it. 4 billion claimed records must not become 4 billion
        // reads of a socket that will never deliver them.
        let mut reply = Vec::new();
        reply.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        reply.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        reply.extend_from_slice(&0u32.to_be_bytes());
        reply.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = read(reply).unwrap_err().to_string();
        assert!(err.contains("cap"), "{err}");
        assert!(err.contains("4294967295"), "name the claim: {err}");
    }

    #[test]
    fn the_whole_32_bit_count_is_read_not_just_some_of_its_bytes() {
        // 65536 is 00 01 00 00: every byte differs from its neighbours, so a
        // reader that picked up the wrong offset would compute 0 and sail past
        // its own cap. (A count of u32::MAX cannot catch that — all four bytes
        // are identical, so any mis-indexing reads the same value.) The reader's
        // own message names the claim, which is what pins the byte order here:
        // the decoder's later check produces a different, generic message.
        let mut reply = Vec::new();
        reply.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        reply.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        reply.extend_from_slice(&0u32.to_be_bytes());
        reply.extend_from_slice(&65_536u32.to_be_bytes());
        let err = read(reply).unwrap_err().to_string();
        assert!(
            err.contains("claims 65536 devices"),
            "the reader must reject it on its own terms: {err}"
        );
    }

    #[test]
    fn exactly_the_cap_is_still_accepted() {
        // The boundary must be inclusive: 256 devices is legal, 257 is not.
        let records: Vec<_> = (0..MAX_DEVICES)
            .map(|i| record(&format!("3-{i}"), 0x0403, 0x6001, 0))
            .collect();
        assert_eq!(read(devlist_reply(&records)).unwrap().len(), 256);
    }

    #[test]
    fn a_truncated_reply_is_an_error_not_a_short_device_list() {
        let full = devlist_reply(&[record("3-2", 0x0403, 0x6001, 2)]);
        for cut in [0, 4, OP_COMMON_LEN, OP_COMMON_LEN + 4, full.len() - 1] {
            assert!(
                read(full[..cut].to_vec()).is_err(),
                "a reply cut at {cut} must not parse"
            );
        }
        assert!(read(full).is_ok(), "the intact reply parses");
    }

    #[test]
    fn a_wrong_version_reply_is_refused() {
        let mut reply = devlist_reply(&[]);
        reply[0..2].copy_from_slice(&0x0110u16.to_be_bytes());
        // `{:#}` renders the whole chain: the decoder's reason must reach the
        // user, not just this layer's "decoding the devlist reply".
        let err = format!("{:#}", read(reply).unwrap_err());
        assert!(err.contains("version"), "{err}");
        assert!(err.contains("0x0110"), "name what the peer sent: {err}");
    }

    #[test]
    fn a_reply_carrying_a_failure_status_is_refused() {
        let mut reply = devlist_reply(&[]);
        reply[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(
            read(reply).is_err(),
            "a non-zero status is not a device list"
        );
    }

    #[test]
    fn two_identical_devices_are_both_reported() {
        // D9's ambiguity case: the resolver, not the reader, decides what to do
        // about it — so the reader must not silently deduplicate.
        let devices = read(devlist_reply(&[
            record("3-2", 0x0403, 0x6001, 0),
            record("3-3", 0x0403, 0x6001, 0),
        ]))
        .unwrap();
        let id: DeviceId = "0403:6001".parse().unwrap();
        assert_eq!(devices.iter().filter(|d| d.id == id).count(), 2);
    }
}
