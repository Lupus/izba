//! URB-phase header validation for the **guest → upstream** direction only.
//!
//! After a device is imported, izbad is a byte pipe. It validates the frames a
//! guest sends and splices the ones the upstream sends back opaquely. The
//! asymmetry is deliberate (design D6):
//!
//! - The guest → upstream direction terminates in a privileged host service
//!   (`usbipd`), so hostile guest bytes reaching its parser are a real risk —
//!   cf. CVE-2021-3682, where a malicious USB-redirection client reached code
//!   execution with the privileges of the host QEMU process. That direction
//!   earns a validator.
//! - The upstream → guest direction's victim is a guest kernel already assumed
//!   hostile under izba's threat model, so parsing it buys nothing while adding
//!   a stateful parser to the hot path: `RET_SUBMIT` zeroes `direction` and
//!   `ep`, so framing replies would require tracking seqnum → direction for
//!   every in-flight request.
//!
//! Client-sent frames, by contrast, are entirely self-describing, so this
//! validator is stateless.
//!
//! This is a hygiene and framing control, NOT an authorization control: it
//! cannot distinguish a legitimate URB from a malicious well-formed one.
//! Enforcement happens at import time, against the device allowlist.

use super::op::UsbipError;

pub const USBIP_CMD_SUBMIT: u32 = 1;
pub const USBIP_CMD_UNLINK: u32 = 2;
pub const USBIP_RET_SUBMIT: u32 = 3;
pub const USBIP_RET_UNLINK: u32 = 4;

/// Every URB message begins with a fixed 48-byte header.
pub const URB_HEADER_LEN: usize = 48;

/// Cap on a single transfer. The protocol imposes none — `transfer_buffer_length`
/// is a bare u32, and the Linux stub will honestly try to allocate whatever is
/// asked, which is CVE-2016-3955. Serial-class traffic (izba's v1 scope) is
/// orders of magnitude below this.
pub const MAX_TRANSFER_BUFFER: u32 = 1024 * 1024;

/// Matches the kernel's own `USBIP_MAX_ISO_PACKETS`; the Linux stub drops the
/// connection above this, so accepting more would only forward a frame the
/// upstream is guaranteed to reject.
pub const MAX_ISO_PACKETS: u32 = 1024;

/// Sentinel meaning "this is not an isochronous transfer".
const NOT_ISO: u32 = 0xffff_ffff;

/// Byte offsets within the 48-byte header.
const OFF_COMMAND: usize = 0;
const OFF_SEQNUM: usize = 4;
const OFF_DIRECTION: usize = 12;
const OFF_EP: usize = 16;
const OFF_TRANSFER_BUFFER_LENGTH: usize = 24;
const OFF_NUMBER_OF_PACKETS: usize = 32;

/// Bytes per isochronous packet descriptor.
const ISO_DESCRIPTOR_LEN: u32 = 16;

/// A validated client-sent URB header plus exactly how many payload bytes
/// follow it, so the caller can stream them through a fixed-size copy without
/// ever sizing a buffer from an attacker-controlled length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestUrb {
    pub command: u32,
    pub seqnum: u32,
    pub direction: u32,
    pub ep: u32,
    pub payload_len: usize,
}

fn be32(header: &[u8; URB_HEADER_LEN], off: usize) -> u32 {
    u32::from_be_bytes([
        header[off],
        header[off + 1],
        header[off + 2],
        header[off + 3],
    ])
}

/// Validate one client-sent URB header.
///
/// Rejects anything a legitimate client would never send: a server-side reply
/// command, an out-of-range endpoint or direction, an oversized transfer, or an
/// absurd isochronous packet count.
pub fn decode_guest_urb(header: &[u8; URB_HEADER_LEN]) -> Result<GuestUrb, UsbipError> {
    let command = be32(header, OFF_COMMAND);
    if command != USBIP_CMD_SUBMIT && command != USBIP_CMD_UNLINK {
        // A guest sending RET_SUBMIT/RET_UNLINK is impersonating the server.
        return Err(UsbipError::BadCode(command as u16));
    }
    let seqnum = be32(header, OFF_SEQNUM);

    // UNLINK is header-only: its remaining fields are the victim seqnum and
    // padding, and direction/ep are unused (zero).
    if command == USBIP_CMD_UNLINK {
        return Ok(GuestUrb {
            command,
            seqnum,
            direction: 0,
            ep: 0,
            payload_len: 0,
        });
    }

    let direction = be32(header, OFF_DIRECTION);
    if direction > 1 {
        return Err(UsbipError::BadCode(direction as u16));
    }
    let ep = be32(header, OFF_EP);
    if ep > 15 {
        return Err(UsbipError::BadCode(ep as u16));
    }

    let transfer_buffer_length = be32(header, OFF_TRANSFER_BUFFER_LENGTH);
    if transfer_buffer_length > MAX_TRANSFER_BUFFER {
        return Err(UsbipError::TooLarge("transfer_buffer_length"));
    }

    let number_of_packets = be32(header, OFF_NUMBER_OF_PACKETS);
    let iso_bytes = if number_of_packets == NOT_ISO {
        0
    } else {
        if number_of_packets > MAX_ISO_PACKETS {
            return Err(UsbipError::TooLarge("number_of_packets"));
        }
        number_of_packets
            .checked_mul(ISO_DESCRIPTOR_LEN)
            .ok_or(UsbipError::TooLarge("iso descriptors"))?
    };

    // OUT carries its transfer buffer; IN requests carry none (the data comes
    // back in the reply). Isochronous descriptors travel in BOTH directions.
    let buffer_bytes = if direction == 0 {
        transfer_buffer_length
    } else {
        0
    };
    let payload_len = buffer_bytes
        .checked_add(iso_bytes)
        .ok_or(UsbipError::TooLarge("payload"))? as usize;

    Ok(GuestUrb {
        command,
        seqnum,
        direction,
        ep,
        payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(direction: u32, ep: u32, len: u32, n_iso: u32) -> [u8; URB_HEADER_LEN] {
        let mut h = [0u8; URB_HEADER_LEN];
        h[OFF_COMMAND..OFF_COMMAND + 4].copy_from_slice(&USBIP_CMD_SUBMIT.to_be_bytes());
        h[OFF_SEQNUM..OFF_SEQNUM + 4].copy_from_slice(&7u32.to_be_bytes());
        h[OFF_DIRECTION..OFF_DIRECTION + 4].copy_from_slice(&direction.to_be_bytes());
        h[OFF_EP..OFF_EP + 4].copy_from_slice(&ep.to_be_bytes());
        h[OFF_TRANSFER_BUFFER_LENGTH..OFF_TRANSFER_BUFFER_LENGTH + 4]
            .copy_from_slice(&len.to_be_bytes());
        h[OFF_NUMBER_OF_PACKETS..OFF_NUMBER_OF_PACKETS + 4].copy_from_slice(&n_iso.to_be_bytes());
        h
    }

    #[test]
    fn out_transfer_payload_is_the_buffer() {
        let u = decode_guest_urb(&submit(0, 2, 512, NOT_ISO)).unwrap();
        assert_eq!(u.command, USBIP_CMD_SUBMIT);
        assert_eq!(u.seqnum, 7);
        assert_eq!(u.payload_len, 512, "OUT carries its transfer buffer");
    }

    #[test]
    fn in_transfer_has_no_payload() {
        let u = decode_guest_urb(&submit(1, 2, 512, NOT_ISO)).unwrap();
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
        let mut h = [0u8; URB_HEADER_LEN];
        h[..4].copy_from_slice(&USBIP_CMD_UNLINK.to_be_bytes());
        let u = decode_guest_urb(&h).unwrap();
        assert_eq!(u.command, USBIP_CMD_UNLINK);
        assert_eq!(u.payload_len, 0);
    }

    /// A guest sending a server-side reply code is a protocol violation.
    #[test]
    fn guest_may_not_send_reply_commands() {
        for cmd in [USBIP_RET_SUBMIT, USBIP_RET_UNLINK, 0, 99] {
            let mut h = [0u8; URB_HEADER_LEN];
            h[..4].copy_from_slice(&cmd.to_be_bytes());
            assert!(
                matches!(decode_guest_urb(&h).unwrap_err(), UsbipError::BadCode(_)),
                "command {cmd} must be rejected"
            );
        }
    }

    #[test]
    fn oversized_transfer_buffer_is_rejected() {
        let err = decode_guest_urb(&submit(0, 1, MAX_TRANSFER_BUFFER + 1, NOT_ISO)).unwrap_err();
        assert!(matches!(err, UsbipError::TooLarge(_)), "{err:?}");
    }

    #[test]
    fn transfer_buffer_at_the_cap_is_accepted() {
        let u = decode_guest_urb(&submit(0, 1, MAX_TRANSFER_BUFFER, NOT_ISO)).unwrap();
        assert_eq!(u.payload_len, MAX_TRANSFER_BUFFER as usize);
    }

    #[test]
    fn absurd_iso_packet_count_is_rejected() {
        let err = decode_guest_urb(&submit(0, 1, 64, MAX_ISO_PACKETS + 1)).unwrap_err();
        assert!(matches!(err, UsbipError::TooLarge(_)), "{err:?}");
    }

    #[test]
    fn out_of_range_endpoint_and_direction_are_rejected() {
        assert!(decode_guest_urb(&submit(0, 16, 8, NOT_ISO)).is_err());
        assert!(decode_guest_urb(&submit(2, 1, 8, NOT_ISO)).is_err());
    }

    /// The worst legitimate case must not overflow the payload computation.
    #[test]
    fn maximum_legal_frame_does_not_overflow() {
        let u = decode_guest_urb(&submit(0, 1, MAX_TRANSFER_BUFFER, MAX_ISO_PACKETS)).unwrap();
        assert_eq!(
            u.payload_len,
            MAX_TRANSFER_BUFFER as usize + MAX_ISO_PACKETS as usize * 16
        );
    }
}
