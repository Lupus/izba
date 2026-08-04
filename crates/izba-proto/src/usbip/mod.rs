//! USB/IP wire protocol (protocol version 1.1.1, `0x0111`).
//!
//! izbad speaks this protocol to an upstream usbip server (`usbipd-win` on a
//! Windows host, or Linux `usbipd`) on behalf of a sandbox. The guest NEVER
//! speaks it: it sends izbad a device *label* over the USB vsock plane, and
//! izbad performs the whole op phase itself against a host-configured upstream.
//! See `docs/superpowers/specs/2026-08-04-izba-usb-passthrough-design.md` (D1).
//!
//! Two properties of this module are load-bearing for security:
//!
//! 1. **Every multi-byte field is big-endian** — deliberately unlike izba's own
//!    u32-LE frames (`crate::codec`). Do not cross-contaminate the two.
//! 2. **Caps are applied before allocation.** Both the device count in an
//!    `OP_REP_DEVLIST` and `transfer_buffer_length` in a URB header are
//!    attacker-influenced `u32`s with no protocol-level maximum; sizing a
//!    buffer from either is the CVE-2016-3955 bug (a crafted USB/IP length
//!    field yielding a remote out-of-bounds write). Decoders here bound the
//!    value first and stream payloads through fixed-size copies.

pub mod op;
pub mod urb;

pub use op::{
    decode_op_rep_devlist, decode_op_rep_import, encode_op_req_devlist, encode_op_req_import,
    UsbDeviceRecord, UsbipError, OP_REP_DEVLIST, OP_REP_IMPORT, OP_REQ_DEVLIST, OP_REQ_IMPORT,
    USBIP_VERSION,
};
pub use urb::{
    decode_guest_urb, GuestUrb, MAX_ISO_PACKETS, MAX_TRANSFER_BUFFER, URB_HEADER_LEN,
    USBIP_CMD_SUBMIT, USBIP_CMD_UNLINK, USBIP_RET_SUBMIT, USBIP_RET_UNLINK,
};

#[cfg(test)]
mod tests {
    /// The `usbip_op` fuzz target lives outside the workspace, so a rename here
    /// would not fail any workspace gate — it would silently break the fuzz job
    /// instead. This pins the exact re-exported surface that target calls.
    #[test]
    fn fuzz_target_surface_is_reachable_from_the_crate_root() {
        let _ = crate::usbip::decode_op_rep_devlist(&[]);
        let _ = crate::usbip::decode_op_rep_import(&[]);
        let header = [0u8; crate::usbip::URB_HEADER_LEN];
        let _ = crate::usbip::decode_guest_urb(&header);
    }
}
