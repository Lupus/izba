#![no_main]
use libfuzzer_sys::fuzz_target;

// izbad decodes these bytes from an upstream usbip server, whose replies carry
// attacker-shaped counts and fixed-size string arrays. Neither decoder may
// panic, and neither may allocate proportionally to a claimed count.
fuzz_target!(|data: &[u8]| {
    let _ = izba_proto::usbip::decode_op_rep_devlist(data);
    let _ = izba_proto::usbip::decode_op_rep_import(data);

    // The URB validator takes a fixed-size header from the hostile guest leg.
    if data.len() >= izba_proto::usbip::URB_HEADER_LEN {
        let mut header = [0u8; izba_proto::usbip::URB_HEADER_LEN];
        header.copy_from_slice(&data[..izba_proto::usbip::URB_HEADER_LEN]);
        let _ = izba_proto::usbip::decode_guest_urb(&header);
    }
});
