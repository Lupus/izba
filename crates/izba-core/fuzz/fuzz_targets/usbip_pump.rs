#![no_main]
use libfuzzer_sys::fuzz_target;

// The guest → upstream URB validator: the one new parser on this feature's
// hostile-input path, since it stands between a sandbox's bytes and a
// privileged host service (`usbipd`). Arbitrary input must never panic, and
// must never forward anything past a header the validator rejected.
//
// The 1028 handshake itself needs no target of its own: it is the already-fuzzed
// length-prefixed frame codec (`izba-proto/fuzz/fuzz_targets/frame.rs`), and the
// USB/IP op-phase decoders are covered by `usbip_op`.
fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    let _ = izba_core::usb::broker::session::pump_guest_to_upstream(
        std::io::Cursor::new(data),
        &mut out,
    );
});
