#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // read_frame is pub; feed arbitrary bytes and assert it never panics.
    // Acceptable outcomes: Err(TooLarge), Err(Eof), Err(Io(...)), Err(Json(...)).
    // Unacceptable: panic, or any allocation proportional to an untrusted u32
    // exceeding MAX_FRAME (the TooLarge guard must fire before vec allocation).
    let _ = izba_proto::read_frame::<_, serde_json::Value>(&mut &data[..]);
});
