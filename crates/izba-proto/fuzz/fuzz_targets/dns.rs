#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // read_dns_msg and servfail are both pub.
    // Feed arbitrary bytes through both entry points and assert no panics.
    let _ = izba_proto::dns::read_dns_msg(&mut &data[..]);
    // servfail treats data as a raw query; must not panic for any input.
    let _ = izba_proto::dns::servfail(data);
});
