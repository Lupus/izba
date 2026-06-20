#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Interpret the raw fuzz bytes as a single OCI layer (plain tar or gzipped
    // tar — flatten_layers detects gzip magic automatically).  The decoder will
    // mostly reject junk, which is fine: the property we check is that
    // flatten_layers never panics, never escapes a path outside the root, and
    // never allocates memory proportional to an unchecked field in the input.
    //
    // Single-layer interpretation: simpler than trying to split bytes into
    // multiple layers.  Path-traversal and whiteout semantics are still
    // exercised because the path-normalization + whiteout logic runs on every
    // entry regardless of layer count.
    // flatten_layers wants `Box<dyn Read>` (i.e. `'static`); `data` is borrowed
    // from the fuzzer, so own the bytes before boxing the reader.
    let readers: Vec<Box<dyn std::io::Read>> =
        vec![Box::new(Cursor::new(data.to_vec()))];
    let mut out = Vec::new();
    // Acceptable: Ok(...), Err(non-UTF-8 path), Err(.. traversal), Err(I/O),
    //             Err(GNUSparse rejection), Err(hardlink traversal).
    // Unacceptable: panic, infinite loop, or unbounded allocation.
    let _ = izba_core::image::flatten::flatten_layers(readers, &mut out);
});
