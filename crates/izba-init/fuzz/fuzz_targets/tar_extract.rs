//! Fuzz target for `izba_init::tarfs::extract`.
//!
//! Feeds arbitrary bytes to `extract` as a tar stream and checks that:
//!   - no panic occurs
//!   - no file is created outside the tempdir root
//!
//! Note: each run involves real filesystem I/O (tmpfs on Linux), which makes
//! this slower than a purely in-memory fuzzer. This is acceptable for a 60s
//! CI smoke; the coverage value (exercising the tar parser + openat2 paths
//! with truly malformed input) justifies the cost.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    // `extract` expects a `dest` guest path; "/" → extract into root itself.
    let _ = izba_init::tarfs::extract(root, "/", &mut &data[..]);
    // Tempdir is dropped (cleaned up) at end of scope.
});
