//! Fuzz target for `izba_init::tarfs::extract`.
//!
//! Feeds arbitrary bytes to `extract` as a tar stream and asserts:
//!   - no panic, hang, or OOM occurs
//!
//! Out-of-root containment is enforced by `openat2(RESOLVE_IN_ROOT)` at the
//! kernel level and is exercised deterministically by the `prop_containment_no_escape`
//! proptest in `tarfs.rs`, which covers symlink-write-through, `..`/absolute-path
//! entry names, and out-of-order archives. This target focuses on parser robustness
//! against truly malformed/truncated byte streams, not on containment logic.
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
