//! Sandbox save/load archives (spec docs/superpowers/specs/2026-09-29-sandbox-save-load-design.md).
//! A pure library: no daemon or CLI assumptions. `.izba` = zstd(tar):
//! `manifest.json` first, then images / named volumes / sandbox files, disks
//! as `<path>.d/<offset-hex>` data-chunk entries, `checksums.json` last.

pub mod fsutil;
pub mod load;
pub mod manifest;
pub mod save;
pub mod sparse;
#[cfg(test)]
pub(crate) mod testutil;
pub mod workspace;

/// Archive format version written by this build; newer is refused on load.
pub const FORMAT_VERSION: u32 = 1;
/// Zero-elision granularity: an all-zero block of this size is never stored.
pub const ZERO_BLOCK: u64 = 64 * 1024;
/// Upper bound of one chunk entry's body (bounds memory per entry).
pub const MAX_CHUNK: u64 = 4 * 1024 * 1024;
/// Progress sink (daemon Progress frames / CLI stderr).
pub type Progress<'a> = &'a mut dyn FnMut(String);
