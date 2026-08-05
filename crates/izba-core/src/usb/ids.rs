//! USB device identity as a human types it: `vid:pid`.
//!
//! Deliberately strict — four hex digits each, no shorthand. A grant is a
//! consent record, and a typo that silently widened or narrowed it would be a
//! consent bug, not a usability one. See F-USB-3: this pair is *asserted* by
//! the device, so it expresses human intent, never provenance.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId {
    pub vid: u16,
    pub pid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDeviceIdError;

impl fmt::Display for ParseDeviceIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a USB id in vid:pid form, four hex digits each (e.g. 0403:6001)")
    }
}

impl std::error::Error for ParseDeviceIdError {}

fn hex4(s: &str) -> Result<u16, ParseDeviceIdError> {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ParseDeviceIdError);
    }
    u16::from_str_radix(s, 16).map_err(|_| ParseDeviceIdError)
}

impl FromStr for DeviceId {
    type Err = ParseDeviceIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (v, p) = s.split_once(':').ok_or(ParseDeviceIdError)?;
        Ok(Self {
            vid: hex4(v)?,
            pid: hex4(p)?,
        })
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.vid, self.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_vid_pid() {
        let id: DeviceId = "0403:6001".parse().unwrap();
        assert_eq!(id.vid, 0x0403);
        assert_eq!(id.pid, 0x6001);
        assert_eq!(id.to_string(), "0403:6001");
    }

    #[test]
    fn uppercase_input_is_accepted_and_normalises_to_lowercase() {
        // lsusb prints uppercase on some platforms; the canonical form is lower.
        let id: DeviceId = "1A86:7523".parse().unwrap();
        assert_eq!(id.to_string(), "1a86:7523");
    }

    #[test]
    fn rejects_anything_that_is_not_exactly_four_hex_colon_four_hex() {
        // Short forms are refused rather than zero-padded: "403:6001" is far too
        // easy to mistype for a different device, and a grant is a consent record.
        for bad in [
            "403:6001",
            "0403:601",
            "0403-6001",
            "04036001",
            "0403:6001:0",
            "",
            "0403:",
            ":6001",
            "zzzz:6001",
            "0403:600g",
            " 0403:6001",
            "0403:6001 ",
            "00403:6001",
        ] {
            assert!(bad.parse::<DeviceId>().is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn error_names_the_expected_shape() {
        let err = "nope".parse::<DeviceId>().unwrap_err().to_string();
        assert!(err.contains("vid:pid"), "{err}");
        assert!(err.contains("0403:6001"), "actionable example: {err}");
    }

    #[test]
    fn hex_digits_are_parsed_at_their_real_magnitude() {
        // Guards against a radix or byte-order slip: every nibble position must
        // land where it belongs.
        let id: DeviceId = "1234:abcd".parse().unwrap();
        assert_eq!(id.vid, 0x1234);
        assert_eq!(id.pid, 0xabcd);
        let max: DeviceId = "ffff:0000".parse().unwrap();
        assert_eq!(max.vid, u16::MAX);
        assert_eq!(max.pid, 0);
        assert_eq!(max.to_string(), "ffff:0000");
    }
}
