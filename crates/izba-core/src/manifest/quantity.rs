//! Kubernetes binary quantity strings (`Ki`/`Mi`/`Gi`/`Ti`) <-> bytes.
//! Only the binary (power-of-two) suffixes are accepted — izba sizes are all
//! binary, and refusing decimal SI (`GB`) avoids the 1000-vs-1024 footgun.

use anyhow::{bail, Context, Result};

const UNITS: &[(&str, u64)] = &[
    ("Ki", 1 << 10),
    ("Mi", 1 << 20),
    ("Gi", 1 << 30),
    ("Ti", 1 << 40),
];

/// Parse a binary quantity string to bytes. `"4Gi" -> 4*2^30`.
pub fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    for (suffix, mult) in UNITS {
        if let Some(num) = s.strip_suffix(suffix) {
            let n: u64 = num
                .trim()
                .parse()
                .with_context(|| format!("invalid quantity {s:?}"))?;
            return n
                .checked_mul(*mult)
                .with_context(|| format!("quantity {s:?} overflows"));
        }
    }
    bail!("quantity {s:?} must end in Ki/Mi/Gi/Ti (e.g. 4Gi, 512Mi)")
}

/// Parse to whole MiB (memory). Errors if not a whole MiB multiple.
pub fn parse_mib(s: &str) -> Result<u32> {
    let bytes = parse_bytes(s)?;
    if !bytes.is_multiple_of(1 << 20) {
        bail!("memory {s:?} must be a whole number of MiB");
    }
    u32::try_from(bytes >> 20).with_context(|| format!("memory {s:?} too large"))
}

/// Parse to whole GiB (root disk / volume sizing where GiB units are required).
pub fn parse_gib(s: &str) -> Result<u64> {
    let bytes = parse_bytes(s)?;
    if !bytes.is_multiple_of(1 << 30) {
        bail!("size {s:?} must be a whole number of GiB (e.g. 8Gi)");
    }
    Ok(bytes >> 30)
}

/// Format bytes as the largest exact binary unit. `0 -> "0"`.
pub fn format(bytes: u64) -> String {
    if bytes == 0 {
        return "0".to_string();
    }
    for (suffix, mult) in UNITS.iter().rev() {
        if bytes.is_multiple_of(*mult) {
            return format!("{}{}", bytes / *mult, suffix);
        }
    }
    format!("{bytes}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gi_and_mi_to_bytes() {
        assert_eq!(parse_bytes("4Gi").unwrap(), 4u64 << 30);
        assert_eq!(parse_bytes("512Mi").unwrap(), 512u64 << 20);
        assert_eq!(parse_bytes("1Ki").unwrap(), 1024);
    }

    #[test]
    fn parse_mib_rounds_to_whole_mib() {
        assert_eq!(parse_mib("4Gi").unwrap(), 4096);
        assert_eq!(parse_mib("512Mi").unwrap(), 512);
        assert!(parse_mib("500Ki").is_err(), "sub-MiB memory is rejected");
    }

    #[test]
    fn parse_gib_requires_whole_gib() {
        assert_eq!(parse_gib("8Gi").unwrap(), 8);
        assert!(parse_gib("512Mi").is_err(), "rootDisk must be whole GiB");
    }

    #[test]
    fn format_picks_largest_exact_unit() {
        assert_eq!(format(4u64 << 30), "4Gi");
        assert_eq!(format(512u64 << 20), "512Mi");
        assert_eq!(format(0), "0");
    }

    #[test]
    fn format_then_parse_round_trips() {
        for b in [1u64 << 20, 8u64 << 30, 3u64 << 30, 700u64 << 20] {
            assert_eq!(parse_bytes(&format(b)).unwrap(), b);
        }
    }

    #[test]
    fn rejects_garbage_and_bare_numbers() {
        assert!(parse_bytes("4").is_err());
        assert!(parse_bytes("4GB").is_err()); // decimal SI not supported; Gi/Mi only
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("-1Gi").is_err());
    }
}
