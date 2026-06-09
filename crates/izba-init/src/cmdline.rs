//! Kernel command line parsing.

use std::collections::BTreeMap;

/// Parses a kernel command line into key/value pairs.
///
/// Tokens are whitespace-separated; `k=v` becomes `(k, v)` and a bare flag
/// becomes `(flag, "")`. Later duplicates win.
pub fn parse(s: &str) -> BTreeMap<String, String> {
    s.split_whitespace()
        .map(|tok| match tok.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (tok.to_string(), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pairs_and_flags() {
        let m = parse("izba.hostname=web ip=dhcp console=ttyS0 quiet");
        assert_eq!(m.len(), 4);
        assert_eq!(m["izba.hostname"], "web");
        assert_eq!(m["ip"], "dhcp");
        assert_eq!(m["console"], "ttyS0");
        assert_eq!(m["quiet"], "");
    }

    #[test]
    fn empty_input_is_empty() {
        assert!(parse("").is_empty());
        assert!(parse("   \n\t ").is_empty());
    }

    #[test]
    fn value_may_contain_equals() {
        let m = parse("opt=a=b");
        assert_eq!(m["opt"], "a=b");
    }
}
