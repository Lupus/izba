//! Derive a sandbox name from an arbitrary directory name.

use anyhow::bail;

/// Sanitize `input` into a valid sandbox name (`[a-z0-9][a-z0-9_.-]*`):
/// lowercase; every disallowed char becomes `-`; runs of `-` collapse;
/// leading/trailing `-` are stripped. Errors if nothing valid remains.
pub fn sanitize(input: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let mapped = match ch.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '_' | '.') => c,
            _ => '-',
        };
        if mapped == '-' && out.ends_with('-') {
            continue; // collapse repeats
        }
        out.push(mapped);
    }
    let name = out.trim_matches('-').to_string();
    if name.is_empty() {
        bail!("cannot derive a sandbox name from '{input}'; pass --name");
    }
    izba_core::sandbox::validate_name(&name)?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sanitize_names() {
        // Underscores are allowed by core validate_name and kept as-is.
        assert_eq!(sanitize("My_Proj").unwrap(), "my_proj");
        assert_eq!(sanitize("Web App!").unwrap(), "web-app");
        assert_eq!(sanitize("---x--").unwrap(), "x");
        assert_eq!(sanitize("izba").unwrap(), "izba");
        assert_eq!(sanitize("a..b").unwrap(), "a..b");
        // Nothing valid left → error.
        assert!(sanitize("!!!").is_err());
        assert!(sanitize("").is_err());
        // Sanitized result must still pass core validation (leading '.').
        assert!(sanitize(".hidden").is_err());
    }
}
