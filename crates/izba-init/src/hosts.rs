//! Guest `/etc/hosts` management: make `localhost` and the sandbox hostname
//! resolve inside the workload.
//!
//! Container runtimes (docker, podman) write the container hostname into
//! `/etc/hosts` at start, so images never ship their own entry; izba sets the
//! hostname via `izba.hostname` but until now nothing added it to the hosts
//! file, and every tool that resolves the local hostname logged a failure
//! (most visibly sudo: `sudo: unable to resolve host <name>`). `127.0.1.1`
//! follows the Debian convention for a host with no permanent address — and
//! loopback is exempt from the nft REDIRECT rule, so the entry never touches
//! the egress plane.

use std::io;
use std::path::Path;

/// Read-modify-write [`ensure_entries`] against the hosts file at `path`.
/// A missing file is treated as empty (created). Returns whether the file
/// was rewritten — `Ok(false)` means every entry was already present.
pub fn sync_file(path: &Path, hostname: Option<&str>) -> io::Result<bool> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let updated = ensure_entries(&existing, hostname);
    if updated == existing {
        return Ok(false);
    }
    std::fs::write(path, updated)?;
    Ok(true)
}

/// Returns `existing` with `localhost` and (when given) `hostname` guaranteed
/// to resolve, appending whichever entries are missing.
///
/// Idempotent by token match: the overlay persists `/etc/hosts` across
/// reboots, so an entry present from a previous boot — or shipped by the
/// image, or hand-edited by the user — is left untouched.
pub fn ensure_entries(existing: &str, hostname: Option<&str>) -> String {
    let mut out = existing.to_string();
    let mut ensure = |addr: &str, name: &str| {
        if has_name(&out, name) {
            return;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(addr);
        out.push('\t');
        out.push_str(name);
        out.push('\n');
    };
    ensure("127.0.0.1", "localhost");
    if let Some(h) = hostname.filter(|h| !h.is_empty()) {
        ensure("127.0.1.1", h);
    }
    out
}

/// Whether `name` already resolves: some non-comment line lists it as a
/// hostname/alias field (any whitespace-separated field after the address).
fn has_name(hosts: &str, name: &str) -> bool {
    hosts.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        fields.next().is_some() && fields.any(|f| f == name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_gets_localhost_and_hostname() {
        let out = ensure_entries("", Some("web"));
        assert_eq!(out, "127.0.0.1\tlocalhost\n127.0.1.1\tweb\n");
    }

    #[test]
    fn typical_image_file_gets_only_hostname_appended() {
        let existing = "127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n";
        let out = ensure_entries(existing, Some("web"));
        assert_eq!(out, format!("{existing}127.0.1.1\tweb\n"));
    }

    #[test]
    fn present_hostname_is_untouched() {
        let existing = "127.0.0.1 localhost\n10.0.0.7 web\n";
        assert_eq!(ensure_entries(existing, Some("web")), existing);
    }

    #[test]
    fn alias_field_counts_as_present() {
        let existing = "127.0.0.1 localhost\n10.0.0.7 gateway web\n";
        assert_eq!(ensure_entries(existing, Some("web")), existing);
    }

    #[test]
    fn idempotent_across_reboots() {
        let once = ensure_entries("127.0.0.1 localhost\n", Some("web"));
        assert_eq!(ensure_entries(&once, Some("web")), once);
    }

    #[test]
    fn prefix_name_is_not_a_match() {
        let existing = "127.0.0.1 localhost\n10.0.0.7 web2\n";
        let out = ensure_entries(existing, Some("web"));
        assert_eq!(out, format!("{existing}127.0.1.1\tweb\n"));
    }

    #[test]
    fn commented_mention_does_not_count() {
        let existing = "127.0.0.1 localhost # not web\n# 1.2.3.4 web\n";
        let out = ensure_entries(existing, Some("web"));
        assert_eq!(out, format!("{existing}127.0.1.1\tweb\n"));
    }

    #[test]
    fn no_hostname_still_ensures_localhost() {
        assert_eq!(ensure_entries("", None), "127.0.0.1\tlocalhost\n");
        let existing = "127.0.0.1 localhost\n";
        assert_eq!(ensure_entries(existing, None), existing);
    }

    #[test]
    fn empty_hostname_is_ignored() {
        assert_eq!(ensure_entries("", Some("")), "127.0.0.1\tlocalhost\n");
    }

    #[test]
    fn missing_trailing_newline_is_repaired_before_append() {
        let out = ensure_entries("127.0.0.1 localhost", Some("web"));
        assert_eq!(out, "127.0.0.1 localhost\n127.0.1.1\tweb\n");
    }

    #[test]
    fn sync_file_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        assert!(sync_file(&path, Some("web")).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1\tlocalhost\n127.0.1.1\tweb\n"
        );
    }

    #[test]
    fn sync_file_appends_to_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        assert!(sync_file(&path, Some("web")).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1 localhost\n127.0.1.1\tweb\n"
        );
    }

    #[test]
    fn sync_file_reports_untouched_when_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let complete = "127.0.0.1 localhost\n10.0.0.7 web\n";
        std::fs::write(&path, complete).unwrap();
        assert!(!sync_file(&path, Some("web")).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), complete);
    }

    #[test]
    fn sync_file_propagates_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        // The path IS a directory: read fails with something other than
        // NotFound, which must surface instead of clobbering the file.
        assert!(sync_file(dir.path(), Some("web")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sync_file_does_not_clobber_unreadable_file() {
        use std::os::unix::fs::PermissionsExt;
        // root ignores file modes, so the read below would succeed and the
        // assertion would be meaningless — skip (mirrors the crate's
        // environment-skip pattern for privileged/denied operations).
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "precious\n").unwrap();
        // Write-only: the read fails (non-NotFound) while a write WOULD
        // succeed — only correct error handling leaves the file intact.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
        let res = sync_file(&path, Some("web"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(res.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "precious\n");
    }
}
