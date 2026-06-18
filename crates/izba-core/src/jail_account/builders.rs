use std::path::{Path, PathBuf};

/// Returns the Windows Firewall SDDL for a single-account inbound CC allow rule.
///
/// Format: `D:(A;;CC;;;<sid>)` — one DACL ACE granting `CC` (create connection)
/// to the given SID.  This string is passed verbatim to `netsh` or the Windows
/// Firewall COM API.
pub fn firewall_sddl(sid: &str) -> String {
    format!("D:(A;;CC;;;{sid})")
}

/// Sanitize a sandbox name into the common `<safe>` slug used in both the
/// account and rule names.
///
/// Rules: lowercase; any char outside `[a-z0-9-]` → `-`.
fn safe_slug(sandbox: &str) -> String {
    sandbox
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Windows local account name for the per-sandbox VMM process.
///
/// Format: `izba-spk-<safe>`, where `<safe>` is the sanitized sandbox name.
/// The total length is capped at **20 characters** (Windows local-username
/// limit); the `<safe>` portion is truncated if necessary so that
/// `"izba-spk-".len() + safe.len() ≤ 20`.
pub fn account_name(sandbox: &str) -> String {
    const PREFIX: &str = "izba-spk-";
    const MAX: usize = 20;
    let safe = safe_slug(sandbox);
    let max_safe = MAX - PREFIX.len(); // 11
    let truncated = &safe[..safe.len().min(max_safe)];
    let name = format!("{PREFIX}{truncated}");
    debug_assert!(name.len() <= MAX, "account_name too long: {name}");
    name
}

/// Windows Firewall rule display-name for the per-sandbox deny rule.
///
/// Format: `izba-deny-<safe>` — no length cap (firewall DisplayNames are
/// long-tolerant), but the same sanitization is applied for consistency.
pub fn rule_name(sandbox: &str) -> String {
    format!("izba-deny-{}", safe_slug(sandbox))
}

/// argv vector for the elevated helper's `provision` sub-command.
///
/// Produces:
/// ```text
/// provision --sandbox <name> --grant <path0> [--grant <pathN>…] --sid-out <file> --cred-out <file>
/// ```
pub fn provision_argv(
    sandbox: &str,
    grants: &[PathBuf],
    sid_out: &Path,
    cred_out: &Path,
) -> Vec<String> {
    let mut argv = vec![
        "provision".to_string(),
        "--sandbox".to_string(),
        sandbox.to_string(),
    ];
    for g in grants {
        argv.push("--grant".to_string());
        argv.push(g.to_string_lossy().into_owned());
    }
    argv.push("--sid-out".to_string());
    argv.push(sid_out.to_string_lossy().into_owned());
    argv.push("--cred-out".to_string());
    argv.push(cred_out.to_string_lossy().into_owned());
    argv
}

/// argv vector for the elevated helper's `deprovision` sub-command.
///
/// Produces: `deprovision --sandbox <name>`
pub fn deprovision_argv(sandbox: &str) -> Vec<String> {
    vec![
        "deprovision".to_string(),
        "--sandbox".to_string(),
        sandbox.to_string(),
    ]
}

/// argv vector for the elevated helper's `gc` sub-command.
///
/// Produces: `gc --live <name0> [--live <nameN>…]`
pub fn gc_argv(live: &[String]) -> Vec<String> {
    let mut argv = vec!["gc".to_string()];
    for name in live {
        argv.push("--live".to_string());
        argv.push(name.clone());
    }
    argv
}

/// Returns the `izba-spk-*` account names from `existing` whose corresponding
/// sandbox name is **not** in `live`.
///
/// The sandbox name is recovered by stripping the `izba-spk-` prefix; the
/// comparison is done on the sanitized form, so `live` entries are also
/// sanitized before the lookup.
pub fn gc_orphans(existing: &[String], live: &[String]) -> Vec<String> {
    const PREFIX: &str = "izba-spk-";
    // Build a set of sanitized live slugs for O(1) lookup.
    let live_slugs: std::collections::HashSet<String> = live.iter().map(|s| safe_slug(s)).collect();
    existing
        .iter()
        .filter(|name| {
            if let Some(slug) = name.strip_prefix(PREFIX) {
                // The stored name already went through safe_slug at creation
                // time; compare directly.
                !live_slugs.contains(slug)
            } else {
                // Not an izba-spk-* name — leave it alone (not our concern).
                false
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── firewall_sddl ────────────────────────────────────────────────────────

    #[test]
    fn sddl_basic() {
        assert_eq!(firewall_sddl("S-1-5-21-1"), "D:(A;;CC;;;S-1-5-21-1)");
    }

    #[test]
    fn sddl_full_sid() {
        let sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
        assert_eq!(firewall_sddl(sid), format!("D:(A;;CC;;;{sid})"));
    }

    // ── safe_slug / account_name / rule_name ─────────────────────────────────

    #[test]
    fn account_name_simple() {
        assert_eq!(account_name("my-box"), "izba-spk-my-box");
    }

    #[test]
    fn account_name_uppercase_spaces() {
        // "My Box" → lowercase + space→dash
        assert_eq!(account_name("My Box"), "izba-spk-my-box");
    }

    #[test]
    fn account_name_special_chars() {
        // Special chars → dash
        assert_eq!(account_name("foo_bar.baz"), "izba-spk-foo-bar-baz");
    }

    #[test]
    fn account_name_length_cap() {
        // A very long sandbox name must produce an account name ≤ 20 chars.
        let long = "a-very-long-sandbox-name-that-exceeds-the-limit";
        let name = account_name(long);
        assert!(
            name.len() <= 20,
            "account_name too long ({} chars): {name}",
            name.len()
        );
        assert!(name.starts_with("izba-spk-"));
    }

    #[test]
    fn account_name_max_boundary() {
        // Exactly 11-char safe part should yield exactly 20-char account.
        let sandbox = "12345678901"; // 11 chars, all alnum
        let name = account_name(sandbox);
        assert_eq!(name.len(), 20);
        assert_eq!(name, "izba-spk-12345678901");
    }

    #[test]
    fn account_name_truncation_correctness() {
        // safe slug of "abcdefghijklmnopqrstuvwxyz" is itself (26 lowercase alpha).
        // Truncated to 11: "abcdefghijk".
        let name = account_name("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(name, "izba-spk-abcdefghijk");
        assert_eq!(name.len(), 20);
    }

    #[test]
    fn rule_name_simple() {
        assert_eq!(rule_name("my-box"), "izba-deny-my-box");
    }

    #[test]
    fn rule_name_long_not_truncated() {
        // Rule names have no hard cap — long names should not be truncated.
        let long = "a-very-long-sandbox-name-that-exceeds-twenty-chars";
        let rn = rule_name(long);
        assert!(rn.starts_with("izba-deny-"));
        // The safe part must be the full sanitized name.
        let expected_safe = safe_slug(long);
        assert_eq!(rn, format!("izba-deny-{expected_safe}"));
    }

    // ── provision_argv ────────────────────────────────────────────────────────

    #[test]
    fn provision_argv_single_grant() {
        let argv = provision_argv(
            "my-sandbox",
            &[PathBuf::from("/run/vm/my-sandbox")],
            Path::new("/tmp/sid.txt"),
            Path::new("/tmp/cred.json"),
        );
        assert_eq!(
            argv,
            vec![
                "provision",
                "--sandbox",
                "my-sandbox",
                "--grant",
                "/run/vm/my-sandbox",
                "--sid-out",
                "/tmp/sid.txt",
                "--cred-out",
                "/tmp/cred.json",
            ]
        );
    }

    #[test]
    fn provision_argv_multiple_grants() {
        let argv = provision_argv(
            "sb",
            &[
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ],
            Path::new("/x/sid"),
            Path::new("/x/cred"),
        );
        // Spot-check the grant flags appear in order.
        let grants: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0] == "--grant")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(grants, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn provision_argv_no_grants() {
        let argv = provision_argv("sb", &[], Path::new("/sid"), Path::new("/cred"));
        assert_eq!(
            argv,
            vec![
                "provision",
                "--sandbox",
                "sb",
                "--sid-out",
                "/sid",
                "--cred-out",
                "/cred"
            ]
        );
    }

    // ── deprovision_argv ──────────────────────────────────────────────────────

    #[test]
    fn deprovision_argv_basic() {
        assert_eq!(
            deprovision_argv("my-sandbox"),
            vec!["deprovision", "--sandbox", "my-sandbox"]
        );
    }

    // ── gc_argv ───────────────────────────────────────────────────────────────

    #[test]
    fn gc_argv_multiple_live() {
        let live = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let argv = gc_argv(&live);
        assert_eq!(
            argv,
            vec!["gc", "--live", "a", "--live", "b", "--live", "c"]
        );
    }

    #[test]
    fn gc_argv_empty_live() {
        let argv = gc_argv(&[]);
        assert_eq!(argv, vec!["gc"]);
    }

    // ── gc_orphans ────────────────────────────────────────────────────────────

    #[test]
    fn gc_orphans_basic() {
        let existing = vec!["izba-spk-a".to_string(), "izba-spk-b".to_string()];
        let live = vec!["a".to_string()];
        let orphans = gc_orphans(&existing, &live);
        assert_eq!(orphans, vec!["izba-spk-b"]);
    }

    #[test]
    fn gc_orphans_all_live() {
        let existing = vec!["izba-spk-a".to_string(), "izba-spk-b".to_string()];
        let live = vec!["a".to_string(), "b".to_string()];
        assert!(gc_orphans(&existing, &live).is_empty());
    }

    #[test]
    fn gc_orphans_none_live() {
        let existing = vec!["izba-spk-x".to_string(), "izba-spk-y".to_string()];
        let orphans = gc_orphans(&existing, &[]);
        assert_eq!(orphans.len(), 2);
    }

    #[test]
    fn gc_orphans_ignores_non_izba_names() {
        // Accounts not prefixed with izba-spk- should be left alone (not returned).
        let existing = vec!["izba-spk-a".to_string(), "some-other-account".to_string()];
        let live: Vec<String> = vec![];
        let orphans = gc_orphans(&existing, &live);
        // Only the izba-spk-a is an orphan; some-other-account is ignored.
        assert_eq!(orphans, vec!["izba-spk-a"]);
    }

    #[test]
    fn gc_orphans_live_unsanitized_matches() {
        // Live names go through safe_slug, so "My Box" matches stored "my-box".
        let existing = vec!["izba-spk-my-box".to_string()];
        let live = vec!["My Box".to_string()];
        // "My Box" → safe_slug → "my-box", which is the stored slug.
        assert!(gc_orphans(&existing, &live).is_empty());
    }
}
