//! Pure-std naming utilities for izba per-sandbox Windows local accounts and
//! firewall rules.
//!
//! This crate has **no dependencies** (pure `std`) so it can be embedded in
//! the ELEVATED `izba-jail-helper` binary without pulling in the full
//! `izba-core` dependency tree (hyper / TLS / OCI / hickory …).

use std::path::{Path, PathBuf};

/// Returns the Windows Firewall SDDL match condition for a single account.
///
/// Format: `D:(A;;CC;;;<sid>)` — one DACL ACE granting `CC` (create connection)
/// to the given SID.  This string is the `-LocalUser` condition that tells the
/// Firewall rule *which user's traffic to match*.  The actual action (Block or
/// Allow) is determined by the `-Action` parameter of `New-NetFirewallRule`, not
/// by the SDDL itself; the rules created by `izba-jail-helper` use `-Action Block`.
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

/// Maximum length of a Windows local account name.
const ACCOUNT_NAME_MAX: usize = 20;

/// The fixed prefix for all izba per-sandbox Windows accounts.
pub const ACCOUNT_PREFIX: &str = "izba-sb-";

/// The fixed prefix for all izba per-sandbox Windows Firewall deny rules.
pub const RULE_PREFIX: &str = "izba-deny-";

/// Maximum characters of the sanitized slug that fit inside `ACCOUNT_NAME_MAX`.
/// `ACCOUNT_NAME_MAX - ACCOUNT_PREFIX.len()` = 20 - 8 = 12.
///
/// Both `account_name` and `rule_name` truncate to this length so that the slug
/// embedded in the rule name round-trips with the slug embedded in the account
/// name — enabling GC to reconstruct the correct rule name from a stored
/// truncated account name.
pub const ACCOUNT_SLUG_MAX: usize = ACCOUNT_NAME_MAX - ACCOUNT_PREFIX.len();

/// Windows local account name for the per-sandbox VMM process.
///
/// Format: `izba-sb-<safe>`, where `<safe>` is the sanitized sandbox name.
/// The total length is capped at **20 characters** (Windows local-username
/// limit); the `<safe>` portion is truncated to [`ACCOUNT_SLUG_MAX`] chars if
/// necessary so that `ACCOUNT_PREFIX.len() + safe.len() ≤ ACCOUNT_NAME_MAX`.
pub fn account_name(sandbox: &str) -> String {
    let safe = safe_slug(sandbox);
    let truncated = &safe[..safe.len().min(ACCOUNT_SLUG_MAX)];
    let name = format!("{ACCOUNT_PREFIX}{truncated}");
    debug_assert!(
        name.len() <= ACCOUNT_NAME_MAX,
        "account_name too long: {name}"
    );
    name
}

/// Windows Firewall rule display-name for the per-sandbox deny rule.
///
/// Format: `izba-deny-<safe>` — the sanitized, **truncated** sandbox slug,
/// using the same [`ACCOUNT_SLUG_MAX`] cap as [`account_name`].  This ensures
/// the slug embedded in the rule name is identical to the slug embedded in the
/// account name, so GC can reconstruct the correct rule name from a stored
/// truncated account name and clean up firewall rules that were installed at
/// provision time.
pub fn rule_name(sandbox: &str) -> String {
    let safe = safe_slug(sandbox);
    let truncated = &safe[..safe.len().min(ACCOUNT_SLUG_MAX)];
    format!("{RULE_PREFIX}{truncated}")
}

/// argv vector for the elevated helper's `provision` sub-command.
///
/// Produces:
/// ```text
/// provision --sandbox <name> --grant <rw0> [--grant <rwN>…] --grant-ro <ro0> [--grant-ro <roN>…] --sid-out <file> --cred-out <file>
/// ```
///
/// `grants_rw` paths receive `Modify` (read/write) access — sandbox-specific
/// paths such as the workspace, sandbox dir, and named volume images.
///
/// `grants_ro` paths receive `ReadExec` (read-only) access — shared RO
/// artifacts such as `images_dir` (erofs base images) and `artifacts_dir`
/// (kernel + initrd).
pub fn provision_argv(
    sandbox: &str,
    grants_rw: &[PathBuf],
    grants_ro: &[PathBuf],
    sid_out: &Path,
    cred_out: &Path,
) -> Vec<String> {
    let mut argv = vec![
        "provision".to_string(),
        "--sandbox".to_string(),
        sandbox.to_string(),
    ];
    for g in grants_rw {
        argv.push("--grant".to_string());
        argv.push(g.to_string_lossy().into_owned());
    }
    for g in grants_ro {
        argv.push("--grant-ro".to_string());
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

/// Returns the `izba-sb-*` account names from `existing` whose corresponding
/// sandbox name is **not** in `live`.
///
/// Orphan detection is based on the full `account_name(sandbox)` — including
/// the same truncation that `account_name` applies — so a sandbox whose safe
/// slug exceeds [`ACCOUNT_SLUG_MAX`] chars is matched by its truncated stored
/// account name and is never falsely classified as an orphan.
pub fn gc_orphans(existing: &[String], live: &[String]) -> Vec<String> {
    // Build a set of full account names for all live sandboxes.  Using
    // `account_name` here means the same truncation is applied on both sides
    // of the comparison, eliminating the mismatch that would arise if we
    // compared a truncated stored slug against an untruncated live slug.
    let live_accounts: std::collections::HashSet<String> =
        live.iter().map(|s| account_name(s)).collect();
    existing
        .iter()
        .filter(|name| {
            if name.starts_with(ACCOUNT_PREFIX) {
                // An existing izba-sb-* account is an orphan iff it does not
                // correspond to any currently-live sandbox.
                !live_accounts.contains(*name)
            } else {
                // Not an izba-sb-* name — leave it alone (not our concern).
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
        assert_eq!(account_name("my-box"), "izba-sb-my-box");
    }

    #[test]
    fn account_name_uppercase_spaces() {
        // "My Box" → lowercase + space→dash
        assert_eq!(account_name("My Box"), "izba-sb-my-box");
    }

    #[test]
    fn account_name_special_chars() {
        // Special chars → dash
        assert_eq!(account_name("foo_bar.baz"), "izba-sb-foo-bar-baz");
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
        assert!(name.starts_with("izba-sb-"));
    }

    #[test]
    fn account_name_max_boundary() {
        // Exactly 12-char safe part should yield exactly 20-char account.
        let sandbox = "123456789012"; // 12 chars, all alnum
        let name = account_name(sandbox);
        assert_eq!(name.len(), 20);
        assert_eq!(name, "izba-sb-123456789012");
    }

    #[test]
    fn account_name_truncation_correctness() {
        // safe slug of "abcdefghijklmnopqrstuvwxyz" is itself (26 lowercase alpha).
        // Truncated to 12: "abcdefghijkl".
        let name = account_name("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(name, "izba-sb-abcdefghijkl");
        assert_eq!(name.len(), 20);
    }

    #[test]
    fn rule_name_simple() {
        assert_eq!(rule_name("my-box"), "izba-deny-my-box");
    }

    /// For a long sandbox name, `rule_name` must truncate the slug to the same
    /// `ACCOUNT_SLUG_MAX` as `account_name`.  This round-trip consistency is
    /// what lets GC reconstruct the correct firewall rule name from a stored
    /// truncated account name.
    ///
    /// The slug length cap (`ACCOUNT_SLUG_MAX` = 12) is what matters, not the
    /// total length of the rule name.  The rule prefix is 10 chars
    /// (`"izba-deny-"`) vs the account prefix's 8 (`"izba-sb-"`), so the rule
    /// name will always be two characters longer than the account name — the
    /// important invariant is slug equality, not overall-name equality.
    #[test]
    fn rule_name_long_truncated_consistently() {
        let long = "a-very-long-sandbox-name-that-exceeds-twenty-chars";

        let rn = rule_name(long);
        let an = account_name(long);

        assert!(
            rn.starts_with("izba-deny-"),
            "rule_name must start with izba-deny-: {rn}"
        );
        assert!(
            an.starts_with("izba-sb-"),
            "account_name must start with izba-sb-: {an}"
        );

        // Both slugs must be equal (same truncation to ACCOUNT_SLUG_MAX = 12).
        let rule_slug = rn.strip_prefix("izba-deny-").unwrap();
        let acct_slug = an.strip_prefix("izba-sb-").unwrap();
        assert_eq!(
            rule_slug, acct_slug,
            "rule_name slug '{rule_slug}' must match account_name slug '{acct_slug}'"
        );

        // Slug length must be capped at ACCOUNT_SLUG_MAX.
        assert!(
            rule_slug.len() <= ACCOUNT_SLUG_MAX,
            "rule slug must be ≤ ACCOUNT_SLUG_MAX ({ACCOUNT_SLUG_MAX}) chars: '{rule_slug}' (len={})",
            rule_slug.len()
        );
    }

    // ── provision_argv ────────────────────────────────────────────────────────

    #[test]
    fn provision_argv_single_grant() {
        let argv = provision_argv(
            "my-sandbox",
            &[PathBuf::from("/run/vm/my-sandbox")],
            &[],
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
            &[],
            Path::new("/x/sid"),
            Path::new("/x/cred"),
        );
        // Spot-check the --grant flags appear in order.
        let grants: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0] == "--grant")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(grants, vec!["/a", "/b", "/c"]);
        // No --grant-ro flags present.
        assert!(!argv.iter().any(|s| s == "--grant-ro"));
    }

    #[test]
    fn provision_argv_no_grants() {
        let argv = provision_argv("sb", &[], &[], Path::new("/sid"), Path::new("/cred"));
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

    #[test]
    fn provision_argv_ro_grants_emitted() {
        let argv = provision_argv(
            "sb",
            &[PathBuf::from("/rw/sandbox")],
            &[PathBuf::from("/ro/images"), PathBuf::from("/ro/artifacts")],
            Path::new("/sid"),
            Path::new("/cred"),
        );
        // --grant-ro must appear for each RO path.
        let ro_grants: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0] == "--grant-ro")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(ro_grants, vec!["/ro/images", "/ro/artifacts"]);
        // --grant (RW) still present for the rw path.
        let rw_grants: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0] == "--grant")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(rw_grants, vec!["/rw/sandbox"]);
    }

    #[test]
    fn provision_argv_ro_grants_after_rw_grants() {
        // RO grants must appear AFTER all RW grants in the argv vector, before
        // --sid-out / --cred-out.
        let argv = provision_argv(
            "sb",
            &[PathBuf::from("/rw/a"), PathBuf::from("/rw/b")],
            &[PathBuf::from("/ro/images")],
            Path::new("/sid"),
            Path::new("/cred"),
        );
        let last_grant_idx = argv
            .iter()
            .enumerate()
            .filter(|(_, s)| s.as_str() == "--grant")
            .map(|(i, _)| i)
            .next_back()
            .unwrap();
        let first_grant_ro_idx = argv
            .iter()
            .enumerate()
            .find(|(_, s)| s.as_str() == "--grant-ro")
            .map(|(i, _)| i)
            .unwrap();
        assert!(
            first_grant_ro_idx > last_grant_idx,
            "--grant-ro must appear after all --grant flags"
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
        let existing = vec!["izba-sb-a".to_string(), "izba-sb-b".to_string()];
        let live = vec!["a".to_string()];
        let orphans = gc_orphans(&existing, &live);
        assert_eq!(orphans, vec!["izba-sb-b"]);
    }

    #[test]
    fn gc_orphans_all_live() {
        let existing = vec!["izba-sb-a".to_string(), "izba-sb-b".to_string()];
        let live = vec!["a".to_string(), "b".to_string()];
        assert!(gc_orphans(&existing, &live).is_empty());
    }

    #[test]
    fn gc_orphans_none_live() {
        let existing = vec!["izba-sb-x".to_string(), "izba-sb-y".to_string()];
        let orphans = gc_orphans(&existing, &[]);
        assert_eq!(orphans.len(), 2);
    }

    #[test]
    fn gc_orphans_ignores_non_izba_names() {
        // Accounts not prefixed with izba-sb- should be left alone (not returned).
        let existing = vec!["izba-sb-a".to_string(), "some-other-account".to_string()];
        let live: Vec<String> = vec![];
        let orphans = gc_orphans(&existing, &live);
        // Only the izba-sb-a is an orphan; some-other-account is ignored.
        assert_eq!(orphans, vec!["izba-sb-a"]);
    }

    #[test]
    fn gc_orphans_live_unsanitized_matches() {
        // Live names go through safe_slug, so "My Box" matches stored "my-box".
        let existing = vec!["izba-sb-my-box".to_string()];
        let live = vec!["My Box".to_string()];
        // "My Box" → safe_slug → "my-box", which is the stored slug.
        assert!(gc_orphans(&existing, &live).is_empty());
    }

    #[test]
    fn gc_orphans_long_name_not_false_orphan() {
        // A sandbox whose safe slug exceeds ACCOUNT_SLUG_MAX (12) must NOT be
        // reported as an orphan when it is actually live.
        //
        // "my-very-long-sandbox-name" → safe slug "my-very-long-sandbox-name"
        // (25 chars, > 12) → account_name truncates to "izba-sb-my-very-lon"
        // (19 chars).  The stored account is the TRUNCATED form; the bug was
        // that gc_orphans compared the truncated stored slug ("my-very-lon")
        // against the untruncated live slug ("my-very-long-sandbox-name") and
        // never found a match, falsely classifying the account as an orphan.
        let sandbox = "my-very-long-sandbox-name";
        let stored_account = account_name(sandbox); // "izba-sb-my-very-long"
        assert_eq!(stored_account.len(), 20);

        let existing = vec![stored_account];
        let live = vec![sandbox.to_string()];
        assert!(
            gc_orphans(&existing, &live).is_empty(),
            "live long-named sandbox was falsely classified as an orphan"
        );
    }

    #[test]
    fn gc_orphans_long_live_mixed_with_genuine_orphan() {
        // Mix: one long-named live sandbox (truncated account) + one genuine
        // orphan.  Only the orphan must be returned.
        let live_sandbox = "my-very-long-sandbox-name";
        let live_account = account_name(live_sandbox); // "izba-sb-my-very-long"
        let orphan_account = "izba-sb-gone".to_string();

        let existing = vec![live_account.clone(), orphan_account.clone()];
        let live = vec![live_sandbox.to_string()];
        let orphans = gc_orphans(&existing, &live);
        assert_eq!(
            orphans,
            vec![orphan_account],
            "expected only the genuine orphan to be returned"
        );
    }
}
