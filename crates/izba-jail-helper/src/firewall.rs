//! Windows Firewall block/unblock rules for per-sandbox local accounts.
//!
//! Each provisioned sandbox account is made network-dead by two Windows
//! Firewall rules (outbound + inbound BLOCK) keyed by the account's SID in
//! SDDL form. The spike (`hack/spike/New-NetFirewallRule`) proved that a
//! `New-NetFirewallRule -LocalUser "D:(A;;CC;;;<SID>)"` rule reliably causes
//! outbound connects from that account to fail with `WSAEACCES`.
//!
//! # Rule naming
//!
//! Given a base rule name (e.g. `"izba-sb-<sandbox>"`) this module creates:
//!
//! - `<rule>` — outbound BLOCK
//! - `<rule>-in` — inbound BLOCK
//!
//! Both are created atomically by [`block`] and both are removed by
//! [`unblock`].
//!
//! # Implementation choice
//!
//! The implementation shells out to `powershell.exe -NoProfile -NonInteractive`
//! with a `-Command` string (per spec §5.5). The raw WFP COM API is NOT used —
//! PowerShell's `NetSecurity` cmdlets are the supported high-level surface and
//! the spike confirmed they work correctly.
//!
//! # Cross-compile note
//!
//! `std::process::Command` is available on all platforms, so this module
//! compiles everywhere. [`block`] and [`unblock`] early-return
//! `Err("windows-only")` on non-Windows to avoid actually spawning
//! `powershell.exe`. The pure command-builder functions ([`block_ps_command`],
//! [`unblock_ps_command`]) are fully testable on all platforms.

// ── Pure SDDL builder ────────────────────────────────────────────────────────

/// Build the SDDL `LocalUser` descriptor for `sid`.
///
/// The string `D:(A;;CC;;;<sid>)` is a DACL with a single ACE that grants the
/// `CC` (Create Child / Connect) right to the named SID. Windows Firewall
/// interprets this as "match traffic from this SID".
///
/// This replicates the one-liner from `izba-core/src/firewall.rs` without
/// creating a cross-crate dependency.
fn firewall_sddl(sid: &str) -> String {
    format!("D:(A;;CC;;;{sid})")
}

// ── Pure command builders ─────────────────────────────────────────────────────

/// Build the PowerShell `-Command` string that installs both firewall block
/// rules (outbound + inbound) for `sid` under the display name `rule`.
///
/// The outbound rule is named `<rule>` and the inbound rule `<rule>-in`.
///
/// The returned string is safe to pass directly as the argument to
/// `powershell -NoProfile -NonInteractive -Command <output>`.
pub fn block_ps_command(rule: &str, sid: &str) -> String {
    let sddl = firewall_sddl(sid);
    // Use a semicolon to chain the two New-NetFirewallRule calls in one
    // -Command invocation so we make only one powershell.exe process.
    format!(
        "New-NetFirewallRule \
            -DisplayName '{rule}' \
            -Direction Outbound \
            -Action Block \
            -Profile Any \
            -LocalUser \"{sddl}\"; \
        New-NetFirewallRule \
            -DisplayName '{rule}-in' \
            -Direction Inbound \
            -Action Block \
            -Profile Any \
            -LocalUser \"{sddl}\"",
    )
}

/// Build the PowerShell `-Command` string that removes both firewall rules
/// (outbound `<rule>` and inbound `<rule>-in`) installed by [`block_ps_command`].
///
/// Uses `-ErrorAction SilentlyContinue` so the command exits cleanly even when
/// the rules are already absent (idempotent).
pub fn unblock_ps_command(rule: &str) -> String {
    format!(
        "Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue \
            | Remove-NetFirewallRule -ErrorAction SilentlyContinue; \
        Get-NetFirewallRule -DisplayName '{rule}-in' -ErrorAction SilentlyContinue \
            | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
    )
}

// ── Execution helpers ─────────────────────────────────────────────────────────

/// Run a PowerShell command string and surface non-zero exit codes / stderr as
/// `Err`.
#[cfg_attr(not(windows), allow(dead_code))]
fn run_ps(cmd: &str) -> Result<(), String> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
        .output()
        .map_err(|e| format!("powershell spawn failed: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!(
        "powershell exited with {}: stderr={stderr:?} stdout={stdout:?}",
        output.status
    ))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Install outbound + inbound BLOCK rules for the account identified by `sid`.
///
/// Creates two rules:
/// - `<rule>` — outbound BLOCK
/// - `<rule>-in` — inbound BLOCK
///
/// Requires administrator/elevated privileges.
///
/// On non-Windows returns `Err("windows-only")` without spawning any process.
#[cfg(windows)]
pub fn block(rule: &str, sid: &str) -> Result<(), String> {
    run_ps(&block_ps_command(rule, sid))
}

/// Install outbound + inbound BLOCK rules — stub on non-Windows.
///
/// Returns `Err("windows-only")`.
#[cfg(not(windows))]
pub fn block(_rule: &str, _sid: &str) -> Result<(), String> {
    Err("windows-only".into())
}

/// Remove both firewall rules created by [`block`] (idempotent).
///
/// Treats "no matching rule" as success. Uses `-ErrorAction SilentlyContinue`
/// in the PowerShell command so a missing rule does not cause a non-zero exit.
///
/// On non-Windows returns `Err("windows-only")` without spawning any process.
#[cfg(windows)]
pub fn unblock(rule: &str) -> Result<(), String> {
    run_ps(&unblock_ps_command(rule))
}

/// Remove both firewall rules — stub on non-Windows.
///
/// Returns `Err("windows-only")`.
#[cfg(not(windows))]
pub fn unblock(_rule: &str) -> Result<(), String> {
    Err("windows-only".into())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── firewall_sddl ────────────────────────────────────────────────────────

    #[test]
    fn sddl_format() {
        assert_eq!(
            firewall_sddl("S-1-5-21-111-222-333-1001"),
            "D:(A;;CC;;;S-1-5-21-111-222-333-1001)"
        );
    }

    // ── block_ps_command ─────────────────────────────────────────────────────

    #[test]
    fn block_cmd_contains_new_firewall_rule() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("New-NetFirewallRule"),
            "block command must contain New-NetFirewallRule: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_contains_display_name_outbound() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-DisplayName 'izba-sb-mybox'"),
            "block command must have outbound display name: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_contains_display_name_inbound() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-DisplayName 'izba-sb-mybox-in'"),
            "block command must have inbound display name: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_direction_outbound() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-Direction Outbound"),
            "block command must specify -Direction Outbound: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_direction_inbound() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-Direction Inbound"),
            "block command must specify -Direction Inbound: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_action_block() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-Action Block"),
            "block command must specify -Action Block: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_profile_any() {
        let cmd = block_ps_command("izba-sb-mybox", "S-1-5-21-111-222-333-1001");
        assert!(
            cmd.contains("-Profile Any"),
            "block command must specify -Profile Any: {cmd:?}"
        );
    }

    #[test]
    fn block_cmd_local_user_sddl() {
        let sid = "S-1-5-21-111-222-333-1001";
        let cmd = block_ps_command("izba-sb-mybox", sid);
        let expected_sddl = format!("-LocalUser \"D:(A;;CC;;;{sid})\"");
        assert!(
            cmd.contains(&expected_sddl),
            "block command must contain -LocalUser with correct SDDL: {cmd:?}"
        );
    }

    // ── unblock_ps_command ───────────────────────────────────────────────────

    #[test]
    fn unblock_cmd_contains_get_firewall_rule() {
        let cmd = unblock_ps_command("izba-sb-mybox");
        assert!(
            cmd.contains("Get-NetFirewallRule"),
            "unblock command must contain Get-NetFirewallRule: {cmd:?}"
        );
    }

    #[test]
    fn unblock_cmd_contains_remove_firewall_rule() {
        let cmd = unblock_ps_command("izba-sb-mybox");
        assert!(
            cmd.contains("Remove-NetFirewallRule"),
            "unblock command must contain Remove-NetFirewallRule: {cmd:?}"
        );
    }

    #[test]
    fn unblock_cmd_contains_display_name_outbound() {
        let cmd = unblock_ps_command("izba-sb-mybox");
        assert!(
            cmd.contains("'izba-sb-mybox'"),
            "unblock command must reference outbound rule name: {cmd:?}"
        );
    }

    #[test]
    fn unblock_cmd_contains_display_name_inbound() {
        let cmd = unblock_ps_command("izba-sb-mybox");
        assert!(
            cmd.contains("'izba-sb-mybox-in'"),
            "unblock command must reference inbound rule name: {cmd:?}"
        );
    }

    #[test]
    fn unblock_cmd_is_idempotent_silent_continue() {
        let cmd = unblock_ps_command("izba-sb-mybox");
        assert!(
            cmd.contains("SilentlyContinue"),
            "unblock command must use -ErrorAction SilentlyContinue for idempotency: {cmd:?}"
        );
    }

    // ── Windows execution test (elevation-gated) ─────────────────────────────
    // Skipped on non-Windows at compile time.  On Windows it creates a throwaway
    // rule with an obviously-fake SID, verifies no error, then removes it.
    // If PowerShell cannot be found or elevation is missing, it runtime-skips.

    #[cfg(windows)]
    #[test]
    fn block_unblock_roundtrip_throwaway_rule() {
        // Use a well-formed but synthetic SID (NULL SID = S-1-0-0) for the test
        // so we never accidentally affect a real account.
        let test_rule = format!("izba-fw-test-{}", std::process::id());
        let test_sid = "S-1-0-0";

        let result = block(&test_rule, test_sid);
        if let Err(ref e) = result {
            if e.contains("Access is denied")
                || e.contains("access denied")
                || e.contains("elevated")
            {
                eprintln!("block_unblock_roundtrip_throwaway_rule: not elevated, skipping");
                return;
            }
            if e.contains("powershell spawn failed") {
                eprintln!("block_unblock_roundtrip_throwaway_rule: powershell not found, skipping");
                return;
            }
        }
        result.expect("block should succeed when elevated");

        // Cleanup — must succeed (idempotent).
        unblock(&test_rule).expect("unblock should succeed");
        // Second unblock must also succeed (idempotent).
        unblock(&test_rule).expect("second unblock (already gone) should succeed");
    }
}
