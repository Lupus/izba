//! Transactional `provision` / `deprovision` / `gc` orchestration for
//! per-sandbox Windows local accounts.
//!
//! # Design
//!
//! All orchestration logic goes through the [`Ops`] trait so the ordering and
//! rollback behaviour are fully testable without FFI. The real Windows
//! implementation is [`WinOps`], gated to `#[cfg(windows)]`. A [`FakeOps`]
//! that records calls and can be told to fail at a specific step lives in the
//! `#[cfg(test)]` section and drives the unit tests.
//!
//! # Provisioning steps (in order)
//!
//! 1. `create_account` → sid + password
//! 2. `hide` (suppress from the Windows sign-in screen)
//! 3. For each granted path: `grant(path, sid, Modify)`
//! 4. `block(rule, sid)` (Windows Firewall deny rule)
//! 5. Write `sid_out` and `cred_out`.
//!
//! Any failure triggers a reverse rollback: unblock → unhide → delete_account
//! (in reverse order of what was already done).

use std::path::{Path, PathBuf};

#[cfg(windows)]
use izba_jail_naming::ACCOUNT_PREFIX;
use izba_jail_naming::{account_name, gc_orphans, rule_name};

use crate::dacl::GrantLevel;

// ── Ops trait (all platforms) ────────────────────────────────────────────────

/// Operations surface used by the orchestration functions.
///
/// All methods return `Result<_, String>` where the error is a human-readable
/// diagnostic. Implementations must be idempotent where the function
/// description says "idempotent".
pub trait Ops {
    /// Create a local account with `name`.
    ///
    /// Returns `(sid_string, password)` on success.
    fn create_account(&self, name: &str) -> Result<(String, String), String>;

    /// Delete the local account `name` (idempotent — absent is Ok).
    fn delete_account(&self, name: &str) -> Result<(), String>;

    /// Best-effort profile deletion for `name`.
    fn delete_profile(&self, name: &str);

    /// Hide `name` from the Windows sign-in screen (idempotent).
    fn hide(&self, name: &str) -> Result<(), String>;

    /// Restore `name`'s sign-in-screen visibility (idempotent — absent is Ok).
    fn unhide(&self, name: &str) -> Result<(), String>;

    /// Add an inheritable `Modify` ACE for `sid` to `path`.
    fn grant(&self, path: &Path, sid: &str, level: GrantLevel) -> Result<(), String>;

    /// Install outbound + inbound BLOCK rules for `sid`.
    fn block(&self, rule: &str, sid: &str) -> Result<(), String>;

    /// Remove the firewall rules for `rule` (idempotent — absent is Ok).
    fn unblock(&self, rule: &str) -> Result<(), String>;

    /// Return all local account names matching the `izba-spk-*` prefix.
    ///
    /// The real implementation uses `NetUserEnum`; the fake returns a
    /// pre-loaded list.
    fn enumerate_accounts(&self) -> Result<Vec<String>, String>;
}

// ── Windows implementation ────────────────────────────────────────────────────

/// Real Windows implementation of [`Ops`].  Calls Tasks 4-6 FFI functions.
#[cfg(windows)]
pub struct WinOps;

#[cfg(windows)]
impl Ops for WinOps {
    fn create_account(&self, name: &str) -> Result<(String, String), String> {
        crate::account::create_account(name)
    }

    fn delete_account(&self, name: &str) -> Result<(), String> {
        crate::account::delete_account(name)
    }

    fn delete_profile(&self, name: &str) {
        crate::account::delete_profile(name)
    }

    fn hide(&self, name: &str) -> Result<(), String> {
        crate::userlist::hide(name)
    }

    fn unhide(&self, name: &str) -> Result<(), String> {
        crate::userlist::unhide(name)
    }

    fn grant(&self, path: &Path, sid: &str, level: GrantLevel) -> Result<(), String> {
        crate::dacl::grant(path, sid, level)
    }

    fn block(&self, rule: &str, sid: &str) -> Result<(), String> {
        crate::firewall::block(rule, sid)
    }

    fn unblock(&self, rule: &str) -> Result<(), String> {
        crate::firewall::unblock(rule)
    }

    fn enumerate_accounts(&self) -> Result<Vec<String>, String> {
        win_enumerate_accounts()
    }
}

/// Enumerate local accounts via `NetUserEnum` level 0 and return those whose
/// names start with `izba-spk-`.
#[cfg(windows)]
fn win_enumerate_accounts() -> Result<Vec<String>, String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_Success, NetApiBufferFree, NetUserEnum, FILTER_NORMAL_ACCOUNT, USER_INFO_0,
    };

    const MAX_PREFERRED_LEN: u32 = u32::MAX;

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;
    let mut names: Vec<String> = Vec::new();

    loop {
        // SAFETY: NetUserEnum is called with valid out-parameters; the buffer is
        // freed via NetApiBufferFree on every exit path.
        let status = unsafe {
            NetUserEnum(
                std::ptr::null(),      // local machine
                0,                     // level 0 = name only
                FILTER_NORMAL_ACCOUNT, // filter: normal accounts
                &mut buf,
                MAX_PREFERRED_LEN,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        let done = status == NERR_Success;
        // ERROR_MORE_DATA (234) means there are more entries — keep looping.
        const ERROR_MORE_DATA: u32 = 234;
        if status != NERR_Success && status != ERROR_MORE_DATA {
            // Free buffer if allocated before returning error.
            if !buf.is_null() {
                unsafe { NetApiBufferFree(buf as *mut _) };
            }
            return Err(format!("NetUserEnum: NET_API_STATUS {status}"));
        }

        // SAFETY: buf points to an array of USER_INFO_0 (only the usri0_name
        // field, a *const u16 NUL-terminated UTF-16 string).
        unsafe {
            let entries =
                std::slice::from_raw_parts(buf as *const USER_INFO_0, entries_read as usize);
            for entry in entries {
                if entry.usri0_name.is_null() {
                    continue;
                }
                // Decode the NUL-terminated UTF-16 name.
                let len = (0..).take_while(|&i| *entry.usri0_name.add(i) != 0).count();
                let slice = std::slice::from_raw_parts(entry.usri0_name, len);
                if let Ok(name) = String::from_utf16(slice) {
                    if name.starts_with(ACCOUNT_PREFIX) {
                        names.push(name);
                    }
                }
            }
            NetApiBufferFree(buf as *mut _);
            buf = std::ptr::null_mut();
        }

        if done {
            break;
        }
    }

    Ok(names)
}

// ── Provision ────────────────────────────────────────────────────────────────

/// Provision a per-sandbox Windows local account.
///
/// Steps (in order):
/// 1. Create the account (`izba-spk-<slug>`).
/// 2. Hide it from the Windows sign-in screen.
/// 3. Grant `Modify` access to each path in `grants`.
/// 4. Install the firewall deny rule (`izba-deny-<slug>`) keyed to the SID.
/// 5. Write the SID to `sid_out` and the password to `cred_out`.
///
/// On any failure, everything created so far is rolled back in reverse order
/// before the error is returned.
pub fn provision<O: Ops>(
    ops: &O,
    sandbox: &str,
    grants: &[PathBuf],
    sid_out: &Path,
    cred_out: &Path,
) -> Result<(), String> {
    let acct = account_name(sandbox);
    let rule = rule_name(sandbox);

    // Track rollback obligations as we go.
    let mut hidden = false;
    let mut grants_applied: usize = 0;

    // Step 1: create account.
    let (sid, password) = match ops.create_account(&acct) {
        Ok(pair) => pair,
        Err(e) => return Err(format!("provision({sandbox}): create_account: {e}")),
    };
    // Account is now created; all rollback paths below must delete it.

    // Step 2: hide from sign-in screen.
    if let Err(e) = ops.hide(&acct) {
        rollback(ops, sandbox, hidden, 0, &rule);
        return Err(format!("provision({sandbox}): hide: {e}"));
    }
    hidden = true;

    // Step 3: grant each path.
    for path in grants {
        if let Err(e) = ops.grant(path, &sid, GrantLevel::Modify) {
            rollback(ops, sandbox, hidden, grants_applied, &rule);
            return Err(format!(
                "provision({sandbox}): grant({}): {e}",
                path.display()
            ));
        }
        grants_applied += 1;
    }

    // Step 4: install firewall block rule.
    if let Err(e) = ops.block(&rule, &sid) {
        rollback(ops, sandbox, hidden, grants_applied, &rule);
        return Err(format!("provision({sandbox}): block: {e}"));
    }

    // Step 5: write output files.
    if let Err(e) = std::fs::write(sid_out, &sid) {
        // Firewall rule is now live — must roll back including unblock.
        rollback_with_unblock(ops, sandbox, hidden, &rule);
        return Err(format!(
            "provision({sandbox}): write sid_out({}): {e}",
            sid_out.display()
        ));
    }
    if let Err(e) = std::fs::write(cred_out, &password) {
        // sid_out was written — remove it as part of rollback (best-effort).
        let _ = std::fs::remove_file(sid_out);
        rollback_with_unblock(ops, sandbox, hidden, &rule);
        return Err(format!(
            "provision({sandbox}): write cred_out({}): {e}",
            cred_out.display()
        ));
    }

    Ok(())
}

/// Roll back steps that completed before `block` was called:
/// unhide (if hidden), then delete the account unconditionally.
/// `grants_applied` is unused — DACL ACEs have no per-path undo primitive; the
/// account deletion itself removes the SID from all future ACL evaluations.
fn rollback<O: Ops>(ops: &O, sandbox: &str, hidden: bool, _grants_applied: usize, _rule: &str) {
    if hidden {
        let _ = ops.unhide(&account_name(sandbox));
    }
    // The account was always created before this path is reached.
    let _ = ops.delete_account(&account_name(sandbox));
}

/// Roll back including unblock (called when firewall block succeeded before
/// the I/O failure).
fn rollback_with_unblock<O: Ops>(ops: &O, sandbox: &str, hidden: bool, rule: &str) {
    let _ = ops.unblock(rule);
    rollback(ops, sandbox, hidden, 0, rule);
}

// ── Deprovision ──────────────────────────────────────────────────────────────

/// Deprovision a per-sandbox Windows local account.
///
/// Steps (in order, each idempotent):
/// 1. Unblock (remove firewall rules).
/// 2. Unhide (remove from UserList).
/// 3. Delete account.
/// 4. Delete profile (best-effort).
///
/// **Intentional DACL residue:** any ACEs previously granted by `provision`
/// (workspace path `Modify` rights) reference the account SID.  Deleting the
/// account orphans those SIDs — they become inert tombstones in the DACL that
/// no longer resolve to a principal and are evaluated as "deny" by the kernel.
/// This is the same approach used in rollback: no per-ACE removal primitive
/// exists, and the security impact is nil because the SID no longer exists.
pub fn deprovision<O: Ops>(ops: &O, sandbox: &str) -> Result<(), String> {
    let acct = account_name(sandbox);
    let rule = rule_name(sandbox);

    // Each step is attempted regardless of the previous step's outcome, so
    // errors are accumulated and all returned at once.
    let mut errors: Vec<String> = Vec::new();

    if let Err(e) = ops.unblock(&rule) {
        errors.push(format!("unblock: {e}"));
    }
    if let Err(e) = ops.unhide(&acct) {
        errors.push(format!("unhide: {e}"));
    }
    if let Err(e) = ops.delete_account(&acct) {
        errors.push(format!("delete_account: {e}"));
    }
    ops.delete_profile(&acct);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("deprovision({sandbox}): {}", errors.join("; ")))
    }
}

// ── GC ───────────────────────────────────────────────────────────────────────

/// Garbage-collect orphaned per-sandbox accounts.
///
/// Enumerates `izba-spk-*` accounts via [`Ops::enumerate_accounts`], computes
/// the orphan set (those not in `live`) via [`gc_orphans`], and deprovisions
/// each orphan.
///
/// All errors are accumulated and returned as a single string. Partial failures
/// do NOT abort — remaining orphans are still attempted.
pub fn gc<O: Ops>(ops: &O, live: &[String]) -> Result<(), String> {
    let existing = ops.enumerate_accounts()?;
    let orphans = gc_orphans(&existing, live);

    let mut errors: Vec<String> = Vec::new();
    for orphan_account in &orphans {
        // gc receives full account names like "izba-spk-foo"; we need to derive
        // the sandbox name from the account name to call deprovision.  We use
        // the account name directly as a sandbox identifier here because
        // `account_name(account_name_as_sandbox)` == account_name_as_sandbox
        // when the name already has the prefix stripped length ≤ ACCOUNT_SLUG_MAX.
        //
        // Actually: deprovision calls `account_name(sandbox)` internally.
        // To get back to the right account we pass the orphan account name
        // itself with the "izba-spk-" prefix stripped.
        let sandbox_slug = orphan_account
            .strip_prefix("izba-spk-")
            .unwrap_or(orphan_account.as_str());
        if let Err(e) = deprovision(ops, sandbox_slug) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("gc: {}", errors.join("; ")))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── FakeOps ───────────────────────────────────────────────────────────────

    /// Call record for one [`FakeOps`] invocation.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Call {
        CreateAccount(String),
        DeleteAccount(String),
        DeleteProfile(String),
        Hide(String),
        Unhide(String),
        Grant(PathBuf, String, String), // (path, sid, "ReadExec"|"Modify")
        Block(String, String),          // (rule, sid)
        Unblock(String),
        EnumerateAccounts,
    }

    /// A fake implementation of [`Ops`] that:
    /// - records every call in order (for assertion),
    /// - fails the call at step index `fail_at` (0-based, counting all calls
    ///   that can fail),
    /// - returns a configurable list from `enumerate_accounts`.
    pub struct FakeOps {
        pub calls: RefCell<Vec<Call>>,
        /// 0-based index of the fallible call that should return an error.
        /// `None` = succeed all.
        pub fail_at: Option<usize>,
        /// Counter of how many fallible calls have been made so far.
        fail_counter: RefCell<usize>,
        /// Pre-loaded account list returned by `enumerate_accounts`.
        pub accounts: Vec<String>,
    }

    impl FakeOps {
        pub fn new() -> Self {
            FakeOps {
                calls: RefCell::new(Vec::new()),
                fail_at: None,
                fail_counter: RefCell::new(0),
                accounts: Vec::new(),
            }
        }

        pub fn with_fail_at(fail_at: usize) -> Self {
            FakeOps {
                fail_at: Some(fail_at),
                ..FakeOps::new()
            }
        }

        pub fn with_accounts(accounts: Vec<String>) -> Self {
            FakeOps {
                accounts,
                ..FakeOps::new()
            }
        }

        /// Try to advance the failure counter; return `Err` if this is the
        /// designated step.
        fn maybe_fail(&self, label: &str) -> Result<(), String> {
            let n = {
                let mut c = self.fail_counter.borrow_mut();
                let n = *c;
                *c += 1;
                n
            };
            if self.fail_at == Some(n) {
                Err(format!("FakeOps: injected failure at step {n} ({label})"))
            } else {
                Ok(())
            }
        }

        pub fn recorded(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    impl Ops for FakeOps {
        fn create_account(&self, name: &str) -> Result<(String, String), String> {
            self.calls
                .borrow_mut()
                .push(Call::CreateAccount(name.to_string()));
            self.maybe_fail("create_account")?;
            Ok((
                "S-1-5-21-fake-sid".to_string(),
                "FakePassword1!".to_string(),
            ))
        }

        fn delete_account(&self, name: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(Call::DeleteAccount(name.to_string()));
            Ok(())
        }

        fn delete_profile(&self, name: &str) {
            self.calls
                .borrow_mut()
                .push(Call::DeleteProfile(name.to_string()));
        }

        fn hide(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(Call::Hide(name.to_string()));
            self.maybe_fail("hide")?;
            Ok(())
        }

        fn unhide(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(Call::Unhide(name.to_string()));
            Ok(())
        }

        fn grant(&self, path: &Path, sid: &str, level: GrantLevel) -> Result<(), String> {
            let level_str = match level {
                GrantLevel::ReadExec => "ReadExec",
                GrantLevel::Modify => "Modify",
            };
            self.calls.borrow_mut().push(Call::Grant(
                path.to_path_buf(),
                sid.to_string(),
                level_str.to_string(),
            ));
            self.maybe_fail("grant")?;
            Ok(())
        }

        fn block(&self, rule: &str, sid: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(Call::Block(rule.to_string(), sid.to_string()));
            self.maybe_fail("block")?;
            Ok(())
        }

        fn unblock(&self, rule: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(Call::Unblock(rule.to_string()));
            Ok(())
        }

        fn enumerate_accounts(&self) -> Result<Vec<String>, String> {
            self.calls.borrow_mut().push(Call::EnumerateAccounts);
            self.maybe_fail("enumerate_accounts")?;
            Ok(self.accounts.clone())
        }
    }

    // ── Provision happy path ──────────────────────────────────────────────────

    #[test]
    fn provision_happy_path_call_order() {
        let ops = FakeOps::new();
        let tmp = TempDir::new().unwrap();
        let sid_out = tmp.path().join("sid.txt");
        let cred_out = tmp.path().join("cred.json");
        let grant_path = tmp.path().join("workspace");
        std::fs::create_dir_all(&grant_path).unwrap();

        provision(
            &ops,
            "my-sandbox",
            std::slice::from_ref(&grant_path),
            &sid_out,
            &cred_out,
        )
        .expect("provision should succeed");

        let calls = ops.recorded();
        // Expected order: CreateAccount, Hide, Grant, Block.
        assert!(
            matches!(&calls[0], Call::CreateAccount(n) if n == "izba-spk-my-sandbox"),
            "first call must be CreateAccount: {:?}",
            calls[0]
        );
        assert!(
            matches!(&calls[1], Call::Hide(n) if n == "izba-spk-my-sandbox"),
            "second call must be Hide: {:?}",
            calls[1]
        );
        assert!(
            matches!(&calls[2], Call::Grant(p, _, lvl) if p == &grant_path && lvl == "Modify"),
            "third call must be Grant(Modify): {:?}",
            calls[2]
        );
        assert!(
            matches!(&calls[3], Call::Block(r, _) if r == "izba-deny-my-sandbox"),
            "fourth call must be Block: {:?}",
            calls[3]
        );
        assert_eq!(calls.len(), 4, "no extra calls expected: {calls:?}");
    }

    #[test]
    fn provision_happy_path_writes_sid_and_cred() {
        let ops = FakeOps::new();
        let tmp = TempDir::new().unwrap();
        let sid_out = tmp.path().join("sid.txt");
        let cred_out = tmp.path().join("cred.json");

        provision(&ops, "sb", &[], &sid_out, &cred_out).unwrap();

        assert_eq!(
            std::fs::read_to_string(&sid_out).unwrap(),
            "S-1-5-21-fake-sid"
        );
        assert_eq!(
            std::fs::read_to_string(&cred_out).unwrap(),
            "FakePassword1!"
        );
    }

    // ── Provision failure + rollback ──────────────────────────────────────────

    /// Step 0 = create_account fails → nothing to roll back.
    #[test]
    fn provision_fail_create_account_no_rollback() {
        let ops = FakeOps::with_fail_at(0);
        let tmp = TempDir::new().unwrap();

        let err = provision(
            &ops,
            "sb",
            &[],
            &tmp.path().join("sid"),
            &tmp.path().join("cred"),
        )
        .unwrap_err();
        assert!(
            err.contains("create_account"),
            "error must mention create_account: {err}"
        );

        let calls = ops.recorded();
        // Only CreateAccount was called; no Unhide / DeleteAccount.
        assert!(
            calls.iter().all(|c| matches!(c, Call::CreateAccount(_))),
            "no rollback calls expected: {calls:?}"
        );
    }

    /// Step 1 = hide fails → must roll back: DeleteAccount (unhide was not done).
    #[test]
    fn provision_fail_hide_rolls_back_account() {
        let ops = FakeOps::with_fail_at(1);
        let tmp = TempDir::new().unwrap();

        let err = provision(
            &ops,
            "sb",
            &[],
            &tmp.path().join("sid"),
            &tmp.path().join("cred"),
        )
        .unwrap_err();
        assert!(err.contains("hide"), "error must mention hide: {err}");

        let calls = ops.recorded();
        // Rollback must call DeleteAccount but NOT Unhide (hide never completed).
        assert!(
            calls.iter().any(|c| matches!(c, Call::DeleteAccount(_))),
            "DeleteAccount must be called in rollback: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::Unhide(_))),
            "Unhide must NOT be called (hide never succeeded): {calls:?}"
        );
    }

    /// Step 2 = block fails (after create_account + hide + grant) → must roll
    /// back: Unhide + DeleteAccount (no Unblock because block never succeeded).
    #[test]
    fn provision_fail_block_rolls_back_hide_and_account() {
        let ops = FakeOps::with_fail_at(2); // step 0=create,1=hide,2=block (no grants)
        let tmp = TempDir::new().unwrap();

        let err = provision(
            &ops,
            "sb",
            &[],
            &tmp.path().join("sid"),
            &tmp.path().join("cred"),
        )
        .unwrap_err();
        assert!(err.contains("block"), "error must mention block: {err}");

        let calls = ops.recorded();
        assert!(
            calls.iter().any(|c| matches!(c, Call::Unhide(_))),
            "Unhide must be called in rollback: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| matches!(c, Call::DeleteAccount(_))),
            "DeleteAccount must be called in rollback: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::Unblock(_))),
            "Unblock must NOT be called (block never succeeded): {calls:?}"
        );
    }

    /// With one grant path: step 2 = grant fails → Unhide + DeleteAccount; no Unblock.
    #[test]
    fn provision_fail_grant_rolls_back_properly() {
        let ops = FakeOps::with_fail_at(2); // step 0=create,1=hide,2=grant
        let tmp = TempDir::new().unwrap();
        let grant_path = tmp.path().join("ws");
        std::fs::create_dir_all(&grant_path).unwrap();

        let err = provision(
            &ops,
            "sb",
            &[grant_path],
            &tmp.path().join("sid"),
            &tmp.path().join("cred"),
        )
        .unwrap_err();
        assert!(err.contains("grant"), "error must mention grant: {err}");

        let calls = ops.recorded();
        assert!(
            calls.iter().any(|c| matches!(c, Call::Unhide(_))),
            "Unhide must be called in rollback: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| matches!(c, Call::DeleteAccount(_))),
            "DeleteAccount must be called in rollback: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::Unblock(_))),
            "Unblock must NOT be called (block never reached): {calls:?}"
        );
    }

    // ── Deprovision ───────────────────────────────────────────────────────────

    #[test]
    fn deprovision_call_order() {
        let ops = FakeOps::new();

        deprovision(&ops, "my-sandbox").expect("deprovision should succeed");

        let calls = ops.recorded();
        // Expected order: Unblock, Unhide, DeleteAccount, DeleteProfile.
        assert!(
            matches!(&calls[0], Call::Unblock(r) if r == "izba-deny-my-sandbox"),
            "first call must be Unblock: {:?}",
            calls[0]
        );
        assert!(
            matches!(&calls[1], Call::Unhide(n) if n == "izba-spk-my-sandbox"),
            "second call must be Unhide: {:?}",
            calls[1]
        );
        assert!(
            matches!(&calls[2], Call::DeleteAccount(n) if n == "izba-spk-my-sandbox"),
            "third call must be DeleteAccount: {:?}",
            calls[2]
        );
        assert!(
            matches!(&calls[3], Call::DeleteProfile(n) if n == "izba-spk-my-sandbox"),
            "fourth call must be DeleteProfile: {:?}",
            calls[3]
        );
        assert_eq!(calls.len(), 4, "unexpected extra calls: {calls:?}");
    }

    // ── GC ────────────────────────────────────────────────────────────────────

    #[test]
    fn gc_deprovisions_orphans_only() {
        let ops = FakeOps::with_accounts(vec![
            "izba-spk-alive".to_string(),
            "izba-spk-orphan".to_string(),
            "other-account".to_string(),
        ]);

        gc(&ops, &["alive".to_string()]).expect("gc should succeed");

        let calls = ops.recorded();
        // Unblock must mention "orphan", not "alive".
        let unblocks: Vec<&str> = calls
            .iter()
            .filter_map(|c| {
                if let Call::Unblock(r) = c {
                    Some(r.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            unblocks,
            vec!["izba-deny-orphan"],
            "only the orphan rule must be unblocked: {unblocks:?}"
        );

        // No deprovision operations for "alive".
        assert!(
            calls
                .iter()
                .filter_map(|c| {
                    if let Call::DeleteAccount(n) = c {
                        Some(n.as_str())
                    } else {
                        None
                    }
                })
                .all(|n| !n.contains("alive")),
            "alive account must not be deprovisioned"
        );
    }

    /// Long sandbox name: stored as truncated account "izba-spk-my-very-lon",
    /// live name "my-very-long-sandbox-name" → must NOT be orphan.
    #[test]
    fn gc_long_name_not_false_orphan() {
        let sandbox = "my-very-long-sandbox-name";
        let stored = account_name(sandbox); // "izba-spk-my-very-lon"
        assert_eq!(stored.len(), 20);

        let ops = FakeOps::with_accounts(vec![stored.clone()]);

        gc(&ops, &[sandbox.to_string()]).expect("gc should succeed");

        let calls = ops.recorded();
        // No deprovision calls at all — only EnumerateAccounts.
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, Call::Unblock(_) | Call::DeleteAccount(_)))
                .count(),
            0,
            "long-named live sandbox must not be deprovisioned: {calls:?}"
        );
    }

    #[test]
    fn gc_no_live_deprovisions_all_izba_accounts() {
        let ops = FakeOps::with_accounts(vec!["izba-spk-a".to_string(), "izba-spk-b".to_string()]);

        gc(&ops, &[]).expect("gc should succeed");

        let all_calls = ops.recorded();
        let deleted: Vec<&str> = all_calls
            .iter()
            .filter_map(|c| {
                if let Call::DeleteAccount(n) = c {
                    Some(n.as_str())
                } else {
                    None
                }
            })
            .collect();
        // Both must be deprovisioned (order may vary but both must appear).
        assert!(
            deleted.contains(&"izba-spk-a"),
            "izba-spk-a must be deleted"
        );
        assert!(
            deleted.contains(&"izba-spk-b"),
            "izba-spk-b must be deleted"
        );
    }

    // ── GC: truncated-name orphan cleans up matching rule (FIX 2 + FIX 3) ─────

    /// A stored account whose name was truncated at provision time (long sandbox
    /// name) must be deprovisioned AND the `Unblock` call must use a rule name
    /// that round-trips from the same truncated slug.
    ///
    /// This proves that `rule_name` now truncates consistently with `account_name`
    /// and that GC no longer leaks the firewall rule for long-named sandboxes.
    #[test]
    fn gc_orphaned_truncated_account_cleans_up_matching_rule() {
        use izba_jail_naming::{account_name as an, rule_name as rn};

        // A very long sandbox name.  At provision time, both account_name and
        // rule_name truncate its slug to ACCOUNT_SLUG_MAX (11) chars.
        let long = "my-very-long-sandbox-name-that-exceeds-limit";
        let stored_account = an(long); // e.g. "izba-spk-my-very-lon" (20 chars)
        let expected_rule = rn(long); // e.g. "izba-deny-my-very-lon" — same slug

        // Sanity: slugs must match.
        let acct_slug = stored_account.strip_prefix("izba-spk-").unwrap();
        let rule_slug = expected_rule.strip_prefix("izba-deny-").unwrap();
        assert_eq!(
            acct_slug, rule_slug,
            "provision and rule slugs must be equal for GC round-trip"
        );

        // Simulate: the account is in the enumeration list, but NOT in live.
        let ops = FakeOps::with_accounts(vec![stored_account.clone()]);
        gc(&ops, &[]).expect("gc should succeed");

        let calls = ops.recorded();

        // Unblock must be called with the rule that matches the truncated slug.
        let unblocked_rules: Vec<&str> = calls
            .iter()
            .filter_map(|c| {
                if let Call::Unblock(r) = c {
                    Some(r.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            unblocked_rules,
            vec![expected_rule.as_str()],
            "Unblock must use the round-trip rule name '{expected_rule}'; got {unblocked_rules:?}"
        );

        // The account itself must be deleted.
        let deleted: Vec<&str> = calls
            .iter()
            .filter_map(|c| {
                if let Call::DeleteAccount(n) = c {
                    Some(n.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            deleted.contains(&stored_account.as_str()),
            "DeleteAccount must be called for '{stored_account}'"
        );
    }

    // ── Provision: write-failure rollback (FIX 3) ─────────────────────────────

    /// When writing `sid_out` fails (path under non-existent directory),
    /// the rollback must call Unblock + Unhide + DeleteAccount — i.e. the
    /// post-block rollback path is exercised.
    #[test]
    fn provision_write_sid_failure_triggers_full_rollback() {
        let ops = FakeOps::new();
        let tmp = TempDir::new().unwrap();
        // Point sid_out at a path whose parent doesn't exist.
        let sid_out = tmp.path().join("nonexistent_dir").join("sid.txt");
        let cred_out = tmp.path().join("cred.json");

        let err = provision(&ops, "sb", &[], &sid_out, &cred_out).unwrap_err();
        assert!(err.contains("sid_out"), "error must mention sid_out: {err}");

        let calls = ops.recorded();

        // Block was called (step 4 succeeds before the I/O failure).
        assert!(
            calls.iter().any(|c| matches!(c, Call::Block(_, _))),
            "Block must have been called before the failure: {calls:?}"
        );
        // Unblock must be called in rollback.
        assert!(
            calls.iter().any(|c| matches!(c, Call::Unblock(_))),
            "Unblock must be called in rollback after sid_out write failure: {calls:?}"
        );
        // Unhide must be called (hide succeeded at step 2).
        assert!(
            calls.iter().any(|c| matches!(c, Call::Unhide(_))),
            "Unhide must be called in rollback: {calls:?}"
        );
        // DeleteAccount must be called.
        assert!(
            calls.iter().any(|c| matches!(c, Call::DeleteAccount(_))),
            "DeleteAccount must be called in rollback: {calls:?}"
        );
    }

    /// When writing `cred_out` fails, the rollback path must also call
    /// Unblock + Unhide + DeleteAccount.
    #[test]
    fn provision_write_cred_failure_triggers_full_rollback() {
        let ops = FakeOps::new();
        let tmp = TempDir::new().unwrap();
        let sid_out = tmp.path().join("sid.txt");
        // Point cred_out at a path whose parent doesn't exist.
        let cred_out = tmp.path().join("nonexistent_dir").join("cred.json");

        let err = provision(&ops, "sb", &[], &sid_out, &cred_out).unwrap_err();
        assert!(
            err.contains("cred_out"),
            "error must mention cred_out: {err}"
        );

        let calls = ops.recorded();

        assert!(
            calls.iter().any(|c| matches!(c, Call::Unblock(_))),
            "Unblock must be called in rollback after cred_out write failure: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| matches!(c, Call::Unhide(_))),
            "Unhide must be called in rollback: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| matches!(c, Call::DeleteAccount(_))),
            "DeleteAccount must be called in rollback: {calls:?}"
        );
    }
}
