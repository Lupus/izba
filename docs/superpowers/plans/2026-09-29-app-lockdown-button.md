# Desktop App Lock-down Button Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the per-sandbox Windows lock-down (MVP-D) usable from the desktop app — a Lock down / Unlock control with an honest, recorded-fact "restart to apply" badge — and stop GUI Remove from leaking a locked sandbox's Windows account.

**Architecture:** izba-core records the account a VMM was actually launched as (`RunState.lockdown_account`) and the daemon's Inspect reply derives `lockdown_restart_required` from one pure predicate. The Tauri app calls the existing client-side `orchestrate::{lockdown, unlock}` (same path as the CLI; no new daemon RPC) through its `DaemonApi` seam, and a new `LockdownRow` in the Overview Sandbox card renders it (Windows only — gated by `lockdown_supported()`).

**Tech Stack:** Rust (izba-core, izba-cli, Tauri 2 `app/src-tauri`), React + TypeScript + Vitest + Playwright (`app/`), shadcn/ui, lucide-react.

**Spec:** `docs/superpowers/specs/2026-09-29-app-lockdown-button-design.md`

## Global Constraints

- Additive `#[serde(default)]` fields only; **no `DAEMON_PROTO_VERSION` bump**.
- Lock-down stays client-side: no new `DaemonRequest` variant.
- `lockdown`/`unlock` Tauri commands run via `run_action` (never the shared polling lock).
- Every command in `generate_handler![…]` has a `case` in `app/e2e/mock/tauri-mock.js` and an arm in the bridge dispatch in `app/src-tauri/src/lib.rs` (`tauriMockParity.test.ts` enforces the mock).
- GUI Remove of a locked sandbox: unlock FIRST; unlock failure/cancel ⇒ abort with no Rm (fail-closed).
- UI copy (verbatim): button `Lock down`; pending `Waiting for approval…`; cancel note `cancelled — nothing changed`; locked summary `locked · <account> · network blocked` / `network open`; button `Unlock`; badges `restart to apply` and `still running as account — restart to apply`.
- Workspace gates before every commit touching `crates/` (source `.cargo-env` if present): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, plus the windows-gnu cross check/clippy (`cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli` and `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`).
- App gate before every commit touching `app/` or core public types: `cd app && npm ci && npm run build && npm run test && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Stage files explicitly (never `git add -A`); conventional commits; end each commit message with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Unit tests never bind unix/vsock listeners.

## Review Focus

1. **Sandbox switch while a UAC prompt is open** — the result of a lock-down started on sandbox A must not render on sandbox B's card. (Task 3: `LockdownRow` is keyed by name in `SandboxCard` and ignores late results via an `alive` guard; test included.)
2. **Double-click while the prompt is pending** — must not fire a second elevation. (Task 3: both buttons disabled while pending; test included.)
3. **Restart from the header row** — the "restart to apply" badge must clear after a restart without switching tabs. (Task 3: `OverviewTab` re-fetches `inspect` when `sandbox.state.kind` changes; test included.)
4. **Pre-upgrade running sandbox, configured locked, `state.json` without the field** — must report restart-required, never "applied". (Task 1: predicate truth-table row.)
5. **Remove of a locked sandbox with UAC declined** — nothing deleted, actionable error naming `izba windows-cleanup`. (Task 2: test included.)

---

### Task 1: Core — record the booted account + restart-required predicate + Inspect/status

**Files:**
- Modify: `crates/izba-core/src/jail_account/state.rs` (predicate + tests)
- Modify: `crates/izba-core/src/jail_account/mod.rs` (re-export)
- Modify: `crates/izba-core/src/state.rs:128-175` (`RunState.lockdown_account` + round-trip tests)
- Modify: `crates/izba-core/src/sandbox.rs:1130-1190,1263-1290` (`record_run_state` gains the account)
- Modify: `crates/izba-core/src/daemon/proto.rs:251-345` (`SandboxDetail` two fields + `Debug`)
- Modify: `crates/izba-core/src/daemon/server.rs:951-1032` (`handle_inspect` fills them)
- Modify: `crates/izba-cli/src/commands/status.rs:40-70` (restart-required suffix + test)
- Modify: every `RunState { … }` and `SandboxDetail { … }` struct literal in `crates/` (tests included — find with `grep -rn "RunState {\|SandboxDetail {" crates`) AND in `app/src-tauri/src/{fake.rs,views.rs}` (the app is outside the workspace; it must still compile).

**Interfaces:**
- Produces:
  - `izba_core::jail_account::lockdown_restart_required(configured: &LockdownState, booted_account: Option<&str>, running: bool) -> bool`
  - `RunState.lockdown_account: Option<String>` (`#[serde(default)]`)
  - `SandboxDetail.lockdown_account: Option<String>` and `SandboxDetail.lockdown_restart_required: bool` (both `#[serde(default)]`)

- [ ] **Step 1: Write the failing predicate tests** in `jail_account/state.rs`'s `mod tests`:

```rust
    // --- lockdown_restart_required truth table ---

    #[test]
    fn restart_never_required_when_not_running() {
        let locked = LockdownState::Locked(locked_info());
        assert!(!lockdown_restart_required(&locked, None, false));
        assert!(!lockdown_restart_required(&LockdownState::Unlocked, Some("izba-sb-foo"), false));
    }

    #[test]
    fn locked_and_booted_as_that_account_is_applied() {
        let locked = LockdownState::Locked(locked_info());
        assert!(!lockdown_restart_required(&locked, Some("izba-sb-foo"), true));
    }

    #[test]
    fn locked_but_booted_unconfined_requires_restart() {
        // Also the pre-upgrade case: a state.json without the field reads as
        // None, and we cannot prove the VMM runs as the account.
        let locked = LockdownState::Locked(locked_info());
        assert!(lockdown_restart_required(&locked, None, true));
    }

    #[test]
    fn locked_but_booted_as_a_different_account_requires_restart() {
        let locked = LockdownState::Locked(locked_info());
        assert!(lockdown_restart_required(&locked, Some("izba-sb-other"), true));
    }

    #[test]
    fn unlocked_but_still_running_as_account_requires_restart() {
        assert!(lockdown_restart_required(&LockdownState::Unlocked, Some("izba-sb-foo"), true));
        let degraded = LockdownState::Degraded { reason: "x".into() };
        assert!(lockdown_restart_required(&degraded, Some("izba-sb-foo"), true));
    }

    #[test]
    fn unlocked_and_booted_unconfined_is_applied() {
        assert!(!lockdown_restart_required(&LockdownState::Unlocked, None, true));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core jail_account::state`
Expected: FAIL — `cannot find function lockdown_restart_required`.

- [ ] **Step 3: Implement the predicate** in `jail_account/state.rs` (after `impl LockdownState`), and add it to `mod.rs`'s `pub use state::{…}` list:

```rust
/// Whether a sandbox is RUNNING with a lock-down posture other than the one
/// configured on disk — lock-down only takes effect at the next start. The
/// single source of truth for "restart to apply": the daemon's Inspect reply
/// carries its answer, and neither the CLI nor the app re-derives it.
///
/// `booted_account` is the account the live VMM was launched as
/// (`RunState.lockdown_account`); `None` also covers a `state.json` written
/// before that field existed — a configured-locked sandbox then reports
/// restart-required, because we cannot prove it runs as the account.
pub fn lockdown_restart_required(
    configured: &LockdownState,
    booted_account: Option<&str>,
    running: bool,
) -> bool {
    if !running {
        return false;
    }
    match configured {
        LockdownState::Locked(info) => booted_account != Some(info.account.as_str()),
        LockdownState::Unlocked | LockdownState::Degraded { .. } => booted_account.is_some(),
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core jail_account::state`
Expected: PASS.

- [ ] **Step 5: Write failing `RunState` tests** in `crates/izba-core/src/state.rs`'s tests (next to the `usb_kernel` ones):

```rust
    #[test]
    fn a_state_json_written_before_lockdown_account_reads_as_none() {
        // Same safe direction as usb_kernel: an old record never claims the
        // VMM was launched as the lock-down account.
        let mut v = serde_json::to_value(sample_run_state()).unwrap();
        v.as_object_mut().unwrap().remove("lockdown_account");
        let s: RunState = serde_json::from_value(v).unwrap();
        assert!(s.lockdown_account.is_none());
    }

    #[test]
    fn run_state_roundtrips_lockdown_account() {
        let mut s = sample_run_state();
        s.lockdown_account = Some("izba-sb-web".into());
        let back: RunState = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.lockdown_account.as_deref(), Some("izba-sb-web"));
    }
```

Run: `cargo test -p izba-core state::tests` → FAIL (no field).

- [ ] **Step 6: Add the field** to `RunState` (after `vnc`):

```rust
    /// The Windows lock-down account (MVP-D) this run's VMM was launched as,
    /// or `None` when it ran as the invoking user. Recorded at launch — like
    /// `usb_kernel`/`vnc`, this is the only answer to "is the RUNNING VMM
    /// confined to the account", which `lockdown.json` (the configured
    /// posture, applied at the NEXT start) cannot give. `serde(default)`: a
    /// pre-field `state.json` reads as `None`.
    #[serde(default)]
    pub lockdown_account: Option<String>,
```

Fix every `RunState { … }` literal the compiler reports with `lockdown_account: None,`.

- [ ] **Step 7: Record it at launch.** In `sandbox.rs` start path, capture before `driver.launch(&spec)` consumes nothing (it takes `&spec`) — right after the `VmSpec` is final:

```rust
    // Recorded in state.json only once boot succeeded (record_run_state), so
    // it states a launch that actually happened; a locked launch that fails
    // fails the whole start — there is no silent fallback to mis-record.
    let lockdown_account = spec.lockdown.as_ref().map(|l| l.account().to_string());
```

Pass it as a new last argument to `record_run_state(…, has_vnc, lockdown_account)`; add the `lockdown_account: Option<String>` parameter and the `lockdown_account,` field in the `RunState` it builds; extend its doc comment ("…and which lock-down account, if any, the VMM was launched as"). Add a unit test next to the existing `record_run_state`/`started_run_state` tests that calls `record_run_state` with `Some("izba-sb-x".into())` using the same fake `VmHandle` those tests use, then `load_json::<RunState>` the state file and assert `lockdown_account == Some("izba-sb-x")`.

Run: `cargo test -p izba-core` → PASS.

- [ ] **Step 8: `SandboxDetail` fields.** In `daemon/proto.rs` after `vnc_restart_required`:

```rust
    /// The lock-down account the live VMM was launched as (from
    /// `RunState.lockdown_account`); `None` when stopped or unconfined.
    /// Additive + serde(default) → no DAEMON_PROTO_VERSION bump.
    #[serde(default)]
    pub lockdown_account: Option<String>,
    /// Running with a lock-down posture other than the configured one
    /// (`jail_account::lockdown_restart_required`). Additive + serde(default)
    /// → no DAEMON_PROTO_VERSION bump; an older daemon reads as `false`.
    #[serde(default)]
    pub lockdown_restart_required: bool,
```

Add both to the manual `impl Debug for SandboxDetail` (`.field("lockdown_account", &self.lockdown_account).field("lockdown_restart_required", &self.lockdown_restart_required)`). Fix every `SandboxDetail { … }` literal in `crates/` and `app/src-tauri/src/` with `lockdown_account: None, lockdown_restart_required: false,`.

- [ ] **Step 9: Fill them in `handle_inspect`** (server.rs), after `booted_vnc`:

```rust
    let lockdown_account = if running {
        run_state.as_ref().and_then(|s| s.lockdown_account.clone())
    } else {
        None
    };
    let lockdown_restart_required = crate::jail_account::lockdown_restart_required(
        &crate::jail_account::lockdown_state(&d.paths, &name),
        lockdown_account.as_deref(),
        running,
    );
```

and in the literal: `lockdown_account, lockdown_restart_required,`. Add a server test next to the existing inspect/vnc_restart tests: write a `lockdown.json` (`LockdownFile { state: Some(LockedInfo{account:"izba-sb-<name>".into(), sid:"S-1".into(), net_blocked:true}) }` via `save_json` into `paths.sandbox_dir(name).join(LOCKDOWN_FILE)`) for a sandbox the test's registry reports running with a `RunState` whose `lockdown_account: None`, and assert `lockdown_restart_required == true` and `lockdown_account == None`; then rewrite the `RunState` with `lockdown_account: Some("izba-sb-<name>")` and assert `false` / `Some(..)`. (Model it on however the existing `vnc_restart_required` inspect test sets up a running registry entry — search `needs_vnc_restart` tests in server.rs.) If no existing test can put a sandbox into running liveness without a VM, test the stopped case (`lockdown_account == None`, `restart_required == false` even when locked) and rely on the predicate's truth table for the running arms — state which you did in the commit body.

- [ ] **Step 10: `izba status` suffix.** In `status.rs::render`:

```rust
    let mut lockdown = lockdown_state(paths, &det.name).summary();
    if det.lockdown_restart_required {
        lockdown.push_str(" (restart required)");
    }
```

Test next to `renders_lockdown_locked_when_state_file_present`:

```rust
    #[test]
    fn renders_lockdown_restart_required_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        let mut det = detail(None);
        det.lockdown_restart_required = true;
        let out = render(&paths, &det, None);
        assert!(out.contains("lock-down:   unlocked (restart required)"), "{out}");
    }
```

(Adapt `Paths`/`detail` construction to what the neighbouring tests use.)

- [ ] **Step 11: Run all workspace gates + app backend compile**

Run the workspace gates from Global Constraints, then `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
Expected: all green.

- [ ] **Step 12: Commit**

```bash
git add crates/izba-core/src/jail_account/state.rs crates/izba-core/src/jail_account/mod.rs crates/izba-core/src/state.rs crates/izba-core/src/sandbox.rs crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs crates/izba-cli/src/commands/status.rs <every other file you touched for struct literals>
git commit -m "feat(core,cli): record the booted lock-down account; restart-required in inspect + status"
```

---

### Task 2: App backend — DaemonApi lock-down surface, view, commands, remove fix

**Files:**
- Modify: `app/src-tauri/src/daemon.rs` (trait + `RealDaemon`)
- Modify: `app/src-tauri/src/fake.rs` (`FakeDaemon` state + impl + tests)
- Modify: `app/src-tauri/src/views.rs` (`LockdownView`, `LockdownResultView`, `SandboxDetailView.lockdown`)
- Modify: `app/src-tauri/src/commands.rs` (`inspect_core`, `lockdown_core`, `unlock_core`, `remove_core` + tests)
- Modify: `app/src-tauri/src/lib.rs` (two `#[tauri::command]`s, `generate_handler!`, bridge dispatch arms)
- Modify: `app/e2e/mock/tauri-mock.js` (two cases)
- Modify: `app/src/lib/types.ts`, `app/src/lib/ipc.ts`, and every TS fixture that builds a `SandboxDetail` (`grep -rln "vnc_restart_required" app/src app/e2e`) gains `lockdown: null`.

**Interfaces:**
- Consumes (Task 1): `SandboxDetail.lockdown_account`, `SandboxDetail.lockdown_restart_required`.
- Produces:
  - `DaemonApi::lockdown_supported(&self) -> bool`
  - `DaemonApi::lockdown_state(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownState>`
  - `DaemonApi::lockdown(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownOutcome>`
  - `DaemonApi::unlock(&mut self, name: &str) -> anyhow::Result<()>`
  - Rust `LockdownView { locked: bool, account: Option<String>, net_blocked: bool, restart_required: bool, booted_as_account: bool }` (serde snake_case, `Serialize`)
  - `SandboxDetailView.lockdown: Option<LockdownView>`
  - `commands::lockdown_core(d, name) -> Result<String, String>` returning `"locked"` | `"cancelled"`
  - `commands::unlock_core(d, name) -> Result<(), String>`
  - Tauri commands `lockdown { name } -> "locked" | "cancelled"`, `unlock { name } -> null`
  - TS: `interface LockdownView { locked: boolean; account: string | null; net_blocked: boolean; restart_required: boolean; booted_as_account: boolean }`, `SandboxDetail.lockdown: LockdownView | null`, `api.lockdown(name): Promise<"locked" | "cancelled">`, `api.unlock(name): Promise<void>`
  - Mock scenario hooks: `scenario.lockdownOutcome` (`"locked"` default | `"cancelled"`), `scenario.lockdownError` (string ⇒ reject).

- [ ] **Step 1: Failing Rust tests** in `commands.rs` tests:

```rust
    #[test]
    fn inspect_core_omits_lockdown_when_unsupported() {
        let mut d = FakeDaemon { lockdown_supported: false, ..FakeDaemon::default() };
        assert!(inspect_core(&mut d, "web").unwrap().lockdown.is_none());
    }

    #[test]
    fn inspect_core_maps_lockdown_state_and_restart_fact() {
        let mut d = FakeDaemon::default();
        d.lockdown_account = Some("izba-sb-web".into());
        d.lockdown_restart_required = true;
        let v = inspect_core(&mut d, "web").unwrap().lockdown.unwrap();
        assert!(!v.locked);
        assert!(v.restart_required);
        assert!(v.booted_as_account);
        assert_eq!(v.account, None);
    }

    #[test]
    fn lockdown_core_locks_then_inspect_reports_locked() {
        let mut d = FakeDaemon::default();
        assert_eq!(lockdown_core(&mut d, "web").unwrap(), "locked");
        let v = inspect_core(&mut d, "web").unwrap().lockdown.unwrap();
        assert!(v.locked);
        assert_eq!(v.account.as_deref(), Some("izba-sb-web"));
        assert!(v.net_blocked);
    }

    #[test]
    fn lockdown_core_reports_a_declined_prompt_as_cancelled_not_an_error() {
        let mut d = FakeDaemon { lockdown_cancel: true, ..FakeDaemon::default() };
        assert_eq!(lockdown_core(&mut d, "web").unwrap(), "cancelled");
        assert!(!inspect_core(&mut d, "web").unwrap().lockdown.unwrap().locked);
    }

    #[test]
    fn unlock_core_clears_the_lock() {
        let mut d = FakeDaemon::default();
        lockdown_core(&mut d, "web").unwrap();
        unlock_core(&mut d, "web").unwrap();
        assert!(!inspect_core(&mut d, "web").unwrap().lockdown.unwrap().locked);
    }

    #[test]
    fn remove_core_releases_a_locked_sandbox_account_before_rm() {
        let mut d = FakeDaemon::default();
        lockdown_core(&mut d, "web").unwrap();
        d.calls.clear();
        remove_core(&mut d, "web", false).unwrap();
        assert_eq!(d.calls, vec!["unlock:web".to_string(), "rm:web:false".to_string()]);
    }

    #[test]
    fn remove_core_aborts_without_rm_when_unlock_is_declined() {
        let mut d = FakeDaemon::default();
        lockdown_core(&mut d, "web").unwrap();
        d.unlock_fail = Some("unlock cancelled by user".into());
        d.calls.clear();
        let err = remove_core(&mut d, "web", false).unwrap_err();
        assert!(err.contains("was not released"), "{err}");
        assert!(err.contains("izba windows-cleanup"), "{err}");
        assert!(!d.calls.iter().any(|c| c.starts_with("rm:")), "{:?}", d.calls);
    }

    #[test]
    fn remove_core_never_unlocks_an_unlocked_sandbox() {
        let mut d = FakeDaemon::default();
        remove_core(&mut d, "web", true).unwrap();
        assert_eq!(d.calls, vec!["rm:web:true".to_string()]);
    }
```

Run: `cd app/src-tauri && cargo test` → FAIL (missing fields/fns).

- [ ] **Step 2: Trait + views.** Add to `DaemonApi` (daemon.rs), after `vnc_set`:

```rust
    /// Whether per-sandbox Windows lock-down (MVP-D) exists on this host.
    /// Decides whether the UI renders the control at all.
    fn lockdown_supported(&self) -> bool;
    /// The CONFIGURED lock-down posture (`lockdown.json`), applied at the next start.
    fn lockdown_state(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownState>;
    /// Provision the per-sandbox account (pops UAC). Client-side, like `izba lockdown`.
    fn lockdown(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownOutcome>;
    /// Deprovision the per-sandbox account (pops UAC). Client-side, like `izba unlock`.
    fn unlock(&mut self, name: &str) -> anyhow::Result<()>;
```

`RealDaemon` impl:

```rust
    fn lockdown_supported(&self) -> bool {
        cfg!(windows)
    }

    fn lockdown_state(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownState> {
        Ok(izba_core::jail_account::lockdown_state(&self.paths, name))
    }

    fn lockdown(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownOutcome> {
        ensure_sandbox_exists(&self.paths, name)?;
        izba_core::jail_account::lockdown(&izba_core::jail_account::WinBackend, &self.paths, name)
    }

    fn unlock(&mut self, name: &str) -> anyhow::Result<()> {
        ensure_sandbox_exists(&self.paths, name)?;
        izba_core::jail_account::unlock(&izba_core::jail_account::WinBackend, &self.paths, name)
    }
```

with a private helper in daemon.rs (same guard as `izba lockdown`/`unlock`):

```rust
/// Same guard as `izba lockdown`/`izba unlock`: a bad name fails with a clean
/// message instead of an elevated helper run against a missing sandbox.
fn ensure_sandbox_exists(paths: &Paths, name: &str) -> anyhow::Result<()> {
    if !paths.sandbox_dir(name).join(izba_core::state::CONFIG_FILE).exists() {
        anyhow::bail!("no sandbox named {name:?} (no config.json found)");
    }
    Ok(())
}
```

In views.rs:

```rust
/// Lock-down (MVP-D) posture as the Sandbox card renders it. `locked`/
/// `account`/`net_blocked` are the CONFIGURED posture (`lockdown.json`);
/// `restart_required`/`booted_as_account` are recorded facts about the run
/// (the daemon's Inspect reply) — never re-derived here.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LockdownView {
    pub locked: bool,
    pub account: Option<String>,
    pub net_blocked: bool,
    pub restart_required: bool,
    pub booted_as_account: bool,
}

impl LockdownView {
    pub fn new(configured: &izba_core::jail_account::LockdownState, detail: &SandboxDetail) -> Self {
        let info = match configured {
            izba_core::jail_account::LockdownState::Locked(i) => Some(i),
            _ => None,
        };
        LockdownView {
            locked: info.is_some(),
            account: info.map(|i| i.account.clone()),
            net_blocked: info.is_some_and(|i| i.net_blocked),
            restart_required: detail.lockdown_restart_required,
            booted_as_account: detail.lockdown_account.is_some(),
        }
    }
}
```

Add `pub lockdown: Option<LockdownView>,` to `SandboxDetailView` (doc: "`None` when lock-down does not exist on this host — the UI hides the row") and `lockdown: None,` in `From<SandboxDetail>` (inspect_core fills it).

- [ ] **Step 3: Commands.** In commands.rs:

```rust
pub fn inspect_core(d: &mut dyn DaemonApi, name: &str) -> Result<SandboxDetailView, String> {
    let detail = d.inspect(name).map_err(|e| e.to_string())?;
    let lockdown = if d.lockdown_supported() {
        let configured = d.lockdown_state(name).map_err(|e| e.to_string())?;
        Some(LockdownView::new(&configured, &detail))
    } else {
        None
    };
    let mut view = SandboxDetailView::from(detail);
    view.lockdown = lockdown;
    Ok(view)
}

/// Core of `lockdown`: `"locked"`, or `"cancelled"` when the user declined
/// the UAC prompt — a choice, not an error, so it is not an `Err`.
pub fn lockdown_core(d: &mut dyn DaemonApi, name: &str) -> Result<String, String> {
    match d.lockdown(name).map_err(|e| format!("{e:#}"))? {
        izba_core::jail_account::LockdownOutcome::Locked(_) => Ok("locked".into()),
        izba_core::jail_account::LockdownOutcome::Cancelled => Ok("cancelled".into()),
    }
}

pub fn unlock_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.unlock(name).map_err(|e| format!("{e:#}"))
}

/// Core of `remove`. A locked sandbox's Windows account + firewall rule are
/// released FIRST (the CLI's `izba rm` does the same); if that fails or the
/// UAC prompt is declined, the remove is ABORTED — nothing has been deleted
/// yet, so a retry is safe — rather than leaking the account behind a remove
/// that reports success. (The CLI warns and continues; the GUI has no
/// channel for a warning attached to a success.)
pub fn remove_core(d: &mut dyn DaemonApi, name: &str, force: bool) -> Result<(), String> {
    if d.lockdown_supported() {
        let configured = d.lockdown_state(name).map_err(|e| e.to_string())?;
        if configured.is_locked() {
            d.unlock(name).map_err(|e| {
                format!(
                    "Windows account for '{name}' was not released ({e:#}) — approve the \
                     prompt to remove it, or run 'izba windows-cleanup' later"
                )
            })?;
        }
    }
    d.remove(name, force).map_err(|e| e.to_string())
}
```

- [ ] **Step 4: FakeDaemon.** New fields (with `Default` values): `lockdown_supported: bool` (`true`), `locked: std::collections::HashSet<String>` (empty), `lockdown_cancel: bool` (`false`), `unlock_fail: Option<String>` (`None`), `lockdown_account: Option<String>` (`None`), `lockdown_restart_required: bool` (`false`). `inspect` returns `lockdown_account: self.lockdown_account.clone(), lockdown_restart_required: self.lockdown_restart_required`. Impl:

```rust
    fn lockdown_supported(&self) -> bool {
        self.lockdown_supported
    }
    fn lockdown_state(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownState> {
        Ok(if self.locked.contains(name) {
            izba_core::jail_account::LockdownState::Locked(izba_core::jail_account::LockedInfo {
                account: format!("izba-sb-{name}"),
                sid: "S-1-5-21-0".into(),
                net_blocked: true,
            })
        } else {
            izba_core::jail_account::LockdownState::Unlocked
        })
    }
    fn lockdown(&mut self, name: &str) -> anyhow::Result<izba_core::jail_account::LockdownOutcome> {
        self.calls.push(format!("lockdown:{name}"));
        if self.fail_action {
            anyhow::bail!("provision helper failed: boom");
        }
        if self.lockdown_cancel {
            return Ok(izba_core::jail_account::LockdownOutcome::Cancelled);
        }
        self.locked.insert(name.to_string());
        let izba_core::jail_account::LockdownState::Locked(info) = self.lockdown_state(name)? else {
            unreachable!("just inserted");
        };
        Ok(izba_core::jail_account::LockdownOutcome::Locked(info))
    }
    fn unlock(&mut self, name: &str) -> anyhow::Result<()> {
        self.calls.push(format!("unlock:{name}"));
        if let Some(msg) = &self.unlock_fail {
            anyhow::bail!("{msg}");
        }
        self.locked.remove(name);
        Ok(())
    }
```

- [ ] **Step 5: Tauri commands + dispatch.** In lib.rs next to `vnc_set`:

```rust
/// Pops a UAC prompt and blocks until the user answers — `run_action`, so the
/// shared polling lock is never held while the prompt is open.
#[tauri::command]
async fn lockdown(state: State<'_, AppState>, name: String) -> Result<String, String> {
    run_action(&state, move |d| commands::lockdown_core(d, &name)).await
}

#[tauri::command]
async fn unlock(state: State<'_, AppState>, name: String) -> Result<(), String> {
    run_action(&state, move |d| commands::unlock_core(d, &name)).await
}
```

Add `lockdown, unlock` to `generate_handler![…]` and bridge-dispatch arms:

```rust
        "lockdown" => to_json(commands::lockdown_core(d, &arg_str(&args, "name")?)?),
        "unlock" => to_json(commands::unlock_core(d, &arg_str(&args, "name")?)?),
```

Add a `dispatch_tests` case mirroring the existing ones: dispatch `"lockdown"` with `{"name":"web"}` against `FakeDaemon::default()` ⇒ `json!("locked")`.

Run: `cd app/src-tauri && cargo test` → PASS.

- [ ] **Step 6: Frontend types/ipc/mock.** types.ts:

```ts
/** Lock-down (MVP-D) posture. `locked`/`account`/`net_blocked` are the
 *  configured posture; `restart_required`/`booted_as_account` are recorded
 *  facts about the live run. */
export interface LockdownView {
  locked: boolean;
  account: string | null;
  net_blocked: boolean;
  restart_required: boolean;
  booted_as_account: boolean;
}
```

and in `SandboxDetail`: `/** `null` when lock-down does not exist on this host (non-Windows) — hide the row. */ lockdown: LockdownView | null;`. ipc.ts:

```ts
  lockdown: (name: string) => invoke<"locked" | "cancelled">("lockdown", { name }),
  unlock: (name: string) => invoke<void>("unlock", { name }),
```

tauri-mock.js, after `vnc_set`:

```js
      case "lockdown": {
        calls.push("lockdown:" + args.name);
        if (scenario.lockdownError) return err(scenario.lockdownError);
        const outcome = scenario.lockdownOutcome || "locked";
        const d = scenario.details && scenario.details[args.name];
        if (d && d.lockdown && outcome === "locked") {
          d.lockdown.locked = true;
          d.lockdown.account = "izba-sb-" + args.name;
          d.lockdown.net_blocked = true;
          const sbx = (scenario.sandboxes || []).find(function (s) {
            return s.name === args.name;
          });
          d.lockdown.restart_required = !!(sbx && sbx.state && sbx.state.kind === "running");
        }
        return Promise.resolve(outcome);
      }
      case "unlock": {
        calls.push("unlock:" + args.name);
        const d = scenario.details && scenario.details[args.name];
        if (d && d.lockdown) {
          d.lockdown.locked = false;
          d.lockdown.account = null;
          d.lockdown.restart_required = d.lockdown.booted_as_account;
        }
        return action();
      }
```

Add `lockdown: null` to every TS/JS `SandboxDetail` fixture (`app/src/test/overview/fixtures.ts` `detailFixture`, and the others found by grep, incl. e2e scenario files).

- [ ] **Step 7: App gate** (Global Constraints). Expected: green, incl. `tauriMockParity`.

- [ ] **Step 8: Commit**

```bash
git add app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs app/src-tauri/src/views.rs app/src-tauri/src/commands.rs app/src-tauri/src/lib.rs app/e2e/mock/tauri-mock.js app/src/lib/types.ts app/src/lib/ipc.ts <fixture files>
git commit -m "feat(app): lock-down/unlock commands + view; GUI remove releases a locked sandbox's account"
```

---

### Task 3: UI — LockdownRow in the Sandbox card + inspect refresh

**Files:**
- Create: `app/src/components/overview/LockdownRow.tsx`
- Modify: `app/src/components/overview/SandboxCard.tsx` (render row; new `onChanged` prop)
- Modify: `app/src/components/overview/OverviewTab.tsx` (refetch on state kind change + on `onChanged`)
- Create: `app/src/test/overview/lockdownRow.test.tsx`
- Modify: `app/src/test/overview/overviewTab.test.tsx` (refetch test)
- Create: `app/e2e/lockdown.spec.ts` (mock-driven Playwright journey)

**Interfaces:**
- Consumes (Task 2): `LockdownView`, `SandboxDetail.lockdown`, `api.lockdown`, `api.unlock`, mock `scenario.lockdownOutcome`/`lockdownError`.
- Produces: `LockdownRow({ name, lockdown, onChanged }: { name: string; lockdown: LockdownView; onChanged: () => void })`; `SandboxCard` prop `onChanged?: () => void`.

- [ ] **Step 1: Failing Vitest** `app/src/test/overview/lockdownRow.test.tsx` (mock `../../lib/ipc` the way sibling tests mock `api`; check an existing test such as `displayTab.test.tsx` for the exact `vi.mock` shape):

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LockdownView } from "../../lib/types";

const lockdown = vi.fn();
const unlock = vi.fn();
vi.mock("../../lib/ipc", () => ({ api: { lockdown: (n: string) => lockdown(n), unlock: (n: string) => unlock(n) } }));

import { LockdownRow } from "../../components/overview/LockdownRow";

const unlocked: LockdownView = { locked: false, account: null, net_blocked: false, restart_required: false, booted_as_account: false };
const locked: LockdownView = { locked: true, account: "izba-sb-web", net_blocked: true, restart_required: false, booted_as_account: true };

beforeEach(() => {
  lockdown.mockReset();
  unlock.mockReset();
});

describe("LockdownRow", () => {
  it("offers Lock down when unlocked", () => {
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    expect(screen.getByText("unlocked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /lock down/i })).toBeEnabled();
  });

  it("waits for approval, disables the button, then reports back", async () => {
    let resolve!: (v: "locked") => void;
    lockdown.mockReturnValue(new Promise((r) => (resolve = r)));
    const onChanged = vi.fn();
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={onChanged} />);
    await userEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(screen.getByText("Waiting for approval…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /waiting for approval/i })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /waiting for approval/i }));
    expect(lockdown).toHaveBeenCalledTimes(1);
    resolve("locked");
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("treats a declined prompt as a quiet cancel, not an error", async () => {
    lockdown.mockResolvedValue("cancelled");
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(await screen.findByText("cancelled — nothing changed")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a failure as an error", async () => {
    lockdown.mockRejectedValue("provision helper failed: boom");
    render(<LockdownRow name="web" lockdown={unlocked} onChanged={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: /lock down/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("provision helper failed: boom");
  });

  it("summarizes the locked posture and confirms before unlocking", async () => {
    unlock.mockResolvedValue(undefined);
    const onChanged = vi.fn();
    render(<LockdownRow name="web" lockdown={locked} onChanged={onChanged} />);
    expect(screen.getByText("locked · izba-sb-web · network blocked")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^unlock$/i }));
    expect(unlock).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /^unlock sandbox$/i }));
    await waitFor(() => expect(unlock).toHaveBeenCalledWith("web"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("renders network open when the firewall rule is absent", () => {
    render(<LockdownRow name="web" lockdown={{ ...locked, net_blocked: false }} onChanged={() => {}} />);
    expect(screen.getByText("locked · izba-sb-web · network open")).toBeInTheDocument();
  });

  it("badges a lock that has not taken effect yet", () => {
    render(<LockdownRow name="web" lockdown={{ ...locked, restart_required: true, booted_as_account: false }} onChanged={() => {}} />);
    expect(screen.getByText("restart to apply")).toBeInTheDocument();
  });

  it("badges an unlock that has not taken effect yet", () => {
    render(<LockdownRow name="web" lockdown={{ ...unlocked, restart_required: true, booted_as_account: true }} onChanged={() => {}} />);
    expect(screen.getByText("still running as account — restart to apply")).toBeInTheDocument();
  });

  it("drops a late result after the row unmounts (sandbox switched)", async () => {
    let resolve!: (v: "cancelled") => void;
    lockdown.mockReturnValue(new Promise((r) => (resolve = r)));
    const onChanged = vi.fn();
    const { unmount } = render(<LockdownRow name="web" lockdown={unlocked} onChanged={onChanged} />);
    await userEvent.click(screen.getByRole("button", { name: /lock down/i }));
    unmount();
    resolve("cancelled");
    await new Promise((r) => setTimeout(r, 0));
    expect(onChanged).not.toHaveBeenCalled();
  });
});
```

Also in `sandboxCard.test.tsx`: `it("hides the lock-down row when the host has no lock-down", …)` rendering `detailFixture()` (lockdown null) ⇒ `queryByText("lock-down")` is null; and `it("shows the lock-down row when the host supports it", …)` with `detailFixture({ lockdown: {…unlocked} })` ⇒ `getByText("lock-down")` present. (Mock `LockdownRow`'s ipc as above or mock `../../lib/ipc`.)

Run: `cd app && npx vitest run src/test/overview` → FAIL (module missing). *(Use the repo's npm script if `npx` is disallowed in scripts — locally it is fine.)*

- [ ] **Step 2: Implement `LockdownRow.tsx`.** Follow `SandboxCard.tsx`'s `Row` layout (import or replicate its label/value row — if `Row` is not exported, export it from `SandboxCard.tsx` or move it to `CardShell.tsx`; do not duplicate styling). Behaviour:

```tsx
import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "../Spinner";
import { ConfirmDialog } from "../ConfirmDialog";
import { api } from "../../lib/ipc";
import type { LockdownView } from "../../lib/types";

type Phase = { kind: "idle" } | { kind: "pending" } | { kind: "cancelled" } | { kind: "error"; message: string };

/** Per-sandbox Windows lock-down (MVP-D). Each action pops a UAC prompt; a
 *  declined prompt is the user's choice, not a failure. Takes effect at the
 *  next start — the badge is the daemon's recorded fact, never guessed here. */
export function LockdownRow({ name, lockdown, onChanged }: Readonly<{ name: string; lockdown: LockdownView; onChanged: () => void }>) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [confirming, setConfirming] = useState(false);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  const run = async (action: () => Promise<"locked" | "cancelled" | void>) => {
    setPhase({ kind: "pending" });
    try {
      const outcome = await action();
      if (!alive.current) return;
      setPhase(outcome === "cancelled" ? { kind: "cancelled" } : { kind: "idle" });
      if (outcome !== "cancelled") onChanged();
    } catch (e) {
      if (!alive.current) return;
      setPhase({ kind: "error", message: String(e) });
    }
  };
  // … render: summary text, badge, button (disabled while pending, label
  // "Waiting for approval…" with <Spinner/> while pending), cancel note,
  // error with role="alert", ConfirmDialog (title "Unlock sandbox?",
  // confirmLabel "Unlock sandbox", danger, message explaining the VMM will
  // run as your own user with network access after the next restart).
}
```

Summary text: locked ⇒ `` `locked · ${lockdown.account} · ${lockdown.net_blocked ? "network blocked" : "network open"}` ``; else `unlocked`. Badge when `restart_required`: locked ⇒ `restart to apply`; unlocked ⇒ `still running as account — restart to apply` (warning tone — use the `--warning` token classes the Meter uses, e.g. `text-warning`). Lock button: `variant="secondary"`, `size="sm"`, `<ShieldCheck />` icon + `Lock down`, `title="Requires administrator approval (UAC)"`. Unlock button: `variant="ghost"`, `size="sm"`, `Unlock`, opens the dialog; dialog confirm ⇒ `setConfirming(false); void run(() => api.unlock(name))`.

- [ ] **Step 3: Wire into `SandboxCard`** after the `confinement` row:

```tsx
      {detail?.lockdown && (
        <LockdownRow key={name} name={name} lockdown={detail.lockdown} onChanged={onChanged ?? (() => {})} />
      )}
```

(`key={name}` resets the row's phase when the user switches sandboxes.) Add the optional `onChanged` prop to `SandboxCard`'s props with a doc comment.

- [ ] **Step 4: `OverviewTab` refresh.** Turn the fetch into a `refresh` counter: `const [rev, setRev] = useState(0);` add `sandbox.state.kind` and `rev` to the effect's dependency list (keep `setDetail(null)` ONLY when the name changes — otherwise the card flashes "…"; track the previous name with a ref), and pass `onChanged={() => setRev((r) => r + 1)}` to `SandboxCard`. Test in `overviewTab.test.tsx`: render with a running sandbox, `rerender` with `state: { kind: "stopped" }`, assert `api.inspect` was called twice (follow the file's existing ipc mock).

- [ ] **Step 5: Run Vitest** → PASS.

- [ ] **Step 6: Playwright journey** `app/e2e/lockdown.spec.ts`, modelled on `app/e2e/display.spec.ts` (same scenario setup helper): a running sandbox `web` whose detail has `lockdown: {locked:false, account:null, net_blocked:false, restart_required:false, booted_as_account:false}`; open it, click **Lock down**, expect `locked · izba-sb-web · network blocked` and `restart to apply` (the mock re-fetch via `onChanged`); click **Unlock**, confirm **Unlock sandbox**, expect `unlocked`. Second test: `scenario.lockdownOutcome = "cancelled"` ⇒ expect `cancelled — nothing changed` and still `unlocked`. Third: a detail with `lockdown: null` ⇒ no `lock-down` label.

Run: the repo's Playwright script (see `app/package.json`, e.g. `npm run e2e -- lockdown`). Expected: PASS.

- [ ] **Step 7: App gate** (Global Constraints) → green.

- [ ] **Step 8: Commit**

```bash
git add app/src/components/overview/LockdownRow.tsx app/src/components/overview/SandboxCard.tsx app/src/components/overview/OverviewTab.tsx app/src/test/overview/lockdownRow.test.tsx app/src/test/overview/sandboxCard.test.tsx app/src/test/overview/overviewTab.test.tsx app/e2e/lockdown.spec.ts <anything else touched>
git commit -m "feat(app): lock-down row in the Overview sandbox card"
```

---

### Task 4: Docs

**Files:**
- Modify: `docs/roadmap.md` (MVP-D line: note the app button shipped)
- Modify: `README.md` only if it documents lock-down as CLI-only (grep `lockdown`); otherwise leave it.

- [ ] **Step 1:** In `docs/roadmap.md` where MVP-D is described (`per-sandbox account + izba lockdown/unlock (MVP-D, PR #53)`), append "; the desktop app's Lock down / Unlock control + restart-to-apply badge followed in 2026-09".
- [ ] **Step 2:** `grep -n -i "lockdown\|lock-down" README.md` — if a section says it is CLI-only, add one sentence that the app's Overview → Sandbox card offers the same control on Windows.
- [ ] **Step 3: Commit** `docs: note the desktop app lock-down control`.
