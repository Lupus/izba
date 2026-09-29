# Desktop app: per-sandbox Windows lock-down button

**Status:** approved design (2026-09-29, owner)
**Closes the deferred follow-up of:** PR #53 (MVP-D, per-sandbox Windows
account) — "App lock-down button — deferred follow-up (App CI passes without
it)". Original intent: `2026-06-18-windows-per-sandbox-account-design.md` §146
("a 'lock down' button with the UAC-shield affordance; status badge").

## 1. Problem

`izba lockdown` / `izba unlock` (MVP-D) provision / deprovision a per-sandbox
Windows local account (`izba-sb-<name>`) plus an outbound-deny firewall rule;
the next start launches the VMM as that account. The feature is CLI-only: the
desktop app has no control, no status, and — a latent bug — its **Remove**
path (`RealDaemon::remove` → `DaemonRequest::Rm`) does not release the account,
so removing a locked sandbox from the GUI leaks the account + firewall rule
(the CLI's `izba rm` releases them first).

A second, honesty gap: nothing records which account a *running* VMM was
actually launched as. Lock-down takes effect only on the next start, so after
locking a running sandbox, no surface can truthfully say "configured locked,
but still running unconfined until restart".

## 2. Goals / non-goals

Goals:
- Lock down / unlock a sandbox from the Overview tab's Sandbox card (Windows).
- A durable, recorded-fact "restart to apply" signal, shared by the app and
  `izba status`.
- GUI Remove of a locked sandbox releases the account, fail-closed.

Non-goals (YAGNI): GUI for `izba windows-cleanup`; the never-produced
`LockdownState::Degraded`; lock-down at create time; any daemon RPC for
lock-down (it stays client-side, exactly like the CLI — izbad cannot
self-elevate).

## 3. Design

### 3.1 Core: record the booted account (izba-core)

- `RunState` (`state.json`) gains
  `#[serde(default)] pub lockdown_account: Option<String>`. `sandbox::start`
  captures `spec.lockdown.as_ref().map(|l| l.account().to_string())` before
  launch and passes it to `record_run_state`, which writes it next to
  `confinement`. Written only after `driver.launch` succeeded, so it states a
  launch that actually happened (a locked launch that fails, fails the start —
  there is no silent fallback to record wrongly).
- `SandboxDetail` (daemon Inspect reply) gains
  `#[serde(default)] pub lockdown_account: Option<String>` (the booted
  account, `None` when stopped) and
  `#[serde(default)] pub lockdown_restart_required: bool`, both filled by
  `handle_inspect` — the latter from the predicate below, using the SAME
  `running` liveness predicate as `vnc_restart_required` and the configured
  state from `orchestrate::lockdown_state(&d.paths, name)`. Additive +
  `serde(default)` ⇒ **no `DAEMON_PROTO_VERSION` bump** (an older daemon's
  reply reads as `None`/`false`). Its manual `Debug` impl gains both fields.
- One pure predicate in `jail_account` (single source of truth):

  ```rust
  pub fn lockdown_restart_required(
      configured: &LockdownState,
      booted_account: Option<&str>,
      running: bool,
  ) -> bool
  ```

  `false` when not running. Running: `Locked(info)` ⇒ `booted != Some(info.account)`;
  `Unlocked`/`Degraded` ⇒ `booted.is_some()`. A pre-upgrade running sandbox
  (field absent ⇒ `None`) that is configured locked therefore reports
  restart-required — conservative and honest (we cannot prove it runs as the
  account).
- `izba status` appends ` (restart required)` to its existing `lock-down:` line
  when `det.lockdown_restart_required` is true (the daemon computed it; the
  CLI never re-derives it).

### 3.2 App backend (app/src-tauri)

- `DaemonApi` gains:
  - `lockdown_supported(&self) -> bool` — `RealDaemon`: `cfg!(windows)`;
    `FakeDaemon`: a settable field (default `true` so tests reach the surface).
  - `lockdown_state(&mut self, name) -> anyhow::Result<LockdownState>` —
    `RealDaemon`: `orchestrate::lockdown_state(&self.paths, name)`.
  - `lockdown(&mut self, name) -> anyhow::Result<LockdownOutcome>` and
    `unlock(&mut self, name) -> anyhow::Result<()>` — `RealDaemon` calls
    `orchestrate::{lockdown, unlock}(&WinBackend, &self.paths, name)`
    (same path as the CLI, which also validates `config.json` exists first).
- Tauri commands `lockdown(name) -> LockdownResultView` (`"locked"` |
  `"cancelled"`) and `unlock(name) -> ()`, both via `run_action` (fresh
  connection, `spawn_blocking`) so an open UAC prompt never holds the shared
  polling lock. Registered in `generate_handler!`, the bridge dispatch, and the
  Playwright IPC mock (`tauriMockParity` gate).
- `SandboxDetailView` gains `lockdown: Option<LockdownView>`:
  `LockdownView { locked: bool, account: Option<String>, net_blocked: bool,
  restart_required: bool, booted_as_account: bool }`. `inspect_core` fills it
  only when `d.lockdown_supported()` — `locked`/`account`/`net_blocked` from
  `d.lockdown_state(name)`, `restart_required` = `detail.lockdown_restart_required`,
  `booted_as_account` = `detail.lockdown_account.is_some()`; otherwise `None` — that one field decides
  whether the UI renders the control at all (Linux: hidden).
- **Remove fix:** `remove_core` (the GUI Remove) checks `lockdown_state`; if
  locked, it calls `unlock` FIRST. `Err` (UAC declined / helper failed) aborts
  the remove with: `sandbox '<name>' was NOT removed: its Windows lock-down
  account could not be released (<cause>). Approve the prompt and retry, or
  remove it from the CLI with 'izba rm <name>' (then 'izba windows-cleanup').`
  Nothing has been deleted, so a retry is safe. Fail-closed (the CLI is
  warn-and-continue) because the GUI has no post-success warning channel.

### 3.3 UI (app/src) — Sandbox card, "lock-down" row

Rendered only when `detail.lockdown !== null`.
- **Unlocked:** `unlocked` + **Lock down** button with a shield icon
  (`lucide-react` `ShieldCheck`). While in flight: spinner + "Waiting for
  approval…". Outcome `cancelled` ⇒ muted note "cancelled — nothing changed"
  (not an error). Error ⇒ destructive inline text.
- **Locked:** `locked · <account> · network blocked` (or `network open`) +
  **Unlock** button. Unlock is a security-weakening action ⇒ existing
  `ConfirmDialog` first, then the UAC prompt.
- **restart_required:** warning-tone badge "restart to apply" when configured
  locked; "still running as account — restart to apply" when configured
  unlocked but `booted_as_account`. Restart is already in the header row.
- Stopped sandboxes can be locked/unlocked; no badge (applies on next start).
- After any action the detail is re-fetched so the row reflects disk truth.
  `OverviewTab` also re-fetches `inspect` when the sandbox's state kind
  changes (today it fetches once per name), so a Restart clears the badge.

## 4. Testing

- Core: predicate truth table (every configured × booted × running combo);
  `RunState` round-trip incl. a pre-field `state.json`; `record_run_state`
  persists the account; Inspect maps it; `izba status` restart-required line.
- Tauri: `FakeDaemon` lockdown / cancel / unlock; `inspect_core` view mapping
  (supported vs not); remove-on-locked ordering (unlock before Rm; declined
  unlock ⇒ no Rm, actionable error); unlocked remove never calls unlock.
- Frontend (Vitest): row hidden / unlocked / pending / cancelled / error /
  locked / restart-required (both wordings) / unlock confirm; mock parity.
- Real Windows: CI dev installer (`hack/devbuild.sh`), manual click-through on
  the Windows host (UAC cannot be automated in CI). The CLI path stays covered
  by `hack/spike/validate-izba-windows.ps1`.

## 5. Contracts touched (change all ends)

- `RunState` + `SandboxDetail` (additive, serde-default) — every struct-literal
  construction site in `crates/` AND `app/src-tauri` must gain the field (the
  app is outside the workspace gates; run the app gate locally).
- `generate_handler!` ↔ `app/e2e/mock/tauri-mock.js` ↔ bridge dispatch.
