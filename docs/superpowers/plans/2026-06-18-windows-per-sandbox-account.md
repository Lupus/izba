# Windows per-sandbox local account ("lock down") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in per-sandbox Windows hardening that runs the VMM under a dedicated, ACL-scoped, network-dead standard local account, layered on PR #37's restricted-token/Low-IL confinement.

**Architecture:** A tiny elevated `izba-jail-helper.exe` performs the admin-only account/registry/firewall lifecycle at the UAC moment; izbad stays unprivileged and launches the VMM via `CreateProcessWithLogonW` as the account. Lock-down state is persisted per-sandbox and re-derived from disk on startup. Host-testable logic (state, builders, GC, DPAPI, proto, status) is TDD'd through the six workspace gates; Windows FFI is validated via CI + `powershell.exe` interop.

**Tech Stack:** Rust (`windows-sys` for Win32 FFI: NetApi32, advapi32/DPAPI, registry, `CreateProcessWithLogonW`, `ShellExecuteExW` runas), the existing `procmgr`/`confine` jailer, `serde`, framed-JSON `daemon::proto`, Tauri (app).

## Global Constraints

- All six workspace gates green before every commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- Windows FFI bodies are `#[cfg(windows)]`; non-Windows compiles a stub so the cross gate still sees the surface (mirror `confine_probe`).
- Unit tests never bind unix/vsock listeners; Windows FFI tests **runtime-skip** when not elevated / on `PermissionDenied` (mirror `full_connect_via_listener` + `confine_probe`).
- Touching `izba-core`/`izba-proto` public types ⇒ run the app gate locally (`cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`).
- Any wire-breaking frame change ⇒ bump `DAEMON_PROTO_VERSION`; keep `proto`/`build` `#[serde(default)]`.
- Conventional commits; TDD (test first); frequent commits.
- Naming: account `izba-sb-<sandbox>`, firewall rule `izba-deny-<sandbox>`, state file `lockdown.json`, sealed cred `lockdown.cred`.
- Loud on degradation: a failed provision fails the lock-down loudly and leaves the sandbox **unlocked**; never run a "locked" sandbox unconfined.

---

## File structure

- Create `crates/izba-core/src/jail_account/mod.rs` — unprivileged client surface: lock-down state types, status rendering, helper-invocation (elevated run), DPAPI seal/unseal, SDDL/argv builders, GC diff. Split into:
  - `state.rs` — `LockdownState`, `lockdown.json` serde, status strings.
  - `builders.rs` — pure SDDL + helper-argv builders + GC diff (fully host-testable).
  - `dpapi.rs` — `CryptProtectData`/`CryptUnprotectData` seal/unseal (`#[cfg(windows)]` + stub).
  - `helper.rs` — resolve helper path (exe-relative), elevated invoke via `ShellExecuteExW`, parse result.
- Create `crates/izba-jail-helper/` — new binary crate (elevated helper). `main.rs` verb dispatch + non-windows stub; `account.rs`, `userlist.rs`, `dacl.rs`, `firewall.rs`, `provision.rs`.
- Modify `crates/izba-core/src/procmgr/mod.rs` + `procmgr/windows.rs` — `CreateProcessWithLogonW` launch path when locked down (compose with confined token).
- Modify `crates/izba-core/src/sandbox.rs` — provision/deprovision orchestration, state persistence, startup reconcile, orphan detection, status.
- Modify `crates/izba-proto` daemon proto — `Lockdown`/`Unlock`/`WindowsCleanup` + `RequiresElevation`; version bump.
- Modify `crates/izba-core/src/daemon/{server,proto,client}.rs` — handlers.
- Modify `crates/izba-cli` — `lockdown`/`unlock`/`windows-cleanup` verbs + status display.
- Modify `app/src-tauri` + frontend — lock-down command on the `DaemonApi`/`FakeDaemon` seam + button.
- Modify `.github/workflows/_artifacts.yml` + installer scripts — ship `izba-jail-helper.exe`.
- Modify `.github/workflows/e2e.yml` (windows-whp) — provision→launch→read-deny→net-block→deprovision assertion.

---

## Phase A — host-testable logic (full TDD, six gates)

### Task 1: Lock-down state types + serde + status

**Files:**
- Create: `crates/izba-core/src/jail_account/mod.rs`, `crates/izba-core/src/jail_account/state.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod jail_account;`)
- Test: inline `#[cfg(test)]` in `state.rs`

**Interfaces:**
- Produces:
  - `pub enum LockdownState { Unlocked, Locked(LockedInfo), Degraded { reason: String } }`
  - `pub struct LockedInfo { pub account: String, pub sid: String, pub net_blocked: bool }`
  - `impl LockdownState { pub fn summary(&self) -> String; pub fn is_locked(&self) -> bool; }`
  - `#[derive(Serialize, Deserialize, Default)] pub struct LockdownFile { #[serde(default)] pub state: Option<LockedInfo> }` persisted as `lockdown.json`.

- [ ] **Step 1: Failing test** — serde round-trip of `LockdownFile { state: Some(LockedInfo{account:"izba-sb-foo",sid:"S-1-5-...",net_blocked:true}) }` and `summary()` strings (`unlocked`, `locked(account=…, sid=…, net=blocked)`, `degraded: …`).
- [ ] **Step 2:** Run `cargo test -p izba-core jail_account::state` → FAIL (module missing).
- [ ] **Step 3:** Implement the types + `summary()`/`is_locked()` + `Default`.
- [ ] **Step 4:** `cargo test -p izba-core jail_account::state` → PASS.
- [ ] **Step 5:** fmt + clippy + windows-gnu check; commit `feat(core): lock-down state types + status`.

### Task 2: SDDL + helper-argv builders + GC diff (pure)

**Files:**
- Create: `crates/izba-core/src/jail_account/builders.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `LockedInfo` (Task 1).
- Produces:
  - `pub fn firewall_sddl(sid: &str) -> String` → `D:(A;;CC;;;<sid>)`.
  - `pub fn account_name(sandbox: &str) -> String` / `pub fn rule_name(sandbox: &str) -> String` (sanitize to `izba-sb-<safe>` / `izba-deny-<safe>`; assert length ≤ 20 for the account, the Windows local-username limit).
  - `pub fn provision_argv(sandbox: &str, grants: &[PathBuf], sid_out: &Path, cred_out: &Path) -> Vec<String>` and `deprovision_argv`, `gc_argv(live: &[String])`.
  - `pub fn gc_orphans(existing: &[String], live: &[String]) -> Vec<String>` — `izba-sb-*` names whose sandbox ∉ live.

- [ ] **Step 1: Failing tests** — `firewall_sddl("S-1-5-21-1")=="D:(A;;CC;;;S-1-5-21-1)"`; `account_name("My Box")=="izba-sb-my-box"` and length cap; `gc_orphans(["izba-sb-a","izba-sb-b"],["a"])==["izba-sb-b"]`; argv vectors contain the expected flags/paths.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement pure builders.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** gates; commit `feat(core): SDDL/argv builders + GC-orphan diff`.

## Phase B — elevated helper (`izba-jail-helper`, FFI, runtime-skip tests)

### Task 3: Helper crate scaffold + verb parsing + stub

**Files:**
- Create: `crates/izba-jail-helper/Cargo.toml`, `crates/izba-jail-helper/src/main.rs`
- Modify: root `Cargo.toml` workspace `members`
- Test: inline arg-parse tests (host-testable, no FFI)

**Interfaces:**
- Produces: a binary with verbs `provision|deprovision|gc`, JSON result on stdout, exit 0 ok / 1 error. Non-windows `main` prints `izba-jail-helper: windows-only` and exits 2. Arg parsing in a pure `parse_args(argv) -> Result<Verb, String>` that is unit-tested on all platforms.

- [ ] Steps: failing test on `parse_args`; FAIL; implement parse + stub `main`; PASS; gates (incl. windows-gnu `cargo check` of the new crate — add it to the cross gate list mentally, it builds under gnu); commit `feat(jail-helper): crate scaffold + verb parsing`.

### Task 4: Account create/delete + random password

**Files:** Create `crates/izba-jail-helper/src/account.rs`

**Interfaces:**
- Produces (`#[cfg(windows)]`): `pub fn create_account(name:&str)->Result<(String /*sid*/, String /*password*/)>` (NetUserAdd level 1, `UF_DONT_EXPIRE_PASSWD|UF_SCRIPT`, member of Users only; strong random 24-char password meeting complexity; SID via `LookupAccountNameW`); `pub fn delete_account(name:&str)->Result<()>` (NetUserDel, ok-if-absent); `pub fn delete_profile(name:&str)` best-effort.
- Stub on non-windows returns `Err("windows-only")`.

- [ ] Steps: TDD where host-testable (password complexity generator is pure → unit-test it; account FFI gets a `#[cfg(windows)]` test that runtime-skips when not elevated and otherwise create→lookup-sid→delete round-trips). Implement via `windows-sys::Win32::NetworkManagement::NetManagement::{NetUserAdd,NetUserDel}` + `LookupAccountNameW`. Commit `feat(jail-helper): local account create/delete + random pw`.

### Task 5: UserList hide + DACL grant

**Files:** Create `userlist.rs`, `dacl.rs`

**Interfaces:**
- `userlist.rs`: `pub fn hide(name:&str)->Result<()>` / `unhide(name:&str)` — set/clear `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList\<name>=0` (DWORD) via `RegCreateKeyExW`/`RegSetValueExW`/`RegDeleteValueW`.
- `dacl.rs`: `pub fn grant(path:&Path, sid:&str, access:GrantLevel)->Result<()>` — add an allow ACE for the account SID (`SetNamedSecurityInfoW` + `SetEntriesInAclW`, inheritable) preserving existing ACEs; `GrantLevel::{ReadExec, Modify}`.

- [ ] Steps: registry path/value formatting is pure → unit-test the key path builder; FFI runtime-skips unelevated. Implement. Commit `feat(jail-helper): UserList hide + per-account DACL grant`.

### Task 6: Firewall add/remove

**Files:** Create `firewall.rs`

**Interfaces:**
- Produces: `pub fn block(rule:&str, sid:&str)->Result<()>` / `unblock(rule:&str)`. Implementation: shell out to `powershell -NoProfile -Command New-NetFirewallRule -DisplayName <rule> -Direction Outbound -Action Block -Profile Any -LocalUser "D:(A;;CC;;;<sid>)"` (+ an inbound twin), and `Get-NetFirewallRule -DisplayName <rule> | Remove-NetFirewallRule` for unblock. (Decision per spec §5.5; the spike proved this exact rule blocks.)
- The PS command string is built by a pure function reusing `firewall_sddl` (Task 2) → unit-test the argument string.

- [ ] Steps: pure command-builder test; FFI run gated. Implement. Commit `feat(jail-helper): per-SID firewall block add/remove`.

### Task 7: Helper provision/deprovision/gc orchestration + rollback

**Files:** Create `provision.rs`; wire into `main.rs`

**Interfaces:**
- Produces: `pub fn provision(sandbox,grants,sid_out,cred_out)->Result<()>` running account→hide→DACL→firewall in order, **rolling back** created artifacts on any failure, then writing SID to `sid_out` and the password to `cred_out` (ACL'd to the invoking user). `deprovision(sandbox)` reverses idempotently. `gc(live)` enumerates `izba-sb-*` (NetUserEnum) + `izba-deny-*` rules and deprovisions orphans.

- [ ] Steps: orchestration ordering + rollback decision tree is testable with injected fakes (trait `Ops` with create/hide/dacl/firewall; a fake records calls and forces a failure at step k → assert rollback unwinds k-1..0). Implement real `WinOps` over Tasks 4-6. Commit `feat(jail-helper): transactional provision/deprovision/gc`.

## Phase C — izba-core unprivileged integration

### Task 8: DPAPI seal/unseal

**Files:** Create `crates/izba-core/src/jail_account/dpapi.rs`

**Interfaces:**
- Produces (`#[cfg(windows)]`): `pub fn seal(plain:&[u8])->Result<Vec<u8>>` (`CryptProtectData`, user scope, no `LOCAL_MACHINE`), `pub fn unseal(blob:&[u8])->Result<Vec<u8>>` (`CryptUnprotectData`). Non-windows stub `Err`.

- [ ] Steps: `#[cfg(windows)]` round-trip test `unseal(seal(b"pw"))==b"pw"` (runs on the windows-native CI job + interop); the seal/unseal API shape compiles under windows-gnu. Implement. Commit `feat(core): DPAPI seal/unseal for the lock-down credential`.

### Task 9: Elevated helper invocation client

**Files:** Create `crates/izba-core/src/jail_account/helper.rs`

**Interfaces:**
- Consumes: builders (Task 2).
- Produces: `pub fn helper_path()->Result<PathBuf>` (resolve `izba-jail-helper.exe` beside `current_exe()`); `pub fn run_elevated(argv:&[String])->Result<ElevationOutcome>` via `ShellExecuteExW` verb `runas` (UAC), waiting on the process handle, reading `sid_out`/`cred_out`. Returns `ElevationOutcome::{Ok, Cancelled, Failed(String)}` (map UAC-cancel `ERROR_CANCELLED` to `Cancelled`).

- [ ] Steps: `helper_path` resolution is host-testable (inject `current_exe`); `run_elevated` FFI gated/interop. Implement. Commit `feat(core): elevated izba-jail-helper invocation client`.

### Task 10: Locked-down VMM launch (`CreateProcessWithLogonW`)

**Files:** Modify `crates/izba-core/src/procmgr/mod.rs`, `procmgr/windows.rs`

**Interfaces:**
- Consumes: confined-token spawn (PR #37 `spawn_confined`), `LockedInfo`, DPAPI unseal.
- Produces: `pub fn spawn_confined_as(spec,log,policy,account:&str,password:&Zeroizing<String>)->Result<(ProcId,ConfinementMode)>` — `CreateProcessWithLogonW(account, ".", password, LOGON_WITH_PROFILE, …, CREATE_SUSPENDED)`, then apply the existing restricted-token/Low-IL/job steps to the suspended process before resume. (If composing token+logon proves infeasible in one call, document the fallback: logon launch + in-process self-confine, mirroring the spike's `confined-whp`.) Existing `spawn_confined` unchanged for the non-locked path.

- [ ] Steps: argument-marshalling + the launch decision (`locked ? spawn_confined_as : spawn_confined`) are host-testable; the FFI runs in CI/interop. Implement. Commit `feat(vmm): launch the confined VMM as the per-sandbox account`.

### Task 11: sandbox.rs orchestration + reconcile + status

**Files:** Modify `crates/izba-core/src/sandbox.rs`

**Interfaces:**
- Consumes: Tasks 1-10.
- Produces: `pub fn lockdown(name)->Result<LockdownOutcome>` (compute grants = [workspace share, sandbox dir, this sandbox's named volumes]; call `run_elevated(provision_argv…)`; seal cred; persist `lockdown.json`); `pub fn unlock(name)` (`deprovision_argv` + clear state + `restore_confined_workspace`); start path consults `lockdown.json` and uses `spawn_confined_as`; `pub fn reconcile_lockdown_on_start()` re-derives state from disk + detects orphans (enumerate `izba-sb-*` unprivileged, diff vs live); status surfaces `LockdownState`.

- [ ] Steps: grants computation + state transitions + orphan detection are host-testable with a fake elevation client (trait seam). Implement. Commit `feat(core): sandbox lock-down orchestration + startup reconcile`.

## Phase D — daemon + CLI

### Task 12: proto + daemon handlers

**Files:** Modify `crates/izba-proto` (or `daemon/proto.rs`), `daemon/server.rs`, `daemon/client.rs`

**Interfaces:**
- Produces: `DaemonRequest::{Lockdown{name}, Unlock{name}, WindowsCleanup}`; `DaemonReply::RequiresElevation{argv:Vec<String>}` (izbad cannot self-elevate → returns the helper argv for the CLI/app to run); bump `DAEMON_PROTO_VERSION`; `#[serde(default)]` preserved.

- [ ] Steps: proto serde round-trip tests; handler unit tests with a fake sandbox layer; version-bump self-heal test. Implement. Commit `feat(daemon): lock-down/unlock/cleanup RPCs (+proto bump)`.

### Task 13: CLI verbs + status

**Files:** Modify `crates/izba-cli`

**Interfaces:**
- Produces: `izba lockdown <name>` / `izba unlock <name>` / `izba windows-cleanup`; on `RequiresElevation` the CLI runs the elevated helper (UAC) then reports back; `izba status` shows the per-sandbox lock-down line.

- [ ] Steps: clap parse tests + a status-rendering test against `LockdownState::summary()`; the elevation call is the Task 9 client. Implement. Commit `feat(cli): lockdown/unlock/windows-cleanup + status`.

## Phase E — app, packaging, e2e

### Task 14: app surface + button

**Files:** Modify `app/src-tauri/src/*`, frontend, `FakeDaemon`

**Interfaces:** add `lockdown(name)`/`unlock(name)` to `DaemonApi` + `FakeDaemon`; a lock-down button with the UAC-shield affordance; status badge.

- [ ] Steps: backend `cargo test` + frontend vitest (feed lcov to Sonar per the SonarCloud-gate memory); run the **app gate** locally. Commit `feat(app): lock-down button + daemon surface`.

### Task 15: packaging — ship the helper

**Files:** Modify `.github/workflows/_artifacts.yml`, Inno/installer script, `hack/devbuild.sh` if needed

**Interfaces:** build `izba-jail-helper.exe` in the Windows artifact job; install it beside `izba.exe`; exe-relative discovery (no env vars).

- [ ] Steps: add the build+package step; verify the installer lays it down; commit `build(release): ship izba-jail-helper.exe`.

### Task 16: e2e windows-whp assertion

**Files:** Modify `.github/workflows/e2e.yml`, add `hack/spike`-derived assertion script

**Interfaces:** on the windows-whp leg: lockdown a real sandbox → boot the microVM as the account (WHP works) → a probe as the account is read-DENIED outside its grant and firewall-BLOCKED → unlock removes account+rule, no orphan.

- [ ] Steps: adapt the spike orchestrator into a CI assertion (elevated runner); wire into e2e; dispatch-run it. Commit `test(e2e): assert per-sandbox account read-deny + net-block on WHP`.

---

## Self-review

- **Spec coverage:** §3 spike → Tasks (evidence already committed) + Task 16; §5.1 components → Tasks 3-13; §5.2 lifecycle → Tasks 7,11; §5.3 ACL/IL → Tasks 5,11 (reuses PR #37 restore); §5.4 DPAPI cred → Tasks 8,11; §5.5 firewall → Tasks 6,7; §5.6 GC → Tasks 7,11,13; §6 daemon/status → Tasks 12,13; §7 packaging → Task 15; §8 testing → every task + Task 16. No gaps.
- **Placeholder scan:** FFI tasks specify exact Win32 calls + the runtime-skip test pattern; host-testable tasks carry concrete assertions. The one explicit fallback (Task 10 token+logon composition) is documented as a decision, not a TODO.
- **Type consistency:** `LockedInfo`/`LockdownState`/`firewall_sddl`/`account_name`/`provision_argv`/`spawn_confined_as`/`RequiresElevation` used consistently across tasks.

## Execution handoff

Subagent-driven: fresh subagent per task, two-stage review between tasks, gates green per commit.
