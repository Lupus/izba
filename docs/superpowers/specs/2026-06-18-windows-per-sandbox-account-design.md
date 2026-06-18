# Windows per-sandbox local account ("lock down") — design

**Status:** approved design (2026-06-18)
**Depends on:** the Windows VMM jailer (`feat/windows-vmm-jailer`, PR #37 —
restricted-token + Low-IL + job confinement). This work *layers on top of* that
confinement; it does not replace it.
**Security findings addressed:** F-06 (unjailed/under-confined VMM) read-confinement
residual; the host-side egress-bypass residual noted in the F-06 threat analysis.
**Roadmap:** the "per-VM service accounts" read-confinement path that
[the F-06 probe](../../security/findings-2026-06-15.md) and the
WHP/AppContainer probe deferred as "out of scope (admin)".

## 1. Summary

Add an opt-in, per-sandbox hardening for Windows: run a sandbox's VMM under a
**dedicated standard local account** (`izba-spk-<sandbox>`) that is ACL-scoped to
*only that sandbox's files* and made **network-dead** with a per-SID firewall
block. A "lock down" action (UAC-shielded button / CLI verb) provisions the
identity; teardown on `unlock` / `rm` removes it. izbad itself stays unprivileged;
the only elevated component is a tiny helper invoked at the provision/deprovision
moments.

This composes with PR #37's confinement: the VMM runs as the dedicated account
**and** under the restricted token + Low integrity + job. The result of a VM
escape into the host-side VMM process drops from "read everything the human user
can read" to "read/write only this one sandbox's data, with no privileges, no
other projects, no credentials, and no network".

## 2. Goals / non-goals

**Goals (both weighted equally):**

- **Read-confinement.** The VMM process cannot read the user's home, credentials,
  other projects, or other sandboxes — only the files explicitly granted to its
  sandbox. Closes the F-06 residual that PR #37 (same-user Low-IL) left open: a
  Low-IL process under the *same* user can still *read* all the user's files.
- **Distinct OS principal per sandbox.** A clean kill/cleanup boundary and no
  cross-sandbox interference; each sandbox is its own security principal (SID).

**Non-goals (this milestone):**

- Not a kernel boundary. A WHP/Hyper-V or win32k 0-day bypasses the account
  boundary; process mitigations (PR #37) shrink but do not eliminate this.
- Not default-on. Lock-down is strictly opt-in per sandbox.
- Does not close the izbad RPC channel (F-09 izbad peer-cred is the companion
  hardening, tracked separately). A compromised VMM can still speak to izbad.
- Linux parity (uid/gid/namespace jailer) is out of scope here — this is the
  Windows datapath only.
- AppContainer / read-restricting SIDs remain out (empirically break WHP / process
  init — see the WHP/AppContainer probe).

## 3. Empirical foundation (gating spike)

Before designing, a gating spike (`hack/spike/whp-local-account-spike.ps1`, run on
the real Win11 24H2 host, build 26100) answered the feasibility questions. It
reuses the jailer's `confine_probe` (WHvCreatePartition → OK/DENIED) plus throwaway
`confined-whp` and `net-connect` roles, runs them under a freshly-created throwaway
standard local account across a minimal-grant matrix, and tears the account down.

| Leg | Principal / condition | Result |
| --- | --- | --- |
| baseline | current user, direct | WHP **OK** |
| 1 | **bare standard local account** (member of `Users` only) | WHP **OK** |
| 3 | **local account + restricted-token + Low-IL** (full stack) | WHP **OK** |
| 2 | local account + `Hyper-V Administrators` | WHP **OK** (not required) |
| F0 | account outbound TCP connect, no firewall rule (control) | **ALLOWED** |
| F1 | account outbound TCP connect, per-SID `-LocalUser` block | **BLOCKED** (WSAEACCES) |

**Conclusions, all empirically confirmed on real hardware:**

1. WHvCreatePartition is **not** gated on `Hyper-V Administrators` or any privileged
   group — a least-privilege per-sandbox account can run the VMM (leg 1).
2. PR #37's restricted-token + Low-IL confinement **composes** with the separate
   account; no conflict (leg 3).
3. A single `New-NetFirewallRule -Direction Outbound -Action Block -Profile Any
   -LocalUser "D:(A;;CC;;;<SID>)"` makes the account **network-dead** (leg F1). The
   `-LocalUser` ALE user-id condition (`FWPM_CONDITION_ALE_USER_ID`) is the correct
   mechanism; a WFP block manifests as `connect()` → `WSAEACCES` (10013), distinct
   from refused/timeout, which is the signature the probe classifies.
4. `spawn_confined` uses a `CreateRestrictedToken`-derived token +
   `CreateProcessAsUserW`, so it needs **no** `SeAssignPrimaryTokenPrivilege` and
   works for any standard account (the baseline ran as the non-elevated user).

The spike script is retained as the design's evidence artifact and as the basis
for the e2e assertion.

## 4. Threat model delta

A hostile guest that escapes the VM into the **host-side VMM process** (running as
`izba-spk-<sandbox>` + restricted token + Low IL + job) can reach:

**Blast radius (what it CAN touch):**

- **This sandbox's own data** — the virtiofs workspace share (the user's project
  source) and this sandbox's named volumes. Irreducible: the VMM legitimately
  serves these.
- **World-readable system locations** (`C:\Windows`, `Program Files`). Low value.
- **The izbad RPC socket** (AF_UNIX vsock bridge). Until F-09 peer-cred lands, a
  compromised VMM can issue izbad RPCs as if trusted. Tracked separately.

**Newly blocked vs. PR #37 alone:**

- **Home, credentials, other projects, other sandboxes → ACCESS_DENIED** (the
  account SID is absent from those DACLs). This is the read-confinement win.
- **Host network egress → none** (per-SID firewall block). The host-side process
  can no longer exfiltrate the project source to the internet, bypassing the guest
  egress firewall. Legitimate egress is unaffected because it flows through **izbad
  as the user** (a different SID), not the VMM account.
- **Privilege escalation** — `DISABLE_MAX_PRIVILEGE` strips the token (no
  SeImpersonate "potato", no SeDebug, no driver load); no admin → no services /
  scheduled tasks / persistence.
- **Write-up** — Low IL blocks modifying Medium+ objects regardless of DACLs.

**Residuals (stated honestly, not oversold):**

- The current sandbox's project + volumes are exposed (it is the work data).
- The izbad RPC channel until F-09.
- Kernel attack surface — not a kernel boundary.

## 5. Architecture

### 5.1 Components

- **`izba-jail-helper.exe`** — the *only* elevated component. A small standalone
  Windows binary shipped beside `izba.exe`. Verbs (argv, structured JSON on
  stdin/stdout, exit-code outcome):
  - `provision --sandbox <name> --sid-out <file> --grant <path>…` — create the
    account, set a strong random password (returned to izbad over a one-shot
    secure channel, see §5.4), hide it via `UserList`, DACL-grant the listed
    paths, add the per-SID firewall block. Idempotent.
  - `deprovision --sandbox <name>` — remove firewall rule, unhide, delete account
    + profile. Idempotent (safe if already gone).
  - `gc --live <name>…` — sweep `izba-spk-*` accounts / `izba-deny-*` rules whose
    sandbox is not in the live set; deprovision each.
  It is invoked with elevation (`ShellExecute`/`runas` → UAC) exactly at the
  lock-down / unlock / cleanup moments. It does **not** stay resident.
- **izba-core (unprivileged, in izbad + CLI):**
  - `procmgr` Windows launch path extended to `CreateProcessWithLogonW` as the
    account when a sandbox is locked down (atop the existing confined-token path).
  - new `jail_account.rs` (Windows): the helper-invocation client, DPAPI cred
    seal/unseal, lock-down state types.
  - `sandbox.rs`: lock-down state on disk; provision/deprovision orchestration;
    status reporting.
- **izba-cli:** `izba lockdown <name>` / `izba unlock <name>` verbs and
  `izba windows-cleanup` (elevated GC). Lock-down state surfaced in `izba status`.
- **app (Tauri):** a "lock down" button with the UAC-shield affordance; status
  badge. (App is outside the workspace — its gate is run separately.)

### 5.2 Lock-down lifecycle (state machine)

Lock-down state is persisted in the sandbox dir (`lockdown.json`,
`#[serde(default)]` for forward-compat) and, like all izba state, is re-derived /
re-verified from disk on izbad startup — izbad holds no authoritative lock-down
state.

```
unlocked ──lockdown──▶ [UAC] helper provision ──▶ locked(account, sid, fw)
   ▲                                                   │
   │                                              VM launched as account
   │                                              (CreateProcessWithLogonW +
   │                                               restricted token + Low IL + job)
   └──unlock / rm──[UAC] helper deprovision ◀────────┘
```

Each transition is **one UAC prompt**. Provisioning is transactional: if any step
fails, the helper rolls back what it created and returns an error; izba fails the
lock-down **loudly** and leaves the sandbox unlocked (never silently runs a
"locked" sandbox unconfined). This follows the existing loud-on-security-degradation
rule.

Order within `provision` (all inside one elevation):
1. create account (Users only, strong random pw, `PasswordNeverExpires`)
2. `UserList=<acct>=0` (hide from sign-in screen / switcher)
3. DACL-grant the account `(RX)`/`(M)` on {workspace share, sandbox dir, this
   sandbox's named volumes}; rely on absence-from-DACL for deny-by-default elsewhere
4. add per-SID outbound + inbound firewall **block** (`-LocalUser` SDDL)
5. return the sealed credential + SID to izbad

`deprovision` reverses 4→1 and is idempotent.

### 5.3 ACL + integrity-label model

- **DACL grants** name only the three sandbox-scoped surfaces. Deny-by-default is
  structural: a fresh SID is not in the DACLs of the user's home / other projects /
  other sandboxes, so those are already `ACCESS_DENIED`. We do **not** add explicit
  DENY ACEs (belt-and-suspenders that can break legitimate traverse).
- **Traverse:** the default Everyone "bypass-traverse checking" privilege lets the
  account reach a granted leaf under the user's home without read on the
  intermediate dirs.
- **Integrity:** reuse PR #37 unchanged. The VMM runs Low-IL and PR #37 already
  Low-labels the workspace write surface on start and restores it on teardown
  (`ConfinementStatus::is_confined()` → `sandbox::restore_confined_workspace`). No
  new IL machinery — the per-account DACLs simply layer on top.

### 5.4 Credential handling

The account password is generated by the helper (strong random), never shown to
the user. It is needed by izbad for `CreateProcessWithLogonW` on each VM (re)launch
(e.g. `izba stop` then `izba start`). Decision: **persist it, DPAPI-sealed under the
current user** (`CryptProtectData`, `CRYPTPROTECT_LOCAL_MACHINE` *not* set — user
scope), stored as `lockdown.cred` in the sandbox dir. Rationale: the user is
already the trust root; a user-scoped DPAPI blob is readable only by that user, and
persisting it lets izbad relaunch the VM across izbad restarts without re-elevation.
The helper returns the freshly-generated password to izbad over a one-shot file the
helper ACLs to the user and izbad deletes after sealing.

### 5.5 Firewall

Per-SID outbound + inbound block rule named `izba-deny-<sandbox>` via
`New-NetFirewallRule … -LocalUser "D:(A;;CC;;;<SID>)" -Profile Any`. Added in
`provision`, removed in `deprovision`, swept by `gc`. Safe because the VMM needs
zero IP networking (guest egress is brokered by izbad over AF_UNIX vsock as the
user principal). Loopback is exempt by Windows default, which is acceptable (local
services have their own auth).

### 5.6 Orphan GC + cleanup

If izbad / the app dies with a locked-down sandbox live, the account + rule persist
(teardown needs admin). Reconciliation:

- **reconcile-on-next-elevation:** every `provision`/`deprovision` UAC also runs the
  `gc` sweep for the live set izbad passes, so orphans are cleared at the next
  elevated action.
- **explicit sweep:** `izba windows-cleanup` elevates and runs `gc` against the
  current live sandbox set; surfaced as a remediation hint in `izba status` when
  orphans are detected (izbad can *detect* `izba-spk-*` accounts unprivileged via
  enumeration, even though it cannot *remove* them).

No standing privileged GC service (keeps with the unprivileged-izbad ethos).

## 6. Daemon / proto / status

- New `DaemonRequest::Lockdown { name }` / `Unlock { name }` (and a
  `WindowsCleanup`) — these return a `RequiresElevation` result carrying the
  helper argv the CLI/app must run elevated, since izbad cannot self-elevate. The
  CLI/app performs the UAC launch, then reports the outcome back for izbad to
  persist state + (re)launch the VM.
- `DAEMON_PROTO_VERSION` bumped (wire-breaking new frames). Both `proto` and `build`
  remain `#[serde(default)]` so a stale daemon self-heals via one restart, per the
  existing compatibility contract.
- `izba status` / daemon status gains a per-sandbox `lockdown` field:
  `unlocked` | `locked(account=…, sid=…, net=blocked)` | `degraded(reason)`. The
  confinement summary already shows token/IL/job; lock-down extends it. Loud on any
  degradation.
- The app's `DaemonApi` + `FakeDaemon` seam gains the lock-down surface; the app
  gate is run locally + in App CI.

## 7. Build / packaging

- `izba-jail-helper` is a new binary target. Non-Windows builds compile a stub
  (`eprintln!("windows-only")`) so it stays in the cross-checked surface, mirroring
  `confine_probe`.
- The installer (`release.yml` / `_artifacts.yml`) ships `izba-jail-helper.exe`
  beside `izba.exe` (exe-relative discovery, no env vars — same pattern as CH /
  virtiofsd libexec discovery).
- The helper is invoked by absolute path resolved relative to `izba.exe`.

## 8. Testing strategy

- **Unit (host-testable, like `jail_windows.rs`):** SDDL construction for the
  firewall rule; argv building for the helper verbs; lock-down state
  serde/round-trip; DPAPI seal/unseal round-trip (Windows-gated); status rendering
  for each lock-down state; the GC live-set diff logic.
- **Helper FFI unit tests** (`#[cfg(windows)]`): account create/delete, UserList
  set/clear, firewall add/remove — each gated to skip when not elevated (CI runner
  is elevated; dev machines self-skip on access-denied), following the
  `confine_probe` runtime-skip discipline.
- **e2e (windows-whp, `e2e.yml`):** provision → launch a real microVM as the
  account → assert (a) the VM boots and WHP works, (b) a probe running as the
  account is read-denied on a host path outside the grant, (c) the account's
  outbound connect is firewall-BLOCKED, (d) deprovision removes account + rule;
  assert no orphan remains. The spike's matrix is the template.
- The six workspace gates + the two cross (windows-gnu) gates + App CI must stay
  green; SonarCloud gate (coverage + Security Rating A) and Greptile review must be
  satisfied.

## 9. Open questions / future

- F-09 izbad peer-cred — the companion hardening that closes the last channel a
  network-dead, read-confined VMM still has. Out of scope here; referenced.
- A future global "always lock down on Windows" policy (default-on) once the UX is
  proven; this milestone is opt-in only.
- Linux parity (dedicated uid/gid + namespaces) is the analogous F-06 fix on the
  other datapath; separate design.

## 10. Appendix — spike artifact

`hack/spike/whp-local-account-spike.ps1` (+ the `confined-whp` / `net-connect`
roles added to `crates/izba-core/examples/confine_probe.rs`) is the reproducible
evidence for §3. It is elevated, self-cleaning (random throwaway account + rule
removed in a `finally`), and prints the matrix above.
