# Windows VMM jailer — Chromium-sandbox replication reference

> **Date:** 2026-06-16 · **Status:** design reference, ready for an implementation
> plan. Scope: the **Windows** half of security findings **F-06** (VMM + file
> server run unjailed as the full host user) and **F-07** (file server
> unconfined) from [`findings-2026-06-15.md`](findings-2026-06-15.md). The
> **Linux** half (cloud-hypervisor seccomp/Landlock, virtiofsd
> `--sandbox namespace`, an unprivileged user-namespace jailer) is a sibling
> design tracked separately.

## Why this document exists

izba's Windows driver spawns a usermode VMM (Microsoft **OpenVMM** on the
Windows Hypervisor Platform / WHP) with **no host-side confinement**: no token
restriction, no integrity drop, no job, no process mitigations
(`procmgr/windows.rs` does only `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`).
A VM-escape or a bug in OpenVMM's **in-process** virtio-fs/9p server (it ships
its own — there is no separate, separately-jailable `virtiofsd` on Windows, and
no `--sandbox` knob) therefore runs with the **full invoking-user** privileges
against the user's real project directory. For a sandboxing product this is the
last line of defense, and it is absent.

Rather than invent a confinement scheme, we replicate the **Chromium Windows
sandbox** — the most battle-tested usermode process sandbox on the platform —
adapted to two hard constraints we established empirically (below). This doc is
the self-contained engineering reference: the Chromium mechanism in full, the
crate survey, and the concrete izba adaptation with its required divergences.

---

## 1. Two empirical findings that constrain the whole design

Probed on a real Win11 24H2 host (build 26100, non-admin user) on 2026-06-16. A
tiny native probe called `WHvCreatePartition` (the call that opens
`\Device\VidExo`, the WHP kernel device) under different tokens:

| Token shape | `WHvCreatePartition` |
| --- | --- |
| Unconfined (control) | `S_OK` |
| **AppContainer / lowbox, zero capabilities** | **`0x80070005` ACCESS_DENIED** |
| Restricted token (`DISABLE_MAX_PRIVILEGE`), Medium IL | `S_OK` |
| Low integrity | `S_OK` |
| **Restricted token + Low integrity** | `S_OK` |

**Finding A — AppContainer is out.** A lowbox token's only "allow" identity is
its package SID (+ granted capabilities). `\Device\VidExo`'s security descriptor
does not list any package SID, so the device open is denied. Granting it would
mean rewriting the device object's SD — an admin, persistent, fragile operation
izba cannot perform per-launch. (This is exactly the privilege Hyper-V's `vmms`
broker has, via the special `NT VIRTUAL MACHINE\<GUID>` accounts, that a third
party does not.) So the `rappct`/AppContainer crate route and Chromium's LPAC
layer are unavailable to us.

**Finding B — the restricted-token path is strong and works.** A restricted
token with **all privileges deleted** *and* **Low integrity** still opens
`\Device\VidExo`. The denial in Finding A was specifically the *package SID*, not
integrity level and not privilege stripping. So the Chromium model **minus
AppContainer** — restricted token + low integrity + job + alternate desktop +
process mitigations + handle hygiene — is fully compatible with WHP.

**Predicted-but-not-tested constraint (same root cause as Finding A):**
`CreateRestrictedToken` **restricting SIDs** trigger a second access-check pass
against the device SD (§4.2). Adding a SID `\Device\VidExo` does not grant — e.g.
the Null SID `S-1-0-0` used by Chromium's tightest `USER_LOCKDOWN` level, or a
*unique per-sandbox* SID — will deny the device open just as the package SID did.
**Validate the chosen token level against a live `WHvCreatePartition` before
committing** (§7).

---

## 2. Crate survey verdict — build it, don't buy it

There is **no maintained, production-quality Rust crate** that delivers
Chromium-style restricted-token + integrity + job + mitigation confinement on
Windows. Survey (2026-06-16):

| Crate | Status | Verdict |
| --- | --- | --- |
| **gaol** (Servo) | v0.2.1, last published 2019; no `windows.rs` backend ever written | Unusable on Windows |
| **birdcage** (Phylum) | Linux+macOS only; **GPL-3.0** | Wrong platform + copyleft |
| **extrasafe** | Linux-only (seccomp/Landlock) | N/A |
| **nanosandbox** | v0.1.0, 31 downloads, toy | Not production |
| **rappct** | Maintained, MIT, but **AppContainer/LPAC-focused** | Wrong mechanism (Finding A rules out AppContainer) |
| **win32job** | v2.0.3, maintained, MIT/Apache | **Use for the job-object slice** (memory/affinity/priority/kill-on-close; raw `SetInformationJobObject` still needed for CPU-rate, active-process limit, UI restrictions) |
| **windows** (windows-rs) | Microsoft-maintained, MIT/Apache | **The foundation** — exposes every primitive as raw FFI; we write the orchestration |

The de-facto industry pattern is hand-rolled orchestration over `windows-rs`.
The closest precedent is **OpenAI Codex's `windows-sandbox-rs`** (crate
`codex-windows-sandbox`) — it confines *third-party target processes it does not
control*, exactly our situation. We examined its source (2026-06-16) to decide
reuse; **verdict: crib structure, do not depend.** Reasons:

- **Not a consumable crate.** Version `0.0.0`, not on crates.io, `edition 2024`,
  depends on five internal `codex-*` crates (`codex-protocol`, `codex-utils-*`,
  `codex-otel`); ~35 files / several thousand LOC (ConPTY, elevated/UAC, WFP,
  DPAPI, audit). Apache-2.0, so vendoring is *legal* but means surgery.
- **Run-to-completion API.** `run_windows_sandbox_capture(...) -> CaptureResult`
  owns, `WaitForSingleObject`-waits, and reaps the child. izba needs detached /
  long-lived (§6.2). No detach path.
- **Uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`** (child dies with launcher) —
  exactly the daemonless-survival violation §6.2 forbids.
- **Never sets an integrity level**; its model is write-restricted token +
  synthetic restricting SIDs + **mandatory on-disk deny-read ACLs** + **WFP
  network lockdown** — none of which we want, and the hardcoded token flags
  (`WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE | LUA_TOKEN`) + an unrelated
  restricting SID are a real risk to `\Device\VidExo` access.
- **Confirms our §6.1 call:** codex independently uses `DISABLE_MAX_PRIVILEGE`
  + a single-token launch for an uncontrolled target, and no AppContainer.

Borrow verbatim (Apache-2.0 attribution) only the Win32 plumbing in
`token.rs` / `process.rs` / `proc_thread_attr.rs`; invert the lifecycle
(`bin/command_runner/win.rs`, `stdio_bridge.rs`). Our confiner is ~200–400 LOC.

**Decision:** depend on `windows` (feature gates `Win32_Security`,
`Win32_Security_Authorization`, `Win32_Security_Isolation`,
`Win32_System_Threading`, `Win32_System_JobObjects`,
`Win32_System_StationsAndDesktops`) and optionally `win32job`. Note izba already
uses `windows-sys` in `procmgr/windows.rs`; adding `windows` (the higher-level
sibling) is justified by the SID/handle/`Result` ergonomics this much
orchestration needs. Write the token/IL/mitigation/`ProcThreadAttribute`
orchestration ourselves.

---

## 3. Chromium architecture — broker vs. target

The minimal Chromium configuration is two processes: a privileged **broker** and
the **target** (sandboxed) process; the sandbox is a library linked into both.
The broker must outlive its targets.

- **Broker** authors policy, spawns targets, and hosts the IPC/interception
  service that performs policy-allowed operations on behalf of a target. The
  OS cannot grant a process *more* than it started with, and a maximally
  restricted token cannot complete process bootstrap — so the broker constructs
  the restrictions and applies them to a child.
- **Target** calls `TargetServices::Init()` very early in `main()`, then
  `LowerToken()` once setup is done, voluntarily dropping the last privileges.

Critical caveat Chromium states explicitly: **the IPC/interception path is for
compatibility, not security** ("the interception + IPC mechanism does not provide
security"). The threat model assumes the target is already running malicious code
a few calls into `main()`. Everything below is built on that assumption.

> **izba mapping:** **izbad is the broker.** It already holds no authoritative
> state, adopts sandboxes from disk at startup, and is the natural long-lived
> privileged-setup point. The target is **OpenVMM, a third-party binary** — see
> the load-bearing divergence in §6.

---

## 4. The token — the core mechanism

### 4.1 `CreateRestrictedToken`

```c
BOOL CreateRestrictedToken(
  HANDLE  ExistingTokenHandle,
  DWORD   Flags,                 // DISABLE_MAX_PRIVILEGE | SANDBOX_INERT | LUA_TOKEN | WRITE_RESTRICTED
  DWORD   DisableSidCount,  PSID_AND_ATTRIBUTES  SidsToDisable,   // deny-only SIDs
  DWORD   DeletePrivilegeCount, PLUID_AND_ATTRIBUTES PrivilegesToDelete,
  DWORD   RestrictedSidCount, PSID_AND_ATTRIBUTES  SidsToRestrict,  // restricting SIDs
  PHANDLE NewTokenHandle);
```

Three independent restrictions:
- **Deny-only SIDs** (`SidsToDisable`): the SID can match a `Deny` ACE but never
  an `Allow` ACE. Subtractive only.
- **Privilege deletion** (`PrivilegesToDelete`, or `DISABLE_MAX_PRIVILEGE` =
  delete all except `SeChangeNotifyPrivilege`).
- **Restricting SIDs** (`SidsToRestrict`): always enabled for access checks; see
  the dual-check below.

`Flags`: `DISABLE_MAX_PRIVILEGE 0x1`, `SANDBOX_INERT 0x2` (skip AppLocker/SRP),
`LUA_TOKEN 0x4`, `WRITE_RESTRICTED 0x8` (restricting SIDs apply to **write**
access only — reads use the normal SID list).

### 4.2 The dual access-check (the load-bearing mechanic)

> The system performs **two** access checks: one using the token's enabled SIDs,
> one using the restricting SIDs. **Access is granted only if both allow it.**

Effective grant = (normal token SIDs) ∩ (restricting SIDs) against the object
DACL. This is *why* a restricting SID the object's SD doesn't list denies access
— and precisely why the Null SID (`USER_LOCKDOWN`), a package SID (AppContainer),
or a unique per-sandbox SID would all break `\Device\VidExo` (Finding A / the
predicted constraint in §1).

### 4.3 Chromium's `TokenLevel` ladder (`sandbox/win/src/security_level.h`)

```
enum TokenLevel { USER_LOCKDOWN=0, USER_LIMITED, USER_INTERACTIVE,
                  USER_RESTRICTED_NON_ADMIN, USER_RESTRICTED_SAME_ACCESS,
                  USER_UNPROTECTED, USER_LAST };
```

| TokenLevel | Restricting SIDs | Deny-only SIDs | Privileges |
| --- | --- | --- | --- |
| **USER_LOCKDOWN** | Null SID `S-1-0-0` | All | None |
| **USER_LIMITED** | Users, Everyone, RESTRICTED (+ logon-session SID) | all except {Users, Everyone, Interactive} | Traverse |
| **USER_INTERACTIVE** | Users, Everyone, RESTRICTED, Owner (+ current-user, logon-session) | all except {Users, Everyone, Interactive, Local, Authenticated-Users, User} | Traverse |
| **USER_RESTRICTED_NON_ADMIN** | Users, Everyone, Interactive, Local, Authenticated-Users, User, RESTRICTED (+ current-user, logon-session) | all except those | Traverse |
| **USER_RESTRICTED_SAME_ACCESS** | All | None | All |
| **USER_UNPROTECTED** | None | None | All |

(Levels map to `RestrictedToken` builder calls in `restricted_token_utils.cc`:
`BuildDenyOnlySids()` → `SidsToDisable`, `BuildRestrictedSids()` →
`SidsToRestrict`, `DISABLE_MAX_PRIVILEGE` when delete-all is set.)

### 4.4 The two-token model + `LowerToken()`

The OS loader touches too many resources for a fully locked-down token to
bootstrap. Chromium builds **two** tokens via `SetTokenLevel(initial, lockdown)`:
the **lockdown** token is the process *primary* token; the **initial** (looser)
token is set as an *impersonation* token on the **main thread only**. Early init
runs under the initial token, then the target calls `LowerToken()` to drop the
impersonation, leaving only the lockdown token. Irreversible. Other threads never
see the initial token.

**Handle-hygiene rule (verbatim):** "Make sure any sensitive OS handles obtained
with the initial token are closed before calling `LowerToken()`. Any leaked
handle can be abused by malware to escape the sandbox." Handles are **not**
re-access-checked after the drop — a handle opened under the looser token keeps
working, but nothing new can be opened.

> **izba consequence (critical):** the two-token + `LowerToken()` trick requires
> the *target* to call `LowerToken()` — i.e. Chromium controls the target's
> source. **We do not control OpenVMM.** See §6.

---

## 5. The other layers (all AppContainer-independent — all survive Finding A)

**Integrity level (§ MAC).** `SetTokenInformation(token, TokenIntegrityLevel,
&TOKEN_MANDATORY_LABEL{ Label.Sid = <IL SID> })`. SIDs: Untrusted `S-1-16-0`,
Low `S-1-16-4096`, Medium-low `S-1-16-6144`, Medium `S-1-16-8192`. Default object
rule is **no-write-up**; with `MITIGATION_HARDEN_TOKEN_IL_POLICY` also no
open-up of this process's token. Chromium applies a **delayed** IL: create at a
usable IL, lower to the lockdown IL on the suspended process just before
`ResumeThread`. (For izba: **Low**, not Untrusted — Finding B validated Low opens
VidExo; Untrusted is untested and likely too tight.)

**Job object.** `SetInformationJobObject` with:
- `JOBOBJECT_BASIC_UI_RESTRICTIONS.UIRestrictionsClass`: `JOB_OBJECT_UILIMIT_HANDLES`
  (no cross-process USER handles), `_READCLIPBOARD`, `_WRITECLIPBOARD`,
  `_SYSTEMPARAMETERS`, `_DISPLAYSETTINGS`, `_GLOBALATOMS`, `_DESKTOP`,
  `_EXITWINDOWS`.
- `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.BasicLimitInformation.LimitFlags`:
  `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (`ActiveProcessLimit = 1` → no children),
  `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, **and in Chromium**
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. No `*_BREAKAWAY_OK`. Plus memory/CPU caps
  via `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`.
  > **izba divergence:** see §6 — we must NOT use `KILL_ON_JOB_CLOSE`.

**Alternate desktop / window station** *(optional, low priority for izba — see
§6.2.2).* `CreateDesktop` (+ optionally `CreateWindowStation`), named in
`STARTUPINFO.lpDesktop`, restrictive SD. Closes the "shatter" vector (same-desktop
`SendMessage`/`PostMessage` to a higher-priv window). This is **load-bearing for
Chromium** (its renderer lives on the *interactive* desktop next to GUI), but for
izba's **headless, Low-IL** VMM the cross-privilege shatter is already blocked by
UIPI (integrity level), so the alternate desktop is belt-and-suspenders, not a
co-equal boundary — see §6.2.2.

**Process mitigation policies.** Two delivery paths, both used: at creation via
`UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &DWORD64[])`,
and post-launch via `SetProcessMitigationPolicy`. Relevant flags and their
**compatibility hazards** (the hazards decide which we can enable on OpenVMM):

| Mitigation | OS policy | Hazard for a VMM |
| --- | --- | --- |
| DEP, SEHOP, bottom-up + high-entropy ASLR, force-relocate | `…_DEP_ENABLE`, `…_BOTTOM_UP_ASLR`, `…_HIGH_ENTROPY_ASLR`, `…_FORCE_RELOCATE_IMAGES` | Safe; enable. |
| Strict handle checks | `PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY` (**post-start only**) | Safe; enable. |
| DLL search order | `SetDefaultDllDirectories` (**post-start only**) | May break implicit app-dir DLLs — test. |
| Harden token IL | token mandatory-policy edit | Safe; enable. |
| Extension-point disable | `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY` | Blocks AppInit DLLs / global hooks / LSPs — safe for a VMM; enable. |
| Image-load: no-remote, no-low-label, prefer-sys32 | `PROCESS_MITIGATION_IMAGE_LOAD_POLICY` | Safe; enable. |
| Child-process restriction | `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` | **OpenVMM spawns a worker child** (`openvmm vm`) — see §6; likely must be **OFF** or applied to the worker, not the parent. |
| win32k lockdown | `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY` (`DisallowWin32kSystemCalls`) | Biggest kernel-surface cut, **but breaks GDI/USER**. Test whether OpenVMM/WHP need win32k; if headless, attempt it. |
| ACG (dynamic-code) | `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` | **Breaks JIT/runtime codegen** — a VMM/emulator may JIT. Likely **OFF**; test. |
| CIG (MS-signed only) | `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` (`MicrosoftSignedOnly`) | **Breaks loading non-MS-signed DLLs** — OpenVMM is not MS-signed in our bundle → **OFF** unless we sign. |

**Handle hygiene.** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` passes the *exact*
inheritable-handle set; with it present, `bInheritHandles = TRUE` inherits *only*
those. Keep all other handles non-inheritable
(`SetHandleInformation … HANDLE_FLAG_INHERIT = 0`). (Chromium's target-side
`handle_closer` that sweeps stray handles at `LowerToken()` is unavailable to us
— third-party target — so the inherit-list discipline is our only anti-leak
control; make it tight.)

### 5.1 Chromium's exact spawn ordering (`broker_services.cc`)

1. Build both tokens (`CreateRestrictedToken` ×2; lockdown = primary, initial =
   impersonation).
2. Resolve/create the alternate desktop; put its name in `STARTUPINFO.lpDesktop`.
3. Create the job (`CreateJobObject` + `SetInformationJobObject`).
4. Build the attribute list: `InitializeProcThreadAttributeList` →
   `UpdateProcThreadAttribute` for mitigations, child-process policy, handle
   list (and, only for AppContainer, security-capabilities — **omitted for us**).
5. `CreateProcessAsUserW(lockdown_token, …, CREATE_SUSPENDED |
   EXTENDED_STARTUPINFO_PRESENT, …, &startup_info_ex, &pi)` with
   `bInheritHandles = TRUE` (constrained by the handle list).
6. `SetThreadToken(&pi.hThread, initial_token)` (looser token on main thread for
   bootstrap).
7. `AssignProcessToJobObject(job, pi.hProcess)`.
8. Lower the integrity level on the suspended process to the lockdown IL.
9. `ResumeThread`.
10. In the target: `TargetServices::Init()` → … → `LowerToken()`.

---

## 6. The izba adaptation — required divergences from Chromium

Two facts about izba force concrete departures. Get these right or the design is
wrong.

### 6.1 We do not control the target → single-token launch, no `LowerToken()`

OpenVMM is a third-party binary; we cannot make it call `TargetServices::Init()`
/ `LowerToken()`. The two-token + impersonation + drop model (§4.4) is therefore
**unavailable**. We launch with a **single token** that is the process's primary
identity for its whole life — so that one token must permit OpenVMM's full
bootstrap **and** the `\Device\VidExo` open (there is no later looser phase, and
no later tighter phase).

Consequences:
- **Token level:** not `USER_LOCKDOWN` (Null restricting SID → denies VidExo).
  The strongest level that still opens VidExo is **`USER_LIMITED`**, falling back
  to **`USER_RESTRICTED_NON_ADMIN`** if `USER_LIMITED`'s restricting set is too
  tight for the device SD or for OpenVMM init. Pick the most restrictive of the
  two that passes the live `WHvCreatePartition` probe (§7). Pair with
  **`DISABLE_MAX_PRIVILEGE`** (Finding B: all privileges droppable) + **Low
  integrity**.
- **No unique per-sandbox restricting SID** (would break VidExo). Therefore
  **per-VM *mutual* isolation** (VM-A's process cannot read VM-B's files) is
  **not achievable** for same-user WHP processes without per-VM service accounts
  (admin-provisioned, Hyper-V's `vmms` model) — documented residual, not in
  scope. What F-06 *does* buy on Windows is **host↔VMM** deprivilege: the VMM
  cannot write-up to the user's Medium-IL files outside its share, cannot gain
  privilege, and is resource-bounded. (Child-process creation is **not** blocked
  — see §6.3: OpenVMM forks a worker and the Windows child-block primitive is
  all-or-nothing, so it is not applied; children merely inherit the deprivileged
  token + Low IL.)
- This matches the Codex precedent exactly (it also confines uncooperative target
  binaries with a single restricted token + job, no `LowerToken`).
- **Optional future hardening:** a tiny izba-authored **launcher shim** (which we
  *do* control) could be the target of the restricted-token launch, open any
  handles needing a looser token, then re-launch OpenVMM with the tightest token
  — recovering part of the two-token benefit. Deferred; the single-token path is
  the baseline.

### 6.2 The daemonless-survival contract → no `KILL_ON_JOB_CLOSE`, security is create-time

A load-bearing izba contract: *"killing/upgrading izbad never harms sandboxes."*
Chromium's `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (the broker holds the job handle;
last-handle-close terminates every member) would kill every VMM the instant the
broker (izbad) exits **or is intentionally upgraded** — a direct violation. There
is no clean Windows primitive to hand a job handle across a daemon restart, so
this is fundamental, not a tuning issue. `procmgr/windows.rs` already documents
avoiding job objects for exactly this reason.

**Does dropping `KILL_ON_JOB_CLOSE` cost security? No — it is a lifecycle/cleanup
control, not a containment boundary.** The reasoning:

- The boundary is the **token + integrity level + process mitigations**, which
  are **immutable properties set at process creation**. The process cannot undo
  them; nobody without privileges the process lacks can either. A VMM that
  lingers after izbad dies is therefore still Low-IL, restricted-token,
  cannot-write-up, cannot-escalate — an *unsupervised* process, not an
  *unconfined* one. `KILL_ON_JOB_CLOSE` terminating it would tidy up, not contain.
- After izbad death the VMM is in fact **more** isolated: its egress path
  (guest → vsock 1027 → izbad) is dead, so it cannot even reach the network
  broker.
- izba does not need the job for cleanup: orphan reclamation already comes from
  the disk-state invariant (pid + creation-time identity) and the
  `procmgr/windows.rs` tree-kill. Cleanup is izba's model, not the job's job.

**The design rule that makes this safe — put every security-relevant restriction
on an immutable create-time property; leave only resource governance on the job:**

| Restriction | Where to put it | Survives izbad death? |
| --- | --- | --- |
| Token (restricted SIDs, dropped privileges) | `CreateProcessAsUser` primary token | **Yes** (immutable) |
| Integrity level (Low) | token, set before resume | **Yes** (immutable) |
| Process mitigations (DEP/ASLR/CIG-off/win32k/extension-point…) | creation-time `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | **Yes** (immutable) |
| **Child-process blocking** *(considered, NOT applied — §6.3)* | would be creation-time `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`, but it is all-or-nothing and would block OpenVMM's own worker, so it is **off**; children inherit the restricted token + Low IL instead | n/a (not applied) |
| Shatter protection *(optional, §6.2.2)* | mostly **Low IL / UIPI**; optionally the alternate desktop (`STARTUPINFO.lpDesktop`, §5) — **not** the job's UI flags | **Yes** (immutable) |
| Memory / CPU caps | job object | No — lapses if the job dies (see below) |

So the only thing the job carries is **resource caps**, and those are *not* part
of the confidentiality/integrity boundary — see §6.2.1 for why they are a
low-value DoS backstop. The job is therefore **best-effort**: held by izbad
**without** `KILL_ON_JOB_CLOSE` (add `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` so an
adopted VMM is never tied to a launcher's handle), **named per sandbox** so izbad
can `OpenJobObject` it again on restart. (A job without `KILL_ON_JOB_CLOSE`
generally persists as long as it has live member processes even after its last
handle closes, so caps likely never actually lapse and izbad merely re-acquires
the management handle on adoption — **verify this kernel behavior at
implementation**; if a handle-less job *is* torn down, izbad re-creates and
re-assigns via a nested job on adoption. Either way only a DoS backstop is at
risk for the gap, never the boundary.)

- Post-start-only mitigations (`STRICT_HANDLE_CHECKS`, `DLL_SEARCH_ORDER`) cannot
  be applied to an uncooperative target after the fact — fold what we can into
  the **creation-time** `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` and accept that
  the strictly-post-start ones are unavailable without the launcher shim (§6.1).

#### 6.2.1 Are resource caps even worth it for izba?

Mostly a **DoS/availability backstop, not a boundary control** — deliberately
low priority:

- For a **well-behaved VMM** the caps are largely redundant: cloud-hypervisor /
  OpenVMM are launched with the guest's vCPU count and RAM size, and the
  hypervisor enforces those *on the guest*. The guest cannot use more than it was
  given, so the host-side VMM footprint is already ≈ (guest RAM + emulation
  overhead) + its vCPU threads.
- The caps matter only when the **VMM process itself is compromised** (a VM
  escape — the very threat F-06 exists for). An attacker with code execution in
  the host-side VMM is no longer the *guest*, so the hypervisor's guest limits no
  longer bind it: it can `malloc` arbitrarily and spin every core. A job
  memory/CPU cap is then a **host-DoS backstop**. (Secondary case: device-
  emulation amplification bugs where a hostile guest makes the VMM over-allocate
  host-side without a full escape.)
- Conclusion: resource caps are defense-in-depth against availability loss from
  an *already-escaped* VMM — strictly lower value than the token/IL/mitigation
  boundary. This is *why* the job can be best-effort and its lapse is acceptable:
  the only thing at risk during an izbad gap is a low-value DoS backstop, never
  containment.

#### 6.2.2 Is the alternate desktop needed for izba?

**No — it is optional, low-priority hardening, mostly subsumed by Low IL.** It is
load-bearing for *Chromium* and largely redundant for *izba* because the two
threat surfaces differ:

- **Shatter requires (a) a higher-priv victim *window* on the same desktop and
  (b) the ability to message it.** Chromium's renderer runs on the **interactive
  desktop** beside the browser UI and the user's GUI apps — both conditions hold,
  so the alternate desktop is a real escalation cut.
- For izba both conditions largely fail. **(a)** OpenVMM is spawned
  `CREATE_NO_WINDOW`, headless, with no message-pump windows — almost no shatter
  *surface* to be driven. **(b)** The cross-privilege direction is already blocked
  by **UIPI** (User Interface Privilege Isolation, Vista+): a **Low-IL** process
  cannot send window messages **up** to the Medium-IL user apps / izba GUI. The
  integrity level we already apply buys most of the desktop's benefit for free.
- Residual the desktop would still cover: same-IL → same-IL messaging (e.g. one
  Low-IL VMM to another), and UIPI bypasses. But with headless VMMs there is no
  victim window, so this is thin and exotic (it needs injected third-party
  windowing code, which CIG / extension-point mitigations already push against).

**Recommendation:** treat the alternate desktop as **cheap belt-and-suspenders,
not a required layer.** One shared non-interactive izba desktop with a restrictive
SD (set via `STARTUPINFO.lpDesktop`) is inexpensive and closes the UIPI-bypass
residual, so include it if convenient — but do **not** rank it with
token/IL/mitigations, and dropping it costs izba essentially nothing because Low
IL already does the work. (If kept, it survives izbad death the same way the job
does: the desktop persists while in-use processes run on it, and the restricted
token prevents the confined process from opening any other desktop.)

### 6.3 OpenVMM's worker child

OpenVMM runs the actual VM in an `openvmm vm` worker child (already known to
`procmgr/windows.rs`'s tree-kill). So:
- `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = RESTRICTED` and the job's
  `ActiveProcessLimit = 1` would **block the worker** — they must be **off**, or
  the confinement must target the worker. Preferred: launch the worker confined
  too (it inherits the parent's restricted token by default; verify the worker
  also opens VidExo under it), and size the job's `ActiveProcessLimit` to the real
  process count rather than 1.
- The file-server confinement rides on confining the worker (the in-process
  virtio-fs server lives wherever the device backend runs).

---

## 7. Validation plan (do this before/with implementation)

Extend the existing Windows validation harness (`hack/spike/validate-izba-windows.ps1`):

1. **Token-level probe** — for each candidate (`USER_LIMITED`,
   `USER_RESTRICTED_NON_ADMIN`) × Low IL, launch the §1-style probe and assert
   `WHvCreatePartition == S_OK`. Lock in the most restrictive that passes.
2. **OpenVMM boot under the token** — start a real sandbox with the confined
   launch; assert the guest boots (reuse the e2e boot check) and the worker child
   starts. Iterate the mitigation set until boot is green (expect CIG/ACG off).
3. **Negative containment test** — from inside the confined VMM process context,
   assert a **write to a Medium-IL host file** outside the share is **denied**
   (Low IL no-write-up), and the token query shows restricted + Low IL.
   (Child-process creation is **not** a tested gate — it is not blocked; see
   §6.3.)
4. **Daemonless-survival test** — kill izbad; assert the VMM keeps running and
   stays at its restricted token (security boundary intact), then on izbad
   restart the resource job is re-applied.

These mirror the existing KVM/WHP e2e gating and slot into `e2e.yml`.

---

## 8. Integration sketch (izba code)

- New module `crates/izba-core/src/procmgr/jail_windows.rs`: a
  `spawn_detached_confined(cmd: &CommandSpec, policy: &WindowsConfinement, log)`
  that mirrors `spawn_detached` but performs the §5.1 sequence (minus the
  two-token / `LowerToken` / kill-on-close per §6) via `windows`-crate FFI +
  `win32job`.
- Extend `CommandSpec` (today just `argv`) or add a parallel
  `ConfinementPolicy { token_level, integrity, mitigations, job_limits,
  acl_paths }` threaded from the VMM driver, so the cloud-hypervisor/Linux path
  ignores it and the OpenVMM/Windows path consumes it.
- **Capability detection + graceful degradation** (izba UX contract): probe once
  at startup whether the restricted-token launch can open WHP on this host
  (validated yes on 24H2); if a future host/policy blocks it, degrade to the next
  weaker tier and **surface an honest reason** in `izba status` health
  (e.g. `confinement: restricted+lowIL+job` vs `degraded: token-only (job
  unavailable)`), consistent with the "honest unhealthy reason" contract and the
  desktop app's existing health surface. Never require the user to configure
  anything; the installer enables the WHP feature once.

---

## 9. Source list

- Chromium sandbox design doc — <https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md>
- `sandbox/win/src/security_level.h` — <https://raw.githubusercontent.com/chromium/chromium/main/sandbox/win/src/security_level.h>
- `restricted_token_utils.cc` / `restricted_token.cc` / `process_mitigations.cc` / `broker_services.cc` (same tree)
- `CreateRestrictedToken` — <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken>
- Restricted Tokens — <https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens>
- Project Zero, "You Won't Believe what this One Line Change Did to the Chrome Sandbox" — <https://projectzero.google/2020/04/you-wont-believe-what-this-one-line.html>
- windows-rs docs — <https://microsoft.github.io/windows-docs-rs/>
- `win32job` — <https://crates.io/crates/win32job>
- OpenAI Codex Windows sandbox deep-dive — <https://codex.danielvaughan.com/2026/05/14/codex-cli-windows-sandbox-engineering-restricted-tokens-acls-elevated-architecture/>
- izba empirical WHP/AppContainer probe (2026-06-16) — recorded in agent memory `izba-windows-whp-appcontainer-probe`
