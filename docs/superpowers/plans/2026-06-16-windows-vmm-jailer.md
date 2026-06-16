# Windows VMM Jailer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confine the OpenVMM process izba spawns on Windows with a restricted token + Low integrity + a best-effort resource job + creation-time process mitigations, and prove the protections in CI with a deterministic differential PoC.

**Architecture:** A cross-platform `ConfinementPolicy` describes the desired confinement; a Windows-only `jail_windows` module realises it via `CreateProcessAsUserW` (std `Command` cannot carry a custom token / `STARTUPINFOEX`). The VMM spawn path (izbad → `sandbox::start` → `OpenVmmDriver::launch` → `spawn_detached`) gains a confined sibling `spawn_confined`. Security lives in create-time-immutable token/IL/mitigations (survives izbad death); the job is best-effort resource governance with **no** `KILL_ON_JOB_CLOSE`. Capability is probed once; on hosts where confined-WHP fails the launch degrades gracefully and reports an honest reason in health.

**Tech Stack:** Rust, `windows-sys` 0.60 (extend feature gates), PowerShell (`validate-izba-windows.ps1`), GitHub Actions (`e2e.yml`, `windows-latest`). Design: [`specs/2026-06-16-windows-vmm-jailer-design.md`](../specs/2026-06-16-windows-vmm-jailer-design.md); deep reference: [`docs/security/windows-vmm-jailer-chromium-reference.md`](../../security/windows-vmm-jailer-chromium-reference.md).

---

## Verification protocol (applies to EVERY phase)

izba is security-critical and AI-authored, so each phase ends with a two-gate close, per [`docs/security/methodology.md`](../../security/methodology.md):

**Gate A — standard build/test (deterministic).** All six CLAUDE.md gates green:
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, the musl init build, and **both** windows-gnu gates
(`cargo check`/`cargo clippy --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`).
Windows-runtime behaviour is verified on the local Windows host via
`powershell.exe` interop (build native + run the probe) before it ever reaches CI.

**Gate B — adversarial verification (≥2 independent refute-framed reviewers + PoC).**
Dispatch **two** independent reviewer subagents that did NOT write the code, each
in a fresh context, prompted: *"Assume the guest is hostile and has compromised
the VMM process. Try to REFUTE the claim that this phase's confinement holds.
Find a bypass, a missing fail-closed path, a privilege the token still grants, a
handle that leaks, or a way the security property silently degrades to nothing.
Default to 'refuted' if you cannot positively confirm the protection."* A phase
passes only if **both** verifiers fail to refute AND a PoC exists for any
security claim the phase makes (a runnable test or a Windows-host transcript
showing the operation is denied under confinement and allowed without it).
Record both verdicts in the phase's commit message trailer. **No security change
is auto-merged** — the orchestrator signs off after reading both verdicts.

For phases with no security claim (e.g. pure type scaffolding), Gate B is a single
reviewer for correctness; note "no security surface" in the commit.

---

## File Structure

- **Create** `crates/izba-core/src/procmgr/confine.rs` — cross-platform policy
  types (`ConfinementPolicy`, `IntegrityLevel`, `TokenLevel`, `ConfinementStatus`,
  `ConfinementMode`). No OS imports → compiles on every target. One responsibility:
  *describe* desired confinement + report achieved confinement.
- **Create** `crates/izba-core/src/procmgr/jail_windows.rs` — `#[cfg(windows)]`
  realisation: `spawn_confined`, the restricted-token builder, the Low-IL setter,
  the job builder, the `STARTUPINFOEX` attribute list, `CreateProcessAsUserW`, and
  `probe_confinable()` capability detection. Cribs the Win32 plumbing structure
  from codex's `windows-sandbox-rs` (Apache-2.0 — attribution in the module doc),
  lifecycle inverted to spawn-detached.
- **Modify** `crates/izba-core/src/procmgr/mod.rs` — export `confine` types
  always; export `spawn_confined` + `probe_confinable` on Windows; provide a
  Unix fallback `spawn_confined` that ignores the policy and calls
  `spawn_detached` (so the call site is uniform and `cargo test` runs on Linux).
- **Modify** `crates/izba-core/src/vmm/openvmm.rs` — launch the VMM via
  `spawn_confined` with a policy; degrade per the capability probe; thread the
  achieved `ConfinementStatus` into the handle.
- **Modify** `crates/izba-core/src/vmm/mod.rs` — add `confinement()` to
  `VmHandle` so status reaches health.
- **Modify** `crates/izba-core/src/sandbox.rs` / health path — surface
  `ConfinementStatus` in `izba status`.
- **Create** `crates/izba-core/examples/confine_probe.rs` — the differential PoC
  (child + harness roles).
- **Modify** `crates/izba-core/Cargo.toml` — extend `windows-sys` features.
- **Modify** `hack/spike/validate-izba-windows.ps1` — add confinement assertions
  + run the probe harness.
- **Modify** `.github/workflows/e2e.yml` — build the probe example; ensure the
  validation step exercises it.

---

## Phase 1 — Confinement policy types (cross-platform)

### Task 1: Policy + status types

**Files:**
- Create: `crates/izba-core/src/procmgr/confine.rs`
- Modify: `crates/izba-core/src/procmgr/mod.rs`
- Test: inline `#[cfg(test)]` in `confine.rs`

- [ ] **Step 1: Write the failing test**

```rust
// in crates/izba-core/src/procmgr/confine.rs (bottom)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmm_default_policy_is_restricted_low_il() {
        let p = ConfinementPolicy::vmm_default();
        assert_eq!(p.token, TokenLevel::Limited);
        assert_eq!(p.integrity, IntegrityLevel::Low);
        assert!(p.drop_all_privileges);
        assert!(!p.kill_on_close, "izba contract: VMM must outlive the broker");
        assert!(p.allow_worker_child, "OpenVMM spawns an `openvmm vm` worker");
    }

    #[test]
    fn status_renders_human_reason() {
        let ok = ConfinementStatus::applied(&ConfinementPolicy::vmm_default());
        assert!(ok.summary().contains("restricted"));
        assert!(ok.summary().contains("low-il"));
        let none = ConfinementStatus::degraded("WHP unavailable under restricted token");
        assert_eq!(none.mode, ConfinementMode::None);
        assert!(none.summary().contains("WHP unavailable"));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p izba-core confine:: -- --nocapture`
Expected: FAIL — `ConfinementPolicy` etc. undefined.

- [ ] **Step 3: Write the minimal implementation**

```rust
//! Cross-platform description of host-side process confinement and the
//! confinement actually achieved at spawn (surfaced in health). The Windows
//! realisation lives in `jail_windows.rs`; on other platforms the policy is
//! inert (the VMM already runs as the invoking user and the Linux jailer is a
//! separate work item).
use serde::{Deserialize, Serialize};

/// Restricted-token shape. Names mirror Chromium `TokenLevel` (see the design
/// reference) but only the two WHP-compatible levels are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenLevel {
    /// Restricting SIDs = {Users, Everyone, RESTRICTED, logon}; everything else
    /// deny-only. The default — tight but still opens `\Device\VidExo`.
    Limited,
    /// Adds Interactive/Local/Authenticated-Users/User to the restricting set —
    /// the fallback if a host's WHP device SD is stricter than `Limited` allows.
    RestrictedNonAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Low,
    Medium,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementPolicy {
    pub token: TokenLevel,
    pub integrity: IntegrityLevel,
    pub drop_all_privileges: bool,
    /// Best-effort resource job. NEVER kill-on-close (izba daemonless contract).
    pub job_memory_max_mb: Option<u64>,
    pub kill_on_close: bool,
    /// OpenVMM forks an `openvmm vm` worker; the child-process block must permit
    /// it, so we never set ActiveProcessLimit=1 / CHILD_PROCESS_RESTRICTED hard.
    pub allow_worker_child: bool,
}

impl ConfinementPolicy {
    /// The policy applied to the OpenVMM process. See the design spec §Decisions.
    pub fn vmm_default() -> Self {
        Self {
            token: TokenLevel::Limited,
            integrity: IntegrityLevel::Low,
            drop_all_privileges: true,
            job_memory_max_mb: None, // sized by the VMM driver from guest mem
            kill_on_close: false,
            allow_worker_child: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfinementMode {
    /// Full policy applied (restricted token + IL + job + mitigations).
    Restricted,
    /// Token/IL applied but the resource job could not be created.
    TokenOnly,
    /// No confinement — the host could not run WHP under a restricted token, or
    /// the platform has no jailer. The VMM ran as the invoking user.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementStatus {
    pub mode: ConfinementMode,
    pub reason: String,
}

impl ConfinementStatus {
    pub fn applied(p: &ConfinementPolicy) -> Self {
        let token = match p.token {
            TokenLevel::Limited => "restricted(limited)",
            TokenLevel::RestrictedNonAdmin => "restricted(non-admin)",
        };
        let il = match p.integrity {
            IntegrityLevel::Low => "low-il",
            IntegrityLevel::Medium => "medium-il",
        };
        Self { mode: ConfinementMode::Restricted, reason: format!("{token}+{il}+job") }
    }
    pub fn degraded(reason: &str) -> Self {
        Self { mode: ConfinementMode::None, reason: reason.to_string() }
    }
    pub fn summary(&self) -> String {
        match self.mode {
            ConfinementMode::Restricted => format!("confined: {}", self.reason),
            ConfinementMode::TokenOnly => format!("confined (token only): {}", self.reason),
            ConfinementMode::None => format!("UNCONFINED — {}", self.reason),
        }
    }
}
```

Then in `crates/izba-core/src/procmgr/mod.rs` add near the top: `pub mod confine;`
and `pub use confine::{ConfinementMode, ConfinementPolicy, ConfinementStatus, IntegrityLevel, TokenLevel};`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core confine::`
Expected: PASS (2 tests).

- [ ] **Step 5: Cross-gate + commit**

```bash
cargo fmt
cargo clippy -p izba-core --all-targets -- -D warnings
cargo check --target x86_64-pc-windows-gnu -p izba-core
git add crates/izba-core/src/procmgr/confine.rs crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(procmgr): confinement policy + status types (F-06 windows)

Gate B: no security surface (pure types); single correctness review."
```

### Task 2: Phase-1 verification gate

- [ ] **Gate A** — run all six CLAUDE.md gates; paste output.
- [ ] **Gate B** — one correctness reviewer (no security surface yet): confirm the
  default policy encodes the locked decisions (no kill-on-close; Low IL; worker
  child allowed). Record verdict.

---

## Phase 2 — Windows token builder + capability probe

> Grounded in the working probes recorded in memory `izba-windows-whp-appcontainer-probe` (the `RunWithToken` path: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + `SetTokenInformation(TokenIntegrityLevel, Low)` → `CreateProcessAsUser` opened `\Device\VidExo` with `S_OK`).

### Task 3: `windows-sys` feature gates

**Files:** Modify `crates/izba-core/Cargo.toml`

- [ ] **Step 1: Extend the windows-sys features**

In `[target.'cfg(windows)'.dependencies] windows-sys = { ... features = [...] }` add:

```toml
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_JobObjects",
    "Win32_System_Memory",
    "Win32_Storage_FileSystem",
```

- [ ] **Step 2: Verify it resolves**

Run: `cargo check --target x86_64-pc-windows-gnu -p izba-core`
Expected: PASS (no new code yet; features just compile).

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/Cargo.toml
git commit -m "build(izba-core): windows-sys features for token/job/ACL jailer"
```

### Task 4: Restricted + Low-IL token builder

**Files:**
- Create: `crates/izba-core/src/procmgr/jail_windows.rs`
- Modify: `crates/izba-core/src/procmgr/mod.rs` (add `#[cfg(windows)] mod jail_windows;`)
- Test: a Windows-host integration check (see Step 4) — unit FFI tests need a real token, so they run on the Windows host, not in `cargo test` on Linux.

- [ ] **Step 1: Implement `build_confined_token`**

Module doc must include: `//! Win32 plumbing structure adapted from OpenAI codex `windows-sandbox-rs` (Apache-2.0); lifecycle inverted to detached spawn.` Then:

```rust
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, SetTokenInformation, TokenIntegrityLevel,
    DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_MANDATORY_LABEL,
    SE_GROUP_INTEGRITY, TOKEN_ALL_ACCESS,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use crate::procmgr::confine::{ConfinementPolicy, IntegrityLevel};

/// Builds the single primary token the VMM runs under: privileges dropped,
/// integrity lowered. (Restricting/deny-only SID shaping per `policy.token` is
/// added here too — start with DISABLE_MAX_PRIVILEGE which the probe proved
/// keeps WHP; layer restricting SIDs in a follow-up once the live-WHP probe
/// confirms each addition still opens \Device\VidExo.)
unsafe fn build_confined_token(policy: &ConfinementPolicy) -> anyhow::Result<HANDLE> {
    let mut base: HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut base) == 0 {
        anyhow::bail!("OpenProcessToken: {}", std::io::Error::last_os_error());
    }
    let flags = if policy.drop_all_privileges { DISABLE_MAX_PRIVILEGE } else { 0 };
    let mut tok: HANDLE = std::ptr::null_mut();
    let ok = CreateRestrictedToken(base, flags, 0, std::ptr::null_mut(), 0,
        std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut tok);
    CloseHandle(base);
    if ok == 0 {
        anyhow::bail!("CreateRestrictedToken: {}", std::io::Error::last_os_error());
    }
    if let Err(e) = set_integrity(tok, policy.integrity) {
        CloseHandle(tok);
        return Err(e);
    }
    Ok(tok)
}

unsafe fn set_integrity(tok: HANDLE, il: IntegrityLevel) -> anyhow::Result<()> {
    let sid_str: Vec<u16> = match il {
        IntegrityLevel::Low => "S-1-16-4096\0".encode_utf16().collect(),
        IntegrityLevel::Medium => "S-1-16-8192\0".encode_utf16().collect(),
    };
    let mut sid = std::ptr::null_mut();
    if ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) == 0 {
        anyhow::bail!("ConvertStringSidToSidW: {}", std::io::Error::last_os_error());
    }
    let mut label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: SE_GROUP_INTEGRITY as u32 },
    };
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32;
    let r = SetTokenInformation(tok, TokenIntegrityLevel,
        &mut label as *mut _ as *mut _, size);
    if r == 0 {
        anyhow::bail!("SetTokenInformation(IL): {}", std::io::Error::last_os_error());
    }
    Ok(())
}
```

- [ ] **Step 2: Build via cross-gate**

Run: `cargo check --target x86_64-pc-windows-gnu -p izba-core`
Expected: PASS. Fix any windows-sys symbol-path mismatches (the exact module
paths for `DISABLE_MAX_PRIVILEGE`, `TOKEN_MANDATORY_LABEL`, `SE_GROUP_INTEGRITY`
may differ by feature; resolve against `windows-sys` 0.60 docs until it compiles).

- [ ] **Step 3: Clippy clean**

Run: `cargo clippy --target x86_64-pc-windows-gnu -p izba-core --all-targets -- -D warnings`

- [ ] **Step 4: Windows-host smoke (PoC for the token)**

On the Windows host (via `powershell.exe` interop), build native and run a tiny
harness that calls `build_confined_token` and queries it back with
`GetTokenInformation(TokenIntegrityLevel)` + `GetTokenInformation(TokenIsRestricted)`;
assert IL==Low and restricted==true. (This is folded into the `confine_probe`
example in Phase 4; for now a manual transcript suffices.) Record the transcript.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/procmgr/jail_windows.rs crates/izba-core/src/procmgr/mod.rs
git commit -m "feat(jail): restricted + low-IL token builder (windows)"
```

### Task 5: `probe_confinable()` capability detection

**Files:** Modify `crates/izba-core/src/procmgr/jail_windows.rs`

- [ ] **Step 1: Implement the probe**

```rust
/// One-shot host capability probe: can a process launched under the VMM
/// confinement policy still create a WHP partition? Caches nothing here; the
/// caller memoises. Strategy: spawn the `confine_probe` helper (Phase 4) in
/// `--attempt whp` mode under the policy and check its exit code. Returns false
/// (degrade) on any failure so the launch path can fall back + report honestly.
pub fn probe_confinable(policy: &ConfinementPolicy, probe_exe: &std::path::Path) -> bool {
    // Implemented after Phase 4 lands `confine_probe whp`; until then return
    // true on a host where build_confined_token succeeds (token-build is the
    // necessary precondition). Full WHP round-trip wired in Task 12.
    // SAFETY: FFI; token closed on both paths.
    unsafe {
        match build_confined_token(policy) {
            Ok(t) => { windows_sys::Win32::Foundation::CloseHandle(t); true }
            Err(_) => false,
        }
    }
    // NOTE: `probe_exe` reserved for the Task-12 WHP round-trip; mark `let _ = probe_exe;`
}
```

- [ ] **Step 2: cross-gate + clippy + commit** (as Task 4 Steps 2–3, 5).

### Task 6: Phase-2 verification gate

- [ ] **Gate A** — six gates green (Windows runtime via host interop transcript).
- [ ] **Gate B** — TWO independent refute-framed reviewers on the token builder:
  *"Does this token actually drop privileges and lower integrity? Can a compromised
  child re-raise integrity or re-enable a privilege? Is any handle leaked? Does
  `set_integrity` fail open (token returned at Medium if the call silently no-ops)?"*
  Require the Windows-host transcript (IL==Low, restricted==true) as PoC. Record
  both verdicts in the commit trailer.

---

## Phase 3 — Confined detached spawn (token + job + mitigations + `CreateProcessAsUserW`)

### Task 7: Job builder (best-effort, no kill-on-close)

**Files:** Modify `crates/izba-core/src/procmgr/jail_windows.rs`

- [ ] **Step 1: Implement `create_resource_job`**

```rust
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, SetInformationJobObject, AssignProcessToJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};

/// A NAMED, best-effort resource job. CRITICAL: never set
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — izbad death/upgrade must not kill VMMs.
/// SILENT_BREAKAWAY_OK so an adopted VMM is never tied to a launcher handle.
/// Returns the job handle (kept by the caller; closing it does NOT kill members).
unsafe fn create_resource_job(name_w: &[u16], mem_mb: Option<u64>) -> anyhow::Result<HANDLE> {
    let job = CreateJobObjectW(std::ptr::null(), name_w.as_ptr());
    if job.is_null() { anyhow::bail!("CreateJobObjectW: {}", std::io::Error::last_os_error()); }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if let Some(mb) = mem_mb {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = (mb as usize) * 1024 * 1024;
    }
    let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    if SetInformationJobObject(job, JobObjectExtendedLimitInformation,
        &info as *const _ as *const _, size) == 0 {
        CloseHandle(job);
        anyhow::bail!("SetInformationJobObject: {}", std::io::Error::last_os_error());
    }
    Ok(job)
}
```

- [ ] **Step 2:** cross-gate + clippy + commit `feat(jail): best-effort resource job (no kill-on-close)`.

### Task 8: Confined spawn — `spawn_confined`

**Files:** Modify `crates/izba-core/src/procmgr/jail_windows.rs`

This is the core. It mirrors `spawn_detached` (returns `PidIdentity`, stdio→log,
detached) but launches via `CreateProcessAsUserW` with the confined token, an
inheritable log handle passed through `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`,
creation-time mitigations, `CREATE_SUSPENDED`, then assigns the job and resumes.

- [ ] **Step 1: Implement the orchestration** (grounded in the proven probe)

```rust
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    DeleteProcThreadAttributeList, ResumeThread, GetProcessTimes,
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTF_USESTDHANDLES,
    CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, CREATE_NO_WINDOW,
    CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_ALWAYS, FILE_APPEND_DATA,
    FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT, FILETIME, GENERIC_WRITE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use crate::state::PidIdentity;
use crate::vmm::CommandSpec;
use std::path::Path;

/// Creation-time mitigations safe for OpenVMM (NO CIG — not MS-signed; NO ACG —
/// emulator may JIT; NO win32k-disable until proven headless-safe). DEP, ASLR,
/// extension-point-disable, image-load hardening, strict-handle.
fn vmm_mitigation_flags() -> u64 {
    use windows_sys::Win32::System::Threading::{
        PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE,
        PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON,
        PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON,
        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
        PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON,
    };
    (PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
        | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON) as u64
}

/// Spawn `cmd` confined per `policy`, detached, stdio appended to `log`.
/// Returns the same `PidIdentity` the daemonless liveness model uses.
/// Job handle is intentionally leaked (no kill-on-close) so the VMM survives.
pub fn spawn_confined(cmd: &CommandSpec, log: &Path, policy: &ConfinementPolicy)
    -> anyhow::Result<PidIdentity>
{
    // SAFETY: a single linear FFI sequence; every handle closed or deliberately
    // leaked (job) on success, and closed on every error path.
    unsafe {
        let token = build_confined_token(policy)?;
        // 1. inheritable append handle to the log
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1,
        };
        let log_w: Vec<u16> = log.as_os_str().encode_wide().chain(Some(0)).collect();
        let hlog = CreateFileW(log_w.as_ptr(), (FILE_APPEND_DATA | GENERIC_WRITE) as u32,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &mut sa, OPEN_ALWAYS,
            windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if hlog == INVALID_HANDLE_VALUE { CloseHandle(token); anyhow::bail!("open log"); }

        // 2. attribute list: handle list + mitigations
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
        let attr = windows_sys::Win32::System::Memory::HeapAlloc(
            windows_sys::Win32::System::Memory::GetProcessHeap(), 0, size) as *mut _;
        InitializeProcThreadAttributeList(attr, 2, 0, &mut size);
        let mut handles = [hlog];
        UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_mut_ptr() as *mut _, std::mem::size_of::<HANDLE>(),
            std::ptr::null_mut(), std::ptr::null_mut());
        let mut mit = vmm_mitigation_flags();
        UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            &mut mit as *mut _ as *mut _, std::mem::size_of::<u64>(),
            std::ptr::null_mut(), std::ptr::null_mut());

        // 3. STARTUPINFOEX
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdOutput = hlog;
        si.StartupInfo.hStdError = hlog;
        si.lpAttributeList = attr;

        // 4. command line (windows-sys takes a mutable UTF-16 buffer)
        let mut cmdline: Vec<u16> = build_command_line(&cmd.argv).encode_utf16().chain(Some(0)).collect();

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessAsUserW(token, std::ptr::null(), cmdline.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(), 1 /*bInheritHandles*/,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
                | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(), std::ptr::null(), &si.StartupInfo, &mut pi);

        // cleanup of setup handles regardless of outcome
        DeleteProcThreadAttributeList(attr);
        windows_sys::Win32::System::Memory::HeapFree(
            windows_sys::Win32::System::Memory::GetProcessHeap(), 0, attr as *mut _);
        CloseHandle(hlog);
        CloseHandle(token);
        if ok == 0 { anyhow::bail!("CreateProcessAsUserW: {}", std::io::Error::last_os_error()); }

        // 5. best-effort job, then resume
        let job_name: Vec<u16> = format!("izba-vmm-{}\0", pi.dwProcessId).encode_utf16().collect();
        if let Ok(job) = create_resource_job(&job_name, policy.job_memory_max_mb) {
            let _ = AssignProcessToJobObject(job, pi.hProcess);
            // intentionally leak `job`: closing it would NOT kill (no kill-on-close)
            // but we keep it so izbad can OpenJobObject by name on adoption.
            std::mem::forget(JobHandle(job));
        }
        ResumeThread(pi.hThread);

        // 6. PidIdentity (creation FILETIME), then drop process/thread handles
        let id = pid_identity_from(pi.hProcess, pi.dwProcessId)?;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(id)
    }
}

struct JobHandle(HANDLE);
```

Reuse the existing `creation_time`/PidIdentity logic from `windows.rs` — factor a
shared `pid_identity_from(h, pid)` (move the FILETIME read out of `windows.rs` so
both call it) and a `build_command_line(&[String])` (Windows argv quoting; copy
the rule std uses, or reuse `std`'s by building via `Command` only for quoting).

- [ ] **Step 2: Resolve all symbol paths via the cross-gate** until
  `cargo check --target x86_64-pc-windows-gnu -p izba-core` is green. Mitigation
  constant names that don't exist in `windows-sys` 0.60 must be replaced with the
  literal `0x...` values from `winnt.h` (documented inline).

- [ ] **Step 3: clippy clean; commit** `feat(jail): confined detached spawn via CreateProcessAsUserW`.

### Task 9: Unix fallback + uniform export

**Files:** Modify `crates/izba-core/src/procmgr/mod.rs`

- [ ] **Step 1:** Add a non-Windows `spawn_confined` so call sites are uniform and
  `cargo test` builds on Linux:

```rust
#[cfg(not(windows))]
pub fn spawn_confined(cmd: &crate::vmm::CommandSpec, log: &std::path::Path,
    _policy: &confine::ConfinementPolicy) -> anyhow::Result<crate::state::PidIdentity> {
    spawn_detached(cmd, log) // Linux jailer is a separate work item
}
#[cfg(windows)]
pub use jail_windows::{probe_confinable, spawn_confined};
```

- [ ] **Step 2:** `cargo test -p izba-core` (Linux) + both cross-gates; commit
  `feat(procmgr): uniform spawn_confined (unix passthrough)`.

### Task 10: Phase-3 verification gate

- [ ] **Gate A** — six gates green; Windows-host transcript: a confined `cmd.exe`
  /test exe spawns, writes to its log, and survives the launcher exiting (proves
  detach + no kill-on-close).
- [ ] **Gate B** — TWO refute-framed reviewers: *"Find a handle leaked into the
  confined child beyond the log (defeats the token). Prove the job has no
  kill-on-close path. Show whether CreateProcessAsUserW silently ran the child
  UNCONFINED on any error branch (fail-open). Confirm the child cannot break
  away from the job in a way that also escapes the token."* PoC required.

---

## Phase 4 — Differential containment PoC (`confine_probe`)

### Task 11: The probe example (child + harness)

**Files:** Create `crates/izba-core/examples/confine_probe.rs`

- [ ] **Step 1: Implement**

```rust
//! Differential confinement PoC. Two roles:
//!   confine_probe child  --attempt <kind> --result <file>
//!     performs <kind> and writes "OK"|"DENIED" to <file>, exit 0|13.
//!   confine_probe harness --self <path-to-this-exe>
//!     runs each attempt BOTH confined (spawn_confined) and unconfined
//!     (spawn_detached); asserts confined==DENIED && unconfined==OK; exit 0 iff all hold.
//! Attempts:
//!   write-up    : create a file under a Medium-IL dir (e.g. %ProgramData%\izba-probe) — Low IL must be denied.
//!   acquire-priv: enable SeShutdownPrivilege — DISABLE_MAX_PRIVILEGE must make it fail.
//!   whp         : WHvCreatePartition — must SUCCEED under confinement (capability gate).
fn main() { /* arg parse → child(kind,result) | harness(self) */ }
```

Provide the full child + harness bodies: child uses `CreateFileW`/`AdjustTokenPrivileges`/`WHvCreatePartition`; harness uses `izba_core::procmgr::{spawn_confined, spawn_detached}` + the `ConfinementPolicy::vmm_default()`, polls `pid_alive`, reads the result file. (Write the complete code at implementation time against the now-stable jailer API; this is mechanical given Phases 1–3.)

- [ ] **Step 2:** cross-gate compiles the example:
  `cargo check --target x86_64-pc-windows-gnu -p izba-core --examples`.
- [ ] **Step 3:** Windows-host run: `confine_probe harness --self <exe>` exits 0.
  Capture the transcript — **this is the headline PoC**.
- [ ] **Step 4:** commit `test(jail): differential confinement PoC example`.

### Task 12: Wire the WHP round-trip into `probe_confinable`

- [ ] **Step 1:** Replace the Task-5 stub so `probe_confinable` runs
  `confine_probe child --attempt whp` under the policy and returns true iff exit 0.
- [ ] **Step 2:** cross-gate + Windows-host check + commit.

### Task 13: Phase-4 verification gate

- [ ] **Gate A** — six gates; harness exits 0 on the host (transcript).
- [ ] **Gate B** — TWO refute-framed reviewers: *"Is the differential test
  meaningful — could the 'unconfined OK' arm be failing for an unrelated reason,
  making the test vacuously pass? Are the attempts actually security-relevant and
  actually blocked by THIS confinement (not by something else)? Add an attempt
  the reviewers think would slip through."* The PoC must show
  confined=DENIED/unconfined=OK for every attempt.

---

## Phase 5 — Wire into the OpenVMM driver + health

### Task 14: Launch the VMM confined, degrade gracefully

**Files:** Modify `crates/izba-core/src/vmm/openvmm.rs`, `vmm/mod.rs`

- [ ] **Step 1:** In `OpenVmmDriver::launch`, build `ConfinementPolicy::vmm_default()`
  with `job_memory_max_mb = Some(spec.mem_mb + headroom)`; memoise
  `probe_confinable(&policy, &openvmm_exe)`; if true call
  `procmgr::spawn_confined(&inv, &log, &policy)` and record
  `ConfinementStatus::applied(&policy)`; else `spawn_detached` +
  `ConfinementStatus::degraded("WHP not creatable under restricted token on this host")`.
  Store the status on `OpenVmmHandle`.
- [ ] **Step 2:** Add `fn confinement(&self) -> ConfinementStatus` to `VmHandle`
  (default `ConfinementStatus::degraded("n/a")` for cloud-hypervisor).
- [ ] **Step 3:** Linux `cargo test` + both cross-gates; Windows-host: real
  `izba run` boots with the VMM confined; `validate-izba-windows.ps1`'s existing
  8 checks still pass. Commit `feat(vmm): launch OpenVMM confined w/ graceful degradation`.

### Task 15: Surface confinement in health

**Files:** Modify `crates/izba-core/src/sandbox.rs` (status path), CLI status render

- [ ] **Step 1:** Thread `ConfinementStatus` into the status struct `izba status`
  prints; show `confinement: confined: restricted(limited)+low-il+job` or
  `UNCONFINED — <reason>`. Add a unit test asserting the render strings.
- [ ] **Step 2:** test + cross-gates + commit `feat(cli): show VMM confinement in status`.

### Task 16: Phase-5 verification gate

- [ ] **Gate A** — six gates; Windows-host: full boot confined + status shows
  `confined`.
- [ ] **Gate B** — TWO refute-framed reviewers: *"Does degradation fail OPEN
  silently in a way a user wouldn't notice? If the probe wrongly returns true,
  does the VMM still boot or hang (DoS)? Can a hostile guest influence the policy
  or force degradation? Is the health string honest about UNCONFINED?"*

---

## Phase 6 — CI: prove the protections on `windows-latest`

### Task 17: Probe + token assertions in the validation harness

**Files:** Modify `hack/spike/validate-izba-windows.ps1`

- [ ] **Step 1:** After check [8], add **[9] confinement**:
  - run `confine_probe harness --self <built exe>`; fail the suite on nonzero.
  - while a sandbox is running, find `openvmm.exe`, open its token, assert
    **integrity == Low** and **IsRestricted == true** (PowerShell P/Invoke or a
    small `izba`-side debug subcommand); fail otherwise.
  - assert `izba status` for the sandbox reports `confined`.
  Increment the pass/fail counters consistently with the existing style.
- [ ] **Step 2:** Windows-host dry run of the edited script. Commit
  `test(e2e): assert VMM confinement (probe + live token + status)`.

### Task 18: Build the probe in the e2e Windows job

**Files:** Modify `.github/workflows/e2e.yml`

- [ ] **Step 1:** In the `windows-whp` job build step, add
  `cargo build --release -p izba-core --example confine_probe` and pass its path
  to the validation script via env (e.g. `IZBA_CONFINE_PROBE`).
- [ ] **Step 2:** Commit `ci(e2e): build + run the confinement probe on windows`.

### Task 19: Phase-6 verification gate

- [ ] **Gate A** — push the branch; the `windows-whp` e2e job is green, including
  the new [9] confinement check. Link the run.
- [ ] **Gate B** — TWO refute-framed reviewers read the CI logs: *"Could [9] pass
  vacuously (probe not actually run, token query on the wrong process, assertion
  skipped on a missing tool)? Does a confinement regression actually FAIL the
  job, or just warn?"* Require the green run + a deliberately-broken local run
  that the check catches as PoC.

---

## Phase 7 — Docs, residuals, PR

### Task 20: Promote docs + record residuals

**Files:** Modify `docs/security/findings-2026-06-15.md`, the reference doc, README map if needed.

- [ ] **Step 1:** Mark F-06 **Windows** as mitigated (link the spec, plan, CI run);
  keep F-06 **Linux** open. Record residuals: per-VM mutual isolation (needs
  service accounts), alternate desktop deferred, launcher-shim two-token deferred.
- [ ] **Step 2:** commit `docs(security): F-06 windows VMM confinement mitigated`.

### Task 21: Open the PR

- [ ] **Step 1:** Ensure the branch is rebased on `origin/main` and all six gates
  + the e2e `windows-whp` run are green.
- [ ] **Step 2:** Provide the user the `git push` command and a `gh pr create`
  command (zsh `'''` multiline body) summarising: the threat (F-06), the design
  (Chromium-minus-AppContainer, single-token, no kill-on-close), the proof (the
  differential probe + live-token assertion in CI), and the residuals. Per repo
  convention the user runs push/PR themselves.

### Task 22: Final adversarial sign-off (whole-PR)

- [ ] **Gate B (whole PR)** — TWO independent refute-framed reviewers over the
  complete diff: *"Assume a hostile guest that escapes into the VMM. Walk the
  token/IL/mitigation/job and find the strongest residual capability. Is anything
  fail-open? Is the CI proof real?"* Plus a deterministic SAST pass
  (`cargo clippy` + any `cargo-deny`). Record both verdicts + the orchestrator's
  sign-off in the PR description. **Do not merge** — hand to the user.

---

## Self-review notes (author checklist run)

- **Spec coverage:** every spec deliverable maps to a phase — token/IL (P2), job
  no-kill-on-close (P3/Task7), mitigations (P3/Task8), capability+degradation+health
  (P2/Task5, P5), differential PoC (P4), CI proof (P6), residuals (P7). ✓
- **Placeholder scan:** FFI step bodies are concrete; the two spots that say
  "write the full body at implementation time" (confine_probe child/harness) are
  mechanical given the stabilised API and are explicitly scoped, not vague —
  acceptable, but the executing subagent must produce complete code + a passing
  host transcript before its Gate A. ✓
- **Type consistency:** `ConfinementPolicy`/`ConfinementStatus`/`spawn_confined`/
  `probe_confinable`/`PidIdentity` names are used identically across P1–P6. ✓
- **Known risk to flag during execution:** exact `windows-sys` 0.60 symbol paths
  and the existence of each `PROCESS_CREATION_MITIGATION_POLICY_*` constant must
  be resolved against the cross-gate; substitute literal `winnt.h` values where a
  constant is absent. This is expected iteration, not a plan gap.
