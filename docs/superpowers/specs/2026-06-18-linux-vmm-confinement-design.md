# Linux host-side VMM confinement (MVP-C) — design

**Date:** 2026-06-18
**Status:** approved (brainstorming complete)
**Closes:** F-06-Linux (unjailed VMM, partial — built-ins), F-07 (virtiofsd `--sandbox none`, full)
**Mints + registers:** F-27 (CH no Landlock), F-28 (no host resource bound), F-29 (no per-sandbox uid — accepted residual)

## 1. Problem

On Linux, `cloud-hypervisor` and `virtiofsd` are spawned via `spawn_detached`
as the **full invoking host user** with no filesystem confinement, no resource
bound, and `virtiofsd --sandbox none`. virtiofsd parses guest FUSE requests
directly against the user's **real project directory**; cloud-hypervisor is the
last line of defense against a VM escape. A compromise of either yields the
invoking user's full privileges and filesystem view — exactly the boundary izba
exists to protect (threat model A2 containment; findings F-06/F-07).

The Windows side already ships a jailer (restricted token + Low IL + job).
MVP-C is the **Linux realization of the same `procmgr::confine` seam**, using
host built-ins only (no custom uid/namespace jailer in this milestone).

## 2. Constraints (what makes Linux different)

- **Daemonless, no root.** izba runs as the invoking user; `izbad` is not
  privileged. A classic Firecracker-style dedicated-uid-per-sandbox jailer needs
  a setuid helper or root and is therefore **out of scope** (→ F-29, deferred).
- **Confinement is applied via component built-ins + spawn rlimits**, not a
  spawn-time token wrapper as on Windows:
  - `cloud-hypervisor` v42.0 self-confines via `--seccomp true` (already its
    default) and `--landlock` (filesystem confinement to the paths in its VM
    config). `--landlock` requires the **Landlock LSM** active in the host
    kernel.
  - `virtiofsd` v1.13.3 self-confines via `--sandbox namespace` (unprivileged
    user+mount+pid namespace; the upstream default) or `--sandbox chroot`.
  - Best-effort `setrlimit` at spawn bounds host resource use (→ F-28).
- **Spike findings (2026-06-18, real WSL2 host + a cilium CI node):**
  unprivileged user namespaces work without root; **Landlock is frequently
  absent** (`/sys/kernel/security/lsm` did not list it on the CI node); seccomp
  filter mode is universally available. The host owner can enable Landlock in
  their kernel (`CONFIG_SECURITY_LANDLOCK` + `lsm=...,landlock`), but the design
  must treat it as possibly-absent.

## 3. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Built-ins only.** No custom userns/uid jailer in MVP-C. | Ships fast, no root, fully closes F-07. The userns jailer is a documented follow-up (F-29 residual). |
| D2 | **Fail closed** + reuse the existing `--allow-unconfined` escape hatch. | Parity with the Windows jailer; honors the standing "never silently downgrade security" rule. |
| D3 | **Required floor** = `seccomp ON` **AND** `virtiofsd` real sandbox (`namespace`\|`chroot`) **AND** `Landlock active`. Floor unmet + no `--allow-unconfined` ⇒ refuse to launch. | The owner chose Landlock-in-floor. All three are root-free; Landlock-less hosts fail closed by design with an actionable message. |
| D4 | **virtiofsd: `--sandbox namespace`, fall back to `chroot`.** If neither is available (no userns), the virtiofsd floor leg fails. | namespace is the root-free upstream default; chroot covers userns-restricted-but-CAP_SYS_CHROOT-capable hosts. |
| D5 | **rlimits are best-effort, NOT part of the floor.** Applied at spawn; failure to apply is logged, never blocks, never drops below `Restricted`. | F-28 is DoS-hardening, not an escape boundary; making it a hard gate would add fragility for little containment value. |
| D6 | **Linux `ConfinementMode` is `Restricted` or `None` only — no `Partial`.** With `--allow-unconfined`, report `None` with a reason listing whatever incidentally applied. | Never overstate confinement. A bypassed floor gets no partial credit. Avoids touching the Windows-shaped enum. |
| D7 | **No proto/state changes.** Reuse `ConfinementStatus`, `VmSpec.allow_unconfined`, the `--allow-unconfined` flag, state.json persistence, and `izba status` display — all already shipped by the Windows jailer. | Minimal blast radius; the seam was built cross-platform on purpose. |

## 4. Architecture

Reuse the existing cross-platform seam in `crates/izba-core/src/procmgr/confine.rs`
(`ConfinementStatus { mode, reason }`, `ConfinementMode`). Add the Linux
mechanism in a new module and wire it into the cloud-hypervisor driver. No other
driver, the daemon proto, the CLI, or state.json change.

```
izba run --[allow-unconfined]→ VmSpec.allow_unconfined  (EXISTS)
                                      │
        CloudHypervisorDriver::launch │
                                      ▼
   jail_linux::Capabilities::probe()  ──→ { userns, landlock, seccomp }
                                      │
   jail_linux::plan(caps, allow_unconfined)
        ├─ floor met            → ConfinementPlan{ flags…, status: Restricted }
        └─ floor unmet & !allow  → Err(actionable floor error)   ← FAIL CLOSED
        └─ floor unmet & allow   → ConfinementPlan{ best-effort flags, status: None }
                                      │
   build_invocations(spec, tools, &plan)   ← injects virtiofsd --sandbox / CH --seccomp,--landlock
                                      │
   spawn_detached_with_limits(cmd, log, &rlimits)   ← best-effort setrlimit pre_exec (F-28)
                                      │
   ChHandle { …, confinement: plan.status }  → VmHandle::confinement()  → state.json → izba status
```

## 5. Components

### 5.1 `crates/izba-core/src/procmgr/jail_linux.rs` (new, `#[cfg(target_os = "linux")]`)

- `struct Capabilities { userns: bool, landlock: bool, seccomp: bool }`
  - `Capabilities::probe() -> Self`:
    - **userns:** attempt `unshare(CLONE_NEWUSER)` in a `fork`ed child (the only
      reliable signal across distros/sysctls); treat child exit 0 as available.
      (Reading `user.max_user_namespaces` / `kernel.unprivileged_userns_clone`
      alone is insufficient — some hosts gate by AppArmor/seccomp.)
    - **landlock:** `landlock_create_ruleset(NULL, 0,
      LANDLOCK_CREATE_RULESET_VERSION)` — returns the ABI version (≥1) when the
      LSM is active, `-ENOSYS`/`-EOPNOTSUPP` otherwise. The canonical probe.
    - **seccomp:** `prctl(PR_GET_SECCOMP)` succeeds on any seccomp-capable
      kernel; effectively always true on supported hosts.
- `struct ConfinementPlan { virtiofsd_sandbox: VirtiofsdSandbox, ch_seccomp: bool, ch_landlock: bool, rlimits: ResourceLimits, status: ConfinementStatus }`
- `enum VirtiofsdSandbox { Namespace, Chroot, None }`
- `fn plan(caps: &Capabilities, allow_unconfined: bool) -> anyhow::Result<ConfinementPlan>`
  - virtiofsd sandbox: `Namespace` if `userns`, else `Chroot` if a CAP_SYS_CHROOT
    probe passes, else `None`.
  - floor met = `seccomp && landlock && sandbox != None`.
  - floor met ⇒ `status = Restricted` with reason
    `"seccomp+landlock+virtiofs:<mode>[+rlimits]"`.
  - floor unmet & `!allow_unconfined` ⇒ `Err` whose message names **each** failed
    leg and the remediation (enable Landlock: `CONFIG_SECURITY_LANDLOCK` +
    `lsm=...,landlock`; userns sysctl) and ends with "or pass `--allow-unconfined`".
  - floor unmet & `allow_unconfined` ⇒ `status = None` (reason lists what *did*
    apply) but flags still set best-effort.
- `struct ResourceLimits { address_space: Option<u64>, nofile: Option<u64>, nproc: Option<u64> }`
  - `ResourceLimits::for_vmm(mem_mb: u64) -> Self`: `address_space = mem_mb + headroom`
    (generous — CH maps guest RAM), conservative `nofile`/`nproc` ceilings.

**Non-Linux compile parity** (`#[cfg(not(target_os = "linux"))]`): a stub
`Capabilities::probe()` returning all-false and a `plan()` that yields
`status = None`/no flags, so `izba-core` still compiles for the
`x86_64-pc-windows-gnu` cross-gate (cloud-hypervisor never runs there).

### 5.2 `confine.rs` — one additive constructor

Add `ConfinementStatus::confined(reason: &str) -> Self` (mode `Restricted`,
caller-supplied reason). The existing `applied()` hardcodes Windows token text;
Linux needs its own honest reason string. `degraded()` already covers `None`.
`summary()` is unchanged (already renders `Restricted`/`None`).

### 5.3 `crates/izba-core/src/procmgr/unix.rs` — rlimits at spawn

Add `spawn_detached_with_limits(cmd, log, limits: &ResourceLimits)` (or extend
`spawn_detached` with an optional limits arg). In the existing `pre_exec`
closure, after `setsid`, call `setrlimit(RLIMIT_AS/RLIMIT_NOFILE/RLIMIT_NPROC)`
for each `Some` limit. Failures are swallowed (best-effort, D5) — the closure
must stay async-signal-safe (no allocation; `nix::sys::resource::setrlimit`).

### 5.4 `crates/izba-core/src/vmm/cloud_hypervisor.rs`

- `build_invocations(spec, tools, plan: &ConfinementPlan)`:
  - virtiofsd argv: replace the hardcoded `--sandbox none` with
    `--sandbox <plan.virtiofsd_sandbox>`.
  - CH argv: append `--seccomp true` (explicit) when `plan.ch_seccomp`, and
    `--landlock` when `plan.ch_landlock`.
- `CloudHypervisorDriver::launch`:
  - `let caps = Capabilities::probe();`
  - `let plan = jail_linux::plan(&caps, spec.allow_unconfined)?;` — the `?`
    propagates the floor error (fail closed).
  - spawn virtiofsd + CH via `spawn_detached_with_limits(.., &plan.rlimits)`.
  - `ChHandle { …, confinement: plan.status }`.
- `ChHandle.confinement()` returns the stored status (replaces the current
  hardcoded `degraded("…not yet implemented")`).

### 5.5 Docs & CI

- **Findings register** (`docs/security/findings-2026-06-15.md`): mark F-07
  closed and F-06-Linux mitigated-by-built-ins; add F-27/F-28/F-29 with status.
- **CLAUDE.md** load-bearing contracts: note CH/virtiofsd now launch confined on
  Linux (seccomp+landlock+sandbox), fail-closed, `--allow-unconfined` to opt out.
- **`docs/testing.md`**: document the host-kernel Landlock requirement and how to
  enable it on WSL2; note that Landlock-less environments need `--allow-unconfined`.
- **CI (`e2e.yml` linux-kvm leg):** enable Landlock on the runner if feasible,
  else run with `--allow-unconfined` **plus a canary** asserting the achieved
  `ConfinementMode` so a silent regression away from `Restricted` is caught.

## 6. Error handling (fail-closed, never silent)

- Floor unmet + `!allow_unconfined`: `launch` returns the actionable floor error
  (§5.1). No process is spawned.
- `--allow-unconfined`: launch proceeds; `ConfinementMode::None`; the reason
  lists what incidentally applied; the loud warning path already exists (status
  summary `UNCONFINED — …`, and the daemon/CLI surface it).
- rlimit application failure: logged to `vmm.log`, launch continues (D5).

**Status-honesty assumption:** the `Restricted` status stored in `ChHandle` is
trustworthy because virtiofsd and cloud-hypervisor **fail closed** on
flag-application error — virtiofsd that cannot enter its `--sandbox` exits
before creating its socket (the socket-wait times out → launch returns an
error), and cloud-hypervisor aborts if `--landlock`/`--seccomp` cannot be
applied (the VM dies → health reports unhealthy). If a future CH or virtiofsd
release downgrades such a failure to a warning, this assumption breaks and the
status could overstate the achieved confinement.

## 7. Testing (TDD)

- **Unit (host-testable, no KVM):**
  - `build_invocations` emits the right virtiofsd `--sandbox` value and CH
    `--seccomp`/`--landlock` flags for each `ConfinementPlan` (mock the plan).
  - `jail_linux::plan` floor logic: every `(userns, landlock, seccomp)` combo →
    correct `Restricted`/`Err`/`None`; `allow_unconfined` flips `Err`→`None`;
    error message names each failed leg.
  - `ResourceLimits::for_vmm` scales with `mem_mb`.
  - `ConfinementStatus::confined` renders an honest `Restricted` summary.
- **Probe smoke:** `Capabilities::probe()` returns without panicking; values
  are self-consistent (best-effort assertions, environment-dependent).
- **Integration (KVM-gated, `IZBA_INTEGRATION=1`):**
  - VM boots with confinement applied; `/workspace` virtiofs mount works;
    console clean; `confinement().mode == Restricted` (when the runner has
    Landlock) — else the test self-skips with a clear Landlock-absent reason.
  - Negative: a forced floor failure refuses to launch without
    `--allow-unconfined` and the error names the missing leg.
- **`confine_probe` example:** extend or mirror the Windows probe example to
  dump Linux `Capabilities` + the resulting plan, for the spike and CI canaries.

## 8. Scope boundaries (YAGNI / deferred)

- **Out:** custom userns/uid jailer (F-29 residual — separate follow-up),
  full cgroup v2 resource control (F-28 covers rlimits only), OpenVMM-on-Linux
  (the Linux driver is cloud-hypervisor; OpenVMM is the Windows/WHP path),
  Landlock custom rule shaping beyond CH's auto-derived config rules.

## 9. New findings (definitions for the register)

- **F-27 — cloud-hypervisor runs without Landlock filesystem confinement.** A CH
  compromise reaches the full host-user filesystem. *Closed by `--landlock`
  (floor leg).*
- **F-28 — no host resource bound on the VMM + virtiofsd.** A runaway/hostile
  guest can exhaust host memory/FDs/PIDs. *Mitigated best-effort by `setrlimit`
  at spawn; full cgroup control deferred.*
- **F-29 — VMM/virtiofsd run under the invoking user's uid (no per-sandbox uid
  separation).** *Accepted residual for MVP-C (daemonless/no-root); deferred to
  the userns-jailer follow-up.*
