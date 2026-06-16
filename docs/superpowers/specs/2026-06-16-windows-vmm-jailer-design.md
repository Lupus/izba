# Windows VMM jailer — design (Windows-only, F-06)

> **Date:** 2026-06-16 · **Status:** approved design, ready for an implementation
> plan. Scope: the **Windows** half of finding **F-06** (the host-side VMM runs
> unjailed as the full invoking user). Deep rationale + the Chromium mechanism +
> the empirical probes live in
> [`docs/security/windows-vmm-jailer-chromium-reference.md`](../../security/windows-vmm-jailer-chromium-reference.md);
> this doc locks scope + decisions for the first PR. The **Linux** half
> (cloud-hypervisor seccomp/Landlock, virtiofsd `--sandbox namespace`,
> unprivileged userns jailer) is out of scope here.

## Problem

izba spawns OpenVMM on Windows with no host-side confinement
(`procmgr/windows.rs::spawn_detached` does only
`CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`). A VM-escape or a bug in OpenVMM's
in-process virtio-fs server runs with the **full invoking-user** privileges
against the user's real project directory. F-06.

## Decisions (locked — see the reference doc for the why)

1. **Model:** the Chromium Windows usermode-sandbox stack **minus AppContainer**
   — a restricted token + **Low integrity** + a resource-only job + process
   mitigations + handle hygiene. (Probe-proven: AppContainer denies WHP
   `\Device\VidExo`; restricted-token + Low-IL keeps it.)
2. **Single-token launch, no `LowerToken()`.** OpenVMM is third-party; we cannot
   make it cooperate. One token is the process's whole-life identity, tight
   enough to confine but loose enough to open `\Device\VidExo` and bootstrap.
   Token = `DISABLE_MAX_PRIVILEGE` (drop all privileges) + **Low IL**. **NO
   restricting SIDs.** Live-validated 2026-06-16: adding the Chromium
   `USER_LIMITED` restricting-SID set (Users/Everyone/RESTRICTED ± logon SID)
   makes the process fail to initialize (`0xC0000142` STATUS_DLL_INIT_FAILED) —
   reproduced even with native `cmd.exe`, so it is fundamental, not .NET-specific.
   Chromium survives this only via two-token warmup (`LowerToken`), which a
   third-party VMM can't do and which doesn't transfer to child processes. So
   `TokenLevel` is effectively a single proven shape; the `Limited`/
   `RestrictedNonAdmin` enum variants are forward-declared but inert.
   **Consequence (residual):** the token gives *integrity* protection (Low-IL
   no-write-up + no privileges) but **not read-confinement** — a Low-IL
   non-restricted VMM can still READ the user's files. Read-confinement would
   need AppContainer (breaks WHP) or per-VM service accounts (admin); both out of
   scope.
3. **No `KILL_ON_JOB_CLOSE`.** izba's contract is "killing/upgrading izbad never
   harms sandboxes." The security boundary is the **create-time-immutable** token
   + IL + mitigations (survive izbad death). The job is **best-effort
   resource-governance only**, named per sandbox, `SILENT_BREAKAWAY_OK`,
   re-acquired on adoption.
4. **Security on immutable create-time properties:** child-process blocking via
   `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (sized for OpenVMM's worker
   child, not `ActiveProcessLimit=1`); shatter protection is **optional** (Low-IL
   /UIPI already covers it for a headless VMM — alternate desktop is
   belt-and-suspenders, deferred).
5. **Reuse:** no usable crate exists (`codex-windows-sandbox` is unpublished,
   monorepo-coupled, run-to-completion + kill-on-close). Build on the existing
   `windows-sys` dependency (extend feature gates), cribbing the Win32 plumbing
   structure (Apache-2.0 attribution) but inverting the lifecycle to
   spawn-detached. Confined launch is `CreateProcessAsUserW` (std `Command`
   cannot carry a custom token / `STARTUPINFOEX`).
6. **UX — LOUD on degradation, never silent** (general izba rule, see memory
   `izba-loud-on-security-degradation`). If the VMM cannot be confined on a host,
   izba **FAILS CLOSED** by default: it refuses to start the sandbox with a clear
   error. To proceed unconfined the user must pass an explicit, deliberately
   awkward opt-in flag (`--allow-unconfined`); even then izba emits a prominent
   CLI warning, shows `UNCONFINED` in `izba status`, and (follow-up) warns in the
   desktop UI. Never silently downgrade. (Distinct from Linux, where the jailer is
   a not-yet-implemented milestone — reported honestly in status, not gated by the
   flag.)

## What the first PR delivers (and proves in CI)

- A `ConfinementPolicy` + a Windows jailer (`jail_windows.rs`) that spawns a
  process under restricted-token + Low-IL + best-effort job + creation-time
  mitigations, returning the same `PidIdentity` the daemonless model relies on.
- The OpenVMM spawn path goes through the jailer behind the policy, with
  capability detection + graceful degradation + health surfacing.
- **Demonstrated protections (the deterministic PoC):** an izba-authored
  `confine-probe` example launched **confined vs unconfined**; CI asserts the
  security-relevant operations (write-up to a Medium-IL host file outside the
  share; acquiring a deleted privilege; spawning a disallowed child) **fail under
  confinement and succeed unconfined** — the methodology's required abuse-case
  PoC.
- **Integration proof:** the existing Windows e2e suite (`validate-izba-windows.ps1`)
  still boots a real VM **with the VMM confined**, and a new assertion queries
  the live `openvmm.exe` token to confirm Low IL + restricted.

## Non-goals (this PR)

- Linux jailer (separate plan). Alternate desktop / window station (deferred,
  §6.2.2 of the reference). Per-VM *mutual* file isolation (needs per-VM service
  accounts — admin; documented residual). The optional launcher-shim two-token
  hardening (§6.1). MITM/credential work (M5).

## Acceptance / verification

- All six CLAUDE.md gates green (incl. `x86_64-pc-windows-gnu` check + clippy).
- The `confine-probe` differential test passes in the Windows e2e job.
- The real-VM Windows e2e still passes with confinement on; the live-token
  assertion passes.
- **Adversarial verification (per the security methodology, §"two principles"):**
  every protection claim is routed through **≥2 independent refute-framed
  verifier agents** (that did not write the code), with a **PoC required** and a
  final sign-off; no security change is auto-merged. Baked into every plan phase.
