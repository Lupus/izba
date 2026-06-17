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
   non-restricted VMM still runs as the user and can READ the user's files.
   Read-confinement needs a **distinct security principal**, and the only two
   ways to get one both have costs: AppContainer (probe-proven to break WHP →
   ruled out), or a **dedicated low-privilege local account** for the VMM (needs
   one-time admin at install). The latter is the documented **future hardening
   tier** (`izba install --harden`, see §7) — not built here, but the path is
   real: it would ACL-grant the VMM account just the workspace + scratch and
   close this residual. Two assumptions remain unverified for that tier and are
   probe-gated before it ships: (i) WHP works under a separate standard account
   in **Hyper-V Administrators**; (ii) the per-run cross-account ACL/profile
   plumbing. Until then the residual is accepted (integrity-only). See Non-goals
   for the tier's status.
3. **No `KILL_ON_JOB_CLOSE`.** izba's contract is "killing/upgrading izbad never
   harms sandboxes." The security boundary is the **create-time-immutable** token
   + IL + mitigations (survive izbad death). The job is **best-effort
   resource-governance only**, named per sandbox, `SILENT_BREAKAWAY_OK`,
   re-acquired on adoption.
4. **Security on immutable create-time properties** (token + IL + mitigations).
   **Child-process creation is NOT blocked:** OpenVMM forks an `openvmm vm`
   worker, and the only Windows primitive for it
   (`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY =
   PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) is all-or-nothing — there is no
   per-worker exception — so it cannot be applied without breaking the VM.
   Children DO inherit the restricted token + Low IL (so they run deprivileged),
   but they are not prevented from spawning. Shatter protection is **optional**
   (Low-IL/UIPI already covers it for a headless VMM — alternate desktop is
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

7. **The writable surface must be Low-labelled, and restored on teardown.** A
   Low-IL process cannot write *up* to Medium-IL objects (MIC no-write-up), so
   every path the confined VMM must write has to be Low-labelled first. Two
   surfaces qualify: (a) the per-sandbox **scratch dir** izbad created at Medium
   (`console.log`, `rw.img`, the vsock socket under `run/`) — without it the VM
   never boots (empty console.log, 100% boot failure under confinement); and
   (b) the **virtiofs workspace share** (the user's project dir) — the guest
   writes `/workspace` through the in-process virtiofs server, which runs *inside*
   the Low-IL VMM, so without a Low label there the guest's writes fail and the
   core izba function is dead under confinement. The label is inheritable
   (`OBJECT_INHERIT | CONTAINER_INHERIT`); for the common case inheritance is
   **probe-proven** (2026-06-17: a Medium process doing a plain create in the
   labelled tree yields a Low child, so user-created-mid-session files stay
   guest-writable). Narrow exceptions (atomic-rename-in) are residuals below.
   **Restore on teardown:** the user's workspace is raised back to Medium when the
   VMM is gone — on graceful stop, force-remove, AND the stale-state sweep that
   `list`/daemon-adoption runs (the orphan reconcile point). A *missed* restore is
   benign (a stale Low label lets Medium tools write *down* to it freely; only a
   mild integrity weakening until the next adoption sweep re-asserts Medium), so
   the design is best-effort + idempotent rather than transactional. Restore is
   gated on `ConfinementStatus::is_confined()` so unconfined/legacy sandboxes are
   untouched, and on non-Windows the whole relabel/restore pair is a no-op.
   Relabelling happens **before** `state.json` is written, so the state.json-gated
   teardown restore cannot undo it on an early failure — the launch path therefore
   restores every share it labelled on its own error paths (label-failure,
   confined-spawn-failure, boot-timeout), so a failed confined start never strands
   the user's dir at Low.

   **Accepted residuals of integrity-relabelling (all benign for the boundary;
   each cleanly closed by the dedicated-account tier, which never relabels the
   user's dir).** Surfaced by adversarial review, documented at the code site:
   - *Approximate restore.* Teardown re-asserts an *explicit* Medium label rather
     than capturing+restoring the exact prior SACL. Equivalent for the universal
     case (project dirs are unlabelled == effective Medium); a dir genuinely
     sub-Medium before izba ran ends up Medium (mildly *more* restrictive). Rare.
   - *Atomic-rename-in.* A host save that creates a temp *outside* the labelled
     tree and renames it in keeps its non-Low label, which the Low-IL guest then
     can't write. Narrow (most editors/git temp within the same dir → inherits
     Low); fully fixed by the account tier.
   - *Post-teardown Low files.* Re-propagation refreshes only *inherited* child
     labels; files the Low-IL VMM created carry their own *explicit* Low label and
     keep it, so the workspace can hold a scattering of Low files after teardown.
     Benign (Medium tools write *down* freely).
   - *Worker-child liveness.* Liveness is judged from the tracked `openvmm.exe`
     parent; OpenVMM may leave an untracked `openvmm vm` worker that outlives it
     (pre-existing `windows.rs` caveat). If the parent dies but a worker survives,
     teardown could raise the workspace while that worker still runs. Pre-existing
     stop-semantics gap, not introduced here; closed by the account tier (and a
     future worker-aware liveness fix).

## What the first PR delivers (and proves in CI)

- A `ConfinementPolicy` + a Windows jailer (`jail_windows.rs`) that spawns a
  process under restricted-token + Low-IL + best-effort job + creation-time
  mitigations, returning the same `PidIdentity` the daemonless model relies on.
- The OpenVMM spawn path goes through the jailer behind the policy, with
  capability detection + graceful degradation + health surfacing.
- **Demonstrated protections (the deterministic PoC):** an izba-authored
  `confine-probe` example launched **confined vs unconfined**; CI asserts the
  security-relevant operations (write-up to a Medium-IL host file outside the
  share; acquiring a deleted privilege) **fail under confinement and succeed
  unconfined** — the methodology's required abuse-case PoC.
- **Integration proof:** the existing Windows e2e suite (`validate-izba-windows.ps1`)
  still boots a real VM **with the VMM confined**, and a new assertion queries
  the live `openvmm.exe` token to confirm Low IL + restricted.

## Non-goals (this PR)

- Linux jailer (separate plan). Alternate desktop / window station (deferred,
  §6.2.2 of the reference). The optional launcher-shim two-token hardening (§6.1).
  MITM/credential work (M5).
- **Dedicated-account hardening tier (`izba install --harden`)** — the documented
  *future opt-in* that closes the read-confinement residual (decision 2): a
  one-time admin installer creates a low-privilege `izba-vmm` local account in
  Hyper-V Administrators; the VMM then runs as that distinct principal with the
  workspace+scratch ACL-granted per run, giving read **and** write confinement
  (and removing the need to integrity-relabel the user's dir). Not built in this
  PR; gated on the two probes named in decision 2. This is the SOTA ceiling;
  the default (no-admin) tier this PR ships is the verified floor.

## Acceptance / verification

- All six CLAUDE.md gates green (incl. `x86_64-pc-windows-gnu` check + clippy).
- The `confine-probe` differential test passes in the Windows e2e job.
- The real-VM Windows e2e still passes with confinement on; the live-token
  assertion passes.
- **Adversarial verification (per the security methodology, §"two principles"):**
  every protection claim is routed through **≥2 independent refute-framed
  verifier agents** (that did not write the code), with a **PoC required** and a
  final sign-off; no security change is auto-merged. Baked into every plan phase.
