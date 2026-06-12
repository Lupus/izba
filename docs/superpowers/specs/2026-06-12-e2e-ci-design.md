# Real end-to-end CI: KVM (Linux) + OpenVMM/WHP (Windows) — design

Date: 2026-06-12. Status: approved.

Extends the CI delivered by the 2026-06-12 GitHub Actions design with the
suites that boot real microVMs. Until now these ran only on the developer's
WSL2 host (Linux) and a manually driven Windows 11 host (Windows).

## Probe findings (empirical, 2026-06-12, throwaway `probe/e2e-caps` run)

Both GitHub-hosted runner images can run real VMs:

- **ubuntu-latest:** `/dev/kvm` exists; a one-line udev rule
  (`KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"` +
  `udevadm trigger`) makes it read-write for the runner user. CPU exposes
  virt flags. apt `erofs-utils` is 1.7.1 (too old; we need ≥ 1.8 for
  `--tar=f`) and apt `passt` (0.0~git20240220) lacks `--vhost-user` — both
  must come from pinned source builds instead.
- **windows-latest:** `HypervisorPresent: True`, `Microsoft-Hyper-V` and
  `HypervisorPlatform` features both **Enabled**, `hypervisorlaunchtype
  Auto`. WHP is active without any reboot — OpenVMM should run as-is.

## Decisions

1. **Standalone workflow `.github/workflows/e2e.yml`** (not bolted onto
   `artifacts.yml`): `ci.yml` stays fast, `artifacts.yml` stays a publisher,
   `e2e.yml` owns slow truth. It duplicates the kernel/mke2fs/initramfs job
   YAML from `artifacts.yml` **with identical cache keys**, so the kernel is
   normally a ~2 min cache restore. The duplication (~60 lines) is the
   accepted cost of independence; a reusable `workflow_call` refactor is
   deliberate YAGNI until a third consumer exists.
2. **Triggers:** `push` to main, `workflow_dispatch`, and a **weekly cron**
   (`0 3 * * 1`, Monday 03:00 UTC — not nightly). Since every merge already runs the full suite, a schedule
   only catches external drift: expired OpenVMM artifact pins, runner-image
   changes (e.g. GitHub disabling Hyper-V on windows-latest), registry-side
   image changes, and GitHub's 7-day cache eviction (the weekly run keeps the
   kernel cache warm). Weekly bounds that detection window at 1/7th the cost
   of nightly. A "skip if unchanged" guard was rejected: running unchanged
   code is precisely how drift is detected.
3. **Scope — everything env-gated today:**
   - Linux leg: `integration` (15 tests), `daemon_e2e` (5 scenarios),
     tty Tier-2 (`tty_e2e`, `--features ttytests`), ttystorm M0 churn gate.
   - Windows leg: `hack/spike/validate-izba-windows.ps1` (21 checks),
     tty Tier-2, ttystorm M0 churn gate.
4. **Supply-chain pinning closes out** (rule: nothing unpinned is executed):
   - `hack/fetch-artifacts.sh` gains sha256 pins for the cloud-hypervisor
     v42.0 and virtiofsd v1.13.3 downloads (verify after download, delete on
     mismatch — same pattern as `build-kernel.sh`).
   - New `hack/build-passt.sh`: pinned passt release tarball from passt.top
     (tag `2026_05_26`, the version validated on the developer host),
     sha256-verified, plain `make` build, output `dist/passt-<tag>`.
5. **ttystorm gate becomes scripted CI checks** instead of manual runs:
   `hack/ci/ttystorm-gate.sh` (Linux) and `hack/ci/ttystorm-gate.ps1`
   (Windows). Flow: the script creates and boots its own sandbox (`izba run`
   with a marker command, which also auto-starts izbad), runs
   `ttystorm <name> floodfast 20 2048`, then `ttystorm <name> chop 30 256`,
   then asserts `izba exec <name> -- echo alive` succeeds, then removes the
   sandbox. This encodes the M0 exit criteria (izbad-path churn must not
   kill the VM).
6. **Windows leg builds natively, and MSVC becomes the source-of-truth
   Windows toolchain.** The e2e leg builds `izba.exe` with the runner's
   native MSVC toolchain (`cargo build --release -p izba-cli`): `tty_e2e`
   needs a native cargo test run anyway (`CARGO_BIN_EXE`), so one toolchain
   serves everything. To keep "what we test" and "what we ship" the same
   binary, `artifacts.yml`'s `izba-windows` job switches from the ubuntu
   win-gnu cross build to a native MSVC build on windows-latest. The
   win-gnu cross `check`/`clippy` gates in `ci.yml` stay (cheap portability
   gates; they catch cfg/linker drift), but the published bundle is MSVC.
   Only `mkfs.erofs.exe` (MinGW cross, unchanged) and the boot artifacts
   arrive as workflow artifacts from ubuntu jobs.

## Workflow shape

```
e2e.yml  (push: main | cron: weekly | workflow_dispatch)
├── kernel        ubuntu   cache vmlinux-${hashFiles(kernel.config, build-kernel.sh)}
├── mke2fs        ubuntu   (copies of the artifacts.yml jobs)
├── initramfs     ubuntu   needs: mke2fs
├── erofs-exe     ubuntu   mkfs.erofs.exe via build-mkfs-erofs-windows.sh
├── linux-kvm     ubuntu   needs: kernel, initramfs
└── windows-whp   windows  needs: kernel, initramfs, erofs-exe
```

**linux-kvm steps:** udev KVM enable + `[ -r /dev/kvm ] && [ -w /dev/kvm ]`
assert → restore tool cache (cloud-hypervisor, virtiofsd, passt, native
mkfs.erofs 1.9.1 via `build-mkfs-erofs-windows.sh --linux-only`; keyed on the
hack script hashes) → build any cache misses → download vmlinux/initramfs
artifacts → `actions/cache` on `IZBA_TEST_CACHE` (the alpine:3.20 OCI pull) →
run, in order, with `IZBA_INTEGRATION=1` and `--test-threads=1`:
`integration`, `daemon_e2e`, `tty_e2e` (`IZBA_TTY_E2E=1`), ttystorm gate.
Timeout 60 min.

**windows-whp steps:** fetch pinned `openvmm.exe` (actions/cache keyed on the
pin; `hack/fetch-openvmm.sh` does sha256 verification) → native release build
of izba-cli → stage `izba.exe` + `libexec/mkfs.erofs.exe` + `openvmm.exe` +
boot artifacts where the CLI expects them → `validate-izba-windows.ps1` →
`tty_e2e` → ttystorm gate. Timeout 60 min.

**Failure diagnostics:** both legs upload the sandbox data dir's `logs/`
trees (console.log, vmm.log, passt.log, daemon logs) as a workflow artifact
with `if: failure()` — CI-debugging without SSH.

## Risks / iteration plan

- **openvmm.exe fetch auth:** `fetch-openvmm.sh` downloads a CI artifact
  from microsoft/openvmm via `gh run download`; the repo-scoped
  `GITHUB_TOKEN` may 403 cross-repo. Try it first; if refused, fall back to a
  user-supplied PAT secret (`OPENVMM_FETCH_TOKEN`) used only by this step.
  The pinned artifact also expires ~Sep 2026; the re-pin procedure is in the
  script header, and the weekly cron surfaces the expiry as a red run.
- **First real OpenVMM boot on a hosted runner is unproven.** The probe
  showed WHP enabled, but consomme networking and boot timing under nested
  virt are unknowns. Budget ≥ 10 CI iterations for this leg.
- **Boot-time assertions** (`boot_to_healthy_under_5s`-style) may flake on
  shared 4-core runners. If observed, relax via an env knob consumed by the
  test (e.g. `IZBA_BOOT_BUDGET_SECS`), keeping the strict default locally —
  never weaken the local gate to make CI green.
- **Serial, not parallel, test execution** (`--test-threads=1`) keeps RAM
  within the 16 GB runner budget (each test boots a 1 GiB VM + sidecars).

## Bring-up findings (2026-06-12, recorded post-implementation)

- `GITHUB_TOKEN` DOES fetch the cross-repo openvmm.exe artifact — the PAT
  fallback was never needed.
- Ubuntu-24.04 runners set `kernel.apparmor_restrict_unprivileged_userns=1`,
  which kills the unconfined static passt at startup ("Failed to detach
  isolating namespaces"); the linux-kvm job flips the sysctl off first.
- Hosted-runner nested virt boots slowly (Windows kernel up at ~19-25 s vs
  ~4 s locally); the predicted boot-budget knob shipped as
  `IZBA_BOOT_TIMEOUT_SECS` (default 30 s unchanged; CI sets 120).
- **Hosted Windows runners lose all ConPTY child output** in the service
  session — even a trivial echo fixture renders an empty screen (run
  27445265822). The windows-whp job runs a ConPTY canary and auto-skips
  tty Tier-1/Tier-2 when it fails; tty coverage on Windows stays on the
  manual spike-host route. Linux tty steps are unconditional.
- The 21-check validation suite and the ttystorm M0 churn gate pass on
  hosted Windows runners — real OpenVMM/WHP VMs work in CI.

## Out of scope

- e2e on pull requests (can be added later as a PR label or an explicit
  dispatch against a branch).
- Publishing e2e-validated bundles (release promotion stays at M2).
- KVM inside the `windows-native` unit-test job (units don't need VMs).
- Dropping the win-gnu target entirely: the cross check/clippy gates stay
  as portability tripwires even though the shipped binary is now MSVC.
