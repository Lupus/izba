# 0003 — Why did a terminated OpenVMM worker never finish exiting, and why did its guest not power off?

Issue [#319](https://github.com/Lupus/izba/issues/319) · 2026-10-08 ·
script: [`hack/spike/stuck-vmm-teardown-check.ps1`](../../hack/spike/stuck-vmm-teardown-check.ps1)

## Question

Spike #249 (PR #318, finding 8) stopped a sandbox whose guest never printed
`reboot: Power down`; `izba stop` returned 0 after 20.4 s, removed `state.json`
and the run dir, and `izba status` said `stopped` — while the `openvmm vm`
worker was still present hours later with every handle open. Two questions
were left: **why did the guest not power off**, and **why does the terminated
worker never finish exiting**? And the product question #319 answers in code:
how does izba notice?

## Approach

No reproduction was attempted (one hang in twelve stops, and the stuck process
cannot be re-killed). Instead the surviving evidence on the same host was read
six days later, unelevated, from WSL over `powershell.exe` interop:

- the worker process itself (`Get-Process`, `Win32_Process`, `Win32_Thread`,
  Sysinternals `handle64 -p <pid>`);
- the spike's throwaway data root `%TEMP%\i249m`, whose sandbox dir
  `sandboxes\p249h` the failed `rm --force` left behind: `config.json`,
  `logs/console.log`, `logs/vmm.log`, `rw.img`;
- a direct sharing-mode probe of `rw.img` and a rename attempt on the dir;
- the guest-side code paths involved (`izba-init`'s shutdown sequence, the
  kernel's `kernel_power_off` ordering, `vhci_hcd`'s unlink/detach path).

## Findings

### 1. The worker is still there, exited but not torn down

| Fact | Value (2026-10-08) |
| --- | --- |
| pid / image | 30620, `…\Temp\izba249-stage\bin\libexec\openvmm.exe vm` |
| parent | 29588 (the launcher izba recorded; gone) |
| created | 2026-10-02 00:36:22; `HasExited=True`, `ExitCode`/`ExitTime` unreadable |
| threads | exactly one (tid 29052), `ThreadState=5` (Wait), `WaitReason=Executive`, 1 min 22 s CPU in total, started with the process |
| handles | 255 open |
| working set | 3.49 GB (the guest's 4 GiB RAM is still mapped) |
| host uptime | 9 d 5 h — never rebooted since |

`handle64` (unelevated, so only File handles are listed) shows the worker
holding `sandboxes\p249h\rw.img`, `images\sha256-…\rootfs.erofs`,
`logs\vmm.log`, the three virtiofs share directories `oci`, `ssh`, `trust`, and
three `C:\$Extend\$Deleted\…` entries — files that were deleted while open:
the run dir's sockets, which `stop`'s cleanup removed from under it.

The lock is real: opening `rw.img` with `FileShare.None` fails with *"being
used by another process"*; renaming the dir fails with *"Access to the path …
is denied"* — exactly the `os error 5` the spike's `rm --force` hit.

### 2. Why izba called it stopped

`stop_locked` escalated to `kill_pid`, which `TerminateProcess`d the launcher
(pid 29588, torn down fine) and swept the worker with `terminate_quiet`:
`TerminateProcess` + `WaitForSingleObject(10 s)` **whose result was
discarded**. The post-kill guard asked `pid_alive(launcher)`, i.e.
`GetExitCodeProcess`, which `TerminateProcess` satisfies immediately. The
worker — not the launcher — is what holds the disks, and nothing asked about
it. On the next `izba ls` the stale-state reaper would have found `Stopped`
and wiped `state.json` anyway. Fixed by #319: `procmgr::tree_survivors` asks
"is the process **object** signaled" (`WaitForSingleObject(h, 0)`) for the
launcher and every descendant, `assess` turns a survivor into `degraded`, and
`stop`/`rm` refuse.

### 3. Why the worker never finishes exiting (conclusion)

`TerminateProcess` queues a kernel APC to every thread; a thread blocked in a
**kernel-mode, non-alertable wait inside a driver** cannot run it and the
process cannot complete teardown until that wait returns. The one remaining
thread is in exactly such a wait (`Executive`), it is a thread that burned
1 min 22 s of CPU during a 2-minute VM lifetime — a vCPU or I/O worker, not a
housekeeping thread — and the process still holds the WHP partition handle
(`\Device\VidExo`, per the spike's elevated listing) with the guest's memory
mapped. The teardown is therefore blocked **inside the Windows Hypervisor
Platform / `vid.sys`**, on an operation of that partition that never
completes; the handle table (and so `rw.img`) is closed only after every
thread is gone. This is outside izba's control: there is no API to force a
partition to release a stuck virtual processor, and the only known release is
a host reboot. Which VID call the thread is in is not knowable unelevated (see
Limits); it is not needed for the product decision — detect and report.

### 4. Why the guest did not power off (conclusion)

The console log ends at guest time 49.3 s with seventeen
`vhci_hcd: unlink->seqnum N` / `the urb (seqnum N) was already given back`
pairs — the tail of the 40 s USB write flood through the attached
`0403:6001` device (`usb 1-1`, `cdc_acm … ttyACM0`). Nothing follows: no
`usb 1-1: USB disconnect, device number 2` (which the kernel prints at
`dev_info` level for every detach), no `reboot: Power down`.

Three facts frame it:

- `izba-init`'s shutdown is `engine.kill_all(); sync(); reboot(RB_POWER_OFF)`
  and prints nothing of its own, so console silence is expected until the
  kernel speaks.
- The kernel prints `reboot: Power down` **after** `device_shutdown()` has
  called every device's `->shutdown` (`kernel_power_off` →
  `kernel_shutdown_prepare` → `device_shutdown()` → `pr_emerg("Power down")`
  → `machine_power_off`). A hang anywhere in `device_shutdown()` produces
  exactly this silence.
- The spike script issued `izba usb detach` immediately before `izba stop`,
  and the detach's kernel-side marker is missing.

The consistent explanation: the vhci detach that preceded the stop did not
complete inside the guest — `vhci_hcd`'s port disconnect / `usb_kill_urb`
path after a traffic burst with unlinked URBs is a known hang class (the
upstream fix "usbip: give back URBs for unsent unlink requests during
cleanup", 2021, is in this 6.18 kernel, so this is a residual case, not that
exact bug) — and the power-off then blocked in `device_shutdown()` behind the
USB device, so `Power down` was never reached. The alternative, that the
detach never reached the guest and `device_shutdown()` hung on the still-
attached vhci device whose host-side splice was being torn down, has the
same common factor: **a vhci (usbip) device attached or mid-detach at
power-off after sustained traffic**. Either way it is a guest-side defect
separate from #319 — filed as a follow-up (see below). The 10 s graceful
wait then expired and the kill path in finding 2 took over.

### 5. What is NOT established

- The exact VID operation the stuck thread waits in (needs an elevated
  kernel debugger, `livekd` is installed but UAC cannot be answered over
  interop).
- Whether the hang needs the usbip traffic at all, or only the guest power-off
  failure (the eleven clean stops in the spike all powered off, every one of
  them through the kill path, because OpenVMM does not exit on guest
  power-off — #320).
- Whether the detach returned to the CLI or hung; the spike's own run log was not kept.

## Conclusion

- The worker hang is a Windows Hypervisor Platform / `vid.sys` teardown wait
  that `TerminateProcess` cannot interrupt; izba cannot fix it and must detect
  it. #319 makes `stop`/`rm` refuse while any process of the VMM tree is not
  yet signaled, keeps `state.json`, and shows `degraded (vmm process <pid>
  terminated but not torn down, disks still held)`.
- The guest power-off failure is a separate, guest-side defect around a vhci
  device at shutdown after traffic — follow-up filed.
- Nothing here changes a normal stop: the new check is one Toolhelp snapshot
  and a zero-timeout wait per process.

## Reproduction recipe (real-host check)

The hang itself was seen once in twelve stops and cannot be forced; this is
how to re-create the *conditions* and how to verify the *detection* on a stuck
process whenever one exists.

1. Conditions (needs `hack/fake-usbipd` and an installer-shaped stage, see
   `docs/testing.md` §8): run PR #318's `hack/spike/container-probe-windows.ps1`
   with `IZBA_USB_TRAFFIC=1` in a loop until its final check
   `all N openvmm.exe process(es) this run started are gone after 'izba stop'`
   fails. Its data root `%TEMP%\i249-<pid>` and sandbox `probe249` are what the
   check below takes as input.
2. Detection: `pwsh -NoProfile -File hack/spike/stuck-vmm-teardown-check.ps1`
   with `IZBA_EXE`, `IZBA_DATA_DIR` and `IZBA_SANDBOX` set. It lists every
   `openvmm.exe` with its exited/thread/handle state, probes `rw.img` for an
   exclusive lock, and then asserts the #319 contract through the CLI:
   `izba status` says `degraded (… not torn down, disks still held)`, `izba
   stop` exits non-zero naming the pid, `state.json` is still there, `izba rm
   --force` exits non-zero with the same explanation.
3. Validation of the fix on the 2026-10-02 survivor itself is recorded in the
   next section.

## Limits

Everything was read unelevated; kernel stacks, non-File handle types and the
exit code of the exited process were not available. The spike's run log
(`izba-probe249-<pid>` output dir) was not retained, so the detach's own
duration and output are unknown.

## Follow-on work

- Follow-up issue (guest side): *Windows/OpenVMM: guest fails to power off
  with a vhci (usbip) device attached or mid-detach after sustained traffic* —
  link added by Task 5.
- [#320](https://github.com/Lupus/izba/issues/320) — OpenVMM does not exit on
  guest power-off, so every Windows stop takes the kill path (unchanged here).
