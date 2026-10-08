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
| parent | 29588 — the launcher izba recorded. Its process OBJECT is still there too: exited 2026-10-02 00:38:38 with code 1 (the `TerminateProcess` code), signaled, holding nothing; its pid stays reserved because the worker holds a handle to its parent, so `OpenProcess` still succeeds and `GetProcessTimes` still reports its real creation time (`134353605823541370`, 00:36:22.354), while CIM and `tasklist` no longer list it |
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
  outlived its launcher and still holds the disks)`; when the launcher is gone
  but a worker is still running, `stop` re-sweeps the guarded tree before it
  decides.
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
   `izba status` says `degraded (vmm process <pid> outlived its launcher and
   still holds the disks)`, `izba
   stop` exits non-zero naming the pid, `state.json` is still there, `izba rm
   --force` exits non-zero with the same explanation.
   If the stuck sandbox's `state.json` is gone (an older build removed it),
   re-create it with the launcher's REAL creation time: while the worker
   holds a handle to its parent, `OpenProcess(<launcher pid>)` still works
   and `GetProcessTimes` returns it — a forged value reads as a recycled pid
   and the sandbox as stopped (see Run 2 below).
3. Validation of the fix on the 2026-10-02 survivor itself is recorded in
   [Validation on the 2026-10-02 survivor](#validation-on-the-2026-10-02-survivor)
   below.

## Validation on the 2026-10-02 survivor

Run on 2026-10-08 against the real stuck worker (pid 30620 — still present,
still one thread in `Wait:Executive`, 255 handles), with `izba.exe`
cross-built from this branch and dropped into a copy of the spike's
installer-shaped stage, against the data root `%TEMP%\i249m`. Three runs,
and the two that did not pass taught something each.

**What had to be reconstructed first.** At 18:46:55 that day — after the
evidence above was read, and not by this work — everything deletable under
`%TEMP%\i249m` and the spike's workspace dir `%TEMP%\i249-ws-p249h` was
removed (the pattern fits a cleanup of the spike's leftovers; `izba249-stage`,
named differently, survived). The worker kept every handle: `rw.img`,
`rootfs.erofs` and the `oci`/`ssh`/`trust` share dirs now show up in its
handle table as `C:\$Extend\$Deleted\…` entries (NTFS's name for a file
unlinked while open); `vmm.log` kept its name. So the sandbox dir had only
`logs/vmm.log` left; `config.json` was restored from a copy taken at 18:39,
and `state.json` — which the old build had deleted on 2026-10-02 — was
re-created. The detection looks only at the process tree, so the emptied
directory changes nothing about what is validated, except that the script's
`rw.img` sharing probe now reports `False` (no path to open; the worker holds
the unlinked inode).

**Run 1 (binary `fa9b93f`, before the final-review fixes), `starttime: 0`:**
11/11 PASS. It proved the detection, not its discrimination: a zero start
time disables every creation-time comparison.

**Run 2 (binary `fff0e1f`, with the recycled-pid guards), `starttime` forged
to 1.5 s before the worker's creation: 9 FAIL** — `status: stopped`, `stop`
exited 0 and deleted `state.json`. Four more forged values (boot + 1 tick, the
worker's own creation time, zero) all read `stopped` too. The cause is in
finding 1's table: the launcher's process object still exists, so
`OpenProcess(29588)` succeeds and reports a creation time that differs from
the forged one — exactly the signature of a stranger holding a recycled pid,
and the pid-holder guard correctly dropped everything created after it.
(Separately, `OpenProcess(4)` fails with `ERROR_ACCESS_DENIED` for an
unprivileged caller on this host, so the boot guard was disabled, as
designed — it never fired in any run.) The lesson for the recipe below: a
reconstructed `state.json` must carry the launcher's REAL creation time;
anything else is, to the guards, a different process.

**Run 3 (binary `fff0e1f`), `starttime` = the launcher's real creation time
read from its still-reserved process object:**

```json
{ "vmm_pid": { "pid": 29588, "starttime": 134353605823541370 }, "sidecar_pids": [],
  "started_unix_ms": 1790886982000, "usb_kernel": true, "vnc": false }
```

```
[20:54:42.127] openvmm.exe processes on the host:
[20:54:42.382]   pid=30620 ppid=29588 exited=n/a threads=1 handles=255 working_set_mb=3330
[20:54:42.385] rw.img exclusively held by another process: False
[20:54:42.851] izba status: rc=0
  status:      degraded (vmm process 30620 outlived its launcher and still holds the disks)
[20:54:42.858] PASS  status does not report a clean stop (no bare "stopped" line)
[20:54:42.859] PASS  status reports the stuck teardown (degraded ... outlived its launcher and still holds the disks)
[20:54:55.081] izba stop: rc=1
  izba: error: sandbox 'p249h': VMM process 30620 from its last run is still present and
  holds the sandbox's disks (rw.img, volumes), so the sandbox is not cleanly stopped;
  state preserved so it cannot be double-booted, and `izba status p249h` reports it
  degraded. Run `izba stop p249h` again to make it exit; if it stays in the process
  list after that, it is stuck in kernel-side teardown, which only a host reboot releases.
[20:54:55.083] PASS  stop exits non-zero
[20:54:55.084] PASS  stop names a pid and says the disks are still held
[20:54:55.085] PASS  stop says what to do (run stop again / host reboot)
[20:54:55.088] PASS  state.json is preserved after the refused stop
[20:55:07.368] izba rm --force: rc=1
  izba: error: sandbox 'p249h': VMM process 30620 from its last run is still present … (same text)
[20:55:07.369] PASS  rm --force exits non-zero
[20:55:07.369] PASS  rm --force gives the same explanation, not a raw Access is denied
[20:55:07.372] PASS  sandbox dir still exists after the refused rm
[20:55:07.372] VERDICT: izba reports the stuck teardown honestly on every surface
```

Eleven of eleven checks pass; `state.json` was still present afterwards and
the daemon's adoption sweep did not reap it. `stop` and `rm --force` each
took about 12 s: with the launcher gone, `stop` first re-sweeps the guarded
tree (a `TerminateProcess` on the stuck worker, which cannot take effect, plus
the bounded 10 s wait for it to die) and polls the tree for 2 s before it
refuses — the price of making an orphaned but still-RUNNING worker
recoverable through the same path. (The `exited=n/a` in the census is
cosmetic: under `pwsh` 7, `Get-Process -Id` does not return the exited-but-
present process, so the script falls back; the CIM row still shows it.)

**One thing observed on the way, outside #319.** The outer shell that ran the
check never got end-of-file on its stdout until `izba daemon stop` was issued
for that data root: the `izba daemon run` the first CLI call auto-spawned had
inherited the pipe, and a daemon supervising a degraded sandbox never
idle-exits. The moment the daemon stopped, the pipe drained — every run,
including with stdout redirected to a file (WSL interop still relays through
a pipe). `izba <anything> | <consumer>` on Windows therefore blocks the
consumer for as long as an auto-started daemon lives — filed as
[#326](https://github.com/Lupus/izba/issues/326).

## Limits

Everything was read unelevated; kernel stacks, non-File handle types and the
exit code of the exited process were not available. The spike's run log
(`izba-probe249-<pid>` output dir) was not retained, so the detach's own
duration and output are unknown. The files the worker holds were unlinked by
an outside cleanup on 2026-10-08 (see Validation), so the `rw.img` sharing
probe can no longer be re-run against this survivor; the process-tree facts
are unaffected.

## Follow-on work

- [#325](https://github.com/Lupus/izba/issues/325) — guest side: *Windows/
  OpenVMM: guest fails to power off with a vhci (usbip) device attached or
  mid-detach after sustained traffic — `stop` always escalates to kill*
  (`type:bug`, P3, M), from finding 4.
- [#326](https://github.com/Lupus/izba/issues/326) — Windows CLI: an
  auto-spawned `izba daemon run` inherits the caller's stdout
  pipe, so a piped `izba` command blocks its consumer until the daemon exits
  (see Validation) — filed separately.
- [#320](https://github.com/Lupus/izba/issues/320) — OpenVMM does not exit on
  guest power-off, so every Windows stop takes the kill path (unchanged here).
