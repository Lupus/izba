# 0002 — Why did the container state read `unknown` on Windows, and how slow is the probe?

Spike [#249](https://github.com/Lupus/izba/issues/249) (child of
[#193](https://github.com/Lupus/izba/issues/193)) · 2026-10-02 ·
script: [`hack/spike/container-probe-windows.ps1`](../../hack/spike/container-probe-windows.ps1) ·
tool: [`hack/spike/probe-latency/`](../../hack/spike/probe-latency/)

## Question

\#193 reported that on Windows/OpenVMM both `izba status` and the desktop app's
Overview tab said `container: unknown` for a sandbox whose workload was
demonstrably running (the console log showed `[OCI] container started OK`, and
`lsusb` and an interactive shell worked inside it). It offered two unverified
causes, both read off the commit trail:

1. **The probe times out on this platform.** The daemon bounds the guest
   round trip (`CONTAINER_PROBE_TIMEOUT`, 5 s) and answers `None` — rendered
   `unknown` — when it does not complete.
2. **Overlapping-poll skipping.** The app skips a poll tick while the previous
   one is in flight; if a probe never completes, a fresh one is never started.

So: what is the probe's real round-trip latency on a Windows/OpenVMM host
compared with its bound, and which cause — (1), (2), or something else — makes
`SandboxDetail.container` come back `None` there?

## Approach

Everything ran on the host #193 was reported from (Windows 11 25H2, build
26200.9457, OpenVMM/WHP), unelevated, driven from WSL over `powershell.exe`
interop, in throwaway data roots under `%TEMP%` — no sandbox under
`%LOCALAPPDATA%\izba` was started or modified.

**Two instruments**, because the rendered line cannot tell the interesting
cases apart — `None` and a guest-reported `ContainerState::Unknown` both print
`unknown`, and the daemon logs nothing when a probe fails:

- `izba status`, for the `container:` line a user sees and its wall time.
- `probe-latency`, a small tool built for this spike on `izba-core`'s public
  API. Per iteration it performs the sequence the daemon's probe performs
  (`sandbox::control`, which runs a liveness `Health` exchange and then dials
  the control port again; then one request/response), times each phase, and
  prints the raw guest reply plus what `SandboxDetail.container` would be:
  `none`, or `some:<state>` (so `some:unknown` is visibly not `none`). It also
  times one bare dial + round trip. `--request stats` does the same for the
  Stats probe. It talks to the guest directly; the daemon is not in the path.

**Builds and guests**, to separate "the code" from "that day":

| Label | izba.exe | Guest kernel + initramfs |
| --- | --- | --- |
| installed | `305a42d` (2026-09-30 installer) | its own bundle (6.18.43) |
| Aug-6 guest | `305a42d` | `vmlinux-usb` 6.12.30 + an initramfs built 2026-08-06 23:58, the pair staged for the USB e2e work the day before #193 was filed (still on disk in `dist/local/artifacts-usb-e2e/`), booted via `IZBA_KERNEL_USB` + `IZBA_INITRAMFS` |
| main | `main` at `8c871d44` plus the spike tool (pre-rebase build; `izba version` reads `dfe94c8`), cross-built `x86_64-pc-windows-gnu` | the installed bundle (no `izba-init`/`izba-proto` change between `305a42d` and `main`) |

The installed build matters because its probe is the code of the report date:
`probe_container_state`, `handle_inspect`'s probe call, `sandbox::control`,
`liveness_of`, `rpc`, `default_connector` and `live_run_dir` are identical
between the tree of that week (`12e5a5ed`, and `a2b31407` before it) and
`305a42d`. `main` matters because #305 has since rewritten the probe's time
bound (`DeadlineStream`) and no Windows test covers the container line. The
Aug-6 guest is the closest surviving thing to what was booted then; whether it
is byte-for-byte what ran on 2026-08-07 is not recorded anywhere.

**Scenarios:**

- fresh `alpine:3.20` and `ubuntu:24.04` sandboxes;
- the #193 shape: `ubuntu:24.04` + a USB grant (boots `vmlinux-usb`) + a device
  attached over the usbip plane (`hack/fake-usbipd`);
- a byte copy of the very sandbox #193 was observed on (`izba-test`: created in
  June, named volume, the original USB grant), in its own data root with the
  workspace repointed and its June image-cache entry repaired the way izba's
  own error message prescribes — installed build, today's bundle;
- the boot window (status polled as fast as it answers while `izba start`
  runs);
- overlapping probes (4 concurrent `izba status` pollers; 8 concurrent
  `probe-latency` workers);
- the daemon stopped and respawned while the sandbox runs, so it has to adopt
  the sandbox from disk;
- an `izba exec` held open; 1,500 sequential probes of one sandbox;
- a busy guest: busy loops on both vCPUs, continuous 1 GiB `dd … conv=fsync`
  writes, and a 40 s write loop through the attached USB device.

The committed script covers boot window, idle, overlapping probes, attached
device, daemon restart, busy guest and a 300-probe soak, through both probes,
and exits non-zero if any reading of the live sandbox is not `running`. It
refuses a data root that is not empty, and stops and removes only the sandbox
it created. It was run in full twice in the form committed here (main;
installed + Aug-6 guest).
The sandbox copy, the held-open exec, the 1,500-probe soak and the USB write
loop were one-off runs of its ad hoc predecessors; the script's opt-in
`IZBA_USB_TRAFFIC` branch reproduces that last one but has not itself been run.

## Findings

### 1. The probe takes milliseconds; the bound is 5 seconds

`probe_container_state` — the probe behind `izba status` — against real guests
on this host (ms; "probe" is the full sequence the daemon runs, "round trip" is
one dial + one `Health` exchange, which includes the guest forking
`crun state`):

| Condition | Build / guest | n | probe p50 | probe p95 | probe max | round trip p50 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| idle | main / bundle | 300 | 5.1 | 5.8 | 10.1 | 2.3 |
| idle | installed / bundle (alpine) | 300 | 5.8 | 7.4 | 21.3 | 2.6 |
| idle | installed / Aug-6 guest | 300 | 5.3 | 6.3 | 8.7 | 2.4 |
| 8 overlapping workers | main | 800 | 13.7 | 19.1 | 28.2 | 6.4 |
| USB device attached | main | 100 | 5.5 | 6.6 | 9.2 | 2.5 |
| write loop through the USB device (3,828 writes in 40 s) | main | 300 | 7.0 | 10.5 | 16.9 | 3.1 |
| busy loops on both vCPUs (load 4.0) | main | 300 | 8.0 | 10.5 | 14.6 | 3.7 |
| busy loops on both vCPUs | installed / Aug-6 guest | 300 | 7.5 | 9.8 | 17.5 | 3.0 |
| continuous 1 GiB fsync'd writes | main | 300 | 6.0 | 37.6 | 83.5 | 2.7 |
| continuous 1 GiB fsync'd writes | installed / Aug-6 guest | 300 | 5.6 | 41.9 | **85.3** | 2.5 |
| copy of the `izba-test` sandbox | installed / bundle | 60 | 5.6 | 9.0 | 13.4 | 2.6 |

**7,120 Health probe replicas, zero failures; the slowest took 85.3 ms —
1.7 % of the 5,000 ms bound** (59× headroom), and that was under continuous
disk writeback. Idle, the time goes about 3.6 ms to `sandbox::control` (the
liveness check's own `Health` round trip plus a second dial) and about 1.5 ms
to the probe's `Health` exchange; a bare dial through OpenVMM's hybrid-vsock
bridge is about 0.7 ms.

The Stats probe (`probe_guest_stats`, which feeds the desktop app's container
line today) is dominated by the guest's deliberate ~250 ms CPU sample: **80
probes on main, p50 257 ms idle and 260 ms with both vCPUs saturated, max
264.6 ms — 5.3 % of its 5,000 ms bound** (19× headroom).

`izba status` as a whole takes about 200 ms wall on this host (it lands on
100/200/300 ms steps; one call in 1,500 took 1,386 ms). That is not the probe:
`izba ls`, which probes no guest, takes the same ~190 ms.

### 2. Cause (1), "the probe is too slow on this platform", is refuted

The platform would have to be about fifty times slower than its worst
measurement under load. This says nothing about a *single guest* whose
`crun state` hung on one boot — see finding 5.

### 3. Cause (2), "overlapping-poll skipping", cannot print `unknown`

In the component #193 was observed in (`ContainerStatus.tsx`, as of
`12e5a5ed`), a skipped tick leaves the previous value on screen, and a
timed-out or failed `inspect` *hides* the line (`setContainer(undefined)`).
"unknown" was rendered only for a **successful** inspect whose `container` was
absent or was the guest's own `unknown`. The skip logic can make the line
stale or missing; it cannot make it say unknown. Four concurrent `izba status`
pollers (60 readings) and eight concurrent probe workers (800 probes, three
runs) never produced anything but `running`.

Today's Overview is different, and worth knowing about: `useStats` keeps the
skip, but a **failed** stats poll now marks the snapshot stale, and
`SandboxCard` renders a stale snapshot's container as `unknown`
(`fresh = stale ? null : stats`). So in the current app, any error from the
Stats call — not only a guest answer — prints "unknown" for a sandbox the last
good snapshot said was running.

### 4. The symptom does not reproduce

More than 2,000 `izba status` readings of live sandboxes, every one
`container: running`:

| Scenario | Build | Guest | `izba status` |
| --- | --- | --- | --- |
| fresh alpine / ubuntu | installed | bundle | running |
| ubuntu + USB grant (USB kernel) | installed | bundle | running |
| + device attached | installed, main | bundle | running |
| + device attached | installed | Aug-6 guest | running |
| copy of `izba-test`, device attached | installed | bundle | running |
| 4 overlapping pollers | installed | bundle | running ×60 |
| `izba exec … sleep` held open (no PTY) | installed | bundle | running |
| 1,500 probes of one sandbox | installed | bundle | running ×1,500; exec still works afterwards |
| boot window | main, installed | bundle, Aug-6 | `stopped`/`unknown` → `running`/`running`; none of 52 readings showed a non-stopped sandbox without `running` |
| daemon stopped and respawned (adoption from disk) | main, installed | bundle, Aug-6 | running ×20; exec works |
| saturated vCPUs; continuous fsync'd writes | main, installed | bundle, Aug-6 | running |
| USB write loop | main | bundle | running |

The raw guest reply was `"container":"running"` in all 7,120 Health probes, so
neither `None` nor a guest-reported `unknown` was ever seen.

What this matrix does **not** cover: the sandbox copy and the Aug-6 guest were
never combined with each other or with a host binary from August; no PTY
(`exec -it`) session was open; no long uptime; no host sleep/resume; and no
session in which a CLI and an app with different `DAEMON_PROTO_VERSION`s kept
respawning the daemon in turn — all of which describe the dogfooding afternoon
\#193 came from better than a fresh data root does.

### 5. Everything that can make a live sandbox read `unknown`

From `handle_inspect` / `probe_container_state` / `izba-init`'s `Health`
handler, the Inspect path (`izba status`, and the app until 2026-08-09):

| # | Mechanism | For the #193 observation |
| --- | --- | --- |
| A | the daemon's registry says the sandbox is stopped, so no probe is made | not recorded — the report does not quote the `status:` line. A fresh adoption after a daemon restart does not do it (finding 4) |
| B | `sandbox::control` fails: the liveness re-check says stopped, or the dial fails | exec goes through the same call and worked |
| C | the exchange fails or outlasts the 5 s bound: a wedged guest, a reset, or the report-date `set_io_timeout` call failing | platform latency refuted (finding 1); the `set_io_timeout` path works on the installed build; a `crun state` that *hung* in that one guest is not excluded |
| D | the reply is not a `Health`, or does not decode | the same binaries decode it today |
| E | the guest's `izba-init` predates `Health.container` (before 2026-06-24) | excluded by the report's own console quote: `container started OK (running after …ms)` was introduced by `e0058e17`, a descendant of the commit that added the field (`bdd01005`) |
| F | the guest answers `container: unknown` because its own `crun state izba` failed | not reproduced with the Aug-6 guest |
| G | the daemon predates the field (`SandboxDetail.container` is `serde(default)`) | excluded: the USB RPCs that worked that day need proto ≥ 4, long after the field |

E is what the report's *first* sighting was (a June initramfs), which it
already identified. For the sighting it filed, B, D, E and G are excluded;
**A, and a guest-side `crun state` that failed (F) or hung (C), remain — and
none of them leaves a trace.** \#193 describes the symptom as constant
("regardless of the truth"). A constant symptom that is gone on a fresh data
root, fresh daemon and freshly booted guest points at state these experiments
reset — the daemon/registry of that session, or the guest of that boot — or at
artifacts that were not the ones tested here.

The Stats path (the app's Overview since 2026-08-09) has its own routes on top:
a guest without `Request::Stats`, a `GuestStats` without `container`, and the
stale-poller rendering in finding 3.

### 6. One way to get `unknown` on a running workload today — and it is not the probe's speed

Booting the Aug-6 initramfs under the current build, the script goes red on
exactly one thing: all 80 Stats probes return `none`
(`reading the Stats response: clean EOF before frame`, after ~4 ms — a guest
that does not know `Request::Stats` closes the connection), while all 1,800
Health probes say `running`. The desktop app's Overview takes its container
line from Stats, so by the code that sandbox reads **`unknown` in the app and
`running` in `izba status`** (the app itself was not run here). This is
guest/host version skew through stale boot artifacts — the situation #194
describes, and the same class as #193's first sighting.

### 7. Why the original cannot be pinned down further

- **A failed probe is silent.** Every step of both probes ends in `.ok()?`;
  nothing is logged, so `daemon.log` holds no record of why a container line
  was ever unknown.
- **Different answers render identically.** `None` ("the host could not ask"),
  `Some(Unknown)` ("the guest could not tell") and, in the app, "the stats poll
  failed" all print `unknown`.
- **Nothing says which init was booted** (#194).
- **No test looks at the container line on Windows.** `validate-izba-windows.ps1`
  never asserts it, so nothing would have caught a regression, and nothing
  shows whether it ever worked on the report date.

### 8. Two unrelated defects found on the way

**`izba stop` always takes 10–12 s on Windows.** All eleven clean stops logged
(installed and main) took 10.2–11.7 s. Timed against the host clock in two of
them: the guest console shows `reboot: Power down` 0.13 s and 0.28 s after the
request, but the VMM process is still there until 10.1 s — the moment the 10 s
graceful wait in `stop_locked` gives up and kills it. OpenVMM does not exit
when the guest powers off, so every stop on Windows ends in the kill
escalation.

**A terminated VMM worker that never finishes exiting goes unnoticed.** On
Windows a sandbox is two `openvmm.exe` processes: the one izba spawns and
records in `state.json` (~15 MB), and a worker child that holds the partition,
the disks and the sockets. One run (the USB write loop, then CPU saturation and
a 3 GB write) was stopped while its guest never got as far as `Power down`.
`stop` took 20.4 s — the 10 s graceful wait plus a `TERMINATION_WAIT_MS` that
ran out — and returned 0; izba then removed `state.json` and the run dir. The
worker was still there twenty-five minutes later: `HasExited=True`, one thread
left in a kernel `Wait:Executive`, all 255 handles open including
`\Device\VidExo` and `rw.img`, 3.3 GB working set — so `izba rm --force`
failed with `Access is denied`. `kill_pid` terminates the worker in its
descendant sweep (`terminate_quiet`), which discards the result of its wait;
the "VMM survived SIGKILL — state preserved" guard in `stop_locked` looks only
at the recorded pid, and Windows `pid_alive` reads the exit code, which
`TerminateProcess` sets at once. So a worker that is terminated but not torn
down is invisible to izba while it keeps the sandbox's disks locked. It
happened once in twelve stops and was not re-triggered on purpose (the process
cannot be killed a second time); both full runs of the committed script, which
check every `openvmm.exe` they started, ended with all of them gone.

### Dead ends

- The session transcript that filed #193 is no longer on disk, and Windows
  `daemon.log` keeps no request history, so the original `status:` line and the
  exact binaries of that afternoon are not recoverable.
- A per-probe leak was a promising fit for "permanently unknown on a
  long-polled sandbox"; 1,500 probes in a row all read `running` and exec still
  worked afterwards. (No fd or thread count was taken inside the guest.)
- An `izba exec` held open does not block the guest's `crun state`.

## Recommendation

Neither candidate cause is real: the probe is fifty-odd times faster than its
bound under the worst load tried, and poll skipping cannot print `unknown`.
The symptom is absent on the installed build and on `main`, and what did cause
it on 2026-08-07 is not recoverable — the product kept no trace. So the
sibling fix item (#251) has no identified defect to fix; re-scope it to the
two things that were actually missing:

1. **Regression coverage on the Windows leg** — assert `container: running`
   for a booted sandbox in `validate-izba-windows.ps1` (the Health path), and
   cover the Stats-fed value the app shows. This is the tripwire #193 never
   had; if the symptom is real and state-dependent, this is what will catch it
   with evidence attached.
2. **Make `unknown` say why** — in `handle_inspect` / `handle_stats`, keep the
   reason a probe returned nothing (stopped per the registry, control dial
   failed, deadline passed, connection closed, undecodable or unexpected
   reply) and log it; and stop rendering "the host could not ask", "the guest
   answered unknown" and "the stats poll failed" as the same word. With that
   in place the next sighting is a one-line diagnosis instead of a spike.
   Additive `serde(default)` fields; whether it needs a `DAEMON_PROTO_VERSION`
   bump follows the rule #297 set (an absent field must not read as a healthy
   answer).

The time bound itself should stay exactly as it is.

\#193 should stay open until (1) is in. If it is then closed, the closing note
should say what was *not* excluded: a stale registry (A) and a guest-side
`crun state` that failed or hung (F, C), in a long-lived dogfooding session
this spike did not recreate. #194 (artifact provenance) is the fix for the one
route to "`unknown` while running" that was reproduced here.

## Follow-on Work

Proposed; none filed yet (awaiting sign-off):

- **Re-scope #251** as described above (coverage + "say why it is unknown"),
  instead of a new item.
- **New — Windows: `izba stop` always waits out the full 10 s graceful
  timeout** because OpenVMM does not exit when the guest powers off, which
  happens within 0.3 s (`type:performance`, P3, S).
- **New — Windows: a terminated VMM worker stuck in process teardown goes
  unnoticed**; `stop` reports success, `state.json` is removed, the disks stay
  locked and `rm` fails (`type:reliability`, P2, M). Includes finding out why
  the guest did not power off after sustained usbip traffic.
- **Existing #194** — no change in scope; this spike adds a reproduced case
  for it (finding 6).
