# Sandbox Stats & Overview Facelift — Design

Date: 2026-08-08
Status: approved (owner sign-off in session; "four-card dashboard" layout)
Issues: closes #203 (docker engine readiness visibility); GUI Overview facelift

## 1. Goal

Turn the GUI sandbox Overview tab into a four-card dashboard showing, per
sandbox: docker engine status, resource usage vs limits (CPU/memory), process
count + a read-only mini-top, and storage usage — how much host disk the
sandbox occupies and how much of that is docker. Clean, easy to grasp, not
cluttered. GUI-only surface (no new CLI command), except `izba status` gains an
`engine:` line for docker-mode sandboxes (the #203 closure).

## 2. Trust model (governs everything below)

Every number shown comes from one of two tiers:

- **Host tier — trusted.** Derived on the host from `/proc/<vmm_pid>` and the
  sandbox's on-disk files. Available even when the sandbox is stopped (disk)
  or the guest is wedged (CPU/RSS). Primary numbers (bars) use this tier.
- **Guest tier — untrusted.** Reported by izba-init over a new control RPC.
  The guest is hostile (see docs/security/): every guest-supplied string is
  sanitized and every guest-supplied list truncated **at the daemon boundary**
  before entering `SandboxStats`. The GUI labels guest data ("guest-reported")
  and renders it as secondary information.

Sanitization contract (daemon boundary, applied to all guest strings):
strip ASCII control chars (anything < 0x20 except none — no tabs/newlines
survive) and non-ASCII is allowed but length-capped; cap process `comm` at 32
chars, docker `detail` at 256 chars; truncate the process list to at most 15
entries regardless of what the guest sent. A guest that lies about numbers can
only mislead its own stats display, never break the host or other sandboxes.

## 3. Guest RPC: `Request::Stats` (vsock 1025)

New variant on `izba_proto::Request`, served by izba-init's control server.
Response: `Response::Stats(GuestStats)`.

```rust
// izba-proto
pub struct GuestStats {
    pub processes: Vec<ProcSample>,   // top 15 by CPU, descending
    pub process_count: u32,           // total live processes in guest
    pub load1_centi: u32,             // loadavg × 100 (1/5/15 min)
    pub load5_centi: u32,
    pub load15_centi: u32,
    pub mem_total_kb: u64,            // /proc/meminfo MemTotal
    pub mem_available_kb: u64,        // /proc/meminfo MemAvailable
    pub mounts: Vec<MountUsage>,      // statfs per interesting mount
    pub docker: Option<DockerEngine>, // Some(..) only when izba.docker=1
    pub container: Option<ContainerState>, // same info as Health, saves a round-trip
}
pub struct ProcSample {
    pub pid: u32,
    pub comm: String,       // /proc/<pid>/comm, guest-controlled
    pub state: char,        // R/S/D/Z/T…
    pub cpu_permille: u32,  // share of ONE cpu, 0..=1000×ncpu
    pub rss_kb: u64,
}
pub struct MountUsage {
    pub path: String,        // guest mountpoint, e.g. "/", "/var/lib/docker"
    pub total_bytes: u64,
    pub avail_bytes: u64,
}
pub struct DockerEngine {
    pub running: bool,          // a live `dockerd` process exists
    pub detail: Option<String>, // when !running: bounded tail of ENGINE_LOG
}
```

Collection (izba-init, all host-testable through an injectable procfs/statfs
seam — **no listeners in unit tests**, per the repo test-design constraint):

- **CPU% is computed inside the call**: sample `utime+stime` per PID from
  `/proc/<pid>/stat` twice, ~250 ms apart, and report the delta over the
  interval. The RPC stays stateless — no cross-call cache in init, no PID-reuse
  hazard. The 250 ms latency is invisible at a 3 s poll cadence.
- Process scan covers the whole guest: the workload container has its own pid
  namespace, but pidns is hierarchical — init's `/proc` sees every process.
- Mounts reported: `/rootfs` (the overlay upper — the writable layer's
  filesystem-level fullness) and each user-volume mountpoint (from the
  already-parsed `izba.volumes` list), reported under their *guest* paths
  (`/`, `/var/lib/docker`, …).
- Docker engine detection (docker mode only): scan `/proc/<pid>/comm` for a
  live `dockerd`. When absent, read the last ≤256 bytes of
  `/var/log/izba-dockerd.log` (init-root path) as `detail` — that log already
  distinguishes "image ships no dockerd" from a crashed engine.
- `container` mirrors what `Health` reports today, so the daemon's stats
  handler needs exactly **one** guest round-trip.

Adding a `Request` variant is additive for the guest protocol (host and guest
ship from the same tree; an old guest replying `Error` to an unknown variant
degrades to `guest: None`, which the UI already handles as "not responding").

## 4. Daemon RPC: `DaemonRequest::Stats { name }`

Response: `DaemonResponse::Stats(SandboxStats)`. **`DAEMON_PROTO_VERSION` 4 → 5**
(new request variant; a stale daemon is auto-restarted by the hello check, so
the bump is self-healing).

```rust
// izba-core daemon proto
pub struct SandboxStats {
    pub name: String,
    pub running: bool,
    pub uptime_ms: Option<u64>,      // host-derived from vmm_pid starttime
    pub host: Option<HostResources>, // None when stopped or non-Linux host
    pub disk: HostDisk,              // always present (host files exist)
    pub guest: Option<GuestStats>,   // None: stopped / unreachable / timeout
}
pub struct HostResources {
    pub cpu_permille: Option<u32>, // VMM process; None on the first sample
    pub rss_kb: u64,               // VMM VmRSS — the sandbox's real host cost
    pub cpus_limit: u32,           // config.cpus (denominator for the bar)
    pub mem_limit_mb: u32,         // config.mem_mb
}
pub struct HostDisk {
    pub rw_img_bytes: u64,            // allocated (sparse-aware) rw.img
    pub volumes: Vec<VolumeDisk>,     // per attached volume
    pub logs_bytes: u64,              // logs dir walk
    pub image_bytes: u64,             // rootfs.erofs size — labeled shared
}
pub struct VolumeDisk {
    pub guest_path: String,
    pub allocated_bytes: u64,
    pub docker: bool, // guest_path == volume::DOCKER_VOLUME_PATH
}
```

Handler behavior:

- **CPU%**: the daemon keeps an ephemeral in-memory map
  `name → (cpu_ticks, instant)` from the previous Stats call and reports the
  delta. This cache is *not* authoritative state (disk-state invariant intact):
  it is derived, per-process-lifetime, and its loss only costs one `None`
  sample. Keyed by `PidIdentity` so a VMM restart never splices two processes'
  tick counters.
- **RSS** from `/proc/<pid>/status` VmRSS; PID validity re-verified via the
  existing `PidIdentity` starttime check first. All `/proc` reading is
  `cfg(target_os = "linux")`; elsewhere `host: None` (the windows-gnu
  cross-gate must stay green; Windows host resources are a follow-up).
- **Disk** works for stopped sandboxes: `allocated_bytes()` (existing helper,
  `blocks()*512` on unix, `len()` fallback elsewhere) on `rw.img` and each
  volume image; a bounded walk of the logs dir; the content-addressed
  `rootfs.erofs` size reported separately as `image_bytes` because it is
  **shared** between sandboxes on the same image — the GUI must not sum it
  into the per-sandbox footprint headline.
- **Guest fetch** is time-bounded (same discipline as the container-state
  probe — a wedged guest returns `guest: None`, never a hung daemon reply),
  then sanitized per §2. The guest's 16 MiB `MAX_FRAME` budget means the
  daemon must truncate lists/strings *after* deserialize, and cap the frame
  it will read from the guest where the existing client supports it.

## 5. #203: engine visibility in `izba status`

For a docker-mode sandbox (`det.docker`), `izba status` additionally issues
`DaemonRequest::Stats` and prints under the existing `mode:` line:

```
mode:        docker (nested Docker Engine)
engine:      running
```

or `engine:      not running (…first line of detail…)` / `engine:      unknown
(guest not responding)`. Non-docker sandboxes and stopped sandboxes print no
`engine:` line. Detail strings are already daemon-sanitized (§2) — the CLI
prints them as-is but single-line.

## 6. Tauri layer

- `DaemonApi` gains `fn stats(&mut self, name: &str) -> Result<SandboxStats>`;
  `RealDaemon` implements it; `FakeDaemon` returns configurable fixtures.
- New `#[tauri::command] stats(name)` on the shared poll connection (safe: the
  daemon-side guest probe is time-bounded), exposed via a `stats_core`
  function testable against `FakeDaemon` like the existing commands.
- `views.rs`: new `SandboxStatsView` (camelCase JSON: `hostCpuPermille`,
  `rssKb`, byte fields, `dockerEngine: { running, detail } | null`, processes
  array, etc.) with a `From<SandboxStats>` impl + mapping tests.
- `SandboxDetailView` finally carries what it drops today: `docker: bool`,
  `cpus: u32`, `memMb: u32`, `confinement: string | null` — the Sandbox card
  needs them.

## 7. GUI: the four-card dashboard

Approved layout (Overview tab):

```
┌ ● web — ghcr.io/…/node:20 ────────── [Start][Stop][Restart][Remove] ┐
│ ┌─ Sandbox ────────────────────┐  ┌─ Resources ──────────────────┐  │
│ │ state        running · 2h 14m│  │ CPU   ▮▮▮▯▯▯▯▯▯▯  34%  4 vCPU│  │
│ │ container    running         │  │ MEM   ▮▮▮▮▮▮▯▯▯▯  2.5/4 GiB  │  │
│ │ confinement  confined        │  │       guest: 1.9 GiB used    │  │
│ │ firewall     enforcing · 12  │  │ load 0.42 · 61 processes     │  │
│ │ docker       ● engine running│  └──────────────────────────────┘  │
│ │ workspace    ~/git/web       │                                    │
│ └──────────────────────────────┘                                    │
│ ┌─ Storage · 3.8 GiB on host ──────────────────────────────────────┐│
│ │ [■■■■■■■□□□□□□□]  segmented: docker/writable/volumes/logs        ││
│ │ ■ docker 2.1 GiB (21% of 10 GiB)  ■ writable layer 1.2 GiB       ││
│ │ ■ volumes 410 MiB  ■ logs 12 MiB   + image 890 MiB (shared)      ││
│ └──────────────────────────────────────────────────────────────────┘│
│ ┌─ Processes · guest-reported ─────────────────────────────────────┐│
│ │  PID  NAME             CPU%    MEM      (top 10, monospace,      ││
│ │  812  node             42.1    312 MiB   CPU-sorted, total count)││
│ └──────────────────────────────────────────────────────────────────┘│
```

Components (all new files under `app/src/components/overview/`):

- `SandboxCard` — state + uptime, container line (absorbs the current
  `ContainerStatus` rendering, fed from the stats poll — no own poller),
  confinement, firewall (existing `FirewallStatus` badge moves in), docker
  engine row (only in docker mode; success/destructive/muted dot), workspace.
- `ResourcesCard` — CPU bar: host `cpu_permille / (cpus_limit×1000)`; MEM bar:
  host `rss_kb` vs `mem_limit_mb`; secondary line "guest: X used of Y"
  (guest-reported); "load L1 · N processes". Bars: 4 px, `bg-success`, amber
  ≥ 80 %, `bg-destructive` ≥ 95 % — thresholds in one exported, unit-tested
  helper (`meterTone(fraction)`), used by every bar (mutation-gate lesson:
  the rule and its call sites share one tested predicate).
- `StorageCard` — headline "X on host" = rw_img + Σvolumes + logs (image
  excluded — shared); one segmented horizontal bar (docker / writable /
  volumes / logs) + legend rows with human bytes (`formatBytes` helper,
  binary units, tested); docker legend row adds "(N % of `limit`)" from guest
  statfs when available; trailing muted "+ image … (shared)".
- `ProcessesCard` — monospace top-10 table (PID, NAME, CPU %, MEM), caption
  "guest-reported", footer "N total". React escaping + daemon sanitization
  make hostile comms inert; the card never grows past 10 rows.
- `useStats(name, intervalMs = 3000)` hook — single poller for the whole tab:
  `setInterval` + in-flight guard (reply-race lesson) + unmount guard;
  returns `{ stats, error, phase }`.

Degraded states (all explicitly designed, all tested):

- **Stopped**: Sandbox + Storage cards fully live (host data); Resources and
  Processes render a quiet muted "not running" body.
- **Running, guest unreachable** (`guest: null`): CPU/MEM bars still live
  (host tier); Processes card shows "guest not responding"; docker row shows
  "engine unknown".
- **Docker engine down**: "● engine not running — see logs" (destructive dot),
  detail as tooltip/secondary text.
- Non-docker sandbox: no docker row, no docker storage segment.

Style: existing vocabulary only — shadcn `Card`, current Tailwind tokens,
two-column grid (`grid gap-4 md:grid-cols-2`, Storage + Processes span both),
big-number/small-label typography, `text-muted-foreground-2` secondary text.
Action buttons move from the tab body to the detail header row. No new
dependencies.

## 8. Testing

- **izba-init**: stats collector against a fake procfs tree in a tempdir
  (stat parsing incl. comm-with-spaces/parens, CPU delta math, top-15
  selection, meminfo, loadavg, dockerd detection present/absent/log-tail);
  no sockets.
- **izba-proto**: serde round-trips for every new type; unknown-variant
  behavior documented by test.
- **izba-core**: daemon handler unit tests with tempdir sandbox layouts
  (sparse-file allocation vs len, docker-volume identification via
  `DOCKER_VOLUME_PATH`, logs walk, image_bytes separation); CPU-cache delta +
  PidIdentity-keying test; sanitization tests (control chars, oversized comm,
  1000-process truncation to 15).
- **app/src-tauri**: `views.rs` mapping tests; `stats_core` against
  `FakeDaemon`; `SandboxDetailView` extension test.
- **app/src (vitest)**: per-card tests for every degraded state above +
  threshold tones + byte formatting; Overview composition test (single
  poller, cards present).
- **KVM e2e** (env-gated): running sandbox returns plausible stats (process
  count ≥ 1, mem_total > 0, rw_img_bytes > 0); docker-mode sandbox reports
  `engine running` after boot settle; `izba status` shows the `engine:` line.
- All six workspace gates + the separate app gate; mutation-gate discipline:
  every guard expression that appears at >1 call site is a named, tested
  helper.

## 9. Out of scope (explicit)

- Windows host-resource tier (`host: None` there; disk + guest tiers work).
- Kill-from-UI, sortable process table, historical charts.
- A `izba stats` CLI command (RPC makes it trivial later).
- dockerd auto-restart or health-gating lifecycle (visibility only — the
  engine stays fire-and-forget per the docker-mode spec).
- Absorbing the Rail/list poller (only the Overview tab's pollers merge).
