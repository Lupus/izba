# Sandbox Stats & Overview Facelift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new trust-tiered stats plane (guest `Request::Stats` RPC + daemon `DaemonRequest::Stats`) feeding a four-card GUI Overview dashboard (sandbox / resources / storage / processes) and an `engine:` line in `izba status` (closes #203).

**Architecture:** izba-init collects guest stats from `/proc` (stateless RPC, two-sample CPU inside the call); izbad combines them with trusted host-tier data (VMM `/proc/<pid>`, sparse-aware disk sizes) and sanitizes every guest string/list at the daemon boundary; the Tauri app maps the wire type to a view and renders four cards fed by one shared poller. Spec: `docs/superpowers/specs/2026-08-08-sandbox-stats-overview-facelift-design.md`.

**Tech Stack:** Rust (izba-proto / izba-init / izba-core / izba-cli / app/src-tauri), React + TypeScript + Tailwind + shadcn (app/src), vitest + testing-library, cargo test.

## Global Constraints

- All six workspace gates green before every commit: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, musl izba-init build, windows-gnu `cargo check` + clippy for izba-proto/izba-core/izba-cli. Tasks touching `app/` additionally run the app gate: `cd app && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)` and `npx vitest run` for frontend tests.
- Unit tests never bind unix/vsock listeners (sandbox denies bind with EPERM). Use `UnixStream::pair()` fakes; tests that need a listener must runtime-skip on `PermissionDenied`.
- The guest is hostile: every guest-supplied string is sanitized and every guest-supplied list truncated at the daemon boundary (Task 4's `sanitize_guest_stats`), before the data reaches CLI or GUI.
- `DAEMON_PROTO_VERSION` goes 4 → 5 exactly once (Task 4). No other wire-frame change may piggyback unbumped.
- Host `/proc` reading in izba-core is `#[cfg(target_os = "linux")]`; non-Linux returns `None` — the windows-gnu cross-gates must stay green.
- Any guard expression used at more than one call site must be a named, unit-tested helper (mutation-gate discipline).
- TDD: write the failing test first in every step pair. Conventional commits (`feat(init): …`, `feat(core): …`, `feat(app): …`).
- Sanitization caps (single source of truth, Task 4): 15 processes, 32 mounts, comm ≤ 32 chars, docker detail ≤ 256 chars, mount path ≤ 128 chars; control characters stripped from all guest strings.
- View JSON uses snake_case field names (matches existing `SandboxDetailView` / `VolumeSpecView` convention), NOT camelCase.

---

### Task 1: izba-proto stats wire types

**Files:**
- Modify: `crates/izba-proto/src/messages.rs` (types + `Request::Stats` + `Response::Stats`)
- Modify: `crates/izba-proto/src/lib.rs` (re-export the new types alongside the existing ones)

**Interfaces:**
- Consumes: existing `Request`/`Response` enums, `ContainerState`.
- Produces (later tasks rely on these exact shapes): `GuestStats { processes: Vec<ProcSample>, process_count: u32, load1_centi: u32, load5_centi: u32, load15_centi: u32, mem_total_kb: u64, mem_available_kb: u64, mounts: Vec<MountUsage>, docker: Option<DockerEngine>, container: Option<ContainerState> }`, `ProcSample { pid: u32, comm: String, state: char, cpu_permille: u32, rss_kb: u64 }`, `MountUsage { path: String, total_bytes: u64, avail_bytes: u64 }`, `DockerEngine { running: bool, detail: Option<String> }`, `Request::Stats`, `Response::Stats(GuestStats)`.

- [ ] **Step 1: Write the failing serde round-trip test**

At the bottom of `crates/izba-proto/src/messages.rs` (create a `#[cfg(test)] mod tests` there if none exists in that file; check first — codec tests live in `codec.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_request_and_response_round_trip() {
        let req = Request::Stats;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"stats\""), "snake_case tag: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Stats));

        let resp = Response::Stats(GuestStats {
            processes: vec![ProcSample {
                pid: 812,
                comm: "node".into(),
                state: 'R',
                cpu_permille: 421,
                rss_kb: 319_488,
            }],
            process_count: 61,
            load1_centi: 42,
            load5_centi: 30,
            load15_centi: 19,
            mem_total_kb: 4_046_412,
            mem_available_kb: 2_012_004,
            mounts: vec![MountUsage {
                path: "/var/lib/docker".into(),
                total_bytes: 10 * 1024 * 1024 * 1024,
                avail_bytes: 8 * 1024 * 1024 * 1024,
            }],
            docker: Some(DockerEngine {
                running: true,
                detail: None,
            }),
            container: Some(ContainerState::Running),
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        match back {
            Response::Stats(g) => {
                assert_eq!(g.processes.len(), 1);
                assert_eq!(g.processes[0].comm, "node");
                assert_eq!(g.process_count, 61);
                assert_eq!(g.docker.as_ref().unwrap().running, true);
                assert_eq!(g.container, Some(ContainerState::Running));
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn old_guest_rejects_stats_request_as_unknown_variant() {
        // A pre-stats guest deserializing `{"type":"stats"}` fails at serde —
        // its control loop replies nothing and drops the conn, which the
        // daemon maps to `guest: None`. Documented here: the request tag must
        // stay exactly "stats" so this failure mode is stable.
        let s = serde_json::to_string(&Request::Stats).unwrap();
        assert_eq!(s, r#"{"type":"stats"}"#);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-proto stats_request` — FAILS: `GuestStats` not found.

- [ ] **Step 3: Add the types and variants**

In `crates/izba-proto/src/messages.rs`, after the `HealthInfo` struct:

```rust
/// One process in the guest's mini-top, reported by init's `/proc` scan.
/// All fields are guest-reported and therefore UNTRUSTED: the daemon
/// sanitizes `comm` and truncates the containing list before anything
/// host-side renders it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcSample {
    pub pid: u32,
    /// `/proc/<pid>/comm` — guest-controlled bytes.
    pub comm: String,
    /// Kernel state char (R/S/D/Z/T/…).
    pub state: char,
    /// CPU share over the sampling interval, in permille of ONE cpu
    /// (a multi-threaded process can exceed 1000).
    pub cpu_permille: u32,
    pub rss_kb: u64,
}

/// Filesystem-level fullness of one guest mount (statfs), under its guest
/// path (`/`, `/var/lib/docker`, …). Guest-reported, untrusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountUsage {
    pub path: String,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

/// Nested Docker Engine liveness as observed by init (a live `dockerd`
/// process in the guest's pid namespace tree). Present only when the
/// sandbox booted with `izba.docker=1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerEngine {
    pub running: bool,
    /// When `!running`: a bounded tail of the engine log, so the host can
    /// say WHY (crashed vs "image ships no dockerd"). Guest-controlled.
    pub detail: Option<String>,
}

/// Guest-side stats payload for [`Request::Stats`]. Everything here is
/// guest-reported: the host treats it as display data, never as authority.
/// CPU percentages are computed inside the call (two `/proc` samples
/// ~250 ms apart), so the RPC is stateless.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestStats {
    /// Top processes by CPU over the sampling interval, descending.
    pub processes: Vec<ProcSample>,
    /// Total live processes in the guest (all pid namespaces — init's
    /// `/proc` sees the workload container's tree too).
    pub process_count: u32,
    /// Load averages × 100 (`/proc/loadavg`).
    pub load1_centi: u32,
    pub load5_centi: u32,
    pub load15_centi: u32,
    /// `/proc/meminfo` MemTotal / MemAvailable.
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub mounts: Vec<MountUsage>,
    /// `Some` only when the guest booted with `izba.docker=1`.
    pub docker: Option<DockerEngine>,
    /// Same container state `Health` reports — lets the daemon serve both
    /// from one guest round-trip.
    pub container: Option<ContainerState>,
}
```

Add to `Request` (after `UsbDetach`):

```rust
    /// Guest resource stats for the host's status surfaces: mini-top,
    /// memory, load, mount fullness, docker-engine liveness. Read-only,
    /// side-effect-free; the reply is UNTRUSTED guest data which izbad
    /// sanitizes before display. Takes ~250 ms (in-call CPU sampling).
    Stats,
```

Add to `Response` (after `UsbAttached`):

```rust
    Stats(GuestStats),
```

Re-export in `crates/izba-proto/src/lib.rs` next to the existing `messages` re-exports: `DockerEngine`, `GuestStats`, `MountUsage`, `ProcSample`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-proto` — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-proto/src/messages.rs crates/izba-proto/src/lib.rs
git commit -m "feat(proto): guest Stats RPC wire types (mini-top, mounts, docker engine)"
```

---

### Task 2: izba-init stats collector (pure, procfs-seamed)

**Files:**
- Create: `crates/izba-init/src/stats.rs`
- Modify: `crates/izba-init/src/main.rs` (add `mod stats;` — actually `stats` must be in the library if server.rs is lib-side; check: `server.rs` is `crates/izba-init/src/server.rs` referenced via `izba_init::` paths in places — put `pub mod stats;` wherever `usb`/`net` modules are declared (`src/lib.rs` if it exists, else `main.rs`); follow the existing pattern for `docker.rs`.)

**Interfaces:**
- Consumes: `izba_proto::{GuestStats, ProcSample, MountUsage, DockerEngine}` (Task 1).
- Produces (Task 3 relies on): `pub struct StatsContext { pub procfs: PathBuf, pub rootfs: PathBuf, pub volume_paths: Vec<String>, pub docker: bool, pub engine_log: PathBuf, pub clk_tck: u64, pub page_kb: u64 }`, `pub fn collect(ctx: &StatsContext) -> GuestStats` (fills everything except `container`, which stays `None` for the dispatch site to set), plus pure internals: `ProcRaw`, `scan_procs`, `parse_stat_line`, `compute_processes`, `parse_meminfo`, `parse_loadavg`, `collect_mounts`, `engine_status`, `log_tail`.

- [ ] **Step 1: Write the failing tests**

Create `crates/izba-init/src/stats.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake_proc(dir: &std::path::Path, pid: u32, comm: &str, state: char, ticks: u64, rss_pages: u64) {
        let d = dir.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        // Real /proc/<pid>/stat layout: pid (comm) state ppid pgrp session
        // tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
        // We put all ticks in utime and zero stime; rss is field 24.
        let rest = format!(
            "{state} 1 1 1 0 -1 4194560 100 0 0 0 {ticks} 0 0 0 20 0 1 0 300 10000000 {rss_pages} 18446744073709551615"
        );
        fs::write(d.join("stat"), format!("{pid} ({comm}) {rest}\n")).unwrap();
    }

    #[test]
    fn parse_stat_line_survives_hostile_comm() {
        // comm may contain spaces AND parens: parse from the LAST ')'.
        let line = "42 (a (b) c) R 1 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 1 0 300 1000 55 0";
        let p = parse_stat_line(line).unwrap();
        assert_eq!(p.comm, "a (b) c");
        assert_eq!(p.state, 'R');
        assert_eq!(p.ticks, 10); // utime 7 + stime 3
        assert_eq!(p.rss_pages, 55);
    }

    #[test]
    fn parse_stat_line_rejects_garbage() {
        assert!(parse_stat_line("").is_none());
        assert!(parse_stat_line("1 (x").is_none());
        assert!(parse_stat_line("1 (x) R 1").is_none());
    }

    #[test]
    fn scan_procs_reads_numeric_dirs_only() {
        let t = tempfile::tempdir().unwrap();
        fake_proc(t.path(), 1, "init", 'S', 5, 100);
        fake_proc(t.path(), 812, "node", 'R', 50, 200);
        fs::create_dir_all(t.path().join("sys")).unwrap(); // non-numeric: skipped
        let procs = scan_procs(t.path());
        assert_eq!(procs.len(), 2);
    }

    #[test]
    fn compute_processes_delta_and_top_selection() {
        // 20 procs; proc N gains N ticks over the interval. Top 15 must be
        // pids 20..=6 descending; process_count counts the AFTER snapshot.
        let before: Vec<ProcRaw> = (1..=20)
            .map(|i| ProcRaw { pid: i, comm: format!("p{i}"), state: 'S', ticks: 1000, rss_pages: 10 })
            .collect();
        let after: Vec<ProcRaw> = (1..=20)
            .map(|i| ProcRaw { pid: i, comm: format!("p{i}"), state: 'S', ticks: 1000 + i as u64, rss_pages: 10 })
            .collect();
        // clk_tck 100, interval 250 ms, page 4 KiB.
        let (samples, count) = compute_processes(&before, &after, 250, 100, 4);
        assert_eq!(count, 20);
        assert_eq!(samples.len(), 15);
        assert_eq!(samples[0].pid, 20);
        // 20 ticks over 25 available (100 Hz × 0.25 s) = 800 permille.
        assert_eq!(samples[0].cpu_permille, 800);
        assert_eq!(samples[0].rss_kb, 40); // 10 pages × 4 KiB
        assert_eq!(samples[14].pid, 6);
    }

    #[test]
    fn compute_processes_new_pid_counts_from_zero() {
        // A pid present only in the AFTER snapshot must not credit its whole
        // cumulative tick count as interval CPU.
        let before = vec![];
        let after = vec![ProcRaw { pid: 9, comm: "fresh".into(), state: 'R', ticks: 1_000_000, rss_pages: 1 }];
        let (samples, _) = compute_processes(&before, &after, 250, 100, 4);
        assert_eq!(samples[0].cpu_permille, 0);
    }

    #[test]
    fn parse_meminfo_extracts_total_and_available() {
        let s = "MemTotal:        4046412 kB\nMemFree:          1000 kB\nMemAvailable:    2012004 kB\n";
        assert_eq!(parse_meminfo(s), (4_046_412, 2_012_004));
    }

    #[test]
    fn parse_loadavg_to_centi() {
        assert_eq!(parse_loadavg("0.42 0.30 1.19 2/61 812\n"), (42, 30, 119));
        assert_eq!(parse_loadavg("garbage"), (0, 0, 0));
    }

    #[test]
    fn engine_status_detects_dockerd_process() {
        let procs = vec![ProcRaw { pid: 7, comm: "dockerd".into(), state: 'S', ticks: 0, rss_pages: 0 }];
        let t = tempfile::tempdir().unwrap();
        let e = engine_status(&procs, &t.path().join("nolog"));
        assert!(e.running);
        assert!(e.detail.is_none());
    }

    #[test]
    fn engine_status_reports_log_tail_when_dead() {
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("d.log");
        fs::write(&log, "boot\nfailed to start daemon: no such cgroup\n").unwrap();
        let e = engine_status(&[], &log);
        assert!(!e.running);
        let d = e.detail.unwrap();
        assert!(d.contains("no such cgroup"), "{d}");
    }

    #[test]
    fn log_tail_is_bounded() {
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("d.log");
        fs::write(&log, "x".repeat(10_000)).unwrap();
        assert!(log_tail(&log).unwrap().len() <= 256);
    }

    #[test]
    fn collect_mounts_reports_guest_paths() {
        // statfs seam: the injected fn records which real path was probed and
        // returns fixed numbers; the report must carry GUEST paths.
        let probed = std::cell::RefCell::new(Vec::new());
        let mounts = collect_mounts(
            std::path::Path::new("/rootfs"),
            &["/var/lib/docker".to_string()],
            &|p| {
                probed.borrow_mut().push(p.to_path_buf());
                Some((100, 40))
            },
        );
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].path, "/");
        assert_eq!(mounts[1].path, "/var/lib/docker");
        assert_eq!(mounts[1].total_bytes, 100);
        assert_eq!(mounts[1].avail_bytes, 40);
        let probed = probed.borrow();
        assert_eq!(probed[0], std::path::Path::new("/rootfs"));
        assert_eq!(probed[1], std::path::Path::new("/rootfs/var/lib/docker"));
    }
}
```

(`tempfile` is already a dev-dependency of izba-init — verify in its `Cargo.toml`; add under `[dev-dependencies]` if missing.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init stats` — FAILS: functions not defined.

- [ ] **Step 3: Implement the collector**

Above the test module in `crates/izba-init/src/stats.rs`:

```rust
//! Guest-side stats collection for `Request::Stats` (see the design spec
//! `docs/superpowers/specs/2026-08-08-sandbox-stats-overview-facelift-design.md`).
//!
//! Everything here reads through an injectable procfs root / statfs fn so the
//! whole module is host-testable without a VM (and without binding sockets).
//! CPU shares are computed from two `/proc` samples taken ~250 ms apart
//! INSIDE `collect` — the RPC stays stateless: no cross-call cache, no
//! PID-reuse hazard.

use izba_proto::{DockerEngine, GuestStats, MountUsage, ProcSample};
use std::path::{Path, PathBuf};

/// Everything `collect` needs, wired once at boot by `main.rs`.
pub struct StatsContext {
    pub procfs: PathBuf,
    pub rootfs: PathBuf,
    /// Guest mountpoints of the user volumes, in `izba.volumes` order.
    pub volume_paths: Vec<String>,
    pub docker: bool,
    pub engine_log: PathBuf,
    pub clk_tck: u64,
    /// Page size in KiB (for `rss_pages` → KiB).
    pub page_kb: u64,
}

/// One process from a `/proc` scan (cumulative ticks — deltas happen in
/// [`compute_processes`]).
#[derive(Debug, Clone)]
pub struct ProcRaw {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ticks: u64,
    pub rss_pages: u64,
}

/// How long `collect` waits between its two `/proc` samples.
const SAMPLE_INTERVAL_MS: u64 = 250;
/// How many processes the guest reports (the daemon re-truncates anyway).
const TOP_N: usize = 15;
/// Engine-log tail budget for `DockerEngine::detail`.
const LOG_TAIL_BYTES: u64 = 256;

/// Parse one `/proc/<pid>/stat` line. The comm field may contain spaces and
/// parens; the kernel's own format is only unambiguous from the LAST `)`.
pub fn parse_stat_line(line: &str) -> Option<ProcRaw> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let pid: u32 = line[..open].trim().parse().ok()?;
    let comm = line[open + 1..close].to_string();
    let rest: Vec<&str> = line[close + 1..].split_ascii_whitespace().collect();
    // rest[0]=state, rest[11]=utime, rest[12]=stime, rest[21]=rss (man proc(5)).
    if rest.len() < 22 {
        return None;
    }
    let state = rest[0].chars().next()?;
    let utime: u64 = rest[11].parse().ok()?;
    let stime: u64 = rest[12].parse().ok()?;
    let rss_pages: u64 = rest[21].parse().ok()?;
    Some(ProcRaw { pid, comm, state, ticks: utime + stime, rss_pages })
}

/// Scan every numeric `/proc` entry. Races (a pid exiting mid-scan) just
/// drop that entry — never an error.
pub fn scan_procs(procfs: &Path) -> Vec<ProcRaw> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(procfs) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(line) = std::fs::read_to_string(e.path().join("stat")) {
            if let Some(p) = parse_stat_line(&line) {
                out.push(p);
            }
        }
    }
    out
}

/// Delta the two samples into the top-N list. `process_count` reflects the
/// AFTER snapshot. A pid absent from BEFORE gets 0 interval-CPU (never its
/// cumulative total).
pub fn compute_processes(
    before: &[ProcRaw],
    after: &[ProcRaw],
    interval_ms: u64,
    clk_tck: u64,
    page_kb: u64,
) -> (Vec<ProcSample>, u32) {
    let prev: std::collections::HashMap<u32, u64> =
        before.iter().map(|p| (p.pid, p.ticks)).collect();
    let denom = clk_tck.saturating_mul(interval_ms).max(1);
    let mut rows: Vec<(u64, ProcSample)> = after
        .iter()
        .map(|p| {
            let delta = p.ticks.saturating_sub(prev.get(&p.pid).copied().unwrap_or(p.ticks));
            let permille = (delta.saturating_mul(1000).saturating_mul(1000) / denom) as u32;
            (
                delta,
                ProcSample {
                    pid: p.pid,
                    comm: p.comm.clone(),
                    state: p.state,
                    cpu_permille: permille,
                    rss_kb: p.rss_pages.saturating_mul(page_kb),
                },
            )
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.pid.cmp(&b.1.pid)));
    let count = after.len() as u32;
    (rows.into_iter().take(TOP_N).map(|(_, s)| s).collect(), count)
}

/// `(MemTotal, MemAvailable)` in KiB; 0 for anything unparseable.
pub fn parse_meminfo(s: &str) -> (u64, u64) {
    let grab = |key: &str| {
        s.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_ascii_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (grab("MemTotal:"), grab("MemAvailable:"))
}

/// `(load1, load5, load15) × 100`; zeros for anything unparseable.
pub fn parse_loadavg(s: &str) -> (u32, u32, u32) {
    let mut it = s.split_ascii_whitespace().map(|f| {
        f.parse::<f64>()
            .map(|v| (v * 100.0).round().clamp(0.0, u32::MAX as f64) as u32)
            .unwrap_or(0)
    });
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// statfs each interesting mount through the injected probe, reporting under
/// GUEST paths: the overlay upper as `/`, each volume under its declared
/// mountpoint. A failing probe just drops that row.
pub fn collect_mounts(
    rootfs: &Path,
    volume_paths: &[String],
    statfs: &dyn Fn(&Path) -> Option<(u64, u64)>,
) -> Vec<MountUsage> {
    let mut out = Vec::new();
    if let Some((total, avail)) = statfs(rootfs) {
        out.push(MountUsage { path: "/".into(), total_bytes: total, avail_bytes: avail });
    }
    for gp in volume_paths {
        let real = rootfs.join(gp.trim_start_matches('/'));
        if let Some((total, avail)) = statfs(&real) {
            out.push(MountUsage { path: gp.clone(), total_bytes: total, avail_bytes: avail });
        }
    }
    out
}

/// Bounded tail of the engine log (last [`LOG_TAIL_BYTES`], lossy UTF-8,
/// trimmed). `None` when the log is missing/empty.
pub fn log_tail(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let s = String::from_utf8_lossy(&buf).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Engine liveness = a live `dockerd` anywhere in the guest's process tree
/// (init's `/proc` sees the workload container's pidns too). When dead, the
/// log tail says why — that log already distinguishes "image ships no
/// dockerd" from a crash.
pub fn engine_status(procs: &[ProcRaw], engine_log: &Path) -> DockerEngine {
    let running = procs.iter().any(|p| p.comm == "dockerd");
    DockerEngine {
        running,
        detail: if running { None } else { log_tail(engine_log) },
    }
}

/// statfs via statvfs; `(total, avail)` in bytes.
fn statfs_real(p: &Path) -> Option<(u64, u64)> {
    let s = nix::sys::statvfs::statvfs(p).ok()?;
    let frag = s.fragment_size() as u64;
    Some((
        (s.blocks() as u64).saturating_mul(frag),
        (s.blocks_available() as u64).saturating_mul(frag),
    ))
}

/// Full guest collection. Blocks ~[`SAMPLE_INTERVAL_MS`]. `container` is left
/// `None` — the control-server dispatch fills it (it owns the crun query).
pub fn collect(ctx: &StatsContext) -> GuestStats {
    let before = scan_procs(&ctx.procfs);
    std::thread::sleep(std::time::Duration::from_millis(SAMPLE_INTERVAL_MS));
    let after = scan_procs(&ctx.procfs);
    let (processes, process_count) =
        compute_processes(&before, &after, SAMPLE_INTERVAL_MS, ctx.clk_tck.max(1), ctx.page_kb);
    let mem = std::fs::read_to_string(ctx.procfs.join("meminfo")).unwrap_or_default();
    let (mem_total_kb, mem_available_kb) = parse_meminfo(&mem);
    let load = std::fs::read_to_string(ctx.procfs.join("loadavg")).unwrap_or_default();
    let (load1_centi, load5_centi, load15_centi) = parse_loadavg(&load);
    let mounts = collect_mounts(&ctx.rootfs, &ctx.volume_paths, &statfs_real);
    let docker = ctx.docker.then(|| engine_status(&after, &ctx.engine_log));
    GuestStats {
        processes,
        process_count,
        load1_centi,
        load5_centi,
        load15_centi,
        mem_total_kb,
        mem_available_kb,
        mounts,
        docker,
        container: None,
    }
}
```

Note on statvfs field types: on some targets `statvfs` fields are `u32`/`u64` differently — the `as u64` casts keep it portable; if clippy flags a useless cast on this target, allow it locally with a comment (`#[allow(clippy::unnecessary_cast)] // statvfs field widths vary by target`).

Declare the module following the existing pattern for `docker`/`net` (in `main.rs`: `mod stats;` — plus re-export if server.rs needs a use path; server.rs lives in the same binary crate and refers to sibling modules via `crate::`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-init stats` — PASS. Also `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` (statvfs must link on musl).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/stats.rs crates/izba-init/src/main.rs
git commit -m "feat(init): guest stats collector (procfs-seamed, stateless two-sample CPU)"
```

---

### Task 3: wire `Request::Stats` into init's control server

**Files:**
- Modify: `crates/izba-init/src/server.rs` (`serve_control`, `control_conn`, `dispatch_control_request` + their tests)
- Modify: `crates/izba-init/src/main.rs` (build the `StatsContext`, pass to `serve_control`)

**Interfaces:**
- Consumes: `stats::{StatsContext, collect}` (Task 2), `crate::oci::container_state(crate::oci::CONTAINER_ID)`.
- Produces: init answers `Request::Stats` with `Response::Stats(GuestStats)` where `container` is set the same way `Health` sets it.

- [ ] **Step 1: Write the failing test**

In `server.rs`'s existing test module (which drives `control_conn` over `UnixStream::pair()` — follow the existing `Request::Health` test at ~line 511 for the harness shape):

```rust
#[test]
fn stats_request_returns_guest_stats_with_container_state() {
    // Fake procfs with one process; StatsContext pointing at it.
    let t = tempfile::tempdir().unwrap();
    let d = t.path().join("proc").join("1");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("stat"),
        "1 (init) S 0 1 1 0 -1 0 0 0 0 0 2 1 0 0 20 0 1 0 3 1000 50 0\n",
    )
    .unwrap();
    std::fs::write(t.path().join("proc").join("meminfo"), "MemTotal: 500 kB\nMemAvailable: 250 kB\n").unwrap();
    std::fs::write(t.path().join("proc").join("loadavg"), "0.10 0.20 0.30 1/1 1\n").unwrap();
    let ctx = std::sync::Arc::new(crate::stats::StatsContext {
        procfs: t.path().join("proc"),
        rootfs: t.path().join("rootfs"), // absent: mounts just come back empty
        volume_paths: vec![],
        docker: false,
        engine_log: t.path().join("no.log"),
        clk_tck: 100,
        page_kb: 4,
    });
    let mut c = /* same pair-based harness the Health test uses, threading `ctx` */;
    match rpc(&mut c, &Request::Stats) {
        Response::Stats(g) => {
            assert_eq!(g.process_count, 1);
            assert_eq!(g.mem_total_kb, 500);
            assert_eq!(g.load5_centi, 20);
            assert!(g.docker.is_none());
            // On a crun-less unit host container state is Unknown — but SET.
            assert!(g.container.is_some());
        }
        other => panic!("expected Stats, got {other:?}"),
    }
}
```

(Adapt the harness plumb exactly as the existing tests construct `control_conn` args — they will all need the new `Arc<StatsContext>` parameter; give the other tests a minimal `test_stats_ctx()` helper with an empty tempdir procfs.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init server` — FAILS to compile (arity) or the new test fails.

- [ ] **Step 3: Implement**

- `serve_control` and `control_conn` gain `stats: Arc<crate::stats::StatsContext>` (thread it exactly like the existing `usb: Arc<UsbState>`).
- `dispatch_control_request` gains the parameter and the arm (place after `UsbDetach`):

```rust
        Request::Stats => {
            let mut g = crate::stats::collect(stats);
            // Same honest container source as Health: queried fresh, Unknown
            // when crun can't answer — never a stale claim.
            g.container = Some(crate::oci::container_state(crate::oci::CONTAINER_ID));
            Response::Stats(g)
        }
```

- `main.rs`: after the `docker` flag and `vols` are known, build the context and pass it to `serve_control`:

```rust
    let stats_ctx = std::sync::Arc::new(stats::StatsContext {
        procfs: "/proc".into(),
        rootfs: "/rootfs".into(),
        volume_paths: vols.clone(),
        docker,
        engine_log: docker::ENGINE_LOG.into(),
        clk_tck: unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64,
        page_kb: (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1024) as u64) / 1024,
    });
```

(`vols` is the `izba.volumes` list already parsed for `setup_user_volumes`; match its actual variable type — it is a `Vec<String>` derived from the comma-split. If `serve_control`'s call site is before `vols`/`docker` are computed, move the context construction to just before the spawn — do NOT reorder boot steps.)

- [ ] **Step 4: Run tests + gates**

Run: `cargo test -p izba-init` — PASS. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/server.rs crates/izba-init/src/main.rs
git commit -m "feat(init): serve Request::Stats on the control port"
```

---

### Task 4: daemon wire types, proto bump, guest-data sanitizer, shared docker-path predicate

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` (`SandboxStats` + friends, `DaemonRequest::Stats`, `DaemonResponse::Stats`, `DAEMON_PROTO_VERSION` 4→5)
- Create: `crates/izba-core/src/daemon/stats.rs` (sanitizer + caps; declared in `crates/izba-core/src/daemon/mod.rs`)
- Modify: `crates/izba-core/src/volume.rs` (extract `is_docker_volume_path`)

**Interfaces:**
- Consumes: `izba_proto::GuestStats` (Task 1), `volume::DOCKER_VOLUME_PATH`.
- Produces (Tasks 5-7 rely on):

```rust
pub struct SandboxStats { pub name: String, pub running: bool, pub uptime_ms: Option<u64>, pub host: Option<HostResources>, pub disk: HostDisk, pub guest: Option<izba_proto::GuestStats> }
pub struct HostResources { pub cpu_permille: Option<u32>, pub rss_kb: u64, pub cpus_limit: u32, pub mem_limit_mb: u32 }
pub struct HostDisk { pub rw_img_bytes: u64, pub volumes: Vec<VolumeDisk>, pub logs_bytes: u64, pub image_bytes: u64 }
pub struct VolumeDisk { pub guest_path: String, pub allocated_bytes: u64, pub docker: bool }
// daemon::stats
pub fn sanitize_guest_stats(g: GuestStats) -> GuestStats;
// volume
pub fn is_docker_volume_path(p: &Path) -> bool;
```

- [ ] **Step 1: Write the failing tests**

`crates/izba-core/src/daemon/stats.rs` (tests-first skeleton):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::{DockerEngine, GuestStats, MountUsage, ProcSample};

    fn base() -> GuestStats {
        GuestStats {
            processes: vec![],
            process_count: 0,
            load1_centi: 0,
            load5_centi: 0,
            load15_centi: 0,
            mem_total_kb: 0,
            mem_available_kb: 0,
            mounts: vec![],
            docker: None,
            container: None,
        }
    }

    #[test]
    fn strips_control_chars_and_caps_comm() {
        let mut g = base();
        g.processes.push(ProcSample {
            pid: 1,
            comm: format!("evil\x1b[2J\x07{}", "a".repeat(100)),
            state: 'R',
            cpu_permille: 1,
            rss_kb: 1,
        });
        let s = sanitize_guest_stats(g);
        let comm = &s.processes[0].comm;
        assert!(comm.chars().all(|c| !c.is_control()));
        assert!(comm.starts_with("evil"));
        assert_eq!(comm.chars().count(), MAX_COMM);
    }

    #[test]
    fn truncates_hostile_process_and_mount_floods() {
        let mut g = base();
        for i in 0..1000 {
            g.processes.push(ProcSample { pid: i, comm: "x".into(), state: 'S', cpu_permille: 0, rss_kb: 0 });
            g.mounts.push(MountUsage { path: format!("/m{i}"), total_bytes: 0, avail_bytes: 0 });
        }
        let s = sanitize_guest_stats(g);
        assert_eq!(s.processes.len(), MAX_PROCESSES);
        assert_eq!(s.mounts.len(), MAX_MOUNTS);
    }

    #[test]
    fn caps_docker_detail_and_mount_paths() {
        let mut g = base();
        g.docker = Some(DockerEngine { running: false, detail: Some(format!("\n\nboom{}", "b".repeat(1000))) });
        g.mounts.push(MountUsage { path: format!("/{}", "p".repeat(1000)), total_bytes: 1, avail_bytes: 1 });
        let s = sanitize_guest_stats(g);
        let d = s.docker.unwrap().detail.unwrap();
        assert!(d.chars().count() <= MAX_DETAIL);
        assert!(!d.contains('\n'));
        assert!(s.mounts[0].path.chars().count() <= MAX_PATH);
    }
}
```

`volume.rs` test (in its existing test module):

```rust
#[test]
fn is_docker_volume_path_matches_component_wise() {
    use std::path::Path;
    assert!(is_docker_volume_path(Path::new("/var/lib/docker")));
    assert!(is_docker_volume_path(Path::new("/var/lib/docker/.")));
    assert!(is_docker_volume_path(Path::new("/var/./lib/docker")));
    assert!(!is_docker_volume_path(Path::new("/var/lib/docker2")));
    assert!(!is_docker_volume_path(Path::new("/var/lib")));
}
```

`proto.rs` test (existing test module):

```rust
#[test]
fn stats_daemon_frames_round_trip() {
    let req = DaemonRequest::Stats { name: "web".into() };
    let s = serde_json::to_string(&req).unwrap();
    let back: DaemonRequest = serde_json::from_str(&s).unwrap();
    assert!(matches!(back, DaemonRequest::Stats { name } if name == "web"));

    let resp = DaemonResponse::Stats(SandboxStats {
        name: "web".into(),
        running: true,
        uptime_ms: Some(1234),
        host: Some(HostResources { cpu_permille: Some(340), rss_kb: 2_621_440, cpus_limit: 4, mem_limit_mb: 4096 }),
        disk: HostDisk {
            rw_img_bytes: 1_288_490_189,
            volumes: vec![VolumeDisk { guest_path: "/var/lib/docker".into(), allocated_bytes: 2_254_857_830, docker: true }],
            logs_bytes: 12_582_912,
            image_bytes: 933_232_640,
        },
        guest: None,
    });
    let s = serde_json::to_string(&resp).unwrap();
    let back: DaemonResponse = serde_json::from_str(&s).unwrap();
    match back {
        DaemonResponse::Stats(st) => {
            assert!(st.disk.volumes[0].docker);
            assert_eq!(st.host.unwrap().cpu_permille, Some(340));
        }
        other => panic!("expected Stats, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core daemon::stats volume::tests::is_docker proto` — FAILS: types/functions missing.

- [ ] **Step 3: Implement**

`crates/izba-core/src/daemon/proto.rs`:
- `pub const DAEMON_PROTO_VERSION: u32 = 5;` with a comment line noting v5 = Stats RPC.
- Add the four structs (doc-comment each: `host`/`disk` are host-derived and trusted; `guest` is guest-reported, sanitized, untrusted; `image_bytes` is shared between sandboxes on the same image and must NOT be summed into a per-sandbox footprint).
- `DaemonRequest::Stats { name: String }` (next to `Inspect`), `DaemonResponse::Stats(SandboxStats)`.

`crates/izba-core/src/daemon/stats.rs`:

```rust
//! Sanitization of guest-reported stats at the daemon trust boundary.
//!
//! The guest is hostile (docs/security/): its strings may carry terminal
//! escapes, its lists may be flood-sized (MAX_FRAME is 16 MiB). Everything
//! in `GuestStats` passes through here exactly once — in the daemon's Stats
//! handler — before any CLI/GUI rendering.

use izba_proto::GuestStats;

pub const MAX_PROCESSES: usize = 15;
pub const MAX_MOUNTS: usize = 32;
pub const MAX_COMM: usize = 32;
pub const MAX_DETAIL: usize = 256;
pub const MAX_PATH: usize = 128;

/// Strip control characters (incl. newlines/ESC) and cap length in chars.
fn clean(s: &str, cap: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(cap).collect()
}

pub fn sanitize_guest_stats(mut g: GuestStats) -> GuestStats {
    g.processes.truncate(MAX_PROCESSES);
    for p in &mut g.processes {
        p.comm = clean(&p.comm, MAX_COMM);
        if p.state.is_control() {
            p.state = '?';
        }
    }
    g.mounts.truncate(MAX_MOUNTS);
    for m in &mut g.mounts {
        m.path = clean(&m.path, MAX_PATH);
    }
    if let Some(d) = &mut g.docker {
        d.detail = d.detail.take().map(|s| clean(&s, MAX_DETAIL));
    }
    g
}
```

Wait — the comm-cap test asserts `chars().count() == MAX_COMM` after cleaning a longer string: `clean` filters THEN takes, so the count is exactly `MAX_COMM` when ≥ cap survives filtering. Consistent.

Declare `pub mod stats;` in `crates/izba-core/src/daemon/mod.rs`.

`crates/izba-core/src/volume.rs` — extract the predicate and reuse it inside `inject_docker_volume` (replacing the inline component comparison so rule + call sites share one tested helper):

```rust
/// Component-wise match against [`DOCKER_VOLUME_PATH`] so `/var/lib/docker/.`
/// and friends don't slip past (shared by volume injection and stats
/// attribution — keep both call sites on THIS predicate).
pub fn is_docker_volume_path(p: &std::path::Path) -> bool {
    let target: Vec<std::path::Component> =
        std::path::Path::new(DOCKER_VOLUME_PATH).components().collect();
    p.components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .eq(target.iter().cloned())
}
```

- [ ] **Step 4: Run tests + cross-gates**

Run: `cargo test -p izba-core` — PASS. `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli` — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/stats.rs crates/izba-core/src/daemon/mod.rs crates/izba-core/src/volume.rs
git commit -m "feat(core): SandboxStats wire types, guest-data sanitizer, proto v5"
```

---

### Task 5: daemon Stats handler (host tier + guest fetch)

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (dispatch arm + `handle_stats` + host/guest helpers + tests)
- Modify: `crates/izba-core/src/daemon/mod.rs` or wherever `struct Daemon` lives (add the ephemeral CPU cache field) — find `struct Daemon` first; it is the type behind `Arc<Daemon>` in server.rs.
- Modify: `crates/izba-core/src/sandbox.rs` (make `allocated_bytes` `pub(crate)`)

**Interfaces:**
- Consumes: Task 4 types + `sanitize_guest_stats` + `is_docker_volume_path`; `sandbox::control`, `set_io_timeout`, `probe_container_state`'s pattern; `RunState { vmm_pid: PidIdentity, started_unix_ms }`; `procmgr::pid_alive`; `VolumeSpec::image_path(paths, sandbox)`; `Paths::{sandbox_dir, logs_dir, image_dir}`.
- Produces: `DaemonRequest::Stats { name }` → `DaemonResponse::Stats(SandboxStats)`; works for stopped sandboxes (disk only), running sandboxes on Linux (full host tier), wedged guests (time-bounded → `guest: None`).

- [ ] **Step 1: Write the failing tests**

In server.rs's test module (using the same in-process daemon + `rpc()` harness as the existing `Inspect` tests — see `inspect_surfaces_persisted_user_fallback` for the fixture-building pattern):

```rust
#[test]
fn stats_on_stopped_sandbox_reports_disk_breakdown() {
    // Same daemon/tempdir fixture as the inspect tests, with a config.json
    // for "web" whose volumes include a /var/lib/docker entry, plus:
    //   sandbox_dir/rw.img       — sparse 1 GiB, 1 MiB written
    //   volume img for docker    — sparse, 2 MiB written (use image_path())
    //   logs_dir/console.log     — 4096 bytes
    //   image_dir(digest)/rootfs.erofs — 8192 bytes
    // Then:
    match rpc(&mut c, &DaemonRequest::Stats { name: "web".into() }) {
        DaemonResponse::Stats(s) => {
            assert!(!s.running);
            assert_eq!(s.uptime_ms, None);
            assert!(s.host.is_none());
            assert!(s.guest.is_none());
            assert!(s.disk.rw_img_bytes >= 1024 * 1024, "sparse-aware: allocated, not len; got {}", s.disk.rw_img_bytes);
            assert!(s.disk.rw_img_bytes < 1024 * 1024 * 1024, "must not report the sparse length");
            let dv = s.disk.volumes.iter().find(|v| v.docker).expect("docker volume attributed");
            assert!(dv.allocated_bytes >= 2 * 1024 * 1024 - 65536);
            assert!(s.disk.logs_bytes >= 4096);
            assert!(s.disk.image_bytes >= 8192);
        }
        other => panic!("expected Stats, got {other:?}"),
    }
}

#[test]
fn stats_on_missing_sandbox_errors() {
    match rpc(&mut c, &DaemonRequest::Stats { name: "nope".into() }) {
        DaemonResponse::Error { .. } => {}
        other => panic!("expected Error, got {other:?}"),
    }
}
```

Pure-helper tests (same file or a `#[cfg(test)]` block near the helpers):

```rust
#[test]
fn cpu_permille_from_tick_delta() {
    // 50 ticks over 1000 ms at 100 Hz = half a CPU = 500 permille.
    assert_eq!(cpu_permille(1000, 1050, 1000, 100), Some(500));
    // Non-monotonic (VMM restarted / cache stale): honest None, never junk.
    assert_eq!(cpu_permille(2000, 1000, 1000, 100), None);
    assert_eq!(cpu_permille(0, 0, 0, 100), None); // zero elapsed
}

#[test]
fn parse_vmm_stat_ticks_and_status_rss() {
    let stat = "1234 (cloud-hyperviso) S 1 1 1 0 -1 4194560 0 0 0 0 700 300 0 0 20 0 8 0 555 0 99999 0";
    assert_eq!(vmm_ticks_from_stat(stat), Some(1000));
    let status = "Name:\tcloud-hyperviso\nVmPeak:\t 9999 kB\nVmRSS:\t 2621440 kB\n";
    assert_eq!(rss_kb_from_status(status), Some(2_621_440));
}

#[test]
fn stats_cache_is_keyed_by_pid_identity() {
    let cache = StatsCpuCache::default();
    let id_a = crate::state::PidIdentity { pid: 10, starttime: 111 };
    let id_b = crate::state::PidIdentity { pid: 10, starttime: 222 }; // reused pid
    assert_eq!(cache.observe("web", &id_a, 1000, ms(0)), None); // first sample
    assert_eq!(cache.observe("web", &id_a, 1100, ms(1000)), Some(100));
    // Same pid, NEW process: must reset, never splice tick counters.
    assert_eq!(cache.observe("web", &id_b, 50, ms(2000)), None);
}
```

(`ms(n)` = a monotonic instant helper: `Instant` can't be constructed at an offset — implement `observe` to take an `Instant` and in tests derive instants via `let t0 = Instant::now();` + `t0 + Duration::from_millis(n)`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core stats` — FAILS.

- [ ] **Step 3: Implement**

In `sandbox.rs`: `fn allocated_bytes` → `pub(crate) fn allocated_bytes`.

In `server.rs` (or a sibling `daemon/stats_host.rs` if server.rs feels crowded — reviewer's call; keep the dispatch arm in server.rs either way):

```rust
/// Ephemeral per-sandbox CPU sample cache. NOT authoritative state (the
/// disk-state invariant is untouched): losing it costs exactly one `None`
/// cpu_permille sample. Keyed by PidIdentity so a restarted VMM (same pid,
/// different starttime) never splices two processes' tick counters.
#[derive(Default)]
pub(crate) struct StatsCpuCache {
    inner: Mutex<HashMap<String, (crate::state::PidIdentity, u64, Instant)>>,
}

impl StatsCpuCache {
    /// Record `ticks` for `name`/`id` at `now`; returns cpu_permille vs the
    /// previous sample when identities match, else None.
    pub(crate) fn observe(
        &self,
        name: &str,
        id: &crate::state::PidIdentity,
        ticks: u64,
        now: Instant,
    ) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let prev = inner.insert(name.to_string(), (id.clone(), ticks, now));
        let (pid, pticks, pat) = prev?;
        if pid != *id {
            return None;
        }
        let elapsed_ms = now.duration_since(pat).as_millis() as u64;
        cpu_permille(pticks, ticks, elapsed_ms, host_clk_tck())
    }
}

/// permille of one CPU given a tick delta over `elapsed_ms`. None on zero
/// elapsed or non-monotonic ticks (an honest gap beats a junk spike).
fn cpu_permille(prev_ticks: u64, ticks: u64, elapsed_ms: u64, clk_tck: u64) -> Option<u32> {
    if elapsed_ms == 0 || ticks < prev_ticks {
        return None;
    }
    let delta = ticks - prev_ticks;
    Some((delta.saturating_mul(1_000_000) / clk_tck.max(1).saturating_mul(elapsed_ms)) as u32)
}

#[cfg(target_os = "linux")]
fn host_clk_tck() -> u64 {
    // SAFETY: sysconf is async-signal-safe and takes no pointers.
    (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as u64
}
#[cfg(not(target_os = "linux"))]
fn host_clk_tck() -> u64 { 100 }

/// utime+stime (fields 14+15) from a /proc/<pid>/stat line.
fn vmm_ticks_from_stat(line: &str) -> Option<u64> {
    let close = line.rfind(')')?;
    let rest: Vec<&str> = line[close + 1..].split_ascii_whitespace().collect();
    Some(rest.get(11)?.parse::<u64>().ok()? + rest.get(12)?.parse::<u64>().ok()?)
}

/// VmRSS from /proc/<pid>/status.
fn rss_kb_from_status(s: &str) -> Option<u64> {
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
```

Handler (register `DaemonRequest::Stats { name } => handle_stats(d, name)` in the dispatch match next to `Inspect`):

```rust
/// Guest Stats probe deadline — same wedged-guest discipline as
/// CONTAINER_PROBE_TIMEOUT, plus headroom for the in-guest 250 ms sampling.
const STATS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn handle_stats(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    let config: SandboxConfig = load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
        .with_context(|| format!("no such sandbox '{name}'"))?;
    let status = d.registry.liveness(&name).unwrap_or(Liveness::Stopped).describe();
    let running = status != "stopped";
    let run_state = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?;
    let disk = host_disk(&d.paths, &name, &config);
    let (host, uptime_ms) = if running {
        match &run_state {
            Some(rs) => (
                host_resources(d, &name, &config, &rs.vmm_pid),
                Some(now_unix_ms().saturating_sub(rs.started_unix_ms)),
            ),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let guest = if running {
        probe_guest_stats(d, &name, STATS_PROBE_TIMEOUT).map(crate::daemon::stats::sanitize_guest_stats)
    } else {
        None
    };
    Ok(DaemonResponse::Stats(SandboxStats { name, running, uptime_ms, host, disk, guest }))
}

/// Best-effort guest Stats fetch, probe-shaped like probe_container_state:
/// any failure (unreachable, wedged, pre-stats guest replying Error or
/// dropping the conn) degrades to None, never an error or a hang.
fn probe_guest_stats(d: &Arc<Daemon>, name: &str, timeout: Duration) -> Option<izba_proto::GuestStats> {
    let mut conn = sandbox::control(&d.paths, name, d.connector()).ok()?;
    conn.set_io_timeout(Some(timeout)).ok()?;
    write_frame(&mut conn, &izba_proto::Request::Stats).ok()?;
    match read_frame::<_, Response>(&mut conn).ok()? {
        Response::Stats(g) => Some(g),
        _ => None,
    }
}

/// Trusted host-tier resources; Linux-only (/proc). PidIdentity is
/// re-verified first so a recycled pid can never be read as the VMM.
#[cfg(target_os = "linux")]
fn host_resources(
    d: &Arc<Daemon>,
    name: &str,
    config: &SandboxConfig,
    id: &crate::state::PidIdentity,
) -> Option<HostResources> {
    if !crate::procmgr::pid_alive(id) {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", id.pid)).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{}/status", id.pid)).ok()?;
    let ticks = vmm_ticks_from_stat(&stat)?;
    let rss_kb = rss_kb_from_status(&status)?;
    let cpu_permille = d.stats_cpu.observe(name, id, ticks, Instant::now());
    Some(HostResources { cpu_permille, rss_kb, cpus_limit: config.cpus, mem_limit_mb: config.mem_mb })
}
#[cfg(not(target_os = "linux"))]
fn host_resources(
    _d: &Arc<Daemon>, _name: &str, _config: &SandboxConfig, _id: &crate::state::PidIdentity,
) -> Option<HostResources> {
    None // Windows host tier is spec §9 out-of-scope; guest+disk tiers still work.
}

/// Host-disk breakdown; sparse-aware via allocated_bytes; works stopped.
/// image_bytes is the content-addressed rootfs.erofs — SHARED between
/// sandboxes on the same image, reported separately, never summed into the
/// per-sandbox footprint by consumers.
fn host_disk(paths: &crate::paths::Paths, name: &str, config: &SandboxConfig) -> HostDisk {
    let alloc = |p: &std::path::Path| {
        std::fs::metadata(p).map(|m| crate::sandbox::allocated_bytes(&m)).unwrap_or(0)
    };
    let rw_img_bytes = alloc(&paths.sandbox_dir(name).join("rw.img"));
    let volumes = config
        .volumes
        .iter()
        .map(|v| VolumeDisk {
            guest_path: v.guest_path.display().to_string(),
            allocated_bytes: alloc(&v.image_path(paths, name)),
            docker: crate::volume::is_docker_volume_path(&v.guest_path),
        })
        .collect();
    let logs_bytes = std::fs::read_dir(paths.logs_dir(name))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| crate::sandbox::allocated_bytes(&m))
                .sum()
        })
        .unwrap_or(0);
    let image_bytes = alloc(&paths.image_dir(&config.image_digest).join("rootfs.erofs"));
    HostDisk { rw_img_bytes, volumes, logs_bytes, image_bytes }
}
```

Notes for the implementer:
- `Daemon` gains `pub(crate) stats_cpu: StatsCpuCache` (Default in its constructor).
- `now_unix_ms()`: reuse the existing helper if one exists (grep `started_unix_ms` writers), else `SystemTime::now().duration_since(UNIX_EPOCH)` millis.
- Ephemeral-volume `image_path` panics when `eph_id` is None (pre-provision spec). Config on disk is post-provision so ids exist; still, guard: skip volumes where `v.name.is_none() && v.eph_id.is_none()` instead of panicking the daemon.
- The sparse-file assertions in the disk test need real sparse files: `f.set_len(GiB)` then write 1 MiB at offset 0; on filesystems without sparse support the `< len` assertion could fail — follow `volume.rs`'s existing `actual_bytes` test for how this is already handled in this repo (mirror its approach/skip logic).

- [ ] **Step 4: Run tests + all gates**

Run: `cargo test -p izba-core` — PASS. `cargo clippy --workspace --all-targets -- -D warnings`. Cross: `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli` (the `cfg(not(target_os = "linux"))` arm compiles there).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/server.rs crates/izba-core/src/daemon/mod.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): daemon Stats handler — host resources, disk breakdown, sanitized guest fetch"
```

---

### Task 6: `izba status` engine line (#203)

**Files:**
- Modify: `crates/izba-cli/src/commands/status.rs`

**Interfaces:**
- Consumes: `DaemonRequest::Stats` / `DaemonResponse::Stats` (Task 4), existing `render` + client plumbing in status.rs.
- Produces: for a running docker-mode sandbox, `izba status` prints an `engine:` line directly under `mode:`.

- [ ] **Step 1: Write the failing test**

In status.rs's test module (it has render tests — follow their fixture style):

```rust
#[test]
fn engine_line_renders_all_states() {
    use izba_core::daemon::proto::SandboxStats;
    fn stats_with(docker: Option<izba_proto::DockerEngine>) -> SandboxStats {
        SandboxStats {
            name: "web".into(),
            running: true,
            uptime_ms: None,
            host: None,
            disk: izba_core::daemon::proto::HostDisk {
                rw_img_bytes: 0, volumes: vec![], logs_bytes: 0, image_bytes: 0,
            },
            guest: docker.map(|d| izba_proto::GuestStats {
                processes: vec![], process_count: 0,
                load1_centi: 0, load5_centi: 0, load15_centi: 0,
                mem_total_kb: 0, mem_available_kb: 0, mounts: vec![],
                docker: Some(d), container: None,
            }),
        }
    }
    assert_eq!(
        engine_line(Some(&stats_with(Some(izba_proto::DockerEngine { running: true, detail: None })))),
        "engine:      running"
    );
    assert_eq!(
        engine_line(Some(&stats_with(Some(izba_proto::DockerEngine {
            running: false,
            detail: Some("failed to start daemon: no cgroup".into()),
        })))),
        "engine:      not running (failed to start daemon: no cgroup)"
    );
    assert_eq!(
        engine_line(Some(&stats_with(Some(izba_proto::DockerEngine { running: false, detail: None })))),
        "engine:      not running (see /var/log/izba-dockerd.log in the guest)"
    );
    // Guest unreachable, or a pre-stats guest: honest unknown.
    assert_eq!(engine_line(None), "engine:      unknown (guest not responding)");
    assert_eq!(engine_line(Some(&stats_with(None))), "engine:      unknown (guest not responding)");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-cli engine_line` — FAILS.

- [ ] **Step 3: Implement**

```rust
/// The `engine:` line for a docker-mode sandbox (#203): a dead/absent
/// nested Docker Engine must be visible, not a silent "running" sandbox.
/// `stats` is None when the daemon Stats call itself failed.
fn engine_line(stats: Option<&SandboxStats>) -> String {
    let engine = stats.and_then(|s| s.guest.as_ref()).and_then(|g| g.docker.as_ref());
    match engine {
        Some(e) if e.running => "engine:      running".to_string(),
        Some(e) => match &e.detail {
            // Daemon-sanitized (control chars stripped), safe to print.
            Some(d) => format!("engine:      not running ({d})"),
            None => "engine:      not running (see /var/log/izba-dockerd.log in the guest)".to_string(),
        },
        None => "engine:      unknown (guest not responding)".to_string(),
    }
}
```

In `run`, after the existing render of the `mode:` line: when `det.docker && det.status == "running"`, send `DaemonRequest::Stats { name }` on the same client connection (match how the Inspect request is sent), map `DaemonResponse::Stats(s) => Some(s)`, anything else (including transport error) → `None`, and print `engine_line(stats.as_ref())`. Stopped docker sandboxes print no engine line (matches spec §5).

If `render` is a pure function receiving pre-fetched data, extend its signature with `engine: Option<&str>`-style plumbing consistent with its current shape rather than doing I/O inside render — follow the file's existing structure.

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-cli` — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/status.rs
git commit -m "feat(cli): show nested docker engine state in izba status (#203)"
```

---

### Task 7: Tauri backend — DaemonApi.stats, views, detail-view extension

**Files:**
- Modify: `app/src-tauri/src/daemon.rs` (trait + `RealDaemon` impl)
- Modify: `app/src-tauri/src/fake.rs` (FakeDaemon fixture)
- Modify: `app/src-tauri/src/commands.rs` (`stats_core` + tests)
- Modify: `app/src-tauri/src/views.rs` (`SandboxStatsView` family + extend `SandboxDetailView`)
- Modify: `app/src-tauri/src/lib.rs` (register the `stats` command)

**Interfaces:**
- Consumes: `izba_core::daemon::proto::SandboxStats` (Task 4).
- Produces (frontend relies on this exact JSON): `SandboxStatsView { name, running, uptime_ms, host: Option<HostResourcesView>, disk: HostDiskView, guest: Option<GuestStatsView> }` with nested `HostResourcesView { cpu_permille: Option<u32>, rss_kb, cpus_limit, mem_limit_mb }`, `HostDiskView { rw_img_bytes, volumes: Vec<VolumeDiskView { guest_path, allocated_bytes, docker }>, logs_bytes, image_bytes }`, `GuestStatsView { processes: Vec<ProcessView { pid, comm, state: String, cpu_permille, rss_kb }>, process_count, load1_centi, load5_centi, load15_centi, mem_total_kb, mem_available_kb, mounts: Vec<MountView { path, total_bytes, avail_bytes }>, docker: Option<DockerEngineView { running, detail }>, container: Option<String> }`; `SandboxDetailView` gains `docker: bool, cpus: u32, mem_mb: u32, confinement: Option<String>`.

- [ ] **Step 1: Write the failing tests**

In views.rs's test module:

```rust
#[test]
fn sandbox_stats_view_maps_wire_type() {
    let s = izba_core::daemon::proto::SandboxStats { /* full fixture mirroring Task 4's
        round-trip test, guest: Some(GuestStats{ one process, one mount,
        docker engine running, container Some(Running) }) */ };
    let v = SandboxStatsView::from(s);
    assert!(v.running);
    assert_eq!(v.host.as_ref().unwrap().cpu_permille, Some(340));
    assert!(v.disk.volumes[0].docker);
    let g = v.guest.unwrap();
    assert_eq!(g.processes[0].comm, "node");
    assert_eq!(g.processes[0].state, "R");
    assert_eq!(g.container.as_deref(), Some("running"));
}

#[test]
fn sandbox_detail_view_carries_docker_cpus_mem_confinement() {
    // Extend the EXISTING SandboxDetailView::from test fixture: set
    // docker: true, cpus: 4, mem_mb: 4096, confinement: Some("confined".into())
    // and assert all four land on the view.
}
```

In commands.rs's test module:

```rust
#[test]
fn stats_core_returns_mapped_view() {
    let mut d = FakeDaemon::default();
    let v = stats_core(&mut d, "web").unwrap();
    assert_eq!(v.name, "web");
    assert!(v.disk.rw_img_bytes > 0);
}

#[test]
fn stats_core_maps_daemon_error() {
    let mut d = FakeDaemon::default();
    assert!(stats_core(&mut d, "missing").is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd app/src-tauri && cargo test` — FAILS.

- [ ] **Step 3: Implement**

- views.rs: the view structs above, `#[derive(Debug, Clone, PartialEq, Serialize)]`, snake_case fields (no rename attrs — matches file convention), `From` impls (`state: char` → `String`, `container.map(|c| c.as_str().to_string())`). Extend `SandboxDetailView` + its `From` (`docker: d.docker, cpus: d.cpus, mem_mb: d.mem_mb, confinement: d.confinement`).
- daemon.rs: trait method `fn stats(&mut self, name: &str) -> anyhow::Result<izba_core::daemon::proto::SandboxStats>;` + `RealDaemon` impl mirroring `inspect`'s request/response match with `DaemonRequest::Stats` / `DaemonResponse::Stats`.
- fake.rs: `stats` returns, for known sandboxes, a deterministic fixture (running sandbox: host Some with `cpu_permille: Some(340)`, `rss_kb: 2_621_440`, limits from the fake's detail; disk with `rw_img_bytes: 1_288_490_189`, one docker volume `2_254_857_830`, logs `12_582_912`, image `933_232_640`; guest Some with 3 processes incl. a `dockerd`, `process_count: 61`, loads 42/30/19, mem 4 GiB total / 2 GiB available, one `/var/lib/docker` mount 10 GiB total / 8 GiB avail, docker engine running, container running); unknown name → `Err`. Keep it consistent with how fake.rs fabricates `inspect`.
- commands.rs: `pub fn stats_core(d: &mut dyn DaemonApi, name: &str) -> Result<SandboxStatsView, String> { d.stats(name).map(SandboxStatsView::from).map_err(|e| e.to_string()) }` (mirror `inspect_core`'s error formatting exactly).
- lib.rs: `#[tauri::command] async fn stats(...)` wrapper on the shared poll connection, registered in `invoke_handler` — mirror the `inspect` wrapper verbatim (same state access, same spawn/mutex pattern).

- [ ] **Step 4: Run the app backend gate**

Run: `cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` — PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src/daemon.rs app/src-tauri/src/fake.rs app/src-tauri/src/commands.rs app/src-tauri/src/views.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): stats command + view mapping; surface docker/cpus/mem/confinement on detail view"
```

---

### Task 8: frontend plumbing — types, api, formatters, useStats hook

**Files:**
- Modify: `app/src/lib/types.ts` (stats interfaces + extend `SandboxDetail`)
- Modify: `app/src/lib/ipc.ts` (`api.stats`)
- Create: `app/src/lib/format.ts`
- Create: `app/src/lib/useStats.ts`
- Test: `app/src/test/format.test.ts`, `app/src/test/useStats.test.tsx`

**Interfaces:**
- Consumes: Task 7's JSON shape.
- Produces (Task 9 relies on): TS interfaces mirroring Task 7 view structs field-for-field (snake_case); `api.stats(name)`; `formatBytes(n: number): string` (binary units, one decimal, e.g. `1.2 GiB`, `410 MiB`, `0 B`); `formatUptime(ms: number): string` (`2h 14m`, `3d 5h`, `45s`); `meterTone(fraction: number): "ok" | "warn" | "crit"` (warn ≥ 0.8, crit ≥ 0.95); `useStats(name: string, intervalMs?: number): { stats: SandboxStats | null; error: string | null }`.

- [ ] **Step 1: Write the failing tests**

`app/src/test/format.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { formatBytes, formatUptime, meterTone } from "../lib/format";

describe("formatBytes", () => {
  it("renders binary units with one decimal", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KiB");
    expect(formatBytes(1288490189)).toBe("1.2 GiB");
    expect(formatBytes(429916160)).toBe("410.0 MiB");
  });
});

describe("formatUptime", () => {
  it("picks the two most significant units", () => {
    expect(formatUptime(45_000)).toBe("45s");
    expect(formatUptime(8_040_000)).toBe("2h 14m");
    expect(formatUptime(277_200_000)).toBe("3d 5h");
  });
});

describe("meterTone", () => {
  it("applies the 80/95 thresholds", () => {
    expect(meterTone(0)).toBe("ok");
    expect(meterTone(0.79)).toBe("ok");
    expect(meterTone(0.8)).toBe("warn");
    expect(meterTone(0.94)).toBe("warn");
    expect(meterTone(0.95)).toBe("crit");
    expect(meterTone(2)).toBe("crit");
  });
});
```

`app/src/test/useStats.test.tsx` (mock `api` via `vi.mock` like manifestTab.test.tsx; use `vi.useFakeTimers`):

```tsx
// Renders a probe component using useStats("web", 1000):
// 1. resolves first tick immediately → stats non-null
// 2. api.stats rejects on next tick → hook keeps last good stats and sets error
// 3. a hanging promise + an elapsed interval → no overlapping second call
//    (assert api.stats called once while first call is pending)
// 4. unmount clears the interval (no further calls after unmount)
```

Write these four cases as real tests following the polling-test patterns already used in the app's test suite (search for existing fake-timer usage; if `ContainerStatus` has a test today, mirror its structure).

- [ ] **Step 2: Run to verify failure**

Run: `cd app && npx vitest run src/test/format.test.ts src/test/useStats.test.tsx` — FAILS.

- [ ] **Step 3: Implement**

`app/src/lib/format.ts`:

```ts
/** Binary-unit bytes, one decimal above B (410.0 MiB, 1.2 GiB). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return u === 0 ? `${Math.round(v)} B` : `${v.toFixed(1)} ${units[u]}`;
}

/** Uptime as its two most significant units (2h 14m, 3d 5h, 45s). */
export function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/** Meter color class selector: ok < 0.8 ≤ warn < 0.95 ≤ crit. The single
 *  source of the thresholds — every usage bar goes through this. */
export function meterTone(fraction: number): "ok" | "warn" | "crit" {
  if (fraction >= 0.95) return "crit";
  if (fraction >= 0.8) return "warn";
  return "ok";
}
```

`app/src/lib/useStats.ts` — poll loop lifted from ContainerStatus's proven shape (in-flight guard so replies can't race, cancelled guard on unmount, keep last good data on transient failure):

```ts
import { useEffect, useState } from "react";
import { api } from "./ipc";
import type { SandboxStats } from "./types";

/** Single shared stats poller for the Overview tab. Keeps the last good
 *  snapshot through transient failures (error is surfaced alongside), skips
 *  overlapping ticks so replies never resolve out of order. */
export function useStats(name: string, intervalMs = 3000): {
  stats: SandboxStats | null;
  error: string | null;
} {
  const [stats, setStats] = useState<SandboxStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    setStats(null);
    setError(null);
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const s = await api.stats(name);
        if (!cancelled) {
          setStats(s);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [name, intervalMs]);

  return { stats, error };
}
```

`types.ts`: interfaces exactly mirroring Task 7's produces-block (snake_case); extend `SandboxDetail` with `docker: boolean; cpus: number; mem_mb: number; confinement: string | null;`. `ipc.ts`: `stats: (name: string) => invoke<SandboxStats>("stats", { name }),`.

- [ ] **Step 4: Run tests**

Run: `cd app && npx vitest run` — PASS (including existing suites; the SandboxDetail extension is additive).

- [ ] **Step 5: Commit**

```bash
git add app/src/lib/types.ts app/src/lib/ipc.ts app/src/lib/format.ts app/src/lib/useStats.ts app/src/test/format.test.ts app/src/test/useStats.test.tsx
git commit -m "feat(app): stats types, ipc, formatters, shared useStats poller"
```

---

### Task 9: the four-card Overview dashboard

**Files:**
- Create: `app/src/components/overview/Meter.tsx`, `SandboxCard.tsx`, `ResourcesCard.tsx`, `StorageCard.tsx`, `ProcessesCard.tsx`, `OverviewTab.tsx`
- Modify: `app/src/components/Detail.tsx` (header actions + OverviewTab; drop WorkspacePath/ContainerStatus/FirewallStatus imports from Detail)
- Delete: `app/src/components/ContainerStatus.tsx`, `app/src/components/WorkspacePath.tsx` (absorbed; `git rm`; delete their tests if present — search `app/src/test/` for references)
- Keep: `app/src/components/FirewallStatus.tsx` (rendered inside SandboxCard)
- Test: `app/src/test/overview/{meter,sandboxCard,resourcesCard,storageCard,processesCard,overviewTab}.test.tsx`

**Interfaces:**
- Consumes: `useStats`, `formatBytes`, `formatUptime`, `meterTone`, `containerLabel` (existing `app/src/lib/container.ts`), `FirewallStatus`, shadcn `Card` (`@/components/ui/card`), types from Task 8.
- Produces: `<OverviewTab sandbox={SandboxView} />`; `Detail.tsx` renders it for `tab === "overview"` and hosts the action buttons in the header row.

- [ ] **Step 1: Write the failing tests**

All card tests mock `../lib/ipc` (`vi.mock`) and, where simpler, render cards directly with props (design the cards to take their data slice as props and keep `useStats` only in OverviewTab — that makes every degraded state a plain-props test). Cases (one `it` each):

- meter: fraction 0.5 → ok tone class (`bg-success`); 0.85 → warn class; 0.97 → crit class; width style `50%` clamped at 100%.
- SandboxCard: shows state+uptime ("running · 2h 14m"), container label, confinement, workspace; docker row "engine running" when engine running; "engine not running — see logs" + detail text when dead; "engine unknown" when running but `guest` null; NO docker row when `detail.docker` is false; stopped sandbox → no uptime, no container line.
- ResourcesCard: running with host → CPU "34%" and "4 vCPU" visible, MEM "2.5 GiB / 4.0 GiB", guest secondary line "guest: 1.9 GiB used", "load 0.42 · 61 processes"; stopped → renders "not running" placeholder and no bars; running with `host` null (non-Linux) but guest present → guest-derived MEM only, no CPU bar.
- StorageCard: headline excludes image_bytes (fixture: rw 1.2 GiB + docker vol 2.1 GiB + other vol 400 MiB + logs 12 MiB → "3.7 GiB on host"); legend shows docker row with "(21% of 10.0 GiB)" when the guest mount for /var/lib/docker is present; "(shared)" image suffix; no docker segment for a non-docker sandbox.
- ProcessesCard: renders top rows with pid/comm/cpu/mem, caption "guest-reported", footer "61 total"; guest null + running → "guest not responding"; stopped → "not running".
- OverviewTab: with mocked `api.stats` resolving a full fixture — all four cards present; stats error + no data yet → cards render their placeholder states (not a crash).

Build one shared `fixtures.ts` under `app/src/test/overview/` exporting a full `SandboxStats` running fixture (mirror FakeDaemon's numbers from Task 7) plus a stopped variant — keeps the six test files short.

- [ ] **Step 2: Run to verify failure**

Run: `cd app && npx vitest run src/test/overview` — FAILS (components missing).

- [ ] **Step 3: Implement the components**

`Meter.tsx`:

```tsx
import { meterTone } from "../../lib/format";

const TONE_CLASS: Record<ReturnType<typeof meterTone>, string> = {
  ok: "bg-success",
  warn: "bg-warning",
  crit: "bg-destructive",
};

/** Thin horizontal usage bar. `fraction` may exceed 1 (clamped visually). */
export function Meter({ fraction, label }: Readonly<{ fraction: number; label: string }>) {
  const pct = Math.min(1, Math.max(0, fraction)) * 100;
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(pct)}
      className="h-1 w-full overflow-hidden rounded-full bg-muted"
    >
      <div className={`h-full rounded-full ${TONE_CLASS[meterTone(fraction)]}`} style={{ width: `${pct}%` }} />
    </div>
  );
}
```

(Check `app/src/theme.css` / `tailwind.config.ts` for an existing warn/amber token — the repo has `bg-success`/`bg-destructive`; if no `bg-warning` exists, add a `--warning` CSS variable + Tailwind color following exactly how `success` is defined in both files, same shape for dark theme.)

Card skeleton convention for all four (shadcn):

```tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
// header: <CardTitle className="text-sm font-medium">Resources</CardTitle>
// rows: <div className="flex items-baseline justify-between text-sm">…
// labels: <span className="text-muted-foreground-2">…</span>
```

(Check `card.tsx` for the exact exported names before writing; some shadcn generations export `CardTitle`/`CardDescription` differently.)

`ResourcesCard` core logic (illustrative — bars only when the tier exists):

```tsx
export function ResourcesCard({ stats }: Readonly<{ stats: SandboxStats | null }>) {
  if (!stats?.running) return <PlaceholderCard title="Resources" body="not running" />;
  const host = stats.host;
  const guest = stats.guest;
  const cpuFrac =
    host?.cpu_permille != null && host.cpus_limit > 0
      ? host.cpu_permille / (host.cpus_limit * 1000)
      : null;
  const memFrac = host ? host.rss_kb / (host.mem_limit_mb * 1024) : null;
  const guestUsedKb = guest ? guest.mem_total_kb - guest.mem_available_kb : null;
  // CPU row: "34%" big + "4 vCPU" muted + <Meter>; MEM row: "2.5 GiB / 4.0 GiB"
  // + <Meter>; guest secondary line; "load {load1_centi/100} · {process_count}
  // processes" from guest when present.
}
```

`StorageCard` core logic:

```tsx
const dockerBytes = disk.volumes.filter(v => v.docker).reduce((a, v) => a + v.allocated_bytes, 0);
const otherVolBytes = disk.volumes.filter(v => !v.docker).reduce((a, v) => a + v.allocated_bytes, 0);
const total = disk.rw_img_bytes + dockerBytes + otherVolBytes + disk.logs_bytes; // image EXCLUDED: shared
// Segmented bar: one flex row of divs, width = segment/total*100%, colors:
// docker bg-primary, writable bg-success, volumes bg-muted-foreground-2, logs bg-muted;
// omit zero segments. Legend rows: colored square (h-2 w-2 rounded-sm inline-block)
// + label + formatBytes. Docker fullness: find guest mount whose path is
// "/var/lib/docker" → "(N% of {formatBytes(total_bytes)})".
// Trailing muted line: `+ image {formatBytes(disk.image_bytes)} (shared)`.
```

`SandboxCard` rows: state (`StatusDot` reuse + text + `· {formatUptime(uptime_ms)}` when present), container (`containerLabel(guest?.container ?? stats?.container ?? null)` — note: wire `container` for the card comes from `guest.container`; when `guest` is null while running show "unknown"), confinement (`detail.confinement ?? "unknown"`), firewall (`<FirewallStatus name={name} />`), docker engine row (tri-state per the tests), workspace (`detail.workspace`, truncate with `truncate` class + `title` attr). The card receives `detail: SandboxDetail | null` (fetched once via `api.inspect` in OverviewTab, non-polling — workspace/confinement/docker-mode don't change while running) and `stats: SandboxStats | null`.

`ProcessesCard`: `font-mono text-xs` table — `<table className="w-full">` with right-aligned CPU/MEM columns, `{(p.cpu_permille / 10).toFixed(1)}` for CPU %, `formatBytes(p.rss_kb * 1024)` for MEM; slice(0, 10).

`OverviewTab.tsx`:

```tsx
export function OverviewTab({ sandbox }: Readonly<{ sandbox: SandboxView }>) {
  const { stats } = useStats(sandbox.name);
  const [detail, setDetail] = useState<SandboxDetail | null>(null);
  useEffect(() => {
    let alive = true;
    setDetail(null);
    api.inspect(sandbox.name).then(
      (d) => { if (alive) setDetail(d); },
      () => {},
    );
    return () => { alive = false; };
  }, [sandbox.name]);
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <SandboxCard name={sandbox.name} state={sandbox.state} detail={detail} stats={stats} />
      <ResourcesCard stats={stats} />
      <div className="md:col-span-2"><StorageCard stats={stats} detail={detail} /></div>
      <div className="md:col-span-2"><ProcessesCard stats={stats} /></div>
    </div>
  );
}
```

`Detail.tsx` changes:
- Header row becomes `flex items-center justify-between`: left = StatusDot + name + image line; right = the four action buttons (moved intact — the `act`/`pending`/`label` machinery already lives in Detail; keep it there).
- `{tab === "overview" && <OverviewTab sandbox={sandbox} />}` replaces the inline block; the error line from actions stays near the buttons; `git rm` ContainerStatus.tsx + WorkspacePath.tsx and update any tests referencing them.

- [ ] **Step 4: Run tests + full app gate**

Run: `cd app && npx vitest run && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)` — PASS. Also `npx eslint .` if the repo's app lint script exists (check package.json scripts; Sonar gate is strict).

- [ ] **Step 5: Commit**

```bash
git add app/src/components/overview app/src/components/Detail.tsx app/src/test/overview
git rm app/src/components/ContainerStatus.tsx app/src/components/WorkspacePath.tsx
git commit -m "feat(app): four-card Overview dashboard (sandbox/resources/storage/processes)"
```

---

### Task 10: KVM e2e coverage + docs

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (guest + daemon stats assertions on a real VM)
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (status engine line on the docker e2e sandbox)
- Modify: `CLAUDE.md` (contracts: proto v5, Stats RPC, trust boundary)

**Interfaces:**
- Consumes: everything above.
- Produces: real-VM proof that the numbers are live, sane, and the engine line works.

- [ ] **Step 1: Add integration assertions**

In `integration.rs`, extend the existing docker-mode test (`docker_mode_engine_runs_containers`) — after the engine is known-up, open a control connection the way the test file already does for Health/exec and assert:

```rust
// [stats] Guest stats are live and sane on a real VM.
let mut c = /* existing control-conn helper */;
izba_proto::write_frame(&mut c, &izba_proto::Request::Stats).unwrap();
match izba_proto::read_frame::<_, izba_proto::Response>(&mut c).unwrap() {
    izba_proto::Response::Stats(g) => {
        assert!(g.process_count >= 1, "at least init+crun+dockerd: {}", g.process_count);
        assert!(g.mem_total_kb > 100_000, "meminfo parsed: {}", g.mem_total_kb);
        assert!(!g.mounts.is_empty(), "overlay statfs reported");
        let e = g.docker.expect("docker engine status present in docker mode");
        assert!(e.running, "dockerd detected by comm scan: {:?}", e.detail);
        assert!(g.container.is_some());
    }
    other => panic!("expected Stats, got {other:?}"),
}
```

And in a NON-docker lifecycle test, assert `g.docker.is_none()`.

- [ ] **Step 2: Add daemon_e2e assertions**

In `daemon_e2e.rs`'s docker test, after the sandbox is running: run `izba status <name>` via the existing CLI-invocation helper and assert stdout contains `mode:        docker` AND `engine:      running`. In the same test (or an existing stats-suitable spot), drive `DaemonRequest::Stats` through a daemon client if the file has one handy and assert `disk.rw_img_bytes > 0 && host.is_some() && guest.is_some()`; if the file only exercises the CLI surface, the status assertion suffices.

- [ ] **Step 3: Run the real-VM suites** (unsandboxed; KVM works here)

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1` and `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1` — PASS.

- [ ] **Step 4: Update CLAUDE.md**

In the load-bearing contracts section, extend the vsock-ports bullet: control port 1025 also serves `Request::Stats` (guest-reported, daemon-sanitized; ~250 ms in-call CPU sampling), and note `DAEMON_PROTO_VERSION = 5` (v5 = `DaemonRequest::Stats`). One or two sentences — CLAUDE.md stays terse.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/tests/integration.rs crates/izba-cli/tests/daemon_e2e.rs CLAUDE.md
git commit -m "test(e2e): real-VM stats sanity + docker engine visibility; document stats contract"
```
