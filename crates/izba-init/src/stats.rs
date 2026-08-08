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
    Some(ProcRaw {
        pid,
        comm,
        state,
        ticks: utime + stime,
        rss_pages,
    })
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
            let delta = p
                .ticks
                .saturating_sub(prev.get(&p.pid).copied().unwrap_or(p.ticks));
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
    (
        rows.into_iter().take(TOP_N).map(|(_, s)| s).collect(),
        count,
    )
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
        out.push(MountUsage {
            path: "/".into(),
            total_bytes: total,
            avail_bytes: avail,
        });
    }
    for gp in volume_paths {
        let real = rootfs.join(gp.trim_start_matches('/'));
        if let Some((total, avail)) = statfs(&real) {
            out.push(MountUsage {
                path: gp.clone(),
                total_bytes: total,
                avail_bytes: avail,
            });
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
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
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
    let (processes, process_count) = compute_processes(
        &before,
        &after,
        SAMPLE_INTERVAL_MS,
        ctx.clk_tck.max(1),
        ctx.page_kb,
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake_proc(
        dir: &std::path::Path,
        pid: u32,
        comm: &str,
        state: char,
        ticks: u64,
        rss_pages: u64,
    ) {
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
            .map(|i| ProcRaw {
                pid: i,
                comm: format!("p{i}"),
                state: 'S',
                ticks: 1000,
                rss_pages: 10,
            })
            .collect();
        let after: Vec<ProcRaw> = (1..=20)
            .map(|i| ProcRaw {
                pid: i,
                comm: format!("p{i}"),
                state: 'S',
                ticks: 1000 + i as u64,
                rss_pages: 10,
            })
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
        let after = vec![ProcRaw {
            pid: 9,
            comm: "fresh".into(),
            state: 'R',
            ticks: 1_000_000,
            rss_pages: 1,
        }];
        let (samples, _) = compute_processes(&before, &after, 250, 100, 4);
        assert_eq!(samples[0].cpu_permille, 0);
    }

    #[test]
    fn parse_meminfo_extracts_total_and_available() {
        let s =
            "MemTotal:        4046412 kB\nMemFree:          1000 kB\nMemAvailable:    2012004 kB\n";
        assert_eq!(parse_meminfo(s), (4_046_412, 2_012_004));
    }

    #[test]
    fn parse_loadavg_to_centi() {
        assert_eq!(parse_loadavg("0.42 0.30 1.19 2/61 812\n"), (42, 30, 119));
        assert_eq!(parse_loadavg("garbage"), (0, 0, 0));
    }

    #[test]
    fn engine_status_detects_dockerd_process() {
        let procs = vec![ProcRaw {
            pid: 7,
            comm: "dockerd".into(),
            state: 'S',
            ticks: 0,
            rss_pages: 0,
        }];
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
