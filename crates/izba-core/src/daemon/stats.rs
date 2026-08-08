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
            g.processes.push(ProcSample {
                pid: i,
                comm: "x".into(),
                state: 'S',
                cpu_permille: 0,
                rss_kb: 0,
            });
            g.mounts.push(MountUsage {
                path: format!("/m{i}"),
                total_bytes: 0,
                avail_bytes: 0,
            });
        }
        let s = sanitize_guest_stats(g);
        assert_eq!(s.processes.len(), MAX_PROCESSES);
        assert_eq!(s.mounts.len(), MAX_MOUNTS);
    }

    #[test]
    fn caps_docker_detail_and_mount_paths() {
        let mut g = base();
        g.docker = Some(DockerEngine {
            running: false,
            detail: Some(format!("\n\nboom{}", "b".repeat(1000))),
        });
        g.mounts.push(MountUsage {
            path: format!("/{}", "p".repeat(1000)),
            total_bytes: 1,
            avail_bytes: 1,
        });
        let s = sanitize_guest_stats(g);
        let d = s.docker.unwrap().detail.unwrap();
        assert!(d.chars().count() <= MAX_DETAIL);
        assert!(!d.contains('\n'));
        assert!(s.mounts[0].path.chars().count() <= MAX_PATH);
    }
}
