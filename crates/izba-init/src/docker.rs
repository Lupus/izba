//! Docker-mode engine plumbing (spec §2 delegation + §5 auto-start).
//!
//! Docker-mode sandboxes run a full container engine (dockerd) INSIDE the
//! izba-managed OCI container, so it can itself create nested cgroups for the
//! containers it launches. That requires the guest cgroup2 hierarchy to
//! **delegate** control down into the container's own cgroup — writing
//! `+controller` entries into every ancestor's `cgroup.subtree_control` file
//! (crun/dockerd manage everything at and below the container's own cgroup
//! themselves). Once delegation is applied, [`start_engine`] execs dockerd
//! inside the running container via `crun exec` — fire-and-forget, no
//! auto-restart (a dead engine stays dead until the sandbox itself restarts,
//! matching every other izba workload process).

use std::io::Write;
use std::path::{Path, PathBuf};

/// In-container log for the auto-started engine — the honest record when
/// dockerd is missing or dies (no auto-restart; restart = sandbox restart).
pub const ENGINE_LOG: &str = "/var/log/izba-dockerd.log";

/// The controllers delegated into the container's cgroup subtree.
const CONTROLLERS: &str = "+cpu +memory +pids +io";

/// The subtree_control writes that let the container cgroup create
/// controller-bearing children: the root and every ancestor of the
/// container cgroup (exclusive of the container cgroup itself — crun/the
/// engine manage below that point). Pure; [`apply_delegation`] executes.
pub fn delegation_plan(container_cgroup: &str) -> Vec<(PathBuf, String)> {
    let segments: Vec<&str> = container_cgroup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    // Prefixes of length 0..segments.len() are the root plus every ancestor,
    // EXCLUDING the full path (the container cgroup itself, which crun/the
    // engine own below this point).
    (0..segments.len())
        .map(|i| {
            let prefix = segments[..i].join("/");
            let path = if prefix.is_empty() {
                PathBuf::from("cgroup.subtree_control")
            } else {
                PathBuf::from(format!("{prefix}/cgroup.subtree_control"))
            };
            (path, CONTROLLERS.to_string())
        })
        .collect()
}

/// Execute the plan against `cgroup_root` (`/sys/fs/cgroup` in the guest; a
/// tempdir in tests) with **per-controller, best-effort writes**: each
/// controller token in a plan entry (e.g. `"+cpu"`, `"+io"`) is written to
/// its `cgroup.subtree_control` file as an INDEPENDENT write, opening the
/// file fresh each time. This matters because cgroup v2 rejects an entire
/// multi-token write (`EINVAL`) the instant ANY one controller in it is
/// unavailable — so a single missing controller must never take the others
/// down with it. A missing `cgroup.subtree_control` file (no such cgroup
/// directory) or a kernel-refused controller both fail only THAT write; they
/// are logged and the loop continues to the next controller/level. Returns
/// `Ok` as long as at least one controller write across the whole plan
/// succeeded; `Err` (the last observed error) only when every single write —
/// every controller, every ancestor level — failed. The caller treats even an
/// `Err` as loud-but-nonfatal (dockerd still starts; nested limits degrade
/// honestly).
pub fn apply_delegation(cgroup_root: &Path, container_cgroup: &str) -> std::io::Result<()> {
    let plan = delegation_plan(container_cgroup);
    if plan.is_empty() {
        return Ok(());
    }
    let mut any_written = false;
    let mut last_err: Option<std::io::Error> = None;
    for (rel, controllers) in plan {
        let path = cgroup_root.join(rel);
        for controller in controllers.split_whitespace() {
            match write_controller(&path, controller) {
                Ok(()) => any_written = true,
                Err(e) => {
                    eprintln!(
                        "izba-init: docker-mode cgroup delegation: writing {controller} to {}: {e}",
                        path.display()
                    );
                    last_err = Some(e);
                }
            }
        }
    }
    if any_written {
        Ok(())
    } else {
        Err(last_err.expect("non-empty plan always attempts at least one controller write"))
    }
}

/// Write a single controller token (e.g. `"+cpu"`) to `path`, opening it
/// fresh for this one write — the unit of failure cgroup v2 actually uses
/// (one `write(2)` per control message), so one controller's `EINVAL` can
/// never poison a sibling controller's write.
fn write_controller(path: &Path, controller: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    writeln!(f, "{controller}")
}

/// Extract the container's cgroup path out of `/proc/<pid>/cgroup` content.
///
/// The guest kernel is unified-hierarchy (cgroup v2 only), so the file has
/// exactly one line in the `0::<path>` form. Returns `None` when that line is
/// absent (unparseable/legacy content) so the caller can report an honest
/// "cgroup unknown" rather than guessing.
pub fn parse_cgroup_path(proc_cgroup: &str) -> Option<String> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
}

/// `crun exec` argv that starts the engine detached-by-spawn: probe for
/// dockerd, log honestly if absent, else exec it with output to
/// [`ENGINE_LOG`]. Runs as container root (`--user 0:0`) — dockerd needs root
/// to manage its own cgroups/netns/mounts inside the container.
pub fn dockerd_exec_argv(cgroup_manager: crate::oci::CgroupManager) -> Vec<String> {
    let script = format!(
        "mkdir -p /var/log; if command -v dockerd >/dev/null 2>&1; then exec dockerd >>{ENGINE_LOG} 2>&1; else echo 'izba: docker mode is on but the image ships no dockerd' >>{ENGINE_LOG}; fi"
    );
    crate::oci::crun_exec_argv(
        cgroup_manager,
        false,
        "/",
        &[],
        Some("0:0"),
        &["/bin/sh".into(), "-c".into(), script],
    )
}

/// Spawn the engine fire-and-forget (`Command::spawn` is non-blocking, just
/// like every exec in `exec.rs`; the caller does not wait). A dead dockerd
/// stays dead — no auto-restart philosophy.
// reason: forks a live /sbin/crun against the running container — guest-only;
// the argv it builds is unit-tested via dockerd_exec_argv.
#[mutants::skip]
pub fn start_engine() {
    let cgmgr = crate::oci::detect_cgroup_manager();
    let argv = dockerd_exec_argv(cgmgr);
    if let Err(e) = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .spawn()
    {
        eprintln!("izba-init: docker-mode engine spawn failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_plan_enables_controllers_down_the_chain() {
        // Container cgroup "/izba" ⇒ enable controllers in the root's
        // subtree_control so /izba can create controller-bearing children.
        let plan = delegation_plan("/izba");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, PathBuf::from("cgroup.subtree_control"));
        assert_eq!(plan[0].1, "+cpu +memory +pids +io");
        // Nested container cgroup ⇒ every ancestor below the root, plus the root.
        let plan = delegation_plan("/a/b");
        let files: Vec<_> = plan
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            files,
            vec!["cgroup.subtree_control", "a/cgroup.subtree_control"]
        );
    }

    #[test]
    fn apply_delegation_writes_fake_cgroupfs() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("cgroup.subtree_control"), "").unwrap();
        apply_delegation(root.path(), "/izba").unwrap();
        // Each controller is its own independent write (opened fresh, not one
        // joined write) — assert all four landed, proving each was actually
        // attempted rather than only the last one surviving a truncate.
        let content = std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap();
        for token in ["+cpu", "+memory", "+pids", "+io"] {
            assert!(content.contains(token), "missing {token} in {content:?}");
        }
    }

    #[test]
    fn apply_delegation_missing_file_is_reported() {
        let root = tempfile::tempdir().unwrap();
        assert!(apply_delegation(root.path(), "/izba").is_err());
    }

    #[test]
    fn apply_delegation_one_ancestor_level_failing_does_not_block_others() {
        // Faithfully injecting a SINGLE CONTROLLER's failure needs real
        // cgroup2 content validation (a plain tempdir file accepts any bytes
        // — there is no "+bogus-controller is EINVAL but +cpu is fine" to
        // fake short of a real kernel). What IS cheap and meaningful here:
        // proving the write LOOP doesn't `?`-abort the whole delegation the
        // moment one PLAN ENTRY fails — i.e. a missing ancestor level must
        // not prevent a level that does exist from still getting delegated.
        // The true per-controller EINVAL-degrades-only-itself path is left
        // to Task 7's real-VM boot (see the report's Task 7 concerns).
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("cgroup.subtree_control"), "").unwrap();
        // Deliberately do NOT create "a/cgroup.subtree_control" — container
        // cgroup "/a/b" needs both the root and "a" delegated.
        apply_delegation(root.path(), "/a/b").unwrap(); // Ok: the root level succeeded.
        let content = std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap();
        for token in ["+cpu", "+memory", "+pids", "+io"] {
            assert!(content.contains(token), "missing {token} in {content:?}");
        }
    }

    #[test]
    fn dockerd_exec_argv_runs_engine_as_root_with_honest_logging() {
        let argv = dockerd_exec_argv(crate::oci::CgroupManager::Cgroupfs);
        assert_eq!(argv[0], crate::oci::CRUN_PATH);
        let joined = argv.join(" ");
        assert!(joined.contains("exec"));
        assert!(
            joined.contains("--user 0:0"),
            "engine starts as container root"
        );
        // The in-container command: probe for dockerd, log honestly either way.
        let cmd = argv.last().unwrap();
        assert!(cmd.contains("command -v dockerd"), "must probe before exec");
        assert!(
            cmd.contains(ENGINE_LOG),
            "stdout/err to the honest log file"
        );
        assert!(
            cmd.contains("exec dockerd"),
            "engine replaces the probe shell"
        );
    }

    #[test]
    fn parse_cgroup_path_extracts_unified_hierarchy_path() {
        assert_eq!(parse_cgroup_path("0::/izba\n"), Some("/izba".to_string()));
        assert_eq!(parse_cgroup_path("0::/\n"), Some("/".to_string()));
        assert_eq!(parse_cgroup_path(""), None);
        assert_eq!(parse_cgroup_path("garbage\n"), None);
    }
}
