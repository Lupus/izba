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
/// tempdir in tests). Every target file is expected to already exist — a real
/// cgroupfs never needs one created (`cgroup.subtree_control` is always
/// present in an existing cgroup directory) — so a missing file is reported
/// as an error rather than silently created. Controllers a kernel lacks make
/// the write fail too — the caller treats delegation failure as
/// loud-but-nonfatal (dockerd still starts; nested limits degrade honestly).
pub fn apply_delegation(cgroup_root: &Path, container_cgroup: &str) -> std::io::Result<()> {
    for (rel, value) in delegation_plan(container_cgroup) {
        let path = cgroup_root.join(rel);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)?;
        f.write_all(value.as_bytes())?;
    }
    Ok(())
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
        std::fs::create_dir_all(root.path().join("izba")).unwrap();
        std::fs::write(root.path().join("cgroup.subtree_control"), "").unwrap();
        apply_delegation(root.path(), "/izba").unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory +pids +io"
        );
    }

    #[test]
    fn apply_delegation_missing_file_is_reported() {
        let root = tempfile::tempdir().unwrap();
        assert!(apply_delegation(root.path(), "/izba").is_err());
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
