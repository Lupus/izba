//! OCI container lifecycle using crun inside the guest.
//!
//! Responsibilities (all host-testable except the actual crun exec):
//!
//! 1. Mount the `izba-oci` virtiofs bundle share (handled in `mounts.rs`).
//! 2. Install the pause binary at `PAUSE_GUEST_PATH` inside the overlay.
//! 3. Detect the cgroup manager available on this kernel.
//! 4. Build the `crun run --detach` argv and launch the container.
//! 5. Parse `crun state` output to check container health.
//!
//! The launch function is intentionally thin: it is a thin wrapper around the
//! testable pieces so the unit tests can cover every branch without a live crun.

use std::path::PathBuf;

// ──────────────────────────────────────────────────────────────────────────────
// Constants re-exported from izba-proto; derived paths are computed here once
// so callers get a single source of truth.
// ──────────────────────────────────────────────────────────────────────────────

/// virtiofs tag for the OCI bundle share (same value as `izba_proto::OCI_TAG`;
/// defined here so callers within izba-init can import from a single place
/// without depending on izba-proto directly).
pub const BUNDLE_TAG: &str = izba_proto::OCI_TAG;

/// Guest mountpoint of the OCI bundle share (under the overlay root).
/// `config.json` is at `<BUNDLE_MOUNT>/config.json`; crun is called with
/// `-b <BUNDLE_MOUNT>`.
pub const BUNDLE_MOUNT: &str = "/rootfs/izba-oci";

/// Host path of the pause binary once the overlay is assembled.
///
/// `PAUSE_GUEST_PATH` = `/.izba/pause` (in the container's view, i.e.
/// relative to `/rootfs`). From init's perspective the overlay is at
/// `/rootfs`, so the host path is `/rootfs` + `PAUSE_GUEST_PATH`.
pub fn pause_host_path() -> PathBuf {
    let guest = izba_proto::PAUSE_GUEST_PATH;
    PathBuf::from("/rootfs").join(guest.strip_prefix('/').unwrap_or(guest))
}

/// Host path of the pause binary's parent directory.
pub fn pause_host_dir() -> PathBuf {
    // PAUSE_GUEST_PATH = "/.izba/pause" → parent ".izba" → host "/rootfs/.izba"
    pause_host_path()
        .parent()
        .expect("PAUSE_GUEST_PATH must have a parent dir")
        .to_path_buf()
}

/// Fixed container id. All crun state/exec calls use this name.
pub const CONTAINER_ID: &str = "izba";

/// Path to the vendored static crun binary.
pub const CRUN_PATH: &str = "/sbin/crun";

/// Guest path for crun's stdout+stderr log (writable tmpfs is always mounted).
pub const CRUN_LOG_PATH: &str = "/tmp/crun.log";

/// Maximum number of bytes to tail from `CRUN_LOG_PATH` when reporting a
/// failed container start.
const LOG_TAIL_BYTES: usize = 2048;

// ──────────────────────────────────────────────────────────────────────────────
// Cgroup manager detection
// ──────────────────────────────────────────────────────────────────────────────

/// Which cgroup manager to pass to crun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupManager {
    /// cgroup2 is mounted and functional; crun can create sub-cgroups.
    Cgroupfs,
    /// No working cgroup2 hierarchy; tell crun to skip cgroup accounting.
    Disabled,
}

impl CgroupManager {
    /// The `--cgroup-manager=<value>` string for this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            CgroupManager::Cgroupfs => "cgroupfs",
            CgroupManager::Disabled => "disabled",
        }
    }
}

/// Detect the available cgroup manager, mirroring the spike's logic.
///
/// 1. Mount `cgroup2` at `/sys/fs/cgroup` if it is not already mounted.
/// 2. If `/sys/fs/cgroup/cgroup.controllers` exists → `cgroupfs`.
/// 3. Otherwise → `disabled`.
///
/// The mount attempt is best-effort: if it fails (already mounted or
/// permission denied in tests), we still probe `cgroup.controllers`.
pub fn detect_cgroup_manager() -> CgroupManager {
    // Try to mount cgroup2 if not already present. Failure is fine (it may
    // already be mounted, or we may be in a unit-test environment).
    let _ = nix::mount::mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        CgroupManager::Cgroupfs
    } else {
        CgroupManager::Disabled
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Argv construction (pure, fully testable)
// ──────────────────────────────────────────────────────────────────────────────

/// Build the `crun run` argument vector for `CONTAINER_ID`.
///
/// Returns the full argv to exec (first element is the binary path).
pub fn crun_run_argv(cgroup_manager: CgroupManager) -> Vec<String> {
    vec![
        CRUN_PATH.to_string(),
        format!("--cgroup-manager={}", cgroup_manager.as_str()),
        "run".to_string(),
        "--detach".to_string(),
        CONTAINER_ID.to_string(),
        "-b".to_string(),
        BUNDLE_MOUNT.to_string(),
    ]
}

/// Build the `crun state` argument vector for `container_id`.
#[allow(dead_code)]
pub fn crun_state_argv(container_id: &str) -> Vec<String> {
    vec![
        CRUN_PATH.to_string(),
        "state".to_string(),
        container_id.to_string(),
    ]
}

// ──────────────────────────────────────────────────────────────────────────────
// crun state JSON parse
// ──────────────────────────────────────────────────────────────────────────────

/// Returns `true` when `crun state` output indicates the container is running.
///
/// `crun state` emits OCI state JSON with a `"status"` field. The value is
/// `"running"` when the container is live; `"stopped"`, `"created"`, or absent
/// when it is not. An unparseable output is treated as not-running.
pub fn parse_crun_state_running(json: &str) -> bool {
    // We only need the "status" field, so a simple substring search is fine and
    // avoids pulling in serde_json into the musl binary.
    // OCI state spec: status ∈ { "creating", "created", "running", "stopped" }
    // crun additionally emits "paused".
    extract_status_field(json)
        .map(|s| s == "running")
        .unwrap_or(false)
}

/// Extracts the value of the `"status"` key from a JSON object without a full
/// JSON parser.  Returns `None` when the key is absent or the value is not a
/// simple quoted string.
fn extract_status_field(json: &str) -> Option<&str> {
    // Parser assumption: we return the value of the FIRST `"status"` occurrence
    // in the JSON text.  This is correct for crun's OCI state JSON because no
    // earlier field name or string value contains the literal substring
    // `"status"` — the field always appears at the top level and is the only
    // occurrence.  The extracted value is then compared exactly to `"running"`,
    // so transitional/other states ("created", "stopped", "paused", "creating")
    // all correctly map to not-running.
    //
    // Look for `"status"` followed by optional whitespace, `:`, optional
    // whitespace, and a quoted string value.
    let key_pos = json.find("\"status\"")?;
    let after_key = &json[key_pos + 8..]; // len("\"status\"") = 8
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let end = inner.find('"')?;
    Some(&inner[..end])
}

// ──────────────────────────────────────────────────────────────────────────────
// Pause binary installation
// ──────────────────────────────────────────────────────────────────────────────

/// Copy the running init binary to `pause_host_path()` so it is available
/// inside the container at `PAUSE_GUEST_PATH`.
///
/// The overlay upper is writable, so the copy persists across the container
/// lifetime.  Uses `std::env::current_exe()` to locate the running binary
/// (typically `/init` in the guest).
///
/// Returns `Err` on any I/O failure.
pub fn install_pause_binary() -> std::io::Result<()> {
    let src = std::env::current_exe()?;
    let dir = pause_host_dir();
    std::fs::create_dir_all(&dir)?;
    let dst = pause_host_path();
    std::fs::copy(&src, &dst)?;
    // chmod 0755 so it is executable from inside the container.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&dst, perms)?;
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Container launch
// ──────────────────────────────────────────────────────────────────────────────

/// Launch the OCI workload container with crun and report success/failure.
///
/// This function:
/// 1. Installs the pause binary (fail-soft: logs the error, continues).
/// 2. Detects the cgroup manager.
/// 3. Runs `crun run --detach izba -b <bundle>`, redirecting crun's
///    stdout+stderr to `CRUN_LOG_PATH`.
/// 4. On failure, prints a prominent error to the serial console including
///    the crun exit code and the tail of the crun log.
///
/// **Does NOT exit or panic on failure** — a failed container start leaves
/// the VM alive and diagnosable; the controlling process decides next steps.
pub fn launch_container() {
    // Step 1: install pause binary.
    if let Err(e) = install_pause_binary() {
        eprintln!("izba-init: [OCI] installing pause binary: {e}");
        // Continue: the container start will fail and that gives better info.
    }

    // Step 2: cgroup manager.
    let cgmgr = detect_cgroup_manager();
    eprintln!("izba-init: [OCI] cgroup manager: {}", cgmgr.as_str());

    // Step 3: launch crun.
    let argv = crun_run_argv(cgmgr);
    eprintln!("izba-init: [OCI] launching container: {:?}", argv);

    // Open crun.log for stdout+stderr capture.
    let log_file = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(CRUN_LOG_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("izba-init: [OCI] cannot open {CRUN_LOG_PATH}: {e}; crun output lost");
            // Fall back: we can still launch crun, its output goes nowhere.
            // Build a /dev/null fallback.
            match std::fs::OpenOptions::new().write(true).open("/dev/null") {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("izba-init: [OCI] cannot open /dev/null either; aborting launch");
                    return;
                }
            }
        }
    };

    use std::os::unix::io::IntoRawFd;
    let log_fd = log_file.into_raw_fd();

    // SAFETY: the fd is valid (just opened) and we dup2 it before exec.
    let status = unsafe {
        // Fork and exec crun with stdout+stderr → log_fd.
        launch_crun_child(&argv, log_fd)
    };

    // Close the log fd in the parent (the child side is closed at exec).
    unsafe {
        libc::close(log_fd);
    }

    match status {
        Ok(0) => {
            eprintln!("izba-init: [OCI] container started OK");
        }
        Ok(code) => {
            let tail = read_log_tail(CRUN_LOG_PATH, LOG_TAIL_BYTES);
            eprintln!(
                "izba-init: [OCI] *** CONTAINER START FAILED *** crun exited with code {code}"
            );
            eprintln!("izba-init: [OCI] --- crun log tail ({CRUN_LOG_PATH}) ---");
            eprintln!("{tail}");
            eprintln!("izba-init: [OCI] --- end crun log ---");
            eprintln!("izba-init: [OCI] sandbox is alive but workload container is NOT running");
        }
        Err(e) => {
            eprintln!("izba-init: [OCI] *** CONTAINER START ERROR ***: {e}");
            eprintln!("izba-init: [OCI] sandbox is alive but workload container is NOT running");
        }
    }
}

/// Fork, dup2 `log_fd` onto stdout+stderr of the child, then exec crun.
/// Waits for the child and returns its exit code, or an error.
///
/// # Safety
/// The caller must ensure `log_fd` is a valid, open file descriptor.
unsafe fn launch_crun_child(argv: &[String], log_fd: libc::c_int) -> std::io::Result<i32> {
    // Build the CString argv and the pointer array BEFORE fork so the child
    // never allocates or panics (inheriting the parent's malloc locks would be
    // unsafe in a multi-threaded PID-1).  If any argument contains an interior
    // NUL (impossible with our static argv, but handle it honestly), fail in
    // the parent before forking.
    let c_strings: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| {
            std::ffi::CString::new(s.as_str()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("argv contains interior NUL: {e}"),
                )
            })
        })
        .collect::<std::io::Result<_>>()?;
    let mut c_ptrs: Vec<*const libc::c_char> = c_strings
        .iter()
        .map(|cs| cs.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let pid = libc::fork();
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: redirect stdout + stderr to the log file.
        libc::dup2(log_fd, libc::STDOUT_FILENO);
        libc::dup2(log_fd, libc::STDERR_FILENO);
        libc::close(log_fd);

        // argv and pointer array are already built; no allocation here.
        libc::execv(c_ptrs[0], c_ptrs.as_mut_ptr());
        // execv failed; write to the log (which is on fd 1/2 now) and exit.
        let msg = b"execv failed\n";
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        libc::_exit(127);
    }

    // Parent: wait for crun.
    let mut status: libc::c_int = 0;
    loop {
        let ret = libc::waitpid(pid, &mut status, 0);
        if ret == pid {
            break;
        }
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR — retry.
            }
            return Err(err);
        }
    }

    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(-1)
    }
}

/// Read the last `max_bytes` of a file as a UTF-8 string (lossily).
fn read_log_tail(path: &str, max_bytes: usize) -> String {
    let data = std::fs::read(path).unwrap_or_default();
    let start = data.len().saturating_sub(max_bytes);
    String::from_utf8_lossy(&data[start..]).into_owned()
}

/// Check whether the container with `id` is currently running by invoking
/// `crun state <id>` and parsing the OCI state JSON.
///
/// Returns `false` if crun fails or the state is not "running".
///
/// Used by the controller validation checkpoint and future exec integration
/// (task 4: exec enters the container instead of bare chroot).
#[allow(dead_code)]
pub fn container_running(id: &str) -> bool {
    let out = std::process::Command::new(CRUN_PATH)
        .args(["state", id])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            parse_crun_state_running(&String::from_utf8_lossy(&o.stdout))
        }
        _ => false,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests (host-testable; no live crun, no VM, no socket bind)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants derived from izba-proto ────────────────────────────────────

    #[test]
    fn bundle_tag_matches_proto_oci_tag() {
        // BUNDLE_TAG is a re-export of izba_proto::OCI_TAG.
        assert_eq!(BUNDLE_TAG, izba_proto::OCI_TAG);
        assert_eq!(BUNDLE_TAG, "izba-oci");
    }

    #[test]
    fn bundle_mount_is_under_rootfs() {
        assert!(BUNDLE_MOUNT.starts_with("/rootfs/"));
    }

    #[test]
    fn pause_host_path_is_rootfs_plus_pause_guest_path() {
        let guest = izba_proto::PAUSE_GUEST_PATH;
        let expected = PathBuf::from("/rootfs").join(guest.strip_prefix('/').unwrap_or(guest));
        assert_eq!(pause_host_path(), expected);
        // Spot-check the literal value: PAUSE_GUEST_PATH = "/.izba/pause"
        assert_eq!(pause_host_path(), PathBuf::from("/rootfs/.izba/pause"));
    }

    #[test]
    fn pause_host_dir_is_parent_of_pause_host_path() {
        assert_eq!(pause_host_dir(), PathBuf::from("/rootfs/.izba"));
    }

    // ── crun run argv construction ───────────────────────────────────────────

    #[test]
    fn crun_run_argv_cgroupfs_branch() {
        let argv = crun_run_argv(CgroupManager::Cgroupfs);
        assert_eq!(argv[0], CRUN_PATH);
        assert_eq!(argv[1], "--cgroup-manager=cgroupfs");
        assert_eq!(argv[2], "run");
        assert_eq!(argv[3], "--detach");
        assert_eq!(argv[4], CONTAINER_ID);
        assert_eq!(argv[5], "-b");
        assert_eq!(argv[6], BUNDLE_MOUNT);
        assert_eq!(argv.len(), 7);
    }

    #[test]
    fn crun_run_argv_disabled_branch() {
        let argv = crun_run_argv(CgroupManager::Disabled);
        assert_eq!(argv[1], "--cgroup-manager=disabled");
        // Rest of argv is identical to cgroupfs branch.
        assert_eq!(argv[2], "run");
        assert_eq!(argv[3], "--detach");
        assert_eq!(argv[4], CONTAINER_ID);
        assert_eq!(argv[5], "-b");
        assert_eq!(argv[6], BUNDLE_MOUNT);
    }

    #[test]
    fn crun_run_argv_no_no_pivot() {
        // The production config uses the overlay root which supports pivot_root;
        // --no-pivot must NOT be present.
        let argv = crun_run_argv(CgroupManager::Cgroupfs);
        assert!(
            !argv.iter().any(|a| a == "--no-pivot"),
            "--no-pivot must not appear in the production argv"
        );
    }

    #[test]
    fn crun_state_argv_contains_id() {
        let argv = crun_state_argv("izba");
        assert_eq!(argv[0], CRUN_PATH);
        assert_eq!(argv[1], "state");
        assert_eq!(argv[2], "izba");
        assert_eq!(argv.len(), 3);
    }

    // ── crun state JSON parse ────────────────────────────────────────────────

    #[test]
    fn parse_running_status_returns_true() {
        let json = r#"{"ociVersion":"1.0.2","id":"izba","pid":42,"status":"running","bundle":"/rootfs/izba-oci","rootfs":"/rootfs","created":"2026-01-01T00:00:00.0Z","owner":""}"#;
        assert!(parse_crun_state_running(json));
    }

    #[test]
    fn parse_stopped_status_returns_false() {
        let json = r#"{"ociVersion":"1.0.2","id":"izba","pid":0,"status":"stopped","bundle":"/rootfs/izba-oci","rootfs":"/rootfs","created":"2026-01-01T00:00:00.0Z","owner":""}"#;
        assert!(!parse_crun_state_running(json));
    }

    #[test]
    fn parse_created_status_returns_false() {
        let json = r#"{"status":"created","id":"izba"}"#;
        assert!(!parse_crun_state_running(json));
    }

    #[test]
    fn parse_empty_string_returns_false() {
        assert!(!parse_crun_state_running(""));
    }

    #[test]
    fn parse_missing_status_field_returns_false() {
        assert!(!parse_crun_state_running(r#"{"id":"izba"}"#));
    }

    #[test]
    fn parse_paused_status_returns_false() {
        let json = r#"{"status":"paused","id":"izba"}"#;
        assert!(!parse_crun_state_running(json));
    }

    #[test]
    fn parse_with_whitespace_around_colon() {
        let json = r#"{ "status" : "running" }"#;
        assert!(parse_crun_state_running(json));
    }

    // ── OCI mount op shape (mirrors mounts.rs test convention) ──────────────
    // These tests verify that the mount added in mounts.rs has the right shape
    // without importing mounts directly; we import from the parent (mounts is
    // not pub here). Instead we verify the expected contract values are correct.

    #[test]
    fn bundle_tag_and_mount_constants_are_consistent() {
        // The mount op in mounts.rs uses OCI_TAG as source and BUNDLE_MOUNT as
        // target. Check they are coherent.
        assert_eq!(BUNDLE_TAG, "izba-oci");
        assert_eq!(BUNDLE_MOUNT, "/rootfs/izba-oci");
        // Bundle mount must be under /rootfs so the bundle is accessible to init.
        let mount_path = std::path::Path::new(BUNDLE_MOUNT);
        assert!(mount_path.starts_with("/rootfs"));
    }

    #[test]
    fn cgroup_manager_as_str() {
        assert_eq!(CgroupManager::Cgroupfs.as_str(), "cgroupfs");
        assert_eq!(CgroupManager::Disabled.as_str(), "disabled");
    }

    // ── extract_status_field internal ────────────────────────────────────────

    #[test]
    fn extract_status_field_finds_value() {
        assert_eq!(
            extract_status_field(r#"{"status":"running"}"#),
            Some("running")
        );
        assert_eq!(
            extract_status_field(r#"{"status" : "stopped" }"#),
            Some("stopped")
        );
    }

    #[test]
    fn extract_status_field_absent() {
        assert_eq!(extract_status_field(r#"{"id":"x"}"#), None);
        assert_eq!(extract_status_field(""), None);
    }
}
