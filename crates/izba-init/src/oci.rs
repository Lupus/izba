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
use std::time::{Duration, Instant};

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

/// Guest path for crun's structured `--log` (crun's own trace).
pub const CRUN_LOG_PATH: &str = "/tmp/crun.log";

/// Guest path for crun's (and the container process's) stdout+stderr — kept
/// SEPARATE from `--log` so crun's `--log` truncation can't clobber the
/// container process's own output (e.g. a pause panic).
pub const CRUN_OUT_PATH: &str = "/tmp/crun.out";

/// Maximum number of bytes to tail from `CRUN_LOG_PATH` when reporting a
/// failed container start.
const LOG_TAIL_BYTES: usize = 4096;

/// Upper bound on how long [`launch_container`] waits for the detached crun
/// container to reach `running` before giving up (fail-honest, not fatal).
const CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for the container to reach `running`.
const CONTAINER_READY_POLL: Duration = Duration::from_millis(20);

// ──────────────────────────────────────────────────────────────────────────────
// User-namespace floor (Option A)
// ──────────────────────────────────────────────────────────────────────────────

/// Path the kernel exposes for the per-userns nesting/count limit.
const MAX_USER_NS_PATH: &str = "/proc/sys/user/max_user_namespaces";

/// Parse `/proc/sys/user/max_user_namespaces` content into its numeric value.
///
/// The file holds a single decimal integer (possibly trailing newline). `0`
/// means user namespaces are administratively disabled; a positive value means
/// the container's `user` namespace (Option A's mapping mechanism) can be
/// created. Unparseable/empty content yields `None` (treated as "unknown").
pub fn parse_max_user_namespaces(content: &str) -> Option<u64> {
    content.trim().parse::<u64>().ok()
}

/// Whether the guest kernel permits creating user namespaces — the **only**
/// floor Option A needs (it is VMM-independent: no idmapped mount, no virtiofsd
/// translate). Reads [`MAX_USER_NS_PATH`]; a missing file (kernel without
/// `CONFIG_USER_NS`) or a `0` value means the floor is NOT met.
///
/// `#[mutants::skip]`: reads a real `/proc` path that only exists in a booted
/// guest; the unit suite covers the parse via [`parse_max_user_namespaces`].
#[mutants::skip]
pub fn userns_floor_met() -> bool {
    match std::fs::read_to_string(MAX_USER_NS_PATH) {
        Ok(s) => parse_max_user_namespaces(&s).is_some_and(|n| n > 0),
        Err(_) => false,
    }
}

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
        // --log=FILE (a global option) is the reliable way to capture container
        // setup errors under --detach: crun closes stdio across the detach
        // double-fork, so a setup failure (pivot_root, exec, mount) would
        // otherwise vanish. The launcher tails this file on failure.
        format!("--log={CRUN_LOG_PATH}"),
        format!("--cgroup-manager={}", cgroup_manager.as_str()),
        "run".to_string(),
        "--detach".to_string(),
        // izba-init runs on the INITRAMFS root (it mounts the overlay at
        // /rootfs but never switch_roots into it), and the kernel refuses to
        // pivot_root out of an initramfs. So crun must use MS_MOVE+chroot, not
        // pivot_root, to enter the container rootfs. Verified on a real boot:
        // without this, crun fails after "Running container on PID" with the
        // error invisible (it happens post-pivot inside the container ns). The
        // VM remains the security boundary, so chroot-vs-pivot is acceptable.
        "--no-pivot".to_string(),
        // run-options (--detach, -b) MUST precede the positional CONTAINER_ID;
        // crun rejects options after the id ("`run` requires a maximum of 1
        // arguments"). Verified on a real boot.
        "-b".to_string(),
        BUNDLE_MOUNT.to_string(),
        CONTAINER_ID.to_string(),
    ]
}

/// Build the `crun exec` argument vector to enter container `CONTAINER_ID`.
///
/// crun exec runs `<user_argv>` inside the already-running container, joining
/// its namespaces and (by default) its process spec. izba layers the per-exec
/// `--cwd`, `--env K=V`, optional `--user uid:gid`, and `--tty` from the
/// `ExecRequest`; the container's image env/PATH/USER apply for anything not
/// overridden here.
///
/// Argument order: global options (`--cgroup-manager`) precede the `exec`
/// subcommand, then exec-options precede the positional `CONTAINER_ID`, then
/// the user's argv is the trailing positional list (mirroring `crun_run_argv`,
/// where crun rejects options that follow the container id).
///
/// `cwd` is the working directory inside the container; `env` is the per-exec
/// environment overlay; `user` is `Some("uid:gid")` to run as that uid/gid
/// (skipped when `None`, so the container's configured user applies); `tty`
/// requests a pseudo-terminal (the caller wires the pty as the child's stdio).
pub fn crun_exec_argv(
    cgroup_manager: CgroupManager,
    tty: bool,
    cwd: &str,
    env: &[(String, String)],
    user: Option<&str>,
    user_argv: &[String],
) -> Vec<String> {
    let mut argv = vec![
        CRUN_PATH.to_string(),
        format!("--cgroup-manager={}", cgroup_manager.as_str()),
        "exec".to_string(),
    ];
    if tty {
        argv.push("--tty".to_string());
    }
    argv.push("--cwd".to_string());
    argv.push(cwd.to_string());
    for (k, v) in env {
        argv.push("--env".to_string());
        argv.push(format!("{k}={v}"));
    }
    if let Some(u) = user {
        argv.push("--user".to_string());
        argv.push(u.to_string());
    }
    // Positional container id, then the user's command + args.
    argv.push(CONTAINER_ID.to_string());
    argv.extend(user_argv.iter().cloned());
    argv
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

/// Parse the OCI `status` field out of `crun state` JSON into a
/// [`izba_proto::ContainerState`].
///
/// `crun state` emits OCI state JSON with a `"status"` field whose value is one
/// of the OCI runtime states (`creating`/`created`/`running`/`stopped`, plus
/// crun's `paused`). Returns `None` when no `"status"` field is present at all
/// (the output is not OCI state JSON / is unparseable); a present-but-undefined
/// status value maps to [`izba_proto::ContainerState::Unknown`].
///
/// We only need the `"status"` field, so a substring search is used rather than
/// pulling serde_json into the musl binary.
pub fn parse_container_state(json: &str) -> Option<izba_proto::ContainerState> {
    extract_status_field(json).map(izba_proto::ContainerState::from_oci_status)
}

/// Extracts the value of the `"status"` key from a JSON object without a full
/// JSON parser.  Returns `None` when the key is absent or the value is not a
/// simple quoted string.
fn extract_status_field(json: &str) -> Option<&str> {
    // Parser assumption: we return the value of the FIRST `"status"` occurrence
    // in the JSON text.  This is correct for crun's OCI state JSON because no
    // earlier field name or string value contains the literal substring
    // `"status"` — the field always appears at the top level and is the only
    // occurrence.  The extracted value is then mapped by
    // `ContainerState::from_oci_status`, so every OCI state ("running",
    // "created", "stopped", "paused", "creating") is reported faithfully and an
    // unrecognized value becomes `Unknown`.
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
///
/// `#[mutants::skip]`: copies `current_exe()` to the fixed guest path
/// `pause_host_path()` (`/rootfs/.izba/pause`), so it only does meaningful work
/// inside a booted guest with the overlay assembled; the unit suite has no
/// `/rootfs`. The `Ok(())` mutant is indistinguishable from real success
/// without that filesystem. Exercised by the real-VM checkpoint.
#[mutants::skip]
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
///
/// `#[mutants::skip]`: orchestrates real side effects only available in a
/// booted guest — installs the pause binary under `/rootfs`, detects the
/// cgroup hierarchy, and forks `/sbin/crun run` — none reachable from the unit
/// suite (no `/rootfs`, no crun). The `replace with ()` mutant cannot be
/// distinguished without a live VM; covered by the real-VM checkpoint. Its
/// pure helpers (`crun_run_argv`, `read_log_tail`) are unit-tested.
#[mutants::skip]
pub fn launch_container() {
    // Step 1: install pause binary.
    if let Err(e) = install_pause_binary() {
        eprintln!("izba-init: [OCI] installing pause binary: {e}");
        // Continue: the container start will fail and that gives better info.
    }

    // Step 1.5: user-namespace floor (Option A). The OCI config.json ALWAYS
    // carries the container `user` namespace + uid/gid transposition — there is
    // no silent no-userns fallback. If the kernel can't create user namespaces
    // the crun launch below fails closed; warn loudly first so the serial log
    // names the real cause instead of a cryptic crun map-write error.
    if !userns_floor_met() {
        eprintln!(
            "izba-init: [OCI] *** USER-NAMESPACE FLOOR NOT MET *** the guest kernel reports \
             user namespaces unavailable ({MAX_USER_NS_PATH} missing or 0); the workload \
             container requires a user namespace (Option A uid mapping) and will fail to start \
             — NOT downgrading to an unmapped container"
        );
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
        .open(CRUN_OUT_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("izba-init: [OCI] cannot open {CRUN_OUT_PATH}: {e}; crun output lost");
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
            // `crun run --detach` returns once the monitor is forked, BEFORE the
            // detached child has finished creating the container (clone of the
            // namespaces — including the `user` namespace + uid/gid map write —
            // then exec of PID 1). Until that completes, `/run/crun/izba/status`
            // is absent and a racing `crun exec` fails "container does not
            // exist". So block here until `crun state` reports `running`, so the
            // sandbox is only reported healthy once exec/ssh can actually enter
            // the container. Bounded; a timeout is logged but not fatal (the
            // sandbox stays alive + diagnosable, consistent with fail-honest).
            let waited = wait_container_running(CONTAINER_ID, CONTAINER_READY_TIMEOUT);
            eprintln!(
                "izba-init: [OCI] container started OK (running after {:?})",
                waited
            );
        }
        Ok(code) => {
            let tail = read_log_tail(CRUN_LOG_PATH, LOG_TAIL_BYTES);
            let out = read_log_tail(CRUN_OUT_PATH, LOG_TAIL_BYTES);
            eprintln!(
                "izba-init: [OCI] *** CONTAINER START FAILED *** crun exited with code {code}"
            );
            eprintln!("izba-init: [OCI] --- crun stdio tail ({CRUN_OUT_PATH}) ---");
            eprintln!("{out}");
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

/// Block until `crun state <id>` reports `running`, or `timeout` elapses.
/// Returns the elapsed wait. A timeout is logged loudly but is NOT fatal — the
/// sandbox stays alive and diagnosable (fail-honest), and exec/ssh will then
/// surface crun's own "container not running" error rather than racing it.
///
/// `#[mutants::skip]`: spins on `container_running`, which shells out to a live
/// `/sbin/crun state` only present in a booted guest; the unit suite has no
/// crun, so the loop/timeout branches can't be distinguished without a VM.
/// Exercised by the real-VM checkpoint.
#[mutants::skip]
fn wait_container_running(id: &str, timeout: Duration) -> Duration {
    let start = Instant::now();
    loop {
        if container_running(id) {
            return start.elapsed();
        }
        if start.elapsed() >= timeout {
            eprintln!(
                "izba-init: [OCI] *** container '{id}' did not reach 'running' within {timeout:?} \
                 *** exec/ssh into this sandbox will fail until it does"
            );
            return start.elapsed();
        }
        std::thread::sleep(CONTAINER_READY_POLL);
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

/// Query the workload container's live state by invoking `crun state <id>` and
/// parsing the OCI state JSON.
///
/// Returns [`izba_proto::ContainerState::Unknown`] when crun cannot be run,
/// exits non-zero (e.g. the container was never created), or emits output
/// without a parseable `status` field — it never reports a falsely-healthy
/// state, so the host can surface an honest "container exited / unknown" rather
/// than implying the sandbox is healthy.
///
/// `#[mutants::skip]`: this shells out to a real `/sbin/crun state <id>` against
/// a live container, which exists only inside a booted microVM. Unit tests run
/// on a crun-less host where the `Command` always fails (→ `Unknown`), so no
/// unit test can distinguish the result mutants here; the running-vs-exited
/// behavior is exercised by the real-VM checkpoint. The JSON parsing it
/// delegates to (`parse_container_state`) is unit-tested directly.
#[mutants::skip]
pub fn container_state(id: &str) -> izba_proto::ContainerState {
    let out = std::process::Command::new(CRUN_PATH)
        .args(["state", id])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_container_state(&String::from_utf8_lossy(&o.stdout))
            .unwrap_or(izba_proto::ContainerState::Unknown),
        _ => izba_proto::ContainerState::Unknown,
    }
}

/// Check whether the container with `id` is currently running.
///
/// Thin honest wrapper over [`container_state`]; retained for the controller
/// validation checkpoint and callers that only need the boolean.
///
/// `#[mutants::skip]`: delegates to the crun-shelling `container_state`, which
/// is itself unreachable from the unit suite (see its note).
#[mutants::skip]
#[allow(dead_code)]
pub fn container_running(id: &str) -> bool {
    container_state(id).is_running()
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
        assert_eq!(argv[1], format!("--log={CRUN_LOG_PATH}"));
        assert_eq!(argv[2], "--cgroup-manager=cgroupfs");
        assert_eq!(argv[3], "run");
        assert_eq!(argv[4], "--detach");
        assert_eq!(argv[5], "--no-pivot");
        // run-options before the positional id (crun rejects the reverse).
        assert_eq!(argv[6], "-b");
        assert_eq!(argv[7], BUNDLE_MOUNT);
        assert_eq!(argv[8], CONTAINER_ID);
        assert_eq!(argv.len(), 9);
    }

    #[test]
    fn crun_run_argv_disabled_branch() {
        let argv = crun_run_argv(CgroupManager::Disabled);
        assert_eq!(argv[2], "--cgroup-manager=disabled");
        // Rest of argv is identical to cgroupfs branch.
        assert_eq!(argv[3], "run");
        assert_eq!(argv[4], "--detach");
        assert_eq!(argv[5], "--no-pivot");
        // run-options before the positional id (crun rejects the reverse).
        assert_eq!(argv[6], "-b");
        assert_eq!(argv[7], BUNDLE_MOUNT);
        assert_eq!(argv[8], CONTAINER_ID);
    }

    #[test]
    fn crun_run_argv_has_no_pivot() {
        // izba-init runs on the initramfs root, which cannot be pivot_root'd out
        // of, so crun MUST use --no-pivot (MS_MOVE+chroot). Verified on a real
        // boot: without it the container fails to start.
        let argv = crun_run_argv(CgroupManager::Cgroupfs);
        assert!(
            argv.iter().any(|a| a == "--no-pivot"),
            "--no-pivot is required (init runs on the initramfs root)"
        );
    }

    // ── crun exec argv construction ──────────────────────────────────────────

    #[test]
    fn crun_exec_argv_pipe_minimal() {
        // No tty, no env, no user override, single-word command.
        let argv = crun_exec_argv(
            CgroupManager::Cgroupfs,
            false,
            "/workspace",
            &[],
            None,
            &["sh".to_string()],
        );
        assert_eq!(
            argv,
            vec![
                CRUN_PATH.to_string(),
                "--cgroup-manager=cgroupfs".to_string(),
                "exec".to_string(),
                "--cwd".to_string(),
                "/workspace".to_string(),
                CONTAINER_ID.to_string(),
                "sh".to_string(),
            ]
        );
        // No --tty in the pipe path.
        assert!(!argv.iter().any(|a| a == "--tty"));
    }

    #[test]
    fn crun_exec_argv_tty_adds_flag_before_cwd() {
        let argv = crun_exec_argv(
            CgroupManager::Disabled,
            true,
            "/",
            &[],
            None,
            &["bash".to_string()],
        );
        // --tty appears, and it precedes --cwd (exec-options before positionals).
        let tty_pos = argv.iter().position(|a| a == "--tty").expect("--tty");
        let cwd_pos = argv.iter().position(|a| a == "--cwd").expect("--cwd");
        assert!(tty_pos < cwd_pos, "--tty must precede --cwd: {argv:?}");
        assert_eq!(argv[1], "--cgroup-manager=disabled");
    }

    #[test]
    fn crun_exec_argv_env_pairs_become_env_flags() {
        let env = vec![
            ("FOO".to_string(), "bar".to_string()),
            ("EMPTY".to_string(), String::new()),
        ];
        let argv = crun_exec_argv(
            CgroupManager::Cgroupfs,
            false,
            "/workspace",
            &env,
            None,
            &["env".to_string()],
        );
        // Each pair becomes "--env" "K=V"; an empty value yields "K=".
        let env_flags: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, a)| *a == "--env" && argv.get(i + 1).is_some())
            .map(|(i, _)| &argv[i + 1])
            .collect();
        assert_eq!(env_flags, vec!["FOO=bar", "EMPTY="]);
    }

    #[test]
    fn crun_exec_argv_user_override() {
        let argv = crun_exec_argv(
            CgroupManager::Cgroupfs,
            false,
            "/",
            &[],
            Some("1000:1000"),
            &["id".to_string()],
        );
        let user_pos = argv.iter().position(|a| a == "--user").expect("--user");
        assert_eq!(argv[user_pos + 1], "1000:1000");
        // --user precedes the container id positional.
        let id_pos = argv
            .iter()
            .position(|a| a == CONTAINER_ID)
            .expect("container id");
        assert!(user_pos < id_pos, "--user must precede the id: {argv:?}");
    }

    #[test]
    fn crun_exec_argv_user_argv_is_trailing_after_id() {
        let argv = crun_exec_argv(
            CgroupManager::Cgroupfs,
            false,
            "/",
            &[],
            None,
            &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
        );
        let id_pos = argv
            .iter()
            .position(|a| a == CONTAINER_ID)
            .expect("container id");
        assert_eq!(&argv[id_pos + 1..], &["sh", "-c", "echo hi"]);
    }

    #[test]
    fn crun_exec_argv_options_precede_container_id() {
        // Every option flag must come before the positional container id, which
        // must come before the user's argv. Mirrors crun's parser constraint.
        let argv = crun_exec_argv(
            CgroupManager::Cgroupfs,
            true,
            "/workspace",
            &[("K".to_string(), "V".to_string())],
            Some("0:0"),
            &["cmd".to_string()],
        );
        let id_pos = argv
            .iter()
            .position(|a| a == CONTAINER_ID)
            .expect("container id");
        for opt in ["--tty", "--cwd", "--env", "--user"] {
            let p = argv.iter().position(|a| a == opt).unwrap();
            assert!(p < id_pos, "{opt} must precede container id: {argv:?}");
        }
    }

    #[test]
    fn crun_state_argv_contains_id() {
        let argv = crun_state_argv("izba");
        assert_eq!(argv[0], CRUN_PATH);
        assert_eq!(argv[1], "state");
        assert_eq!(argv[2], "izba");
        assert_eq!(argv.len(), 3);
    }

    // ── crun state → ContainerState parse ────────────────────────────────────

    #[test]
    fn parse_running_status_from_full_state_json() {
        use izba_proto::ContainerState;
        let json = r#"{"ociVersion":"1.0.2","id":"izba","pid":42,"status":"running","bundle":"/rootfs/izba-oci","rootfs":"/rootfs","created":"2026-01-01T00:00:00.0Z","owner":""}"#;
        assert_eq!(parse_container_state(json), Some(ContainerState::Running));
        assert!(parse_container_state(json).unwrap().is_running());
    }

    #[test]
    fn parse_stopped_status_from_full_state_json() {
        use izba_proto::ContainerState;
        let json = r#"{"ociVersion":"1.0.2","id":"izba","pid":0,"status":"stopped","bundle":"/rootfs/izba-oci","rootfs":"/rootfs","created":"2026-01-01T00:00:00.0Z","owner":""}"#;
        assert_eq!(parse_container_state(json), Some(ContainerState::Stopped));
        assert!(!parse_container_state(json).unwrap().is_running());
    }

    #[test]
    fn parse_with_whitespace_around_colon() {
        let json = r#"{ "status" : "running" }"#;
        assert_eq!(
            parse_container_state(json),
            Some(izba_proto::ContainerState::Running)
        );
    }

    #[test]
    fn parse_container_state_maps_each_oci_status() {
        use izba_proto::ContainerState;
        for (status, want) in [
            ("creating", ContainerState::Creating),
            ("created", ContainerState::Created),
            ("running", ContainerState::Running),
            ("stopped", ContainerState::Stopped),
            ("paused", ContainerState::Paused),
        ] {
            let json = format!(r#"{{"id":"izba","status":"{status}"}}"#);
            assert_eq!(parse_container_state(&json), Some(want), "{status}");
        }
    }

    #[test]
    fn parse_container_state_unknown_status_value_is_unknown_not_none() {
        // A present `status` we don't recognize is honestly Unknown — distinct
        // from a missing status field (None), which means "not OCI state JSON".
        let json = r#"{"id":"izba","status":"weird"}"#;
        assert_eq!(
            parse_container_state(json),
            Some(izba_proto::ContainerState::Unknown)
        );
    }

    #[test]
    fn parse_container_state_missing_status_is_none() {
        assert_eq!(parse_container_state(r#"{"id":"izba"}"#), None);
        assert_eq!(parse_container_state(""), None);
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

    // ── user-namespace floor parse ───────────────────────────────────────────

    #[test]
    fn parse_max_user_namespaces_positive() {
        assert_eq!(parse_max_user_namespaces("15000\n"), Some(15000));
        assert_eq!(parse_max_user_namespaces("1"), Some(1));
        assert_eq!(parse_max_user_namespaces("  42  \n"), Some(42));
    }

    #[test]
    fn parse_max_user_namespaces_zero_means_disabled() {
        // 0 is parseable but the floor check treats it as not-met.
        assert_eq!(parse_max_user_namespaces("0\n"), Some(0));
    }

    #[test]
    fn parse_max_user_namespaces_unparseable_is_none() {
        assert_eq!(parse_max_user_namespaces(""), None);
        assert_eq!(parse_max_user_namespaces("garbage"), None);
        assert_eq!(parse_max_user_namespaces("-1"), None);
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

    // ── read_log_tail internal ───────────────────────────────────────────────

    #[test]
    fn read_log_tail_returns_full_content_when_under_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        std::fs::write(&path, b"hello crun\n").unwrap();
        assert_eq!(
            read_log_tail(path.to_str().unwrap(), LOG_TAIL_BYTES),
            "hello crun\n"
        );
    }

    #[test]
    fn read_log_tail_truncates_to_last_max_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        // 10 bytes of content, ask for only the last 4.
        std::fs::write(&path, b"0123456789").unwrap();
        assert_eq!(read_log_tail(path.to_str().unwrap(), 4), "6789");
    }

    #[test]
    fn read_log_tail_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");
        assert_eq!(read_log_tail(path.to_str().unwrap(), LOG_TAIL_BYTES), "");
    }
}
