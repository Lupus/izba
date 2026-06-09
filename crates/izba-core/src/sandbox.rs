//! Sandbox lifecycle orchestration: create / start / stop / remove / list.
//!
//! izba is daemonless — `start` spawns the VMM detached and exits; later
//! invocations (`stop`, `exec`, `ls`) are new processes that reconstruct state
//! from disk and reach the guest through a [`Connector`].

use anyhow::{bail, Context};
use std::fs::{self, File};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use izba_proto::{read_frame, write_frame, Request, Response, CONTROL_PORT, STREAM_PORT};
use nix::fcntl::{Flock, FlockArg};

use crate::image::store::ImageStore;
use crate::liveness::{assess, Liveness, Probes};
use crate::paths::Paths;
use crate::procmgr;
use crate::state::{load_json, save_json, RunState, SandboxConfig, CONFIG_FILE, STATE_FILE};
use crate::vmm::{BlockDisk, FsShare, IoStream, VmSpec, VmmDriver};

const DEFAULT_BOOT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_BOOT_POLL: Duration = Duration::from_millis(200);
/// Per-attempt deadline for any single control-plane request/response.
const CONTROL_RPC_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct CreateOpts {
    pub image_digest: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    pub rw_size_gb: u64,
}

/// Boot artifacts shared by all sandboxes (kernel + initramfs with izba-init).
#[derive(Debug, Clone)]
pub struct Artifacts {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
}

#[derive(Debug)]
pub struct SandboxInfo {
    pub name: String,
    pub image_ref: String,
    pub liveness: Liveness,
}

/// How post-boot invocations reach the guest control port.
///
/// Production code uses [`default_connector`]; tests substitute socketpair
/// fakes.
pub type Connector<'a> = &'a dyn Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>>;

/// The production connector: hybrid-vsock through `run/vsock.sock`.
pub fn default_connector() -> impl Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> {
    |paths: &Paths, name: &str| {
        let sock = paths.run_dir(name).join("vsock.sock");
        let s = crate::vsock::hybrid_connect(&sock, CONTROL_PORT)?;
        Ok(Box::new(s) as Box<dyn IoStream>)
    }
}

/// The production stream-port connector: hybrid-vsock through `run/vsock.sock`
/// to [`STREAM_PORT`].
///
/// Returns a concrete [`std::os::unix::net::UnixStream`] (not `Box<dyn
/// IoStream>`) because stream pumps need `try_clone` for the second direction
/// and `shutdown` to signal half-close — neither is expressible on the trait.
pub fn default_stream_connector(
) -> impl Fn(&Paths, &str) -> anyhow::Result<std::os::unix::net::UnixStream> {
    |paths: &Paths, name: &str| {
        let sock = paths.run_dir(name).join("vsock.sock");
        crate::vsock::hybrid_connect(&sock, STREAM_PORT)
    }
}

/// Validate a sandbox name: `[a-z0-9][a-z0-9_.-]*`, at most 64 characters.
///
/// Names become path components, so this also blocks traversal (`../evil`).
pub fn validate_name(name: &str) -> anyhow::Result<()> {
    let head_ok = name
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let tail_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'));
    if !head_ok || !tail_ok || name.len() > 64 {
        bail!("invalid sandbox name '{name}' (allowed: [a-z0-9][a-z0-9_.-]*, max 64 chars)");
    }
    Ok(())
}

/// One bounded control-plane round trip: apply `timeout` to the stream, send
/// `req`, read the reply, clear the timeout. A deadline miss is mapped to a
/// clear "control plane timed out" error instead of a raw I/O error.
fn rpc(
    stream: &mut Box<dyn IoStream>,
    req: &Request,
    timeout: Duration,
) -> anyhow::Result<Response> {
    stream.set_io_timeout(Some(timeout))?;
    let result = (|| -> anyhow::Result<Response> {
        write_frame(stream, req)?;
        Ok(read_frame::<_, Response>(stream)?)
    })();
    let _ = stream.set_io_timeout(None);
    result.map_err(|e| {
        if is_timeout(&e) {
            e.context(format!("control plane timed out after {timeout:?}"))
        } else {
            e
        }
    })
}

fn is_timeout(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
        })
    })
}

pub fn create(paths: &Paths, name: &str, opts: &CreateOpts) -> anyhow::Result<()> {
    validate_name(name)?;
    let dir = paths.sandbox_dir(name);
    if dir.exists() {
        bail!("sandbox '{name}' already exists");
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // Anything failing past this point leaves a partial sandbox — clean it up.
    let populate = || -> anyhow::Result<()> {
        fs::create_dir_all(paths.logs_dir(name))?;
        fs::create_dir_all(paths.run_dir(name))?;

        let config = SandboxConfig {
            image_digest: opts.image_digest.clone(),
            image_ref: opts.image_ref.clone(),
            cpus: opts.cpus,
            mem_mb: opts.mem_mb,
            workspace: opts.workspace.clone(),
        };
        save_json(&dir.join(CONFIG_FILE), &config)?;

        // Sparse scratch disk: apparent size only, no blocks allocated.
        let rw = dir.join("rw.img");
        let f = File::create(&rw).with_context(|| format!("creating {}", rw.display()))?;
        f.set_len(opts.rw_size_gb * 1024 * 1024 * 1024)
            .with_context(|| format!("sizing {}", rw.display()))?;
        drop(f); // release the file handle before running mkfs on it

        // Best-effort: pre-format the scratch disk on the host so the guest
        // does not need an embedded mke2fs.  Failure is non-fatal — if
        // mkfs.ext4 is absent or fails, the guest-side mke2fs (if present in
        // the initramfs) will handle it; if neither works, init exits with a
        // clear error.
        match which::which("mkfs.ext4") {
            Err(_) => {
                // mkfs.ext4 not on PATH — guest must handle formatting.
            }
            Ok(mkfs) => {
                let out = std::process::Command::new(&mkfs)
                    .args(["-q", "-F"])
                    .arg(&rw)
                    .output();
                match out {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        eprintln!(
                            "warning: mkfs.ext4 on {} failed ({}): {}",
                            rw.display(),
                            o.status,
                            String::from_utf8_lossy(&o.stderr).trim()
                        );
                    }
                    Err(e) => {
                        eprintln!("warning: failed to run {}: {e}", mkfs.display());
                    }
                }
            }
        }
        Ok(())
    };
    let result = populate();
    if result.is_err() {
        let _ = fs::remove_dir_all(&dir);
    }
    result
}

/// Take the per-sandbox exclusive lock (released on drop).
fn lock_sandbox(paths: &Paths, name: &str) -> anyhow::Result<Flock<File>> {
    let lock_path = paths.sandbox_dir(name).join("lock");
    let f = match File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("no such sandbox '{name}'")
        }
        Err(e) => return Err(e).with_context(|| format!("opening {}", lock_path.display())),
    };
    match Flock::lock(f, FlockArg::LockExclusiveNonblock) {
        Ok(l) => Ok(l),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => {
            bail!("sandbox '{name}' is busy (another operation in progress)")
        }
        Err((_, e)) => Err(e).with_context(|| format!("locking {}", lock_path.display())),
    }
}

/// Liveness probes backed by /proc and a control-port health roundtrip.
struct RealProbes<'a> {
    connector: Connector<'a>,
    paths: &'a Paths,
    name: &'a str,
}

impl Probes for RealProbes<'_> {
    fn pid_alive(&self, id: &crate::state::PidIdentity) -> bool {
        procmgr::pid_alive(id)
    }

    fn control_answers(&self) -> bool {
        let attempt = || -> anyhow::Result<()> {
            let mut s = (self.connector)(self.paths, self.name)?;
            match rpc(&mut s, &Request::Health, CONTROL_RPC_TIMEOUT)? {
                Response::Health(_) => Ok(()),
                other => bail!("unexpected health reply: {other:?}"),
            }
        };
        attempt().is_ok()
    }
}

fn liveness_of(paths: &Paths, name: &str, connector: Connector) -> anyhow::Result<Liveness> {
    let state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))?;
    let probes = RealProbes {
        connector,
        paths,
        name,
    };
    Ok(assess(state.as_ref(), &probes))
}

pub fn start(
    paths: &Paths,
    name: &str,
    driver: &dyn VmmDriver,
    art: &Artifacts,
) -> anyhow::Result<()> {
    start_with_timeouts(
        paths,
        name,
        driver,
        art,
        DEFAULT_BOOT_TIMEOUT,
        DEFAULT_BOOT_POLL,
    )
}

pub fn start_with_timeouts(
    paths: &Paths,
    name: &str,
    driver: &dyn VmmDriver,
    art: &Artifacts,
    boot_timeout: Duration,
    poll: Duration,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let _lock = lock_sandbox(paths, name)?;

    let config: SandboxConfig = load_json(&paths.sandbox_dir(name).join(CONFIG_FILE))?
        .with_context(|| format!("no such sandbox '{name}'"))?;

    let conn = default_connector();
    if liveness_of(paths, name, &conn)? != Liveness::Stopped {
        bail!("sandbox '{name}' is already running");
    }

    let console_log = paths.logs_dir(name).join("console.log");
    let spec = VmSpec {
        kernel: art.kernel.clone(),
        initramfs: art.initramfs.clone(),
        cmdline: "console=ttyS0 ip=dhcp".to_string(),
        cpus: config.cpus,
        mem_mb: config.mem_mb,
        disks: vec![
            BlockDisk {
                path: ImageStore::new(paths).rootfs_path(&config.image_digest),
                readonly: true,
            },
            BlockDisk {
                path: paths.sandbox_dir(name).join("rw.img"),
                readonly: false,
            },
        ],
        shares: vec![FsShare {
            tag: "workspace".to_string(),
            host_path: config.workspace.clone(),
        }],
        net: true,
        console_log: console_log.clone(),
        run_dir: paths.run_dir(name),
    };

    let mut handle = driver.launch(&spec)?;

    // Everything after launch must kill the handle on failure, or the VMM
    // would be orphaned with no state.json pointing at it.
    let booted = (|| -> anyhow::Result<()> {
        // Boot-wait: poll the guest control port until Health answers. Each
        // attempt is individually bounded so a wedged-but-accepting guest
        // cannot stall past the boot budget.
        let deadline = Instant::now() + boot_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempt_timeout = CONTROL_RPC_TIMEOUT
                .min(remaining)
                .max(Duration::from_millis(10));
            let healthy = (|| -> anyhow::Result<bool> {
                let mut s = handle.connect(CONTROL_PORT)?;
                Ok(matches!(
                    rpc(&mut s, &Request::Health, attempt_timeout)?,
                    Response::Health(_)
                ))
            })()
            .unwrap_or(false);
            if healthy {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "sandbox '{name}' did not become healthy within {boot_timeout:?}; \
                     check {} for boot output",
                    console_log.display()
                );
            }
            std::thread::sleep(poll);
        }

        let mut pids = handle.pids();
        let vmm_idx = pids
            .iter()
            .position(|(role, _)| role == "vmm")
            .context("driver returned no 'vmm' pid")?;
        let (_, vmm_pid) = pids.remove(vmm_idx);
        let state = RunState {
            vmm_pid,
            sidecar_pids: pids,
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        save_json(&paths.sandbox_dir(name).join(STATE_FILE), &state)?;
        Ok(())
    })();

    if let Err(e) = booted {
        let _ = handle.kill();
        // Best-effort: clear stale sockets/pid files so a retry starts clean.
        clear_run_dir_files(paths, name);
        return Err(e);
    }
    Ok(())
}

/// Best-effort removal of regular files in the run dir (sockets, pid files).
fn clear_run_dir_files(paths: &Paths, name: &str) {
    let run = paths.run_dir(name);
    let Ok(entries) = fs::read_dir(&run) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| !t.is_dir()).unwrap_or(false) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Open a control-port stream to a running (or degraded) sandbox.
pub fn control(
    paths: &Paths,
    name: &str,
    connector: Connector,
) -> anyhow::Result<Box<dyn IoStream>> {
    validate_name(name)?;
    match liveness_of(paths, name, connector)? {
        Liveness::Running | Liveness::Degraded(_) => connector(paths, name),
        Liveness::Stopped => bail!("sandbox '{name}' is not running"),
    }
}

pub fn stop(
    paths: &Paths,
    name: &str,
    connector: Connector,
    timeout: Duration,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let _lock = lock_sandbox(paths, name)?;
    stop_locked(paths, name, connector, timeout, true)
}

/// Shared stop machinery; caller must hold the sandbox lock.
///
/// When `graceful` is false the guest RPC is skipped and all pids are killed
/// outright (force-remove path).
fn stop_locked(
    paths: &Paths,
    name: &str,
    connector: Connector,
    timeout: Duration,
    graceful: bool,
) -> anyhow::Result<()> {
    let state_path = paths.sandbox_dir(name).join(STATE_FILE);
    let state: Option<RunState> = load_json(&state_path)?;
    let probes = RealProbes {
        connector,
        paths,
        name,
    };
    let state = match (assess(state.as_ref(), &probes), state) {
        (Liveness::Stopped, _) | (_, None) => return cleanup_runtime(paths, name),
        (_, Some(s)) => s,
    };

    if graceful {
        // Best-effort: the guest may die mid-reply or hang, which is fine —
        // the bounded RPC guarantees we reach the escalation path below.
        let _ = (|| -> anyhow::Result<()> {
            let mut s = connector(paths, name)?;
            let _ = rpc(&mut s, &Request::Shutdown, CONTROL_RPC_TIMEOUT);
            Ok(())
        })();
        let deadline = Instant::now() + timeout;
        while procmgr::pid_alive(&state.vmm_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let any_alive = procmgr::pid_alive(&state.vmm_pid)
        || state
            .sidecar_pids
            .iter()
            .any(|(_, id)| procmgr::pid_alive(id));
    if any_alive {
        // Escalate: vmm first, then sidecars.
        procmgr::kill_pid(&state.vmm_pid)?;
        for (_, id) in &state.sidecar_pids {
            procmgr::kill_pid(id)?;
        }
        // SIGKILL is asynchronous; wait briefly so cleanup happens after death.
        let deadline = Instant::now() + Duration::from_secs(2);
        while procmgr::pid_alive(&state.vmm_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // A VMM that survives SIGKILL (e.g. stuck in uninterruptible sleep)
        // must keep its state.json, or a later start would double-boot.
        // Integration-covered; not unit-tested (would require an unkillable
        // process).
        if procmgr::pid_alive(&state.vmm_pid) {
            bail!(
                "VMM survived SIGKILL (pid {}); state preserved — retry stop",
                state.vmm_pid.pid
            );
        }
    }

    cleanup_runtime(paths, name)
}

/// Remove state.json and everything inside the run dir (sockets, pid files).
fn cleanup_runtime(paths: &Paths, name: &str) -> anyhow::Result<()> {
    let state_path = paths.sandbox_dir(name).join(STATE_FILE);
    match fs::remove_file(&state_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", state_path.display())),
    }
    let run = paths.run_dir(name);
    if run.is_dir() {
        for entry in fs::read_dir(&run)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

pub fn remove(paths: &Paths, name: &str, connector: Connector, force: bool) -> anyhow::Result<()> {
    validate_name(name)?;
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        bail!("no such sandbox '{name}'");
    }
    // Rename to a sibling tombstone *while holding the lock*, so a concurrent
    // start cannot slip in between liveness check and deletion: once renamed,
    // the old name has no config.json and start fails with "no such sandbox".
    let tombstone = paths
        .sandboxes_dir()
        .join(format!("{name}.removing-{}", std::process::id()));
    {
        let _lock = lock_sandbox(paths, name)?;
        match liveness_of(paths, name, connector)? {
            Liveness::Stopped => {}
            _ if !force => bail!("sandbox '{name}' is running (use force to remove)"),
            _ => stop_locked(paths, name, connector, Duration::ZERO, false)?,
        }
        fs::rename(&dir, &tombstone)
            .with_context(|| format!("renaming {} for removal", dir.display()))?;
    } // the lock file moved with the dir; release before deleting it
    if let Err(e) = fs::remove_dir_all(&tombstone) {
        eprintln!(
            "warning: sandbox '{name}' renamed to {} but final deletion failed: {e}",
            tombstone.display()
        );
    }
    Ok(())
}

pub fn list(paths: &Paths, connector: Connector) -> anyhow::Result<Vec<SandboxInfo>> {
    let dir = paths.sandboxes_dir();
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Tombstones from interrupted `remove` final-deletes are inert debris,
        // not sandboxes.
        if name.contains(".removing-") {
            continue;
        }
        let config: SandboxConfig = match load_json(&entry.path().join(CONFIG_FILE)) {
            Ok(Some(c)) => c,
            Ok(None) => {
                eprintln!("warning: sandbox '{name}' has no {CONFIG_FILE}; skipping");
                continue;
            }
            Err(e) => {
                eprintln!("warning: skipping sandbox '{name}': {e:#}");
                continue;
            }
        };
        let liveness = match liveness_of(paths, &name, connector) {
            Ok(l) => l,
            Err(e) => {
                // Corrupt state.json must not abort the whole listing; report
                // the sandbox as stopped and leave the file for inspection.
                eprintln!(
                    "warning: sandbox '{name}' has unreadable state ({e:#}); showing as stopped"
                );
                out.push(SandboxInfo {
                    name,
                    image_ref: config.image_ref,
                    liveness: Liveness::Stopped,
                });
                continue;
            }
        };
        if liveness == Liveness::Stopped {
            // Correct stale state left behind by a VMM that died on its own —
            // but only if no concurrent operation (e.g. start) holds the lock,
            // otherwise we could delete the state.json it just wrote.
            let state_path = entry.path().join(STATE_FILE);
            if state_path.exists() {
                if let Ok(_lock) = lock_sandbox(paths, &name) {
                    let _ = fs::remove_file(&state_path);
                }
            }
        }
        out.push(SandboxInfo {
            name,
            image_ref: config.image_ref,
            liveness,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PidIdentity;
    use crate::vmm::{CommandSpec, VmHandle};
    use izba_proto::HealthInfo;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Identity of the current (test) process — alive for the test's duration.
    fn live_identity() -> PidIdentity {
        let pid = std::process::id();
        PidIdentity {
            pid,
            starttime: procmgr::proc_starttime(pid).unwrap(),
        }
    }

    /// Identity that `pid_alive` rejects (starttime mismatch).
    fn dead_identity() -> PidIdentity {
        PidIdentity {
            pid: std::process::id(),
            starttime: 1,
        }
    }

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        (dir, paths)
    }

    fn opts(workspace: &Path) -> CreateOpts {
        CreateOpts {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 1024,
            workspace: workspace.to_path_buf(),
            rw_size_gb: 1,
        }
    }

    fn arts() -> Artifacts {
        Artifacts {
            kernel: PathBuf::from("/art/vmlinux"),
            initramfs: PathBuf::from("/art/initramfs.img"),
        }
    }

    /// Spawn a real detached `sleep 30` and return its identity.
    fn spawn_sleep(dir: &Path) -> PidIdentity {
        procmgr::spawn_detached(
            &CommandSpec {
                argv: vec!["sleep".into(), "30".into()],
            },
            &dir.join("sleep.log"),
        )
        .unwrap()
    }

    /// Poll until `id` is dead (or fail after 2 s).
    fn wait_dead(id: &PidIdentity) -> bool {
        (0..40).any(|_| {
            if !procmgr::pid_alive(id) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
            !procmgr::pid_alive(id)
        })
    }

    fn write_state(paths: &Paths, name: &str, vmm: PidIdentity) {
        save_json(
            &paths.sandbox_dir(name).join(STATE_FILE),
            &RunState {
                vmm_pid: vmm,
                sidecar_pids: vec![],
                started_unix_ms: 0,
            },
        )
        .unwrap();
    }

    // -----------------------------------------------------------------------
    // MockDriver / MockHandle
    // -----------------------------------------------------------------------

    struct MockDriver {
        captured: Mutex<Option<VmSpec>>,
        health_delay: Duration,
        answer_health: bool,
        omit_vmm_pid: bool,
        /// `killed` flag of the most recently launched handle.
        last_killed: Mutex<Option<Arc<AtomicBool>>>,
    }

    impl MockDriver {
        fn new() -> Self {
            Self::with(Duration::ZERO, true)
        }

        fn with(health_delay: Duration, answer_health: bool) -> Self {
            Self {
                captured: Mutex::new(None),
                health_delay,
                answer_health,
                omit_vmm_pid: false,
                last_killed: Mutex::new(None),
            }
        }

        /// A driver whose handle reports no "vmm" pid (driver bug simulation).
        fn without_vmm_pid() -> Self {
            Self {
                omit_vmm_pid: true,
                ..Self::new()
            }
        }
    }

    impl VmmDriver for MockDriver {
        fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>> {
            *self.captured.lock().unwrap() = Some(spec.clone());
            let killed = Arc::new(AtomicBool::new(false));
            *self.last_killed.lock().unwrap() = Some(killed.clone());
            let pids = if self.omit_vmm_pid {
                vec![]
            } else {
                vec![("vmm".to_string(), live_identity())]
            };
            Ok(Box::new(MockHandle {
                alive: Arc::new(AtomicBool::new(true)),
                killed,
                health_delay: self.health_delay,
                answer_health: self.answer_health,
                pids,
            }))
        }
    }

    struct MockHandle {
        alive: Arc<AtomicBool>,
        killed: Arc<AtomicBool>,
        health_delay: Duration,
        answer_health: bool,
        pids: Vec<(String, PidIdentity)>,
    }

    impl VmHandle for MockHandle {
        fn connect(&self, _port: u32) -> anyhow::Result<Box<dyn IoStream>> {
            if !self.answer_health {
                anyhow::bail!("connection refused (mock)");
            }
            let (client, server) = UnixStream::pair()?;
            let delay = self.health_delay;
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                // fake izba-init: answer ONE request then close
                let mut s = server;
                if let Ok(req) = read_frame::<_, Request>(&mut s) {
                    let resp = match req {
                        Request::Health => Response::Health(HealthInfo {
                            version: "test".into(),
                            uptime_ms: 1,
                        }),
                        _ => Response::Ok,
                    };
                    let _ = write_frame(&mut s, &resp);
                }
            });
            Ok(Box::new(client))
        }

        fn pids(&self) -> Vec<(String, PidIdentity)> {
            self.pids.clone()
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }

        fn kill(&mut self) -> anyhow::Result<()> {
            self.alive.store(false, Ordering::SeqCst);
            self.killed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Socketpair-backed fake of izba-init for post-start invocations.
    ///
    /// Each connection answers exactly one request. Received requests are
    /// appended to `log`. When a `Shutdown` arrives and `kill_on_shutdown` is
    /// set, the given process is killed — simulating the guest powering off.
    fn fake_connector(
        log: Arc<Mutex<Vec<Request>>>,
        kill_on_shutdown: Option<PidIdentity>,
    ) -> impl Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> {
        move |_paths: &Paths, _name: &str| {
            let (client, server) = UnixStream::pair()?;
            let log = log.clone();
            let kill_on_shutdown = kill_on_shutdown.clone();
            std::thread::spawn(move || {
                let mut s = server;
                if let Ok(req) = read_frame::<_, Request>(&mut s) {
                    let resp = match req {
                        Request::Health => Response::Health(HealthInfo {
                            version: "test".into(),
                            uptime_ms: 1,
                        }),
                        Request::Shutdown => {
                            if let Some(id) = &kill_on_shutdown {
                                let _ = procmgr::kill_pid(id);
                            }
                            Response::Ok
                        }
                        _ => Response::Ok,
                    };
                    log.lock().unwrap().push(req);
                    let _ = write_frame(&mut s, &resp);
                }
            });
            Ok(Box::new(client) as Box<dyn IoStream>)
        }
    }

    /// Connector to a guest that accepts the request but never replies —
    /// simulates a wedged-but-accepting control plane.
    fn hanging_connector() -> impl Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> {
        |_paths: &Paths, _name: &str| {
            let (client, server) = UnixStream::pair()?;
            std::thread::spawn(move || {
                let mut s = server;
                let _ = read_frame::<_, Request>(&mut s);
                // Keep the socket open so the client cannot see EOF.
                std::thread::sleep(Duration::from_secs(10));
            });
            Ok(Box::new(client) as Box<dyn IoStream>)
        }
    }

    fn count_shutdowns(log: &Arc<Mutex<Vec<Request>>>) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| matches!(r, Request::Shutdown))
            .count()
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_writes_layout() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        let o = opts(&ws);

        create(&paths, "web", &o).unwrap();

        let sdir = paths.sandbox_dir("web");
        let config: SandboxConfig = load_json(&sdir.join(CONFIG_FILE)).unwrap().unwrap();
        assert_eq!(config.image_digest, o.image_digest);
        assert_eq!(config.image_ref, o.image_ref);
        assert_eq!(config.cpus, o.cpus);
        assert_eq!(config.mem_mb, o.mem_mb);
        assert_eq!(config.workspace, o.workspace);

        let rw = sdir.join("rw.img");
        assert!(rw.is_file());
        assert_eq!(
            fs::metadata(&rw).unwrap().len(),
            o.rw_size_gb * 1024 * 1024 * 1024
        );

        assert!(paths.logs_dir("web").is_dir());
        assert!(paths.run_dir("web").is_dir());

        let err = create(&paths, "web", &o).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err:#}");
    }

    #[test]
    fn start_builds_correct_spec() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts()).unwrap();

        let spec = driver
            .captured
            .lock()
            .unwrap()
            .take()
            .expect("spec captured");
        assert_eq!(spec.kernel, PathBuf::from("/art/vmlinux"));
        assert_eq!(spec.initramfs, PathBuf::from("/art/initramfs.img"));
        assert!(
            spec.cmdline.contains("console=ttyS0 ip=dhcp"),
            "cmdline: {}",
            spec.cmdline
        );
        assert_eq!(spec.cpus, 2);
        assert_eq!(spec.mem_mb, 1024);

        assert_eq!(spec.disks.len(), 2);
        assert_eq!(
            spec.disks[0].path,
            ImageStore::new(&paths).rootfs_path("sha256:abc")
        );
        assert!(spec.disks[0].readonly);
        assert_eq!(spec.disks[1].path, paths.sandbox_dir("web").join("rw.img"));
        assert!(!spec.disks[1].readonly);

        assert_eq!(spec.shares.len(), 1);
        assert_eq!(spec.shares[0].tag, "workspace");
        assert_eq!(spec.shares[0].host_path, ws);

        assert!(spec.net);
        assert_eq!(spec.console_log, paths.logs_dir("web").join("console.log"));
        assert_eq!(spec.run_dir, paths.run_dir("web"));

        let state: RunState = load_json(&paths.sandbox_dir("web").join(STATE_FILE))
            .unwrap()
            .expect("state.json written");
        assert_eq!(state.vmm_pid, live_identity());
        assert!(state.sidecar_pids.is_empty());
    }

    #[test]
    fn start_waits_for_health() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::with(Duration::from_millis(200), true);
        start_with_timeouts(
            &paths,
            "web",
            &driver,
            &arts(),
            Duration::from_secs(2),
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(paths.sandbox_dir("web").join(STATE_FILE).is_file());
    }

    #[test]
    fn start_timeout_kills_and_mentions_console_log() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        // Debris from a previous failed run; the failure path must clear it.
        fs::write(paths.run_dir("web").join("stale.sock"), b"").unwrap();

        let driver = MockDriver::with(Duration::ZERO, false);
        let err = start_with_timeouts(
            &paths,
            "web",
            &driver,
            &arts(),
            Duration::from_millis(300),
            Duration::from_millis(50),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("console.log"),
            "error should point at console.log, got: {err:#}"
        );
        let killed = driver
            .last_killed
            .lock()
            .unwrap()
            .clone()
            .expect("handle launched");
        assert!(killed.load(Ordering::SeqCst), "handle must be killed");
        assert!(
            !paths.sandbox_dir("web").join(STATE_FILE).exists(),
            "state.json must not be written on boot failure"
        );
        let leftovers: Vec<_> = fs::read_dir(paths.run_dir("web"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "run/ must be cleared on boot failure, found: {leftovers:?}"
        );
    }

    #[test]
    fn start_kills_on_missing_vmm_pid() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::without_vmm_pid();
        let err = start(&paths, "web", &driver, &arts()).unwrap_err();

        assert!(err.to_string().contains("vmm"), "got: {err:#}");
        let killed = driver
            .last_killed
            .lock()
            .unwrap()
            .clone()
            .expect("handle launched");
        assert!(
            killed.load(Ordering::SeqCst),
            "handle must be killed when no 'vmm' pid is reported"
        );
        assert!(
            !paths.sandbox_dir("web").join(STATE_FILE).exists(),
            "state.json must not be written when start fails"
        );
    }

    #[test]
    fn start_twice_rejected() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts()).unwrap();

        let err = start(&paths, "web", &driver, &arts()).unwrap_err();
        assert!(err.to_string().contains("already running"), "got: {err:#}");
    }

    #[test]
    fn stop_graceful() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        // Real short-lived child stands in for the VMM; the fake guest kills
        // it when it receives Shutdown, so stop() observes a graceful death.
        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log.clone(), Some(sleep_id.clone()));
        stop(&paths, "web", &conn, Duration::from_secs(5)).unwrap();

        assert_eq!(count_shutdowns(&log), 1, "Shutdown must be sent once");
        assert!(!paths.sandbox_dir("web").join(STATE_FILE).exists());
        assert!(wait_dead(&sleep_id), "vmm stand-in must be dead");
    }

    #[test]
    fn stop_escalates() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        // Guest accepts Shutdown but never dies → stop must escalate to SIGKILL.
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log.clone(), None);
        stop(&paths, "web", &conn, Duration::from_millis(300)).unwrap();

        assert!(wait_dead(&sleep_id), "escalation must kill the vmm");
        assert!(!paths.sandbox_dir("web").join(STATE_FILE).exists());
    }

    #[test]
    fn rm_running_needs_force() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", live_identity());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        let err = remove(&paths, "web", &conn, false).unwrap_err();
        assert!(err.to_string().contains("running"), "got: {err:#}");
        assert!(paths.sandbox_dir("web").is_dir(), "dir must survive");
    }

    #[test]
    fn rm_force_kills_then_deletes() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        remove(&paths, "web", &conn, true).unwrap();

        assert!(!paths.sandbox_dir("web").exists(), "dir must be gone");
        assert!(wait_dead(&sleep_id), "force remove must kill the vmm");
    }

    #[test]
    fn ls_reports_dead_vmm_as_stopped() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        write_state(&paths, "web", dead_identity());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        let infos = list(&paths, &conn).unwrap();

        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "web");
        assert_eq!(infos[0].image_ref, "ubuntu:22.04");
        assert_eq!(infos[0].liveness, Liveness::Stopped);
        assert!(
            !paths.sandbox_dir("web").join(STATE_FILE).exists(),
            "stale state.json must be corrected (deleted)"
        );
    }

    #[test]
    fn control_timeout_is_bounded() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        // vmm "alive" (this test process), guest accepts but never replies.
        write_state(&paths, "web", live_identity());

        let conn = hanging_connector();
        let t0 = Instant::now();
        let infos = list(&paths, &conn).unwrap();
        let elapsed = t0.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "liveness must be bounded by the RPC timeout, took {elapsed:?}"
        );
        assert_eq!(infos.len(), 1);
        assert!(
            matches!(infos[0].liveness, Liveness::Degraded(_)),
            "wedged control plane must report Degraded, got {:?}",
            infos[0].liveness
        );
    }

    #[test]
    fn ls_tolerates_corrupt_state() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "bad", &opts(&ws)).unwrap();
        create(&paths, "good", &opts(&ws)).unwrap();
        fs::write(paths.sandbox_dir("bad").join(STATE_FILE), b"{garbage").unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        let infos = list(&paths, &conn).unwrap();

        assert_eq!(infos.len(), 2, "corrupt sandbox must not abort the listing");
        assert_eq!(infos[0].name, "bad");
        assert_eq!(infos[0].liveness, Liveness::Stopped);
        assert_eq!(infos[1].name, "good");
        assert!(
            paths.sandbox_dir("bad").join(STATE_FILE).exists(),
            "corrupt state.json must be left for inspection, not auto-deleted"
        );
    }

    #[test]
    fn name_validation() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();

        let err = create(&paths, "../evil", &opts(&ws)).unwrap_err();
        assert!(
            err.to_string().contains("invalid sandbox name"),
            "got: {err:#}"
        );
        assert!(
            !paths.sandboxes_dir().join("../evil").exists(),
            "nothing may be created outside sandboxes/"
        );

        assert!(validate_name("ok-name.1").is_ok());
        assert!(validate_name("web").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("-leading-dash").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("UPPER").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name(&"a".repeat(65)).is_err());
        assert!(validate_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn flock_serializes_start() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        // connect() answers after 300 ms, so the lock is held long enough for
        // the loser to hit either the flock or the already-running check.
        let driver = MockDriver::with(Duration::from_millis(300), true);
        let art = arts();

        let results: Vec<anyhow::Result<()>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        start_with_timeouts(
                            &paths,
                            "web",
                            &driver,
                            &art,
                            Duration::from_secs(2),
                            Duration::from_millis(50),
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let oks = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(oks, 1, "exactly one start must win: {results:?}");
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("one loser");
        let msg = err.to_string();
        assert!(
            msg.contains("busy") || msg.contains("already running"),
            "loser error should be busy/already running, got: {msg}"
        );
    }

    /// Verify that `create` pre-formats rw.img with ext4 when `mkfs.ext4` is
    /// available on PATH.  Skipped (with a note) when mkfs.ext4 is absent so
    /// the test suite stays green in minimal CI environments.
    #[test]
    fn create_preformats_rw_when_mkfs_available() {
        if which::which("mkfs.ext4").is_err() {
            eprintln!("SKIP create_preformats_rw_when_mkfs_available: mkfs.ext4 not on PATH");
            return;
        }

        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let rw = paths.sandbox_dir("web").join("rw.img");
        assert!(rw.is_file(), "rw.img must exist after create()");

        // The ext4 superblock starts at byte offset 1024.  If mkfs.ext4 ran
        // successfully the magic bytes 0x53EF will be at offsets 1080-1081
        // (within the superblock at +56).  Reading the first 64 KiB and
        // checking for any non-zero byte past offset 1024 is a quick proxy.
        let mut f = fs::File::open(&rw).unwrap();
        let mut buf = vec![0u8; 65536];
        use std::io::Read as _;
        let n = f.read(&mut buf).unwrap();
        let superblock_region = &buf[1024..n.min(2048)];
        let nonzero = superblock_region.iter().any(|&b| b != 0);
        assert!(
            nonzero,
            "rw.img superblock region must be non-zero after mkfs.ext4 pre-format"
        );
    }
}
