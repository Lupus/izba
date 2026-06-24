//! Sandbox lifecycle orchestration: create / start / stop / remove / list.
//!
//! izba is daemonless — `start` spawns the VMM detached and exits; later
//! invocations (`stop`, `exec`, `ls`) are new processes that reconstruct state
//! from disk and reach the guest through a [`Connector`].

use anyhow::{bail, Context};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use izba_proto::{
    read_frame, write_frame, Request, Response, CONTROL_PORT, OCI_TAG, PAUSE_GUEST_PATH,
    STREAM_PORT,
};

use crate::image::runtime_config::{trust_env_strings, ContainerMode, SpecParams, INTERACTIVE_CWD};
use crate::image::store::ImageStore;
#[cfg(windows)]
use crate::jail_account::orchestrate;
use crate::liveness::{assess, Liveness, Probes};
use crate::paths::Paths;
use crate::procmgr;
use crate::state::{load_json, save_json, RunState, SandboxConfig, CONFIG_FILE, STATE_FILE};
use crate::vmm::{BlockDisk, FsShare, IoStream, LockdownLaunch, VmHandle, VmSpec, VmmDriver};

const DEFAULT_BOOT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_BOOT_POLL: Duration = Duration::from_millis(200);
/// Per-attempt deadline for any single control-plane request/response.
const CONTROL_RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Boot health budget: `IZBA_BOOT_TIMEOUT_SECS` env override, else 30s.
/// CI runners with slow nested virtualization set this; the strict local
/// default is intentionally unchanged.
fn boot_timeout_from_env(raw: Option<&str>) -> Duration {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BOOT_TIMEOUT)
}

#[derive(Debug, Clone)]
pub struct CreateOpts {
    pub image_digest: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    pub rw_size_gb: u64,
    pub ports: Vec<crate::state::PortRule>,
    pub volumes: Vec<crate::volume::VolumeSpec>,
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
/// Returns a concrete [`crate::vmm::UdsStream`] (not `Box<dyn IoStream>`)
/// because stream pumps need `try_clone` for the second direction and
/// `shutdown` to signal half-close — neither is expressible on the trait.
pub fn default_stream_connector() -> impl Fn(&Paths, &str) -> anyhow::Result<crate::vmm::UdsStream>
{
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

/// Last `n` lines of the guest serial console, formatted for appending to a
/// boot-failure error. Empty string when the log is missing or unreadable.
fn console_tail(log: &std::path::Path, n: usize) -> String {
    let Ok(text) = fs::read_to_string(log) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let tail = &lines[lines.len().saturating_sub(n)..];
    format!(
        "\n--- console.log (last {} lines) ---\n{}",
        tail.len(),
        tail.join("\n")
    )
}

/// Disk list for a launch: `[erofs=vda (RO), rw=vdb (RW), vol₀=vdc, …]`.
/// Volumes append in declaration order (the binding the cmdline + guest mount
/// plan rely on).
fn build_vm_disks(
    paths: &Paths,
    name: &str,
    image_digest: &str,
    volumes: &[crate::volume::VolumeSpec],
) -> Vec<BlockDisk> {
    let mut disks = vec![
        BlockDisk {
            path: ImageStore::new(paths).rootfs_path(image_digest),
            readonly: true,
        },
        BlockDisk {
            path: paths.sandbox_dir(name).join("rw.img"),
            readonly: false,
        },
    ];
    for v in volumes.iter() {
        disks.push(BlockDisk {
            path: v.image_path(paths, name),
            readonly: false,
        });
    }
    disks
}

/// Kernel cmdline for a launch. `izba.volumes` carries the ordered guest
/// mountpoints (vdc, vdd, …) only when volumes are present.
fn build_cmdline(name: &str, volumes: &[crate::volume::VolumeSpec]) -> String {
    let mut c = format!("console=ttyS0 izba.hostname={name} izba.egress=1");
    if !volumes.is_empty() {
        c.push_str(&format!(
            " izba.volumes={}",
            crate::volume::cmdline_value(volumes)
        ));
    }
    c
}

/// Resolve the per-sandbox account credentials to use when launching the VMM,
/// or `None` when the sandbox is not locked down (the normal path).
///
/// On Windows: reads `lockdown.json` + unseals `lockdown.cred` via DPAPI.
/// Returns `Some(LockdownLaunch)` for a `Locked` sandbox, `None` otherwise.
///
/// On non-Windows: always `None` — lock-down is Windows-only.
#[cfg(windows)]
fn compute_launch_lockdown(paths: &Paths, name: &str) -> anyhow::Result<Option<LockdownLaunch>> {
    use crate::jail_account::state::LockdownState;
    match orchestrate::lockdown_state(paths, name) {
        LockdownState::Locked(info) => {
            let pw = orchestrate::unseal_password(&orchestrate::WinBackend, paths, name)?
                .ok_or_else(|| {
                    anyhow::anyhow!("locked sandbox '{name}' has no readable lockdown.cred")
                })?;
            Ok(Some(LockdownLaunch::new(info.account, pw)))
        }
        LockdownState::Unlocked | LockdownState::Degraded { .. } => Ok(None),
    }
}

#[cfg(not(windows))]
fn compute_launch_lockdown(_paths: &Paths, _name: &str) -> anyhow::Result<Option<LockdownLaunch>> {
    Ok(None)
}

pub fn create(paths: &Paths, name: &str, opts: &CreateOpts) -> anyhow::Result<()> {
    validate_name(name)?;
    let dir = paths.sandbox_dir(name);
    if dir.exists() {
        bail!("sandbox '{name}' already exists");
    }
    // 0700 on Unix for the per-sandbox dir and every izba-owned ancestor it
    // creates (data root + `sandboxes/`) — never world-traversable on a
    // multi-user host (matches the `ca/` and `daemon/` hardening; F-15).
    crate::paths::create_dir_700(&dir, paths.root())?;

    // Anything failing past this point leaves a partial sandbox — clean it up.
    let populate = || -> anyhow::Result<()> {
        crate::paths::create_dir_700(&paths.logs_dir(name), paths.root())?;
        crate::paths::create_dir_700(&paths.run_dir(name), paths.root())?;

        // Assign stable ids to ephemeral volumes before building config and
        // provisioning, so the id is persisted in config.json and stays stable
        // across starts (the disk slot is keyed off id, not list position).
        let mut volumes = opts.volumes.clone();
        crate::volume::assign_eph_ids(&mut volumes);

        // Single-writer guard: persistent volumes may only be referenced by one sandbox.
        crate::volume::validate_volumes(&volumes)?;
        for v in volumes.iter().filter(|v| v.is_persistent()) {
            let vol_name = v.name.as_deref().unwrap();
            ensure_volume_not_shared(paths, vol_name, name)?;
        }

        let config = SandboxConfig {
            image_digest: opts.image_digest.clone(),
            image_ref: opts.image_ref.clone(),
            cpus: opts.cpus,
            mem_mb: opts.mem_mb,
            workspace: opts.workspace.clone(),
            ports: opts.ports.clone(),
            volumes: volumes.clone(),
        };
        save_json(&dir.join(CONFIG_FILE), &config)?;

        // Sparse scratch disk: apparent size only, no blocks allocated.
        let rw = dir.join("rw.img");
        let f = File::create(&rw).with_context(|| format!("creating {}", rw.display()))?;
        mark_sparse(&f); // no-op on Unix; NTFS needs an explicit opt-in
        f.set_len(opts.rw_size_gb * 1024 * 1024 * 1024)
            .with_context(|| format!("sizing {}", rw.display()))?;
        drop(f); // release the file handle before running mkfs on it

        // Best-effort: pre-format the scratch disk on the host so the guest
        // does not need an embedded mke2fs.  Failure is non-fatal — if
        // mkfs.ext4 is absent or fails, the guest-side mke2fs (if present in
        // the initramfs) will handle it; if neither works, init exits with a
        // clear error.
        best_effort_mkfs(&rw);

        // User volumes: same sparse-create + best-effort-format pattern.
        // A persistent volume whose image already exists is reused as-is
        // (never reformatted), so its data survives across sandboxes.
        for v in volumes.iter() {
            let img = v.image_path(paths, name);
            ensure_volume_image(&img, v.size_bytes, paths.root())
                .with_context(|| format!("provisioning volume {}", v.guest_path.display()))?;
        }
        Ok(())
    };
    let result = populate();
    if result.is_err() {
        let _ = fs::remove_dir_all(&dir);
    }
    result
}

/// On NTFS, `set_len` allocates real clusters — without this, every sandbox
/// physically reserves its full rw_size_gb. Unix filesystems extend sparsely
/// by default, hence the no-op. Best-effort: failure costs disk space, not
/// correctness.
#[cfg(windows)]
fn mark_sparse(f: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned: u32 = 0;
    // SAFETY: valid file handle; no in/out buffers; null overlapped = sync.
    unsafe {
        DeviceIoControl(
            f.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
fn mark_sparse(_f: &File) {}

/// Best-effort host-side ext4 pre-format. Non-fatal: if `mkfs.ext4` is absent
/// or fails, the guest-side mke2fs reformats the blank image at boot.
fn best_effort_mkfs(path: &Path) {
    match which::which("mkfs.ext4") {
        Err(_) => {} // not on PATH — guest handles formatting
        Ok(mkfs) => {
            let out = std::process::Command::new(&mkfs)
                .args(["-q", "-F"])
                .arg(path)
                .output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => eprintln!(
                    "warning: mkfs.ext4 on {} failed ({}): {}",
                    path.display(),
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => eprintln!("warning: failed to run {}: {e}", mkfs.display()),
            }
        }
    }
}

/// Create a sparse ext4-preformatted image at `path` of `size_bytes`, unless
/// it already exists (persistent volumes are reused as-is — never reformatted,
/// so their data survives across sandboxes).
fn ensure_volume_image(path: &Path, size_bytes: u64, root: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        crate::paths::create_dir_700(parent, root)?;
    }
    let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    mark_sparse(&f);
    f.set_len(size_bytes)
        .with_context(|| format!("sizing {}", path.display()))?;
    drop(f);
    best_effort_mkfs(path);
    Ok(())
}

/// Holds the per-sandbox exclusive lock; explicitly unlocks on drop.
///
/// The explicit `unlock` (flock LOCK_UN) matters: dropping the `File` alone
/// releases a flock only when the LAST fd to the open file description
/// closes, and forked children (VMM/sidecar spawns, including from other
/// threads in parallel tests) momentarily inherit the fd until their exec.
/// An explicit unlock releases the lock immediately regardless.
struct SandboxLock(File);

impl Drop for SandboxLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Path of the per-sandbox lock file — deliberately a SIBLING of the
/// sandbox dir (`sandboxes/.<name>.lock`), not a file inside it: `remove`
/// renames the dir while holding the lock, and Windows refuses to rename a
/// directory containing an open file. The leading dot keeps the file name
/// outside the valid sandbox-name space (names start with `[a-z0-9]`), so
/// it can never collide with a real sandbox directory; `list` skips
/// non-directories anyway.
fn lock_path(paths: &Paths, name: &str) -> PathBuf {
    paths.sandboxes_dir().join(format!(".{name}.lock"))
}

/// Take the per-sandbox exclusive lock (released eagerly when the returned
/// guard drops).
fn lock_sandbox(paths: &Paths, name: &str) -> anyhow::Result<SandboxLock> {
    // The dir check replaces the old open-NotFound mapping (the lock file no
    // longer lives inside the sandbox dir). A concurrent remove between this
    // check and the lock acquisition is caught right after: the winner holds
    // the lock and every post-lock state read fails with a clear error.
    if !paths.sandbox_dir(name).is_dir() {
        bail!("no such sandbox '{name}'");
    }
    let lock_path = lock_path(paths, name);
    let f = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(SandboxLock(f)),
        Err(std::fs::TryLockError::WouldBlock) => {
            bail!("sandbox '{name}' is busy (another operation in progress)")
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", lock_path.display()))
        }
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

/// Resolve the host `(uid, gid)` that owns the virtiofs `workspace` share — the
/// anchor for the Option A container user-namespace transposition.
///
/// On Unix this is the owner of the `workspace` directory exactly as the guest's
/// (unprivileged, untranslated) virtiofsd will present it. If the stat fails
/// (e.g. the path was just removed) we fall back to the running process's
/// effective uid/gid, which is also what virtiofsd runs as.
///
/// On non-Unix hosts (Windows/OpenVMM) there is no POSIX owner to read; the
/// OpenVMM bundled virtiofs presents files under a fixed identity, so we anchor
/// at `(0, 0)`. For izba's default root workload that yields an identity map
/// (correct); the non-root-USER case on the OpenVMM backend is pending the
/// WHP-leg validation (see the crun-userns spike findings) — the guest-userns
/// mechanism itself is identical on both backends.
///
/// `#[mutants::skip]`: returns a real file's `(uid, gid)`. A unit test can only
/// observe the test process's own euid/egid (a freshly-created dir is owned by
/// it), and forging a file whose uid != gid needs root — so the uid↔gid-swap
/// and Ok-vs-Err-arm mutants are indistinguishable from correct behavior
/// without privilege. Covered by the real-VM userns round-trip tests, which
/// assert the workspace owner appears as the workload USER inside the guest.
#[mutants::skip]
fn workspace_owner(workspace: &Path) -> (u32, u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(workspace) {
            Ok(m) => (m.uid(), m.gid()),
            Err(e) => {
                // Fail-honest: the anchor falls back to the process owner (what
                // virtiofsd runs as), but log it — a wrong anchor surfaces later
                // as confusing in-container /workspace ownership.
                eprintln!(
                    "izba: [userns] warning: stat({}) failed ({e}); falling back to \
                     euid/egid for the Option A workspace-owner anchor — in-container \
                     /workspace ownership may be wrong",
                    workspace.display()
                );
                (
                    nix::unistd::Uid::effective().as_raw(),
                    nix::unistd::Gid::effective().as_raw(),
                )
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = workspace;
        (0, 0)
    }
}

/// Write `oci/config.json` into `oci_dir` for the interactive (pause) mode.
///
/// Generates an OCI runtime spec via [`crate::image::runtime_config::generate_spec`]
/// in Interactive mode, then atomically writes it as `config.json` (tempfile +
/// rename) so a concurrent reader never sees a torn file. Mode 0644.
///
/// `oci_dir` is `<sandbox_dir>/oci/` and must already exist before this call.
fn write_oci_bundle(
    oci_dir: &Path,
    name: &str,
    image_config: Option<&oci_client::config::Config>,
    ca_present: bool,
    workspace: &Path,
) -> anyhow::Result<()> {
    // Gate the CA trust-env defaults on the bundle actually being present —
    // same gate the guest applies in `build_env_overlay` (trust_bundle_present).
    // Today the host always writes ca.pem so this is always-open, but encoding
    // the gate keeps service-mode (a real entrypoint as PID 1, deferred) from
    // inheriting SSL_CERT_FILE=… when no CA exists.
    let trust = if ca_present {
        trust_env_strings()
    } else {
        Vec::new()
    };
    let pause_argv: Vec<String> = vec![PAUSE_GUEST_PATH.to_string(), "__pause".to_string()];
    let ((uid, gid), user_warn) = crate::image::runtime_config::resolve_process_user(
        image_config.and_then(|c| c.user.as_deref()),
    );
    if let Some(w) = user_warn {
        eprintln!("warning: sandbox '{name}': {w}");
    }
    // Option A anchor: the host (uid, gid) that owns the virtiofs `workspace`,
    // as the guest will see it. izba's virtiofsd runs UNPRIVILEGED and applies
    // no uid translation, so the guest sees the share's real host owner; the
    // container user namespace transposes it to the workload USER so the image
    // USER owns `/workspace`. See `compute_userns_mappings`.
    let host_owner = workspace_owner(workspace);
    let params = SpecParams {
        mode: ContainerMode::Interactive {
            pause_argv: &pause_argv,
        },
        image: image_config,
        entrypoint_override: None,
        cmd_override: None,
        env_overrides: &[],
        trust_env: &trust,
        cwd_override: Some(INTERACTIVE_CWD),
        user: (uid, gid),
        host_owner,
        hostname: name,
        terminal: false,
    };
    let spec =
        crate::image::runtime_config::generate_spec(&params).context("generating OCI spec")?;
    let json = serde_json::to_vec_pretty(&spec).context("serializing OCI spec")?;

    // Atomic write: tempfile in the same dir, then rename into place.
    let mut tmp = tempfile::Builder::new()
        .prefix(".config-")
        .tempfile_in(oci_dir)
        .context("creating tempfile for oci/config.json")?;
    use std::io::Write as _;
    tmp.write_all(&json)
        .context("writing oci/config.json content")?;
    // Set mode 0644 before persisting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .context("setting oci/config.json permissions")?;
    }
    tmp.persist(oci_dir.join("config.json"))
        .context("persisting oci/config.json")?;
    Ok(())
}

/// Writes the SSH host key and authorized_keys into the per-sandbox ssh share
/// dir, creating it if needed. Returns the share dir path.
/// Called next to the trust block in start_with_timeouts.
pub fn write_ssh_material(paths: &Paths, name: &str) -> anyhow::Result<std::path::PathBuf> {
    let ssh_share = paths.ssh_share_dir(name);
    std::fs::create_dir_all(&ssh_share)
        .with_context(|| format!("creating ssh share dir {}", ssh_share.display()))?;
    let id =
        crate::ssh::identity::ensure_identity(&paths.ssh_dir()).context("loading ssh identity")?;
    std::fs::copy(&id.host_private, ssh_share.join("ssh_host_ed25519_key"))
        .with_context(|| format!("copying host key into {}", ssh_share.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssh_share.join("ssh_host_ed25519_key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .with_context(|| format!("setting 0600 on host key in {}", ssh_share.display()))?;
    }
    let authk = crate::ssh::identity::user_public_openssh(&paths.ssh_dir())
        .context("reading user public key")?;
    std::fs::write(ssh_share.join("authorized_keys"), format!("{}\n", authk))
        .with_context(|| format!("writing authorized_keys into {}", ssh_share.display()))?;
    Ok(ssh_share)
}

pub fn start(
    paths: &Paths,
    name: &str,
    driver: &dyn VmmDriver,
    art: &Artifacts,
    allow_unconfined: bool,
) -> anyhow::Result<()> {
    let timeout = boot_timeout_from_env(std::env::var("IZBA_BOOT_TIMEOUT_SECS").ok().as_deref());
    start_with_timeouts(
        paths,
        name,
        driver,
        art,
        allow_unconfined,
        timeout,
        DEFAULT_BOOT_POLL,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_with_timeouts(
    paths: &Paths,
    name: &str,
    driver: &dyn VmmDriver,
    art: &Artifacts,
    allow_unconfined: bool,
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

    // Bake the izba root CA into the guest trust store: write a per-sandbox copy
    // of just the public cert (NEVER the CA dir — it holds the private key) and
    // share it as the read-only `izba-trust` virtiofs tag. izba-init copies it
    // into the guest CA bundle so leaves the MITM mints are trusted in-guest.
    let trust_dir = paths.sandbox_dir(name).join("trust");
    std::fs::create_dir_all(&trust_dir)
        .with_context(|| format!("creating trust dir {}", trust_dir.display()))?;
    let ca = crate::ca::load_or_create(&paths.ca_dir()).context("loading izba CA")?;
    std::fs::write(trust_dir.join("ca.pem"), ca.cert_pem())
        .with_context(|| format!("writing guest CA into {}", trust_dir.display()))?;

    // Deliver the SSH host key + authorized_keys to the guest as the read-only
    // izba-ssh virtiofs share. Mirrors the trust-CA channel.
    let ssh_share = write_ssh_material(paths, name).context("preparing izba-ssh share")?;

    // Single-writer: a persistent volume may back at most one LIVE sandbox.
    for v in config.volumes.iter().filter(|v| v.is_persistent()) {
        let vol = v.name.as_deref().unwrap();
        if let Some(holder) = persistent_volume_holder(paths, vol, name, &conn)? {
            bail!("persistent volume {vol:?} is in use by running sandbox '{holder}'");
        }
    }

    // Write the per-sandbox OCI bundle (`oci/config.json`) and expose it to
    // the guest as the `izba-oci` virtiofs share. The guest's crun reads this
    // config to start the workload container (Pillar A2).
    let oci_dir = paths.sandbox_dir(name).join("oci");
    std::fs::create_dir_all(&oci_dir)
        .with_context(|| format!("creating oci dir {}", oci_dir.display()))?;
    // Load the image config (Entrypoint/Cmd/Env/WorkingDir/User). None is fine
    // for images cached by a pre-crun izba — generate_spec treats it as a bare
    // image with root user and no default env.
    let image_cfg_file = ImageStore::new(paths).load_config(&config.image_digest)?;
    let image_config = image_cfg_file.as_ref().and_then(|f| f.config.as_ref());
    write_oci_bundle(
        &oci_dir,
        name,
        image_config,
        trust_dir.join("ca.pem").exists(),
        &config.workspace,
    )
    .with_context(|| format!("writing oci/config.json for sandbox '{name}'"))?;

    // The guest is a pure vsock island: no NIC, no DHCP. izba.egress=1 is
    // always on — guest egress rides the izbad-owned vsock 1027 plane.
    // izba.volumes (when present) carries the ordered guest mountpoints.
    let cmdline = build_cmdline(name, &config.volumes);
    // Resolve per-sandbox account credentials when the sandbox is locked down
    // (Windows MVP-D).  On non-Windows and for unlocked sandboxes this is None
    // and the normal confined/unconfined path is used.
    let lockdown = compute_launch_lockdown(paths, name)?;
    let spec = VmSpec {
        kernel: art.kernel.clone(),
        initramfs: art.initramfs.clone(),
        cmdline,
        cpus: config.cpus,
        mem_mb: config.mem_mb,
        disks: build_vm_disks(paths, name, &config.image_digest, &config.volumes),
        shares: vec![
            FsShare {
                tag: "workspace".to_string(),
                host_path: config.workspace.clone(),
            },
            FsShare {
                tag: "izba-trust".to_string(),
                host_path: trust_dir.clone(),
            },
            FsShare {
                tag: OCI_TAG.to_string(),
                host_path: oci_dir.clone(),
            },
            FsShare {
                tag: "izba-ssh".to_string(),
                host_path: ssh_share.clone(),
            },
        ],
        console_log: console_log.clone(),
        run_dir: paths.run_dir(name),
        allow_unconfined,
        lockdown,
    };

    let mut handle = driver.launch(&spec)?;

    // Everything after launch must kill the handle on failure, or the VMM
    // would be orphaned with no state.json pointing at it.
    let booted = (|| -> anyhow::Result<()> {
        wait_for_boot(handle.as_ref(), name, &console_log, boot_timeout, poll)?;
        record_run_state(paths, name, handle.as_ref())
    })();

    if let Err(e) = booted {
        let _ = handle.kill();
        // A confined launch Low-labelled the VMM's write surfaces (workspace +
        // writable disks). Boot failed BEFORE state.json was written, so the
        // state.json-gated teardown restore (restore_confined_workspace) cannot
        // fire — restore them here from the spec, gated on the handle's actual
        // confinement so an unconfined (--allow-unconfined) start never touches
        // the user's dirs. The VMM was just killed, so this is safe. No-op on
        // non-Windows.
        if handle.confinement().is_confined() {
            for p in spec.confined_write_surfaces() {
                let _ = procmgr::restore_integrity_recursive(&p);
            }
        }
        // Best-effort: clear stale sockets/pid files so a retry starts clean.
        clear_run_dir_files(paths, name);
        return Err(e);
    }
    Ok(())
}

/// Poll the guest control port until `Health` answers, or `boot_timeout`
/// elapses. Each attempt is individually bounded so a wedged-but-accepting
/// guest cannot stall past the boot budget.
fn wait_for_boot(
    handle: &dyn VmHandle,
    name: &str,
    console_log: &std::path::Path,
    boot_timeout: Duration,
    poll: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + boot_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_timeout = CONTROL_RPC_TIMEOUT
            .min(remaining)
            .max(Duration::from_millis(10));
        if control_is_healthy(handle, attempt_timeout) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "sandbox '{name}' did not become healthy within {boot_timeout:?}; \
                 check {} for boot output{}",
                console_log.display(),
                console_tail(console_log, 15)
            );
        }
        std::thread::sleep(poll);
    }
}

/// One bounded `Health` probe over the control port; any error (not-yet-up,
/// timeout) is squashed to `false` so the boot-wait loop keeps polling.
fn control_is_healthy(handle: &dyn VmHandle, attempt_timeout: Duration) -> bool {
    (|| -> anyhow::Result<bool> {
        let mut s = handle.connect(CONTROL_PORT)?;
        Ok(matches!(
            rpc(&mut s, &Request::Health, attempt_timeout)?,
            Response::Health(_)
        ))
    })()
    .unwrap_or(false)
}

/// Persist the post-boot `state.json`: the VMM pid (split out of the driver's
/// pid list) plus the remaining sidecar pids, the start timestamp, and the
/// host-side confinement actually achieved for the VMM (so status can report it
/// honestly — and loudly when unconfined).
fn record_run_state(paths: &Paths, name: &str, handle: &dyn VmHandle) -> anyhow::Result<()> {
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
        confinement: Some(handle.confinement()),
    };
    save_json(&paths.sandbox_dir(name).join(STATE_FILE), &state)
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
        (Liveness::Stopped, _) | (_, None) => {
            // VMM is already dead; sidecars (virtiofsd) usually self-exit with
            // their vhost-user peer, but not always — best-effort kill them.
            // The VMM is gone, so restore the confined workspace's integrity.
            restore_confined_workspace(paths, name);
            kill_sidecars_from_state(paths, name);
            return cleanup_runtime(paths, name);
        }
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

    // The VMM is confirmed dead above; restore the confined workspace's
    // integrity before wiping state.json (after which we'd lose the "was
    // confined" signal).
    restore_confined_workspace(paths, name);
    cleanup_runtime(paths, name)
}

/// Best-effort kill every sidecar recorded in state.json.
///
/// Called before wiping state.json so orphaned virtiofsd processes
/// (which normally self-exit when their vhost-user peer dies but sometimes
/// do not) are reaped.  Errors are ignored — the cleanup must proceed
/// regardless.
fn kill_sidecars_from_state(paths: &Paths, name: &str) {
    let state_path = paths.sandbox_dir(name).join(STATE_FILE);
    let state: Option<RunState> = match load_json(&state_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Some(s) = state {
        for (_, id) in &s.sidecar_pids {
            let _ = procmgr::kill_pid(id);
        }
    }
}

/// Restore a confined sandbox's write surfaces to Medium integrity after the VMM
/// is gone.
///
/// On Windows the confined VMM runs at Low IL, so its write surfaces — the
/// workspace share (the user's project dir) AND every writable disk backing file
/// (notably named persistent volumes under `<data>/volumes`) — are Low-labelled
/// at launch (mirroring [`VmSpec::confined_write_surfaces`]); this undoes that.
/// A complete no-op on non-Windows and for unconfined/legacy sandboxes
/// (`is_confined()` gate), and best-effort + idempotent — re-asserting Medium is
/// safe to repeat, and a missed restore only leaves a benign Low label (Medium
/// tools write *down* to it).
///
/// (The scratch dir + the disks inside it — rw.img, anon volumes — are wiped on
/// `rm` and re-labelled on the next start, so they need no separate restore; only
/// the persistent, OUTSIDE-the-sandbox-dir surfaces genuinely matter, but
/// restoring the in-sandbox ones too is harmless.)
///
/// Safe to call on every teardown path: graceful stop, force-remove, AND the
/// stale-state sweep that `list` (hence daemon adoption) runs — that sweep is how
/// an orphaned VMM's label is eventually reconciled. MUST run only once the VMM
/// is dead (every caller ensures this before wiping state.json), so the label is
/// never pulled out from under a still-running guest.
fn restore_confined_workspace(paths: &Paths, name: &str) {
    let dir = paths.sandbox_dir(name);
    let state: Option<RunState> = load_json(&dir.join(STATE_FILE)).ok().flatten();
    let confined = state
        .as_ref()
        .and_then(|s| s.confinement.as_ref())
        .is_some_and(|c| c.is_confined());
    if !confined {
        return;
    }
    let cfg = match load_json::<SandboxConfig>(&dir.join(CONFIG_FILE)) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return,
        Err(e) => {
            eprintln!("warning: sandbox '{name}': cannot read config to restore integrity: {e:#}");
            return;
        }
    };
    // Reconstruct the same write surfaces the confined launch Low-labelled (the
    // spec is gone post-launch): the workspace share + every writable disk
    // backing file. Mirrors VmSpec::confined_write_surfaces via the persisted
    // config. Best-effort: a failure on one surface must not skip the rest.
    let mut surfaces = vec![cfg.workspace.clone()];
    for disk in build_vm_disks(paths, name, &cfg.image_digest, &cfg.volumes) {
        if !disk.readonly {
            surfaces.push(disk.path);
        }
    }
    for p in &surfaces {
        if let Err(e) = procmgr::restore_integrity_recursive(p) {
            eprintln!(
                "warning: sandbox '{name}': restoring {} to Medium integrity failed: {e:#}",
                p.display()
            );
        }
    }
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
    } // release the lock (it lives beside the dir, so the rename was safe)
    if let Err(e) = fs::remove_dir_all(&tombstone) {
        eprintln!(
            "warning: sandbox '{name}' renamed to {} but final deletion failed: {e}",
            tombstone.display()
        );
    }
    // Best-effort: the lock file is inert debris once the sandbox is gone
    // (a late-coming locker bails on the missing dir before creating one).
    let _ = fs::remove_file(lock_path(paths, name));
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
        if let Some(info) = scan_sandbox_entry(paths, connector, &entry)? {
            out.push(info);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Classify one entry under `<data>/sandboxes`. Returns `None` for entries that
/// are not live sandboxes (non-dirs, tombstones, half-created dirs missing a
/// config), `Some` for everything reported to the caller. Warnings are emitted
/// for skipped-but-noteworthy dirs, exactly as the inline loop did.
fn scan_sandbox_entry(
    paths: &Paths,
    connector: Connector,
    entry: &fs::DirEntry,
) -> anyhow::Result<Option<SandboxInfo>> {
    if !entry.file_type()?.is_dir() {
        return Ok(None);
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    // Tombstones from interrupted `remove` final-deletes are inert debris,
    // not sandboxes.
    if name.contains(".removing-") {
        return Ok(None);
    }
    let config: SandboxConfig = match load_json(&entry.path().join(CONFIG_FILE)) {
        Ok(Some(c)) => c,
        Ok(None) => {
            eprintln!("warning: sandbox '{name}' has no {CONFIG_FILE}; skipping");
            return Ok(None);
        }
        Err(e) => {
            eprintln!("warning: skipping sandbox '{name}': {e:#}");
            return Ok(None);
        }
    };
    let liveness = match liveness_of(paths, &name, connector) {
        Ok(l) => l,
        Err(e) => {
            // Corrupt state.json must not abort the whole listing; report
            // the sandbox as stopped and leave the file for inspection.
            eprintln!("warning: sandbox '{name}' has unreadable state ({e:#}); showing as stopped");
            return Ok(Some(SandboxInfo {
                name,
                image_ref: config.image_ref,
                liveness: Liveness::Stopped,
            }));
        }
    };
    if liveness == Liveness::Stopped {
        reap_stale_stopped(paths, &name, connector, &entry.path());
    }
    Ok(Some(SandboxInfo {
        name,
        image_ref: config.image_ref,
        liveness,
    }))
}

/// Best-effort cleanup of a stopped sandbox's stale runtime state left behind by
/// a VMM that died on its own — but only if no concurrent operation (e.g. start)
/// holds the lock, otherwise we could delete the state.json it just wrote. Also
/// kills any sidecars (virtiofsd) that may still be alive though the VMM is gone.
fn reap_stale_stopped(paths: &Paths, name: &str, connector: Connector, sandbox_dir: &Path) {
    let state_path = sandbox_dir.join(STATE_FILE);
    if !state_path.exists() {
        return;
    }
    let Ok(_lock) = lock_sandbox(paths, name) else {
        return;
    };
    // The liveness above was read WITHOUT the lock; a `start` may have raced in
    // and booted a fresh (confined) VM by now. Re-confirm Stopped UNDER the lock
    // before the destructive sweep — otherwise we would delete a freshly-written
    // state.json AND, worse, restore the workspace to Medium while the new Low-IL
    // VMM is still running (yanking its write access). Only proceed if still down.
    if liveness_of(paths, name, connector).ok() != Some(Liveness::Stopped) {
        return;
    }
    // This stale-state sweep is also the daemon-adoption reconcile point: an
    // orphaned confined VMM that has since died gets its workspace integrity
    // restored here before its state is wiped.
    restore_confined_workspace(paths, name);
    kill_sidecars_from_state(paths, name);
    let _ = fs::remove_file(&state_path);
}

/// Every persistent-volume name referenced by any sandbox's `config.json`.
/// A volume is "referenced" if some sandbox (running or stopped) declares it;
/// that is the keep rule for prune (mirrors Docker).
fn referenced_volume_names(paths: &Paths) -> anyhow::Result<std::collections::HashSet<String>> {
    let mut names = std::collections::HashSet::new();
    let dir = paths.sandboxes_dir();
    if !dir.is_dir() {
        return Ok(names);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let config: SandboxConfig = match load_json(&entry.path().join(CONFIG_FILE)) {
            Ok(Some(c)) => c,
            _ => continue, // half-created / tombstone dirs reference nothing
        };
        for v in &config.volumes {
            if let Some(n) = &v.name {
                names.insert(n.clone());
            }
        }
    }
    Ok(names)
}

/// Remove persistent volume images under `<data>/volumes` not referenced by
/// any sandbox config. Returns the names removed and the bytes reclaimed.
pub fn prune_volumes(paths: &Paths) -> anyhow::Result<crate::volume::Pruned> {
    let dir = paths.volumes_dir();
    if !dir.is_dir() {
        return Ok(crate::volume::Pruned::default());
    }
    let referenced = referenced_volume_names(paths)?;
    let mut on_disk = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let fname = entry.file_name().to_string_lossy().into_owned();
        if let Some(name) = fname.strip_suffix(".img") {
            on_disk.push(name.to_string());
        }
    }
    let mut pruned = crate::volume::Pruned::default();
    for name in crate::volume::unreferenced_volumes(&on_disk, &referenced) {
        let img = paths.volume_image(&name);
        let bytes = fs::metadata(&img).map(|m| m.len()).unwrap_or(0);
        fs::remove_file(&img).with_context(|| format!("removing {}", img.display()))?;
        pruned.removed.push(name);
        pruned.reclaimed_bytes += bytes;
    }
    pruned.removed.sort();
    Ok(pruned)
}

/// Sandboxes whose config references persistent volume `vol`.
fn referenced_by(paths: &Paths, vol: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let dir = paths.sandboxes_dir();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let cfg_path = entry.path().join(CONFIG_FILE);
        let Some(cfg) = load_json::<SandboxConfig>(&cfg_path)? else {
            continue;
        };
        if cfg.volumes.iter().any(|v| v.name.as_deref() == Some(vol)) {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

/// Fail if a persistent volume is already referenced by a sandbox OTHER than `current`.
///
/// Enforces the single-writer invariant: a named (persistent) volume may be
/// attached to at most one sandbox config at a time. Ephemeral volumes have no
/// name and are never subject to this check.
fn ensure_volume_not_shared(paths: &Paths, vol: &str, current: &str) -> anyhow::Result<()> {
    let others: Vec<String> = referenced_by(paths, vol)?
        .into_iter()
        .filter(|s| s != current)
        .collect();
    if !others.is_empty() {
        bail!(
            "persistent volume '{vol}' is already in use by: {} (detach it there first)",
            others.join(", ")
        );
    }
    Ok(())
}
/// On-disk allocation: blocks × 512 on Unix, file length elsewhere.
fn allocated_bytes(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks() * 512
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

/// Enumerate persistent volume images under `<data>/volumes`, with declared
/// size, on-disk allocation (best-effort), and which sandbox configs use them.
pub fn list_volumes(paths: &Paths) -> anyhow::Result<Vec<crate::volume::VolumeInfo>> {
    let dir = paths.volumes_dir();
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let fname = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = fname.strip_suffix(".img") else {
            continue;
        };
        let meta = entry.metadata()?;
        let mut refs = referenced_by(paths, name)?;
        refs.sort();
        out.push(crate::volume::VolumeInfo {
            name: name.to_string(),
            size_bytes: meta.len(),
            actual_bytes: allocated_bytes(&meta),
            referenced_by: refs,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Append a volume to a sandbox's config (applied on next start). Validates the
/// new set, assigns an eph_id if ephemeral, provisions the backing image.
pub fn attach_volume(
    paths: &Paths,
    name: &str,
    spec: crate::volume::VolumeSpec,
) -> anyhow::Result<()> {
    let cfg_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig =
        load_json(&cfg_path)?.with_context(|| format!("no such sandbox '{name}'"))?;
    cfg.volumes.push(spec);
    crate::volume::validate_volumes(&cfg.volumes)?;
    // Single-writer guard: check the last-added spec (the one we just pushed).
    let new_spec = cfg.volumes.last().unwrap();
    if new_spec.is_persistent() {
        let vol_name = new_spec.name.as_deref().unwrap();
        ensure_volume_not_shared(paths, vol_name, name)?;
    }
    crate::volume::assign_eph_ids(&mut cfg.volumes);
    let v = cfg.volumes.last().unwrap();
    ensure_volume_image(&v.image_path(paths, name), v.size_bytes, paths.root())
        .with_context(|| format!("provisioning volume {}", v.guest_path.display()))?;
    save_json(&cfg_path, &cfg)?;
    Ok(())
}

/// Drop the volume mounted at `guest_path` from a sandbox's config (applied on
/// next start). No image I/O — persistent images survive; an orphaned ephemeral
/// image is reclaimed at `rm`.
pub fn detach_volume(
    paths: &Paths,
    name: &str,
    guest_path: &std::path::Path,
) -> anyhow::Result<()> {
    let cfg_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig =
        load_json(&cfg_path)?.with_context(|| format!("no such sandbox '{name}'"))?;
    let before = cfg.volumes.len();
    cfg.volumes.retain(|v| v.guest_path != guest_path);
    if cfg.volumes.len() == before {
        bail!(
            "no volume mounted at {} in sandbox '{name}'",
            guest_path.display()
        );
    }
    save_json(&cfg_path, &cfg)?;
    Ok(())
}

/// Delete a single persistent volume image. Fails closed if any sandbox config
/// references it. Returns bytes reclaimed.
pub fn remove_volume(paths: &Paths, name: &str) -> anyhow::Result<u64> {
    let refs = referenced_by(paths, name)?;
    if !refs.is_empty() {
        bail!("volume '{name}' is in use by: {}", refs.join(", "));
    }
    let img = paths.volume_image(name);
    if !img.exists() {
        bail!("no such volume '{name}'");
    }
    let bytes = fs::metadata(&img).map(|m| m.len()).unwrap_or(0);
    fs::remove_file(&img).with_context(|| format!("removing {}", img.display()))?;
    Ok(bytes)
}

/// If a *live* sandbox other than `exclude` references persistent volume
/// `vol_name`, return that sandbox's name. Enforces single-writer at start.
fn persistent_volume_holder(
    paths: &Paths,
    vol_name: &str,
    exclude: &str,
    connector: Connector,
) -> anyhow::Result<Option<String>> {
    let dir = paths.sandboxes_dir();
    if !dir.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == exclude || name.contains(".removing-") {
            continue;
        }
        let config: SandboxConfig = match load_json(&entry.path().join(CONFIG_FILE)) {
            Ok(Some(c)) => c,
            _ => continue,
        };
        let references = config
            .volumes
            .iter()
            .any(|v| v.name.as_deref() == Some(vol_name));
        if references && liveness_of(paths, &name, connector)? != Liveness::Stopped {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        count_shutdowns, dead_identity, fake_connector, hanging_connector, live_identity,
        spawn_sleep, test_paths, wait_dead, write_state, write_state_with_sidecars, MockDriver,
    };
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // workspace_owner (Option A userns anchor)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn workspace_owner_reads_dir_owner() {
        // A freshly created dir is owned by the running process's euid/egid,
        // which is exactly what an unprivileged virtiofsd would present.
        let dir = tempfile::tempdir().unwrap();
        let (uid, gid) = workspace_owner(dir.path());
        let euid = nix::unistd::Uid::effective().as_raw();
        let egid = nix::unistd::Gid::effective().as_raw();
        assert_eq!((uid, gid), (euid, egid));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_owner_missing_path_falls_back_to_euid() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let (uid, gid) = workspace_owner(&missing);
        let euid = nix::unistd::Uid::effective().as_raw();
        let egid = nix::unistd::Gid::effective().as_raw();
        assert_eq!((uid, gid), (euid, egid));
    }

    // -----------------------------------------------------------------------
    // compute_launch_lockdown (non-Windows: always None)
    // -----------------------------------------------------------------------

    /// On non-Windows platforms the lock-down feature is a no-op: the helper
    /// must return `None` unconditionally regardless of what is on disk,
    /// so the normal confined/unconfined path is always used.
    #[cfg(not(windows))]
    #[test]
    fn compute_launch_lockdown_returns_none_on_non_windows() {
        let (_dir, paths) = test_paths();
        // A sandbox dir is not needed — the non-Windows impl ignores paths.
        let result = compute_launch_lockdown(&paths, "any-name").expect("must not error");
        assert!(
            result.is_none(),
            "compute_launch_lockdown must return None on non-Windows"
        );
    }

    // -----------------------------------------------------------------------
    // Sandbox-specific helpers (not shared)
    // -----------------------------------------------------------------------

    #[test]
    fn create_provisions_volume_images() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let mut o = opts(&ws);
        o.volumes = vec![
            crate::volume::VolumeSpec {
                name: None,
                guest_path: "/eph".into(),
                size_bytes: 1 << 20,
                eph_id: None,
            },
            crate::volume::VolumeSpec {
                name: Some("cache".into()),
                guest_path: "/data".into(),
                size_bytes: 1 << 20,
                eph_id: None,
            },
        ];
        create(&paths, "web", &o).unwrap();
        assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
        assert!(paths.volume_image("cache").exists());
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.volumes.len(), 2);
    }

    #[test]
    fn create_assigns_eph_ids_and_persists_them() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let mut o = opts(&ws);
        o.volumes = vec![
            crate::volume::parse_volume_flag("cache:/data:1g").unwrap(), // persistent
            crate::volume::parse_volume_flag("/scratch:1g").unwrap(),    // ephemeral
        ];
        create(&paths, "web", &o).unwrap();
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.volumes[0].eph_id, None); // persistent: no eph_id
        assert_eq!(cfg.volumes[1].eph_id, Some(0)); // first ephemeral gets id 0
        assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
    }

    #[test]
    fn create_keeps_existing_persistent_volume() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(paths.volumes_dir()).unwrap();
        std::fs::write(paths.volume_image("keep"), b"SENTINEL-DATA").unwrap();
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::VolumeSpec {
            name: Some("keep".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        }];
        create(&paths, "web", &o).unwrap();
        let data = std::fs::read(paths.volume_image("keep")).unwrap();
        assert!(data.starts_with(b"SENTINEL-DATA"));
    }

    #[test]
    fn prune_removes_unreferenced_only() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        // "kept" is referenced by a sandbox; "orphan" is not.
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::VolumeSpec {
            name: Some("kept".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        }];
        create(&paths, "web", &o).unwrap();
        std::fs::write(paths.volume_image("orphan"), vec![0u8; 4096]).unwrap();

        let pruned = prune_volumes(&paths).unwrap();
        assert_eq!(pruned.removed, vec!["orphan".to_string()]);
        assert!(!paths.volume_image("orphan").exists());
        assert!(paths.volume_image("kept").exists());
    }

    #[test]
    fn disks_append_volumes_after_rw() {
        let (_dir, paths) = test_paths();
        let vols = vec![
            crate::volume::VolumeSpec {
                name: None,
                guest_path: "/a".into(),
                size_bytes: 1 << 20,
                eph_id: Some(0), // ids must be pre-assigned; build_vm_disks trusts them
            },
            crate::volume::VolumeSpec {
                name: Some("c".into()),
                guest_path: "/b".into(),
                size_bytes: 1 << 20,
                eph_id: None,
            },
        ];
        let disks = build_vm_disks(&paths, "web", "sha256:x", &vols);
        assert_eq!(disks.len(), 4);
        assert!(disks[0].readonly && !disks[1].readonly);
        assert_eq!(
            disks[2].path,
            paths.sandbox_dir("web").join("volumes/0.img")
        );
        assert_eq!(disks[3].path, paths.volume_image("c"));
    }

    #[test]
    fn cmdline_includes_volumes_when_present() {
        let vols = vec![crate::volume::VolumeSpec {
            name: None,
            guest_path: "/a".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        }];
        assert!(build_cmdline("web", &vols).contains("izba.volumes=/a"));
        assert!(!build_cmdline("web", &[]).contains("izba.volumes"));
    }

    fn opts(workspace: &Path) -> CreateOpts {
        CreateOpts {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 1024,
            workspace: workspace.to_path_buf(),
            rw_size_gb: 1,
            ports: Vec::new(),
            volumes: Vec::new(),
        }
    }

    fn arts() -> Artifacts {
        Artifacts {
            kernel: PathBuf::from("/art/vmlinux"),
            initramfs: PathBuf::from("/art/initramfs.img"),
        }
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
    fn create_persists_ports() {
        use crate::state::PortRule;
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        let mut o = opts(&ws);
        o.ports = vec![PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 8080,
            guest_port: 80,
        }];
        create(&paths, "web", &o).unwrap();
        let config: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(config.ports, o.ports);
    }

    #[test]
    fn start_builds_correct_spec() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts(), false).unwrap();

        let spec = driver
            .captured
            .lock()
            .unwrap()
            .take()
            .expect("spec captured");
        assert_eq!(spec.kernel, PathBuf::from("/art/vmlinux"));
        assert_eq!(spec.initramfs, PathBuf::from("/art/initramfs.img"));
        assert!(
            spec.cmdline
                .contains("console=ttyS0 izba.hostname=web izba.egress=1"),
            "cmdline: {}",
            spec.cmdline
        );
        assert!(
            !spec.cmdline.contains("ip=dhcp"),
            "ip=dhcp must be absent: {}",
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

        assert_eq!(spec.shares.len(), 4); // workspace + izba-trust + izba-oci + izba-ssh
        assert_eq!(spec.shares[0].tag, "workspace");
        assert_eq!(spec.shares[0].host_path, ws);
        // The izba CA is baked into every guest via the read-only izba-trust
        // share (a per-sandbox copy of just the public cert).
        assert_eq!(spec.shares[1].tag, "izba-trust");
        assert_eq!(
            spec.shares[1].host_path,
            paths.sandbox_dir("web").join("trust")
        );
        assert!(
            paths
                .sandbox_dir("web")
                .join("trust")
                .join("ca.pem")
                .exists(),
            "guest CA cert written for the izba-trust share"
        );
        // The OCI bundle is delivered to the guest as the izba-oci share.
        assert_eq!(spec.shares[2].tag, izba_proto::OCI_TAG);
        assert_eq!(
            spec.shares[2].host_path,
            paths.sandbox_dir("web").join("oci")
        );
        assert!(
            paths
                .sandbox_dir("web")
                .join("oci")
                .join("config.json")
                .exists(),
            "oci/config.json written for the izba-oci share"
        );

        assert_eq!(spec.console_log, paths.logs_dir("web").join("console.log"));
        assert_eq!(spec.run_dir, paths.run_dir("web"));

        let state: RunState = load_json(&paths.sandbox_dir("web").join(STATE_FILE))
            .unwrap()
            .expect("state.json written");
        assert_eq!(state.vmm_pid, live_identity());
        assert!(state.sidecar_pids.is_empty());
    }

    #[test]
    fn start_writes_parseable_interactive_oci_config() {
        use crate::image::runtime_config::INTERACTIVE_CWD;
        use izba_proto::{OCI_TAG, PAUSE_GUEST_PATH};
        use oci_spec::runtime::{LinuxNamespaceType, Spec};

        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts(), false).unwrap();

        let spec_captured = driver
            .captured
            .lock()
            .unwrap()
            .take()
            .expect("spec captured");
        // The izba-oci share host_path holds config.json.
        let oci_share = spec_captured
            .shares
            .iter()
            .find(|s| s.tag == OCI_TAG)
            .expect("izba-oci share present");
        let config_path = oci_share.host_path.join("config.json");
        let json = fs::read_to_string(&config_path).expect("oci/config.json readable");

        // Must parse as a valid OCI runtime Spec.
        let spec: Spec = serde_json::from_str(&json).expect("config.json is a valid OCI Spec");

        // Root path must be /rootfs (CONTAINER_ROOTFS).
        let root = spec.root().as_ref().expect("root present");
        assert_eq!(
            root.path().to_string_lossy(),
            crate::image::runtime_config::CONTAINER_ROOTFS
        );

        // Process args must be the pause argv.
        let proc = spec.process().as_ref().expect("process present");
        let args = proc.args().clone().expect("args present");
        assert_eq!(
            args,
            vec![PAUSE_GUEST_PATH.to_string(), "__pause".to_string()]
        );

        // cwd must be INTERACTIVE_CWD (/workspace).
        assert_eq!(proc.cwd().to_string_lossy(), INTERACTIVE_CWD);

        // D1: no network namespace — the container shares izba-init's netns.
        let nss = spec
            .linux()
            .as_ref()
            .expect("linux section")
            .namespaces()
            .clone()
            .expect("namespaces");
        let types: Vec<LinuxNamespaceType> = nss.iter().map(|n| n.typ()).collect();
        assert!(
            !types.contains(&LinuxNamespaceType::Network),
            "network namespace must be absent (D1)"
        );
    }

    #[test]
    fn start_cmdline_egress_flag() {
        // izba.egress=1 is unconditional (the guest is always a vsock island).
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();

        create(&paths, "web", &opts(&ws)).unwrap();
        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts(), false).unwrap();
        let spec = driver.captured.lock().unwrap().take().expect("spec");
        assert!(
            spec.cmdline.contains("izba.egress=1"),
            "cmdline must contain izba.egress=1: {}",
            spec.cmdline
        );
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
            false,
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
            false,
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
        let err = start(&paths, "web", &driver, &arts(), false).unwrap_err();

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
        start(&paths, "web", &driver, &arts(), false).unwrap();

        let err = start(&paths, "web", &driver, &arts(), false).unwrap_err();
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
                            false,
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

    /// Verify that `stop` reaps sidecar processes (e.g. virtiofsd) that
    /// are still alive when the VMM has already died on its own.
    ///
    /// Scenario: state.json records a dead VMM identity and one live sidecar
    /// (`sleep 30`).  `stop()` must kill the sidecar and remove state.json.
    #[test]
    fn stop_reaps_orphaned_sidecars() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        // Sidecar is a real live process.
        let sidecar_id = spawn_sleep(dir.path());
        assert!(
            procmgr::pid_alive(&sidecar_id),
            "sidecar must be alive initially"
        );

        // VMM identity is forged-dead (starttime mismatch).
        write_state_with_sidecars(
            &paths,
            "web",
            dead_identity(),
            vec![("virtiofsd:workspace".to_string(), sidecar_id.clone())],
        );

        // Connector will not be called because the VMM is already dead.
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, None);
        stop(&paths, "web", &conn, Duration::from_secs(5)).unwrap();

        // state.json must be gone.
        assert!(
            !paths.sandbox_dir("web").join(STATE_FILE).exists(),
            "state.json must be removed after stop"
        );
        // Sidecar must be dead within 2 s.
        assert!(
            wait_dead(&sidecar_id),
            "orphaned sidecar must be killed by stop()"
        );
    }

    /// A confined sandbox's teardown takes the load-config + restore-integrity
    /// branch of `restore_confined_workspace` (the integrity restore itself is a
    /// no-op on non-Windows; here we exercise the control flow). Must not panic.
    #[test]
    fn restore_confined_workspace_runs_full_path_for_confined_sandbox() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        // Include a NAMED persistent volume so restore exercises the writable-disk
        // loop (the named volume image lives outside the sandbox scratch dir).
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::VolumeSpec {
            name: Some("data".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        }];
        create(&paths, "web", &o).unwrap();
        // Record a CONFINED status so restore loads config + restores the ws.
        save_json(
            &paths.sandbox_dir("web").join(STATE_FILE),
            &RunState {
                vmm_pid: dead_identity(),
                sidecar_pids: vec![],
                started_unix_ms: 0,
                confinement: Some(procmgr::ConfinementStatus::applied(
                    &procmgr::ConfinementPolicy::vmm_default(),
                )),
            },
        )
        .unwrap();
        restore_confined_workspace(&paths, "web"); // Ok(Some(config)) arm
    }

    /// `restore_confined_workspace` is a no-op for unconfined/legacy sandboxes
    /// and tolerates a missing or malformed config without panicking — it is
    /// called best-effort on every teardown path.
    #[test]
    fn restore_confined_workspace_skips_unconfined_and_tolerates_bad_config() {
        let (_dir, paths) = test_paths();
        let sdir = paths.sandbox_dir("box");
        fs::create_dir_all(&sdir).unwrap();
        // No state.json -> not confined -> early return.
        restore_confined_workspace(&paths, "box");
        // Unconfined state (confinement: None) -> is_confined() false -> return.
        write_state(&paths, "box", dead_identity());
        restore_confined_workspace(&paths, "box");
        // Confined state but config.json MISSING (Ok(None) arm).
        let confined = RunState {
            vmm_pid: dead_identity(),
            sidecar_pids: vec![],
            started_unix_ms: 0,
            confinement: Some(procmgr::ConfinementStatus::applied(
                &procmgr::ConfinementPolicy::vmm_default(),
            )),
        };
        save_json(&sdir.join(STATE_FILE), &confined).unwrap();
        restore_confined_workspace(&paths, "box"); // Ok(None) arm
                                                   // Confined state but MALFORMED config.json (Err arm).
        fs::write(sdir.join(CONFIG_FILE), b"{ not json").unwrap();
        restore_confined_workspace(&paths, "box"); // Err arm
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

    #[test]
    fn boot_timeout_defaults_when_env_unset() {
        assert_eq!(boot_timeout_from_env(None), DEFAULT_BOOT_TIMEOUT);
    }

    #[test]
    fn boot_timeout_parses_seconds_override() {
        assert_eq!(boot_timeout_from_env(Some("120")), Duration::from_secs(120));
    }

    #[test]
    fn boot_timeout_ignores_garbage() {
        assert_eq!(boot_timeout_from_env(Some("garbage")), DEFAULT_BOOT_TIMEOUT);
    }

    #[test]
    fn boot_timeout_trims_whitespace() {
        assert_eq!(boot_timeout_from_env(Some(" 45 ")), Duration::from_secs(45));
    }

    #[test]
    fn list_volumes_reports_size_and_references() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        // Persistent volume referenced by sandbox "web".
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("cache:/data:1g").unwrap()];
        create(&paths, "web", &o).unwrap();
        let got = list_volumes(&paths).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "cache");
        assert_eq!(got[0].size_bytes, 1 << 30);
        assert_eq!(got[0].referenced_by, vec!["web".to_string()]);
    }

    #[test]
    fn remove_volume_refuses_when_referenced() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("cache:/data:1g").unwrap()];
        create(&paths, "web", &o).unwrap();
        let err = remove_volume(&paths, "cache").unwrap_err().to_string();
        assert!(err.contains("in use"), "got: {err}");
        assert!(paths.volume_image("cache").exists());
    }

    #[test]
    fn remove_volume_deletes_unreferenced() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.volumes_dir()).unwrap();
        std::fs::write(paths.volume_image("old"), vec![0u8; 4096]).unwrap();
        let freed = remove_volume(&paths, "old").unwrap();
        assert!(!paths.volume_image("old").exists());
        assert!(freed > 0);
    }

    #[test]
    fn attach_volume_appends_provisions_and_persists() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        let spec = crate::volume::parse_volume_flag("/scratch:1g").unwrap();
        attach_volume(&paths, "web", spec).unwrap();
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.volumes.len(), 1);
        assert_eq!(cfg.volumes[0].eph_id, Some(0));
        assert!(paths.sandbox_dir("web").join("volumes/0.img").exists());
    }

    #[test]
    fn attach_volume_rejects_duplicate_guest_path() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        attach_volume(
            &paths,
            "web",
            crate::volume::parse_volume_flag("/data:1g").unwrap(),
        )
        .unwrap();
        let err = attach_volume(
            &paths,
            "web",
            crate::volume::parse_volume_flag("x:/data:1g").unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn detach_volume_removes_entry_no_file_io() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();
        attach_volume(
            &paths,
            "web",
            crate::volume::parse_volume_flag("/data:1g").unwrap(),
        )
        .unwrap();
        let img = paths.sandbox_dir("web").join("volumes/0.img");
        assert!(img.exists());
        detach_volume(&paths, "web", std::path::Path::new("/data")).unwrap();
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(cfg.volumes.is_empty());
        assert!(img.exists(), "detach must not delete the backing image");
    }

    // -----------------------------------------------------------------------
    // Single-writer guard: one sandbox per persistent volume
    // -----------------------------------------------------------------------

    /// attach_volume must refuse if a persistent volume is already referenced
    /// by a different sandbox's config.
    #[test]
    fn attach_volume_refuses_volume_in_use_by_another_sandbox() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // Sandbox A already has "shared" in its config.
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("shared:/data:1g").unwrap()];
        create(&paths, "sandbox-a", &o).unwrap();

        // Sandbox B has no volumes.
        create(&paths, "sandbox-b", &opts(&ws)).unwrap();

        // Attempting to attach "shared" to B must fail with "in use".
        let err = attach_volume(
            &paths,
            "sandbox-b",
            crate::volume::parse_volume_flag("shared:/data:1g").unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("in use"), "expected 'in use', got: {err}");
    }

    /// attach_volume must succeed when a persistent volume is referenced by
    /// nobody at all.
    #[test]
    fn attach_volume_allows_free_persistent_volume() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        create(&paths, "sandbox-a", &opts(&ws)).unwrap();

        attach_volume(
            &paths,
            "sandbox-a",
            crate::volume::parse_volume_flag("fresh:/data:1g").unwrap(),
        )
        .unwrap();
    }

    /// After detaching a persistent volume from sandbox A, attaching it to B
    /// must succeed (it is now free).
    #[test]
    fn attach_volume_allows_reattach_after_detach() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // Sandbox A holds "shared".
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("shared:/data:1g").unwrap()];
        create(&paths, "sandbox-a", &o).unwrap();

        // Sandbox B exists with no volumes.
        create(&paths, "sandbox-b", &opts(&ws)).unwrap();

        // Detach from A -- now the volume is free.
        detach_volume(&paths, "sandbox-a", std::path::Path::new("/data")).unwrap();

        // Attaching to B must now succeed.
        attach_volume(
            &paths,
            "sandbox-b",
            crate::volume::parse_volume_flag("shared:/data:1g").unwrap(),
        )
        .unwrap();
    }

    /// create must refuse if a persistent volume in opts.volumes is already
    /// referenced by another sandbox's config.
    #[test]
    fn create_refuses_persistent_volume_in_use() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // Sandbox A holds "shared".
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("shared:/data:1g").unwrap()];
        create(&paths, "sandbox-a", &o).unwrap();

        // Creating sandbox B with the same persistent volume must fail.
        let mut o2 = opts(&ws);
        o2.volumes = vec![crate::volume::parse_volume_flag("shared:/data:1g").unwrap()];
        let err = create(&paths, "sandbox-b", &o2).unwrap_err().to_string();
        assert!(err.contains("in use"), "expected 'in use', got: {err}");
    }

    /// write_ssh_material populates the per-sandbox ssh share dir with the
    /// host private key and the user authorized_keys file; key is 0600 on Unix.
    #[test]
    fn write_ssh_material_creates_expected_files() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.ssh_dir()).unwrap();

        let share_dir = write_ssh_material(&paths, "web").unwrap();

        let host_key = share_dir.join("ssh_host_ed25519_key");
        let authk = share_dir.join("authorized_keys");
        assert!(host_key.exists(), "host private key must be written");
        assert!(authk.exists(), "authorized_keys must be written");

        let authk_bytes = std::fs::read(&authk).unwrap();
        let authk_str = std::str::from_utf8(&authk_bytes).unwrap();
        assert!(
            authk_str.starts_with("ssh-ed25519 "),
            "authorized_keys must begin with ssh-ed25519"
        );
        assert!(
            authk_bytes.last().copied() == Some(b'\n'),
            "authorized_keys must end with newline"
        );

        let id = crate::ssh::identity::ensure_identity(&paths.ssh_dir()).unwrap();
        let src = std::fs::read(&id.host_private).unwrap();
        let dst = std::fs::read(&host_key).unwrap();
        assert_eq!(src, dst, "host key content must match source");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&host_key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "host private key must be 0600");
        }
    }

    /// start delivers the izba-ssh share in the VmSpec shares vec.
    #[test]
    fn start_includes_ssh_share() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let driver = MockDriver::new();
        start(&paths, "web", &driver, &arts(), false).unwrap();

        let spec = driver
            .captured
            .lock()
            .unwrap()
            .take()
            .expect("spec captured");

        assert_eq!(
            spec.shares.len(),
            4,
            "workspace + izba-trust + izba-oci + izba-ssh"
        );
        let ssh_share = spec
            .shares
            .iter()
            .find(|s| s.tag == "izba-ssh")
            .expect("izba-ssh share must be present");
        assert_eq!(ssh_share.host_path, paths.ssh_share_dir("web"));
        assert!(ssh_share.host_path.join("ssh_host_ed25519_key").exists());
        assert!(ssh_share.host_path.join("authorized_keys").exists());
    }

    /// Ephemeral volumes (no name) are not subject to the single-writer guard;
    /// two sandboxes may both declare an ephemeral volume without conflict.
    #[test]
    fn attach_volume_ephemeral_not_blocked_by_guard() {
        let (_dir, paths) = test_paths();
        let ws = paths.root().join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // Sandbox A has an ephemeral volume at /scratch.
        let mut o = opts(&ws);
        o.volumes = vec![crate::volume::parse_volume_flag("/scratch:1g").unwrap()];
        create(&paths, "sandbox-a", &o).unwrap();

        // Sandbox B has no volumes yet.
        create(&paths, "sandbox-b", &opts(&ws)).unwrap();

        // Attaching an ephemeral volume to B must succeed -- no cross-sandbox guard.
        attach_volume(
            &paths,
            "sandbox-b",
            crate::volume::parse_volume_flag("/scratch:1g").unwrap(),
        )
        .unwrap();
    }
}
