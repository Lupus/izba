//! The izbad server: one thread per client connection, dispatching framed
//! `DaemonRequest`s onto the same `sandbox::*` lifecycle functions the
//! daemonless CLI used to call directly. All external effects are seams in
//! [`DaemonDeps`] so unit tests run against socketpair fakes.

use anyhow::{bail, Context};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use izba_proto::{read_frame, write_frame, Response};

use crate::daemon::egress::EgressManager;
use crate::daemon::proto::{
    DaemonHello, DaemonRequest, DaemonResponse, DaemonStatus, SandboxDetail,
};
use crate::daemon::registry::Registry;
use crate::daemon::relays::{self, RelayManager};
use crate::daemon::{supervisor, transport};
use crate::liveness::Liveness;
use crate::paths::Paths;
use crate::portfwd::copy_until_eof;
use crate::procmgr;
use crate::sandbox::{self, Artifacts, Connector, CreateOpts};
use crate::state::{load_json, SandboxConfig, CONFIG_FILE};
use crate::vmm::{IoStream, UdsStream, VmmDriver};

const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the shared MITM tier-1 runtime: load/mint the persistent izba CA, sign
/// per-SNI leaves under it, verify real upstreams against the Mozilla roots, and
/// audit every decision. Returns `None` if CA init or the runtime fails — the
/// daemon must still come up (it also serves bare sandboxes that never MITM).
/// With `None`, bare sandboxes keep their transparent direct dial, but an
/// ENFORCING sandbox's HTTP(S) FAILS CLOSED at the router (it is never silently
/// downgraded to a direct dial — see `router::tcp_connect`). The per-sandbox
/// policy travels with each flow, so no policy is needed here.
fn build_mitm_runtime(
    paths: &Paths,
    audit: crate::daemon::egress::audit::AuditSink,
) -> Option<Arc<crate::daemon::egress::mitm_runtime::MitmRuntime>> {
    use crate::daemon::egress::mitm::{upstream_client_config_webpki, CertCache};
    use crate::daemon::egress::mitm_runtime::MitmRuntime;

    // The MITM datapath signs/verifies with the ring CryptoProvider (aws-lc-rs
    // is also linked via oci-client's reqwest, so an ambiguous process default
    // would panic). Installing it is best-effort: an existing default is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = match crate::ca::load_or_create(&paths.ca_dir()) {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("izbad: egress MITM disabled — CA init failed: {e:#}");
            return None;
        }
    };
    let certs = Arc::new(CertCache::new(ca));
    match MitmRuntime::start(certs, upstream_client_config_webpki(), audit) {
        Ok(rt) => Some(Arc::new(rt)),
        Err(e) => {
            eprintln!("izbad: egress MITM disabled — runtime start failed: {e:#}");
            None
        }
    }
}

/// Boxed, thread-shareable flavor of [`sandbox::Connector`] — the daemon
/// owns it for its lifetime and lends `&dyn Fn` views to connection threads.
pub type SharedConnector =
    Box<dyn Fn(&Paths, &str) -> anyhow::Result<Box<dyn IoStream>> + Send + Sync>;

/// Like [`SharedConnector`], but dialing the guest stream port (vsock 1026);
/// concrete [`UdsStream`] because splicing needs `try_clone` + `shutdown`.
pub type SharedStreamConnector =
    Box<dyn Fn(&Paths, &str) -> anyhow::Result<UdsStream> + Send + Sync>;

/// Seam over `artifacts::locate`.
pub type ArtifactsFn = Box<dyn Fn(&Paths) -> anyhow::Result<Artifacts> + Send + Sync>;

/// Seam over `image::ensure_image`: image ref → digest (pulling if needed).
pub type ResolveImageFn = Box<dyn Fn(&Paths, &str) -> anyhow::Result<String> + Send + Sync>;

/// Injectable seams: production wiring in [`DaemonDeps::production`], fakes
/// in tests (mirrors the `Connector` convention in sandbox.rs).
pub struct DaemonDeps {
    pub version: String,
    pub driver: Box<dyn VmmDriver + Send + Sync>,
    pub connector: SharedConnector,
    pub stream_connector: SharedStreamConnector,
    pub artifacts: ArtifactsFn,
    pub resolve_image: ResolveImageFn,
    pub egress_policy: std::sync::Arc<dyn crate::daemon::egress::policy::Policy>,
    pub egress_resolver: std::sync::Arc<dyn crate::daemon::egress::dns::Resolver>,
}

impl DaemonDeps {
    pub fn production() -> Self {
        #[cfg(unix)]
        use crate::vmm::cloud_hypervisor::CloudHypervisorDriver as DefaultDriver;
        #[cfg(windows)]
        use crate::vmm::openvmm::OpenVmmDriver as DefaultDriver;
        Self {
            version: transport::daemon_version(),
            driver: Box::new(DefaultDriver),
            connector: Box::new(sandbox::default_connector()),
            stream_connector: Box::new(sandbox::default_stream_connector()),
            artifacts: Box::new(crate::artifacts::locate),
            resolve_image: Box::new(crate::image::ensure_image),
            egress_policy: std::sync::Arc::new(crate::daemon::egress::policy::AllowAll),
            egress_resolver: std::sync::Arc::new(crate::daemon::egress::dns::UdpForwarder::system()),
        }
    }
}

pub struct Daemon {
    pub paths: Paths,
    pub deps: DaemonDeps,
    pub registry: Registry,
    pub relays: RelayManager,
    pub egress: EgressManager,
    started: Instant,
    active_conns: AtomicUsize,
    shutdown: AtomicBool,
    idle_since: Mutex<Instant>,
}

impl Daemon {
    pub fn new(paths: Paths, deps: DaemonDeps) -> Self {
        // Clone the egress seams before `deps` is moved into the struct. The
        // MITM tier-1 runtime is built from the persistent izba CA; if that
        // fails the daemon still runs (bare sandboxes never MITM), but enforcing
        // sandboxes' HTTP(S) then fails closed at the router rather than
        // downgrading — logged in `build_mitm_runtime`.
        let audit = crate::daemon::egress::audit::AuditSink::new(paths.clone());
        let mitm = build_mitm_runtime(&paths, audit.clone());
        let egress = EgressManager::new(
            Arc::clone(&deps.egress_policy),
            Arc::clone(&deps.egress_resolver),
            mitm,
            audit,
        );
        Self {
            paths,
            deps,
            registry: Registry::new(),
            relays: RelayManager::new(),
            egress,
            started: Instant::now(),
            active_conns: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            idle_since: Mutex::new(Instant::now()),
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    fn connector(&self) -> Connector<'_> {
        &*self.deps.connector
    }
}

/// RAII connection counter (idle-exit input). Constructed in the ACCEPT
/// loop, not in the handler thread — otherwise a connection accepted just
/// before an idle-exit check could go uncounted and the daemon would exit
/// under a live client.
pub struct ConnGuard(Arc<Daemon>);

impl ConnGuard {
    fn new(d: Arc<Daemon>) -> Self {
        d.active_conns.fetch_add(1, Ordering::SeqCst);
        Self(d)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active_conns.fetch_sub(1, Ordering::SeqCst);
        *self.0.idle_since.lock().unwrap() = Instant::now();
    }
}

/// Serve one client connection: hello, then request/response frames until
/// EOF — or until an `OpenStream` converts the connection into a raw splice.
/// `_guard` is the accept-time connection count; dropped when we return.
pub fn handle_connection(d: &Arc<Daemon>, mut stream: UdsStream, _guard: ConnGuard) {
    let hello: DaemonHello = match read_frame(&mut stream) {
        Ok(h) => h,
        Err(_) => return,
    };
    let _ = hello; // the CLIENT decides about proto mismatches
    if write_frame(
        &mut stream,
        &DaemonResponse::HelloOk {
            version: d.deps.version.clone(),
            proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
            build: crate::build_info::BuildInfoOwned::current(),
        },
    )
    .is_err()
    {
        return;
    }
    // A second handle onto the same socket for in-flight Progress frames, so
    // the `progress` closure does not hold a long-lived `&mut stream` borrow
    // across `dispatch` (whose terminal response is written to `stream`).
    let mut progress_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    loop {
        let req: DaemonRequest = match read_frame(&mut stream) {
            Ok(r) => r,
            Err(_) => return, // client done (or died) — both are fine
        };
        match req {
            DaemonRequest::OpenStream { name } => {
                match open_guest_stream(d, &name) {
                    Ok(g) => {
                        if write_frame(&mut stream, &DaemonResponse::Ok).is_err() {
                            return;
                        }
                        splice(stream, g);
                    }
                    Err(e) => {
                        let _ = write_frame(
                            &mut stream,
                            &DaemonResponse::Error {
                                message: format!("{e:#}"),
                            },
                        );
                    }
                }
                return; // the connection is consumed either way
            }
            req => {
                let mut progress = |message: String| {
                    let _ =
                        write_frame(&mut progress_stream, &DaemonResponse::Progress { message });
                };
                let resp = dispatch(d, req, &mut progress);
                if write_frame(&mut stream, &resp).is_err() {
                    return;
                }
            }
        }
    }
}

/// Liveness-gate `name`, then dial its vsock stream port. The caller (the
/// client CLI) sends the guest `StreamOpen` frame itself once spliced.
fn open_guest_stream(d: &Daemon, name: &str) -> anyhow::Result<UdsStream> {
    drop(sandbox::control(&d.paths, name, d.connector())?);
    (d.deps.stream_connector)(&d.paths, name)
}

/// Bidirectional byte pump with shutdown(Write)+drain teardown on both legs
/// (the vsock half-close contract: full teardown once TX is done).
fn splice(a: UdsStream, b: UdsStream) {
    let (Ok(a_r), Ok(b_r)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let mut a_w = a;
    let mut b_w = b;
    let up = std::thread::spawn(move || {
        copy_until_eof(a_r, &mut b_w);
        let _ = b_w.shutdown(std::net::Shutdown::Write);
    });
    copy_until_eof(b_r, &mut a_w);
    let _ = a_w.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

pub fn dispatch(
    d: &Arc<Daemon>,
    req: DaemonRequest,
    progress: &mut dyn FnMut(String),
) -> DaemonResponse {
    let result = (|| -> anyhow::Result<DaemonResponse> {
        Ok(match req {
            DaemonRequest::Create(c) => {
                crate::volume::validate_volumes(&c.volumes)?;
                progress(format!(
                    "resolving {} (pulls if not cached)...",
                    c.image_ref
                ));
                let digest = (d.deps.resolve_image)(&d.paths, &c.image_ref)?;
                sandbox::create(
                    &d.paths,
                    &c.name,
                    &CreateOpts {
                        image_digest: digest,
                        image_ref: c.image_ref.clone(),
                        cpus: c.cpus,
                        mem_mb: c.mem_mb,
                        workspace: c.workspace.clone(),
                        rw_size_gb: c.rw_size_gb,
                        ports: c.ports.clone(),
                        volumes: c.volumes.clone(),
                    },
                )?;
                d.registry.set(&c.name, &c.image_ref, Liveness::Stopped);
                DaemonResponse::Created { name: c.name }
            }
            DaemonRequest::Start { name } => {
                progress(format!("starting '{name}'..."));
                // Load config FIRST (reused below for relay republish), then
                // bind the vsock_1027 egress listener BEFORE launch so the
                // guest can dial izbad during boot. Every sandbox owns one —
                // egress is unconditional now.
                let config: SandboxConfig =
                    load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
                        .with_context(|| format!("no config.json for '{name}'"))?;
                let art = (d.deps.artifacts)(&d.paths)?;
                d.egress.ensure_listening(&d.paths, &name)?;
                if let Err(e) = sandbox::start(&d.paths, &name, d.deps.driver.as_ref(), &art) {
                    // Boot never happened — tear the listener back down.
                    d.egress.stop(&d.paths, &name);
                    return Err(e);
                }
                // (Re-)apply the persisted publish rules afresh, as threads.
                d.relays.stop_all(&name);
                for rule in &config.ports {
                    if let Err(e) = d.relays.publish(&d.paths, &name, rule.clone()) {
                        progress(format!(
                            "warning: not publishing {}:{}: {e:#}",
                            rule.bind, rule.host_port
                        ));
                    }
                }
                relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
                d.registry.set(&name, &config.image_ref, Liveness::Running);
                DaemonResponse::Ok
            }
            // Stop/Rm tear relays down only AFTER the sandbox op succeeds —
            // a failed stop/rm (e.g. `rm` without force on a running
            // sandbox) must leave published ports running. During a graceful
            // stop the relay threads still accept; their vsock dials fail
            // once the VM dies, which relay_one handles (logged, conn
            // closed) — same ordering as the pre-daemon relay teardown.
            DaemonRequest::Stop { name } => {
                sandbox::stop(&d.paths, &name, d.connector(), STOP_TIMEOUT)?;
                d.relays.stop_all(&name);
                d.egress.stop(&d.paths, &name);
                let _ = std::fs::remove_file(relays::rules_path(&d.paths, &name));
                d.registry.set_liveness(&name, Liveness::Stopped);
                DaemonResponse::Ok
            }
            DaemonRequest::Rm { name, force } => {
                sandbox::remove(&d.paths, &name, d.connector(), force)?;
                d.relays.stop_all(&name);
                d.egress.stop(&d.paths, &name);
                d.registry.remove(&name);
                DaemonResponse::Ok
            }
            DaemonRequest::List => DaemonResponse::List {
                sandboxes: d.registry.summaries(),
            },
            DaemonRequest::Inspect { name } => {
                let config: SandboxConfig =
                    load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
                        .with_context(|| format!("no such sandbox '{name}'"))?;
                let status = d
                    .registry
                    .liveness(&name)
                    .unwrap_or(Liveness::Stopped)
                    .describe();
                DaemonResponse::Inspect(SandboxDetail {
                    name,
                    image_ref: config.image_ref,
                    image_digest: config.image_digest,
                    cpus: config.cpus,
                    mem_mb: config.mem_mb,
                    workspace: config.workspace.display().to_string(),
                    status,
                    ports: config.ports,
                })
            }
            DaemonRequest::GuestRpc { name, req } => {
                let mut conn = sandbox::control(&d.paths, &name, d.connector())?;
                write_frame(&mut conn, &req)?;
                let resp: Response = read_frame(&mut conn)?;
                DaemonResponse::Guest { payload: resp }
            }
            DaemonRequest::PortPublish { name, rule } => {
                // Same liveness gate as the old publish_port.
                drop(sandbox::control(&d.paths, &name, d.connector())?);
                d.relays.publish(&d.paths, &name, rule)?;
                relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
                DaemonResponse::Ok
            }
            DaemonRequest::PortUnpublish {
                name,
                bind,
                host_port,
            } => {
                sandbox_must_exist(&d.paths, &name)?;
                d.relays.unpublish(&name, bind, host_port)?;
                relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
                DaemonResponse::Ok
            }
            DaemonRequest::PortList { name } => {
                sandbox_must_exist(&d.paths, &name)?;
                DaemonResponse::Ports {
                    rules: d.relays.active(&name),
                }
            }
            DaemonRequest::Status => DaemonResponse::Status(DaemonStatus {
                version: d.deps.version.clone(),
                proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
                build: crate::build_info::BuildInfoOwned::current(),
                pid: std::process::id(),
                uptime_ms: d.started.elapsed().as_millis() as u64,
                socket: d.paths.daemon_socket().display().to_string(),
                sandboxes: d.registry.summaries(),
            }),
            DaemonRequest::VolumePrune => {
                let pruned = sandbox::prune_volumes(&d.paths)?;
                DaemonResponse::Pruned {
                    removed: pruned.removed,
                    reclaimed_bytes: pruned.reclaimed_bytes,
                }
            }
            DaemonRequest::ReloadPolicy { name } => {
                sandbox_must_exist(&d.paths, &name)?;
                d.egress.reload_policy(&d.paths, &name);
                DaemonResponse::Ok
            }
            DaemonRequest::Shutdown => {
                d.request_shutdown();
                DaemonResponse::Ok
            }
            DaemonRequest::OpenStream { .. } => {
                bail!("OpenStream is handled at the connection layer")
            }
        })
    })();
    result.unwrap_or_else(|e| DaemonResponse::Error {
        message: format!("{e:#}"),
    })
}

/// Pre-daemon port commands errored on unknown sandboxes; keep that contract.
fn sandbox_must_exist(paths: &Paths, name: &str) -> anyhow::Result<()> {
    if !paths.sandbox_dir(name).join(CONFIG_FILE).is_file() {
        anyhow::bail!("no such sandbox '{name}'");
    }
    Ok(())
}

/// Rebuild the world from disk: sweep debris dirs, migrate legacy relay
/// processes, re-create relay threads for running sandboxes, fill the
/// registry. Runs once, before the accept loop.
pub fn adopt(d: &Arc<Daemon>) {
    if let Ok(entries) = std::fs::read_dir(d.paths.sandboxes_dir()) {
        for e in entries.flatten() {
            if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains(".removing-") || !e.path().join(CONFIG_FILE).is_file() {
                eprintln!("izbad: sweeping debris dir '{name}'");
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let infos = match sandbox::list(&d.paths, d.connector()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("izbad: adoption: list failed: {e:#}");
            return;
        }
    };
    for info in &infos {
        match relays::load_rules_migrating(&d.paths, &info.name) {
            Ok((rules, legacy)) => {
                for pid in &legacy {
                    eprintln!(
                        "izbad: killing legacy relay process {} of '{}'",
                        pid.pid, info.name
                    );
                    let _ = procmgr::kill_pid(pid);
                }
                if info.liveness == Liveness::Stopped {
                    let _ = std::fs::remove_file(relays::rules_path(&d.paths, &info.name));
                } else {
                    for rule in &rules {
                        if let Err(e) = d.relays.publish(&d.paths, &info.name, rule.clone()) {
                            eprintln!(
                                "izbad: not re-publishing {}:{} for '{}': {e:#}",
                                rule.bind, rule.host_port, info.name
                            );
                        }
                    }
                    let _ = relays::save_rules(&d.paths, &info.name, &d.relays.active(&info.name));
                }
            }
            Err(e) => eprintln!("izbad: ports.json for '{}': {e:#}", info.name),
        }
        // Rebind the egress listener for every live sandbox; a bind failure
        // is logged but never aborts adoption of the rest.
        if info.liveness != Liveness::Stopped {
            if let Err(e) = d.egress.ensure_listening(&d.paths, &info.name) {
                eprintln!("izbad: egress listener for '{}': {e:#}", info.name);
            }
        }
    }
    d.registry.replace_all(infos);
}

/// One exit decision. Shutdown always wins; otherwise exit only when the
/// daemon has been idle (no client connections AND no running sandboxes)
/// for at least `idle_limit` (`None` = never idle-exit).
pub(crate) fn should_exit(d: &Daemon, idle_limit: Option<Duration>) -> bool {
    if d.shutdown_requested() {
        return true;
    }
    let Some(limit) = idle_limit else {
        return false;
    };
    if d.active_conns.load(Ordering::SeqCst) > 0 || d.registry.running_count() > 0 {
        *d.idle_since.lock().unwrap() = Instant::now();
        return false;
    }
    d.idle_since.lock().unwrap().elapsed() >= limit
}

pub(crate) fn idle_limit_from(env: &dyn Fn(&str) -> Option<String>) -> Option<Duration> {
    match env("IZBA_DAEMON_IDLE_SECS").and_then(|s| s.parse::<u64>().ok()) {
        Some(0) => None,
        Some(n) => Some(Duration::from_secs(n)),
        None => Some(Duration::from_secs(900)),
    }
}

/// The daemon main: flock, bind, adopt, supervise, accept until shutdown or
/// idle-exit. Blocking — `izba daemon run` calls this on its main thread.
pub fn run_daemon(paths: &Paths) -> anyhow::Result<()> {
    run_daemon_with(paths, DaemonDeps::production())
}

pub fn run_daemon_with(paths: &Paths, deps: DaemonDeps) -> anyhow::Result<()> {
    std::fs::create_dir_all(paths.daemon_dir())
        .with_context(|| format!("creating {}", paths.daemon_dir().display()))?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.daemon_lock())
        .with_context(|| format!("opening {}", paths.daemon_lock().display()))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => bail!("daemon already running"),
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(e).context("locking the daemon lock file")
        }
    }

    // The spec promises a fresh daemon.log per daemon instance; spawn_detached
    // appends, so truncate now that the flock proves we are the only daemon.
    // (When auto-started detached, our own stderr IS this file in append mode:
    // truncating sets length 0 and appends continue at the new end — correct.)
    let _ = std::fs::File::create(paths.daemon_log());

    let listener = transport::bind_socket(paths)?;
    listener
        .set_nonblocking(true)
        .context("listener nonblocking")?;
    let d = Arc::new(Daemon::new(paths.clone(), deps));
    eprintln!(
        "izbad {} listening on {}",
        d.deps.version,
        paths.daemon_socket().display()
    );
    adopt(&d);

    // Supervisor tick (observe + relay respawn). Dies with the process.
    {
        let d = Arc::clone(&d);
        std::thread::spawn(move || loop {
            if d.shutdown_requested() {
                return;
            }
            supervisor::tick(&d.paths, &d.registry, &d.relays, &d.egress, d.connector());
            std::thread::sleep(supervisor::tick_interval());
        });
    }

    let idle_limit = idle_limit_from(&|k| std::env::var(k).ok());
    loop {
        if should_exit(&d, idle_limit) {
            break;
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                // Count the connection NOW (see ConnGuard) so the next
                // should_exit() already observes it.
                let guard = ConnGuard::new(Arc::clone(&d));
                let d = Arc::clone(&d);
                std::thread::spawn(move || handle_connection(&d, stream, guard));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("izbad: accept error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    d.request_shutdown(); // stops the supervisor thread for library embedders
    let _ = std::fs::remove_file(paths.daemon_socket());
    let _ = lock.unlock();
    eprintln!("izbad: exiting");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::*;
    use crate::sandbox::CreateOpts;
    use crate::state::{load_json, RunState, SandboxConfig, CONFIG_FILE, STATE_FILE};
    use crate::testutil::{
        fake_connector, live_identity, spawn_sleep, test_paths, wait_dead, write_state, MockDriver,
    };
    use crate::vmm::UdsStream;
    use izba_proto::{read_frame, write_frame, Request, Response};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// Deps wired to fakes: mock driver, socketpair guest, static digest.
    fn test_deps() -> DaemonDeps {
        let log = Arc::new(Mutex::new(Vec::new()));
        DaemonDeps {
            version: "testv".into(),
            driver: Box::new(MockDriver::new()),
            connector: Box::new(fake_connector(log, None)),
            stream_connector: Box::new(|_paths, _name| {
                // Fake guest stream port: echo everything back, then close.
                let (host, guest) = UdsStream::pair()?;
                std::thread::spawn(move || {
                    let mut g = guest;
                    let mut buf = [0u8; 4096];
                    loop {
                        match g.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if g.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                Ok(host)
            }),
            artifacts: Box::new(|_| {
                Ok(crate::sandbox::Artifacts {
                    kernel: "/art/vmlinux".into(),
                    initramfs: "/art/initramfs.img".into(),
                })
            }),
            resolve_image: Box::new(|_, _| Ok("sha256:abc".into())),
            egress_policy: std::sync::Arc::new(crate::daemon::egress::policy::AllowAll),
            egress_resolver: std::sync::Arc::new(crate::daemon::egress::dns::UdpForwarder::new(
                "127.0.0.1:53".parse().unwrap(),
            )),
        }
    }

    /// The vsock-churn guard at the splice level: a client that dies abruptly
    /// mid-stream must not make the daemon drop the guest (vsock) leg while
    /// the guest still has buffered TX — the guest leg is drained to EOF
    /// instead. The guest writer completing without error is the proof.
    #[test]
    fn splice_drains_guest_leg_when_client_dies() {
        let (client_daemon_end, client_peer) = UdsStream::pair().unwrap();
        let (guest_daemon_end, guest_peer) = UdsStream::pair().unwrap();
        drop(client_peer); // client vanished before reading anything

        const TOTAL: usize = 8 * 1024 * 1024;
        let guest = std::thread::spawn(move || -> std::io::Result<()> {
            let mut g = guest_peer;
            let chunk = [b'g'; 64 * 1024];
            let mut sent = 0;
            while sent < TOTAL {
                let n = (TOTAL - sent).min(chunk.len());
                g.write_all(&chunk[..n])?;
                sent += n;
            }
            g.shutdown(std::net::Shutdown::Write)?;
            // Drain the host's half-close like izba-init does.
            let mut buf = [0u8; 4096];
            while !matches!(g.read(&mut buf), Ok(0) | Err(_)) {}
            Ok(())
        });

        splice(client_daemon_end, guest_daemon_end);
        guest
            .join()
            .unwrap()
            .expect("guest writer must complete: splice must drain the vsock leg, not drop it");
    }

    fn test_daemon() -> (tempfile::TempDir, Arc<Daemon>) {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        (dir, Arc::new(Daemon::new(paths, test_deps())))
    }

    /// Connect a fake client: spawns handle_connection on the pair peer and
    /// performs the hello. Returns the client end.
    fn client_conn(d: &Arc<Daemon>) -> UdsStream {
        let (client, server) = UdsStream::pair().unwrap();
        let d2 = Arc::clone(d);
        let guard = ConnGuard::new(Arc::clone(d)); // as the accept loop would
        std::thread::spawn(move || handle_connection(&d2, server, guard));
        let mut c = client;
        write_frame(
            &mut c,
            &DaemonHello {
                version: "whatever".into(),
                proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
            },
        )
        .unwrap();
        let resp: DaemonResponse = read_frame(&mut c).unwrap();
        match resp {
            DaemonResponse::HelloOk { version, proto, .. } => {
                assert_eq!(version, "testv");
                assert_eq!(proto, crate::daemon::proto::DAEMON_PROTO_VERSION);
            }
            other => panic!("expected HelloOk, got {other:?}"),
        }
        c
    }

    fn rpc(c: &mut UdsStream, req: &DaemonRequest) -> DaemonResponse {
        write_frame(c, req).unwrap();
        loop {
            match read_frame::<_, DaemonResponse>(c).unwrap() {
                DaemonResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    }

    fn create_req(dir: &tempfile::TempDir, name: &str) -> DaemonRequest {
        DaemonRequest::Create(DaemonCreate {
            name: name.into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: dir.path().join("ws"),
            rw_size_gb: 1,
            ports: Vec::new(),
            volumes: Vec::new(),
        })
    }

    #[test]
    fn hello_reports_server_version() {
        let (_dir, d) = test_daemon();
        let _c = client_conn(&d); // assertions inside
    }

    #[test]
    fn create_then_list_and_inspect() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(&mut c, &create_req(&dir, "web")) {
            DaemonResponse::Created { name } => assert_eq!(name, "web"),
            other => panic!("create: {other:?}"),
        }
        // Disk artifacts exist (same as daemonless create).
        let config: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(config.image_digest, "sha256:abc");

        match rpc(&mut c, &DaemonRequest::List) {
            DaemonResponse::List { sandboxes } => {
                assert_eq!(sandboxes.len(), 1);
                assert_eq!(sandboxes[0].name, "web");
                assert_eq!(sandboxes[0].status, "stopped");
            }
            other => panic!("list: {other:?}"),
        }

        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.image_digest, "sha256:abc");
                assert_eq!(det.cpus, 1);
                assert_eq!(det.status, "stopped");
            }
            other => panic!("inspect: {other:?}"),
        }

        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "ghost".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("no such sandbox"), "{message}")
            }
            other => panic!("inspect ghost: {other:?}"),
        }
    }

    /// DEVIATION from the planned test: the plan had `test_daemon()` +
    /// `fake_connector(log, None)` here, but `MockDriver` records THIS test
    /// process (`live_identity()`) as the vmm pid in state.json, and a
    /// connector that never reacts to Shutdown would make `sandbox::stop`
    /// wait the full 10 s STOP_TIMEOUT and then SIGKILL the test runner
    /// itself. Instead: a disposable `sleep` child stands in for the vmm
    /// (state.json swapped after start), and the connector kills it on
    /// Shutdown — same graceful-stop shape as sandbox.rs's `stop_graceful`.
    #[test]
    fn start_then_stop_via_mock_driver() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let vmm = spawn_sleep(dir.path());
        let mut deps = test_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        match rpc(&mut c, &DaemonRequest::Start { name: "web".into() }) {
            DaemonResponse::Ok => {}
            // Start now binds the vsock_1027 egress listener unconditionally;
            // runtime-skip where the sandbox denies bind (house pattern).
            DaemonResponse::Error { message }
                if message.contains("denied")
                    || message.contains("Permission")
                    || message.contains("not permitted") =>
            {
                eprintln!("SKIP start_then_stop_via_mock_driver: bind denied: {message}");
                return;
            }
            other => panic!("start: {other:?}"),
        }
        let state: Option<RunState> =
            load_json(&d.paths.sandbox_dir("web").join(STATE_FILE)).unwrap();
        assert!(state.is_some(), "state.json written by start");
        assert_eq!(
            d.registry.liveness("web"),
            Some(crate::liveness::Liveness::Running)
        );

        // Swap the MockDriver-recorded vmm identity (this very test process)
        // for the disposable child, so stop can never escalate onto us.
        write_state(&d.paths, "web", vmm.clone());

        match rpc(&mut c, &DaemonRequest::Stop { name: "web".into() }) {
            DaemonResponse::Ok => {}
            other => panic!("stop: {other:?}"),
        }
        assert_eq!(
            d.registry.liveness("web"),
            Some(crate::liveness::Liveness::Stopped)
        );
        assert!(wait_dead(&vmm), "vmm stand-in must be dead after stop");
    }

    /// Every Start binds the vsock_1027 listener; Stop removes it.
    /// Runtime-skips where the sandbox denies bind.
    #[test]
    fn start_binds_egress_listener_stop_removes_it() {
        use crate::daemon::egress;
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let vmm = spawn_sleep(dir.path());
        let mut deps = test_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        let req = create_req(&dir, "web");
        assert!(matches!(rpc(&mut c, &req), DaemonResponse::Created { .. }));
        match rpc(&mut c, &DaemonRequest::Start { name: "web".into() }) {
            DaemonResponse::Ok => {}
            // Bind EPERM wears several wordings across sandboxes ("Permission
            // denied", "Operation not permitted") — runtime-skip on any.
            DaemonResponse::Error { message }
                if message.contains("denied")
                    || message.contains("Permission")
                    || message.contains("not permitted") =>
            {
                eprintln!("SKIP start_binds_egress_listener: bind denied: {message}");
                return;
            }
            other => panic!("start: {other:?}"),
        }
        assert!(d.egress.listening("web"));
        assert!(egress::listener_path(&d.paths, "web").exists());

        write_state(&d.paths, "web", vmm.clone());
        assert!(matches!(
            rpc(&mut c, &DaemonRequest::Stop { name: "web".into() }),
            DaemonResponse::Ok
        ));
        assert!(!d.egress.listening("web"));
        assert!(!egress::listener_path(&d.paths, "web").exists());
    }

    #[test]
    fn rm_without_force_keeps_relays() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        write_state(&d.paths, "web", live_identity()); // it looks running
                                                       // Publish a relay thread (skip if this sandbox denies binds).
        let l = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: bind denied");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = l.local_addr().unwrap().port();
        drop(l);
        let rule = crate::state::PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: port,
            guest_port: 80,
        };
        match rpc(
            &mut c,
            &DaemonRequest::PortPublish {
                name: "web".into(),
                rule: rule.clone(),
            },
        ) {
            DaemonResponse::Ok => {}
            other => panic!("publish: {other:?}"),
        }
        // rm WITHOUT force on a running sandbox must fail AND leave relays alone.
        match rpc(
            &mut c,
            &DaemonRequest::Rm {
                name: "web".into(),
                force: false,
            },
        ) {
            DaemonResponse::Error { message } => assert!(message.contains("running"), "{message}"),
            other => panic!("rm: {other:?}"),
        }
        assert_eq!(
            d.relays.active("web"),
            vec![rule],
            "relays must survive a failed rm"
        );
    }

    #[test]
    fn port_commands_on_unknown_sandbox_error() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::PortList {
                name: "ghost".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("no such sandbox"), "{message}")
            }
            other => panic!("port ls ghost: {other:?}"),
        }
        match rpc(
            &mut c,
            &DaemonRequest::PortUnpublish {
                name: "ghost".into(),
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("no such sandbox"), "{message}")
            }
            other => panic!("port unpublish ghost: {other:?}"),
        }
    }

    #[test]
    fn guest_rpc_proxies_health() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        write_state(&d.paths, "web", live_identity()); // running per pid probe
        match rpc(
            &mut c,
            &DaemonRequest::GuestRpc {
                name: "web".into(),
                req: Request::Health,
            },
        ) {
            DaemonResponse::Guest {
                payload: Response::Health(h),
            } => assert_eq!(h.version, "test"),
            other => panic!("guest rpc: {other:?}"),
        }
    }

    #[test]
    fn guest_rpc_on_stopped_sandbox_errors() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        match rpc(
            &mut c,
            &DaemonRequest::GuestRpc {
                name: "web".into(),
                req: Request::Health,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("not running"), "{message}")
            }
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn open_stream_splices_bytes() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        write_state(&d.paths, "web", live_identity());

        write_frame(&mut c, &DaemonRequest::OpenStream { name: "web".into() }).unwrap();
        match read_frame::<_, DaemonResponse>(&mut c).unwrap() {
            DaemonResponse::Ok => {}
            other => panic!("open stream: {other:?}"),
        }
        // Past this point the conn is raw bytes spliced to the echo guest.
        c.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn status_and_shutdown() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::Status) {
            DaemonResponse::Status(s) => {
                assert_eq!(s.version, "testv");
                assert_eq!(s.pid, std::process::id());
            }
            other => panic!("status: {other:?}"),
        }
        assert!(matches!(
            rpc(&mut c, &DaemonRequest::Shutdown),
            DaemonResponse::Ok
        ));
        assert!(d.shutdown_requested());
    }

    #[test]
    fn idle_exit_policy() {
        let (_dir, d) = test_daemon();
        // No limit -> never exits on idleness.
        assert!(!should_exit(&d, None));
        // Zero-duration limit + nothing running + no conns -> exit.
        assert!(should_exit(&d, Some(std::time::Duration::ZERO)));
        // A running sandbox blocks idle-exit.
        d.registry
            .set("web", "x", crate::liveness::Liveness::Running);
        assert!(!should_exit(&d, Some(std::time::Duration::ZERO)));
        d.registry
            .set_liveness("web", crate::liveness::Liveness::Stopped);
        // An active connection blocks idle-exit.
        let _c = client_conn(&d);
        std::thread::sleep(std::time::Duration::from_millis(50)); // let the conn register
        assert!(!should_exit(&d, Some(std::time::Duration::ZERO)));
        // Shutdown request always wins.
        d.request_shutdown();
        assert!(should_exit(&d, None));
    }

    #[test]
    fn idle_limit_env_parsing() {
        let none = |_: &str| None;
        assert_eq!(
            idle_limit_from(&none),
            Some(std::time::Duration::from_secs(900))
        );
        let zero = |k: &str| (k == "IZBA_DAEMON_IDLE_SECS").then(|| "0".to_string());
        assert_eq!(idle_limit_from(&zero), None);
        let five = |k: &str| (k == "IZBA_DAEMON_IDLE_SECS").then(|| "5".to_string());
        assert_eq!(
            idle_limit_from(&five),
            Some(std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn adopt_rebuilds_view_and_sweeps_debris() {
        let (dir, d) = test_daemon();
        // A legit stopped sandbox.
        crate::sandbox::create(
            &d.paths,
            "web",
            &CreateOpts {
                image_digest: "sha256:abc".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
            },
        )
        .unwrap();
        // Debris: a half-created dir (no config.json) and a tombstone.
        std::fs::create_dir_all(d.paths.sandbox_dir("half")).unwrap();
        std::fs::create_dir_all(d.paths.sandboxes_dir().join("dead.removing-123")).unwrap();

        adopt(&d);

        assert_eq!(
            d.registry.liveness("web"),
            Some(crate::liveness::Liveness::Stopped)
        );
        assert!(
            !d.paths.sandbox_dir("half").exists(),
            "half-created dir swept"
        );
        assert!(
            !d.paths.sandboxes_dir().join("dead.removing-123").exists(),
            "tombstone swept"
        );
    }
}
