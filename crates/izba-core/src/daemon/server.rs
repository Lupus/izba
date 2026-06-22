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
            egress_resolver: crate::daemon::egress::sys_resolver::SystemResolver::new()
                .expect("build system DNS resolver"),
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
        let egress = EgressManager::new(Arc::clone(&deps.egress_resolver), mitm, audit);
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
    if read_frame::<_, DaemonHello>(&mut stream).is_err() {
        return; // hello never arrived — the CLIENT decides about proto mismatches
    }
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
    // A single Progress handle reused across requests (matches the pre-refactor
    // single-clone-outside-the-loop behavior).
    let Ok(mut progress_stream) = stream.try_clone() else {
        return;
    };
    loop {
        let req: DaemonRequest = match read_frame(&mut stream) {
            Ok(r) => r,
            Err(_) => return, // client done (or died) — both are fine
        };
        // `serve_request` consumes `stream` only when the request converts the
        // connection into a raw splice (or the socket dies); otherwise it
        // hands the stream back so the loop can read the next request.
        match serve_request(d, req, stream, &mut progress_stream) {
            Some(s) => stream = s,
            None => return,
        }
    }
}

/// Handle one request frame on an established connection. Returns the stream
/// to keep serving on, or `None` once the connection is finished (a write
/// failed, or an `OpenStream` spliced/consumed it).
fn serve_request(
    d: &Arc<Daemon>,
    req: DaemonRequest,
    mut stream: UdsStream,
    progress_stream: &mut UdsStream,
) -> Option<UdsStream> {
    if let DaemonRequest::OpenStream { name } = req {
        serve_open_stream(d, &name, stream);
        return None; // the connection is consumed either way
    }
    let mut progress = |message: String| {
        let _ = write_frame(progress_stream, &DaemonResponse::Progress { message });
    };
    let resp = dispatch(d, req, &mut progress);
    write_frame(&mut stream, &resp).ok().map(|()| stream)
}

/// Reply to an `OpenStream`, then splice the connection to the guest stream
/// port. Consumes `stream`.
fn serve_open_stream(d: &Arc<Daemon>, name: &str, mut stream: UdsStream) {
    match open_guest_stream(d, name) {
        Ok(g) => {
            if write_frame(&mut stream, &DaemonResponse::Ok).is_ok() {
                splice(stream, g);
            }
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
    dispatch_inner(d, req, progress).unwrap_or_else(|e| DaemonResponse::Error {
        message: format!("{e:#}"),
    })
}

/// The fallible body of [`dispatch`]: route each request variant to its
/// handler. The arms stay one-line so the routing itself carries no nesting;
/// the per-variant work lives in the `handle_*` helpers below.
fn dispatch_inner(
    d: &Arc<Daemon>,
    req: DaemonRequest,
    progress: &mut dyn FnMut(String),
) -> anyhow::Result<DaemonResponse> {
    match req {
        DaemonRequest::Create(c) => handle_create(d, c, progress),
        DaemonRequest::Start {
            name,
            allow_unconfined,
        } => handle_start(d, name, allow_unconfined, progress),
        DaemonRequest::Stop { name } => handle_stop(d, name),
        DaemonRequest::Rm { name, force } => handle_rm(d, name, force),
        DaemonRequest::List => Ok(DaemonResponse::List {
            sandboxes: d.registry.summaries(),
        }),
        DaemonRequest::Inspect { name } => handle_inspect(d, name),
        DaemonRequest::GuestRpc { name, req } => handle_guest_rpc(d, name, req),
        DaemonRequest::PortPublish {
            name,
            rule,
            persist,
        } => handle_port_publish(d, name, rule, persist),
        DaemonRequest::PortUnpublish {
            name,
            bind,
            host_port,
        } => handle_port_unpublish(d, name, bind, host_port),
        DaemonRequest::PortList { name } => {
            sandbox_must_exist(&d.paths, &name)?;
            Ok(DaemonResponse::Ports {
                rules: d.relays.active(&name),
            })
        }
        DaemonRequest::Status => Ok(DaemonResponse::Status(DaemonStatus {
            version: d.deps.version.clone(),
            proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
            build: crate::build_info::BuildInfoOwned::current(),
            pid: std::process::id(),
            uptime_ms: d.started.elapsed().as_millis() as u64,
            socket: d.paths.daemon_socket().display().to_string(),
            sandboxes: d.registry.summaries(),
        })),
        DaemonRequest::VolumePrune => {
            let pruned = sandbox::prune_volumes(&d.paths)?;
            Ok(DaemonResponse::Pruned {
                removed: pruned.removed,
                reclaimed_bytes: pruned.reclaimed_bytes,
            })
        }
        DaemonRequest::ReloadPolicy { name } => {
            sandbox_must_exist(&d.paths, &name)?;
            d.egress.reload_policy(&d.paths, &name);
            Ok(DaemonResponse::Ok)
        }
        DaemonRequest::Shutdown => {
            d.request_shutdown();
            Ok(DaemonResponse::Ok)
        }
        DaemonRequest::OpenStream { .. } => {
            bail!("OpenStream is handled at the connection layer")
        }
        DaemonRequest::VolumeList => handle_volume_list(d),
        DaemonRequest::VolumeRemove { name } => handle_volume_remove(d, name),
        DaemonRequest::VolumeAttach { name, spec } => handle_volume_attach(d, name, spec),
        DaemonRequest::VolumeDetach { name, guest_path } => {
            handle_volume_detach(d, name, guest_path)
        }
    }
}

/// Best-effort: regenerate the izba-managed ~/.ssh/config from the set of
/// non-stopped sandboxes. A failure (perms, read-only HOME) is logged and
/// never fails the lifecycle — same posture as relays/egress.
fn regen_ssh_config(d: &Arc<Daemon>) {
    let names = d.registry.running_names();
    if let Err(e) = crate::ssh::config::regenerate(&d.paths, &names) {
        eprintln!("izbad: ssh config regen failed (non-fatal): {e:#}");
    }
}

fn handle_create(
    d: &Arc<Daemon>,
    c: crate::daemon::proto::DaemonCreate,
    progress: &mut dyn FnMut(String),
) -> anyhow::Result<DaemonResponse> {
    crate::volume::validate_volumes(&c.volumes)?;
    // Preflight (confined intent only): reject a workspace that cannot be
    // Low-integrity-relabelled for the confined VMM (e.g. a folder at a drive
    // root) BEFORE anything is written to disk, with an actionable message —
    // never leave the user a created-but-unstartable sandbox. Skipped under
    // --allow-unconfined, where the VMM never relabels the workspace. No-op off
    // Windows. Fails fast, before the (possibly slow) image pull.
    if !c.allow_unconfined {
        crate::procmgr::ensure_confinable(&c.workspace)?;
    }
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
    Ok(DaemonResponse::Created { name: c.name })
}

fn handle_start(
    d: &Arc<Daemon>,
    name: String,
    allow_unconfined: bool,
    progress: &mut dyn FnMut(String),
) -> anyhow::Result<DaemonResponse> {
    progress(format!("starting '{name}'..."));
    // Load config FIRST (reused below for relay republish), then
    // bind the vsock_1027 egress listener BEFORE launch so the
    // guest can dial izbad during boot. Every sandbox owns one —
    // egress is unconditional now.
    let config: SandboxConfig = load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
        .with_context(|| format!("no config.json for '{name}'"))?;
    let art = (d.deps.artifacts)(&d.paths)?;
    d.egress.ensure_listening(&d.paths, &name)?;
    if let Err(e) = sandbox::start(
        &d.paths,
        &name,
        d.deps.driver.as_ref(),
        &art,
        allow_unconfined,
    ) {
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
    regen_ssh_config(d);
    Ok(DaemonResponse::Ok)
}

// Stop/Rm tear relays down only AFTER the sandbox op succeeds —
// a failed stop/rm (e.g. `rm` without force on a running
// sandbox) must leave published ports running. During a graceful
// stop the relay threads still accept; their vsock dials fail
// once the VM dies, which relay_one handles (logged, conn
// closed) — same ordering as the pre-daemon relay teardown.
fn handle_stop(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    sandbox::stop(&d.paths, &name, d.connector(), STOP_TIMEOUT)?;
    d.relays.stop_all(&name);
    d.egress.stop(&d.paths, &name);
    let _ = std::fs::remove_file(relays::rules_path(&d.paths, &name));
    d.registry.set_liveness(&name, Liveness::Stopped);
    regen_ssh_config(d);
    Ok(DaemonResponse::Ok)
}

fn handle_rm(d: &Arc<Daemon>, name: String, force: bool) -> anyhow::Result<DaemonResponse> {
    sandbox::remove(&d.paths, &name, d.connector(), force)?;
    d.relays.stop_all(&name);
    d.egress.stop(&d.paths, &name);
    d.registry.remove(&name);
    regen_ssh_config(d);
    Ok(DaemonResponse::Ok)
}

fn handle_inspect(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    let config: SandboxConfig = load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
        .with_context(|| format!("no such sandbox '{name}'"))?;
    let status = d
        .registry
        .liveness(&name)
        .unwrap_or(Liveness::Stopped)
        .describe();
    // Host-side VMM confinement is recorded in state.json at launch.
    // None (stopped / pre-confinement state) ⇒ CLI shows "unknown".
    let confinement = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?
    .and_then(|s| s.confinement)
    .map(|c| c.summary());
    Ok(DaemonResponse::Inspect(SandboxDetail {
        name,
        image_ref: config.image_ref,
        image_digest: config.image_digest,
        cpus: config.cpus,
        mem_mb: config.mem_mb,
        workspace: config.workspace.display().to_string(),
        status,
        ports: config.ports,
        volumes: config.volumes,
        confinement,
    }))
}

fn handle_guest_rpc(
    d: &Arc<Daemon>,
    name: String,
    req: izba_proto::Request,
) -> anyhow::Result<DaemonResponse> {
    let mut conn = sandbox::control(&d.paths, &name, d.connector())?;
    write_frame(&mut conn, &req)?;
    let resp: Response = read_frame(&mut conn)?;
    Ok(DaemonResponse::Guest { payload: resp })
}

fn handle_port_publish(
    d: &Arc<Daemon>,
    name: String,
    rule: crate::state::PortRule,
    persist: bool,
) -> anyhow::Result<DaemonResponse> {
    // Same liveness gate as the old publish_port.
    drop(sandbox::control(&d.paths, &name, d.connector())?);
    // Idempotent: re-publishing an identical active rule is a no-op for the
    // relay (this is what the app's "Make persistent" button does).
    if !d.relays.active(&name).contains(&rule) {
        d.relays.publish(&d.paths, &name, rule.clone())?;
    }
    relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
    if persist {
        persist_port_rule(&d.paths, &name, &rule)?;
    }
    Ok(DaemonResponse::Ok)
}

fn handle_port_unpublish(
    d: &Arc<Daemon>,
    name: String,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> anyhow::Result<DaemonResponse> {
    sandbox_must_exist(&d.paths, &name)?;
    // Always drop the persisted rule from config — works even when the sandbox
    // is stopped (the relay map has no entry), so a persisted-only port can be
    // removed. (Greptile P1.)
    let unpersisted = unpersist_port_rule(&d.paths, &name, bind, host_port)?;
    // Tear down a live relay if one exists; a missing relay (stopped sandbox /
    // post-restart) is NOT an error.
    let relay_removed = d.relays.unpublish(&name, bind, host_port).is_ok();
    if relay_removed {
        relays::save_rules(&d.paths, &name, &d.relays.active(&name))?;
    }
    if !unpersisted && !relay_removed {
        bail!("no such published port: {bind}:{host_port}");
    }
    Ok(DaemonResponse::Ok)
}

fn persist_port_rule(
    paths: &Paths,
    name: &str,
    rule: &crate::state::PortRule,
) -> anyhow::Result<()> {
    let p = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig =
        load_json(&p)?.with_context(|| format!("no config for '{name}'"))?;
    if !cfg
        .ports
        .iter()
        .any(|r| r.bind == rule.bind && r.host_port == rule.host_port)
    {
        cfg.ports.push(rule.clone());
        crate::state::save_json(&p, &cfg)?;
    }
    Ok(())
}

fn unpersist_port_rule(
    paths: &Paths,
    name: &str,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> anyhow::Result<bool> {
    let p = paths.sandbox_dir(name).join(CONFIG_FILE);
    let mut cfg: SandboxConfig =
        load_json(&p)?.with_context(|| format!("no config for '{name}'"))?;
    let before = cfg.ports.len();
    cfg.ports
        .retain(|r| !(r.bind == bind && r.host_port == host_port));
    let removed = cfg.ports.len() != before;
    if removed {
        crate::state::save_json(&p, &cfg)?;
    }
    Ok(removed)
}

fn handle_volume_list(d: &Arc<Daemon>) -> anyhow::Result<DaemonResponse> {
    let volumes = sandbox::list_volumes(&d.paths)?;
    Ok(DaemonResponse::Volumes { volumes })
}

fn handle_volume_remove(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    let bytes = sandbox::remove_volume(&d.paths, &name)?;
    Ok(DaemonResponse::Pruned {
        removed: vec![name],
        reclaimed_bytes: bytes,
    })
}

fn handle_volume_attach(
    d: &Arc<Daemon>,
    name: String,
    spec: crate::volume::VolumeSpec,
) -> anyhow::Result<DaemonResponse> {
    sandbox::attach_volume(&d.paths, &name, spec)?;
    Ok(DaemonResponse::Ok)
}

fn handle_volume_detach(
    d: &Arc<Daemon>,
    name: String,
    guest_path: std::path::PathBuf,
) -> anyhow::Result<DaemonResponse> {
    sandbox::detach_volume(&d.paths, &name, &guest_path)?;
    Ok(DaemonResponse::Ok)
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
    crate::paths::create_dir_700(&paths.daemon_dir(), paths.root())?;
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
            allow_unconfined: false,
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
                // No state.json (never started) ⇒ confinement unknown.
                assert_eq!(det.confinement, None);
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
        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: false,
            },
        ) {
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
        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: false,
            },
        ) {
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
                persist: false,
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

    // ── B2: volume dispatch + port persist/unpersist ──────────────────────

    /// Helper: create a sandbox via RPC, return the client connection.
    fn setup_sandbox_with_client(
        dir: &tempfile::TempDir,
        d: &Arc<Daemon>,
        name: &str,
    ) -> UdsStream {
        let mut c = client_conn(d);
        match rpc(&mut c, &create_req(dir, name)) {
            DaemonResponse::Created { .. } => {}
            other => panic!("create: {other:?}"),
        }
        c
    }

    #[test]
    fn volume_list_returns_volumes_listing() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        // Create a sandbox with a persistent volume so the volume image exists.
        let volumes = vec![crate::volume::VolumeSpec {
            name: Some("cache".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        }];
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
                volumes,
            },
        )
        .unwrap();
        match rpc(&mut c, &DaemonRequest::VolumeList) {
            DaemonResponse::Volumes { volumes } => {
                assert!(
                    volumes.iter().any(|v| v.name == "cache"),
                    "expected 'cache' in volume list, got: {volumes:?}"
                );
            }
            other => panic!("volume list: {other:?}"),
        }
    }

    #[test]
    fn volume_attach_shows_in_inspect_detach_removes_it() {
        let (dir, d) = test_daemon();
        let mut c = setup_sandbox_with_client(&dir, &d, "web");

        let spec = crate::volume::VolumeSpec {
            name: Some("cache".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 20,
            eph_id: None,
        };
        // Attach.
        match rpc(
            &mut c,
            &DaemonRequest::VolumeAttach {
                name: "web".into(),
                spec: spec.clone(),
            },
        ) {
            DaemonResponse::Ok => {}
            other => panic!("volume attach: {other:?}"),
        }
        // Inspect should show the attached volume.
        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert!(
                    det.volumes.iter().any(|v| v.guest_path == spec.guest_path),
                    "volume not in inspect after attach: {:?}",
                    det.volumes
                );
            }
            other => panic!("inspect after attach: {other:?}"),
        }
        // Detach.
        match rpc(
            &mut c,
            &DaemonRequest::VolumeDetach {
                name: "web".into(),
                guest_path: "/data".into(),
            },
        ) {
            DaemonResponse::Ok => {}
            other => panic!("volume detach: {other:?}"),
        }
        // Inspect must no longer list the volume.
        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert!(
                    det.volumes.iter().all(|v| v.guest_path != spec.guest_path),
                    "volume still present after detach: {:?}",
                    det.volumes
                );
            }
            other => panic!("inspect after detach: {other:?}"),
        }
    }

    #[test]
    fn volume_remove_referenced_returns_error() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        // Create a sandbox that references the "shared" persistent volume.
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
                volumes: vec![crate::volume::VolumeSpec {
                    name: Some("shared".into()),
                    guest_path: "/share".into(),
                    size_bytes: 1 << 20,
                    eph_id: None,
                }],
            },
        )
        .unwrap();
        // Remove should fail because "web" references it.
        match rpc(
            &mut c,
            &DaemonRequest::VolumeRemove {
                name: "shared".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("in use") || message.contains("referenced"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected Error for referenced volume remove, got: {other:?}"),
        }
    }

    #[test]
    fn port_publish_persist_writes_to_config() {
        let (dir, d) = test_daemon();
        let mut c = setup_sandbox_with_client(&dir, &d, "web");
        // Make the sandbox look running so PortPublish's liveness gate passes.
        write_state(&d.paths, "web", live_identity());

        // Pick a port we can try to bind (skip if denied by sandbox).
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0));
        let (port, _l) = match probe {
            Ok(l) => {
                let port = l.local_addr().unwrap().port();
                // Drop listener so the relay can bind.
                drop(l);
                (port, ())
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP port_publish_persist_writes_to_config: bind denied");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };

        let rule = crate::state::PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: port,
            guest_port: 8080,
        };
        match rpc(
            &mut c,
            &DaemonRequest::PortPublish {
                name: "web".into(),
                rule: rule.clone(),
                persist: true,
            },
        ) {
            DaemonResponse::Ok => {}
            other => panic!("port publish: {other:?}"),
        }
        // The rule must be persisted in config.json.
        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .expect("config.json must exist");
        assert!(
            cfg.ports
                .iter()
                .any(|r| r.bind == rule.bind && r.host_port == rule.host_port),
            "persisted rule not found in config.ports: {:?}",
            cfg.ports
        );
    }

    #[test]
    fn port_unpublish_drops_from_config() {
        let (dir, d) = test_daemon();
        let mut c = setup_sandbox_with_client(&dir, &d, "web");
        write_state(&d.paths, "web", live_identity());

        let probe = std::net::TcpListener::bind(("127.0.0.1", 0));
        let port = match probe {
            Ok(l) => {
                let port = l.local_addr().unwrap().port();
                drop(l);
                port
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP port_unpublish_drops_from_config: bind denied");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };

        let rule = crate::state::PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: port,
            guest_port: 8080,
        };
        // Publish with persist=true first.
        assert!(matches!(
            rpc(
                &mut c,
                &DaemonRequest::PortPublish {
                    name: "web".into(),
                    rule: rule.clone(),
                    persist: true,
                }
            ),
            DaemonResponse::Ok
        ));
        // Verify it's in config.
        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .expect("config.json must exist");
        assert!(cfg.ports.iter().any(|r| r.host_port == rule.host_port));

        // Now unpublish.
        assert!(matches!(
            rpc(
                &mut c,
                &DaemonRequest::PortUnpublish {
                    name: "web".into(),
                    bind: rule.bind,
                    host_port: rule.host_port,
                }
            ),
            DaemonResponse::Ok
        ));
        // Must be removed from config.
        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .expect("config.json must exist");
        assert!(
            !cfg.ports.iter().any(|r| r.host_port == rule.host_port),
            "rule still present in config.ports after unpublish: {:?}",
            cfg.ports
        );
    }

    // ── Direct unit tests for persist_port_rule / unpersist_port_rule ────────
    //
    // These tests call the helpers DIRECTLY — no daemon, no socket bind — so
    // they work even in sandboxed environments that deny TcpListener::bind.

    /// Write a minimal config.json for a named sandbox into `paths`.
    fn write_config_for_persist(paths: &Paths, name: &str) {
        let dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: dir.join("ws"),
            ports: Vec::new(),
            volumes: Vec::new(),
        };
        crate::state::save_json(&dir.join(CONFIG_FILE), &cfg).unwrap();
    }

    fn port_rule(bind: &str, host_port: u16, guest_port: u16) -> crate::state::PortRule {
        crate::state::PortRule {
            bind: bind.parse().unwrap(),
            host_port,
            guest_port,
        }
    }

    fn load_persisted_ports(paths: &Paths, name: &str) -> Vec<crate::state::PortRule> {
        let p = paths.sandbox_dir(name).join(CONFIG_FILE);
        let cfg: SandboxConfig = load_json(&p).unwrap().unwrap();
        cfg.ports
    }

    #[test]
    fn persist_port_rule_adds_a_rule() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let r = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&paths, "sb", &r).unwrap();

        let ports = load_persisted_ports(&paths, "sb");
        assert_eq!(ports, vec![r]);
    }

    #[test]
    fn persist_port_rule_same_rule_twice_is_idempotent() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let r = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&paths, "sb", &r).unwrap();
        persist_port_rule(&paths, "sb", &r).unwrap(); // second call must not dup

        let ports = load_persisted_ports(&paths, "sb");
        assert_eq!(ports.len(), 1, "expected exactly one rule, got: {ports:?}");
        assert_eq!(ports[0], r);
    }

    #[test]
    fn persist_port_rule_different_rule_appends() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let r1 = port_rule("127.0.0.1", 8080, 80);
        let r2 = port_rule("0.0.0.0", 9090, 90);
        persist_port_rule(&paths, "sb", &r1).unwrap();
        persist_port_rule(&paths, "sb", &r2).unwrap();

        let ports = load_persisted_ports(&paths, "sb");
        assert_eq!(ports.len(), 2, "expected two rules, got: {ports:?}");
        assert!(ports.contains(&r1));
        assert!(ports.contains(&r2));
    }

    #[test]
    fn unpersist_port_rule_removes_matching_rule() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let r = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&paths, "sb", &r).unwrap();

        unpersist_port_rule(&paths, "sb", r.bind, r.host_port).unwrap();

        let ports = load_persisted_ports(&paths, "sb");
        assert!(ports.is_empty(), "rule must be removed, got: {ports:?}");
    }

    #[test]
    fn unpersist_port_rule_absent_rule_is_noop() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        // No rule persisted yet — unpersist must succeed silently.
        unpersist_port_rule(&paths, "sb", "127.0.0.1".parse().unwrap(), 8080).unwrap();

        let ports = load_persisted_ports(&paths, "sb");
        assert!(ports.is_empty());
    }

    #[test]
    fn unpersist_port_rule_only_removes_matching_leaving_others() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let r1 = port_rule("127.0.0.1", 8080, 80);
        let r2 = port_rule("0.0.0.0", 9090, 90);
        persist_port_rule(&paths, "sb", &r1).unwrap();
        persist_port_rule(&paths, "sb", &r2).unwrap();

        // Remove only r1.
        unpersist_port_rule(&paths, "sb", r1.bind, r1.host_port).unwrap();

        let ports = load_persisted_ports(&paths, "sb");
        assert_eq!(ports, vec![r2], "only r2 must remain, got: {ports:?}");
    }

    // ── FIX 1 (Greptile P1): port_unpublish works on stopped sandbox ──────────
    //
    // These tests call handle_port_unpublish directly — no relay bind needed —
    // so they work even in sandboxed environments that deny TcpListener::bind.
    // Mirrors the adopt_rebuilds_view… and persist_port_rule_* test patterns.

    /// A stopped sandbox (no relay ever started) with a persisted port rule:
    /// handle_port_unpublish must return Ok and remove the persisted rule.
    #[test]
    fn port_unpublish_removes_persisted_rule_when_stopped() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let bind: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let host_port = 8080u16;
        let r = port_rule("127.0.0.1", host_port, 80);
        // Persist a rule directly into config (simulates a rule saved at publish time).
        persist_port_rule(&paths, "sb", &r).unwrap();
        assert_eq!(load_persisted_ports(&paths, "sb"), vec![r.clone()]);

        // Build a daemon (no relay published — sandbox is "stopped").
        let d = Arc::new(Daemon::new(paths.clone(), test_deps()));
        // handle_port_unpublish must succeed and remove the persisted rule.
        let result = handle_port_unpublish(&d, "sb".into(), bind, host_port);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let remaining = load_persisted_ports(&paths, "sb");
        assert!(
            remaining.is_empty(),
            "persisted rule must be removed, got: {remaining:?}"
        );
    }

    /// No persisted rule AND no live relay → handle_port_unpublish must return
    /// an error containing "no such published port".
    #[test]
    fn port_unpublish_unknown_rule_errors() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let bind: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let host_port = 9999u16;
        // Nothing persisted, no relay running.
        let d = Arc::new(Daemon::new(paths.clone(), test_deps()));
        let result = handle_port_unpublish(&d, "sb".into(), bind, host_port);
        let err = result.expect_err("expected Err for unknown port");
        assert!(
            err.to_string().contains("no such published port"),
            "unexpected error: {err:#}"
        );
    }

    // ── SSH config regeneration (Task 12) ──────────────────────────────────────
    //
    // Tests call `crate::ssh::config::regenerate` directly (the lighter path)
    // and separately unit-test `registry.running_names` in registry.rs.
    //
    // HOME isolation: `regenerate` injects an Include line into $HOME/.ssh/config.
    // We redirect HOME to a per-test tempdir so the real ~/.ssh/config is NEVER
    // touched. Because Rust tests run concurrently, we scope the env override
    // tightly: set it, call regenerate, then restore it before the tempdir drops.
    // Using std::env::set_var is safe here because these tests do not share the
    // HOME variable with other tests in a way that could race (they each get a
    // distinct temp path, and neither test reads HOME before setting it).

    /// Helper: set HOME (Unix) / USERPROFILE (Windows) to `dir`, returning the
    /// old value so the caller can restore it.
    #[cfg(unix)]
    fn override_home(dir: &std::path::Path) -> Option<String> {
        let old = std::env::var("HOME").ok();
        // SAFETY: single-threaded section; tests using this helper must not
        // run concurrently with each other. Each invocation uses a unique path
        // so even under parallel execution the only hazard is a transient wrong
        // HOME in the brief window — acceptable because we restore immediately
        // after the single regenerate call.
        unsafe {
            std::env::set_var("HOME", dir);
        }
        old
    }

    #[cfg(unix)]
    fn restore_home(old: Option<String>) {
        unsafe {
            match old {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[cfg(windows)]
    fn override_home(dir: &std::path::Path) -> Option<String> {
        let old = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("USERPROFILE", dir);
        }
        old
    }

    #[cfg(windows)]
    fn restore_home(old: Option<String>) {
        unsafe {
            match old {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    /// When config_management is enabled (default), `regen_ssh_config` writes
    /// `<data>/ssh/config` containing `Host izba-<name>` stubs for running
    /// sandboxes.
    #[test]
    fn regen_ssh_config_writes_managed_config_for_running_names() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let ssh_dir = paths.ssh_dir();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Default settings: config_management = true.

        // Redirect HOME so the Include injection does not touch the real
        // ~/.ssh/config.
        let fake_home = tempfile::tempdir().unwrap();
        let old_home = override_home(fake_home.path());

        let names: Vec<String> = vec!["alpha".into(), "beta".into()];
        let result = crate::ssh::config::regenerate(&paths, &names);

        restore_home(old_home);

        result.unwrap();

        let managed = ssh_dir.join("config");
        assert!(managed.exists(), "managed config not written");
        let body = std::fs::read_to_string(&managed).unwrap();
        assert!(
            body.contains("Host izba-alpha"),
            "alpha stub missing: {body}"
        );
        assert!(body.contains("Host izba-beta"), "beta stub missing: {body}");
        assert!(
            body.contains("Host izba-*"),
            "wildcard block missing: {body}"
        );
    }

    /// When config_management is disabled, `regenerate` is a no-op — the
    /// managed config file must NOT be created.
    #[test]
    fn regen_ssh_config_noop_when_config_management_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let ssh_dir = paths.ssh_dir();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        crate::ssh::settings::save(
            &ssh_dir,
            &crate::ssh::settings::SshSettings {
                config_management: false,
            },
        )
        .unwrap();

        let fake_home = tempfile::tempdir().unwrap();
        let old_home = override_home(fake_home.path());

        let result = crate::ssh::config::regenerate(&paths, &["foo".into()]);

        restore_home(old_home);

        result.unwrap();
        assert!(
            !ssh_dir.join("config").exists(),
            "config must not be written when config_management=false"
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
