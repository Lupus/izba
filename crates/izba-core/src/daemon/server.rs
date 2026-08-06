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
use crate::daemon::supervisor::StartsInFlight;
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

/// Seam over `artifacts::locate`. Takes the variant because a sandbox holding
/// USB grants needs a different kernel image than one that does not.
pub type ArtifactsFn =
    Box<dyn Fn(&Paths, crate::artifacts::KernelVariant) -> anyhow::Result<Artifacts> + Send + Sync>;

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
    /// The guest-facing USB plane. Bound per sandbox only while that sandbox
    /// holds a grant, so a sandbox without USB has no 1028 socket at all.
    pub usb: crate::usb::broker::UsbBroker,
    /// Sandboxes with a `Start` in flight — see [`StartsInFlight`]. Consulted
    /// by the supervisor tick so it doesn't clobber a booting sandbox's
    /// egress listener/relays while the disk still honestly says Stopped.
    starting: StartsInFlight,
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
        let usb = crate::usb::broker::UsbBroker::new(audit.clone());
        let egress = EgressManager::new(Arc::clone(&deps.egress_resolver), mitm, audit);
        Self {
            paths,
            deps,
            registry: Registry::new(),
            relays: RelayManager::new(),
            egress,
            usb,
            starting: StartsInFlight::new(),
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
            // Load + compile ONCE and apply that exact snapshot. Validating
            // here and then having the egress manager re-read the file by
            // path would be a TOCTOU: if policy.yaml is replaced/broken
            // between the two reads, the second read fails and the manager's
            // fail-closed fallback silently arms deny-all while this RPC
            // still answers Ok — the validated config would never be the one
            // applied. Both parse and compile errors surface to the caller
            // (#138/#83); the live policy is untouched on failure. (The
            // unattended paths — daemon start / ensure_listening — still
            // fail closed via resolve_policy.)
            let cfg = crate::daemon::egress::config::EgressPolicyConfig::load_or_materialize(
                &d.paths.sandbox_dir(&name),
            )?;
            let policy = cfg.into_policy(&name)?;
            d.egress.apply_policy(&name, policy);
            Ok(DaemonResponse::Ok)
        }
        DaemonRequest::Shutdown => {
            d.request_shutdown();
            Ok(DaemonResponse::Ok)
        }
        DaemonRequest::OpenStream { .. } => {
            bail!("OpenStream is handled at the connection layer")
        }
        DaemonRequest::UsbUpstreamShow => handle_usb_upstream_show(d),
        DaemonRequest::UsbUpstreamSet {
            host,
            port,
            allow_remote,
        } => handle_usb_upstream_set(d, host, port, allow_remote),
        DaemonRequest::UsbListDevices => handle_usb_list_devices(d),
        DaemonRequest::UsbAllow {
            name,
            device,
            busid_pin,
        } => handle_usb_allow(d, name, device, busid_pin),
        DaemonRequest::UsbRevoke { name, device } => handle_usb_revoke(d, name, device),
        DaemonRequest::UsbStatus { name } => handle_usb_status(d, name),
        DaemonRequest::UsbAttach { name, device } => handle_usb_attach(d, name, device, true),
        DaemonRequest::UsbDetach { name, device } => handle_usb_attach(d, name, device, false),
        DaemonRequest::VolumeList => handle_volume_list(d),
        DaemonRequest::VolumeRemove { name } => handle_volume_remove(d, name),
        DaemonRequest::VolumeAttach { name, spec } => handle_volume_attach(d, name, spec),
        DaemonRequest::Unknown => Err(anyhow::anyhow!(
            "unknown request type: this izbad build is older than the izba CLI \
             talking to it; restart the daemon (`izba daemon stop` — the next \
             CLI command respawns it) or upgrade so both ends match"
        )),
        DaemonRequest::VolumeDetach { name, guest_path } => {
            handle_volume_detach(d, name, guest_path)
        }
    }
}

/// Best-effort: regenerate the izba-managed ~/.ssh/config from the set of
/// non-stopped sandboxes. A failure (perms, read-only HOME) is logged and
/// never fails the lifecycle — same posture as relays/egress.
// reason: daemon-wired glue (registry.running_names → ssh::config::regenerate,
// best-effort/log-only). running_names + the regeneration logic (regenerate_with)
// are unit-tested; invoking this directly would write the real ~/.ssh.
#[mutants::skip]
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
            // `izba build` sets this to provision the throwaway build host
            // with the `izba-buildout` rw share at `/out`; normal create/run
            // leave it false.
            builder: c.builder,
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
    // A sandbox with device grants boots the USB-capable kernel; every other
    // one boots a kernel that physically cannot talk to a USB device (D4).
    // Resolving it here means a missing USB kernel fails the start with an
    // actionable error rather than booting a guest whose attaches do nothing.
    let variant = if config.usb.is_enabled() {
        crate::artifacts::KernelVariant::Usb
    } else {
        crate::artifacts::KernelVariant::Base
    };
    let art = (d.deps.artifacts)(&d.paths, variant)?;
    // Held across the whole listener-bind → boot → relay-republish window
    // (dropped on return, success or error): tells the supervisor tick to
    // spare this sandbox's egress/relays while state.json doesn't exist yet
    // and the disk scan honestly (but prematurely) reports it Stopped
    // (#134). The guard only gates the TICK's stops — this handler's own
    // error-path `egress.stop` below still runs normally while it's held.
    //
    // `begin` refuses a duplicate in-flight name: two concurrent
    // `Start{name}` calls both racing here would otherwise both bind the
    // listener and both call `sandbox::start`, and the loser of `start`'s
    // internal flock would hit the error path below and tear down the
    // WINNER's listener mid-boot. Bail before any side effect.
    let Some(_start_guard) = d.starting.begin(&name) else {
        bail!("a start for '{name}' is already in progress");
    };
    // A non-CLI client (e.g. the GUI) can hit this RPC directly for a
    // pre-existing (legacy) sandbox without ever going through the CLI's own
    // `ensure_socket_budget` precheck (`create.rs`/`run.rs`) — give it the
    // same actionable "IZBA_DATA_DIR too deep" message instead of a raw
    // SUN_LEN bind error surfacing from `ensure_listening` below (#71).
    crate::paths::ensure_socket_budget(&d.paths, &name)?;
    d.egress
        .ensure_listening(&d.paths, &name, &d.paths.run_dir(&name))?;
    // Same dir, same moment: a granted sandbox must have its USB plane up
    // before the guest boots and dials it. On failure the egress listener bound
    // just above is torn down too, so the two planes are armed and disarmed
    // together rather than leaving one behind for the supervisor to reap.
    if let Err(e) = d.usb.refresh(&d.paths, &name, &d.paths.run_dir(&name)) {
        d.egress.stop(&name, &d.paths.run_dir(&name));
        return Err(e);
    }
    if let Err(e) = sandbox::start(
        &d.paths,
        &name,
        d.deps.driver.as_ref(),
        &art,
        allow_unconfined,
    ) {
        if e.downcast_ref::<sandbox::AlreadyRunning>().is_some() {
            // The sandbox is alive: the listener bound by its original
            // start is still serving (ensure_listening above was a no-op)
            // — leave it. And heal a stale registry entry so a redundant
            // `izba run` self-corrects List/Inspect instead of returning
            // success while the daemon keeps reporting "stopped" (#67).
            if let Ok(live) = sandbox::liveness_of(&d.paths, &name, d.connector()) {
                d.registry.set(&name, &config.image_ref, live);
            }
            return Err(e);
        }
        // Boot never happened — tear the listener back down, in the SAME
        // dir the bind above used. Not `live_run_dir`: a stale pre-upgrade
        // state.json (crashed old run, `run_dir: None`, dead pid) would
        // make it resolve to the legacy dir and miss the listener just
        // bound in `paths.run_dir`.
        d.egress.stop(&name, &d.paths.run_dir(&name));
        d.usb.stop(&name, &d.paths.run_dir(&name));
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
    // Resolve the LIVE run dir before `sandbox::stop` deletes state.json —
    // once it's gone, `live_run_dir` can only fall back to the new-scheme
    // dir, missing the true legacy dir of a pre-upgrade (adopted) sandbox
    // whose `RunState.run_dir` was `None` (review follow-up).
    let run_dir = crate::sandbox::live_run_dir(&d.paths, &name);
    sandbox::stop(&d.paths, &name, d.connector(), STOP_TIMEOUT)?;
    d.relays.stop_all(&name);
    d.egress.stop(&name, &run_dir);
    d.usb.stop(&name, &run_dir);
    let _ = std::fs::remove_file(relays::rules_path(&d.paths, &name));
    d.registry.set_liveness(&name, Liveness::Stopped);
    regen_ssh_config(d);
    Ok(DaemonResponse::Ok)
}

fn handle_rm(d: &Arc<Daemon>, name: String, force: bool) -> anyhow::Result<DaemonResponse> {
    // Same ordering concern as `handle_stop` above: resolve before delete.
    let run_dir = crate::sandbox::live_run_dir(&d.paths, &name);
    sandbox::remove(&d.paths, &name, d.connector(), force)?;
    d.relays.stop_all(&name);
    d.egress.stop(&name, &run_dir);
    d.usb.stop(&name, &run_dir);
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
    let run_state = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?;
    let confinement = run_state
        .as_ref()
        .and_then(|s| s.confinement.clone())
        .map(|c| c.summary());
    // Symbolic-USER→root fallback (#114): also recorded in state.json at
    // launch. None ⇒ the image's USER resolved normally, or the sandbox
    // predates this field — the CLI prints nothing either way.
    let user_fallback = run_state
        .as_ref()
        .and_then(|s| s.user_fallback.as_ref())
        .map(|f| f.declared.clone());
    // Honesty: the VM (liveness) being up does not mean the workload container
    // inside it is. Probe the guest's container state best-effort; any failure
    // (unreachable/wedged guest, or a guest that doesn't report it) maps to
    // `None` → the CLI renders "unknown". A stopped VM can't hold a live
    // container, so skip the dial (it would only fail) and report `None`.
    let container = if status == "stopped" {
        None
    } else {
        probe_container_state(d, &name, CONTAINER_PROBE_TIMEOUT)
    };
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
        container,
        user_fallback,
    }))
}

/// Upper bound for the guest `Health` probe I/O. A wedged-but-accepting guest
/// must not pin the inspect handler (and, transitively, a polling GUI client)
/// forever — after this deadline the probe degrades to `None`/"unknown".
const CONTAINER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Best-effort probe of a sandbox's in-guest container state via the guest
/// `Health` RPC. Returns `None` on any failure — a stopped sandbox (the
/// control dial fails), an unreachable/wedged guest (bounded by `timeout`), or
/// a guest old enough that its `HealthInfo` carries no `container` field — so
/// inspect degrades to "unknown" instead of erroring. Mirrors
/// `handle_guest_rpc`'s single request/response exchange, but swallows errors
/// rather than surfacing them.
fn probe_container_state(
    d: &Arc<Daemon>,
    name: &str,
    timeout: Duration,
) -> Option<izba_proto::ContainerState> {
    let mut conn = sandbox::control(&d.paths, name, d.connector()).ok()?;
    conn.set_io_timeout(Some(timeout)).ok()?;
    write_frame(&mut conn, &izba_proto::Request::Health).ok()?;
    match read_frame::<_, Response>(&mut conn).ok()? {
        Response::Health(h) => h.container,
        _ => None,
    }
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
/// The fail-closed gate for USB passthrough.
///
/// Called FIRST in every USB handler except the two upstream verbs — before any
/// address, device id, or sandbox name is examined — so that a daemon whose
/// operator never configured USB has no USB code path a caller can drive at
/// all. "Disabled adds zero surface" is a structural claim here, not a flag
/// check buried after the parsing.
fn usb_settings_or_refuse(d: &Arc<Daemon>) -> anyhow::Result<crate::usb::UsbSettings> {
    let s = crate::usb::settings::load(&d.paths.usb_dir());
    if !crate::usb::is_configured(&s) {
        bail!(
            "usb passthrough is not configured — run \
             `izba usb upstream set <host>` to point izba at a usbip server"
        );
    }
    Ok(s)
}

fn handle_usb_upstream_show(d: &Arc<Daemon>) -> anyhow::Result<DaemonResponse> {
    let s = crate::usb::settings::load(&d.paths.usb_dir());
    let Some(up) = s.upstream.clone() else {
        return Ok(DaemonResponse::UsbUpstream { upstream: None });
    };
    let (resolved, trust) = crate::usb::classify_configured(&up.host, up.port);
    Ok(DaemonResponse::UsbUpstream {
        upstream: Some(crate::daemon::proto::UsbUpstreamInfo {
            warning: crate::usb::trust::describe(trust, &up.host),
            trust: trust.as_str().to_string(),
            resolved: resolved.map(|ip| ip.to_string()),
            host: up.host,
            port: up.port,
        }),
    })
}

fn handle_usb_upstream_set(
    d: &Arc<Daemon>,
    host: String,
    port: u16,
    allow_remote: bool,
) -> anyhow::Result<DaemonResponse> {
    let (_resolved, trust) = crate::usb::classify_configured(&host, port);
    if crate::usb::trust::is_refused(trust, allow_remote) {
        bail!(
            "refusing '{host}' as a usbip upstream: it is reachable from the \
             internet (or does not resolve, which izba treats the same way), and \
             USB/IP has no authentication or encryption. Pass --allow-remote if \
             you genuinely mean it."
        );
    }
    let mut s = crate::usb::settings::load(&d.paths.usb_dir());
    s.upstream = Some(crate::usb::Upstream { host, port });
    s.allow_remote_upstream = allow_remote;
    crate::usb::settings::save(&d.paths.usb_dir(), &s)?;
    Ok(DaemonResponse::Ok)
}

fn handle_usb_list_devices(d: &Arc<Daemon>) -> anyhow::Result<DaemonResponse> {
    let s = usb_settings_or_refuse(d)?;
    // Re-classify at dial time: what the name resolved to when it was stored is
    // not a promise about what it resolves to now.
    let addr = crate::usb::dialable_upstream(&s)?;
    let shared = crate::usb::inventory::fetch(addr)?;
    Ok(DaemonResponse::UsbDevices {
        devices: crate::usb::list_devices(&d.paths, &shared, crate::usb::usbipd_state::probe()),
    })
}

fn handle_usb_allow(
    d: &Arc<Daemon>,
    name: String,
    device: String,
    busid_pin: Option<String>,
) -> anyhow::Result<DaemonResponse> {
    usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    sandbox::edit_usb_grants(&d.paths, &name, |usb| {
        crate::usb::grants::grant(
            usb,
            crate::usb::UsbGrant {
                device: id,
                busid_pin,
                description: String::new(),
                granted_at_unix_ms: crate::usb::now_unix_ms(),
            },
        )
    })?;
    // The first grant closes this sandbox's LAN path to the usbip upstream on
    // its NEXT egress connection, not at its next restart.
    d.egress
        .apply_usb_guard(&name, crate::usb::guard_for(&d.paths, &name));
    refresh_usb_plane(d, &name);
    Ok(DaemonResponse::Ok)
}

fn handle_usb_revoke(
    d: &Arc<Daemon>,
    name: String,
    device: String,
) -> anyhow::Result<DaemonResponse> {
    usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    sandbox::edit_usb_grants(&d.paths, &name, |usb| crate::usb::grants::revoke(usb, id))?;
    // Withdrawing consent has to reach the device, not just the record: one
    // already attached stays bound to the guest's vhci — and unavailable to the
    // host — until something detaches it. Best-effort, because the sandbox may
    // well be stopped, and the revoke itself is already durable on disk.
    if let Err(e) = handle_guest_rpc(
        d,
        name.clone(),
        izba_proto::Request::UsbDetach {
            device: id.to_string(),
        },
    ) {
        eprintln!("izbad: detaching {id} from '{name}' after revoke: {e:#}");
    }
    // Symmetrically: revoking the last grant reopens the sandbox's ordinary LAN
    // access straight away rather than leaving a stale denial behind.
    d.egress
        .apply_usb_guard(&name, crate::usb::guard_for(&d.paths, &name));
    refresh_usb_plane(d, &name);
    Ok(DaemonResponse::Ok)
}

fn handle_usb_status(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    usb_settings_or_refuse(d)?;
    sandbox_must_exist(&d.paths, &name)?;
    let cfg: crate::state::SandboxConfig =
        crate::state::load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
            .ok_or_else(|| anyhow::anyhow!("sandbox '{name}' has no config"))?;
    Ok(DaemonResponse::UsbStatus {
        grants: cfg
            .usb
            .devices
            .iter()
            .map(|g| crate::daemon::proto::UsbGrantInfo {
                device: g.device.to_string(),
                busid_pin: g.busid_pin.clone(),
                description: g.description.clone(),
                granted_at_unix_ms: g.granted_at_unix_ms,
            })
            .collect(),
    })
}

/// Bring `name`'s USB plane in line with the grants just written.
///
/// The first grant opens it and the last revoke closes it, both without a
/// restart — the same "takes effect on the next attempt, not the next boot"
/// contract as the egress guard beside it. Best-effort: the grant is already
/// durable on disk, and the next start or supervisor tick rebinds from it, so a
/// bind failure here must not fail the consent action the user actually asked
/// for.
fn refresh_usb_plane(d: &Arc<Daemon>, name: &str) {
    let run_dir = crate::sandbox::live_run_dir(&d.paths, name);
    if let Err(e) = d.usb.refresh(&d.paths, name, &run_dir) {
        eprintln!("izbad: USB listener for '{name}': {e:#}");
    }
}

/// Attach or detach one already-granted device on a running sandbox.
///
/// Both verbs share one shape, and the order of its checks is the point: the
/// feature gate, the device id, the sandbox, and the grant are all settled on
/// the host before a single byte reaches the guest. A grant check that ran
/// after the guest RPC would answer "sandbox is not running" for a device the
/// user never consented to — reporting the wrong problem, and leaking whether
/// the sandbox is up to a caller who was never entitled to the device.
///
/// izbad does not attach anything itself: it forwards to izba-init, which dials
/// the USB plane and hands the resulting socket to `vhci-hcd`. The grant is
/// re-checked there too, by the broker, against the same on-disk record — this
/// check is the honest early error, not the boundary.
///
/// **Detach is deliberately NOT gated on the grant.** Detaching is a
/// de-escalation, and the state that most needs it is exactly the one where the
/// grant is already gone: a device attached before a revoke is still bound to
/// the guest's vhci and still unavailable to the host. Requiring the grant
/// there would tell the user to re-grant a device in order to release it, and
/// leave them no other way out short of stopping the sandbox.
fn handle_usb_attach(
    d: &Arc<Daemon>,
    name: String,
    device: String,
    attach: bool,
) -> anyhow::Result<DaemonResponse> {
    usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    if attach {
        let cfg: crate::state::SandboxConfig =
            crate::state::load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
                .ok_or_else(|| anyhow::anyhow!("sandbox '{name}' has no config"))?;
        if crate::usb::grants::find(&cfg.usb, id).is_none() {
            anyhow::bail!(
                "{id} is not granted to '{name}' — run `izba usb allow {name} --device {id}` first"
            );
        }
    }
    let req = if attach {
        izba_proto::Request::UsbAttach {
            device: id.to_string(),
        }
    } else {
        izba_proto::Request::UsbDetach {
            device: id.to_string(),
        }
    };
    handle_guest_rpc(d, name, req)
}

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
    // Snapshot BEFORE the disk scan: adoption runs before the accept loop
    // and the supervisor thread are started, so in practice nothing can
    // mutate the registry concurrently here — but taking the snapshot
    // first keeps this call site honest with the same contract as the
    // supervisor tick's (see registry::Registry::replace_all's doc).
    let snap = d.registry.snapshot();
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
        // is logged but never aborts adoption of the rest. Adoption serves
        // an already-running VM, so it must bind in the LIVE dir recorded in
        // state.json (a pre-hash-scheme sandbox's legacy dir), never blindly
        // in the new-scheme dir.
        if info.liveness != Liveness::Stopped {
            let run_dir = crate::sandbox::live_run_dir(&d.paths, &info.name);
            if let Err(e) = d.egress.ensure_listening(&d.paths, &info.name, &run_dir) {
                eprintln!("izbad: egress listener for '{}': {e:#}", info.name);
            }
            if let Err(e) = d.usb.refresh(&d.paths, &info.name, &run_dir) {
                eprintln!("izbad: USB listener for '{}': {e:#}", info.name);
            }
        }
    }
    d.registry.replace_all(snap, infos);
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
            supervisor::tick(
                &d.paths,
                &d.registry,
                &d.relays,
                &d.egress,
                &d.usb,
                d.connector(),
                &d.starting,
            );
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
    use crate::state::{
        load_json, save_json, RunState, SandboxConfig, UserFallback, CONFIG_FILE, STATE_FILE,
    };
    use crate::testutil::{
        fake_connector, hanging_connector, live_identity, spawn_sleep, test_paths, wait_dead,
        write_state, write_state_with_run_dir, MockDriver,
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
            artifacts: Box::new(|_, variant| {
                Ok(crate::sandbox::Artifacts {
                    variant,
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
            builder: false,
        })
    }

    #[test]
    fn hello_reports_server_version() {
        let (_dir, d) = test_daemon();
        let _c = client_conn(&d); // assertions inside
    }

    #[test]
    fn unknown_request_variant_gets_clean_error() {
        // A request `type` this build doesn't know (a newer client inside the
        // same proto version) must produce an honest Error reply — not the
        // pre-v2 behavior of failing the frame read and dropping the
        // connection with no explanation.
        let req: DaemonRequest =
            serde_json::from_str(r#"{"type":"volume_defrag","name":"x"}"#).unwrap();
        assert!(matches!(req, DaemonRequest::Unknown));

        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(&mut c, &req) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("unknown request type"), "{message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    fn expect_ok_resp(resp: DaemonResponse) {
        match resp {
            DaemonResponse::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    fn set_loopback_upstream(c: &mut UdsStream) {
        expect_ok_resp(rpc(
            c,
            &DaemonRequest::UsbUpstreamSet {
                host: "127.0.0.1".into(),
                port: 3240,
                allow_remote: false,
            },
        ));
    }

    /// The structural claim behind "disabled USB adds zero attack surface":
    /// with no upstream configured, every USB verb refuses BEFORE it looks at a
    /// device id or a sandbox name.
    #[test]
    fn usb_requests_refuse_when_no_upstream_is_configured() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        for req in [
            DaemonRequest::UsbListDevices,
            DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
            DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbStatus { name: "web".into() },
        ] {
            match rpc(&mut c, &req) {
                DaemonResponse::Error { message } => assert!(
                    message.contains("not configured"),
                    "{req:?} must refuse before touching its fields: {message}"
                ),
                other => panic!("{req:?} must refuse when USB is off, got {other:?}"),
            }
        }
    }

    /// The datapath verbs join the same refusal set: with USB off, neither
    /// looks at a device id, a sandbox, or the guest.
    #[test]
    fn the_datapath_verbs_also_refuse_when_no_upstream_is_configured() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        for req in [
            DaemonRequest::UsbAttach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbDetach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ] {
            match rpc(&mut c, &req) {
                DaemonResponse::Error { message } => {
                    assert!(message.contains("not configured"), "{req:?}: {message}")
                }
                other => panic!("{req:?} must refuse when USB is off, got {other:?}"),
            }
        }
    }

    #[test]
    fn attaching_a_device_that_was_never_granted_is_refused_before_the_guest_is_touched() {
        // The grant is the authorization boundary. Reaching the guest first
        // would answer "sandbox is not running" for a device the user never
        // consented to — the wrong problem, and it tells a caller who is not
        // entitled to the device whether the sandbox is up.
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        write_config_for_persist(&d.paths, "web");

        match rpc(
            &mut c,
            &DaemonRequest::UsbAttach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("not granted"), "{message}");
                assert!(
                    message.contains("izba usb allow"),
                    "say how to fix it: {message}"
                );
            }
            other => panic!("attach must refuse an ungranted device, got {other:?}"),
        }
    }

    #[test]
    fn granting_arms_the_usb_plane_and_revoking_disarms_it_without_a_restart() {
        // The consent action has to move the plane, not just the record. A
        // grant that left the plane closed would make every attach fail until
        // the next start; a revoke that left it open would keep serving a
        // sandbox whose consent was withdrawn.
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        write_config_for_persist(&d.paths, "web");
        assert!(!d.usb.listening("web"), "no grants yet");

        // Establish that this environment CAN bind, using a second sandbox and
        // the manager directly. Skipping on "the plane did not come up" would
        // otherwise pass a handler that never called refresh at all — the two
        // look identical from here.
        write_config_for_persist(&d.paths, "probe");
        grant_on_disk(&d.paths, "probe");
        let probe_dir = d.paths.run_dir("probe");
        if d.usb.refresh(&d.paths, "probe", &probe_dir).is_err() || !d.usb.listening("probe") {
            eprintln!("SKIP: this environment cannot bind the USB plane");
            return;
        }
        d.usb.stop("probe", &probe_dir);

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ));
        assert!(
            d.usb.listening("web"),
            "granting must arm the plane now, not at the next start"
        );

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ));
        assert!(
            !d.usb.listening("web"),
            "revoking the last grant must close the plane now, not at the next start"
        );
    }

    /// Write a grant straight into a sandbox's config, bypassing the RPC — used
    /// to set up a control case the RPC path is being tested against.
    fn grant_on_disk(paths: &Paths, name: &str) {
        crate::sandbox::edit_usb_grants(paths, name, |usb| {
            crate::usb::grants::grant(
                usb,
                crate::usb::UsbGrant {
                    device: "0403:6001".parse().unwrap(),
                    busid_pin: None,
                    description: String::new(),
                    granted_at_unix_ms: 1,
                },
            )
        })
        .unwrap();
    }

    #[test]
    fn detaching_is_not_gated_on_the_grant() {
        // Detach is a de-escalation, and the state that most needs it is
        // exactly the one where the grant is already gone: a device attached
        // before a revoke is still bound to the guest's vhci and still
        // unavailable to the host. Refusing there would tell the user to
        // re-grant a device in order to release it.
        //
        // So detach must reach the guest — here it fails on the sandbox being
        // stopped, which is the honest answer, NOT on the missing grant.
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        write_config_for_persist(&d.paths, "web");

        match rpc(
            &mut c,
            &DaemonRequest::UsbDetach {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ) {
            DaemonResponse::Error { message } => assert!(
                !message.contains("not granted"),
                "detach must not be refused for a missing grant: {message}"
            ),
            // A guest reply at all means it got past the grant check, which is
            // the whole point.
            DaemonResponse::Guest { .. } => {}
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_device_id_never_reaches_the_sandbox_lookup() {
        // `403:6001` is a plausible typo for a real id; it must be refused on
        // its own terms rather than as "no such sandbox".
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        match rpc(
            &mut c,
            &DaemonRequest::UsbAttach {
                name: "nonexistent".into(),
                device: "403:6001".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("vid:pid"), "{message}");
                assert!(
                    !message.contains("no such sandbox"),
                    "the id is the problem, not the sandbox: {message}"
                );
            }
            other => panic!("expected a parse refusal, got {other:?}"),
        }
    }

    #[test]
    fn attaching_on_a_sandbox_that_does_not_exist_says_so() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        match rpc(
            &mut c,
            &DaemonRequest::UsbAttach {
                name: "nonexistent".into(),
                device: "0403:6001".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("no such sandbox"), "{message}")
            }
            other => panic!("expected a missing-sandbox refusal, got {other:?}"),
        }
    }

    #[test]
    fn usb_upstream_show_is_answerable_with_the_feature_off() {
        // The one question a user must be able to ask before configuring
        // anything: is this on?
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::UsbUpstreamShow) {
            DaemonResponse::UsbUpstream { upstream } => assert!(upstream.is_none()),
            other => panic!("expected UsbUpstream, got {other:?}"),
        }
    }

    #[test]
    fn setting_a_loopback_upstream_persists_it_without_a_warning() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);

        let s = crate::usb::settings::load(&d.paths.usb_dir());
        assert_eq!(s.upstream.as_ref().unwrap().host, "127.0.0.1");
        assert!(!s.allow_remote_upstream);

        match rpc(&mut c, &DaemonRequest::UsbUpstreamShow) {
            DaemonResponse::UsbUpstream { upstream } => {
                let u = upstream.expect("configured");
                assert_eq!(u.trust, "own-host-loopback");
                assert_eq!(u.resolved.as_deref(), Some("127.0.0.1"));
                assert!(u.warning.is_none(), "loopback is the recommended setup");
            }
            other => panic!("expected UsbUpstream, got {other:?}"),
        }
    }

    #[test]
    fn a_public_upstream_is_refused_unless_explicitly_allowed() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "203.0.113.7".into(),
                port: 3240,
                allow_remote: false,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("internet"), "{message}");
                assert!(
                    message.contains("--allow-remote"),
                    "name the opt-in: {message}"
                );
            }
            other => panic!("a public upstream must be refused, got {other:?}"),
        }
        assert!(
            crate::usb::settings::load(&d.paths.usb_dir())
                .upstream
                .is_none(),
            "a refused upstream must not be persisted"
        );
    }

    #[test]
    fn a_public_upstream_is_accepted_once_the_user_opts_in_and_still_warns() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "203.0.113.7".into(),
                port: 3240,
                allow_remote: true,
            },
        ));
        match rpc(&mut c, &DaemonRequest::UsbUpstreamShow) {
            DaemonResponse::UsbUpstream { upstream } => {
                let u = upstream.expect("configured");
                assert_eq!(u.trust, "public");
                assert!(
                    u.warning.is_some(),
                    "opting in silences the refusal, never the warning"
                );
            }
            other => panic!("expected UsbUpstream, got {other:?}"),
        }
    }

    #[test]
    fn allow_then_status_then_revoke_round_trips_through_disk() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&dir, "web"));
        set_loopback_upstream(&mut c);

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: Some("3-2".into()),
            },
        ));

        match rpc(&mut c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus { grants } => {
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].device, "0403:6001");
                assert_eq!(grants[0].busid_pin.as_deref(), Some("3-2"));
                assert!(grants[0].granted_at_unix_ms > 0, "grants are stamped");
            }
            other => panic!("expected UsbStatus, got {other:?}"),
        }
        // The grant is the sandbox's own managed truth, on disk.
        assert!(crate::usb::guard_for(&d.paths, "web").sandbox_usb_enabled);

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ));
        match rpc(&mut c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus { grants } => assert!(grants.is_empty()),
            other => panic!("expected UsbStatus, got {other:?}"),
        }
        assert!(!crate::usb::guard_for(&d.paths, "web").sandbox_usb_enabled);
    }

    #[test]
    fn a_malformed_device_id_is_a_clean_error_not_a_grant() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&dir, "web"));
        set_loopback_upstream(&mut c);
        match rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "not-an-id".into(),
                busid_pin: None,
            },
        ) {
            DaemonResponse::Error { message } => assert!(message.contains("vid:pid"), "{message}"),
            other => panic!("expected an error, got {other:?}"),
        }
        assert!(!crate::usb::guard_for(&d.paths, "web").sandbox_usb_enabled);
    }

    #[test]
    fn granting_to_a_sandbox_that_does_not_exist_is_refused() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        match rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "ghost".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ) {
            DaemonResponse::Error { message } => assert!(message.contains("ghost"), "{message}"),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn revoking_a_grant_that_was_never_made_is_refused() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&dir, "web"));
        set_loopback_upstream(&mut c);
        match rpc(
            &mut c,
            &DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("not granted"), "{message}")
            }
            other => panic!("expected an error, got {other:?}"),
        }
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
                // A stopped VM can't hold a live container; the daemon skips the
                // probe and reports None → CLI "unknown" (never falsely healthy).
                assert_eq!(det.container, None);
                // No state.json ⇒ no recorded symbolic-USER fallback either.
                assert_eq!(det.user_fallback, None);
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

    /// #114 surface acceptance: a persisted symbolic-USER→root fallback in
    /// state.json is read back through `Inspect` unchanged.
    #[test]
    fn inspect_surfaces_persisted_user_fallback() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(&mut c, &create_req(&dir, "web")) {
            DaemonResponse::Created { name } => assert_eq!(name, "web"),
            other => panic!("create: {other:?}"),
        }

        save_json(
            &d.paths.sandbox_dir("web").join(STATE_FILE),
            &RunState {
                vmm_pid: live_identity(),
                sidecar_pids: vec![],
                started_unix_ms: 0,
                confinement: None,
                run_dir: None,
                user_fallback: Some(UserFallback::new("node")),
                usb_kernel: false,
            },
        )
        .unwrap();

        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.user_fallback, Some("node".into()));
            }
            other => panic!("inspect: {other:?}"),
        }
    }

    /// #138/#83 reload acceptance criterion: a broken `policy.yaml` must
    /// surface a parse error to the caller instead of the daemon silently
    /// swapping in a deny-all live policy.
    #[test]
    fn reload_policy_surfaces_parse_error_instead_of_silent_deny_all() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "fw")),
            DaemonResponse::Created { .. }
        ));

        std::fs::write(
            d.paths.sandbox_dir("fw").join("policy.yaml"),
            "portz: [80]\n",
        )
        .unwrap();

        match rpc(&mut c, &DaemonRequest::ReloadPolicy { name: "fw".into() }) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("portz"), "{message}")
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// TOCTOU-fix acceptance: a well-formed `policy.yaml` is loaded and
    /// compiled exactly once and that snapshot is applied — the reload
    /// answers `Ok` rather than erroring or silently arming deny-all. The
    /// egress manager's live-slot swap on a real listener is covered at the
    /// unit level by `egress::mod::tests::apply_policy_swaps_a_live_slot`
    /// (no live listener exists here — `Create` never arms one — so
    /// `apply_policy` is a documented no-op on the manager side; the RPC
    /// result is what this test asserts).
    #[test]
    fn reload_policy_applies_a_valid_snapshot() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "fw2")),
            DaemonResponse::Created { .. }
        ));

        std::fs::write(
            d.paths.sandbox_dir("fw2").join("policy.yaml"),
            "enforce: true\nallow:\n  - api.anthropic.com\n",
        )
        .unwrap();

        match rpc(&mut c, &DaemonRequest::ReloadPolicy { name: "fw2".into() }) {
            DaemonResponse::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
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
        // Start binds in the new-scheme dir (no state.json existed yet).
        assert!(egress::listener_path(&d.paths.run_dir("web")).exists());

        // Swap the MockDriver-recorded vmm identity for the disposable
        // child, same as the sibling test above — but keep the real
        // `run_dir: Some(paths.run_dir(name))` that `record_run_state`
        // wrote for this (non-legacy) Start, or `Stop` would resolve the
        // wrong (legacy) dir and never see this test's listener.
        write_state_with_run_dir(&d.paths, "web", vmm.clone(), Some(d.paths.run_dir("web")));
        assert!(matches!(
            rpc(&mut c, &DaemonRequest::Stop { name: "web".into() }),
            DaemonResponse::Ok
        ));
        assert!(!d.egress.listening("web"));
        assert!(!egress::listener_path(&d.paths.run_dir("web")).exists());
    }

    /// A non-CLI client (e.g. the GUI) can call `Start` directly for a
    /// pre-existing sandbox without ever going through the CLI's own
    /// `ensure_socket_budget` precheck (`create.rs`/`run.rs`). `handle_start`
    /// must reject a too-deep root with the same actionable
    /// "IZBA_DATA_DIR too deep" message BEFORE binding the egress listener,
    /// not a raw SUN_LEN bind error surfacing from `ensure_listening`
    /// (review follow-up on #71). The sandbox dir + config.json are
    /// hand-written here (bypassing `sandbox::create`'s own check) to
    /// stand in for that direct-RPC path.
    #[test]
    fn handle_start_rejects_deep_root_before_binding_listener() {
        let dir = tempfile::tempdir().unwrap();
        let deep_root = dir.path().join("d".repeat(100));
        let paths = Paths::with_root(deep_root);
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        save_json(
            &paths.sandbox_dir("web").join(CONFIG_FILE),
            &SandboxConfig {
                usb: Default::default(),
                image_digest: "sha256:abc".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                ports: Vec::new(),
                volumes: Vec::new(),
                builder: false,
                build: None,
                rw_size_gb: 1,
            },
        )
        .unwrap();
        let d = Arc::new(Daemon::new(paths, test_deps()));
        let mut progress_log = Vec::new();
        let err = handle_start(&d, "web".into(), false, &mut |s| progress_log.push(s))
            .expect_err("deep root must be rejected before binding the listener");
        let msg = format!("{err:#}");
        assert!(msg.contains("IZBA_DATA_DIR"), "{msg}");
        assert!(
            !d.egress.listening("web"),
            "listener must not have been bound"
        );
    }

    /// A pre-upgrade ("legacy") sandbox — adopted with `RunState.run_dir:
    /// None`, so its egress listener actually lives at
    /// `paths.legacy_run_dir(name)`, not the new-scheme `paths.run_dir(name)`
    /// — must have that TRUE legacy socket removed by `Stop`. `handle_stop`
    /// used to resolve `live_run_dir` AFTER `sandbox::stop` deletes
    /// `state.json`; with the state gone, `live_run_dir` can only fall back
    /// to the new-scheme dir, leaking the legacy socket file forever
    /// (review follow-up). Runtime-skips where the sandbox denies bind.
    #[test]
    fn stop_removes_legacy_egress_listener_of_adopted_sandbox() {
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
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));

        // Simulate adoption of a pre-upgrade sandbox: `state.json` with
        // `run_dir: None` (the legacy sentinel `write_state` already
        // writes), and the egress listener actually bound in the legacy
        // dir — exactly what daemon-startup adoption does for such a
        // sandbox (`live_run_dir` resolves `None` to `legacy_run_dir`).
        write_state(&d.paths, "web", vmm.clone());
        match d
            .egress
            .ensure_listening(&d.paths, "web", &d.paths.legacy_run_dir("web"))
        {
            Ok(()) => {}
            // Chain-aware guard (house pattern from egress/mod.rs tests):
            // anyhow's plain Display prints only the OUTERMOST context
            // ("binding egress listener <path>"), so string-matching `e`
            // would hard-fail instead of skipping in a bind-denied sandbox.
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP stop_removes_legacy_egress_listener: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(d.egress.listening("web"));
        let legacy_sock = egress::listener_path(&d.paths.legacy_run_dir("web"));
        assert!(legacy_sock.exists(), "precondition: legacy socket bound");

        assert!(matches!(
            rpc(&mut c, &DaemonRequest::Stop { name: "web".into() }),
            DaemonResponse::Ok
        ));
        assert!(!d.egress.listening("web"));
        assert!(
            !legacy_sock.exists(),
            "Stop must remove the TRUE (legacy) egress socket, not just the \
             new-scheme dir's (which never had one)"
        );
    }

    /// Same bug, `handle_rm` side: `sandbox::remove` renames the whole
    /// sandbox dir (including `state.json`) to a tombstone and deletes it —
    /// an even more thorough state wipe than `Stop`'s `cleanup_runtime`.
    /// `Rm --force` on a legacy-adopted ("running") sandbox must still find
    /// and remove the TRUE legacy egress socket.
    #[test]
    fn rm_force_removes_legacy_egress_listener_of_adopted_sandbox() {
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
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));

        // Same legacy-adoption simulation as the Stop test above.
        write_state(&d.paths, "web", vmm.clone());
        match d
            .egress
            .ensure_listening(&d.paths, "web", &d.paths.legacy_run_dir("web"))
        {
            Ok(()) => {}
            // Chain-aware guard — same rationale as the Stop test above.
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP rm_force_removes_legacy_egress_listener: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(d.egress.listening("web"));
        let legacy_sock = egress::listener_path(&d.paths.legacy_run_dir("web"));
        assert!(legacy_sock.exists(), "precondition: legacy socket bound");

        assert!(matches!(
            rpc(
                &mut c,
                &DaemonRequest::Rm {
                    name: "web".into(),
                    force: true,
                }
            ),
            DaemonResponse::Ok
        ));
        assert!(!d.egress.listening("web"));
        assert!(
            !legacy_sock.exists(),
            "Rm --force must remove the TRUE (legacy) egress socket, not just \
             the new-scheme dir's (which never had one)"
        );
    }

    /// A `Start` racing a name that's already mid-boot must bail fast,
    /// honestly, and WITHOUT touching egress — never reach
    /// `ensure_listening`/`sandbox::start`, and never sabotage a real
    /// winner's listener via the error-path `egress.stop`. Simulates the
    /// "winner mid-boot" window by holding the `StartsInFlight` guard
    /// directly (the same guard `handle_start` holds across its own
    /// listener-bind → boot → relay-republish window) rather than racing
    /// two real threads through the flock in `sandbox::start`.
    #[test]
    fn concurrent_start_of_same_name_fails_fast_without_touching_egress() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        assert!(!d.egress.listening("web"), "nothing started yet");

        // Hold the in-flight mark as a real winner's `handle_start` would.
        let _winner_guard = d
            .starting
            .begin("web")
            .expect("first begin for 'web' succeeds");

        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: false,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("already in progress"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected an in-progress error, got: {other:?}"),
        }
        // The loser must not have touched egress at all — no bind attempt,
        // and (were a real winner mid-boot) no `egress.stop` sabotage.
        assert!(
            !d.egress.listening("web"),
            "loser must not bind/touch the egress listener"
        );
    }

    /// #67: a redundant Start on an already-running sandbox must (a) heal a
    /// stale registry entry to the actual liveness and (b) NOT tear down the
    /// live sandbox's egress listener. Before the fix, `handle_start` took
    /// the generic boot-failure error path: it called `d.egress.stop` on the
    /// listener `ensure_listening` had just no-op'd (already bound), and
    /// returned before ever reaching `registry.set(Running)`.
    #[test]
    fn start_already_running_heals_registry_and_keeps_egress() {
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
        // `Create` seeds the registry Stopped — exactly the stale cache
        // entry a crashed/never-adopted daemon would carry for a sandbox
        // that is, in fact, live on disk right now.
        assert_eq!(d.registry.liveness("web"), Some(Liveness::Stopped));

        // Make the sandbox actually live: a real pid + state.json in the
        // new-scheme run dir (what a real post-Start state.json records),
        // and its egress listener already bound there — exactly what the
        // FIRST (real) Start would have left behind.
        write_state_with_run_dir(&d.paths, "web", vmm.clone(), Some(d.paths.run_dir("web")));
        match d
            .egress
            .ensure_listening(&d.paths, "web", &d.paths.run_dir("web"))
        {
            Ok(()) => {}
            // Chain-aware guard — same rationale as the legacy-egress tests
            // above: a bind-denying sandbox must skip, not fail.
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP start_already_running_heals_registry_and_keeps_egress: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(d.egress.listening("web"), "precondition: listener bound");

        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "web".into(),
                allow_unconfined: false,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("already running"), "got: {message}");
            }
            other => panic!("expected an already-running error, got: {other:?}"),
        }
        assert!(
            d.egress.listening("web"),
            "the redundant Start must NOT tear down the live sandbox's egress listener"
        );
        assert_eq!(
            d.registry.liveness("web"),
            Some(Liveness::Running),
            "the redundant Start must heal the stale registry entry"
        );
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
    fn inspect_folds_running_container_state_from_guest() {
        // A running sandbox: the daemon probes the guest Health RPC and folds
        // the reported container state onto the inspect detail. The fake guest
        // reports a live container, so this proves the probe→fold path end to
        // end (not just the serde default).
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        // Two things make a sandbox "live" here: the cached registry liveness
        // (drives the inspect `status` string) and an on-disk live pid (the
        // gate `sandbox::control` checks before dialing the guest). Set both so
        // the probe actually reaches the fake guest.
        d.registry.set_liveness("web", Liveness::Running);
        write_state(&d.paths, "web", live_identity());
        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert_eq!(det.status, "running");
                assert_eq!(det.container, Some(izba_proto::ContainerState::Running));
            }
            other => panic!("inspect: {other:?}"),
        }
    }

    #[test]
    fn container_probe_times_out_on_wedged_guest() {
        // A guest that accepts the control connection and reads the Health
        // request but never replies must not pin the probe (and transitively a
        // polling GUI's inspect) forever — the bounded probe degrades to None
        // within its timeout instead of blocking until the peer goes away.
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let mut deps = test_deps();
        deps.connector = Box::new(hanging_connector());
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        write_state(&d.paths, "web", live_identity());

        let t0 = Instant::now();
        let state = probe_container_state(&d, "web", Duration::from_millis(200));
        assert_eq!(state, None);
        // Well under the hanging fake's 10 s hold: proves the timeout fired,
        // not the peer's eventual exit.
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "probe blocked {:?} instead of timing out",
            t0.elapsed()
        );
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
                builder: false,
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
                builder: false,
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
            usb: Default::default(),
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: dir.join("ws"),
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            build: None,
            rw_size_gb: 8,
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
    // Tests call `crate::ssh::config::regenerate_with` directly, injecting a
    // hermetic env closure that maps HOME/USERPROFILE to a per-test tempdir.
    // No global env mutation — safe under parallel test execution.

    /// When config_management is enabled (default), `regenerate_with` writes
    /// `<data>/ssh/config` containing `Host izba-<name>` stubs for running
    /// sandboxes and injects an Include line into the fake home's .ssh/config.
    #[test]
    fn regen_ssh_config_writes_managed_config_for_running_names() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let ssh_dir = paths.ssh_dir();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Default settings: config_management = true.

        let fake_home = tempfile::tempdir().unwrap();
        let fake_home_path = fake_home.path().to_owned();
        let env = |k: &str| -> Option<String> {
            if k == "HOME" || k == "USERPROFILE" {
                Some(fake_home_path.to_string_lossy().into_owned())
            } else {
                std::env::var(k).ok()
            }
        };

        let names: Vec<String> = vec!["alpha".into(), "beta".into()];
        crate::ssh::config::regenerate_with(&paths, &names, &env).unwrap();

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

        // The Include line must have landed in the fake home's .ssh/config.
        let user_cfg = fake_home.path().join(".ssh").join("config");
        assert!(user_cfg.exists(), "user config not created in fake home");
        let user_body = std::fs::read_to_string(&user_cfg).unwrap();
        assert!(
            user_body.contains("Include"),
            "Include not injected into user config: {user_body}"
        );
    }

    /// When config_management is disabled, `regenerate_with` is a no-op — the
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
        let fake_home_path = fake_home.path().to_owned();
        let env = |k: &str| -> Option<String> {
            if k == "HOME" || k == "USERPROFILE" {
                Some(fake_home_path.to_string_lossy().into_owned())
            } else {
                std::env::var(k).ok()
            }
        };

        crate::ssh::config::regenerate_with(&paths, &["foo".into()], &env).unwrap();
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
                builder: false,
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

    /// Kills the "replace `!=` with `==`" mutant in `adopt`'s egress-rebind
    /// guard: a STOPPED sandbox (config.json present, no live pid — the
    /// mutant's flipped condition would treat it as live and bind an egress
    /// listener for it) must come out of adoption with NO egress listener
    /// bound and no `vsock.sock_1027` file in either runtime-dir layout.
    /// (The running side of the guard — that a live sandbox DOES get its
    /// listener rebound on adoption — is covered by
    /// `stop_removes_legacy_egress_listener_of_adopted_sandbox` and
    /// `rm_force_removes_legacy_egress_listener_of_adopted_sandbox`, which
    /// both call `d.egress.ensure_listening` directly to simulate exactly
    /// what adoption does for a live sandbox, then assert the listener is
    /// live before tearing it down.)
    #[test]
    fn adopt_does_not_bind_egress_for_a_stopped_sandbox() {
        use crate::daemon::egress;
        let (dir, d) = test_daemon();
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
                builder: false,
            },
        )
        .unwrap();
        // No write_state call: no state.json ⇒ Liveness::Stopped.

        adopt(&d);

        assert_eq!(
            d.registry.liveness("web"),
            Some(crate::liveness::Liveness::Stopped)
        );
        assert!(
            !d.egress.listening("web"),
            "adoption must not bind an egress listener for a stopped sandbox"
        );
        assert!(
            !egress::listener_path(&d.paths.run_dir("web")).exists(),
            "no vsock.sock_1027 in the new-scheme run dir"
        );
        assert!(
            !egress::listener_path(&d.paths.legacy_run_dir("web")).exists(),
            "no vsock.sock_1027 in the legacy run dir"
        );
    }

    /// Kills the "replace `run_daemon_with` body with `Ok(())`" mutant: it
    /// actually binds the real daemon socket, adopts, serves the accept
    /// loop, and honors `Shutdown` — none of which happens if the body is a
    /// no-op stub. Real `UnixListener::bind`, so it follows the house
    /// runtime-skip convention (see `full_connect_via_listener` in
    /// `vsock.rs`, `bind_creates_dir_and_replaces_stale_socket` in
    /// `transport.rs`): some sandboxes deny `bind` with EPERM. Locally that
    /// means this test SKIPs; CI's runners (incl. the mutation-gate host)
    /// bind for real and this is what kills the mutant there.
    #[test]
    fn run_daemon_with_actually_serves() {
        let (dir, paths) = test_paths();

        // Pre-probe bind permission on a throwaway socket before starting
        // the daemon thread, so a denied environment skips cleanly instead
        // of the daemon thread returning an opaque bind error.
        let probe_sock = dir.path().join("probe.sock");
        match transport::UdsListener::bind(&probe_sock) {
            Ok(l) => drop(l),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: sandbox denies UnixListener::bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind probe failure: {e}"),
        }
        let _ = std::fs::remove_file(&probe_sock);

        let daemon_paths = paths.clone();
        let handle = std::thread::spawn(move || run_daemon_with(&daemon_paths, test_deps()));

        // Poll for the daemon to actually bind+listen (thread scheduling is
        // not synchronized with us).
        let sock_path = paths.daemon_socket();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut client = loop {
            match UdsStream::connect(&sock_path) {
                Ok(c) => break c,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("could not connect to daemon socket within 5s: {e}"),
            }
        };

        write_frame(
            &mut client,
            &DaemonHello {
                version: "whatever".into(),
                proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
            },
        )
        .unwrap();
        match read_frame::<_, DaemonResponse>(&mut client).unwrap() {
            DaemonResponse::HelloOk { version, proto, .. } => {
                assert_eq!(version, "testv");
                assert_eq!(proto, crate::daemon::proto::DAEMON_PROTO_VERSION);
            }
            other => panic!("expected HelloOk, got {other:?}"),
        }

        write_frame(&mut client, &DaemonRequest::List).unwrap();
        match read_frame::<_, DaemonResponse>(&mut client).unwrap() {
            DaemonResponse::List { sandboxes } => {
                assert!(sandboxes.is_empty(), "fresh data dir has no sandboxes")
            }
            other => panic!("expected List, got {other:?}"),
        }

        write_frame(&mut client, &DaemonRequest::Shutdown).unwrap();
        match read_frame::<_, DaemonResponse>(&mut client).unwrap() {
            DaemonResponse::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        drop(client);

        // Bounded join: Shutdown must make the accept loop exit (server.rs
        // `should_exit`), polled every 100ms — 10s is generous headroom.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(handle.join());
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => panic!("run_daemon_with returned an error: {e:#}"),
            Ok(Err(_)) => panic!("run_daemon_with thread panicked"),
            Err(_) => panic!("run_daemon_with did not exit within 10s of Shutdown"),
        }
    }
}
