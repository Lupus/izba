//! The izbad server: one thread per client connection, dispatching framed
//! `DaemonRequest`s onto the same `sandbox::*` lifecycle functions the
//! daemonless CLI used to call directly. All external effects are seams in
//! [`DaemonDeps`] so unit tests run against socketpair fakes.

use anyhow::{bail, Context};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use izba_proto::{read_frame, write_frame, Response};

use crate::daemon::egress::EgressManager;
use crate::daemon::peercred;
use crate::daemon::proto::{
    DaemonHello, DaemonRequest, DaemonResponse, DaemonStatus, HostDisk, HostResources,
    SandboxDetail, SandboxStats, VolumeDisk,
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

/// What `izba daemon status` needs to describe izbad's upstream trust honestly
/// (#283). `error` is `Some` exactly when izbad ended up with NO extra roots
/// and NO MITM because something failed — which also means every ENFORCING
/// sandbox's HTTP(S) is failing closed. Reporting only `extra_ca_files` would
/// render that state as the benign "webpki roots only", advising the operator
/// to do what they had already done.
#[derive(Debug, Clone)]
struct TrustStatus {
    /// File names loaded from `<data>/trust/extra`, in load order.
    extra_ca_files: Vec<String>,
    /// `"<cause>: <error>"` for the failure that disabled the MITM, if any —
    /// the cause is part of it because CA init, the extra-CA load and the
    /// runtime start fail for very different reasons.
    error: Option<String>,
}

/// The outcome of [`build_mitm_runtime`]: the runtime the egress plane uses,
/// plus the trust posture the operator is shown.
struct MitmInit {
    runtime: Option<Arc<crate::daemon::egress::mitm_runtime::MitmRuntime>>,
    trust: TrustStatus,
}

/// Build the shared MITM tier-1 runtime: load/mint the persistent izba CA, sign
/// per-SNI leaves under it, verify real upstreams against the Mozilla roots plus
/// any host-installed extra roots, and audit every decision. `runtime` is `None`
/// if CA init, the extra-CA load, or the runtime fails — the daemon must still
/// come up (it also serves bare sandboxes that never MITM). With `None`, bare
/// sandboxes keep their transparent direct dial, but an ENFORCING sandbox's
/// HTTP(S) FAILS CLOSED at the router (it is never silently downgraded to a
/// direct dial — see `router::tcp_connect`). The per-sandbox policy travels
/// with each flow, so no policy is needed here.
///
/// Every failure path also records `trust.error`, so `Status` can surface the
/// degradation rather than hiding it behind an empty file list (#283).
fn build_mitm_runtime(paths: &Paths, audit: crate::daemon::egress::audit::AuditSink) -> MitmInit {
    use crate::daemon::egress::mitm::CertCache;
    use crate::daemon::egress::mitm_runtime::MitmRuntime;

    // The MITM datapath signs/verifies with the ring CryptoProvider (aws-lc-rs
    // is also linked via oci-client's reqwest, so an ambiguous process default
    // would panic). Installing it is best-effort: an existing default is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // `what` rides along on the wire: the three causes (CA init, extra-CA
    // load, runtime start) are NOT interchangeable, and dropping it let the
    // CLI report a CA-init or runtime failure as an extra-CA load failure.
    let failed = |what: &str, e: &anyhow::Error| {
        eprintln!("izbad: egress MITM disabled — {what}: {e:#}");
        MitmInit {
            runtime: None,
            trust: TrustStatus {
                extra_ca_files: Vec::new(),
                error: Some(format!("{what}: {e:#}")),
            },
        }
    };

    let ca = match crate::ca::load_or_create(&paths.ca_dir()) {
        Ok(ca) => ca,
        Err(e) => return failed("CA init failed", &e),
    };
    // Extra roots (#283): a corrupt file disables the MITM (enforcing
    // sandboxes then fail closed at the router) rather than silently trusting
    // fewer roots than the operator installed. `sandbox::start` refuses with
    // the same error, so the user sees it on the very next command.
    let extra = match crate::trust::load_extra_cas(&paths.trust_extra_dir()) {
        Ok(extra) => extra,
        Err(e) => return failed("extra CA load failed", &e),
    };
    let extra_names: Vec<String> = extra.iter().map(|f| f.name.clone()).collect();
    // Logged unconditionally (a zero count is worth a line too: it tells the
    // operator reading the daemon log that the directory was consulted).
    eprintln!(
        "izbad: extra CA files loaded from {}: {} [{}]",
        paths.trust_extra_dir().display(),
        extra_names.len(),
        extra_names.join(", ")
    );
    let certs = Arc::new(CertCache::new(ca));
    match MitmRuntime::start(certs, crate::trust::upstream_client_config(&extra), audit) {
        Ok(rt) => MitmInit {
            runtime: Some(Arc::new(rt)),
            trust: TrustStatus {
                extra_ca_files: extra_names,
                error: None,
            },
        },
        Err(e) => failed("runtime start failed", &e),
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
/// USB grants needs a different kernel image than one that does not, and
/// `vnc` because a VNC-enabled sandbox additionally requires the KasmVNC
/// bundle (fail-closed: locate bails when `vnc` is true and it is missing).
pub type ArtifactsFn = Box<
    dyn Fn(&Paths, crate::artifacts::KernelVariant, bool) -> anyhow::Result<Artifacts>
        + Send
        + Sync,
>;

/// Seam over `image::ensure_image`: image ref → digest (pulling if needed).
pub type ResolveImageFn = Box<dyn Fn(&Paths, &str) -> anyhow::Result<String> + Send + Sync>;

/// Injectable usbipd probe. Production spawns `usbipd.exe`; tests hand over a
/// fixed table, which is the only way the handlers' *use* of it is observable.
pub type UsbipdProbeFn =
    Box<dyn Fn() -> Option<Vec<crate::usb::usbipd_state::UsbipdDevice>> + Send + Sync>;

/// Injectable seams: production wiring in [`DaemonDeps::production`], fakes
/// in tests (mirrors the `Connector` convention in sandbox.rs).
pub struct DaemonDeps {
    pub version: String,
    pub driver: Box<dyn VmmDriver + Send + Sync>,
    pub connector: SharedConnector,
    pub stream_connector: SharedStreamConnector,
    pub artifacts: ArtifactsFn,
    pub resolve_image: ResolveImageFn,
    pub usbipd_probe: UsbipdProbeFn,
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
            usbipd_probe: Box::new(crate::usb::usbipd_state::probe),
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
    /// The VNC display relay plane, DELIBERATELY a second `RelayManager`
    /// rather than more entries in `relays` (spec 2026-08-09 §5). The VNC
    /// relay is derived per-start state on an ephemeral port: it must never
    /// reach `ports.json`, and `handle_port_publish`/`handle_port_unpublish`
    /// persist `relays.active(name)` WHOLESALE. Sharing one map would leak a
    /// `guest_port: 6901` rule into a user's persisted ports the first time
    /// they published anything — the separation IS the firewall, so keep
    /// these two managers apart (guard test:
    /// `vnc_relay_never_persists_into_ports_json`).
    pub vnc_relays: RelayManager,
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
    /// Ephemeral per-sandbox CPU sample cache for `Stats` (#203). NOT
    /// authoritative disk state — see [`StatsCpuCache`]'s own doc. Linux-only:
    /// the host CPU/RSS tier itself is Linux-only (`/proc`), so a build for
    /// any other target would otherwise carry a permanently-unread field.
    #[cfg(target_os = "linux")]
    stats_cpu: StatsCpuCache,
    /// Upstream trust posture as of daemon start (#283), for `Status`: the
    /// extra-CA files loaded, or why none were. Not authoritative state — a
    /// display record of what THIS process trusts; a changed directory needs
    /// a daemon restart.
    trust: TrustStatus,
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
        let trust = mitm.trust;
        let usb = crate::usb::broker::UsbBroker::new(audit.clone());
        let egress = EgressManager::new(Arc::clone(&deps.egress_resolver), mitm.runtime, audit);
        Self {
            paths,
            deps,
            registry: Registry::new(),
            relays: RelayManager::new(),
            vnc_relays: RelayManager::new(),
            egress,
            usb,
            starting: StartsInFlight::new(),
            started: Instant::now(),
            active_conns: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            idle_since: Mutex::new(Instant::now()),
            #[cfg(target_os = "linux")]
            stats_cpu: StatsCpuCache::default(),
            trust,
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

/// The daemon-log line for a rejected control connection, or `None` when the
/// peer was allowed. Pure so the accept loop's decision is testable without
/// binding a listener.
fn peer_denial_log(verdict: peercred::PeerVerdict) -> Option<String> {
    match verdict {
        peercred::PeerVerdict::Allow(_) => None,
        peercred::PeerVerdict::Deny {
            peer_uid,
            owner_uid,
        } => Some(format!(
            "izbad: control connection from uid {peer_uid} rejected \
             (daemon runs as uid {owner_uid}); izba must run as the daemon's owner"
        )),
    }
}

/// The startup report line for unix-socket peer authentication mode, or
/// `None` when there is nothing to report. Derived from `enforcement_mode()`,
/// the SAME predicate the accept loop's `authorize_stream` call uses, so this
/// line can never claim "enforced" on a platform where the accept loop
/// actually can't (F-09). Pure like `peer_denial_log`, so the startup report
/// is testable without binding a listener.
///
/// It covers the two peer-authoritative unix planes the one
/// `enforcement_mode()` predicate governs — the control socket and the
/// per-sandbox egress listeners (`daemon::egress`, F-CRED-5). Naming only the
/// control socket would leave an operator on an unenforced platform to INFER
/// the egress posture, which is the reported-vs-implied gap this line closes.
///
/// Two things this line must keep being careful about, both of which a
/// well-meaning tightening of the wording has already got wrong once:
///
/// * **It is read as an INVENTORY.** izbad binds a THIRD peer-authoritative
///   unix listener per sandbox — the USB broker on `vsock.sock_1028`
///   (`crate::usb::broker`) — with no peer check on either platform. Listing
///   "control + egress" and stopping there tells an operator that every izbad
///   unix socket is gated, which is worse than printing nothing. So the line
///   names the broker as the plane it does NOT cover; `peer_auth_mode_line_
///   does_not_imply_the_usb_broker_is_covered` pins that. Adding a peer check
///   there is deliberately out of scope for F-CRED-5 — but if one ever lands,
///   this line has to move with it.
/// * **It must not claim a protection izba never applied.** The unenforced
///   platform is Windows, and there no izba code path *hardens* these sockets:
///   `paths::create_dir_700`, the egress chmod and `transport::bind_socket`'s
///   chmod are all `#[cfg(unix)]`. "Gated by directory permissions only" read
///   as a claim that izba had gated them; in fact they inherit the
///   `%LOCALAPPDATA%` profile DACL, which izba does not author.
///
///   Do not over-correct that into "izba touches no ACL here" — it does, and
///   in the widening direction, so the line must not imply an izba-applied
///   restriction either. `VmSpec::confined_write_surfaces` includes the run
///   dir, so every default Windows start stamps it (and by inheritance the
///   egress and USB sockets in it) with a **Low** mandatory-integrity label so
///   the Low-IL VMM can write at all; and `izba lockdown` grants the
///   per-sandbox `izba-sb-<name>` account an inheritable Modify ACE on that
///   same dir (`jail_account::orchestrate::compute_grants`). Both widen.
fn peer_auth_mode_line() -> Option<String> {
    match peercred::enforcement_mode() {
        peercred::PeerAuth::Enforced => {
            // `owner_uid()` is `Some` whenever `enforcement_mode()` is
            // `Enforced` (see its doc comment).
            peercred::owner_uid().map(|uid| {
                format!(
                    "izbad: unix-socket peer authentication enforced (uid {uid}) \
                     — control socket + per-sandbox egress listeners; the \
                     per-sandbox USB broker socket is not covered"
                )
            })
        }
        peercred::PeerAuth::Unavailable => Some(
            "izbad: unix-socket peer authentication UNAVAILABLE on this platform \
             — the control socket and the per-sandbox egress listeners accept any \
             local peer that can open them; izba never hardens their permissions \
             here, so they inherit their containing directory's ACL; the \
             per-sandbox USB broker socket is not covered on any platform"
                .to_string(),
        ),
    }
}

/// One accept-loop iteration: accept a connection, authenticate its peer,
/// and hand it to a fresh handler thread — or log/sleep on a transient
/// accept error. Split out of `run_daemon_with` purely for readability;
/// every `continue` in the original loop body becomes a `return` here, which
/// has the same effect (the caller's loop immediately re-evaluates
/// `should_exit` and calls this again).
///
/// ORDERING IS LOAD-BEARING (F-09): the peer check runs AFTER
/// `set_nonblocking` succeeds and BEFORE `ConnGuard::new` is constructed.
/// Rejecting after the guard exists would corrupt the daemon's idle-exit
/// connection accounting; rejecting before the nonblocking guard would let
/// an unauthorized connection cost a blocking `accept`-thread turn. An
/// unauthorized connection must cost no thread and read no frame — dropping
/// `stream` closes it and the client sees EOF.
fn accept_and_dispatch(listener: &transport::UdsListener, d: &Arc<Daemon>) {
    match listener.accept() {
        Ok((stream, _peer)) => {
            if stream.set_nonblocking(false).is_err() {
                return;
            }
            if let Some(line) = peer_denial_log(peercred::authorize_stream(&stream)) {
                eprintln!("{line}");
                return;
            }
            // Count the connection NOW (see ConnGuard) so the next
            // should_exit() already observes it.
            let guard = ConnGuard::new(Arc::clone(d));
            let d = Arc::clone(d);
            std::thread::spawn(move || handle_connection(&d, stream, guard));
        }
        Err(e) => {
            if let Some(line) = accept_error_message(&e) {
                eprintln!("{line}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The diagnostic for an `accept()` error, or `None` when the error is the
/// benign non-blocking retry. Pure so the classification is testable without
/// binding a listener.
fn accept_error_message(e: &std::io::Error) -> Option<String> {
    (e.kind() != std::io::ErrorKind::WouldBlock).then(|| format!("izbad: accept error: {e}"))
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
        DaemonRequest::Stats { name } => handle_stats(d, name),
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
            extra_ca_files: d.trust.extra_ca_files.clone(),
            trust_error: d.trust.error.clone(),
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
        DaemonRequest::VncSet { name, enabled } => handle_vnc_set(d, name, enabled),
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

/// The OCI image label sbx uses to mark engine-bearing images; izba honors it
/// for sbx parity (spec §1).
pub const START_DOCKER_LABEL: &str = "com.docker.sandboxes.start-docker";

/// Resolve the sandbox's docker mode: an explicit CLI choice wins; otherwise
/// the image label enables it iff its value is exactly "true"; otherwise off.
pub fn resolve_docker_mode(
    cli: Option<bool>,
    labels: Option<&std::collections::HashMap<String, String>>,
) -> bool {
    match cli {
        Some(v) => v,
        None => labels
            .and_then(|l| l.get(START_DOCKER_LABEL))
            .is_some_and(|v| v == "true"),
    }
}

fn handle_create(
    d: &Arc<Daemon>,
    c: crate::daemon::proto::DaemonCreate,
    progress: &mut dyn FnMut(String),
) -> anyhow::Result<DaemonResponse> {
    crate::volume::validate_volumes(&c.volumes, c.vnc)?;
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
    // Docker mode is a create-time decision (spec §1): the CLI's explicit choice
    // wins, else the sbx start-docker label. Builder sandboxes never get docker
    // mode — the privileged builder profile skips the userns docker mode
    // depends on, so the combination is contradictory; builder wins silently
    // (it is set only by `izba build`, never user-visible).
    let docker = if c.builder {
        false
    } else {
        let cfg = crate::image::store::ImageStore::new(&d.paths)
            .load_config(&digest)
            .ok()
            .flatten();
        resolve_docker_mode(
            c.docker,
            cfg.as_ref()
                .and_then(|f| f.config.as_ref())
                .and_then(|cc| cc.labels.as_ref()),
        )
    };
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
            docker,
            vnc: c.vnc,
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
    // #234: this line used to announce a start unconditionally, so a redundant
    // `izba start`/`izba run` against a sandbox that is already up printed
    // "starting '<name>'..." for a (re)start that never happened — and
    // `run --policy` leaned on that false claim to explain when an edited
    // allow-list would take effect. Probe first and say which of the two is
    // actually about to occur, mirroring `sandbox::start`'s own refusal
    // predicate (anything other than `Stopped` is an `AlreadyRunning`).
    //
    // The probe is NOT the authority — the flock + re-check inside
    // `sandbox::start` still is, and a sandbox can die between the two — so a
    // lost race costs a slightly-stale progress line, never correctness.
    let live = sandbox::liveness_of(&d.paths, &name, d.connector()).unwrap_or(Liveness::Stopped);
    progress(match &live {
        Liveness::Stopped => format!("starting '{name}'..."),
        Liveness::Running => format!("'{name}' is already running — not restarting it"),
        Liveness::Degraded(why) => {
            format!("'{name}' is already up but degraded ({why}) — not restarting it")
        }
    });
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
    // A VNC-enabled sandbox additionally needs the KasmVNC erofs bundle;
    // `artifacts::locate` fails closed when it's requested but missing.
    let vnc = config.vnc;
    let art = (d.deps.artifacts)(&d.paths, variant, vnc)?;
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
    // Every bail-out below leaves NO plane of this sandbox armed, the VNC
    // relay included: each of these failures means the sandbox is not (and is
    // not becoming) live — `ensure_socket_budget` fails on a static property
    // of the data root, and `ensure_listening` is idempotent, so it can only
    // fail for a sandbox that has no listener, i.e. no live run. A relay still
    // held for this name is therefore a previous run's leftover, and leaving
    // it would keep a host port open onto a dead guest.
    if let Err(e) = crate::paths::ensure_socket_budget(&d.paths, &name) {
        d.vnc_relays.stop_all(&name);
        return Err(e);
    }
    if let Err(e) = d
        .egress
        .ensure_listening(&d.paths, &name, &d.paths.run_dir(&name))
    {
        d.vnc_relays.stop_all(&name);
        return Err(e);
    }
    // Same dir, same moment: a granted sandbox must have its USB plane up
    // before the guest boots and dials it. On failure the egress listener bound
    // just above is torn down too, so the two planes are armed and disarmed
    // together rather than leaving one behind for the supervisor to reap.
    if let Err(e) = d.usb.refresh(&d.paths, &name, &d.paths.run_dir(&name)) {
        d.egress.stop(&name, &d.paths.run_dir(&name));
        d.vnc_relays.stop_all(&name);
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
            // …and re-publish a MISSING VNC relay for a run that booted with
            // one. This is the documented recovery path: when the publish
            // below fails, the start errors out with "re-run `izba start`",
            // and a repeat start on a live sandbox lands exactly here. Keyed
            // on the BOOTED fact (state.json), never on `config.vnc`: a `vnc
            // on` since boot has no desktop to reach yet (that is what
            // `vnc_restart_required` reports).
            if booted_with_vnc(&d.paths, &name) && d.vnc_relays.active(&name).is_empty() {
                match publish_vnc_relay(d, &name) {
                    Ok(port) => progress(format!("vnc: http://127.0.0.1:{port}/")),
                    Err(pe) => progress(format!("warning: VNC relay still unavailable: {pe:#}")),
                }
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
        // The VNC relay of a previous run of this name (if the daemon still
        // holds one) dies with the same failure, so a failed start leaves no
        // plane of this sandbox half-armed.
        d.vnc_relays.stop_all(&name);
        return Err(e);
    }
    // (Re-)apply the persisted publish rules afresh, as threads.
    d.relays.stop_all(&name);
    d.vnc_relays.stop_all(&name);
    for rule in &config.ports {
        if let Err(e) = d.relays.publish(&d.paths, &name, rule.clone()) {
            progress(format!(
                "warning: not publishing {}:{}: {e:#}",
                rule.bind, rule.host_port
            ));
        }
    }
    d.relays.save_active(&d.paths, &name)?;
    // The VNC display relay: an EPHEMERAL loopback port onto the guest's
    // KasmVNC endpoint, created per start and never persisted (it lives in
    // the separate `vnc_relays` manager, so the `save_rules` call above
    // cannot see it). Unlike a user's published port, a failure here is not
    // a warning: a `--vnc` sandbox whose desktop is unreachable from the host
    // is a silently useless sandbox, so fail the start loudly rather than
    // degrade. The VM itself IS up at this point, which is why the message
    // names the retry: a repeat `izba start` hits the already-running branch
    // above, which re-publishes a missing relay.
    if config.vnc {
        let port = publish_vnc_relay(d, &name).with_context(|| {
            format!(
                "publishing the VNC display relay (the sandbox is running; \
                 re-run `izba start {name}` to retry just the relay)"
            )
        })?;
        progress(format!("vnc: http://127.0.0.1:{port}/"));
    }
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
    // The VNC relay is per-run derived state: it dies with the run that
    // created it (a fresh ephemeral port is allocated by the next start).
    d.vnc_relays.stop_all(&name);
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
    d.vnc_relays.stop_all(&name);
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
    // Same "is this run actually live" predicate `handle_usb_status` uses, so
    // the two answers can never disagree about the same sandbox.
    let running = d.registry.liveness(&name).unwrap_or(Liveness::Stopped) != Liveness::Stopped;
    let booted_vnc = run_state.as_ref().map(|s| s.vnc).unwrap_or(false);
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
    // The VNC display: the ephemeral relay this run published (host port), and
    // whether the guest's KasmVNC endpoint behind it actually answers. Both
    // are keyed on the RELAY (and the run being live), NEVER on `config.vnc`:
    // `vnc off` on a live sandbox flips config immediately but cannot unmake
    // the desktop it booted with (that is what `vnc_restart_required` says),
    // so a config-keyed answer would report "not running" next to a URL that
    // still works — the reachability question is about the RUN, not the
    // config. `vnc_port.is_some()` short-circuits a plain sandbox at zero
    // cost, so no dial is spent on one.
    //
    // `vnc_url` follows the relay + the host-only password: a URL is the right
    // thing to hand a user whose desktop is merely still coming up, but a
    // STOPPED sandbox's lingering relay must not advertise one. `vnc_running`
    // costs one bounded dial with the same budget/degrade posture as the
    // container probe above (any failure ⇒ `false`, never an error).
    let vnc_port = if running {
        d.vnc_relays.active(&name).first().map(|r| r.host_port)
    } else {
        None
    };
    let vnc_running = vnc_port.is_some() && probe_vnc_endpoint(d, &name, CONTAINER_PROBE_TIMEOUT);
    let vnc_url = vnc_port.and_then(|port| {
        crate::vnc::read_password(&d.paths, &name)
            .ok()
            .map(|pw| format!("http://izba:{pw}@127.0.0.1:{port}/"))
    });
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
        docker: config.docker,
        vnc: config.vnc,
        vnc_running,
        vnc_url,
        vnc_restart_required: needs_vnc_restart(config.vnc, running, booted_vnc),
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

/// Best-effort liveness probe of the guest's KasmVNC endpoint: one bounded
/// `StreamOpen::TcpDial{6901}` through the sandbox's stream port, closed
/// immediately. `true` only when the guest answers `Response::Ok`, i.e. it
/// really did connect to a listening `127.0.0.1:6901` inside the guest — a
/// dead desktop stays dead and is reported as such (no auto-restart, same
/// posture as a dead dockerd). Every failure mode (stream port unreachable,
/// wedged guest, `Error{ConnectFailed}`, junk reply) maps to `false`.
/// (In docker mode the guest-side dial reaches the container's wildcard
/// listener via the `192.168.127.2` veth fallback instead of loopback — same
/// TcpDial contract either way.)
///
/// Uses the SAME `StreamOpen::TcpDial` contract as `portfwd::relay_one`, so
/// what this probes is exactly what the relay in front of it does.
fn probe_vnc_endpoint(d: &Arc<Daemon>, name: &str, timeout: Duration) -> bool {
    let Ok(mut s) = (d.deps.stream_connector)(&d.paths, name) else {
        return false;
    };
    if s.set_io_timeout(Some(timeout)).is_err() {
        return false;
    }
    let answered = write_frame(
        &mut s,
        &izba_proto::StreamOpen::TcpDial {
            port: crate::vnc::WEBSOCKET_PORT,
        },
    )
    .is_ok()
        && matches!(read_frame::<_, Response>(&mut s), Ok(Response::Ok));
    // Full teardown once we're done talking: CH does not propagate a vsock
    // half-close guest→host (the load-bearing contract), so never leave this
    // probe's connection half-open.
    let _ = s.shutdown(std::net::Shutdown::Both);
    answered
}

/// Ephemeral per-sandbox CPU sample cache. NOT authoritative state (the
/// disk-state invariant is untouched): losing it costs exactly one `None`
/// cpu_permille sample. Keyed by PidIdentity so a restarted VMM (same pid,
/// different starttime) never splices two processes' tick counters.
///
/// Linux-only, like the whole host CPU/RSS tier it backs (`/proc`-derived) —
/// see `host_resources`'s `#[cfg(target_os = "linux")]` split.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct StatsCpuCache {
    inner: Mutex<HashMap<String, (crate::state::PidIdentity, u64, Instant)>>,
}

#[cfg(target_os = "linux")]
impl StatsCpuCache {
    /// Record `ticks` for `name`/`id` at `now`; returns cpu_permille vs the
    /// previous sample when identities match, else None.
    fn observe(
        &self,
        name: &str,
        id: &crate::state::PidIdentity,
        ticks: u64,
        now: Instant,
    ) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let prev = inner.insert(name.to_string(), (id.clone(), ticks, now));
        let (pid, pticks, pat) = prev?;
        if pid != *id {
            return None;
        }
        let elapsed_ms = now.duration_since(pat).as_millis() as u64;
        cpu_permille(pticks, ticks, elapsed_ms, host_clk_tck())
    }
}

/// permille of one CPU given a tick delta over `elapsed_ms`. None on zero
/// elapsed or non-monotonic ticks (an honest gap beats a junk spike).
#[cfg(target_os = "linux")]
fn cpu_permille(prev_ticks: u64, ticks: u64, elapsed_ms: u64, clk_tck: u64) -> Option<u32> {
    if elapsed_ms == 0 || ticks < prev_ticks {
        return None;
    }
    let delta = ticks - prev_ticks;
    Some((delta.saturating_mul(1_000_000) / clk_tck.max(1).saturating_mul(elapsed_ms)) as u32)
}

#[cfg(target_os = "linux")]
fn host_clk_tck() -> u64 {
    use nix::libc;
    // SAFETY: sysconf is async-signal-safe and takes no pointers.
    (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as u64
}

/// utime+stime (fields 14+15) from a /proc/<pid>/stat line.
#[cfg(target_os = "linux")]
fn vmm_ticks_from_stat(line: &str) -> Option<u64> {
    let close = line.rfind(')')?;
    let rest: Vec<&str> = line[close + 1..].split_ascii_whitespace().collect();
    Some(rest.get(11)?.parse::<u64>().ok()? + rest.get(12)?.parse::<u64>().ok()?)
}

/// VmRSS from /proc/<pid>/status.
#[cfg(target_os = "linux")]
fn rss_kb_from_status(s: &str) -> Option<u64> {
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Guest Stats probe deadline — same wedged-guest discipline as
/// CONTAINER_PROBE_TIMEOUT, plus headroom for the in-guest 250 ms sampling.
const STATS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn handle_stats(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    let config: SandboxConfig = load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
        .with_context(|| format!("no such sandbox '{name}'"))?;
    let liveness = d.registry.liveness(&name).unwrap_or(Liveness::Stopped);
    let running = liveness != Liveness::Stopped;
    let run_state = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?;
    let disk = host_disk(&d.paths, &name, &config);
    let (host, uptime_ms) = if running {
        match &run_state {
            Some(rs) => (
                host_resources(d, &name, &config, &rs.vmm_pid),
                Some(crate::usb::now_unix_ms().saturating_sub(rs.started_unix_ms)),
            ),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let guest = if running {
        probe_guest_stats(d, &name, STATS_PROBE_TIMEOUT)
            .map(crate::daemon::stats::sanitize_guest_stats)
    } else {
        None
    };
    Ok(DaemonResponse::Stats(SandboxStats {
        name,
        running,
        uptime_ms,
        host,
        disk,
        guest,
    }))
}

/// Best-effort guest Stats fetch, probe-shaped like probe_container_state:
/// any failure (unreachable, wedged, pre-stats guest replying Error or
/// dropping the conn) degrades to None, never an error or a hang.
fn probe_guest_stats(
    d: &Arc<Daemon>,
    name: &str,
    timeout: Duration,
) -> Option<izba_proto::GuestStats> {
    let mut conn = sandbox::control(&d.paths, name, d.connector()).ok()?;
    conn.set_io_timeout(Some(timeout)).ok()?;
    write_frame(&mut conn, &izba_proto::Request::Stats).ok()?;
    match read_frame::<_, Response>(&mut conn).ok()? {
        Response::Stats(g) => Some(g),
        _ => None,
    }
}

/// Trusted host-tier resources; Linux-only (/proc). PidIdentity is
/// re-verified first so a recycled pid can never be read as the VMM.
#[cfg(target_os = "linux")]
fn host_resources(
    d: &Arc<Daemon>,
    name: &str,
    config: &SandboxConfig,
    id: &crate::state::PidIdentity,
) -> Option<HostResources> {
    if !crate::procmgr::pid_alive(id) {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", id.pid)).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{}/status", id.pid)).ok()?;
    let ticks = vmm_ticks_from_stat(&stat)?;
    let rss_kb = rss_kb_from_status(&status)?;
    let cpu_permille = d.stats_cpu.observe(name, id, ticks, Instant::now());
    Some(HostResources {
        cpu_permille,
        rss_kb,
        cpus_limit: config.cpus,
        mem_limit_mb: config.mem_mb,
    })
}
#[cfg(not(target_os = "linux"))]
#[mutants::skip] // reason: constant one-line stub whose only property (always None — the Windows host tier is spec §9 out-of-scope) is pinned by host_resources_stub_is_always_none on the platform that compiles it. The gate cannot kill mutants here: on Linux the body is cfg'd out (phantom miss), and on Windows the generated `Some(Default::default())` doesn't compile (unviable), which the caught-nowhere reconciler counts as a survivor.
fn host_resources(
    _d: &Arc<Daemon>,
    _name: &str,
    _config: &SandboxConfig,
    _id: &crate::state::PidIdentity,
) -> Option<HostResources> {
    None // Windows host tier is spec §9 out-of-scope; guest+disk tiers still work.
}

/// Host-disk breakdown; sparse-aware via allocated_bytes; works stopped.
/// image_bytes is the content-addressed rootfs.erofs — SHARED between
/// sandboxes on the same image, reported separately, never summed into the
/// per-sandbox footprint by consumers.
fn host_disk(paths: &Paths, name: &str, config: &SandboxConfig) -> HostDisk {
    let alloc = |p: &std::path::Path| {
        std::fs::metadata(p)
            .map(|m| crate::sandbox::allocated_bytes(&m))
            .unwrap_or(0)
    };
    let rw_img_bytes = alloc(&paths.sandbox_dir(name).join("rw.img"));
    let volumes = config
        .volumes
        .iter()
        // Ephemeral volumes get their eph_id at provision time (assign_eph_ids,
        // run before config.json is ever persisted); a spec with neither a name
        // nor an eph_id would panic VolumeSpec::image_path. Skip it defensively
        // rather than crash the daemon on a request that is otherwise read-only.
        .filter(|v| v.name.is_some() || v.eph_id.is_some())
        .map(|v| VolumeDisk {
            guest_path: v.guest_path.display().to_string(),
            allocated_bytes: alloc(&v.image_path(paths, name)),
            docker: crate::volume::is_docker_volume_path(&v.guest_path),
        })
        .collect();
    let logs_bytes = std::fs::read_dir(paths.logs_dir(name))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| crate::sandbox::allocated_bytes(&m))
                .sum()
        })
        .unwrap_or(0);
    let image_bytes = alloc(&paths.image_dir(&config.image_digest).join("rootfs.erofs"));
    HostDisk {
        rw_img_bytes,
        volumes,
        logs_bytes,
        image_bytes,
    }
}

fn handle_guest_rpc(
    d: &Arc<Daemon>,
    name: String,
    req: izba_proto::Request,
) -> anyhow::Result<DaemonResponse> {
    // Stats must never cross the daemon boundary raw: GuestStats carries
    // hostile-guest-controlled strings/lists that only `sanitize_guest_stats`
    // (crate::daemon::stats) is allowed to touch, and that sanitizer has
    // exactly one call site — the dedicated Stats handler. Refuse here rather
    // than proxy, so a client can never bypass sanitization by wrapping
    // Request::Stats in a GuestRpc.
    if matches!(req, izba_proto::Request::Stats) {
        bail!("use DaemonRequest::Stats, not GuestRpc, to fetch sandbox stats (sanitized path)");
    }
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
    let bound_here = !d.relays.active(&name).contains(&rule);
    if bound_here {
        d.relays.publish(&d.paths, &name, rule.clone())?;
    }
    d.relays.save_active(&d.paths, &name)?;
    if persist {
        // The live effects above land BEFORE this, and taking the per-sandbox
        // lock (#181) turned this step from "fails only on I/O error" into
        // "fails routinely under contention". Without compensation the request
        // would report failure while the port is actually forwarding — and the
        // rule would then vanish at the next start, since config.json never
        // got it. So undo exactly what THIS request did: a relay that was
        // already live is not ours to tear down (that is the "Make persistent"
        // path, where the port must keep working).
        if let Err(e) = persist_port_rule(&d.paths, &name, &rule) {
            // "I bound it" is NOT "I own it". A sibling publish of the same
            // rule that arrived after our bind saw it already active, adopted
            // it, and may have persisted it successfully while our own persist
            // was losing the lock. Tearing the relay down then would hand that
            // caller a port that is neither forwarding nor recorded — worse
            // than the leak we are compensating for. So the relay is ours to
            // remove only while config.json still does NOT list the rule.
            //
            // A read failure here means we cannot tell, and the two mistakes
            // are not symmetric: a leaked relay is recoverable with `izba port
            // unpublish`, destroying a sibling's live port is not. Keep the
            // relay and say so.
            //
            // Hold the per-sandbox lock across the decision AND the teardown
            // when it is free: persisting requires that same lock, so holding
            // it makes "nobody has persisted this" true for the whole window
            // rather than just at the instant of the read.
            //
            // A single `try_lock`, deliberately — no retry, no block. We are on
            // this path precisely BECAUSE the lock was contended, so waiting
            // for it would mean the common case (the one that leaves a port
            // forwarding after a failed publish) stops rolling back at all.
            // When it is still held we fall back to the unlocked read, which is
            // the same check a moment earlier: a narrower window than the leak
            // it replaces, and it fails toward keeping the relay.
            let _decision_guard = crate::sandbox::lock_sandbox(&d.paths, &name).ok();
            let ours_to_remove = match rule_is_persisted(&d.paths, &name, &rule) {
                Ok(persisted) => !persisted,
                Err(read_err) => {
                    return Err(e).with_context(|| {
                        format!(
                            "left the relay for {bind}:{port} up: could not read config.json to \
                             tell whether another request had already persisted it ({read_err:#}). \
                             Re-run `izba port unpublish {bind}:{port}` if it is unwanted",
                            bind = rule.bind,
                            port = rule.host_port,
                        )
                    });
                }
            };
            if bound_here && ours_to_remove {
                // The compensation can fail too, and swallowing that would be
                // the same false-success shape #181 is about, one level down:
                // the caller is told the publish failed while the port is in
                // fact still forwarding. Say so, and name the recovery.
                if let Err(note) = rollback_published_relay(d, &name, &rule) {
                    return Err(e).with_context(|| {
                        format!(
                            "rolling back the relay for {bind}:{port} also failed — {note}; \
                             re-run `izba port unpublish {bind}:{port}` once the sandbox is idle",
                            bind = rule.bind,
                            port = rule.host_port,
                        )
                    });
                }
            }
            return Err(e);
        }
    }
    Ok(DaemonResponse::Ok)
}

/// Does `config.json` currently list this rule? The rollback's ownership test:
/// a rule some request has already persisted is not ours to tear down, however
/// it got there.
fn rule_is_persisted(
    paths: &Paths,
    name: &str,
    rule: &crate::state::PortRule,
) -> anyhow::Result<bool> {
    let p = paths.sandbox_dir(name).join(CONFIG_FILE);
    let cfg: SandboxConfig = load_json(&p)?.with_context(|| format!("no config for '{name}'"))?;
    Ok(cfg
        .ports
        .iter()
        .any(|r| r.bind == rule.bind && r.host_port == rule.host_port))
}

/// Undo a relay this request bound, after its config write was refused.
///
/// Split out from `handle_port_publish` so BOTH of its failure modes are
/// directly testable — the branch only reachable when compensation fails is
/// exactly the one that must not be silent. `Err` carries a human-facing note
/// describing what is still live, never a swallowed error.
fn rollback_published_relay(
    d: &Arc<Daemon>,
    name: &str,
    rule: &crate::state::PortRule,
) -> Result<(), String> {
    d.relays
        .unpublish(name, rule.bind, rule.host_port)
        .map_err(|e| format!("the relay is still forwarding ({e:#})"))?;
    // Only worth rewriting once the relay is actually gone: while the unpublish
    // is failing the rule is still in `active`, so a rewrite would put it right
    // back. A rule left in ports.json outlives the request — `adopt`
    // re-publishes from that file, so a daemon restart would resurrect a port
    // the caller was told had failed.
    d.relays.save_active(&d.paths, name).map_err(|e| {
        format!("ports.json still lists it, so a daemon restart would re-adopt it ({e:#})")
    })
}

fn handle_port_unpublish(
    d: &Arc<Daemon>,
    name: String,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> anyhow::Result<DaemonResponse> {
    sandbox_must_exist(&d.paths, &name)?;
    // ports.json is DERIVED state, so reconcile it to the live relay set
    // whenever it still lists this rule — not only when a relay was just torn
    // down (#181). A failed publish rollback can strand a rule there with no
    // live relay and nothing in config.json, and `adopt` republishes every
    // ports.json rule of a running sandbox — so that entry would resurrect the
    // port on the next daemon restart. This command is what the rollback's
    // error message tells the user to run, so it has to be able to clear it.
    //
    // Read it FIRST, and propagate. It is the one fallible step here that has
    // no side effect of its own, so running it before the config write is what
    // keeps a failure from stripping config.json and returning Ok. And a read
    // error is NOT absence: `load_rules_migrating` already maps a missing file
    // to an empty list, so the only cases reaching the error arm are a file
    // that cannot be read or matches neither schema — exactly the cases where
    // reporting "no such published port" would be a lie, since the rule may
    // still be on disk for `adopt` to republish once the file is readable.
    //
    // The list is scoped to this block ON PURPOSE: it is a PROBE, not data to
    // write back. Carrying it down to the reconcile below would make that a
    // read-modify-write over a snapshot taken before the two steps in between,
    // so a concurrent port operation landing in that window would be erased by
    // the write — the very shape this PR exists to remove, reintroduced one
    // file over. The reconcile re-reads.
    let stranded_in_rules = {
        let (persisted_rules, _) = relays::load_rules_migrating(&d.paths, &name)?;
        persisted_rules
            .iter()
            .any(|r| r.bind == bind && r.host_port == host_port)
    };
    // Always drop the persisted rule from config — works even when the sandbox
    // is stopped (the relay map has no entry), so a persisted-only port can be
    // removed. (Greptile P1.)
    let unpersisted = unpersist_port_rule(&d.paths, &name, bind, host_port)?;
    // Tear down a live relay if one exists; a missing relay (stopped sandbox /
    // post-restart) is NOT an error.
    let relay_removed = d.relays.unpublish(&name, bind, host_port).is_ok();
    if relay_removed {
        d.relays.save_active(&d.paths, &name)?;
    } else if stranded_in_rules {
        // Drop just THIS rule rather than overwriting with the live set: no
        // relay was torn down, so for a stopped sandbox that set is empty and
        // an overwrite would take the neighbouring entries with it. They are
        // not inert — `relays::persisted_host_ports` reads every sandbox's
        // ports.json to pick a VNC display port that avoids persisted fixed
        // rules (#221), so discarding them narrows that avoidance set.
        //
        // This is the ONLY ports.json writer that must read the file to decide
        // what to write — every other one overwrites it wholesale from
        // `RelayManager::active`, the in-memory authority. So it does the
        // read-modify-write inside `relays`, under the lock that serializes it
        // against those writers; doing it here, unguarded, would erase a
        // publish that landed between the read and the write.
        // On the manager, not free-standing: it re-checks liveness inside the
        // same guard, so a publish of this very rule that raced the probe above
        // is not deleted out from under its own success report.
        d.relays
            .remove_persisted_rule(&d.paths, &name, bind, host_port)?;
    }
    if !unpersisted && !relay_removed && !stranded_in_rules {
        bail!("no such published port: {bind}:{host_port}");
    }
    Ok(DaemonResponse::Ok)
}

/// Both port-rule verbs run through `sandbox::edit_sandbox_config` so the
/// read-modify-write of the WHOLE `config.json` happens under the per-sandbox
/// lock (#181). Unlocked, two overlapping publishes on independent daemon
/// threads each loaded this config and each wrote it back, so a published port
/// simply vanished while the user held a success message.
fn persist_port_rule(
    paths: &Paths,
    name: &str,
    rule: &crate::state::PortRule,
) -> anyhow::Result<()> {
    crate::sandbox::edit_sandbox_config(paths, name, |cfg| {
        if !cfg
            .ports
            .iter()
            .any(|r| r.bind == rule.bind && r.host_port == rule.host_port)
        {
            cfg.ports.push(rule.clone());
        }
        Ok(())
    })
}

fn unpersist_port_rule(
    paths: &Paths,
    name: &str,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> anyhow::Result<bool> {
    crate::sandbox::edit_sandbox_config(paths, name, |cfg| {
        let before = cfg.ports.len();
        cfg.ports
            .retain(|r| !(r.bind == bind && r.host_port == host_port));
        Ok(cfg.ports.len() != before)
    })
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
        devices: crate::usb::list_devices(
            &d.paths,
            &shared,
            (d.deps.usbipd_probe)(),
            &d.usb.attached_map(),
        ),
    })
}

/// The description to store on a new grant. Pure so the match rule is testable
/// without a live usbipd.
///
/// Best-effort by design (D-E): a grant is a standing config edit and must not
/// fail because the name is unavailable. When there is no pin, an unpinned grant
/// matches any busid, so the id-alone rule in `usbipd_state::describe` is the
/// right one; a pinned grant names the exact device it pinned.
fn grant_description(
    known: Option<&[crate::usb::usbipd_state::UsbipdDevice]>,
    id: crate::usb::DeviceId,
    busid_pin: Option<&str>,
) -> String {
    known
        .and_then(|k| crate::usb::usbipd_state::describe(k, busid_pin.unwrap_or(""), id))
        .unwrap_or_default()
        .to_string()
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
    // Derived host-side, never accepted from the client: the grant record is
    // host-only managed truth (D1), and this is the value every later surface
    // shows the human.
    let description =
        grant_description((d.deps.usbipd_probe)().as_deref(), id, busid_pin.as_deref());
    sandbox::edit_usb_grants(&d.paths, &name, |usb| {
        crate::usb::grants::grant(
            usb,
            crate::usb::UsbGrant {
                device: id,
                busid_pin: busid_pin.clone(),
                description: description.clone(),
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
    // Liveness and the run record are read exactly as `handle_inspect` reads
    // them, so the two answers can never disagree about the same sandbox.
    let running = d.registry.liveness(&name).unwrap_or(Liveness::Stopped) != Liveness::Stopped;
    let usb_kernel = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?
    .map(|s| s.usb_kernel)
    .unwrap_or(false);
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
        attached: d
            .usb
            .attached_to(&name)
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        restart_required: needs_usb_restart(!cfg.usb.devices.is_empty(), running, usb_kernel),
    })
}

/// Whether a sandbox's grants are ahead of the kernel it is running.
///
/// Only a LIVE run can need a restart: a stopped sandbox picks the right kernel
/// the moment it starts, and telling its owner to restart it would be noise. A
/// running sandbox that already booted the USB kernel is likewise fine — the
/// grant it just gained is live.
fn needs_usb_restart(has_grants: bool, running: bool, usb_kernel: bool) -> bool {
    has_grants && running && !usb_kernel
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

/// Enable or disable VNC on a sandbox's config (spec 2026-08-09).
///
/// Idempotent: a request that matches the current setting is a no-op `Ok`,
/// same as `persist_port_rule`'s sibling handlers. There is no artifact check
/// here — enabling only records intent; `handle_start`'s `artifacts` call is
/// the fail-closed gate (a missing KasmVNC bundle fails the START, not this
/// RPC), and `vnc_restart_required` on `Inspect` is what tells a user whose
/// sandbox is already running that the change hasn't taken effect yet.
///
/// The volume cap DOES matter here, though: VNC's `kasmvnc.erofs` takes the
/// last of the 26 virtio-blk slots (`disk_port` asserts < 26), so a sandbox
/// already at the plain 24-volume cap must be refused BEFORE `config.vnc` is
/// flipped to true — otherwise its next start would try to build 27 disks and
/// panic the VMM driver instead of failing with an actionable error.
fn handle_vnc_set(d: &Arc<Daemon>, name: String, enabled: bool) -> anyhow::Result<DaemonResponse> {
    sandbox_must_exist(&d.paths, &name)?;
    // Through the locked helper like every other config verb (#181) — the
    // equality check included. An earlier revision kept that check outside the
    // lock as a read-only fast path, so a redundant toggle stayed cheap; it was
    // dropped because the only caller (the GUI's Display tab) toggles from
    // explicit state-conditional buttons and never polls, so the carve-out
    // bought nothing while leaving one verb able to answer Ok without ever
    // holding the lock.
    //
    // The volume-cap check lives in here too: it reads the very list a
    // concurrent volume attach is rewriting. It stays gated on an ACTUAL
    // change, so re-affirming an already-enabled desktop cannot start failing
    // on an over-cap config that predates the check.
    crate::sandbox::edit_sandbox_config(&d.paths, &name, |cfg| {
        if cfg.vnc == enabled {
            return Ok(());
        }
        if enabled {
            crate::volume::validate_volumes(&cfg.volumes, true)?;
        }
        cfg.vnc = enabled;
        Ok(())
    })?;
    Ok(DaemonResponse::Ok)
}

/// Publish this run's VNC display relay: an EPHEMERAL loopback host port
/// (kernel-chosen, `host_port: 0`) onto the guest's KasmVNC endpoint, in the
/// daemon's separate `vnc_relays` manager so it can never be persisted into
/// `ports.json`. Returns the bound host port. One helper, two call sites
/// (`handle_start` and `adopt`), so the two can never disagree about which
/// manager/port/guest-port a VNC relay uses.
///
/// The kernel-chosen port additionally avoids every persisted fixed rule
/// across sandboxes (#221) via `relays::allocate_avoiding`.
fn publish_vnc_relay(d: &Arc<Daemon>, name: &str) -> anyhow::Result<u16> {
    let avoid = relays::persisted_host_ports(&d.paths);
    let (port, collided) = relays::allocate_avoiding(
        &avoid,
        10,
        || {
            d.vnc_relays.publish_bound(
                &d.paths,
                name,
                crate::state::PortRule {
                    bind: std::net::Ipv4Addr::LOCALHOST,
                    host_port: 0,
                    guest_port: crate::vnc::WEBSOCKET_PORT,
                },
            )
        },
        |p| {
            let _ = d
                .vnc_relays
                .unpublish(name, std::net::Ipv4Addr::LOCALHOST, p);
        },
    )?;
    if collided {
        eprintln!(
            "izbad: VNC relay for '{name}' kept port {port}, which a sandbox's \
             ports.json persists as a fixed rule — that sandbox's next start may \
             fail its publish (rebind attempts exhausted)"
        );
    }
    Ok(port)
}

/// Whether a sandbox's CURRENT run actually BOOTED with VNC (`state.json`'s
/// recorded fact — the same one `vnc_restart_required` is derived from), as
/// opposed to merely being configured for it now.
fn booted_with_vnc(paths: &Paths, name: &str) -> bool {
    load_json::<crate::state::RunState>(&paths.sandbox_dir(name).join(crate::state::STATE_FILE))
        .ok()
        .flatten()
        .map(|s| s.vnc)
        .unwrap_or(false)
}

/// Whether a sandbox's live run is behind its configured VNC setting.
///
/// Unlike `needs_usb_restart`, this is BIDIRECTIONAL: turning VNC OFF on a
/// running sandbox needs a restart just as much as turning it ON does — the
/// booted desktop (or lack of one) doesn't change until the VM reboots either
/// way. A stopped sandbox never needs one: its next start just picks up
/// whatever `config.vnc` says.
fn needs_vnc_restart(enabled: bool, running: bool, booted_vnc: bool) -> bool {
    running && enabled != booted_vnc
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
                    let _ = d.relays.save_active(&d.paths, &info.name);
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
            // The VNC relay is in-memory only, so a restarted/upgraded izbad
            // would otherwise leave a live desktop unreachable until the
            // sandbox itself is restarted — exactly what the "izbad holds no
            // authoritative state, adoption never harms sandboxes" contract
            // forbids. Keyed on what the run actually BOOTED (`state.json`),
            // not on `config.vnc`: a `vnc on` since boot has no desktop to
            // reach yet (that's what `vnc_restart_required` says).
            if booted_with_vnc(&d.paths, &info.name) {
                match publish_vnc_relay(d, &info.name) {
                    Ok(port) => eprintln!(
                        "izbad: re-published VNC relay for '{}' on 127.0.0.1:{port}",
                        info.name
                    ),
                    Err(e) => eprintln!("izbad: VNC relay for '{}': {e:#}", info.name),
                }
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
                &d.vnc_relays,
                &d.egress,
                &d.usb,
                d.connector(),
                &d.starting,
            );
            std::thread::sleep(supervisor::tick_interval());
        });
    }

    if let Some(line) = peer_auth_mode_line() {
        eprintln!("{line}");
    }

    let idle_limit = idle_limit_from(&|k| std::env::var(k).ok());
    loop {
        if should_exit(&d, idle_limit) {
            break;
        }
        accept_and_dispatch(&listener, &d);
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

    #[test]
    fn resolve_docker_mode_precedence() {
        use std::collections::HashMap;
        let on: HashMap<String, String> = [(
            "com.docker.sandboxes.start-docker".to_string(),
            "true".to_string(),
        )]
        .into();
        let off: HashMap<String, String> = [(
            "com.docker.sandboxes.start-docker".to_string(),
            "false".to_string(),
        )]
        .into();
        // CLI wins over label, both directions.
        assert!(!resolve_docker_mode(Some(false), Some(&on)));
        assert!(resolve_docker_mode(Some(true), None));
        // Label decides when CLI is silent; only the literal "true" enables.
        assert!(resolve_docker_mode(None, Some(&on)));
        assert!(!resolve_docker_mode(None, Some(&off)));
        assert!(!resolve_docker_mode(None, None));
    }

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
            artifacts: Box::new(|_, variant, _| {
                Ok(crate::sandbox::Artifacts {
                    variant,
                    kernel: "/art/vmlinux".into(),
                    initramfs: "/art/initramfs.img".into(),
                    kasmvnc_erofs: None,
                })
            }),
            resolve_image: Box::new(|_, _| Ok("sha256:abc".into())),
            // The honest default for a host with no local usbipd, and it leaves
            // every other test's behaviour exactly as it was.
            usbipd_probe: Box::new(|| None),
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
            docker: None,
            vnc: false,
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

    #[test]
    fn a_grant_records_the_product_name_izba_already_knows() {
        // The grant record is what every later surface reads — `izba usb status`,
        // the app's granted list, and the CLI consent banner. Storing an empty
        // description there makes all three name a physical device by four hex
        // digits, which is exactly where "is this the board on my desk?" needs
        // answering.
        let known = vec![crate::usb::usbipd_state::UsbipdDevice {
            busid: "12-4".to_string(),
            id: crate::usb::DeviceId {
                vid: 0x303a,
                pid: 0x1001,
            },
            description: "USB JTAG/serial debug unit".to_string(),
            bound: true,
            attached: false,
        }];
        assert_eq!(
            grant_description(
                Some(&known),
                crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                },
                None
            ),
            "USB JTAG/serial debug unit"
        );
    }

    #[test]
    fn a_grant_with_no_name_available_records_an_empty_one_rather_than_failing() {
        // A grant is a standing config edit; it must keep working with no local
        // usbipd and no reachable upstream. Every surface already renders an
        // empty description cleanly (the consent banner drops the parentheses).
        assert_eq!(
            grant_description(
                None,
                crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                },
                None
            ),
            ""
        );
    }

    #[test]
    fn a_pinned_grant_takes_the_name_of_the_device_it_pinned() {
        let known = vec![
            crate::usb::usbipd_state::UsbipdDevice {
                busid: "3-2".to_string(),
                id: crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001,
                },
                description: "board on the left".to_string(),
                bound: true,
                attached: false,
            },
            crate::usb::usbipd_state::UsbipdDevice {
                busid: "3-3".to_string(),
                id: crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001,
                },
                description: "board on the right".to_string(),
                bound: true,
                attached: false,
            },
        ];
        assert_eq!(
            grant_description(
                Some(&known),
                crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                },
                Some("3-3"),
            ),
            "board on the right"
        );
    }

    #[test]
    fn granting_through_the_rpc_stores_the_name_usbipd_reported() {
        // The pure `grant_description` tests above prove the match rule. This one
        // proves the handler actually calls it — the defect in #195 was a live
        // wire that went nowhere, and a predicate test could never have seen it.
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let mut deps = test_deps();
        deps.usbipd_probe = Box::new(|| {
            Some(vec![crate::usb::usbipd_state::UsbipdDevice {
                busid: "12-4".to_string(),
                id: crate::usb::DeviceId {
                    vid: 0x303a,
                    pid: 0x1001,
                },
                description: "USB JTAG/serial debug unit".to_string(),
                bound: true,
                attached: false,
            }])
        });
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        set_loopback_upstream(&mut c);
        write_config_for_persist(&d.paths, "web");

        handle_usb_allow(&d, "web".to_string(), "303a:1001".to_string(), None)
            .expect("grant should succeed");

        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.usb.devices[0].description, "USB JTAG/serial debug unit",
            "the handler must record the name, not an empty string"
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

    /// All eight combinations, because the field's whole job is the one case
    /// where consent is ahead of the running kernel.
    #[test]
    fn only_a_live_run_on_the_wrong_kernel_needs_a_restart() {
        assert!(needs_usb_restart(true, true, false));

        // No grants: nothing to apply.
        assert!(!needs_usb_restart(false, true, false));
        assert!(!needs_usb_restart(false, true, true));
        // Stopped: the next start picks the right kernel by itself, so telling
        // its owner to restart it would be noise.
        assert!(!needs_usb_restart(true, false, false));
        assert!(!needs_usb_restart(true, false, true));
        assert!(!needs_usb_restart(false, false, false));
        assert!(!needs_usb_restart(false, false, true));
        // Already running the USB kernel: the grant is live.
        assert!(!needs_usb_restart(true, true, true));
    }

    /// Unlike `needs_usb_restart`, this predicate is BIDIRECTIONAL: disabling
    /// VNC on a live run needs a restart just as much as enabling it does.
    #[test]
    fn needs_vnc_restart_truth_table() {
        assert!(!needs_vnc_restart(false, false, false));
        assert!(!needs_vnc_restart(true, false, false)); // stopped: next start picks it up
        assert!(needs_vnc_restart(true, true, false)); // enable while running
        assert!(needs_vnc_restart(false, true, true)); // disable while running
        assert!(!needs_vnc_restart(true, true, true));
    }

    #[test]
    fn a_stopped_sandbox_with_a_fresh_grant_is_not_told_to_restart() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&dir, "web"));
        set_loopback_upstream(&mut c);
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ));
        match rpc(&mut c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus {
                grants,
                attached,
                restart_required,
            } => {
                assert_eq!(grants.len(), 1, "the grant itself is durable");
                assert!(attached.is_empty(), "nothing is spliced");
                assert!(!restart_required);
            }
            other => panic!("expected UsbStatus, got {other:?}"),
        }
    }

    /// The whole point of `restart_required`: a device granted to a sandbox
    /// that is ALREADY running cannot be attached, because the kernel with the
    /// USB stack is chosen at boot. All three inputs are varied against the
    /// real handler, not just the predicate behind it.
    #[test]
    fn a_running_sandbox_is_told_to_restart_only_once_it_has_a_grant() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&dir, "web"));
        set_loopback_upstream(&mut c);
        d.registry.set_liveness("web", Liveness::Running);

        // Running, but nothing granted: there is nothing to apply, and a
        // standing restart prompt would just train people to ignore it.
        assert!(!status_restart_required(&mut c));

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ));
        assert!(
            status_restart_required(&mut c),
            "a grant on a live run of the base kernel needs a restart"
        );

        // Same grant, but this run booted the USB kernel: nothing to do.
        save_json(
            &d.paths.sandbox_dir("web").join(crate::state::STATE_FILE),
            &RunState {
                vmm_pid: live_identity(),
                sidecar_pids: vec![],
                started_unix_ms: 0,
                confinement: None,
                run_dir: None,
                user_fallback: None,
                usb_kernel: true,
                vnc: false,
            },
        )
        .unwrap();
        assert!(!status_restart_required(&mut c));
    }

    fn status_restart_required(c: &mut UdsStream) -> bool {
        match rpc(c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus {
                restart_required, ..
            } => restart_required,
            other => panic!("expected UsbStatus, got {other:?}"),
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
            DaemonResponse::UsbStatus { grants, .. } => {
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
            DaemonResponse::UsbStatus { grants, .. } => assert!(grants.is_empty()),
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

    /// #198: `handle_create`'s `if c.builder { false } else { … }` guard must
    /// win over an explicit `--docker`, not just over the label
    /// (`resolve_docker_mode_precedence` only pins the pure fn's own
    /// precedence — this pins the call site's builder short-circuit, which
    /// never even calls `resolve_docker_mode`). A `builder: izba build`
    /// create with `docker: Some(true)` must still persist `docker: false`.
    #[test]
    fn handle_create_forces_docker_off_for_a_builder_sandbox_even_with_docker_true() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "builder-web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: true,
                docker: Some(true),
                vnc: false,
            }),
        ) {
            DaemonResponse::Created { name } => assert_eq!(name, "builder-web"),
            other => panic!("create: {other:?}"),
        }
        let config: SandboxConfig =
            load_json(&d.paths.sandbox_dir("builder-web").join(CONFIG_FILE))
                .unwrap()
                .unwrap();
        assert!(config.builder, "builder flag itself must still persist");
        assert!(
            !config.docker,
            "builder wins silently: docker must be forced off even though \
             the request asked for it"
        );
    }

    /// #216 (spec 2026-08-12): docker mode + VNC is now a supported
    /// combination — the desktop binds the wildcard address in the
    /// container's netns and the relay reaches it over the veth fallback —
    /// so `handle_create` must accept it and persist both flags.
    #[test]
    fn handle_create_accepts_vnc_plus_docker() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: false,
                docker: Some(true),
                vnc: true,
            }),
        ) {
            DaemonResponse::Created { name } => assert_eq!(name, "web"),
            other => panic!("expected Created, got {other:?}"),
        }
        let config: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(config.vnc, "vnc must persist");
        assert!(config.docker, "docker must persist");
        assert!(config.docker_effective(), "and be effective (not builder)");
    }

    /// A `builder` create forces docker off; `vnc: true` alongside it must
    /// still succeed and persist `docker: true` with `docker_effective() ==
    /// false` — the refusal that used to key on the EFFECTIVE docker flag is
    /// gone, but this pin (builder wins) still matters.
    #[test]
    fn handle_create_allows_vnc_plus_docker_when_builder_forces_docker_off() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "builder-web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: true,
                docker: Some(true),
                vnc: true,
            }),
        ) {
            DaemonResponse::Created { name } => assert_eq!(name, "builder-web"),
            other => panic!("expected Created, got {other:?}"),
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
                vnc: false,
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

    /// The call-site companion to `ArtifactsFn`'s `vnc` parameter: before
    /// this test `handle_start` hardcoded `false` regardless of the
    /// sandbox's actual `config.vnc` (a stub left by an earlier task,
    /// call-site-tested here per the USB-restart-required post-mortem —
    /// "a rule with a test and a call site without one" is this feature's
    /// recurring defect class). Two sandboxes, both directions, against the
    /// same fake, so a hardcoded value on either side cannot pass.
    #[test]
    fn handle_start_passes_the_sandboxs_real_vnc_flag_to_artifacts() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen_vnc: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let seen = seen_vnc.clone();
        let mut deps = test_deps();
        deps.artifacts = Box::new(move |_, variant, vnc| {
            *seen.lock().unwrap() = Some(vnc);
            Ok(crate::sandbox::Artifacts {
                variant,
                kernel: "/art/vmlinux".into(),
                initramfs: "/art/initramfs.img".into(),
                kasmvnc_erofs: if vnc {
                    Some("/art/kasmvnc.erofs".into())
                } else {
                    None
                },
            })
        });
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);

        let vnc_req = DaemonRequest::Create(DaemonCreate {
            name: "withvnc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: dir.path().join("ws"),
            rw_size_gb: 1,
            ports: Vec::new(),
            volumes: Vec::new(),
            allow_unconfined: false,
            builder: false,
            docker: None,
            vnc: true,
        });
        assert!(matches!(
            rpc(&mut c, &vnc_req),
            DaemonResponse::Created { .. }
        ));
        // Start's ultimate outcome doesn't matter here (a sandboxed test env
        // may deny the egress listener bind, same as the sibling tests
        // above) — the artifacts fn runs before that bind, so the recorded
        // value is what matters.
        let _ = rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "withvnc".into(),
                allow_unconfined: false,
            },
        );
        assert_eq!(
            *seen_vnc.lock().unwrap(),
            Some(true),
            "handle_start must pass config.vnc=true through to the artifacts fn"
        );

        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "plain")),
            DaemonResponse::Created { .. }
        ));
        let _ = rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "plain".into(),
                allow_unconfined: false,
            },
        );
        assert_eq!(
            *seen_vnc.lock().unwrap(),
            Some(false),
            "handle_start must pass config.vnc=false through to the artifacts fn"
        );
    }

    /// `VncSet` persists `config.vnc`, is idempotent, and `restart_required`
    /// on `Inspect` follows `needs_vnc_restart`'s bidirectional truth table
    /// against the real handler (not just the predicate alone).
    #[test]
    fn vnc_set_persists_and_restart_required_is_bidirectional() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));

        // "Boot" the sandbox with VNC off — a live run whose config is about
        // to move ahead of what it actually booted.
        d.registry.set_liveness("web", Liveness::Running);
        save_json(
            &d.paths.sandbox_dir("web").join(STATE_FILE),
            &RunState {
                vmm_pid: live_identity(),
                sidecar_pids: vec![],
                started_unix_ms: 0,
                confinement: None,
                run_dir: None,
                user_fallback: None,
                usb_kernel: false,
                vnc: false,
            },
        )
        .unwrap();

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ));
        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => {
                assert!(det.vnc, "VncSet must persist the enable");
                assert!(
                    det.vnc_restart_required,
                    "a live run booted without VNC needs a restart to pick up the new setting"
                );
            }
            other => panic!("expected Inspect, got {other:?}"),
        }

        // Idempotent: the same request again is Ok, and config.json is
        // untouched (still just the one flip from above).
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ));
        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(cfg.vnc, "config unchanged means still enabled");

        // Stopped: the next start already picks up the new setting by
        // itself, so telling the user to restart it would be noise.
        d.registry.set_liveness("web", Liveness::Stopped);
        match rpc(&mut c, &DaemonRequest::Inspect { name: "web".into() }) {
            DaemonResponse::Inspect(det) => assert!(!det.vnc_restart_required),
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    /// The guard Task 4's reviewer flagged: enabling VNC on a sandbox already
    /// at the plain 24-volume cap must be refused BEFORE `config.vnc` flips —
    /// otherwise its next start would try to build 27 disks (rootfs + rw +
    /// 24 volumes + kasmvnc.erofs) and panic the VMM driver's `disk_port`
    /// assert (< 26 slots), instead of failing with an actionable error here.
    #[test]
    fn vnc_set_refuses_to_enable_over_the_volume_cap() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));

        // Config-level fixture: write 24 volumes directly, bypassing
        // create's own volume-count validation (which would refuse a 24-
        // volume Create alongside vnc:true, but not a plain 24-volume one).
        let p = d.paths.sandbox_dir("web").join(CONFIG_FILE);
        let mut cfg: SandboxConfig = load_json(&p).unwrap().unwrap();
        cfg.volumes = (0..24)
            .map(|i| crate::volume::VolumeSpec {
                name: Some(format!("v{i}")),
                guest_path: format!("/data{i}").into(),
                size_bytes: 1 << 20,
                eph_id: None,
            })
            .collect();
        save_json(&p, &cfg).unwrap();
        let before = std::fs::read_to_string(&p).unwrap();

        match rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("volume"), "{message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(before, after, "a refused VncSet must not touch config.json");
    }

    /// #216 (spec 2026-08-12): enabling VNC on an existing docker-mode
    /// sandbox is supported — the netns split is handled by the guest-side
    /// wildcard bind, not by refusing here.
    #[test]
    fn vnc_set_enables_on_a_docker_mode_sandbox() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: false,
                docker: Some(true),
                vnc: false,
            }),
        ) {
            DaemonResponse::Created { .. } => {}
            other => panic!("create: {other:?}"),
        }
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ));
        let config: SandboxConfig = load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(
            config.vnc,
            "VncSet must flip config.vnc on a docker sandbox"
        );
    }

    /// The refusal keys on `docker_effective()`, not the raw `docker` field —
    /// a `builder: true` sandbox created with `docker: Some(true)` persists
    /// `docker: true` but `docker_effective() == false` (builder wins, see
    /// `docker_effective_is_docker_and_not_builder`), so `VncSet{enabled:
    /// true}` against it must succeed.
    #[test]
    fn vnc_set_allows_enabling_on_a_builder_forced_off_docker_sandbox() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "builder-web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: true,
                docker: Some(true),
                vnc: false,
            }),
        ) {
            DaemonResponse::Created { .. } => {}
            other => panic!("create: {other:?}"),
        }
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "builder-web".into(),
                enabled: true,
            },
        ));
        let cfg: SandboxConfig = load_json(&d.paths.sandbox_dir("builder-web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(cfg.vnc, "VncSet must have taken effect");
    }

    /// Task 8 carry-over: `VncSet` against a name that does not exist must
    /// fail with the house "no such sandbox" wording (the `sandbox_must_exist`
    /// gate), not with a raw config-read error — the CLI/GUI key their
    /// messaging off it, same as every other per-sandbox RPC.
    #[test]
    fn vnc_set_on_unknown_sandbox_errors() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "ghost".into(),
                enabled: true,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("no such sandbox"), "{message}")
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // VNC display relay (spec 2026-08-09 §5)
    // -----------------------------------------------------------------

    /// Deps for a daemon that can start a `--vnc` sandbox: the artifacts fn
    /// hands back the KasmVNC bundle such a start fails closed without.
    fn vnc_deps() -> DaemonDeps {
        let mut deps = test_deps();
        deps.artifacts = Box::new(|_, variant, vnc| {
            Ok(crate::sandbox::Artifacts {
                variant,
                kernel: "/art/vmlinux".into(),
                initramfs: "/art/initramfs.img".into(),
                kasmvnc_erofs: if vnc {
                    Some("/art/kasmvnc.erofs".into())
                } else {
                    None
                },
            })
        });
        deps
    }

    fn create_vnc_req(dir: &tempfile::TempDir, name: &str) -> DaemonRequest {
        match create_req(dir, name) {
            DaemonRequest::Create(mut c) => {
                c.vnc = true;
                DaemonRequest::Create(c)
            }
            other => panic!("create_req built {other:?}"),
        }
    }

    /// A fake guest stream port that answers ONE `StreamOpen` frame the way
    /// izba-init does: `Ok` when `reachable` (something IS listening on the
    /// dialed guest port), `Error{ConnectFailed}` otherwise. Records every
    /// dialed port so a test can prove WHICH port was probed.
    fn dial_answering_stream_connector(
        seen: Arc<Mutex<Vec<u16>>>,
        reachable: bool,
    ) -> impl Fn(&Paths, &str) -> anyhow::Result<UdsStream> + Send + Sync + 'static {
        move |_paths: &Paths, _name: &str| {
            let (host, guest) = UdsStream::pair()?;
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let mut g = guest;
                let Ok(open) = read_frame::<_, izba_proto::StreamOpen>(&mut g) else {
                    return;
                };
                if let izba_proto::StreamOpen::TcpDial { port } = open {
                    seen.lock().unwrap().push(port);
                }
                let resp = if reachable {
                    Response::Ok
                } else {
                    Response::Error {
                        kind: izba_proto::ErrorKind::ConnectFailed,
                        message: "connection refused".into(),
                    }
                };
                let _ = write_frame(&mut g, &resp);
            });
            Ok(host)
        }
    }

    /// Start `name`, or report `false` (having logged) where this environment
    /// denies the binds a start needs — the house runtime-skip pattern.
    fn start_or_skip(c: &mut UdsStream, name: &str, test: &str) -> bool {
        match rpc(
            c,
            &DaemonRequest::Start {
                name: name.into(),
                allow_unconfined: false,
            },
        ) {
            DaemonResponse::Ok => true,
            DaemonResponse::Error { message }
                if message.contains("denied")
                    || message.contains("Permission")
                    || message.contains("not permitted") =>
            {
                eprintln!("SKIP {test}: bind denied: {message}");
                false
            }
            other => panic!("start: {other:?}"),
        }
    }

    /// THE persistence firewall (spec 2026-08-09 §5): the VNC relay lives in
    /// `d.vnc_relays`, never in `d.relays`, because both port handlers persist
    /// `relays.active(name)` WHOLESALE into `ports.json`. Publishing an
    /// unrelated port afterwards is exactly the moment a shared map would leak
    /// a `guest_port: 6901` rule into the user's persisted ports — and it
    /// would then be re-published (on a FIXED port) by every later start and
    /// by adoption.
    #[test]
    fn vnc_relay_never_persists_into_ports_json() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(&mut c, "desk", "vnc_relay_never_persists_into_ports_json") {
            return;
        }

        // The relay exists, on an ephemeral port, in the VNC map ONLY.
        let vnc_rules = d.vnc_relays.active("desk");
        assert_eq!(vnc_rules.len(), 1, "one VNC relay per start: {vnc_rules:?}");
        assert_eq!(vnc_rules[0].guest_port, crate::vnc::WEBSOCKET_PORT);
        assert_ne!(vnc_rules[0].host_port, 0, "an ephemeral host port");
        assert!(
            d.relays.active("desk").is_empty(),
            "the VNC relay must never enter the published-ports manager"
        );

        // Now publish a real port — the operation that rewrites ports.json.
        let user_port = crate::testutil::reserve_port().expect("bind denied");
        let rule = crate::state::PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: user_port,
            guest_port: 8080,
        };
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::PortPublish {
                name: "desk".into(),
                rule: rule.clone(),
                persist: false,
            },
        ));

        let (persisted, _) = relays::load_rules_migrating(&d.paths, "desk").unwrap();
        assert_eq!(
            persisted,
            vec![rule],
            "ports.json must hold the user's rule and nothing else"
        );
        assert!(
            persisted
                .iter()
                .all(|r| r.guest_port != crate::vnc::WEBSOCKET_PORT),
            "a VNC relay rule must never reach ports.json: {persisted:?}"
        );
    }

    /// A plain sandbox gets no VNC relay at all (the absence guard for the
    /// test above — a start that published one unconditionally would open a
    /// host port onto a guest with nothing listening).
    #[test]
    fn plain_sandbox_start_publishes_no_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "plain")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "plain",
            "plain_sandbox_start_publishes_no_vnc_relay",
        ) {
            return;
        }
        assert!(
            d.vnc_relays.active("plain").is_empty(),
            "a sandbox without --vnc must have no VNC relay"
        );
    }

    /// Stop tears the relay down AND releases its host port — the relay is
    /// per-run derived state, and a stopped sandbox must not leave a listening
    /// socket onto a dead guest.
    #[test]
    fn stop_tears_down_the_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let vmm = spawn_sleep(dir.path());
        let mut deps = vnc_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(&mut c, "desk", "stop_tears_down_the_vnc_relay") {
            return;
        }
        let port = d.vnc_relays.active("desk")[0].host_port;

        // Swap the MockDriver-recorded vmm identity for the disposable child
        // (as the sibling start/stop tests do), keeping this start's real
        // run_dir so Stop resolves the same sockets.
        write_state_with_run_dir(&d.paths, "desk", vmm.clone(), Some(d.paths.run_dir("desk")));
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::Stop {
                name: "desk".into(),
            },
        ));

        assert!(
            d.vnc_relays.active("desk").is_empty(),
            "stop must tear the VNC relay down"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "VNC relay port never released");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The same teardown at the OTHER call site: `rm`. (A rule with a test
    /// and a call site without one is this project's recurring defect class.)
    #[test]
    fn rm_tears_down_the_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let vmm = spawn_sleep(dir.path());
        let mut deps = vnc_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(&mut c, "desk", "rm_tears_down_the_vnc_relay") {
            return;
        }
        assert_eq!(d.vnc_relays.active("desk").len(), 1);

        write_state_with_run_dir(&d.paths, "desk", vmm.clone(), Some(d.paths.run_dir("desk")));
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::Rm {
                name: "desk".into(),
                force: true,
            },
        ));
        assert!(
            d.vnc_relays.active("desk").is_empty(),
            "rm must tear the VNC relay down"
        );
    }

    /// `Inspect` on a live VNC sandbox: the credentialed URL points at the
    /// relay's real ephemeral port and carries the host-only per-start
    /// password, and `vnc_running` is the guest's own answer — proved by the
    /// dialed port being 6901, not merely by the relay existing.
    #[test]
    fn inspect_reports_vnc_url_and_running_from_the_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let mut deps = vnc_deps();
        deps.stream_connector = Box::new(dial_answering_stream_connector(Arc::clone(&seen), true));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "desk",
            "inspect_reports_vnc_url_and_running_from_the_relay",
        ) {
            return;
        }
        let port = d.vnc_relays.active("desk")[0].host_port;
        let pw = crate::vnc::read_password(&d.paths, "desk").unwrap();

        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "desk".into(),
            },
        ) {
            DaemonResponse::Inspect(det) => {
                assert!(det.vnc);
                assert_eq!(
                    det.vnc_url,
                    Some(format!("http://izba:{pw}@127.0.0.1:{port}/")),
                    "the URL must carry this start's password and the relay's real port"
                );
                assert!(det.vnc_running, "the guest answered the dial");
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
        assert_eq!(
            *seen.lock().unwrap(),
            vec![crate::vnc::WEBSOCKET_PORT],
            "the liveness probe must dial the guest's KasmVNC port"
        );
    }

    /// Honesty: a relay in front of a dead desktop is NOT "running". The URL
    /// still surfaces (the relay and the password are real — the desktop may
    /// simply still be coming up), but `vnc_running` follows the guest.
    #[test]
    fn inspect_reports_vnc_not_running_when_the_guest_port_is_dead() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let mut deps = vnc_deps();
        deps.stream_connector = Box::new(dial_answering_stream_connector(Arc::clone(&seen), false));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "desk",
            "inspect_reports_vnc_not_running_when_the_guest_port_is_dead",
        ) {
            return;
        }
        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "desk".into(),
            },
        ) {
            DaemonResponse::Inspect(det) => {
                assert!(
                    !det.vnc_running,
                    "a refused guest dial must not report a running desktop"
                );
                assert!(det.vnc_url.is_some(), "the relay URL still surfaces");
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    /// A plain (non-VNC) sandbox reports no URL and no running desktop, and
    /// costs no guest dial at all.
    #[test]
    fn inspect_reports_no_vnc_for_a_plain_sandbox() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let mut deps = vnc_deps();
        deps.stream_connector = Box::new(dial_answering_stream_connector(Arc::clone(&seen), true));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "plain")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "plain",
            "inspect_reports_no_vnc_for_a_plain_sandbox",
        ) {
            return;
        }
        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "plain".into(),
            },
        ) {
            DaemonResponse::Inspect(det) => {
                assert!(!det.vnc && !det.vnc_running && det.vnc_url.is_none());
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "a plain sandbox must cost no VNC probe dial"
        );
    }

    /// A STOPPED sandbox is never probed, even if the daemon still holds a
    /// relay for it (e.g. one that outlived its run): a dead VM cannot answer,
    /// so the dial would only burn the inspect budget. Same posture as the
    /// container probe's `status == "stopped"` short-circuit.
    #[test]
    fn inspect_does_not_probe_vnc_on_a_stopped_sandbox() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let mut deps = vnc_deps();
        deps.stream_connector = Box::new(dial_answering_stream_connector(Arc::clone(&seen), true));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        // Never started: the registry reports it stopped. Plant a relay
        // anyway, so only the liveness gate can keep the probe from running.
        let Some(()) = plant_vnc_relay_or_skip(
            &d,
            "desk",
            "inspect_does_not_probe_vnc_on_a_stopped_sandbox",
        ) else {
            return;
        };

        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "desk".into(),
            },
        ) {
            DaemonResponse::Inspect(det) => {
                assert!(
                    !det.vnc_running,
                    "a stopped sandbox can never have a running desktop"
                );
                assert!(
                    det.vnc_url.is_none(),
                    "a stopped sandbox must not advertise a URL for a lingering relay: {:?}",
                    det.vnc_url
                );
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "a stopped sandbox must cost no VNC probe dial"
        );
        d.vnc_relays.stop_all("desk");
    }

    /// Reachability is a property of the RUN, not of `config.vnc`: `izba vnc
    /// off` on a live sandbox flips the config immediately but cannot unmake
    /// the desktop that booted — so inspect must keep reporting
    /// `vnc_running: true` (alongside `vnc_restart_required: true`) instead of
    /// contradicting itself with "not running" next to a URL that still works.
    #[test]
    fn vnc_off_on_a_live_sandbox_keeps_reporting_the_running_desktop() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let mut deps = vnc_deps();
        deps.stream_connector = Box::new(dial_answering_stream_connector(Arc::clone(&seen), true));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "desk",
            "vnc_off_on_a_live_sandbox_keeps_reporting_the_running_desktop",
        ) {
            return;
        }

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "desk".into(),
                enabled: false,
            },
        ));
        match rpc(
            &mut c,
            &DaemonRequest::Inspect {
                name: "desk".into(),
            },
        ) {
            DaemonResponse::Inspect(det) => {
                assert!(!det.vnc, "config now says VNC is off");
                assert!(
                    det.vnc_restart_required,
                    "the live run is ahead of its config"
                );
                assert!(
                    det.vnc_running,
                    "the booted desktop is still up and reachable — config cannot unmake it"
                );
                assert!(det.vnc_url.is_some(), "and its URL still works");
            }
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    /// The probe's budget, not just its verdict (the rule-with-a-test /
    /// call-site-without-one defect class): a guest that accepts the stream
    /// connection and reads the `TcpDial` but never replies must not pin
    /// `handle_inspect` — and transitively a polling GUI — forever.
    #[test]
    fn vnc_probe_times_out_on_wedged_guest() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let mut deps = vnc_deps();
        // Accepts, reads, never answers, holds the socket open for 10 s.
        deps.stream_connector = Box::new(|_paths: &Paths, _name: &str| {
            let (host, guest) = UdsStream::pair()?;
            std::thread::spawn(move || {
                let mut g = guest;
                let _ = read_frame::<_, izba_proto::StreamOpen>(&mut g);
                std::thread::sleep(Duration::from_secs(10));
            });
            Ok(host)
        });
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));

        let t0 = Instant::now();
        let answered = probe_vnc_endpoint(&d, "desk", Duration::from_millis(200));
        assert!(!answered, "a wedged guest is not a running desktop");
        // Well under the hanging fake's 10 s hold: proves the timeout fired,
        // not the peer's eventual exit.
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "probe blocked {:?} instead of timing out",
            t0.elapsed()
        );
    }

    /// Fail-loud, not degrade: a `--vnc` start whose relay cannot be published
    /// must FAIL (a sandbox with an unreachable desktop is silently useless),
    /// with a message that names the retry.
    #[test]
    fn start_fails_loudly_when_the_vnc_relay_cannot_be_published() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        d.vnc_relays.fail_next_publish_bound();

        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "desk".into(),
                allow_unconfined: false,
            },
        ) {
            DaemonResponse::Error { message } if message.contains("unavailable") => {
                assert!(
                    message.contains("izba start desk"),
                    "the failure must name the retry: {message}"
                );
            }
            // This environment could not even bind the egress listener.
            DaemonResponse::Error { message }
                if message.contains("denied")
                    || message.contains("Permission")
                    || message.contains("not permitted") =>
            {
                eprintln!(
                    "SKIP start_fails_loudly_when_the_vnc_relay_cannot_be_published: {message}"
                );
                return;
            }
            other => panic!("expected the relay failure to fail the start, got {other:?}"),
        }
        assert!(d.vnc_relays.active("desk").is_empty());
    }

    /// …and the recovery the message promises: a repeat `izba start` on the
    /// still-running sandbox re-publishes the missing relay (it lands in the
    /// already-running branch, which still returns the honest error).
    #[test]
    fn repeat_start_republishes_a_missing_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        if !start_or_skip(
            &mut c,
            "desk",
            "repeat_start_republishes_a_missing_vnc_relay",
        ) {
            return;
        }
        // Lose the relay exactly as a failed publish would have left it.
        d.vnc_relays.stop_all("desk");
        assert!(d.vnc_relays.active("desk").is_empty());

        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "desk".into(),
                allow_unconfined: false,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("already running"), "{message}")
            }
            other => panic!("expected an already-running error, got {other:?}"),
        }
        let rules = d.vnc_relays.active("desk");
        assert_eq!(rules.len(), 1, "the repeat start must republish the relay");
        assert_eq!(rules[0].guest_port, crate::vnc::WEBSOCKET_PORT);
        d.vnc_relays.stop_all("desk");
    }

    /// Plant a VNC relay for `name` the way a previous run would have left
    /// one. `None` (having logged) where the environment denies the bind.
    fn plant_vnc_relay_or_skip(d: &Arc<Daemon>, name: &str, test: &str) -> Option<()> {
        match publish_vnc_relay(d, name) {
            Ok(_) => Some(()),
            Err(e) => {
                eprintln!("SKIP {test}: VNC relay bind denied: {e:#}");
                None
            }
        }
    }

    /// A VMM driver that cannot launch — the fastest way to a `handle_start`
    /// failure AFTER its listener/relay teardown responsibilities begin (an
    /// unhealthy-guest failure would burn the whole 30 s boot budget).
    struct FailingDriver;

    impl VmmDriver for FailingDriver {
        fn launch(
            &self,
            _spec: &crate::vmm::VmSpec,
        ) -> anyhow::Result<Box<dyn crate::vmm::VmHandle>> {
            anyhow::bail!("mock launch failure")
        }
    }

    /// A start that never booted must leave NO plane of the sandbox armed —
    /// including a VNC relay left over from an earlier run of the same name
    /// (the error path already stops egress + USB; the VNC relay is the third
    /// plane and must go with them).
    #[test]
    fn failed_start_tears_down_a_stale_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let mut deps = vnc_deps();
        deps.driver = Box::new(FailingDriver);
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        let Some(()) =
            plant_vnc_relay_or_skip(&d, "desk", "failed_start_tears_down_a_stale_vnc_relay")
        else {
            return;
        };

        match rpc(
            &mut c,
            &DaemonRequest::Start {
                name: "desk".into(),
                allow_unconfined: false,
            },
        ) {
            // A start that never reached the driver (this environment denies
            // the egress listener bind) proves nothing about the teardown.
            DaemonResponse::Error { message }
                if message.contains("denied")
                    || message.contains("Permission")
                    || message.contains("not permitted") =>
            {
                eprintln!("SKIP failed_start_tears_down_a_stale_vnc_relay: bind denied: {message}");
                return;
            }
            DaemonResponse::Error { message } => {
                assert!(message.contains("mock launch failure"), "{message}")
            }
            other => panic!("expected the start to fail, got {other:?}"),
        }
        assert!(
            d.vnc_relays.active("desk").is_empty(),
            "a failed start must not leave a VNC relay behind"
        );
    }

    /// A successful start REPLACES any relay of a previous run rather than
    /// stacking a second one: the sandbox has exactly one desktop, so it must
    /// have exactly one URL.
    #[test]
    fn start_replaces_a_stale_vnc_relay() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        let Some(()) = plant_vnc_relay_or_skip(&d, "desk", "start_replaces_a_stale_vnc_relay")
        else {
            return;
        };
        let stale_port = d.vnc_relays.active("desk")[0].host_port;

        if !start_or_skip(&mut c, "desk", "start_replaces_a_stale_vnc_relay") {
            return;
        }
        let rules = d.vnc_relays.active("desk");
        assert_eq!(rules.len(), 1, "exactly one VNC relay per run: {rules:?}");
        // The stale relay was genuinely stopped, not merely dropped from the
        // map — its port comes back (unless the kernel happened to hand the
        // fresh relay the very same ephemeral port, which is equally proof it
        // was released first).
        if rules[0].host_port != stale_port {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if std::net::TcpListener::bind(("127.0.0.1", stale_port)).is_ok() {
                    break;
                }
                assert!(Instant::now() < deadline, "stale relay port never released");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    /// The VNC relay is in-memory only, so a restarted/upgraded izbad must
    /// re-publish it during adoption — otherwise a running desktop stays
    /// unreachable until the sandbox itself is restarted, breaking the
    /// "killing/upgrading izbad never harms sandboxes" contract. Keyed on
    /// what the run BOOTED (`state.json`), not on `config.vnc`.
    #[test]
    fn adopt_republishes_the_vnc_relay_of_a_booted_vnc_sandbox() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let d = Arc::new(Daemon::new(paths, vnc_deps()));
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_vnc_req(&dir, "desk")),
            DaemonResponse::Created { .. }
        ));
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "plain")),
            DaemonResponse::Created { .. }
        ));
        // Both look alive on disk; only "desk" recorded a VNC boot.
        save_json(
            &d.paths.sandbox_dir("desk").join(STATE_FILE),
            &RunState {
                vmm_pid: live_identity(),
                sidecar_pids: vec![],
                started_unix_ms: 0,
                confinement: None,
                run_dir: Some(d.paths.run_dir("desk")),
                user_fallback: None,
                usb_kernel: false,
                vnc: true,
            },
        )
        .unwrap();
        write_state_with_run_dir(
            &d.paths,
            "plain",
            live_identity(),
            Some(d.paths.run_dir("plain")),
        );

        // A fresh daemon over the same data root = the post-restart adoption.
        let fresh = Arc::new(Daemon::new(d.paths.clone(), vnc_deps()));
        adopt(&fresh);

        let rules = fresh.vnc_relays.active("desk");
        if rules.is_empty() {
            eprintln!("SKIP adopt_republishes_the_vnc_relay: no relay bound (bind denied?)");
            return;
        }
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].guest_port, crate::vnc::WEBSOCKET_PORT);
        assert_ne!(rules[0].host_port, 0);
        assert!(
            fresh.vnc_relays.active("plain").is_empty(),
            "a sandbox that did not boot with VNC must get no relay"
        );
        assert!(
            fresh.relays.active("desk").is_empty(),
            "adoption must not put the VNC relay in the published-ports manager"
        );
        fresh.vnc_relays.stop_all("desk");
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
                docker: false,
                vnc: false,
            },
        )
        .unwrap();
        let d = Arc::new(Daemon::new(paths, test_deps()));
        // A relay left by a previous run of this name: an early bail-out must
        // leave NO plane armed, the VNC relay included (the sandbox is not,
        // and is not becoming, live).
        let planted =
            plant_vnc_relay_or_skip(&d, "web", "handle_start_rejects_deep_root").is_some();

        let mut progress_log = Vec::new();
        let err = handle_start(&d, "web".into(), false, &mut |s| progress_log.push(s))
            .expect_err("deep root must be rejected before binding the listener");
        let msg = format!("{err:#}");
        assert!(msg.contains("IZBA_DATA_DIR"), "{msg}");
        assert!(
            !d.egress.listening("web"),
            "listener must not have been bound"
        );
        if planted {
            assert!(
                d.vnc_relays.active("web").is_empty(),
                "a refused start must not leave a stale VNC relay listening"
            );
        }
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

    /// #234: a Start against a sandbox that is already up must NOT announce a
    /// start. The line used to be emitted unconditionally at the top of
    /// `handle_start`, before `sandbox::start` returned its `AlreadyRunning`
    /// refusal — so `izba run --policy` against a running sandbox printed
    /// "starting '<name>'..." for a (re)start that never happened, which was
    /// half of what made the stale-enforcement window invisible.
    #[test]
    fn start_already_running_does_not_announce_a_start() {
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
        // Make it live exactly as its first (real) Start would have left it.
        write_state_with_run_dir(&d.paths, "web", vmm.clone(), Some(d.paths.run_dir("web")));

        let mut said: Vec<String> = Vec::new();
        let err = handle_start(&d, "web".into(), false, &mut |m| said.push(m))
            .expect_err("a live sandbox must refuse the redundant start");
        // The progress line is emitted BEFORE any listener bind, so both
        // assertions below hold even in a sandbox that denies `bind` with
        // EPERM (this crate's test-design constraint) — no runtime skip is
        // needed for the part this test is actually about.
        assert!(
            !said.iter().any(|m| m.starts_with("starting '")),
            "must not announce a start that does not happen: {said:?}"
        );
        assert!(
            said.iter()
                .any(|m| m.contains("already running") || m.contains("already up but degraded")),
            "must say the sandbox is already up: {said:?}"
        );
        // The typed refusal itself is only reachable where the bind IS
        // permitted; a bind-denied environment fails earlier, which says
        // nothing about the wording under test. Report that leg as SKIPPED
        // rather than folding it into the assertion — an environment silently
        // accepting a *different* error as success is exactly how a test stops
        // covering what it claims to (the sibling bind-denied tests above print
        // the same kind of notice). CI runs unconfined, so the leg is exercised
        // there.
        let bind_denied = err.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
        });
        if bind_denied {
            eprintln!(
                "SKIP (partial) start_already_running_does_not_announce_a_start: bind denied, \
                 so the typed AlreadyRunning refusal was not reached: {err:#}"
            );
        } else {
            assert!(
                err.downcast_ref::<sandbox::AlreadyRunning>().is_some(),
                "expected AlreadyRunning, got: {err:#}"
            );
        }
    }

    /// The already-running republish check is `booted_with_vnc(...) &&
    /// vnc_relays.active(...).is_empty()` — both conjuncts matter. A
    /// non-VNC sandbox trivially satisfies the second (it never had a
    /// relay), so an `&&`→`||` mutation would still evaluate true on the
    /// first conjunct's `false` and wrongly attempt `publish_vnc_relay` for
    /// a sandbox with no VNC endpoint on the other end. Assert the redundant
    /// Start leaves it relay-less.
    #[test]
    fn start_already_running_non_vnc_sandbox_publishes_no_vnc_relay() {
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

        // Make it look live, with a non-VNC state.json (write_state_with_run_dir
        // always records `vnc: false`) and its egress listener already bound —
        // exactly what a real first Start would have left behind.
        write_state_with_run_dir(&d.paths, "web", vmm.clone(), Some(d.paths.run_dir("web")));
        match d
            .egress
            .ensure_listening(&d.paths, "web", &d.paths.run_dir("web"))
        {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!(
                    "SKIP start_already_running_non_vnc_sandbox_publishes_no_vnc_relay: bind denied: {e:#}"
                );
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }

        assert!(
            d.vnc_relays.active("web").is_empty(),
            "precondition: no VNC relay yet"
        );
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
            d.vnc_relays.active("web").is_empty(),
            "a non-VNC sandbox's redundant Start must not publish a VNC relay"
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
        let Some(port) = crate::testutil::reserve_port() else {
            eprintln!("SKIP: bind denied");
            return;
        };
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
    fn guest_rpc_refuses_stats_request() {
        // A GuestRpc carrying Request::Stats must be refused, never proxied:
        // the raw guest Response::Stats(GuestStats) would bypass
        // sanitize_guest_stats (crate::daemon::stats), which is only ever
        // called from the dedicated Stats handler. Even on a live sandbox
        // (where the guest would happily answer), the daemon must reject the
        // request before it ever dials the guest.
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
                req: Request::Stats,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("DaemonRequest::Stats"),
                    "expected the error to point at the dedicated Stats RPC: {message}"
                );
            }
            other => panic!("expected a refusal, got a raw guest proxy: {other:?}"),
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

    /// #283: an unparsable file under `<data>/trust/extra` disables the MITM,
    /// so every ENFORCING sandbox's HTTP(S) fails closed. `Status` must SAY so
    /// — reporting only an empty `extra_ca_files` renders the degraded state
    /// as the benign "webpki roots only" and tells the operator to install the
    /// CA they already installed.
    #[test]
    fn status_reports_an_extra_ca_load_failure() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        std::fs::create_dir_all(paths.trust_extra_dir()).unwrap();
        std::fs::write(
            paths.trust_extra_dir().join("corp.pem"),
            "not a certificate\n",
        )
        .unwrap();
        // Built inside Daemon::new, so this covers the real wiring.
        let d = Arc::new(Daemon::new(paths, test_deps()));
        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::Status) {
            DaemonResponse::Status(s) => {
                let err = s.trust_error.expect("load failure surfaced");
                assert!(err.contains("corp.pem"), "{err}");
                assert!(
                    err.contains("extra CA load failed"),
                    "the CAUSE must ride along, not just the inner error: {err}"
                );
                assert!(
                    s.extra_ca_files.is_empty(),
                    "nothing was loaded: {:?}",
                    s.extra_ca_files
                );
            }
            other => panic!("status: {other:?}"),
        }
    }

    /// The healthy counterpart: a good file loads, and no error is reported.
    #[test]
    fn status_reports_loaded_extra_ca_files_without_an_error() {
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        std::fs::create_dir_all(paths.trust_extra_dir()).unwrap();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = crate::daemon::egress::mitm::IzbaCa::generate().unwrap();
        std::fs::write(paths.trust_extra_dir().join("corp.pem"), ca.cert_pem()).unwrap();
        let d = Arc::new(Daemon::new(paths, test_deps()));
        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::Status) {
            DaemonResponse::Status(s) => {
                assert_eq!(s.extra_ca_files, ["corp.pem"]);
                assert!(s.trust_error.is_none(), "{:?}", s.trust_error);
            }
            other => panic!("status: {other:?}"),
        }
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
                docker: false,
                vnc: false,
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
                docker: false,
                vnc: false,
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

        let Some(port) = crate::testutil::reserve_port() else {
            eprintln!("SKIP port_publish_persist_writes_to_config: bind denied");
            return;
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

        let Some(port) = crate::testutil::reserve_port() else {
            eprintln!("SKIP port_unpublish_drops_from_config: bind denied");
            return;
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
            docker: false,
            vnc: false,
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
                docker: false,
                vnc: false,
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
                docker: false,
                vnc: false,
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

    // -----------------------------------------------------------------
    // #203 Stats handler (Task 5)
    // -----------------------------------------------------------------

    #[test]
    fn stats_on_stopped_sandbox_reports_disk_breakdown() {
        let (dir, d) = test_daemon();
        let name = "web";
        let sdir = d.paths.sandbox_dir(name);
        std::fs::create_dir_all(&sdir).unwrap();
        std::fs::create_dir_all(d.paths.logs_dir(name)).unwrap();

        let docker_vol = crate::volume::VolumeSpec {
            name: None,
            guest_path: "/var/lib/docker".into(),
            size_bytes: 10 << 30,
            eph_id: Some(0),
        };
        let config = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: dir.path().join("ws"),
            ports: vec![],
            volumes: vec![docker_vol.clone()],
            builder: false,
            build: None,
            rw_size_gb: 1,
            usb: Default::default(),
            docker: true,
            vnc: false,
        };
        save_json(&sdir.join(CONFIG_FILE), &config).unwrap();

        // sandbox_dir/rw.img: sparse 1 GiB, 1 MiB of real data written.
        let rw_path = sdir.join("rw.img");
        {
            let f = std::fs::File::create(&rw_path).unwrap();
            f.set_len(1 << 30).unwrap();
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&rw_path)
                .unwrap();
            f.write_all(&vec![0xABu8; 1 << 20]).unwrap();
        }
        // Sparse-aware skip: a filesystem that cannot represent holes (some
        // container overlays / exotic tmpfs configs) would allocate the full
        // apparent length up front, which would fail the `< len` assertion
        // below for a reason that has nothing to do with the Stats handler.
        let rw_allocated = crate::sandbox::allocated_bytes(&std::fs::metadata(&rw_path).unwrap());
        if rw_allocated >= 1 << 30 {
            eprintln!(
                "SKIP stats_on_stopped_sandbox_reports_disk_breakdown: {} does not support sparse files",
                sdir.display()
            );
            return;
        }

        // Docker volume image: sparse, 2 MiB of real data written.
        let vol_path = docker_vol.image_path(&d.paths, name);
        std::fs::create_dir_all(vol_path.parent().unwrap()).unwrap();
        {
            let f = std::fs::File::create(&vol_path).unwrap();
            f.set_len(10 << 30).unwrap();
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&vol_path)
                .unwrap();
            f.write_all(&vec![0xCDu8; 2 << 20]).unwrap();
        }

        // logs_dir/console.log — 4096 bytes.
        std::fs::write(d.paths.logs_dir(name).join("console.log"), vec![0u8; 4096]).unwrap();

        // image_dir(digest)/rootfs.erofs — 8192 bytes.
        let img_dir = d.paths.image_dir(&config.image_digest);
        std::fs::create_dir_all(&img_dir).unwrap();
        std::fs::write(img_dir.join("rootfs.erofs"), vec![0u8; 8192]).unwrap();

        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::Stats { name: name.into() }) {
            DaemonResponse::Stats(s) => {
                assert!(!s.running);
                assert_eq!(s.uptime_ms, None);
                assert!(s.host.is_none());
                assert!(s.guest.is_none());
                assert!(
                    s.disk.rw_img_bytes >= 1024 * 1024,
                    "sparse-aware: allocated, not len; got {}",
                    s.disk.rw_img_bytes
                );
                assert!(
                    s.disk.rw_img_bytes < 1024 * 1024 * 1024,
                    "must not report the sparse length"
                );
                let dv = s
                    .disk
                    .volumes
                    .iter()
                    .find(|v| v.docker)
                    .expect("docker volume attributed");
                assert!(dv.allocated_bytes >= 2 * 1024 * 1024 - 65536);
                assert!(s.disk.logs_bytes >= 4096);
                assert!(s.disk.image_bytes >= 8192);
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn stats_on_missing_sandbox_errors() {
        let (_dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::Stats {
                name: "nope".into(),
            },
        ) {
            DaemonResponse::Error { .. } => {}
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn probe_guest_stats_folds_a_real_guest_reply() {
        // The fake guest connector answers Request::Stats with a real
        // Response::Stats(GuestStats) (see testutil::fake_guest_stats). This
        // kills both `probe_guest_stats -> None` (the function must actually
        // return the guest's reply, not degrade unconditionally) and the
        // `delete match arm Response::Stats(g)` mutant (deleting that arm
        // routes a genuine Stats reply through the `_ => None` catch-all).
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        assert!(matches!(
            rpc(&mut c, &create_req(&dir, "web")),
            DaemonResponse::Created { .. }
        ));
        write_state(&d.paths, "web", live_identity()); // running per pid probe

        let guest = probe_guest_stats(&d, "web", STATS_PROBE_TIMEOUT);
        let g = guest.expect("fake guest answers Request::Stats");
        assert_eq!(g.process_count, 7, "the marker field must survive intact");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_resources_reports_the_live_test_process() {
        // Uses the test process itself as the "vmm": a PidIdentity built with
        // the correct starttime (procmgr::proc_starttime, same helper used at
        // real spawn time) is unambiguously alive, so host_resources must
        // return Some with real /proc-derived fields — kills `host_resources
        // -> None`.
        let (_dir, d) = test_daemon();
        let config = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 512,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 1,
            usb: Default::default(),
            docker: false,
            vnc: false,
        };
        let id = live_identity();
        let res = host_resources(&d, "web", &config, &id).expect("live pid must report resources");
        assert!(res.rss_kb > 0, "expected a real VmRSS reading, got 0");
        assert_eq!(res.cpus_limit, 2);
        assert_eq!(res.mem_limit_mb, 512);

        // Same pid, wrong starttime (simulates a recycled pid): the identity
        // re-check must refuse it, never read the wrong process. This kills
        // `delete !` on the pid_alive gate (which would flip the guard to
        // "refuse the live identity, accept the dead one").
        let wrong = crate::testutil::dead_identity();
        assert!(
            host_resources(&d, "web", &config, &wrong).is_none(),
            "a recycled pid must never be read as the live vmm"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn host_resources_stub_is_always_none() {
        // The non-Linux host tier is out of scope (spec §9): host_resources
        // must always degrade to None here, never fabricate a Default
        // reading. Kills `host_resources -> Some(Default::default())`.
        let (_dir, d) = test_daemon();
        let config = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 256,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 1,
            usb: Default::default(),
            docker: false,
            vnc: false,
        };
        let id = live_identity();
        assert!(host_resources(&d, "web", &config, &id).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_permille_from_tick_delta() {
        // 50 ticks over 1000 ms at 100 Hz = half a CPU = 500 permille.
        assert_eq!(cpu_permille(1000, 1050, 1000, 100), Some(500));
        // Non-monotonic (VMM restarted / cache stale): honest None, never junk.
        assert_eq!(cpu_permille(2000, 1000, 1000, 100), None);
        assert_eq!(cpu_permille(0, 0, 0, 100), None); // zero elapsed
                                                      // Equal ticks (no CPU consumed this interval) is a valid 0% sample,
                                                      // NOT a gap: `ticks < prev_ticks` must stay strict (`<`), never `<=`.
        assert_eq!(cpu_permille(1000, 1000, 1000, 100), Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_clk_tck_is_a_sane_user_hz() {
        // USER_HZ is >= 24 on any real kernel (100 is the typical value); an
        // upper bound of 10_000 guards against a nonsense sysconf() result.
        // This kills both `host_clk_tck -> 0` and `host_clk_tck -> 1` mutants
        // (0 is below the floor; 1 would also make cpu_permille observably
        // wrong, but the direct range assertion is the precise kill).
        let t = host_clk_tck();
        assert!((24..=10_000).contains(&t), "implausible CLK_TCK: {t}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vmm_stat_ticks_and_status_rss() {
        let stat =
            "1234 (cloud-hyperviso) S 1 1 1 0 -1 4194560 0 0 0 0 700 300 0 0 20 0 8 0 555 0 99999 0";
        assert_eq!(vmm_ticks_from_stat(stat), Some(1000));
        let status = "Name:\tcloud-hyperviso\nVmPeak:\t 9999 kB\nVmRSS:\t 2621440 kB\n";
        assert_eq!(rss_kb_from_status(status), Some(2_621_440));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stats_cache_is_keyed_by_pid_identity() {
        let cache = StatsCpuCache::default();
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let id_a = crate::state::PidIdentity {
            pid: 10,
            starttime: 111,
        };
        let id_b = crate::state::PidIdentity {
            pid: 10,
            starttime: 222,
        }; // reused pid
        assert_eq!(cache.observe("web", &id_a, 1000, ms(0)), None); // first sample
                                                                    // Same identity, second sample: yields a rate rather than None. The exact
                                                                    // permille value depends on the host's actual CLK_TCK (host_clk_tck() is
                                                                    // NOT injectable here — this asserts the presence of a rate, not its
                                                                    // magnitude, which is covered precisely by cpu_permille_from_tick_delta).
        assert!(cache.observe("web", &id_a, 1100, ms(1000)).is_some());
        // Same pid, NEW process: must reset, never splice tick counters.
        assert_eq!(cache.observe("web", &id_b, 50, ms(2000)), None);
    }

    #[test]
    fn peer_denial_renders_an_actionable_log_line() {
        let line = super::peer_denial_log(super::peercred::PeerVerdict::Deny {
            peer_uid: 0,
            owner_uid: 1000,
        });
        let line = line.expect("a Deny verdict must produce a log line");
        // Pin the SEMANTIC SLOTS, not just presence of both uids — a
        // transposed `format!(peer_uid, owner_uid)` swap would still pass a
        // bare `contains("uid 0")`/`contains("uid 1000")` pair.
        assert!(line.contains("from uid 0"), "got: {line}");
        assert!(line.contains("runs as uid 1000"), "got: {line}");
        assert!(
            line.contains("rejected"),
            "the line must say the connection was rejected; got: {line}"
        );
    }

    #[test]
    fn allowed_peer_produces_no_log_line() {
        assert!(super::peer_denial_log(super::peercred::PeerVerdict::Allow(
            super::peercred::PeerAuth::Enforced
        ))
        .is_none());
        assert!(super::peer_denial_log(super::peercred::PeerVerdict::Allow(
            super::peercred::PeerAuth::Unavailable
        ))
        .is_none());
    }

    /// The startup report line must always agree with what this platform's
    /// `enforcement_mode()` actually reports — same guarantee as
    /// `peercred::enforcement_mode_agrees_with_authorize_stream_on_our_own_pair`,
    /// but for the human-facing startup line rather than the accept-time
    /// verdict. Run on whatever CI shard this lands on (Linux or Windows),
    /// so both real `enforcement_mode()` outcomes get covered somewhere.
    #[test]
    fn peer_auth_mode_line_matches_this_platforms_enforcement_mode() {
        let line = super::peer_auth_mode_line();
        match super::peercred::enforcement_mode() {
            super::peercred::PeerAuth::Enforced => {
                let line = line.expect("Enforced must produce a startup line");
                assert!(line.contains("enforced"), "got: {line}");
                let uid = super::peercred::owner_uid()
                    .expect("enforcement_mode() == Enforced implies owner_uid().is_some()");
                assert!(line.contains(&format!("uid {uid}")), "got: {line}");
            }
            super::peercred::PeerAuth::Unavailable => {
                let line = line.expect("Unavailable must still produce a startup line");
                assert!(line.contains("UNAVAILABLE"), "got: {line}");
            }
        }
    }

    /// The SAME `enforcement_mode()` predicate now governs two unix planes:
    /// the control socket and every per-sandbox egress listener (F-CRED-5).
    /// The startup line is the only place an operator learns the posture, so
    /// it must name BOTH — otherwise a Windows operator reading "control
    /// socket ... UNAVAILABLE" is left to INFER the egress plane's posture,
    /// which is exactly the reported-vs-implied gap F-09 closed for control.
    #[test]
    fn peer_auth_mode_line_names_both_peer_authoritative_planes() {
        let line = super::peer_auth_mode_line().expect("a startup line is always produced");
        assert!(
            line.contains("control"),
            "the line must still name the control socket; got: {line}"
        );
        assert!(
            line.contains("egress"),
            "the line must also name the egress plane the same predicate now \
             governs; got: {line}"
        );
    }

    /// A security-posture line is read as an INVENTORY. This daemon binds a
    /// THIRD peer-authoritative unix listener per sandbox — the USB broker on
    /// `vsock.sock_1028` (`crate::usb::broker`) — and that one has NO peer
    /// check, on either platform. A line that names "control + egress" and
    /// stops there invites an operator to conclude every izbad unix socket is
    /// gated, which is worse than saying nothing.
    ///
    /// So the line must name the broker as UNCOVERED. Kills the mutant that
    /// drops the exclusion clause while leaving the (still-passing)
    /// `control`/`egress` assertions above intact.
    #[test]
    fn peer_auth_mode_line_does_not_imply_the_usb_broker_is_covered() {
        let line = super::peer_auth_mode_line().expect("a startup line is always produced");
        assert!(
            line.contains("USB broker"),
            "the line must name the one peer-authoritative unix plane it does \
             NOT cover; got: {line}"
        );
        assert!(
            line.contains("not"),
            "naming the USB broker is only honest if the line says it is NOT \
             covered; got: {line}"
        );
    }

    #[test]
    fn would_block_accept_error_produces_no_log_line() {
        let e = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert!(super::accept_error_message(&e).is_none());
    }

    #[test]
    fn other_accept_errors_produce_a_diagnostic() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        let line = super::accept_error_message(&e).expect("a non-WouldBlock error must log");
        assert!(line.contains("accept error"), "got: {line}");
    }

    // ── #181: the port-rule persistence verbs hold the per-sandbox lock ──────
    //
    // `persist_port_rule`/`unpersist_port_rule` are read-modify-writes of the
    // WHOLE config.json. Unlocked, two overlapping requests on independent
    // daemon threads each load the same file and each write it back, so the
    // later write silently discards the earlier — a published port simply
    // vanishes while the user holds a success message.

    #[test]
    fn persist_port_rule_refuses_while_the_sandbox_lock_is_held() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let held = crate::sandbox::lock_sandbox(&paths, "sb").expect("take the lock");
        let err = persist_port_rule(&paths, "sb", &port_rule("127.0.0.1", 8080, 80))
            .unwrap_err()
            .to_string();
        assert!(err.contains("busy"), "must refuse while locked: {err}");
        assert!(
            load_persisted_ports(&paths, "sb").is_empty(),
            "a refused persist must not have rewritten config.json"
        );

        drop(held);
        persist_port_rule(&paths, "sb", &port_rule("127.0.0.1", 8080, 80))
            .expect("the same persist succeeds once the lock is released");
    }

    #[test]
    fn unpersist_port_rule_refuses_while_the_sandbox_lock_is_held() {
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");
        let r = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&paths, "sb", &r).unwrap();

        let held = crate::sandbox::lock_sandbox(&paths, "sb").expect("take the lock");
        let err = unpersist_port_rule(&paths, "sb", r.bind, r.host_port)
            .unwrap_err()
            .to_string();
        assert!(err.contains("busy"), "must refuse while locked: {err}");
        assert_eq!(
            load_persisted_ports(&paths, "sb").len(),
            1,
            "a refused unpersist must not have rewritten config.json"
        );

        drop(held);
        assert!(unpersist_port_rule(&paths, "sb", r.bind, r.host_port).unwrap());
    }

    #[test]
    fn concurrent_port_persists_cannot_lose_one_that_reported_success() {
        // Two `izba port publish --persist` requests for one sandbox, on
        // independent threads. Under the lock the only two outcomes are "both
        // persisted" (serialized) or "one refused as busy" — never "both
        // reported success and one rule is gone".
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        let start = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for host_port in [8080u16, 9090] {
            let paths = paths.clone();
            let start = Arc::clone(&start);
            handles.push(std::thread::spawn(move || {
                let r = port_rule("127.0.0.1", host_port, 80);
                start.wait();
                (host_port, persist_port_rule(&paths, "sb", &r).is_ok())
            }));
        }
        let outcomes: Vec<(u16, bool)> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let ports = load_persisted_ports(&paths, "sb");
        for (host_port, reported_ok) in &outcomes {
            if *reported_ok {
                assert!(
                    ports.iter().any(|r| r.host_port == *host_port),
                    "publish of :{host_port} reported success but is absent from \
                     config.json — a concurrent edit silently discarded it \
                     (ports on disk: {ports:?})"
                );
            }
        }
        assert!(
            outcomes.iter().any(|(_, ok)| *ok),
            "at least one of two concurrent persists must succeed"
        );
    }

    #[test]
    fn back_to_back_port_persists_never_report_busy() {
        // The lock is per-verb, so ordinary sequential publishing must never
        // see the new "busy" refusal.
        let (_dir, paths) = test_paths();
        write_config_for_persist(&paths, "sb");

        for host_port in [8080u16, 9090, 7070] {
            persist_port_rule(&paths, "sb", &port_rule("127.0.0.1", host_port, 80))
                .unwrap_or_else(|e| panic!("sequential persist of :{host_port} failed: {e:#}"));
        }
        for host_port in [8080u16, 9090, 7070] {
            assert!(
                unpersist_port_rule(&paths, "sb", "127.0.0.1".parse().unwrap(), host_port)
                    .unwrap_or_else(|e| panic!(
                        "sequential unpersist of :{host_port} failed: {e:#}"
                    ))
            );
        }
        assert!(load_persisted_ports(&paths, "sb").is_empty());
    }

    // ── #181: the VNC toggle is a config.json read-modify-write too ──────────
    //
    // `VncSet` arrived with proto v6, after #181 was filed, so it was a fifth
    // whole-file read-modify-write skipping the lock: a `vnc on` overlapping a
    // port/volume/USB edit could discard it (or be discarded) with both
    // requests reporting success. Caught by review on the #181 PR.

    fn load_config_for_persist(paths: &Paths, name: &str) -> SandboxConfig {
        let p = paths.sandbox_dir(name).join(CONFIG_FILE);
        load_json(&p).unwrap().unwrap()
    }

    #[test]
    fn vnc_set_refuses_while_the_sandbox_lock_is_held() {
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");

        let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
        let err = handle_vnc_set(&d, "web".to_string(), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("busy"), "must refuse while locked: {err}");
        assert!(
            !load_config_for_persist(&d.paths, "web").vnc,
            "a refused vnc toggle must not have rewritten config.json"
        );

        drop(held);
        handle_vnc_set(&d, "web".to_string(), true)
            .expect("the same toggle succeeds once the lock is released");
        assert!(load_config_for_persist(&d.paths, "web").vnc);
    }

    #[test]
    fn even_a_no_op_vnc_set_is_serialized_like_every_other_config_verb() {
        // An earlier revision kept the equality check OUTSIDE the lock so a
        // redundant toggle stayed a cheap read-only no-op. That carve-out was
        // dropped: the GUI calls `vncSet` only from explicit, state-conditional
        // buttons, never on a poll, so it bought nothing — and it left one verb
        // able to answer Ok without ever holding the lock, which is exactly the
        // exception the contract exists to not have. The equality check now
        // lives inside the closure, where a redundant toggle rewrites identical
        // bytes.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");

        let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
        let err = handle_vnc_set(&d, "web".to_string(), false)
            .expect_err("no config verb answers Ok without the lock")
            .to_string();
        assert!(err.contains("busy"), "must refuse while locked: {err}");
        drop(held);

        handle_vnc_set(&d, "web".to_string(), false)
            .expect("the same no-op succeeds once the lock is released");
        assert!(!load_config_for_persist(&d.paths, "web").vnc);
    }

    #[test]
    fn a_redundant_vnc_enable_still_skips_the_volume_cap_check() {
        // Moving the equality check inside the closure must not start
        // re-validating a sandbox that is ALREADY vnc-enabled: an over-cap
        // config that predates the check would otherwise become impossible to
        // re-affirm. Same carve-out as before, just relocated.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");

        let p = d.paths.sandbox_dir("web").join(CONFIG_FILE);
        let mut cfg: SandboxConfig = load_json(&p).unwrap().unwrap();
        cfg.vnc = true;
        cfg.volumes = (0..24)
            .map(|i| crate::volume::VolumeSpec {
                name: Some(format!("v{i}")),
                guest_path: format!("/data{i}").into(),
                size_bytes: 1 << 20,
                eph_id: None,
            })
            .collect();
        save_json(&p, &cfg).unwrap();

        handle_vnc_set(&d, "web".to_string(), true)
            .expect("re-affirming an already-enabled desktop must not re-validate volumes");
        assert!(load_config_for_persist(&d.paths, "web").vnc);
    }

    #[test]
    fn concurrent_vnc_and_port_edits_cannot_lose_one() {
        // The CROSS-verb window: a `vnc on` and a `port publish --persist` for
        // one sandbox, on independent threads, each rewriting the whole
        // config.json. Unlocked, one silently discards the other while both
        // report success.
        const ROUNDS: usize = 20;
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");

        for round in 0..ROUNDS {
            let host_port = 8000 + round as u16;
            let enabled = round % 2 == 0;
            let start = Arc::new(std::sync::Barrier::new(2));

            let d2 = Arc::clone(&d);
            let s2 = Arc::clone(&start);
            let vnc = std::thread::spawn(move || {
                s2.wait();
                handle_vnc_set(&d2, "web".to_string(), enabled).is_ok()
            });

            let paths = d.paths.clone();
            let s3 = Arc::clone(&start);
            let port = std::thread::spawn(move || {
                let r = port_rule("127.0.0.1", host_port, 80);
                s3.wait();
                persist_port_rule(&paths, "web", &r).is_ok()
            });

            let vnc_ok = vnc.join().unwrap();
            let port_ok = port.join().unwrap();

            let cfg = load_config_for_persist(&d.paths, "web");
            if vnc_ok {
                assert_eq!(
                    cfg.vnc, enabled,
                    "vnc set to {enabled} reported success but config.json disagrees \
                     after round {round} — a concurrent edit discarded it"
                );
            }
            if port_ok {
                assert!(
                    cfg.ports.iter().any(|r| r.host_port == host_port),
                    "publish of :{host_port} reported success but is absent from \
                     config.json after round {round} — a concurrent edit discarded it"
                );
            }
        }
    }

    // ── #181: a persist that loses the lock must not leave live effects ──────
    //
    // `handle_port_publish` binds the relay and saves ports.json BEFORE
    // persisting into config.json. Making `persist_port_rule` take the lock
    // turned that last step from "fails only on I/O error" into "fails
    // routinely under contention", so without compensation the request now
    // reports failure while the port is actually forwarding — and the rule
    // would vanish on the next start, since config.json never got it.
    // Tested at the CALL SITE: a rule with a test and a call site without one
    // is this project's recurring defect class.

    /// A live-enough sandbox for `handle_port_publish`'s liveness gate, plus a
    /// free loopback port. Returns `None` when the environment denies `bind`.
    fn publishable_sandbox(
        dir: &tempfile::TempDir,
        paths: Paths,
        who: &str,
    ) -> Option<(Arc<Daemon>, u16, crate::state::PidIdentity)> {
        // Reserved, not probed: the relay binds this port much later, so it
        // must be one no other test's `:0` bind can be handed in the meantime.
        let Some(host_port) = crate::testutil::reserve_port() else {
            eprintln!("SKIP {who}: bind denied");
            return None;
        };

        let vmm = spawn_sleep(dir.path());
        let mut deps = test_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        write_config_for_persist(&d.paths, "web");
        write_state(&d.paths, "web", vmm.clone());
        Some((d, host_port, vmm))
    }

    /// A scenario attempt that proved nothing: the host port was taken between
    /// the probe and the relay's bind, so the request failed for a reason that
    /// has nothing to do with the behaviour under test.
    struct Stolen;

    /// `handle_port_publish`, with that harness collision told apart from the
    /// verdict under test.
    ///
    /// `publishable_sandbox` closes its probe socket before the relay binds, so
    /// any other test in this binary that asks the kernel for an ephemeral port
    /// in that window can be handed the very port just released — the
    /// `bind(("127.0.0.1", 0))` probes elsewhere in this file and `free_port`
    /// in `relays.rs`/`supervisor.rs` all draw from the same range. A collision
    /// is a fact about the harness, never about the request, so it is retried
    /// rather than asserted on. Keyed on THIS rule's own `bind:port` so the
    /// forced `host port 127.0.0.1:0 is unavailable` failure injected in
    /// `relays.rs` can never be mistaken for one.
    fn publish_unless_stolen(
        d: &Arc<Daemon>,
        rule: &crate::state::PortRule,
        persist: bool,
    ) -> Result<anyhow::Result<DaemonResponse>, Stolen> {
        let r = handle_port_publish(d, "web".into(), rule.clone(), persist);
        if let Err(e) = &r {
            let taken = format!("host port {}:{} is unavailable", rule.bind, rule.host_port);
            if format!("{e:#}").contains(&taken) {
                return Err(Stolen);
            }
        }
        Ok(r)
    }

    /// Run a port-publish scenario against a fresh sandbox and a freshly probed
    /// host port, RETRYING the whole scenario — sandbox and port both — when
    /// `body` reports the port was stolen. Returns without running anything
    /// where binding is denied outright, matching `publishable_sandbox`.
    ///
    /// The retry has to rebuild the sandbox, not just re-probe: the port is
    /// baked into the rule and into whatever `config.json`/`ports.json` state
    /// the scenario wrote before the racy publish.
    fn port_publish_scenario(who: &str, body: impl Fn(&Arc<Daemon>, u16) -> Result<(), Stolen>) {
        for _ in 0..20 {
            let (dir, paths) = test_paths();
            let Some((d, host_port, _vmm)) = publishable_sandbox(&dir, paths, who) else {
                return;
            };
            if body(&d, host_port).is_ok() {
                return;
            }
        }
        panic!("{who}: no host port survived the probe->bind window in 20 attempts");
    }

    /// Runtime-skip probe for the two tests below, which bind for real.
    fn port_bind_works(who: &str) -> bool {
        match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP {who}: bind denied ({e})");
                false
            }
            Err(e) => panic!("bind probe: {e}"),
        }
    }

    #[test]
    fn a_port_taken_before_the_bind_reads_as_stolen() {
        // Half one of the seam's contract: an occupied host port is a harness
        // collision. Without this the retry driver would never fire and the
        // flake it exists to kill would come straight back.
        port_publish_scenario(
            "a_port_taken_before_the_bind_reads_as_stolen",
            |d, host_port| {
                let rule = port_rule("127.0.0.1", host_port, 80);
                // Play the thief ourselves. Losing that race to a real one
                // proves nothing either way, so it is a retry, not a failure —
                // this test must not become an instance of the flake it guards.
                let Ok(_thief) = std::net::TcpListener::bind(("127.0.0.1", host_port)) else {
                    return Err(Stolen);
                };
                assert!(
                    publish_unless_stolen(d, &rule, true).is_err(),
                    "a port held by someone else must read as stolen, not as a verdict"
                );
                Ok(())
            },
        );
    }

    #[test]
    fn a_busy_lock_is_a_verdict_not_a_collision() {
        // Half two, and the one that keeps the seam honest: `busy` is exactly
        // what the tests below assert on, so it must survive the filter. A
        // predicate that swallowed it as a collision would never let this
        // scenario report success, so the driver would panic itself out after
        // 20 attempts rather than pass.
        port_publish_scenario(
            "a_busy_lock_is_a_verdict_not_a_collision",
            |d, host_port| {
                let rule = port_rule("127.0.0.1", host_port, 80);

                let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
                let verdict = publish_unless_stolen(d, &rule, true);
                drop(held);

                let err = format!(
                    "{:#}",
                    verdict?.expect_err("the persist half must be refused")
                );
                assert!(err.contains("busy"), "got: {err}");
                Ok(())
            },
        );
    }

    #[test]
    fn a_stolen_port_retries_the_whole_scenario() {
        // The driver's contract: `Stolen` buys a fresh sandbox and a fresh
        // port, and the scenario runs again — it is not a failure, and it is
        // not silently dropped.
        if !port_bind_works("a_stolen_port_retries_the_whole_scenario") {
            return;
        }
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        port_publish_scenario("a_stolen_port_retries_the_whole_scenario", |_d, _port| {
            if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                Err(Stolen)
            } else {
                Ok(())
            }
        });
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "the driver must re-run the scenario until it is not a collision"
        );
    }

    #[test]
    fn a_persist_refused_as_busy_leaves_no_relay_behind() {
        port_publish_scenario(
            "a_persist_refused_as_busy_leaves_no_relay_behind",
            |d, host_port| {
                let rule = port_rule("127.0.0.1", host_port, 80);

                let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
                let err = publish_unless_stolen(d, &rule, true);
                drop(held);

                let err = err?.expect_err("a persisted publish must fail while the lock is held");
                let err = err.to_string();
                assert!(err.contains("busy"), "expected a busy refusal, got: {err}");

                assert!(
                    !d.relays.active("web").contains(&rule),
                    "the request reported failure, so it must not leave the port forwarding"
                );
                assert!(
                    !relays::load_rules_migrating(&d.paths, "web")
                        .unwrap()
                        .0
                        .contains(&rule),
                    "ports.json must not keep a rule the request rejected"
                );
                assert!(
                    !load_persisted_ports(&d.paths, "web").contains(&rule),
                    "config.json must not keep a rule the request rejected"
                );
                Ok(())
            },
        );
    }

    #[test]
    fn an_uncontended_persisted_publish_still_binds_the_relay() {
        port_publish_scenario(
            "an_uncontended_persisted_publish_still_binds_the_relay",
            |d, host_port| {
                // Control for the rollback above: it must fire only on failure.
                let rule = port_rule("127.0.0.1", host_port, 80);

                publish_unless_stolen(d, &rule, true)?
                    .expect("an uncontended persisted publish must succeed");

                assert!(d.relays.active("web").contains(&rule));
                assert!(load_persisted_ports(&d.paths, "web").contains(&rule));
                Ok(())
            },
        );
    }

    #[test]
    fn a_busy_persist_does_not_tear_down_a_pre_existing_relay() {
        port_publish_scenario(
            "a_busy_persist_does_not_tear_down_a_pre_existing_relay",
            |d, host_port| {
                // The rollback must undo only what THIS request did. Re-persisting an
                // already-live rule is exactly what the app's "Make persistent" button
                // does, and losing the lock there must not kill the running relay.
                let rule = port_rule("127.0.0.1", host_port, 80);

                // Already forwarding, not yet persisted.
                publish_unless_stolen(d, &rule, false)?
                    .expect("the first, unpersisted publish must succeed");
                assert!(d.relays.active("web").contains(&rule));

                let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
                let err = handle_port_publish(d, "web".into(), rule.clone(), true)
                    .expect_err("the persist half must be refused while the lock is held");
                drop(held);
                assert!(err.to_string().contains("busy"), "got: {err}");

                assert!(
                    d.relays.active("web").contains(&rule),
                    "the relay predates this request — a failed persist must not tear it down"
                );
                Ok(())
            },
        );
    }

    // ── #181: a rollback that ITSELF fails must be loud, never swallowed ─────
    //
    // The compensation in `handle_port_publish` can fail too. Discarding those
    // errors would let the request return failure while the port keeps
    // forwarding — or while `ports.json` still lists a rule `config.json` never
    // got, which a daemon restart would re-adopt into a live relay the user was
    // told had failed.

    #[test]
    fn rolling_back_a_relay_that_is_not_there_says_it_is_still_forwarding() {
        let (dir, paths) = test_paths();
        let Some((d, host_port, _vmm)) = publishable_sandbox(
            &dir,
            paths,
            "rolling_back_a_relay_that_is_not_there_says_it_is_still_forwarding",
        ) else {
            return;
        };
        // Never published, so the unpublish half of the rollback fails.
        let rule = port_rule("127.0.0.1", host_port, 80);

        let note = rollback_published_relay(&d, "web", &rule)
            .expect_err("unpublishing a relay that is not held must report, not swallow");
        assert!(
            note.contains("still forwarding"),
            "the note must say the port may still be live; got: {note}"
        );
    }

    #[test]
    fn a_rollback_that_cannot_rewrite_ports_json_says_it_would_be_re_adopted() {
        port_publish_scenario(
            "a_rollback_that_cannot_rewrite_ports_json_says_it_would_be_re_adopted",
            |d, host_port| {
                let rule = port_rule("127.0.0.1", host_port, 80);
                publish_unless_stolen(d, &rule, false)?.expect("publish must succeed");

                // Fault injection that works regardless of uid: a directory where the
                // rules file goes makes the write fail with IsADirectory.
                let rules = relays::rules_path(&d.paths, "web");
                std::fs::remove_file(&rules).ok();
                std::fs::create_dir_all(&rules).unwrap();

                let note = rollback_published_relay(d, "web", &rule)
                    .expect_err("a ports.json rewrite failure must report, not swallow");
                assert!(
                    note.contains("re-adopt"),
                    "the note must warn the rule would come back on restart; got: {note}"
                );
                Ok(())
            },
        );
    }

    #[test]
    fn a_clean_rollback_reports_nothing() {
        port_publish_scenario("a_clean_rollback_reports_nothing", |d, host_port| {
            let rule = port_rule("127.0.0.1", host_port, 80);
            publish_unless_stolen(d, &rule, false)?.expect("publish must succeed");

            rollback_published_relay(d, "web", &rule)
                .expect("a clean rollback must report nothing");
            assert!(!d.relays.active("web").contains(&rule));
            assert!(
                !relays::load_rules_migrating(&d.paths, "web")
                    .unwrap()
                    .0
                    .contains(&rule),
                "a clean rollback must also drop the rule from ports.json"
            );
            Ok(())
        });
    }

    // ── #181: the documented recovery must actually recover ─────────────────
    //
    // A rollback whose ports.json rewrite failed strands a rule there with no
    // live relay and nothing in config.json. `adopt` republishes every
    // ports.json rule of a running sandbox, so that entry resurrects the port
    // on the next daemon restart — and the error this PR emits points the user
    // at `izba port unpublish`, so that command has to be able to clear it.

    #[test]
    fn unpublish_clears_a_rule_stranded_in_ports_json() {
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let rule = port_rule("127.0.0.1", 8080, 80);
        // Exactly the state a failed rollback leaves: ports.json only.
        relays::save_rules(&d.paths, "web", std::slice::from_ref(&rule)).unwrap();

        handle_port_unpublish(&d, "web".into(), rule.bind, rule.host_port)
            .expect("the documented recovery command must clear a stranded rule");

        assert!(
            !relays::load_rules_migrating(&d.paths, "web")
                .unwrap()
                .0
                .contains(&rule),
            "ports.json must not keep a rule no relay and no config references"
        );
    }

    #[test]
    fn unpublish_of_a_port_that_exists_nowhere_still_errors() {
        // The reconcile above must not turn the genuine "no such published
        // port" case into a silent success.
        //
        // ports.json deliberately holds a NEIGHBOUR sharing the bind address
        // but not the port: the stranded-rule probe matches on bind AND port,
        // and an empty file would let a probe matching on EITHER pass this test
        // unnoticed (that is the mutant this seeding kills). With a bind-only
        // match the probe would call the rule stranded, reconcile, and return
        // Ok for a port that exists nowhere.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let neighbour = port_rule("127.0.0.1", 9090, 90);
        relays::save_rules(&d.paths, "web", std::slice::from_ref(&neighbour)).unwrap();

        let err = handle_port_unpublish(&d, "web".into(), "127.0.0.1".parse().unwrap(), 9999)
            .expect_err("a port that exists nowhere is still an error");
        assert!(
            err.to_string().contains("no such published port"),
            "got: {err}"
        );
        assert!(
            relays::load_rules_migrating(&d.paths, "web")
                .unwrap()
                .0
                .contains(&neighbour),
            "a failed unpublish must leave ports.json alone"
        );
    }

    #[test]
    fn unpublish_of_a_known_port_on_a_different_bind_still_errors() {
        // The other half of the same AND: same host port, different bind.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let neighbour = port_rule("127.0.0.1", 9090, 90);
        relays::save_rules(&d.paths, "web", std::slice::from_ref(&neighbour)).unwrap();

        let err = handle_port_unpublish(&d, "web".into(), "127.0.0.2".parse().unwrap(), 9090)
            .expect_err("a different bind address is a different rule");
        assert!(
            err.to_string().contains("no such published port"),
            "got: {err}"
        );
        assert!(
            relays::load_rules_migrating(&d.paths, "web")
                .unwrap()
                .0
                .contains(&neighbour),
            "a failed unpublish must leave ports.json alone"
        );
    }

    #[test]
    fn clearing_a_stranded_rule_keeps_the_other_entries() {
        // The reconcile must remove the TARGET rule, not overwrite ports.json
        // with the live relay set: for a stopped sandbox that set is empty, so
        // an overwrite would take the neighbours with it. They are not inert —
        // `relays::persisted_host_ports` reads every sandbox's ports.json to
        // pick a VNC display port that avoids persisted fixed rules (#221), so
        // dropping them narrows that avoidance set into a later collision.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let target = port_rule("127.0.0.1", 8080, 80);
        let neighbour = port_rule("127.0.0.1", 9090, 90);
        relays::save_rules(&d.paths, "web", &[target.clone(), neighbour.clone()]).unwrap();

        handle_port_unpublish(&d, "web".into(), target.bind, target.host_port)
            .expect("clearing a stranded rule must succeed");

        let (rules, _) = relays::load_rules_migrating(&d.paths, "web").unwrap();
        assert!(
            !rules.contains(&target),
            "the target rule must be gone; got {rules:?}"
        );
        assert!(
            rules.contains(&neighbour),
            "an unrelated rule must survive; got {rules:?}"
        );
    }

    // ── #181: an unreadable ports.json is not the same as "no such rule" ─────
    //
    // The stranded-rule probe used `unwrap_or(false)`, so a read or parse
    // failure was indistinguishable from absence — the third swallow-an-error
    // shape on this PR. `load_rules_migrating` already maps a MISSING file to
    // `Ok(empty)`, so the only things that reach the error arm are a genuinely
    // unreadable file or one matching neither schema, and in exactly those
    // cases "no such published port" is a lie: the rule may still be on disk,
    // and `adopt` republishes it once the file is readable again.

    /// ports.json that parses as neither the current nor the legacy schema.
    fn corrupt_ports_json(d: &Arc<Daemon>, name: &str) {
        std::fs::write(relays::rules_path(&d.paths, name), b"{ not ports.json }").unwrap();
    }

    #[test]
    fn unpublish_reports_an_unreadable_ports_json_rather_than_absence() {
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        corrupt_ports_json(&d, "web");

        let err = handle_port_unpublish(&d, "web".into(), "127.0.0.1".parse().unwrap(), 8080)
            .expect_err("an unreadable ports.json must not be reported as absence");
        let err = format!("{err:#}");
        assert!(
            !err.contains("no such published port"),
            "a read failure must not masquerade as 'the rule is not there': {err}"
        );
        assert!(
            err.contains("ports.json"),
            "the error must name the file it could not read: {err}"
        );
    }

    #[test]
    fn an_unreadable_ports_json_fails_before_config_json_is_touched() {
        // The probe is fallible, so it must run BEFORE the config write — the
        // same fail-before-side-effects rule this PR added to CLAUDE.md.
        // Otherwise the command strips the rule from config.json, returns Ok
        // because it "unpersisted something", and leaves the stranded entry.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let rule = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&d.paths, "web", &rule).unwrap();
        corrupt_ports_json(&d, "web");

        let err = handle_port_unpublish(&d, "web".into(), rule.bind, rule.host_port)
            .expect_err("an unreadable ports.json must fail the command");
        assert!(format!("{err:#}").contains("ports.json"), "got: {err:#}");
        assert!(
            load_persisted_ports(&d.paths, "web").contains(&rule),
            "config.json must be untouched when the command fails"
        );
    }

    #[test]
    fn a_missing_ports_json_is_still_absence_not_an_error() {
        // Guard the other direction: `load_rules_migrating` maps NotFound to an
        // empty list, and propagating read errors must not turn the ordinary
        // "no ports.json yet" case into a failure.
        let (_dir, d) = test_daemon();
        write_config_for_persist(&d.paths, "web");
        let rule = port_rule("127.0.0.1", 8080, 80);
        persist_port_rule(&d.paths, "web", &rule).unwrap();
        assert!(!relays::rules_path(&d.paths, "web").exists());

        handle_port_unpublish(&d, "web".into(), rule.bind, rule.host_port)
            .expect("a persisted-only port unpublishes fine with no ports.json");
        assert!(load_persisted_ports(&d.paths, "web").is_empty());
    }

    // ── #181: "I bound it" is not "I own it" ────────────────────────────────
    //
    // A sibling publish of the same rule that arrives after our bind sees the
    // relay already active, adopts it, and may persist it successfully while
    // our own persist is losing the lock. Rolling back then hands that caller a
    // port that is neither forwarding nor recorded.

    #[test]
    fn a_failed_publish_does_not_tear_down_a_relay_another_request_persisted() {
        port_publish_scenario(
            "a_failed_publish_does_not_tear_down_a_relay_another_request_persisted",
            |d, host_port| {
                let rule = port_rule("127.0.0.1", host_port, 80);
                // The sibling's work: the rule is already in config.json. Our request
                // will bind the relay itself (`bound_here`) and then fail to persist.
                persist_port_rule(&d.paths, "web", &rule).unwrap();

                let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
                let err = publish_unless_stolen(d, &rule, true);
                drop(held);
                let err = err?
                    .expect_err("the persist half must still be refused while the lock is held");
                assert!(err.to_string().contains("busy"), "got: {err:#}");

                assert!(
                    d.relays.active("web").contains(&rule),
                    "config.json already lists this rule, so the relay is not ours to \
                 tear down — a sibling request is relying on it"
                );
                assert!(
                    load_persisted_ports(&d.paths, "web").contains(&rule),
                    "and the sibling's persisted rule must survive untouched"
                );
                Ok(())
            },
        );
    }

    #[test]
    fn a_failed_publish_still_rolls_back_a_relay_nobody_persisted() {
        port_publish_scenario(
            "a_failed_publish_still_rolls_back_a_relay_nobody_persisted",
            |d, host_port| {
                // The control: with config.json NOT listing the rule, the relay really
                // is this request's own and must still be rolled back. Without this the
                // ownership test above could be satisfied by never rolling back at all.
                let rule = port_rule("127.0.0.1", host_port, 80);
                // A NEAR-MISS in config.json: same bind, different host port. The
                // ownership check keys on bind AND port, and loopback is the bind of
                // essentially every rule — so a check matching on either half alone
                // would call this rule "already persisted" and skip the rollback,
                // reinstating the leak. An empty config.json cannot tell the two apart.
                let neighbour = port_rule("127.0.0.1", host_port.wrapping_add(1).max(1024), 90);
                persist_port_rule(&d.paths, "web", &neighbour).unwrap();

                let held = crate::sandbox::lock_sandbox(&d.paths, "web").expect("take the lock");
                let err = publish_unless_stolen(d, &rule, true);
                drop(held);
                let err = err?.expect_err("a persisted publish must fail while the lock is held");
                assert!(err.to_string().contains("busy"), "got: {err:#}");

                assert!(
                    !d.relays.active("web").contains(&rule),
                    "nothing persisted THIS rule, so the failed request must not \
                     leave it forwarding"
                );
                assert!(
                    load_persisted_ports(&d.paths, "web").contains(&neighbour),
                    "and the unrelated persisted rule must be untouched"
                );
                Ok(())
            },
        );
    }

    #[test]
    fn a_publish_that_cannot_read_config_keeps_the_relay_and_says_so() {
        port_publish_scenario(
            "a_publish_that_cannot_read_config_keeps_the_relay_and_says_so",
            |d, host_port| {
                // The "cannot tell who owns it" arm. The two mistakes are not
                // symmetric: a leaked relay is recoverable with `izba port unpublish`,
                // tearing down a sibling's live port is not — so an unreadable
                // config.json must keep the relay and report, never silently roll back.
                //
                // Also the one case that exercises the decision guard being TAKEN: the
                // sandbox lock is free here (the persist fails on I/O, not contention),
                // so the handler acquires it, hits the read error, and must still
                // release it — asserted at the end.
                let rule = port_rule("127.0.0.1", host_port, 80);

                // Uid-independent I/O failure: a directory where the file goes.
                let cfg = d.paths.sandbox_dir("web").join(CONFIG_FILE);
                std::fs::remove_file(&cfg).unwrap();
                std::fs::create_dir_all(&cfg).unwrap();

                let err = publish_unless_stolen(d, &rule, true)?
                    .expect_err("an unreadable config.json must fail the publish");
                let err = format!("{err:#}");
                assert!(
                    err.contains("left the relay") && err.contains("could not read config.json"),
                    "the error must say the relay is still up and why: {err}"
                );
                assert!(
                    d.relays.active("web").contains(&rule),
                    "an undecidable ownership check must keep the relay, not tear it down"
                );
                assert!(
                    crate::sandbox::lock_sandbox(&d.paths, "web").is_ok(),
                    "the decision guard must be released even on the error path"
                );
                Ok(())
            },
        );
    }
}
