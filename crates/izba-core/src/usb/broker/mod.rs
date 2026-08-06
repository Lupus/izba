//! The guest-facing USB plane (vsock 1028).
//!
//! izbad binds one listener per sandbox, **only** while that sandbox holds at
//! least one device grant and an upstream is configured. With USB off there is
//! nothing for a guest to dial — not a listener that would refuse, but no
//! socket at all. That is the phase-2 "disabled USB adds no attack surface"
//! promise kept structurally rather than argued.
//!
//! The plane carries exactly one request shape ([`izba_proto::StreamOpen::UsbAttach`]),
//! and everything after the reply is opaque bytes in one direction and
//! validated URBs in the other. See [`session`] for the op phase.

pub mod session;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use izba_proto::{read_frame, write_frame, ErrorKind, Response, StreamOpen, USB_PORT};

use crate::daemon::egress::audit::{AuditRecord, AuditSink, Tier};
use crate::daemon::transport::UdsListener;
use crate::paths::Paths;
use crate::vmm::{IoStream, UdsStream};

/// Host-side unix path the VMM bridges guest-initiated vsock-1028 connections
/// to, the same `<run dir>/vsock.sock_<port>` convention the egress plane uses.
pub fn listener_path(run_dir: &Path) -> PathBuf {
    run_dir.join(format!("vsock.sock_{USB_PORT}"))
}

/// How long a guest may take over the whole attach handshake — the one frame it
/// sends and everything izbad does before replying.
///
/// Enforced as a TOTAL budget, not a per-read one. A socket timeout bounds each
/// individual `read(2)`, which a guest defeats trivially by sending one byte
/// just under the limit forever; [`Deadlined`] is what makes the deadline real.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many attach handshakes may be in flight per sandbox.
///
/// Attach is a human-driven action — one at a time in practice — so this sits
/// far above any legitimate use and exists only to bound a guest that opens
/// connections in a loop. Past it, connections are dropped at accept rather
/// than queued: izbad's threads and descriptors are shared with every other
/// sandbox, which makes an unbounded accept loop here a cross-sandbox denial of
/// service rather than merely a local one.
const MAX_INFLIGHT_HANDSHAKES: usize = 8;

/// Wraps a reader so no read is attempted past `deadline`.
///
/// The per-socket timeout still bounds each individual read; this bounds their
/// SUM, which is what turns "a guest cannot hold a thread open" from a claim
/// into a fact. Once the budget is spent every further read fails immediately,
/// so a drip-feeding guest is cut off instead of serviced indefinitely.
struct Deadlined<R> {
    inner: R,
    deadline: std::time::Instant,
}

impl<R: Read> Read for Deadlined<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if std::time::Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the USB attach handshake took too long",
            ));
        }
        self.inner.read(buf)
    }
}

struct BrokerSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// Counts handshakes in flight and releases its slot however the connection
/// ends, including a panic in the handler.
struct InflightGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// All USB listeners, keyed by sandbox name. The daemon owns one instance for
/// its lifetime; a daemon restart severs live attachments, which the guest sees
/// as a device unplug — honest, and consistent with "VMs are never
/// auto-restarted".
pub struct UsbBroker {
    inner: Mutex<HashMap<String, BrokerSlot>>,
    audit: AuditSink,
}

impl UsbBroker {
    pub fn new(audit: AuditSink) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            audit,
        }
    }

    /// Bind or unbind `name`'s USB plane to match what is on disk right now.
    ///
    /// Deliberately not called `ensure_listening` like its egress sibling: it
    /// also **unbinds**. Revoking the last grant has to close the plane, not
    /// leave it open until the next restart — the same reasoning that makes
    /// `apply_usb_guard` take effect on the next flow rather than the next boot.
    ///
    /// Idempotent, and it rebinds a slot whose accept thread died, so it
    /// doubles as the supervisor's respawn path.
    pub fn refresh(&self, paths: &Paths, name: &str, run_dir: &Path) -> Result<()> {
        if !crate::usb::plane_wanted(paths, name) {
            self.stop(name, run_dir);
            return Ok(());
        }
        let mut inner = self.inner.lock().unwrap();
        if let Some(slot) = inner.get(name) {
            if !slot.thread.is_finished() {
                return Ok(());
            }
            // Only reachable if the accept thread exited unexpectedly: `stop`
            // always removes the slot, so it never leaves a finished one behind.
            inner.remove(name);
        }
        let path = listener_path(run_dir);
        crate::paths::create_dir_700(run_dir, paths.root())
            .with_context(|| format!("creating run dir {}", run_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", run_dir.display()))?;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing stale {}", path.display())),
        }
        let listener = UdsListener::bind(&path)
            .with_context(|| format!("binding USB listener {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("USB listener nonblocking")?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let paths2 = paths.clone();
        let audit = self.audit.clone();
        let sandbox = name.to_string();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        // Claim a slot BEFORE spawning: a guest that dials in a
                        // loop must be refused at accept, not after it has
                        // already cost a thread.
                        if inflight.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_HANDSHAKES {
                            inflight.fetch_sub(1, Ordering::SeqCst);
                            eprintln!(
                                "izbad: too many USB handshakes in flight for '{sandbox}'; \
                                 dropping a connection"
                            );
                            continue;
                        }
                        let guard = InflightGuard(Arc::clone(&inflight));
                        let paths = paths2.clone();
                        let audit = audit.clone();
                        let sandbox = sandbox.clone();
                        std::thread::spawn(move || {
                            let _guard = guard;
                            handle_conn(conn, &sandbox, &paths, &audit)
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("izbad: USB accept for '{sandbox}': {e}");
                        return;
                    }
                }
            }
        });
        inner.insert(name.to_string(), BrokerSlot { stop, thread });
        Ok(())
    }

    /// Stop and join `name`'s listener and remove its socket file. Only the
    /// accept loop is joined: an in-flight attachment is a live device stream,
    /// and it ends when the VM does.
    pub fn stop(&self, name: &str, run_dir: &Path) {
        let slot = self.inner.lock().unwrap().remove(name);
        if let Some(slot) = slot {
            slot.stop.store(true, Ordering::SeqCst);
            let _ = slot.thread.join();
        }
        // Remove the socket unconditionally: a listener bound by a previous
        // daemon leaves a file this process has no slot for, and leaving it
        // behind would let the VMM bridge a connection to nothing.
        let _ = std::fs::remove_file(listener_path(run_dir));
    }

    /// Test hook: a slot whose accept thread has already finished, standing in
    /// for one that crashed. Mirrors `EgressManager::insert_for_test`.
    #[cfg(test)]
    fn insert_finished_slot(&self, name: &str) {
        let thread = std::thread::spawn(|| {});
        while !thread.is_finished() {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.inner.lock().unwrap().insert(
            name.to_string(),
            BrokerSlot {
                stop: Arc::new(AtomicBool::new(false)),
                thread,
            },
        );
    }

    pub fn listening(&self, name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|s| !s.thread.is_finished())
            .unwrap_or(false)
    }
}

/// Serve one guest-initiated USB connection.
// reason: transport glue. `serve_attach` below carries every decision and is
// unit-tested over a `UnixStream` pair; what is left here is the timeout, the
// real dialer, and the splice, none of which exist without a bound listener.
#[mutants::skip]
fn handle_conn(mut conn: UdsStream, sandbox: &str, paths: &Paths, audit: &AuditSink) {
    // Two layers, and both are needed: the socket timeout bounds each read, and
    // `Deadlined` (inside `serve_attach`) bounds their sum.
    let _ = conn.set_io_timeout(Some(HANDSHAKE_TIMEOUT));
    let Some((_attached, upstream)) = serve_attach(&mut conn, sandbox, paths, audit, dial) else {
        return;
    };
    // The deadline has to go before the splice: URBs arrive whenever the device
    // has something to say, which may be minutes from now or never.
    let _ = conn.set_io_timeout(None);
    splice(conn, upstream);
}

/// Read the guest's one frame, authorize it, import the device, and reply.
///
/// Generic over both streams and over the dialer, so the entire handshake —
/// including every refusal — is exercised without binding anything. Returns the
/// imported device and the upstream connection when the caller should now
/// splice; `None` when the exchange ended, in which case the guest has already
/// been told why.
fn serve_attach<C, U, D>(
    conn: &mut C,
    sandbox: &str,
    paths: &Paths,
    audit: &AuditSink,
    dial: D,
) -> Option<(session::Attached, U)>
where
    C: Read + Write,
    U: Read + Write,
    D: Fn(SocketAddr) -> Result<U>,
{
    // The frame is read through a total deadline: a guest that dials and then
    // drip-feeds one byte at a time would otherwise satisfy every per-read
    // timeout and hold this thread indefinitely.
    let open: StreamOpen = {
        let mut bounded = Deadlined {
            inner: &mut *conn,
            deadline: std::time::Instant::now() + HANDSHAKE_TIMEOUT,
        };
        read_frame(&mut bounded).ok()?
    };
    let StreamOpen::UsbAttach { device } = open else {
        // This plane exists for exactly one purpose. Anything else arriving on
        // it is a guest probing what it was handed, not a mistake to guess at.
        let _ = write_frame(
            conn,
            &Response::Error {
                kind: ErrorKind::BadRequest,
                message: "only usb_attach is handled on the USB port".into(),
            },
        );
        return None;
    };

    match attach(sandbox, paths, &device, audit, dial) {
        Ok((attached, upstream)) => {
            write_frame(
                conn,
                &Response::UsbAttached {
                    devid: attached.devid,
                    speed: attached.speed,
                },
            )
            .ok()?;
            Some((attached, upstream))
        }
        Err(refusal) => {
            // Only the guest-safe half crosses the boundary. The full chain is
            // already in the audit log and the daemon's stderr, both host-only.
            let _ = write_frame(
                conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: refusal.guest,
                },
            );
            None
        }
    }
}

/// A refused attach, split into the half the guest may be told and the half the
/// host keeps.
///
/// The split exists because of D1: the guest must never learn the upstream's
/// address. Host-side errors routinely name it — `connecting to the usbip
/// upstream at 10.0.0.5:3240` — and izba-init passes izbad's message straight
/// through to the user, so returning the raw chain would hand the guest the
/// upstream topology every time a dial failed. The full chain still reaches the
/// audit log and the daemon's stderr, which are host-only.
struct Refusal {
    /// Safe to send across the boundary: device-level facts the guest already
    /// knows, or a reason with no topology in it.
    guest: String,
    /// The real error, for the audit log.
    host: String,
}

impl Refusal {
    /// A reason that is inherently free of host topology — it is about the
    /// device the guest just named, or the sandbox's own grants.
    fn device_level(e: impl std::fmt::Display) -> Self {
        let text = e.to_string();
        Self {
            guest: text.clone(),
            host: text,
        }
    }

    /// A reason that touches the upstream. The guest gets the shape of the
    /// failure and nothing else.
    fn upstream(guest: &str, host: impl std::fmt::Display) -> Self {
        Self {
            guest: guest.to_string(),
            host: host.to_string(),
        }
    }
}

/// Everything between the guest's frame and its reply: authorize, enumerate,
/// import, verify. Returns the imported device and the connection carrying it.
fn attach<U, D>(
    sandbox: &str,
    paths: &Paths,
    device: &str,
    audit: &AuditSink,
    dial: D,
) -> std::result::Result<(session::Attached, U), Refusal>
where
    U: Read + Write,
    D: Fn(SocketAddr) -> Result<U>,
{
    let settings = crate::usb::settings::load(&paths.usb_dir());
    // Re-classified here, not merely read: a hostname accepted as private when
    // it was configured can resolve somewhere else by the time a guest asks.
    // Its refusal names the host, so the guest gets the generic form.
    let addr = crate::usb::dialable_upstream(&settings)
        .map_err(|e| Refusal::upstream("usb passthrough is not available for this sandbox", e))?;
    let id: crate::usb::DeviceId = device.parse().map_err(Refusal::device_level)?;

    // The grant is re-read from disk on every attach rather than cached: a
    // revoke must take effect on the next attempt, not at the next restart.
    let grants = crate::usb::grants_of(paths, sandbox);
    let Some(grant) = crate::usb::grants::find(&grants, id).cloned() else {
        let r = Refusal::device_level(format!("{id} is not granted to '{sandbox}'"));
        deny(audit, sandbox, addr, &id.to_string(), &r.host);
        return Err(r);
    };

    let outcome = (|| -> std::result::Result<(session::Attached, U), Refusal> {
        // One operation per TCP connection, so this is two dials: the devlist
        // connection is dropped, and the import connection becomes the URB
        // stream. Every dial and I/O failure names the address, so all of them
        // are reported to the guest generically.
        let unreachable = |e| Refusal::upstream("the usbip upstream is not reachable", e);
        let mut lister = dial(addr).map_err(|e| unreachable(format!("{e:#}")))?;
        lister
            .write_all(&izba_proto::usbip::encode_op_req_devlist())
            .map_err(|e| unreachable(format!("sending OP_REQ_DEVLIST: {e}")))?;
        lister.flush().ok();
        let devices = crate::usb::inventory::read_devlist_reply(&mut lister)
            .map_err(|e| unreachable(format!("{e:#}")))?;
        drop(lister);

        // From here the reasons are about the DEVICE — which one the grant
        // names, and whether the upstream returned it — so they carry no
        // topology and go through verbatim. They are also the actionable ones.
        let chosen = session::resolve(&devices, &grant)
            .map_err(|e| Refusal::device_level(format!("{e:#}")))?;
        let mut up = dial(addr).map_err(|e| unreachable(format!("{e:#}")))?;
        let attached = session::import(&mut up, &chosen, &grant)
            .map_err(|e| Refusal::device_level(format!("{e:#}")))?;
        Ok((attached, up))
    })();

    match outcome {
        Ok((attached, up)) => {
            audit.record(
                AuditRecord::allow(
                    sandbox,
                    addr.ip(),
                    addr.port(),
                    Some(&id.to_string()),
                    Tier::Usb,
                    "usb grant",
                )
                .with_request("attach", attached.busid.clone()),
            );
            Ok((attached, up))
        }
        Err(r) => {
            deny(audit, sandbox, addr, &id.to_string(), &r.host);
            Err(r)
        }
    }
}

/// Audit a refused attach. Every failure path goes through here, so a denial is
/// as visible in `izba netlog` as an allowed one — a device izba refused is
/// exactly what a user comes to the log to understand.
fn deny(audit: &AuditSink, sandbox: &str, addr: SocketAddr, device: &str, rule: &str) {
    audit.record(
        AuditRecord::deny(
            sandbox,
            addr.ip(),
            addr.port(),
            Some(device),
            Tier::Usb,
            rule,
        )
        .with_request("attach", String::new()),
    );
}

// reason: real-socket glue; the op phase it feeds is unit-tested end to end and
// exercising this needs a bound listener, which the house rule forbids.
#[mutants::skip]
fn dial(addr: SocketAddr) -> Result<std::net::TcpStream> {
    let sock = std::net::TcpStream::connect_timeout(&addr, crate::usb::inventory::IO_TIMEOUT)
        .with_context(|| format!("connecting to the usbip upstream at {addr}"))?;
    sock.set_read_timeout(Some(crate::usb::inventory::IO_TIMEOUT))?;
    sock.set_write_timeout(Some(crate::usb::inventory::IO_TIMEOUT))?;
    Ok(sock)
}

/// Pipe the imported device between the guest and the upstream, validating only
/// the direction that ends in a privileged host service (D6).
///
/// Both legs are fully shut down when either finishes: Cloud Hypervisor does
/// not propagate a vsock half-close guest→host, so a polite `shutdown(Write)`
/// would leave the other side waiting forever.
// reason: thread/socket plumbing over `session::pump_guest_to_upstream`, which
// carries the validation and is unit-tested; driving this needs two real
// sockets and a live import.
#[mutants::skip]
fn splice(guest: UdsStream, upstream: std::net::TcpStream) {
    let (Ok(guest_r), Ok(up_r)) = (guest.try_clone(), upstream.try_clone()) else {
        return;
    };
    // Both timeouts set by `dial` for the interactive op phase must go before
    // the splice. The read one because URBs arrive at the device's pace, so a
    // deadline would tear down an idle-but-healthy attachment. The WRITE one
    // because a usbipd that stops draining for a few seconds would otherwise
    // fail a write mid-URB — which not only kills a healthy attachment but
    // leaves a half-forwarded URB in the host service's parser, exactly what
    // `pump_guest_to_upstream` promises never to do.
    let _ = up_r.set_read_timeout(None);
    let mut guest_w = guest;
    let mut up_w = upstream;
    let _ = up_w.set_write_timeout(None);

    let out = std::thread::spawn(move || {
        if let Err(e) = session::pump_guest_to_upstream(guest_r, &mut up_w) {
            eprintln!("izbad: USB stream refused: {e:#}");
        }
        let _ = up_w.shutdown(Shutdown::Both);
    });
    // Upstream → guest is spliced opaquely: its victim would be a guest kernel
    // already assumed hostile, and parsing it would need per-seqnum state.
    let mut buf = [0u8; 32 * 1024];
    let mut r = up_r;
    loop {
        match std::io::Read::read(&mut r, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if guest_w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = guest_w.shutdown(Shutdown::Both);
    let _ = out.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::audit::AuditSink;

    /// Write a sandbox whose config either holds a grant or does not, plus the
    /// daemon-level upstream setting, since the plane needs both. Built from
    /// the real types rather than hand-written JSON: the on-disk grant shape is
    /// whatever `SandboxConfig` serializes, and a test that guessed it would
    /// pass while agreeing with nothing.
    fn seed(root: &Path, name: &str, granted: bool, configured: bool) -> Paths {
        let paths = Paths::with_root(root.to_path_buf());
        let dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut usb = crate::usb::UsbConfig::default();
        if granted {
            usb.devices.push(crate::usb::UsbGrant {
                device: "0403:6001".parse().unwrap(),
                busid_pin: None,
                description: String::new(),
                granted_at_unix_ms: 1,
            });
        }
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:x".into(),
            image_ref: "img".into(),
            cpus: 1,
            mem_mb: 512,
            workspace: dir.join("ws"),
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            build: None,
            rw_size_gb: 0,
            usb,
        };
        crate::state::save_json(&dir.join(crate::state::CONFIG_FILE), &cfg).unwrap();
        if configured {
            crate::usb::settings::save(
                &paths.usb_dir(),
                &crate::usb::UsbSettings {
                    upstream: Some(crate::usb::Upstream {
                        host: "127.0.0.1".into(),
                        port: 3240,
                    }),
                    allow_remote_upstream: false,
                },
            )
            .unwrap();
        }
        paths
    }

    fn bind_denied(e: &anyhow::Error) -> bool {
        let s = format!("{e:#}");
        s.contains("Permission denied") || s.contains("Operation not permitted")
    }

    // ---- the handshake, driven over a socket pair with a fake upstream ----

    /// A scripted usbip upstream: answers a devlist with `devices`, then an
    /// import with whatever record `import_reply` supplies. Built from the
    /// phase-1 encoders so the test pins the wire format, not our idea of it.
    struct FakeUpstream {
        reply: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Read for FakeUpstream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl Write for FakeUpstream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn device_record(busid: &str, vid: u16, pid: u16) -> Vec<u8> {
        use izba_proto::usbip::DEVICE_RECORD_LEN;
        let mut b = vec![0u8; DEVICE_RECORD_LEN];
        let path = "/sys/devices/pci0000:00/usb3";
        b[..path.len()].copy_from_slice(path.as_bytes());
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        b[0x120..0x124].copy_from_slice(&3u32.to_be_bytes()); // busnum
        b[0x124..0x128].copy_from_slice(&2u32.to_be_bytes()); // devnum
        b[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes()); // speed
        b[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        b[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        b
    }

    fn devlist(records: &[Vec<u8>]) -> Vec<u8> {
        use izba_proto::usbip::{OP_REP_DEVLIST, USBIP_VERSION};
        let mut out = Vec::new();
        out.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        out.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn import_reply(record: Vec<u8>) -> Vec<u8> {
        use izba_proto::usbip::{OP_REP_IMPORT, USBIP_VERSION};
        let mut out = Vec::new();
        out.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        out.extend_from_slice(&OP_REP_IMPORT.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&record);
        out
    }

    /// A dialer whose Nth call replays the Nth canned reply. Two dials per
    /// attach — devlist, then import — because USB/IP allows one operation per
    /// connection.
    fn dialer(replies: Vec<Vec<u8>>) -> impl Fn(SocketAddr) -> Result<FakeUpstream> {
        let calls = std::sync::Mutex::new(replies.into_iter());
        move |_addr| {
            let next = calls.lock().unwrap().next();
            match next {
                Some(reply) => Ok(FakeUpstream {
                    reply: std::io::Cursor::new(reply),
                    sent: Vec::new(),
                }),
                None => anyhow::bail!("upstream refused the connection"),
            }
        }
    }

    /// Drive one handshake: write `open` to the guest end, run the server half,
    /// and return what the guest received back.
    fn exchange<D, U>(
        paths: &Paths,
        sandbox: &str,
        open: &StreamOpen,
        dial: D,
    ) -> (Option<session::Attached>, Response)
    where
        U: Read + Write,
        D: Fn(SocketAddr) -> Result<U>,
    {
        let (mut guest, mut server) = UdsStream::pair().unwrap();
        write_frame(&mut guest, open).unwrap();
        let audit = AuditSink::new(paths.clone());
        let got = serve_attach(&mut server, sandbox, paths, &audit, dial);
        let reply: Response = read_frame(&mut guest).expect("the guest is always answered");
        (got.map(|(a, _)| a), reply)
    }

    fn granted_paths(tmp: &tempfile::TempDir) -> Paths {
        seed(tmp.path(), "web", true, true)
    }

    #[test]
    fn a_granted_device_is_imported_and_the_guest_gets_its_devid_and_speed() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let rec = device_record("3-2", 0x0403, 0x6001);
        let (attached, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![devlist(std::slice::from_ref(&rec)), import_reply(rec)]),
        );
        assert!(attached.is_some(), "the caller is told to splice");
        match reply {
            Response::UsbAttached { devid, speed } => {
                assert_eq!(devid, session::devid(3, 2));
                assert_eq!(speed, 2);
            }
            other => panic!("expected usb_attached, got {other:?}"),
        }
    }

    #[test]
    fn a_device_that_was_never_granted_is_refused_and_named() {
        // The guest asks for something real that this sandbox simply does not
        // hold. It must be told which device, not merely "no".
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let rec = device_record("1-1", 0x1a86, 0x7523);
        let (attached, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "1a86:7523".into(),
            },
            dialer(vec![devlist(std::slice::from_ref(&rec)), import_reply(rec)]),
        );
        assert!(attached.is_none());
        match reply {
            Response::Error { message, .. } => {
                assert!(message.contains("1a86:7523"), "{message}");
                assert!(message.contains("not granted"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_attach_is_audited_as_a_denial() {
        // A device izba refused is exactly what a user comes to `izba netlog`
        // to understand, so the deny must reach the log, not just the guest.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "1a86:7523".into(),
            },
            dialer(vec![]),
        );
        let log = std::fs::read_to_string(paths.logs_dir("web").join("egress-audit.jsonl"))
            .expect("an audit line was written");
        assert!(log.contains("\"tier\":\"usb\""), "{log}");
        assert!(log.contains("deny"), "{log}");
        assert!(log.contains("1a86:7523"), "name the device: {log}");
    }

    #[test]
    fn a_successful_attach_is_audited_with_the_busid_it_resolved_to() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let rec = device_record("3-2", 0x0403, 0x6001);
        exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![devlist(std::slice::from_ref(&rec)), import_reply(rec)]),
        );
        let log =
            std::fs::read_to_string(paths.logs_dir("web").join("egress-audit.jsonl")).unwrap();
        assert!(log.contains("allow"), "{log}");
        assert!(log.contains("3-2"), "the busid is the useful detail: {log}");
    }

    #[test]
    fn any_frame_other_than_usb_attach_is_refused_on_this_plane() {
        // The USB plane is single-purpose. A guest sending an egress or exec
        // frame here is probing, and gets one honest refusal.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        for open in [
            StreamOpen::Dns,
            StreamOpen::TcpConnect {
                addr: "1.2.3.4".into(),
                port: 443,
            },
            StreamOpen::TcpDial { port: 22 },
        ] {
            let (attached, reply) = exchange(&paths, "web", &open, dialer(vec![]));
            assert!(attached.is_none());
            match reply {
                Response::Error { kind, message } => {
                    assert_eq!(kind, ErrorKind::BadRequest, "{open:?}");
                    assert!(message.contains("only usb_attach"), "{open:?}: {message}");
                }
                other => panic!("{open:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_malformed_device_id_is_refused_without_dialing_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (attached, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "not-an-id".into(),
            },
            |_: SocketAddr| -> Result<FakeUpstream> { panic!("must not dial") },
        );
        assert!(attached.is_none());
        match reply {
            Response::Error { message, .. } => assert!(message.contains("vid:pid"), "{message}"),
            other => panic!("expected a parse refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_upstream_that_does_not_export_the_granted_device_is_reported_as_such() {
        // The grant is fine; the hardware is simply not shared. The guest must
        // learn that, and the human must learn how to fix it.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (_, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![devlist(&[])]),
        );
        match reply {
            Response::Error { message, .. } => {
                assert!(message.contains("does not export"), "{message}");
                assert!(message.contains("usbipd bind"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_upstream_that_hands_back_a_different_device_is_refused_after_import() {
        // The post-import re-verification, end to end: the devlist is honest and
        // the import is not. Nothing may reach the guest.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (attached, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![
                devlist(&[device_record("3-2", 0x0403, 0x6001)]),
                import_reply(device_record("3-2", 0x1a86, 0x7523)),
            ]),
        );
        assert!(
            attached.is_none(),
            "no splice for a device izba did not ask for"
        );
        match reply {
            Response::Error { message, .. } => assert!(message.contains("mismatch"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn no_refusal_ever_tells_the_guest_where_the_upstream_is() {
        // D1: the guest names a device and learns nothing else. Host-side errors
        // routinely embed the address ("connecting to the usbip upstream at
        // 127.0.0.1:3240"), and izba-init passes izbad's message straight
        // through to the user — so a raw error chain would hand the guest the
        // upstream's topology on every failed dial.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let leaky = |addr: SocketAddr| -> Result<FakeUpstream> {
            anyhow::bail!("connecting to the usbip upstream at {addr}: connection refused")
        };
        let (_, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            leaky,
        );
        let Response::Error { message, .. } = reply else {
            panic!("expected a refusal");
        };
        for secret in ["127.0.0.1", "3240"] {
            assert!(
                !message.contains(secret),
                "the guest must not learn {secret}: {message}"
            );
        }
        assert!(
            message.contains("not reachable"),
            "but it must still learn the SHAPE of the failure: {message}"
        );

        // The host still gets the whole thing, in the audit log.
        let log =
            std::fs::read_to_string(paths.logs_dir("web").join("egress-audit.jsonl")).unwrap();
        assert!(
            log.contains("connection refused"),
            "the real reason must survive host-side: {log}"
        );
    }

    #[test]
    fn a_device_level_refusal_still_reaches_the_guest_verbatim() {
        // The redaction must not flatten everything into "something failed":
        // which device is missing, and how to share it, are exactly what the
        // person reading the guest's error needs, and they name no host.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (_, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![devlist(&[])]),
        );
        let Response::Error { message, .. } = reply else {
            panic!("expected a refusal");
        };
        assert!(message.contains("0403:6001"), "{message}");
        assert!(message.contains("usbipd bind"), "{message}");
    }

    #[test]
    fn an_unreachable_upstream_is_reported_rather_than_looking_like_a_missing_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (_, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            dialer(vec![]),
        );
        match reply {
            Response::Error { message, .. } => {
                assert!(message.contains("not reachable"), "{message}")
            }
            other => panic!("expected a dial failure, got {other:?}"),
        }
    }

    #[test]
    fn an_attach_with_no_upstream_configured_is_refused_before_the_grant_is_read() {
        // Reaching this at all means the plane was bound without an upstream,
        // which `refresh` prevents — so this is the belt to that braces.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, false);
        let (_, reply) = exchange(
            &paths,
            "web",
            &StreamOpen::UsbAttach {
                device: "0403:6001".into(),
            },
            |_: SocketAddr| -> Result<FakeUpstream> { panic!("must not dial") },
        );
        match reply {
            // Generic on purpose: the underlying refusal can name the host
            // (a public upstream is refused by name), and that must not cross.
            Response::Error { message, .. } => {
                assert!(message.contains("not available"), "{message}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_guest_that_says_nothing_gets_no_reply_and_no_dial() {
        // An empty connection is not an attach: nothing is authorized, nothing
        // is dialed, and the server simply drops it.
        let tmp = tempfile::tempdir().unwrap();
        let paths = granted_paths(&tmp);
        let (guest, mut server) = UdsStream::pair().unwrap();
        drop(guest);
        let audit = AuditSink::new(paths.clone());
        let got = serve_attach(
            &mut server,
            "web",
            &paths,
            &audit,
            |_: SocketAddr| -> Result<FakeUpstream> { panic!("must not dial") },
        );
        assert!(got.is_none());
    }

    #[test]
    fn the_usb_listener_sits_on_1028_beside_the_egress_socket() {
        assert_eq!(
            listener_path(Path::new("/data/run/aabbccdd")),
            PathBuf::from("/data/run/aabbccdd/vsock.sock_1028")
        );
    }

    #[test]
    fn a_sandbox_without_grants_gets_no_listener_at_all() {
        // The phase-2 promise made structural: USB off means there is nothing
        // to dial, not something that would refuse.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", false, true);
        let run = tmp.path().join("run");
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        b.refresh(&paths, "web", &run).unwrap();
        assert!(!b.listening("web"));
        assert!(!listener_path(&run).exists(), "and no socket file either");
    }

    #[test]
    fn a_grant_without_a_configured_upstream_still_binds_nothing() {
        // A grant alone cannot reach hardware: with no upstream there is
        // nowhere to import from, so the plane would only be a way to ask.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, false);
        let run = tmp.path().join("run");
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        b.refresh(&paths, "web", &run).unwrap();
        assert!(!b.listening("web"));
        assert!(!listener_path(&run).exists());
    }

    #[test]
    fn a_granted_sandbox_gets_a_listener_and_revoking_takes_it_away() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, true);
        let run = tmp.path().join("run");
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        match b.refresh(&paths, "web", &run) {
            Ok(()) => {}
            Err(e) if bind_denied(&e) => {
                eprintln!("SKIP: bind denied in this environment: {e:#}");
                return;
            }
            Err(e) => panic!("refresh: {e:#}"),
        }
        assert!(b.listening("web"));
        assert!(listener_path(&run).exists());

        // Idempotent while the grant stands.
        b.refresh(&paths, "web", &run).unwrap();
        assert!(b.listening("web"));

        // Revoke on disk, refresh again: the plane closes without a restart.
        let paths = seed(tmp.path(), "web", false, true);
        b.refresh(&paths, "web", &run).unwrap();
        assert!(!b.listening("web"));
        assert!(!listener_path(&run).exists());
    }

    #[test]
    fn the_bound_listener_actually_serves_a_connection() {
        // Everything else about the plane is tested through `serve_attach`
        // directly. This is the only check that the accept loop runs at all,
        // reaches the handler, and keeps going — i.e. that a guest dialing the
        // socket gets an answer rather than silence.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, true);
        let run = tmp.path().join("run");
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        match b.refresh(&paths, "web", &run) {
            Ok(()) => {}
            Err(e) if bind_denied(&e) => {
                eprintln!("SKIP: bind denied in this environment: {e:#}");
                return;
            }
            Err(e) => panic!("refresh: {e:#}"),
        }

        // Twice, so a loop that served exactly one connection and stopped is
        // caught too.
        for attempt in 0..2 {
            let mut c = UdsStream::connect(listener_path(&run))
                .unwrap_or_else(|e| panic!("attempt {attempt}: connect: {e}"));
            write_frame(&mut c, &StreamOpen::Dns).unwrap();
            match read_frame::<_, Response>(&mut c) {
                Ok(Response::Error { kind, .. }) => assert_eq!(kind, ErrorKind::BadRequest),
                other => panic!("attempt {attempt}: expected a refusal, got {other:?}"),
            }
        }
        b.stop("web", &run);
    }

    #[test]
    fn a_stale_socket_file_is_replaced_rather_than_failing_the_bind() {
        // A previous daemon's socket file (or any leftover) sits exactly where
        // this bind needs to go. Leaving it would make every start after an
        // unclean shutdown fail to arm the plane.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, true);
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(listener_path(&run), b"left behind").unwrap();

        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        match b.refresh(&paths, "web", &run) {
            Ok(()) => assert!(b.listening("web"), "the stale file must not block the bind"),
            Err(e) if bind_denied(&e) => eprintln!("SKIP: bind denied: {e:#}"),
            Err(e) => panic!("refresh: {e:#}"),
        }
        b.stop("web", &run);
    }

    #[test]
    fn the_inflight_guard_returns_its_slot() {
        // The cap is only a cap if slots come back. A guard that forgot to
        // release would let eight connections wedge the plane permanently.
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            n.fetch_add(1, Ordering::SeqCst);
            let _g = InflightGuard(Arc::clone(&n));
            assert_eq!(n.load(Ordering::SeqCst), 1);
        }
        assert_eq!(n.load(Ordering::SeqCst), 0, "the slot must be released");
    }

    #[test]
    fn the_handshake_cap_admits_up_to_the_limit_and_then_refuses() {
        // Mirrors the accept loop's claim: `fetch_add` returns the count BEFORE
        // the increment, so the comparison must admit exactly
        // MAX_INFLIGHT_HANDSHAKES connections — one off in either direction
        // either wedges the plane early or removes the bound entirely.
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut guards = Vec::new();
        for i in 0..MAX_INFLIGHT_HANDSHAKES {
            let admitted = n.fetch_add(1, Ordering::SeqCst) < MAX_INFLIGHT_HANDSHAKES;
            assert!(admitted, "connection {i} must be admitted");
            guards.push(InflightGuard(Arc::clone(&n)));
        }
        assert!(
            n.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_HANDSHAKES,
            "the one past the cap must be refused"
        );
        n.fetch_sub(1, Ordering::SeqCst);
        // And once they finish, the plane is usable again.
        guards.clear();
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert!(n.fetch_add(1, Ordering::SeqCst) < MAX_INFLIGHT_HANDSHAKES);
    }

    #[test]
    fn a_slot_whose_accept_thread_died_is_rebound() {
        // The supervisor calls `refresh` on every tick precisely so a crashed
        // accept loop comes back. Treating a dead slot as live would leave the
        // sandbox with a socket file nothing is listening on — every guest
        // attach then fails with no explanation on the host side.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", true, true);
        let run = tmp.path().join("run");
        let b = UsbBroker::new(AuditSink::new(paths.clone()));
        b.insert_finished_slot("web");
        assert!(!b.listening("web"), "the stand-in slot is already finished");

        match b.refresh(&paths, "web", &run) {
            Ok(()) => assert!(b.listening("web"), "a dead slot must be rebound"),
            Err(e) if bind_denied(&e) => eprintln!("SKIP: bind denied: {e:#}"),
            Err(e) => panic!("refresh: {e:#}"),
        }
        b.stop("web", &run);
    }

    #[test]
    fn stopping_a_sandbox_that_was_never_bound_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", false, true);
        UsbBroker::new(AuditSink::new(paths)).stop("web", &tmp.path().join("run"));
    }

    #[test]
    fn stop_removes_a_socket_file_left_by_a_previous_daemon() {
        // Adoption inherits sockets this process has no slot for; leaving one
        // behind would let the VMM bridge a guest connection to nothing.
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed(tmp.path(), "web", false, true);
        let run = tmp.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(listener_path(&run), b"stale").unwrap();
        UsbBroker::new(AuditSink::new(paths)).stop("web", &run);
        assert!(!listener_path(&run).exists());
    }
}
