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

/// How long a guest may take over the whole attach handshake — the one frame
/// it sends and everything izbad does before replying. A guest that dials and
/// then says nothing must not hold a thread or a device claim open.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

struct BrokerSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
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
                        let paths = paths2.clone();
                        let audit = audit.clone();
                        let sandbox = sandbox.clone();
                        std::thread::spawn(move || handle_conn(conn, &sandbox, &paths, &audit));
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
    // A guest that dials and then says nothing must not hold a thread — or a
    // claim on somebody's hardware — open.
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
    let open: StreamOpen = read_frame(conn).ok()?;
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
        Err(e) => {
            // izbad's reason is the useful one and the guest is going to show it
            // to a human; pass it through rather than reducing it to a code.
            let _ = write_frame(
                conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!("{e:#}"),
                },
            );
            None
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
) -> Result<(session::Attached, U)>
where
    U: Read + Write,
    D: Fn(SocketAddr) -> Result<U>,
{
    let settings = crate::usb::settings::load(&paths.usb_dir());
    // Re-classified here, not merely read: a hostname accepted as private when
    // it was configured can resolve somewhere else by the time a guest asks.
    let addr = crate::usb::dialable_upstream(&settings)?;
    let id: crate::usb::DeviceId = device.parse()?;

    // The grant is re-read from disk on every attach rather than cached: a
    // revoke must take effect on the next attempt, not at the next restart.
    let grants = crate::usb::grants_of(paths, sandbox);
    let Some(grant) = crate::usb::grants::find(&grants, id).cloned() else {
        let e = format!("{id} is not granted to '{sandbox}'");
        deny(audit, sandbox, addr, &id.to_string(), &e);
        anyhow::bail!(e);
    };

    let outcome = (|| -> Result<(session::Attached, U)> {
        // One operation per TCP connection, so this is two dials: the devlist
        // connection is dropped, and the import connection becomes the URB
        // stream.
        let mut lister = dial(addr)?;
        lister
            .write_all(&izba_proto::usbip::encode_op_req_devlist())
            .context("sending OP_REQ_DEVLIST")?;
        lister.flush().ok();
        let devices = crate::usb::inventory::read_devlist_reply(&mut lister)?;
        drop(lister);

        let chosen = session::resolve(&devices, &grant)?;
        let mut up = dial(addr)?;
        let attached = session::import(&mut up, &chosen, &grant)?;
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
        Err(e) => {
            deny(audit, sandbox, addr, &id.to_string(), &format!("{e:#}"));
            Err(e)
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
    // URBs arrive at the device's pace; a read timeout here would tear down an
    // idle-but-healthy attachment.
    let _ = up_r.set_read_timeout(None);
    let mut guest_w = guest;
    let mut up_w = upstream;

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
                assert!(message.contains("refused the connection"), "{message}")
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
            Response::Error { message, .. } => {
                assert!(message.contains("not configured"), "{message}")
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
