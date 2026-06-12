//! Host-side port-publish relay: pure vsock, no passt involvement, so the same
//! code serves Cloud Hypervisor/Linux and OpenVMM/Windows.
//!
//! A published rule is a thread inside izbad, owned by the daemon's
//! `RelayManager` and driven by [`run_relay_listener`]: the manager binds the
//! `TcpListener` (so port-in-use errors are synchronous) and, per accepted
//! connection, the loop opens a hybrid-vsock connection to the guest
//! [`STREAM_PORT`], sends `StreamOpen::TcpDial`, and — on `Response::Ok` —
//! pumps bytes both ways with graceful `shutdown(Write)`+drain teardown.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, Context};
use izba_proto::{read_frame, write_frame, Response, StreamOpen, STREAM_PORT};

use crate::state::PortRule;
use crate::vmm::UdsStream;
use crate::vsock::hybrid_connect;

/// Parse a publish rule: `HOST:GUEST` or `BIND:HOST:GUEST`.
///
/// `BIND` is an IPv4 address (default `127.0.0.1`); ports are `u16 >= 1`.
pub fn parse_rule(spec: &str) -> anyhow::Result<PortRule> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind, host_s, guest_s) = match parts.as_slice() {
        [host, guest] => (Ipv4Addr::LOCALHOST, *host, *guest),
        [bind, host, guest] => {
            let bind: Ipv4Addr = bind
                .parse()
                .with_context(|| format!("invalid bind address '{bind}' in rule '{spec}'"))?;
            (bind, *host, *guest)
        }
        _ => bail!("invalid port rule '{spec}' (expected HOST:GUEST or BIND:HOST:GUEST)"),
    };
    let host_port = parse_port(host_s, spec)?;
    let guest_port = parse_port(guest_s, spec)?;
    Ok(PortRule {
        bind,
        host_port,
        guest_port,
    })
}

fn parse_port(s: &str, spec: &str) -> anyhow::Result<u16> {
    let p: u16 = s
        .parse()
        .with_context(|| format!("invalid port '{s}' in rule '{spec}'"))?;
    if p == 0 {
        bail!("port 0 is not allowed in rule '{spec}'");
    }
    Ok(p)
}

/// In-daemon relay accept loop on an already-bound listener. Nonblocking
/// accept + 100 ms tick so the owning daemon can cancel it via `stop`
/// (std has no way to interrupt a blocking accept portably). Returns when
/// `stop` is set or on a listener error.
pub fn run_relay_listener(
    listener: TcpListener,
    vsock: &Path,
    guest_port: u16,
    stop: &AtomicBool,
) -> anyhow::Result<()> {
    listener.set_nonblocking(true).context("set_nonblocking")?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, _peer)) => {
                // Accepted sockets inherit nonblocking on some platforms.
                client.set_nonblocking(false).context("accepted socket")?;
                let vsock = vsock.to_path_buf();
                std::thread::spawn(move || {
                    if let Err(e) = relay_one(client, &vsock, guest_port) {
                        eprintln!("relay connection error: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e).context("accept"),
        }
    }
    Ok(())
}

/// Serve one accepted TCP connection: open a vsock TcpDial to the guest port,
/// and on `Ok` pump bytes both ways with graceful teardown.
pub fn relay_one(client: TcpStream, vsock: &Path, guest_port: u16) -> anyhow::Result<()> {
    let mut vs = hybrid_connect(vsock, STREAM_PORT)
        .with_context(|| format!("vsock connect for guest port {guest_port}"))?;
    write_frame(&mut vs, &StreamOpen::TcpDial { port: guest_port }).context("sending TcpDial")?;
    match read_frame::<_, Response>(&mut vs)? {
        Response::Ok => {}
        Response::Error { kind, message } => {
            // Guest port closed (or worse): close the client connection.
            bail!("guest dial failed ({kind:?}): {message}");
        }
        other => bail!("unexpected reply to TcpDial: {other:?}"),
    }
    pump_bidirectional(client, vs);
    Ok(())
}

/// Pump bytes both ways between the host TCP `client` and the vsock `vs`, with
/// graceful `shutdown(Write)`+drain on each side at EOF. Always shut down the
/// vsock side with `shutdown(Write)` rather than an abrupt drop (the OpenVMM
/// churn mitigation).
fn pump_bidirectional(client: TcpStream, vs: UdsStream) {
    let client_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let vs_r = match vs.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut client_w = client;
    let mut vs_w = vs;

    // client -> vsock; on client EOF, half-close the vsock write side.
    let up = std::thread::spawn(move || {
        copy_until_eof(client_r, &mut vs_w);
        let _ = vs_w.shutdown(Shutdown::Write);
    });
    // vsock -> client; on vsock EOF, half-close the client write side.
    copy_until_eof(vs_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = up.join();
}

/// Copy `r` → `w` until `r` reaches EOF (or a read error). A write failure
/// does NOT end the loop: the destination may be gone, but the source must
/// still be consumed to EOF, discarding. Abandoning the read side of a vsock
/// leg while the guest has buffered TX makes the VMM's relay-socket write
/// fail, which panics OpenVMM's virtio_vsock (`connections.rs:1093` assert —
/// the vsock-churn crash). Draining keeps every vsock teardown EOF-shaped.
/// The drain ends when the guest half-closes, which the opposite pump
/// direction triggers via its `shutdown(Write)` on EOF of the dead peer.
pub(crate) fn copy_until_eof(mut r: impl Read, w: &mut impl Write) {
    let mut buf = [0u8; 32 * 1024];
    let mut discard = false;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        if !discard && w.write_all(&buf[..n]).is_err() {
            discard = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_guest() {
        let r = parse_rule("8080:80").unwrap();
        assert_eq!(r.bind, Ipv4Addr::LOCALHOST);
        assert_eq!(r.host_port, 8080);
        assert_eq!(r.guest_port, 80);
    }

    #[test]
    fn parse_bind_host_guest() {
        let r = parse_rule("0.0.0.0:8080:80").unwrap();
        assert_eq!(r.bind, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(r.host_port, 8080);
        assert_eq!(r.guest_port, 80);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_rule("nope").is_err());
        assert!(parse_rule("a:b:c:d").is_err());
        assert!(parse_rule("8080:notaport").is_err());
        assert!(parse_rule("999.999.999.999:8080:80").is_err());
    }

    #[test]
    fn parse_rejects_port_zero() {
        assert!(parse_rule("0:80").is_err());
        assert!(parse_rule("8080:0").is_err());
    }

    /// The vsock-churn guard: when the destination dies mid-stream, the copy
    /// must keep consuming the source to EOF (discarding) instead of
    /// returning early — an early return drops the vsock socket while the
    /// guest still has buffered TX, which panics OpenVMM's virtio_vsock.
    /// The writer completing without error is the observable proof.
    #[test]
    fn copy_drains_source_after_write_failure() {
        let (mut src_w, src_r) = UdsStream::pair().unwrap();
        let (mut dead_w, dead_peer) = UdsStream::pair().unwrap();
        drop(dead_peer); // every write into dead_w now fails

        const TOTAL: usize = 8 * 1024 * 1024; // far beyond socketpair buffers
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            let chunk = [b'x'; 64 * 1024];
            let mut sent = 0;
            while sent < TOTAL {
                let n = (TOTAL - sent).min(chunk.len());
                src_w.write_all(&chunk[..n])?;
                sent += n;
            }
            Ok(())
        });

        copy_until_eof(src_r, &mut dead_w);
        writer.join().unwrap().expect(
            "source writer must complete: the copy must drain to EOF, not abandon the read side",
        );
    }

    #[test]
    fn relay_listener_stops_on_flag() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        // Real TcpListener — runtime-skip where bind is denied.
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: TcpListener::bind denied in this environment");
                return;
            }
            Err(e) => panic!("bind: {e}"),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let t = std::thread::spawn(move || {
            run_relay_listener(listener, Path::new("/nonexistent.sock"), 80, &stop2)
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!t.is_finished(), "loop must keep running until stopped");
        stop.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();
        let res = t.join().unwrap();
        assert!(res.is_ok(), "clean stop: {res:?}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "must notice the flag within one tick"
        );
    }

    /// Drive the per-connection relay logic without binding a TcpListener:
    /// a UnixStream::pair stands in for the vsock side, and a connected
    /// TcpStream pair stands in for the client. Binds a loopback listener for
    /// the TcpStream pair → runtime-skip on PermissionDenied.
    #[test]
    fn relay_one_pumps_after_ok() {
        // Build a connected TcpStream pair via a throwaway loopback listener.
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP relay_one_pumps_after_ok: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let connect_t = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server_side, _peer) = listener.accept().unwrap();
        let client_side = connect_t.join().unwrap();

        // Fake guest: a UnixStream::pair where the "init" half answers Ok then
        // echoes. We bypass hybrid_connect by calling the pump directly: split
        // relay_one's post-handshake half into pump_bidirectional here.
        let (init_half, host_half) = UdsStream::pair().unwrap();

        // init side: read host bytes, echo with prefix, then close.
        let init_t = std::thread::spawn(move || {
            let mut s = init_half;
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            s.shutdown(Shutdown::Write).unwrap();
        });

        // Wire the host TCP client to the host vsock half via the same pump
        // relay_one uses post-Ok.
        let pump_t = std::thread::spawn(move || pump_bidirectional(server_side, host_half));

        // The "curl" side writes through client_side and reads the echo.
        let mut curl = client_side;
        curl.write_all(b"hi").unwrap();
        curl.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        curl.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");

        init_t.join().unwrap();
        pump_t.join().unwrap();
    }
}
