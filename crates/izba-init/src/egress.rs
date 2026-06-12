//! Guest egress stub — M1. This file ships the DNS half (UDP :53 →
//! per-query vsock `Dns` stream to izbad); the TCP REDIRECT half (nft +
//! SO_ORIGINAL_DST) lands with the phase-B kernel/nft artifacts.

use izba_proto::{dns, write_frame, StreamOpen, EGRESS_PORT};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

/// Dial the host (CID 2) egress port. Production dialer; tests substitute
/// a socketpair half through the `forward_query` seam.
///
/// `VMADDR_CID_HOST` (2) is the host CID in the vsock world.  The VMM
/// bridges `connect(cid=2, port=EGRESS_PORT)` to the unix socket at
/// `run/vsock.sock_1027` owned by izbad.
///
/// vsock 0.5: `VsockStream::connect_with_cid_port(u32, u32)` is a static
/// that returns `io::Result<VsockStream>` (the crate uses `std::io::Result`
/// internally, not a nix::Result), so no error conversion is needed.
pub fn dial_host() -> io::Result<vsock::VsockStream> {
    vsock::VsockStream::connect_with_cid_port(libc::VMADDR_CID_HOST, EGRESS_PORT)
}

/// One UDP query → one `Dns` vsock stream → one response. Any failure
/// becomes SERVFAIL so the client fails fast instead of timing out.
pub fn forward_query<S, D>(dial: D, query: &[u8]) -> Vec<u8>
where
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    match try_forward(dial, query) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("izba-init: dns forward: {e}");
            dns::servfail(query)
        }
    }
}

/// One `Dns` vsock stream: send `StreamOpen::Dns`, write the framed query,
/// read back one framed response.
///
/// `write_frame` returns `Result<(), FrameError>` (not `io::Result`). We
/// map the `FrameError` to `io::Error` via its `Display` impl. The DNS
/// framing helpers (`write_dns_msg`, `read_dns_msg`) already return
/// `io::Result`, so no conversion is needed there.
fn try_forward<S, D>(dial: D, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    let mut s = dial()?;
    write_frame(&mut s, &StreamOpen::Dns).map_err(|e| io::Error::other(e.to_string()))?;
    dns::write_dns_msg(&mut s, query)?;
    match dns::read_dns_msg(&mut s)? {
        Some(resp) => Ok(resp),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no dns response from izbad",
        )),
    }
}

/// Bind 0.0.0.0:53. Split out of `serve_dns_udp` so the bind can happen on
/// the main thread BEFORE `apply_nft` (the redirect rule is meaningless, and
/// worse, blackholes :53, if nothing is listening), giving a real
/// happens-before between "listener exists" and "rule installed".
pub fn bind_dns_udp() -> io::Result<UdpSocket> {
    UdpSocket::bind(("0.0.0.0", 53))
}

/// Serve DNS forever (daemon thread) on an already-bound socket; one thread
/// per query so a slow upstream cannot head-of-line-block other resolutions.
/// M1: unbounded thread-per-query (and one izbad conn each) — the host-side bound is M2 scope.
pub fn serve_dns_udp(sock: UdpSocket) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: dns stub recv: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock2 = sock.try_clone()?;
        std::thread::spawn(move || {
            let resp = forward_query(dial_host, &query);
            let _ = sock2.send_to(&resp, peer);
        });
    }
}

/// Loopback port the nat-output REDIRECT delivers all outbound TCP to.
pub const REDIRECT_PORT: u16 = 15001;

/// The fixed transparent-redirect ruleset. Loopback destinations (`return`)
/// are never redirected — that is the WORKING DNS path (resolv.conf points
/// to 127.0.0.1; the stub answers from 0.0.0.0:53; loopback reply matches).
/// All other TCP goes to the stub at :15001. `udp dport 53` pulls
/// hardcoded-resolver queries to the stub too, but replies are currently
/// DROPPED: the stub answers from an unconnected wildcard socket so the
/// reply's source address doesn't match what the client sent to, conntrack's
/// reverse-NAT tuple never matches, and the client never sees the answer
/// (the textbook transparent-UDP-proxy reply problem). The udp:53 redirect
/// rule stays as the hook for a future IP_ORIGDSTADDR transparent-reply fix;
/// until then, apps that hardcode an external UDP resolver get no DNS (known
/// M1 gap). The stub's own egress is AF_VSOCK — not IP — so no exclusion
/// rule is needed and no redirect loop is possible. Non-DNS UDP is denied
/// structurally (no route once the NIC goes away in phase C).
pub const NFT_RULESET: &str = "\
table ip izba {
  chain output {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    meta l4proto tcp redirect to :15001
    udp dport 53 redirect to :53
  }
}
";

/// Apply the ruleset via the vendored static nft.
pub fn apply_nft() -> io::Result<()> {
    std::fs::write("/tmp/izba-egress.nft", NFT_RULESET)?;
    let status = std::process::Command::new("/sbin/nft")
        .args(["-f", "/tmp/izba-egress.nft"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("nft -f exited {status}")));
    }
    Ok(())
}

/// Recover the pre-REDIRECT destination from conntrack.
/// One tiny unsafe getsockopt; integration-covered (needs a real
/// REDIRECTed socket, which unit tests cannot make).
fn original_dst(conn: &TcpStream) -> io::Result<SocketAddrV4> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

/// Bind the redirect listener. Split out of `serve_tcp_redirect` so the bind
/// happens on the main thread BEFORE `apply_nft`: the REDIRECT rule sends all
/// guest TCP here, so a listener must already exist or every connect gets a
/// loopback RST. Returning the bound listener gives apply_nft a happens-before.
pub fn bind_tcp_redirect() -> io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
}

/// Serve the redirect listener forever (daemon thread) on an already-bound
/// listener.
pub fn serve_tcp_redirect(listener: TcpListener) -> io::Result<()> {
    loop {
        let (conn, _peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: tcp redirect accept: {e}");
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        std::thread::spawn(move || {
            let orig = match original_dst(&conn) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("izba-init: SO_ORIGINAL_DST: {e}");
                    return;
                }
            };
            handle_redirected(conn, orig, dial_host);
        });
    }
}

/// Splice one redirected client connection to izbad via TcpConnect.
///
/// Teardown mirrors server.rs::tcp_dial, with the roles flipped, but it has
/// to shut down BOTH sockets at the end where tcp_dial shuts down only one.
/// In tcp_dial both pumps touch the same `conn` fd, so the terminal
/// `shutdown(conn, SHUT_RDWR)` happens to unblock the reader thread too.
/// Here the two pumps read DIFFERENT sockets: the up-thread reads the client
/// (`client_r`), the main pump reads the vsock (`host`). The terminal
/// `shutdown(host, SHUT_RDWR)` only unblocks the main-side reader/vsock — it
/// does nothing for the up-thread, which is parked in `client_r.read()`. If
/// the remote closed first while the app still holds its write side open, the
/// up-thread would block forever and `up.join()` would hang (leaking the
/// thread + its fds). So once the main host->client pump is done we also
/// fully shut down the client socket, which delivers EOF to the up-thread's
/// read and lets it (and the join) finish.
pub fn handle_redirected<S, D>(client: TcpStream, orig: SocketAddrV4, dial: D)
where
    S: Read + Write + AsRawFd + Send + 'static,
    D: FnOnce() -> io::Result<S>,
{
    let mut host = match dial() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("izba-init: egress dial for {orig}: {e}");
            return;
        }
    };
    if write_frame(
        &mut host,
        &StreamOpen::TcpConnect {
            addr: orig.ip().to_string(),
            port: orig.port(),
        },
    )
    .is_err()
    {
        return;
    }
    match izba_proto::read_frame::<_, izba_proto::Response>(&mut host) {
        Ok(izba_proto::Response::Ok) => {}
        Ok(izba_proto::Response::Error { kind, message }) => {
            eprintln!("izba-init: egress {orig}: {kind:?}: {message}");
            return; // client socket drops -> app sees RST/EOF (honest refusal)
        }
        _ => return,
    }

    let host_w = match crate::server::dup_fd(host.as_raw_fd()) {
        Ok(d) => File::from(d),
        Err(_) => return,
    };
    let client_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    // client -> izbad
    let up = std::thread::spawn(move || {
        let mut host_w = host_w;
        crate::server::relay_pump(client_r, &mut host_w);
        unsafe { libc::shutdown(host_w.as_raw_fd(), libc::SHUT_WR) };
    });
    // izbad -> client; izbad full-closes when the remote is done.
    let mut client_w = client;
    crate::server::relay_pump(&mut host, &mut client_w);
    // Full shutdown (Both), not just Write: the inbound direction has nowhere
    // to deliver now that the host pump is done, and — unlike tcp_dial, whose
    // two pumps share one fd — the up-thread reads THIS client socket, so it
    // will sit in client_r.read() forever unless we close its read side too.
    // SHUT_RDWR here delivers EOF to the up-thread (releasing up.join()).
    let _ = client_w.shutdown(std::net::Shutdown::Both);
    // Unblock the main-side vsock and finish the vsock teardown.
    unsafe { libc::shutdown(host.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::read_frame;
    use std::os::unix::net::UnixStream;

    /// Fake izbad on the far end of a socketpair: expects the `Dns` frame,
    /// answers each framed query with `re:<query>`.
    fn fake_izbad() -> (UnixStream, std::thread::JoinHandle<()>) {
        let (mine, theirs) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(
                matches!(open, StreamOpen::Dns),
                "expected Dns, got {open:?}"
            );
            while let Ok(Some(q)) = dns::read_dns_msg(&mut s) {
                let mut r = b"re:".to_vec();
                r.extend_from_slice(&q);
                dns::write_dns_msg(&mut s, &r).unwrap();
            }
        });
        (mine, h)
    }

    #[test]
    fn forwards_one_query() {
        let (sock, h) = fake_izbad();
        let resp = forward_query(|| Ok(sock), b"hello");
        assert_eq!(resp, b"re:hello");
        h.join().unwrap();
    }

    #[test]
    fn dial_failure_becomes_servfail() {
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let resp = forward_query::<UnixStream, _>(
            || Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no izbad")),
            &q,
        );
        assert_eq!(&resp[..2], &[0xbe, 0xef], "ID preserved");
        assert_eq!(resp[3] & 0x0f, 0x02, "SERVFAIL");
    }

    #[test]
    fn truncated_peer_becomes_servfail() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        drop(theirs); // izbad vanished
        let q = [0x00u8, 0x01, 0x01, 0x00];
        let resp = forward_query(|| Ok(mine), &q);
        assert_eq!(resp[3] & 0x0f, 0x02);
    }

    #[test]
    fn nft_ruleset_shape() {
        // The contract bits the redirect depends on; the full file is integration-tested.
        assert!(NFT_RULESET.contains("type nat hook output priority -100"));
        assert!(NFT_RULESET.contains("ip daddr 127.0.0.0/8 return"));
        assert!(NFT_RULESET.contains(&format!("redirect to :{REDIRECT_PORT}")));
        assert!(NFT_RULESET.contains("udp dport 53 redirect to :53"));
    }

    /// handle_redirected with an injected orig-dst and a socketpair "izbad":
    /// the TcpConnect frame carries the original destination; bytes flow
    /// both ways after Ok. Binds a loopback TcpListener — runtime-skip
    /// where denied (the accepted TcpStream plays the redirected client).
    #[test]
    fn redirected_conn_speaks_tcp_connect() {
        use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP redirected_conn_speaks_tcp_connect: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        let app = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET").unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        });
        let (client, _) = listener.accept().unwrap();

        let (izbad, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            match open {
                StreamOpen::TcpConnect { addr, port } => {
                    assert_eq!(addr, "93.184.216.34");
                    assert_eq!(port, 443);
                }
                other => panic!("expected TcpConnect, got {other:?}"),
            }
            write_frame(&mut s, &izba_proto::Response::Ok).unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"GET");
            s.write_all(b"200ok").unwrap();
            // Full close: izbad's splice tears down with drain.
        });

        let orig = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        handle_redirected(client, orig, || Ok(izbad));

        assert_eq!(app.join().unwrap(), b"200ok");
        fake.join().unwrap();
    }

    /// Regression: the up-thread reads the app's client socket, not the vsock.
    /// If izbad closes first while the app keeps its write side open, the
    /// terminal shutdown(host) alone never unblocks that read — handle_redirected
    /// would hang in up.join(). The full client shutdown(Both) is what frees it.
    /// We assert (a) handle_redirected returns at all, and (b) the app's pending
    /// read sees EOF because handle_redirected fully closed the client socket.
    #[test]
    fn remote_close_first_does_not_hang() {
        use std::net::{TcpListener, TcpStream};
        use std::sync::mpsc;
        use std::time::Duration;

        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP remote_close_first_does_not_hang: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();

        // The app connects but deliberately never closes its write side; it
        // just blocks reading until EOF. If handle_redirected leaves the client
        // socket's read side open, this read parks forever.
        let (app_eof_tx, app_eof_rx) = mpsc::channel::<usize>();
        let app = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"hi").unwrap();
            // No shutdown(Write): the app holds its write side open.
            let mut out = Vec::new();
            let n = s.read_to_end(&mut out).unwrap();
            app_eof_tx.send(n).unwrap();
        });
        let (client, _) = listener.accept().unwrap();

        // Fake izbad: reply Ok, then immediately close (remote closes first).
        let (izbad, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::TcpConnect { .. }));
            write_frame(&mut s, &izba_proto::Response::Ok).unwrap();
            // Drop `s` -> izbad's side closes while the app's write side stays open.
        });

        let orig = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            handle_redirected(client, orig, || Ok(izbad));
            let _ = done_tx.send(());
        });

        // Watchdog: handle_redirected must return; a hang means the up-thread
        // never unblocked.
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("handle_redirected hung: up-thread never unblocked");
        handle.join().unwrap();

        // And the full client shutdown must have delivered EOF to the app.
        let n = app_eof_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("app read never saw EOF: client socket not fully shut down");
        assert_eq!(n, 0, "app should see EOF with no inbound bytes");
        app.join().unwrap();
        fake.join().unwrap();
    }
}
