//! Per-connection dispatch for the egress plane: read the guest's
//! `StreamOpen` frame, then route. `TcpConnect` → policy → host dial-out →
//! splice; `Dns` (and `TcpConnect` to :53 — a hardcoded-resolver client) →
//! the resolver. The M5 MITM/vault branch hangs off this dispatch point.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use izba_proto::{dns, read_frame, write_frame, ErrorKind, Response, StreamOpen};

use super::dns::Resolver;
use super::mitm_runtime::{MitmRuntime, OrigDst};
use super::policy::{FlowDesc, Policy, Verdict};
use crate::vmm::UdsStream;

/// Same cap as the guest-side TcpDial: a wedged dial must not pin a thread.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one guest-initiated egress connection (the vsock-1027 bridge).
/// `mitm` (when present) routes tier-1 HTTP(S) ports through the loopback hop.
pub fn handle_conn(
    mut conn: UdsStream,
    sandbox: &str,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    mitm: Option<&MitmRuntime>,
) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return, // malformed first frame: nothing spliced yet, just drop
    };
    match open {
        StreamOpen::TcpConnect { addr, port } => {
            tcp_connect(conn, sandbox, policy, resolver, mitm, &addr, port)
        }
        StreamOpen::Dns => dns_loop(conn, resolver),
        _ => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "unsupported StreamOpen on the egress port".into(),
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn tcp_connect(
    mut conn: UdsStream,
    sandbox: &str,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    mitm: Option<&MitmRuntime>,
    addr: &str,
    port: u16,
) {
    // TCP DNS: izbad IS the resolver — always allowed (the resolver path, not
    // arbitrary guest egress), answer locally. After Ok the raw stream carries
    // RFC 1035 TCP framing, exactly the `Dns` stream contract.
    if port == 53 {
        if write_frame(&mut conn, &Response::Ok).is_err() {
            return;
        }
        dns_loop(conn, resolver);
        return;
    }
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!("not an IP literal: {addr}"),
                },
            );
            return;
        }
    };

    // Tier 1 — HTTP(S): hand the flow to the MITM runtime via the loopback hop.
    // The policy decision happens AFTER TLS termination, on the decrypted Host,
    // inside the MITM handler — so we do NOT pre-check on the IP here (an IP is
    // never on a domain allow-list).
    if let Some(mitm) = mitm {
        if matches!(port, 80 | 443) {
            mitm_hop(conn, mitm, ip, port, sandbox);
            return;
        }
    }

    // Tier 2 — non-HTTP TCP: policy on the destination (T9 consults DNS-snoop
    // for the FQDN; today on the addr as given).
    let flow = FlowDesc::l3(sandbox, addr, port);
    if policy.check(&flow) == Verdict::Deny {
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!("egress to {addr}:{port} denied by policy"),
            },
        );
        return;
    }
    match TcpStream::connect_timeout(&SocketAddr::new(ip, port), DIAL_TIMEOUT) {
        Ok(target) => {
            if write_frame(&mut conn, &Response::Ok).is_err() {
                return;
            }
            crate::portfwd::pump_bidirectional(target, conn);
        }
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: e.to_string(),
                },
            );
        }
    }
}

/// Tier-1 loopback hop: pre-bind a loopback source so the source port is known
/// BEFORE connecting, register the `OrigDst` (register-before-connect → no race
/// with the MITM accept claim), dial the MITM listener, then splice the vsock
/// leg with the *unchanged* blocking pump (the OpenVMM churn invariant stays
/// untouched — only the loopback TCP enters tokio, never the vsock `UdsStream`).
fn mitm_hop(mut conn: UdsStream, mitm: &MitmRuntime, ip: IpAddr, port: u16, sandbox: &str) {
    use socket2::{Domain, Socket, Type};
    let listen = mitm.listen_addr();
    let connect = || -> std::io::Result<TcpStream> {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        sock.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        let src_port = sock
            .local_addr()?
            .as_socket()
            .map(|a| a.port())
            .ok_or_else(|| std::io::Error::other("no loopback source port"))?;
        // Register BEFORE connect so the accept handler can always claim it.
        mitm.register(
            src_port,
            OrigDst {
                ip,
                port,
                sandbox: sandbox.to_string(),
            },
        );
        sock.connect(&listen.into())?;
        Ok(sock.into())
    };
    match connect() {
        Ok(sock) => {
            if write_frame(&mut conn, &Response::Ok).is_err() {
                return;
            }
            crate::portfwd::pump_bidirectional(sock, conn);
        }
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: format!("MITM loopback dial: {e}"),
                },
            );
        }
    }
}

/// Framed query/response pairs until EOF; resolver failures become SERVFAIL
/// so the guest client fails fast instead of timing out.
fn dns_loop(mut conn: UdsStream, resolver: &dyn Resolver) {
    while let Ok(Some(query)) = dns::read_dns_msg(&mut conn) {
        let resp = resolver.handle(&query).unwrap_or_else(|e| {
            eprintln!("izbad: dns forward failed: {e:#}");
            dns::servfail(&query)
        });
        if dns::write_dns_msg(&mut conn, &resp).is_err() {
            break; // stop answering, but still drain + half-close below
        }
    }
    let _ = conn.shutdown(std::net::Shutdown::Write);
    // Drain to EOF so the guest is never force-closed with TX buffered
    // (the M0 vsock-churn contract; mirrors copy_until_eof's discipline).
    let mut sink = [0u8; 4096];
    loop {
        match std::io::Read::read(&mut conn, &mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::AllowAll;
    use std::io::{Read, Write};

    struct FakeResolver;
    impl Resolver for FakeResolver {
        fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut r = b"ans:".to_vec();
            r.extend_from_slice(query);
            Ok(r)
        }
    }

    struct FailingResolver;
    impl Resolver for FailingResolver {
        fn handle(&self, _q: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("upstream down")
        }
    }

    struct DenyAll;
    impl Policy for DenyAll {
        fn check(&self, _f: &FlowDesc) -> Verdict {
            Verdict::Deny
        }
    }

    fn spawn_handler(
        policy: &'static (dyn Policy + Sync),
        resolver: &'static (dyn Resolver + Sync),
    ) -> UdsStream {
        let (client, server) = UdsStream::pair().unwrap();
        std::thread::spawn(move || handle_conn(server, "web", policy, resolver, None));
        client
    }

    #[test]
    fn dns_stream_roundtrips_queries() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        dns::write_dns_msg(&mut c, b"q1").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q1");
        dns::write_dns_msg(&mut c, b"q2").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q2");
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(dns::read_dns_msg(&mut c).unwrap().is_none());
    }

    #[test]
    fn dns_resolver_failure_becomes_servfail() {
        let mut c = spawn_handler(&AllowAll, &FailingResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(&resp[..2], &[0xbe, 0xef]);
        assert_eq!(resp[3] & 0x0f, 0x02, "RCODE=SERVFAIL");
    }

    #[test]
    fn tcp_connect_denied_by_policy() {
        let mut c = spawn_handler(&DenyAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.4".into(),
                port: 443,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(message.contains("denied"), "{message}");
            }
            other => panic!("expected deny error, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_bad_addr_is_bad_request() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "not-an-ip".into(),
                port: 80,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_port53_routes_to_resolver() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "8.8.8.8".into(),
                port: 53,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        dns::write_dns_msg(&mut c, b"tq").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:tq");
    }

    #[test]
    fn unsupported_stream_open_is_bad_request() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(&mut c, &StreamOpen::TcpDial { port: 80 }).unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Real dial-out happy path + refused port. Binds a TcpListener —
    /// runtime-skip where denied.
    #[test]
    fn tcp_connect_dials_and_splices() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_connect_dials_and_splices: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        c.write_all(b"hi").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");
        srv.join().unwrap();
    }

    #[test]
    fn tcp_connect_refused_reports_connect_failed() {
        let port = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                drop(l);
                p
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_connect_refused: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::ConnectFailed),
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
    }

    /// A guest that stops reading responses mid-stream must not deadlock
    /// the handler: pending queries get consumed and the loop tears down.
    ///
    /// Honest scope: an in-process socketpair cannot deterministically
    /// force the server's response write to fail while an observer stays
    /// alive, so this test CANNOT distinguish `break`+drain from
    /// `return`+drop in dns_loop's write-failure arm — it guards the
    /// no-hang property only. The drain-on-write-failure contract itself
    /// is load-bearing-tested at the splice level
    /// (`portfwd::copy_drains_source_after_write_failure` and
    /// `server::splice_drains_guest_leg_when_client_dies`), which dns_loop
    /// mirrors.
    #[test]
    fn dns_loop_no_deadlock_when_client_stops_reading() {
        let (mut c, server) = UdsStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut s = server;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::Dns));
            dns_loop(s, &FakeResolver);
        });
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        // Happy-path: one round-trip confirms the loop is running.
        dns::write_dns_msg(&mut c, b"q0").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q0");
        // Send more queries but stop reading responses; the server must not
        // deadlock — it must consume our TX and tear down.
        dns::write_dns_msg(&mut c, b"q1").unwrap();
        dns::write_dns_msg(&mut c, b"q2").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        // Drop the read half so unread response data in the kernel buffer
        // does not prevent the peer's shutdown from completing.
        drop(c);
        h.join()
            .expect("dns_loop must not hang after write failure");
    }
}
