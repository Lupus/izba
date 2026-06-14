//! Per-connection dispatch for the egress plane: read the guest's
//! `StreamOpen` frame, then route. `TcpConnect` → policy → host dial-out →
//! splice; `Dns` (and `TcpConnect` to :53 — a hardcoded-resolver client) →
//! the resolver. The M5 MITM/vault branch hangs off this dispatch point.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use izba_proto::{dns, read_frame, write_frame, ErrorKind, Response, StreamOpen};

use super::audit::{AuditRecord, AuditSink, Tier};
use super::dns::Resolver;
use super::dns_snoop::{self, SnoopStore};
use super::mitm_runtime::{MitmRuntime, OrigDst};
use super::policy::{FlowDesc, Policy, Verdict};
use crate::vmm::UdsStream;

/// Same cap as the guest-side TcpDial: a wedged dial must not pin a thread.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one guest-initiated egress connection (the vsock-1027 bridge).
/// `mitm` (when present) routes tier-1 HTTP(S) ports through the loopback hop.
#[allow(clippy::too_many_arguments)]
pub fn handle_conn(
    mut conn: UdsStream,
    sandbox: &str,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    mitm: Option<&MitmRuntime>,
    audit: &AuditSink,
    snoop: &SnoopStore,
) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return, // malformed first frame: nothing spliced yet, just drop
    };
    match open {
        StreamOpen::TcpConnect { addr, port } => tcp_connect(
            conn, sandbox, policy, resolver, mitm, audit, snoop, &addr, port,
        ),
        StreamOpen::Dns => dns_loop(conn, resolver, sandbox, snoop),
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
    audit: &AuditSink,
    snoop: &SnoopStore,
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
        dns_loop(conn, resolver, sandbox, snoop);
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

    // Tier 2 — non-HTTP TCP: recover the FQDN from DNS-snoop and decide. An
    // enforcing policy is strict (private-address denylist + default-deny on a
    // raw-IP dial with no snoop record); a bare sandbox stays permissive.
    let (verdict, flow, rule) = decide_tier2(policy, snoop, sandbox, ip, port);
    audit.record(AuditRecord::from_flow(verdict, &flow, ip, Tier::L3, rule));
    if verdict == Verdict::Deny {
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

/// Tier-2 (non-HTTP TCP) decision: recover the FQDN(s) izbad resolved for `ip`
/// and decide. Returns the verdict, the `FlowDesc` to audit, and a rule label.
///
/// Enforcing policy (a declared firewall): a private/loopback/link-local
/// destination is denied (DNS-rebinding / SSRF guard); a raw-IP dial with no
/// snoop record is default-denied (the red flag); otherwise the flow is allowed
/// iff ANY snooped name passes the policy. A non-enforcing `AllowAll` keeps
/// today's permissive behavior — it decides on the address as given.
pub fn decide_tier2(
    policy: &dyn Policy,
    snoop: &SnoopStore,
    sandbox: &str,
    ip: IpAddr,
    port: u16,
) -> (Verdict, FlowDesc, &'static str) {
    let names = snoop.fqdns_for(sandbox, ip);
    let mut flow = FlowDesc::l3(sandbox, ip.to_string(), port);
    flow.host = names.first().cloned();

    if !policy.enforces() {
        // Permissive bare sandbox: decide on the addr (today's behavior).
        let verdict = policy.check(&flow);
        return (verdict, flow, "permissive");
    }

    if is_private(ip) {
        return (Verdict::Deny, flow, "private-address denylist");
    }
    if names.is_empty() {
        return (Verdict::Deny, flow, "no DNS-snoop record (raw IP)");
    }
    // Allow if any resolved name passes the allow-list.
    for name in &names {
        let mut f = flow.clone();
        f.addr = name.clone();
        f.host = Some(name.clone());
        if policy.check(&f) == Verdict::Allow {
            return (Verdict::Allow, f, "allow-list");
        }
    }
    (Verdict::Deny, flow, "not in allow-list")
}

/// Private / loopback / link-local / unspecified destinations the egress plane
/// must never reach from an enforced sandbox (SSRF + DNS-rebinding guard).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Framed query/response pairs until EOF; resolver failures become SERVFAIL
/// so the guest client fails fast instead of timing out. Each answer is snooped
/// into `snoop` (IP→FQDN for tier-2) BEFORE the reply is written, so the mapping
/// is installed before the guest can dial the resolved address.
fn dns_loop(mut conn: UdsStream, resolver: &dyn Resolver, sandbox: &str, snoop: &SnoopStore) {
    while let Ok(Some(query)) = dns::read_dns_msg(&mut conn) {
        let resp = resolver.handle(&query).unwrap_or_else(|e| {
            eprintln!("izbad: dns forward failed: {e:#}");
            dns::servfail(&query)
        });
        snoop.record(sandbox, &dns_snoop::extract_a_aaaa(&resp));
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
    use crate::daemon::egress::policy::{AllowAll, RegoPolicy};
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
        let audit = AuditSink::new(crate::paths::Paths::with_root(
            std::env::temp_dir().join("izba-router-audit-test"),
        ));
        let snoop = SnoopStore::new();
        std::thread::spawn(move || {
            handle_conn(server, "web", policy, resolver, None, &audit, &snoop)
        });
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

    // --- decide_tier2: pure tier-2 decision (no listeners). ---

    #[test]
    fn decide_tier2_denies_raw_ip_with_no_snoop() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443);
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("no DNS-snoop"), "{rule}");
    }

    #[test]
    fn decide_tier2_allows_snooped_allowlisted_fqdn() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        let (v, f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(f.host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(rule, "allow-list");
    }

    #[test]
    fn decide_tier2_denies_snooped_but_unlisted_fqdn() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("evil.example.com".to_string(), ip, 300)]);
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443);
        assert_eq!(v, Verdict::Deny);
        assert_eq!(rule, "not in allow-list");
    }

    /// DNS-rebinding guard: even a rebinding to an allow-listed name that points
    /// at a private IP is denied by the address denylist.
    #[test]
    fn decide_tier2_denies_private_ip_even_when_snooped() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443);
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("private"), "{rule}");
    }

    /// A bare sandbox (non-enforcing AllowAll) keeps today's permissive
    /// behavior — a raw-IP dial with no snoop record is allowed.
    #[test]
    fn decide_tier2_permissive_allows_raw_ip() {
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (v, _f, rule) = decide_tier2(&AllowAll, &snoop, "web", ip, 8443);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(rule, "permissive");
        // Permissive even reaches a private IP (M1 behavior preserved).
        let priv_ip: IpAddr = "10.0.0.5".parse().unwrap();
        let (v2, _f2, _r) = decide_tier2(&AllowAll, &snoop, "web", priv_ip, 8443);
        assert_eq!(v2, Verdict::Allow);
    }

    /// dns_loop installs the IP→FQDN snoop mapping from each answer it returns.
    #[test]
    fn dns_loop_snoops_returned_a_records() {
        use crate::daemon::egress::dns_snoop;
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::str::FromStr;

        let ip = std::net::Ipv4Addr::new(203, 0, 113, 7);
        let name = Name::from_str("api.anthropic.com.").unwrap();
        let mut msg = Message::new();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(name, 300, RData::A(A(ip))));
        let response = msg.to_vec().unwrap();

        struct FixedResolver(Vec<u8>);
        impl Resolver for FixedResolver {
            fn handle(&self, _q: &[u8]) -> anyhow::Result<Vec<u8>> {
                Ok(self.0.clone())
            }
        }
        let resolver = FixedResolver(response);
        let snoop = SnoopStore::new();
        let _ = dns_snoop::extract_a_aaaa(&[]); // (parser exercised by its own tests)

        let (mut c, server) = UdsStream::pair().unwrap();
        // Borrow `snoop`/`resolver` into the scoped thread that runs dns_loop.
        std::thread::scope(|s| {
            let h = s.spawn(|| dns_loop(server, &resolver, "web", &snoop));
            dns::write_dns_msg(&mut c, b"q").unwrap();
            let _ = dns::read_dns_msg(&mut c).unwrap(); // the resolved answer
            c.shutdown(std::net::Shutdown::Write).unwrap();
            drop(c); // let dns_loop's drain reach EOF and return
            h.join().unwrap();
        });

        assert_eq!(
            snoop.fqdns_for("web", IpAddr::V4(ip)),
            vec!["api.anthropic.com".to_string()],
            "the resolved A record was snooped into the store"
        );
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
            dns_loop(s, &FakeResolver, "web", &SnoopStore::new());
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
