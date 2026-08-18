// SPDX-License-Identifier: Apache-2.0
//! Integration coverage for the M5 P1 pinning passthrough (§5.2, D3): a flow
//! whose ClientHello SNI is on the router's candidate list is spliced
//! UNTERMINATED, and everything else still lands under the izba CA.
//!
//! The proof is whose certificate the client sees. The guest here trusts ONLY
//! the fake upstream's CA and not izba's, so a successful handshake means the
//! bytes reached the upstream untouched, and a failed one means izbad
//! terminated. That distinction is invisible to an in-crate test, which is why
//! this lives beside `egress_mitm.rs` rather than in `mitm_runtime.rs`.
//!
//! Binds loopback listeners, so it runtime-skips where the sandbox denies
//! bind.
//!
//! Four mutations survived the whole workspace suite before this file existed
//! (see the per-test docs below for which test kills which):
//!   O1 — `router.rs`'s tier-1 gate can stop passing `passthrough_names(...)`
//!        into `mitm_hop`/`register` and nothing in-crate notices, because the
//!        in-crate harness always drives `mitm: None`.
//!   O2 — `passthrough_splice` can dial the wrong address/port and nothing
//!        notices, because the existing positive case only asserted "some
//!        bytes flowed", never "from THIS upstream".
//!   O3 — the peek-not-consume discipline (`&TcpStream` blocks
//!        `AsyncReadExt::read` but not `try_read`/`readable()+recv`) is
//!        defended only by review.
//!   O4 — the empty-candidate-list guard that skips the larger peek entirely
//!        is a zero-cost/performance property, not a protocol-observable one;
//!        see `NOT COVERED` below for why no test here claims it.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use izba_core::daemon::egress::audit::{parse_line, AuditSink, Tier};
use izba_core::daemon::egress::config::EgressPolicyConfig;
use izba_core::daemon::egress::dns::Resolver;
use izba_core::daemon::egress::dns_snoop::SnoopStore;
use izba_core::daemon::egress::mitm::{
    server_config_with_resolver, upstream_client_config, CertCache, IzbaCa,
};
use izba_core::daemon::egress::mitm_runtime::{MitmRuntime, OrigDst};
use izba_core::daemon::egress::policy::{AllowAll, Policy};
use izba_core::daemon::egress::router::{self, UsbGuard};
use izba_core::vmm::UdsStream;
use izba_proto::{read_frame, write_frame, Response, StreamOpen};
use rustls::pki_types::{CertificateDer, ServerName};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_ring() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn can_bind() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok()
}

/// A TLS upstream under `cache`'s CA that answers every connection with
/// `body` after reading one line. Deliberately NOT an HTTP server: a
/// passthrough is an opaque pipe, and asserting on a non-HTTP exchange proves
/// nothing parsed it.
async fn spawn_pinned_upstream(cache: Arc<CertCache>, body: &'static str) -> u16 {
    let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(cache)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut b = [0u8; 5];
                let _ = tls.read_exact(&mut b).await;
                let _ = tls.write_all(body.as_bytes()).await;
                let _ = tls.flush().await;
                // A graceful TLS close_notify, not just a dropped TCP socket —
                // without it rustls treats the peer's plain close as an
                // unexpected-EOF error rather than end-of-stream (mirrors
                // `egress_mitm.rs`'s `spawn_upstream`).
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// Bounds every `pinned_flow` call below so a mutation that turns "terminate"
/// into "hang forever" (e.g. O3's consuming peek, which leaves both the MITM
/// acceptor and our own client waiting on bytes neither side will ever send)
/// fails as a clean, fast assertion instead of wedging the test binary.
const FLOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Drive one flow through the runtime exactly as `router::mitm_hop` does, with
/// `passthrough` standing in for what `router::passthrough_names` computed.
async fn pinned_flow(
    mitm: &MitmRuntime,
    policy: &Arc<dyn Policy>,
    gcfg: &Arc<rustls::ClientConfig>,
    sni: &'static str,
    dst_port: u16,
    passthrough: Vec<String>,
) -> Result<String, String> {
    match tokio::time::timeout(
        FLOW_TIMEOUT,
        pinned_flow_inner(mitm, policy, gcfg, sni, dst_port, passthrough),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!("flow timed out after {FLOW_TIMEOUT:?}")),
    }
}

async fn pinned_flow_inner(
    mitm: &MitmRuntime,
    policy: &Arc<dyn Policy>,
    gcfg: &Arc<rustls::ClientConfig>,
    sni: &'static str,
    dst_port: u16,
    passthrough: Vec<String>,
) -> Result<String, String> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    sock.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    let src_port = sock.local_addr().unwrap().as_socket().unwrap().port();
    mitm.register(
        src_port,
        OrigDst {
            ip: Ipv4Addr::LOCALHOST.into(),
            port: dst_port,
            sandbox: "web".into(),
        },
        Arc::clone(policy),
        passthrough.into(),
    );
    sock.connect(&mitm.listen_addr().into()).unwrap();
    sock.set_nonblocking(true).unwrap();
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream).unwrap();

    let connector = TlsConnector::from(Arc::clone(gcfg));
    let name = ServerName::try_from(sni).unwrap();
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"HELLO").await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    tls.read_to_end(&mut got).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&got).into_owned())
}

/// Build the runtime plus a guest config trusting ONLY the upstream's CA.
/// Returns (runtime, guest config, upstream cert cache).
fn harness() -> (MitmRuntime, Arc<rustls::ClientConfig>, Arc<CertCache>) {
    let up_ca = IzbaCa::generate().unwrap();
    let up_ca_der: CertificateDer<'static> = up_ca.cert_der();
    let up_cache = Arc::new(CertCache::new(up_ca));

    let mut up_roots = rustls::RootCertStore::empty();
    up_roots.add(up_ca_der.clone()).unwrap();
    let upstream_cfg = upstream_client_config(up_roots);

    let izba_ca = IzbaCa::generate().unwrap();
    let izba_certs = Arc::new(CertCache::new(izba_ca));

    let audit = AuditSink::new(izba_core::paths::Paths::with_root(
        std::env::temp_dir().join("izba-egress-inspect-test-audit"),
    ));
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

    // The pinned client: trusts the UPSTREAM's CA and NOT izba's.
    let mut guest_roots = rustls::RootCertStore::empty();
    guest_roots.add(up_ca_der).unwrap();
    let mut gcfg = rustls::ClientConfig::builder()
        .with_root_certificates(guest_roots)
        .with_no_client_auth();
    gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    (mitm, Arc::new(gcfg), up_cache)
}

/// Positive case, and also the O3 witness: the FULL guest ClientHello (and
/// nothing but it) must reach the upstream. A `peek` that started consuming
/// even the first byte would leave `copy_bidirectional` relaying a truncated
/// record, and the upstream's TLS accept — which must complete for
/// `tls.write_all`/`read_to_end` below to succeed at all — would fail.
#[test]
fn a_candidate_sni_is_spliced_untouched() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP a_candidate_sni_is_spliced_untouched: bind denied");
        return;
    }
    let (mitm, gcfg, up_cache) = harness();
    let policy: Arc<dyn Policy> = Arc::new(AllowAll);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_pinned_upstream(up_cache, "PINNED-PONG").await;
        let got = pinned_flow(
            &mitm,
            &policy,
            &gcfg,
            "pinned.vendor.com",
            up_port,
            vec!["pinned.vendor.com".to_string()],
        )
        .await
        .expect("a pinned client that trusts only its own CA must complete the handshake");
        assert!(
            got.contains("PINNED-PONG"),
            "the bytes must come from the real upstream, unparsed: {got}"
        );
    });
}

#[test]
fn an_sni_off_the_candidate_list_is_terminated() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP an_sni_off_the_candidate_list_is_terminated: bind denied");
        return;
    }
    let (mitm, gcfg, up_cache) = harness();
    let policy: Arc<dyn Policy> = Arc::new(AllowAll);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_pinned_upstream(up_cache, "PINNED-PONG").await;
        // The guest CLAIMS the pinned name, but the router bound no candidate
        // to this address — so izbad terminates and the pinned client, which
        // does not trust the izba CA, must fail.
        let err = pinned_flow(
            &mitm,
            &policy,
            &gcfg,
            "pinned.vendor.com",
            up_port,
            Vec::new(),
        )
        .await
        .expect_err("an empty candidate list must terminate, not splice");
        assert!(
            !err.is_empty(),
            "the pinned client must reject the izba-CA leaf"
        );
    });
}

/// O2: the splice must dial the flow's OWN `dst.ip:dst.port` — not merely
/// "some" upstream. Two upstreams share the same CA (so cert trust alone
/// cannot distinguish them) but answer with distinct bodies; the registered
/// `OrigDst.port` names the CORRECT one, and the DECOY sits one port over —
/// exactly the `port + 1` mutation this obligation names. A splice that
/// dialed the decoy (or anything else) would surface as the wrong body, or as
/// a handshake failure if nothing is listening where it dialed instead.
#[test]
fn a_splice_dials_the_flows_own_upstream_not_a_decoy() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP a_splice_dials_the_flows_own_upstream_not_a_decoy: bind denied");
        return;
    }
    let (mitm, gcfg, up_cache) = harness();
    let policy: Arc<dyn Policy> = Arc::new(AllowAll);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let correct_port = spawn_pinned_upstream(Arc::clone(&up_cache), "SPLICE-HIT-CORRECT").await;
        let _decoy_port = spawn_pinned_upstream(Arc::clone(&up_cache), "SPLICE-HIT-DECOY").await;

        let got = pinned_flow(
            &mitm,
            &policy,
            &gcfg,
            "pinned.vendor.com",
            correct_port,
            vec!["pinned.vendor.com".to_string()],
        )
        .await
        .expect("the splice must reach the flow's own upstream and complete");
        assert!(
            got.contains("SPLICE-HIT-CORRECT"),
            "must reach dst.ip:dst.port's real upstream: {got}"
        );
        assert!(
            !got.contains("SPLICE-HIT-DECOY"),
            "must NOT reach a different upstream (e.g. a `port + 1` dial): {got}"
        );
    });
}

/// Never actually invoked (port 53 short-circuits before any resolver call on
/// the `TcpConnect` path this test drives) — present only to satisfy
/// `router::handle_conn`'s signature.
struct DummyResolver;
impl Resolver for DummyResolver {
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(query.to_vec())
    }
}

/// Produce the raw bytes of a real TLS ClientHello for `sni`, generated
/// in-memory (no socket, no completed handshake) — just enough wire input for
/// the router's SNI peek to classify.
fn client_hello_bytes(sni: &'static str) -> Vec<u8> {
    install_ring();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = ServerName::try_from(sni).unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

/// O1: `router.rs`'s tier-1 gate (`policy.enforces() && policy.inspects(port)`)
/// must hand the REAL `passthrough_names(...)` result to `mitm_hop` ->
/// `MitmRuntime::register` — not an empty stand-in. This drives the actual
/// production entry point (`router::handle_conn`, `mitm: Some(&real_mitm)`),
/// which nothing in-crate does (the in-crate router tests only ever pass
/// `mitm: None`, and `egress_mitm.rs`/this file's other tests call
/// `MitmRuntime::register` directly, bypassing this call site entirely).
///
/// The router's own non-overridable SSRF floor (`is_hard_denied`, checked
/// before tier-1 for EVERY sandbox) refuses loopback/link-local/documentation
/// destinations unconditionally — see constraint #3 — so there is no address
/// this test could bind a real fake upstream on AND legally hand to
/// `handle_conn`. The oracle is therefore the audit trail `passthrough_splice`
/// unconditionally writes the moment it is entered, regardless of whether its
/// own dial to `dst.ip:dst.port` (a real, unreachable "public" address) ever
/// succeeds: a Tier::L3 record whose rule names the passthrough. That record
/// can only appear if the router handed a non-empty, SNI-matching candidate
/// list all the way through to the runtime — which is exactly the wiring O1
/// says is unverified. If the router instead passed `Vec::new()`, the flow
/// would fall straight to ordinary MITM termination, which (since our probe
/// never completes a real handshake) never produces ANY audit record for this
/// flow (see `mitm_runtime.rs`'s accept_loop: a TLS accept failure writes no
/// audit line — the M5 diagnosability follow-up) — so this test would instead
/// time out with no record found.
#[test]
fn o1_router_wires_real_passthrough_candidates_into_the_runtime() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP o1_router_wires_real_passthrough_candidates_into_the_runtime: bind denied");
        return;
    }

    // A real MitmRuntime, built exactly as izbad's `server::build_mitm_runtime`
    // does. The upstream trust store is irrelevant here — `1.2.3.4` is never
    // actually reached by a live server this test controls, so an empty root
    // store is fine (any real upstream dial fails before any cert is checked).
    let upstream_cfg = upstream_client_config(rustls::RootCertStore::empty());
    let izba_ca = IzbaCa::generate().unwrap();
    let izba_certs = Arc::new(CertCache::new(izba_ca));

    let audit_root = std::env::temp_dir().join(format!(
        "izba-egress-inspect-o1-audit-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&audit_root);
    let audit_paths = izba_core::paths::Paths::with_root(audit_root);
    let audit = AuditSink::new(audit_paths.clone());
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

    // The real policy the router consults: enforcing, and declaring the
    // pinning passthrough for `pinned.vendor.com:443` — port 443 is the
    // unconditional tier-1 baseline, so no extra `protocol: http` widening
    // entry is needed.
    let cfg = EgressPolicyConfig::from_yaml(
        "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
    )
    .unwrap();
    let policy: Arc<dyn Policy> = cfg.into_policy("web").unwrap();

    // DNS-snoop binding: izbad's OWN resolver "answered" pinned.vendor.com ->
    // 1.2.3.4 for this sandbox — the candidate list is bound to the address,
    // never trusted from the SNI alone (see `router::passthrough_names`'s
    // doc).
    let snoop = SnoopStore::new();
    let dst_ip: IpAddr = "1.2.3.4".parse().unwrap();
    snoop.record("web", &[("pinned.vendor.com".to_string(), dst_ip, 300)]);

    let (mut client, server) = UdsStream::pair().unwrap();
    let thread_audit_paths = audit_paths.clone();
    std::thread::spawn(move || {
        let resolver = DummyResolver;
        router::handle_conn(
            server,
            "web",
            policy,
            &resolver,
            Some(&mitm),
            &AuditSink::new(thread_audit_paths),
            &snoop,
            UsbGuard::default(),
        );
    });

    write_frame(
        &mut client,
        &StreamOpen::TcpConnect {
            addr: "1.2.3.4".to_string(),
            port: 443,
        },
    )
    .expect("write StreamOpen frame");
    let resp: Response = read_frame(&mut client).expect("read tier-1 response");
    assert!(
        matches!(resp, Response::Ok),
        "mitm_hop must accept the loopback dial: {resp:?}"
    );

    let hello = client_hello_bytes("pinned.vendor.com");
    client
        .write_all(&hello)
        .expect("write the ClientHello onto the spliced pipe");

    // Poll the audit trail: bounded by `router::DIAL_TIMEOUT` (10s) plus
    // margin, since a correctly-wired flow only writes its record after the
    // (doomed) dial to 1.2.3.4 resolves one way or the other.
    let audit_file = audit_paths.logs_dir("web").join("egress-audit.jsonl");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut found = None;
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&audit_file) {
            if let Some(rec) = text
                .lines()
                .filter_map(parse_line)
                .find(|r| r.tier == Tier::L3 && r.rule.contains("passthrough"))
            {
                found = Some(rec);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let rec = found.expect(
        "router.rs's real call site must hand passthrough_names' candidates through to \
         MitmRuntime::register — no passthrough-tier audit record appeared within the \
         dial-timeout budget",
    );
    assert_eq!(
        rec.host.as_deref(),
        Some("pinned.vendor.com"),
        "the passthrough audit record must name the matched SNI: {rec:?}"
    );
}
