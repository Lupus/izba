// SPDX-License-Identifier: Apache-2.0
//! Host-level end-to-end test of the M2 MITM datapath through the loopback
//! runtime. A simulated guest connects to the `MitmRuntime` exactly as
//! `router::mitm_hop` does (pre-bound loopback source + register-before-connect),
//! izbad terminates the guest TLS under its CA, the `RegoPolicy` decides on the
//! decrypted Host, and an allowed flow is re-originated to a fake TLS upstream.
//! This exercises the whole host-side firewall (accept -> claim-by-src-port ->
//! per-SNI leaf -> policy -> upstream) without a VM.
//!
//! Binds loopback listeners, so it runtime-skips where the sandbox denies bind
//! (the house pattern) and runs for real in the KVM e2e CI leg.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use izba_core::daemon::egress::mitm::{
    server_config_with_resolver, upstream_client_config, CertCache, IzbaCa,
};
use izba_core::daemon::egress::mitm_runtime::{MitmRuntime, OrigDst};
use izba_core::daemon::egress::policy::RegoPolicy;
use rustls::pki_types::{CertificateDer, ServerName};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_ring() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install ring provider");
    });
}

fn can_bind() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok()
}

/// Bind a fake TLS upstream that presents a leaf for any SNI under `cache`'s CA
/// and answers `body`. Returns the bound port. Runs on the caller's runtime.
async fn spawn_upstream(cache: Arc<CertCache>, body: &'static str) -> u16 {
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
                // Read the replayed request head to CRLFCRLF.
                let mut buf = Vec::new();
                let mut b = [0u8; 1];
                loop {
                    match tls.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    buf.push(b[0]);
                    if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// Act as the guest: mirror `router::mitm_hop` (pre-bind a loopback source,
/// register the OrigDst, connect), then TLS-handshake under the izba CA with
/// `sni`, send a request, and return the response text.
async fn guest_request(
    mitm: &MitmRuntime,
    gcfg: &Arc<rustls::ClientConfig>,
    sni: &'static str,
    dst_port: u16,
    req_line: &str,
) -> String {
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
        .expect("guest TLS handshake under the izba CA");
    tls.write_all(format!("{req_line} HTTP/1.1\r\nHost: {sni}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    tls.flush().await.unwrap();
    let mut got = Vec::new();
    tls.read_to_end(&mut got).await.unwrap();
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
fn mitm_firewall_allows_and_denies_by_decrypted_host() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP mitm_firewall_allows_and_denies_by_decrypted_host: bind denied");
        return;
    }

    // The fake upstream's own CA (created sync so the MITM upstream config can
    // trust it before the runtime starts).
    let up_ca = IzbaCa::generate().unwrap();
    let up_ca_der: CertificateDer<'static> = up_ca.cert_der();
    let up_cache = Arc::new(CertCache::new(up_ca));
    let mut up_roots = rustls::RootCertStore::empty();
    up_roots.add(up_ca_der).unwrap();
    let upstream_cfg = upstream_client_config(up_roots);

    // The izba CA the guest trusts + the cert cache that signs the leaves.
    let izba_ca = IzbaCa::generate().unwrap();
    let izba_ca_der = izba_ca.cert_der();
    let izba_certs = Arc::new(CertCache::new(izba_ca));

    // Default-deny allow-list: api.anthropic.com allowed, evil.* denied.
    let policy = Arc::new(RegoPolicy::embedded().unwrap());

    // Start the MITM runtime (sync context — its own runtime can block_on bind).
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, policy).expect("start MITM runtime");

    // Guest rustls config: trusts ONLY the izba CA (proves leaves chain to it).
    let mut guest_roots = rustls::RootCertStore::empty();
    guest_roots.add(izba_ca_der).unwrap();
    let mut gcfg = rustls::ClientConfig::builder()
        .with_root_certificates(guest_roots)
        .with_no_client_auth();
    gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let gcfg = Arc::new(gcfg);

    // Drive the guest-side async work on a dedicated runtime (kept separate from
    // the MITM runtime; both drop cleanly in this sync test).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_upstream(up_cache, "UPSTREAM-PONG").await;

        // ALLOW: SNI api.anthropic.com is on the allow-list -> 200 from upstream.
        let allowed = guest_request(
            &mitm,
            &gcfg,
            "api.anthropic.com",
            up_port,
            "GET /v1/messages",
        )
        .await;
        assert!(allowed.contains("200 OK"), "allowed flow status: {allowed}");
        assert!(
            allowed.contains("UPSTREAM-PONG"),
            "allowed flow body must come from the real upstream through the MITM: {allowed}"
        );

        // DENY: SNI evil.example.com is not allow-listed -> izbad 403, no upstream.
        let denied = guest_request(&mitm, &gcfg, "evil.example.com", up_port, "GET /x").await;
        assert!(denied.contains("403"), "denied flow status: {denied}");
        assert!(
            denied.contains("izba egress policy"),
            "denied flow must be izbad's synthesized 403: {denied}"
        );
    });
}
