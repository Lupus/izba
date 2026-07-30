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

use izba_core::daemon::egress::audit::{parse_line, AuditSink, Tier};
use izba_core::daemon::egress::config::{Access, EgressPolicyConfig};
use izba_core::daemon::egress::mitm::{
    server_config_with_resolver, upstream_client_config, CertCache, IzbaCa,
};
use izba_core::daemon::egress::mitm_runtime::{MitmRuntime, OrigDst};
use izba_core::daemon::egress::policy::{RegoPolicy, Verdict};
use izba_core::paths::Paths;
use rustls::pki_types::{CertificateDer, ServerName};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_ring() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // Best-effort: an already-installed ring default (e.g. from another
        // test in this binary) is fine — both install the same provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
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
    policy: &Arc<dyn izba_core::daemon::egress::policy::Policy>,
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
        Arc::clone(policy),
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

    // Start the MITM runtime (sync context — its own runtime can block_on bind).
    let audit =
        izba_core::daemon::egress::audit::AuditSink::new(izba_core::paths::Paths::with_root(
            std::env::temp_dir().join("izba-egress-mitm-test-audit"),
        ));
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

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

        // Default-deny allow-list: api.anthropic.com allowed, evil.* denied. The
        // policy now travels with each registered flow (the runtime is shared).
        // M2.1 port-aware: a host is allowed only on its listed ports, so the
        // data doc names the (ephemeral) upstream port this test actually dials.
        let data = format!(
            r#"{{"host_rules": {{"api.anthropic.com": {{"ports": [{up_port}], "access": "read-write"}}}}, "sandbox_host_rules": {{}}, "sandbox_git_rules": {{}}}}"#
        );
        let policy: Arc<dyn izba_core::daemon::egress::policy::Policy> =
            Arc::new(RegoPolicy::with_data(&data).unwrap());

        // ALLOW: SNI api.anthropic.com is on the allow-list -> 200 from upstream.
        let allowed = guest_request(
            &mitm,
            &policy,
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
        let denied =
            guest_request(&mitm, &policy, &gcfg, "evil.example.com", up_port, "GET /x").await;
        assert!(denied.contains("403"), "denied flow status: {denied}");
        assert!(
            denied.contains("izba egress policy"),
            "denied flow must be izbad's synthesized 403: {denied}"
        );
    });
}

/// Wildcard allow entries enforce through the real MITM path: the policy is
/// compiled from `policy.yaml` text (YAML -> data doc -> Rego), a one-label
/// wildcard admits `api.example.test` and refuses both the apex and a
/// deeper subdomain on the decrypted Host.
#[test]
fn mitm_firewall_enforces_wildcard_hosts() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP mitm_firewall_enforces_wildcard_hosts: bind denied");
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

    // Start the MITM runtime (sync context — its own runtime can block_on bind).
    let audit =
        izba_core::daemon::egress::audit::AuditSink::new(izba_core::paths::Paths::with_root(
            std::env::temp_dir().join("izba-egress-mitm-wildcard-test-audit"),
        ));
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

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

        // Policy compiled from YAML text through the real from_yaml -> data doc
        // -> Rego pipeline: a one-label wildcard on `example.test`. M2.1 is
        // port-aware (see `mitm_firewall_allows_and_denies_by_decrypted_host`
        // above), so the scoped `ports:` names the (ephemeral) upstream port
        // this test actually dials — the bare-string form from the task brief
        // would default to [80, 443], which this loopback fixture never binds.
        let cfg = izba_core::daemon::egress::config::EgressPolicyConfig::from_yaml(&format!(
            "enforce: true\nallow:\n  - host: '*.example.test'\n    ports: [{up_port}]\n"
        ))
        .unwrap();
        let policy = cfg.into_policy("web").unwrap();

        // ALLOW: api.example.test is one label under the wildcard -> 200 from upstream.
        let allowed = guest_request(
            &mitm,
            &policy,
            &gcfg,
            "api.example.test",
            up_port,
            "GET /v1/messages",
        )
        .await;
        assert!(allowed.contains("200 OK"), "allowed flow status: {allowed}");
        assert!(
            allowed.contains("UPSTREAM-PONG"),
            "allowed flow body must come from the real upstream through the MITM: {allowed}"
        );

        // DENY: example.test is the apex, which a wildcard never matches -> 403.
        let denied_apex =
            guest_request(&mitm, &policy, &gcfg, "example.test", up_port, "GET /x").await;
        assert!(
            denied_apex.contains("403"),
            "apex flow status: {denied_apex}"
        );
        assert!(
            denied_apex.contains("izba egress policy"),
            "apex flow must be izbad's synthesized 403: {denied_apex}"
        );

        // DENY: a.b.example.test is two labels deep, past the one-label wildcard -> 403.
        let denied_deep =
            guest_request(&mitm, &policy, &gcfg, "a.b.example.test", up_port, "GET /x").await;
        assert!(
            denied_deep.contains("403"),
            "deep flow status: {denied_deep}"
        );
        assert!(
            denied_deep.contains("izba egress policy"),
            "deep flow must be izbad's synthesized 403: {denied_deep}"
        );
    });
}

/// AC4: a host entry built the exact way `izba policy allow HOST --read`
/// writes it (`EgressPolicyConfig::allow` + `set_host_access(.., Access::Read)`,
/// `enforce: true`) must, through the real MITM enforcement layer, allow GET
/// and HEAD (the two methods `--help` promises for `read`) and deny POST on
/// that host, with an audit (netlog) record for each. This pins the
/// CLI-written config *shape* compiling through `into_policy` into a real
/// enforcing policy — not a hand-written rego data doc.
#[test]
fn mitm_firewall_cli_shaped_read_access_allows_get_denies_post() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP mitm_firewall_cli_shaped_read_access_allows_get_denies_post: bind denied");
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

    // A fresh, process-unique audit root so this test's assertions on the
    // written JSONL are not polluted by a stale file from a previous run.
    let audit_root = std::env::temp_dir().join(format!(
        "izba-egress-mitm-read-access-test-audit-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&audit_root);
    let audit_paths = Paths::with_root(audit_root);
    let audit = AuditSink::new(audit_paths.clone());
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

    // Guest rustls config: trusts ONLY the izba CA (proves leaves chain to it).
    let mut guest_roots = rustls::RootCertStore::empty();
    guest_roots.add(izba_ca_der).unwrap();
    let mut gcfg = rustls::ClientConfig::builder()
        .with_root_certificates(guest_roots)
        .with_no_client_auth();
    gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let gcfg = Arc::new(gcfg);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_upstream(up_cache, "UPSTREAM-PONG").await;

        // Build the policy the SAME way `izba policy allow HOST --read` does:
        // `allow()` upserts the host/port (default access read-write), then
        // `set_host_access()` narrows it to Read; `enforce` is set explicitly
        // because `EgressPolicyConfig::default()` starts non-enforcing.
        let mut cfg = EgressPolicyConfig::default();
        cfg.allow("api.anthropic.com", up_port);
        cfg.set_host_access("api.anthropic.com", Access::Read);
        cfg.enforce = true;
        let policy = cfg.into_policy("web").unwrap();

        // ALLOW: GET is permitted under Access::Read -> 200 from the real upstream.
        let allowed = guest_request(
            &mitm,
            &policy,
            &gcfg,
            "api.anthropic.com",
            up_port,
            "GET /v1/messages",
        )
        .await;
        assert!(allowed.contains("200 OK"), "GET flow status: {allowed}");
        assert!(
            allowed.contains("UPSTREAM-PONG"),
            "GET flow body must come from the real upstream through the MITM: {allowed}"
        );

        // ALLOW: HEAD is the OTHER method Access::Read permits (read =
        // GET/HEAD only) -> 200, reaching the real upstream exactly like GET.
        // A real HEAD response carries no body, so assert on the status line
        // rather than the (fake-upstream-echoed) body text.
        let head_allowed = guest_request(
            &mitm,
            &policy,
            &gcfg,
            "api.anthropic.com",
            up_port,
            "HEAD /v1/messages",
        )
        .await;
        assert!(
            head_allowed.contains("200 OK"),
            "HEAD flow status: {head_allowed}"
        );

        // DENY: POST is refused under Access::Read (read = GET/HEAD only) ->
        // izbad's synthesized 403, never reaching the upstream (which would
        // otherwise happily answer any method with 200 UPSTREAM-PONG).
        let denied = guest_request(
            &mitm,
            &policy,
            &gcfg,
            "api.anthropic.com",
            up_port,
            "POST /v1/messages",
        )
        .await;
        assert!(denied.contains("403"), "POST flow status: {denied}");
        assert!(
            denied.contains("izba egress policy"),
            "POST flow must be izbad's synthesized 403 (upstream never reached): {denied}"
        );
        assert!(
            !denied.contains("UPSTREAM-PONG"),
            "POST flow must NOT reach the real upstream: {denied}"
        );

        // Both decisions must land in the audit (netlog) trail: an Allow
        // record for the GET, a Deny record for the POST, both scoped to the
        // decrypted Host, tier L7 (MITM-terminated).
        let audit_file = audit_paths.logs_dir("web").join("egress-audit.jsonl");
        let text = std::fs::read_to_string(&audit_file)
            .unwrap_or_else(|e| panic!("reading {}: {e}", audit_file.display()));
        let records: Vec<_> = text.lines().filter_map(parse_line).collect();

        let get_record = records
            .iter()
            .find(|r| r.method.as_deref() == Some("GET"))
            .expect("an audit record for the GET flow");
        assert_eq!(
            get_record.verdict,
            Verdict::Allow,
            "GET audit record: {get_record:?}"
        );
        assert_eq!(
            get_record.tier,
            Tier::L7,
            "GET audit record: {get_record:?}"
        );
        assert_eq!(
            get_record.host.as_deref(),
            Some("api.anthropic.com"),
            "GET audit record: {get_record:?}"
        );

        let head_record = records
            .iter()
            .find(|r| r.method.as_deref() == Some("HEAD"))
            .expect("an audit record for the HEAD flow");
        assert_eq!(
            head_record.verdict,
            Verdict::Allow,
            "HEAD audit record: {head_record:?}"
        );
        assert_eq!(
            head_record.tier,
            Tier::L7,
            "HEAD audit record: {head_record:?}"
        );
        assert_eq!(
            head_record.host.as_deref(),
            Some("api.anthropic.com"),
            "HEAD audit record: {head_record:?}"
        );

        let post_record = records
            .iter()
            .find(|r| r.method.as_deref() == Some("POST"))
            .expect("an audit record for the POST flow");
        assert_eq!(
            post_record.verdict,
            Verdict::Deny,
            "POST audit record: {post_record:?}"
        );
        assert_eq!(
            post_record.tier,
            Tier::L7,
            "POST audit record: {post_record:?}"
        );
        assert_eq!(
            post_record.host.as_deref(),
            Some("api.anthropic.com"),
            "POST audit record: {post_record:?}"
        );
    });
}
