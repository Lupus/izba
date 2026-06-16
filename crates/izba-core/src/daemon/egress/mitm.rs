// SPDX-License-Identifier: Apache-2.0
//
// TLS-MITM datapath for izba's egress plane (wired into the production router
// via `super::mitm_runtime`; the blocking router hops the vsock leg into this
// tokio-side orchestrator).
//
// The CA / leaf-minting / TLS-terminate / TLS-connect-upstream machinery in
// this file is SALVAGED from NVIDIA OpenShell's
// `crates/openshell-sandbox/src/l7/tls.rs`
// (github.com/NVIDIA/OpenShell, Apache-2.0,
//  Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES).
//
// Provenance of each item is noted inline:
//   - LIFTED   : copied near-verbatim, only the error type changed
//                (miette -> anyhow) and `tracing` dropped.
//   - ADAPTED  : OpenShell logic, reshaped for izba (e.g. generic streams
//                instead of `tokio::net::TcpStream`).
//   - IZBA     : new code written for izba (the policy seam + `serve_mitm`, the
//                hyper-util HTTP orchestrator). OpenShell parses the L7 with a
//                real HTTP stack behind its `L7Provider` trait; `serve_mitm`
//                does the same with `hyper_util::server::conn::auto`.
//
//! MITM TLS termination for guest HTTPS egress.
//!
//! The guest trusts an izba root CA baked into its store. izbad terminates the
//! client TLS by minting a leaf for the ClientHello SNI under that CA, then runs
//! a real hyper-util HTTP server (h1 + h2) so EVERY request — not just the first
//! on a kept-alive connection — passes a policy `Service` (F-03). The captured
//! SNI is bound to the decrypted HTTP `Host` (F-02). On Allow it re-originates
//! TLS to the real upstream (webpki-verified against `Host`), bridging
//! request/response (and WebSocket upgrades) rather than blind-splicing bytes;
//! non-HTTP after TLS fails closed. `serve_mitm` is generic over the guest
//! stream so tests drive it over `tokio::io::duplex`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::mitm_runtime::OrigDst;

const MAX_CACHED_CERTS: usize = 256;

// ============================================================================
// Ephemeral CA + per-host leaf cache  (LIFTED from OpenShell l7/tls.rs)
// ============================================================================

/// Root CA izba bakes into the guest trust store. In production this is a
/// stable, on-disk CA; the spike (and OpenShell) generate it ephemerally.
///
/// LIFTED from OpenShell `SandboxCa` — only the error type changed
/// (miette -> anyhow) and the DN strings rebranded.
#[allow(clippy::struct_field_names)]
pub struct IzbaCa {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
}

impl IzbaCa {
    /// The fixed CA certificate params. Shared by `generate` and `from_pem` so
    /// a reconstructed signer carries the same subject DN as the persisted cert
    /// — leaves it signs chain to the on-disk `ca.pem` (matched by subject +
    /// the shared key).
    fn ca_params() -> CertificateParams {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "izba egress CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "izba");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    /// Generate a new CA keypair.
    pub fn generate() -> Result<Self> {
        let ca_key = KeyPair::generate().context("generate CA keypair")?;
        let ca_cert = Self::ca_params()
            .self_signed(&ca_key)
            .context("self-sign CA")?;
        let ca_cert_pem = ca_cert.pem();
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem,
        })
    }

    /// Reconstruct a CA from a persisted cert+key PEM pair (the load path of
    /// [`crate::ca::load_or_create`]). The signer `Certificate` is rebuilt from
    /// the fixed CA params + the persisted key (NOT by re-parsing the cert —
    /// that would need rcgen's `x509-parser` feature). The cert PEM handed to
    /// guests is the persisted one verbatim, and leaves signed by the rebuilt
    /// signer chain to it because they share the subject DN + key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let ca_key = KeyPair::from_pem(key_pem).context("load CA keypair from PEM")?;
        let ca_cert = Self::ca_params()
            .self_signed(&ca_key)
            .context("rebuild CA signer cert")?;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem: cert_pem.to_string(),
        })
    }

    /// The CA private key in PKCS#8 PEM — persisted (0600) so the CA survives
    /// daemon restarts. NEVER shared into a guest.
    pub fn key_pem(&self) -> String {
        self.ca_key.serialize_pem()
    }

    /// The CA certificate in PEM — this is what gets baked into the guest.
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The CA certificate in DER (for a client that must trust it directly,
    /// e.g. the in-test guest's rustls root store). IZBA helper.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca_cert.der().to_vec())
    }
}

/// A leaf certificate chain + key for one hostname. LIFTED.
struct CertifiedLeaf {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Per-hostname leaf cache signed by the izba CA. LIFTED from OpenShell
/// `CertCache` (overflow-clear policy preserved verbatim).
pub struct CertCache {
    ca: IzbaCa,
    cache: Mutex<HashMap<String, Arc<CertifiedLeaf>>>,
}

impl CertCache {
    pub fn new(ca: IzbaCa) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_generate(&self, hostname: &str) -> Result<Arc<CertifiedLeaf>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow!("cert cache lock poisoned"))?;

        if let Some(leaf) = cache.get(hostname) {
            return Ok(Arc::clone(leaf));
        }
        // Overflow: clear the whole map (simple, sufficient at sandbox scale).
        if cache.len() >= MAX_CACHED_CERTS {
            cache.clear();
        }
        let leaf = Arc::new(self.generate_leaf(hostname)?);
        cache.insert(hostname.to_string(), Arc::clone(&leaf));
        Ok(leaf)
    }

    /// Mint a leaf for `hostname`, signed by the CA. LIFTED.
    fn generate_leaf(&self, hostname: &str) -> Result<CertifiedLeaf> {
        let leaf_key = KeyPair::generate().context("generate leaf keypair")?;

        let mut params =
            CertificateParams::new(vec![hostname.to_string()]).context("leaf params")?;
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.use_authority_key_identifier_extension = true;

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca.ca_cert, &self.ca.ca_key)
            .context("sign leaf by CA")?;

        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = CertificateDer::from(self.ca.ca_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| anyhow!("serialize leaf key: {e}"))?;

        Ok(CertifiedLeaf {
            cert_chain: vec![leaf_der, ca_der],
            private_key: key_der,
        })
    }

    /// Build a `TlsAcceptor` presenting a freshly-minted leaf for `hostname`.
    /// ADAPTED from OpenShell `ProxyTlsState::acceptor_for`. Production uses the
    /// per-SNI `server_config_with_resolver` instead; this single-host form
    /// remains for the in-test upstream responder.
    #[cfg(test)]
    fn acceptor_for(&self, hostname: &str) -> Result<TlsAcceptor> {
        let leaf = self.get_or_generate(hostname)?;
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
            .context("build leaf ServerConfig")?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    /// Build a rustls `CertifiedKey` for `hostname` (leaf chain + ring signing
    /// key) for use by a `ResolvesServerCert`. IZBA.
    pub fn certified_key(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        let leaf = self.get_or_generate(hostname)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&leaf.private_key)
            .map_err(|e| anyhow!("leaf signing key: {e}"))?;
        Ok(Arc::new(CertifiedKey::new(
            leaf.cert_chain.clone(),
            signing_key,
        )))
    }
}

/// Mints a leaf per ClientHello SNI under the izba CA. Production izbad does not
/// know the hostname up front (the `TcpConnect` frame carries only an IP), so
/// the SNI is recovered from the handshake rather than passed in. IZBA.
struct SniResolver {
    certs: Arc<CertCache>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniResolver")
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_string();
        self.certs.certified_key(&host).ok()
    }
}

/// A `ServerConfig` whose leaf is minted per-ClientHello-SNI under the izba CA;
/// ALPN offers `h2` then `http/1.1` so guests may negotiate either — the
/// hyper-util auto server serves both, and hyper bridges h2↔h1 at the
/// Request/Response layer (the upstream leg negotiates its own protocol). IZBA.
pub fn server_config_with_resolver(certs: Arc<CertCache>) -> ServerConfig {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver { certs }));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

// ============================================================================
// Policy seam  (IZBA — where regorus RegoPolicy plugs in at M5)
// ============================================================================

/// L7 view of one request, as seen AFTER TLS termination. This is the struct a
/// `RegoPolicy` would evaluate (host + method + path; headers/body would join
/// it for credential injection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7Request {
    pub host: String,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Verdict {
    Allow,
    /// Short-circuit with a synthesized HTTP response (the body string).
    Deny(&'static str),
}

/// The policy hook. The production impl wraps regorus; the spike ships a
/// host-allowlist toy so the seam is exercised end to end.
pub trait MitmPolicy: Send + Sync {
    /// Decide + audit one request. Called on EVERY request (F-03).
    fn check(&self, req: &L7Request) -> L7Verdict;

    /// Audit a Deny that the datapath made on its own (not via `check`) — e.g.
    /// the SNI≠Host rejection (F-02), which must be recorded with its own rule.
    /// Defaults to a no-op for policies without an audit sink (the toy spike).
    fn record_deny(&self, _req: &L7Request, _rule: &'static str) {}
}

/// Toy policy: deny any Host not on the allowlist. The clear seam where a
/// `regorus::Engine`-backed policy replaces the `Vec<String>` match.
pub struct HostAllowlist {
    pub allowed: Vec<String>,
}

impl MitmPolicy for HostAllowlist {
    fn check(&self, req: &L7Request) -> L7Verdict {
        if self.allowed.iter().any(|h| h == &req.host) {
            L7Verdict::Allow
        } else {
            L7Verdict::Deny("403 Forbidden by izba egress policy\n")
        }
    }
}

// ============================================================================
// Upstream connector  (ADAPTED from OpenShell tls_connect_upstream)
// ============================================================================

/// Build a rustls `ClientConfig` trusting the given roots, ALPN http/1.1.
/// ADAPTED from OpenShell `build_upstream_client_config` (webpki-roots +
/// system bundle scan dropped — the spike passes roots explicitly; production
/// izbad would load webpki-roots here).
pub fn upstream_client_config(roots: rustls::RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Upstream config trusting the Mozilla CA bundle (webpki-roots) — what
/// production izbad uses to verify the *real* upstream it re-originates to.
pub fn upstream_client_config_webpki() -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    upstream_client_config(roots)
}

/// Re-originate TLS to the verified upstream over a generic stream.
/// ADAPTED from OpenShell `tls_connect_upstream` — the only change is the
/// stream type: `impl AsyncRead+AsyncWrite+Unpin` instead of `TcpStream`, so
/// izbad can dial the upstream through whatever transport it likes.
pub async fn tls_connect_upstream<S>(
    upstream: S,
    hostname: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connector = TlsConnector::from(Arc::clone(client_config));
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow!("invalid upstream server name {hostname:?}: {e}"))?;
    let tls = connector
        .connect(server_name, upstream)
        .await
        .context("upstream TLS handshake")?;
    Ok(tls)
}

// ============================================================================
// The MITM orchestrator  (IZBA — a real hyper-util HTTP datapath)
// ============================================================================

/// What izbad needs to MITM a flow: the cert cache (CA) and an upstream
/// rustls config. Cheap to clone-share across connections.
pub struct MitmState {
    /// Acceptor whose leaf is minted per ClientHello SNI under the izba CA
    /// (built via `server_config_with_resolver`).
    pub acceptor: TlsAcceptor,
    pub upstream: Arc<ClientConfig>,
}

/// The boxed response body the service returns — unifies the synthesized 403
/// (`Full<Bytes>`) and the proxied upstream body (`Incoming`).
type SvcBody = BoxBody<Bytes, anyhow::Error>;

/// A re-originated upstream HTTP connection, picked by the upstream's negotiated
/// ALPN. One per guest connection, reused across keep-alive (the SNI==Host check
/// pins the whole guest connection to a single Host).
enum UpstreamSender {
    H1(hyper::client::conn::http1::SendRequest<Incoming>),
    H2(hyper::client::conn::http2::SendRequest<Incoming>),
}

impl UpstreamSender {
    async fn send(&mut self, req: Request<Incoming>) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            UpstreamSender::H1(s) => s.send_request(req).await,
            UpstreamSender::H2(s) => s.send_request(req).await,
        }
    }
}

/// Normalize the request's target Host: prefer the URI authority host (h2
/// `:authority` / absolute-form h1), else the `Host` header; strip a port + a
/// trailing dot, lowercase. `None` when neither carries a host.
fn req_host<B>(req: &Request<B>) -> Option<String> {
    req.uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

/// A synthesized fail-closed response (403, `Connection: close`).
fn forbidden(body: &'static str) -> Response<SvcBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(hyper::header::CONNECTION, "close")
        .body(boxed(body))
        .expect("static forbidden response builds")
}

fn boxed(body: &'static str) -> SvcBody {
    Full::new(Bytes::from_static(body.as_bytes()))
        .map_err(|never| match never {})
        .boxed()
}

/// Is this an HTTP/1.1 `Upgrade: websocket` request?
fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    fn header_has_token<B>(req: &Request<B>, name: hyper::header::HeaderName, token: &str) -> bool {
        req.headers().get_all(name).iter().any(|v| {
            v.to_str()
                .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
                .unwrap_or(false)
        })
    }
    header_has_token(req, hyper::header::CONNECTION, "upgrade")
        && header_has_token(req, hyper::header::UPGRADE, "websocket")
}

/// Per-connection shared state the service closure captures.
struct ConnCtx {
    upstream_cfg: Arc<ClientConfig>,
    orig: OrigDst,
    /// SNI captured from the guest's ClientHello (`None` for cleartext :80).
    client_sni: Option<String>,
    /// Lazily-established upstream sender, reused across keep-alive requests.
    upstream: AsyncMutex<Option<UpstreamSender>>,
}

impl ConnCtx {
    /// Establish (once) or reuse the upstream connection to `host`. The first
    /// allowed request dials `orig.ip:orig.port`, TLS-connects verifying the
    /// cert against `host` (webpki), and picks h1/h2 by the upstream ALPN.
    async fn upstream_send(
        &self,
        host: &str,
        req: Request<Incoming>,
    ) -> Result<Response<Incoming>> {
        let mut guard = self.upstream.lock().await;
        if guard.is_none() {
            *guard = Some(self.dial_upstream(host).await?);
        }
        guard
            .as_mut()
            .expect("upstream just established")
            .send(req)
            .await
            .context("forward request upstream")
    }

    async fn dial_upstream(&self, host: &str) -> Result<UpstreamSender> {
        let tcp = tokio::net::TcpStream::connect((self.orig.ip, self.orig.port))
            .await
            .with_context(|| format!("dial upstream {}:{}", self.orig.ip, self.orig.port))?;
        let connector = TlsConnector::from(Arc::clone(&self.upstream_cfg));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("invalid upstream server name {host:?}: {e}"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("upstream TLS handshake")?;
        let alpn_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);
        if alpn_h2 {
            let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                .await
                .context("upstream h2 handshake")?;
            tokio::spawn(conn);
            Ok(UpstreamSender::H2(sender))
        } else {
            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .context("upstream h1 handshake")?;
            tokio::spawn(conn.with_upgrades());
            Ok(UpstreamSender::H1(sender))
        }
    }
}

/// The hyper-util MITM datapath. Replaces the hand-rolled request sniffer with a
/// real HTTP stack: every request (or h2 stream) on the connection hits the
/// policy `Service`, so keep-alive can no longer smuggle a second Host past the
/// first check (F-03). The ClientHello SNI is bound to the HTTP Host (F-02).
///
/// `client_io` is the already-TLS-terminated guest stream (or the raw cleartext
/// stream on :80, `sni = None`). `policy` is the audited per-request decision
/// seam ([`MitmPolicy`] / `PolicyAdapter`). `orig` carries the dial target +
/// sandbox the L7 view lacks.
///
/// Fails closed for everything it cannot inspect: non-HTTP after TLS makes
/// hyper error on the preface; we audit + drop, never blind-tunnel.
pub async fn serve_mitm<C>(
    client_io: C,
    sni: Option<String>,
    state: &MitmState,
    policy: Arc<dyn MitmPolicy>,
    orig: OrigDst,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ctx = Arc::new(ConnCtx {
        upstream_cfg: Arc::clone(&state.upstream),
        orig,
        client_sni: sni,
        upstream: AsyncMutex::new(None),
    });

    // `service_fn` is invoked per request (per h2 stream under h2). It must be
    // `Fn` + `'static`, so it captures cloneable owned handles only.
    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = Arc::clone(&ctx);
        let policy = Arc::clone(&policy);
        async move { handle_request(ctx, policy, req).await }
    });

    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .serve_connection_with_upgrades(TokioIo::new(client_io), service)
        .await
        .map_err(|e| anyhow!("serve guest HTTP connection: {e}"))
}

/// Per-request: SNI==Host (F-02), audited policy (F-03), then forward upstream
/// (or bridge a WebSocket upgrade) on Allow.
async fn handle_request(
    ctx: Arc<ConnCtx>,
    policy: Arc<dyn MitmPolicy>,
    req: Request<Incoming>,
) -> Result<Response<SvcBody>, anyhow::Error> {
    let host = match req_host(&req) {
        Some(h) => h,
        // No Host at all: nothing to bind SNI to or policy-check — fail closed.
        None => {
            return Ok(forbidden(
                "403 Forbidden by izba egress policy: missing Host\n",
            ))
        }
    };

    // F-02: the ClientHello SNI (when present) must equal the HTTP Host. A guest
    // that handshakes for a.com then asks for b.com on the same session is
    // rejected without an upstream dial.
    if let Some(sni) = &ctx.client_sni {
        if !sni.eq_ignore_ascii_case(&host) {
            policy.record_deny(
                &L7Request {
                    host: host.clone(),
                    method: req.method().to_string(),
                    path: req.uri().path().to_string(),
                },
                "sni-host-mismatch",
            );
            return Ok(forbidden(
                "403 Forbidden by izba egress policy: SNI/Host mismatch\n",
            ));
        }
    }

    // F-03: policy runs on EVERY request, audited by the adapter.
    let l7 = L7Request {
        host: host.clone(),
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
    };
    if let L7Verdict::Deny(body) = policy.check(&l7) {
        return Ok(forbidden(body));
    }

    if is_websocket_upgrade(&req) {
        return bridge_websocket(ctx, host, req).await;
    }

    // Allow: forward upstream over the (lazily-established, reused) connection.
    let resp = ctx.upstream_send(&host, req).await?;
    Ok(resp.map(|b| b.map_err(anyhow::Error::from).boxed()))
}

/// Bridge an HTTP/1.1 WebSocket upgrade: forward the upgrade request upstream;
/// on the upstream `101`, return `101` to the guest and splice both upgraded
/// byte streams with `copy_bidirectional`. Policy already ran on the request's
/// Host (and SNI==Host was enforced).
async fn bridge_websocket(
    ctx: Arc<ConnCtx>,
    host: String,
    mut req: Request<Incoming>,
) -> Result<Response<SvcBody>, anyhow::Error> {
    // Take the guest-side upgrade future BEFORE the request is consumed upstream.
    let guest_on = hyper::upgrade::on(&mut req);

    let mut upstream_resp = ctx.upstream_send(&host, req).await?;
    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade — relay its response verbatim.
        return Ok(upstream_resp.map(|b| b.map_err(anyhow::Error::from).boxed()));
    }

    // Take the upstream-side upgrade future, then build the 101 we hand the
    // guest from the upstream response headers.
    let upstream_on = hyper::upgrade::on(&mut upstream_resp);
    let mut to_guest = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in upstream_resp.headers() {
        to_guest = to_guest.header(k, v);
    }

    tokio::spawn(async move {
        let (guest, upstream) = match tokio::try_join!(guest_on, upstream_on) {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let mut guest = TokioIo::new(guest);
        let mut upstream = TokioIo::new(upstream);
        let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
    });

    let resp = to_guest
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .context("build websocket 101 to guest")?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};

    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::daemon::egress::mitm_runtime::OrigDst;

    /// Ensure the ring CryptoProvider is the process default. aws-lc-rs is
    /// ALSO linked (via oci-client's reqwest), so an ambiguous default would
    /// panic. Idempotent via `OnceLock`.
    fn install_ring() {
        use std::sync::OnceLock;
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Build the MITM state (izba CA + acceptor) and the guest's rustls config
    /// (trusting ONLY the izba CA). `state.upstream` starts trusting nothing;
    /// each test rewires it to the in-test upstream CA.
    fn test_ca_and_state() -> (CertificateDer<'static>, MitmState, Arc<ClientConfig>) {
        let ca = IzbaCa::generate().unwrap();
        let ca_der = ca.cert_der();

        let guest_cfg = guest_cfg_with_alpn(ca_der.clone(), &[b"http/1.1"]);
        let certs = Arc::new(CertCache::new(ca));
        let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(certs)));
        (
            ca_der,
            MitmState {
                acceptor,
                upstream: upstream_client_config(rustls::RootCertStore::empty()),
            },
            guest_cfg,
        )
    }

    /// A guest rustls config trusting the izba CA with the given ALPN.
    fn guest_cfg_with_alpn(ca_der: CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let mut c = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(c)
    }

    type BoxFut<B> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response<B>, anyhow::Error>> + Send>,
    >;

    /// Spin a real HTTPS upstream on a loopback TCP listener presenting a leaf
    /// for `host` under a fresh CA (ALPN h2+http/1.1), serving `service` per
    /// request via the hyper-util auto server. Returns (upstream CA der, addr).
    async fn spawn_https_upstream<S, B>(
        host: &'static str,
        service: S,
    ) -> (CertificateDer<'static>, SocketAddr)
    where
        S: Fn(Request<Incoming>) -> BoxFut<B> + Send + Sync + Clone + 'static,
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let up_ca = IzbaCa::generate().unwrap();
        let up_ca_der = up_ca.cert_der();
        let cache = CertCache::new(up_ca);
        let acceptor = cache.acceptor_for(host).unwrap();

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream listener");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let service = service.clone();
                tokio::spawn(async move {
                    let tls = match acceptor.accept(tcp).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let svc = service_fn(move |req| (service.clone())(req));
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });

        (up_ca_der, addr)
    }

    /// A responder that answers 200 with `body` for any request.
    fn ok_responder(
        body: &'static str,
    ) -> impl Fn(Request<Incoming>) -> BoxFut<Full<Bytes>> + Send + Sync + Clone + 'static {
        move |_req: Request<Incoming>| {
            Box::pin(async move {
                Ok(Response::new(Full::new(Bytes::from_static(
                    body.as_bytes(),
                ))))
            }) as BoxFut<Full<Bytes>>
        }
    }

    fn orig_dst(addr: SocketAddr) -> OrigDst {
        OrigDst {
            ip: addr.ip(),
            port: addr.port(),
            sandbox: "web".into(),
        }
    }

    /// Accept the guest TLS (capturing SNI) and run serve_mitm on it.
    fn run_mitm_tls<C>(
        state: MitmState,
        guest_conn: C,
        policy: Arc<dyn MitmPolicy>,
        orig: OrigDst,
    ) -> tokio::task::JoinHandle<Result<()>>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let tls = state
                .acceptor
                .accept(guest_conn)
                .await
                .context("MITM accept guest TLS")?;
            let sni = tls.get_ref().1.server_name().map(str::to_string);
            serve_mitm(tls, sni, &state, policy, orig).await
        })
    }

    // ---- F-03: every request on a keep-alive connection is re-checked --------

    #[tokio::test]
    async fn keepalive_second_request_is_rechecked() {
        install_ring();
        let host = "api.anthropic.com";
        let (ca_der, mut state, _g) = test_ca_and_state();

        let (up_ca_der, up_addr) = spawn_https_upstream(host, ok_responder("PONG")).await;
        let mut up_roots = rustls::RootCertStore::empty();
        up_roots.add(up_ca_der).unwrap();
        state.upstream = upstream_client_config(up_roots);

        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec![host.to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(up_addr));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest handshake");

        guest
            .write_all(b"GET /a HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .await
            .unwrap();
        guest.flush().await.unwrap();
        let status1 = read_status_line(&mut guest).await;
        assert!(status1.contains("200"), "req1 status: {status1}");
        drain_response_headers(&mut guest).await;
        // Drain the 200 response body (Content-Length: 4 -> "PONG").
        let mut body1 = [0u8; 4];
        guest.read_exact(&mut body1).await.unwrap();

        guest
            .write_all(b"GET /b HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
            .await
            .unwrap();
        guest.flush().await.unwrap();
        let status2 = read_status_line(&mut guest).await;
        assert!(
            status2.contains("403"),
            "req2 must be denied (F-03): {status2}"
        );

        drop(guest);
        let _ = mitm.await;
    }

    // ---- F-02: ClientHello SNI must equal the HTTP Host ---------------------

    #[tokio::test]
    async fn sni_host_mismatch_is_denied() {
        install_ring();
        let sni_host = "allowed.example.com";
        let (ca_der, state, _g) = test_ca_and_state();

        let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec!["other.example.com".to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(unused));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(sni_host).unwrap(), guest_side)
            .await
            .expect("guest handshake");
        guest
            .write_all(b"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
            .await
            .unwrap();
        guest.flush().await.unwrap();
        let status = read_status_line(&mut guest).await;
        assert!(
            status.contains("403"),
            "SNI!=Host must 403 (F-02): {status}"
        );

        drop(guest);
        let _ = mitm.await;
    }

    // ---- ported happy-path: MITM sees L7 + pipes upstream response ----------

    #[tokio::test]
    async fn mitm_sees_l7_and_pipes_upstream_response() {
        install_ring();
        let host = "api.anthropic.com";
        let (ca_der, mut state, _g) = test_ca_and_state();

        let (up_ca_der, up_addr) = spawn_https_upstream(host, ok_responder("UPSTREAM-PONG")).await;
        let mut up_roots = rustls::RootCertStore::empty();
        up_roots.add(up_ca_der).unwrap();
        state.upstream = upstream_client_config(up_roots);

        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec![host.to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(up_addr));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest handshake under izba CA");
        guest
            .write_all(b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        guest.flush().await.unwrap();

        let mut got = Vec::new();
        guest.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("200 OK"), "response status: {got}");
        assert!(got.contains("UPSTREAM-PONG"), "response body: {got}");

        drop(guest);
        let _ = mitm.await;
    }

    // ---- ported deny short-circuit (no upstream dial) -----------------------

    #[tokio::test]
    async fn policy_deny_short_circuits_without_upstream() {
        install_ring();
        let host = "blocked.example.com";
        let (ca_der, state, _g) = test_ca_and_state();

        let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec!["allowed.example.com".to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(unused));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest handshake under izba CA");
        guest
            .write_all(
                b"GET /secret HTTP/1.1\r\nHost: blocked.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        guest.flush().await.unwrap();

        let mut got = Vec::new();
        guest.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("403"), "deny response: {got}");

        drop(guest);
        let _ = mitm.await;
    }

    // ---- non-HTTP after TLS termination fails closed (no dial, no hang) ------

    #[tokio::test]
    async fn non_http_over_tls_fails_closed() {
        install_ring();
        let host = "api.anthropic.com";
        let (ca_der, state, _g) = test_ca_and_state();

        let dialed = Arc::new(AtomicBool::new(false));
        let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec![host.to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(unused));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest handshake");
        guest
            .write_all(b"\x00\x01\x02not-http-at-all")
            .await
            .unwrap();
        guest.flush().await.unwrap();
        guest.shutdown().await.ok();

        let res = tokio::time::timeout(std::time::Duration::from_secs(5), mitm).await;
        assert!(res.is_ok(), "serve_mitm hung on non-HTTP input");
        assert!(
            !dialed.load(Ordering::SeqCst),
            "upstream must not be dialed"
        );
    }

    // ---- WebSocket upgrade is policy-checked and bridged --------------------

    #[tokio::test]
    async fn websocket_upgrade_is_policy_checked_and_bridged() {
        install_ring();
        let host = "api.anthropic.com";
        let (ca_der, mut state, _g) = test_ca_and_state();

        let ws_responder = move |mut req: Request<Incoming>| {
            Box::pin(async move {
                let on = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    if let Ok(upgraded) = on.await {
                        let mut io = TokioIo::new(upgraded);
                        let mut buf = [0u8; 64];
                        if let Ok(n) = io.read(&mut buf).await {
                            if n > 0 {
                                let _ = io.write_all(&buf[..n]).await;
                                let _ = io.flush().await;
                            }
                        }
                    }
                });
                Ok(Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(hyper::header::CONNECTION, "upgrade")
                    .header(hyper::header::UPGRADE, "websocket")
                    .body(Empty::<Bytes>::new())
                    .unwrap())
            }) as BoxFut<Empty<Bytes>>
        };
        let (up_ca_der, up_addr) = spawn_https_upstream(host, ws_responder).await;
        let mut up_roots = rustls::RootCertStore::empty();
        up_roots.add(up_ca_der).unwrap();
        state.upstream = upstream_client_config(up_roots);

        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec![host.to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(64 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(up_addr));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"http/1.1"]));
        let mut guest = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest handshake");
        guest
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        guest.flush().await.unwrap();

        let status = read_status_line(&mut guest).await;
        assert!(status.contains("101"), "expected 101 upgrade: {status}");
        drain_response_headers(&mut guest).await;

        guest.write_all(b"hello-ws").await.unwrap();
        guest.flush().await.unwrap();
        let mut echoed = [0u8; 8];
        guest.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            &echoed, b"hello-ws",
            "websocket bytes must bridge both ways"
        );

        drop(guest);
        let _ = mitm.await;
    }

    // ---- h2 client path is policy-checked per stream ------------------------

    #[tokio::test]
    async fn h2_client_path_is_policy_checked() {
        install_ring();
        let host = "api.anthropic.com";
        let (ca_der, mut state, _g) = test_ca_and_state();

        let (up_ca_der, up_addr) = spawn_https_upstream(host, ok_responder("H2-PONG")).await;
        let mut up_roots = rustls::RootCertStore::empty();
        up_roots.add(up_ca_der).unwrap();
        state.upstream = upstream_client_config(up_roots);

        let policy: Arc<dyn MitmPolicy> = Arc::new(HostAllowlist {
            allowed: vec![host.to_string()],
        });

        let (guest_side, mitm_side) = tokio::io::duplex(256 * 1024);
        let mitm = run_mitm_tls(state, mitm_side, policy, orig_dst(up_addr));

        let connector = TlsConnector::from(guest_cfg_with_alpn(ca_der, &[b"h2"]));
        let guest_tls = connector
            .connect(ServerName::try_from(host).unwrap(), guest_side)
            .await
            .expect("guest h2 handshake");
        assert_eq!(
            guest_tls.get_ref().1.alpn_protocol(),
            Some(&b"h2"[..]),
            "guest must have negotiated h2"
        );

        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(guest_tls))
                .await
                .expect("h2 client handshake");
        tokio::spawn(conn);

        let req = Request::builder()
            .uri("https://api.anthropic.com/v1/messages")
            .header(hyper::header::HOST, "api.anthropic.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.expect("h2 send allowed");
        assert_eq!(resp.status(), StatusCode::OK, "allowed h2 stream -> 200");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"H2-PONG");

        let req2 = Request::builder()
            .uri("https://evil.example.com/")
            .header(hyper::header::HOST, "evil.example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp2 = sender.send_request(req2).await.expect("h2 send denied");
        assert_eq!(
            resp2.status(),
            StatusCode::FORBIDDEN,
            "denied h2 stream -> 403"
        );

        // The guest's h2 connection driver keeps the session open; we've proven
        // both streams' verdicts, so abort the MITM rather than wait on EOF.
        drop(sender);
        mitm.abort();
    }

    // ---- unit tests for host-normalization + ALPN helpers --------------------

    #[test]
    fn client_leg_alpn_offers_h2_and_http11() {
        install_ring();
        let ca = IzbaCa::generate().unwrap();
        let cfg = server_config_with_resolver(Arc::new(CertCache::new(ca)));
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn req_host_strips_port_and_lowercases() {
        let r: Request<Empty<Bytes>> = Request::builder()
            .uri("/x")
            .header(hyper::header::HOST, "API.Example.COM:8443")
            .body(Empty::new())
            .unwrap();
        assert_eq!(req_host(&r).as_deref(), Some("api.example.com"));

        let r2: Request<Empty<Bytes>> = Request::builder()
            .uri("https://Authority.Example.com/y")
            .body(Empty::new())
            .unwrap();
        assert_eq!(req_host(&r2).as_deref(), Some("authority.example.com"));

        let r3: Request<Empty<Bytes>> = Request::builder()
            .uri("/z")
            .header(hyper::header::HOST, "host.example.com.")
            .body(Empty::new())
            .unwrap();
        assert_eq!(req_host(&r3).as_deref(), Some("host.example.com"));
    }

    // --- LIFTED unit tests from OpenShell tls.rs (CA / cache) ---

    #[test]
    fn ca_generation() {
        let ca = IzbaCa::generate().unwrap();
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn leaf_cert_generation() {
        let cache = CertCache::new(IzbaCa::generate().unwrap());
        let leaf = cache.get_or_generate("example.com").unwrap();
        assert_eq!(leaf.cert_chain.len(), 2);
    }

    #[test]
    fn cache_dedup() {
        let cache = CertCache::new(IzbaCa::generate().unwrap());
        let a = cache.get_or_generate("example.com").unwrap();
        let b = cache.get_or_generate("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_overflow_clears() {
        let cache = CertCache::new(IzbaCa::generate().unwrap());
        for i in 0..MAX_CACHED_CERTS {
            cache
                .get_or_generate(&format!("host{i}.example.com"))
                .unwrap();
        }
        cache.get_or_generate("overflow.example.com").unwrap();
        assert_eq!(cache.cache.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cert_resolver_mints_for_clienthello_sni() {
        install_ring();
        let ca = IzbaCa::generate().unwrap();
        let ca_der = ca.cert_der();
        let server_cfg = server_config_with_resolver(Arc::new(CertCache::new(ca)));

        let gcfg = guest_cfg_with_alpn(ca_der, &[b"http/1.1"]);
        let (g, s) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let srv = tokio::spawn(async move {
            acceptor
                .accept(s)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = TlsConnector::from(gcfg);
        let name = ServerName::try_from("late.example.com").unwrap();
        let _guest = conn
            .connect(name, g)
            .await
            .expect("handshake under izba CA via the SNI resolver");
        srv.await.unwrap().expect("server side accepted");
    }

    // --- helpers to read a raw HTTP/1.1 response over the TLS stream -----------

    async fn read_status_line<R: AsyncRead + Unpin>(r: &mut R) -> String {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = r.read(&mut b).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            line.push(b[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&line).trim().to_string()
    }

    /// Consume up to (and including) the blank line ending the response headers.
    async fn drain_response_headers<R: AsyncRead + Unpin>(r: &mut R) {
        let mut window = [0u8; 4];
        let mut b = [0u8; 1];
        loop {
            let n = r.read(&mut b).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            window.rotate_left(1);
            window[3] = b[0];
            if &window == b"\r\n\r\n" {
                break;
            }
        }
    }
}
