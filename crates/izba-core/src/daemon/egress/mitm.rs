// SPDX-License-Identifier: Apache-2.0
//
// TLS-MITM datapath for izba's egress plane (M5 SPIKE — not wired into the
// production router yet; see `super::router` for the integration point).
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
//   - IZBA     : new code written for this spike (HTTP request-line sniff,
//                policy seam, the generic-stream orchestrator + pump).
//
//! MITM TLS termination for guest HTTPS egress.
//!
//! The guest trusts an izba root CA baked into its store. izbad terminates the
//! client TLS by minting a leaf for the SNI under that CA, reads the decrypted
//! HTTP request line + Host (L7 visibility for policy / credential injection),
//! applies a policy hook, then re-originates TLS to the real upstream and pipes
//! the bytes back. Operates on any `AsyncRead + AsyncWrite + Unpin` so it is
//! decoupled from the vsock/TCP transport — the test drives it over
//! `tokio::io::duplex`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
/// ALPN pinned to `http/1.1` (h2 deferred — nearly all servers downgrade). IZBA.
pub fn server_config_with_resolver(certs: Arc<CertCache>) -> ServerConfig {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver { certs }));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

/// Detect a TLS ClientHello from the first bytes of a stream. LIFTED verbatim
/// from OpenShell `looks_like_tls` — the non-TLS fallthrough decision point.
pub fn looks_like_tls(peek: &[u8]) -> bool {
    if peek.len() < 3 {
        return false;
    }
    if peek[0] != 0x16 {
        return false; // not ContentType::Handshake
    }
    if peek[1] != 0x03 {
        return false; // TLS major version must be 0x03
    }
    peek[2] <= 0x04 // minor: SSL3.0 (0x00) .. TLS1.3 record (0x04)
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
    fn check(&self, req: &L7Request) -> L7Verdict;
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
// HTTP request-line sniff  (IZBA — replaces OpenShell's hyper/L7Provider stack)
// ============================================================================

/// Read just enough of the decrypted request to prove L7 visibility: the
/// request line (`METHOD SP PATH SP HTTP/x.x`) + the `Host:` header.
///
/// Returns the parsed view AND the raw header bytes consumed, so the caller can
/// forward them verbatim to the upstream (we must not lose what we peeled off).
///
/// NOTE (production path): this hand-rolled reader proves the datapath; the
/// real izbad should parse with `hyper`'s `http1` server so it handles chunked
/// bodies, pipelining, and connection reuse. OpenShell does exactly that behind
/// its `L7Provider::parse_request` trait — that layer is what we did NOT lift
/// (it is fused to OpenShell's OCSF telemetry + OPA engine).
async fn read_request_head<R>(client: &mut R) -> Result<(L7Request, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    // Read byte-by-byte until the CRLFCRLF end-of-headers. Bounded so a
    // malicious guest can't make us buffer forever.
    const MAX_HEAD: usize = 64 * 1024;
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await.context("read request head")?;
        if n == 0 {
            return Err(anyhow!("client closed before end of request headers"));
        }
        head.push(byte[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(anyhow!("request headers exceeded {MAX_HEAD} bytes"));
        }
    }

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        return Err(anyhow!("malformed request line: {request_line:?}"));
    }

    let host = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("host")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_default();

    Ok((L7Request { host, method, path }, head))
}

// ============================================================================
// The MITM orchestrator  (IZBA — the izba-shaped datapath, generic over stream)
// ============================================================================

/// What izbad needs to MITM a flow: the cert cache (CA) and an upstream
/// rustls config. Cheap to clone-share across connections.
pub struct MitmState {
    /// Acceptor whose leaf is minted per ClientHello SNI under the izba CA
    /// (built via `server_config_with_resolver`).
    pub acceptor: TlsAcceptor,
    pub upstream: Arc<ClientConfig>,
}

/// Terminate the guest's client TLS, sniff the request, apply policy, then
/// (on Allow) splice it to `upstream` re-encrypting under a verified TLS
/// session. On Deny, synthesize a response and return without touching the
/// upstream.
///
/// `client` is the raw guest byte stream (post-`StreamOpen::TcpConnect`, in
/// production). The leaf hostname is recovered from the ClientHello SNI by the
/// acceptor's cert resolver. `connect_upstream` is a closure that dials the
/// real upstream (kept abstract so the datapath never owns a socket / the vsock
/// router).
///
/// Returns the `L7Request` it observed, so the caller can audit L7 visibility.
pub async fn mitm_terminate<C, U, F, Fut>(
    client: C,
    state: &MitmState,
    policy: &dyn MitmPolicy,
    connect_upstream: F,
) -> Result<L7Request>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<U>>,
{
    // 1. Terminate the client TLS under a leaf minted for the ClientHello SNI.
    let mut client_tls = state
        .acceptor
        .accept(client)
        .await
        .context("client TLS handshake (leaf under izba CA)")?;

    // 2. Read the decrypted request head — L7 visibility for policy / creds.
    let (req, head_bytes) = read_request_head(&mut client_tls).await?;

    // 3. Policy hook. Deny short-circuits with a synthesized response.
    if let L7Verdict::Deny(body) = policy.check(&req) {
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client_tls
            .write_all(resp.as_bytes())
            .await
            .context("write deny response")?;
        client_tls.flush().await.ok();
        client_tls.shutdown().await.ok();
        return Ok(req);
    }

    // 4. Allow: dial + TLS-connect the real upstream, replay the request head
    //    we already consumed, then pipe both directions.
    let upstream_raw = connect_upstream().await.context("dial upstream")?;
    let mut upstream_tls = tls_connect_upstream(upstream_raw, &req.host, &state.upstream).await?;
    upstream_tls
        .write_all(&head_bytes)
        .await
        .context("replay request head to upstream")?;
    upstream_tls.flush().await.ok();

    pump_bidirectional(client_tls, upstream_tls).await;
    Ok(req)
}

/// Copy both directions to EOF, then full-shutdown each peer. IZBA — mirrors
/// the blocking `portfwd::pump_bidirectional` discipline in async form:
/// drain-to-EOF + explicit `shutdown()` honour the OpenVMM churn-teardown
/// invariant (never force-close a peer with TX still buffered). Failures are
/// swallowed — a half-closed peer is normal teardown, not an error.
async fn pump_bidirectional<A, B>(client: A, upstream: B)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let c2u = tokio::spawn(copy_then_shutdown(cr, uw));
    let u2c = tokio::spawn(copy_then_shutdown(ur, cw));
    let _ = c2u.await;
    let _ = u2c.await;
}

async fn copy_then_shutdown<R, W>(mut r: ReadHalf<R>, mut w: WriteHalf<W>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _ = tokio::io::copy(&mut r, &mut w).await;
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// Ensure the ring CryptoProvider is the process default. aws-lc-rs is
    /// ALSO linked (via oci-client's reqwest), so an ambiguous default would
    /// panic — installing ring explicitly is exactly what production izbad
    /// must do too. Idempotent across tests via `OnceLock`.
    fn install_ring() {
        use std::sync::OnceLock;
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            // Best-effort: another part of the process (e.g. the daemon's
            // build_mitm_runtime, exercised by server tests in the same binary)
            // may have already installed ring as the default. Both install ring,
            // so an "already installed" error is fine to ignore.
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn test_ca_and_state() -> (CertificateDer<'static>, MitmState, Arc<ClientConfig>) {
        let ca = IzbaCa::generate().unwrap();
        let ca_der = ca.cert_der();

        // The guest's rustls config: trusts ONLY the izba CA (proving the
        // MITM leaf chains to it).
        let mut guest_roots = rustls::RootCertStore::empty();
        guest_roots.add(ca_der.clone()).unwrap();
        let guest_cfg = {
            let mut c = ClientConfig::builder()
                .with_root_certificates(guest_roots)
                .with_no_client_auth();
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(c)
        };

        let certs = Arc::new(CertCache::new(ca));
        let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(certs)));
        (
            ca_der,
            MitmState {
                acceptor,
                upstream: dummy_upstream_cfg(),
            },
            guest_cfg,
        )
    }

    /// Upstream rustls config for the MITM->upstream leg. The in-test upstream
    /// presents a cert signed by `upstream_ca`, which this config trusts.
    fn dummy_upstream_cfg() -> Arc<ClientConfig> {
        upstream_client_config(rustls::RootCertStore::empty())
    }

    /// Spin a tiny TLS "upstream" on one end of a duplex: it presents a leaf
    /// for `host` under `upstream_ca`, reads the replayed request, and answers
    /// a fixed body. Returns (its CA der, a duplex end the MITM connects to).
    fn spawn_tls_upstream(
        host: &'static str,
        body: &'static str,
    ) -> (CertificateDer<'static>, tokio::io::DuplexStream) {
        let up_ca = IzbaCa::generate().unwrap();
        let up_ca_der = up_ca.cert_der();
        let cache = CertCache::new(up_ca);
        let acceptor = cache.acceptor_for(host).unwrap();
        let (mitm_side, up_side) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut tls = acceptor.accept(up_side).await.expect("upstream accept");
            // Read the replayed request head (to CRLFCRLF).
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            loop {
                let n = tls.read(&mut b).await.unwrap_or(0);
                if n == 0 {
                    break;
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
            tls.write_all(resp.as_bytes()).await.ok();
            tls.flush().await.ok();
            tls.shutdown().await.ok();
        });
        (up_ca_der, mitm_side)
    }

    #[tokio::test]
    async fn mitm_sees_l7_and_pipes_upstream_response() {
        install_ring();
        let host = "api.anthropic.com";
        let (_izba_ca, mut state, guest_cfg) = test_ca_and_state();

        // Wire the MITM's upstream config to trust the in-test upstream CA.
        let (up_ca_der, up_stream) = spawn_tls_upstream(host, "UPSTREAM-PONG");
        let mut up_roots = rustls::RootCertStore::empty();
        up_roots.add(up_ca_der).unwrap();
        state.upstream = upstream_client_config(up_roots);

        // The guest <-> MITM in-memory pipe.
        let (guest_side, mitm_side) = duplex(64 * 1024);

        // Policy: allow the host under test.
        let policy = HostAllowlist {
            allowed: vec![host.to_string()],
        };

        // Run the MITM. `connect_upstream` just hands over the upstream duplex.
        let up_stream = Mutex::new(Some(up_stream));
        let mitm = tokio::spawn(async move {
            mitm_terminate(mitm_side, &state, &policy, || async move {
                Ok(up_stream.lock().unwrap().take().unwrap())
            })
            .await
        });

        // The guest: TLS-handshake to the MITM (trusting only the izba CA),
        // send a request, read the response.
        let connector = TlsConnector::from(guest_cfg);
        let server_name = ServerName::try_from(host).unwrap();
        let mut guest_tls = connector
            .connect(server_name, guest_side)
            .await
            .expect("(a) guest handshake under izba CA must succeed");

        guest_tls
            .write_all(b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .await
            .unwrap();
        guest_tls.flush().await.unwrap();

        let mut got = Vec::new();
        guest_tls.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8_lossy(&got);

        // (c) upstream response flowed back through the MITM.
        assert!(got.contains("200 OK"), "response status: {got}");
        assert!(got.contains("UPSTREAM-PONG"), "response body: {got}");

        // Close the guest leg so the proxy's drain-to-EOF (guest->upstream
        // direction) completes — without this the churn-safe pump never
        // returns and the `mitm.await` below would block forever.
        drop(guest_tls);

        // (b) the MITM SAW the decrypted L7 request.
        let observed = mitm.await.unwrap().expect("mitm datapath");
        assert_eq!(observed.method, "GET");
        assert_eq!(observed.path, "/v1/messages");
        assert_eq!(observed.host, "api.anthropic.com");
    }

    #[tokio::test]
    async fn policy_deny_short_circuits_without_upstream() {
        install_ring();
        let host = "blocked.example.com";
        let (_izba_ca, state, guest_cfg) = test_ca_and_state();

        let (guest_side, mitm_side) = duplex(64 * 1024);
        // Allowlist does NOT contain `host` -> Deny.
        let policy = HostAllowlist {
            allowed: vec!["allowed.example.com".to_string()],
        };

        let mitm = tokio::spawn(async move {
            mitm_terminate(
                mitm_side,
                &state,
                &policy,
                // If this is ever called, the upstream connector errors —
                // proving Deny short-circuited before any upstream dial.
                || async {
                    Err::<tokio::io::DuplexStream, _>(anyhow!(
                        "upstream must NOT be dialed on deny"
                    ))
                },
            )
            .await
        });

        let connector = TlsConnector::from(guest_cfg);
        let server_name = ServerName::try_from(host).unwrap();
        let mut guest_tls = connector
            .connect(server_name, guest_side)
            .await
            .expect("guest handshake under izba CA");
        guest_tls
            .write_all(b"GET /secret HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
            .await
            .unwrap();
        guest_tls.flush().await.unwrap();

        let mut got = Vec::new();
        guest_tls.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("403 Forbidden"), "deny response: {got}");
        assert!(got.contains("izba egress policy"), "deny body: {got}");

        // The datapath returned the observed request without dialing upstream.
        let observed = mitm.await.unwrap().expect("mitm deny path");
        assert_eq!(observed.host, "blocked.example.com");
        assert_eq!(observed.method, "GET");
    }

    #[tokio::test]
    async fn cert_resolver_mints_for_clienthello_sni() {
        // The resolver must mint a leaf for whatever SNI the ClientHello
        // carries — production izbad never passes the hostname explicitly.
        install_ring();
        let ca = IzbaCa::generate().unwrap();
        let ca_der = ca.cert_der();
        let server_cfg = server_config_with_resolver(Arc::new(CertCache::new(ca)));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let mut gcfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let (g, s) = duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let srv = tokio::spawn(async move {
            acceptor
                .accept(s)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = TlsConnector::from(Arc::new(gcfg));
        let name = ServerName::try_from("late.example.com").unwrap();
        // Hold the client stream open until the server has finished accepting,
        // else dropping it mid-final-flight breaks the server's handshake pipe.
        let _guest = conn
            .connect(name, g)
            .await
            .expect("handshake under izba CA via the SNI resolver");
        srv.await.unwrap().expect("server side accepted");
    }

    // --- LIFTED unit tests from OpenShell tls.rs (CA / cache / tls-sniff) ---

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
        assert_eq!(leaf.cert_chain.len(), 2); // leaf + CA
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

    #[test]
    fn looks_like_tls_detects_clienthello() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        assert!(looks_like_tls(&[0x16, 0x03, 0x03]));
        assert!(!looks_like_tls(b"GET / HTTP/1.1"));
        assert!(!looks_like_tls(&[0x16]));
        assert!(!looks_like_tls(&[0x17, 0x03, 0x03])); // app data, not handshake
    }
}
