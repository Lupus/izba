// SPDX-License-Identifier: Apache-2.0
//! The MITM tokio runtime + the loopback-hop bridge from the blocking egress
//! plane (the M2 design's Option A).
//!
//! `router::tcp_connect` (blocking) registers `(loopback_src_port -> OrigDst)`
//! in the [`DstMap`], dials this runtime's loopback listener, and splices the
//! vsock leg with the *unchanged* blocking `portfwd::pump_bidirectional` — so
//! the OpenVMM churn-teardown invariant is untouched. This runtime accepts the
//! loopback TCP, recovers the `OrigDst` by source port, terminates the guest
//! TLS (per-SNI leaf under the izba CA), runs the egress [`Policy`], and
//! re-originates TLS to the real upstream.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustls::ClientConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::audit::{AuditRecord, AuditSink, Tier};
use super::mitm::{
    self, server_config_with_resolver, CertCache, L7Request, L7Verdict, MitmPolicy, MitmState,
};
use super::policy::{FlowDesc, Policy, Verdict};

/// How long an unclaimed `DstMap` entry lives before the sweep reclaims it
/// (a connection that registered but never reached the accept handler).
const DST_TTL: Duration = Duration::from_secs(30);

/// The original destination izbad knows from the guest's `TcpConnect` frame,
/// recovered by the MITM handler via the loopback source port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrigDst {
    pub ip: IpAddr,
    pub port: u16,
    pub sandbox: String,
}

/// What the router hands the MITM runtime per flow: the original destination
/// plus the per-sandbox policy to apply (the runtime is shared across sandboxes,
/// so the policy travels with the flow rather than living on the runtime).
struct DstEntry {
    dst: OrigDst,
    policy: Arc<dyn Policy>,
    at: Instant,
}

/// Rendezvous between the blocking router and the MITM runtime, keyed by the
/// loopback source port (unique per live connection). The router inserts before
/// connecting; the handler claims (removes) on accept; a TTL sweep guards leaks.
#[derive(Clone, Default)]
pub struct DstMap {
    inner: Arc<Mutex<HashMap<u16, DstEntry>>>,
}

impl DstMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, src_port: u16, dst: OrigDst, policy: Arc<dyn Policy>) {
        self.inner.lock().expect("DstMap poisoned").insert(
            src_port,
            DstEntry {
                dst,
                policy,
                at: Instant::now(),
            },
        );
    }

    /// Claim (remove) the dst + policy for a source port; `None` if unknown or
    /// swept.
    pub fn claim(&self, src_port: u16) -> Option<(OrigDst, Arc<dyn Policy>)> {
        self.inner
            .lock()
            .expect("DstMap poisoned")
            .remove(&src_port)
            .map(|e| (e.dst, e.policy))
    }

    /// Drop entries older than `max_age`.
    pub fn expire_older_than(&self, max_age: Duration) {
        let now = Instant::now();
        self.inner
            .lock()
            .expect("DstMap poisoned")
            .retain(|_, e| now.duration_since(e.at) < max_age);
    }
}

/// Bridges the egress [`Policy`] (`FlowDesc`) into the MITM datapath's
/// [`MitmPolicy`] (`L7Request`) for one connection, closing over the `OrigDst`
/// the router supplied (sandbox + ip + port the L7 view lacks). Records the
/// tier-1 decision to the audit sink — the MITM path's "see every connection".
struct PolicyAdapter {
    policy: Arc<dyn Policy>,
    audit: AuditSink,
    sandbox: String,
    ip: IpAddr,
    port: u16,
}

impl PolicyAdapter {
    /// Test-only constructor: builds a `PolicyAdapter` with an `AllowAll` policy
    /// and a discard `AuditSink` writing to a temp directory.
    #[cfg(test)]
    pub(crate) fn test_new(sandbox: &str, ip: IpAddr, port: u16) -> Self {
        use crate::daemon::egress::policy::AllowAll;
        use crate::paths::Paths;
        let audit = AuditSink::new(Paths::with_root(
            std::env::temp_dir().join("izba-mitm-runtime-test"),
        ));
        Self {
            policy: Arc::new(AllowAll),
            audit,
            sandbox: sandbox.into(),
            ip,
            port,
        }
    }

    pub(crate) fn flow_for(&self, req: &L7Request) -> FlowDesc {
        FlowDesc {
            sandbox: self.sandbox.clone(),
            addr: req.host.clone(),
            port: self.port,
            host: Some(req.host.clone()),
            method: Some(req.method.clone()),
            path: Some(req.path.clone()),
            query: req.query.clone(),
        }
    }
}

impl MitmPolicy for PolicyAdapter {
    fn check(&self, req: &L7Request) -> L7Verdict {
        let flow = self.flow_for(req);
        let verdict = self.policy.check(&flow);
        let rule = match verdict {
            Verdict::Allow => "allow-list",
            Verdict::Deny => "not in allow-list",
        };
        self.audit.record(AuditRecord::from_flow(
            verdict,
            &flow,
            self.ip,
            Tier::L7,
            rule,
        ));
        match verdict {
            Verdict::Allow => L7Verdict::Allow,
            Verdict::Deny => L7Verdict::Deny("403 Forbidden by izba egress policy\n"),
        }
    }

    fn record_deny(&self, req: &L7Request, rule: &'static str) {
        let flow = self.flow_for(req);
        self.audit.record(AuditRecord::from_flow(
            Verdict::Deny,
            &flow,
            self.ip,
            Tier::L7,
            rule,
        ));
    }
}

/// Owns the MITM tokio runtime + its loopback listener. Cheap to share the
/// `DstMap` with the blocking router via [`MitmRuntime::dsts`].
pub struct MitmRuntime {
    _rt: tokio::runtime::Runtime,
    listen: SocketAddr,
    dsts: DstMap,
}

impl MitmRuntime {
    /// Start a multi-thread tokio runtime, bind `127.0.0.1:0`, and serve the
    /// MITM accept loop. `certs` signs per-SNI leaves under the izba CA;
    /// `upstream` verifies the real upstream; `audit` logs every decision. The
    /// per-flow policy travels with each registered flow (the runtime is shared
    /// across sandboxes), so it is not a start-time parameter.
    pub fn start(
        certs: Arc<CertCache>,
        upstream: Arc<ClientConfig>,
        audit: AuditSink,
    ) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .context("build MITM tokio runtime")?;

        let dsts = DstMap::new();
        let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(certs)));

        // Bind synchronously so the loopback port is known before we return.
        let listener = rt
            .block_on(async { TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await })
            .context("bind MITM loopback listener")?;
        let listen = listener.local_addr().context("MITM listener addr")?;

        let dsts_loop = dsts.clone();
        let dsts_sweep = dsts.clone();
        rt.spawn(async move { accept_loop(listener, acceptor, upstream, audit, dsts_loop).await });
        rt.spawn(async move {
            let mut tick = tokio::time::interval(DST_TTL);
            loop {
                tick.tick().await;
                dsts_sweep.expire_older_than(DST_TTL);
            }
        });

        Ok(Self {
            _rt: rt,
            listen,
            dsts,
        })
    }

    /// The loopback address the blocking router dials.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    /// Register the dst + its per-sandbox policy for a loopback source port,
    /// before the router connects.
    pub fn register(&self, src_port: u16, dst: OrigDst, policy: Arc<dyn Policy>) {
        self.dsts.insert(src_port, dst, policy);
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Arc<ClientConfig>,
    audit: AuditSink,
    dsts: DstMap,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        // Recover what izbad knew about this flow by the loopback source port.
        let Some((dst, policy)) = dsts.claim(peer.port()) else {
            // Unknown source port: not a flow we registered — drop it.
            continue;
        };
        let acceptor = acceptor.clone();
        let upstream = Arc::clone(&upstream);
        let policy = Arc::clone(&policy);
        let audit = audit.clone();
        tokio::spawn(async move {
            let state = MitmState { acceptor, upstream };
            let adapter: Arc<dyn MitmPolicy> = Arc::new(PolicyAdapter {
                policy,
                audit,
                sandbox: dst.sandbox.clone(),
                ip: dst.ip,
                port: dst.port,
            });
            // Classify TLS vs cleartext by PEEKING the first wire bytes
            // (`TcpStream::peek` — does not consume them), not by the destination
            // port. This is robust regardless of port: HTTPS may arrive on a
            // non-443 port the router forwards, and the in-runtime tests dial an
            // ephemeral upstream. A TLS ClientHello is terminated under the izba
            // CA (SNI captured from the handshake); anything else is served as
            // cleartext HTTP. No buffering/Rewind adapter — peek leaves the bytes
            // in the socket for the acceptor / h1 server to re-read.
            let mut hdr = [0u8; 5];
            let n = tcp.peek(&mut hdr).await.unwrap_or(0);
            if mitm::looks_like_tls(&hdr[..n]) {
                match state.acceptor.accept(tcp).await {
                    Ok(tls) => {
                        let sni = tls.get_ref().1.server_name().map(str::to_string);
                        let _ = mitm::serve_mitm(tls, sni, &state, adapter, dst.clone()).await;
                    }
                    Err(_) => {
                        // Audited fail-closed: a TLS-looking handshake that fails
                        // (e.g. no SNI ⇒ no leaf) never reaches an upstream.
                    }
                }
            } else {
                let _ = mitm::serve_mitm(tcp, None, &state, adapter, dst.clone()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::AllowAll;

    fn dst(ip: &str, port: u16, sandbox: &str) -> OrigDst {
        OrigDst {
            ip: ip.parse().unwrap(),
            port,
            sandbox: sandbox.into(),
        }
    }

    fn pol() -> Arc<dyn Policy> {
        Arc::new(AllowAll)
    }

    #[test]
    fn dstmap_claims_once_and_expires() {
        let map = DstMap::new();
        map.insert(40001, dst("1.2.3.4", 443, "web"), pol());
        assert_eq!(
            map.claim(40001).map(|(d, _)| d),
            Some(dst("1.2.3.4", 443, "web"))
        );
        assert!(map.claim(40001).is_none(), "second claim must be empty");

        map.insert(40002, dst("5.6.7.8", 443, "web"), pol());
        map.expire_older_than(Duration::ZERO); // everything is stale vs zero age
        assert!(map.claim(40002).is_none(), "expired entry must be gone");
    }

    #[test]
    fn dstmap_unknown_port_is_none() {
        let map = DstMap::new();
        assert!(map.claim(12345).is_none());
    }

    #[test]
    fn flow_for_threads_query_into_flowdesc() {
        let adapter = PolicyAdapter::test_new("web", "203.0.113.5".parse().unwrap(), 443);
        let req = L7Request {
            host: "github.com".into(),
            method: "GET".into(),
            path: "/o/a/info/refs".into(),
            query: Some("service=git-receive-pack".into()),
        };
        let flow = adapter.flow_for(&req);
        assert_eq!(flow.query.as_deref(), Some("service=git-receive-pack"));
        assert_eq!(flow.host.as_deref(), Some("github.com"));
    }
}
