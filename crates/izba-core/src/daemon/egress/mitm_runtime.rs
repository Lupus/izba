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
use tokio::net::{TcpListener, TcpStream};
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

impl MitmPolicy for PolicyAdapter {
    fn check(&self, req: &L7Request) -> L7Verdict {
        let flow = FlowDesc {
            sandbox: self.sandbox.clone(),
            addr: req.host.clone(),
            port: self.port,
            host: Some(req.host.clone()),
            method: Some(req.method.clone()),
            path: Some(req.path.clone()),
        };
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
            let adapter = PolicyAdapter {
                policy,
                audit,
                sandbox: dst.sandbox.clone(),
                ip: dst.ip,
                port: dst.port,
            };
            let dst_addr = (dst.ip, dst.port);
            let dial = || async move {
                TcpStream::connect(dst_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("dial upstream {dst_addr:?}: {e}"))
            };
            // Classify the guest's first bytes: a TLS ClientHello takes the TLS
            // terminate path; cleartext (e.g. apt's HTTP on :80) takes the
            // plaintext HTTP path. Routing by sniff, not by port, also handles
            // TLS-on-:80 / HTTP-on-:443 correctly. A peek that yields nothing
            // (closed/idle) defaults to non-TLS → the HTTP reader then reports a
            // clean "client closed" rather than a bogus TLS handshake error.
            let mut peek = [0u8; 8];
            let n = tcp.peek(&mut peek).await.unwrap_or(0);
            if mitm::looks_like_tls(&peek[..n]) {
                let _ = mitm::mitm_terminate(tcp, &state, &adapter, dial).await;
            } else {
                let _ = mitm::mitm_terminate_http(tcp, &adapter, dial).await;
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
}
