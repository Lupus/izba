//! Terminating system DNS resolver with live config reload. Replaces the
//! start-time-captured `UdpForwarder`: re-reads host DNS config and self-heals
//! on network change (VPN reconnect) via lazy-on-failure + poll + if-watch.
// The public types/functions here will be consumed by Task 7 (SystemResolver
// struct). Suppress dead_code until that task is implemented.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};

/// The query types the guest is allowed to resolve. Terminating resolution
/// gives us this control point; v1 hardcodes a sane set.
// TODO(policy): make per-sandbox DNS caps policy-driven (M-future).
pub(crate) struct DnsCaps {
    allowed: &'static [RecordType],
}

impl DnsCaps {
    pub(crate) const fn v1() -> Self {
        Self {
            allowed: &[
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::TXT,
                RecordType::SRV,
                RecordType::PTR,
                RecordType::NS,
                RecordType::SOA,
                RecordType::CAA,
            ],
        }
    }

    pub(crate) fn permits(&self, qtype: RecordType) -> bool {
        self.allowed.contains(&qtype)
    }
}

/// Build a response that echoes the request's id + question with the given
/// rcode and no answers (NOTIMP / NXDOMAIN / NODATA).
fn response_with_rcode(req: &Message, rcode: ResponseCode) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    Ok(resp.to_vec()?)
}

/// Build a NOERROR response echoing the question and carrying `records` as the
/// answer section. Records come straight from hickory's `Lookup`, so no
/// per-RData destructuring is needed.
fn response_with_answers(req: &Message, records: &[Record]) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    for r in records {
        resp.add_answer(r.clone());
    }
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    Ok(resp.to_vec()?)
}

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::hash::{Hash, Hasher};

/// Source of host DNS config. Seam so reload logic is testable without network.
pub(crate) trait ConfigSource: Send + Sync {
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)>;
}

/// Production: read the host's system DNS config (resolv.conf on unix; adapter
/// DNS servers via the `ipconfig` crate on Windows — picks up the live VPN).
pub(crate) struct SystemConfigSource;

impl ConfigSource for SystemConfigSource {
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
        Ok(hickory_resolver::system_conf::read_system_conf()?)
    }
}

/// Stable hash of the parts of a resolver config that affect reachability
/// (nameservers + search). Hashing the Debug rendering dodges per-field getter
/// drift across hickory versions while still flipping on any server change.
fn fingerprint(config: &ResolverConfig) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    format!("{config:?}").hash(&mut h);
    h.finish()
}

use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver as HickoryResolver, TokioResolver};
use std::sync::{Arc, Mutex};

/// Live resolver + the fingerprint of the config it was built from.
struct ResolverState {
    resolver: TokioResolver,
    fingerprint: u64,
}

/// Swappable holder for the live resolver. Mirrors `PolicyCell`: the lock is
/// held only for an `Arc` clone/replace, never across I/O, so a plain `Mutex`
/// is contention-free. In-flight lookups keep the `Arc` they cloned; a reload
/// takes effect on the next query.
struct ResolverCell {
    inner: Mutex<Arc<ResolverState>>,
}

impl ResolverCell {
    fn new(state: Arc<ResolverState>) -> Self {
        Self {
            inner: Mutex::new(state),
        }
    }
    fn load(&self) -> Arc<ResolverState> {
        Arc::clone(&self.inner.lock().unwrap())
    }
    fn store(&self, state: Arc<ResolverState>) {
        *self.inner.lock().unwrap() = state;
    }
}

/// Build a Tokio resolver from explicit config. MUST be called inside a tokio
/// runtime context (the connection provider uses `Handle::current()`).
fn build_resolver(config: ResolverConfig, opts: ResolverOpts) -> anyhow::Result<TokioResolver> {
    Ok(
        HickoryResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()?,
    )
}

/// Re-read system DNS config; if the fingerprint changed, rebuild the resolver
/// and swap the cell. Returns whether a swap happened. MUST run inside a tokio
/// runtime context (for `build_resolver`).
fn reload_if_changed(cell: &ResolverCell, source: &dyn ConfigSource) -> anyhow::Result<bool> {
    let (config, opts) = source.discover()?;
    let fp = fingerprint(&config);
    if cell.load().fingerprint == fp {
        return Ok(false); // dedupe: no change
    }
    let resolver = build_resolver(config, opts)?;
    cell.store(Arc::new(ResolverState {
        resolver,
        fingerprint: fp,
    }));
    Ok(true)
}

/// Pure front-half of `handle`: parse + capability-gate, with no network. The
/// network back-half consumes `Answerable`.
enum QueryDecision {
    /// Query bytes did not parse → caller returns Err → SERVFAIL at `dns_loop`.
    Unparseable,
    /// Parsed, but the qtype is not permitted → synthesize NOTIMP.
    Unsupported { req: Message },
    /// Parsed and permitted → resolve `name`/`qtype`.
    Answerable {
        req: Message,
        name: hickory_proto::rr::Name,
        qtype: RecordType,
    },
}

fn classify_query(query: &[u8], caps: &DnsCaps) -> QueryDecision {
    let req = match Message::from_vec(query) {
        Ok(m) => m,
        Err(_) => return QueryDecision::Unparseable,
    };
    let Some(q) = req.queries.first() else {
        return QueryDecision::Unparseable; // no question section → SERVFAIL
    };
    let qtype = q.query_type();
    let name = q.name().clone();
    if !caps.permits(qtype) {
        return QueryDecision::Unsupported { req };
    }
    QueryDecision::Answerable { req, name, qtype }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use hickory_resolver::config::{NameServerConfig, ResolverConfig as RC, ResolverOpts};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn config_with(ip: [u8; 4]) -> RC {
        RC::from_parts(
            None,
            vec![],
            vec![NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::from(
                ip,
            )))],
        )
    }

    fn sample_query(id: u16, qtype: RecordType) -> Message {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(Name::from_str("example.com.").unwrap());
        q.set_query_type(qtype);
        m.add_query(q);
        m
    }

    #[test]
    fn v1_caps_permit_common_types_and_reject_dangerous_ones() {
        let caps = DnsCaps::v1();
        assert!(caps.permits(RecordType::A));
        assert!(caps.permits(RecordType::AAAA));
        assert!(caps.permits(RecordType::SRV));
        assert!(!caps.permits(RecordType::ANY));
        assert!(!caps.permits(RecordType::AXFR));
    }

    #[test]
    fn rcode_response_echoes_id_and_question() {
        let req = sample_query(0x1234, RecordType::A);
        let bytes = response_with_rcode(&req, ResponseCode::NotImp).unwrap();
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.message_type, MessageType::Response);
        assert_eq!(resp.response_code, ResponseCode::NotImp);
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.queries[0].query_type(), RecordType::A);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn fingerprint_is_stable_and_change_sensitive() {
        let a = config_with([10, 0, 0, 2]);
        let a2 = config_with([10, 0, 0, 2]);
        let b = config_with([8, 8, 8, 8]);
        assert_eq!(fingerprint(&a), fingerprint(&a2));
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    struct FakeSource {
        ip: std::sync::atomic::AtomicU8,
    }
    impl ConfigSource for FakeSource {
        fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
            let n = self.ip.load(std::sync::atomic::Ordering::SeqCst);
            Ok((config_with([10, 0, 0, n]), ResolverOpts::default()))
        }
    }

    #[test]
    fn reload_swaps_only_on_config_change() {
        // Building a resolver needs a runtime context but does NO network I/O
        // (sockets are created lazily on first query). Safe in sandbox.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let src = FakeSource {
            ip: std::sync::atomic::AtomicU8::new(2),
        };
        let (cfg, opts) = src.discover().unwrap();
        let cell = ResolverCell::new(Arc::new(ResolverState {
            resolver: build_resolver(cfg.clone(), opts).unwrap(),
            fingerprint: fingerprint(&cfg),
        }));

        // Same config → no swap.
        assert!(!reload_if_changed(&cell, &src).unwrap());
        // Change the upstream → swap.
        src.ip.store(8, std::sync::atomic::Ordering::SeqCst);
        assert!(reload_if_changed(&cell, &src).unwrap());
        // Idempotent at the new config.
        assert!(!reload_if_changed(&cell, &src).unwrap());
    }

    #[test]
    fn classify_rejects_garbage() {
        assert!(matches!(
            classify_query(&[0xff, 0x00, 0x01], &DnsCaps::v1()),
            QueryDecision::Unparseable
        ));
    }

    #[test]
    fn classify_permits_allowed_qtype() {
        let bytes = sample_query(1, RecordType::A).to_vec().unwrap();
        match classify_query(&bytes, &DnsCaps::v1()) {
            QueryDecision::Answerable { qtype, name, .. } => {
                assert_eq!(qtype, RecordType::A);
                assert_eq!(name, Name::from_str("example.com.").unwrap());
            }
            _ => panic!("expected Answerable"),
        }
    }

    #[test]
    fn classify_marks_disallowed_qtype_unsupported() {
        let bytes = sample_query(1, RecordType::ANY).to_vec().unwrap();
        match classify_query(&bytes, &DnsCaps::v1()) {
            QueryDecision::Unsupported { req } => {
                let notimp = response_with_rcode(&req, ResponseCode::NotImp).unwrap();
                let resp = Message::from_vec(&notimp).unwrap();
                assert_eq!(resp.response_code, ResponseCode::NotImp);
            }
            _ => panic!("expected Unsupported"),
        }
    }
}
