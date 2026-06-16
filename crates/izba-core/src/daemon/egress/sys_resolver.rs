//! Terminating system DNS resolver with live config reload. Replaces the
//! start-time-captured `UdpForwarder`: re-reads host DNS config and self-heals
//! on network change (VPN reconnect) via lazy-on-failure + poll + if-watch.

use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver as HickoryResolver, TokioResolver};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::dns::Resolver;

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
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    Ok(resp.to_vec()?)
}

/// Header-only truncated response (TC=1, no answers) → the guest retries over
/// TCP:53 (routed to the same resolver). Used when a UDP answer would exceed
/// the 512-byte non-EDNS limit.
fn truncated_response(req: &Message) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = true;
    resp.metadata.response_code = ResponseCode::NoError;
    Ok(resp.to_vec()?)
}

/// Build a NOERROR response echoing the question and carrying `records` as the
/// answer section. Records come straight from hickory's `Lookup`, so no
/// per-RData destructuring is needed. If the encoded response would exceed the
/// 512-byte non-EDNS UDP limit, a TC=1 truncated response is returned instead
/// so the guest retries over TCP:53.
fn response_with_answers(req: &Message, records: &[Record]) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    for r in records {
        resp.add_answer(r.clone());
    }
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    let bytes = resp.to_vec()?;
    if bytes.len() > MAX_UDP_RESPONSE {
        return truncated_response(req);
    }
    Ok(bytes)
}

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

/// Non-EDNS UDP response size limit. The guest stub queries without an OPT RR
/// and we drop EDNS from responses, so the effective cap is the classic 512
/// bytes. Responses that would exceed this are returned as TC=1/no-answers so
/// the guest retries over TCP:53 (routed to the same resolver by `dns_loop`).
const MAX_UDP_RESPONSE: usize = 512;

const MIN_REBUILD_INTERVAL: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const IFWATCH_DEBOUNCE: Duration = Duration::from_secs(1);

pub struct SystemResolver {
    rt: tokio::runtime::Runtime,
    cell: Arc<ResolverCell>,
    caps: DnsCaps,
    source: Arc<dyn ConfigSource>,
    last_reload: Mutex<Instant>,
}

impl SystemResolver {
    /// Build the production system resolver and start its reload tasks.
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let source: Arc<dyn ConfigSource> = Arc::new(SystemConfigSource);

        // Initial build. A host with no DNS config is already broken; fall back
        // to 1.1.1.1 (mirrors the retired UdpForwarder), logged.
        let (config, opts) = source.discover().unwrap_or_else(|e| {
            eprintln!("izbad: no system DNS upstream found ({e:#}); falling back to 1.1.1.1");
            use hickory_resolver::config::CLOUDFLARE;
            let fallback =
                ResolverConfig::from_parts(None, vec![], CLOUDFLARE.udp_and_tcp().collect());
            (fallback, ResolverOpts::default())
        });
        let fp = fingerprint(&config);
        let resolver = {
            let _g = rt.enter();
            build_resolver(config, opts)?
        };
        let cell = Arc::new(ResolverCell::new(Arc::new(ResolverState {
            resolver,
            fingerprint: fp,
        })));

        let me = Arc::new(Self {
            rt,
            cell,
            caps: DnsCaps::v1(),
            source,
            last_reload: Mutex::new(Instant::now()),
        });
        me.spawn_reload_tasks();
        Ok(me)
    }

    fn spawn_reload_tasks(self: &Arc<Self>) {
        // L3: poll every 30s.
        let cell = Arc::clone(&self.cell);
        let source = Arc::clone(&self.source);
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            loop {
                tick.tick().await;
                if let Err(e) = reload_if_changed(&cell, &*source) {
                    eprintln!("izbad: dns poll reload failed: {e:#}");
                }
            }
        });

        // if-watch: proactive reload on interface/IP change (VPN reconnect).
        let cell = Arc::clone(&self.cell);
        let source = Arc::clone(&self.source);
        self.rt.spawn(async move {
            let mut watcher = match if_watch::tokio::IfWatcher::new() {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("izbad: if-watch unavailable ({e:#}); poll-only reload");
                    return;
                }
            };
            while let Some(ev) = watcher.next().await {
                if ev.is_err() {
                    continue;
                }
                // Debounce: VPN connect emits a burst; sleep then reload once.
                // fingerprint-dedupe makes any residual extra reload a no-op.
                tokio::time::sleep(IFWATCH_DEBOUNCE).await;
                if let Err(e) = reload_if_changed(&cell, &*source) {
                    eprintln!("izbad: dns event reload failed: {e:#}");
                }
            }
        });
    }

    /// Lazy reload-on-failure (Layer 2), rate-limited. Runs the apply path in a
    /// runtime context.
    fn try_reload_on_failure(&self) {
        {
            let mut last = self.last_reload.lock().unwrap();
            if last.elapsed() < MIN_REBUILD_INTERVAL {
                return;
            }
            *last = Instant::now();
        }
        let _g = self.rt.enter();
        if let Err(e) = reload_if_changed(&self.cell, &*self.source) {
            eprintln!("izbad: dns failure reload failed: {e:#}");
        }
    }

    fn lookup_once(
        &self,
        name: &hickory_proto::rr::Name,
        qtype: RecordType,
    ) -> Result<Vec<Record>, hickory_resolver::net::NetError> {
        let state = self.cell.load();
        self.rt
            .block_on(state.resolver.lookup(name.clone(), qtype))
            .map(|l| l.answers().to_vec())
    }

    fn resolve(
        &self,
        req: Message,
        name: hickory_proto::rr::Name,
        qtype: RecordType,
    ) -> anyhow::Result<Vec<u8>> {
        match self.lookup_once(&name, qtype) {
            Ok(records) => response_with_answers(&req, &records),
            Err(e) if e.is_nx_domain() => response_with_rcode(&req, ResponseCode::NXDomain),
            Err(e) if e.is_no_records_found() => response_with_rcode(&req, ResponseCode::NoError),
            Err(_transient) => {
                // Layer 2: the upstream may have moved (VPN reconnect). Rebuild
                // from current system config and retry exactly once.
                self.try_reload_on_failure();
                match self.lookup_once(&name, qtype) {
                    Ok(records) => response_with_answers(&req, &records),
                    Err(e) if e.is_nx_domain() => response_with_rcode(&req, ResponseCode::NXDomain),
                    Err(e) if e.is_no_records_found() => {
                        response_with_rcode(&req, ResponseCode::NoError)
                    }
                    Err(e) => anyhow::bail!("dns lookup failed after reload: {e}"),
                }
            }
        }
    }
}

impl Resolver for SystemResolver {
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match classify_query(query, &self.caps) {
            QueryDecision::Unparseable => anyhow::bail!("unparseable DNS query"),
            QueryDecision::Unsupported { req } => response_with_rcode(&req, ResponseCode::NotImp),
            QueryDecision::Answerable { req, name, qtype } => self.resolve(req, name, qtype),
        }
    }
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

    #[test]
    fn oversized_answer_is_truncated_for_tcp_retry() {
        use hickory_proto::rr::{rdata::A, RData, Record};
        let req = sample_query(0x55, RecordType::A);
        let name = Name::from_str("a-fairly-long-cdn-name.example.com.").unwrap();
        // Build 40 A records — enough to push the full response well past 512 bytes.
        let records: Vec<Record> = (0..40u32)
            .map(|i| {
                let ip = std::net::Ipv4Addr::new(203, 0, 113, (i & 0xff) as u8);
                Record::from_rdata(name.clone(), 30, RData::A(A(ip)))
            })
            .collect();

        // Sanity-check: the untruncated encoding must exceed 512 bytes, otherwise
        // the test would not exercise the truncation path.
        let mut full_resp = Message::new(0x55, MessageType::Response, OpCode::Query);
        full_resp.add_query(req.queries[0].clone());
        for r in &records {
            full_resp.add_answer(r.clone());
        }
        let full_bytes = full_resp.to_vec().unwrap();
        assert!(
            full_bytes.len() > MAX_UDP_RESPONSE,
            "pre-condition: full response must exceed 512 bytes (got {})",
            full_bytes.len()
        );

        let bytes = response_with_answers(&req, &records).unwrap();
        assert!(
            bytes.len() <= MAX_UDP_RESPONSE,
            "truncated response must fit 512 bytes: {}",
            bytes.len()
        );
        let resp = Message::from_vec(&bytes).unwrap();
        assert!(resp.truncation, "TC bit must be set");
        assert!(
            resp.answers.is_empty(),
            "answers must be dropped on truncation"
        );
        assert_eq!(resp.id, 0x55, "id must be echoed");
    }

    #[test]
    fn end_to_end_resolves_a_real_name() {
        if std::env::var("IZBA_INTEGRATION").is_err() {
            eprintln!("skipping: set IZBA_INTEGRATION=1 to run (needs network DNS)");
            return;
        }
        let r = SystemResolver::new().unwrap();
        let query = sample_query(0x4242, RecordType::A).to_vec().unwrap();
        let bytes = r.handle(&query).unwrap();
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.id, 0x4242);
        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert!(!resp.answers.is_empty(), "expected at least one A record");
    }
}
