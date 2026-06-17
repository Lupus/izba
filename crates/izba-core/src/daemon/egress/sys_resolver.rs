//! Terminating system DNS resolver with live config reload. Replaces the
//! start-time-captured `UdpForwarder`: re-reads host DNS config and self-heals
//! on network change (VPN reconnect) via lazy-on-failure + poll + if-watch.

use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts, ServerOrderingStrategy};
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
    /// Unix: resolv.conf is authoritative and already in preference order.
    #[cfg(unix)]
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
        Ok(hickory_resolver::system_conf::read_system_conf()?)
    }

    /// Windows: hickory's `read_system_conf` enumerates adapter DNS servers in
    /// an order that does NOT match the OS resolver's interface-metric
    /// preference — with a VPN up it can pick a lower-priority physical NIC's
    /// resolver (e.g. a home router on metric 25) over the VPN's (metric 1),
    /// which both resolves the wrong split-horizon view AND can be a broken
    /// EDNS responder. We mirror Windows: order every connected adapter's DNS
    /// servers by interface metric (lowest = most preferred), drop unroutable
    /// site-local/link-local placeholders, and dedupe. Re-run on every reload
    /// so VPN connect/disconnect is tracked.
    ///
    /// Search/suffix domains are intentionally NOT carried (empty search list),
    /// unlike the Unix `read_system_conf` path: the `ipconfig` 0.3.4 crate
    /// exposes no per-adapter DNS-suffix accessor (only `dns_servers()`), so
    /// reading a VPN's split-DNS suffix would mean hand-rolling
    /// `GetAdaptersAddresses` FFI. Resolving VPN-internal names is a documented
    /// deferred non-goal, and the guest's resolv.conf carries no search list
    /// either (so the guest never sends short names expecting expansion);
    /// fully-qualified internal names still resolve via the metric-selected VPN
    /// resolver above. Revisit if short-name expansion becomes a requirement.
    #[cfg(windows)]
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
        use hickory_resolver::config::NameServerConfig;
        let adapters = ipconfig::get_adapters()?;
        let mut candidates = Vec::new();
        for a in &adapters {
            if a.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
                continue;
            }
            for ip in a.dns_servers() {
                // Per-server family metric, mirroring how Windows scopes route
                // preference (Ipv4Metric for v4 resolvers, Ipv6Metric for v6).
                let metric = if ip.is_ipv4() {
                    a.ipv4_metric()
                } else {
                    a.ipv6_metric()
                };
                candidates.push(Candidate { metric, ip: *ip });
            }
        }
        let ordered = order_upstreams(candidates);
        if ordered.is_empty() {
            anyhow::bail!("no usable system DNS servers discovered");
        }
        let name_servers = ordered
            .into_iter()
            .map(NameServerConfig::udp_and_tcp)
            .collect();
        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        Ok((config, ResolverOpts::default()))
    }
}

/// One candidate upstream: a DNS server IP plus the routing metric of the
/// interface that advertised it (lower = more preferred, mirroring Windows).
#[cfg(any(windows, test))]
#[derive(Clone, Debug)]
struct Candidate {
    metric: u32,
    ip: std::net::IpAddr,
}

/// Order DNS upstreams the way the Windows resolver prefers them: ascending
/// interface metric, dropping unroutable placeholders, deduped preserving
/// first-seen (lowest-metric) order. Pure, so it is unit-tested without the
/// Windows adapter APIs. `sort_by_key` is stable, so equal-metric servers keep
/// the adapter-enumeration order they arrived in.
#[cfg(any(windows, test))]
fn order_upstreams(mut candidates: Vec<Candidate>) -> Vec<std::net::IpAddr> {
    candidates.sort_by_key(|c| c.metric);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for c in candidates {
        if is_usable_resolver(c.ip) && seen.insert(c.ip) {
            out.push(c.ip);
        }
    }
    out
}

/// Reject DNS-server addresses that cannot be a real upstream: unspecified,
/// loopback, IPv4 link-local (169.254/16), IPv6 link-local (fe80::/10) and
/// IPv6 site-local (fec0::/10 — the deprecated Windows placeholders such as
/// `fec0:0:0:ffff::1` that adapters like Tailscale advertise when they have no
/// real IPv6 resolver).
#[cfg(any(windows, test))]
fn is_usable_resolver(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            let lead = v6.segments()[0];
            let is_link_local = (lead & 0xffc0) == 0xfe80;
            let is_site_local = (lead & 0xffc0) == 0xfec0;
            !v6.is_unspecified() && !v6.is_loopback() && !is_link_local && !is_site_local
        }
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

/// Harden the resolver options so the resolver behaves like the OS stub
/// resolver and never second-guesses the upstream order we hand it.
///
/// 1. **Plain DNS (no EDNS/OPT).** Some real-world resolvers — notably consumer
///    routers — answer an EDNS query with a miscounted section header: they
///    echo an OPT record but report it in the authority count (NSCOUNT) with
///    ARCOUNT=0, so the OPT lands outside the ADDITIONAL section. hickory-proto
///    strictly rejects that (`RecordNotInAdditionalSection(OPT)`), turning every
///    lookup into SERVFAIL. We gain nothing from EDNS here: answers are
///    re-encoded to the classic 512-byte non-EDNS form anyway
///    (`response_with_answers`), and anything that overflows 512 bytes falls
///    back to TCP (`try_tcp_on_error`, on by default).
///
/// 2. **Honor our upstream order, sequentially.** `discover()` hands hickory a
///    deliberately preference-ordered upstream list (on Windows, ordered by
///    interface metric so the VPN's resolver precedes a LAN/physical NIC's). But
///    hickory's *defaults* discard that: `QueryStatistics` re-ranks servers by
///    observed RTT and `num_concurrent_reqs = 2` races the top two. When a
///    corporate VPN is active its DNS enforcement is split-horizon — only the
///    VPN's own resolver may answer; a query that escapes to any other (LAN or
///    public) resolver is blocked and comes back as an instant NXDOMAIN. A
///    deprioritized LAN resolver sitting on the local segment answers in well
///    under a millisecond, so that policy-injected NXDOMAIN out-races the
///    correct-but-slower VPN resolver across the tunnel and the guest sees it —
///    intermittently, per name, exactly as a race predicts. (This is also why
///    the OS resolver uses *only* the metric-1 VPN servers, and why other LAN
///    devices not on the VPN resolve fine against the same router.) Mirror the
///    OS resolver: `UserProvidedOrder` keeps our order verbatim, and
///    `num_concurrent_reqs = 1` queries one server at a time, advancing to the
///    next only on transient failure (never on a valid negative answer). A
///    deprioritized resolver is thus consulted only when every preferred one is
///    unreachable.
///
/// Centralized so the initial build, the 1.1.1.1 fallback, and every reload all
/// share these semantics.
fn harden_opts(mut opts: ResolverOpts) -> ResolverOpts {
    opts.edns0 = false;
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    opts.num_concurrent_reqs = 1;
    opts
}

/// Build a Tokio resolver from explicit config. MUST be called inside a tokio
/// runtime context (the connection provider uses `Handle::current()`).
fn build_resolver(config: ResolverConfig, opts: ResolverOpts) -> anyhow::Result<TokioResolver> {
    Ok(
        HickoryResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(harden_opts(opts))
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

    #[test]
    fn harden_opts_disables_upstream_edns() {
        let mut o = ResolverOpts::default();
        o.edns0 = true;
        assert!(
            !harden_opts(o).edns0,
            "upstream queries must not carry EDNS/OPT"
        );
    }

    /// Root-cause regression for the "metric ordering ignored at runtime" bug.
    /// `discover()` hands hickory a preference-ordered upstream list (VPN before
    /// a LAN resolver), but hickory's *default* opts override it at query time:
    /// `QueryStatistics` re-ranks by observed RTT and `num_concurrent_reqs = 2`
    /// races the top two, so a fast LAN resolver — whose answer corporate-VPN
    /// DNS enforcement turns into an instant NXDOMAIN — out-races the correct VPN
    /// resolver and the guest sees NXDOMAIN. `harden_opts` must pin the
    /// OS-resolver semantics.
    #[test]
    fn harden_opts_forces_ordered_sequential_upstreams() {
        let mut o = ResolverOpts::default();
        o.server_ordering_strategy = ServerOrderingStrategy::QueryStatistics;
        o.num_concurrent_reqs = 2;
        let h = harden_opts(o);
        assert_eq!(
            h.server_ordering_strategy,
            ServerOrderingStrategy::UserProvidedOrder,
            "must honor our metric-ordered upstream list, not re-rank by RTT"
        );
        assert_eq!(
            h.num_concurrent_reqs, 1,
            "query upstreams strictly in order; never race a deprioritized server"
        );
    }

    #[test]
    fn upstreams_ordered_by_metric_vpn_before_router() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        // The live izba-test host: GlobalProtect VPN on metric 1, home router
        // on metric 25, a Tailscale fec0:: site-local placeholder on metric 5.
        let vpn1: IpAddr = Ipv4Addr::new(10, 64, 139, 51).into();
        let vpn2: IpAddr = Ipv4Addr::new(10, 21, 231, 4).into();
        let router: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let placeholder: IpAddr = Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1).into();
        let ordered = order_upstreams(vec![
            Candidate {
                metric: 25,
                ip: router,
            },
            Candidate {
                metric: 5,
                ip: placeholder,
            },
            Candidate {
                metric: 1,
                ip: vpn1,
            },
            Candidate {
                metric: 1,
                ip: vpn2,
            },
            Candidate {
                metric: 1,
                ip: vpn1,
            }, // duplicate across adapters
        ]);
        assert_eq!(
            ordered,
            vec![vpn1, vpn2, router],
            "VPN (metric 1) before router (25); fec0:: placeholder dropped; deduped"
        );
    }

    #[test]
    fn unusable_resolver_addresses_are_rejected() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(is_usable_resolver(Ipv4Addr::new(10, 64, 139, 51).into()));
        assert!(is_usable_resolver(Ipv4Addr::new(192, 168, 1, 1).into()));
        assert!(is_usable_resolver(
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).into()
        ));
        assert!(!is_usable_resolver(Ipv4Addr::UNSPECIFIED.into()));
        assert!(!is_usable_resolver(Ipv4Addr::LOCALHOST.into()));
        assert!(!is_usable_resolver(Ipv4Addr::new(169, 254, 1, 1).into()));
        assert!(!is_usable_resolver(
            Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1).into()
        ));
        assert!(!is_usable_resolver(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into()
        ));
        assert!(!is_usable_resolver(Ipv6Addr::LOCALHOST.into()));
    }

    /// Root-cause regression. A consumer router answers an EDNS query with an
    /// OPT record but reports NSCOUNT=1/ARCOUNT=0, so the OPT lands in the
    /// AUTHORITY section — hickory rejects it and we SERVFAIL. The same name
    /// without a client OPT comes back honestly counted and parses fine, which
    /// is exactly why disabling upstream EDNS (`harden_opts`) fixes it.
    #[test]
    fn miscounted_opt_in_authority_section_is_what_breaks_decode() {
        // Header: QD=1 AN=0 NS=1 AR=0, then question, then a misplaced OPT RR
        // (counted as the single authority record).
        let malformed: &[u8] = &[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // header
            0x06, b'n', b'v', b'i', b'd', b'i', b'a', 0x03, b'c', b'o', b'm',
            0x00, // nvidia.com
            0x00, 0x01, 0x00, 0x01, // QTYPE=A QCLASS=IN
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OPT RR
        ];
        let err =
            Message::from_vec(malformed).expect_err("strict decode must reject misplaced OPT");
        // hickory-proto 0.26.1 surfaces this as
        // `DecodeError::RecordNotInAdditionalSection(OPT)`; we match its Display
        // wording rather than the variant because the kind is buried under
        // `ProtoErrorKind` and hickory's own tests string-match it too
        // (see hickory-proto `op/message.rs`). Revisit on a hickory-proto bump.
        assert!(
            err.to_string().contains("OPT only allowed in additional"),
            "unexpected error: {err}"
        );

        // Same NXDOMAIN answer with no OPT (non-EDNS) → honest counts → parses.
        let clean: &[u8] = &[
            0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // AN=0 NS=0 AR=0
            0x06, b'n', b'v', b'i', b'd', b'i', b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
            0x00, 0x01,
        ];
        assert!(
            Message::from_vec(clean).is_ok(),
            "non-EDNS response must parse cleanly"
        );
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
