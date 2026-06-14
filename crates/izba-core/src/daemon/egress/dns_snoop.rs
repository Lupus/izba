//! DNS-snoop store — the tier-2 (non-HTTP) unblock. The guest dials izbad with
//! an IP literal (`SO_ORIGINAL_DST`), never a name, so a domain allow-list is
//! meaningless until the name is recovered. izbad is BOTH resolver and dialer,
//! so it snoops the A/AAAA answers it returns into a per-sandbox `IP → {fqdn}`
//! map and looks the FQDN up at `TcpConnect` time.
//!
//! Honest trust model: DNS-snoop is a cooperative-agent / observability
//! boundary (mirrors Cilium toFQDNs + Azure Firewall). It is defeated by a
//! shared-CDN IP or a hostile in-guest actor that dials a raw IP — HARD
//! enforcement for HTTP(S) is the tier-1 MITM. The router pairs snoop with a
//! default-deny-on-no-record + an RFC1918 denylist (DNS-rebinding guard).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::RData;

/// Lower bound on a snoop entry's lifetime (a hostile-low TTL must not evict the
/// mapping before the guest can dial).
const TTL_FLOOR: Duration = Duration::from_secs(60);
/// Upper bound (Azure Firewall's documented 15-minute FQDN cache cap).
const TTL_CEIL: Duration = Duration::from_secs(15 * 60);

/// Normalize a wire name to an allow-list key: strip the root dot, lowercase.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Parse the A/AAAA answers of a DNS response into `(fqdn, ip, ttl_secs)`.
/// The fqdn is the QUERY name (what the user put on the allow-list), not the
/// CNAME-chain owner — so a flow to a CDN IP still matches the asked-for host.
/// A malformed/non-answer packet yields an empty vec (never an error).
pub fn extract_a_aaaa(resp: &[u8]) -> Vec<(String, IpAddr, u32)> {
    let Ok(msg) = Message::from_vec(resp) else {
        return Vec::new();
    };
    let qname = msg
        .queries()
        .first()
        .map(|q| normalize(&q.name().to_utf8()));
    let mut out = Vec::new();
    for rec in msg.answers() {
        let ip = match rec.data() {
            Some(RData::A(a)) => IpAddr::V4(a.0),
            Some(RData::AAAA(a)) => IpAddr::V6(a.0),
            _ => continue,
        };
        let fqdn = qname
            .clone()
            .unwrap_or_else(|| normalize(&rec.name().to_utf8()));
        out.push((fqdn, ip, rec.ttl()));
    }
    out
}

/// Does `fqdn` match any allow-list rule? Rules (mirroring Cilium toFQDNs):
/// - exact: `api.github.com`
/// - `*.github.com` — exactly ONE extra label (`api.github.com`, not `a.b...`)
/// - `**.github.com` — any depth (`a.b.github.com`); the apex itself never
///   matches a wildcard.
pub fn allowlist_matches(rules: &[String], fqdn: &str) -> bool {
    let fqdn = normalize(fqdn);
    rules.iter().any(|rule| {
        let rule = rule.trim().to_ascii_lowercase();
        if let Some(suffix) = rule.strip_prefix("**.") {
            // Any subdomain (≥1 label) of `suffix`.
            matches!(fqdn.strip_suffix(&suffix), Some(p) if p.ends_with('.') && p.len() > 1)
        } else if let Some(suffix) = rule.strip_prefix("*.") {
            // Exactly one label before `suffix`.
            match fqdn.strip_suffix(&suffix) {
                Some(p) => {
                    matches!(p.strip_suffix('.'), Some(l) if !l.is_empty() && !l.contains('.'))
                }
                None => false,
            }
        } else {
            rule == fqdn
        }
    })
}

struct FqdnEntry {
    fqdn: String,
    expiry: Instant,
}

/// Per-sandbox `IP → {fqdn, expiry}` snoop map. `Send + Sync` (one `Mutex`); the
/// egress manager shares one store across a sandbox's connection threads.
#[derive(Default)]
pub struct SnoopStore {
    // sandbox -> ip -> entries
    inner: Mutex<HashMap<String, HashMap<IpAddr, Vec<FqdnEntry>>>>,
}

impl SnoopStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record snoop entries (from [`extract_a_aaaa`]) for `sandbox`, clamping
    /// each TTL to `[60s, 15min]`.
    pub fn record(&self, sandbox: &str, entries: &[(String, IpAddr, u32)]) {
        self.record_at(sandbox, entries, Instant::now());
    }

    /// FQDNs known for `(sandbox, ip)` that have not expired.
    pub fn fqdns_for(&self, sandbox: &str, ip: IpAddr) -> Vec<String> {
        self.fqdns_for_at(sandbox, ip, Instant::now())
    }

    /// Drop every expired entry (background-sweep hook).
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    // --- clock-injected cores (testable without sleeping) ---

    fn record_at(&self, sandbox: &str, entries: &[(String, IpAddr, u32)], now: Instant) {
        if entries.is_empty() {
            return;
        }
        let mut g = self.inner.lock().expect("SnoopStore poisoned");
        let per_sandbox = g.entry(sandbox.to_string()).or_default();
        for (fqdn, ip, ttl) in entries {
            let ttl = Duration::from_secs(u64::from(*ttl)).clamp(TTL_FLOOR, TTL_CEIL);
            let expiry = now + ttl;
            let names = per_sandbox.entry(*ip).or_default();
            // Refresh an existing name's expiry rather than duplicate it.
            if let Some(e) = names.iter_mut().find(|e| e.fqdn == *fqdn) {
                e.expiry = expiry;
            } else {
                names.push(FqdnEntry {
                    fqdn: fqdn.clone(),
                    expiry,
                });
            }
        }
    }

    fn fqdns_for_at(&self, sandbox: &str, ip: IpAddr, now: Instant) -> Vec<String> {
        let g = self.inner.lock().expect("SnoopStore poisoned");
        g.get(sandbox)
            .and_then(|m| m.get(&ip))
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.expiry > now)
                    .map(|e| e.fqdn.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn sweep_at(&self, now: Instant) {
        let mut g = self.inner.lock().expect("SnoopStore poisoned");
        for per_sandbox in g.values_mut() {
            per_sandbox.retain(|_, entries| {
                entries.retain(|e| e.expiry > now);
                !entries.is_empty()
            });
        }
        g.retain(|_, m| !m.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn a_response(qname: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, Record, RecordType};

        let name = Name::from_str(qname).unwrap();
        let mut msg = Message::new();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(name, ttl, RData::A(A(ip))));
        msg.to_vec().unwrap()
    }

    #[test]
    fn extract_a_aaaa_from_response_bytes() {
        let bytes = a_response("api.anthropic.com.", Ipv4Addr::new(1, 2, 3, 4), 300);
        let got = extract_a_aaaa(&bytes);
        assert_eq!(
            got,
            vec![(
                "api.anthropic.com".to_string(),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                300
            )]
        );
        // Garbage parses to nothing, never panics.
        assert!(extract_a_aaaa(b"\x00\x01garbage").is_empty());
    }

    #[test]
    fn snoop_record_then_lookup_then_expire() {
        let store = SnoopStore::new();
        let base = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // TTL 30s is clamped UP to the 60s floor.
        store.record_at("web", &[("api.anthropic.com".into(), ip, 30)], base);

        assert_eq!(
            store.fqdns_for_at("web", ip, base + Duration::from_secs(30)),
            vec!["api.anthropic.com".to_string()],
            "present within the clamped TTL"
        );
        // Per-sandbox isolation: another sandbox sees nothing.
        assert!(store.fqdns_for_at("other", ip, base).is_empty());
        // Past the 60s floor it is gone.
        assert!(
            store
                .fqdns_for_at("web", ip, base + Duration::from_secs(61))
                .is_empty(),
            "expired after the clamped TTL"
        );
    }

    #[test]
    fn high_ttl_is_clamped_to_the_15min_ceiling() {
        let store = SnoopStore::new();
        let base = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        store.record_at("web", &[("dns.quad9.net".into(), ip, 86_400)], base);
        // Still alive at 14m...
        assert!(!store
            .fqdns_for_at("web", ip, base + Duration::from_secs(14 * 60))
            .is_empty());
        // ...gone just past 15m.
        assert!(store
            .fqdns_for_at("web", ip, base + Duration::from_secs(15 * 60 + 1))
            .is_empty());
    }

    #[test]
    fn sweep_drops_expired_entries() {
        let store = SnoopStore::new();
        let base = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        store.record_at("web", &[("one.one.one.one".into(), ip, 60)], base);
        store.sweep_at(base + Duration::from_secs(61));
        assert!(store.fqdns_for_at("web", ip, base).is_empty());
        // Map fully collapsed (no empty sandbox shells left behind).
        assert!(store.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn wildcard_match_one_label_and_deep() {
        let one = vec!["*.github.com".to_string()];
        assert!(allowlist_matches(&one, "api.github.com"));
        assert!(!allowlist_matches(&one, "a.b.github.com"));
        assert!(
            !allowlist_matches(&one, "github.com"),
            "apex not matched by *."
        );
        assert!(!allowlist_matches(&one, "notgithub.com"), "label boundary");

        let deep = vec!["**.github.com".to_string()];
        assert!(allowlist_matches(&deep, "a.b.github.com"));
        assert!(allowlist_matches(&deep, "api.github.com"));
        assert!(!allowlist_matches(&deep, "github.com"));

        let exact = vec!["api.anthropic.com".to_string()];
        assert!(allowlist_matches(&exact, "api.anthropic.com"));
        assert!(
            allowlist_matches(&exact, "API.Anthropic.COM."),
            "case + root dot"
        );
        assert!(!allowlist_matches(&exact, "evil.anthropic.com"));
    }
}
