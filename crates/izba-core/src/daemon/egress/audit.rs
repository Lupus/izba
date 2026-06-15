//! Structured per-flow egress audit log. Every TCP egress decision (tier-1
//! MITM HTTP(S) and tier-2 non-HTTP) appends one JSON line to the sandbox's
//! `logs/egress-audit.jsonl`, the data behind `izba netlog` ("see every
//! connection"). The record is a pure value (host-testable, no clock); the
//! [`AuditSink`] stamps the wall-clock time and does the append.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::policy::{FlowDesc, Verdict};
use crate::paths::Paths;

/// Which enforcement tier produced the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Tier-1: HTTP(S) terminated by the MITM, decided on the decrypted Host.
    L7,
    /// Tier-2: non-HTTP TCP, decided on the DNS-snoop FQDN (or raw IP).
    L3,
}

/// One audit line. Field order is the on-disk JSON order. `ts_ms` is 0 until
/// the [`AuditSink`] stamps it at write time (keeps the value pure/testable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts_ms: u64,
    pub sandbox: String,
    pub dest_ip: IpAddr,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub tier: Tier,
    pub verdict: Verdict,
    pub rule: String,
}

impl AuditRecord {
    fn base(
        verdict: Verdict,
        sandbox: impl Into<String>,
        dest_ip: IpAddr,
        port: u16,
        host: Option<&str>,
        tier: Tier,
        rule: impl Into<String>,
    ) -> Self {
        Self {
            ts_ms: 0,
            sandbox: sandbox.into(),
            dest_ip,
            port,
            host: host.map(str::to_string),
            method: None,
            path: None,
            tier,
            verdict,
            rule: rule.into(),
        }
    }

    /// An allow record (time stamped by the sink at write).
    pub fn allow(
        sandbox: impl Into<String>,
        dest_ip: IpAddr,
        port: u16,
        host: Option<&str>,
        tier: Tier,
        rule: impl Into<String>,
    ) -> Self {
        Self::base(Verdict::Allow, sandbox, dest_ip, port, host, tier, rule)
    }

    /// A deny record (time stamped by the sink at write).
    pub fn deny(
        sandbox: impl Into<String>,
        dest_ip: IpAddr,
        port: u16,
        host: Option<&str>,
        tier: Tier,
        rule: impl Into<String>,
    ) -> Self {
        Self::base(Verdict::Deny, sandbox, dest_ip, port, host, tier, rule)
    }

    /// Attach the tier-1 HTTP method + path (the MITM path has them).
    pub fn with_request(mut self, method: impl Into<String>, path: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self.path = Some(path.into());
        self
    }

    /// From a verdict + the flow the policy evaluated. `dest_ip` is the literal
    /// the guest dialed; `tier`/`rule` are the caller's.
    pub fn from_flow(
        verdict: Verdict,
        flow: &FlowDesc,
        dest_ip: IpAddr,
        tier: Tier,
        rule: impl Into<String>,
    ) -> Self {
        let mut r = Self::base(
            verdict,
            flow.sandbox.clone(),
            dest_ip,
            flow.port,
            flow.host.as_deref(),
            tier,
            rule,
        );
        r.method = flow.method.clone();
        r.path = flow.path.clone();
        r
    }

    pub fn to_json(&self) -> String {
        // Infallible: every field is a plain serializable scalar/string.
        serde_json::to_string(self).expect("AuditRecord serializes")
    }
}

/// One aggregated endpoint row for `izba netlog --summary` / the app Netlog tab.
/// Records are grouped by `(host-or-ip, port)`; verdict/method/path reflect the
/// latest record in the group, counts tally allow vs deny. Serializable so the
/// Tauri layer can hand it straight to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointSummary {
    /// Resolved name (tier-1 Host / tier-2 DNS-snoop FQDN), else `None` (raw IP).
    pub host: Option<String>,
    pub dest_ip: IpAddr,
    pub port: u16,
    pub tier: Tier,
    /// The current effective verdict (from the most recent record).
    pub verdict: Verdict,
    pub allow_count: u64,
    pub deny_count: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_method: Option<String>,
    pub last_path: Option<String>,
}

/// Group audit `records` by `(host-or-ip, port)`, newest endpoint first.
/// Pure (no clock, no IO) so it is fully host-testable. Key uses the resolved
/// host when present, else the dest IP string, so a raw-IP flow and a named
/// flow to the same IP:port stay distinct rows.
pub fn aggregate(records: impl IntoIterator<Item = AuditRecord>) -> Vec<EndpointSummary> {
    let mut map: HashMap<(String, u16), EndpointSummary> = HashMap::new();
    for r in records {
        let key = (
            r.host.clone().unwrap_or_else(|| r.dest_ip.to_string()),
            r.port,
        );
        let s = map.entry(key).or_insert_with(|| EndpointSummary {
            host: r.host.clone(),
            dest_ip: r.dest_ip,
            port: r.port,
            tier: r.tier,
            verdict: r.verdict,
            allow_count: 0,
            deny_count: 0,
            first_seen_ms: r.ts_ms,
            last_seen_ms: 0,
            last_method: None,
            last_path: None,
        });
        match r.verdict {
            Verdict::Allow => s.allow_count += 1,
            Verdict::Deny => s.deny_count += 1,
        }
        s.first_seen_ms = s.first_seen_ms.min(r.ts_ms);
        // `>=` so that among equal timestamps the later-appended (genuinely
        // newer) record wins — audit lines are appended in chronological order.
        if r.ts_ms >= s.last_seen_ms {
            s.last_seen_ms = r.ts_ms;
            s.verdict = r.verdict;
            s.tier = r.tier;
            s.host = r.host.clone();
            s.dest_ip = r.dest_ip;
            s.last_method = r.method.clone();
            s.last_path = r.path.clone();
        }
    }
    let mut out: Vec<EndpointSummary> = map.into_values().collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.last_seen_ms));
    out
}

/// Parse one JSONL line into an [`AuditRecord`]; `None` on a malformed line
/// (so `izba netlog` skips junk rather than aborting the tail).
pub fn parse_line(line: &str) -> Option<AuditRecord> {
    serde_json::from_str(line.trim()).ok()
}

/// Format an epoch-millis timestamp as `%Y-%m-%d %H:%M:%S` (UTC), falling
/// back to the raw number if it is out of range. Shared by `format_record`
/// and the CLI's `--summary` view so both render dates identically.
pub fn format_ts_ms(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ms.to_string())
}

/// Render one record as a human-readable `izba netlog` line:
/// `<utc>  ALLOW/DENY l7  sandbox  host|ip:port  [METHOD path]  (rule)`.
/// Pure: the timestamp comes from the record, so this is deterministic.
pub fn format_record(rec: &AuditRecord) -> String {
    let ts = format_ts_ms(rec.ts_ms);
    let verdict = match rec.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY ",
    };
    let tier = match rec.tier {
        Tier::L7 => "l7",
        Tier::L3 => "l3",
    };
    let target = rec.host.clone().unwrap_or_else(|| rec.dest_ip.to_string());
    let req = match (&rec.method, &rec.path) {
        (Some(m), Some(p)) => format!("  {m} {p}"),
        _ => String::new(),
    };
    format!(
        "{ts}  {verdict} {tier}  {sandbox}  {target}:{port}{req}  ({rule})",
        sandbox = rec.sandbox,
        port = rec.port,
        rule = rec.rule,
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Appends audit records to per-sandbox `logs/egress-audit.jsonl`. Cheap to
/// clone (holds only [`Paths`]); shared by the blocking router (tier-2) and the
/// MITM runtime (tier-1). Failures are swallowed — an audit write must never
/// take down a live egress flow.
#[derive(Clone)]
pub struct AuditSink {
    paths: Paths,
}

impl AuditSink {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Stamp the record's time and append it as one JSON line.
    pub fn record(&self, mut rec: AuditRecord) {
        rec.ts_ms = now_ms();
        let dir = self.paths.logs_dir(&rec.sandbox);
        if crate::paths::create_dir_700(&dir, self.paths.root()).is_err() {
            return;
        }
        let path = dir.join("egress-audit.jsonl");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let mut line = rec.to_json();
            line.push('\n');
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        ts: u64,
        host: Option<&str>,
        ip: &str,
        port: u16,
        v: Verdict,
        tier: Tier,
    ) -> AuditRecord {
        let mut r = match v {
            Verdict::Allow => AuditRecord::allow("web", ip.parse().unwrap(), port, host, tier, "r"),
            Verdict::Deny => AuditRecord::deny("web", ip.parse().unwrap(), port, host, tier, "r"),
        };
        r.ts_ms = ts;
        r
    }

    #[test]
    fn aggregate_groups_by_host_and_port_counts_and_latest() {
        let recs = vec![
            rec(
                100,
                Some("api.x.com"),
                "1.1.1.1",
                443,
                Verdict::Allow,
                Tier::L7,
            ),
            rec(
                200,
                Some("api.x.com"),
                "1.1.1.1",
                443,
                Verdict::Deny,
                Tier::L7,
            ),
            rec(
                150,
                Some("api.x.com"),
                "1.1.1.1",
                80,
                Verdict::Allow,
                Tier::L7,
            ), // different port → own group
        ];
        let out = aggregate(recs);
        // newest endpoint first: the :443 group's last_seen is 200, the :80 group's is 150.
        assert_eq!(out.len(), 2);
        let g443 = out.iter().find(|s| s.port == 443).unwrap();
        assert_eq!(g443.host.as_deref(), Some("api.x.com"));
        assert_eq!(g443.allow_count, 1);
        assert_eq!(g443.deny_count, 1);
        assert_eq!(g443.first_seen_ms, 100);
        assert_eq!(g443.last_seen_ms, 200);
        assert_eq!(g443.verdict, Verdict::Deny, "latest verdict wins");
        assert_eq!(out[0].port, 443, "sorted by last_seen desc");
    }

    #[test]
    fn aggregate_raw_ip_rows_keep_none_host_and_group_by_ip() {
        let recs = vec![
            rec(10, None, "9.9.9.9", 22, Verdict::Deny, Tier::L3),
            rec(20, None, "9.9.9.9", 22, Verdict::Deny, Tier::L3),
        ];
        let out = aggregate(recs);
        assert_eq!(out.len(), 1);
        assert!(out[0].host.is_none());
        assert_eq!(out[0].dest_ip.to_string(), "9.9.9.9");
        assert_eq!(out[0].deny_count, 2);
    }

    #[test]
    fn aggregate_picks_latest_method_path_and_empty_is_empty() {
        assert!(aggregate(std::iter::empty()).is_empty());
        let mut a = rec(10, Some("h"), "1.1.1.1", 443, Verdict::Allow, Tier::L7);
        a.method = Some("GET".into());
        a.path = Some("/old".into());
        let mut b = rec(20, Some("h"), "1.1.1.1", 443, Verdict::Allow, Tier::L7);
        b.method = Some("POST".into());
        b.path = Some("/new".into());
        let out = aggregate(vec![a, b]);
        assert_eq!(out[0].last_method.as_deref(), Some("POST"));
        assert_eq!(out[0].last_path.as_deref(), Some("/new"));
    }

    #[test]
    fn audit_record_serializes_with_tier_and_verdict() {
        let r = AuditRecord::deny(
            "web",
            "1.2.3.4".parse().unwrap(),
            443,
            Some("api.evil.com"),
            Tier::L7,
            "not in allow-list",
        );
        let j: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(j["verdict"], "deny");
        assert_eq!(j["tier"], "l7");
        assert_eq!(j["host"], "api.evil.com");
        assert_eq!(j["dest_ip"], "1.2.3.4");
        assert_eq!(j["port"], 443);
        assert_eq!(j["rule"], "not in allow-list");
    }

    #[test]
    fn allow_record_omits_absent_l7_fields() {
        let r = AuditRecord::allow(
            "web",
            "9.9.9.9".parse().unwrap(),
            443,
            None,
            Tier::L3,
            "snoop",
        );
        let j: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(j["verdict"], "allow");
        assert_eq!(j["tier"], "l3");
        assert!(j.get("host").is_none(), "absent host must not serialize");
        assert!(j.get("method").is_none());
    }

    #[test]
    fn with_request_attaches_method_and_path() {
        let r = AuditRecord::allow(
            "web",
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.anthropic.com"),
            Tier::L7,
            "allow-list",
        )
        .with_request("GET", "/v1/messages");
        let j: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(j["method"], "GET");
        assert_eq!(j["path"], "/v1/messages");
    }

    #[test]
    fn parse_line_round_trips_a_record() {
        let mut rec = AuditRecord::allow(
            "web",
            "1.2.3.4".parse().unwrap(),
            443,
            Some("api.anthropic.com"),
            Tier::L7,
            "allow-list",
        )
        .with_request("GET", "/v1/messages");
        rec.ts_ms = 1_700_000_000_000;
        let parsed = parse_line(&rec.to_json()).expect("valid line parses");
        assert_eq!(parsed, rec);
        assert!(parse_line("{not json").is_none(), "junk line is skipped");
    }

    #[test]
    fn format_record_renders_allow_and_deny() {
        let mut allow = AuditRecord::allow(
            "web",
            "1.2.3.4".parse().unwrap(),
            443,
            Some("api.anthropic.com"),
            Tier::L7,
            "allow-list",
        )
        .with_request("GET", "/v1/messages");
        allow.ts_ms = 1_700_000_000_000; // fixed → deterministic
        let line = format_record(&allow);
        assert!(line.contains("ALLOW l7"), "{line}");
        assert!(line.contains("api.anthropic.com:443"), "{line}");
        assert!(line.contains("GET /v1/messages"), "{line}");
        assert!(line.contains("(allow-list)"), "{line}");
        assert!(line.contains("2023-11-14"), "renders a UTC date: {line}");

        // Tier-2 deny with no host falls back to the dest IP, no method/path.
        let mut deny = AuditRecord::deny(
            "web",
            "9.9.9.9".parse().unwrap(),
            22,
            None,
            Tier::L3,
            "denied",
        );
        deny.ts_ms = 1_700_000_000_000;
        let dline = format_record(&deny);
        assert!(dline.contains("DENY  l3"), "{dline}");
        assert!(dline.contains("9.9.9.9:22"), "{dline}");
        assert!(
            !dline.contains("  GET"),
            "no request line when absent: {dline}"
        );
    }

    /// The sink appends one JSON line per record and stamps a non-zero time.
    #[test]
    fn sink_appends_jsonl_and_stamps_time() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        let sink = AuditSink::new(paths.clone());
        sink.record(AuditRecord::allow(
            "web",
            "1.2.3.4".parse().unwrap(),
            443,
            Some("api.anthropic.com"),
            Tier::L7,
            "allow-list",
        ));
        sink.record(AuditRecord::deny(
            "web",
            "5.6.7.8".parse().unwrap(),
            443,
            Some("evil.example.com"),
            Tier::L7,
            "not in allow-list",
        ));
        let body =
            std::fs::read_to_string(paths.logs_dir("web").join("egress-audit.jsonl")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "one line per record");
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["verdict"], "allow");
        assert!(first["ts_ms"].as_u64().unwrap() > 0, "sink stamps the time");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["verdict"], "deny");
    }
}
