//! Structured per-flow egress audit log. Every TCP egress decision (tier-1
//! MITM HTTP(S) and tier-2 non-HTTP) appends one JSON line to the sandbox's
//! `logs/egress-audit.jsonl`, the data behind `izba netlog` ("see every
//! connection"). The record is a pure value (host-testable, no clock); the
//! [`AuditSink`] stamps the wall-clock time and does the append.

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

/// Parse one JSONL line into an [`AuditRecord`]; `None` on a malformed line
/// (so `izba netlog` skips junk rather than aborting the tail).
pub fn parse_line(line: &str) -> Option<AuditRecord> {
    serde_json::from_str(line.trim()).ok()
}

/// Render one record as a human-readable `izba netlog` line:
/// `<utc>  ALLOW/DENY l7  sandbox  host|ip:port  [METHOD path]  (rule)`.
/// Pure: the timestamp comes from the record, so this is deterministic.
pub fn format_record(rec: &AuditRecord) -> String {
    let ts = chrono::DateTime::from_timestamp_millis(rec.ts_ms as i64)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| rec.ts_ms.to_string());
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
