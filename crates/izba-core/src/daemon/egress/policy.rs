//! Egress policy seam. The `regorus`-backed [`RegoPolicy`] evaluates a
//! default-deny allow-list (adapted from `Lupus/docker-mitm-bridge`); the
//! [`Policy`] trait keeps the daemon growing by extension (roadmap risk #6).
//!
//! `FlowDesc` carries the L3 tuple plus optional L7 fields the MITM datapath
//! fills after TLS termination (host/method/path) — the policy decides on
//! whatever is present, so tier-1 (HTTP, hard) and tier-2 (DNS-snoop, soft)
//! share one engine.

use serde::Serialize;

/// One egress connection attempt, as seen at the policy check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct FlowDesc {
    pub sandbox: String,
    /// Destination as the guest dialed it — an IP literal (tier-2 / pre-MITM)
    /// or, when DNS-snoop recovered it, the resolved FQDN.
    pub addr: String,
    pub port: u16,
    /// Tier-1: the decrypted `Host` header / SNI (preferred over `addr`).
    pub host: Option<String>,
    /// Tier-1: HTTP method (available for future method/path L7 rules).
    pub method: Option<String>,
    /// Tier-1: request path.
    pub path: Option<String>,
}

impl FlowDesc {
    /// An L3 flow with no L7 detail (tier-2 / pre-MITM).
    pub fn l3(sandbox: impl Into<String>, addr: impl Into<String>, port: u16) -> Self {
        Self {
            sandbox: sandbox.into(),
            addr: addr.into(),
            port,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

pub trait Policy: Send + Sync {
    /// A pure decision: the caller (router tier-2 / MITM tier-1) owns the
    /// structured audit emission, since it knows the tier and the audit sink.
    fn check(&self, flow: &FlowDesc) -> Verdict;
}

/// Default policy for a bare sandbox (no declared `--policy`): everything
/// allowed. The decision is still recorded by the call site's audit sink, so
/// `izba netlog` shows every connection even with no allow-list.
pub struct AllowAll;

impl Policy for AllowAll {
    fn check(&self, _flow: &FlowDesc) -> Verdict {
        Verdict::Allow
    }
}

/// Policy backed by [regorus] — Microsoft's pure-Rust OPA/Rego interpreter —
/// evaluating a default-deny domain allow-list (`egress.rego`).
///
/// CONCURRENCY: `regorus::Engine`'s eval methods take `&mut self`, but
/// [`Policy::check`] is `&self` and the egress manager calls it from many
/// connection threads at once. `Engine` is `Clone` and cheap-clones its
/// compiled AST behind an `Arc` (the `arc` feature also makes it `Send+Sync`),
/// so we hold an immutable *template* and `clone()` it per check — a snapshot
/// that needs no lock and never contends.
pub struct RegoPolicy {
    /// Compiled engine (policy + data loaded). Cloned per `check`.
    template: regorus::Engine,
    /// The boolean query the Rego exposes: `data.egress.allow`.
    query: String,
}

impl RegoPolicy {
    /// The Rego module + data document, embedded so the daemon ships with a
    /// default policy and needs no on-disk file.
    const REGO: &'static str = include_str!("egress.rego");
    const DATA_JSON: &'static str = include_str!("egress_data.json");

    /// Build from the embedded `egress.rego` + `egress_data.json`.
    pub fn embedded() -> anyhow::Result<Self> {
        Self::new(Self::REGO, Self::DATA_JSON)
    }

    /// Build from an explicit Rego module + JSON data document (the per-sandbox
    /// data doc is supplied here at egress start; tests vary the tier).
    pub fn new(rego: &str, data_json: &str) -> anyhow::Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("egress.rego".to_string(), rego.to_string())
            .map_err(|e| anyhow::anyhow!("add_policy: {e}"))?;
        engine
            .add_data_json(data_json)
            .map_err(|e| anyhow::anyhow!("add_data_json: {e}"))?;
        Ok(Self {
            template: engine,
            query: "data.egress.allow".to_string(),
        })
    }

    /// The input the Rego sees. `addr` becomes `input.dest`; the optional L7
    /// fields become `input.host`/`method`/`path` and the Rego prefers
    /// `input.host` over `input.dest` when present. Hand-built so the wire
    /// field names match the Rego, decoupled from `FlowDesc`'s serde names;
    /// `serde_json` escapes the strings (no injection via a hostile value).
    fn input_json(flow: &FlowDesc) -> String {
        let mut obj = serde_json::json!({
            "sandbox": flow.sandbox,
            "dest": flow.addr,
            "port": flow.port,
        });
        if let Some(h) = &flow.host {
            obj["host"] = serde_json::Value::String(h.clone());
        }
        if let Some(m) = &flow.method {
            obj["method"] = serde_json::Value::String(m.clone());
        }
        if let Some(p) = &flow.path {
            obj["path"] = serde_json::Value::String(p.clone());
        }
        obj.to_string()
    }
}

impl Policy for RegoPolicy {
    fn check(&self, flow: &FlowDesc) -> Verdict {
        // Snapshot the compiled engine (cheap Arc-clone of the AST), then feed
        // input + query. Any engine error is a fail-closed Deny — a broken
        // policy must never silently allow egress.
        let mut engine = self.template.clone();
        let verdict = (|| -> anyhow::Result<bool> {
            engine
                .set_input_json(&Self::input_json(flow))
                .map_err(|e| anyhow::anyhow!("set_input_json: {e}"))?;
            engine
                .eval_bool_query(self.query.clone(), false)
                .map_err(|e| anyhow::anyhow!("eval_bool_query: {e}"))
        })();
        match verdict {
            Ok(true) => Verdict::Allow,
            // Fail-closed: a `false` result OR an evaluation error both deny —
            // a broken policy must never silently allow egress. The error is
            // dropped here; the audit sink records the resulting Deny.
            Ok(false) | Err(_) => Verdict::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(sandbox: &str, addr: &str, port: u16) -> FlowDesc {
        FlowDesc::l3(sandbox, addr, port)
    }

    #[test]
    fn allow_all_allows() {
        assert_eq!(AllowAll.check(&flow("web", "1.2.3.4", 443)), Verdict::Allow);
    }

    // --- RegoPolicy: real Rego eval over the embedded policy+data. ---
    // Pure in-memory evaluations: no listeners bound, sandbox-safe.

    #[test]
    fn embedded_policy_builds() {
        RegoPolicy::embedded().expect("embedded rego + data must compile");
    }

    #[test]
    fn global_domain_is_allowed() {
        let p = RegoPolicy::embedded().unwrap();
        assert_eq!(
            p.check(&flow("web", "api.anthropic.com", 443)),
            Verdict::Allow
        );
    }

    #[test]
    fn unlisted_domain_is_denied() {
        let p = RegoPolicy::embedded().unwrap();
        assert_eq!(
            p.check(&flow("web", "evil.example.com", 443)),
            Verdict::Deny,
            "default-deny: an un-listed domain must be denied"
        );
    }

    #[test]
    fn restricted_tier_domain_is_allowed() {
        let p = RegoPolicy::embedded().unwrap();
        assert_eq!(p.check(&flow("build", "github.com", 443)), Verdict::Allow);
    }

    /// Tier-1: the decrypted `Host` drives the decision, preferred over the
    /// raw `addr` the guest dialed — the whole point of MITM L7 policy.
    #[test]
    fn l7_host_field_drives_the_decision() {
        let p = RegoPolicy::embedded().unwrap();

        // Allowed by L7 host even though `addr` is a bare IP not in any list.
        let mut f = flow("web", "1.2.3.4", 443);
        f.host = Some("api.anthropic.com".into());
        f.method = Some("GET".into());
        f.path = Some("/v1/messages".into());
        assert_eq!(
            p.check(&f),
            Verdict::Allow,
            "allowed by L7 host despite raw IP addr"
        );

        // Host preferred over addr: a denied host wins even if `addr` would
        // have matched — a guest can't smuggle past by faking the dialed IP.
        let mut f2 = flow("web", "api.anthropic.com", 443);
        f2.host = Some("evil.example.com".into());
        assert_eq!(
            p.check(&f2),
            Verdict::Deny,
            "denied by L7 host even though addr is allow-listed"
        );
    }

    /// M2's per-sandbox allow-lists: `build` may reach an internal registry;
    /// `web` may not.
    #[test]
    fn per_sandbox_allow_list_is_isolating() {
        let p = RegoPolicy::embedded().unwrap();
        assert_eq!(
            p.check(&flow("build", "internal-registry.corp", 443)),
            Verdict::Allow,
            "build sandbox is allowed its per-sandbox domain"
        );
        assert_eq!(
            p.check(&flow("web", "internal-registry.corp", 443)),
            Verdict::Deny,
            "web sandbox must NOT inherit build's per-sandbox grant"
        );
        assert_eq!(
            p.check(&flow("web", "api.stripe.com", 443)),
            Verdict::Allow,
            "web sandbox is allowed its own per-sandbox domain"
        );
    }

    #[test]
    fn broken_policy_fails_to_build() {
        let err = RegoPolicy::new("package egress\nthis is not valid rego {", "{}");
        assert!(err.is_err(), "a broken policy must not build");
    }

    #[test]
    fn empty_data_denies_everything() {
        let p = RegoPolicy::new(
            RegoPolicy::REGO,
            r#"{"global_domains": [], "sandbox_domains": {}}"#,
        )
        .unwrap();
        assert_eq!(
            p.check(&flow("web", "api.anthropic.com", 443)),
            Verdict::Deny
        );
    }

    #[test]
    fn rego_policy_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RegoPolicy>();
        let p: std::sync::Arc<dyn Policy> = std::sync::Arc::new(RegoPolicy::embedded().unwrap());
        let p2 = std::sync::Arc::clone(&p);
        let h = std::thread::spawn(move || p2.check(&flow("web", "api.openai.com", 443)));
        assert_eq!(h.join().unwrap(), Verdict::Allow);
        assert_eq!(
            p.check(&flow("web", "evil.example.com", 443)),
            Verdict::Deny
        );
    }
}
