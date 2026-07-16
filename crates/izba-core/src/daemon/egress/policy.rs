//! Egress policy seam. The `regorus`-backed [`RegoPolicy`] evaluates a
//! default-deny allow-list (adapted from `Lupus/docker-mitm-bridge`); the
//! [`Policy`] trait keeps the daemon growing by extension (roadmap risk #6).
//!
//! `FlowDesc` carries the L3 tuple plus optional L7 fields the MITM datapath
//! fills after TLS termination (host/method/path/query) — the policy decides on
//! whatever is present, so tier-1 (HTTP, hard) and tier-2 (DNS-snoop, soft)
//! share one engine.

use serde::{Deserialize, Serialize};

use super::config::AllowEntry;

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
    /// Tier-1: raw query string (e.g. "service=git-receive-pack"), for git
    /// read/write discrimination. None for tier-2 / pre-MITM.
    pub query: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

pub trait Policy: Send + Sync {
    /// A pure decision: the caller (router tier-2 / MITM tier-1) owns the
    /// structured audit emission, since it knows the tier and the audit sink.
    fn check(&self, flow: &FlowDesc) -> Verdict;

    /// Whether this policy is a real firewall. Tier-2 (non-HTTP) treats an
    /// enforcing policy strictly — a private-address denylist + default-deny on
    /// a raw-IP dial with no DNS-snoop record. A bare sandbox's [`AllowAll`]
    /// does NOT enforce, so its raw-IP / RFC1918 egress stays permitted
    /// (today's behavior). Defaults to `true`; only `AllowAll` opts out.
    fn enforces(&self) -> bool {
        true
    }
}

/// Default policy for a bare sandbox (no declared `--policy`): everything
/// allowed. The decision is still recorded by the call site's audit sink, so
/// `izba netlog` shows every connection even with no allow-list.
pub struct AllowAll;

impl Policy for AllowAll {
    fn check(&self, _flow: &FlowDesc) -> Verdict {
        Verdict::Allow
    }
    fn enforces(&self) -> bool {
        false
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

/// Hosts any sandbox may reach with FULL method access (POST-based APIs).
const GLOBAL_READ_WRITE: &[&str] = &[
    "api.anthropic.com",
    "console.anthropic.com",
    "api.openai.com",
    "platform.openai.com",
    "github.com",
    "api.github.com",
];
/// Static mirrors — GET/HEAD only (read).
const GLOBAL_READ: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
];

impl RegoPolicy {
    const REGO: &'static str = include_str!("egress.rego");

    /// Build from the embedded `egress.rego` + a generated default data document.
    /// The default doc covers the well-known global hosts; per-sandbox rules
    /// come from a `--policy` file via [`with_data`].
    pub fn embedded() -> anyhow::Result<Self> {
        let mut hosts = serde_json::Map::new();
        let ports = serde_json::json!(AllowEntry::DEFAULT_PORTS); // single source of truth
        for h in GLOBAL_READ_WRITE {
            hosts.insert(
                (*h).into(),
                serde_json::json!({ "ports": ports, "access": "read-write" }),
            );
        }
        for h in GLOBAL_READ {
            hosts.insert(
                (*h).into(),
                serde_json::json!({ "ports": ports, "access": "read" }),
            );
        }
        let data = serde_json::json!({
            "host_rules": hosts,
            "sandbox_host_rules": {},
            "sandbox_git_rules": {},
        });
        Self::new(Self::REGO, &data.to_string())
    }

    /// Build from the embedded `egress.rego` + a supplied data document — the
    /// per-sandbox allow-list a `--policy` file compiles to (see
    /// [`super::config::EgressPolicyConfig`]).
    pub fn with_data(data_json: &str) -> anyhow::Result<Self> {
        Self::new(Self::REGO, data_json)
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
    /// fields become `input.host`/`method`/`path`/`query` and the Rego prefers
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
        if let Some(q) = &flow.query {
            obj["query"] = serde_json::Value::Object(parse_query(q));
        }
        obj.to_string()
    }
}

/// Parse a raw `a=b&c=d` query into a flat JSON object for the rego
/// (`input.query.service`). Percent-decoding is unnecessary: the only key we
/// read is `service`, whose values are fixed ASCII tokens.
fn parse_query(q: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    m
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

    fn git_flow(
        sandbox: &str,
        host: &str,
        method: &str,
        path: &str,
        query: Option<&str>,
    ) -> FlowDesc {
        FlowDesc {
            sandbox: sandbox.into(),
            addr: host.into(),
            port: 443,
            host: Some(host.into()),
            method: Some(method.into()),
            path: Some(path.into()),
            query: query.map(|q| q.into()),
        }
    }

    fn policy_with_git(sandbox: &str, rules_json: &str, hosts_json: &str) -> RegoPolicy {
        let data = format!(
            r#"{{"host_rules":{{}},"sandbox_host_rules":{{"{s}":{h}}},"sandbox_git_rules":{{"{s}":{r}}}}}"#,
            s = sandbox,
            h = hosts_json,
            r = rules_json
        );
        RegoPolicy::with_data(&data).unwrap()
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
        // api.anthropic.com is read-write, so a bare L3 flow (no method) hits the
        // host_rules allow rule — method check only applies when method is present.
        let mut f = flow("web", "api.anthropic.com", 443);
        f.host = Some("api.anthropic.com".into());
        f.method = Some("GET".into());
        assert_eq!(p.check(&f), Verdict::Allow);
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
        // github.com is read-write in the new embedded doc; a GET flow is allowed
        let mut f = flow("build", "github.com", 443);
        f.host = Some("github.com".into());
        f.method = Some("GET".into());
        assert_eq!(p.check(&f), Verdict::Allow);
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
    /// `web` may not. This test uses a custom data doc with the new shape.
    #[test]
    fn per_sandbox_allow_list_is_isolating() {
        // Build a data doc with the new shape that mimics the old embedded sandbox tests.
        let data = serde_json::json!({
            "host_rules": {},
            "sandbox_host_rules": {
                "build": {
                    "internal-registry.corp": {"ports": [80, 443], "access": "read-write"}
                },
                "web": {
                    "api.stripe.com": {"ports": [80, 443], "access": "read-write"}
                }
            },
            "sandbox_git_rules": {}
        });
        let p = RegoPolicy::new(RegoPolicy::REGO, &data.to_string()).unwrap();

        let mut build_internal = flow("build", "internal-registry.corp", 443);
        build_internal.host = Some("internal-registry.corp".into());
        build_internal.method = Some("GET".into());
        assert_eq!(
            p.check(&build_internal),
            Verdict::Allow,
            "build sandbox is allowed its per-sandbox domain"
        );
        let mut web_internal = flow("web", "internal-registry.corp", 443);
        web_internal.host = Some("internal-registry.corp".into());
        web_internal.method = Some("GET".into());
        assert_eq!(
            p.check(&web_internal),
            Verdict::Deny,
            "web sandbox must NOT inherit build's per-sandbox grant"
        );
        let mut web_stripe = flow("web", "api.stripe.com", 443);
        web_stripe.host = Some("api.stripe.com".into());
        web_stripe.method = Some("GET".into());
        assert_eq!(
            p.check(&web_stripe),
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
            r#"{"host_rules": {}, "sandbox_host_rules": {}, "sandbox_git_rules": {}}"#,
        )
        .unwrap();
        assert_eq!(
            p.check(&flow("web", "api.anthropic.com", 443)),
            Verdict::Deny
        );
    }

    /// The loophole, now closed: a globally-allowed host on a non-web port is denied.
    #[test]
    fn global_host_on_non_web_port_is_denied() {
        let p = RegoPolicy::embedded().unwrap();
        let mut f443 = flow("web", "api.anthropic.com", 443);
        f443.host = Some("api.anthropic.com".into());
        f443.method = Some("GET".into());
        assert_eq!(p.check(&f443), Verdict::Allow, "web port stays allowed");

        let mut f22 = flow("web", "api.anthropic.com", 22);
        f22.host = Some("api.anthropic.com".into());
        f22.method = Some("GET".into());
        assert_eq!(
            p.check(&f22),
            Verdict::Deny,
            "non-web port on an allowed host must be denied"
        );
    }

    /// Scoped ports REPLACE the web default: a host listed for 5432 only is
    /// allowed on 5432 and denied on 443.
    #[test]
    fn scoped_ports_replace_the_web_default() {
        let p = RegoPolicy::new(
            RegoPolicy::REGO,
            r#"{"host_rules": {}, "sandbox_host_rules": {"web": {"db.internal": {"ports": [5432], "access": "read-write"}}}, "sandbox_git_rules": {}}"#,
        )
        .unwrap();
        let mut f5432 = flow("web", "db.internal", 5432);
        f5432.host = Some("db.internal".into());
        f5432.method = Some("GET".into());
        assert_eq!(p.check(&f5432), Verdict::Allow);

        let mut f443 = flow("web", "db.internal", 443);
        f443.host = Some("db.internal".into());
        f443.method = Some("GET".into());
        assert_eq!(
            p.check(&f443),
            Verdict::Deny,
            "explicit ports replace, not extend, the web default"
        );
    }

    #[test]
    fn rego_policy_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RegoPolicy>();
        let p: std::sync::Arc<dyn Policy> = std::sync::Arc::new(RegoPolicy::embedded().unwrap());
        let p2 = std::sync::Arc::clone(&p);
        let h = std::thread::spawn(move || {
            let mut f = FlowDesc::l3("web", "api.openai.com", 443);
            f.host = Some("api.openai.com".into());
            f.method = Some("GET".into());
            p2.check(&f)
        });
        assert_eq!(h.join().unwrap(), Verdict::Allow);
        assert_eq!(
            p.check(&flow("web", "evil.example.com", 443)),
            Verdict::Deny
        );
    }

    // ── Git rule table tests ──────────────────────────────────────────────────

    #[test]
    fn git_clone_allowed_when_read_granted_any_vendor() {
        for host in [
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "git.example.org",
        ] {
            let repo = format!("{host}/myorg/app");
            let p = policy_with_git(
                "web",
                &format!(r#"[{{"repo":"{repo}","access":"read"}}]"#),
                "{}",
            );
            // discovery GET
            assert_eq!(
                p.check(&git_flow(
                    "web",
                    host,
                    "GET",
                    "/myorg/app/info/refs",
                    Some("service=git-upload-pack")
                )),
                Verdict::Allow,
                "{host}: clone discovery"
            );
            // data POST
            assert_eq!(
                p.check(&git_flow(
                    "web",
                    host,
                    "POST",
                    "/myorg/app/git-upload-pack",
                    None
                )),
                Verdict::Allow,
                "{host}: clone data"
            );
        }
    }

    #[test]
    fn git_push_denied_when_only_read() {
        let p = policy_with_git(
            "web",
            r#"[{"repo":"github.com/myorg/app","access":"read"}]"#,
            "{}",
        );
        assert_eq!(
            p.check(&git_flow(
                "web",
                "github.com",
                "GET",
                "/myorg/app/info/refs",
                Some("service=git-receive-pack")
            )),
            Verdict::Deny,
            "push discovery denied under read"
        );
        assert_eq!(
            p.check(&git_flow(
                "web",
                "github.com",
                "POST",
                "/myorg/app/git-receive-pack",
                None
            )),
            Verdict::Deny,
            "push data denied under read"
        );
    }

    #[test]
    fn git_push_allowed_when_read_write() {
        let p = policy_with_git(
            "web",
            r#"[{"repo":"github.com/myorg/app","access":"read-write"}]"#,
            "{}",
        );
        assert_eq!(
            p.check(&git_flow(
                "web",
                "github.com",
                "POST",
                "/myorg/app/git-receive-pack",
                None
            )),
            Verdict::Allow
        );
        // read still works (write implies read)
        assert_eq!(
            p.check(&git_flow(
                "web",
                "github.com",
                "POST",
                "/myorg/app/git-upload-pack",
                None
            )),
            Verdict::Allow
        );
    }

    #[test]
    fn git_owner_glob_and_dotgit_suffix() {
        let p = policy_with_git(
            "web",
            r#"[{"repo":"gitlab.com/vendor/*","access":"read"}]"#,
            "{}",
        );
        assert_eq!(
            p.check(&git_flow(
                "web",
                "gitlab.com",
                "POST",
                "/vendor/lib.git/git-upload-pack",
                None
            )),
            Verdict::Allow,
            ".git suffix + owner glob"
        );
        assert_eq!(
            p.check(&git_flow(
                "web",
                "gitlab.com",
                "POST",
                "/other/lib/git-upload-pack",
                None
            )),
            Verdict::Deny,
            "different owner denied"
        );
    }

    #[test]
    fn git_host_scope_matches_any_repo() {
        let p = policy_with_git("web", r#"[{"host":"bitbucket.org","access":"read"}]"#, "{}");
        assert_eq!(
            p.check(&git_flow(
                "web",
                "bitbucket.org",
                "POST",
                "/any/repo/git-upload-pack",
                None
            )),
            Verdict::Allow
        );
    }

    #[test]
    fn git_rule_does_not_grant_ordinary_http() {
        // A git read grant must NOT open the web UI / API on the same host.
        let p = policy_with_git(
            "web",
            r#"[{"repo":"github.com/myorg/app","access":"read-write"}]"#,
            "{}",
        );
        assert_eq!(
            p.check(&git_flow("web", "github.com", "GET", "/myorg/app", None)),
            Verdict::Deny,
            "web UI GET not a git wire op -> denied"
        );
    }

    #[test]
    fn http_access_read_allows_get_denies_post() {
        let p = policy_with_git(
            "web",
            "[]",
            r#"{"pypi.org":{"ports":[80,443],"access":"read"}}"#,
        );
        let mut get = flow("web", "pypi.org", 443);
        get.host = Some("pypi.org".into());
        get.method = Some("GET".into());
        assert_eq!(p.check(&get), Verdict::Allow);
        let mut post = flow("web", "pypi.org", 443);
        post.host = Some("pypi.org".into());
        post.method = Some("POST".into());
        assert_eq!(p.check(&post), Verdict::Deny, "read host denies POST");
    }

    #[test]
    fn http_access_read_write_allows_post() {
        let p = policy_with_git(
            "web",
            "[]",
            r#"{"api.x.com":{"ports":[443],"access":"read-write"}}"#,
        );
        let mut post = flow("web", "api.x.com", 443);
        post.host = Some("api.x.com".into());
        post.method = Some("POST".into());
        assert_eq!(p.check(&post), Verdict::Allow);
    }

    /// Data doc with ONLY wildcard rules (per-sandbox), for the wildcard tests.
    fn wildcard_policy(sandbox: &str, rules_json: serde_json::Value) -> RegoPolicy {
        let data = serde_json::json!({
            "host_rules": {},
            "sandbox_host_rules": {},
            "wildcard_host_rules": [],
            "sandbox_wildcard_host_rules": { sandbox: rules_json },
            "sandbox_git_rules": {}
        });
        RegoPolicy::new(RegoPolicy::REGO, &data.to_string()).unwrap()
    }

    /// An L7 GET flow whose decrypted host == dialed addr (tier-1 shape).
    fn l7_get(sandbox: &str, host: &str, port: u16) -> FlowDesc {
        let mut f = flow(sandbox, host, port);
        f.host = Some(host.into());
        f.method = Some("GET".into());
        f
    }

    /// `*.example.com` matches exactly one extra label — not the apex, not
    /// deeper subdomains, and never a suffix-embedded lookalike host.
    #[test]
    fn single_label_wildcard_matches_one_label_only() {
        let p = wildcard_policy(
            "web",
            serde_json::json!([{"pattern": "*.example.com", "ports": [80, 443], "access": "read-write"}]),
        );
        assert_eq!(
            p.check(&l7_get("web", "api.example.com", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&l7_get("web", "a.b.example.com", 443)),
            Verdict::Deny,
            "one-label wildcard must not match a deeper subdomain"
        );
        assert_eq!(
            p.check(&l7_get("web", "example.com", 443)),
            Verdict::Deny,
            "the apex never matches a wildcard"
        );
        assert_eq!(
            p.check(&l7_get("web", "evilexample.com", 443)),
            Verdict::Deny,
            "suffix embedding must not match (no '.' boundary)"
        );
    }

    /// `**.example.com` matches any depth >= 1, still never the apex.
    #[test]
    fn deep_wildcard_matches_any_depth() {
        let p = wildcard_policy(
            "web",
            serde_json::json!([{"pattern": "**.example.com", "ports": [80, 443], "access": "read-write"}]),
        );
        assert_eq!(
            p.check(&l7_get("web", "a.example.com", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&l7_get("web", "a.b.c.example.com", 443)),
            Verdict::Allow
        );
        assert_eq!(p.check(&l7_get("web", "example.com", 443)), Verdict::Deny);
        assert_eq!(
            p.check(&l7_get("web", "evilexample.com", 443)),
            Verdict::Deny
        );
    }

    /// Wildcard rules carry the same ports/access semantics as exact rules.
    #[test]
    fn wildcard_rule_respects_ports_and_access() {
        let p = wildcard_policy(
            "web",
            serde_json::json!([{"pattern": "*.internal.corp", "ports": [8443], "access": "read"}]),
        );
        assert_eq!(
            p.check(&l7_get("web", "api.internal.corp", 8443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&l7_get("web", "api.internal.corp", 443)),
            Verdict::Deny,
            "explicit ports replace the web default on wildcard rules too"
        );
        let mut post = l7_get("web", "api.internal.corp", 8443);
        post.method = Some("POST".into());
        assert_eq!(p.check(&post), Verdict::Deny, "access: read blocks POST");
    }

    /// A bare L3 flow (tier-2 shape: no decrypted host, no method) matches a
    /// wildcard via the `dest_name := input.dest` fallback — the DNS-snoop path.
    #[test]
    fn wildcard_matches_tier2_bare_flow() {
        let p = wildcard_policy(
            "web",
            serde_json::json!([{"pattern": "*.example.com", "ports": [80, 443], "access": "read-write"}]),
        );
        assert_eq!(
            p.check(&flow("web", "api.example.com", 443)),
            Verdict::Allow
        );
        assert_eq!(p.check(&flow("web", "example.com", 443)), Verdict::Deny);
    }

    /// Per-sandbox wildcard rules do not leak across sandboxes; global
    /// `wildcard_host_rules` apply to every sandbox.
    #[test]
    fn wildcard_scoping_global_vs_sandbox() {
        let data = serde_json::json!({
            "host_rules": {},
            "sandbox_host_rules": {},
            "wildcard_host_rules": [
                {"pattern": "*.shared.corp", "ports": [443], "access": "read-write"}
            ],
            "sandbox_wildcard_host_rules": {
                "build": [{"pattern": "*.build.corp", "ports": [443], "access": "read-write"}]
            },
            "sandbox_git_rules": {}
        });
        let p = RegoPolicy::new(RegoPolicy::REGO, &data.to_string()).unwrap();
        assert_eq!(
            p.check(&l7_get("web", "x.shared.corp", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&l7_get("build", "x.build.corp", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&l7_get("web", "x.build.corp", 443)),
            Verdict::Deny,
            "web must not inherit build's per-sandbox wildcard"
        );
    }
}
