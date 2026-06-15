//! Per-sandbox egress policy config (`izba create --policy <file>`). A small
//! YAML allow-list — mirroring the user's `docker-mitm-bridge` `data.yml` —
//! that compiles to the regorus data document the [`RegoPolicy`] evaluates.
//!
//! The file is scoped to ONE sandbox (it is supplied at create time), so its
//! `allow` list becomes that sandbox's `sandbox_ports[<name>]` entry in the
//! Rego data doc. A sandbox with no policy file stays a bare, non-enforcing
//! [`AllowAll`](super::policy::AllowAll) — today's permissive behavior.
//!
//! Domains are EXACT-match in M2 (the shipped `egress.rego` matches on `in`).
//! Wildcard rules (`*.`/`**.`, see [`super::dns_snoop::allowlist_matches`]) are
//! a planned extension; `from_yaml` accepts them syntactically so a policy
//! written today keeps parsing once enforcement lands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::policy::RegoPolicy;

/// On-disk policy file name under the sandbox directory.
pub const POLICY_FILE: &str = "policy.yaml";

/// One entry in a sandbox's egress allow-list: either a bare host (which
/// authorizes the default web ports) or a host scoped to an explicit port set.
///
/// `#[serde(untagged)]` keeps every existing `allow: [<string>...]` file parsing
/// unchanged — a YAML string deserializes to `Host`, a `{host, ports}` map to
/// `Scoped`. Variant order matters: `Host` is tried first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowEntry {
    /// Bare host → implicit web ports [80, 443].
    Host(String),
    /// Host scoped to an explicit port set (REPLACES the default web ports).
    Scoped { host: String, ports: Vec<u16> },
}

impl AllowEntry {
    /// Ports a bare host authorizes when no explicit set is given.
    pub const DEFAULT_PORTS: [u16; 2] = [80, 443];

    /// The host this entry names.
    pub fn host(&self) -> &str {
        match self {
            AllowEntry::Host(h) => h,
            AllowEntry::Scoped { host, .. } => host,
        }
    }

    /// The ports this entry authorizes: `[80, 443]` for a bare host, else the
    /// explicit set (which REPLACES — not extends — the default).
    pub fn ports(&self) -> Vec<u16> {
        match self {
            AllowEntry::Host(_) => AllowEntry::DEFAULT_PORTS.to_vec(),
            AllowEntry::Scoped { ports, .. } => ports.clone(),
        }
    }
}

/// A sandbox's egress allow-list, parsed from its `--policy` YAML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct EgressPolicyConfig {
    /// Destinations this sandbox may reach (HTTP host for tier-1, DNS-snoop
    /// FQDN for tier-2). A bare host means web ports (80/443) only; a
    /// `{host, ports}` entry names the exact ports allowed for that host.
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

impl EgressPolicyConfig {
    /// Parse the YAML policy file. An empty/comment-only file is a valid
    /// (empty) allow-list — a declared-but-deny-all sandbox.
    pub fn from_yaml(s: &str) -> Result<Self> {
        // serde_yaml maps an all-comments/empty document to `null`; treat that
        // as the default (empty allow-list) rather than an error.
        let cfg: Option<EgressPolicyConfig> =
            serde_yaml::from_str(s).context("parsing egress policy YAML")?;
        Ok(cfg.unwrap_or_default())
    }

    /// The regorus data document for `sandbox`: the allow-list becomes this
    /// sandbox's `sandbox_ports[<name>]` host→ports map (`global_domains` stays
    /// empty — a `--policy` file is scoped to one sandbox, never granted to
    /// others). A bare host maps to the default web ports; a scoped host to its
    /// exact set.
    pub fn to_rego_data_json(&self, sandbox: &str) -> String {
        let mut ports = serde_json::Map::new();
        for entry in &self.allow {
            ports.insert(entry.host().to_string(), serde_json::json!(entry.ports()));
        }
        serde_json::json!({
            "global_domains": {},
            "sandbox_ports": { sandbox: ports },
        })
        .to_string()
    }

    /// Compile to the enforcing [`RegoPolicy`] for `sandbox`.
    pub fn into_policy(&self, sandbox: &str) -> Result<RegoPolicy> {
        RegoPolicy::with_data(&self.to_rego_data_json(sandbox))
    }

    /// The policy file path under a sandbox directory.
    pub fn path_in(sandbox_dir: &Path) -> PathBuf {
        sandbox_dir.join(POLICY_FILE)
    }

    /// Load a sandbox's policy from its directory; `Ok(None)` if none was
    /// declared (a bare, permissive sandbox).
    pub fn load(sandbox_dir: &Path) -> Result<Option<Self>> {
        let path = Self::path_in(sandbox_dir);
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(Self::from_yaml(&s).with_context(|| {
                format!("reading egress policy {}", path.display())
            })?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::{FlowDesc, Policy, Verdict};

    #[test]
    fn parses_bare_host_as_default_web_ports() {
        let cfg = EgressPolicyConfig::from_yaml("allow:\n  - api.anthropic.com\n").unwrap();
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Host("api.anthropic.com".into())]
        );
        assert_eq!(cfg.allow[0].host(), "api.anthropic.com");
        assert_eq!(cfg.allow[0].ports(), vec![80, 443]);
    }

    #[test]
    fn parses_scoped_host_with_explicit_ports() {
        let cfg =
            EgressPolicyConfig::from_yaml("allow:\n  - host: db.internal\n    ports: [5432]\n")
                .unwrap();
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "db.internal".into(),
                ports: vec![5432],
            }]
        );
        assert_eq!(cfg.allow[0].ports(), vec![5432]);
    }

    #[test]
    fn parses_mixed_bare_and_scoped_list() {
        let yaml =
            "allow:\n  - api.anthropic.com\n  - host: registry.internal\n    ports: [443, 5000]\n";
        let cfg = EgressPolicyConfig::from_yaml(yaml).unwrap();
        assert_eq!(cfg.allow.len(), 2);
        assert_eq!(cfg.allow[0], AllowEntry::Host("api.anthropic.com".into()));
        assert_eq!(
            cfg.allow[1],
            AllowEntry::Scoped {
                host: "registry.internal".into(),
                ports: vec![443, 5000]
            }
        );
    }

    #[test]
    fn allow_entry_round_trips_via_serialize() {
        let entries = vec![
            AllowEntry::Host("api.anthropic.com".into()),
            AllowEntry::Scoped {
                host: "db.internal".into(),
                ports: vec![5432],
            },
        ];
        let yaml = serde_yaml::to_string(&entries).unwrap();
        let back: Vec<AllowEntry> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(entries, back);
    }

    #[test]
    fn empty_or_comment_only_is_empty_allow_list() {
        assert_eq!(EgressPolicyConfig::from_yaml("").unwrap().allow.len(), 0);
        assert_eq!(
            EgressPolicyConfig::from_yaml("# just a comment\n")
                .unwrap()
                .allow
                .len(),
            0
        );
    }

    #[test]
    fn data_doc_scopes_ports_to_the_sandbox() {
        let cfg = EgressPolicyConfig {
            allow: vec![AllowEntry::Host("api.anthropic.com".into())],
        };
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        // global stays empty for a declared --policy.
        assert!(doc["global_domains"].as_object().unwrap().is_empty());
        // bare host → default web ports, scoped under the sandbox.
        assert_eq!(
            doc["sandbox_ports"]["web"]["api.anthropic.com"],
            serde_json::json!([80, 443])
        );
    }

    #[test]
    fn compiled_policy_enforces_ports_and_isolation() {
        let cfg = EgressPolicyConfig {
            allow: vec![
                AllowEntry::Host("api.anthropic.com".into()),
                AllowEntry::Scoped {
                    host: "db.internal".into(),
                    ports: vec![5432],
                },
            ],
        };
        let policy = cfg.into_policy("web").unwrap();
        assert!(policy.enforces(), "a declared policy is a firewall");

        // Bare host on a web port: allowed.
        let mut https = FlowDesc::l3("web", "1.2.3.4", 443);
        https.host = Some("api.anthropic.com".into());
        assert_eq!(policy.check(&https), Verdict::Allow);

        // THE LOOPHOLE, NOW CLOSED: same allowed host, non-web port → deny.
        let mut ssh = FlowDesc::l3("web", "1.2.3.4", 22);
        ssh.host = Some("api.anthropic.com".into());
        assert_eq!(
            policy.check(&ssh),
            Verdict::Deny,
            "bare host must NOT authorize port 22"
        );

        // Scoped host on its declared port: allowed.
        let mut db = FlowDesc::l3("web", "1.2.3.4", 5432);
        db.host = Some("db.internal".into());
        assert_eq!(policy.check(&db), Verdict::Allow);

        // Scoped host on a non-declared port (443): denied — explicit ports REPLACE the default.
        let mut db443 = FlowDesc::l3("web", "1.2.3.4", 443);
        db443.host = Some("db.internal".into());
        assert_eq!(
            policy.check(&db443),
            Verdict::Deny,
            "explicit ports replace the web default"
        );

        // Another sandbox does NOT inherit the grant.
        let mut other = FlowDesc::l3("build", "1.2.3.4", 443);
        other.host = Some("api.anthropic.com".into());
        assert_eq!(policy.check(&other), Verdict::Deny);
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(EgressPolicyConfig::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn load_round_trips_a_written_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            EgressPolicyConfig::path_in(dir.path()),
            "allow:\n  - api.openai.com\n",
        )
        .unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.allow, vec![AllowEntry::Host("api.openai.com".into())]);
    }
}
