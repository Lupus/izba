//! Per-sandbox egress policy config (`izba create --policy <file>`). A small
//! YAML allow-list — mirroring the user's `docker-mitm-bridge` `data.yml` —
//! that compiles to the regorus data document the [`RegoPolicy`] evaluates.
//!
//! The file is scoped to ONE sandbox (it is supplied at create time), so its
//! `allow` list becomes that sandbox's `sandbox_domains[<name>]` entry in the
//! Rego data doc. A sandbox with no policy file stays a bare, non-enforcing
//! [`AllowAll`](super::policy::AllowAll) — today's permissive behavior.
//!
//! Domains are EXACT-match in M2 (the shipped `egress.rego` matches on `in`).
//! Wildcard rules (`*.`/`**.`, see [`super::dns_snoop::allowlist_matches`]) are
//! a planned extension; `from_yaml` accepts them syntactically so a policy
//! written today keeps parsing once enforcement lands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::policy::RegoPolicy;

/// On-disk policy file name under the sandbox directory.
pub const POLICY_FILE: &str = "policy.yaml";

/// A sandbox's egress allow-list, parsed from its `--policy` YAML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct EgressPolicyConfig {
    /// Destinations this sandbox may reach (HTTP host for tier-1, DNS-snoop
    /// FQDN for tier-2). Exact-match in M2.
    #[serde(default)]
    pub allow: Vec<String>,
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
    /// sandbox's per-sandbox domains (global stays empty — a `--policy` file is
    /// scoped to one sandbox, never granted to others).
    pub fn to_rego_data_json(&self, sandbox: &str) -> String {
        serde_json::json!({
            "global_domains": [],
            "sandbox_domains": { sandbox: self.allow },
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
    fn parses_allow_list() {
        let cfg = EgressPolicyConfig::from_yaml("allow:\n  - api.anthropic.com\n  - github.com\n")
            .unwrap();
        assert_eq!(cfg.allow, vec!["api.anthropic.com", "github.com"]);
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
    fn data_doc_scopes_domains_to_the_sandbox() {
        let cfg = EgressPolicyConfig {
            allow: vec!["api.anthropic.com".into()],
        };
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert_eq!(doc["global_domains"].as_array().unwrap().len(), 0);
        assert_eq!(doc["sandbox_domains"]["web"][0], "api.anthropic.com");
    }

    #[test]
    fn compiled_policy_enforces_the_allow_list() {
        let cfg = EgressPolicyConfig {
            allow: vec!["api.anthropic.com".into()],
        };
        let policy = cfg.into_policy("web").unwrap();
        assert!(policy.enforces(), "a declared policy is a firewall");

        // The sandbox it was scoped to may reach the listed host...
        let mut allowed = FlowDesc::l3("web", "1.2.3.4", 443);
        allowed.host = Some("api.anthropic.com".into());
        assert_eq!(policy.check(&allowed), Verdict::Allow);

        // ...an unlisted host is denied...
        let mut denied = FlowDesc::l3("web", "1.2.3.4", 443);
        denied.host = Some("evil.example.com".into());
        assert_eq!(policy.check(&denied), Verdict::Deny);

        // ...and another sandbox does NOT inherit the grant.
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
        assert_eq!(cfg.allow, vec!["api.openai.com"]);
    }
}
