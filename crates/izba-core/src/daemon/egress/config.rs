//! Per-sandbox egress policy config (`izba create --policy <file>`). A small
//! YAML allow-list — mirroring the user's `docker-mitm-bridge` `data.yml` —
//! that compiles to the regorus data document the [`RegoPolicy`] evaluates.
//!
//! The file is scoped to ONE sandbox (it is supplied at create time), so its
//! `allow` list becomes that sandbox's `sandbox_host_rules[<name>]` entry in
//! the Rego data doc. A sandbox with no policy file gets an explicit
//! `enforce: false` materialized on first arm — the one-representation
//! invariant that kills the empty-vs-missing-file footgun.
//!
//! Domains are EXACT-match in M2 (the shipped `egress.rego` matches on `in`).
//! Wildcard rules (`*.`/`**.`, see [`super::dns_snoop::allowlist_matches`]) are
//! a planned extension; `from_yaml` accepts them syntactically so a policy
//! written today keeps parsing once enforcement lands.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::audit::EndpointSummary;
use super::policy::{AllowAll, Policy, RegoPolicy, Verdict};

/// On-disk policy file name under the sandbox directory.
pub const POLICY_FILE: &str = "policy.yaml";

/// Read vs full access — the verb shared by HTTP hosts and git repos.
/// HTTP: read = GET/HEAD only; read-write = all methods.
/// Git:  read = clone/fetch; read-write = + push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    Read,
    #[default]
    ReadWrite,
}

fn is_default_access(a: &Access) -> bool {
    *a == Access::ReadWrite
}

/// One entry in a sandbox's egress allow-list: either a bare host (which
/// authorizes the default web ports) or a host scoped to explicit ports/access.
///
/// `#[serde(untagged)]` keeps every existing `allow: [<string>...]` file parsing
/// unchanged — a YAML string deserializes to `Host`, a `{host, ...}` map to
/// `Scoped`. Variant order matters: `Host` is tried first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowEntry {
    /// Bare host → web ports [80, 443], access read-write.
    Host(String),
    /// Host with optional explicit ports (default web) and optional access (default read-write).
    Scoped {
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ports: Option<Vec<u16>>,
        #[serde(default, skip_serializing_if = "is_default_access")]
        access: Access,
    },
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

    /// The ports this entry authorizes: `[80, 443]` for a bare host or when
    /// ports are omitted, else the explicit set (which REPLACES the default).
    pub fn ports(&self) -> Vec<u16> {
        match self {
            AllowEntry::Host(_) => AllowEntry::DEFAULT_PORTS.to_vec(),
            AllowEntry::Scoped { ports, .. } => ports
                .clone()
                .unwrap_or_else(|| AllowEntry::DEFAULT_PORTS.to_vec()),
        }
    }

    /// The access verb for this entry.
    pub fn access(&self) -> Access {
        match self {
            AllowEntry::Host(_) => Access::ReadWrite,
            AllowEntry::Scoped { access, .. } => *access,
        }
    }
}

/// One git rule: a repo/owner glob or a whole-host scope, with an access verb.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GitRule {
    #[serde(flatten)]
    pub target: GitTarget,
    #[serde(default, skip_serializing_if = "is_default_access")]
    pub access: Access,
}

/// `repo:` (host/owner/repo glob) or `host:` (any repo on the host).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitTarget {
    Repo(String),
    Host(String),
}

impl GitTarget {
    /// Parse a CLI/UI target string: a `/` (a host/owner[/repo] path) means a
    /// repo glob; a bare host means the whole-host scope.
    pub fn parse(s: &str) -> Self {
        if s.contains('/') {
            GitTarget::Repo(s.to_string())
        } else {
            GitTarget::Host(s.to_string())
        }
    }

    fn key(&self) -> (&'static str, &str) {
        match self {
            GitTarget::Repo(s) => ("repo", s),
            GitTarget::Host(s) => ("host", s),
        }
    }
}

/// A sandbox's egress policy, parsed from its `--policy` YAML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EgressPolicyConfig {
    /// Explicit posture. Always written by izba (smell: empty-vs-missing). A
    /// present file with no `enforce:` key resolves to `true` (see `from_yaml`).
    pub enforce: bool,
    /// HTTP host allow-list (tier-1 MITM + tier-2 DNS-snoop).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<AllowEntry>,
    /// Git-specific rules (target + access verb).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitRule>,
}

impl<'de> Deserialize<'de> for EgressPolicyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Every deserialization of this type — the izba.yml manifest's
        // `spec.egress` block included — funnels through the same strict
        // walk as `from_yaml`, so an unknown key can never silently widen
        // egress scope on any ingestion path (#138).
        let doc = serde_yaml::Value::deserialize(deserializer)?;
        Self::from_value(&doc).map_err(|e| serde::de::Error::custom(format!("{e:#}")))
    }
}

impl EgressPolicyConfig {
    /// The dedicated build-network policy: enforcing, allow-listing the
    /// Docker Hub hosts the **in-guest `FROM` base-image pull** needs, plus
    /// caller-declared registries/mirrors (`extra_hosts`, from
    /// `izba build --build-allow`). Everything else is denied. Distinct from
    /// a sandbox run policy; never AllowAll. The BuildKit builder image itself
    /// (moby/buildkit) is pulled host-side and is NOT gated by this policy.
    pub fn build_network(extra_hosts: &[String]) -> Self {
        // `registry-1.docker.io` serves manifests + issues the blob redirect;
        // `auth.docker.io` mints the pull bearer token. A blob `GET` 307-redirects
        // to Docker Hub's blob-storage CDN — today an AWS CloudFront distribution
        // (`production.cloudfront.docker.com`, presigned S3 URL), historically the
        // Cloudflare host. We allow-list BOTH: an unlisted redirect target is
        // denied by the MITM (its own 403), which manifests deep in BuildKit as a
        // misleading "403 Forbidden" on the *registry* blob URL. (cloudfront vs
        // cloudflare is a real, easy-to-miss distinction — keep both.)
        const DOCKER_HUB_HOSTS: &[&str] = &[
            "registry-1.docker.io",
            "auth.docker.io",
            "production.cloudfront.docker.com",
            "production.cloudflare.docker.com",
        ];
        let mut allow: Vec<AllowEntry> = DOCKER_HUB_HOSTS
            .iter()
            .map(|h| AllowEntry::Host((*h).to_string()))
            .collect();
        for h in extra_hosts {
            allow.push(AllowEntry::Host(h.clone()));
        }
        Self {
            enforce: true,
            allow,
            git: vec![],
        }
    }

    /// Parse the YAML policy file. An empty/comment-only file is a valid
    /// deny-all — a declared-but-allow-nothing sandbox. A present file without
    /// an explicit `enforce:` key defaults to `enforce: true` (authoring intent).
    ///
    /// Parsed MANUALLY over `serde_yaml::Value`, not via a derived
    /// `Deserialize`: the untagged `AllowEntry` and flattened `GitRule` would
    /// make `#[serde(deny_unknown_fields)]` inert, and a typo'd key silently
    /// falling back to the permissive default is a security footgun (#138).
    /// The manual walk hard-rejects unknown keys at every level and names the
    /// offending field path plus its valid alternatives (#83).
    /// `EgressPolicyConfig`'s `Deserialize` impl (below) delegates to
    /// `from_value` too, so every ingestion path — `policy.yaml` via
    /// `from_yaml`/`load` AND the `izba.yml` manifest's `spec.egress` block —
    /// shares this exact strict walk; only `Serialize` stays derived.
    pub fn from_yaml(s: &str) -> Result<Self> {
        // serde_yaml maps an all-comments/empty document to `null`; treat that
        // as present-but-empty (enforce=true, no rules). Syntax errors keep
        // serde_yaml's "at line N column M" location.
        let doc: serde_yaml::Value =
            serde_yaml::from_str(s).context("parsing egress policy YAML")?;
        Self::from_value(&doc)
    }

    fn from_value(doc: &serde_yaml::Value) -> Result<Self> {
        use serde_yaml::Value;
        let map = match doc {
            Value::Null => {
                return Ok(Self {
                    enforce: true,
                    allow: vec![],
                    git: vec![],
                })
            }
            Value::Mapping(m) => m,
            other => anyhow::bail!(
                "egress policy must be a YAML mapping (valid keys: enforce, allow, git), got {}",
                yaml_kind(other)
            ),
        };
        let mut enforce = None;
        let mut allow = Vec::new();
        let mut git = Vec::new();
        for (k, v) in map {
            match key_str("egress policy", k)?.as_str() {
                // `enforce:` with no value (null) keeps the key-absent default.
                "enforce" if v.is_null() => {}
                "enforce" => enforce = Some(as_bool("enforce", v)?),
                "allow" => {
                    let Value::Sequence(items) = v else {
                        anyhow::bail!("allow: expected a list of entries, got {}", yaml_kind(v));
                    };
                    allow = items
                        .iter()
                        .enumerate()
                        .map(|(i, e)| parse_allow_entry(i, e))
                        .collect::<Result<_>>()?;
                }
                "git" => {
                    let Value::Sequence(items) = v else {
                        anyhow::bail!("git: expected a list of entries, got {}", yaml_kind(v));
                    };
                    git = items
                        .iter()
                        .enumerate()
                        .map(|(i, e)| parse_git_rule(i, e))
                        .collect::<Result<_>>()?;
                }
                other => anyhow::bail!(
                    "unknown key '{other}' in egress policy (valid keys: enforce, allow, git); \
                     see the egress-policy section in README.md"
                ),
            }
        }
        Ok(Self {
            // Present file without `enforce:` → enforce (authoring = intent).
            enforce: enforce.unwrap_or(true),
            allow,
            git,
        })
    }

    /// Toggle enforcement. Returns `true` if the value changed.
    pub fn set_enforce(&mut self, on: bool) -> bool {
        if self.enforce == on {
            false
        } else {
            self.enforce = on;
            true
        }
    }

    /// Set the access verb for `host` (adding the entry if absent). Returns
    /// `true` if the config changed.
    pub fn set_host_access(&mut self, host: &str, access: Access) -> bool {
        if let Some(e) = self.allow.iter_mut().find(|e| e.host() == host) {
            if e.access() == access {
                return false;
            }
            let ports = match e.ports() {
                p if p == AllowEntry::DEFAULT_PORTS.to_vec() => None,
                p => Some(p),
            };
            *e = AllowEntry::Scoped {
                host: host.to_string(),
                ports,
                access,
            };
            true
        } else {
            self.allow.push(AllowEntry::Scoped {
                host: host.to_string(),
                ports: None,
                access,
            });
            true
        }
    }

    /// Upsert a git rule. Returns `true` if added or if the access verb changed.
    pub fn git_allow(&mut self, target: GitTarget, access: Access) -> bool {
        if let Some(r) = self.git.iter_mut().find(|r| r.target == target) {
            if r.access == access {
                return false;
            }
            r.access = access;
            true
        } else {
            self.git.push(GitRule { target, access });
            true
        }
    }

    /// Remove any git rule matching `target`. Returns `true` if one was removed.
    pub fn git_block(&mut self, target: &GitTarget) -> bool {
        let before = self.git.len();
        self.git.retain(|r| &r.target != target);
        self.git.len() != before
    }

    /// The regorus data document for `sandbox`: emits `host_rules` (always
    /// empty — a `--policy` file is scoped to one sandbox), `sandbox_host_rules`
    /// (host → `{ports, access}` per sandbox), `wildcard_host_rules` (always
    /// empty — a `--policy` file is per-sandbox), `sandbox_wildcard_host_rules`
    /// (patterns → `{pattern, ports, access}` per sandbox), and `sandbox_git_rules`
    /// (list of `{repo|host, access}` per sandbox). Hosts are normalized to
    /// ASCII lowercase with trailing dots stripped; wildcard patterns
    /// (`*.` / `**.` prefix) are split into a separate list.
    pub fn to_rego_data_json(&self, sandbox: &str) -> String {
        let mut hosts = serde_json::Map::new();
        let mut wildcards: Vec<serde_json::Value> = Vec::new();
        for e in &self.allow {
            let access = match e.access() {
                Access::Read => "read",
                Access::ReadWrite => "read-write",
            };
            let host = normalize_policy_host(e.host());
            if is_wildcard_host(&host) {
                wildcards.push(
                    serde_json::json!({ "pattern": host, "ports": e.ports(), "access": access }),
                );
            } else {
                hosts.insert(
                    host,
                    serde_json::json!({ "ports": e.ports(), "access": access }),
                );
            }
        }
        let git: Vec<serde_json::Value> = self
            .git
            .iter()
            .map(|r| {
                let (k, v) = r.target.key();
                let access = match r.access {
                    Access::Read => "read",
                    Access::ReadWrite => "read-write",
                };
                serde_json::json!({ k: v, "access": access })
            })
            .collect();
        serde_json::json!({
            "host_rules": {},
            "sandbox_host_rules": { sandbox: hosts },
            "wildcard_host_rules": [],
            "sandbox_wildcard_host_rules": { sandbox: wildcards },
            "sandbox_git_rules": { sandbox: git },
        })
        .to_string()
    }

    /// Compile to a live policy for `sandbox`.
    ///
    /// When `enforce` is `false`, returns an [`AllowAll`] (non-enforcing, bare
    /// sandbox behavior). When `enforce` is `true`, compiles an enforcing
    /// [`RegoPolicy`] — an empty allow-list means deny-all (fail-closed).
    pub fn into_policy(&self, sandbox: &str) -> Result<Arc<dyn Policy>> {
        if !self.enforce {
            return Ok(Arc::new(AllowAll));
        }
        Ok(Arc::new(RegoPolicy::with_data(
            &self.to_rego_data_json(sandbox),
        )?))
    }

    /// The one-representation path: if no `policy.yaml` exists, write an
    /// explicit `enforce: false` (bare sandbox default) and return it.
    /// Otherwise load and return the existing file.
    ///
    /// This kills the empty-vs-missing footgun — after first arm every sandbox
    /// has an explicit `enforce:` on disk, so the posture is always readable
    /// without inferring it from file presence.
    pub fn load_or_materialize(sandbox_dir: &Path) -> Result<Self> {
        match Self::load(sandbox_dir)? {
            Some(cfg) => Ok(cfg),
            None => {
                let cfg = Self {
                    enforce: false,
                    allow: vec![],
                    git: vec![],
                };
                let path = Self::path_in(sandbox_dir);
                std::fs::write(&path, cfg.to_yaml())
                    .with_context(|| format!("writing {}", path.display()))?;
                Ok(cfg)
            }
        }
    }

    /// The policy file path under a sandbox directory.
    pub fn path_in(sandbox_dir: &Path) -> PathBuf {
        sandbox_dir.join(POLICY_FILE)
    }

    /// Persist `self` as `sandbox_dir`'s `policy.yaml`, overwriting any
    /// existing file. Shared by both create paths that seed a policy
    /// programmatically (rather than copying a user-supplied file): the CLI's
    /// `izba build`/`izba create --policy`-less-manifest-egress case
    /// (`izba-cli::commands::persist_policy_config`) and the desktop app's
    /// GUI create path (`seed_manifest_base` in `app/src-tauri/src/
    /// commands.rs`, seeding from a workspace `izba.yml`'s `spec.egress`).
    /// The daemon re-reads `policy.yaml` when it arms the egress plane at
    /// Start, so this must run AFTER Create and BEFORE Start.
    pub fn write_to(&self, sandbox_dir: &Path) -> Result<()> {
        let path = Self::path_in(sandbox_dir);
        std::fs::write(&path, self.to_yaml()).with_context(|| format!("writing {}", path.display()))
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

    /// Ensure `host` authorizes `port`, adding the host and/or the port as
    /// needed. Normalizes the entry to the explicit `Scoped` form. Returns
    /// `true` if the config changed, `false` if `port` was already authorized.
    pub fn allow(&mut self, host: &str, port: u16) -> bool {
        if let Some(entry) = self.allow.iter_mut().find(|e| e.host() == host) {
            let mut ports = entry.ports();
            if ports.contains(&port) {
                return false;
            }
            ports.push(port);
            ports.sort_unstable();
            *entry = AllowEntry::Scoped {
                host: host.to_string(),
                ports: Some(ports),
                access: Access::ReadWrite,
            };
            true
        } else {
            self.allow.push(AllowEntry::Scoped {
                host: host.to_string(),
                ports: Some(vec![port]),
                access: Access::ReadWrite,
            });
            true
        }
    }

    /// Remove `port` from `host`; drop the host entirely once its last port is
    /// gone. Returns `true` if the config changed.
    pub fn block(&mut self, host: &str, port: u16) -> bool {
        let Some(idx) = self.allow.iter().position(|e| e.host() == host) else {
            return false;
        };
        let mut ports = self.allow[idx].ports();
        let before = ports.len();
        ports.retain(|p| *p != port);
        if ports.len() == before {
            return false; // port wasn't authorized
        }
        if ports.is_empty() {
            self.allow.remove(idx);
        } else {
            self.allow[idx] = AllowEntry::Scoped {
                host: host.to_string(),
                ports: Some(ports),
                access: Access::ReadWrite,
            };
        }
        true
    }

    /// Serialize back to canonical `policy.yaml` text (round-trips `from_yaml`).
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("EgressPolicyConfig serializes")
    }
}

/// Normalize a policy-side host or pattern to request-side form: ASCII
/// lowercase + trailing dot stripped. The request side already normalizes
/// (`mitm::normalize_host`, `dns_snoop::normalize`); without this a
/// mixed-case policy entry silently never matches.
fn normalize_policy_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Is this allow-entry host a wildcard pattern (`*.x` / `**.x`)?
fn is_wildcard_host(host: &str) -> bool {
    host.starts_with("*.") || host.starts_with("**.")
}

/// Human name for a YAML value's type, for parse-error messages.
fn yaml_kind(v: &serde_yaml::Value) -> &'static str {
    use serde_yaml::Value;
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a list",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged value",
    }
}

fn key_str(ctx: &str, k: &serde_yaml::Value) -> Result<String> {
    match k {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        other => anyhow::bail!(
            "{ctx}: mapping keys must be strings, got {}",
            yaml_kind(other)
        ),
    }
}

fn as_str(field: &str, v: &serde_yaml::Value) -> Result<String> {
    match v {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        other => anyhow::bail!("{field}: expected a string, got {}", yaml_kind(other)),
    }
}

fn as_bool(field: &str, v: &serde_yaml::Value) -> Result<bool> {
    match v {
        serde_yaml::Value::Bool(b) => Ok(*b),
        other => anyhow::bail!("{field}: expected true or false, got {}", yaml_kind(other)),
    }
}

fn as_port(field: &str, v: &serde_yaml::Value) -> Result<u16> {
    if let serde_yaml::Value::Number(n) = v {
        if let Some(p) = n.as_u64().and_then(|p| u16::try_from(p).ok()) {
            return Ok(p);
        }
    }
    anyhow::bail!(
        "{field}: expected a port number (0-65535), got {}",
        yaml_kind(v)
    )
}

fn parse_ports(field: &str, v: &serde_yaml::Value) -> Result<Vec<u16>> {
    let serde_yaml::Value::Sequence(items) = v else {
        anyhow::bail!(
            "{field}: expected a list of port numbers, got {}",
            yaml_kind(v)
        );
    };
    items
        .iter()
        .enumerate()
        .map(|(j, p)| as_port(&format!("{field}[{j}]"), p))
        .collect()
}

fn parse_access(field: &str, v: &serde_yaml::Value) -> Result<Access> {
    if let serde_yaml::Value::String(s) = v {
        match s.as_str() {
            "read" => return Ok(Access::Read),
            "read-write" => return Ok(Access::ReadWrite),
            other => anyhow::bail!("{field}: expected 'read' or 'read-write', got '{other}'"),
        }
    }
    anyhow::bail!(
        "{field}: expected 'read' or 'read-write', got {}",
        yaml_kind(v)
    )
}

fn parse_allow_entry(i: usize, v: &serde_yaml::Value) -> Result<AllowEntry> {
    use serde_yaml::Value;
    match v {
        // Bare host string → default web ports, read-write.
        Value::String(s) => Ok(AllowEntry::Host(s.clone())),
        Value::Mapping(m) => {
            let mut host = None;
            let mut ports = None;
            let mut access = Access::default();
            for (k, val) in m {
                match key_str(&format!("allow[{i}]"), k)?.as_str() {
                    "host" => host = Some(as_str(&format!("allow[{i}].host"), val)?),
                    "ports" => ports = Some(parse_ports(&format!("allow[{i}].ports"), val)?),
                    "access" => access = parse_access(&format!("allow[{i}].access"), val)?,
                    other => anyhow::bail!(
                        "allow[{i}]: unknown key '{other}' (valid keys: host, ports, access)"
                    ),
                }
            }
            let host =
                host.ok_or_else(|| anyhow::anyhow!("allow[{i}]: missing required key 'host'"))?;
            Ok(AllowEntry::Scoped {
                host,
                ports,
                access,
            })
        }
        other => anyhow::bail!(
            "allow[{i}]: expected a host string or a mapping with keys host, ports, access; \
             got {}",
            yaml_kind(other)
        ),
    }
}

fn parse_git_rule(i: usize, v: &serde_yaml::Value) -> Result<GitRule> {
    use serde_yaml::Value;
    let Value::Mapping(m) = v else {
        anyhow::bail!(
            "git[{i}]: expected a mapping with keys repo (or host) and access, got {}",
            yaml_kind(v)
        );
    };
    let mut target: Option<GitTarget> = None;
    let mut access = Access::default();
    for (k, val) in m {
        let key = key_str(&format!("git[{i}]"), k)?;
        match key.as_str() {
            "repo" | "host" => {
                if target.is_some() {
                    anyhow::bail!("git[{i}]: exactly one of 'repo' or 'host' is required");
                }
                let s = as_str(&format!("git[{i}].{key}"), val)?;
                target = Some(if key == "repo" {
                    GitTarget::Repo(s)
                } else {
                    GitTarget::Host(s)
                });
            }
            "access" => access = parse_access(&format!("git[{i}].access"), val)?,
            other => {
                anyhow::bail!("git[{i}]: unknown key '{other}' (valid keys: repo, host, access)")
            }
        }
    }
    let target = target
        .ok_or_else(|| anyhow::anyhow!("git[{i}]: exactly one of 'repo' or 'host' is required"))?;
    Ok(GitRule { target, access })
}

/// Load a sandbox's policy (or default-empty), apply `f`, persist the result to
/// the sandbox's `policy.yaml`, and return the new config so the caller can
/// decide whether to fire a `ReloadPolicy`.
pub fn edit_policy_file(
    sandbox_dir: &Path,
    f: impl FnOnce(&mut EgressPolicyConfig),
) -> Result<EgressPolicyConfig> {
    let mut cfg = EgressPolicyConfig::load(sandbox_dir)?.unwrap_or_default();
    f(&mut cfg);
    let path = EgressPolicyConfig::path_in(sandbox_dir);
    std::fs::write(&path, cfg.to_yaml()).with_context(|| format!("writing {}", path.display()))?;
    Ok(cfg)
}

impl EgressPolicyConfig {
    /// Additively merge the currently-allowed, named endpoints from `summaries`
    /// into this policy's host allow-list (raw-IP rows skipped — SSRF guard).
    /// Returns the number of host:port pairs newly added. Never removes a rule;
    /// never touches `git` or `enforce`.
    pub fn add_observed_allowed(&mut self, summaries: &[EndpointSummary]) -> usize {
        let mut added = 0;
        for s in summaries {
            if s.verdict != Verdict::Allow {
                continue;
            }
            if let Some(host) = &s.host {
                if self.allow(host, s.port) {
                    added += 1;
                }
            }
        }
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::{FlowDesc, Verdict};

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
                ports: Some(vec![5432]),
                access: Access::ReadWrite,
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
                ports: Some(vec![443, 5000]),
                access: Access::ReadWrite,
            }
        );
    }

    #[test]
    fn allow_entry_round_trips_via_serialize() {
        let entries = vec![
            AllowEntry::Host("api.anthropic.com".into()),
            AllowEntry::Scoped {
                host: "db.internal".into(),
                ports: Some(vec![5432]),
                access: Access::ReadWrite,
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
            enforce: true,
            allow: vec![AllowEntry::Host("api.anthropic.com".into())],
            git: vec![],
        };
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        // host_rules stays empty for a declared --policy.
        assert!(doc["host_rules"].as_object().unwrap().is_empty());
        // bare host → default web ports, scoped under the sandbox.
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["api.anthropic.com"]["ports"],
            serde_json::json!([80, 443])
        );
    }

    // This test exercises the full into_policy() → rego pipeline with the new
    // `sandbox_host_rules`/`sandbox_git_rules` data shape from Task 3.
    #[test]
    fn compiled_policy_enforces_ports_and_isolation() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("api.anthropic.com".into()),
                AllowEntry::Scoped {
                    host: "db.internal".into(),
                    ports: Some(vec![5432]),
                    access: Access::ReadWrite,
                },
            ],
            git: vec![],
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
    fn allow_adds_new_host_as_scoped_single_port() {
        let mut cfg = EgressPolicyConfig::default();
        assert!(cfg.allow("api.x.com", 443));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            }]
        );
        // Idempotent: allowing an already-authorized port is a no-op.
        assert!(!cfg.allow("api.x.com", 443));
    }

    #[test]
    fn allow_extends_existing_host_ports_sorted() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("api.x.com".into())], // {80,443}
            git: vec![],
        };
        assert!(cfg.allow("api.x.com", 8080));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![80, 443, 8080]),
                access: Access::ReadWrite,
            }]
        );
    }

    #[test]
    fn block_removes_port_then_host_when_last() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("api.x.com".into())], // {80,443}
            git: vec![],
        };
        assert!(cfg.block("api.x.com", 443));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![80]),
                access: Access::ReadWrite,
            }]
        );
        assert!(
            cfg.block("api.x.com", 80),
            "removing the last port drops the host"
        );
        assert!(cfg.allow.is_empty());
        assert!(
            !cfg.block("api.x.com", 80),
            "blocking an absent host is a no-op"
        );
    }

    #[test]
    fn to_yaml_round_trips_through_from_yaml() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("api.x.com".into()),
                AllowEntry::Scoped {
                    host: "db.internal".into(),
                    ports: Some(vec![5432]),
                    access: Access::ReadWrite,
                },
            ],
            git: vec![],
        };
        let back = EgressPolicyConfig::from_yaml(&cfg.to_yaml()).unwrap();
        assert_eq!(back, cfg);
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

    /// `write_to` must actually write `path_in(sandbox_dir)` — kills the
    /// `replace write_to -> Ok(())` mutant, which would return success
    /// without writing anything (a silent no-op that `load` would see as
    /// "no policy declared").
    #[test]
    fn write_to_round_trips_through_load() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("api.x.com".into()),
                AllowEntry::Scoped {
                    host: "db.internal".into(),
                    ports: Some(vec![5432]),
                    access: Access::Read,
                },
            ],
            git: vec![],
        };
        cfg.write_to(dir.path()).unwrap();
        assert!(
            EgressPolicyConfig::path_in(dir.path()).exists(),
            "write_to must create policy.yaml"
        );
        let reloaded = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(reloaded, cfg);
    }

    #[test]
    fn edit_policy_file_creates_then_rereads() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = edit_policy_file(dir.path(), |c| {
            c.allow("api.x.com", 443);
        })
        .unwrap();
        assert_eq!(cfg.allow.len(), 1);
        // Persisted + re-readable.
        let reloaded = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(reloaded, cfg);
    }

    // ── NEW GRAMMAR TESTS (Task 1) ────────────────────────────────────────────

    #[test]
    fn parses_host_access_read() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pypi.org\n    access: read\n",
        )
        .unwrap();
        assert!(cfg.enforce);
        assert_eq!(cfg.allow[0].host(), "pypi.org");
        assert_eq!(cfg.allow[0].ports(), vec![80, 443]); // ports omitted -> web defaults
        assert_eq!(cfg.allow[0].access(), Access::Read);
    }

    #[test]
    fn bare_string_host_is_read_write() {
        let cfg = EgressPolicyConfig::from_yaml("allow:\n  - api.anthropic.com\n").unwrap();
        assert_eq!(cfg.allow[0].access(), Access::ReadWrite);
    }

    #[test]
    fn parses_git_block_repo_and_host() {
        let yaml = "git:\n  - repo: github.com/myorg/app\n    access: read-write\n  - host: bitbucket.org\n    access: read\n";
        let cfg = EgressPolicyConfig::from_yaml(yaml).unwrap();
        assert_eq!(
            cfg.git[0],
            GitRule {
                target: GitTarget::Repo("github.com/myorg/app".into()),
                access: Access::ReadWrite
            }
        );
        assert_eq!(
            cfg.git[1],
            GitRule {
                target: GitTarget::Host("bitbucket.org".into()),
                access: Access::Read
            }
        );
    }

    #[test]
    fn present_file_without_enforce_defaults_true() {
        // Authoring a policy signals intent to enforce.
        let cfg = EgressPolicyConfig::from_yaml("allow:\n  - api.x.com\n").unwrap();
        assert!(cfg.enforce);
    }

    #[test]
    fn empty_document_is_enforcing_deny_all() {
        // Empty/comment-only present file = declared deny-all (today's behavior).
        let cfg = EgressPolicyConfig::from_yaml("").unwrap();
        assert!(cfg.enforce);
        assert!(cfg.allow.is_empty() && cfg.git.is_empty());
    }

    #[test]
    fn git_helpers_upsert_and_remove() {
        let mut cfg = EgressPolicyConfig::default();
        assert!(cfg.git_allow(GitTarget::Repo("github.com/o/a".into()), Access::Read));
        assert!(!cfg.git_allow(GitTarget::Repo("github.com/o/a".into()), Access::Read)); // idempotent
        assert!(cfg.git_allow(GitTarget::Repo("github.com/o/a".into()), Access::ReadWrite)); // access change
        assert_eq!(cfg.git[0].access, Access::ReadWrite);
        assert!(cfg.git_block(&GitTarget::Repo("github.com/o/a".into())));
        assert!(cfg.git.is_empty());
    }

    #[test]
    fn set_enforce_and_host_access_report_change() {
        let mut cfg = EgressPolicyConfig {
            enforce: false,
            allow: vec![AllowEntry::Host("pypi.org".into())],
            git: vec![],
        };
        assert!(cfg.set_enforce(true));
        assert!(!cfg.set_enforce(true));
        assert!(cfg.set_host_access("pypi.org", Access::Read));
        assert_eq!(cfg.allow[0].access(), Access::Read);
    }

    #[test]
    fn data_doc_emits_access_and_git() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "pypi.org".into(),
                ports: None,
                access: Access::Read,
            }],
            git: vec![GitRule {
                target: GitTarget::Repo("github.com/o/a".into()),
                access: Access::ReadWrite,
            }],
        };
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert!(doc["host_rules"].as_object().unwrap().is_empty());
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["pypi.org"]["ports"],
            serde_json::json!([80, 443])
        );
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["pypi.org"]["access"],
            "read"
        );
        assert_eq!(doc["sandbox_git_rules"]["web"][0]["repo"], "github.com/o/a");
        assert_eq!(doc["sandbox_git_rules"]["web"][0]["access"], "read-write");
    }

    #[test]
    fn new_grammar_round_trips() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("api.anthropic.com".into()),
                AllowEntry::Scoped {
                    host: "pypi.org".into(),
                    ports: None,
                    access: Access::Read,
                },
            ],
            git: vec![GitRule {
                target: GitTarget::Repo("github.com/o/a".into()),
                access: Access::ReadWrite,
            }],
        };
        let back = EgressPolicyConfig::from_yaml(&cfg.to_yaml()).unwrap();
        assert_eq!(back, cfg);
    }

    // ── TASK 4 TESTS ─────────────────────────────────────────────────────────

    #[test]
    fn enforce_false_is_non_enforcing_allow_all() {
        let cfg = EgressPolicyConfig {
            enforce: false,
            allow: vec![],
            git: vec![],
        };
        let p = cfg.into_policy("web").unwrap();
        assert!(!p.enforces(), "enforce:false -> AllowAll");
        assert_eq!(
            p.check(&FlowDesc::l3("web", "1.2.3.4", 443)),
            Verdict::Allow
        );
    }

    #[test]
    fn enforce_true_is_a_firewall() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("api.x.com".into())],
            git: vec![],
        };
        let p = cfg.into_policy("web").unwrap();
        assert!(p.enforces());
    }

    #[test]
    fn load_missing_backfills_explicit_enforce_false() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EgressPolicyConfig::load_or_materialize(dir.path()).unwrap();
        assert!(!cfg.enforce);
        // File now exists and is explicit.
        let txt = std::fs::read_to_string(EgressPolicyConfig::path_in(dir.path())).unwrap();
        assert!(txt.contains("enforce: false"));
    }

    #[test]
    fn add_observed_allowed_is_additive_and_keeps_git() {
        use crate::daemon::egress::audit::{aggregate, AuditRecord, Tier};
        let mut allowed = AuditRecord::allow(
            "web",
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.x.com"),
            Tier::L7,
            "ok",
        );
        allowed.ts_ms = 100;
        let mut denied = AuditRecord::deny(
            "web",
            "2.2.2.2".parse().unwrap(),
            22,
            Some("evil.com"),
            Tier::L3,
            "no",
        );
        denied.ts_ms = 100;
        let summaries = aggregate(vec![allowed, denied]);

        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("existing.com".into())],
            git: vec![GitRule {
                target: GitTarget::Repo("github.com/o/a".into()),
                access: Access::Read,
            }],
        };
        let added = cfg.add_observed_allowed(&summaries);
        assert_eq!(added, 1, "only the allowed named endpoint is added");
        assert!(
            cfg.allow.iter().any(|e| e.host() == "existing.com"),
            "existing host kept"
        );
        assert!(
            cfg.allow.iter().any(|e| e.host() == "api.x.com"),
            "observed host added"
        );
        assert!(
            !cfg.allow.iter().any(|e| e.host() == "evil.com"),
            "denied not added"
        );
        assert_eq!(cfg.git.len(), 1, "git rules untouched");
        assert!(cfg.enforce, "enforce untouched");
    }

    // ── GitTarget::parse TESTS ────────────────────────────────────────────────

    #[test]
    fn git_target_parse_with_slash_is_repo() {
        assert_eq!(
            GitTarget::parse("github.com/owner/repo"),
            GitTarget::Repo("github.com/owner/repo".into())
        );
    }

    #[test]
    fn git_target_parse_bare_host_is_host() {
        assert_eq!(
            GitTarget::parse("github.com"),
            GitTarget::Host("github.com".into())
        );
    }

    // ── mutation-gap closures ─────────────────────────────────────────────────

    #[test]
    fn default_access_is_omitted_from_serialized_yaml() {
        // `skip_serializing_if = "is_default_access"` must drop the `access:` key
        // for a default (read-write) entry. If `is_default_access` is forced to
        // `false`, the redundant key leaks into every serialized file.
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "db.internal".into(),
                ports: Some(vec![5432]),
                access: Access::ReadWrite,
            }],
            git: vec![],
        };
        assert!(
            !cfg.to_yaml().contains("access"),
            "default read-write access must be omitted, got:\n{}",
            cfg.to_yaml()
        );
        // A non-default access (read) must still serialize.
        let cfg2 = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "db.internal".into(),
                ports: Some(vec![5432]),
                access: Access::Read,
            }],
            git: vec![],
        };
        assert!(
            cfg2.to_yaml().contains("access"),
            "a non-default access must be serialized"
        );
    }

    #[test]
    fn set_host_access_preserves_custom_ports() {
        // Changing only the access verb must NOT clobber a host's custom
        // (non-default) ports. The `ports == DEFAULT_PORTS -> None` normalization
        // must match ONLY the default set: a guard forced to `true` (or `==`→`!=`)
        // would null out [22] and silently widen the host to [80, 443].
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "ssh.internal".into(),
                ports: Some(vec![22]),
                access: Access::ReadWrite,
            }],
            git: vec![],
        };
        assert!(cfg.set_host_access("ssh.internal", Access::Read));
        assert_eq!(
            cfg.allow[0].ports(),
            vec![22],
            "custom ports must survive an access-only change"
        );
        assert_eq!(cfg.allow[0].access(), Access::Read);
    }

    #[test]
    fn set_host_access_normalizes_default_ports_to_none() {
        // A host carrying exactly the default web ports must normalize back to
        // `ports: None` (the canonical default form) on an access change, so the
        // file never pins [80, 443] explicitly. A guard forced to `false` would
        // keep `Some([80, 443])`.
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "web.internal".into(),
                ports: Some(vec![80, 443]),
                access: Access::ReadWrite,
            }],
            git: vec![],
        };
        assert!(cfg.set_host_access("web.internal", Access::Read));
        assert_eq!(
            cfg.allow[0],
            AllowEntry::Scoped {
                host: "web.internal".into(),
                ports: None,
                access: Access::Read,
            },
            "default ports must normalize to None on an access change"
        );
    }

    // ── Task 6: build_network policy tests ───────────────────────────────────

    fn flow_with_host(sandbox: &str, host: &str, port: u16) -> FlowDesc {
        let mut f = FlowDesc::l3(sandbox, host, port);
        f.host = Some(host.into());
        f
    }

    #[test]
    fn build_policy_allows_dockerhub_denies_others() {
        let p = EgressPolicyConfig::build_network(&[])
            .into_policy("builder")
            .unwrap();
        assert!(p.enforces());
        assert_eq!(
            p.check(&flow_with_host("builder", "auth.docker.io", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&flow_with_host("builder", "registry-1.docker.io", 443)),
            Verdict::Allow
        );
        // Blob CDN — the real Docker Hub blob redirect target (CloudFront)
        // plus the historical Cloudflare host. A missing CDN host is the exact
        // bug that 403'd the in-VM `alpine` blob pull.
        assert_eq!(
            p.check(&flow_with_host(
                "builder",
                "production.cloudfront.docker.com",
                443
            )),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&flow_with_host(
                "builder",
                "production.cloudflare.docker.com",
                443
            )),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&flow_with_host("builder", "evil.example.com", 443)),
            Verdict::Deny
        );
    }

    #[test]
    fn build_policy_extra_hosts_allowed() {
        let p = EgressPolicyConfig::build_network(&["mirror.example.com".into()])
            .into_policy("builder")
            .unwrap();
        assert_eq!(
            p.check(&flow_with_host("builder", "mirror.example.com", 443)),
            Verdict::Allow
        );
        assert_eq!(
            p.check(&flow_with_host("builder", "evil.example.com", 443)),
            Verdict::Deny
        );
    }

    // ── Task 2: strict, friendly YAML parsing (#138 + #83) ────────────────────

    fn parse_err(yaml: &str) -> String {
        format!(
            "{:#}",
            EgressPolicyConfig::from_yaml(yaml).expect_err("must reject")
        )
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let msg = parse_err("bad_field: true\n");
        assert!(msg.contains("unknown key 'bad_field'"), "{msg}");
        assert!(msg.contains("enforce, allow, git"), "{msg}");
    }

    #[test]
    fn rejects_non_mapping_top_level_document() {
        let msg = parse_err("- example.com\n");
        assert!(msg.contains("must be a YAML mapping"), "{msg}");
        assert!(msg.contains("enforce, allow, git"), "{msg}");
        assert!(msg.contains("got a list"), "{msg}");
    }

    #[test]
    fn rejects_unknown_allow_entry_key_instead_of_permissive_fallback() {
        // The #138 footgun: `portz` typo used to be silently dropped, widening
        // the entry to the permissive default ports.
        let msg = parse_err("allow:\n  - host: example.com\n    portz: [80]\n");
        assert!(msg.contains("allow[0]"), "{msg}");
        assert!(msg.contains("unknown key 'portz'"), "{msg}");
        assert!(msg.contains("host, ports, access"), "{msg}");
    }

    #[test]
    fn rejects_unknown_git_entry_key_with_valid_alternatives() {
        // The #83 F3b repro: `target:` instead of `repo:`/`host:`.
        let msg = parse_err("git:\n  - target: github.com/foo/bar\n");
        assert!(msg.contains("git[0]"), "{msg}");
        assert!(msg.contains("unknown key 'target'"), "{msg}");
        assert!(msg.contains("repo"), "{msg}");
        assert!(msg.contains("host"), "{msg}");
        assert!(
            !msg.contains("no variant of enum"),
            "raw serde text leaked: {msg}"
        );
    }

    #[test]
    fn rejects_git_entry_with_both_repo_and_host() {
        let msg = parse_err("git:\n  - repo: github.com/foo/bar\n    host: github.com\n");
        assert!(
            msg.contains("git[0]") && msg.contains("exactly one of 'repo' or 'host'"),
            "{msg}"
        );
    }

    #[test]
    fn rejects_git_entry_with_neither_repo_nor_host() {
        let msg = parse_err("git:\n  - access: read\n");
        assert!(
            msg.contains("git[0]") && msg.contains("exactly one of 'repo' or 'host'"),
            "{msg}"
        );
    }

    #[test]
    fn rejects_wrong_type_for_enforce() {
        let msg = parse_err("enforce: \"yes\"\n");
        assert!(
            msg.contains("enforce") && msg.contains("expected true or false"),
            "{msg}"
        );
        assert!(msg.contains("got a string"), "{msg}");
    }

    #[test]
    fn rejects_non_list_ports() {
        let msg = parse_err("allow:\n  - host: example.com\n    ports: 80\n");
        assert!(
            msg.contains("allow[0].ports") && msg.contains("expected a list"),
            "{msg}"
        );
    }

    #[test]
    fn rejects_bad_access_value() {
        let msg = parse_err("allow:\n  - host: example.com\n    access: rw\n");
        assert!(msg.contains("allow[0].access"), "{msg}");
        assert!(msg.contains("'read' or 'read-write'"), "{msg}");
    }

    #[test]
    fn rejects_scoped_allow_entry_without_host() {
        let msg = parse_err("allow:\n  - ports: [80]\n");
        assert!(msg.contains("allow[0]") && msg.contains("'host'"), "{msg}");
    }

    #[test]
    fn error_text_never_leaks_serde_internals() {
        for bad in [
            "git:\n  - target: x\n",
            "allow:\n  - host: h\n    portz: [80]\n",
            "bad_field: true\n",
            "allow: 5\n",
            "git: {}\n",
        ] {
            let msg = parse_err(bad);
            for leak in [
                "no variant of enum",
                "untagged enum",
                "flattened data",
                "RawConfig",
            ] {
                assert!(!msg.contains(leak), "input {bad:?} leaked {leak:?}: {msg}");
            }
        }
    }

    #[test]
    fn explicit_null_enforce_still_defaults_true() {
        // `enforce:` with no value parsed as enforce=true before; preserve it.
        let cfg = EgressPolicyConfig::from_yaml("enforce:\nallow:\n  - example.com\n").unwrap();
        assert!(cfg.enforce);
    }

    // ── Task 2: Wildcard splitting + normalization ───────────────────────────

    #[test]
    fn data_doc_splits_wildcards_from_exact_hosts() {
        let cfg = EgressPolicyConfig::from_yaml(
            "allow:\n  - api.example.com\n  - '*.internal.corp'\n  - host: '**.deep.corp'\n    ports: [8443]\n    access: read\n",
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        // Exact host stays in the map; wildcards move to the list.
        assert!(doc["sandbox_host_rules"]["web"]["api.example.com"].is_object());
        assert!(doc["sandbox_host_rules"]["web"]
            .get("*.internal.corp")
            .is_none());
        let wc = doc["sandbox_wildcard_host_rules"]["web"]
            .as_array()
            .unwrap();
        assert_eq!(wc.len(), 2);
        assert_eq!(wc[0]["pattern"], "*.internal.corp");
        assert_eq!(wc[1]["pattern"], "**.deep.corp");
        assert_eq!(wc[1]["ports"], serde_json::json!([8443]));
        assert_eq!(wc[1]["access"], "read");
        // The global wildcard list exists (empty — a --policy file is per-sandbox).
        assert!(doc["wildcard_host_rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn data_doc_normalizes_case_and_trailing_dot() {
        let cfg =
            EgressPolicyConfig::from_yaml("allow:\n  - API.Example.com.\n  - '*.Internal.CORP.'\n")
                .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert!(
            doc["sandbox_host_rules"]["web"]["api.example.com"].is_object(),
            "policy-side hosts must be lowercased + trailing-dot-stripped to match the normalized request side"
        );
        let wc = doc["sandbox_wildcard_host_rules"]["web"]
            .as_array()
            .unwrap();
        assert_eq!(wc[0]["pattern"], "*.internal.corp");
    }

    /// End-to-end through the real pipeline: YAML -> data doc -> Rego -> verdict.
    #[test]
    fn wildcard_yaml_policy_enforces_end_to_end() {
        let cfg = EgressPolicyConfig::from_yaml("enforce: true\nallow:\n  - '*.internal.corp'\n")
            .unwrap();
        let p = cfg.into_policy("web").unwrap();
        let l7 = |host: &str| FlowDesc {
            sandbox: "web".into(),
            addr: host.into(),
            port: 443,
            host: Some(host.into()),
            method: Some("GET".into()),
            path: None,
            query: None,
        };
        assert_eq!(p.check(&l7("api.internal.corp")), Verdict::Allow);
        assert_eq!(
            p.check(&l7("internal.corp")),
            Verdict::Deny,
            "apex not matched"
        );
        assert_eq!(
            p.check(&l7("a.b.internal.corp")),
            Verdict::Deny,
            "one label only"
        );
    }

    /// Regression for the pre-existing footgun: a mixed-case exact host in
    /// policy.yaml now matches the (lowercased) request host.
    #[test]
    fn mixed_case_exact_host_matches_after_normalization() {
        let cfg =
            EgressPolicyConfig::from_yaml("enforce: true\nallow:\n  - API.Example.com\n").unwrap();
        let p = cfg.into_policy("web").unwrap();
        let f = FlowDesc {
            sandbox: "web".into(),
            addr: "api.example.com".into(),
            port: 443,
            host: Some("api.example.com".into()),
            method: Some("GET".into()),
            path: None,
            query: None,
        };
        assert_eq!(p.check(&f), Verdict::Allow);
    }
}
