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
//! Host matching supports exact names plus Cilium-style wildcards (`*.x` =
//! exactly one extra label, `**.x` = any depth; the apex itself never matches
//! a wildcard). Wildcards compile to `wildcard_host_rules` in the Rego data
//! doc and are matched by `glob.match` in `egress.rego`; malformed patterns
//! are rejected loudly by [`validate_host_pattern`].

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

/// The **inspectability axis** (M5 spec D2): whether izbad may terminate and
/// police this destination at L7, or must splice it opaquely.
///
/// Orthogonal to reachability (`allow`) and, from P2, to injectability: each
/// axis strictly narrows the one above it, and no axis is ever derived from
/// another (D1). Consumed in Rust at the router's tier-1 gate — it is NEVER
/// compiled into the Rego data document (D6), so `to_rego_data_json` must stay
/// byte-identical whether or not an entry declares one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP semantics: tier-1 MITM applies, so method/path rules — and, from
    /// P2, credential injection — are possible here.
    Http,
    /// Opaque TCP: tier-2 splice, no L7 visibility, never injectable. Declared
    /// EXPLICITLY on a web port this is the documented pinning hatch (§5.2).
    Tcp,
}

/// One entry in a sandbox's egress allow-list: either a bare host (which
/// authorizes the default web ports) or a host scoped to explicit ports/access.
///
/// `#[serde(untagged)]` keeps every existing `allow: [<string>...]` file
/// WRITING unchanged — `Host` serializes as a bare YAML string, `Scoped` as a
/// `{host, ...}` map. Deserialize is NOT derived (see the manual `impl`
/// below): it funnels through `parse_allow_entry` instead, for the same
/// reason `EgressPolicyConfig`'s own `Deserialize` does (#138) — a derived
/// untagged deserialize would accept `protocol: tcp` on a wildcard host (DP-3
/// forbids it) and any unknown key, on ANY ingestion path that deserializes a
/// bare `AllowEntry`/`Vec<AllowEntry>` directly (e.g. the GUI's
/// `serde_json::from_value::<Vec<AllowEntry>>`), not just the YAML walk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        /// The declared inspectability, or `None` for "derive from the port".
        /// Stored as an `Option` on purpose: only an EXPLICIT `Some(Tcp)` opens
        /// the pinning passthrough, so a value derived from a port number can
        /// never turn inspection off (D12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<Protocol>,
    },
}

impl<'de> Deserialize<'de> for AllowEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Every deserialization of a bare `AllowEntry` funnels through the
        // same strict walk `EgressPolicyConfig::from_value` uses for a whole
        // `allow:` list, so DP-3's wildcard/`protocol: tcp` refusal and the
        // unknown-key rejection hold on every ingestion path, not just YAML
        // files (#138). `parse_allow_entry` prefixes every error with a
        // caller-supplied context label; a bare `AllowEntry` (this impl) has
        // no list position of its own, so it uses the honest synthetic label
        // `"allow entry"` rather than a fabricated `allow[0]` that would
        // misreport WHICH element of a caller's list was bad — e.g. the GUI
        // deserializing a whole `Vec<AllowEntry>` calls this impl once per
        // element, and a synthetic `allow[0]` would have named the wrong one
        // for every element but the first (#NEW-3). Callers that DO parse a
        // whole list — `EgressPolicyConfig::from_value` — call
        // `parse_allow_entry` directly with the real `"allow[{i}]"` label
        // instead of going through this impl, so their error messages are
        // unaffected.
        let doc = serde_yaml::Value::deserialize(deserializer)?;
        parse_allow_entry("allow entry", &doc)
            .map_err(|e| serde::de::Error::custom(format!("{e:#}")))
    }
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

    /// The inspectability the operator wrote, if any. `None` means the entry
    /// says nothing and the effective value is derived per port.
    pub fn declared_protocol(&self) -> Option<Protocol> {
        match self {
            AllowEntry::Host(_) => None,
            AllowEntry::Scoped { protocol, .. } => *protocol,
        }
    }

    /// Effective inspectability for `port`: the declared value when there is
    /// one, else `http` on the default web ports and `tcp` anywhere else.
    ///
    /// Takes any `u16` with NO membership check against `self.ports()` —
    /// reachability is a separate axis, decided by Rego (D1), not by this
    /// method. The caller is responsible for having already established that
    /// `port` is one this entry actually authorizes; calling this on a port
    /// the entry does not list still answers (derived `tcp` off the default
    /// web ports), it just answers a question nobody should be asking yet.
    ///
    /// Derivation is per-PORT, not per-entry, so `ports: [443, 5432]` is
    /// inspected on 443 and spliced on 5432 with nothing declared — the entry
    /// never has to carry one answer for two different kinds of port.
    pub fn protocol_for(&self, port: u16) -> Protocol {
        self.declared_protocol().unwrap_or({
            if Self::DEFAULT_PORTS.contains(&port) {
                Protocol::Http
            } else {
                Protocol::Tcp
            }
        })
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
                        .map(|(i, e)| parse_allow_entry(&format!("allow[{i}]"), e))
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

    /// The union-direction fold for a wildcard-hosted group's declared
    /// `protocol`, shared by `collapse_duplicate_hosts`'s wildcard-union
    /// collapse and `set_host_access`'s mixed-access wildcard merge (review
    /// NEW-1: the two must agree, since both fold the SAME kind of group).
    /// `Some(Http)` if ANY entry named by `idxs` declares it, else `None`.
    ///
    /// Written so it is STRUCTURALLY incapable of producing `Some(Tcp)`
    /// (review NEW-2) rather than merely relying on DP-3 having refused
    /// `tcp` on a wildcard host at parse time: `AllowEntry::Scoped`'s fields
    /// are public, so a wildcard-hosted `Some(Tcp)` is constructible in Rust
    /// regardless of what any parser enforces, and this fold can only ever
    /// answer `Some(Http)` or `None` — never propagate a `Some(Tcp)` it
    /// happened to see on an input entry.
    fn union_wildcard_protocol(&self, idxs: &[usize]) -> Option<Protocol> {
        idxs.iter()
            .any(|&i| self.allow[i].declared_protocol() == Some(Protocol::Http))
            .then_some(Protocol::Http)
    }

    /// Collapse normalize-equal duplicate entries in `self.allow`. A legacy
    /// or hand-edited `policy.yaml` can carry case-/trailing-dot-equivalent
    /// duplicates (e.g. `api.x.com` + `API.X.COM`); before this pass,
    /// `allow`/`block`/`set_host_access` matched only the FIRST such entry
    /// while compilation could enforce a DIFFERENT one — so an edit could
    /// "succeed" on an entry that was never the one in force. Calling this at
    /// the top of every mutation means the entries a caller finds and edits
    /// are always the ones that already win at compile time, so it can never
    /// change enforcement semantics on its own.
    ///
    /// `to_rego_data_json` compiles the two entry kinds very differently, so
    /// this pass treats them differently too:
    ///
    /// - **Exact hosts** compile into `sandbox_host_rules`, a JSON MAP keyed
    ///   by normalized host — a later entry's whole `{ports, access}`
    ///   OVERWRITES an earlier one under the same key. So duplicates
    ///   genuinely collapse with LAST-WINS semantics: the surviving entry
    ///   lands at the FIRST duplicate's position (host normalized), carrying
    ///   the LAST duplicate's ports/access/spelling; every other duplicate is
    ///   dropped.
    /// - **Wildcard hosts** (`is_wildcard_host`) compile into
    ///   `sandbox_wildcard_host_rules`, a JSON LIST — every matching rule
    ///   grants independently (UNION semantics), never overwritten.
    ///   Collapsing wildcard duplicates with last-wins would silently delete
    ///   real, still-enforced grants (e.g. `[*.x rw ports:[443], *.X read
    ///   ports:[8443]]` enforces BOTH 443 read-write AND 8443 read; last-wins
    ///   would keep only one). So wildcard duplicates only collapse when
    ///   EVERY one of them shares the same access verb — merging into one
    ///   entry with the union of ports is then exactly semantics-preserving.
    ///   When access verbs are mixed, no single `AllowEntry` can represent
    ///   the per-port access split, so they are left as separate entries
    ///   entirely untouched; `allow`/`block`/`set_host_access` below handle
    ///   multiple equivalent wildcard entries directly.
    ///
    /// Non-duplicated entries and overall list order are otherwise untouched.
    fn collapse_duplicate_hosts(&mut self) {
        use std::collections::HashMap;

        let mut indices_by_key: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in self.allow.iter().enumerate() {
            indices_by_key
                .entry(normalize_policy_host(e.host()))
                .or_default()
                .push(i);
        }
        if indices_by_key.values().all(|idxs| idxs.len() <= 1) {
            return; // common case: no duplicates, nothing to do
        }

        let mut drop: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut winners: Vec<(usize, AllowEntry)> = Vec::new();
        for (key, idxs) in &indices_by_key {
            if idxs.len() <= 1 {
                continue;
            }
            if is_wildcard_host(key) {
                let first_access = self.allow[idxs[0]].access();
                let uniform = idxs.iter().all(|&i| self.allow[i].access() == first_access);
                if !uniform {
                    // Mixed access verbs: leave every duplicate as-is, they
                    // each still enforce their own ports independently.
                    continue;
                }
                let mut ports: Vec<u16> =
                    idxs.iter().flat_map(|&i| self.allow[i].ports()).collect();
                ports.sort_unstable();
                ports.dedup();
                // Union direction, mirroring how ports/access already union
                // rather than pick an arbitrary single duplicate: silently
                // dropping a declared `Http` here would be exactly the
                // `⚠ weakens egress` transition the spec calls out, performed
                // with no flag by a routine collapse.
                let protocol = self.union_wildcard_protocol(idxs);
                winners.push((
                    idxs[0],
                    AllowEntry::Scoped {
                        host: key.clone(),
                        ports: Some(ports),
                        access: first_access,
                        protocol,
                    },
                ));
                drop.extend(idxs.iter().skip(1).copied());
                continue;
            }
            let first = idxs[0];
            let last = *idxs.last().expect("idxs.len() > 1");
            let winner = match &self.allow[last] {
                AllowEntry::Host(_) => AllowEntry::Host(key.clone()),
                AllowEntry::Scoped {
                    ports,
                    access,
                    protocol,
                    ..
                } => AllowEntry::Scoped {
                    host: key.clone(),
                    ports: ports.clone(),
                    access: *access,
                    protocol: *protocol,
                },
            };
            winners.push((first, winner));
            drop.extend(idxs.iter().skip(1).copied());
        }
        for (idx, winner) in winners {
            self.allow[idx] = winner;
        }
        let mut i = 0;
        self.allow.retain(|_| {
            let keep = !drop.contains(&i);
            i += 1;
            keep
        });
    }

    /// Wholesale-replace `self.allow` with `allow` -- the entry point for
    /// callers that hold a full replacement list (the GUI policy editor,
    /// which lets a user free-edit the whole allow-list at once rather than
    /// mutating one host at a time).
    ///
    /// Contract: the persisted list is canonical-spelled and duplicate-free
    /// for exact hosts (normalize-equal exact-host entries collapse
    /// last-wins, exactly like every other mutation method), and wildcard
    /// union semantics are preserved (uniform-access wildcard duplicates
    /// merge into one ports-union entry; mixed-access duplicates are left as
    /// separate entries, each still enforcing its own ports independently --
    /// see `collapse_duplicate_hosts`). Every entry's host spelling is
    /// canonicalized via `normalize_policy_host` before the collapse pass
    /// runs, so hand-typed or GUI-pasted spelling variants collapse exactly
    /// like they would if entered one at a time through `allow`/`block`/
    /// `set_host_access`.
    pub fn replace_allow(&mut self, allow: Vec<AllowEntry>) {
        self.allow = allow;
        for e in &mut self.allow {
            match e {
                AllowEntry::Host(host) => *host = normalize_policy_host(host),
                AllowEntry::Scoped { host, .. } => *host = normalize_policy_host(host),
            }
        }
        self.collapse_duplicate_hosts();
    }

    /// All allow-list entries whose host is normalize-equal to `host`, keyed
    /// by the same `normalize_policy_host` identity the mutation methods use
    /// — so a caller echoing post-edit state (e.g. the CLI's access-grant
    /// echo, #149) sees exactly the entry a mutation just touched, under any
    /// spelling of the host. A mixed-access wildcard host legitimately keeps
    /// multiple normalize-equal entries (see `collapse_duplicate_hosts`);
    /// all of them are returned.
    pub fn entries_for_host(&self, host: &str) -> Vec<&AllowEntry> {
        let normalized = normalize_policy_host(host);
        self.allow
            .iter()
            .filter(|e| normalize_policy_host(e.host()) == normalized)
            .collect()
    }

    /// Set the access verb for `host` (adding the entry if absent). Returns
    /// `true` if the config changed.
    ///
    /// A wildcard host can carry multiple normalize-equal entries with mixed
    /// access verbs after `collapse_duplicate_hosts` (they enforce a union
    /// and can't be merged automatically — see that method's doc). Setting a
    /// SINGLE access verb here removes the reason they were kept separate,
    /// so every equivalent entry is set to `access` and then merged into one
    /// entry carrying the union of their ports — exactly what
    /// `collapse_duplicate_hosts` would already do for duplicates that
    /// shared an access verb. An exact host always has at most one matching
    /// entry after the collapse, so this reduces to a plain single-entry
    /// rewrite there, unchanged from before.
    pub fn set_host_access(&mut self, host: &str, access: Access) -> bool {
        self.collapse_duplicate_hosts();
        let normalized = normalize_policy_host(host);
        let idxs: Vec<usize> = self
            .allow
            .iter()
            .enumerate()
            .filter(|(_, e)| normalize_policy_host(e.host()) == normalized)
            .map(|(i, _)| i)
            .collect();

        if idxs.is_empty() {
            self.allow.push(AllowEntry::Scoped {
                host: normalized,
                ports: None,
                access,
                protocol: None,
            });
            return true;
        }
        if idxs.iter().all(|&i| self.allow[i].access() == access) {
            return false;
        }

        let mut ports: Vec<u16> = idxs.iter().flat_map(|&i| self.allow[i].ports()).collect();
        ports.sort_unstable();
        ports.dedup();
        let ports = match ports {
            p if p == AllowEntry::DEFAULT_PORTS.to_vec() => None,
            p => Some(p),
        };

        // This rewrite serves TWO shapes through one path (review NEW-1),
        // and each needs its own fold to agree with how
        // `collapse_duplicate_hosts` already treats the SAME situation:
        //  - An exact host always has exactly one entry in `idxs` after the
        //    `collapse_duplicate_hosts()` call above, so "last" and "only"
        //    coincide; this mirrors `to_rego_data_json`'s map-overwrite
        //    semantics for exact hosts — take the LAST normalize-equal
        //    entry's declaration, whatever it is (including `None` even if
        //    an earlier duplicate declared something).
        //  - A wildcard host can still carry MULTIPLE mixed-access
        //    duplicates here — `collapse_duplicate_hosts` deliberately
        //    leaves those separate (see its doc), and unifying the access
        //    verb below removes that reason, so this call merges them.
        //    Last-wins would silently drop a `protocol` declared on any
        //    duplicate but the last one, exactly the finding-1 defect this
        //    round exists to close; use the same union fold
        //    `collapse_duplicate_hosts`'s wildcard branch uses instead.
        let protocol = if is_wildcard_host(&normalized) {
            self.union_wildcard_protocol(&idxs)
        } else {
            self.allow[*idxs.last().expect("idxs is non-empty here")].declared_protocol()
        };
        let first = idxs[0];
        self.allow[first] = AllowEntry::Scoped {
            host: normalized,
            ports,
            access,
            protocol,
        };
        let drop: std::collections::HashSet<usize> = idxs[1..].iter().copied().collect();
        let mut i = 0;
        self.allow.retain(|_| {
            let keep = !drop.contains(&i);
            i += 1;
            keep
        });
        true
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
    ///
    /// A wildcard host's normalize-equal entries enforce a UNION (see
    /// `collapse_duplicate_hosts`), so a port counts as already authorized if
    /// ANY equivalent entry lists it, regardless of that entry's access
    /// verb — an exact host always has at most one matching entry after the
    /// collapse, so this reduces to the prior single-entry check there.
    ///
    /// KNOWN SHARP EDGE: a declared `protocol` is stored per-ENTRY while the
    /// `protocol: tcp` pinning hatch is semantically per-PORT
    /// (`protocol_for`), so preserving the entry's declaration here (rather
    /// than dropping it — see the sibling `block`/`set_host_access` fix for
    /// why dropping is the worse failure) extends an existing `Some(Tcp)`
    /// pin to the newly-added port too, even though the operator only named
    /// it for the ports that existed when they wrote it. Resolving that
    /// needs a per-port declaration shape, which is its own change (out of
    /// scope here; tracked in the plan's spec §13 follow-up list, not only
    /// here). This is the lesser evil: silent deletion of a declaration is
    /// invisible everywhere, whereas this call mutates `policy.yaml`
    /// directly and never passes the `izba.yml` diff/promote weakening gate
    /// — `izba policy show` (once it lands) is the only surface that reveals
    /// the widened hatch, so "lesser evil" is a narrower claim than "loud
    /// everywhere that matters".
    pub fn allow(&mut self, host: &str, port: u16) -> bool {
        self.collapse_duplicate_hosts();
        let normalized = normalize_policy_host(host);
        let already_granted = self
            .allow
            .iter()
            .filter(|e| normalize_policy_host(e.host()) == normalized)
            .any(|e| e.ports().contains(&port));
        if already_granted {
            return false;
        }
        if let Some(entry) = self
            .allow
            .iter_mut()
            .find(|e| normalize_policy_host(e.host()) == normalized)
        {
            let mut ports = entry.ports();
            ports.push(port);
            ports.sort_unstable();
            let access = entry.access();
            let protocol = entry.declared_protocol();
            *entry = AllowEntry::Scoped {
                host: normalized,
                ports: Some(ports),
                access,
                protocol,
            };
            true
        } else {
            self.allow.push(AllowEntry::Scoped {
                host: normalized,
                ports: Some(vec![port]),
                access: Access::ReadWrite,
                protocol: None,
            });
            true
        }
    }

    /// Remove `port` from `host`; drop the host entirely once its last port is
    /// gone. Returns `true` if the config changed.
    ///
    /// A wildcard host's normalize-equal entries enforce a UNION (see
    /// `collapse_duplicate_hosts`), so a grant only truly disappears once NO
    /// equivalent entry keeps the port — the port is removed from EVERY
    /// matching entry that actually carries it, and any entry left with no
    /// ports is dropped. An exact host always has at most one matching entry
    /// after the collapse, so this reduces to the prior single-entry
    /// behavior there. A matching entry that never carried `port` is left
    /// COMPLETELY untouched (spelling included) — `false` means zero
    /// mutation, not just "no net-visible change".
    pub fn block(&mut self, host: &str, port: u16) -> bool {
        self.collapse_duplicate_hosts();
        let normalized = normalize_policy_host(host);
        let mut changed = false;
        for e in &mut self.allow {
            if normalize_policy_host(e.host()) != normalized {
                continue;
            }
            let mut ports = e.ports();
            if !ports.contains(&port) {
                // This entry never granted `port` -- leave it COMPLETELY
                // untouched (including its original host spelling). A
                // no-op `block` must mutate nothing, matching the
                // changed-bool contract: `false` means zero state change.
                continue;
            }
            ports.retain(|p| *p != port);
            changed = true;
            let access = e.access();
            let protocol = e.declared_protocol();
            *e = AllowEntry::Scoped {
                host: normalized.clone(),
                ports: Some(ports),
                access,
                protocol,
            };
        }
        if changed {
            self.allow.retain(|e| {
                !(normalize_policy_host(e.host()) == normalized && e.ports().is_empty())
            });
        }
        changed
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
///
/// `pub(crate)` (not `pub`, not private): `manifest::diff` keys its
/// proposed-vs-persisted comparison by this same identity function, so its
/// keying can never silently drift from the mutation/compile identity used
/// here and in `to_rego_data_json`. External callers never call this
/// directly -- they go through the mutation methods (`allow`, `block`,
/// `set_host_access`, `replace_allow`), which normalize as part of their
/// documented contract.
pub(crate) fn normalize_policy_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Is this allow-entry host a wildcard pattern (`*.x` / `**.x`)?
///
/// `pub(crate)` so `manifest::diff` classifies entries into the same two
/// compile targets (`sandbox_host_rules` map vs `sandbox_wildcard_host_rules`
/// list) that `to_rego_data_json` uses — the fold semantics differ (#172).
pub(crate) fn is_wildcard_host(host: &str) -> bool {
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

fn parse_protocol(field: &str, v: &serde_yaml::Value) -> Result<Protocol> {
    if let serde_yaml::Value::String(s) = v {
        match s.as_str() {
            "http" => return Ok(Protocol::Http),
            "tcp" => return Ok(Protocol::Tcp),
            other => anyhow::bail!("{field}: expected 'http' or 'tcp', got '{other}'"),
        }
    }
    anyhow::bail!("{field}: expected 'http' or 'tcp', got {}", yaml_kind(v))
}

/// `ctx` is the field-path label used to prefix every error message this
/// parses raises (`"allow[3]"` from a real `allow:` list position, or an
/// honest synthetic label like `"allow entry"` when there is no list
/// position to report — see the `AllowEntry::Deserialize` impl above). The
/// YAML walk (`EgressPolicyConfig::from_value`) always passes the real
/// `"allow[{i}]"`, so its error strings are byte-identical to before this was
/// a label instead of an index (#NEW-3).
fn parse_allow_entry(ctx: &str, v: &serde_yaml::Value) -> Result<AllowEntry> {
    use serde_yaml::Value;
    match v {
        // Bare host string → default web ports, read-write.
        Value::String(s) => {
            validate_host_pattern(s).with_context(|| ctx.to_string())?;
            Ok(AllowEntry::Host(s.clone()))
        }
        Value::Mapping(m) => {
            let mut host = None;
            let mut ports = None;
            let mut access = Access::default();
            let mut protocol = None;
            for (k, val) in m {
                match key_str(ctx, k)?.as_str() {
                    "host" => host = Some(as_str(&format!("{ctx}.host"), val)?),
                    "ports" => ports = Some(parse_ports(&format!("{ctx}.ports"), val)?),
                    "access" => access = parse_access(&format!("{ctx}.access"), val)?,
                    "protocol" => protocol = Some(parse_protocol(&format!("{ctx}.protocol"), val)?),
                    other => anyhow::bail!(
                        "{ctx}: unknown key '{other}' \
                         (valid keys: host, ports, access, protocol)"
                    ),
                }
            }
            let host = host.ok_or_else(|| anyhow::anyhow!("{ctx}: missing required key 'host'"))?;
            validate_host_pattern(&host).with_context(|| ctx.to_string())?;
            // DP-3: the pinning hatch is keyed on the observed SNI, matched
            // EXACTLY. Honouring it for a wildcard would mean a second
            // implementation of the wildcard semantics that live in
            // egress.rego, and a divergence between the two is exactly the
            // shape of a security bug. Refuse, and name the fix.
            if protocol == Some(Protocol::Tcp) && is_wildcard_host(&normalize_policy_host(&host)) {
                anyhow::bail!(
                    "{ctx}: 'protocol: tcp' (the TLS-pinning passthrough) needs an exact \
                     host, but '{host}' is a wildcard pattern — the hatch is matched against the \
                     observed ClientHello SNI. Name each pinned host explicitly."
                );
            }
            Ok(AllowEntry::Scoped {
                host,
                ports,
                access,
                protocol,
            })
        }
        other => anyhow::bail!(
            "{ctx}: expected a host string or a mapping with keys host, ports, access, \
             protocol; got {}",
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

/// Validate an allow-entry host: an exact hostname (no `*`) or a wildcard
/// with `*.` (one label) / `**.` (any depth) as the LEADING label only.
/// Anything else fails loudly — under M2 a malformed pattern was accepted
/// and silently never matched, which is a security footgun.
///
/// For WILDCARD patterns only, the remainder after the `*.`/`**.` prefix is
/// further restricted to ASCII alphanumerics, `-`, `.`, and `_`: wildcard
/// patterns are fed verbatim to regorus `glob.match` (the `wax` engine),
/// which treats `{}`, `[]`, `?`, `<>` (and more) as glob metacharacters —
/// e.g. `*.git{hub.com,evil.com}` would otherwise validate as a well-formed
/// wildcard yet actually match far more than intended (`api.gitevil.com`),
/// silently widening egress. EXACT hosts (no `*` anywhere) are UNCHANGED by
/// this: they are matched by literal map-key equality, never globbed, and
/// may legitimately contain other characters (e.g. `:` in an IPv6 literal).
pub fn validate_host_pattern(host: &str) -> Result<()> {
    let is_wildcard = host.starts_with("*.") || host.starts_with("**.");
    let rest = host
        .strip_prefix("**.")
        .or_else(|| host.strip_prefix("*."))
        .unwrap_or(host);
    if rest.is_empty() || rest.contains('*') {
        anyhow::bail!(
            "invalid host pattern '{host}': '*' is only allowed as a leading '*.' \
             (one subdomain label) or '**.' (any depth) — e.g. '*.example.com', \
             '**.example.com', or an exact host like 'api.example.com'"
        );
    }
    if is_wildcard {
        if let Some(bad) = rest.chars().find(|c| !is_wildcard_remainder_char(*c)) {
            anyhow::bail!(
                "invalid host pattern '{host}': wildcard remainder '{rest}' contains \
                 '{bad}', which regorus glob.match treats as a metacharacter — only \
                 ASCII alphanumerics, '-', '.', and '_' are allowed after the \
                 '*.'/'**.' prefix"
            );
        }
    }
    Ok(())
}

/// Charset allowed in a wildcard pattern's remainder (after the `*.`/`**.`
/// prefix is stripped): ASCII alphanumeric, `-`, `.`, `_` — real hostname
/// characters (underscore occurs in internal DNS names), none of which are
/// wax glob metacharacters.
fn is_wildcard_remainder_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'
}

/// Warn when a policy rule opens a path straight to a USB/IP server.
///
/// Such a rule is **honored** — it is an explicit, granular decision, and a
/// bare host entry authorizes only [`AllowEntry::DEFAULT_PORTS`], so reaching a
/// usbip port means the user wrote the port on purpose. But it hands the agent
/// every device that server exports, which is a strictly coarser grant than
/// izba's own USB support offers, so it is called out at the moment it is made
/// rather than discovered later in an audit log.
///
/// Returns `None` when no rule exposes a usbip endpoint.
pub fn usbip_exposure_warning(
    cfg: &EgressPolicyConfig,
    upstream: Option<(std::net::IpAddr, u16)>,
) -> Option<String> {
    let hits: Vec<String> = cfg
        .allow
        .iter()
        .filter_map(|e| {
            let ports = e.ports();
            let host = e.host();
            // Either the well-known usbip port, or the exact endpoint izba has
            // been configured to use as its own upstream.
            let mut matched: Vec<u16> = ports
                .iter()
                .copied()
                .filter(|p| *p == crate::daemon::egress::router::USBIP_PORT)
                .collect();
            if let Some((up_ip, up_port)) = upstream {
                if ports.contains(&up_port)
                    && host.parse::<std::net::IpAddr>().ok() == Some(up_ip)
                    && !matched.contains(&up_port)
                {
                    matched.push(up_port);
                }
            }
            if matched.is_empty() {
                return None;
            }
            let ports = matched
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!("{host}:{ports}"))
        })
        .collect();
    if hits.is_empty() {
        return None;
    }
    Some(format!(
        "⚠  egress policy permits direct USB/IP access: {}\n\
         \n\
         A USB/IP server has no authentication: anything it exports is available \n\
         to whoever can reach it. This rule therefore grants the agent EVERY \n\
         device that server shares — not a chosen one.\n\
         \n\
         izba has built-in USB support with a per-device allowlist, which is the \n\
         safer and recommended path: the human grants one device to one sandbox \n\
         (`izba usb allow <sandbox> --device <vid:pid>`), izba brokers the \n\
         connection, and nothing else on that server is reachable.\n\
         \n\
         The rule is being honored — you asked for it explicitly. Keep it only if \n\
         you know that is what you want.",
        hits.join(", ")
    ))
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
    for (i, e) in cfg.allow.iter().enumerate() {
        validate_host_pattern(e.host()).with_context(|| format!("allow[{i}]"))?;
    }
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
mod usbip_exposure_tests {
    use super::*;

    fn cfg_with(entries: Vec<AllowEntry>) -> EgressPolicyConfig {
        EgressPolicyConfig {
            allow: entries,
            ..Default::default()
        }
    }

    /// The whole point: opening 3240 cannot happen by accident, because a bare
    /// host entry authorizes only the web ports. No warning for ordinary rules.
    #[test]
    fn ordinary_rules_do_not_warn() {
        let cfg = cfg_with(vec![
            AllowEntry::Host("github.com".into()),
            AllowEntry::Scoped {
                host: "10.1.0.124".into(),
                ports: Some(vec![8080, 443]),
                access: Access::default(),
                protocol: None,
            },
        ]);
        assert!(usbip_exposure_warning(&cfg, None).is_none());
    }

    /// A bare host must not warn even when its name resembles the upstream —
    /// it only opens [80, 443].
    #[test]
    fn bare_host_never_reaches_the_usbip_port() {
        let cfg = cfg_with(vec![AllowEntry::Host("10.1.0.124".into())]);
        let up = Some(("10.1.0.124".parse().unwrap(), 3240));
        assert!(usbip_exposure_warning(&cfg, up).is_none());
    }

    #[test]
    fn explicit_usbip_port_warns_and_recommends_the_device_allowlist() {
        let cfg = cfg_with(vec![AllowEntry::Scoped {
            host: "10.1.0.124".into(),
            ports: Some(vec![3240]),
            access: Access::default(),
            protocol: None,
        }]);
        let msg = usbip_exposure_warning(&cfg, None).expect("must warn");
        assert!(msg.contains("10.1.0.124:3240"), "{msg}");
        assert!(
            msg.contains("izba usb allow"),
            "steer to the safer path: {msg}"
        );
        assert!(msg.contains("EVERY"), "state the actual exposure: {msg}");
        assert!(msg.contains("honored"), "say the rule still applies: {msg}");
    }

    /// A usbipd on a non-default port is caught only when it is the endpoint
    /// izba itself was configured to use.
    #[test]
    fn configured_upstream_on_a_nonstandard_port_warns() {
        let cfg = cfg_with(vec![AllowEntry::Scoped {
            host: "172.30.96.1".into(),
            ports: Some(vec![4000]),
            access: Access::default(),
            protocol: None,
        }]);
        let up = Some(("172.30.96.1".parse().unwrap(), 4000));
        let msg = usbip_exposure_warning(&cfg, up).expect("must warn");
        assert!(msg.contains("172.30.96.1:4000"), "{msg}");

        // A different host on that port is not the configured upstream.
        let other = cfg_with(vec![AllowEntry::Scoped {
            host: "10.9.9.9".into(),
            ports: Some(vec![4000]),
            access: Access::default(),
            protocol: None,
        }]);
        assert!(usbip_exposure_warning(&other, up).is_none());
    }

    #[test]
    fn every_offending_rule_is_named() {
        let cfg = cfg_with(vec![
            AllowEntry::Scoped {
                host: "a.example".into(),
                ports: Some(vec![3240]),
                access: Access::default(),
                protocol: None,
            },
            AllowEntry::Host("github.com".into()),
            AllowEntry::Scoped {
                host: "b.example".into(),
                ports: Some(vec![443, 3240]),
                access: Access::default(),
                protocol: None,
            },
        ]);
        let msg = usbip_exposure_warning(&cfg, None).expect("must warn");
        assert!(msg.contains("a.example:3240"), "{msg}");
        assert!(msg.contains("b.example:3240"), "{msg}");
        assert!(!msg.contains("github.com"), "{msg}");
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

    /// #149: `entries_for_host` must key on the same normalize identity the
    /// mutation methods use (trim + trailing-dot strip + lowercase), so a
    /// caller echoing post-edit state can never miss the entry a mutation
    /// just touched under a different spelling of the same host.
    #[test]
    fn entries_for_host_matches_normalize_equal_spellings() {
        let cfg = EgressPolicyConfig {
            enforce: false,
            allow: vec![
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: Some(vec![443]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Host("other.com".into()),
            ],
            git: vec![],
        };
        let hits = cfg.entries_for_host(" API.X.COM. ");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].host(), "api.x.com");
        assert!(cfg.entries_for_host("missing.com").is_empty());
    }

    /// #149: a wildcard host may legitimately carry multiple normalize-equal
    /// entries with mixed access verbs (union enforcement — see
    /// `collapse_duplicate_hosts`); `entries_for_host` must return ALL of
    /// them so an echo can render the full effective state.
    #[test]
    fn entries_for_host_returns_all_mixed_access_wildcard_entries() {
        let cfg = EgressPolicyConfig {
            enforce: false,
            allow: vec![
                AllowEntry::Scoped {
                    host: "*.x.com".into(),
                    ports: Some(vec![443]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "*.x.com".into(),
                    ports: Some(vec![8443]),
                    access: Access::ReadWrite,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        assert_eq!(cfg.entries_for_host("*.X.com").len(), 2);
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
                protocol: None,
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
                protocol: None,
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
                protocol: None,
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
                    protocol: None,
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
                protocol: None,
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
                protocol: None,
            }]
        );
    }

    /// Allowing a new port on an existing read-only entry must NOT silently
    /// widen it to read-write — that's a security-relevant clobber, not a
    /// side effect of adding a port.
    #[test]
    fn allow_preserves_existing_access_on_rewrite() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            }],
            git: vec![],
        };
        assert!(cfg.allow("api.x.com", 80));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![80, 443]),
                access: Access::Read,
                protocol: None,
            }],
            "adding a port must not clobber the entry's existing access"
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
                protocol: None,
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

    /// Blocking one port of a multi-port read-only entry must leave the
    /// remaining ports' access untouched, not silently widen it to read-write.
    #[test]
    fn block_preserves_existing_access_on_remaining_ports() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![80, 443]),
                access: Access::Read,
                protocol: None,
            }],
            git: vec![],
        };
        assert!(cfg.block("api.x.com", 80));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            }],
            "removing a port must not clobber the remaining entry's access"
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
                    protocol: None,
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
                    protocol: None,
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
                protocol: None,
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
                    protocol: None,
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
                protocol: None,
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
                protocol: None,
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
                protocol: None,
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
                protocol: None,
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
                protocol: None,
            },
            "default ports must normalize to None on an access change"
        );
    }

    // ── Greptile P1 (#84): normalized host matching in mutations ─────────────
    // `to_rego_data_json` normalizes every host (trim + trailing-dot strip +
    // ascii-lowercase) into a JSON map keyed by the normalized spelling, where
    // a later duplicate key silently overwrites an earlier one. Before this
    // fix, `allow`/`block`/`set_host_access` matched existing entries by RAW
    // string equality, so e.g. `allow --read api.x.com` followed by a plain
    // `allow API.X.COM` appended a SEPARATE read-write entry that silently won
    // at compile time — widening a read-only host to read-write. These tests
    // pin normalization-aware matching so equivalent spellings always collapse
    // into one entry.

    /// The exact regression scenario: `allow --read` then a plain `allow` of a
    /// different-case spelling of the same host must merge into ONE entry,
    /// keeping the read-only access — not append a second read-write entry.
    #[test]
    fn allow_case_variant_merges_into_existing_read_entry() {
        let mut cfg = EgressPolicyConfig::default();
        assert!(cfg.allow("api.x.com", 443));
        assert!(cfg.set_host_access("api.x.com", Access::Read));
        // Same host, different case, same port: must match the existing entry
        // (not append a second one) and must be a true no-op since 443 is
        // already authorized (case-insensitively).
        let changed = cfg.allow("API.X.COM", 443);
        assert_eq!(
            cfg.allow.len(),
            1,
            "a case-variant host must merge into the single existing entry: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "api.x.com");
        assert_eq!(
            cfg.allow[0].access(),
            Access::Read,
            "matching a case variant must not silently widen the entry's access"
        );
        assert!(
            !changed,
            "port 443 was already authorized (case-insensitively)"
        );
    }

    /// A trailing-dot spelling of the same host also merges — `allow` on
    /// `api.x.com.` with a NEW port must extend the existing `api.x.com`
    /// entry's ports rather than creating a second entry.
    #[test]
    fn allow_trailing_dot_variant_merges_ports_into_existing_entry() {
        let mut cfg = EgressPolicyConfig::default();
        assert!(cfg.allow("api.x.com", 443));
        assert!(cfg.allow("api.x.com.", 8443));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443, 8443]),
                access: Access::ReadWrite,
                protocol: None,
            }],
            "a trailing-dot spelling must merge into the same entry: {:?}",
            cfg.allow
        );
    }

    /// `block` must also match case/trailing-dot variants: blocking
    /// `API.X.COM.` (port 443) must remove that port from the entry stored as
    /// `api.x.com`.
    #[test]
    fn block_matches_case_and_trailing_dot_variant() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("api.x.com".into())], // {80,443}
            git: vec![],
        };
        assert!(cfg.block("API.X.COM.", 443));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![80]),
                access: Access::ReadWrite,
                protocol: None,
            }],
            "block must match a case/trailing-dot variant of the stored host"
        );
    }

    /// `set_host_access` must match a case-variant spelling of an existing
    /// entry (updating it, not appending a new one), and must normalize the
    /// stored host when it CREATES a brand-new entry from a mixed-case,
    /// trailing-dot spelling.
    #[test]
    fn set_host_access_matches_case_variant_and_normalizes_new_entries() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("pypi.org".into())],
            git: vec![],
        };
        assert!(cfg.set_host_access("PyPI.org", Access::Read));
        assert_eq!(
            cfg.allow.len(),
            1,
            "a case-variant spelling must update the existing entry, not add one: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "pypi.org");
        assert_eq!(cfg.allow[0].access(), Access::Read);

        assert!(cfg.set_host_access("MiXeD.Example.COM.", Access::Read));
        assert_eq!(cfg.allow.len(), 2);
        assert_eq!(
            cfg.allow[1].host(),
            "mixed.example.com",
            "a newly-created entry must store the normalized host spelling"
        );
    }

    /// Wildcard entries flow through `allow` too; `normalize_policy_host` is
    /// lowercase+dot-trim only, so it is safe on `*.example.com` patterns —
    /// prove there's no regression: a mixed-case wildcard is stored
    /// normalized, and re-allowing the already-normalized spelling with the
    /// same port is a true no-op (no duplicate wildcard entry).
    #[test]
    fn allow_wildcard_host_normalizes_and_dedupes() {
        let mut cfg = EgressPolicyConfig::default();
        assert!(cfg.allow("*.Example.COM", 443));
        assert_eq!(cfg.allow[0].host(), "*.example.com");
        assert!(
            !cfg.allow("*.example.com", 443),
            "re-allowing the already-authorized normalized wildcard+port must be a no-op"
        );
        assert_eq!(cfg.allow.len(), 1);
    }

    // ── Greptile P1 #2 (#84): legacy raw duplicates must collapse to the
    // compile-winning entry before mutations ─────────────────────────────────
    // `to_rego_data_json` inserts each entry into a JSON map keyed by its
    // normalized host, so among normalize-equal RAW duplicates (a legacy or
    // hand-edited `policy.yaml`, or a file written before 2aeaac9a) the LAST
    // one in list order wins the whole `{ports, access}` value at compile
    // time. Before `collapse_duplicate_hosts`, `allow`/`block`/
    // `set_host_access` matched only the FIRST such duplicate (`find`/
    // `position`), so an edit could report success while acting on an entry
    // that was never the one actually enforced. These tests construct raw
    // duplicates directly (bypassing `from_yaml`, which never produces them)
    // to pin the collapse.

    #[test]
    fn set_host_access_edits_the_compile_winning_duplicate() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: Some(vec![443]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "API.X.COM".into(),
                    ports: Some(vec![443]),
                    access: Access::ReadWrite,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        // Compile-consistency baseline: the LAST duplicate already wins at
        // compile time, regardless of the first entry's `Read`.
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["api.x.com"]["access"], "read-write",
            "pre-fix baseline: compilation already enforces the LAST duplicate"
        );

        assert!(cfg.set_host_access("api.x.com", Access::Read));
        assert_eq!(
            cfg.allow.len(),
            1,
            "normalize-equal raw duplicates must collapse to one entry: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "api.x.com");
        assert_eq!(cfg.allow[0].access(), Access::Read);

        // Compile-consistency: exactly one key for the host, matching the
        // struct's post-edit state.
        let doc2: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        let hosts = doc2["sandbox_host_rules"]["web"].as_object().unwrap();
        assert_eq!(hosts.len(), 1, "exactly one compiled key for the host");
        assert_eq!(hosts["api.x.com"]["access"], "read");
    }

    #[test]
    fn allow_extends_the_compile_winning_duplicate() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: Some(vec![443]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "API.X.COM".into(),
                    ports: Some(vec![443]),
                    access: Access::ReadWrite,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        assert!(cfg.allow("api.x.com", 8443));
        assert_eq!(
            cfg.allow.len(),
            1,
            "duplicates must collapse before the port is added: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "api.x.com");
        assert_eq!(
            cfg.allow[0].access(),
            Access::ReadWrite,
            "the surviving access must be the LAST duplicate's (the one actually enforced), \
             not the first"
        );
        assert_eq!(cfg.allow[0].ports(), vec![443, 8443]);
    }

    #[test]
    fn block_operates_on_the_compile_winning_duplicates_ports() {
        let dup_base = || {
            vec![
                AllowEntry::Scoped {
                    host: "a".into(),
                    ports: Some(vec![443]),
                    access: Access::ReadWrite,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "A.".into(),
                    ports: Some(vec![8443]),
                    access: Access::ReadWrite,
                    protocol: None,
                },
            ]
        };

        // The last duplicate's ports ([8443]) are the ones actually
        // enforced; blocking that port must remove it, dropping the entry
        // (its only port).
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: dup_base(),
            git: vec![],
        };
        assert!(cfg.block("a", 8443));
        assert!(
            cfg.allow.is_empty(),
            "blocking the winning duplicate's only port must drop the entry: {:?}",
            cfg.allow
        );

        // Port 443 belongs only to the LOSING (first, shadowed) duplicate —
        // it was never enforced, so blocking it must be a no-op.
        let mut cfg2 = EgressPolicyConfig {
            enforce: true,
            allow: dup_base(),
            git: vec![],
        };
        assert!(
            !cfg2.block("a", 443),
            "port 443 was never enforced (shadowed by the winning duplicate) -- block must no-op"
        );
        assert_eq!(
            cfg2.allow,
            vec![AllowEntry::Scoped {
                host: "a".into(),
                ports: Some(vec![8443]),
                access: Access::ReadWrite,
                protocol: None,
            }],
            "collapse must still have happened even though the block itself no-oped"
        );
    }

    /// A bare `Host` duplicate collapses per last-wins too: a `Scoped` read
    /// entry shadowed by a later bare `Host` entry must collapse to the
    /// bare/default-ports read-write semantics (the bare entry is what
    /// compilation actually enforced).
    #[test]
    fn allow_collapses_bare_and_scoped_duplicate_pair() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: Some(vec![22]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Host("API.X.COM".into()),
            ],
            git: vec![],
        };
        // Pre-collapse compile baseline: the bare entry (default web ports,
        // read-write) is what's actually enforced.
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["api.x.com"]["ports"],
            serde_json::json!([80, 443])
        );
        assert_eq!(
            doc["sandbox_host_rules"]["web"]["api.x.com"]["access"],
            "read-write"
        );

        assert!(cfg.allow("api.x.com", 22));
        assert_eq!(
            cfg.allow.len(),
            1,
            "the bare/scoped duplicate pair must collapse: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "api.x.com");
        assert_eq!(cfg.allow[0].access(), Access::ReadWrite);
        assert_eq!(cfg.allow[0].ports(), vec![22, 80, 443]);
    }

    // ── Greptile P1 #3 (#84): wildcard duplicates must preserve UNION
    // semantics through the collapse, never last-wins ─────────────────────────
    // `to_rego_data_json` routes wildcard patterns into
    // `sandbox_wildcard_host_rules` -- a LIST where every matching rule
    // grants independently (union semantics), NOT the last-wins map used for
    // exact hosts (`sandbox_host_rules`). Applying `collapse_duplicate_hosts`'s
    // last-wins rule to normalize-equal WILDCARD duplicates is therefore
    // wrong: it silently drops whichever duplicate's ports the last one
    // doesn't share, deleting real grants a mutation never touched.

    fn mixed_access_wildcard_dupes() -> Vec<AllowEntry> {
        vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![8443]),
                access: Access::Read,
                protocol: None,
            },
        ]
    }

    /// A mixed-access wildcard duplicate pair enforces the UNION today
    /// (443 read-write AND 8443 read, independently). An UNRELATED mutation
    /// must not collapse them via last-wins -- both must survive, and
    /// `to_rego_data_json` must still carry BOTH wildcard rules.
    #[test]
    fn unrelated_mutation_does_not_collapse_mixed_access_wildcard_duplicates() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: mixed_access_wildcard_dupes(),
            git: vec![],
        };
        assert!(cfg.allow("other.host", 443));
        assert_eq!(
            cfg.allow.len(),
            3,
            "the two mixed-access wildcard entries must survive an unrelated mutation \
             untouched, plus the one newly-added entry: {:?}",
            cfg.allow
        );
        assert!(
            cfg.allow
                .iter()
                .any(|e| e.host().eq_ignore_ascii_case("*.x")
                    && e.ports() == vec![443]
                    && e.access() == Access::ReadWrite),
            "the read-write/443 wildcard entry must be untouched: {:?}",
            cfg.allow
        );
        assert!(
            cfg.allow
                .iter()
                .any(|e| e.host().eq_ignore_ascii_case("*.x")
                    && e.ports() == vec![8443]
                    && e.access() == Access::Read),
            "the read/8443 wildcard entry must be untouched: {:?}",
            cfg.allow
        );

        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        let wildcards = doc["sandbox_wildcard_host_rules"]["web"]
            .as_array()
            .unwrap();
        let x_rules: Vec<_> = wildcards.iter().filter(|w| w["pattern"] == "*.x").collect();
        assert_eq!(
            x_rules.len(),
            2,
            "both wildcard rules must still compile independently: {wildcards:?}"
        );
    }

    /// `block` on a mixed-access wildcard duplicate pair must remove the
    /// port from EVERY equivalent entry (union semantics: the grant only
    /// truly disappears once no entry keeps it), dropping any entry whose
    /// ports become empty.
    #[test]
    fn block_removes_port_from_all_equivalent_wildcard_duplicates() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: mixed_access_wildcard_dupes(),
            git: vec![],
        };
        assert!(cfg.block("*.x", 443));
        assert_eq!(
            cfg.allow.len(),
            1,
            "the read-write/443 entry (now empty) must be dropped, the read/8443 entry \
             must remain: {:?}",
            cfg.allow
        );
        // The surviving entry never contained port 443, so it must be left
        // COMPLETELY untouched -- including its original (unnormalized)
        // spelling "*.X" -- not silently rewritten to the canonical "*.x"
        // just because some other equivalent entry was mutated (#84
        // tightening: block() must be a true no-op on entries it doesn't
        // actually change).
        assert_eq!(cfg.allow[0].host(), "*.X");
        assert_eq!(cfg.allow[0].ports(), vec![8443]);
        assert_eq!(cfg.allow[0].access(), Access::Read);
    }

    /// `allow` treats a port as already granted if ANY equivalent wildcard
    /// entry lists it, regardless of that entry's access verb -- port 8443
    /// is granted (read-only) by the second duplicate, so re-`allow`ing it
    /// under the default read-write call must be a true no-op, not widen
    /// the read-only grant or add a redundant entry.
    #[test]
    fn allow_is_a_noop_when_any_equivalent_wildcard_entry_already_grants_the_port() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: mixed_access_wildcard_dupes(),
            git: vec![],
        };
        assert!(
            !cfg.allow("*.x", 8443),
            "port 8443 is already granted (read-only) by the second duplicate"
        );
        assert_eq!(
            cfg.allow,
            mixed_access_wildcard_dupes(),
            "a port already granted by ANY equivalent entry must leave the config untouched"
        );
    }

    /// `set_host_access` on a mixed-access wildcard duplicate pair sets the
    /// access verb uniformly across every equivalent entry, which removes
    /// the reason they were kept separate -- so they must then merge into
    /// ONE entry carrying the union of ports, and the compiled data doc must
    /// carry exactly one wildcard rule for the pattern.
    #[test]
    fn set_host_access_unifies_and_merges_mixed_access_wildcard_duplicates() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: mixed_access_wildcard_dupes(),
            git: vec![],
        };
        assert!(cfg.set_host_access("*.x", Access::Read));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443, 8443]),
                access: Access::Read,
                protocol: None,
            }],
            "setting a uniform access must merge the duplicates into one union-ports entry: {:?}",
            cfg.allow
        );

        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        let wildcards = doc["sandbox_wildcard_host_rules"]["web"]
            .as_array()
            .unwrap();
        assert_eq!(
            wildcards.len(),
            1,
            "exactly one compiled wildcard rule after the merge: {wildcards:?}"
        );
        assert_eq!(wildcards[0]["ports"], serde_json::json!([443, 8443]));
        assert_eq!(wildcards[0]["access"], "read");
    }

    /// Uniform-access wildcard duplicates (no mixed verbs) are exactly
    /// semantics-preserving to merge -- ANY mutation (even one that targets
    /// a different host entirely) collapses them into one union-ports entry,
    /// same as `collapse_duplicate_hosts` already does for exact hosts.
    #[test]
    fn uniform_access_wildcard_duplicates_collapse_to_one_union_entry() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "*.x".into(),
                    ports: Some(vec![443]),
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "*.X".into(),
                    ports: Some(vec![8443]),
                    access: Access::Read,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        // An unrelated no-op mutation still triggers the collapse pass.
        assert!(!cfg.block("nonexistent.example", 1));
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443, 8443]),
                access: Access::Read,
                protocol: None,
            }],
            "same-access wildcard duplicates must merge to one union-ports entry: {:?}",
            cfg.allow
        );
    }

    // ── #84 tightening: block() must be a TRUE no-op on entries it doesn't
    // change ─────────────────────────────────────────────────────────────────
    // block() must only rewrite an entry when its port list actually shrank.
    // An entry that never carried the target port has to come out of the
    // call byte-for-byte identical -- including its ORIGINAL (unnormalized)
    // host spelling -- not silently canonicalized just because some other
    // equivalent entry (or none at all) got touched. Otherwise a returns-false
    // no-op call still mutates struct state, which is both a spec violation
    // (the changed-bool contract implies zero mutation on `false`) and an
    // untested behavior delta ripe for a surviving mutant.

    #[test]
    fn block_noop_on_exact_host_leaves_original_spelling_untouched() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "API.X.COM".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            }],
            git: vec![],
        };
        let before = cfg.allow.clone();
        assert!(
            !cfg.block("api.x.com", 9999),
            "port 9999 was never granted -- block must report no change"
        );
        assert_eq!(
            cfg.allow, before,
            "a no-op block must leave the config byte-for-byte identical, including the \
             original unnormalized host spelling: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "API.X.COM");
    }

    #[test]
    fn block_noop_on_wildcard_duplicates_leaves_both_entries_untouched() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: mixed_access_wildcard_dupes(),
            git: vec![],
        };
        let before = cfg.allow.clone();
        assert!(
            !cfg.block("*.x", 9999),
            "port 9999 is granted by neither equivalent wildcard entry -- block must no-op"
        );
        assert_eq!(
            cfg.allow, before,
            "a no-op block must leave BOTH equivalent wildcard entries byte-for-byte \
             identical, including their original spellings (\"*.x\" and \"*.X\"): {:?}",
            cfg.allow
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

    // ── Task 3: Loud validation of host patterns ──────────────────────────

    #[test]
    fn validate_host_pattern_matrix() {
        for ok in [
            "api.example.com",
            "*.example.com",
            "**.example.com",
            "*.x",
            "localhost",
            "*.my-host.internal",
            "*.foo_bar.corp",
        ] {
            assert!(validate_host_pattern(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in [
            "*",
            "**",
            "*.",
            "**.",
            "foo.*.com",
            "*foo.com",
            "api.*",
            "a.**.b",
            "*.git{hub.com,evil.com}",
            "*.githu?.com",
            "*.githu[bc].com",
            "**.a<b>.com",
        ] {
            let err = validate_host_pattern(bad).expect_err(&format!("{bad} must be rejected"));
            let msg = format!("{err:#}");
            assert!(msg.contains(bad), "error must name the entry: {msg}");
            assert!(
                msg.contains("*."),
                "error must show the accepted forms: {msg}"
            );
        }
    }

    /// The glob-metacharacter rejects specifically: these patterns pass the
    /// "leading `*.`/`**.` only" check but must be caught by the wildcard
    /// remainder charset check, since regorus `glob.match`'s `wax` engine
    /// treats `{}`, `[]`, `?`, `<>` as metacharacters — see
    /// `glob_metacharacters_widen_scope_hence_validation` in policy.rs for
    /// proof that an unvalidated pattern like this actually over-matches.
    #[test]
    fn validate_host_pattern_rejects_glob_metacharacters_in_wildcard_remainder() {
        for (bad, offending) in [
            ("*.git{hub.com,evil.com}", '{'),
            ("*.githu?.com", '?'),
            ("*.githu[bc].com", '['),
            ("**.a<b>.com", '<'),
        ] {
            let err = validate_host_pattern(bad).expect_err(&format!("{bad} must be rejected"));
            let msg = format!("{err:#}");
            assert!(msg.contains(bad), "error must name the pattern: {msg}");
            assert!(
                msg.contains(offending),
                "error must name the offending character '{offending}': {msg}"
            );
            assert!(
                msg.contains("metacharacter") || msg.contains("only ASCII"),
                "error must explain the allowed charset: {msg}"
            );
        }
    }

    #[test]
    fn from_yaml_rejects_malformed_wildcard_loudly() {
        let err = EgressPolicyConfig::from_yaml("allow:\n  - 'foo.*.com'\n")
            .expect_err("mid-label wildcard must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("allow[0]"),
            "must name the entry position: {msg}"
        );
        assert!(
            msg.contains("foo.*.com"),
            "must name the offending value: {msg}"
        );
    }

    #[test]
    fn from_yaml_accepts_wildcard_entries() {
        let cfg = EgressPolicyConfig::from_yaml(
            "allow:\n  - '*.example.com'\n  - host: '**.example.com'\n    ports: [443]\n",
        )
        .unwrap();
        assert_eq!(cfg.allow[0].host(), "*.example.com");
        assert_eq!(cfg.allow[1].host(), "**.example.com");
    }

    #[test]
    fn edit_policy_file_rejects_malformed_pattern_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let err = edit_policy_file(dir.path(), |cfg| {
            cfg.allow("foo.*.com", 443);
        })
        .expect_err("malformed pattern must not be persisted");
        assert!(format!("{err:#}").contains("foo.*.com"));
        assert!(
            !EgressPolicyConfig::path_in(dir.path()).exists(),
            "no policy.yaml stub may be left behind"
        );
    }

    // ── replace_allow: the GUI policy editor's wholesale-set entry point ──
    // (#171) -- must canonicalize every entry's host spelling and collapse
    // normalize-equal duplicates exactly like the mutation methods above, so
    // a full-list replacement can never persist a spelling/duplicate that
    // diverges from compile-time enforcement.

    #[test]
    fn replace_allow_canonicalizes_spelling() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![AllowEntry::Scoped {
            host: "API.Example.com.".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }]);
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.example.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            }],
            "the persisted host spelling must be canonicalized: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn replace_allow_exact_duplicates_last_wins() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "Host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "host.com.".into(),
                ports: Some(vec![8080]),
                access: Access::Read,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![8080]),
                access: Access::Read,
                protocol: None,
            }],
            "normalize-equal exact hosts must collapse to ONE entry carrying the last \
             entry's payload at the first entry's position: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn replace_allow_wildcard_uniform_merges_ports_union() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![8443]),
                access: Access::Read,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443, 8443]),
                access: Access::Read,
                protocol: None,
            }],
            "uniform-access wildcard duplicates must merge into one union-ports entry: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn replace_allow_wildcard_mixed_access_stays_separate() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![8443]),
                access: Access::Read,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow.len(),
            2,
            "mixed-access wildcard duplicates must stay separate, each enforcing its own \
             ports independently: {:?}",
            cfg.allow
        );
        assert!(
            cfg.allow.iter().all(|e| e.host() == "*.x"),
            "both entries' spellings must still be canonicalized: {:?}",
            cfg.allow
        );
        assert!(
            cfg.allow
                .iter()
                .any(|e| e.ports() == vec![443] && e.access() == Access::ReadWrite),
            "the read-write/443 entry must survive: {:?}",
            cfg.allow
        );
        assert!(
            cfg.allow
                .iter()
                .any(|e| e.ports() == vec![8443] && e.access() == Access::Read),
            "the read/8443 entry must survive: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn replace_allow_is_idempotent() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "Host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![8443]),
                access: Access::Read,
                protocol: None,
            },
        ]);
        let once = cfg.allow.clone();
        cfg.replace_allow(once.clone());
        assert_eq!(
            cfg.allow, once,
            "replacing with the result of a previous replace_allow must be a no-op: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn replace_allow_idempotent_on_mixed_access_wildcards() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![8443]),
                access: Access::Read,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow.len(),
            2,
            "mixed-access wildcard duplicates must stay separate: {:?}",
            cfg.allow
        );
        let once = cfg.allow.clone();
        cfg.replace_allow(once.clone());
        assert_eq!(
            cfg.allow.len(),
            2,
            "a second replace_allow with the previous result must not re-merge or drop entries: {:?}",
            cfg.allow
        );
        assert_eq!(
            cfg.allow, once,
            "replacing with the result of a previous replace_allow on mixed-access wildcards must be a no-op: {:?}",
            cfg.allow
        );
    }

    #[test]
    fn parses_protocol_http_on_a_nonweb_port() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        )
        .expect("parses");
        let e = &cfg.allow[0];
        assert_eq!(e.declared_protocol(), Some(Protocol::Http));
        assert_eq!(e.protocol_for(8000), Protocol::Http);
    }

    #[test]
    fn omitted_protocol_is_derived_per_port_not_per_entry() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: mixed.example.com\n    ports: [443, 5432]\n",
        )
        .expect("parses");
        let e = &cfg.allow[0];
        assert_eq!(e.declared_protocol(), None, "nothing was declared");
        assert_eq!(e.protocol_for(443), Protocol::Http, "web port derives http");
        assert_eq!(
            e.protocol_for(5432),
            Protocol::Tcp,
            "other port derives tcp"
        );
    }

    #[test]
    fn bare_host_derives_http_on_the_web_ports() {
        let e = AllowEntry::Host("github.com".into());
        assert_eq!(e.declared_protocol(), None);
        assert_eq!(e.protocol_for(80), Protocol::Http);
        assert_eq!(e.protocol_for(443), Protocol::Http);
        assert_eq!(e.protocol_for(8000), Protocol::Tcp);
    }

    #[test]
    fn protocol_rejects_an_unknown_value_naming_the_valid_ones() {
        let err = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: h.example.com\n    protocol: grpc\n",
        )
        .expect_err("unknown protocol must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("allow[0].protocol"), "{msg}");
        assert!(msg.contains("'http' or 'tcp'"), "{msg}");
        assert!(msg.contains("grpc"), "{msg}");
    }

    #[test]
    fn unknown_key_error_lists_protocol_as_valid() {
        let err = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: h.example.com\n    protokol: http\n",
        )
        .expect_err("unknown key must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown key 'protokol'"), "{msg}");
        assert!(
            msg.contains("valid keys: host, ports, access, protocol"),
            "{msg}"
        );
    }

    // DP-3: matching an SNI against a wildcard in Rust would fork the wildcard
    // semantics that live in egress.rego. Refuse at parse time instead.
    #[test]
    fn explicit_tcp_on_a_wildcard_host_is_refused() {
        let err = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: '*.vendor.com'\n    ports: [443]\n    protocol: tcp\n",
        )
        .expect_err("wildcard passthrough must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("allow[0]"), "{msg}");
        assert!(msg.contains("protocol: tcp"), "{msg}");
        assert!(msg.contains("wildcard"), "{msg}");
    }

    #[test]
    fn explicit_http_on_a_wildcard_host_is_allowed() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: '*.vendor.com'\n    ports: [8000]\n    protocol: http\n",
        )
        .expect("widening inspection over a wildcard is fine");
        assert_eq!(cfg.allow[0].declared_protocol(), Some(Protocol::Http));
    }

    // Global constraint: the Rego data document is untouched by this axis (D6).
    #[test]
    fn protocol_never_reaches_the_rego_data_document() {
        let plain = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [8000]\n",
        )
        .unwrap();
        let declared = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [8000]\n    protocol: http\n",
        )
        .unwrap();
        assert_eq!(
            plain.to_rego_data_json("web"),
            declared.to_rego_data_json("web"),
            "protocol is decided in Rust; the Rego data doc must be byte-identical"
        );
    }

    #[test]
    fn omitted_protocol_round_trips_without_emitting_the_key() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [8000]\n",
        )
        .unwrap();
        let yaml = cfg.to_yaml();
        assert!(
            !yaml.contains("protocol"),
            "canonical YAML must stay unchanged:\n{yaml}"
        );
        assert_eq!(EgressPolicyConfig::from_yaml(&yaml).unwrap(), cfg);
    }

    #[test]
    fn declared_protocol_round_trips_through_yaml() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
        let yaml = cfg.to_yaml();
        assert!(yaml.contains("protocol: tcp"), "{yaml}");
        assert_eq!(EgressPolicyConfig::from_yaml(&yaml).unwrap(), cfg);
    }

    // --- Review round 1, finding 3: the pinning hatch's OWN direction ---
    //
    // `parses_protocol_http_on_a_nonweb_port` (above) pins the WIDENING
    // override (8000 + `protocol: http` -> Http instead of the derived Tcp).
    // This pins the NARROWING one — the hatch itself (spec 5.2): an explicit
    // `protocol: tcp` must beat the derived Http on a default web port. A
    // mutant that made `protocol_for` prefer the derived value on
    // `DEFAULT_PORTS` would silently disable the hatch while every other
    // test in this file still passed.
    #[test]
    fn explicit_tcp_beats_the_derived_http_on_a_default_web_port() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
        assert_eq!(cfg.allow[0].protocol_for(443), Protocol::Tcp);
    }

    // --- Review round 1, finding 1: mutation paths must PRESERVE a
    // declared `protocol`, not silently erase it ---
    //
    // Each of these rewrites `access`/`ports` in place while carrying the
    // OTHER field forward already; before this fix, `protocol` was the one
    // field a rewrite silently dropped to `None` — which, for a declared
    // `Http` on a non-web port, performs the exact `http -> tcp` "weakens
    // egress" transition the spec requires be flagged, with no flag at all.

    #[test]
    fn allow_preserves_a_declared_protocol_when_adding_a_port() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "internal.example.com".into(),
                ports: Some(vec![8000]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Http),
            }],
            git: vec![],
        };
        assert!(cfg.allow("internal.example.com", 9000));
        let entries = cfg.entries_for_host("internal.example.com");
        assert_eq!(
            entries[0].declared_protocol(),
            Some(Protocol::Http),
            "allow() must not silently erase a declared protocol"
        );
    }

    // Finding 1b: `protocol` is stored per-ENTRY while the `protocol: tcp`
    // pinning hatch is semantically per-PORT (`protocol_for`), so preserving
    // the declaration (the fix above) also extends an existing `Some(Tcp)`
    // pin to a brand-new port the operator never named for it. This is an
    // ACCEPTED, KNOWN sharp edge, not a bug: resolving it needs a per-port
    // declaration shape, which is its own change and out of scope here
    // (tracked in the plan's spec §13 follow-up list). Preserving is still
    // the lesser evil: silently dropping the declaration (the alternative)
    // is invisible everywhere, whereas this call mutates `policy.yaml`
    // directly and never passes the `izba.yml` diff/promote weakening gate —
    // `izba policy show` (once it lands) is the only surface that reveals
    // the widened hatch.
    #[test]
    fn allow_extends_an_existing_tcp_pin_to_a_newly_added_port_known_sharp_edge() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "pinned.vendor.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Tcp),
            }],
            git: vec![],
        };
        assert!(cfg.allow("pinned.vendor.com", 8443));
        let entries = cfg.entries_for_host("pinned.vendor.com");
        assert_eq!(entries[0].ports(), vec![443, 8443]);
        assert_eq!(
            entries[0].protocol_for(8443),
            Protocol::Tcp,
            "known sharp edge: the pin extends to the newly added port too"
        );
    }

    #[test]
    fn block_preserves_a_declared_protocol_on_the_remaining_ports() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "internal.example.com".into(),
                ports: Some(vec![8000, 9000]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Http),
            }],
            git: vec![],
        };
        assert!(cfg.block("internal.example.com", 9000));
        let entries = cfg.entries_for_host("internal.example.com");
        assert_eq!(entries[0].ports(), vec![8000]);
        assert_eq!(
            entries[0].declared_protocol(),
            Some(Protocol::Http),
            "block() must not silently erase a declared protocol"
        );
    }

    #[test]
    fn set_host_access_preserves_a_declared_protocol() {
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "internal.example.com".into(),
                ports: Some(vec![8000]),
                access: Access::Read,
                protocol: Some(Protocol::Http),
            }],
            git: vec![],
        };
        assert!(cfg.set_host_access("internal.example.com", Access::ReadWrite));
        let entries = cfg.entries_for_host("internal.example.com");
        assert_eq!(entries[0].access(), Access::ReadWrite);
        assert_eq!(
            entries[0].declared_protocol(),
            Some(Protocol::Http),
            "set_host_access() must not silently erase a declared protocol"
        );
    }

    #[test]
    fn replace_allow_collapse_of_duplicate_exact_hosts_keeps_the_last_entrys_declaration() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "h.example.com".into(),
                ports: Some(vec![8000]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Http),
            },
            AllowEntry::Scoped {
                host: "h.example.com".into(),
                ports: Some(vec![9000]),
                access: Access::ReadWrite,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow.len(),
            1,
            "exact-host duplicates collapse to one: {:?}",
            cfg.allow
        );
        assert_eq!(
            cfg.allow[0].declared_protocol(),
            None,
            "the LAST duplicate wins, mirroring to_rego_data_json's map-overwrite \
             semantics — even though it declares nothing and an earlier duplicate did"
        );
    }

    #[test]
    fn wildcard_collapse_keeps_a_declared_protocol_if_any_duplicate_declares_it() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![8000]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Http),
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![9000]),
                access: Access::ReadWrite,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow.len(),
            1,
            "uniform-access wildcard duplicates merge to one: {:?}",
            cfg.allow
        );
        assert_eq!(
            cfg.allow[0].declared_protocol(),
            Some(Protocol::Http),
            "union direction: the merged entry keeps a declaration ANY duplicate carried \
             (a wildcard can never declare tcp — DP-3 refuses that at parse time)"
        );
    }

    // --- Review round 2, NEW-1: `set_host_access`'s wildcard-merge branch
    // must fold `protocol` the same union direction as
    // `collapse_duplicate_hosts`'s wildcard-union collapse ---
    #[test]
    fn set_host_access_wildcard_merge_preserves_a_declared_protocol_on_the_first_duplicate() {
        // Taking only the LAST duplicate's declaration here (last-wins, the
        // rule that is correct for EXACT hosts) would silently drop a
        // `protocol` declared on the FIRST of a mixed-access wildcard pair —
        // exactly the finding-1 defect, in the one branch round 1's fix
        // missed.
        let mut cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "*.x".into(),
                    ports: Some(vec![8000]),
                    access: Access::ReadWrite,
                    protocol: Some(Protocol::Http),
                },
                AllowEntry::Scoped {
                    host: "*.X".into(),
                    ports: Some(vec![9000]),
                    access: Access::Read,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        assert!(cfg.set_host_access("*.x", Access::Read));
        assert_eq!(
            cfg.allow.len(),
            1,
            "the mixed-access wildcard pair must merge: {:?}",
            cfg.allow
        );
        assert_eq!(
            cfg.allow[0].declared_protocol(),
            Some(Protocol::Http),
            "the declaration on the FIRST duplicate must survive the merge, matching \
             collapse_duplicate_hosts's union direction for the same situation"
        );
    }

    // --- Review round 2, NEW-2: the union fold must be structurally
    // incapable of yielding `Some(Tcp)`, not merely rely on DP-3 having
    // refused it at parse time ---
    #[test]
    fn wildcard_collapse_never_propagates_a_hand_constructed_tcp_declaration() {
        // `AllowEntry::Scoped`'s fields are public, so a hand-constructed
        // wildcard entry CAN carry `Some(Tcp)` even though the parser would
        // refuse it (DP-3). The union fold must still never let it through.
        let mut cfg = EgressPolicyConfig::default();
        cfg.replace_allow(vec![
            AllowEntry::Scoped {
                host: "*.x".into(),
                ports: Some(vec![8000]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Tcp),
            },
            AllowEntry::Scoped {
                host: "*.X".into(),
                ports: Some(vec![9000]),
                access: Access::ReadWrite,
                protocol: None,
            },
        ]);
        assert_eq!(
            cfg.allow.len(),
            1,
            "uniform-access wildcard duplicates merge to one: {:?}",
            cfg.allow
        );
        assert_eq!(
            cfg.allow[0].declared_protocol(),
            None,
            "the fold must never propagate a hand-constructed Some(Tcp) — only Some(Http) \
             or None are reachable outputs"
        );
    }

    // --- Review round 1, finding 2: DP-3 must hold as a TYPE invariant,
    // not just on the `from_yaml`/`from_value` walk ---

    #[test]
    fn allow_entry_deserialize_refuses_tcp_on_a_wildcard_via_json_too() {
        let json = serde_json::json!({
            "host": "*.vendor.com",
            "ports": [443],
            "protocol": "tcp",
        });
        let err = serde_json::from_value::<AllowEntry>(json)
            .expect_err("DP-3 must be enforced on the JSON ingestion path too");
        let msg = err.to_string();
        assert!(msg.contains("wildcard"), "{msg}");
    }

    #[test]
    fn allow_entry_deserialize_refuses_an_unknown_key_via_json_too() {
        let json = serde_json::json!({
            "host": "h.example.com",
            "protokol": "http",
        });
        let err = serde_json::from_value::<AllowEntry>(json)
            .expect_err("an unknown key must be refused on the JSON ingestion path too");
        let msg = err.to_string();
        assert!(msg.contains("unknown key 'protokol'"), "{msg}");
        // Review round 2, NEW-3: a bare `AllowEntry` has no list position of
        // its own, so it must use the honest synthetic label "allow entry",
        // NEVER a fabricated "allow[0]" that would misreport which element
        // of a caller's list was bad.
        assert!(msg.contains("allow entry"), "{msg}");
        assert!(!msg.contains("allow[0]"), "{msg}");
    }

    // Review round 2, NEW-3: the GUI deserializes a whole `Vec<AllowEntry>`
    // in one call, so serde calls `AllowEntry::deserialize` once per
    // element. Before the fix, EVERY element reported itself as `allow[0]`
    // regardless of its real position — a bad key on the SECOND (or eighth)
    // entry named the first. Pin that the false index is gone.
    #[test]
    fn allow_entry_deserialize_in_a_list_does_not_claim_a_false_index() {
        let json = serde_json::json!([
            {"host": "good.example.com"},
            {"host": "bad.example.com", "protokol": "http"},
        ]);
        let err = serde_json::from_value::<Vec<AllowEntry>>(json)
            .expect_err("the unknown key on the second entry must be refused");
        let msg = err.to_string();
        assert!(msg.contains("unknown key 'protokol'"), "{msg}");
        assert!(
            !msg.contains("allow[0]"),
            "must not claim the FIRST entry is the bad one: {msg}"
        );
    }

    #[test]
    fn allow_entry_round_trips_through_json_with_a_declared_protocol() {
        let entry = AllowEntry::Scoped {
            host: "pinned.vendor.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: Some(Protocol::Tcp),
        };
        let json = serde_json::to_value(&entry).unwrap();
        let round_tripped: AllowEntry = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped, entry);
    }

    #[test]
    fn allow_entry_deserialize_still_accepts_the_untagged_shapes_via_json() {
        // A bare-string host and a `{host, ...}` map must both still parse
        // the way the derived `#[serde(untagged)]` used to — now routed
        // through `parse_allow_entry` instead of the derive.
        let host: AllowEntry = serde_json::from_value(serde_json::json!("github.com")).unwrap();
        assert_eq!(host, AllowEntry::Host("github.com".into()));

        let scoped: AllowEntry = serde_json::from_value(serde_json::json!({
            "host": "api.x.com",
            "ports": [443],
        }))
        .unwrap();
        assert_eq!(
            scoped,
            AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            }
        );
    }
}
