# Vendor-neutral git + HTTP-method egress controls — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a vendor-neutral `git:` policy block (read/write per repo across any HTTP git endpoint) plus an `access: read|read-write` verb on HTTP host rules, make egress posture explicit via an always-written `enforce:` flag, and fold in three consolidation smells — all on M2's existing MITM datapath with no streaming/body change.

**Architecture:** The MITM already decrypts `{host,method,path}` and the regorus engine already receives them; this consumes them. Git read/write is keyed on the smart-HTTP wire protocol (`info/refs?service=git-upload-pack|git-receive-pack` + the `POST .../git-upload-pack|git-receive-pack` data legs), not on the hostname, so it works for github/gitlab/bitbucket/gitea/any host. The one datapath-adjacent change is capturing the request **query string** (already parsed on the `Uri`) so the engine can see `?service=`.

**Tech Stack:** Rust (izba-core, izba-cli), regorus 0.4.0 (OPA/Rego), serde/serde_yaml/serde_json, Tauri 2 + React/TypeScript/vitest (app).

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-18-vendor-neutral-git-http-egress-controls-design.md` — every task implements part of it.
- **Six workspace gates must stay green** (CLAUDE.md): `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- **App gate (separate, REQUIRED on `main`):** any change to `izba-core`/`izba-proto` public types — and every frontend task here — must also pass `cd app && npm ci && npm run build && (cd src-tauri && cargo clippy --all-targets -- -D warnings && cargo test)`. The app is `exclude`d from the workspace, so the six gates do NOT catch it.
- **Toolchain:** `[ -f .cargo-env ] && source .cargo-env` before cargo (worktrees may lack it — fall back to the system toolchain).
- **TDD:** test first, watch it fail, minimal impl, watch it pass, commit. Conventional commits (`feat(egress): …`).
- **Fail-closed is sacred:** a policy eval error or `false` must always Deny. Never weaken this.
- **Back-compat:** every existing `policy.yaml` (`allow:` string list or `{host,ports}`) must keep parsing unchanged and mean `access: read-write`.
- **`Access` default = `ReadWrite`**; **a present `policy.yaml` with no `enforce:` key defaults to `enforce: true`** (authoring intent); **no file at all = `enforce: false`** (bare sandbox), synthesized + backfilled on load.

---

## File structure

| File | Responsibility | Tasks |
|------|----------------|-------|
| `crates/izba-core/src/daemon/egress/config.rs` | Grammar model (`Access`, `AllowEntry`, `GitRule`/`GitTarget`, `EgressPolicyConfig{enforce,allow,git}`), parse/serialize, editor helpers, data-doc compiler, posture | 1, 2, 4 |
| `crates/izba-core/src/daemon/egress/egress.rego` | Vendor-neutral rego: access-aware host rules + git wire-op rules; M5 stub deleted | 3 |
| `crates/izba-core/src/daemon/egress/policy.rs` | `FlowDesc.query`, `input_json` query emission, `RegoPolicy::embedded` generated data doc, rego table tests | 3 |
| `crates/izba-core/src/daemon/egress/egress_data.json` | **DELETED** — embedded default doc now generated in Rust (smell D7) | 3 |
| `crates/izba-core/src/daemon/egress/mitm.rs` | `L7Request.query`; populate from `req.uri().query()` | 5 |
| `crates/izba-core/src/daemon/egress/mitm_runtime.rs` | `PolicyAdapter::flow_for` threads `query` into `FlowDesc` | 5 |
| `crates/izba-core/src/daemon/egress/mod.rs` (egress manager) | Posture: `into_policy` returns `Arc<dyn Policy>`; arming honors `enforce` | 4 |
| `crates/izba-cli/src/commands/policy.rs` + `main.rs` | `izba policy git allow/block`, `izba policy enforce on|off`, show renders git+enforce | 6 |
| `crates/izba-cli/src/commands/netlog.rs` + `egress/audit.rs` | Git-op label in summary + per-line views | 7 |
| `app/src-tauri/src/{lib,commands,daemon,fake,views}.rs` | Tauri commands `policy_git_allow/policy_git_block/policy_set_enforce`; `PolicyView{enforcing,git}` | 8 |
| `app/src/lib/{types,ipc}.ts`, `app/src/components/{PolicyEditor,NetlogView,FirewallStatus}.tsx`, `app/src/lib/ports.ts` (new) | Enforce toggle, read/read-write picker, git section, git-aware netlog rows, single `WEB_DEFAULT_PORTS` const | 9, 10 |
| `crates/izba-core/tests/integration.rs` (or egress e2e) | Real-VM git clone allowed / push denied | 11 |

---

## Task 1: Grammar model — `Access`, git rules, `enforce`, editor helpers

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs`

**Interfaces:**
- Produces (used by Tasks 2, 4, 6, 8):
  - `enum Access { Read, ReadWrite }` (`Default = ReadWrite`; serde `read`/`read-write`).
  - `AllowEntry::Host(String)` (unchanged) and `AllowEntry::Scoped { host: String, ports: Option<Vec<u16>>, access: Access }`.
  - `AllowEntry::ports() -> Vec<u16>`, `AllowEntry::access() -> Access`, `AllowEntry::DEFAULT_PORTS: [u16;2]`.
  - `struct GitRule { target: GitTarget, access: Access }`, `enum GitTarget { Repo(String), Host(String) }`.
  - `struct EgressPolicyConfig { enforce: bool, allow: Vec<AllowEntry>, git: Vec<GitRule> }`.
  - Helpers: `set_enforce(&mut self, bool) -> bool`, `git_allow(&mut self, GitTarget, Access) -> bool`, `git_block(&mut self, &GitTarget) -> bool`, `set_host_access(&mut self, &str, Access) -> bool`.

- [ ] **Step 1: Write failing tests** (append to the `tests` module in `config.rs`)

```rust
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
        GitRule { target: GitTarget::Repo("github.com/myorg/app".into()), access: Access::ReadWrite }
    );
    assert_eq!(
        cfg.git[1],
        GitRule { target: GitTarget::Host("bitbucket.org".into()), access: Access::Read }
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
    let mut cfg = EgressPolicyConfig { enforce: false, allow: vec![AllowEntry::Host("pypi.org".into())], git: vec![] };
    assert!(cfg.set_enforce(true));
    assert!(!cfg.set_enforce(true));
    assert!(cfg.set_host_access("pypi.org", Access::Read));
    assert_eq!(cfg.allow[0].access(), Access::Read);
}

#[test]
fn new_grammar_round_trips() {
    let cfg = EgressPolicyConfig {
        enforce: true,
        allow: vec![
            AllowEntry::Host("api.anthropic.com".into()),
            AllowEntry::Scoped { host: "pypi.org".into(), ports: None, access: Access::Read },
        ],
        git: vec![GitRule { target: GitTarget::Repo("github.com/o/a".into()), access: Access::ReadWrite }],
    };
    let back = EgressPolicyConfig::from_yaml(&cfg.to_yaml()).unwrap();
    assert_eq!(back, cfg);
}
```

- [ ] **Step 2: Run, verify they fail to compile/parse**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::config -- --nocapture`
Expected: FAIL — `Access`, `GitRule`, `GitTarget`, `enforce`, helpers undefined.

- [ ] **Step 3: Implement the model.** Replace the `AllowEntry` enum + `EgressPolicyConfig` struct + `from_yaml` in `config.rs` with:

```rust
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowEntry {
    /// Bare host → web ports [80,443], access read-write.
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
    pub const DEFAULT_PORTS: [u16; 2] = [80, 443];

    pub fn host(&self) -> &str {
        match self {
            AllowEntry::Host(h) => h,
            AllowEntry::Scoped { host, .. } => host,
        }
    }
    pub fn ports(&self) -> Vec<u16> {
        match self {
            AllowEntry::Host(_) => AllowEntry::DEFAULT_PORTS.to_vec(),
            AllowEntry::Scoped { ports, .. } => {
                ports.clone().unwrap_or_else(|| AllowEntry::DEFAULT_PORTS.to_vec())
            }
        }
    }
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
    fn key(&self) -> (&'static str, &str) {
        match self {
            GitTarget::Repo(s) => ("repo", s),
            GitTarget::Host(s) => ("host", s),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct EgressPolicyConfig {
    /// Explicit posture. Always written by izba (smell: empty-vs-missing). A
    /// present file with no `enforce:` key resolves to `true` (see `from_yaml`).
    pub enforce: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<AllowEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitRule>,
}

/// Parse helper: `enforce` is `Option` so we can tell "key absent" (→ true,
/// authoring intent) from an explicit value.
#[derive(Deserialize)]
struct RawConfig {
    enforce: Option<bool>,
    #[serde(default)]
    allow: Vec<AllowEntry>,
    #[serde(default)]
    git: Vec<GitRule>,
}

impl EgressPolicyConfig {
    pub fn from_yaml(s: &str) -> Result<Self> {
        let raw: Option<RawConfig> =
            serde_yaml::from_str(s).context("parsing egress policy YAML")?;
        let raw = raw.unwrap_or(RawConfig { enforce: None, allow: vec![], git: vec![] });
        Ok(Self {
            // Present file without `enforce:` → enforce (authoring a policy = intent).
            enforce: raw.enforce.unwrap_or(true),
            allow: raw.allow,
            git: raw.git,
        })
    }

    pub fn set_enforce(&mut self, on: bool) -> bool {
        if self.enforce == on {
            false
        } else {
            self.enforce = on;
            true
        }
    }

    pub fn set_host_access(&mut self, host: &str, access: Access) -> bool {
        if let Some(e) = self.allow.iter_mut().find(|e| e.host() == host) {
            let ports = match e.ports() {
                p if p == AllowEntry::DEFAULT_PORTS.to_vec() => None,
                p => Some(p),
            };
            if e.access() == access {
                return false;
            }
            *e = AllowEntry::Scoped { host: host.to_string(), ports, access };
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

    pub fn git_block(&mut self, target: &GitTarget) -> bool {
        let before = self.git.len();
        self.git.retain(|r| &r.target != target);
        self.git.len() != before
    }
}
```

Keep the existing `allow()`, `block()`, `to_yaml()`, `path_in()`, `load()`, `POLICY_FILE` — but update `allow()`/`block()` to construct `Scoped { host, ports: Some(ports), access: Access::ReadWrite }` (they manage ports only). Update the existing tests that build `AllowEntry::Scoped { host, ports }` to `{ host, ports: Some(vec![...]), access: Access::ReadWrite }`. `GitTarget::key` is `dead_code` until Task 2 — add `#[allow(dead_code)]` or wait (Task 2 uses it; if clippy complains, gate it).

- [ ] **Step 4: Run tests, verify pass**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::config`
Expected: PASS (all new + migrated existing tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/config.rs
git commit -m "feat(egress): access verb + git rules + explicit enforce in policy grammar"
```

---

## Task 2: Data-doc compiler — `to_rego_data_json` new shape

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs`

**Interfaces:**
- Consumes: Task 1 types.
- Produces (used by Task 3 rego + Task 4 `into_policy`): `to_rego_data_json(&self, sandbox: &str) -> String` emitting
  `{ "host_rules": {}, "sandbox_host_rules": { <sandbox>: { <host>: {"ports":[..],"access":"read|read-write"} } }, "sandbox_git_rules": { <sandbox>: [ {"repo|host": <glob>, "access": "..."} ] } }`.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn data_doc_emits_access_and_git() {
    let cfg = EgressPolicyConfig {
        enforce: true,
        allow: vec![AllowEntry::Scoped { host: "pypi.org".into(), ports: None, access: Access::Read }],
        git: vec![GitRule { target: GitTarget::Repo("github.com/o/a".into()), access: Access::ReadWrite }],
    };
    let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
    assert!(doc["host_rules"].as_object().unwrap().is_empty());
    assert_eq!(doc["sandbox_host_rules"]["web"]["pypi.org"]["ports"], serde_json::json!([80, 443]));
    assert_eq!(doc["sandbox_host_rules"]["web"]["pypi.org"]["access"], "read");
    assert_eq!(doc["sandbox_git_rules"]["web"][0]["repo"], "github.com/o/a");
    assert_eq!(doc["sandbox_git_rules"]["web"][0]["access"], "read-write");
}
```

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::config::tests::data_doc_emits_access_and_git`
Expected: FAIL (old `to_rego_data_json` emits `global_domains`/`sandbox_ports`).

- [ ] **Step 3: Replace `to_rego_data_json`**

```rust
pub fn to_rego_data_json(&self, sandbox: &str) -> String {
    let mut hosts = serde_json::Map::new();
    for e in &self.allow {
        let access = match e.access() {
            Access::Read => "read",
            Access::ReadWrite => "read-write",
        };
        hosts.insert(
            e.host().to_string(),
            serde_json::json!({ "ports": e.ports(), "access": access }),
        );
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
        "sandbox_git_rules": { sandbox: git },
    })
    .to_string()
}
```

(Drop the now-unused `#[allow(dead_code)]` on `GitTarget::key` — it is used here.)

- [ ] **Step 4: Run, verify pass** (this will FAIL the old `data_doc_scopes_ports_to_the_sandbox` test — update that test to the new shape: `sandbox_host_rules["web"]["api.anthropic.com"]["ports"]`).

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/config.rs
git commit -m "feat(egress): compile policy to access-aware host_rules + git_rules data doc"
```

---

## Task 3: Rego rewrite + `FlowDesc.query` + generated embedded data

**Files:**
- Rewrite: `crates/izba-core/src/daemon/egress/egress.rego`
- Modify: `crates/izba-core/src/daemon/egress/policy.rs` (add `FlowDesc.query`, `input_json` query, `embedded()` generated doc, table tests)
- Delete: `crates/izba-core/src/daemon/egress/egress_data.json`

**Interfaces:**
- Consumes: Task 2 data-doc shape.
- Produces (used by Tasks 4, 5): `FlowDesc { sandbox, addr, port, host, method, path, query }` (query `Option<String>`, raw e.g. `"service=git-receive-pack"`). `RegoPolicy::embedded()` unchanged signature.

- [ ] **Step 1: Write failing rego table tests** (replace the rego tests in `policy.rs`; keep `flow()` helper, add a git flow builder)

```rust
fn git_flow(sandbox: &str, host: &str, method: &str, path: &str, query: Option<&str>) -> FlowDesc {
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
        s = sandbox, h = hosts_json, r = rules_json
    );
    RegoPolicy::with_data(&data).unwrap()
}

#[test]
fn git_clone_allowed_when_read_granted_any_vendor() {
    for host in ["github.com", "gitlab.com", "bitbucket.org", "git.example.org"] {
        let repo = format!("{host}/myorg/app");
        let p = policy_with_git("web", &format!(r#"[{{"repo":"{repo}","access":"read"}}]"#), "{}");
        // discovery GET
        assert_eq!(
            p.check(&git_flow("web", host, "GET", "/myorg/app/info/refs", Some("service=git-upload-pack"))),
            Verdict::Allow, "{host}: clone discovery"
        );
        // data POST
        assert_eq!(
            p.check(&git_flow("web", host, "POST", "/myorg/app/git-upload-pack", None)),
            Verdict::Allow, "{host}: clone data"
        );
    }
}

#[test]
fn git_push_denied_when_only_read() {
    let p = policy_with_git("web", r#"[{"repo":"github.com/myorg/app","access":"read"}]"#, "{}");
    assert_eq!(
        p.check(&git_flow("web", "github.com", "GET", "/myorg/app/info/refs", Some("service=git-receive-pack"))),
        Verdict::Deny, "push discovery denied under read"
    );
    assert_eq!(
        p.check(&git_flow("web", "github.com", "POST", "/myorg/app/git-receive-pack", None)),
        Verdict::Deny, "push data denied under read"
    );
}

#[test]
fn git_push_allowed_when_read_write() {
    let p = policy_with_git("web", r#"[{"repo":"github.com/myorg/app","access":"read-write"}]"#, "{}");
    assert_eq!(
        p.check(&git_flow("web", "github.com", "POST", "/myorg/app/git-receive-pack", None)),
        Verdict::Allow
    );
    // read still works (write implies read)
    assert_eq!(
        p.check(&git_flow("web", "github.com", "POST", "/myorg/app/git-upload-pack", None)),
        Verdict::Allow
    );
}

#[test]
fn git_owner_glob_and_dotgit_suffix() {
    let p = policy_with_git("web", r#"[{"repo":"gitlab.com/vendor/*","access":"read"}]"#, "{}");
    assert_eq!(
        p.check(&git_flow("web", "gitlab.com", "POST", "/vendor/lib.git/git-upload-pack", None)),
        Verdict::Allow, ".git suffix + owner glob"
    );
    assert_eq!(
        p.check(&git_flow("web", "gitlab.com", "POST", "/other/lib/git-upload-pack", None)),
        Verdict::Deny, "different owner denied"
    );
}

#[test]
fn git_host_scope_matches_any_repo() {
    let p = policy_with_git("web", r#"[{"host":"bitbucket.org","access":"read"}]"#, "{}");
    assert_eq!(
        p.check(&git_flow("web", "bitbucket.org", "POST", "/any/repo/git-upload-pack", None)),
        Verdict::Allow
    );
}

#[test]
fn git_rule_does_not_grant_ordinary_http() {
    // A git read grant must NOT open the web UI / API on the same host.
    let p = policy_with_git("web", r#"[{"repo":"github.com/myorg/app","access":"read-write"}]"#, "{}");
    assert_eq!(
        p.check(&git_flow("web", "github.com", "GET", "/myorg/app", None)),
        Verdict::Deny, "web UI GET not a git wire op -> denied"
    );
}

#[test]
fn http_access_read_allows_get_denies_post() {
    let p = policy_with_git("web", "[]", r#"{"pypi.org":{"ports":[80,443],"access":"read"}}"#);
    let mut get = flow("web", "pypi.org", 443); get.method = Some("GET".into());
    assert_eq!(p.check(&get), Verdict::Allow);
    let mut post = flow("web", "pypi.org", 443); post.method = Some("POST".into());
    assert_eq!(p.check(&post), Verdict::Deny, "read host denies POST");
}

#[test]
fn http_access_read_write_allows_post() {
    let p = policy_with_git("web", "[]", r#"{"api.x.com":{"ports":[443],"access":"read-write"}}"#);
    let mut post = flow("web", "api.x.com", 443); post.method = Some("POST".into());
    assert_eq!(p.check(&post), Verdict::Allow);
}
```

Keep the existing embedded-policy tests (`global_domain_is_allowed`, etc.) but update them to the new embedded hosts (they evaluate `RegoPolicy::embedded()`; the embedded hosts list is unchanged in Step 4 except pypi/npm/crates become `read`). Adjust any that assumed a port-only doc.

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::policy`
Expected: FAIL — `FlowDesc.query` missing; rego has no git/access rules.

- [ ] **Step 3a: Add `query` to `FlowDesc` + emit `input.query`** in `policy.rs`:

```rust
// in struct FlowDesc, after `path`:
    /// Tier-1: raw query string (e.g. "service=git-receive-pack"), for git
    /// read/write discrimination. None for tier-2 / pre-MITM.
    pub query: Option<String>,
```

In `input_json`, after the `path` block:

```rust
    if let Some(q) = &flow.query {
        obj["query"] = serde_json::Value::Object(parse_query(q));
    }
```

Add the helper (module-level in `policy.rs`):

```rust
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
```

- [ ] **Step 3b: Rewrite `egress.rego`** entirely:

```rego
# izba egress policy — vendor-neutral.
#
# HTTP host rules carry an `access` verb (read = GET/HEAD; read-write = all
# methods). Git rules key on the smart-HTTP wire protocol (info/refs?service +
# the upload-pack/receive-pack data legs) so read/write control works for ANY
# git host, not just github.com. Per-sandbox scoped (one engine per sandbox).

package egress
import rego.v1

default allow := false

# Destination for HTTP host matching: decrypted Host (tier-1) else dialed addr.
dest_name := input.host
dest_name := input.dest if not input.host

read_method if input.method in ["GET", "HEAD"]

host_access_ok(access) if access == "read-write"
host_access_ok(access) if {
    access == "read"
    read_method
}

# --- HTTP host allow-list (access-aware) ---
allow if {
    rule := data.host_rules[dest_name]
    input.port in rule.ports
    host_access_ok(rule.access)
}
allow if {
    rule := data.sandbox_host_rules[input.sandbox][dest_name]
    input.port in rule.ports
    host_access_ok(rule.access)
}

# --- Vendor-neutral git rules ---
service_kind("git-upload-pack") := "read"
service_kind("git-receive-pack") := "write"

# Discovery leg: GET <repo>/info/refs?service=<svc>
git_request := {"service": input.query.service, "repo_path": rp} if {
    input.method == "GET"
    endswith(input.path, "/info/refs")
    rp := trim_suffix(input.path, "/info/refs")
}
# Data leg: POST <repo>/git-upload-pack | <repo>/git-receive-pack
git_request := {"service": svc, "repo_path": rp} if {
    input.method == "POST"
    some svc in ["git-upload-pack", "git-receive-pack"]
    suffix := sprintf("/%s", [svc])
    endswith(input.path, suffix)
    rp := trim_suffix(input.path, suffix)
}

# Canonical repo id: "<host>/<owner>/<repo>", trimming ".git" and slashes.
git_repo_id := id if {
    bare := trim_suffix(trim(git_request.repo_path, "/"), ".git")
    id := sprintf("%s/%s", [input.host, bare])
}

git_rule_matches(rule) if {
    rule.repo
    glob.match(rule.repo, ["/"], git_repo_id)
}
git_rule_matches(rule) if {
    rule.host
    rule.host == input.host
}

git_kind := service_kind(git_request.service)

allow if {
    some rule in data.sandbox_git_rules[input.sandbox]
    git_rule_matches(rule)
    git_kind == "read"
    rule.access in {"read", "read-write"}
}
allow if {
    some rule in data.sandbox_git_rules[input.sandbox]
    git_rule_matches(rule)
    git_kind == "write"
    rule.access == "read-write"
}
```

- [ ] **Step 3c: Generate the embedded default doc in Rust** (smell D7 — no `[80,443]` literal repetition). In `policy.rs`, delete `const DATA_JSON` + the `include_str!("egress_data.json")`, and replace `embedded()`:

```rust
/// Hosts any sandbox may reach with FULL method access (POST-based APIs).
const GLOBAL_READ_WRITE: &[&str] = &[
    "api.anthropic.com", "console.anthropic.com",
    "api.openai.com", "platform.openai.com",
    "github.com", "api.github.com",
];
/// Static mirrors — GET/HEAD only (read).
const GLOBAL_READ: &[&str] = &[
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "crates.io", "static.crates.io", "index.crates.io",
];

impl RegoPolicy {
    const REGO: &'static str = include_str!("egress.rego");

    pub fn embedded() -> anyhow::Result<Self> {
        let mut hosts = serde_json::Map::new();
        let ports = serde_json::json!(AllowEntry::DEFAULT_PORTS); // single source of truth
        for h in GLOBAL_READ_WRITE {
            hosts.insert((*h).into(), serde_json::json!({ "ports": ports, "access": "read-write" }));
        }
        for h in GLOBAL_READ {
            hosts.insert((*h).into(), serde_json::json!({ "ports": ports, "access": "read" }));
        }
        let data = serde_json::json!({
            "host_rules": hosts,
            "sandbox_host_rules": {},
            "sandbox_git_rules": {},
        });
        Self::new(Self::REGO, &data.to_string())
    }
    // with_data(), new() unchanged.
}
```

Add `use super::config::AllowEntry;` to `policy.rs`. Then `git rm crates/izba-core/src/daemon/egress/egress_data.json`.

- [ ] **Step 4: Run tests, verify pass**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress`
Expected: PASS. Fix any embedded-host test that asserted the old port-only shape.

- [ ] **Step 5: Commit**

```bash
git add -A crates/izba-core/src/daemon/egress/
git rm crates/izba-core/src/daemon/egress/egress_data.json
git commit -m "feat(egress): vendor-neutral git rego + access-aware host rules; generate default doc

Deletes the inert M5 stub and the egress_data.json port-literal repetition."
```

---

## Task 4: Explicit posture — `into_policy` honors `enforce`; create materializes; load backfills

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (`into_policy`, `load`, a `materialize`/default writer)
- Modify: the egress manager that arms a sandbox's policy — `crates/izba-core/src/daemon/egress/mod.rs` (find the call to `EgressPolicyConfig::load(...).into_policy(...)` / the `AllowAll` fallback)
- Modify: `crates/izba-cli/src/commands/mod.rs` `persist_policy` (write `enforce` for `--policy`) and the create path that makes a bare sandbox

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `into_policy(&self, sandbox: &str) -> anyhow::Result<std::sync::Arc<dyn Policy>>` (AllowAll when `!enforce`, else RegoPolicy). `EgressPolicyConfig::ensure_materialized(sandbox_dir) -> Result<()>` writing an explicit `enforce:false` default when absent.

- [ ] **Step 1: Write failing tests** (in `config.rs` tests)

```rust
#[test]
fn enforce_false_is_non_enforcing_allow_all() {
    let cfg = EgressPolicyConfig { enforce: false, allow: vec![], git: vec![] };
    let p = cfg.into_policy("web").unwrap();
    assert!(!p.enforces(), "enforce:false -> AllowAll");
    assert_eq!(p.check(&FlowDesc::l3("web", "1.2.3.4", 443)), Verdict::Allow);
}

#[test]
fn enforce_true_is_a_firewall() {
    let cfg = EgressPolicyConfig { enforce: true, allow: vec![AllowEntry::Host("api.x.com".into())], git: vec![] };
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
```

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::config`
Expected: FAIL — `into_policy` returns `RegoPolicy` not `Arc<dyn Policy>`; `load_or_materialize` undefined.

- [ ] **Step 3: Implement.** In `config.rs`:

```rust
use std::sync::Arc;
use super::policy::{AllowAll, Policy};

impl EgressPolicyConfig {
    pub fn into_policy(&self, sandbox: &str) -> Result<Arc<dyn Policy>> {
        if !self.enforce {
            return Ok(Arc::new(AllowAll));
        }
        Ok(Arc::new(RegoPolicy::with_data(&self.to_rego_data_json(sandbox))?))
    }

    /// The one representation: if no `policy.yaml` exists, write an explicit
    /// `enforce: false` (bare sandbox) and return it. Otherwise load it.
    pub fn load_or_materialize(sandbox_dir: &std::path::Path) -> Result<Self> {
        match Self::load(sandbox_dir)? {
            Some(cfg) => Ok(cfg),
            None => {
                let cfg = Self { enforce: false, allow: vec![], git: vec![] };
                let path = Self::path_in(sandbox_dir);
                std::fs::write(&path, cfg.to_yaml())
                    .with_context(|| format!("writing {}", path.display()))?;
                Ok(cfg)
            }
        }
    }
}
```

Update the egress manager (`mod.rs`): replace the `match EgressPolicyConfig::load(dir)? { Some(cfg) => cfg.into_policy(name)? as Arc<dyn Policy>, None => Arc::new(AllowAll) }` arming logic with `EgressPolicyConfig::load_or_materialize(dir)?.into_policy(name)?`. Grep for the existing `AllowAll` fallback + `into_policy` call sites and route them all through `load_or_materialize`.

Update `persist_policy` (cli `mod.rs`): after validating the user's `--policy` file, it currently copies it verbatim. Keep that, but it now carries whatever `enforce` the user set (default true via `from_yaml`). For a bare `izba create` with no `--policy`, ensure the daemon's first arming materializes `enforce:false` (handled by `load_or_materialize`).

- [ ] **Step 4: Run, verify pass** (the workspace — `into_policy`'s new return type ripples to callers)

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core; cargo build -p izba-cli`
Expected: PASS. Fix call sites that did `let p: RegoPolicy = cfg.into_policy(..)?` to take `Arc<dyn Policy>`.

- [ ] **Step 5: Commit**

```bash
git add -A crates/izba-core crates/izba-cli
git commit -m "feat(egress): explicit enforce posture; materialize policy.yaml, kill empty-vs-missing footgun"
```

---

## Task 5: MITM query plumbing

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/mitm.rs` (`L7Request` + builders)
- Modify: `crates/izba-core/src/daemon/egress/mitm_runtime.rs` (`PolicyAdapter::flow_for`)

**Interfaces:**
- Consumes: Task 3 `FlowDesc.query`.
- Produces: `L7Request { host, method, path, query: Option<String> }`; `flow_for` copies `query` through.

- [ ] **Step 1: Write failing test** (in `mitm_runtime.rs` tests — exercise `flow_for` via a small constructor, or in `mitm.rs` where `L7Request` is built)

```rust
#[test]
fn flow_for_threads_query_into_flowdesc() {
    let adapter = PolicyAdapter::test_new("web", "203.0.113.5".parse().unwrap(), 443);
    let req = L7Request {
        host: "github.com".into(),
        method: "GET".into(),
        path: "/o/a/info/refs".into(),
        query: Some("service=git-receive-pack".into()),
    };
    let flow = adapter.flow_for(&req);
    assert_eq!(flow.query.as_deref(), Some("service=git-receive-pack"));
    assert_eq!(flow.host.as_deref(), Some("github.com"));
}
```

(Add a `#[cfg(test)] pub(crate) fn test_new(...)` ctor to `PolicyAdapter` building it with an `AllowAll` policy + a discard `AuditSink`, if one isn't already available.)

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::mitm`
Expected: FAIL — `L7Request` has no `query`.

- [ ] **Step 3: Implement.**
  - `mitm.rs` `L7Request`: add `pub query: Option<String>,`.
  - Every `L7Request { host, method, path }` literal in `mitm.rs` (the `audit_l7` closure ~line 587, the SNI-mismatch builder ~639, the policy builder ~653) gains `query: req.uri().query().map(|q| q.to_string()),`.
  - `mitm_runtime.rs` `flow_for`: add `query: req.query.clone(),` to the `FlowDesc` literal.

- [ ] **Step 4: Run, verify pass**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress; cargo clippy -p izba-core --all-targets -- -D warnings`
Expected: PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs crates/izba-core/src/daemon/egress/mitm_runtime.rs
git commit -m "feat(egress): capture request query so git read/write reaches the policy"
```

---

## Task 6: CLI — `izba policy git allow/block`, `izba policy enforce on|off`, show renders git

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs`

**Interfaces:**
- Consumes: Task 1 `git_allow`/`git_block`/`set_enforce`/`GitTarget`/`Access`; `edit_policy_file`; `maybe_reload`.
- Produces: CLI verbs.

- [ ] **Step 1: Write failing clap parse tests** (in `policy.rs` or `main.rs` tests)

```rust
#[test]
fn parse_policy_git_allow_write() {
    use clap::Parser;
    let cli = crate::Cli::try_parse_from(
        ["izba", "policy", "git", "allow", "web", "github.com/o/a", "--write"]
    ).unwrap();
    // assert it routes to PolicyCmd::Git { sub: GitSub::Allow { write: true, .. } }
}

#[test]
fn parse_policy_enforce_on() {
    use clap::Parser;
    crate::Cli::try_parse_from(["izba", "policy", "enforce", "web", "on"]).unwrap();
}
```

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli policy`
Expected: FAIL — variants undefined.

- [ ] **Step 3: Implement.** Extend `PolicyCmd`:

```rust
#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    Show { name: String },
    Allow { name: String, target: String },
    Block { name: String, target: String },
    Enable { name: String },
    Reload { name: String },
    /// Fine-grained git controls (clone/fetch/push per repo)
    #[command(subcommand)]
    Git(GitSub),
    /// Turn this sandbox's firewall on or off
    Enforce { name: String, state: EnforceState },
}

#[derive(Debug, Subcommand)]
pub enum GitSub {
    /// Allow git on REPO (host/owner/repo, globs ok) or a whole HOST; read unless --write
    Allow { name: String, target: String, #[arg(long)] write: bool },
    /// Remove a git rule for REPO/HOST
    Block { name: String, target: String },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum EnforceState { On, Off }
```

Wire in `run()`:

```rust
PolicyCmd::Git(GitSub::Allow { name, target, write }) => {
    let access = if *write { Access::ReadWrite } else { Access::Read };
    let gt = parse_git_target(target);
    edit_policy_file(&paths.sandbox_dir(name), |c| { c.git_allow(gt.clone(), access); })?;
    maybe_reload(paths, name);
    Ok(0)
}
PolicyCmd::Git(GitSub::Block { name, target }) => {
    let gt = parse_git_target(target);
    edit_policy_file(&paths.sandbox_dir(name), |c| { c.git_block(&gt); })?;
    maybe_reload(paths, name);
    Ok(0)
}
PolicyCmd::Enforce { name, state } => {
    let on = matches!(state, EnforceState::On);
    edit_policy_file(&paths.sandbox_dir(name), |c| { c.set_enforce(on); })?;
    maybe_reload(paths, name);
    Ok(0)
}
```

`parse_git_target`: a target containing a `/` after the host is a `Repo`; a bare host (no `/`) is a `Host`:

```rust
pub(crate) fn parse_git_target(s: &str) -> GitTarget {
    if s.contains('/') { GitTarget::Repo(s.to_string()) } else { GitTarget::Host(s.to_string()) }
}
```

Extend `show()` to print the `enforce` state + a `git:` section (iterate `cfg.git`, print `<target> (<access>)`). Add `use izba_core::daemon::egress::config::{Access, GitRule, GitTarget};`.

- [ ] **Step 4: Run, verify pass**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-cli; cargo clippy -p izba-cli --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/policy.rs crates/izba-cli/src/main.rs
git commit -m "feat(cli): izba policy git allow/block + policy enforce on|off"
```

---

## Task 7: Netlog git-op labeling

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/audit.rs` (a `git_op_label` helper + use it in `format_record`)
- Modify: `crates/izba-cli/src/commands/netlog.rs` (`format_summary_row`)

**Interfaces:**
- Produces: `pub fn git_op_label(method: Option<&str>, path: Option<&str>) -> Option<&'static str>` → `Some("git clone")` for `*/git-upload-pack` POST, `Some("git push")` for `*/git-receive-pack` POST, else `None`. (The definitive data leg is the POST; labels need no query.)

- [ ] **Step 1: Write failing test** (in `audit.rs`)

```rust
#[test]
fn git_op_label_from_post_legs() {
    assert_eq!(git_op_label(Some("POST"), Some("/o/a/git-upload-pack")), Some("git clone/fetch"));
    assert_eq!(git_op_label(Some("POST"), Some("/o/a.git/git-receive-pack")), Some("git push"));
    assert_eq!(git_op_label(Some("GET"), Some("/o/a")), None);
    assert_eq!(git_op_label(None, None), None);
}
```

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::audit::tests::git_op_label_from_post_legs`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement** in `audit.rs`:

```rust
/// Human label for a git wire op, from the request line. The POST data leg is
/// the definitive signal (clone vs push) and needs no query string.
pub fn git_op_label(method: Option<&str>, path: Option<&str>) -> Option<&'static str> {
    let (m, p) = (method?, path?);
    if m != "POST" {
        return None;
    }
    if p.ends_with("/git-upload-pack") {
        Some("git clone/fetch")
    } else if p.ends_with("/git-receive-pack") {
        Some("git push")
    } else {
        None
    }
}
```

In `format_record` (audit.rs ~215-236) and `format_summary_row` (netlog.rs ~110-119), when `git_op_label(method, path)` is `Some(label)`, render `label` in place of the raw `{method} {path}`. Example for `format_summary_row`:

```rust
let req = match git_op_label(s.last_method.as_deref(), s.last_path.as_deref()) {
    Some(label) => format!("  {label}"),
    None => match (&s.last_method, &s.last_path) {
        (Some(m), Some(p)) => format!("  {m} {p}"),
        _ => String::new(),
    },
};
```

(Import `use izba_core::daemon::egress::audit::git_op_label;` in netlog.rs.)

- [ ] **Step 4: Run, verify pass**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core daemon::egress::audit; cargo test -p izba-cli netlog`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/audit.rs crates/izba-cli/src/commands/netlog.rs
git commit -m "feat(netlog): label git clone/push rows in the audit views"
```

---

## Task 8: App backend — Tauri commands for git rules + enforce

**Files:**
- Modify: `app/src-tauri/src/views.rs` (`PolicyView` gains `git`)
- Modify: `app/src-tauri/src/daemon.rs` (`DaemonApi` trait + `RealDaemon`), `app/src-tauri/src/fake.rs` (`FakeDaemon`)
- Modify: `app/src-tauri/src/commands.rs` + `app/src-tauri/src/lib.rs` (`#[tauri::command]` + registration)

**Interfaces:**
- Consumes: Task 1 helpers, Task 4 posture.
- Produces: Tauri commands `policy_git_allow(name, target, write)`, `policy_git_block(name, target)`, `policy_set_enforce(name, on)`; `PolicyView { enforcing, allow, git }`.

- [ ] **Step 1: Write failing test** (in `daemon.rs`/`fake.rs` tests — exercise via `FakeDaemon`)

```rust
#[test]
fn fake_policy_git_allow_then_show() {
    let d = FakeDaemon::default();
    d.policy_set_enforce("web", true).unwrap();
    d.policy_git_allow("web", "github.com/o/a", true).unwrap();
    let view = d.policy_show("web").unwrap();
    assert!(view.enforcing);
    assert_eq!(view.git.len(), 1);
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cd app/src-tauri && cargo test`
Expected: FAIL — methods + `PolicyView.git` undefined.

- [ ] **Step 3: Implement.**
  - `views.rs`: `pub struct PolicyView { pub enforcing: bool, pub allow: Vec<AllowEntry>, pub git: Vec<GitRule> }`. (Re-export `GitRule` from `izba_core::daemon::egress::config`.)
  - `daemon.rs` `DaemonApi`: add `fn policy_git_allow(&self, name: &str, target: &str, write: bool) -> Result<()>`, `fn policy_git_block(&self, name: &str, target: &str) -> Result<()>`, `fn policy_set_enforce(&self, name: &str, on: bool) -> Result<()>`. `RealDaemon` impls route through `edit_and_reload` calling `cfg.git_allow(parse_git_target(target), access)`, `cfg.git_block(&...)`, `cfg.set_enforce(on)`. `policy_show` populates `git: cfg.git`. (Move/duplicate `parse_git_target` from CLI into a shared spot or inline the same `contains('/')` rule.)
  - `fake.rs`: mirror with the in-memory `EgressPolicyConfig`.
  - `commands.rs` + `lib.rs`: `#[tauri::command]` wrappers `policy_git_allow`/`policy_git_block`/`policy_set_enforce` and add to the `invoke_handler!` list.

- [ ] **Step 4: Run, verify pass**

Run: `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src
git commit -m "feat(app): tauri commands for git rules + enforce toggle"
```

---

## Task 9: Frontend — types, IPC, enforce toggle, single port constant

**Files:**
- Create: `app/src/lib/ports.ts` (`export const WEB_DEFAULT_PORTS = [80, 443] as const;`)
- Modify: `app/src/lib/types.ts` (`Access`, `GitRule`, `PolicyView.git`), `app/src/lib/ipc.ts` (new invokes)
- Modify: `app/src/components/PolicyEditor.tsx` (enforce toggle; consume `WEB_DEFAULT_PORTS`), `app/src/components/NetlogView.tsx` (consume `WEB_DEFAULT_PORTS`), `app/src/components/FirewallStatus.tsx`

**Interfaces:**
- Consumes: Task 8 commands + `PolicyView { enforcing, allow, git }`.

- [ ] **Step 1: Write failing vitest** (`app/src/test/policyEditor.test.tsx`)

```tsx
it("toggles enforce via the daemon", async () => {
  // render PolicyEditor with a fake ipc; click the enforce switch;
  // expect api.policySetEnforce(name, false) called.
});
it("uses the shared WEB_DEFAULT_PORTS constant", async () => {
  const { WEB_DEFAULT_PORTS } = await import("../lib/ports");
  expect(WEB_DEFAULT_PORTS).toEqual([80, 443]);
});
```

- [ ] **Step 2: Run, verify fail**

Run: `cd app && npm test -- policyEditor`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `ports.ts`: `export const WEB_DEFAULT_PORTS = [80, 443] as const;`
  - `types.ts`: `export type Access = "read" | "read-write"; export type GitRule = ({ repo: string } | { host: string }) & { access?: Access }; export interface PolicyView { enforcing: boolean; allow: AllowEntry[]; git: GitRule[]; }` and widen `AllowEntry` object form with optional `access`.
  - `ipc.ts`: `policySetEnforce(name, on) => invoke("policy_set_enforce", { name, on })`, `policyGitAllow(name, target, write) => invoke("policy_git_allow", { name, target, write })`, `policyGitBlock(name, target) => invoke("policy_git_block", { name, target })`.
  - `PolicyEditor.tsx`: replace the inline `[80, 443]` in `toRow` (line 12) with `WEB_DEFAULT_PORTS`; add an enforce on/off switch bound to `policySetEnforce`; disable the rule editors when `!enforcing`.
  - `NetlogView.tsx`: replace the `${e}:80`/`${e}:443` expansion (lines 12-13) with a loop over `WEB_DEFAULT_PORTS`.
  - `FirewallStatus.tsx`: read `enforcing` from `PolicyView` (unchanged source, now explicit).

- [ ] **Step 4: Run, verify pass**

Run: `cd app && npm test && npm run build`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "feat(app): enforce toggle + single WEB_DEFAULT_PORTS constant"
```

---

## Task 10: Frontend — git section + git-aware netlog rows

**Files:**
- Create: `app/src/components/AccessPicker.tsx` (shared read / read-write control)
- Modify: `app/src/components/PolicyEditor.tsx` (Git repos section), `app/src/components/NetlogView.tsx` (git-op rows + allow-read/allow-write/block)

**Interfaces:**
- Consumes: Task 9 types/ipc + `AccessPicker`.

- [ ] **Step 1: Write failing vitest** (`app/src/test/netlogView.test.tsx`, `policyEditor.test.tsx`)

```tsx
it("renders a git push row and offers allow-write", async () => {
  // summary row: last_method POST, last_path /o/a/git-receive-pack
  // expect text "git push" and an "Allow write" button calling policyGitAllow(name, "github.com/o/a", true)
});
it("edits git rules in the Git section", async () => {
  // add a repo glob, pick read-write, save -> policyGitAllow called
});
```

A `git_repo_from_row(host, path)` helper (front-end): strip `/info/refs|/git-upload-pack|/git-receive-pack` + `.git` from path, join `host + "/" + owner/repo`.

- [ ] **Step 2: Run, verify fail**

Run: `cd app && npm test -- netlogView policyEditor`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `AccessPicker.tsx`: a two-option segmented control (`read` / `read-write`) with an `onChange` prop; used on host rows and git rows.
  - `PolicyEditor.tsx`: add a "Git repos" section listing `view.git`, each row = target text + `AccessPicker` + remove; an "add repo" row; Save routes through `policyGitAllow`/`policyGitBlock`.
  - `NetlogView.tsx`: when a row's `last_path` matches a git wire op (helper from Step 1), render `git clone → owner/repo` / `git push → owner/repo`; show **Allow read** / **Allow write** / **Block** buttons calling `policyGitAllow(name, repo, write)` / `policyGitBlock(name, repo)`. Keep the raw-IP SSRF guard (disabled Allow with tooltip).

- [ ] **Step 4: Run, verify pass**

Run: `cd app && npm test && npm run build && (cd src-tauri && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: PASS (full app gate).

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "feat(app): git repos editor section + git-aware netlog rows"
```

---

## Task 11: Real-VM e2e — git clone allowed, push denied

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (or the egress e2e test module) — env-gated `IZBA_INTEGRATION=1`

**Interfaces:**
- Consumes: the whole feature end to end through a booted microVM.

- [ ] **Step 1: Write the gated test** (skips when `IZBA_INTEGRATION` unset, per the `full_connect_via_listener` pattern)

```rust
#[test]
fn git_read_only_repo_allows_clone_denies_push() {
    if std::env::var("IZBA_INTEGRATION").is_err() { return; }
    // 1. create a sandbox with policy.yaml:
    //      enforce: true
    //      git:
    //        - repo: github.com/octocat/Hello-World
    //          access: read
    // 2. exec `git clone https://github.com/octocat/Hello-World` -> exit 0
    // 3. exec a push to that repo -> non-zero + netlog shows a denied "git push" row.
}
```

- [ ] **Step 2: Run locally with KVM** (sandbox disabled — `/dev/kvm` works here unsandboxed per CLAUDE.md)

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration git_read_only -- --test-threads=1`
Expected: PASS (or documented skip if artifacts absent).

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(egress): e2e git clone allowed / push denied on a read-only repo"
```

---

## Final verification (before PR)

- [ ] Six workspace gates all green (commands in Global Constraints).
- [ ] App gate green: `cd app && npm ci && npm run build && (cd src-tauri && cargo clippy --all-targets -- -D warnings && cargo test)`.
- [ ] `grep -rn "80, 443" crates/ app/src` shows only `AllowEntry::DEFAULT_PORTS` (Rust) and `WEB_DEFAULT_PORTS` (TS) as definitions — no stray inline copies in production paths.
- [ ] `grep -rn "_upstream_tiers_for_M5\|global_domains\|sandbox_ports" crates/` is empty (old shape fully removed).
- [ ] Manual smoke: `izba policy git allow web github.com/o/a --write`, `izba policy show web` renders the git rule + enforce state; `izba policy enforce web off` flips posture.

## Self-review notes (coverage vs spec)

- Spec §2 grammar → Task 1. §3 access/git data doc → Task 2. §4 vendor-neutral rego + query → Task 3 + 5. §5 explicit posture/migration → Task 4. §6 config compiler → Tasks 1-2. §7 smells: inert stub + tiers removed (Task 3), empty-vs-missing (Task 4), triple-literal (Tasks 3 Rust-gen + 9 TS const). §8 UX → Tasks 6 (CLI), 7 (netlog labels), 8-10 (app). §9 tests → woven per task + Task 11 e2e.
- Deferred (spec §1 non-goals): ref-level rules, `methods:` escape hatch, git-over-SSH, credential injection — no tasks, intentionally.
