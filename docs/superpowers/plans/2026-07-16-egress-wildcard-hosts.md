# Egress Wildcard Hosts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `allow: ["*.mydomain.com"]` in egress policies actually matches (Cilium `toFQDNs` semantics), on both MITM (tier-1) and DNS-snoop (tier-2) enforcement paths, with loud validation of malformed patterns.

**Architecture:** Wildcard entries split out of the exact-host Rego maps into `wildcard_host_rules` / `sandbox_wildcard_host_rules` lists at data-doc compile time (`config.rs::to_rego_data_json`); `egress.rego` matches them with `glob.match(pattern, ["."], dest_name)` (`*` = exactly one label, `**` = any depth, apex never matches). Both tiers already funnel through `RegoPolicy::check`, so no Rust datapath changes. Policy-side hosts get normalized (lowercase + strip trailing dot) to match the already-normalized request side. The dead `dns_snoop::allowlist_matches` is deleted.

**Tech Stack:** Rust, regorus (Rego), serde_yaml, clap; React/TypeScript + vitest for the Tauri app.

**Spec:** `docs/superpowers/specs/2026-07-16-egress-wildcard-hosts-design.md` — read it first.

## Global Constraints

- All six workspace gates green before every commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. (Per-task it is acceptable to run the first three plus the cross-check; the musl/cross-clippy gates must run before the final push.) Source `.cargo-env` if present.
- Conventional commits (`feat(core): ...`, `test(core): ...`, `docs: ...`).
- TDD: write the failing test, see it fail, implement, see it pass.
- Wildcard semantics are FROZEN by the spec: `*.x` = exactly ONE extra label; `**.x` = any depth ≥ 1; the apex (`x` itself) NEVER matches a wildcard; patterns/hosts compared lowercase, trailing dot stripped.
- Unit tests never bind unix/vsock/TCP listeners without a runtime skip (`can_bind()` pattern) — some sandboxes deny bind with EPERM.
- Working dir: `/home/kolkhovskiy/git/izba/.claude/worktrees/egress-wildcard-hosts`.

---

### Task 1: Wildcard allow rules in egress.rego (matcher core)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/egress.rego` (insert after the two exact-host allow rules, lines 25-35)
- Test: `crates/izba-core/src/daemon/egress/policy.rs` (append to existing `mod tests`)

**Interfaces:**
- Consumes: existing `RegoPolicy::new(RegoPolicy::REGO, data_json)`, `Policy::check(&FlowDesc) -> Verdict`, test helper `flow(sandbox, addr, port)`.
- Produces: the Rego consumes two NEW data-doc keys later tasks emit: `wildcard_host_rules: [{pattern, ports, access}]` (global) and `sandbox_wildcard_host_rules: {<sandbox>: [{pattern, ports, access}]}`. Field name is exactly `pattern`.

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in `policy.rs`:

```rust
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
        assert_eq!(p.check(&l7_get("web", "api.example.com", 443)), Verdict::Allow);
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
        assert_eq!(p.check(&l7_get("web", "a.example.com", 443)), Verdict::Allow);
        assert_eq!(p.check(&l7_get("web", "a.b.c.example.com", 443)), Verdict::Allow);
        assert_eq!(p.check(&l7_get("web", "example.com", 443)), Verdict::Deny);
        assert_eq!(p.check(&l7_get("web", "evilexample.com", 443)), Verdict::Deny);
    }

    /// Wildcard rules carry the same ports/access semantics as exact rules.
    #[test]
    fn wildcard_rule_respects_ports_and_access() {
        let p = wildcard_policy(
            "web",
            serde_json::json!([{"pattern": "*.internal.corp", "ports": [8443], "access": "read"}]),
        );
        assert_eq!(p.check(&l7_get("web", "api.internal.corp", 8443)), Verdict::Allow);
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
        assert_eq!(p.check(&flow("web", "api.example.com", 443)), Verdict::Allow);
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
        assert_eq!(p.check(&l7_get("web", "x.shared.corp", 443)), Verdict::Allow);
        assert_eq!(p.check(&l7_get("build", "x.build.corp", 443)), Verdict::Allow);
        assert_eq!(
            p.check(&l7_get("web", "x.build.corp", 443)),
            Verdict::Deny,
            "web must not inherit build's per-sandbox wildcard"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-core --lib daemon::egress::policy -- wildcard single_label deep_`
Expected: FAIL — all new tests hit `Verdict::Deny` on the Allow assertions (the Rego has no wildcard rules yet).

- [ ] **Step 3: Add the wildcard allow rules to egress.rego** — insert directly after the `sandbox_host_rules` allow rule (after line 35), keeping the section comment style:

```rego
# --- Wildcard HTTP host allow-list ---
# `glob.match` with `.` as the delimiter gives Cilium toFQDNs semantics:
# `*` = exactly one label, `**` = any depth (>= 1); the apex itself never
# matches — the literal `.` after the wildcard has nothing to consume.
allow if {
    some rule in data.wildcard_host_rules
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}
allow if {
    some rule in data.sandbox_wildcard_host_rules[input.sandbox]
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress::policy`
Expected: PASS (all new + all pre-existing policy tests).

**Contingency (only if a Step-4 failure shows regorus's `glob.match` deviating from these semantics — e.g. `**` refusing the delimiter or apex matching):** replace the two `glob.match(...)` lines with a pure-Rego helper added above the rules, and re-run:

```rego
wildcard_match(pattern, name) if {
    suffix := trim_prefix(pattern, "**.")
    pattern != suffix
    endswith(name, sprintf(".%s", [suffix]))
}
wildcard_match(pattern, name) if {
    not startswith(pattern, "**.")
    suffix := trim_prefix(pattern, "*.")
    pattern != suffix
    endswith(name, sprintf(".%s", [suffix]))
    label := trim_suffix(name, sprintf(".%s", [suffix]))
    label != ""
    not contains(label, ".")
}
```

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p izba-core && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-core/src/daemon/egress/egress.rego crates/izba-core/src/daemon/egress/policy.rs
git commit -m "feat(core): wildcard host rules in the egress Rego (Cilium toFQDNs semantics)"
```

---

### Task 2: Compile wildcards + normalization into the data doc

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (`to_rego_data_json`, lines ~339-369; new private helpers)
- Modify: `crates/izba-core/src/daemon/egress/policy.rs` (`embedded()`, the `data` json at lines ~137-141)
- Test: `crates/izba-core/src/daemon/egress/config.rs` `mod tests`

**Interfaces:**
- Consumes: Task 1's Rego keys `wildcard_host_rules` / `sandbox_wildcard_host_rules` with rule objects `{pattern, ports, access}`.
- Produces: `to_rego_data_json` always emits all five keys (`host_rules`, `sandbox_host_rules`, `wildcard_host_rules`, `sandbox_wildcard_host_rules`, `sandbox_git_rules`); private fns `normalize_policy_host(&str) -> String` and `is_wildcard_host(&str) -> bool` (Task 3 reuses neither — validation is separate).

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in `config.rs`:

```rust
    #[test]
    fn data_doc_splits_wildcards_from_exact_hosts() {
        let cfg = EgressPolicyConfig::from_yaml(
            "allow:\n  - api.example.com\n  - '*.internal.corp'\n  - host: '**.deep.corp'\n    ports: [8443]\n    access: read\n",
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        // Exact host stays in the map; wildcards move to the list.
        assert!(doc["sandbox_host_rules"]["web"]["api.example.com"].is_object());
        assert!(doc["sandbox_host_rules"]["web"].get("*.internal.corp").is_none());
        let wc = doc["sandbox_wildcard_host_rules"]["web"].as_array().unwrap();
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
        let cfg = EgressPolicyConfig::from_yaml(
            "allow:\n  - API.Example.com.\n  - '*.Internal.CORP.'\n",
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        assert!(
            doc["sandbox_host_rules"]["web"]["api.example.com"].is_object(),
            "policy-side hosts must be lowercased + trailing-dot-stripped to match the normalized request side"
        );
        let wc = doc["sandbox_wildcard_host_rules"]["web"].as_array().unwrap();
        assert_eq!(wc[0]["pattern"], "*.internal.corp");
    }

    /// End-to-end through the real pipeline: YAML -> data doc -> Rego -> verdict.
    #[test]
    fn wildcard_yaml_policy_enforces_end_to_end() {
        let cfg =
            EgressPolicyConfig::from_yaml("enforce: true\nallow:\n  - '*.internal.corp'\n").unwrap();
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
        assert_eq!(p.check(&l7("internal.corp")), Verdict::Deny, "apex not matched");
        assert_eq!(p.check(&l7("a.b.internal.corp")), Verdict::Deny, "one label only");
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
```

(`FlowDesc` needs importing in the tests module if not already: the module already has `use crate::daemon::egress::policy::{FlowDesc, Verdict};`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::config -- data_doc wildcard_yaml mixed_case`
Expected: FAIL — no `sandbox_wildcard_host_rules` key, wildcard stays in the host map, mixed-case never matches.

- [ ] **Step 3: Implement** — in `config.rs`, add private helpers above `to_rego_data_json`:

```rust
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
```

Rewrite the host loop in `to_rego_data_json` (keep the git part untouched) and extend the final json:

```rust
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
```

```rust
        serde_json::json!({
            "host_rules": {},
            "sandbox_host_rules": { sandbox: hosts },
            "wildcard_host_rules": [],
            "sandbox_wildcard_host_rules": { sandbox: wildcards },
            "sandbox_git_rules": { sandbox: git },
        })
        .to_string()
```

Update the method's doc comment to mention the wildcard split. In `policy.rs::embedded()`, extend the default data doc for shape consistency:

```rust
        let data = serde_json::json!({
            "host_rules": hosts,
            "sandbox_host_rules": {},
            "wildcard_host_rules": [],
            "sandbox_wildcard_host_rules": {},
            "sandbox_git_rules": {},
        });
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress`
Expected: PASS, including all pre-existing config data-doc shape tests (if one asserts the exact old key set, extend it for the two new keys — that is the only acceptable existing-test edit).

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p izba-core && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-core/src/daemon/egress/config.rs crates/izba-core/src/daemon/egress/policy.rs
git commit -m "feat(core): compile wildcard allow entries + host normalization into the Rego data doc"
```

---

### Task 3: Loud validation of host patterns

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (new pub fn; wire into `parse_allow_entry` ~line 576 and `edit_policy_file` ~line 649)
- Test: `crates/izba-core/src/daemon/egress/config.rs` `mod tests`

**Interfaces:**
- Produces: `pub fn validate_host_pattern(host: &str) -> Result<()>` in `config.rs` (Task 8's GUI mirrors its rule client-side; Task 5's CLI relies on `edit_policy_file` calling it).
- Coverage map (why these two call sites suffice): `parse_allow_entry` covers every LOAD path — `policy.yaml` via `from_yaml`/`load`, daemon `ReloadPolicy`, and the manifest `spec.egress` block (its `Deserialize` delegates to `from_value`). `edit_policy_file` covers every WRITE path — CLI `policy allow/block/enable`, and ALL app/daemon mutations (`app/src-tauri/src/daemon.rs` `edit_and_reload` → `edit_policy_file`, including `policy_set_full` which injects `AllowEntry` values that never passed a parser).

- [ ] **Step 1: Write the failing tests:**

```rust
    #[test]
    fn validate_host_pattern_matrix() {
        for ok in [
            "api.example.com",
            "*.example.com",
            "**.example.com",
            "*.x",
            "localhost",
        ] {
            assert!(validate_host_pattern(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in ["*", "**", "*.", "**.", "foo.*.com", "*foo.com", "api.*", "a.**.b"] {
            let err = validate_host_pattern(bad).expect_err(&format!("{bad} must be rejected"));
            let msg = format!("{err:#}");
            assert!(msg.contains(bad), "error must name the entry: {msg}");
            assert!(msg.contains("*."), "error must show the accepted forms: {msg}");
        }
    }

    #[test]
    fn from_yaml_rejects_malformed_wildcard_loudly() {
        let err = EgressPolicyConfig::from_yaml("allow:\n  - 'foo.*.com'\n")
            .expect_err("mid-label wildcard must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("allow[0]"), "must name the entry position: {msg}");
        assert!(msg.contains("foo.*.com"), "must name the offending value: {msg}");
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::config -- validate_host from_yaml_rejects from_yaml_accepts edit_policy_file_rejects`
Expected: FAIL — `validate_host_pattern` not found (compile error). Fix by writing the fn, then the wiring tests fail at runtime.

- [ ] **Step 3: Implement** — add near the other free fns in `config.rs`:

```rust
/// Validate an allow-entry host: an exact hostname (no `*`) or a wildcard
/// with `*.` (one label) / `**.` (any depth) as the LEADING label only.
/// Anything else fails loudly — under M2 a malformed pattern was accepted
/// and silently never matched, which is a security footgun.
pub fn validate_host_pattern(host: &str) -> Result<()> {
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
    Ok(())
}
```

Wire into `parse_allow_entry` — bare-string arm:

```rust
        // Bare host string → default web ports, read-write.
        Value::String(s) => {
            validate_host_pattern(s).with_context(|| format!("allow[{i}]"))?;
            Ok(AllowEntry::Host(s.clone()))
        }
```

and in the mapping arm, right after `let host = host.ok_or_else(...)?;`:

```rust
            validate_host_pattern(&host).with_context(|| format!("allow[{i}]"))?;
```

Wire into `edit_policy_file`, after `f(&mut cfg);` and before the write:

```rust
    for e in &cfg.allow {
        validate_host_pattern(e.host())?;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p izba-core && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-core/src/daemon/egress/config.rs
git commit -m "feat(core): loudly validate egress host patterns on every load and write path"
```

---

### Task 4: Delete the dead wildcard matcher

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/dns_snoop.rs` (delete `allowlist_matches`, lines ~56-80, and its test `wildcard_match_one_label_and_deep`, lines ~253-275)
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (module doc lines 11-14 references it)

**Interfaces:**
- Consumes: nothing. `allowlist_matches` has zero production callers (verified); `normalize` in the same file stays (the snoop store uses it).
- Produces: nothing — semantics live in the Rego now (Task 1's tests cover every case the deleted test covered: one-label, deep, apex, suffix-embedding; case/trailing-dot normalization is covered by Task 2's tests).

- [ ] **Step 1: Delete** `pub fn allowlist_matches` (with its doc comment) and the `wildcard_match_one_label_and_deep` test from `dns_snoop.rs`.

- [ ] **Step 2: Replace the config.rs module-doc caveat** (lines 11-14):

```rust
//! Host matching supports exact names plus Cilium-style wildcards (`*.x` =
//! exactly one extra label, `**.x` = any depth; the apex itself never matches
//! a wildcard). Wildcards compile to `wildcard_host_rules` in the Rego data
//! doc and are matched by `glob.match` in `egress.rego`; malformed patterns
//! are rejected loudly by [`validate_host_pattern`].
```

- [ ] **Step 3: Verify nothing references the deleted fn**

Run: `grep -rn "allowlist_matches" crates/ app/`
Expected: no output.

- [ ] **Step 4: Gate + commit**

Run: `cargo test -p izba-core && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-core/src/daemon/egress/dns_snoop.rs crates/izba-core/src/daemon/egress/config.rs
git commit -m "refactor(core): drop the dead dns_snoop wildcard matcher — the Rego is the one matcher"
```

---

### Task 5: CLI surface (`izba policy allow '*.x'` + help)

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs` (`PolicyCmd::Allow`/`Block` doc comments, lines ~14-29)
- Test: `crates/izba-cli/src/commands/policy.rs` `mod tests`

**Interfaces:**
- Consumes: Task 3's validation via `edit_policy_file` (no new CLI validation code — `apply_edit` → `edit_policy_file` already bails on a malformed pattern before writing). `parse_target`'s `rsplit_once(':')` already handles `*.x:8443`.

- [ ] **Step 1: Write the failing tests:**

```rust
    #[test]
    fn allow_accepts_wildcard_target() {
        use izba_core::daemon::egress::config::{Access, AllowEntry, EgressPolicyConfig};
        let dir = tempfile::tempdir().unwrap();
        apply_edit(dir.path(), Edit::Allow, "*.example.com", 443).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            }]
        );
    }

    #[test]
    fn allow_rejects_malformed_wildcard_target_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let err = apply_edit(dir.path(), Edit::Allow, "foo.*.com", 443)
            .expect_err("mid-label wildcard must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("foo.*.com"), "must name the bad pattern: {msg}");
        assert!(
            !dir.path().join("policy.yaml").exists(),
            "failed edit must leave no policy.yaml"
        );
    }
```

- [ ] **Step 2: Run tests to verify state** — `cargo test -p izba-cli allow_`
Expected: `allow_accepts_wildcard_target` PASSES already (validation permits it); `allow_rejects_malformed_wildcard_target_loudly` PASSES via Task 3. If both pass, these are regression pins — keep them. If either fails, fix per Task 3's wiring before proceeding.

- [ ] **Step 3: Update the clap doc comments** — `Allow` variant:

```rust
    /// Allow an HTTP(S) destination: HOST, a wildcard (*.HOST = one subdomain
    /// label, **.HOST = any depth; the apex needs its own entry), or
    /// HOST:PORT (port defaults to 443; access is read-write). To actually
    /// block anything else, enforcement must be on (see `enforce`).
    /// Auto-reloads a running sandbox.
```

and its `target` field: `/// Destination to allow: HOST, *.HOST, **.HOST, or HOST:PORT (port defaults to 443)`.
`Block` variant target: `/// Destination to remove: HOST, *.HOST, **.HOST, or HOST:PORT (port defaults to 443)`.

- [ ] **Step 4: Gate + commit**

Run: `cargo test -p izba-cli && cargo clippy -p izba-cli --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-cli/src/commands/policy.rs
git commit -m "feat(cli): wildcard targets in izba policy allow/block help + regression pins"
```

---

### Task 6: MITM end-to-end wildcard test

**Files:**
- Modify: `crates/izba-core/tests/egress_mitm.rs` (new test alongside `mitm_firewall_allows_and_denies_by_decrypted_host`)

**Interfaces:**
- Consumes: the file's existing harness (fake TLS upstream, `MitmRuntime`, register-before-connect helpers — read the existing test and REUSE its helpers verbatim) plus `EgressPolicyConfig::from_yaml(...).into_policy("...")` so the test exercises the full YAML→data-doc→Rego pipeline, not a hand-built `RegoPolicy`.

- [ ] **Step 1: Read the existing test** `mitm_firewall_allows_and_denies_by_decrypted_host` in full and identify: how the policy is injected into `MitmRuntime`, how a simulated guest flow with a chosen SNI/Host is driven, and how allow vs deny is asserted (deny = the `403 Forbidden by izba egress policy` body).

- [ ] **Step 2: Add the test** — same shape as the existing one, with the policy built from YAML:

```rust
/// Wildcard allow entries enforce through the real MITM path: the policy is
/// compiled from `policy.yaml` text (YAML -> data doc -> Rego), a one-label
/// wildcard admits `api.example.test` and refuses both the apex and a
/// deeper subdomain on the decrypted Host.
#[tokio::test(flavor = "multi_thread")]
async fn mitm_firewall_enforces_wildcard_hosts() {
    install_ring();
    if !can_bind() {
        eprintln!("skipping: sandbox denies bind");
        return;
    }
    let cfg = izba_core::daemon::egress::config::EgressPolicyConfig::from_yaml(
        "enforce: true\nallow:\n  - '*.example.test'\n",
    )
    .unwrap();
    let policy = cfg.into_policy("web").unwrap();
    // ... drive the harness exactly like the existing test, once per host:
    //   "api.example.test"  -> expect the upstream response (Allow)
    //   "example.test"      -> expect the 403 policy body (Deny: apex)
    //   "a.b.example.test"  -> expect the 403 policy body (Deny: one label only)
}
```

(The `...` is filled by mirroring the existing test's harness calls — same
upstream fake, same connect/claim sequence; only the policy source and the
host list differ. Do not redesign the harness.)

- [ ] **Step 3: Run it for real** — the test binds loopback listeners, so run it with the Bash sandbox DISABLED (it self-skips inside the sandbox and that proves nothing):

Run (unsandboxed): `cargo test -p izba-core --test egress_mitm -- --nocapture`
Expected: PASS with both the pre-existing and the new test actually executing (no "skipping: sandbox denies bind" lines).

- [ ] **Step 4: Gate + commit**

Run: `cargo test -p izba-core && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
```bash
git add crates/izba-core/tests/egress_mitm.rs
git commit -m "test(core): wildcard hosts enforce through the real MITM datapath"
```

---

### Task 7: Docs

**Files:**
- Modify: `README.md` (egress policy section, the `policy.yaml` example ~lines 67-93)
- Modify: `docs/egress-firewall-building-blocks.md` (the DNS-snoop matcher paragraph ~lines 82-92)

- [ ] **Step 1: README** — add a wildcard line to the YAML example after the `api.anthropic.com` entry:

```yaml
    - api.anthropic.com          # web ports only: 80 and 443
    - "*.mydomain.com"           # one subdomain label (api.mydomain.com; quote it — YAML)
    - "**.mydomain.com"          # any depth (a.b.mydomain.com); apex needs its own entry
```

and after the "A bare host authorizes ports 80 and 443 only..." paragraph, add:

```markdown
  Host entries may be wildcards: `*.mydomain.com` matches exactly one
  subdomain label (`api.mydomain.com`, not `a.b.mydomain.com`), and
  `**.mydomain.com` matches any depth. The apex (`mydomain.com`) never
  matches a wildcard — list it explicitly alongside. Patterns apply on both
  enforcement paths (decrypted SNI/Host and the DNS-snooped connect gate),
  and a malformed pattern (`foo.*.com`) is rejected loudly when the policy
  loads. Quote wildcard entries in YAML — a bare `*` is YAML syntax.
```

- [ ] **Step 2: building-blocks doc** — find the sentence describing planned snoop-matcher semantics ("exact / `*.x` one-label / `**.x` any depth, Cilium semantics", ~line 91) and annotate it as shipped, e.g. append: `*(Shipped: matched in `egress.rego` via `glob.match` with a `.` delimiter — one canonical matcher for both tiers, not a separate snoop-side list.)*` — adjust to the doc's actual phrasing after reading the paragraph.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/egress-firewall-building-blocks.md
git commit -m "docs: document wildcard egress host patterns"
```

---

### Task 8: GUI (PolicyEditor wildcard awareness) + app gate

**Files:**
- Modify: `app/src/components/PolicyEditor.tsx` (Hosts section help text ~line 260, placeholder ~line 273, `save()` ~line 229; new `hostPatternError` helper)
- Test: `app/src/test/policyEditor.test.tsx`

**Interfaces:**
- Consumes: nothing new over IPC — `AllowEntry` shape unchanged; the daemon re-validates via Task 3 (client check is UX, not the trust boundary).
- Produces: exported `hostPatternError(host: string): string | null` (exported for the test).

- [ ] **Step 1: Write the failing tests** — add to `app/src/test/policyEditor.test.tsx`, following the file's existing render/mocking pattern (read it first; reuse its `api` mock setup):

```tsx
it("accepts a wildcard host pattern and saves it", async () => {
  // Following the file's existing pattern: render PolicyEditor with the
  // mocked api, type "*.example.com" into the host input, click Save,
  // and assert api.policySetFull was called with
  // [{ host: "*.example.com", ports: [443], access: "read-write" }].
});

it("rejects a malformed wildcard pattern before saving", async () => {
  // Type "foo.*.com" into the host input, click Save, and assert:
  // - api.policySetFull was NOT called
  // - the error text mentions 'foo.*.com'
});
```

(Fill the bodies using the file's real helpers — the existing tests show how rows are added and Save is clicked; keep their idiom exactly.)

- [ ] **Step 2: Run to verify the reject-test fails**

Run: `cd app && npx vitest run src/test/policyEditor.test.tsx`
Expected: the malformed-pattern test FAILS (no client-side validation yet).

- [ ] **Step 3: Implement** — in `PolicyEditor.tsx`:

```tsx
/** Mirror of the daemon's validate_host_pattern: '*' only as a leading
 *  '*.'/'**.' label. The daemon re-validates on save — this is UX only. */
export function hostPatternError(host: string): string | null {
  const rest = host.startsWith("**.") ? host.slice(3) : host.startsWith("*.") ? host.slice(2) : host;
  if (rest === "" || rest.includes("*")) {
    return `Invalid host pattern "${host}": * is only allowed as a leading *. (one label) or **. (any depth) — e.g. *.example.com`;
  }
  return null;
}
```

In `save()`, before building `allow`:

```tsx
      for (const r of hosts) {
        const h = r.host.trim();
        if (h === "") continue;
        const bad = hostPatternError(h);
        if (bad) {
          setError(bad);
          return;
        }
      }
```

Update the Hosts help text:

```tsx
              Hosts this sandbox may reach — exact (api.example.com) or wildcard
              (*.example.com = one subdomain label, **.example.com = any depth; the
              apex needs its own entry). Add a port to a host, or remove one with its ✕.
```

and the placeholder: `placeholder="api.example.com or *.example.com"`.

- [ ] **Step 4: Run the app gates**

Run: `cd app && npm ci && npx vitest run && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: all PASS (the src-tauri part needs the worktree toolchain quirk: source `.cargo-env` if present).

- [ ] **Step 5: Commit**

```bash
git add app/src/components/PolicyEditor.tsx app/src/test/policyEditor.test.tsx
git commit -m "feat(app): wildcard host patterns in the policy editor (help + client-side validation)"
```

---

### Task 9: Full gates, delivery

- [ ] **Step 1: Run all six workspace gates** (source `.cargo-env` first):

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

Expected: all green.

- [ ] **Step 2: Re-run the unsandboxed MITM e2e** (`cargo test -p izba-core --test egress_mitm`) to confirm the wildcard path executes for real.

- [ ] **Step 3: Push the branch, open a draft PR** (repo-owner authorization in CLAUDE.md: push + `gh pr create` directly, unsandboxed), body summarizing spec + wildcard semantics table, ending with the Claude Code attribution trailer.
