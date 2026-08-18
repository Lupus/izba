# M5 P1 — the inspectability axis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make L7 inspectability a declared policy property (`protocol: http | tcp` on an allow entry) instead of a hard-coded `matches!(port, 80 | 443)`, so an operator can police an internal API on `:8000` and can open a documented, loud passthrough hatch for a TLS-pinned host — with no credential code anywhere.

**Architecture:** `protocol` is parsed by the existing strict manual walk into `AllowEntry`, compiled into an `InspectionTable` that rides beside the Rego engine (the axis is decided in Rust, never by Rego — D6), and consulted by the router's tier-1 gate. The pinning hatch is decided on the ClientHello SNI *before* TLS termination, and — because SNI is guest-controlled — only over a candidate set the router pre-computes from DNS-snoop through `decide_tier2`, so a passthrough flow is provably a subset of what tier-2 already permits.

**Tech Stack:** Rust, `serde_yaml` (manual walk, no derive), `regorus` (untouched), `tokio` + `tokio-rustls` (MITM runtime), `rustls` (untouched).

**Spec:** [docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md](../specs/2026-08-17-m5-credential-vault-design.md) — P1 is the second row of §3.1; the binding sections are D1, D2, D3, D12, §5, §7.1–§7.4, §7.8.

---

## Global Constraints

Every task's requirements implicitly include this section.

- **All six workspace gates green before every commit** (CLAUDE.md "Build & test"):
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`,
  `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`,
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
  Run `[ -f .cargo-env ] && source .cargo-env` first.
- **The app gate is NOT optional here.** `AllowEntry` is a public `izba-core` type the Tauri app embeds by path (`app/src-tauri/src/daemon.rs:68,82,383,419`, `fake.rs:249,285,694`). After any change to `AllowEntry` run:
  `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- **The default datapath must be byte-identical.** A policy in which no entry declares `protocol:` must compile to a byte-identical Rego data document AND take the same router branch it takes today. Both are guard-tested (Task 1 Step 1, Task 3 Step 1).
- **`to_rego_data_json` is not extended.** `protocol` never reaches Rego (D6). `egress.rego` is not edited in this plan.
- **Fail closed, always in the inspect direction.** Every ambiguity — a short peek, a malformed ClientHello, an absent SNI, a missing snoop record — resolves to *terminate and police*, never to splice. This is the one place in P1 where the obvious implementation has an exploitable failure direction (spec §7.4).
- **Only an explicit `protocol: tcp` opens the hatch.** A value *derived* from the port number never disables inspection (D12).
- **Unit tests never bind unix/vsock listeners** — some sandboxes deny `bind` with EPERM. Use `UnixStream::pair()` fakes; a test that genuinely needs a listener must runtime-skip on `PermissionDenied` (see `full_connect_via_listener` in `crates/izba-core/src/vsock.rs`, and `can_bind()` in `crates/izba-core/tests/egress_mitm.rs`).
- **TDD**: write the failing test, run it, watch it fail for the right reason, then implement. Conventional commits (`feat(egress): …`). Commit at the end of every task.
- **Mutation gate**: izba runs an incremental `cargo-mutants` gate that fails when a mutant survives on every CI platform. Prefer testing pure functions directly over asserting only through end-to-end paths.
- **No `git add -A`.** Stage named paths, verify with `git diff --cached --stat`, then commit.

---

## File Structure

| File | Change | Responsibility |
| --- | --- | --- |
| `crates/izba-core/src/daemon/egress/config.rs` | modify | `Protocol` enum, `protocol` on `AllowEntry::Scoped`, `parse_protocol`, effective-value accessors |
| `crates/izba-core/src/daemon/egress/inspect.rs` | **create** | `InspectionTable` — the axis compiled out of the allow-list |
| `crates/izba-core/src/daemon/egress/policy.rs` | modify | `Policy::inspects` / `Policy::passthrough_host`; `RegoPolicy` carries an `InspectionTable` |
| `crates/izba-core/src/daemon/egress/clienthello.rs` | **create** | Total, allocation-bounded ClientHello SNI extractor over a peeked buffer |
| `crates/izba-core/src/daemon/egress/router.rs` | modify | The tier-1 gate; `passthrough_names` (snoop-bound candidate set) |
| `crates/izba-core/src/daemon/egress/mitm_runtime.rs` | modify | Bounded ClientHello peek, the passthrough splice, its `Tier::L3` audit record |
| `crates/izba-core/src/daemon/egress/mod.rs` | modify | `mod inspect; mod clienthello;` |
| `crates/izba-core/src/manifest/diff.rs` | modify | `allow_index` carries protocol; `egress_weakens` flags `http → tcp` |
| `crates/izba-cli/src/commands/policy.rs` | modify | `render_policy` prints the axis, loudly for a passthrough entry |
| `crates/izba-core/tests/egress_inspect.rs` | **create** | Integration: `:8000` is policed; a passthrough host is never terminated |
| `CLAUDE.md`, the spec | modify | The contract paragraph; spec §15 Q4 resolved |

---

## Design decisions taken during planning

These resolve gaps the spec left open. Each is a *narrowing* of what the spec's prose would have produced; none widens any axis.

**DP-1 — `inspects()` never drops below `{80, 443}`.** The spec's §7.3 replaces `matches!(port, 80 | 443) && policy.enforces()` with `policy.enforces() && policy.inspects(port)`. Read literally as "∃ an entry declaring http on this port", that would *stop* inspecting `:443` for an enforcing policy whose allow-list happens to name no web-port host — moving those flows from a fail-closed L7 deny to a tier-2 deny. Same verdict today, but a different code path, a different audit `Tier`, and a control that shrinks when the allow-list shrinks. So `inspects(port)` is `port ∈ {80, 443} ∪ {ports declaring http}`: the axis widens only. The single narrowing device is the host-keyed hatch, decided on SNI (D3).

**DP-2 — the hatch is bound to the destination by DNS-snoop, not by the guest's SNI alone.** SNI is a string the guest chooses. A passthrough that spliced to `OrigDst.ip` on the strength of that string alone would be an unrestricted exfiltration channel: `SNI: pinned.vendor.com` + any IP the guest likes. Tier-1 does not have this problem today because `dial_upstream` verifies the upstream certificate against the vetted host (`mitm.rs:503-510`) — and a passthrough has no such verification by construction, since the point is that only the *guest* validates the certificate. So the router computes the candidate set: the snoop-bound FQDNs for that IP that the operator declared passthrough, filtered through `decide_tier2`. **A passthrough flow is exactly a tier-2 flow that additionally proves its SNI** — strictly narrower than what tier-2 already permits for the same address, and it inherits the rebinding guard (`is_lan` ⇒ no name-authorized reach) for free.

**DP-3 — the hatch requires an exact host; `protocol: tcp` on a wildcard entry is a parse error.** Matching an SNI against `*.vendor.com` in Rust would mean reimplementing the wildcard semantics that live in `egress.rego`, and a divergence between the two implementations is precisely the shape of a security bug. Rejecting at parse time with a message naming the fix ("name the host explicitly") is fail-closed and costs an operator one line. `protocol: http` on a wildcard is fine — it only widens inspection.

**DP-4 — the hatch is TLS-only.** A cleartext leg has no pinning to protect, so it always terminates. A host declared `protocol: tcp` that is then reached in cleartext is inspected — izba enforcing more than the declaration asks for, which is the direction D12 already sanctions.

**DP-5 — `protocol` is stored as `Option<Protocol>`, and only `Some(Tcp)` opens the hatch.** `None` means "derive from the port". Derivation is per-port, not per-entry, so an entry listing `[443, 5432]` is inspected on `443` and spliced on `5432` without the operator writing anything. A derived `Tcp` never registers a passthrough (D12).

**DP-6 — P1 adds no policy-mutation CLI surface.** `izba policy allow --protocol` would drag the normalized-mutation contract (#170/#172: `collapse_duplicate_hosts`, `set_host_access`, the compile-faithful diff fold) into a plan that is otherwise purely additive. The authoring paths that work on day one are editing `policy.yaml` directly and — because `spec.egress` in `izba.yml` deserializes through the *same* `EgressPolicyConfig` (`config.rs:147-159`) — `izba diff` / `izba promote`, which is also where the `⚠ weakens egress` gate lives. `izba policy show` renders the axis read-only (Task 7). A `--protocol` authoring flag is named as a follow-up in Task 9.

**DP-7 — this also answers spec §15 open question 4.** `protocol` is on the manifest's `spec.egress` automatically, because the manifest reuses `EgressPolicyConfig` verbatim rather than mirroring it. That is not a choice to make; it is a fact to test (Task 6).

**DP-8 — `izba status` has no egress block today** (`crates/izba-cli/src/commands/status.rs` renders no policy at all), so §5.2's "reported by `izba status`" lands on `izba policy show`. Adding an egress block to `status` is out of scope and named as a follow-up.

---

### Task 1: `Protocol` on the allow entry

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (`AllowEntry` at `:52`, `parse_allow_entry` at `:832`, `parse_access` at `:818`)
- Modify (mechanical only): `crates/izba-cli/src/commands/policy.rs`, `crates/izba-core/src/manifest/diff.rs`
- Test: in-file `#[cfg(test)] mod tests` in `config.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub enum Protocol { Http, Tcp }` (`Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize`, `#[serde(rename_all = "lowercase")]`)
  - `AllowEntry::Scoped` gains `protocol: Option<Protocol>`
  - `pub fn AllowEntry::declared_protocol(&self) -> Option<Protocol>`
  - `pub fn AllowEntry::protocol_for(&self, port: u16) -> Protocol`

- [ ] **Step 1: Write the failing tests**

Add to `config.rs`'s test module:

```rust
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
    assert_eq!(e.protocol_for(5432), Protocol::Tcp, "other port derives tcp");
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
    assert!(msg.contains("valid keys: host, ports, access, protocol"), "{msg}");
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
    assert!(!yaml.contains("protocol"), "canonical YAML must stay unchanged:\n{yaml}");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::config`
Expected: FAIL — `Protocol` not found, `declared_protocol` not found.

- [ ] **Step 3: Add the `Protocol` type and the accessors**

In `config.rs`, immediately after the `Access` type's helpers (near `is_default_access` at `:40`):

```rust
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
```

Extend the variant and add the accessors:

```rust
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
```

```rust
    /// The inspectability the operator wrote, if any. `None` means the entry
    /// says nothing and the effective value is derived per port.
    pub fn declared_protocol(&self) -> Option<Protocol> {
        match self {
            AllowEntry::Host(_) => None,
            AllowEntry::Scoped { protocol, .. } => *protocol,
        }
    }

    /// Effective inspectability for one of this entry's ports: the declared
    /// value when there is one, else `http` on the default web ports and `tcp`
    /// anywhere else.
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
```

- [ ] **Step 4: Add the parse leaf and wire it into the walk**

Beside `parse_access` (`config.rs:818`):

```rust
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
```

In `parse_allow_entry` (`config.rs:832`), add the key arm, the valid-key list, the field, and the DP-3 wildcard refusal:

```rust
            let mut host = None;
            let mut ports = None;
            let mut access = Access::default();
            let mut protocol = None;
            for (k, val) in m {
                match key_str(&format!("allow[{i}]"), k)?.as_str() {
                    "host" => host = Some(as_str(&format!("allow[{i}].host"), val)?),
                    "ports" => ports = Some(parse_ports(&format!("allow[{i}].ports"), val)?),
                    "access" => access = parse_access(&format!("allow[{i}].access"), val)?,
                    "protocol" => {
                        protocol = Some(parse_protocol(&format!("allow[{i}].protocol"), val)?)
                    }
                    other => anyhow::bail!(
                        "allow[{i}]: unknown key '{other}' \
                         (valid keys: host, ports, access, protocol)"
                    ),
                }
            }
            let host =
                host.ok_or_else(|| anyhow::anyhow!("allow[{i}]: missing required key 'host'"))?;
            validate_host_pattern(&host).with_context(|| format!("allow[{i}]"))?;
            // DP-3: the pinning hatch is keyed on the observed SNI, matched
            // EXACTLY. Honouring it for a wildcard would mean a second
            // implementation of the wildcard semantics that live in
            // egress.rego, and a divergence between the two is exactly the
            // shape of a security bug. Refuse, and name the fix.
            if protocol == Some(Protocol::Tcp) && is_wildcard_host(&normalize_policy_host(&host)) {
                anyhow::bail!(
                    "allow[{i}]: 'protocol: tcp' (the TLS-pinning passthrough) needs an exact \
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
```

Update the trailing `other =>` arm's message in the same function so the shape hint matches:

```rust
        other => anyhow::bail!(
            "allow[{i}]: expected a host string or a mapping with keys host, ports, access, \
             protocol; got {}",
            yaml_kind(other)
        ),
```

- [ ] **Step 5: Thread the new field through every existing `Scoped` literal**

This is a mechanical, compiler-verified pass: 111 sites across three files (72 in `config.rs`, 29 in `manifest/diff.rs`, 10 in `izba-cli/src/commands/policy.rs`), nearly all in test modules. Every one gets `protocol: None` — nothing in the tree declares an inspectability yet, and `None` is exactly "unchanged behaviour".

Run `cargo build --workspace 2>&1 | grep -c "missing field \`protocol\`"` to get the live count, add the field at each site, then re-run until zero. The compiler is the oracle: a missed site is a hard error, never a silent behaviour change. Finish with `cargo fmt`.

Do NOT change any test's expectations in this step. If a test's assertion changes, that is a behaviour change and belongs in a later task with its own reasoning.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress::config` → PASS
Then the full gate set: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [ ] **Step 7: Run the app gate**

`AllowEntry` is embedded by the Tauri app. Run:

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

Expected: green with no edits — the app only ever builds `AllowEntry::Host`. If it fails to compile, fix the app site in this task rather than deferring it.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-core/src/daemon/egress/config.rs crates/izba-cli/src/commands/policy.rs crates/izba-core/src/manifest/diff.rs
git diff --cached --stat
git commit -m "feat(egress): declare inspectability with protocol: http|tcp on an allow entry"
```

---

### Task 2: `InspectionTable` and the two `Policy` methods

**Files:**
- Create: `crates/izba-core/src/daemon/egress/inspect.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (add `mod inspect;`)
- Modify: `crates/izba-core/src/daemon/egress/policy.rs` (`Policy` trait `:52`, `AllowAll` `:86`, `RegoPolicy` `:104`, `into_policy` is in `config.rs:568`)
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (`into_policy`)
- Test: in-file in `inspect.rs` and `policy.rs`

**Interfaces:**
- Consumes: `Protocol`, `AllowEntry::declared_protocol`, `AllowEntry::protocol_for` (Task 1).
- Produces:
  - `pub struct InspectionTable` with `pub fn from_config(cfg: &EgressPolicyConfig) -> Self`, `pub fn inspects(&self, port: u16) -> bool`, `pub fn passthrough_host(&self, host: &str, port: u16) -> bool`
  - `Policy::inspects(&self, port: u16) -> bool` (default `false`)
  - `Policy::passthrough_host(&self, host: &str, port: u16) -> bool` (default `false`)
  - `RegoPolicy::with_data_and_inspection(data_json: &str, table: InspectionTable) -> anyhow::Result<Self>`

- [ ] **Step 1: Write the failing tests**

Create `crates/izba-core/src/daemon/egress/inspect.rs` with only its test module first (the impl arrives in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::EgressPolicyConfig;

    fn table(yaml: &str) -> InspectionTable {
        InspectionTable::from_config(&EgressPolicyConfig::from_yaml(yaml).expect("parses"))
    }

    // DP-1: the axis may only WIDEN against today's `matches!(port, 80 | 443)`.
    #[test]
    fn web_ports_are_inspected_even_when_no_entry_names_them() {
        let t = table("enforce: true\nallow:\n  - host: db.internal\n    ports: [5432]\n");
        assert!(t.inspects(80), "the 80/443 baseline is unconditional");
        assert!(t.inspects(443), "the 80/443 baseline is unconditional");
        assert!(!t.inspects(5432), "a derived-tcp port is not inspected");
    }

    #[test]
    fn a_declared_http_port_becomes_inspected() {
        let t = table(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        assert!(t.inspects(8000));
    }

    // The hatch is host-keyed, so it must NOT remove the port from the
    // inspected set — another host may still need L7 on it.
    #[test]
    fn an_explicit_tcp_entry_does_not_uninspect_its_port() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(t.inspects(443), "443 stays inspected for every other host");
        assert!(t.passthrough_host("pinned.vendor.com", 443));
    }

    #[test]
    fn passthrough_is_scoped_to_the_declared_ports() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(!t.passthrough_host("pinned.vendor.com", 80), "port 80 was not declared");
    }

    // DP-5: only an EXPLICIT declaration opens the hatch (D12).
    #[test]
    fn a_derived_tcp_never_opens_the_hatch() {
        let t = table("enforce: true\nallow:\n  - host: db.internal\n    ports: [5432]\n");
        assert!(
            !t.passthrough_host("db.internal", 5432),
            "an omitted protocol is a derivation, not an operator decision"
        );
    }

    #[test]
    fn passthrough_matching_uses_the_policy_host_normalization() {
        let t = table(
            "enforce: true\nallow:\n  - host: Pinned.Vendor.COM\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(t.passthrough_host("pinned.vendor.com", 443), "case-insensitive");
        assert!(t.passthrough_host("pinned.vendor.com.", 443), "trailing dot stripped");
    }

    // The trap this catches: a derived Default would be an EMPTY port set, and
    // `RegoPolicy::embedded()` / `with_data()` (used by the whole existing test
    // suite and by the global-host default policy) would stop inspecting.
    #[test]
    fn the_default_table_is_the_pre_m5_baseline_not_an_empty_set() {
        let t = InspectionTable::default();
        assert!(t.inspects(80) && t.inspects(443));
        assert!(!t.inspects(8000));
        assert!(!t.has_passthrough());
    }

    #[test]
    fn an_unknown_host_never_passes_through() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(!t.passthrough_host("evil.example.com", 443));
    }
}
```

And in `policy.rs`'s test module:

```rust
#[test]
fn allow_all_never_inspects_and_never_passes_through() {
    // M1 behaviour: a bare sandbox is not MITM'd at all, so it has no axis.
    assert!(!AllowAll.inspects(443));
    assert!(!AllowAll.passthrough_host("pinned.vendor.com", 443));
}

#[test]
fn rego_policy_answers_the_axis_from_its_compiled_table() {
    let cfg = crate::daemon::egress::config::EgressPolicyConfig::from_yaml(
        "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
    )
    .unwrap();
    let p = cfg.into_policy("web").unwrap();
    assert!(p.enforces());
    assert!(p.inspects(443), "baseline");
    assert!(p.inspects(8000), "declared http");
    assert!(!p.inspects(5432));
    assert!(p.passthrough_host("pinned.vendor.com", 443));
    assert!(!p.passthrough_host("internal.example.com", 8000));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::inspect daemon::egress::policy`
Expected: FAIL — `InspectionTable` and `Policy::inspects` do not exist.

- [ ] **Step 3: Implement `InspectionTable`**

Prepend to `crates/izba-core/src/daemon/egress/inspect.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! The **inspectability axis** compiled out of an allow-list (M5 spec §5).
//!
//! Held beside the Rego engine rather than inside it: `protocol` is decided in
//! typed Rust and never reaches the data document (D6), so `to_rego_data_json`
//! stays byte-identical whether or not an entry declares one.
//!
//! Two rules make this table safe to consult from the datapath:
//!
//! 1. `inspects` may only ever WIDEN against the pre-M5 `matches!(port, 80|443)`
//!    baseline (DP-1). Inspection is a security control; it must not shrink
//!    because an allow-list shrank.
//! 2. Only an EXPLICIT `protocol: tcp` registers a passthrough (D12). A value
//!    derived from a port number is a convenience, never an operator decision
//!    to disable a control.

use std::collections::BTreeSet;

use super::config::{is_wildcard_host, normalize_policy_host, AllowEntry, EgressPolicyConfig, Protocol};

/// Which ports izbad terminates at L7, and which exact hosts hold the
/// operator's pinning passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionTable {
    inspect_ports: BTreeSet<u16>,
    passthrough: BTreeSet<(String, u16)>,
}

/// **Not derived.** A derived `Default` would produce an EMPTY port set, which
/// reads as "inspect nothing" — so every `RegoPolicy` built without an explicit
/// table (`embedded`, `with_data`, and every test that uses them) would silently
/// stop terminating :80/:443. The default IS the pre-M5 baseline.
impl Default for InspectionTable {
    fn default() -> Self {
        Self {
            inspect_ports: AllowEntry::DEFAULT_PORTS.into_iter().collect(),
            passthrough: BTreeSet::new(),
        }
    }
}

impl InspectionTable {
    /// Compile the axis from a policy config.
    pub fn from_config(cfg: &EgressPolicyConfig) -> Self {
        // Starts from the unconditional baseline (DP-1) and only ever adds.
        let Self {
            mut inspect_ports,
            mut passthrough,
        } = Self::default();
        for e in &cfg.allow {
            let host = normalize_policy_host(e.host());
            for port in e.ports() {
                if e.protocol_for(port) == Protocol::Http {
                    inspect_ports.insert(port);
                }
                // Exact hosts only — `parse_allow_entry` refuses an explicit
                // `tcp` on a wildcard (DP-3), and this guard keeps the
                // invariant true for a config built in code rather than parsed.
                if e.declared_protocol() == Some(Protocol::Tcp) && !is_wildcard_host(&host) {
                    passthrough.insert((host.clone(), port));
                }
            }
        }
        Self {
            inspect_ports,
            passthrough,
        }
    }

    /// Whether a connection to `port` is terminated and policed at L7.
    pub fn inspects(&self, port: u16) -> bool {
        self.inspect_ports.contains(&port)
    }

    /// Whether `host` on `port` carries the operator's explicit pinning
    /// passthrough. `host` is the observed ClientHello SNI; it is normalized
    /// with the same identity the allow-list is keyed on (#170).
    pub fn passthrough_host(&self, host: &str, port: u16) -> bool {
        self.passthrough
            .contains(&(normalize_policy_host(host), port))
    }

    /// Whether any passthrough is declared at all. The datapath uses this to
    /// skip the ClientHello peek entirely for the overwhelmingly common policy
    /// that never opens the hatch, keeping that path byte-identical.
    pub fn has_passthrough(&self) -> bool {
        !self.passthrough.is_empty()
    }
}
```

If `is_wildcard_host` or `normalize_policy_host` are private in `config.rs`, make them `pub(crate)` — do not duplicate either function.

- [ ] **Step 4: Add the trait methods and wire `RegoPolicy`**

In `policy.rs`, on `trait Policy`:

```rust
    /// **Inspectability** (M5 D2): whether a connection to `port` is terminated
    /// and policed at L7 rather than spliced opaquely. Consulted by the egress
    /// router's tier-1 gate, and only when `enforces()` is true.
    ///
    /// Defaults to `false` so a non-enforcing policy is never MITM'd (M1
    /// behaviour). `RegoPolicy` answers from its compiled `InspectionTable`.
    fn inspects(&self, _port: u16) -> bool {
        false
    }

    /// The TLS-pinning passthrough (§5.2): whether the operator explicitly
    /// declared `protocol: tcp` for this exact host and port.
    ///
    /// `host` is the ClientHello SNI, which the guest controls — so a `true`
    /// here is NEVER sufficient on its own. The router additionally requires
    /// the destination address to be DNS-snoop-bound to this name and to pass
    /// `decide_tier2` (DP-2); see `router::passthrough_names`.
    fn passthrough_host(&self, _host: &str, _port: u16) -> bool {
        false
    }
```

`AllowAll` inherits both defaults — no change there. On `RegoPolicy`, add the field and the constructor:

```rust
pub struct RegoPolicy {
    template: regorus::Engine,
    query: String,
    /// The inspectability axis, decided in Rust rather than by the engine (D6).
    inspection: InspectionTable,
}
```

```rust
    /// Build from a data document plus the inspectability axis compiled from
    /// the same config. The two travel together so a policy can never answer
    /// `check` from one revision and `inspects` from another.
    pub fn with_data_and_inspection(
        data_json: &str,
        inspection: InspectionTable,
    ) -> anyhow::Result<Self> {
        let mut p = Self::new(Self::REGO, data_json)?;
        p.inspection = inspection;
        Ok(p)
    }
```

`new` and `embedded` keep `InspectionTable::default()` — which still inspects 80/443, matching today. Then:

```rust
impl Policy for RegoPolicy {
    // … check, allows_name unchanged …

    fn inspects(&self, port: u16) -> bool {
        self.inspection.inspects(port)
    }

    fn passthrough_host(&self, host: &str, port: u16) -> bool {
        self.inspection.passthrough_host(host, port)
    }
}
```

In `config.rs`, `into_policy` (`:568`) becomes:

```rust
    pub fn into_policy(&self, sandbox: &str) -> Result<Arc<dyn Policy>> {
        if !self.enforce {
            return Ok(Arc::new(AllowAll));
        }
        Ok(Arc::new(RegoPolicy::with_data_and_inspection(
            &self.to_rego_data_json(sandbox),
            InspectionTable::from_config(self),
        )?))
    }
```

Add `mod inspect;` + a `pub use` to `crates/izba-core/src/daemon/egress/mod.rs` beside the other submodules, matching how `config`/`policy` are declared there.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress` → PASS
Then: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/daemon/egress/inspect.rs crates/izba-core/src/daemon/egress/mod.rs crates/izba-core/src/daemon/egress/policy.rs crates/izba-core/src/daemon/egress/config.rs
git diff --cached --stat
git commit -m "feat(egress): compile the inspectability axis into the policy"
```

---

### Task 3: The router gate and the snoop-bound passthrough candidates

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (the gate at `:245`, `mitm_hop` at `:318`, `decide_tier2` at `:382`)
- Modify: `crates/izba-core/src/daemon/egress/mitm_runtime.rs` (`DstMap::insert` / `claim`, `MitmRuntime::register`)
- Test: in-file in `router.rs`

**Interfaces:**
- Consumes: `Policy::inspects`, `Policy::passthrough_host` (Task 2).
- Produces:
  - `pub fn router::passthrough_names(policy: &dyn Policy, snoop: &SnoopStore, sandbox: &str, ip: IpAddr, port: u16, usb: UsbGuard) -> Vec<String>`
  - `MitmRuntime::register(&self, src_port: u16, dst: OrigDst, policy: Arc<dyn Policy>, passthrough: Arc<[String]>)`
  - `DstMap::claim(&self, src_port: u16) -> Option<(OrigDst, Arc<dyn Policy>, Arc<[String]>)>`

- [ ] **Step 1: Write the failing tests**

In `router.rs`'s test module. The existing helpers (`RegoPolicy::with_data`, `spawn_handler`, the snoop fixtures) are already there — reuse them rather than inventing new ones.

```rust
    fn inspect_policy(yaml: &str) -> Arc<dyn Policy> {
        crate::daemon::egress::config::EgressPolicyConfig::from_yaml(yaml)
            .expect("parses")
            .into_policy("web")
            .expect("compiles")
    }

    // The guard test for the global constraint: a policy that declares no
    // protocol anywhere gates exactly where it gates today.
    #[test]
    fn a_policy_without_protocol_gates_on_the_web_ports_only() {
        let p = inspect_policy("enforce: true\nallow:\n  - github.com\n");
        for port in [80u16, 443] {
            assert!(p.inspects(port), "port {port} must still be tier-1");
        }
        for port in [22u16, 8000, 5432, 15001] {
            assert!(!p.inspects(port), "port {port} must still be tier-2");
        }
    }

    #[test]
    fn a_declared_http_port_is_gated_into_tier_one() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        assert!(p.enforces() && p.inspects(8000));
    }

    // DP-2: the hatch is bound to the address by DNS-snoop, not by the SNI.
    #[test]
    fn passthrough_candidates_require_a_snoop_binding() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let snoop = SnoopStore::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "no snoop record ⇒ no passthrough, so a raw-IP dial can never splice"
        );
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert_eq!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()),
            vec!["pinned.vendor.com".to_string()]
        );
    }

    #[test]
    fn passthrough_candidates_exclude_a_host_without_the_declaration() {
        let p = inspect_policy("enforce: true\nallow:\n  - api.anthropic.com\n");
        let snoop = SnoopStore::new();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "an ordinary allowed host must still be inspected"
        );
    }

    // The hatch inherits tier-2's DNS-rebinding guard for free.
    #[test]
    fn passthrough_candidates_are_empty_for_a_lan_address() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let snoop = SnoopStore::new();
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "a name must never authorize a LAN target (rebinding)"
        );
    }

    #[test]
    fn a_non_enforcing_policy_has_no_passthrough_candidates() {
        let snoop = SnoopStore::new();
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&AllowAll, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "a bare sandbox is never MITM'd, so it has nothing to pass through"
        );
    }

    // End-to-end through the real `handle_conn`. `spawn_handler` passes
    // `mitm: None`, so an INSPECTED port answers with the fail-closed
    // "firewall unavailable" error while a spliced port takes tier-2 — which
    // makes the gate's branch directly observable without a MITM runtime.
    #[test]
    fn the_router_gate_follows_the_declaration_end_to_end() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let mut c = spawn_handler(p, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "203.0.113.20".into(),
                port: 8000,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut c).unwrap();
        match resp {
            Response::Error { message, .. } => assert!(
                message.contains("HTTP(S) firewall unavailable"),
                ":8000 was declared http, so it must take the tier-1 branch: {message}"
            ),
            other => panic!("expected the fail-closed tier-1 error, got {other:?}"),
        }
    }

    #[test]
    fn an_undeclared_port_still_takes_tier_two() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let mut c = spawn_handler(p, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "203.0.113.21".into(),
                port: 5432,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut c).unwrap();
        match resp {
            Response::Error { message, .. } => assert!(
                message.contains("denied by policy"),
                "5432 was never declared, so it stays tier-2: {message}"
            ),
            other => panic!("expected a tier-2 policy denial, got {other:?}"),
        }
    }
```

Match `spawn_handler`'s real signature and the `write_frame`/`read_frame` imports already present in that test module (`router.rs:634`). `SnoopStore::record` takes `(&str, &[(String, IpAddr, u32)])` — the third element is the TTL.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::router`
Expected: FAIL — `passthrough_names` not found.

- [ ] **Step 3: Implement `passthrough_names` and change the gate**

In `router.rs`, beside `decide_tier2`:

```rust
/// The DNS-snoop-bound names for `ip` that the operator declared as the TLS
/// pinning passthrough on `port` (§5.2). Empty — the case for every policy that
/// never writes `protocol: tcp` — means "inspect", so the datapath is unchanged.
///
/// **Why this is not just `policy.passthrough_host(sni, port)`.** The SNI is a
/// string the guest chooses, and a passthrough has no upstream certificate
/// verification by construction — that is the whole point of the hatch. Deciding
/// on the SNI alone would therefore splice a guest-chosen ADDRESS on the
/// strength of a guest-chosen NAME: an unrestricted exfiltration channel. So the
/// candidate set is derived from what izbad's OWN resolver answered for this
/// address, and is filtered through `decide_tier2` — a passthrough flow is
/// exactly a tier-2 flow that additionally proves its SNI, and it inherits the
/// rebinding guard (`is_lan` ⇒ no name-authorized reach) unchanged.
pub fn passthrough_names(
    policy: &dyn Policy,
    snoop: &SnoopStore,
    sandbox: &str,
    ip: IpAddr,
    port: u16,
    usb: UsbGuard,
) -> Vec<String> {
    // A bare sandbox is never terminated, so it has nothing to pass through.
    if !policy.enforces() {
        return Vec::new();
    }
    // Tier-2 is the ceiling: if this flow would not be permitted as an opaque
    // splice, it is not permitted as a passthrough either.
    let (verdict, _, _) = decide_tier2(policy, snoop, sandbox, ip, port, usb);
    if verdict != Verdict::Allow {
        return Vec::new();
    }
    snoop
        .fqdns_for(sandbox, ip)
        .into_iter()
        .filter(|name| policy.passthrough_host(name, port))
        .filter(|name| {
            // decide_tier2 may have allowed on an explicit-IP rule; require the
            // NAME itself to be reachable before we honour its hatch.
            let mut f = FlowDesc::l3(sandbox, name.clone(), port);
            f.host = Some(name.clone());
            policy.check(&f) == Verdict::Allow
        })
        .collect()
}
```

Then the gate at `:245`:

```rust
    // Tier 1 — an INSPECTED port under an ENFORCING policy MUST be terminated by
    // the MITM, so the allow-list is judged on the decrypted Host (an IP is never
    // on a domain allow-list, so we do NOT pre-check on the IP here). Which ports
    // are inspected is now declared by the policy (`protocol:`, M5 D2) rather than
    // hard-coded to 80/443 — but the web ports are always in that set, so this
    // gate only ever widens (DP-1). A bare (non-enforcing) sandbox skips this
    // entirely and keeps the transparent direct dial — no CA trust, no http/1.1
    // downgrade, M1 behavior preserved.
    if policy.enforces() && policy.inspects(port) {
        match mitm {
            Some(mitm) => {
                let passthrough: Arc<[String]> =
                    passthrough_names(&*policy, snoop, sandbox, ip, port, usb).into();
                mitm_hop(
                    conn,
                    mitm,
                    Arc::clone(&policy),
                    ip,
                    port,
                    sandbox,
                    passthrough,
                )
            }
            None => { /* … unchanged fail-closed arm … */ }
        }
        return;
    }
```

`mitm_hop` gains the parameter and passes it to `register`:

```rust
fn mitm_hop(
    mut conn: UdsStream,
    mitm: &MitmRuntime,
    policy: Arc<dyn Policy>,
    ip: IpAddr,
    port: u16,
    sandbox: &str,
    passthrough: Arc<[String]>,
) {
    // … unchanged …
        mitm.register(
            src_port,
            OrigDst { ip, port, sandbox: sandbox.to_string() },
            Arc::clone(&policy),
            Arc::clone(&passthrough),
        );
    // … unchanged …
}
```

In `mitm_runtime.rs`, extend `DstEntry` with `passthrough: Arc<[String]>`, thread it through `DstMap::insert` / `claim` and `MitmRuntime::register`. `OrigDst` itself is **not** changed — it stays a pure destination, so `mitm.rs` and its test literals are untouched.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress` → PASS
Then: `cargo test --workspace` — the existing router/mitm_runtime tests must still pass; where a call site needs the new argument, pass `Arc::from(Vec::new())` and say so in the test's name or a comment, not by weakening an assertion.

`MitmRuntime::register` is also called from **`crates/izba-core/tests/egress_mitm.rs:99`** (its `guest_request` helper). That file is outside the crate, so only `cargo test --workspace` catches it — update it in this task, passing an empty candidate list.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/router.rs crates/izba-core/src/daemon/egress/mitm_runtime.rs
git diff --cached --stat
git commit -m "feat(egress): gate tier-1 on the declared inspectability, not the port"
```

---

### Task 4: A total ClientHello SNI extractor

**Files:**
- Create: `crates/izba-core/src/daemon/egress/clienthello.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (add `mod clienthello;`)
- Test: in-file

**Interfaces:**
- Consumes: nothing.
- Produces: `pub enum Sni { Found(String), Incomplete, None }` and `pub fn peek_sni(buf: &[u8]) -> Sni`.

This function parses bytes a hostile guest wrote. It must be **total**: no panics, no slice indexing, no unbounded allocation, no recursion.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid TLS 1.2+ ClientHello record whose
    /// only extension is `server_name` carrying `host` (or no extensions when
    /// `host` is `None`).
    fn client_hello(host: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(h) = host {
            let mut sni = vec![0x00]; // NameType: host_name
            sni.extend_from_slice(&(h.len() as u16).to_be_bytes());
            sni.extend_from_slice(h.as_bytes());
            let mut list = (sni.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&sni);
            ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type server_name
            ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&list);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0x00); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01); // compression_methods length
        body.push(0x00);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01]; // HandshakeType: client_hello
        let n = body.len();
        hs.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01]; // handshake, legacy version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_the_sni_from_a_well_formed_client_hello() {
        let buf = client_hello(Some("pinned.vendor.com"));
        assert_eq!(peek_sni(&buf), Sni::Found("pinned.vendor.com".into()));
    }

    #[test]
    fn lowercases_and_strips_the_trailing_dot() {
        let buf = client_hello(Some("Pinned.Vendor.COM."));
        assert_eq!(peek_sni(&buf), Sni::Found("pinned.vendor.com".into()));
    }

    #[test]
    fn a_client_hello_without_server_name_is_none() {
        assert_eq!(peek_sni(&client_hello(None)), Sni::None);
    }

    // The load-bearing distinction: "not yet" must not read as "no".
    #[test]
    fn every_truncation_of_a_valid_hello_is_incomplete_never_none() {
        let full = client_hello(Some("pinned.vendor.com"));
        for cut in 1..full.len() {
            assert_eq!(
                peek_sni(&full[..cut]),
                Sni::Incomplete,
                "a {cut}-byte prefix must ask for more, not answer"
            );
        }
    }

    #[test]
    fn an_empty_buffer_is_incomplete() {
        assert_eq!(peek_sni(&[]), Sni::Incomplete);
    }

    #[test]
    fn a_non_handshake_record_is_none() {
        assert_eq!(peek_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]), Sni::None);
    }

    #[test]
    fn a_handshake_that_is_not_a_client_hello_is_none() {
        let mut buf = client_hello(Some("h.example.com"));
        buf[5] = 0x02; // ServerHello
        assert_eq!(peek_sni(&buf), Sni::None);
    }

    #[test]
    fn a_non_ascii_or_oversized_name_is_refused() {
        let long = "a".repeat(300);
        assert_eq!(peek_sni(&client_hello(Some(&long))), Sni::None);
        let mut buf = client_hello(Some("ok.example.com"));
        let pos = buf.len() - 3;
        buf[pos] = 0xff; // not ASCII
        assert_eq!(peek_sni(&buf), Sni::None);
    }

    // Totality: no input may panic.
    #[test]
    fn arbitrary_truncations_and_mutations_never_panic() {
        let full = client_hello(Some("pinned.vendor.com"));
        for i in 0..full.len() {
            for b in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut m = full.clone();
                m[i] = b;
                let _ = peek_sni(&m);
                let _ = peek_sni(&m[..i]);
            }
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::clienthello`
Expected: FAIL — `peek_sni` not found.

- [ ] **Step 3: Implement the extractor**

```rust
// SPDX-License-Identifier: Apache-2.0
//! A total, bounded ClientHello SNI extractor for the pinning-passthrough
//! decision (M5 spec D3, §7.4).
//!
//! The bytes here are written by a hostile guest, so this module reads them
//! with `get(..)` only — no indexing, no slicing that can panic, no recursion,
//! and no allocation beyond one bounded hostname.
//!
//! It answers three things, and the difference between the last two is
//! load-bearing: `Found` (decide), `Incomplete` (the buffer holds a valid
//! prefix — the caller must peek again), and `None` (this is not a ClientHello
//! we will act on). The caller fails CLOSED to termination on both `Incomplete`
//! after its retry budget and `None`: a short read must never become a way to
//! escape inspection.

/// The longest hostname we will accept from an SNI extension (RFC 1035).
const MAX_SNI_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// A complete ClientHello carrying this (lowercased, dot-stripped) name.
    Found(String),
    /// A well-formed prefix: peek again for more bytes.
    Incomplete,
    /// Not a ClientHello, or a complete one with no usable `server_name`.
    None,
}

/// Extract the SNI from a peeked buffer.
pub fn peek_sni(buf: &[u8]) -> Sni {
    // TLSPlaintext: type(1) legacy_version(2) length(2) fragment
    let Some(header) = buf.get(..5) else {
        return Sni::Incomplete;
    };
    if header[0] != 0x16 {
        return Sni::None; // not a handshake record
    }
    let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let Some(fragment) = buf.get(5..5 + rec_len) else {
        return Sni::Incomplete;
    };

    // Handshake: msg_type(1) length(3) body
    let Some(&msg_type) = fragment.first() else {
        return Sni::None;
    };
    if msg_type != 0x01 {
        return Sni::None; // not a ClientHello
    }
    let Some(len_bytes) = fragment.get(1..4) else {
        return Sni::None;
    };
    let hs_len =
        ((len_bytes[0] as usize) << 16) | ((len_bytes[1] as usize) << 8) | len_bytes[2] as usize;
    let Some(body) = fragment.get(4..4 + hs_len) else {
        // The record is complete but the handshake message is not: the
        // ClientHello is fragmented across records. We do not reassemble —
        // treat it as "more bytes wanted", which after the caller's retry
        // budget fails closed to termination.
        return Sni::Incomplete;
    };

    let mut c = Cursor { buf: body, at: 0 };
    if c.skip(2 + 32).is_none() {
        return Sni::None; // client_version + random
    }
    if c.skip_vec8().is_none() {
        return Sni::None; // legacy_session_id
    }
    if c.skip_vec16().is_none() {
        return Sni::None; // cipher_suites
    }
    if c.skip_vec8().is_none() {
        return Sni::None; // legacy_compression_methods
    }
    let Some(exts) = c.take_vec16() else {
        return Sni::None; // no extensions block at all ⇒ no SNI
    };

    let mut e = Cursor { buf: exts, at: 0 };
    while let Some(ext_type) = e.take_u16() {
        let Some(ext_body) = e.take_vec16() else {
            return Sni::None;
        };
        if ext_type != 0x0000 {
            continue;
        }
        // ServerNameList: list_length(2) then entries of type(1) length(2) name
        let mut l = Cursor { buf: ext_body, at: 0 };
        let Some(list) = l.take_vec16() else {
            return Sni::None;
        };
        let mut n = Cursor { buf: list, at: 0 };
        while let Some(name_type) = n.take_u8() {
            let Some(name) = n.take_vec16() else {
                return Sni::None;
            };
            if name_type != 0x00 {
                continue; // only host_name is defined
            }
            return match normalize_sni(name) {
                Some(s) => Sni::Found(s),
                None => Sni::None,
            };
        }
        return Sni::None;
    }
    Sni::None
}

/// Lowercase, strip one trailing dot, and refuse anything that is not a plain
/// ASCII hostname of a sane length. The result is compared against the
/// operator's allow-list, so a name we cannot canonicalize is refused outright.
fn normalize_sni(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_SNI_LEN {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?;
    if !s.is_ascii() {
        return None;
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// A non-panicking forward reader over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn skip(&mut self, n: usize) -> Option<()> {
        self.at = self.at.checked_add(n)?;
        (self.at <= self.buf.len()).then_some(())
    }

    fn take_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let s = self.buf.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// A `u8`-length-prefixed vector's body.
    fn take_vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.take_u8()? as usize;
        self.take(n)
    }

    /// A `u16`-length-prefixed vector's body.
    fn take_vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.take_u16()? as usize;
        self.take(n)
    }

    fn skip_vec8(&mut self) -> Option<()> {
        self.take_vec8().map(|_| ())
    }

    fn skip_vec16(&mut self) -> Option<()> {
        self.take_vec16().map(|_| ())
    }
}
```

Note the `Incomplete` rule the tests pin: a truncation of a valid hello is `Incomplete` only while the shortfall is in the record header or the record body. Once the record body is present, structural nonsense inside it is `None`. If `every_truncation_of_a_valid_hello_is_incomplete_never_none` fails for prefixes longer than the record header, adjust the implementation — not the test — so any shortfall against a declared length reports `Incomplete`.

Add `mod clienthello;` to `mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress::clienthello` → PASS
Then: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/clienthello.rs crates/izba-core/src/daemon/egress/mod.rs
git diff --cached --stat
git commit -m "feat(egress): add a total ClientHello SNI extractor for the pinning hatch"
```

---

### Task 5: The pre-termination peek and the passthrough splice

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/mitm_runtime.rs` (`accept_loop` at `:236`, the 5-byte peek at `:274`)
- Test: in-file

**Interfaces:**
- Consumes: `Sni`, `peek_sni` (Task 4); `DstMap::claim` returning the passthrough list (Task 3).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing tests**

The peek loop and the splice both need a live socket, so test the **decision** as a pure function and leave the I/O to Task 8's integration test:

```rust
    // The decision the peek loop makes once it has (or fails to get) bytes.
    #[test]
    fn a_matching_sni_on_the_candidate_list_passes_through() {
        let cands: Vec<String> = vec!["pinned.vendor.com".into()];
        assert!(should_passthrough(&Sni::Found("pinned.vendor.com".into()), &cands));
    }

    #[test]
    fn an_sni_off_the_candidate_list_is_terminated() {
        let cands: Vec<String> = vec!["pinned.vendor.com".into()];
        assert!(!should_passthrough(&Sni::Found("evil.example.com".into()), &cands));
    }

    // Fail closed in the inspect direction, on every ambiguity.
    #[test]
    fn incomplete_and_absent_snis_are_terminated() {
        let cands: Vec<String> = vec!["pinned.vendor.com".into()];
        assert!(!should_passthrough(&Sni::Incomplete, &cands), "a short read must not escape inspection");
        assert!(!should_passthrough(&Sni::None, &cands));
    }

    #[test]
    fn an_empty_candidate_list_never_passes_through() {
        assert!(!should_passthrough(&Sni::Found("pinned.vendor.com".into()), &[]));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::mitm_runtime`
Expected: FAIL — `should_passthrough` not found.

- [ ] **Step 3: Implement the decision, the peek loop and the splice**

In `mitm_runtime.rs`:

```rust
/// How much of a ClientHello we are willing to peek. A TLS record caps at
/// 16 KiB and a post-quantum key share pushes a real hello past 2 KiB, so this
/// is generous rather than tight.
const SNI_PEEK_MAX: usize = 16 * 1024;
/// A ClientHello can span several TCP segments, so one `peek` may return a
/// short buffer. Retry to this bound and then FAIL CLOSED to termination.
const SNI_PEEK_TRIES: usize = 16;
const SNI_PEEK_DELAY: Duration = Duration::from_millis(20);

/// Whether this flow takes the pinning passthrough. Pure, so the fail-closed
/// direction is testable without a socket: anything other than a complete
/// ClientHello whose SNI is on the router's pre-computed candidate list
/// terminates and is policed.
fn should_passthrough(sni: &clienthello::Sni, candidates: &[String]) -> bool {
    match sni {
        clienthello::Sni::Found(name) => candidates.iter().any(|c| c == name),
        // A short read, a fragmented hello, a missing or unusable SNI: inspect.
        clienthello::Sni::Incomplete | clienthello::Sni::None => false,
    }
}

/// Peek (never consume) up to a full ClientHello, retrying while the buffer
/// holds only a valid prefix. Returns the best answer within the budget; the
/// bytes stay in the socket for whichever path runs next.
async fn peek_client_hello(tcp: &tokio::net::TcpStream) -> clienthello::Sni {
    let mut buf = vec![0u8; SNI_PEEK_MAX];
    for _ in 0..SNI_PEEK_TRIES {
        let n = tcp.peek(&mut buf).await.unwrap_or(0);
        match clienthello::peek_sni(&buf[..n]) {
            clienthello::Sni::Incomplete => tokio::time::sleep(SNI_PEEK_DELAY).await,
            decided => return decided,
        }
    }
    clienthello::Sni::Incomplete
}
```

And in `accept_loop`, after the TLS classification peek:

```rust
            let mut hdr = [0u8; 5];
            let n = tcp.peek(&mut hdr).await.unwrap_or(0);
            if mitm::looks_like_tls(&hdr[..n]) {
                // The pinning hatch (§5.2, D3) is decided from the ClientHello
                // SNI BEFORE termination, and only over the candidate list the
                // router derived from DNS-snoop — never from the SNI alone
                // (router::passthrough_names explains why). The list is empty
                // for every policy that declares no `protocol: tcp`, so the
                // common path does not even take the larger peek.
                if !passthrough.is_empty() {
                    let sni = peek_client_hello(&tcp).await;
                    if should_passthrough(&sni, &passthrough) {
                        let host = match &sni {
                            clienthello::Sni::Found(h) => h.clone(),
                            _ => unreachable!("should_passthrough only accepts Found"),
                        };
                        passthrough_splice(tcp, &dst, &audit_pt, &host).await;
                        return;
                    }
                }
                match state.acceptor.accept(tcp).await {
                    // … unchanged …
                }
            } else {
                // DP-4: a cleartext leg has no pinning to protect, so it always
                // terminates — izba enforcing more than the declaration asks
                // for, which is the direction D12 sanctions.
                let _ = mitm::serve_mitm(tcp, None, &state, adapter, dst.clone()).await;
            }
```

`audit_pt` is a clone of `audit` taken before it moves into the `PolicyAdapter`. The splice:

```rust
/// Splice a pinned flow straight through, unterminated. Audited as what it
/// actually is — a tier-3/L3 opaque pipe — so `izba netlog` shows the operator
/// exactly which flows their hatch exempted from L7 (§7.7).
async fn passthrough_splice(
    mut client: tokio::net::TcpStream,
    dst: &OrigDst,
    audit: &AuditSink,
    sni: &str,
) {
    let mut flow = FlowDesc::l3(&dst.sandbox, dst.ip.to_string(), dst.port);
    flow.host = Some(sni.to_string());
    let mut upstream = match tokio::net::TcpStream::connect((dst.ip, dst.port)).await {
        Ok(s) => s,
        Err(_) => {
            audit.record(AuditRecord::from_flow(
                Verdict::Deny,
                &flow,
                dst.ip,
                Tier::L3,
                "passthrough (protocol: tcp) — upstream dial failed",
            ));
            return;
        }
    };
    audit.record(AuditRecord::from_flow(
        Verdict::Allow,
        &flow,
        dst.ip,
        Tier::L3,
        "passthrough (protocol: tcp)",
    ));
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress::mitm_runtime` → PASS
Then all six gates.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm_runtime.rs
git diff --cached --stat
git commit -m "feat(egress): decide the pinning passthrough on the ClientHello SNI, pre-termination"
```

---

### Task 6: `protocol: http → tcp` is a `⚠ weakens egress` transition

**Files:**
- Modify: `crates/izba-core/src/manifest/diff.rs` (`allow_index` at `:113`, `egress_weakens` at `:141`)
- Test: in-file

**Interfaces:**
- Consumes: `AllowEntry::protocol_for` (Task 1).
- Produces: nothing for later tasks.

- [ ] **Step 1: Write the failing tests**

```rust
    fn eg(yaml: &str) -> EgressPolicyConfig {
        EgressPolicyConfig::from_yaml(yaml).expect("parses")
    }

    #[test]
    fn dropping_inspection_from_http_to_tcp_weakens_egress() {
        let from = eg("enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(
            egress_weakens(&from, &to),
            "the hatch drops L7 enforcement for this host — it must be flagged"
        );
    }

    #[test]
    fn adding_inspection_from_tcp_to_http_does_not_weaken() {
        let from = eg(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let to = eg("enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n");
        assert!(!egress_weakens(&from, &to), "restoring inspection tightens");
    }

    #[test]
    fn declaring_the_implied_protocol_is_not_a_change() {
        let from = eg("enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n    protocol: http\n",
        );
        assert!(!egress_weakens(&from, &to), "writing down what was already true");
        assert!(!egress_weakens(&to, &from));
    }

    #[test]
    fn opening_a_new_inspected_port_still_weakens_as_new_reachability() {
        let from = eg("enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [443, 8000]\n    protocol: http\n",
        );
        assert!(egress_weakens(&from, &to), "a new (host, port) is new reach");
    }

    // DP-7: the manifest reuses EgressPolicyConfig verbatim, so `protocol`
    // rides `spec.egress` with no mirroring — pin that so a future refactor
    // that forks the type is caught here.
    #[test]
    fn protocol_round_trips_through_a_manifest_spec_egress_block() {
        let spec: crate::manifest::schema::SandboxSpec = serde_yaml::from_str(
            "image: alpine\negress:\n  enforce: true\n  allow:\n    - host: pinned.vendor.com\n      ports: [443]\n      protocol: tcp\n",
        )
        .expect("spec.egress deserializes through EgressPolicyConfig's strict walk");
        assert_eq!(
            spec.egress.allow[0].declared_protocol(),
            Some(Protocol::Tcp)
        );
    }
```

Adapt the last test's `SandboxSpec` literal to the real field names and required keys in `crates/izba-core/src/manifest/schema.rs` — the point is that `protocol` survives the manifest path, not the exact minimal spec.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib manifest::diff`
Expected: FAIL — `dropping_inspection_from_http_to_tcp_weakens_egress` fails; the fold ignores `protocol`.

- [ ] **Step 3: Carry protocol through the compile-faithful fold**

`allow_index`'s value becomes a pair. The fold rules mirror the existing ones exactly — exact hosts OVERWRITE all prior cells for the host, wildcards UNION — with inspection folding to the most-inspecting value, the same direction `Access` folds to the most-permitting:

```rust
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<(String, u16), (Access, Protocol)> {
    let mut m: BTreeMap<(String, u16), (Access, Protocol)> = BTreeMap::new();
    for e in &eg.allow {
        let host = normalize_policy_host(e.host());
        let acc = e.access();
        if is_wildcard_host(&host) {
            for p in e.ports() {
                let proto = e.protocol_for(p);
                let entry = m.entry((host.clone(), p)).or_insert((acc, proto));
                if acc == Access::ReadWrite {
                    entry.0 = Access::ReadWrite;
                }
                // UNION: any rule granting inspection carries the cell.
                if proto == Protocol::Http {
                    entry.1 = Protocol::Http;
                }
            }
        } else {
            m.retain(|(h, _), _| h != &host);
            for p in e.ports() {
                m.insert((host.clone(), p), (acc, e.protocol_for(p)));
            }
        }
    }
    m
}
```

and in `egress_weakens`:

```rust
    for ((host, port), (to_access, to_proto)) in &ti {
        match fi.get(&(host.clone(), *port)) {
            None => return true, // new (host, port) allowed
            Some((from_access, from_proto)) => {
                if *from_access == Access::Read && *to_access == Access::ReadWrite {
                    return true; // widened verb on this (host, port)
                }
                // §5.2: dropping a host from inspected to opaque removes L7
                // enforcement for it — a weakening even though reachability
                // is unchanged.
                if *from_proto == Protocol::Http && *to_proto == Protocol::Tcp {
                    return true;
                }
            }
        }
    }
```

Update the doc comment on `egress_weakens` to list the new transition.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib manifest` → PASS. Every existing diff test must still pass untouched.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/diff.rs
git diff --cached --stat
git commit -m "feat(manifest): flag protocol: http -> tcp as a weakens-egress transition"
```

---

### Task 7: `izba policy show` reports the axis

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs` (`render_policy` at `:262`)
- Test: in-file

**Interfaces:**
- Consumes: `AllowEntry::declared_protocol`, `protocol_for` (Task 1).
- Produces: nothing for later tasks.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn show_marks_a_declared_http_port_as_inspected() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("internal.example.com"), "{out}");
        assert!(out.contains("http (inspected)"), "{out}");
    }

    #[test]
    fn show_is_loud_about_a_pinning_passthrough() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("passthrough"), "{out}");
        assert!(out.contains("no L7 rules"), "the operator must see what they gave up:\n{out}");
    }

    #[test]
    fn show_is_unchanged_for_a_policy_that_declares_nothing() {
        let cfg = EgressPolicyConfig::from_yaml("enforce: true\nallow:\n  - github.com\n").unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            !out.contains("passthrough") && !out.contains("inspected"),
            "the default rendering must not grow noise:\n{out}"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-cli --lib policy`
Expected: FAIL — the rendering carries no protocol.

- [ ] **Step 3: Render the axis**

In `render_policy`'s allow-list loop, after the access string:

```rust
                    // The inspectability axis (M5 §5). Silent when the entry
                    // declares nothing, so an existing policy renders exactly
                    // as it did; loud for the pinning hatch, which is the one
                    // value that gives enforcement up.
                    let proto_str = match e.declared_protocol() {
                        None => String::new(),
                        Some(Protocol::Http) => "  protocol: http (inspected)".to_string(),
                        Some(Protocol::Tcp) => {
                            "  protocol: tcp (passthrough: opaque splice, no L7 rules)".to_string()
                        }
                    };
                    let _ = writeln!(
                        out,
                        "    {}  [{ports}] ({access_str}){proto_str}",
                        e.host()
                    );
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-cli` → PASS, then all six gates.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/policy.rs
git diff --cached --stat
git commit -m "feat(cli): report the inspectability axis in izba policy show"
```

---

### Task 8: Integration — a pinned host reaches its own upstream, unterminated

**Files:**
- Create: `crates/izba-core/tests/egress_inspect.rs`
- Reference (reuse its harness): `crates/izba-core/tests/egress_mitm.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: nothing.

**What this task does and does not prove.** The router's gate is already covered
end-to-end in Task 3 through the real `handle_conn` (`spawn_handler`, whose
`mitm: None` makes the branch observable). What no in-crate test can show is the
*wire outcome* of the hatch — that izbad really did not terminate — because that
is only visible to a TLS client checking whose certificate it got. That is this
task's job, and it drives `MitmRuntime` directly the way `egress_mitm.rs` does.

Read `egress_mitm.rs` first and reuse `install_ring`, `can_bind`, `spawn_upstream`,
and the CA construction verbatim. Do not build a second harness.

- [ ] **Step 1: Write the failing tests**

```rust
// SPDX-License-Identifier: Apache-2.0
//! Integration coverage for the M5 P1 pinning passthrough (§5.2, D3): a flow
//! whose ClientHello SNI is on the router's candidate list is spliced
//! UNTERMINATED, and everything else still lands under the izba CA.
//!
//! The proof is whose certificate the client sees. The guest here trusts ONLY
//! the fake upstream's CA and not izba's, so a successful handshake means the
//! bytes reached the upstream untouched, and a failed one means izbad
//! terminated. That distinction is invisible to an in-crate test, which is why
//! this lives beside `egress_mitm.rs` rather than in `mitm_runtime.rs`.
//!
//! Binds loopback listeners, so it runtime-skips where the sandbox denies bind.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use izba_core::daemon::egress::audit::AuditSink;
use izba_core::daemon::egress::mitm::{
    server_config_with_resolver, upstream_client_config, CertCache, IzbaCa,
};
use izba_core::daemon::egress::mitm_runtime::{MitmRuntime, OrigDst};
use izba_core::daemon::egress::policy::{AllowAll, Policy};
use rustls::pki_types::{CertificateDer, ServerName};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_ring() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn can_bind() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok()
}

/// A TLS upstream under `cache`'s CA that answers every connection with
/// `PINNED-PONG` after reading one line. Deliberately NOT an HTTP server: a
/// passthrough is an opaque pipe, and asserting on a non-HTTP exchange proves
/// nothing parsed it.
async fn spawn_pinned_upstream(cache: Arc<CertCache>) -> u16 {
    let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(cache)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut b = [0u8; 5];
                let _ = tls.read_exact(&mut b).await;
                let _ = tls.write_all(b"PINNED-PONG").await;
                let _ = tls.flush().await;
            });
        }
    });
    port
}

/// Drive one flow through the runtime exactly as `router::mitm_hop` does, with
/// `passthrough` standing in for what `router::passthrough_names` computed.
async fn pinned_flow(
    mitm: &MitmRuntime,
    policy: &Arc<dyn Policy>,
    gcfg: &Arc<rustls::ClientConfig>,
    sni: &'static str,
    dst_port: u16,
    passthrough: Vec<String>,
) -> Result<String, String> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    sock.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    let src_port = sock.local_addr().unwrap().as_socket().unwrap().port();
    mitm.register(
        src_port,
        OrigDst {
            ip: Ipv4Addr::LOCALHOST.into(),
            port: dst_port,
            sandbox: "web".into(),
        },
        Arc::clone(policy),
        passthrough.into(),
    );
    sock.connect(&mitm.listen_addr().into()).unwrap();
    sock.set_nonblocking(true).unwrap();
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream).unwrap();

    let connector = TlsConnector::from(Arc::clone(gcfg));
    let name = ServerName::try_from(sni).unwrap();
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"HELLO").await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    tls.read_to_end(&mut got).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&got).into_owned())
}

/// Build the runtime plus a guest config trusting ONLY the upstream's CA.
/// Returns (runtime, guest config, upstream cert cache).
fn harness() -> (MitmRuntime, Arc<rustls::ClientConfig>, Arc<CertCache>) {
    let up_ca = IzbaCa::generate().unwrap();
    let up_ca_der: CertificateDer<'static> = up_ca.cert_der();
    let up_cache = Arc::new(CertCache::new(up_ca));

    let mut up_roots = rustls::RootCertStore::empty();
    up_roots.add(up_ca_der.clone()).unwrap();
    let upstream_cfg = upstream_client_config(up_roots);

    let izba_ca = IzbaCa::generate().unwrap();
    let izba_certs = Arc::new(CertCache::new(izba_ca));

    let audit = AuditSink::new(izba_core::paths::Paths::with_root(
        std::env::temp_dir().join("izba-egress-inspect-test-audit"),
    ));
    let mitm = MitmRuntime::start(izba_certs, upstream_cfg, audit).expect("start MITM runtime");

    // The pinned client: trusts the UPSTREAM's CA and NOT izba's.
    let mut guest_roots = rustls::RootCertStore::empty();
    guest_roots.add(up_ca_der).unwrap();
    let mut gcfg = rustls::ClientConfig::builder()
        .with_root_certificates(guest_roots)
        .with_no_client_auth();
    gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    (mitm, Arc::new(gcfg), up_cache)
}

#[test]
fn a_candidate_sni_is_spliced_untouched() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP a_candidate_sni_is_spliced_untouched: bind denied");
        return;
    }
    let (mitm, gcfg, up_cache) = harness();
    let policy: Arc<dyn Policy> = Arc::new(AllowAll);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_pinned_upstream(up_cache).await;
        let got = pinned_flow(
            &mitm,
            &policy,
            &gcfg,
            "pinned.vendor.com",
            up_port,
            vec!["pinned.vendor.com".to_string()],
        )
        .await
        .expect("a pinned client that trusts only its own CA must complete the handshake");
        assert!(
            got.contains("PINNED-PONG"),
            "the bytes must come from the real upstream, unparsed: {got}"
        );
    });
}

#[test]
fn an_sni_off_the_candidate_list_is_terminated() {
    install_ring();
    if !can_bind() {
        eprintln!("SKIP an_sni_off_the_candidate_list_is_terminated: bind denied");
        return;
    }
    let (mitm, gcfg, up_cache) = harness();
    let policy: Arc<dyn Policy> = Arc::new(AllowAll);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let up_port = spawn_pinned_upstream(up_cache).await;
        // The guest CLAIMS the pinned name, but the router bound no candidate
        // to this address — so izbad terminates and the pinned client, which
        // does not trust the izba CA, must fail.
        let err = pinned_flow(
            &mitm,
            &policy,
            &gcfg,
            "pinned.vendor.com",
            up_port,
            Vec::new(),
        )
        .await
        .expect_err("an empty candidate list must terminate, not splice");
        assert!(
            !err.is_empty(),
            "the pinned client must reject the izba-CA leaf"
        );
    });
}
```

- [ ] **Step 2: Run to verify they fail (or skip honestly)**

Run: `cargo test -p izba-core --test egress_inspect -- --nocapture`
Expected before Task 5's code exists: a compile failure on the 4-argument
`register`; after it, `a_candidate_sni_is_spliced_untouched` fails until the
splice works. If the harness cannot bind on this machine, both tests print SKIP
— report that as a skip, never as a pass. An integration test that never ran is
not evidence.

- [ ] **Step 3: Make them pass**

Fix the product, not the test. The likely first failure is the peek loop
returning `Incomplete` because the ClientHello arrives in more than one segment
— that is the retry budget doing its job, and if it still fails the budget or
the parser needs work, not the assertion.

- [ ] **Step 4: Run the gates and commit**

```bash
git add crates/izba-core/tests/egress_inspect.rs
git diff --cached --stat
git commit -m "test(egress): a pinned host is spliced untouched; everything else terminates"
```

---

### Task 9: Documentation and the named follow-ups

**Files:**
- Modify: `CLAUDE.md` (the "Load-bearing contracts" section)
- Modify: `docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md` (§3.1 staging table, §15)
- Modify: `README.md` if it documents the egress policy grammar (check first; skip silently if it does not)

- [ ] **Step 1: Update the load-bearing contract in `CLAUDE.md`**

In the `**Cmdline chain:**`/egress area, add to the egress contract paragraph:

```markdown
  **Inspectability is declared, not derived (M5 P1):** an allow entry carries
  `protocol: http | tcp`. `EgressPolicyConfig` compiles it into an
  `InspectionTable` (`daemon/egress/inspect.rs`) that rides beside the Rego
  engine — `protocol` NEVER enters `to_rego_data_json` (guard-tested). The
  router's tier-1 gate is `policy.enforces() && policy.inspects(port)`, and
  `inspects` always includes 80/443, so the axis only ever widens. The one
  narrowing device is the TLS-pinning hatch: an EXPLICIT `protocol: tcp` on an
  EXACT host (a wildcard is a parse error), decided from the ClientHello SNI
  before termination — and only over the candidate list
  `router::passthrough_names` derives from DNS-snoop through `decide_tier2`,
  never from the SNI alone, which the guest controls. Every ambiguity (short
  peek, fragmented hello, absent SNI) fails closed to termination.
  `protocol: http → tcp` is a `⚠ weakens egress` transition in
  `manifest::diff`.
```

- [ ] **Step 2: Mark P1 delivered in the spec and resolve its open question**

In §3.1's table, change P1's "Independently valuable?" cell to `**Delivered** — pays off M2 debt; L7 rules and the pinning hatch landed with no credential code`.

In §15, replace open question 4 with its answer:

```markdown
4. ~~Whether `protocol` belongs on the manifest's `spec.egress`~~ — **resolved
   during P1 planning: it is not a choice.** `izba.yml`'s `spec.egress`
   deserializes through `EgressPolicyConfig`'s own strict walk
   (`config.rs:147-159`), so `protocol` rides the manifest automatically; the
   USB comparison does not apply, because `spec.usb` mirrors a separate consent
   record while `spec.egress` reuses the policy type verbatim. What P1 owed was
   therefore a test that it survives the manifest round-trip, and the
   `http → tcp` weakening flag — both delivered.
```

Also append to §5.2, after the `weakens egress` paragraph:

```markdown
**Refinements taken during P1 implementation** (each narrows; none widens):
`inspects()` never drops below `{80, 443}`, so the axis only widens against the
pre-M5 baseline; the hatch requires an exact host, since matching an SNI against
a wildcard would fork the wildcard semantics that live in `egress.rego`; the
hatch is TLS-only, because a cleartext leg has no pinning to protect; and the
hatch is bound to the destination by DNS-snoop through `decide_tier2`, not by
the SNI alone — a passthrough flow is exactly a tier-2 flow that additionally
proves its SNI. Without that last one the hatch would splice a guest-chosen
address on the strength of a guest-chosen name.
```

- [ ] **Step 3: Name the follow-ups**

Append to §13 (out-of-scope follow-ups, named not built):

```markdown
- **`izba policy allow --protocol http|tcp`** — P1 deliberately added no
  policy-mutation CLI surface, because threading a new field through the
  normalized-mutation contract (#170/#172: `collapse_duplicate_hosts`,
  `set_host_access`, the compile-faithful diff fold) is a separate piece of work
  from the axis itself. Authoring works today by editing `policy.yaml` or
  through `izba.yml` + `izba diff`/`izba promote`, which is also where the
  weakening gate lives. `izba policy show` renders the axis read-only.
- **An egress block in `izba status`.** §5.2 says the axis is reported by
  `izba status`, but `status` renders no egress posture at all today, so P1
  landed the reporting in `izba policy show`. Adding an egress summary to
  `status` — inspected ports, passthrough hosts, enforce posture — is a small
  standalone improvement.
- **Reassembling a ClientHello fragmented across TLS records.** P1's extractor
  reads the first record only; a hello split across records reports
  `Incomplete` and therefore fails closed to termination, which breaks
  passthrough for a client that fragments. Rare in practice, honest in
  behaviour, and worth fixing if a real client hits it.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md
git diff --cached --stat
git commit -m "docs(m5): record the P1 inspectability contract and its named follow-ups"
```

---

## Definition of done

- All six workspace gates green, plus the app gate.
- `cargo test -p izba-core --test egress_inspect` passes (or skips honestly on a
  `bind`-denied sandbox, reported as a skip and not as a pass).
- A policy declaring no `protocol:` anywhere produces a byte-identical Rego data
  document and takes the same router branch as before this plan.
- The three follow-ups in Task 9 Step 3 are written down in the spec.
