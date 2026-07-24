# DNS Egress Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DNS resolution policy-aware in izbad's egress router so an enforcing sandbox can only resolve names its policy could authorize; every other QNAME is denied (NXDOMAIN), never forwarded upstream, and netlogged.

**Architecture:** Add a port/access-agnostic `resolvable` rule to `egress.rego` and a `Policy::allows_name` accessor. Gate the router's single DNS chokepoint (`dns_loop`, which serves `Dns`, `DnsTcp`, and `TcpConnect:53`): under an enforcing policy, parse the QNAME, and if the policy cannot authorize it, answer NXDOMAIN + audit-deny instead of forwarding. Non-enforcing sandboxes are untouched.

**Tech Stack:** Rust, `regorus` (Rego engine, already vendored), `hickory-proto` (DNS parse, already a dep of `dns_snoop.rs`).

## Global Constraints

- Design spec: `docs/superpowers/specs/2026-07-24-izba-dns-egress-enforcement-design.md` — the authority; read it first.
- TDD: tests first, watch them fail, then implement. Conventional commits (`feat(core): ...`, `feat(proto): ...`). Frequent commits.
- All six workspace gates must be green before the final push: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`, and the two `x86_64-pc-windows-gnu` check+clippy gates. Source `.cargo-env` first if present.
- No wire-protocol / manifest / `DAEMON_PROTO_VERSION` change. No app-gate impact (we deliberately reuse `Tier::L3`, add no audit enum variant).
- An **incremental cargo-mutants gate** runs in CI. New code with a trivially-surviving equivalent mutant must be handled the same way `servfail` is (a pinned, drift-checked exclusion in `.cargo/mutants.toml`) — see Task 1 Step 6.
- `izba-proto` must stay `no_std`-friendly of host assumptions and cross-compile to Windows — `nxdomain` uses only `&[u8]`/`Vec<u8>`, no new deps.

---

### Task 1: `nxdomain` DNS response helper (izba-proto)

**Files:**
- Modify: `crates/izba-proto/src/dns.rs` (add `nxdomain`, mirroring `servfail` at lines 38-46)
- Modify: `.cargo/mutants.toml` (add the equivalent-mutant exclusion, mirroring the `servfail` entry)
- Test: `crates/izba-proto/src/dns.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `pub fn nxdomain(query: &[u8]) -> Vec<u8>` — returns `query` with QR=1, RA=1, RCODE=3; ID + question section preserved; runt (<4 byte) input returned unchanged.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/izba-proto/src/dns.rs`:

```rust
#[test]
fn nxdomain_sets_qr_ra_rcode_keeps_id() {
    // 12-byte header: ID=0xbeef, flags=0x0100 (RD), 1 question.
    let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let r = nxdomain(&q);
    assert_eq!(&r[..2], &[0xbe, 0xef], "ID preserved");
    assert_eq!(r[2], 0x81, "QR set, RD preserved");
    assert_eq!(r[3], 0x83, "RA set, RCODE=3 (NXDOMAIN)");
    assert_eq!(&r[4..6], &q[4..6], "QDCOUNT preserved");
    assert_eq!(r.len(), q.len());
}

#[test]
fn nxdomain_on_runt_query_does_not_panic() {
    assert_eq!(nxdomain(&[0x01]), vec![0x01]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-proto nxdomain -- --nocapture`
Expected: FAIL — `cannot find function nxdomain in this scope`.

- [ ] **Step 3: Write minimal implementation**

Add directly after `servfail` (after line 46) in `crates/izba-proto/src/dns.rs`:

```rust
/// Turn `query` into an NXDOMAIN response in place: QR=1, RA=1, RCODE=3.
/// ID and question section are preserved so the client can match it. The
/// egress router uses this to deny a DNS name an enforcing policy did not
/// authorize — the query is never forwarded upstream.
//
// Mutation note: like `servfail`, the `| -> ^` mutant of `(resp[3] & 0xf0) | 0x03`
// is EQUIVALENT — `& 0xf0` clears the low nibble, so `| 0x03` and `^ 0x03` always
// agree — hence unkillable, and excluded by name in `.cargo/mutants.toml`.
pub fn nxdomain(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 4 {
        resp[2] |= 0x80; // QR: this is a response
        resp[3] = (resp[3] & 0xf0) | 0x03; // RCODE = NXDOMAIN
        resp[3] |= 0x80; // RA
    }
    resp
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-proto nxdomain`
Expected: PASS (both tests).

- [ ] **Step 5: Add a proptest robustness case (mirror `prop_servfail_robustness`)**

Add inside the `proptest! { ... }` block in the same test module:

```rust
/// nxdomain on arbitrary query bytes must never panic; length preserved,
/// ID preserved, and for >=4-byte inputs QR+RA set and RCODE low nibble = 3.
#[test]
fn prop_nxdomain_robustness(query in proptest::collection::vec(any::<u8>(), 0..=512usize)) {
    let resp = nxdomain(&query);
    prop_assert_eq!(resp.len(), query.len(), "length must be preserved");
    if query.len() >= 2 {
        prop_assert_eq!(&resp[..2], &query[..2], "ID preserved");
    }
    if query.len() >= 4 {
        prop_assert_eq!(resp[2], query[2] | 0x80, "QR set, other bits preserved");
        prop_assert!(resp[3] & 0x80 != 0, "RA set");
        prop_assert_eq!(resp[3] & 0x0f, 0x03, "RCODE = NXDOMAIN");
    }
    if query.len() >= 6 {
        prop_assert_eq!(&resp[4..6], &query[4..6], "QDCOUNT preserved");
    }
}
```

Run: `cargo test -p izba-proto nxdomain`
Expected: PASS.

- [ ] **Step 6: Pin the equivalent-mutant exclusion**

Read the existing `servfail` exclusion in `.cargo/mutants.toml` and `hack/mutants-check-excludes.py`. Add the analogous entry for `nxdomain`'s `(resp[3] & 0xf0) | 0x03` line (the `| -> ^` mutant), copying the servfail entry's exact shape/format. Then verify the drift checker is happy:

Run: `python3 hack/mutants-check-excludes.py`
Expected: exits 0 (no drift).

- [ ] **Step 7: Commit**

```bash
git add crates/izba-proto/src/dns.rs .cargo/mutants.toml
git commit -m "feat(proto): add nxdomain DNS response helper for policy-denied queries"
```

---

### Task 2: `resolvable` Rego rule + `Policy::allows_name` (izba-core)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/egress.rego` (append `resolvable` rules)
- Modify: `crates/izba-core/src/daemon/egress/policy.rs` (trait method + `RegoPolicy` override + tests)

**Interfaces:**
- Consumes: `RegoPolicy` (existing), `data.egress.resolvable` (new Rego rule).
- Produces: `Policy::allows_name(&self, sandbox: &str, name: &str) -> bool` — default `true`; `RegoPolicy` evaluates `data.egress.resolvable` with input `{sandbox, host: name}`, fail-closed `false` on engine error.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/izba-core/src/daemon/egress/policy.rs`:

```rust
#[test]
fn allows_name_exact_and_unlisted() {
    let p = RegoPolicy::embedded().unwrap();
    assert!(p.allows_name("web", "api.anthropic.com"), "listed global host resolvable");
    assert!(!p.allows_name("web", "evil.example.com"), "unlisted host not resolvable");
}

#[test]
fn allows_name_is_port_agnostic() {
    // A host scoped to a single non-web port is still resolvable (the bug a
    // fixed-port probe would cause).
    let data = r#"{"host_rules":{},"sandbox_host_rules":{"web":{"db.internal":{"ports":[5432],"access":"read-write"}}},"sandbox_git_rules":{}}"#;
    let p = RegoPolicy::with_data(data).unwrap();
    assert!(p.allows_name("web", "db.internal"), "port-agnostic: 5432-only host resolvable");
}

#[test]
fn allows_name_wildcard_and_apex() {
    let data = serde_json::json!({
        "host_rules": {}, "sandbox_host_rules": {},
        "wildcard_host_rules": [], "sandbox_git_rules": {},
        "sandbox_wildcard_host_rules": { "web": [{"pattern": "*.example.com", "ports": [443], "access": "read"}] }
    });
    let p = RegoPolicy::new(RegoPolicy::REGO, &data.to_string()).unwrap();
    assert!(p.allows_name("web", "api.example.com"), "wildcard child resolvable");
    assert!(!p.allows_name("web", "example.com"), "apex not resolvable");
    assert!(!p.allows_name("web", "a.b.example.com"), "single-label wildcard depth");
}

#[test]
fn allows_name_git_host_and_repo_prefix() {
    let p = policy_with_git(
        "web",
        r#"[{"repo":"github.com/myorg/app","access":"read"},{"host":"gitlab.com","access":"read"}]"#,
        "{}",
    );
    assert!(p.allows_name("web", "github.com"), "git repo host resolvable");
    assert!(p.allows_name("web", "gitlab.com"), "git host-scope resolvable");
    assert!(!p.allows_name("web", "bitbucket.org"), "unlisted git host not resolvable");
}

#[test]
fn allows_name_is_per_sandbox_isolated() {
    let data = serde_json::json!({
        "host_rules": {}, "sandbox_git_rules": {},
        "sandbox_host_rules": { "build": {"registry.corp": {"ports": [443], "access": "read"}} }
    });
    let p = RegoPolicy::new(RegoPolicy::REGO, &data.to_string()).unwrap();
    assert!(p.allows_name("build", "registry.corp"));
    assert!(!p.allows_name("web", "registry.corp"), "web must not inherit build's grant");
}

#[test]
fn allow_all_allows_any_name() {
    assert!(AllowAll.allows_name("web", "anything.example.com"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core allows_name`
Expected: FAIL — `no method named allows_name`.

- [ ] **Step 3: Append the `resolvable` rules to the Rego**

Append to `crates/izba-core/src/daemon/egress/egress.rego`:

```rego

# --- DNS resolvability (port/access-agnostic) ---
# May this QNAME be resolved at all? A name is resolvable iff SOME allow rule
# could match this host — port/method/access are deliberately ignored here and
# still enforced at connect time (tier-1 MITM / tier-2). This closes the
# QNAME-exfil channel: a name absent from every rule is never sent upstream.
default resolvable := false
resolvable if data.host_rules[input.host]
resolvable if data.sandbox_host_rules[input.sandbox][input.host]
resolvable if {
    some rule in data.wildcard_host_rules
    glob.match(rule.pattern, ["."], input.host)
}
resolvable if {
    some rule in data.sandbox_wildcard_host_rules[input.sandbox]
    glob.match(rule.pattern, ["."], input.host)
}
resolvable if {
    some rule in data.sandbox_git_rules[input.sandbox]
    rule.host == input.host
}
resolvable if {
    some rule in data.sandbox_git_rules[input.sandbox]
    startswith(rule.repo, sprintf("%s/", [input.host]))
}
```

- [ ] **Step 4: Add the trait method + `RegoPolicy` override**

In `crates/izba-core/src/daemon/egress/policy.rs`, add to the `Policy` trait (after `enforces`):

```rust
    /// Port/access-agnostic DNS gate: may this QNAME be resolved at all under
    /// an enforcing policy? Only consulted by the egress router when
    /// `enforces()` is true. Default permissive so a non-enforcing / future
    /// policy never blocks DNS by accident.
    fn allows_name(&self, _sandbox: &str, _name: &str) -> bool {
        true
    }
```

Add the `RegoPolicy` override inside `impl Policy for RegoPolicy` (after `check`):

```rust
    fn allows_name(&self, sandbox: &str, name: &str) -> bool {
        // Port/access-agnostic evaluation of `data.egress.resolvable`. Any
        // engine error is a fail-closed `false` — mirrors `check`.
        let input = serde_json::json!({ "sandbox": sandbox, "host": name }).to_string();
        let mut engine = self.template.clone();
        let verdict = (|| -> anyhow::Result<bool> {
            engine
                .set_input_json(&input)
                .map_err(|e| anyhow::anyhow!("set_input_json: {e}"))?;
            engine
                .eval_bool_query("data.egress.resolvable".to_string(), false)
                .map_err(|e| anyhow::anyhow!("eval_bool_query: {e}"))
        })();
        matches!(verdict, Ok(true))
    }
```

`AllowAll` needs no override (the trait default `true` is correct).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p izba-core allows_name`
Expected: PASS (all six tests).

- [ ] **Step 6: Regenerate & confirm the embedded doc has the wildcard keys**

The embedded doc in `RegoPolicy::embedded()` already includes `wildcard_host_rules`/`sandbox_wildcard_host_rules`. Confirm `allows_name_exact_and_unlisted` (which uses `embedded()`) passes — a missing key would make `resolvable` error → fail-closed. If any Rego rule references an absent `data.*` key, add that key (as `[]`/`{}`) to `embedded()` and to the `with_data` callers' expected shape. (The provided tests exercise all four data shapes, so a missing key surfaces here.)

- [ ] **Step 7: Commit**

```bash
git add crates/izba-core/src/daemon/egress/egress.rego crates/izba-core/src/daemon/egress/policy.rs
git commit -m "feat(core): add port-agnostic resolvable rule + Policy::allows_name"
```

---

### Task 3: `qname_of` QNAME extractor (izba-core)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/dns_snoop.rs` (add `qname_of` + tests)

**Interfaces:**
- Produces: `pub fn qname_of(msg: &[u8]) -> Option<String>` — first question's name, lowercased, trailing dot trimmed; `None` on parse failure, no question, or a root (`.`) query.

- [ ] **Step 1: Write the failing tests**

First read the top of `dns_snoop.rs` to match its existing `hickory_proto` import style (it already parses a `Message` in `extract_a_aaaa`). Add to its `tests` module:

```rust
#[test]
fn qname_of_extracts_lowercased_dotless_name() {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let mut m = Message::query();
    m.add_query(Query::query(Name::from_str("API.Anthropic.COM.").unwrap(), RecordType::A));
    let bytes = m.to_vec().unwrap();
    assert_eq!(qname_of(&bytes).as_deref(), Some("api.anthropic.com"));
}

#[test]
fn qname_of_none_on_garbage_and_empty() {
    assert_eq!(qname_of(&[0xff, 0x00, 0x01]), None, "unparseable -> None");
    assert_eq!(qname_of(&[]), None, "empty -> None");
}

#[test]
fn qname_of_none_on_root_query() {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut m = Message::query();
    m.add_query(Query::query(Name::root(), RecordType::NS));
    let bytes = m.to_vec().unwrap();
    assert_eq!(qname_of(&bytes), None, "root '.' query -> None");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core qname_of`
Expected: FAIL — `cannot find function qname_of`.

- [ ] **Step 3: Write the implementation**

Add to `crates/izba-core/src/daemon/egress/dns_snoop.rs` (mirror the module's existing `Message::from_vec` usage — adjust the import path to match `extract_a_aaaa`):

```rust
/// The first question's name in a DNS query — lowercased, trailing dot trimmed
/// (`api.anthropic.com`). `None` if the message does not parse, has no question,
/// or is a root (`.`) query. The egress router treats `None` as a fail-closed
/// deny (SERVFAIL) under an enforcing policy.
pub fn qname_of(msg: &[u8]) -> Option<String> {
    let parsed = hickory_proto::op::Message::from_vec(msg).ok()?;
    let q = parsed.queries().first()?;
    let name = q.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p izba-core qname_of`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/dns_snoop.rs
git commit -m "feat(core): add qname_of DNS question extractor for the egress DNS gate"
```

---

### Task 4: Gate `dns_loop` on policy (izba-core, router)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (change `dns_loop` signature + 3 call sites; add the enforcement branch; add tests; update 2 existing direct-call tests)

**Interfaces:**
- Consumes: `Policy::allows_name` (Task 2), `Policy::enforces`, `dns_snoop::qname_of` (Task 3), `dns::nxdomain` (Task 1), `AuditRecord::deny`, `Tier::L3`.
- Produces: no new public interface; `dns_loop`'s new signature is `fn dns_loop(conn, policy: &dyn Policy, resolver: &dyn Resolver, sandbox: &str, audit: &AuditSink, snoop: &SnoopStore, over_tcp: bool)`.

- [ ] **Step 1: Write the failing tests**

Add these helpers + tests to the `tests` module in `crates/izba-core/src/daemon/egress/router.rs`. `spawn_handler` already accepts a `policy` arg and passes it through `handle_conn`.

```rust
/// Build a minimal A-record DNS query for `name` with a fixed ID.
fn dns_query(name: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let mut m = Message::query();
    m.set_id(0x1234);
    m.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

/// Enforcing + unlisted QNAME → NXDOMAIN, and the query is NOT forwarded
/// (a forwarded FakeResolver reply would be `ans:...`, not a valid NXDOMAIN
/// derived from our query ID).
#[test]
fn enforcing_denies_unlisted_qname_with_nxdomain() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(&mut c, &StreamOpen::Dns).unwrap();
    let q = dns_query("evil.example.com.");
    dns::write_dns_msg(&mut c, &q).unwrap();
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(&resp[..2], &q[..2], "our query ID preserved (not a resolver echo)");
    assert_eq!(resp[3] & 0x0f, 0x03, "RCODE=NXDOMAIN");
}

/// Enforcing + allow-listed QNAME → forwarded (FakeResolver echoes `ans:`).
#[test]
fn enforcing_allows_listed_qname_and_forwards() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(&mut c, &StreamOpen::Dns).unwrap();
    let q = dns_query("api.anthropic.com.");
    dns::write_dns_msg(&mut c, &q).unwrap();
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(&resp[..4], b"ans:", "listed name forwarded to the resolver");
}

/// Non-enforcing (bare) sandbox → unchanged pass-through for ANY name.
#[test]
fn non_enforcing_forwards_any_qname() {
    let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
    write_frame(&mut c, &StreamOpen::Dns).unwrap();
    let q = dns_query("evil.example.com.");
    dns::write_dns_msg(&mut c, &q).unwrap();
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(&resp[..4], b"ans:", "bare sandbox forwards unchanged");
}

/// DnsTcp gets identical enforcement to UDP Dns.
#[test]
fn enforcing_denies_unlisted_over_dnstcp() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(&mut c, &StreamOpen::DnsTcp).unwrap();
    let q = dns_query("evil.example.com.");
    dns::write_dns_msg(&mut c, &q).unwrap();
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(resp[3] & 0x0f, 0x03, "DnsTcp denial is NXDOMAIN too");
}

/// TcpConnect:53 (the guest dialing an upstream resolver) gets identical
/// enforcement after the Ok handshake.
#[test]
fn enforcing_denies_unlisted_over_tcpconnect53() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(&mut c, &StreamOpen::TcpConnect { addr: "8.8.8.8".into(), port: 53 }).unwrap();
    assert!(matches!(read_frame::<_, Response>(&mut c).unwrap(), Response::Ok));
    let q = dns_query("evil.example.com.");
    dns::write_dns_msg(&mut c, &q).unwrap();
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(resp[3] & 0x0f, 0x03, "TcpConnect:53 denial is NXDOMAIN too");
}

/// Enforcing + unparseable query → SERVFAIL (fail-closed), not forwarded.
#[test]
fn enforcing_servfails_unparseable_query() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(&mut c, &StreamOpen::Dns).unwrap();
    dns::write_dns_msg(&mut c, &[0xff, 0x00, 0x01]).unwrap(); // not a DNS message
    let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
    assert_eq!(resp[3] & 0x0f, 0x02, "unparseable under enforce -> SERVFAIL");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core --lib daemon::egress::router`
Expected: FAIL — the new tests compile-fail (arity of `dns_loop` / behavior). If they compile, they fail on assertions (enforcing path still forwards today).

- [ ] **Step 3: Change the `dns_loop` signature and add the enforcement branch**

Replace `dns_loop` (currently `router.rs:395-427`) with:

```rust
/// Framed query/response pairs until EOF. Under an ENFORCING policy each query
/// is gated on its QNAME: a name the policy could not authorize is denied with
/// NXDOMAIN (an unparseable query with SERVFAIL) and audit-logged, and is NEVER
/// forwarded upstream — closing the QNAME-exfil channel. Allowed (and all
/// non-enforcing) queries forward as before; resolver failures become SERVFAIL.
/// Each forwarded answer is snooped (IP→FQDN for tier-2) BEFORE its reply is
/// written, so the mapping is installed before the guest can dial the address.
#[allow(clippy::too_many_arguments)]
fn dns_loop(
    mut conn: UdsStream,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    sandbox: &str,
    audit: &AuditSink,
    snoop: &SnoopStore,
    over_tcp: bool,
) {
    while let Ok(Some(query)) = dns::read_dns_msg(&mut conn) {
        if policy.enforces() {
            let name = dns_snoop::qname_of(&query);
            let authorized = name
                .as_deref()
                .is_some_and(|n| policy.allows_name(sandbox, n));
            if !authorized {
                let (reply, rule): (Vec<u8>, &str) = match &name {
                    Some(_) => (dns::nxdomain(&query), "DNS: not in allow-list"),
                    None => (dns::servfail(&query), "DNS: unparseable query (enforcing)"),
                };
                audit.record(AuditRecord::deny(
                    sandbox,
                    Ipv4Addr::UNSPECIFIED.into(),
                    53,
                    name.as_deref(),
                    Tier::L3,
                    rule,
                ));
                if dns::write_dns_msg(&mut conn, &reply).is_err() {
                    break;
                }
                continue;
            }
        }
        let result = if over_tcp {
            resolver.handle_tcp(&query)
        } else {
            resolver.handle(&query)
        };
        let resp = result.unwrap_or_else(|e| {
            eprintln!("izbad: dns forward failed: {e:#}");
            dns::servfail(&query)
        });
        snoop.record(sandbox, &dns_snoop::extract_a_aaaa(&resp));
        if dns::write_dns_msg(&mut conn, &resp).is_err() {
            break; // stop answering, but still drain + half-close below
        }
    }
    let _ = conn.shutdown(std::net::Shutdown::Write);
    // Drain to EOF so the guest is never force-closed with TX buffered
    // (the M0 vsock-churn contract; mirrors copy_until_eof's discipline).
    let mut sink = [0u8; 4096];
    loop {
        match std::io::Read::read(&mut conn, &mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
```

Confirm the imports at the top of `router.rs` already bring `Tier` into scope (`use super::audit::{AuditRecord, AuditSink, Tier};`) and `Ipv4Addr` (line 6) and `dns` (via `izba_proto::{dns, ...}`). No new `use` needed.

- [ ] **Step 4: Update the 3 production call sites**

In `handle_conn` (`router.rs:38-55`), the `Dns`/`DnsTcp` arms:

```rust
        StreamOpen::Dns => dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, false),
        StreamOpen::DnsTcp => dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, true),
```

In `tcp_connect` (`router.rs:75-81`), the `port == 53` short-circuit:

```rust
    if port == 53 {
        if write_frame(&mut conn, &Response::Ok).is_err() {
            return;
        }
        dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, true);
        return;
    }
```

(`tcp_connect` already has `policy: Arc<dyn Policy>`, `audit`, `snoop`, `sandbox` in scope.)

- [ ] **Step 5: Update the 2 existing direct-`dns_loop` tests**

`dns_loop_snoops_returned_a_records` and `dns_loop_no_deadlock_when_client_stops_reading` call `dns_loop` directly with the old signature. Update both calls to the new arity, using a non-enforcing `AllowAll` (preserves the exact behavior they assert) and a temp `AuditSink`:

```rust
// in dns_loop_snoops_returned_a_records — replace the dns_loop spawn line:
let audit = AuditSink::new(crate::paths::Paths::with_root(
    std::env::temp_dir().join("izba-router-dnsloop-test"),
));
let h = s.spawn(|| dns_loop(server, &AllowAll, &resolver, "web", &audit, &snoop, false));
```

```rust
// in dns_loop_no_deadlock_when_client_stops_reading — replace the dns_loop call:
let audit = AuditSink::new(crate::paths::Paths::with_root(
    std::env::temp_dir().join("izba-router-dnsloop-test"),
));
dns_loop(s, &AllowAll, &FakeResolver, "web", &audit, &SnoopStore::new(), false);
```

Add `use crate::daemon::egress::policy::AllowAll;` if not already imported in the test module (it is imported at `router.rs:432`).

- [ ] **Step 6: Run the router tests to verify they pass**

Run: `cargo test -p izba-core --lib daemon::egress::router`
Expected: PASS (new + existing tests).

- [ ] **Step 7: Full workspace gates**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-core/src/daemon/egress/router.rs
git commit -m "feat(core): enforce policy on DNS resolution in the egress router (#148)

Gate dns_loop (Dns/DnsTcp/TcpConnect:53) on an enforcing policy: deny an
unauthorized QNAME with NXDOMAIN (unparseable -> SERVFAIL) + a netlog entry,
never forwarding it upstream. Closes the QNAME-exfil / DNS-C2 channel that
made enforce:true a false promise for DNS. Non-enforcing sandboxes unchanged."
```

---

### Task 5: End-to-end verification (real VM, KVM-gated)

**Files:**
- Reference: `crates/izba-core/tests/integration.rs`, `docs/testing.md`
- Possibly modify: `crates/izba-core/tests/integration.rs` (add a DNS-enforcement e2e case if the harness supports an enforcing policy + in-guest resolution assertion)

**Interfaces:** none (verification task).

- [ ] **Step 1: Survey the existing egress/DNS integration coverage**

Read `crates/izba-core/tests/integration.rs` for existing egress cases. Determine whether a case already boots an enforcing sandbox and performs in-guest DNS. Note the harness helpers for: creating a sandbox with a `--policy`, running an in-guest command, and reading `logs/egress-audit.jsonl`.

- [ ] **Step 2: Add (or extend) a DNS-enforcement e2e case**

If a natural seam exists, add one gated test asserting the four-quadrant behavior end-to-end through a real microVM:
- enforcing sandbox: in-guest `getent hosts evil.example.com` (or `nslookup`) FAILS to resolve; an allow-listed name (e.g. `api.anthropic.com`) resolves.
- the denied query appears in `logs/egress-audit.jsonl` as a `deny` with `rule` starting `DNS:`.
If the harness cannot express this cleanly, record why in the PR and rely on the unit-level four-quadrant coverage (Task 4) — do not force a brittle e2e.

- [ ] **Step 3: Run the KVM integration + daemon e2e suites (unsandboxed)**

```bash
IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1
IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1
```
Expected: green (new case passes; no regression). `/dev/kvm` works here — run with the Bash sandbox disabled.

- [ ] **Step 4: Commit any e2e additions**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): e2e DNS egress enforcement across the four policy quadrants (#148)"
```

---

## Self-Review

**Spec coverage:**
- Decision point / gate in `dns_loop` covering all 3 variants → Task 4. ✓
- `allows_name` + `resolvable` Rego (port-agnostic) → Task 2. ✓
- `qname_of` extractor → Task 3. ✓
- `nxdomain` synthesis → Task 1. ✓
- Netlog via `Tier::L3` deny record → Task 4 (Step 3). ✓
- Four-quadrant + DnsTcp/TcpConnect:53 + unparseable + snoop-intact tests → Task 4 (Step 1) + existing `dns_loop_snoops_returned_a_records` retained via Task 4 Step 5. ✓
- End-to-end verification → Task 5. ✓
- `servfail` left untouched (mutation exclusion intact) → Task 1 adds a sibling, does not edit `servfail`. ✓

**Placeholder scan:** none — every code step shows complete code.

**Type consistency:** `dns_loop(conn, policy: &dyn Policy, resolver, sandbox, audit, snoop, over_tcp)` used identically in the signature (Task 4 Step 3) and all call sites (Steps 4–5). `allows_name(&self, sandbox: &str, name: &str) -> bool` consistent between Task 2 (def) and Task 4 (use). `qname_of(&[u8]) -> Option<String>` consistent between Task 3 (def) and Task 4 (use). `nxdomain(&[u8]) -> Vec<u8>` consistent between Task 1 (def) and Task 4 (use).
