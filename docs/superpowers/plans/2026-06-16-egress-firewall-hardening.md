# Egress Firewall Hardening (P1+P2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close egress findings F-01 (SSRF open proxy), F-02 (MITM SNI≠Host + missing private-IP guard), and F-03 (keep-alive only first request checked) by making the address denylist unconditional and replacing the hand-rolled MITM HTTP sniffer with a real hyper-util HTTP stack.

**Architecture:** Two serialized phases on the izbad egress plane. Phase 1 is a `router.rs`-only chokepoint change (PR-A). Phase 2 replaces `mitm.rs`'s orchestrator with a `hyper_util::server::conn::auto` policy `Service` that checks every request, binds ClientHello SNI to the HTTP Host, bridges h1/h2, handles WebSocket via h1 Upgrade, and fails closed on non-HTTP (PR-B). The CA/cert-cache/`SniResolver`, the loopback-hop `DstMap` rendezvous, and the OpenVMM churn-teardown on the vsock leg are untouched.

**Tech Stack:** Rust, tokio, rustls/tokio-rustls (ring), rcgen, hyper 1.x + hyper-util 0.1 + hyper-rustls 0.27 + http-body-util 0.1, regorus, webpki-roots.

**Design spec:** `docs/superpowers/specs/2026-06-16-egress-firewall-hardening-design.md`. **P3 (DNS) is out of scope** — see `docs/security/egress-firewall-p3-dns-resolve-and-pin.md`.

---

## Pre-flight (once, before any task)

- [ ] **Rebase onto real latest main.** This branch was cut from a stale local `origin/main` (no `deny.toml`). Run unsandboxed:

```bash
git -C /home/kolkhovskiy/git/izba fetch origin
cd /home/kolkhovskiy/git/izba/.claude/worktrees/egress-firewall-hardening
git rebase origin/main
ls deny.toml   # MUST now exist (PR #26's cargo-deny gate)
```

- [ ] **Baseline build green** (unsandboxed — KVM/network not needed, just the toolchain):

```bash
[ -f /home/kolkhovskiy/git/izba/.cargo-env ] && source /home/kolkhovskiy/git/izba/.cargo-env
cargo test -p izba-core --lib
```
Expected: all green (the existing 160+ lib tests pass).

> **Gate for every commit in this plan** (run before each `git commit`):
> ```bash
> cargo fmt --check
> cargo clippy -p izba-core --all-targets -- -D warnings
> cargo test -p izba-core --lib
> ```
> The Windows cross gate (`cargo clippy --target x86_64-pc-windows-gnu ...`) is
> run once at the end of each phase, not per-commit.

---

# Phase 1 — F-01 unconditional SSRF address denylist (PR-A)

**File:** `crates/izba-core/src/daemon/egress/router.rs` (only).

## Task 1: Harden `is_private` against IPv4-mapped IPv6

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (`is_private`, ~line 263; tests in the `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test** (add into `mod tests`):

```rust
#[test]
fn is_private_canonicalizes_ipv4_mapped_v6() {
    // ::ffff:127.0.0.1 and ::ffff:10.0.0.1 must be screened via their v4.
    assert!(is_private("::ffff:127.0.0.1".parse().unwrap()));
    assert!(is_private("::ffff:10.0.0.1".parse().unwrap()));
    assert!(is_private("::ffff:169.254.169.254".parse().unwrap()));
    // A public mapped address is NOT private.
    assert!(!is_private("::ffff:1.2.3.4".parse().unwrap()));
    // Native v6 loopback / public still classified correctly.
    assert!(is_private("::1".parse().unwrap()));
    assert!(!is_private("2606:4700:4700::1111".parse().unwrap()));
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p izba-core --lib is_private_canonicalizes_ipv4_mapped_v6`
Expected: FAIL — `::ffff:10.0.0.1` currently returns false (the v6 arm doesn't unwrap mapped v4).

- [ ] **Step 3: Implement** — make the V6 arm canonicalize mapped v4 first:

```rust
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            // Screen IPv4-mapped (::ffff:a.b.c.d) via the embedded v4 — a known
            // SSRF bypass. `to_ipv4_mapped` matches ONLY ::ffff:/96 (unlike the
            // deprecated `to_ipv4`, which would mis-map ::1 to 0.0.0.1).
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cargo test -p izba-core --lib is_private_canonicalizes_ipv4_mapped_v6`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/router.rs
git commit -m "fix(egress): screen IPv4-mapped IPv6 in the egress address denylist (F-01)"
```

## Task 2: Make `decide_tier2` deny private addresses unconditionally

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (`decide_tier2` ~line 226; flip `decide_tier2_permissive_allows_raw_ip` ~line 447; add a new test)

- [ ] **Step 1: Write the failing test + flip the codified hole.**

Add:
```rust
/// F-01: even a bare (non-enforcing AllowAll) sandbox must NOT be usable as an
/// SSRF proxy to loopback / link-local+metadata / RFC1918 / unspecified.
#[test]
fn decide_tier2_denies_private_even_for_bare_sandbox() {
    let snoop = SnoopStore::new();
    for ip in [
        "127.0.0.1",
        "169.254.169.254", // cloud metadata (link-local)
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "0.0.0.0",
    ] {
        let (v, _f, rule) = decide_tier2(&AllowAll, &snoop, "web", ip.parse().unwrap(), 6379);
        assert_eq!(v, Verdict::Deny, "bare sandbox must not reach {ip}");
        assert!(rule.contains("private"), "{ip}: {rule}");
    }
    // A public IP is still allowed for a bare sandbox.
    let (v, _f, _r) = decide_tier2(&AllowAll, &snoop, "web", "1.2.3.4".parse().unwrap(), 443);
    assert_eq!(v, Verdict::Allow);
}
```

Replace the body of the existing `decide_tier2_permissive_allows_raw_ip` (it currently asserts a bare sandbox reaches `10.0.0.5`) with the corrected expectation:
```rust
/// A bare sandbox (non-enforcing AllowAll) keeps today's permissive behavior for
/// PUBLIC destinations — a raw-IP dial with no snoop record is allowed — but the
/// unconditional SSRF denylist still blocks private addresses (F-01).
#[test]
fn decide_tier2_permissive_allows_public_raw_ip_but_denies_private() {
    let snoop = SnoopStore::new();
    let (v, _f, rule) = decide_tier2(&AllowAll, &snoop, "web", "1.2.3.4".parse().unwrap(), 8443);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(rule, "permissive");
    let (v2, _f2, r2) = decide_tier2(&AllowAll, &snoop, "web", "10.0.0.5".parse().unwrap(), 8443);
    assert_eq!(v2, Verdict::Deny);
    assert!(r2.contains("private"), "{r2}");
}
```
(Delete the old `decide_tier2_permissive_allows_raw_ip` — its name/intent are replaced.)

- [ ] **Step 2: Run, verify failure**

Run: `cargo test -p izba-core --lib decide_tier2`
Expected: the two new/edited tests FAIL (private IPs currently Allowed under AllowAll).

- [ ] **Step 3: Implement** — hoist the `is_private` guard above the `enforces()` split in `decide_tier2`:

```rust
pub fn decide_tier2(
    policy: &dyn Policy,
    snoop: &SnoopStore,
    sandbox: &str,
    ip: IpAddr,
    port: u16,
) -> (Verdict, FlowDesc, &'static str) {
    let names = snoop.fqdns_for(sandbox, ip);
    let mut flow = FlowDesc::l3(sandbox, ip.to_string(), port);
    flow.host = names.first().cloned();

    // UNCONDITIONAL SSRF / DNS-rebinding guard — applies to bare AND enforcing
    // sandboxes. A bare sandbox stays permissive for PUBLIC destinations only.
    if is_private(ip) {
        return (Verdict::Deny, flow, "private-address denylist");
    }

    if !policy.enforces() {
        let verdict = policy.check(&flow);
        return (verdict, flow, "permissive");
    }

    // (enforcing) private already denied above.
    if names.is_empty() {
        return (Verdict::Deny, flow, "no DNS-snoop record (raw IP)");
    }
    for name in &names {
        let mut f = flow.clone();
        f.addr = name.clone();
        f.host = Some(name.clone());
        if policy.check(&f) == Verdict::Allow {
            return (Verdict::Allow, f, "allow-list");
        }
    }
    (Verdict::Deny, flow, "not in allow-list")
}
```
(Remove the now-duplicate `if is_private(ip)` block that was inside the enforcing branch. Keep `decide_tier2_denies_private_ip_even_when_snooped` — it still passes.)

- [ ] **Step 4: Run, verify pass**

Run: `cargo test -p izba-core --lib decide_tier2`
Expected: PASS (all decide_tier2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/router.rs
git commit -m "fix(egress): deny private/loopback/metadata egress for bare sandboxes too (F-01)"
```

## Task 3: SSRF guard on the MITM tier-1 datapath

The MITM tier-1 path (`tcp_connect`, `port ∈ {80,443}` + enforcing) never calls `decide_tier2`, so it needs its own guard. Place ONE guard at the top of `tcp_connect` right after the IP parse — it covers both the MITM tier-1 path and the tier-2 path at runtime (port 53 short-circuits earlier and is unaffected).

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/router.rs` (`tcp_connect` ~line 56-89; add a handler test)

- [ ] **Step 1: Write the failing test** (uses the existing `spawn_handler`, which passes `mitm=None`; an enforcing policy + private OrigDst on 443 must deny with a *private-address* reason, NOT the "firewall unavailable" fail-closed reason — proving the guard fires before the MITM block):

```rust
#[test]
fn mitm_path_denies_private_origdst_before_mitm() {
    let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
    write_frame(
        &mut c,
        &StreamOpen::TcpConnect { addr: "127.0.0.1".into(), port: 443 },
    )
    .unwrap();
    match read_frame::<_, Response>(&mut c).unwrap() {
        Response::Error { kind, message } => {
            assert_eq!(kind, ErrorKind::ConnectFailed);
            assert!(message.contains("private"), "want private-address deny, got: {message}");
        }
        other => panic!("expected private-address deny, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run, verify failure**

Run: `cargo test -p izba-core --lib mitm_path_denies_private_origdst_before_mitm`
Expected: FAIL — currently a private OrigDst on 443 reaches the MITM block and returns the "firewall unavailable" message (or attempts a hop), not a "private" deny.

- [ ] **Step 3: Implement** — insert the guard immediately after the `let ip: IpAddr = match addr.parse() { ... };` block in `tcp_connect` (before the `if matches!(port, 80 | 443) ...` block):

```rust
    // UNCONDITIONAL SSRF guard for the whole TCP datapath (tier-1 MITM + tier-2).
    // port 53 short-circuited above; this covers everything else. Mirrors
    // decide_tier2's denylist so the MITM path can't be used to reach the host.
    if is_private(ip) {
        let flow = FlowDesc::l3(sandbox, addr, port);
        audit.record(AuditRecord::from_flow(
            Verdict::Deny, &flow, ip, Tier::L3, "private-address denylist",
        ));
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!("egress to {addr}:{port} denied: private address"),
            },
        );
        return;
    }
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test -p izba-core --lib router`
Expected: PASS (the new test + all existing router tests; `tcp_connect_dials_and_splices` uses `127.0.0.1` — see note).

> **NOTE — fix `tcp_connect_dials_and_splices` / `tcp_connect_refused_reports_connect_failed`:** both bind/dial `127.0.0.1`, which the new guard now denies. Update them to bind on a loopback listener but rewrite the *dialed addr* the guest sends. Loopback is intrinsically the test's target, so the cleanest fix is to special-case the guard for tests is WRONG (don't weaken prod). Instead, change those two tests to assert the new behavior: a `127.0.0.1` TcpConnect now returns a `ConnectFailed` "private address" deny. Concretely, replace their bodies with an assertion that dialing loopback is denied:
> ```rust
> #[test]
> fn tcp_connect_loopback_is_denied_as_private() {
>     let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
>     write_frame(&mut c, &StreamOpen::TcpConnect { addr: "127.0.0.1".into(), port: 9 }).unwrap();
>     match read_frame::<_, Response>(&mut c).unwrap() {
>         Response::Error { kind, message } => {
>             assert_eq!(kind, ErrorKind::ConnectFailed);
>             assert!(message.contains("private"), "{message}");
>         }
>         other => panic!("expected private deny, got {other:?}"),
>     }
> }
> ```
> Delete `tcp_connect_dials_and_splices` and `tcp_connect_refused_reports_connect_failed` (their real-dial happy-path is now covered by the MITM e2e in Phase 2 and the loopback target is forbidden). Keep `tcp_connect_port53_routes_to_resolver`, `tcp_connect_bad_addr_is_bad_request`, `unsupported_stream_open_is_bad_request`, `enforcing_https_fails_closed_when_mitm_unavailable` (the last uses `1.2.3.4`, a public IP — still valid).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/router.rs
git commit -m "fix(egress): deny private-address OrigDst on the MITM tier-1 path (F-01/F-02)"
```

## Task 4: Phase-1 cross-gate + PR-A

- [ ] **Step 1: Full gate incl. Windows cross**

```bash
cargo fmt --check
cargo clippy -p izba-core --all-targets -- -D warnings
cargo test -p izba-core --lib
cargo clippy --target x86_64-pc-windows-gnu -p izba-core --all-targets -- -D warnings
```
Expected: all green.

- [ ] **Step 2: Open PR-A** (give the user these commands — do not run `gh` from the sandbox):

```sh
git push -u origin worktree-egress-firewall-hardening
```
```sh
gh pr create --title 'fix(egress): unconditional SSRF address denylist (F-01)' --body '''
Closes F-01 and the F-02 private-IP gap. Makes the private/loopback/link-local/metadata/unspecified denylist an unconditional chokepoint in router.rs — applied to bare AND enforcing sandboxes, on both the tier-2 path and the MITM tier-1 path — plus IPv4-mapped-IPv6 bypass hardening. Bare sandboxes keep public egress; they lose loopback/metadata/RFC1918. Spec: docs/superpowers/specs/2026-06-16-egress-firewall-hardening-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
'''
```

- [ ] **Step 3: Check CI** with `gh pr checks` until green.

---

# Phase 2 — F-02/F-03 hyper-util MITM engine (PR-B, rebased on PR-A)

**Files:** `crates/izba-core/Cargo.toml`, `crates/izba-core/src/daemon/egress/mitm.rs`, `crates/izba-core/src/daemon/egress/mitm_runtime.rs`.

> Phase 2 implementation steps give the **approach + exact APIs + the test contract**; the executing subagent compiles and reconciles type details against the compiler (idiomatic for an async-Rust rewrite). The **tests are the contract** — they must pass as written.

## Task 5: Add the hyper stack as direct deps

**Files:** Modify `crates/izba-core/Cargo.toml`.

- [ ] **Step 1: Add deps** (versions already resolved in `Cargo.lock`, so no graph change):

```toml
# --- M2 MITM HTTP engine: hyper-util auto server (h1+h2) + per-request policy.
# Replaces the hand-rolled request sniffer; all already transitive via
# reqwest/oci-client, so no new cargo-deny surface. Pure-Rust + rustls/ring →
# x86_64-pc-windows-gnu cross stays green.
hyper = { version = "1", default-features = false, features = ["server", "client", "http1", "http2"] }
hyper-util = { version = "0.1", default-features = false, features = ["server-auto", "client-legacy", "http1", "http2", "tokio"] }
http-body-util = "0.1"
```
Ensure `tokio` features include `macros` (the existing `#[tokio::test]`s need it — if it builds today they are present; otherwise add `macros` to the dev-deps tokio).

- [ ] **Step 2: Build + supply-chain gate** (unsandboxed):

```bash
cargo build -p izba-core
cargo deny check advisories bans licenses sources
```
Expected: build green; `cargo deny` all `ok` (the four crates were already in the graph).

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/Cargo.toml Cargo.lock
git commit -m "build(egress): add hyper/hyper-util/http-body-util for the MITM engine"
```

## Task 6: Offer h2+http/1.1 on the client leg; extract SNI post-handshake

**Files:** Modify `crates/izba-core/src/daemon/egress/mitm.rs` (`server_config_with_resolver` ~line 241; add a helper + test).

- [ ] **Step 1: Write the failing test:**

```rust
#[test]
fn client_leg_alpn_offers_h2_and_http11() {
    let ca = IzbaCa::generate().unwrap();
    let cfg = server_config_with_resolver(Arc::new(CertCache::new(ca)));
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
}
```

- [ ] **Step 2: Run, verify failure** — `cargo test -p izba-core --lib client_leg_alpn_offers_h2_and_http11` (currently only `http/1.1`).

- [ ] **Step 3: Implement** — in `server_config_with_resolver`, set:

```rust
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
```

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs
git commit -m "feat(egress): offer h2 + http/1.1 on the MITM client leg"
```

## Task 7: The policy `Service` — SNI==Host + per-request policy + upstream forward

This replaces `mitm_terminate` + `read_request_head` + the manual `pump_bidirectional` with a hyper datapath. Design:

- A `tower`/`hyper::service::service_fn` closure capturing: the per-flow `Arc<dyn Policy>`, the audit sink, `sandbox`, `OrigDst{ip,port}`, the captured `client_sni: Option<String>`, the upstream `Arc<ClientConfig>` (webpki), and a lazily-established **shared upstream sender** (one upstream TLS connection per guest connection, reused across keep-alive requests; valid because SNI==Host pins the connection to one host).
- Per request the service: (a) reads `Host` (`req.uri().host()` for h2 absolute-form / the `host` header for h1 — normalize both, strip port); (b) if `client_sni` is Some and `!eq_ignore_ascii_case(host)` → return `403`; (c) `policy.check(FlowDesc{host, ...})` audited → Deny returns `403`; (d) Allow → forward via the upstream sender, returning the upstream response.
- Upstream sender: `let tcp = tokio::net::TcpStream::connect((orig.ip, orig.port)).await?;` → `tokio_rustls::TlsConnector::from(upstream_cfg).connect(ServerName::try_from(host), tcp).await?` (verifies cert for `host` against webpki) → pick `hyper::client::conn::http1::handshake` or `http2::handshake` based on `tls.get_ref().1.alpn_protocol()` → `tokio::spawn` the connection task → keep the `SendRequest` for reuse.

**Files:** Modify `crates/izba-core/src/daemon/egress/mitm.rs` (new orchestrator fn; keep CA/cache/SniResolver/`looks_like_tls`/`upstream_client_config*`). Extend tests.

- [ ] **Step 1: Write the failing tests** (extend the `duplex`-driven harness; reuse `test_ca_and_state`, `spawn_tls_upstream`, `install_ring`). The new orchestrator entry point is `serve_mitm(client_io, sni: Option<String>, state, policy_adapter, orig_dst)` (name it to fit; the test calls it). Two contracts:

```rust
/// F-03: every request on a kept-alive connection is policy-checked, not just
/// the first. Request 1 to the allowed host passes; request 2 reusing the same
/// TLS+TCP session with a DIFFERENT host is denied (403) and never reaches
/// upstream.
#[tokio::test]
async fn keepalive_second_request_is_rechecked() {
    install_ring();
    // Allow only api.anthropic.com; upstream answers for it.
    // Drive two requests over ONE guest TLS connection: first Host allowed,
    // second Host evil.example.com → expect 200 then 403.
    // (Build with test_ca_and_state + a single guest TlsStream; send
    //  "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n" then
    //  "GET / HTTP/1.1\r\nHost: evil.example.com\r\n\r\n" on the same stream;
    //  assert the second response is 403 Forbidden.)
}

/// F-02: ClientHello SNI must equal the HTTP Host. A guest that handshakes with
/// SNI=a.com then sends Host: b.com is rejected with 403, no upstream dial.
#[tokio::test]
async fn sni_host_mismatch_is_denied() {
    install_ring();
    // guest connects with ServerName "allowed.example.com" (gets a leaf),
    // sends "GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n" → 403.
}
```
(Port the existing `mitm_sees_l7_and_pipes_upstream_response` and `policy_deny_short_circuits_without_upstream` to call `serve_mitm` with `sni = Some(host)`.)

- [ ] **Step 2: Run, verify failure** — `cargo test -p izba-core --lib mitm` (new tests fail to compile/pass; `serve_mitm` doesn't exist yet).

- [ ] **Step 3: Implement `serve_mitm`** using `hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(client_io), service_fn(...))`. Host normalization helper:

```rust
fn req_host<B>(req: &hyper::Request<B>) -> Option<String> {
    req.uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

fn forbidden(body: &'static str) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(hyper::StatusCode::FORBIDDEN)
        .header(hyper::header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap()
}
```
The SNI==Host check inside the service: `if let Some(sni) = &client_sni { if Some(sni.as_str()) != host.as_deref() { audit Deny "sni-host-mismatch"; return Ok(forbidden(...)); } }`. Keep the existing `PolicyAdapter` (mitm_runtime.rs) shape for the audited policy decision, or inline an equivalent `policy.check(FlowDesc{...})` + `audit.record(...)`.

> Compiler-reconciliation hotspots (expected; resolve against `cargo build`):
> the body type for responses you synthesize vs. responses you proxy must unify
> (use `http_body_util::combinators::BoxBody<Bytes, E>` or
> `http_body_util::Either`); the upstream `SendRequest` h1-vs-h2 enum; and the
> `bytes` crate may need adding (it's transitive — add as a direct dep if the
> compiler asks).

- [ ] **Step 4: Run, verify pass** — `cargo test -p izba-core --lib mitm` (all, incl. ported happy-path/deny + the two new).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs
git commit -m "feat(egress): hyper-util MITM service — per-request policy + SNI==Host (F-02/F-03)"
```

## Task 8: Wire `serve_mitm` into the runtime; port-classify; non-HTTP fails closed

**Files:** Modify `crates/izba-core/src/daemon/egress/mitm_runtime.rs` (`accept_loop` ~line 200-238).

- [ ] **Step 1: Write the failing test** — a non-HTTP-over-TLS payload after termination must be denied cleanly (no panic/hang, no upstream dial). Add to `mitm.rs` tests (it exercises `serve_mitm` directly):

```rust
/// Non-HTTP after TLS termination ⇒ clean fail-closed (hyper rejects the
/// preface); serve_mitm returns without dialing upstream and without hanging.
#[tokio::test]
async fn non_http_over_tls_fails_closed() {
    install_ring();
    // guest handshakes (SNI allowed) then sends raw non-HTTP bytes
    // (e.g. b"\x00\x01\x02not-http") and half-closes; assert serve_mitm
    // completes (Ok/err) within a timeout and the upstream connector closure
    // was never invoked.
}
```

- [ ] **Step 2: Run, verify failure** (the connector-never-called assertion or a hang).

- [ ] **Step 3: Implement** — in `accept_loop`, after `dsts.claim(peer.port())` gives `(dst, policy)`, classify by `dst.port`:

```rust
        tokio::spawn(async move {
            let client_io: tokio::io::BufReader<_> = /* the accepted tcp */;
            if dst.port == 443 {
                // TLS-terminate; capture SNI; serve_mitm over the TLS stream.
                match acceptor.accept(tcp).await {
                    Ok(tls) => {
                        let sni = tls.get_ref().1.server_name().map(|s| s.to_string());
                        let _ = mitm::serve_mitm(tls, sni, &state, &adapter, dst.clone()).await;
                    }
                    Err(_) => { /* audited fail-closed: bad TLS on :443 */ }
                }
            } else {
                // port 80 cleartext: serve_mitm directly, sni = None.
                let _ = mitm::serve_mitm(tcp, None, &state, &adapter, dst.clone()).await;
            }
        });
```
Remove `mitm::mitm_terminate`, `read_request_head`, the old async `pump_bidirectional`/`copy_then_shutdown`, `MitmState` if unused, and the `#[cfg(test)] acceptor_for` if now unused — delete dead code, keep `looks_like_tls` only if still referenced (else delete its now-unused warning). `serve_mitm` non-HTTP handling: hyper's `serve_connection_with_upgrades` returns an error on a bad preface; treat as audited drop.

- [ ] **Step 4: Run, verify pass** — `cargo test -p izba-core --lib` (whole crate; ensure the runtime tests `dstmap_*` still pass).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs crates/izba-core/src/daemon/egress/mitm_runtime.rs
git commit -m "feat(egress): port-classified MITM wiring; non-HTTP fails closed (F-02)"
```

## Task 9: WebSocket upgrade bridging

**Files:** Modify `crates/izba-core/src/daemon/egress/mitm.rs` (in `serve_mitm`'s service); add a test.

- [ ] **Step 1: Write the failing test** — a WebSocket `Upgrade` request to an allowed host is policy-checked, gets `101`, and bytes bridge both ways:

```rust
/// A WebSocket upgrade to an allowed host is policy-checked, returns 101, and
/// the upgraded byte stream is bridged guest<->upstream.
#[tokio::test]
async fn websocket_upgrade_is_policy_checked_and_bridged() {
    install_ring();
    // upstream: accept the upgrade, echo one frame's bytes. guest: send
    // "GET /ws HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: Upgrade\r\n
    //  Upgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n",
    // expect 101, then send bytes and read them echoed back.
}
```

- [ ] **Step 2: Run, verify failure.**

- [ ] **Step 3: Implement** — in the service, when the request carries `Connection: Upgrade` + `Upgrade: websocket` and policy=Allow: forward the upgrade request upstream; on the upstream `101`, return `101` to the guest; then `tokio::spawn` a task that awaits `hyper::upgrade::on(guest_req)` and `hyper::upgrade::on(upstream_resp)` and runs `tokio::io::copy_bidirectional` between the two upgraded `TokioIo` streams. Policy still ran on the upgrade request's Host (and SNI==Host already enforced).

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs
git commit -m "feat(egress): bridge WebSocket upgrades through the MITM (F-03)"
```

## Task 10: h2 client-path test + Phase-2 cross-gate + PR-B

- [ ] **Step 1: Add an h2 client-path test** — drive the guest leg over h2 (negotiated via ALPN `h2`) and assert per-stream policy still applies:

```rust
/// The guest negotiates h2 (ALPN) and each request stream is policy-checked.
#[tokio::test]
async fn h2_client_path_is_policy_checked() {
    install_ring();
    // guest ClientConfig with alpn ["h2"]; send a request via an h2 client
    // (hyper::client::conn::http2 or hyper_util legacy Client over the duplex);
    // assert allowed Host → upstream 200, and a denied Host → 403.
}
```

- [ ] **Step 2: Run, verify pass** — `cargo test -p izba-core --lib`.

- [ ] **Step 3: Full gate incl. Windows cross**

```bash
cargo fmt --check
cargo clippy -p izba-core --all-targets -- -D warnings
cargo test -p izba-core --lib
cargo deny check advisories bans licenses sources
cargo clippy --target x86_64-pc-windows-gnu -p izba-core --all-targets -- -D warnings
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
```
Expected: all green.

- [ ] **Step 4: Commit + push + open PR-B** (rebased on PR-A / latest main):

```bash
git add crates/izba-core/src/daemon/egress/mitm.rs
git commit -m "test(egress): h2 client-path policy coverage"
```
Then give the user:
```sh
git push -u origin worktree-egress-firewall-hardening
```
```sh
gh pr create --title 'feat(egress): hyper-util MITM engine — per-request policy, SNI==Host, h2, WebSocket (F-02/F-03)' --body '''
Replaces the hand-rolled MITM HTTP sniffer with a hyper-util auto::Builder (h1+h2) policy Service. Closes F-02 (SNI==Host binding; private-IP guard landed in PR-A) and F-03 (every request policy-checked + audited, not just the first). WebSocket bridges via h1 Upgrade; non-HTTP-over-TLS fails closed; port-based TLS/cleartext classification (no peek/Rewind adapter). CA/cert-cache/SniResolver/loopback-hop/DstMap/churn-teardown contracts unchanged. Spec: docs/superpowers/specs/2026-06-16-egress-firewall-hardening-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
'''
```

- [ ] **Step 5: Check CI** with `gh pr checks` until green (watch the windows `cargo test` job — known occasionally-flaky per the CI-flakes notes; re-run if it hangs).

---

## Self-review notes (coverage map)

| Spec requirement | Task |
| --- | --- |
| F-01 unconditional denylist (tier-2) | Task 2 |
| F-01 MITM tier-1 private guard | Task 3 |
| F-01 IPv4-mapped-v6 hardening | Task 1 |
| F-01 bare keeps public egress | Task 2 (assertion) |
| F-02 SNI==Host | Task 7 |
| F-02 upstream cert verified vs Host (webpki) | Task 7 (upstream connector) |
| F-03 per-request policy + audit | Task 7 |
| h1+h2 engine | Tasks 6, 7, 10 |
| WebSocket via h1 Upgrade | Task 9 |
| non-HTTP fails closed | Task 8 |
| port-based classification (no Rewind) | Task 8 |
| deps already in graph / cargo-deny clean | Task 5 |
| Windows cross stays green | Tasks 4, 10 |
| contracts unchanged (DstMap/loopback/churn) | Tasks 7, 8 (kept) |

**F-05 (DNS) intentionally absent** — Phase 3 follow-on, gated on hickory-resolver (`docs/security/egress-firewall-p3-dns-resolve-and-pin.md`).
