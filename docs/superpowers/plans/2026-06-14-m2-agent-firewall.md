# M2 Agent Firewall (merged MITM L7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** izbad MITMs guest HTTP(S) egress, applies a two-tier (L7 + DNS-snoop) per-sandbox `regorus` allow-list with an audit log, and bakes its CA into the guest — the merged M2 agent firewall.

**Architecture:** A dedicated tokio MITM runtime in izbad, reached from the blocking vsock egress plane via a **loopback-hop** (the proven blocking `portfwd::pump_bidirectional` carries the vsock leg unchanged, so the OpenVMM churn invariant is untouched). Datapath + policy are vendored from two proven spikes. CA reaches the guest via a read-only virtiofs share.

**Tech Stack:** Rust, tokio, rustls/tokio-rustls/rcgen (ring), regorus, hickory-proto. Spikes: `worktree-agent-ad6d548620c1b7803` (mitm.rs), `worktree-agent-a3d5e8d4b200cedd7` (RegoPolicy).

**Source of truth for the design:** [../specs/2026-06-14-m2-agent-firewall-merged-design.md](../specs/2026-06-14-m2-agent-firewall-merged-design.md).

---

## Progress (2026-06-14) — branch `feat/m2-agent-firewall`

**DONE (committed, all six gates green: workspace tests + clippy -D warnings + fmt + musl-static init + windows cross-check):**
- ✅ **T1** vendor MITM datapath (`mitm.rs`, SPDX-attributed, 8 tests)
- ✅ **T2** per-SNI cert resolver (mint leaves from the ClientHello)
- ✅ **T3** `RegoPolicy` behind `Policy` + L7 `FlowDesc` (host/method/path); regorus pinned 0.4 (cached; bump to 0.10 when network — API-compatible)
- ✅ **T4** `MitmRuntime` + `DstMap` loopback bridge
- ✅ **T5** router two-tier dispatch (`:80/:443` → loopback hop; DNS always-allow; tier-2 direct dial); `socket2` register-before-connect (no race); churn invariant untouched
- ✅ **T12** CA-in-guest (`izba-init`: `izba-trust` share, `write_trust_anchor`, CA-bundle exec env) — contract: tag `izba-trust`, file `ca.pem`, guest `/etc/izba/ca{,-bundle}.pem`
- ✅ **T13 (host-level slice)** `tests/egress_mitm.rs` — full host-side e2e: guest→loopback-hop→MITM→RegoPolicy allow(`api.anthropic.com`→upstream)/deny(`evil.*`→403). Runs locally + in the normal `cargo test` CI gate (skips on bind-EPERM).

**REMAINING (not started; ordered):**
- **T6/T7** structured audit log + `izba netlog` (the "see every connection" view). The policy still `eprintln!`s.
- **T8/T9** DNS-snoop tier-2 (non-HTTP FQDN allow-list + RFC1918 denylist).
- **T10** `--policy` config surface (per-sandbox YAML → regorus data + tier-2 list).
- **T11** persistent CA mint (`ca.rs`) + `izba-trust` host share in `sandbox.rs` + **daemon construction of `MitmRuntime`** — **until this lands the daemon passes `mitm=None`, so production sandboxes do NOT yet MITM** (the datapath is proven, just not activated in `server.rs`).
- **T14 (real-VM slice)** guest-`curl`-through-MITM e2e in `e2e.yml` on both platforms (needs T10+T11 + an initramfs rebuild).

**Key handoff facts:** regorus is `0.4` (offline-cached); the daemon activation gap is the one thing between "proven datapath" and "live firewall" (T10+T11); the T12 merge is already in this branch.

---

## File structure

- `crates/izba-core/src/daemon/egress/mitm.rs` — MITM datapath (vendored, then a per-SNI cert resolver added).
- `crates/izba-core/src/daemon/egress/mitm_runtime.rs` — the tokio runtime, loopback listener, `DstMap`. **New.**
- `crates/izba-core/src/daemon/egress/policy.rs` — `RegoPolicy` + `FlowDesc` grown with L7 fields (vendored + extended).
- `crates/izba-core/src/daemon/egress/dns_snoop.rs` — tier-2 store. **New.**
- `crates/izba-core/src/daemon/egress/audit.rs` — structured per-flow audit record + writer. **New.**
- `crates/izba-core/src/daemon/egress/router.rs` — tier dispatch (modified).
- `crates/izba-core/src/daemon/egress/config.rs` — policy file parse → regorus data + tier-2 list. **New.**
- `crates/izba-core/src/ca.rs` — izba root-CA mint/persist. **New.**
- `crates/izba-core/src/sandbox.rs` — `izba-trust` FsShare + CA wiring (modified).
- `crates/izba-init/src/{mounts.rs,main.rs,exec.rs}` — CA-in-guest (modified).
- `crates/izba-cli/src/commands/netlog.rs` + `exec.rs`/create — `izba netlog`, `--policy` flag. **New/modified.**

## Conventions

- `[ -f .cargo-env ] && source .cargo-env` first. Gates that must stay green (run per task as relevant): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`, `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`.
- Unit tests never bind listeners (sandbox EPERM): use in-memory fakes (`tokio::io::duplex`, `UnixStream::pair`) or runtime-skip on `PermissionDenied`.
- Commit after each task (conventional commits, the `Co-Authored-By` trailer).

---

## Task 1: Vendor the proven MITM datapath into the feature branch

**Files:**
- Create: `crates/izba-core/src/daemon/egress/mitm.rs` (from spike)
- Modify: `crates/izba-core/Cargo.toml`, `crates/izba-core/src/daemon/egress/mod.rs`, `Cargo.lock`

- [ ] **Step 1: Copy the proven spike files.** From `.claude/worktrees/agent-ad6d548620c1b7803`: `mitm.rs`, the `Cargo.toml` MITM dep block (`rustls`/`tokio-rustls`/`rcgen` ring + `rustls-pemfile`, `tokio` gains `io-util`, dev-dep `tokio` rt-multi-thread/macros/io-util/time), the `pub mod mitm;` line in `mod.rs`, and apply the e2e-test teardown fix (`drop(guest_tls);` before `mitm.await` in `mitm_sees_l7_and_pipes_upstream_response`).
- [ ] **Step 2: Build + test.** Run `cargo test -p izba-core --lib daemon::egress::mitm`. Expected: `7 passed`.
- [ ] **Step 3: Gates.** `cargo clippy -p izba-core --all-targets -- -D warnings`, `cargo fmt -p izba-core --check`, `cargo check --target x86_64-pc-windows-gnu -p izba-core`. Expected: all green.
- [ ] **Step 4: Commit** — `feat(core): vendor OpenShell-salvage TLS-MITM datapath (M2)`.

## Task 2: Per-SNI cert resolver (mint leaves from the ClientHello)

Replace the spike's explicit-SNI `acceptor_for(sni)` with a rustls `ResolvesServerCert` so the acceptor mints a leaf from whatever SNI the guest's ClientHello carries — required because in production izbad does not know the hostname up front (the `TcpConnect` frame carries only an IP).

**Files:** Modify `crates/izba-core/src/daemon/egress/mitm.rs`

- [ ] **Step 1: Failing test.** Add to the `tests` module:
```rust
#[tokio::test]
async fn cert_resolver_mints_for_clienthello_sni() {
    install_ring();
    let ca = IzbaCa::generate().unwrap();
    let ca_der = ca.cert_der();
    let server_cfg = server_config_with_resolver(Arc::new(CertCache::new(ca)));
    // guest trusts only the izba CA, connects with SNI = late.example.com
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let mut gcfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (g, s) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let srv = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()).map_err(|e| e.to_string()) });
    let conn = TlsConnector::from(Arc::new(gcfg));
    let name = ServerName::try_from("late.example.com").unwrap();
    conn.connect(name, g).await.expect("handshake under izba CA via resolver");
    srv.await.unwrap().expect("server accept");
}
```
- [ ] **Step 2: Run, verify fail** (`server_config_with_resolver` undefined).
- [ ] **Step 3: Implement.** Add a resolver that pulls SNI from `ClientHello::server_name()` and reuses `CertCache::get_or_generate`:
```rust
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

struct SniResolver { certs: Arc<CertCache> }
impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SniResolver") }
}
impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_string();
        self.certs.certified_key(&host).ok()   // builds a CertifiedKey from the cached leaf
    }
}

/// A ServerConfig whose cert is minted per-ClientHello-SNI under the izba CA.
pub fn server_config_with_resolver(certs: Arc<CertCache>) -> ServerConfig {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver { certs }));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}
```
Add `CertCache::certified_key(&self, host) -> Result<Arc<CertifiedKey>>` that wraps `get_or_generate` into a rustls `CertifiedKey` (sign key via `rustls::crypto::ring::sign::any_supported_type`).
- [ ] **Step 4: Run, verify pass.** Also refactor `mitm_terminate` to accept a `&TlsAcceptor` built from this config (SNI no longer a param); update the two existing e2e tests to use it. Run `cargo test -p izba-core --lib daemon::egress::mitm`. Expected: all green.
- [ ] **Step 5: Gates + commit** — `feat(core): mint MITM leaves per ClientHello SNI`.

## Task 3: Vendor RegoPolicy + grow FlowDesc with L7 fields

**Files:** Modify `crates/izba-core/src/daemon/egress/policy.rs`, `Cargo.toml`, `Cargo.lock`

- [ ] **Step 1: Copy** `RegoPolicy`, `egress.rego`, `egress_data.json`, the `regorus` dep (pin **0.10**, `default-features=false, features=["std","arc","regex","glob"]`), and the `Serialize` on `FlowDesc` from `.claude/worktrees/agent-a3d5e8d4b200cedd7`.
- [ ] **Step 2: Grow `FlowDesc`** with optional L7 fields the MITM path fills:
```rust
pub struct FlowDesc {
    pub sandbox: String,
    pub addr: String,         // IP literal (tier-2) OR resolved host
    pub port: u16,
    pub host: Option<String>, // tier-1: decrypted Host/SNI
    pub method: Option<String>,
    pub path: Option<String>,
}
```
Update `RegoPolicy::input_json` to emit `host`/`method`/`path` when present; update `egress.rego` so tier-1 rules prefer `input.host` and fall back to `input.dest`. Keep existing tests green; add a test that a tier-1 flow with `host=api.anthropic.com, method=GET` is allowed and `method=DELETE` on a restricted-tier host is denied.
- [ ] **Step 3: Run** `cargo test -p izba-core --lib daemon::egress::policy`. Expected: green.
- [ ] **Step 4: Gates + commit** — `feat(core): RegoPolicy behind the Policy trait + L7 FlowDesc fields`.

## Task 4: MITM runtime + DstMap + loopback listener

**Files:** Create `crates/izba-core/src/daemon/egress/mitm_runtime.rs`; modify `mod.rs`

- [ ] **Step 1: Failing test** for the DstMap claim/expire logic (pure, no listener):
```rust
#[test]
fn dstmap_claims_once_and_expires() {
    let map = DstMap::new();
    map.insert(40001, OrigDst { ip: "1.2.3.4".parse().unwrap(), port: 443, sandbox: "web".into() });
    assert!(map.claim(40001).is_some());
    assert!(map.claim(40001).is_none(), "second claim must be empty");
    map.insert(40002, OrigDst { ip: "5.6.7.8".parse().unwrap(), port: 443, sandbox: "web".into() });
    map.expire_older_than(std::time::Duration::ZERO); // everything stale
    assert!(map.claim(40002).is_none(), "expired entry gone");
}
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `OrigDst`, `DstMap` (`Arc<Mutex<HashMap<u16,(OrigDst,Instant)>>>` with `insert`/`claim`(remove)/`expire_older_than`), and `MitmRuntime`:
```rust
pub struct MitmRuntime { rt: tokio::runtime::Runtime, pub listen: SocketAddr, dsts: DstMap }
impl MitmRuntime {
    /// Start a multi-thread tokio runtime, bind 127.0.0.1:0, serve the MITM.
    pub fn start(certs: Arc<CertCache>, upstream: Arc<ClientConfig>,
                 policy: Arc<dyn Policy>, audit: AuditSink) -> Result<Self> { /* spawn accept loop */ }
    /// Called from the blocking router: register dst, return the loopback port to dial.
    pub fn register(&self, src_port: u16, dst: OrigDst) { self.dsts.insert(src_port, dst); }
    pub fn listen_addr(&self) -> SocketAddr { self.listen }
}
```
The accept loop: `tokio::net::TcpListener::accept()` → `peer.port()` → `dsts.claim(port)` (drop on miss) → `server_config_with_resolver` acceptor → `mitm_terminate(tcp, &state, &*policy, || async { TcpStream::connect((dst.ip,dst.port)).await })` → audit. (The listener bind is integration-tested, not unit-tested.)
- [ ] **Step 4: Run** the DstMap test. Expected: pass. Gates.
- [ ] **Step 5: Commit** — `feat(core): MITM tokio runtime + loopback DstMap bridge`.

## Task 5: Router tier dispatch (loopback-hop wiring)

**Files:** Modify `crates/izba-core/src/daemon/egress/router.rs`, `mod.rs` (EgressManager holds `Option<Arc<MitmRuntime>>`)

- [ ] **Step 1: Read** `router.rs:19-100` (`handle_conn`, `tcp_connect`) and `portfwd.rs:112-156` (`pump_bidirectional`). Confirm the dial+pump shape.
- [ ] **Step 2: Implement** the tier branch in `tcp_connect`, after policy-allow, before the direct dial:
```rust
// Tier-1 candidate ports go through the MITM loopback; everything else keeps
// the existing direct dial (tier-2 verdict already applied above).
if let Some(mitm) = mitm_runtime {
    if matches!(port, 80 | 443) {
        // bind a loopback source so we know the src port BEFORE connecting
        let sock = std::net::TcpStream::connect(mitm.listen_addr())?; // ephemeral src
        let src_port = sock.local_addr()?.port();
        mitm.register(src_port, OrigDst { ip, port, sandbox: sandbox.to_string() });
        write_frame(&mut conn, &Response::Ok)?;
        crate::portfwd::pump_bidirectional(sock, conn); // UNCHANGED vsock leg
        return;
    }
}
// else: existing direct TcpStream::connect_timeout + pump path
```
Note: register must happen before `pump_bidirectional` starts forwarding the ClientHello, but `connect` already fixed `src_port`; register immediately after `connect`, before the first pump read — there is no race because the MITM accept handler claims lazily on the first poll.
- [ ] **Step 3: Test.** This path needs a listener; gate it behind an integration-style test that runs only when binds are permitted (skip on EPERM), wiring a fake `MitmRuntime` that echoes. Add `tcp_connect_routes_443_to_loopback` (skip-on-EPERM).
- [ ] **Step 4: Gates + commit** — `feat(core): route :80/:443 egress through the MITM loopback`.

## Task 6: Structured audit record + sink

**Files:** Create `crates/izba-core/src/daemon/egress/audit.rs`; modify `policy.rs` (emit), `mod.rs`

- [ ] **Step 1: Failing test:**
```rust
#[test]
fn audit_record_serializes_with_tier_and_verdict() {
    let r = AuditRecord::deny(/*sandbox*/"web", "1.2.3.4".parse().unwrap(), 443,
        Some("api.evil.com"), Tier::L7, "not in allow-list");
    let j: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
    assert_eq!(j["verdict"], "deny");
    assert_eq!(j["tier"], "l7");
    assert_eq!(j["host"], "api.evil.com");
}
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `AuditRecord { ts_ms, sandbox, dest_ip, port, host, method, path, tier, verdict, matched_rule }` (serde), `Tier`, `Verdict`, `to_json()`, and an `AuditSink` that appends JSON lines to `<sandbox_dir>/logs/egress-audit.jsonl` (create dir, `O_APPEND`, line-buffered). `ts_ms` is passed in (no `Date::now` in pure code; the sink stamps via `SystemTime`).
- [ ] **Step 4: Wire** `RegoPolicy::check` and the MITM handler to emit allow + deny records via the sink. Replace the `AllowAll` `eprintln!`.
- [ ] **Step 5: Run, verify pass. Gates + commit** — `feat(core): structured per-flow egress audit log`.

## Task 7: `izba netlog` command

**Files:** Create `crates/izba-cli/src/commands/netlog.rs`; modify cli command enum; add daemon proto verb if needed (read the audit file directly from disk — no daemon round-trip needed since it's a file under the sandbox dir).

- [ ] **Step 1: Implement** `izba netlog <sandbox> [--follow]` — resolve the sandbox dir, read `logs/egress-audit.jsonl`, pretty-print each record (`ts  ALLOW/DENY  sandbox  host|ip:port  method path  (rule)`); `--follow` tails. Read-only, no policy logic.
- [ ] **Step 2: Test** the line-formatting function with a fixed `AuditRecord` (pure). Add `netlog_formats_allow_and_deny`.
- [ ] **Step 3: Gates + commit** — `feat(cli): izba netlog egress audit view`.

## Task 8: DNS-snoop store (tier-2 data)

**Files:** Create `crates/izba-core/src/daemon/egress/dns_snoop.rs`; modify `Cargo.toml` (`hickory-proto`, read-only), `mod.rs`

- [ ] **Step 1: Failing tests:**
```rust
#[test] fn snoop_record_then_lookup_then_expire() { /* insert A-record, lookup IP→fqdn, advance past TTL clamp → gone */ }
#[test] fn wildcard_match_one_label_and_deep() { assert!(matches("*.github.com","api.github.com")); assert!(!matches("*.github.com","a.b.github.com")); assert!(matches("**.github.com","a.b.github.com")); }
#[test] fn extract_a_aaaa_from_response_bytes() { /* hickory-proto parse of a fixed response → (qname, ip, ttl) */ }
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `SnoopStore` (per-sandbox `Arc<Mutex<HashMap<IpAddr, Vec<FqdnEntry{fqdn,expiry}>>>>`, `record(sandbox,&[(fqdn,ip,ttl)])` clamping `ttl→[60s,15min]`, `fqdns_for(sandbox,ip)` filtering expired, background-sweep hook), `extract_a_aaaa(&[u8])` via `hickory_proto::op::Message::from_vec`, and `allowlist_matches(rules,&fqdn)` (exact / `*.` one-label / `**.` deep).
- [ ] **Step 4: Run, verify pass. Gates + commit** — `feat(core): DNS-snoop FQDN store for the non-HTTP tail`.

## Task 9: Tier-2 dispatch + RFC1918 denylist

**Files:** Modify `router.rs` (dns_loop feeds the store; tcp_connect tier-2 check), `mod.rs` (EgressManager holds `SnoopStore`)

- [ ] **Step 1:** Thread `sandbox: &str` + `&SnoopStore` into `dns_loop`; after resolving, `store.record(sandbox, extract_a_aaaa(&resp)?)` **before** writing the reply (so the mapping is installed before the guest can dial).
- [ ] **Step 2:** In `tcp_connect`, for non-MITM ports: `let names = store.fqdns_for(sandbox, ip);` build `FlowDesc{addr: ip, host: names.first(), ...}`; deny if `ip` is RFC1918/link-local; deny if `names.is_empty()` and not in `allow_raw_cidrs`; else `policy.check`. Audit the verdict.
- [ ] **Step 3: Test** `tcp_connect_tier2_denies_raw_ip_with_no_snoop` and `..allows_snstored_fqdn` with a fake store + fake policy (skip-on-EPERM for the listener parts; the decision function itself is pure-testable — extract a `decide_tier2(store, policy, sandbox, ip, port) -> Verdict`).
- [ ] **Step 4: Gates + commit** — `feat(core): tier-2 DNS-snoop egress policy + RFC1918 denylist`.

## Task 10: Policy config surface

**Files:** Create `crates/izba-core/src/daemon/egress/config.rs`; modify `izba-cli` create command (`--policy <file>`), `sandbox.rs` (persist policy under sandbox dir, load at egress start)

- [ ] **Step 1: Failing test:** parse a YAML policy (`allow:`/`allow_tcp:`) → `(rego_data_json, tier2_rules)`; assert the data doc contains the domains and the tier-2 list parses `host:port`.
- [ ] **Step 2: Implement** `EgressPolicyConfig::from_yaml(&str)` → builds the regorus data doc (`{global_domains:[...], sandbox_domains:{...}}`) + `Vec<AllowRule>` for tier-2. Persist the raw file to `<sandbox_dir>/policy.yaml` at create; load it when constructing the `RegoPolicy` + `SnoopStore` allow-list at egress start. Bare sandbox (no file) ⇒ `AllowAll` + audit (today's behavior).
- [ ] **Step 3:** Add `--policy <path>` to `izba create`/run; copy into the sandbox dir.
- [ ] **Step 4: Run, verify pass. Gates + commit** — `feat: per-sandbox egress policy config (--policy)`.

## Task 11: izba CA mint/persist + izba-trust virtiofs share

**Files:** Create `crates/izba-core/src/ca.rs`; modify `sandbox.rs` (FsShare), `vmm` FsShare plumbing if needed

- [ ] **Step 1: Failing test:** `IzbaCa::load_or_create(dir)` is idempotent (second call returns the same cert PEM); the CA cert is a valid CA (basic-constraints CA:TRUE).
- [ ] **Step 2: Implement** `ca.rs`: mint a root CA (reuse `mitm::IzbaCa::generate`), persist `ca.pem`+`ca.key` under `<data>/ca/` (0700), `load_or_create`. This CA is the one the MITM `CertCache` signs leaves with **and** the one baked into guests.
- [ ] **Step 3:** In `sandbox.rs::start`, write `ca.pem` into a per-sandbox host dir and add `FsShare{ tag: "izba-trust", host_path, read_only: true }` to the `VmSpec` (beside the `workspace` share). Read `sandbox.rs:393-396` for the share list shape.
- [ ] **Step 4: Test + gates + commit** — `feat(core): persistent izba root CA + izba-trust guest share`.

## Task 12: CA-in-guest (izba-init)

**Files:** Modify `crates/izba-init/src/mounts.rs` (mount izba-trust), `main.rs` (`write_trust_anchor`), `exec.rs` (CA-bundle env defaults)

- [ ] **Step 1: Failing tests (host-testable):** `build_combined_bundle(ca_pem, Some(system_pem))` concatenates; `Some` absent ⇒ CA-only; `trust_env_pairs()` returns the 6 vars with the guest paths. (Pure functions — no `/rootfs` write in the test.)
- [ ] **Step 2: Implement** `write_trust_anchor()` (mirror `write_resolv_conf` at `main.rs:195-201`): read `/<trust-mount>/ca.pem`, write `/rootfs/etc/izba/ca.pem` + `/rootfs/etc/izba/ca-bundle.pem` (CA ++ guest system bundle if a known path exists), best-effort append to `/rootfs/etc/ssl/certs/ca-certificates.crt`. Add the `izba-trust` `MountOp` in `rootfs_mount_plan()` (`mounts.rs:64-75`). Add the `TRUST_ENV` table + default-unless-overridden injection in `exec.rs:94-101`, values pointing at post-chroot guest paths (`/etc/izba/...`).
- [ ] **Step 3: Run** host-testable tests. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` (must stay static).
- [ ] **Step 4: Gates + commit** — `feat(init): bake the izba CA into the guest trust store`.

## Task 13: Integration e2e + churn tests

**Files:** Modify `crates/izba-core/tests/integration.rs` (or a new `egress_mitm.rs` test), gated by `IZBA_INTEGRATION=1`

- [ ] **Step 1:** Write `mitm_allows_and_denies_with_audit`: boot a real sandbox with a `--policy` allowing `example.com` only; in-guest `curl -sS https://example.com` succeeds (leaf trusts izba CA), `curl https://denied.test` is blocked; assert both appear in `logs/egress-audit.jsonl` with the right verdict. (Use a real reachable allowed host + a deny target.)
- [ ] **Step 2:** Write `tier2_raw_ip_denied`: a non-HTTP TCP dial to an un-snooped IP is denied.
- [ ] **Step 3:** Write `mitm_churn_keeps_vm_alive`: drive the loopback-hop path under the ttystorm-style churn (20×2MiB + 30× rapid open/close) and assert the VM stays alive — re-proves the OpenVMM invariant under the hop.
- [ ] **Step 4: Run locally (unsandboxed, KVM):** `IZBA_INTEGRATION=1 cargo test -p izba-core --test <name> -- --test-threads=1`. Iterate until green.
- [ ] **Step 5: Commit** — `test(core): e2e MITM egress allow/deny/audit + churn`.

## Task 14: CI wiring

**Files:** Modify `.github/workflows/e2e.yml` (real-VM legs run the new integration tests + the Windows WHP leg runs the MITM e2e), `.github/workflows/ci.yml` (unit additions already covered by `--workspace`).

- [ ] **Step 1:** Add the egress MITM integration test invocation to the KVM leg and the Windows WHP validation script. Ensure the initramfs rebuild picks up the new izba-init.
- [ ] **Step 2:** Verify the workflow YAML locally (`actionlint` if available; otherwise a careful read) and dry-run the test invocations locally.
- [ ] **Step 3: Commit** — `ci: run the MITM egress e2e on both real-VM legs`.

## Task 15: Full gate sweep + finalize

- [ ] **Step 1:** Run all six gates on the workspace. Fix anything red.
- [ ] **Step 2:** Run the KVM integration suite locally (unsandboxed). Run the Windows validation via `powershell.exe` if reachable.
- [ ] **Step 3:** Update `docs/roadmap.md` M2 status + the memory file; final commit.
- [ ] **Step 4:** Produce the push + PR commands for the user.

---

## Self-review notes

- **Spec coverage:** datapath (T1–T2), bridge (T4–T5), two-tier policy (T3,T8,T9), audit/netlog (T6,T7), CA-in-guest (T11,T12), config (T10), e2e+CI (T13,T14) — all spec §3 sub-sections mapped.
- **Risk:** the OpenVMM churn invariant is explicitly re-proven (T13.3) by reusing the unchanged blocking pump (T5).
- **Ordering:** T1–T7 yield a working tier-1 MITM firewall with audit (a demoable slice) before tier-2/CA/config deepen it; an interruption after T7+T11+T12 still gives an e2e-testable HTTPS firewall.
