# izba DNS system-resolver with live reload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the start-time-captured UDP DNS forwarder with a hickory-backed terminating resolver that re-reads system DNS config and self-heals on host network change (VPN reconnect), curing the observed `WSAENETUNREACH` stale-upstream bug.

**Architecture:** A new `SystemResolver` (behind the existing sync `Resolver` trait) owns a small tokio runtime, a `ResolverCell` (mirror of `PolicyCell`: `Mutex<Arc<ResolverState>>`) holding a live `hickory_resolver::TokioResolver`, and background reload tasks. Resolution *terminates*: parse the query, gate the qtype via `DnsCaps`, `lookup()` via hickory (failover + TCP-fallback + system-config), synthesize the response. Reload layers: lazy-on-failure (load-bearing) + 30s poll + `if-watch` proactive trigger; all funnel into one fingerprint-deduped apply path that swaps the cell.

**Tech Stack:** Rust, `hickory-resolver 0.26` (`system-config`,`tokio`), `hickory-proto 0.26` (already in tree), `if-watch 3` (`tokio`), `futures-util` (already in tree), tokio (already in tree).

**Spec:** `docs/superpowers/specs/2026-06-16-izba-dns-resolver-reload-design.md`

---

## Build environment note

`cargo` must fetch `hickory-resolver` / `if-watch` from crates.io on first build — run cargo commands **with network access** (this WSL2 toolchain has it; disable the Bash sandbox for cargo build/test/check/deny). Source the local toolchain if present: prefix commands with `[ -f .cargo-env ] && source .cargo-env;` (a no-op in worktrees that lack it).

## Verified 0.26 / 3.x API facts (do not "correct" these to older API)

- Resolver build (system): `Resolver::builder_tokio()?.build()?` → `TokioResolver`. **Must be called inside a tokio runtime context** (the connection provider uses `Handle::current()`).
- Resolver build (explicit config, for tests): `Resolver::builder_with_config(config, TokioConnectionProvider::default()).with_options(opts).build()?` — also needs runtime context.
- System config tuple: `hickory_resolver::system_conf::read_system_conf()? -> (ResolverConfig, ResolverOpts)` (gated by `system-config`).
- Lookup: `resolver.lookup(name, RecordType).await -> Result<Lookup, hickory_net::NetError>`; iterate `lookup.records() -> &[Record]`; each `Record` has `.record_type()`, `.ttl()`, `.data()`.
- Error classify: `NetError::is_nx_domain()`, `NetError::is_no_records_found()`. Everything else → treat as transient (reload + retry once).
- Wire (hickory-proto 0.26): `Message::from_vec(&[u8]) -> Result<Message, DecodeError>`; **`message.queries` is a public `Vec<Query>` field (no getter)**; `Message::new(id, MessageType::Response, OpCode::Query)`; `add_query`, `add_answer`, `set_response_code`, `set_recursion_available`, `to_vec()`; `ResponseCode::{NoError, ServFail, NXDomain, NotImp}`; `Query` has `.name()` / `.query_type()`.
- if-watch: `if_watch::tokio::IfWatcher::new()? ` (call inside runtime); it's a `Stream<Item = io::Result<IfEvent>>`; `IfEvent::Up(IpNet)`/`Down(IpNet)`; consume via `futures_util::StreamExt::next().await`.

**If a getter/setter spelling above doesn't resolve at build time, fall back to the public field** (Message header fields are public via the `Metadata` deref). Confirm `read_system_conf`'s error type implements `std::error::Error` for `?` into `anyhow`.

---

## Task 1: Add dependencies and verify all gates early

**Files:**
- Modify: `crates/izba-core/Cargo.toml`

- [ ] **Step 1: Add the two new deps**

In `crates/izba-core/Cargo.toml` `[dependencies]`, after the `hickory-proto` line, add:

```toml
# Terminating system resolver with live config reload (replaces the
# start-time-captured UDP forwarder; self-heals on VPN/network change).
hickory-resolver = { version = "0.26", default-features = false, features = ["system-config", "tokio"] }
# Cross-platform interface/IP change events (netlink on Linux, IP Helper on
# Windows) — proactive reload trigger. Pure-Rust; cross-compiles to windows-gnu.
if-watch = { version = "3", features = ["tokio"] }
```

- [ ] **Step 2: Fetch + build (network required, sandbox disabled)**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo build -p izba-core`
Expected: compiles (downloads hickory-resolver, if-watch, rtnetlink, ipconfig, etc.). If it fails to fetch, you are sandboxed — rerun with network.

- [ ] **Step 3: Verify the supply-chain gate (F-22) on the new deps**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo deny check advisories bans licenses sources`
Expected: PASS. If a transitive trips an advisory/license, STOP and triage per `deny.toml` policy (patch/bump/replace, or a specific time-boxed justified exception — never a blanket ignore). Report the finding before proceeding.

- [ ] **Step 4: Verify the windows-gnu cross gates (primary risk)**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo check --target x86_64-pc-windows-gnu -p izba-core`
Then: `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
Expected: both PASS. If `if-watch`/`hickory-resolver` fail to cross-compile, STOP and report (this gates the whole approach).

- [ ] **Step 5: Commit the deps**

```bash
git add crates/izba-core/Cargo.toml Cargo.lock
git commit -m "build(egress): add hickory-resolver 0.26 + if-watch for DNS reload"
```

---

## Task 2: `DnsCaps` query-type allowlist (pure, TDD)

**Files:**
- Create: `crates/izba-core/src/daemon/egress/sys_resolver.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (register the module)

- [ ] **Step 1: Register the new module**

In `crates/izba-core/src/daemon/egress/mod.rs`, add alongside the other `mod` lines (e.g. near `mod dns;`):

```rust
mod sys_resolver;
```

- [ ] **Step 2: Write the failing test**

Create `crates/izba-core/src/daemon/egress/sys_resolver.rs` with:

```rust
//! Terminating system DNS resolver with live config reload. Replaces the
//! start-time-captured `UdpForwarder`: re-reads host DNS config and self-heals
//! on network change (VPN reconnect) via lazy-on-failure + poll + if-watch.

use hickory_proto::rr::RecordType;

/// The query types the guest is allowed to resolve. Terminating resolution
/// gives us this control point; v1 hardcodes a sane set.
// TODO(policy): make per-sandbox DNS caps policy-driven (M-future).
pub(crate) struct DnsCaps {
    allowed: &'static [RecordType],
}

impl DnsCaps {
    pub(crate) const fn v1() -> Self {
        Self {
            allowed: &[
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::TXT,
                RecordType::SRV,
                RecordType::PTR,
                RecordType::NS,
                RecordType::SOA,
                RecordType::CAA,
            ],
        }
    }

    pub(crate) fn permits(&self, qtype: RecordType) -> bool {
        self.allowed.contains(&qtype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_caps_permit_common_types_and_reject_dangerous_ones() {
        let caps = DnsCaps::v1();
        assert!(caps.permits(RecordType::A));
        assert!(caps.permits(RecordType::AAAA));
        assert!(caps.permits(RecordType::SRV));
        assert!(!caps.permits(RecordType::ANY));
        assert!(!caps.permits(RecordType::AXFR));
    }
}
```

- [ ] **Step 3: Run the test (verify it passes — pure logic)**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo test -p izba-core sys_resolver::tests::v1_caps -- --nocapture`
Expected: PASS. (If `RecordType::ANY`/`AXFR` don't exist under those names, use any two variants not in the allow-list.)

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs crates/izba-core/src/daemon/egress/mod.rs
git commit -m "feat(egress): DnsCaps query-type allowlist for the system resolver"
```

---

## Task 3: Response synthesis helpers (pure, TDD)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs`

- [ ] **Step 1: Write the failing tests**

Add to `sys_resolver.rs` (above the `#[cfg(test)]` block, add imports at top of file):

```rust
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::Record;
```

Add the helpers:

```rust
/// Build a response that echoes the request's id + question with the given
/// rcode and no answers (NOTIMP / NXDOMAIN / NODATA).
fn response_with_rcode(req: &Message, rcode: ResponseCode) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id(), MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    resp.set_recursion_available(true);
    resp.set_response_code(rcode);
    Ok(resp.to_vec()?)
}

/// Build a NOERROR response echoing the question and carrying `records` as the
/// answer section. Records come straight from hickory's `Lookup`, so no
/// per-RData destructuring is needed.
fn response_with_answers(req: &Message, records: &[Record]) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id(), MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    for r in records {
        resp.add_answer(r.clone());
    }
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);
    Ok(resp.to_vec()?)
}
```

Add tests inside the `tests` module:

```rust
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn sample_query(id: u16, qtype: RecordType) -> Message {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(Name::from_str("example.com.").unwrap());
        q.set_query_type(qtype);
        m.add_query(q);
        m
    }

    #[test]
    fn rcode_response_echoes_id_and_question() {
        let req = sample_query(0x1234, RecordType::A);
        let bytes = response_with_rcode(&req, ResponseCode::NotImp).unwrap();
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.id(), 0x1234);
        assert_eq!(resp.message_type(), MessageType::Response);
        assert_eq!(resp.response_code(), ResponseCode::NotImp);
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.queries[0].query_type(), RecordType::A);
        assert!(resp.answers.is_empty());
    }
```

- [ ] **Step 2: Run the tests**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo test -p izba-core sys_resolver::tests::rcode_response -- --nocapture`
Expected: PASS. (If `Query::new`/`set_name`/`set_query_type` or `req.id()`/`message_type()`/`response_code()` getters differ in 0.26, adjust to the actual API — fields are public via the `Metadata` deref as a fallback.)

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): DNS response synthesis helpers (rcode + answers)"
```

---

## Task 4: `classify_query` front-half (pure, TDD)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs`

- [ ] **Step 1: Write the failing tests**

Add to `sys_resolver.rs`:

```rust
use hickory_proto::rr::Name;

/// Pure front-half of `handle`: parse + capability-gate, with no network. The
/// network back-half consumes `Answerable`.
enum QueryDecision {
    /// Query bytes did not parse → caller returns Err → SERVFAIL at `dns_loop`.
    Unparseable,
    /// Parsed, but the qtype is not permitted → synthesize NOTIMP.
    Unsupported { req: Message },
    /// Parsed and permitted → resolve `name`/`qtype`.
    Answerable {
        req: Message,
        name: Name,
        qtype: RecordType,
    },
}

fn classify_query(query: &[u8], caps: &DnsCaps) -> QueryDecision {
    let req = match Message::from_vec(query) {
        Ok(m) => m,
        Err(_) => return QueryDecision::Unparseable,
    };
    let Some(q) = req.queries.first() else {
        return QueryDecision::Unparseable; // no question section → SERVFAIL
    };
    let qtype = q.query_type();
    let name = q.name().clone();
    if !caps.permits(qtype) {
        return QueryDecision::Unsupported { req };
    }
    QueryDecision::Answerable { req, name, qtype }
}
```

Add tests:

```rust
    #[test]
    fn classify_rejects_garbage() {
        assert!(matches!(
            classify_query(&[0xff, 0x00, 0x01], &DnsCaps::v1()),
            QueryDecision::Unparseable
        ));
    }

    #[test]
    fn classify_permits_allowed_qtype() {
        let bytes = sample_query(1, RecordType::A).to_vec().unwrap();
        match classify_query(&bytes, &DnsCaps::v1()) {
            QueryDecision::Answerable { qtype, name, .. } => {
                assert_eq!(qtype, RecordType::A);
                assert_eq!(name, Name::from_str("example.com.").unwrap());
            }
            _ => panic!("expected Answerable"),
        }
    }

    #[test]
    fn classify_marks_disallowed_qtype_unsupported() {
        let bytes = sample_query(1, RecordType::ANY).to_vec().unwrap();
        match classify_query(&bytes, &DnsCaps::v1()) {
            QueryDecision::Unsupported { req } => {
                let notimp = response_with_rcode(&req, ResponseCode::NotImp).unwrap();
                let resp = Message::from_vec(&notimp).unwrap();
                assert_eq!(resp.response_code(), ResponseCode::NotImp);
            }
            _ => panic!("expected Unsupported"),
        }
    }
```

- [ ] **Step 2: Run the tests**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo test -p izba-core sys_resolver::tests::classify -- --nocapture`
Expected: 3 PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): classify_query front-half (parse + capability gate)"
```

---

## Task 5: Fingerprint + `ConfigSource` seam (TDD)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs`

- [ ] **Step 1: Write the failing test + impl**

Add imports + code to `sys_resolver.rs`:

```rust
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::hash::{Hash, Hasher};

/// Source of host DNS config. Seam so reload logic is testable without network.
pub(crate) trait ConfigSource: Send + Sync {
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)>;
}

/// Production: read the host's system DNS config (resolv.conf on unix; adapter
/// DNS servers via the `ipconfig` crate on Windows — picks up the live VPN).
pub(crate) struct SystemConfigSource;

impl ConfigSource for SystemConfigSource {
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
        Ok(hickory_resolver::system_conf::read_system_conf()?)
    }
}

/// Stable hash of the parts of a resolver config that affect reachability
/// (nameservers + search). Hashing the Debug rendering dodges per-field getter
/// drift across hickory versions while still flipping on any server change.
fn fingerprint(config: &ResolverConfig) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    format!("{config:?}").hash(&mut h);
    h.finish()
}
```

Add tests:

```rust
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig as RC};
    use std::net::Ipv4Addr;

    fn config_with(ip: [u8; 4]) -> RC {
        RC::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[Ipv4Addr::from(ip).into()], 53, true),
        )
    }

    #[test]
    fn fingerprint_is_stable_and_change_sensitive() {
        let a = config_with([10, 0, 0, 2]);
        let a2 = config_with([10, 0, 0, 2]);
        let b = config_with([8, 8, 8, 8]);
        assert_eq!(fingerprint(&a), fingerprint(&a2));
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
```

- [ ] **Step 2: Run the test**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo test -p izba-core sys_resolver::tests::fingerprint -- --nocapture`
Expected: PASS. (If `ResolverConfig::from_parts` / `NameServerConfigGroup::from_ips_clear` signatures differ in 0.26, adjust — the test only needs two configs that differ by nameserver IP.)

- [ ] **Step 3: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): ConfigSource seam + change-sensitive fingerprint"
```

---

## Task 6: `ResolverCell` + `build_resolver` + `reload_if_changed` (TDD)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs`

- [ ] **Step 1: Write the impl**

Add to `sys_resolver.rs`:

```rust
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{Resolver as HickoryResolver, TokioResolver};
use std::sync::{Arc, Mutex};

/// Live resolver + the fingerprint of the config it was built from.
struct ResolverState {
    resolver: TokioResolver,
    fingerprint: u64,
}

/// Swappable holder for the live resolver. Mirrors `PolicyCell`: the lock is
/// held only for an `Arc` clone/replace, never across I/O, so a plain `Mutex`
/// is contention-free. In-flight lookups keep the `Arc` they cloned; a reload
/// takes effect on the next query.
struct ResolverCell {
    inner: Mutex<Arc<ResolverState>>,
}

impl ResolverCell {
    fn new(state: Arc<ResolverState>) -> Self {
        Self {
            inner: Mutex::new(state),
        }
    }
    fn load(&self) -> Arc<ResolverState> {
        Arc::clone(&self.inner.lock().unwrap())
    }
    fn store(&self, state: Arc<ResolverState>) {
        *self.inner.lock().unwrap() = state;
    }
}

/// Build a Tokio resolver from explicit config. MUST be called inside a tokio
/// runtime context (the connection provider uses `Handle::current()`).
fn build_resolver(config: ResolverConfig, opts: ResolverOpts) -> anyhow::Result<TokioResolver> {
    Ok(
        HickoryResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build(),
    )
}

/// Re-read system DNS config; if the fingerprint changed, rebuild the resolver
/// and swap the cell. Returns whether a swap happened. MUST run inside a tokio
/// runtime context (for `build_resolver`).
fn reload_if_changed(cell: &ResolverCell, source: &dyn ConfigSource) -> anyhow::Result<bool> {
    let (config, opts) = source.discover()?;
    let fp = fingerprint(&config);
    if cell.load().fingerprint == fp {
        return Ok(false); // dedupe: no change
    }
    let resolver = build_resolver(config, opts)?;
    cell.store(Arc::new(ResolverState {
        resolver,
        fingerprint: fp,
    }));
    Ok(true)
}
```

Note: `builder_with_config(...).build()` returns `TokioResolver` directly in 0.26 (not `Result`). If your 0.26 returns `Result`, add `?` and keep the `Ok(...)` wrapper.

- [ ] **Step 2: Write the failing test (fake source + real runtime; no network)**

Add to the `tests` module:

```rust
    struct FakeSource {
        ip: std::sync::atomic::AtomicU8,
    }
    impl ConfigSource for FakeSource {
        fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
            let n = self.ip.load(std::sync::atomic::Ordering::SeqCst);
            Ok((config_with([10, 0, 0, n]), ResolverOpts::default()))
        }
    }

    #[test]
    fn reload_swaps_only_on_config_change() {
        // Building a resolver needs a runtime context but does NO network I/O
        // (sockets are created lazily on first query). Safe in sandbox.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let src = FakeSource {
            ip: std::sync::atomic::AtomicU8::new(2),
        };
        let (cfg, opts) = src.discover().unwrap();
        let cell = ResolverCell::new(Arc::new(ResolverState {
            resolver: build_resolver(cfg.clone(), opts).unwrap(),
            fingerprint: fingerprint(&cfg),
        }));

        // Same config → no swap.
        assert!(!reload_if_changed(&cell, &src).unwrap());
        // Change the upstream → swap.
        src.ip.store(8, std::sync::atomic::Ordering::SeqCst);
        assert!(reload_if_changed(&cell, &src).unwrap());
        // Idempotent at the new config.
        assert!(!reload_if_changed(&cell, &src).unwrap());
    }
```

- [ ] **Step 3: Run the test**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo test -p izba-core sys_resolver::tests::reload_swaps -- --nocapture`
Expected: PASS. If resolver construction errors with a socket/permission denial in this sandbox, runtime-skip on `PermissionDenied` (project pattern in `vsock.rs`) — but construction should not bind anything.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): ResolverCell + reload_if_changed (fingerprint-deduped swap)"
```

---

## Task 7: `SystemResolver` — `handle`, `resolve`, `new`, reload tasks

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs`

- [ ] **Step 1: Write the impl**

Add to `sys_resolver.rs`:

```rust
use super::dns::Resolver;
use futures_util::StreamExt;
use std::time::{Duration, Instant};

const MIN_REBUILD_INTERVAL: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const IFWATCH_DEBOUNCE: Duration = Duration::from_secs(1);

pub struct SystemResolver {
    rt: tokio::runtime::Runtime,
    cell: Arc<ResolverCell>,
    caps: DnsCaps,
    source: Arc<dyn ConfigSource>,
    last_reload: Mutex<Instant>,
}

impl SystemResolver {
    /// Build the production system resolver and start its reload tasks.
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let source: Arc<dyn ConfigSource> = Arc::new(SystemConfigSource);

        // Initial build. A host with no DNS config is already broken; fall back
        // to 1.1.1.1 (mirrors the retired UdpForwarder), logged.
        let (config, opts) = source.discover().unwrap_or_else(|e| {
            eprintln!("izbad: no system DNS upstream found ({e:#}); falling back to 1.1.1.1");
            (ResolverConfig::cloudflare(), ResolverOpts::default())
        });
        let fp = fingerprint(&config);
        let resolver = {
            let _g = rt.enter();
            build_resolver(config, opts)?
        };
        let cell = Arc::new(ResolverCell::new(Arc::new(ResolverState {
            resolver,
            fingerprint: fp,
        })));

        let me = Arc::new(Self {
            rt,
            cell,
            caps: DnsCaps::v1(),
            source,
            last_reload: Mutex::new(Instant::now()),
        });
        me.spawn_reload_tasks();
        Ok(me)
    }

    fn spawn_reload_tasks(&self) {
        // L3: poll every 30s.
        let cell = Arc::clone(&self.cell);
        let source = Arc::clone(&self.source);
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            loop {
                tick.tick().await;
                if let Err(e) = reload_if_changed(&cell, &*source) {
                    eprintln!("izbad: dns poll reload failed: {e:#}");
                }
            }
        });

        // if-watch: proactive reload on interface/IP change (VPN reconnect).
        let cell = Arc::clone(&self.cell);
        let source = Arc::clone(&self.source);
        self.rt.spawn(async move {
            let mut watcher = match if_watch::tokio::IfWatcher::new() {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("izbad: if-watch unavailable ({e:#}); poll-only reload");
                    return;
                }
            };
            while let Some(ev) = watcher.next().await {
                if ev.is_err() {
                    continue;
                }
                // Debounce: VPN connect emits a burst; sleep then reload once.
                // fingerprint-dedupe makes any residual extra reload a no-op.
                tokio::time::sleep(IFWATCH_DEBOUNCE).await;
                if let Err(e) = reload_if_changed(&cell, &*source) {
                    eprintln!("izbad: dns event reload failed: {e:#}");
                }
            }
        });
    }

    /// Lazy reload-on-failure (Layer 2), rate-limited. Runs the apply path in a
    /// runtime context.
    fn try_reload_on_failure(&self) {
        {
            let mut last = self.last_reload.lock().unwrap();
            if last.elapsed() < MIN_REBUILD_INTERVAL {
                return;
            }
            *last = Instant::now();
        }
        let _g = self.rt.enter();
        if let Err(e) = reload_if_changed(&self.cell, &*self.source) {
            eprintln!("izbad: dns failure reload failed: {e:#}");
        }
    }

    fn lookup_once(&self, name: &Name, qtype: RecordType) -> Result<Vec<Record>, hickory_net::NetError> {
        let state = self.cell.load();
        self.rt
            .block_on(state.resolver.lookup(name.clone(), qtype))
            .map(|l| l.records().to_vec())
    }

    fn resolve(&self, req: Message, name: Name, qtype: RecordType) -> anyhow::Result<Vec<u8>> {
        match self.lookup_once(&name, qtype) {
            Ok(records) => response_with_answers(&req, &records),
            Err(e) if e.is_nx_domain() => response_with_rcode(&req, ResponseCode::NXDomain),
            Err(e) if e.is_no_records_found() => response_with_rcode(&req, ResponseCode::NoError),
            Err(_transient) => {
                // Layer 2: the upstream may have moved (VPN reconnect). Rebuild
                // from current system config and retry exactly once.
                self.try_reload_on_failure();
                match self.lookup_once(&name, qtype) {
                    Ok(records) => response_with_answers(&req, &records),
                    Err(e) if e.is_nx_domain() => response_with_rcode(&req, ResponseCode::NXDomain),
                    Err(e) if e.is_no_records_found() => {
                        response_with_rcode(&req, ResponseCode::NoError)
                    }
                    Err(e) => anyhow::bail!("dns lookup failed after reload: {e}"),
                }
            }
        }
    }
}

impl Resolver for SystemResolver {
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match classify_query(query, &self.caps) {
            QueryDecision::Unparseable => anyhow::bail!("unparseable DNS query"),
            QueryDecision::Unsupported { req } => response_with_rcode(&req, ResponseCode::NotImp),
            QueryDecision::Answerable { req, name, qtype } => self.resolve(req, name, qtype),
        }
    }
}
```

- [ ] **Step 2: Build + clippy (no new unit test here; the pure parts are covered, the network path is integration-tested in Step 3)**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo clippy -p izba-core --all-targets -- -D warnings`
Expected: PASS (clean). Fix any unused-import / API-name issues against the real 0.26 surface.

- [ ] **Step 3: Add an env-gated integration test (real network)**

Add to the `tests` module (gated so it self-skips in CI/sandbox without network):

```rust
    #[test]
    fn end_to_end_resolves_a_real_name() {
        if std::env::var("IZBA_INTEGRATION").is_err() {
            eprintln!("skipping: set IZBA_INTEGRATION=1 to run (needs network DNS)");
            return;
        }
        let r = SystemResolver::new().unwrap();
        let query = sample_query(0x4242, RecordType::A).to_vec().unwrap();
        let bytes = r.handle(&query).unwrap();
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.id(), 0x4242);
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(!resp.answers.is_empty(), "expected at least one A record");
    }
```

Run (with network): `[ -f .cargo-env ] && source .cargo-env; IZBA_INTEGRATION=1 cargo test -p izba-core sys_resolver::tests::end_to_end -- --nocapture`
Expected: PASS (resolves example.com). Without the env var it self-skips.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): SystemResolver — terminating lookup + layered reload"
```

---

## Task 8: Wire into production + trim dead discovery code + full gate run

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/sys_resolver.rs` (export `SystemResolver`)
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (re-export if needed)
- Modify: `crates/izba-core/src/daemon/server.rs:111`
- Modify: `crates/izba-core/src/daemon/egress/dns.rs` (remove now-dead system-discovery code)

- [ ] **Step 1: Make `SystemResolver` reachable from `server.rs`**

In `crates/izba-core/src/daemon/egress/mod.rs`, ensure the module is visible to `server.rs`. If the other egress types are re-exported (e.g. `pub use`), add `pub use sys_resolver::SystemResolver;`. Otherwise reference it by path. Change the `mod sys_resolver;` from Task 2 to `pub(crate) mod sys_resolver;` if `server.rs` needs the path.

- [ ] **Step 2: Swap the production resolver**

In `crates/izba-core/src/daemon/server.rs` at the `DaemonDeps::production()` body (the `egress_resolver:` line ~111), replace:

```rust
            egress_resolver: std::sync::Arc::new(crate::daemon::egress::dns::UdpForwarder::system()),
```

with:

```rust
            egress_resolver: crate::daemon::egress::sys_resolver::SystemResolver::new()
                .expect("build system DNS resolver"),
```

(`SystemResolver::new()` returns `Arc<SystemResolver>`, which coerces to `Arc<dyn Resolver>`.) Leave the `#[cfg(test)]` `DaemonDeps` at ~line 674 using `UdpForwarder::new("127.0.0.1:53")` unchanged.

- [ ] **Step 3: Remove the now-dead discovery code in `dns.rs`**

`UdpForwarder::system()`, `system_upstream()`, `discover_upstream()`, and `parse_resolv_conf()` are no longer reachable from production (only `UdpForwarder::new` is used, by tests). Dead code fails `clippy -D warnings`. Remove `UdpForwarder::system()`, the free fns `system_upstream`, `discover_upstream` (both `#[cfg(unix)]` and `#[cfg(windows)]`), `parse_resolv_conf`, their now-unused imports, and the unit tests that exercised them (`parses_first_nameserver`, `parses_ipv6_nameserver_and_handles_garbage`, and the windows discovery test if present). Keep: the `Resolver` trait, `UdpForwarder` struct, `UdpForwarder::new`, and its `Resolver` impl (still used by tests).

- [ ] **Step 4: Run the full gate suite**

Run each; all must pass:

```bash
[ -f .cargo-env ] && source .cargo-env
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
cargo deny check advisories bans licenses sources
```

Expected: all green. If `dns.rs` removal left an unused `Duration`/`SocketAddr`/`UdpSocket` import, drop it. If `UdpForwarder::new` is now the only constructor and clippy flags anything, address it minimally.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/server.rs \
        crates/izba-core/src/daemon/egress/mod.rs \
        crates/izba-core/src/daemon/egress/dns.rs \
        crates/izba-core/src/daemon/egress/sys_resolver.rs
git commit -m "feat(egress): use SystemResolver in production; drop start-time DNS capture"
```

---

## Final verification (manual, on the Windows host — optional but ideal)

The original bug was Windows/GlobalProtect. After deploying this build, the repro is: connect VPN, start a sandbox, `apt-get update` (works), reconnect VPN, `apt-get update` again — it should self-heal without `izba daemon stop`. This is out of automated scope (needs the VPN host) but is the real acceptance test; note it for the user to validate.

## Self-review notes (coverage vs spec)

- Terminate via hickory typed lookup — Tasks 3, 7. ✅
- DnsCaps capability seam (hardcoded v1 + TODO) — Task 2. ✅
- ResolverCell mirroring PolicyCell (no arc-swap) — Task 6. ✅
- Layer 2 lazy-on-failure (rate-limited, retry once) — Task 7 (`resolve`/`try_reload_on_failure`). ✅
- Layer 3 poll (30s) + if-watch (1s debounce) — Task 7 (`spawn_reload_tasks`). ✅
- ConfigSource test seam + fingerprint dedupe — Tasks 5, 6. ✅
- Untouched `Resolver` trait / `dns_loop` / snoop / SERVFAIL — only `server.rs:111` swapped; `dns_loop` unchanged (it still maps `handle` Err → servfail). ✅
- hickory 0.26 alignment + cargo-deny + windows-gnu cross verified early — Task 1. ✅
- Non-goals (registry shim, true split-DNS) — not implemented, per spec. ✅
