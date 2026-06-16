# izba DNS: system-resolver with live config reload

**Status:** approved design (2026-06-16)
**Branch base:** `origin/main` @ `20e1cc1` (hickory-proto 0.26 / RUSTSEC-2026-0119 fixed)

## Problem

izbad's egress DNS plane forwards raw queries to an upstream **captured once at
daemon start** (`UdpForwarder::system()` → `discover_upstream()`), and never
re-reads it. When the host's DNS routing changes after startup — most acutely a
**VPN reconnect** (observed: Palo Alto GlobalProtect on Windows) — the captured
upstream's network becomes unreachable (`os error 10051` / `WSAENETUNREACH` on
every query), so guest name resolution dies (`apt-get update` fails) until the
daemon is manually restarted. TCP egress is unaffected; only DNS breaks.

The forwarder is also single-server with no failover/TCP-fallback: it binds a
fresh UDP socket per query, sends once, and surfaces any error as SERVFAIL.

## Goals

- Resolve via a real resolver that **re-reads system DNS config** and recovers
  automatically when the host network changes (no daemon restart).
- Keep the existing `Resolver` trait (`sync handle(&[u8]) -> Result<Vec<u8>>`)
  and leave `EgressManager`, `dns_loop`, DNS-snoop, and SERVFAIL paths
  untouched.
- Gain multi-server failover + UDP→TCP fallback for free (via hickory).
- Establish a **DNS-capability seam**: terminating resolution lets us govern
  which query types the guest may use (hardcoded allowlist for v1; policy-wired
  later).

## Non-goals (out of scope for this change)

- True per-suffix split-DNS correctness (resolving VPN-internal names). That
  needs OS-resolver delegation (`DnsQueryEx` on Windows / systemd-resolved
  D-Bus); deferred until a guest actually needs internal names. See the
  resolver-survey discussion in the M-series notes.
- The Windows `RegNotifyChangeKeyValue` registry shim ("Layer 1" full event
  coverage for DNS-server-only changes on a live adapter). `if-watch` covers the
  VPN-reconnect case (interface/IP flap); the lazy-on-failure layer covers the
  rest. Add the registry shim only if first-query latency proves to matter.
- Per-sandbox DNS-capability policy wiring (the seam exists; wiring is future).

## Approach: terminate via hickory typed lookup

Chosen over raw-forwarding (low-level pool) because the high-level typed API is
stable, less code, reuses the in-tree `hickory-proto 0.26`, and — decisively —
**terminating gives a control point** to govern query types / DNS capabilities.
Trade-off accepted: loses faithful EDNS/DNSSEC passthrough. Supported qtypes
(A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, SOA, CAA) cover the sandbox workload
(apt/curl/git/agents); generic `RecordType` lookups remain possible.

## Architecture

### `SystemResolver` — new, behind the existing `Resolver` trait

Drop-in replacement for `UdpForwarder::system()` at `server.rs:111` (and the
secondary construction at `server.rs:674`). Owns:

- `rt: tokio::runtime::Runtime` — small multi-thread (1–2 workers), same pattern
  as `mitm_runtime.rs`. Background reload tasks run here; `handle()` is called
  from blocking egress threads and `block_on`s lookups (never called from a
  runtime thread, so `block_on` is safe).
- `cell: ResolverCell` — the live resolver state, swappable (see below).
- `caps: DnsCaps` — the query-type allowlist (hardcoded constant for v1).
- a rebuild rate-limiter (`Mutex<Instant>`, last-rebuild timestamp).

### `ResolverCell` — mirror of the existing `PolicyCell`

House pattern (deliberately a short-lock `Mutex<Arc<…>>`, **not** `arc-swap`;
see `PolicyCell`'s rationale comment). Holds `Arc<ResolverState>`:

```
struct ResolverState { resolver: TokioResolver, fingerprint: u64 }
struct ResolverCell  { inner: Mutex<Arc<ResolverState>> }
  fn load(&self) -> Arc<ResolverState>     // cheap Arc clone under short lock
  fn store(&self, s: Arc<ResolverState>)   // future loads see the new one
```

The lock is only ever held for an `Arc` clone/replace, never across I/O.
In-flight lookups keep the `Arc` they cloned; a reload affects the next query.

### `ConfigSource` — test seam

```
trait ConfigSource: Send + Sync {
    fn discover(&self) -> anyhow::Result<(ResolverConfig, ResolverOpts)>;
}
```

Production impl wraps `hickory_resolver::system_conf::read_system_conf()` (reads
`/etc/resolv.conf` on unix; adapter DNS servers via the `ipconfig` crate /
`GetAdaptersAddresses` on Windows — picks up the live VPN adapter). A fake impl
drives fingerprint/reload tests without touching the network or binding sockets
(honors the project's no-listener test constraint).

### `DnsCaps` — capability seam

```
struct DnsCaps { allowed: &'static [RecordType] }   // v1: hardcoded constant
  fn permits(&self, qtype: RecordType) -> bool
```

Disallowed qtype → synthesized **NOTIMP** response. v1 ships one fixed set with
a `// TODO(policy): per-sandbox DNS caps` marker at the construction site.

## Resolution flow (`handle`, on the blocking egress thread)

1. Parse `query` bytes → `Message` (hickory-proto). Unparseable → SERVFAIL.
2. Extract first question `(name, qtype)`. No question → FORMERR/SERVFAIL.
3. `caps.permits(qtype)`? No → synthesize NOTIMP, return.
4. `state = cell.load()`; `rt.block_on(state.resolver.lookup(name, qtype))`.
5. Classify the result:
   - **Records** → synthesize response: echo header id + question, set
     `QR=1, RD` (copied), `RA=1`, push answer records, rcode NOERROR. Encode.
   - **No-records / NXDOMAIN** (hickory `ResolveErrorKind::NoRecordsFound`) →
     synthesize the negative response with the right rcode (NXDOMAIN vs NODATA)
     from hickory's response code; include SOA if hickory returned one.
   - **Transport/network error** (io / no-connections / timeout) → **Layer 2**:
     trigger a rate-limited rebuild and **retry the lookup once**; if it still
     fails, return `Err` (→ SERVFAIL at `dns_loop`, unchanged).
6. Return response bytes. `dns_loop` snoops A/AAAA out of them unchanged
   (`extract_a_aaaa(&resp)` operates on raw bytes).

Response synthesis must respect the guest's UDP buffer: if the encoded answer
exceeds the negotiated/standard size, set the `TC` bit so the guest retries over
TCP (already routed to the same resolver via `dns_loop` on TCP:53).

## Reload layers (one shared apply path)

**Apply path** (`reload_if_changed`): `config_source.discover()` → fingerprint =
hash(nameserver socketaddrs + search domains) → if unchanged vs current, drop &
stop (dedupe); else build a fresh `TokioResolver` on `rt` and `cell.store()`.

- **L2 — lazy on-failure (load-bearing):** step 5 above. Rate-limited to ≤1
  rebuild / 2s so a genuinely-down upstream can't spin. This alone cures the
  observed bug.
- **L3 — poll:** `rt`-spawned `interval(30s)` → `reload_if_changed()`. Catches
  silent drift that produced no event and no hard failure.
- **if-watch — proactive:** `rt`-spawned `IfWatcher` stream → 1s debounce →
  `reload_if_changed()`. Catches VPN reconnect (interface/IP flap) fast, with no
  Windows registry shim. Debounce coalesces the event burst a VPN connect emits.

## Dependencies & versioning

- `hickory-resolver = { version = "0.26", default-features = false, features =
  ["system-config", "tokio"] }` — aligns with the in-tree `hickory-proto 0.26`
  (one proto version; rides the RUSTSEC-2026-0119 fix). Confirm the exact
  feature names against 0.26 during implementation (system-config gates
  `read_system_conf`; tokio gates `TokioResolver`).
- `if-watch = { version = "3", features = ["tokio"] }` — cross-platform
  interface/IP event stream (netlink on Linux, IP Helper on Windows).
- **No `arc-swap`** — `ResolverCell` mirrors `PolicyCell`.

## Gates (all must be green before commit)

The standard six **plus** the F-22 supply-chain gate:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
- `cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
- `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
- **`cargo deny check advisories bans licenses sources`** — new deps + their
  transitives (if-watch → rtnetlink/netlink-*/`windows`; hickory-resolver →
  `ipconfig`) must pass. `ignore = []`, `wildcards = deny`. This + the
  windows-gnu cross gates are the **primary integration risks**; verify both
  EARLY (add deps, run `cargo deny` + the cross checks before writing logic).

## Testing (TDD)

Unit (no network, no listeners — fakes per the project constraint):

- Fingerprint: same config → same hash; changed nameserver/search → different.
- `reload_if_changed`: with a fake `ConfigSource`, a changed config swaps the
  cell; an unchanged config is a no-op (dedupe).
- `DnsCaps`: disallowed qtype → NOTIMP; allowed → proceeds.
- Response synthesis (pure, on `Message`): id + question echoed; QR/RA set;
  records placed; NOERROR. Negative: NXDOMAIN vs NODATA rcode mapping.
- Lazy retry: a fake lookup seam that fails transport-class once then succeeds →
  `handle` triggers exactly one rebuild and returns the success; persistent
  transport failure → `Err` (→ SERVFAIL).

Integration (env-gated, real network or a local fake server): end-to-end
`handle()` resolves a real name; reload swaps to a new upstream. Reuse the
existing env-gating style (`IZBA_INTEGRATION`).

## Risks

1. **windows-gnu cross-compile** of `if-watch` + `hickory-resolver` (+
   `ipconfig`, `windows`). Pure-Rust, expected to pass, but unverified — check
   first.
2. **cargo-deny** flags a transitive of if-watch (unmaintained advisory /
   non-allowlisted license). Mitigation: triage per `deny.toml` policy (patch /
   bump / replace / specific time-boxed exception) — never a blanket ignore.
3. hickory 0.26 feature-name / API drift vs the survey (which referenced
   0.26.1). Confirm `read_system_conf`, `TokioResolver`, and
   `ResolveErrorKind` shapes against the actual 0.26 docs during impl.
