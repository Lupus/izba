# M2 — Agent firewall (merged MITM L7 + allow-list + audit) — design

**Status:** approved 2026-06-14. Supersedes the narrow "M2 = domain allow-list"
framing in [roadmap.md](../../roadmap.md): M2 now absorbs M5's MITM datapath
(the leapfrog), and M5 is redefined as the credential vault only.

**Grounded in:** [egress-firewall-building-blocks.md](../../egress-firewall-building-blocks.md)
(building-block decisions + the proven OpenShell-salvage MITM spike),
[2026-06-12-izba-mesh-networking-design.md](2026-06-12-izba-mesh-networking-design.md)
§4 (policy planes) / §5 (credentials at the MITM branch), and the locked vision.

## 1. Goal & scope

The headline, single-sandbox, north–south: **"my agent can only reach
`api.anthropic.com` and `github.com`, every connection it tried is in
`izba netlog`, and there are no uninspectable channels."** This is izba's first
release tag.

**In scope (M2):**
- TLS-MITM datapath in izbad (terminate guest HTTPS, mint per-SNI leaves under
  an izba CA, re-originate to upstream). Salvaged from the proven spike.
- The **loopback-hop bridge** from the blocking vsock egress plane to a
  dedicated tokio MITM runtime.
- **Two-tier policy plane**, one `regorus` engine, default-deny when a policy is
  declared:
  - Tier 1 — HTTP(S): hard L7 decision on `{sandbox, host, method, path, port}`.
  - Tier 2 — non-HTTP TCP: soft **DNS-snoop** FQDN allow-list.
- **Audit log + `izba netlog`** — every allow/deny, structured, per sandbox.
- **CA-in-guest** — bake the izba CA into the guest trust store at boot.
- Per-sandbox policy config (static at create).
- End-to-end tests, local + CI, on both platforms (KVM + OpenVMM/WHP).

**Deferred (NOT M2):**
- Credential injection / per-role vault → **M5** (with OCSF audit schema +
  SPIFFE identity exploration).
- Binary attribution (OpenShell `procfs.rs`) → later.
- HTTP/2 (force http/1.1 via ALPN; nearly all servers downgrade) → follow-up.
- Policy presets (open/balanced/closed) → post-release.

## 2. Milestone restructure

| # | Was | Now |
| --- | --- | --- |
| M2 | domain allow-list + audit | **Agent firewall (merged):** MITM L7 + two-tier allow-list + audit/netlog + CA-in-guest. First release tag. |
| M3 | resources + volumes | unchanged |
| M4 | projects: izba.yaml + mesh | unchanged |
| M5 | credential vault: MITM everything | **Credential vault only:** OCSF audit schema + SPIFFE identity + per-role injection. MITM branch already built in M2; this adds role→secret mapping (needs M4's manifest) + injection + the credential audit layer. |

## 3. Architecture

### 3.1 Datapath & the loopback-hop bridge

izbad's egress plane is blocking std-threads; the MITM datapath is tokio. The
bridge keeps the platform-divergent vsock I/O in the blocking world (where it
already works on Linux/CH and Windows/OpenVMM) and confines tokio to
cross-platform loopback + upstream TCP.

```
guest ──vsock 1027──▶ router::tcp_connect (blocking)
   │  StreamOpen::TcpConnect{addr=IP, port}
   │  policy tier decision (port ∈ {80,443} ⇒ MITM; else tier-2)
   ▼  MITM-elected:
   register (loopback_src_port → {dst_ip,port,sandbox}) in DstMap
   dial blocking TcpStream → 127.0.0.1:<mitm_port>
   portfwd::pump_bidirectional(loopback_tcp, uds_stream)   ← UNCHANGED, churn-safe
                                   │
   tokio MITM runtime ◀────loopback TCP────┘
     accept; peer src_port → DstMap → {dst_ip,port,sandbox}
     TlsAcceptor (ResolvesServerCert mints a leaf for the ClientHello SNI
                  under the izba CA); ALPN = http/1.1
     read decrypted request head → L7Request{sandbox,host,method,path,port}
     regorus policy.check  ── Deny ──▶ synth 403, close
                            ── Allow ─▶ dial dst_ip:port, TLS-connect (SNI=host),
                                        replay head, pump bidirectional
     emit audit record either way
```

- One dedicated `tokio::runtime::Runtime` (multi-thread) for the MITM, started
  once in izbad. Non-MITM'd flows stay on today's blocking splice.
- **DstMap**: `Arc<Mutex<HashMap<u16, OrigDst>>>`, keyed by loopback source
  port (unique per live connection). Entry removed when the MITM handler claims
  it; TTL sweep guards leaks. `127.0.0.1`-only listener; unknown source port ⇒
  hard drop.
- Per-SNI leaf minting upgrades the spike (which passed SNI explicitly) to a
  rustls `ResolvesServerCert` that reads the ClientHello SNI.
- WebSocket: police the `GET`+`Upgrade` request (tier-1 L7), then opaque-pipe
  the upgraded frames through the same pump.
- Non-TLS / non-HTTP bytes arriving on an intercepted port: `looks_like_tls`
  peek (already lifted) classifies; non-TLS ⇒ treat as tier-2 (opaque pump to
  `dst_ip:port` subject to the tier-2 verdict) rather than attempting MITM.

### 3.2 Two-tier policy plane (one regorus engine)

`regorus` behind the existing `Policy` trait. One template `Engine` built at
daemon start (policy module + per-sandbox data doc), `clone()` per check (cheap
Arc'd AST), `arc` feature for `Send+Sync`. Default-deny when a policy is
declared; bare sandboxes stay allow-all until then.

- **Tier 1 (HTTP/S, hard):** input `{sandbox, host, method, path, port}` from
  the decrypted request. The domain allow-list bites here on the real `Host` —
  no shared-CDN-IP ambiguity. Rego mirrors the docker-mitm-bridge lineage
  (domain tiers; method/path available for future rules).
- **Tier 2 (non-HTTP TCP, soft):** a per-sandbox DNS-snoop store
  `IpAddr → {fqdn, expiry}`, populated by snooping the DNS responses izbad
  already forwards (parse with `hickory-proto`), TTL clamped to `[60s, 15min]`.
  On a `TcpConnect` to a non-HTTP port, IP→FQDN(s)→allow-list. Raw-IP with no
  snoop record ⇒ default-deny. Plus an RFC1918/link-local dial denylist
  (anti-rebinding), independent of snoop state.

Both tiers call `policy.check` with the same `FlowDesc` grown to carry the
optional L7 fields; the engine decides on whatever is present.

### 3.3 Audit / netlog

A structured record at the dispatch point for every decision:
`{ts, sandbox, dest_ip, port, sni|host, method?, path?, tier, verdict,
matched_rule?}`. Emitted via `tracing` + a JSON layer to a per-sandbox audit log
on disk (under the sandbox dir). `izba netlog <sandbox> [--follow]` tails/queries
it. This is the "see every connection it tried" headline.

### 3.4 CA-in-guest

izbad mints + persists a root CA (the same CA the MITM signs leaves with).
Transport to the guest: a second **read-only `izba-trust` virtiofs share**
(host dir containing `ca.pem`). izba-init mounts it, writes `ca.pem` + a combined
bundle (izba CA ++ the guest image's system bundle, if present) into the overlay
beside `write_resolv_conf()`, and injects the 6-var CA-bundle env set
(`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO` →
combined bundle; `NODE_EXTRA_CA_CERTS`/`DENO_CERT` → CA only) at the exec choke
point, default-unless-overridden. ~120–180 lines, **no proto change**.
Cert-pinning clients knowingly break (locked posture).

### 3.5 Config surface

Per-sandbox policy declared at create: a CLI flag pointing at (or inlining) a
policy file persisted under the sandbox dir. Shape (M2, static):
```
# izba egress policy (per sandbox)
allow:                       # tier-1 HTTP(S) domains (globs ok)
  - api.anthropic.com
  - "*.github.com"
allow_tcp:                   # tier-2 non-HTTP host:port (DNS-snoop'd)
  - "db.internal:5432"
```
Compiled to the regorus data doc + the tier-2 allow-list at load. Hot-reload is
M4's `reload` verb; M2 is static at create. Bare sandboxes (no policy) stay
allow-all + audited.

## 4. Crate touch-points

- `izba-core`: `daemon/egress/mitm.rs` (datapath, from spike), `mitm` runtime +
  `DstMap` bridge, `router.rs` tier dispatch, `policy.rs` `RegoPolicy` (from
  spike) + `FlowDesc` L7 fields, `daemon/egress/dns_snoop.rs` (store +
  `hickory-proto` parse), `audit.rs`, CA mint/persist + the `izba-trust` FsShare
  in `sandbox.rs`, `izba netlog` plumbing.
- `izba-init`: `izba-trust` mount in `mounts.rs`, `write_trust_anchor()` in
  `main.rs`, CA-bundle env defaults in `exec.rs`.
- `izba-cli`: `izba netlog`, the `--policy` create flag.
- `izba-proto`: no change (CA via virtiofs, not the wire).
- New deps (izba-core): `rustls 0.23`+`tokio-rustls 0.26`+`rcgen 0.13`
  (default-features=false, **ring**), `rustls-pemfile`, `regorus`
  (std/arc/regex/glob), `hickory-proto` (read-only). tokio gains
  `rt-multi-thread`/`net`/`io-util`.

## 5. Testing (local + CI)

- **Unit (host-testable, no listeners):** the spike's 7 MITM tests; `RegoPolicy`
  tier-1/tier-2 + per-sandbox isolation; DNS-snoop store (TTL clamp, wildcard,
  raw-IP default-deny); audit record shape; CA bundle-building.
- **Integration (KVM + OpenVMM, env-gated):** a real guest, izba CA baked in,
  `curl https://<allowed>` succeeds through the MITM (leaf chains to izba CA) and
  is in `izba netlog`; `curl https://<denied>` is blocked + logged; a tier-2
  non-HTTP allow/deny; **a real-OpenVMM churn pass** re-proving the
  drain-to-EOF invariant survives the loopback hop; baseline throughput measured.
- **Windows:** the WHP validation suite gains the MITM e2e; `izba-core` Windows
  cross-check stays green (ring/rcgen/tokio-rustls confirmed by the spike).
- **CI:** the e2e tests land in `.github/workflows/e2e.yml` (real-VM legs) and the
  unit additions in `ci.yml`. Pre-flighted locally with the same invocations.

## 6. Exit criteria

The one-liner demo on **both platforms**, in an automated integration test:
allowed domain reachable + MITM'd + audited; denied domain blocked + audited;
no uninspectable channel (raw-IP/non-snooped TCP denied); baseline throughput
recorded (measured, not gated). All six local gates + both CI legs green.

## 7. Risks

| Risk | Mitigation |
| --- | --- |
| Real-OpenVMM churn under the loopback hop | Reuse the proven blocking `pump_bidirectional` verbatim for the vsock leg; dedicated churn integration test |
| tokio runtime footprint in izbad | One contained runtime; non-MITM flows untouched |
| Rare h2-only endpoints | ALPN-force http/1.1; revisit per concrete break |
| Tier-2 is a soft boundary (shared-CDN-IP, hostile guest) | Documented; tier-1 MITM is the hard boundary; "no uninspectable channels" holds because raw-IP non-snooped TCP is denied |
| Cert-pinning clients break | Accepted/documented locked posture |
