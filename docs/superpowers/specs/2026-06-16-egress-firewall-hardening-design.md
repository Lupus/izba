# Egress firewall hardening — Phases 1 & 2 design

> **Date:** 2026-06-16 · **Status:** approved design, ready for an implementation
> plan. Scope: security findings **F-01** (SSRF) and **F-02/F-03** (MITM
> bypasses) from [`docs/security/findings-2026-06-15.md`](../../security/findings-2026-06-15.md).
> **F-05** (DNS resolve-and-pin) is a deferred follow-on — see
> [`docs/security/egress-firewall-p3-dns-resolve-and-pin.md`](../../security/egress-firewall-p3-dns-resolve-and-pin.md).

## Problem

izba's egress plane (guest → izbad over vsock 1027) has three confirmed bypasses
of its "the guest is hostile from instruction zero" model:

- **F-01 — open SSRF proxy on bare sandboxes.** The private/loopback/link-local
  address denylist (`router.rs::is_private`) is gated behind `policy.enforces()`.
  A bare/M1 sandbox (`AllowAll`, non-enforcing) takes the permissive branch and
  izbad dials *anything* the guest names — `127.0.0.1:6379`, the cloud metadata
  IP `169.254.169.254`, the LAN — **from the host network namespace**. An
  existing test (`decide_tier2_permissive_allows_raw_ip`) even codifies the hole.
- **F-02 — MITM never binds ClientHello SNI to the HTTP Host, and has no
  private-IP guard.** The leaf is minted per ClientHello SNI; the policy verdict,
  the upstream TLS server-name, and the audited host all come from the decrypted
  `Host`. Nothing asserts `SNI == Host`. Worse, the tier-1 MITM path
  (`tcp_connect` for `port ∈ {80,443}` + enforcing) jumps straight to `mitm_hop`
  with **no `is_private` check at all** — a guest can make izbad MITM-dial
  `127.0.0.1:443`.
- **F-03 — only the first request on a kept-alive MITM connection is checked.**
  `read_request_head` runs exactly once; after Allow, the rest of the bytes are
  copied verbatim. HTTP/1.1 keep-alive lets a guest pass `Host: allowed`, then
  reuse the TLS+TCP session for any `Host`. The audit log records only the first.

The MITM datapath was always a spike: `mitm.rs:363` already says *"the real
izbad should parse with hyper's http1 server… OpenShell does exactly that."* The
hand-rolled request-line sniffer is what we replace.

## Goals / non-goals

**Goals:** close F-01, F-02, F-03; move the MITM onto a real HTTP stack so
keep-alive/h2/Host-handling are correct by construction; preserve every existing
load-bearing contract (loopback-hop bridge, `DstMap` rendezvous, OpenVMM
churn-teardown on the vsock leg, fail-closed-for-enforcing).

**Non-goals (recorded, not built here):**
- Default-deny-as-baseline for *bare* sandboxes — a bare `izba run` stays
  allow-all for **public** destinations (M1-compatible "no firewall" mode). F-01
  only closes the SSRF hole for everyone. Flipping the bare default to deny-all is
  a separate product/UX posture decision.
- F-05 DNS resolve-and-pin / rate-limit / QNAME gate — Phase 3 follow-on, gated on
  the hickory-resolver adoption.
- F-04 audit-log integrity; F-23 CA validity/pathlen.
- **h2 *extended-CONNECT* WebSocket** (RFC 8441). WebSocket is handled via the
  HTTP/1.1 `Upgrade` path (the dominant case); a guest doing WebSocket over h2 is
  an out-of-scope edge that degrades to a clean deny, not a hang.

## Architecture

Two independently-shippable phases, serialized (both touch the shared egress
files). All work is izbad-side; no guest/`izba-init` changes.

```
guest (vsock 1027)
  └─ StreamOpen::TcpConnect{addr,port}
       router::tcp_connect          [BLOCKING std-thread plane]
         ├─ port 53            → dns_loop (resolver)         (unchanged)
         ├─ is_private(ip)?    → DENY  ◄── PHASE 1 (unconditional)
         ├─ port∈{80,443} & enforcing
         │     └─ mitm_hop → loopback dial → DstMap rendezvous
         │            └─ MitmRuntime accept_loop  [TOKIO plane]
         │                  └─ handle(tcp, OrigDst, policy)  ◄── PHASE 2 rewrite
         └─ else tier-2: decide_tier2 → dial → splice
```

### Phase 1 — F-01: unconditional SSRF address denylist (`router.rs` only)

Make `is_private` an **unconditional chokepoint** screening *every* egress dial,
bare or enforcing, tier-1 or tier-2.

1. **`decide_tier2`:** screen `is_private(ip)` **before** the `enforces()` branch.
   The permissive (bare) branch then relaxes only the *allow-list* requirement,
   never the address denylist. A bare sandbox keeps reaching **public** IPs; it no
   longer reaches loopback/link-local/RFC1918/unspecified.
2. **Tier-1 MITM path:** in `tcp_connect`, add an `is_private(ip)` guard for
   `port ∈ {80,443}` **before** `mitm_hop` (today there is none). Deny + audit
   (`Tier::L7`, rule `"private-address denylist"`).
3. **Harden `is_private`:** canonicalize **IPv4-mapped IPv6** (`::ffff:a.b.c.d`)
   and IPv4-compatible IPv6, and screen the embedded v4 — a known SSRF bypass.
   Keep the existing v4 (private/loopback/link-local/unspecified/broadcast/
   documentation) and v6 (loopback/unspecified/ULA fc00::/7/link-local fe80::/10)
   coverage.

**Behavior change:** `decide_tier2_permissive_allows_raw_ip`'s private-IP
assertion (currently asserts a bare sandbox reaches `10.0.0.5`) flips to Deny;
its public-IP assertion (`1.2.3.4` allowed) stays.

### Phase 2 — F-02/F-03: hyper-util MITM engine (`mitm.rs` + `mitm_runtime.rs`)

Replace `mitm_terminate`'s hand-rolled body with a real HTTP stack. **Unchanged:**
`IzbaCa` / `CertCache` / `SniResolver` (per-ClientHello-SNI leaf minting under the
izba CA), the blocking router, the loopback-hop `DstMap` rendezvous, and the
OpenVMM churn-teardown discipline on the vsock leg (`portfwd::pump_bidirectional`
stays the splice for the vsock↔loopback hop; only the loopback TCP enters tokio).

**New tokio-side handler** (replaces `accept_loop`'s `mitm_terminate` call):

1. **Classify by port, not by peeking.** The `DstMap` entry carries `OrigDst.port`.
   `443 ⇒ TLS-terminate` (via the existing `state.acceptor`, per-SNI leaf);
   `80 ⇒ cleartext HTTP`. No `looks_like_tls` peek and **no buffering/Rewind
   adapter.** Non-conforming traffic (plaintext to :443, TLS to :80) fails the
   accept / h1 parse → fail closed.
2. **Capture the negotiated SNI** after the TLS handshake via
   `tls.get_ref().1.server_name()` → `Option<String>`. A ClientHello with **no
   SNI** already fails closed today (the `SniResolver` returns no leaf); keep that.
3. **Serve h1 + h2 with hyper-util:**
   `hyper_util::server::conn::auto::Builder::new(TokioExecutor)
   .serve_connection_with_upgrades(TokioIo::new(stream), service)`. The `service`
   is invoked **per request** on the connection (per h2 *stream* under h2) → F-03
   dissolved structurally. The client-leg ALPN (`server_config_with_resolver`) is
   updated to offer `h2` + `http/1.1` so guests may negotiate h2; the upstream leg
   negotiates its own protocol independently and hyper **bridges h2↔h1 at the
   `Request`/`Response` layer** (no byte-splice, so no ALPN leg-asymmetry hazard).
4. **The policy `Service`** (per request):
   - Extract `Host` (`:authority` for h2, `Host` header for h1).
   - **F-02 — `SNI == Host`** (ASCII-case-insensitive, port-stripped) when SNI is
     present. Mismatch ⇒ synthesized **403** + audit (`Tier::L7`, rule
     `"sni-host-mismatch"`); no upstream dial.
   - **Policy check** on `Host` via the existing `PolicyAdapter` → regorus,
     audited **every** request. Deny ⇒ synthesized 403; connection stays open for
     the next (still-checked) request.
   - **Allow ⇒ forward upstream.** One re-originated TLS connection **per guest
     connection**, reused across keep-alive requests (the connection is pinned to
     one `Host` by the SNI==Host check). Dial `OrigDst.ip:port` (Phase 3 upgrades
     this to the izbad-resolved IP) and **verify the upstream cert against `Host`**
     using webpki roots (`upstream_client_config_webpki`). Stream request/response
     bodies.
5. **WebSocket:** the `Service` sees `Upgrade: websocket` ⇒ return `101`, take both
   legs via `hyper::upgrade::on`, and `copy_bidirectional`. (Policy still ran on
   the upgrade request's `Host`.)
6. **Non-HTTP-over-TLS ⇒ fail closed, not tunnel.** If, after TLS termination on
   :443, the payload is not HTTP, hyper's `serve_connection` errors on the
   preface; we **audit + drop** the connection. An L7 HTTP firewall that cannot
   parse the L7 must deny, never blind-tunnel arbitrary bytes to an allow-listed
   IP (that would be zero-inspection exfil). Bare sandboxes are unaffected — they
   never enter the MITM.

**New direct dependencies** (all already transitive via reqwest/oci-client; all
MIT/Apache; pure-Rust + rustls/ring, so the `x86_64-pc-windows-gnu` cross gate
stays green): `hyper` (server+client, http1+http2), `hyper-util` (auto server,
legacy client, tokio rt), `hyper-rustls` (upstream connector), `http-body-util`.
Verify against `cargo-deny` (advisories + licenses) before commit.

## Data flow & failure direction

Every new path **fails closed for enforcing sandboxes** — mismatched SNI, policy
deny, non-HTTP preface, unavailable/failed upstream, private OrigDst ⇒ deny, never
fall through to a direct dial. Bare sandboxes keep transparent direct-dial for
*public* destinations and never enter the MITM. The audit sink records **every**
request (Phase 2 makes "see every connection" structural, fixing F-03's
under-reporting). The existing `mitm=None` fail-closed-when-runtime-absent
contract (router.rs:99-124) is untouched.

## Component boundaries

- **`router.rs`** — blocking dispatch + the `is_private` chokepoint (Phase 1) +
  the loopback-hop registration (unchanged). Owns tier-2 decisions and audit
  emission for the L3 path.
- **`mitm.rs`** — CA/leaf machinery (`IzbaCa`, `CertCache`, `SniResolver`,
  `server_config_with_resolver`) kept; the orchestrator (`mitm_terminate` and its
  hand-rolled `read_request_head`/`pump_bidirectional`) replaced by the hyper-util
  `Service` datapath. The `MitmPolicy`/`L7Request`/`L7Verdict` seam may be folded
  into the `Service` or kept as the policy-adapter shape — implementation detail
  for the plan.
- **`mitm_runtime.rs`** — `MitmRuntime`/`DstMap`/`accept_loop`/`PolicyAdapter`
  kept; `accept_loop` calls the new handler instead of `mitm::mitm_terminate`.
  The per-flow `OrigDst` + policy rendezvous is unchanged.

## Testing (TDD, per phase)

**Phase 1** (unit, no listeners — `UnixStream::pair`/pure-fn style):
- bare (`AllowAll`) sandbox **denied** to loopback / `169.254.169.254` / RFC1918 /
  unspecified / IPv4-mapped-v6 loopback; **still allowed** to a public IP.
- enforcing MITM path denies a private `OrigDst` before `mitm_hop`.
- the flipped `decide_tier2_permissive_allows_raw_ip` assertion.

**Phase 2** (extend the existing `tokio::io::duplex`-driven MITM e2e in `mitm.rs`):
- **keep-alive two-request** (F-03): request 1 `Host: allowed` passes; request 2
  on the *same* connection with `Host: other` is **denied + audited**.
- **SNI≠Host** (F-02): ClientHello SNI `a.com`, request `Host: b.com` ⇒ 403.
- **h2** client path negotiates and is policy-checked per stream.
- a **WebSocket** upgrade is policy-checked then bridged.
- a **non-HTTP-over-443** payload after TLS ⇒ clean audited deny (no hang/panic,
  no upstream dial).
- existing happy-path + deny-short-circuit tests still pass (ported).

Both phases: all six green-before-commit gates incl. `cargo clippy -D warnings`,
`cargo fmt --check`, `cargo check`/`clippy` for `x86_64-pc-windows-gnu`, and the
musl `izba-init` static build.

## Delivery
Two PRs off `main`, serialized: **PR-A = Phase 1**, **PR-B = Phase 2** (rebased on
PR-A). Conventional commits; TDD (tests first).
