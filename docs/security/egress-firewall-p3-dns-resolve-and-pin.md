# Egress firewall hardening — Phase 3 (follow-on): DNS resolve-and-pin

> **Status:** NOT STARTED — deliberately deferred follow-on. This is a context
> stub, not an approved spec. It captures everything needed to execute Phase 3
> later without re-deriving it. Phases 1–2 (SSRF address denylist + hyper-util
> MITM engine) ship first; their approved design is
> [`docs/superpowers/specs/2026-06-16-egress-firewall-hardening-design.md`](../superpowers/specs/2026-06-16-egress-firewall-hardening-design.md).
>
> **Hard prerequisite:** the in-flight `hickory-resolver` adoption (see below)
> must land before Phase 3 starts. Phase 3 builds directly on top of it.

## What Phase 3 fixes

**Finding F-05** (`docs/security/findings-2026-06-15.md`) — two distinct problems
on the DNS plane, both for **enforcing** sandboxes:

1. **DNS-snoop answers are trusted as the tier-2 allow-list key.** `dns_loop`
   records `(guest-chosen-name → resolved-IP)` from answers the guest's own
   queries produced (`router.rs` `dns_loop` → `dns_snoop::extract_a_aaaa`).
   `decide_tier2` then authorizes a raw-IP dial if *any* snooped name for that IP
   passes the allow-list. A guest that influences resolution (its own domain, or
   a low-TTL DNS-rebind) can plant `allowed-name → attacker-IP` and dial it on a
   non-HTTP port to pass tier-2. The 60 s snoop TTL floor *widens* the rebind
   window.
2. **The DNS forwarder is an unconditional, unmetered exfil channel.** `:53`
   (UDP via `StreamOpen::Dns`, and TCP via the `port == 53` short-circuit in
   `router::tcp_connect`) is forwarded to the host resolver for *every* sandbox,
   enforcing or not, *before any policy*, with no rate limit — data-in-QNAMEs C2.

## Hard dependency: the parallel hickory-resolver work

A separate effort is replacing izbad's **raw-UDP DNS forwarder** (the current
`Resolver` impl behind the trait in `daemon/egress/dns.rs`) with
**`hickory-resolver` 0.26.1**, built from `from_system_conf()`, rebuilt/re-read on
resolution failure or a network-change signal. Motivation: after the host OS DNS
servers changed, izbad could no longer resolve anything (the raw forwarder had
stale upstreams). hickory-resolver is pure-Rust, records + TTL aware, mature, and
keeps the static/cross-compile build posture.

**Why this is a prerequisite, not a conflict:** the two efforts touch the DNS
plane at *different layers*.

| Layer | Owner | Touches |
| --- | --- | --- |
| Resolver **implementation** (raw-UDP → hickory) | the parallel DNS work | `daemon/egress/dns.rs` internals |
| Policy **around** the resolver (rate-limit, QNAME gate, resolve-and-pin) | Phase 3 | `router.rs` / `dns_snoop.rs`, *consuming* the resolver |

The **only shared surface is the `Resolver` trait signature.** Phase 3's
resolve-and-pin needs a typed lookup —
`fn resolve(&self, name: &str) -> anyhow::Result<Vec<IpAddr>>` — alongside the
existing raw `fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>>`.
`hickory-resolver` provides this natively (`lookup_ip`), so the typed method is
**most naturally added with the hickory adoption.** Coordinate so there is one
trait change, owned by the hickory PR if convenient; otherwise Phase 3 adds a
thin method on top. Do **not** make competing edits to `dns.rs` resolver
internals from the Phase 3 branch.

## The Phase 3 work (three parts)

### 3a. Resolve-and-pin (the core SSRF/rebind fix)
For **enforcing** sandboxes, stop trusting guest-influenced IPs; izbad resolves
allow-listed names itself at dial time and pins the dial to *its* result.

- **Tier 1 (MITM upstream).** After the Phase-2 `Service` has the request `Host`,
  is `SNI == Host`, and policy = Allow: izbad calls `resolve(Host)` and dials the
  upstream at *its own* resolved IP — **ignoring the guest's `OrigDst.ip`**. This
  is also the "pin upstream to the policy-approved name's resolved address, not
  guest `OrigDst`" half of **F-02**. (Phase 2 ships with the upstream dialing
  `OrigDst.ip` but verifying the upstream cert against `Host` via webpki — already
  strong; Phase 3 upgrades the *dial target*.)
- **Tier 2 (non-HTTP TCP).** In `decide_tier2`, replace "trust the snoop map" with
  "izbad re-resolves": for each snooped/allow-listed candidate name, call
  `resolve(name)` *fresh* and allow only if the guest's dial IP is in that fresh
  result set (and passes the unconditional `is_private` denylist from Phase 1).
  This defeats stale/low-TTL rebind. Snoop becomes observability, **not**
  authorization.

### 3b. DNS rate-limit
Per-sandbox token-bucket on `:53` (both the `StreamOpen::Dns` loop and the
`port == 53` TCP short-circuit), independent of resolver impl. Caps the
QNAME-exfil channel. Lives in `router.rs` / `dns_loop`.

### 3c. QNAME policy-gate (enforcing only)
Parse the QNAME (hickory-proto is already a dep; reuse `dns_snoop`'s decode),
run `policy.check(FlowDesc{ host: Some(qname), .. })`; on Deny answer
`REFUSED`/`NXDOMAIN` instead of forwarding. Bare sandboxes keep unconditional
forward.

## Files Phase 3 will touch
- `crates/izba-core/src/daemon/egress/dns.rs` — **only** the trait `resolve()`
  method (coordinate with hickory PR; no impl-internals edits otherwise).
- `crates/izba-core/src/daemon/egress/router.rs` — `decide_tier2` re-resolve;
  `dns_loop` rate-limit + QNAME gate; tier-1 upstream pin hand-off to Phase-2
  `Service`.
- `crates/izba-core/src/daemon/egress/dns_snoop.rs` — demote snoop to
  observability (drop its authorization role in tier-2).
- `crates/izba-core/src/daemon/egress/policy.rs` — possibly a `rate_limit`
  knob on the policy/config if limits are policy-driven.

## Test plan (TDD)
- **Rebind PoC:** snoop says `allowed → attackerIP`; izbad re-resolves `allowed`
  to its real IP and **refuses** the attacker IP on a non-HTTP port.
- **Pin PoC (tier-1):** guest sets `OrigDst.ip` = attacker IP, `Host` = allowed;
  izbad dials its *own* resolved IP for `Host`, not the guest's.
- **Rate-limit:** a tight query loop trips the per-sandbox bucket.
- **QNAME gate:** a denied name returns `REFUSED`; an allowed name forwards.
- All six green-before-commit gates incl. `x86_64-pc-windows-gnu` cross.

## Sequencing
1. Land Phases 1 + 2 (DNS-independent).
2. Wait for the hickory-resolver adoption to merge (carry the typed `resolve()`).
3. Branch Phase 3 off the merged main; implement 3a/3b/3c on top of hickory.
