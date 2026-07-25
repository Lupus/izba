# Policy-aware DNS egress enforcement (#148)

> **Status:** design approved 2026-07-24. Implements backlog issue
> [#148](https://github.com/Lupus/izba/issues/148) (type:security, P1).
> Scope: the egress router's DNS decision paths + netlog. No wire-protocol,
> manifest, or `DAEMON_PROTO_VERSION` change; no app-gate impact.

## Problem

A sandbox created with `enforce: true` is expected to have controlled egress.
Today it does *not* for DNS. All three DNS entry points into izbad's egress
router —

- `StreamOpen::Dns` (UDP-origin),
- `StreamOpen::DnsTcp` (TCP-origin), and
- `StreamOpen::TcpConnect{port: 53}` (a guest dialing an upstream resolver, which
  izbad answers as the resolver) —

funnel into `router.rs::dns_loop`, which forwards **every** query to the host
resolver unconditionally, before any policy evaluation. DNS-snoop observes the
answers but is monitor-only by design (F-05 / threat model §8), not a control.

The result: a hostile agent inside an *enforcing* sandbox has a wide-open
channel. Data exfiltrates in the QNAME itself (`<base32-secret>.evil.com`), and
DNS-tunnel C2 works over any qtype (TXT is the classic vector). This contradicts
izba's core promise as a security sandbox for untrusted agents and the user's
reasonable mental model of what `enforce: true` means.

**Evidence:** `crates/izba-core/src/daemon/egress/router.rs:75-81` (the
`TcpConnect:53` short-circuit), `router.rs:44-45` + `dns_loop` at
`router.rs:395-416` (the `Dns`/`DnsTcp` pass-through), `router.rs:412` (snoop is
observation only).

## Goal

An enforcing sandbox may resolve only names its policy could authorize. Every
other QNAME is denied — the query is **never sent upstream**, the guest gets a
deterministic `NXDOMAIN`, and a netlog entry records the denial. Non-enforcing
(bare) sandboxes keep today's pass-through behavior exactly.

## Non-goals (out of scope)

- Changing the default (non-enforcing) posture.
- DNSSEC.
- DNS-over-HTTPS / DNS-over-TLS interception. (DoT to an arbitrary resolver on
  `:853` is already denied under enforce: it is a raw-IP tier-2 dial with no
  snoop record.)
- Redesigning the DNS forwarder transport (the hardcoded external-UDP-resolver
  reply path; tracked separately as roadmap risk #3).
- General rate-limiting infrastructure beyond this enforcement path.
- GUI netlog rendering of DNS denials (tracked as #161).

## Design

### 1. The decision point — `dns_loop` (router.rs)

`dns_loop` is the single chokepoint all three DNS variants already pass through,
so the gate lives there and covers `Dns`, `DnsTcp`, and `TcpConnect:53`
uniformly. `handle_conn` already holds `policy: Arc<dyn Policy>` and
`audit: &AuditSink`; thread both into `dns_loop` (it already has `sandbox` and
`snoop`).

Per query, before forwarding:

```text
if policy.enforces() {
    match qname_of(&query) {
        // allowed name: fall through to the existing forward + snoop path
        Some(name) if policy.allows_name(sandbox, &name) => forward,
        // policy deny: do NOT call the resolver; answer NXDOMAIN, log, next query
        Some(name) => { audit.deny(.., name, "DNS: not in allow-list");
                        write nxdomain(&query); continue }
        // fail-closed: an unparseable query under enforce is not forwarded
        // (host = None in the record; see §5)
        None => { audit.deny(.., None, "DNS: unparseable query (enforcing)");
                  write servfail(&query); continue }
    }
} else {
    forward   // bare sandbox: unchanged M1 behavior
}
```

Key properties:

- A denied query **never reaches the resolver** — no upstream lookup, so QNAME
  data never leaves the host.
- An allowed query flows exactly as today, **including** the existing
  `snoop.record(...)` step — tier-2 IP→FQDN attribution is not regressed.
- The decision is on the QNAME regardless of qtype, so `TXT`/`MX`/`SRV` exfil to
  an unlisted name is denied along with `A`/`AAAA`.
- The loop's existing teardown discipline (shutdown-write + drain-to-EOF, the M0
  vsock-churn contract) is unchanged.

### 2. `allows_name` — port-agnostic authorization

The Rego `allow` rule requires a `host` **and** `port` **and** `access` match.
A DNS query carries none of port/access, so `check()` cannot be reused directly.
Instead add a dedicated, port/access-agnostic decision:

- `Policy` trait gains:

  ```rust
  /// Port/access-agnostic: may this QNAME be resolved at all under an
  /// enforcing policy? Only consulted when `enforces()` is true. Default
  /// permissive so a non-enforcing / future policy never blocks DNS by accident.
  fn allows_name(&self, _sandbox: &str, _name: &str) -> bool { true }
  ```

- `RegoPolicy` overrides it to evaluate a new `data.egress.resolvable` boolean
  query with input `{ "sandbox": sandbox, "host": name }`. Any engine error is a
  fail-closed `false` (mirrors `check`'s fail-closed posture).

- `AllowAll` uses the default `true` (never actually reached under non-enforce,
  but a sane default).

New rules appended to `egress.rego`:

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
    glob.match(split(rule.repo, "/")[0], ["/"], input.host)
}
```

> **Implementation note (git-repo host segment):** the git-repo branch matches
> the repo pattern's *host segment* (`split(rule.repo, "/")[0]`) with the same
> `/`-delimited `glob.match` that `allow`'s `git_rule_matches` applies to the
> whole repo id — not a literal `startswith(rule.repo, "<host>/")`. A literal
> prefix would wrongly deny a host-wildcarded repo rule such as
> `*.github.com/org/app` (which `allow` *does* permit), so glob-matching the host
> segment keeps `resolvable` consistent with `allow`. (Verified by
> `allows_name_git_repo_host_wildcard_matches_allow_predicate`.)

This reuses the exact host-matching predicates of `allow` (exact host,
per-sandbox scoping, `*`/`**` wildcard glob) — no logic is duplicated in Rust,
so there is no drift risk (the reason approaches B "probe with a fixed port" and
C "reimplement matching in Rust" were rejected).

**Why over-approximation is the safe direction.** `resolvable` intentionally
answers "could this host match *any* rule", not "is a connection to it allowed
right now". That means a name reachable on some port always resolves (never
breaks a legitimate flow), while the real port/method/access gate still runs at
connect time. A hostile QNAME (`<secret>.evil.com`) resolves only if `evil.com`
or `*.evil.com` is itself listed — which it is not, by definition — so exfil is
still denied. The git-host glob check is likewise a coarse over-approximation
over hosts that are already legitimately listed.

### 3. QNAME extraction — `qname_of`

Add `qname_of(msg: &[u8]) -> Option<String>` in `dns_snoop.rs` (which already
depends on `hickory-proto` for `extract_a_aaaa`): parse the message, and if it
contains **exactly one** question, lowercase that question's name and trim the
trailing dot. `None` on a parse failure, a root (`.`) query, or a query that
does not have exactly one question → the fail-closed deny path.

Requiring a single question closes the multi-question smuggling channel: a
`QDCOUNT != 1` message has no single QNAME to authorize, and forwarding one whose
first question is allow-listed would let a second, exfil-bearing question ride
along in the same UDP datagram to the upstream resolver. Under enforce such a
message is denied, never forwarded (non-enforcing sandboxes keep pass-through).

### 4. Denial synthesis — `nxdomain`

Add `nxdomain(query: &[u8]) -> Vec<u8>` to `izba-proto/src/dns.rs`, a sibling to
the existing `servfail`: same in-place byte flip — `QR=1`, `RA=1`, `RCODE=3`
(NXDOMAIN) — preserving the ID and question section so the guest resolver can
match the response.

`servfail` is left **byte-for-byte untouched** so its pinned
mutation-testing exclusion (`.cargo/mutants.toml`, drift-checked by
`hack/mutants-check-excludes.py`) stays valid. `nxdomain` gets its own tests.

**Why NXDOMAIN** (decided over REFUSED): it is terminal for clients (they stop
rather than fail over to another configured server), is negatively cacheable,
and presents as the same "no such host" the guest would hit on the connection
anyway — it does not confirm to the agent *which* names are policy-blocked vs
genuinely nonexistent. The honest "why" lives in the host-side netlog.

### 5. Netlog

A denied query is recorded via the existing `AuditSink`:

```rust
AuditRecord::deny(sandbox, "0.0.0.0".parse().unwrap(), 53,
                  Some(&qname), Tier::L3, "DNS: not in allow-list")
```

- Reuses `Tier::L3` (decided over a new `Tier::Dns`): zero new types, no app-gate
  impact (a new tier would ripple into the app's TS `Tier` mirror + GUI netlog
  rendering, which is the separately-tracked #161).
- `dest_ip` is a `0.0.0.0` sentinel (the field is a required `IpAddr`; a DNS
  decision has no dest IP). It never surfaces — `aggregate` keys on `host` when
  present and `format_record` renders `host` (`evil.com:53`), so the sentinel is
  invisible in both the summary and the per-line view.
- Only **denials** are logged. Allowed resolutions are already captured by
  DNS-snoop; logging every allowed query would be per-lookup noise.
- The unparseable-query deny uses `rule = "DNS: unparseable query (enforcing)"`
  with `host = None`.

### 6. Blast radius

| File | Change |
| --- | --- |
| `crates/izba-core/src/daemon/egress/router.rs` | gate in `dns_loop`; thread `policy` + `audit` through its 3 call sites |
| `crates/izba-core/src/daemon/egress/policy.rs` | `Policy::allows_name` (trait default + `RegoPolicy` override) |
| `crates/izba-core/src/daemon/egress/egress.rego` | `resolvable` rules |
| `crates/izba-core/src/daemon/egress/dns_snoop.rs` | `qname_of` helper |
| `crates/izba-proto/src/dns.rs` | `nxdomain` helper |

No change to `StreamOpen`, `DaemonRequest`, the manifest, or the daemon proto
version.

## Testing

TDD, tests first. The four-quadrant matrix from the issue's acceptance criteria,
plus edges:

**Router (`dns_loop`):**
- enforcing + **allowed** QNAME → query is forwarded (resolver called), answer
  returned, and the answer is snooped (tier-2 dependency intact).
- enforcing + **denied** QNAME → response is `NXDOMAIN`, a deny netlog record is
  written, and the resolver is **not** called (a counting/panicking fake
  resolver proves the upstream lookup never happens).
- non-enforcing + any QNAME → forwarded unchanged (resolver called), no deny.
- `DnsTcp` and `TcpConnect:53` under enforce → identical denial treatment to
  `Dns` (parametrize the three variants).
- unparseable query under enforce → `SERVFAIL`, deny logged, resolver not called.

**Policy (`allows_name` on `RegoPolicy`, pure in-memory):**
- exact `host_rules` / `sandbox_host_rules` host → resolvable.
- `*`/`**` wildcard host (global + per-sandbox) → resolvable per glob semantics;
  apex and lookalike suffixes not resolvable.
- git-rule host (`host:` scope and `repo:` prefix) → resolvable.
- unlisted name → not resolvable.
- per-sandbox isolation: a name listed only for `build` is not resolvable for
  `web`.
- port-agnostic proof: a host scoped to a single non-web port (e.g. `5432`) is
  still resolvable (the exact bug approach B would have caused).

**Proto (`nxdomain`):**
- sets `QR`/`RA`/`RCODE=3`, preserves ID + QDCOUNT, length preserved; runt input
  does not panic (mirrors the `servfail` unit + proptest coverage).

## Acceptance criteria (from #148)

- [x] Enforcing + QNAME not covered by policy → denied with deterministic rcode
  (NXDOMAIN) + netlog entry.
- [x] Enforcing + QNAME allowed by policy → resolves as today (no regression).
- [x] Non-enforcing → DNS behavior unchanged.
- [x] `DnsTcp` / `TcpConnect:53` get the same enforcement as UDP `Dns`.
- [x] DNS-snoop IP→FQDN attribution still works for allowed queries.
- [x] Regression tests cover all four quadrants.
