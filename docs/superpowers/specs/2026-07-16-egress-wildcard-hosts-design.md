# Wildcard host support for egress policies — design

**Date:** 2026-07-16
**Status:** approved for implementation
**Owner ask:** "allow `*.mydomain.com` in egress policies"

## Problem

Egress policy `allow` entries match HTTP hosts / SNI by **exact Rego map-key
lookup** (`data.host_rules[dest_name]`, `egress.rego`). A `*.mydomain.com`
entry parses fine today (`config.rs` accepts any string, documented as a
"planned extension") but **silently never matches anything** — a security/UX
foot-gun. A Cilium-style wildcard matcher (`dns_snoop::allowlist_matches`)
exists but is dead code with zero production callers.

Related foot-gun: request-side hosts are lowercased and trailing-dot-stripped
(`mitm.rs::normalize_host`, `dns_snoop::normalize`), but policy-side host keys
are emitted **verbatim** — a mixed-case host in `policy.yaml` never matches.

## Goals

1. `allow: ["*.mydomain.com"]` (and scoped `{host: "*.mydomain.com", ports,
   access}`) actually matches, on **both** enforcement tiers:
   - tier-1 MITM (decrypted Host / SNI), and
   - tier-2 DNS-snoop → TcpConnect-by-IP.
2. One canonical matcher; kill the dead second implementation.
3. Malformed patterns fail **loudly** at parse/load, never silently no-op.
4. Policy-side host normalization parity (lowercase, strip trailing dot).

## Non-goals

- Wildcards in **git rules** (`git: [{host: ...}]` stays exact; repo globs
  already exist via `glob.match(rule.repo, ["/"], ...)`).
- Domain-level DNS query gating (there is none today; enforcement stays at
  connect time — unchanged).
- Public-suffix / registrable-domain awareness (`*.com` is syntactically
  valid; the human review gate in `izba promote` + the weakens-egress flag is
  the guard, same as an over-broad exact host).

## Wildcard semantics (Cilium `toFQDNs`, as already documented)

Matches `docs/egress-firewall-building-blocks.md` §DNS-snoop and the dead
`allowlist_matches` implementation:

| Pattern | Matches | Does NOT match |
| --- | --- | --- |
| `api.example.com` (exact) | `api.example.com` | anything else |
| `*.example.com` | `api.example.com` (exactly ONE extra label) | `example.com` (apex), `a.b.example.com` |
| `**.example.com` | `a.example.com`, `a.b.example.com` (any depth ≥ 1) | `example.com` (apex) |

The apex never matches a wildcard — list it explicitly alongside
(`["example.com", "*.example.com"]`). Ports/access semantics are unchanged:
a bare wildcard string gets the web defaults `[80, 443]`, scoped entries
carry their own `ports`/`access`.

## Design

### 1. Data doc: split exact vs wildcard at compile time

`EgressPolicyConfig::to_rego_data_json` (config.rs) keeps exact hosts in the
existing `host_rules` / `sandbox_host_rules` **maps** (O(1) lookup, shape
unchanged — a pre-change daemon artifact stays compatible) and routes entries
whose host starts with `*.` or `**.` into new **lists**:

```json
{
  "wildcard_host_rules":        [ {"pattern": "*.mydomain.com", "ports": [80,443], "access": "read-write"} ],
  "sandbox_wildcard_host_rules": { "<sandbox>": [ {"pattern": "...", "ports": [...], "access": "..."} ] }
}
```

All host keys and patterns are normalized at emit time: ASCII-lowercased +
trailing dot stripped. (This fixes the mixed-case exact-host foot-gun as a
side effect.) The embedded default data doc (`policy.rs`) gains the new keys
as empty containers; a data doc missing them is still valid Rego (iteration
over undefined is simply unsatisfied).

### 2. Matcher: Rego `glob.match` with `.` delimiter

`egress.rego` gains two allow rules mirroring the exact-host pair:

```rego
allow if {
    some rule in data.wildcard_host_rules
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}
allow if {
    some rule in data.sandbox_wildcard_host_rules[input.sandbox]
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}
```

With `.` as the delimiter, glob `*` = exactly one label and `**` = any depth,
which is precisely the Cilium semantics above (apex can't match: the literal
`.` after the wildcard has nothing to consume). regorus's `glob.match` is
already exercised in production for git repo globs. **Verification-first:**
the first implementation task pins regorus's `*`/`**`-with-`["."]` behavior
in unit tests; if regorus deviates, fall back to an equivalent pure-Rego
helper (`endswith` + label count) behind the same rule shape — the data doc
and Rust surface don't change either way.

Tier-1 (`mitm_runtime.rs` PolicyAdapter) and tier-2 (`router.rs::decide_tier2`
iterating snooped FQDNs) both call `RegoPolicy::check`, so **both tiers get
wildcard support with zero Rust datapath changes**. The SNI==Host binding
(F-02) is untouched. Audit/netlog rule labels (`allow-list` /
`not in allow-list`) apply as-is to wildcard matches.

### 3. Dead code removal

Delete `dns_snoop::allowlist_matches` + its unit test; port every case from
that test (one-label, deep, apex, case, trailing dot) into `policy.rs` Rego
tests so the canonical matcher provably preserves the semantics.

### 4. Loud validation (host *patterns*)

New shared validation applied wherever an allow-entry host is accepted
(`config.rs` — used by policy.yaml load, `ReloadPolicy`, manifest
`spec.egress`, and the daemon-side write paths the CLI/GUI call):

- Accepted: no `*` at all (exact host), or a leading `*.` / `**.` whose
  remainder is non-empty and contains no `*`.
- Rejected with an actionable error (entry text + reason + accepted forms):
  any other `*` placement — `foo.*.com`, `*foo.com`, bare `*`, `**`, `*.`,
  `**.`.

Compatibility note: `*.x`/`**.x` entries written under M2 were accepted and
now become **enforced** (they start allowing traffic — that is the feature).
Previously-accepted junk like `foo.*.com` now fails loudly at load; per the
"loud on security degradation" convention this beats the current silent
no-op. `izba policy allow` (`parse_target`) keeps its `host[:port]` split;
patterns flow through the same config-layer validation before the file is
written.

### 5. Surface updates

- **CLI:** `izba policy allow '*.mydomain.com'` works; `--help` for
  `policy allow` and `izba policy show` mention wildcard forms.
- **README** egress section: document the three pattern forms + apex rule.
- **`config.rs` module doc:** drop the "planned extension" caveat.
- **`docs/egress-firewall-building-blocks.md`:** mark the snoop-matcher plan
  as shipped-via-Rego.
- **GUI (`app/`):** `PolicyEditor` already takes free-text hosts; update
  placeholder/help to advertise `*.`/`**.` and mirror the pattern validation
  client-side (reject-before-save with the same rule). No IPC/type changes
  (`AllowEntry` shape is unchanged), but the app gate runs anyway since
  izba-core internals move.

## Testing

TDD throughout (tests first, then implementation):

1. **Rego/policy unit tests** (`policy.rs`): wildcard one-label allow, deep
   label deny for `*.`, deep allow for `**.`, apex deny for both, port +
   access interaction on wildcard rules, per-sandbox wildcard isolation,
   mixed exact+wildcard lists, case/trailing-dot normalization (policy side
   and request side), and the regorus `glob.match` semantics pin.
2. **Config unit tests** (`config.rs`): data-doc shape (exact vs wildcard
   split, normalization), validation accept/reject matrix, YAML + manifest
   `spec.egress` round-trips.
3. **CLI tests**: `policy allow` with a wildcard target; loud failure on a
   malformed pattern (file left unchanged).
4. **e2e** (`egress_mitm.rs`, KVM-gated): wildcard host allowed + non-matching
   host denied through the real MITM path.
5. **GUI** (`app/src/test/policyEditor.test.tsx`): wildcard entry accepted,
   malformed rejected with message.

## Risks

- **regorus glob semantics deviate from gobwas/OPA** → pinned by test task
  #1 before anything builds on it; pure-Rego fallback specified above.
- **Existing policies with malformed `*` entries fail on next load** →
  intentional (loud > silent); error text names the exact entry and fix.
- **Wildcard breadth** (`*.com`) → same trust model as an over-broad exact
  host; `izba promote` review + weakens-egress flagging already gate
  manifest-driven changes.
