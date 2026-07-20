# Bare-host targets open the web ports [80, 443] everywhere — design

**Date:** 2026-07-20
**Status:** approved (owner decision: "let's make bare host be ports [80, 443], make sure it's consistent and documented")
**Origin:** dogfood finding F1b on PR #146 (egress-wildcards campaign): the swarm
followed the README's enforce example with a bare `izba policy allow NAME
archive.ubuntu.com`, got only :443, and apt (HTTP :80) stayed blocked.

## Problem

"Bare host ⇒ web ports 80 + 443" is the documented `policy.yaml` semantic
(`AllowEntry::DEFAULT_PORTS`, README "A bare host authorizes ports 80 and 443"),
and the GUI's `AllowEntry` normalize follows it (`WEB_DEFAULT_PORTS`). But two
surfaces diverge to **443 only**:

1. CLI `izba policy allow|block NAME HOST` (`parse_target` defaults the port to
   `443`), and
2. the GUI PolicyEditor's **Add host** button (new row starts as `ports: [443]`).

Same words, different meaning per surface — a real foot-gun (two dogfood swarm
rounds tripped on it).

## Decision

One rule, all surfaces: **a bare host target means the web ports `[80, 443]`.
An explicit `HOST:PORT` means exactly that one port.** No new syntax; no
policy-evaluation change (the Rego/data-doc semantics already treat a bare YAML
host as `[80, 443]` — this aligns the *editing* surfaces with it).

### CLI (`izba policy allow|block NAME TARGET`)

- `parse_target` returns `(String, Vec<u16>)`: no `:PORT` →
  `AllowEntry::DEFAULT_PORTS.to_vec()`; `HOST:PORT` → `vec![port]`.
  (Wildcard patterns `*.x`/`**.x` are hosts like any other here.)
- `apply_edit` takes `ports: &[u16]` and applies the existing per-port
  `EgressPolicyConfig::allow/block` mutators in order; "changed" = any port
  changed. Persisted form stays `Scoped` (unchanged normalization).
- Symmetry: bare `block HOST` removes ports 80 **and** 443 from the entry;
  ports added explicitly (e.g. `:8443`) survive; the entry is dropped when its
  last port goes (existing `block` behavior, unchanged).
- Help text: the four "port defaults to 443" doc-comments become "a bare HOST
  means the web ports 80+443; HOST:PORT means exactly that port".

### GUI (PolicyEditor)

- **Add host** seeds the new row with `[...WEB_DEFAULT_PORTS]` (80, 443)
  instead of `[443]`. Port chips remain freely editable. No IPC/type change.

### Docs

- README command table (`policy allow`/`policy block` lines) + the egress
  section's enforce walk-through: the apt example becomes the bare
  `izba policy allow NAME archive.ubuntu.com` (+ security.ubuntu.com) again,
  with the sentence explaining bare = 80 + 443 and `:PORT` = exactly that port.
  (This supersedes the F1 hotfix text, which documented the old 443-only
  default.)

## Compatibility

- No wire change (policy.yaml is host-side; `ReloadPolicy` payload unchanged;
  no `DAEMON_PROTO_VERSION` bump; app IPC types unchanged).
- Behavior change is **CLI/GUI editing only** and strictly *widens* what a bare
  `allow` grants (80 in addition to 443) — matching what the same words already
  do in `policy.yaml`. `block HOST` widens symmetrically (removes both web
  ports). Scripts that relied on bare `allow HOST` granting only 443 must spell
  `HOST:443`.

## Testing (TDD)

1. `parse_target`: bare → `[80, 443]`; `HOST:8080` → `[8080]`; invalid port
   still errors (existing case).
2. `apply_edit` round-trip: bare allow writes Scoped `[80, 443]`; bare block on
   a `[80, 443, 8443]` entry leaves `[8443]`; bare block on a pure web entry
   removes it; `HOST:PORT` allow/block still single-port (existing cases
   updated).
3. Wildcard target keeps working through the new signature
   (`*.example.com` → `[80, 443]`).
4. GUI vitest: clicking **Add host** yields a row showing port chips 80 and
   443; saving persists both (existing save-path tests updated).
5. README asserts nothing testable; reviewed by eye.
