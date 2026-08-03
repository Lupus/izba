# Manifest diff: compile-faithful allow-list fold (#172)

**Status:** approved design for issue #172 (type:security).
**Scope:** `crates/izba-core/src/manifest/diff.rs` (+ one visibility widening in
`daemon/egress/config.rs`). No wire changes, no `DAEMON_PROTO_VERSION` bump.

## Problem

`manifest/diff.rs::allow_index` builds the `(normalized host, port) → Access`
view that backs the `⚠ weakens egress` review flag. It folds duplicate cells to
**max-access** for every entry kind. But `to_rego_data_json` compiles the two
entry kinds differently:

- **Exact hosts** land in `sandbox_host_rules`, a JSON **map** keyed by
  normalized host — a later normalize-equal entry's whole `{ports, access}`
  object **overwrites** the earlier one (last-wins, whole-entry).
- **Wildcard hosts** land in `sandbox_wildcard_host_rules`, a **list** — every
  rule grants independently (union), so effective access per (pattern, port)
  is the max across entries.

For exact hosts the max-fold **overstates** the diff's "from" side relative to
enforcement, and `manifest/apply.rs::write_policy` persists the proposal's
allow-list **verbatim**, so `izba promote` can plant normalize-equal duplicates
into managed truth. Combined two-promote attack (neither step flagged):

1. Managed `[host rw 443]`. Propose `[host rw 443, host read 443]` — to-fold =
   max = rw = from-fold → unflagged; **compiled enforcement silently drops to
   read** (last entry wins).
2. Later propose `[host rw 443]` — from-fold = max = rw → unflagged;
   **enforcement widens read → rw** with no `⚠` on the load-bearing review
   gate.

The same divergence has a per-port variant: managed `[host{443} read,
host{8080} rw]` enforces only 8080/rw, but the index reports both cells, so a
proposal re-adding 443 looks like a no-op while actually (re-)opening it.

## Decision: compile-faithful `allow_index` (design (a))

Fold each side of the diff exactly like compilation does:

- **Exact host entry:** first drop every existing index cell for that
  normalized host, then insert `(host, p) → access` for its ports — mirroring
  the JSON-map whole-object overwrite.
- **Wildcard entry:** keep the current max-access accumulation per
  (pattern, port) — that already equals union-of-grants semantics.

`egress_weakens` itself is unchanged: with both sides folded compile-faithfully,
its "new (host, port) or read→rw widen" check becomes precisely "does compiled
enforcement widen".

### Why not (b) canonicalize-on-promote

Routing `write_policy` through a `replace_allow`-style collapse would stop
managed truth from carrying duplicates, but it makes promote persist a
*transformed* allow-list — what the human reviewed in `izba.yml` would no
longer be byte-wise what lands in `policy.yaml`, reopening the TOCTOU-adjacent
display concern the issue itself raises (the review token covers the exact
`izba.yml` shown at diff time). Design (a) alone satisfies every acceptance
criterion while keeping the verbatim-persist story: because the fold is
compile-faithful, what the diff showed as effective **is** what enforcement
becomes after the verbatim persist. Adding (b) on top is hygiene, not a
security requirement — YAGNI.

### Acceptance criteria mapping

- Two-promote scenario: step 2's from-side now folds to the *enforced* read,
  so read→rw is flagged `⚠ weakens egress`. Step 1 remains unflagged, and
  honestly so — it is a narrowing, and the diff now *shows* the narrowing.
- From-side never overstated for exact hosts: last-wins fold ≡ compile.
- Wildcard union: unchanged max-fold ≡ union-of-grants.
- TOCTOU: promote still persists the reviewed allow-list verbatim; diff-shown
  effective semantics equal post-promote enforcement.

## Implementation notes

- `is_wildcard_host` in `config.rs` widens to `pub(crate)` (like
  `normalize_policy_host` did in #170) so `manifest::diff` classifies entries
  identically to compilation. Exact-host cell removal (`m.retain`) cannot
  collide with wildcard cells: wildcard keys always start with `*.`/`**.`,
  which `normalize_policy_host` never produces from an exact host.
- The existing pin `normalize_equal_duplicates_fold_max_access` uses
  `[read first, rw last]` — it still passes under last-wins (the last entry IS
  the max) but no longer discriminates the two folds. Replace it with a
  last-wins pin whose orders differ: `[rw first, read last]` folds to read, so
  a later `[rw]` proposal must be flagged.
- Stale comments describing the max-fold (allow_index doc, the "Fix 1"
  duplicate-host test docs) must be rewritten to describe compile-faithful
  semantics; the Fix-1 *tests* still pass (widening the last entry is still a
  widen) and stay.
- `apply.rs` is untouched: `plan()`'s raw struct compare and `write_policy`'s
  verbatim persist are load-bearing (#170 adjudication: a respelling-only
  change keeps an unflagged delta row because promote genuinely rewrites the
  managed `policy.yaml`).

## Tests (new pins)

1. Two-promote scenario end-to-end at the diff layer: step 1 unflagged,
   step 2 flagged.
2. Exact-host last-wins discriminator: from `[host rw 443, host read 443]`
   (dup, last = read) to `[host rw 443]` ⇒ flagged.
3. Per-port variant: from `[host{443} read, host{8080} rw]` (only 8080/rw
   enforced), to `[host{443} read]` ⇒ flagged (443 is effectively NEW).
4. Wildcard union preserved: from `[*.x read 443, *.x rw 443]` to
   `[*.x rw 443]` ⇒ not flagged (union already granted rw); adding a
   read-duplicate to an rw wildcard ⇒ not flagged.
