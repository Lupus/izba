# Policy host normalized keying everywhere (issues #170 + #171)

**Goal:** close the two remaining code paths that compare or persist egress
policy hosts by RAW string, diverging from the `normalize_policy_host`
identity (trim + trailing-dot strip + ASCII-lowercase) that compilation and
the PR #169 mutation methods enforce:

1. `crates/izba-core/src/manifest/diff.rs::allow_index` keys its
   `(host, port) -> Access` map on `e.host().to_string()` — respelling-only
   manifest changes produce spurious deltas and false `⚠ weakens egress`
   flags (#170).
2. The GUI daemon adapter's `policy_set` / `policy_set_full`
   (`app/src-tauri/src/daemon.rs`, mirrored in `app/src-tauri/src/fake.rs`)
   assign `cfg.allow = allow` wholesale, bypassing normalization/collapse —
   normalize-equal duplicates written by the GUI silently drop rules at
   compile time (exact hosts land in a last-wins JSON map) (#171).

**Approach:** one new core-owned API + one visibility widening, then use them
at both sites. No wire changes, no `DAEMON_PROTO_VERSION` bump, no change to
`to_rego_data_json` compile semantics.

## Global Constraints

- **Compile-semantics contract (do not alter):** exact hosts compile into
  `sandbox_host_rules` (JSON map, later normalize-equal key OVERWRITES —
  last-wins); wildcard patterns (`is_wildcard_host`) compile into
  `sandbox_wildcard_host_rules` (list — every rule grants independently,
  UNION). Any collapse must be last-wins for exact hosts and
  union-preserving for wildcards: uniform-access wildcard duplicates merge
  into one entry with the union of ports; mixed-access wildcard duplicates
  stay separate entries.
- **No silent widening (#147 lineage):** nothing in this plan may widen an
  access verb as a side effect.
- `to_rego_data_json`, YAML parsing, and existing public method signatures
  in `config.rs` stay unchanged. `DAEMON_PROTO_VERSION` is not bumped.
- Unit tests never bind unix/vsock listeners.
- TDD: write the failing test first, then the fix, in the same commit.
- Conventional commits; body includes `Refs #170` and/or `Refs #171`.
- Gates for every task (run from the worktree root, with the main
  checkout's toolchain env:
  `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH`):
  `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`;
  `cargo fmt --check`;
  `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`;
  `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`;
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
  Task 3 additionally runs the app gate:
  `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.

## Task 1 — core: `replace_allow` API + `pub(crate) normalize_policy_host`

**Files:** `crates/izba-core/src/daemon/egress/config.rs`

1. Widen `fn normalize_policy_host(host: &str) -> String` (currently
   private, ~line 691) to `pub(crate)` so `manifest::diff` can use the same
   identity function. Doc-comment why it is crate-visible (diff keying must
   match mutation/compile identity; not `pub` — external callers go through
   the mutation methods).
2. Add to `impl EgressPolicyConfig`:
   `pub fn replace_allow(&mut self, allow: Vec<AllowEntry>)` — the
   wholesale-set entry point for callers that hold a full replacement list
   (the GUI policy editor). Behavior:
   - assign `self.allow = allow`;
   - canonicalize every entry's host spelling in place via
     `normalize_policy_host` (both `AllowEntry::Host` and
     `AllowEntry::Scoped`);
   - run `collapse_duplicate_hosts()` (existing private helper) so
     normalize-equal duplicates collapse per the Global Constraints
     contract before anything is persisted.
   Doc-comment must state the contract: persisted list is canonical-spelled
   and duplicate-free for exact hosts (last-wins), wildcard union
   semantics preserved (uniform-access merge as ports-union, mixed-access
   kept separate).
3. Tests (TDD, module `tests` in config.rs, following existing test style):
   - `replace_allow_canonicalizes_spelling`: entries `"API.Example.com."`
     (Scoped, ports [443], Read) → persisted host `"api.example.com"`.
   - `replace_allow_exact_duplicates_last_wins`: `"Host.com"` Scoped
     {ports:[443], ReadWrite} then `"host.com."` Scoped {ports:[8080],
     Read} → ONE entry, host `"host.com"`, ports `[8080]`, access Read
     (last entry's payload, first entry's position).
   - `replace_allow_wildcard_uniform_merges_ports_union`: `"*.x"` Read
     ports [443] + `"*.X"` Read ports [8443] → one entry `"*.x"` Read
     ports [443, 8443].
   - `replace_allow_wildcard_mixed_access_stays_separate`: `"*.x"`
     ReadWrite ports [443] + `"*.X"` Read ports [8443] → two entries
     remain, both spellings canonicalized to `"*.x"`, each keeping its own
     ports+access.
   - `replace_allow_is_idempotent`: calling `replace_allow` with the
     result of a previous `replace_allow` leaves `allow` unchanged.

**Commit:** `feat(core): add EgressPolicyConfig::replace_allow with canonical host collapse` (body `Refs #171`).

## Task 2 — core: normalized keying in `manifest/diff.rs`

**Files:** `crates/izba-core/src/manifest/diff.rs`

1. In `allow_index` (~line 97): key the map on
   `normalize_policy_host(e.host())` instead of `e.host().to_string()`
   (import `normalize_policy_host` from `crate::daemon::egress::config`).
   Max-access folding then groups normalize-equal hosts automatically.
2. Survey the REST of diff.rs for any other place that compares host
   strings raw between two `EgressPolicyConfig`s (e.g. rendering of
   added/removed allow entries, if host-keyed) and key those comparisons on
   normalized identity too. Human-facing OUTPUT keeps whatever spelling the
   source config carries — normalization here is identity-for-comparison
   only, never display rewriting.
3. Tests (TDD, in diff.rs's existing test module, using its existing
   fixture/builder style):
   - respelling-only change (`"api.example.com"` → `"API.example.com."`,
     same ports/access, both sides enforcing) → `egress_weakens` returns
     false, and the computed egress delta is empty / not flagged
     `⚠ weakens egress`.
   - raw normalize-equal duplicates fold max-access: from-side entries
     `"Host.com"` Read [443] + `"host.com"` ReadWrite [443] vs to-side
     `"host.com"` ReadWrite [443] → NOT weakening (from side already
     read-write under max-access fold).
   - genuine widen across spellings still flagged: from `"Host.com"` Read
     [443] → to `"host.com"` ReadWrite [443] ⇒ `egress_weakens` true.
   - new-host detection across spellings: to-side adds `"HOST.com"` [8080]
     when from-side has `"host.com"` [443] only ⇒ weakening (new port),
     but to-side `"HOST.com"` [443] with same access ⇒ not weakening.

**Commit:** `fix(core): key manifest-diff host comparisons on normalized policy-host identity` (body `Refs #170`).

## Task 3 — app: route GUI wholesale-set paths through `replace_allow`

**Files:** `app/src-tauri/src/daemon.rs`, `app/src-tauri/src/fake.rs`
(app workspace is OUT of the root workspace — separate gate, see Global
Constraints).

1. `daemon.rs::policy_set` (~line 345): closure body becomes
   `cfg.replace_allow(allow);` instead of `cfg.allow = allow;`.
2. `daemon.rs::policy_set_full` (~line 381): `cfg.replace_allow(allow);
   cfg.git = git;` (git rules are `GitTarget`-keyed — not host-normalized,
   unchanged).
3. `fake.rs::policy_set_full` (~line 258): mirror —
   `self.policy.replace_allow(allow); self.policy.git = git;`.
   `fake.rs::policy_set` only records the call today (no state mutation);
   leave that as-is unless a test requires observability.
4. Test (TDD, app side — follow the existing fake/dispatch test style in
   `lib.rs` or `fake.rs`): a `policy_set_full` dispatch carrying
   normalize-equal duplicates (`"Host.com."` ReadWrite [443] +
   `"host.com"` Read [8080]) followed by `policy_show` observes ONE
   canonical `"host.com"` entry with the last entry's payload (ports
   [8080], Read) — proving the GUI save path can no longer persist
   compile-time-colliding duplicates.

**Commit:** `fix(app): normalize GUI wholesale policy writes via replace_allow` (body `Refs #171`).
