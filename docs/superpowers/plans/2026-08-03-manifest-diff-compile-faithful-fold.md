# Manifest Diff Compile-Faithful Fold Implementation Plan (#172)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `manifest/diff.rs::allow_index` fold allow-lists exactly like `to_rego_data_json` compiles them, so the `⚠ weakens egress` review flag is compile-faithful and the #172 two-promote unflagged-widening sequence becomes flagged.

**Architecture:** `allow_index` builds the `(normalized host, port) → Access` comparison view backing `egress_weakens`. Today it max-folds every duplicate cell; compilation instead treats exact hosts as a JSON map (later normalize-equal entry's whole `{ports, access}` OVERWRITES — last-wins whole-entry) and wildcards as a list (UNION — effective access per cell is the max across entries). The fix folds each entry kind the way compilation does. `egress_weakens`, `plan()`, and `write_policy` are untouched.

**Tech Stack:** Rust, `izba-core` crate only. No wire changes, no `DAEMON_PROTO_VERSION` bump.

## Global Constraints

- Compile-semantics contract (verbatim from the spec): **Exact hosts** land in `sandbox_host_rules`, a JSON **map** keyed by normalized host — a later normalize-equal entry's whole `{ports, access}` object **overwrites** the earlier one (last-wins, whole-entry). **Wildcard hosts** (`is_wildcard_host`) land in `sandbox_wildcard_host_rules`, a **list** — every rule grants independently (union), so effective access per (pattern, port) is the max across entries.
- `manifest/apply.rs` must NOT change: `plan()`'s raw struct compare and `write_policy`'s verbatim persist are load-bearing (#170 adjudication — a respelling-only change keeps an unflagged delta row because promote genuinely rewrites managed `policy.yaml`).
- Human-facing delta `from`/`to` strings stay `to_yaml()` verbatim (source spellings); only the comparison index changes.
- Never silently weaken security semantics; when in doubt, the flag fires (fail closed).
- Unit tests never bind unix/vsock listeners.
- Toolchain env (`.cargo-env` uses `$PWD`, wrong from a worktree): `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH`
- All six gates green before the branch is done: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- Conventional commits; every commit message body includes `Refs #172` and ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Compile-faithful `allow_index`

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (~line 731: `is_wildcard_host` visibility)
- Modify: `crates/izba-core/src/manifest/diff.rs` (imports ~line 7; `allow_index` ~lines 91–118; test `normalize_equal_duplicates_fold_max_access` ~lines 656–683)

**Interfaces:**
- Consumes: `normalize_policy_host` (already `pub(crate)`), `is_wildcard_host(host: &str) -> bool` (this task widens it to `pub(crate)`).
- Produces: `allow_index` with compile-faithful folding — Task 2's pins rely on: exact hosts fold last-wins whole-entry; wildcards fold max-access per (pattern, port).

- [ ] **Step 1: Write the failing discriminator test**

In `crates/izba-core/src/manifest/diff.rs`, REPLACE the entire test `normalize_equal_duplicates_fold_max_access` (doc comment and function, ~lines 656–683) with:

```rust
    /// #172: exact-host duplicates fold LAST-WINS, whole-entry — exactly like
    /// the `sandbox_host_rules` JSON-map compile — NOT max-access. With
    /// `[rw first, read last]` the enforced access is read (the last
    /// normalize-equal entry's whole object wins), so a later single-entry
    /// `[rw]` proposal is a genuine widen and must be flagged. A max-access
    /// fold would call the from-side rw and let this widen through unflagged
    /// (step 2 of the #172 two-promote sequence).
    #[test]
    fn exact_host_duplicates_fold_last_wins_not_max() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            },
            AllowEntry::Scoped {
                host: "Host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
            },
        ];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
        }];
        assert!(
            egress_weakens(&from.egress, &to.egress),
            "compiled enforcement was read (last duplicate wins); an rw proposal widens and must flag"
        );
    }
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
cargo test -p izba-core manifest::diff::tests::exact_host_duplicates_fold_last_wins_not_max
```

Expected: FAIL — the current max-access fold reports the from-side as rw, so `egress_weakens` returns false.

- [ ] **Step 3: Widen `is_wildcard_host` to `pub(crate)`**

In `crates/izba-core/src/daemon/egress/config.rs` (~line 731), change:

```rust
fn is_wildcard_host(host: &str) -> bool {
```

to:

```rust
/// `pub(crate)` so `manifest::diff` classifies entries into the same two
/// compile targets (`sandbox_host_rules` map vs `sandbox_wildcard_host_rules`
/// list) that `to_rego_data_json` uses — the fold semantics differ (#172).
pub(crate) fn is_wildcard_host(host: &str) -> bool {
```

If the function already carries a doc comment, append this rationale to it instead of duplicating.

- [ ] **Step 4: Rewrite `allow_index` compile-faithfully**

In `crates/izba-core/src/manifest/diff.rs`, extend the import (~line 7):

```rust
use crate::daemon::egress::config::{
    is_wildcard_host, normalize_policy_host, Access, EgressPolicyConfig,
};
```

Then REPLACE `allow_index` and its doc comment (~lines 91–118) with:

```rust
/// Build the (host, port) -> access view of an allow-list for comparison,
/// folded exactly like `to_rego_data_json` compiles it (#172):
///
/// - **Exact hosts** compile into `sandbox_host_rules`, a JSON MAP keyed by
///   normalized host: a later normalize-equal entry's whole `{ports, access}`
///   object OVERWRITES the earlier one. So each exact-host entry first clears
///   every cell of that host, then inserts its own ports — last-wins,
///   whole-entry.
/// - **Wildcard hosts** compile into `sandbox_wildcard_host_rules`, a JSON
///   LIST where every rule grants independently (UNION): a cell's effective
///   access is the max across the entries that carry it, so cells accumulate
///   and duplicates take max-access.
///
/// Keyed on `normalize_policy_host` (trim + trailing-dot strip + lowercase),
/// the same comparison identity `EgressPolicyConfig`'s own mutation methods
/// and `to_rego_data_json` use (#170). Folding compile-faithfully is
/// load-bearing for the `⚠ weakens egress` gate: a max-access fold overstated
/// the "from" side of duplicate-carrying configs, letting a two-promote
/// sequence widen enforcement read -> read-write with neither step flagged
/// (#172).
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<(String, u16), Access> {
    let mut m: BTreeMap<(String, u16), Access> = BTreeMap::new();
    for e in &eg.allow {
        let host = normalize_policy_host(e.host());
        let acc = e.access();
        if is_wildcard_host(&host) {
            for p in e.ports() {
                let entry = m.entry((host.clone(), p)).or_insert(acc);
                if acc == Access::ReadWrite {
                    *entry = Access::ReadWrite;
                }
            }
        } else {
            // JSON-map overwrite: this entry replaces ALL prior cells for
            // this host, not just the ports it shares with them.
            m.retain(|(h, _), _| h != &host);
            for p in e.ports() {
                m.insert((host.clone(), p), acc);
            }
        }
    }
    m
}
```

(Exact-host `retain` cannot collide with wildcard cells: wildcard keys always start with `*.`/`**.`, which `normalize_policy_host` never produces from an exact host.)

- [ ] **Step 5: Run the full diff test module**

```bash
cargo test -p izba-core manifest::diff
```

Expected: ALL PASS — the new discriminator passes, and every pre-existing test (including `duplicate_host_verb_widening_weakens_egress`, `duplicate_host_pure_tightening_does_not_weaken`, `respelling_only_host_change_does_not_weaken`, `genuine_widen_across_spellings_still_flagged`, `new_host_detection_across_spellings`) still passes: widening/tightening the LAST duplicate is caught identically under last-wins, and single-entry cases are unaffected.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/manifest/diff.rs crates/izba-core/src/daemon/egress/config.rs
git commit -m "fix(core): fold manifest-diff allow-index exactly like policy compile

allow_index max-folded duplicate (host, port) cells, but exact hosts
compile last-wins whole-entry (sandbox_host_rules JSON-map overwrite)
while wildcards compile as UNION. Fold each kind the way to_rego_data_json
does, so the '⚠ weakens egress' gate is compile-faithful and a
duplicate-carrying promote can no longer overstate the from side.

Refs #172

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Scenario pins, stale-comment rewrites, six gates

**Files:**
- Modify: `crates/izba-core/src/manifest/diff.rs` (tests module; doc comments of `duplicate_host_verb_widening_weakens_egress` ~lines 460–462 and `duplicate_host_pure_tightening_does_not_weaken` ~lines 563–565)

**Interfaces:**
- Consumes: Task 1's compile-faithful `allow_index` (exact hosts last-wins whole-entry; wildcards max-access union) via `egress_weakens(from: &EgressPolicyConfig, to: &EgressPolicyConfig) -> bool`.
- Produces: nothing downstream — final pins.

- [ ] **Step 1: Write the three scenario pins**

Append to the tests module in `crates/izba-core/src/manifest/diff.rs`:

```rust
    /// #172: the two-promote widening sequence, end-to-end at the diff layer.
    /// Step 1 — appending a narrower normalize-equal duplicate
    /// (`[h rw 443]` -> `[h rw 443, h read 443]`) NARROWS enforcement to read
    /// (the last duplicate's whole object wins at compile) and must NOT flag.
    /// Step 2 — dropping the duplicate again (`[h rw 443, h read 443]` ->
    /// `[h rw 443]`) WIDENS enforcement read -> read-write and MUST flag.
    /// Before #172, the max-access fold left BOTH steps unflagged.
    #[test]
    fn two_promote_duplicate_sequence_flags_the_widening_step() {
        let mut managed = base();
        managed.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
        }];
        let mut with_dup = base();
        with_dup.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            },
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
            },
        ];
        assert!(
            !egress_weakens(&managed.egress, &with_dup.egress),
            "step 1 narrows enforcement (rw -> read); no flag"
        );
        assert!(
            egress_weakens(&with_dup.egress, &managed.egress),
            "step 2 widens enforcement (read -> rw); MUST flag"
        );
    }

    /// #172 per-port variant: `[h{443} read, h{8080} rw]` compiles to ONLY
    /// 8080/read-write — the last entry's whole `{ports, access}` object wins,
    /// dropping 443 entirely. A proposal keeping just `[h{443} read]`
    /// therefore re-opens 443, an effectively NEW (host, port), and must flag
    /// even though it looks like a pure removal textually.
    #[test]
    fn exact_host_whole_entry_overwrite_drops_earlier_ports() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
            },
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![8080]),
                access: Access::ReadWrite,
            },
        ];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
        }];
        assert!(
            egress_weakens(&from.egress, &to.egress),
            "443 was not enforced before (8080-only entry won at compile); re-opening it must flag"
        );
    }

    /// #172: wildcard duplicates fold as UNION, not last-wins. With
    /// `[*.x rw 443, *.x read 443]` (rw FIRST, read LAST) the union already
    /// grants read-write on 443, so collapsing to `[*.x rw 443]` is not a
    /// widen — a last-wins fold would wrongly call the from-side read and
    /// false-positive here. Adding a redundant read duplicate to an rw
    /// wildcard is likewise not a widen.
    #[test]
    fn wildcard_duplicates_fold_as_union_not_last_wins() {
        let mut dup = base();
        dup.egress.allow = vec![
            AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            },
            AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
            },
        ];
        let mut single = base();
        single.egress.allow = vec![AllowEntry::Scoped {
            host: "*.example.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
        }];
        assert!(
            !egress_weakens(&dup.egress, &single.egress),
            "union already granted rw on 443; collapsing duplicates is no widen"
        );
        assert!(
            !egress_weakens(&single.egress, &dup.egress),
            "adding a redundant read duplicate under an rw wildcard is no widen"
        );
    }
```

- [ ] **Step 2: Run the new pins**

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
cargo test -p izba-core manifest::diff
```

Expected: ALL PASS (the pins hold given Task 1's fold; any failure means Task 1's fold is wrong — stop and report, do not adjust the pins to fit).

- [ ] **Step 3: Rewrite the two stale "Fix 1" test doc comments**

In the same tests module, the doc comment on `duplicate_host_verb_widening_weakens_egress` still says duplicates "must not collapse last-wins" — under #172 they now legitimately DO (compile-faithfully). Replace that test's doc comment with:

```rust
    /// Duplicate exact-host entries fold last-wins at compile, so the LAST
    /// entry is the enforced one — widening ITS verb must flag. (Originally
    /// "Fix 1": a host-keyed index used to mask per-port verb widenings; kept
    /// as a pin that the enforced cell's widen is always caught.)
```

Replace the doc comment on `duplicate_host_pure_tightening_does_not_weaken` with:

```rust
    /// Fix 1 (negative): tightening the verb on the enforced (last) duplicate
    /// entry is a pure tightening and must NOT flag.
```

- [ ] **Step 4: Run all six workspace gates**

```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

Expected: all six green. (No `izba-core` PUBLIC types changed — `is_wildcard_host` is `pub(crate)` — so the separate app gate is not required by this diff; App CI still runs on the PR.)

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/diff.rs
git commit -m "test(core): pin #172 scenarios — two-promote flag, whole-entry port drop, wildcard union

Refs #172

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
