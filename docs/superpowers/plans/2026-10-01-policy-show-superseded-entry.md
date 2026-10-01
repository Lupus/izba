# `policy show` Superseded-Entry Rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `izba policy show` stops advertising a TLS-pinning passthrough (and ports/access) from an allow-list entry that a later entry for the same exact host has superseded, and says a duplicate is the cause.

**Architecture:** A new core primitive, `EgressPolicyConfig::superseded_by()`, is the single place "exact host, last-wins" is decided outside the compile. `InspectionTable::from_config` is refactored to build its passthrough set from it, and the CLI's `render_policy` annotates superseded entries from it. No fold semantics change.

**Tech Stack:** Rust (workspace crates `izba-core`, `izba-cli`), `serde_yaml`/`serde_json` (already dependencies), `cargo test`.

**Spec:** `docs/superpowers/specs/2026-10-01-policy-show-superseded-entry-design.md`

## Global Constraints

- **No fold semantics change.** `to_rego_data_json`, `collapse_duplicate_hosts`, `manifest::diff::allow_index` and the observable behaviour of `InspectionTable::from_config` stay exactly as they are. Do not edit `to_rego_data_json` or `egress.rego`.
- **One fold.** The renderer must not compute "which entry wins" itself; it calls `EgressPolicyConfig::superseded_by()`. `InspectionTable::from_config` calls the same method.
- **Byte-identity.** A policy with no duplicate exact hosts must render byte-identically to today. Existing host lines, the three existing `protocol: tcp` wordings and the `protocol: http (inspected)` wording must not change by a single byte.
- **Exact new strings** (U+26A0 is `⚠`, written `\u{26A0}` in source; `—` is U+2014 written literally, as the file already does):
  - supersession line: `⚠ superseded — NOT in force: a later entry for this host (<winner>) replaces this one wholesale; the last entry for an exact host wins — remove the duplicate`
  - superseded tcp line: `⚠ :<port> protocol: tcp — pinning passthrough NOT in effect: this entry is superseded by a later entry for the same host, so its declaration is never read; declare it on the later entry (or remove that entry) to pin`
  - `<winner>` is the winning entry formatted exactly like a host line without its indent: `<host>  [<ports joined by ", ">] (<read|read-write>)` (two spaces after the host).
- **TDD.** Write each test first and watch it fail for the right reason before writing production code (the byte-identity guard in Task 2 is the one deliberate exception — it is a characterization test and must PASS before the change).
- **Test design constraint (repo rule):** unit tests never bind unix/vsock listeners. Nothing here needs one.
- **Gates** (run from the repo root; `[ -f .cargo-env ] && source .cargo-env` first): `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p izba-core --lib`, `cargo test -p izba-cli`.
- **Commits:** conventional commits, body contains `Refs #243`, and ends with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never `git add -A`; stage named files, check `git status --short`, then commit.
- **CI mutation gate.** CI runs `cargo-mutants` on changed lines. Every new branch and every return value introduced here must be pinned by an assertion that would fail if it were inverted or replaced by a constant. Do not add `#[mutants::skip]`.

## Review Focus

1. **Normalize-equal spellings** (`Pinned.Vendor.COM.` then `pinned.vendor.com`): the first is superseded although the strings differ — Task 1 `superseded_by_matches_normalize_equal_spellings`, Task 2 `show_marks_a_superseded_entry_under_a_different_spelling`.
2. **Three or more duplicates:** every earlier one points at the LAST, not at its immediate successor — Task 1 `superseded_by_points_every_earlier_duplicate_at_the_last_one`, Task 2 `show_names_the_last_duplicate_as_the_winner`.
3. **Wildcard duplicates** (`*.x.com` twice): never marked — wildcards union — Task 1 `superseded_by_never_marks_a_wildcard`, Task 2 `show_never_marks_a_wildcard_duplicate_as_superseded`.
4. **Superseded entry on a sandbox with enforcement off, or with `access: read`:** the supersession wording must win; "turn enforcement on to pin" / "widen to read-write to pin" would be false remedies — Task 2 `show_prefers_the_superseded_wording_over_the_enforce_off_wording` and `show_prefers_the_superseded_wording_over_the_narrow_access_wording`.
5. **Both duplicates declare `tcp` on the same port:** the passthrough IS in force (through the winner); the output must contain the in-force line exactly once and must not say the host has no passthrough — Task 2 `show_keeps_the_winning_entrys_passthrough_in_force`.

---

### Task 1: Core primitive `EgressPolicyConfig::superseded_by` and `InspectionTable` consumes it

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` — add the method right after `entries_for_host` (≈ line 677); add tests inside the existing `mod tests` (starts ≈ line 1600), right after `entries_for_host_returns_all_mixed_access_wildcard_entries`.
- Modify: `crates/izba-core/src/daemon/egress/inspect.rs:89-125` — the `passthrough` half of `from_config`.

**Interfaces:**
- Consumes: existing `normalize_policy_host(&str) -> String`, `is_wildcard_host(&str) -> bool` (both `pub(crate)` in `config.rs`), `AllowEntry::{host, ports, access, declared_protocol_for}`.
- Produces: `pub fn superseded_by(&self) -> Vec<Option<usize>>` on `EgressPolicyConfig`. One slot per `self.allow` entry, same indexing. `Some(j)` ⇔ entry `j` (`j > i`) is the last entry whose normalized host equals entry `i`'s and that host is an exact (non-wildcard) host. `None` ⇔ the entry is in force (including every wildcard entry). Task 2 calls exactly this.

- [ ] **Step 1: Write the failing tests** (in `config.rs`'s `mod tests`)

```rust
    // ── #243: `superseded_by` — the one "exact host, last-wins" decision ────

    #[test]
    fn superseded_by_is_all_none_without_duplicates() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("a.example.com".into()),
                AllowEntry::Host("b.example.com".into()),
                AllowEntry::Host("*.example.com".into()),
            ],
            git: vec![],
        };
        assert_eq!(cfg.superseded_by(), vec![None, None, None]);
    }

    /// Three entries for one host: BOTH earlier ones point at the LAST
    /// (index 3), never at their immediate successor — the compile keeps
    /// only the last `Map::insert`.
    #[test]
    fn superseded_by_points_every_earlier_duplicate_at_the_last_one() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("a.example.com".into()),
                AllowEntry::Host("b.example.com".into()),
                AllowEntry::Host("a.example.com".into()),
                AllowEntry::Host("a.example.com".into()),
            ],
            git: vec![],
        };
        assert_eq!(cfg.superseded_by(), vec![Some(3), None, Some(3), None]);
    }

    /// Supersession is keyed on `normalize_policy_host` (trim + trailing-dot
    /// strip + lowercase), the identity the compile uses — not on the raw
    /// spelling in the file.
    #[test]
    fn superseded_by_matches_normalize_equal_spellings() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("API.X.com.".into()),
                AllowEntry::Host("api.x.com".into()),
            ],
            git: vec![],
        };
        assert_eq!(cfg.superseded_by(), vec![Some(1), None]);
    }

    /// Wildcards compile into a LIST where every rule grants independently
    /// (union) — a duplicate wildcard supersedes nothing, and a wildcard and
    /// the exact host under it never supersede each other.
    #[test]
    fn superseded_by_never_marks_a_wildcard() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "*.x.com".into(),
                    ports: Some(PortSpec::bare_list(&[443])),
                    access: Access::ReadWrite,
                },
                AllowEntry::Scoped {
                    host: "*.X.com".into(),
                    ports: Some(PortSpec::bare_list(&[8443])),
                    access: Access::Read,
                },
                AllowEntry::Host("x.com".into()),
            ],
            git: vec![],
        };
        assert_eq!(cfg.superseded_by(), vec![None, None, None]);
    }

    /// Guard (#243): `superseded_by` must describe exactly what
    /// `to_rego_data_json` compiles. Every exact-host entry it reports as in
    /// force must be the one sitting in `sandbox_host_rules`, with that
    /// entry's ports and access; and there must be no compiled host it did
    /// not account for. If this fails, the reveal surface and the compiled
    /// policy disagree about which duplicate wins.
    #[test]
    fn superseded_by_agrees_with_the_compiled_host_rules() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "dup.example.com".into(),
                    ports: Some(PortSpec::bare_list(&[8443])),
                    access: Access::Read,
                },
                AllowEntry::Host("solo.example.com".into()),
                AllowEntry::Host("*.example.com".into()),
                AllowEntry::Scoped {
                    host: "DUP.example.com.".into(),
                    ports: Some(PortSpec::bare_list(&[9443])),
                    access: Access::ReadWrite,
                },
            ],
            git: vec![],
        };
        let doc: serde_json::Value =
            serde_json::from_str(&cfg.to_rego_data_json("web")).unwrap();
        let rules = doc["sandbox_host_rules"]["web"].as_object().unwrap();
        let superseded = cfg.superseded_by();
        assert_eq!(superseded, vec![Some(3), None, None, None]);

        let mut in_force_exact = 0;
        for (i, e) in cfg.allow.iter().enumerate() {
            let host = normalize_policy_host(e.host());
            if is_wildcard_host(&host) || superseded[i].is_some() {
                continue;
            }
            in_force_exact += 1;
            let access = match e.access() {
                Access::Read => "read",
                Access::ReadWrite => "read-write",
            };
            assert_eq!(rules[&host]["ports"], serde_json::json!(e.ports()), "{host}");
            assert_eq!(rules[&host]["access"], access, "{host}");
        }
        assert_eq!(
            in_force_exact,
            rules.len(),
            "every compiled exact host is an in-force entry, and vice versa"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib superseded_by`
Expected: compile error — `no method named superseded_by found for struct EgressPolicyConfig`.

- [ ] **Step 3: Implement `superseded_by`** (in `config.rs`, immediately after `entries_for_host`)

```rust
    /// Which `allow` entries a LATER entry for the same exact host
    /// supersedes (#243).
    ///
    /// One slot per `self.allow` entry, same indexing: `Some(j)` when entry
    /// `j` (always `j > i`) is the LAST entry whose host is normalize-equal
    /// to entry `i`'s — the one `to_rego_data_json`'s `sandbox_host_rules`
    /// map keeps, because a later `Map::insert` under the same key
    /// overwrites the earlier entry's whole `{ports, access}` — and `None`
    /// when entry `i` is itself in force.
    ///
    /// A wildcard entry is never superseded: wildcards compile into a LIST
    /// where every rule grants independently (see
    /// `collapse_duplicate_hosts`).
    ///
    /// This is the ONE place "exact host, last-wins" is decided outside the
    /// compile itself. `InspectionTable::from_config` builds its passthrough
    /// set from it and `izba policy show` marks superseded entries from it,
    /// so the reveal surface and the datapath cannot fold duplicates
    /// differently; `superseded_by_agrees_with_the_compiled_host_rules` pins
    /// it against the compile.
    pub fn superseded_by(&self) -> Vec<Option<usize>> {
        let hosts: Vec<String> = self
            .allow
            .iter()
            .map(|e| normalize_policy_host(e.host()))
            .collect();
        let mut winner: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (i, host) in hosts.iter().enumerate() {
            if !is_wildcard_host(host) {
                winner.insert(host, i); // a later index overwrites an earlier one
            }
        }
        hosts
            .iter()
            .enumerate()
            .map(|(i, host)| winner.get(host.as_str()).copied().filter(|&w| w != i))
            .collect()
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib superseded_by`
Expected: 5 passed.

- [ ] **Step 5: Refactor `InspectionTable::from_config` to consume it**

In `crates/izba-core/src/daemon/egress/inspect.rs`, replace the block that starts at the comment `// passthrough: LAST-WINS per exact host, mirroring \`to_rego_data_json\`.` and ends just before the final `Self { inspect_ports, passthrough }` (the `winner_by_host` map, its fill loop, and the `for (host, idx) in &winner_by_host` loop) with:

```rust
        // passthrough: LAST-WINS per exact host, mirroring `to_rego_data_json`.
        // The fold itself lives in `EgressPolicyConfig::superseded_by` — the
        // same answer `izba policy show` renders (#243) — so this table and
        // the reveal surface cannot disagree about which duplicate wins.
        // Wildcards are excluded entirely — `parse_allow_entry` refuses an
        // explicit `tcp` on a wildcard (DP-3), and this guard keeps the
        // invariant true for a config built in code rather than parsed.
        let superseded = cfg.superseded_by();
        for (idx, e) in cfg.allow.iter().enumerate() {
            let host = normalize_policy_host(e.host());
            if is_wildcard_host(&host) || superseded[idx].is_some() {
                continue;
            }
            // Per-PORT since #238: a port registers a passthrough only when a
            // declaration was written against that port. There is no
            // entry-level declaration left to project onto the entry's other
            // ports, which is what made `allow`'s widening possible.
            //
            // Asks `declared_protocol_for` — the SAME per-entry primitive
            // `inspect_ports` reaches through `protocol_for` just above, and
            // the one `izba policy show` reports — rather than scanning the
            // spec list for any `tcp`. A scan is a second reading of the axis,
            // and it diverged: for a hand-constructed entry listing one port
            // twice (`http` then `tcp`), `declared_protocol_for`'s `find`
            // answers `http` while a scan registers the passthrough, so izbad
            // spliced a port reported as inspected (PR #260, Greptile P1).
            // `parse_allow_entry` now refuses that input, but this fold must
            // not depend on the parser having been the only way in —
            // `AllowEntry::Scoped`'s fields are public.
            for port in e.ports() {
                if e.declared_protocol_for(port) == Some(Protocol::Tcp) {
                    passthrough.insert((host.clone(), port));
                }
            }
        }
```

Then fix the import at the top of `inspect.rs`: `BTreeMap` is no longer used, so change `use std::collections::{BTreeMap, BTreeSet};` to `use std::collections::BTreeSet;` (if a test in that file still uses `BTreeMap`, import it inside the test module instead). Also update the doc comment on `from_config` only if it names `winner_by_host`; it does not today, so leave it.

- [ ] **Step 6: Run the whole inspect + config suites**

Run: `cargo test -p izba-core --lib daemon::egress::inspect && cargo test -p izba-core --lib daemon::egress::config && cargo test -p izba-core --lib daemon::egress::router`
Expected: all pass, in particular `a_later_duplicate_host_entry_supersedes_an_earlier_tcp_declaration`, `a_hand_constructed_wildcard_tcp_declaration_never_opens_the_hatch`, `passthrough_matching_uses_the_policy_host_normalization`.

- [ ] **Step 7: Lint and format**

Run: `cargo fmt && cargo clippy -p izba-core --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-core/src/daemon/egress/config.rs crates/izba-core/src/daemon/egress/inspect.rs
git status --short
git commit -m "refactor(core): decide exact-host supersession in one place" \
  -m "Add EgressPolicyConfig::superseded_by, the single last-wins decision outside the compile, and build InspectionTable's passthrough set from it. No behaviour change; a guard test pins it against to_rego_data_json.

Refs #243

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `render_policy` marks superseded entries; docs

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs` — `render_policy` (≈ lines 382-513) and its tests (inside `mod tests`, next to `show_keeps_the_read_write_passthrough_wording_unchanged`).
- Modify: `CLAUDE.md` (inspectability contract bullet, ≈ line 291), `README.md` (≈ line 66-71), `docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md` (§13, ≈ lines 379-386 and ≈ 430-433).

**Interfaces:**
- Consumes: `EgressPolicyConfig::superseded_by(&self) -> Vec<Option<usize>>` from Task 1 (one slot per `cfg.allow` entry; `Some(j)` = superseded by entry `j`; `None` = in force).
- Produces: nothing for later tasks. `render_policy`'s signature (`fn render_policy(name: &str, cfg: Option<&EgressPolicyConfig>) -> String`) does not change, so `show()` is untouched.

- [ ] **Step 1: Write the byte-identity guard FIRST and confirm it PASSES on the unmodified renderer**

Add to `policy.rs`'s `mod tests`:

```rust
    /// #243 guard: a policy with no duplicate exact hosts renders
    /// byte-identically to how it did before supersession was rendered.
    /// Whole-output equality, so any stray line or reworded annotation fails.
    #[test]
    fn show_renders_a_duplicate_free_policy_byte_identically() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - api.example.com\n\
             \x20 - host: internal.example.com\n\
             \x20   ports: [8000]\n\
             \x20   protocol: http\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - host: ro.example.com\n\
             \x20   access: read\n\
             \x20 - \"*.example.org\"\n",
        )
        .unwrap();
        assert_eq!(
            render_policy("web", Some(&cfg)),
            "'web' egress policy (enforce: on):\n\
             \x20 http allow-list:\n\
             \x20   api.example.com  [80, 443] (read-write)\n\
             \x20   internal.example.com  [8000] (read-write)\n\
             \x20       :8000 protocol: http (inspected)\n\
             \x20   pinned.vendor.com  [443] (read-write)\n\
             \x20       \u{26A0} :443 protocol: tcp — pinning passthrough: spliced opaquely; \
             no L7 rules, no request audit, no upstream certificate verification\n\
             \x20   ro.example.com  [80, 443] (read)\n\
             \x20   *.example.org  [80, 443] (read-write)\n"
        );
    }
```

Run: `cargo test -p izba-cli show_renders_a_duplicate_free_policy_byte_identically`
Expected: **PASS** against the unmodified `render_policy`. This is a characterization test. If it fails, the expected literal is wrong — correct the LITERAL to match the current output (print it with `-- --nocapture`), never the production code, and say so in your report.

- [ ] **Step 2: Write the failing supersession tests**

Add to the same `mod tests`. Two string constants keep the wording in one place for the tests:

```rust
    // ── #243: a superseded duplicate exact-host entry ───────────────────────

    /// The issue's reproducer: an earlier `protocol: tcp` entry superseded by
    /// a later bare entry for the same host. `InspectionTable` registers no
    /// passthrough; `policy show` used to print the in-force line anyway.
    #[test]
    fn show_marks_a_superseded_entry_and_its_passthrough_as_not_in_force() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - pinned.vendor.com\n",
        )
        .unwrap();
        assert_eq!(
            render_policy("web", Some(&cfg)),
            "'web' egress policy (enforce: on):\n\
             \x20 http allow-list:\n\
             \x20   pinned.vendor.com  [443] (read-write)\n\
             \x20       \u{26A0} superseded — NOT in force: a later entry for this host \
             (pinned.vendor.com  [80, 443] (read-write)) replaces this one wholesale; \
             the last entry for an exact host wins — remove the duplicate\n\
             \x20       \u{26A0} :443 protocol: tcp — pinning passthrough NOT in effect: this \
             entry is superseded by a later entry for the same host, so its declaration is \
             never read; declare it on the later entry (or remove that entry) to pin\n\
             \x20   pinned.vendor.com  [80, 443] (read-write)\n"
        );
    }

    /// The inverse ordering: the `protocol: tcp` entry is LAST, so it wins and
    /// the passthrough is in force — matching `InspectionTable`'s fold. The
    /// earlier bare entry is the superseded one.
    #[test]
    fn show_keeps_a_later_passthrough_in_force_over_an_earlier_bare_entry() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - pinned.vendor.com\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n",
        )
        .unwrap();
        assert_eq!(
            render_policy("web", Some(&cfg)),
            "'web' egress policy (enforce: on):\n\
             \x20 http allow-list:\n\
             \x20   pinned.vendor.com  [80, 443] (read-write)\n\
             \x20       \u{26A0} superseded — NOT in force: a later entry for this host \
             (pinned.vendor.com  [443] (read-write)) replaces this one wholesale; \
             the last entry for an exact host wins — remove the duplicate\n\
             \x20   pinned.vendor.com  [443] (read-write)\n\
             \x20       \u{26A0} :443 protocol: tcp — pinning passthrough: spliced opaquely; \
             no L7 rules, no request audit, no upstream certificate verification\n"
        );
    }

    /// Both duplicates declare `tcp` on :443 — the passthrough IS in force,
    /// through the winner. Exactly one in-force line, and it belongs to the
    /// last entry.
    #[test]
    fn show_keeps_the_winning_entrys_passthrough_in_force() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert_eq!(out.matches("spliced opaquely").count(), 1, "{out}");
        assert_eq!(out.matches("superseded — NOT in force").count(), 1, "{out}");
        assert_eq!(out.matches("pinning passthrough NOT in effect").count(), 1, "{out}");
        assert!(
            out.ends_with(
                "    pinned.vendor.com  [443] (read-write)\n        \u{26A0} :443 protocol: tcp \
                 — pinning passthrough: spliced opaquely; no L7 rules, no request audit, no \
                 upstream certificate verification\n"
            ),
            "the in-force line belongs to the LAST entry:\n{out}"
        );
    }

    /// Three duplicates: both earlier entries name the LAST one as the
    /// winner (ports [9999]), never the middle one (ports [8443]).
    #[test]
    fn show_names_the_last_duplicate_as_the_winner() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: dup.example.com\n\
             \x20   ports: [443]\n\
             \x20 - host: dup.example.com\n\
             \x20   ports: [8443]\n\
             \x20 - host: dup.example.com\n\
             \x20   ports: [9999]\n\
             \x20   access: read\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert_eq!(
            out.matches("a later entry for this host (dup.example.com  [9999] (read))")
                .count(),
            2,
            "{out}"
        );
        assert!(
            !out.contains("a later entry for this host (dup.example.com  [8443]"),
            "the middle duplicate is itself superseded — it is never the winner:\n{out}"
        );
        assert_eq!(out.matches("superseded — NOT in force").count(), 2, "{out}");
    }

    /// Supersession is keyed on the normalized host, so a differently-spelled
    /// earlier entry is superseded too.
    #[test]
    fn show_marks_a_superseded_entry_under_a_different_spelling() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Host("Pinned.Vendor.COM.".into()),
                AllowEntry::Host("pinned.vendor.com".into()),
            ],
            git: vec![],
        };
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains(
                "    Pinned.Vendor.COM.  [80, 443] (read-write)\n        \u{26A0} superseded \
                 — NOT in force: a later entry for this host (pinned.vendor.com  [80, 443] \
                 (read-write))"
            ),
            "{out}"
        );
        assert_eq!(out.matches("superseded — NOT in force").count(), 1, "{out}");
    }

    /// Wildcards union — a duplicate wildcard supersedes nothing, and a
    /// wildcard does not supersede (nor is superseded by) an exact host.
    #[test]
    fn show_never_marks_a_wildcard_duplicate_as_superseded() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: \"*.example.com\"\n\
             \x20   ports: [443]\n\
             \x20 - host: \"*.example.com\"\n\
             \x20   ports: [8443]\n\
             \x20   access: read\n\
             \x20 - example.com\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(!out.contains("superseded"), "{out}");
    }

    /// With enforcement off the existing wording ends "turn enforcement on to
    /// pin" — a false remedy for an entry that is never read. The superseded
    /// wording must win.
    #[test]
    fn show_prefers_the_superseded_wording_over_the_enforce_off_wording() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: false\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - pinned.vendor.com\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains("this entry is superseded by a later entry for the same host"),
            "{out}"
        );
        assert!(!out.contains("turn enforcement on to pin"), "{out}");
    }

    /// Likewise for a narrow access level: "widen to read-write to pin" would
    /// not pin a superseded entry.
    #[test]
    fn show_prefers_the_superseded_wording_over_the_narrow_access_wording() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   access: read\n\
             \x20   protocol: tcp\n\
             \x20 - pinned.vendor.com\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains("this entry is superseded by a later entry for the same host"),
            "{out}"
        );
        assert!(!out.contains("widen to read-write to pin"), "{out}");
    }

    /// A superseded entry's `protocol: http` line stays: `inspect_ports`
    /// unions over EVERY entry, superseded ones included, so the port really
    /// is inspected.
    #[test]
    fn show_keeps_the_inspected_line_on_a_superseded_entry() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: internal.example.com\n\
             \x20   ports: [8000]\n\
             \x20   protocol: http\n\
             \x20 - internal.example.com\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("        :8000 protocol: http (inspected)\n"), "{out}");
        assert_eq!(out.matches("superseded — NOT in force").count(), 1, "{out}");
        assert!(
            izba_core::daemon::egress::inspect::InspectionTable::from_config(&cfg).inspects(8000),
            "the rendering claim must match the table"
        );
    }
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `cargo test -p izba-cli show_`
Expected: the eight tests from Step 2 other than `show_never_marks_a_wildcard_duplicate_as_superseded` FAIL (no `superseded` text is rendered yet; the first prints `spliced opaquely`). `show_never_marks_a_wildcard_duplicate_as_superseded` and the Step 1 guard PASS already — that is expected; they pin behaviour the change must not break.

- [ ] **Step 4: Implement the rendering**

In `render_policy`, inside the `else` branch that prints `"  http allow-list:"`, replace the loop header `for e in &cfg.allow {` and the host-line code down to (and including) the `writeln!(out, "    {}  [{ports}] ({access_str})", e.host());` line with:

```rust
                // `host  [ports] (access)` — the host line's body, and the
                // way a superseding entry is named in the line below.
                let summary = |e: &AllowEntry| {
                    let ports = e
                        .port_specs()
                        .iter()
                        .map(|s| s.port.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let access_str = match e.access() {
                        Access::Read => "read",
                        Access::ReadWrite => "read-write",
                    };
                    format!("{}  [{ports}] ({access_str})", e.host())
                };
                // Duplicate entries for one EXACT host do not add up: the
                // compile keeps only the last (#243). Asked of the core
                // rather than folded here — a renderer-local fold is a second
                // reading of the allow-list, and the last time two readings
                // of it disagreed a host the allow-list denied was spliced
                // with no certificate verification.
                let superseded = cfg.superseded_by();
                for (idx, e) in cfg.allow.iter().enumerate() {
                    let specs = e.port_specs();
                    let winner = superseded[idx].map(|w| &cfg.allow[w]);
                    let _ = writeln!(out, "    {}", summary(e));
                    // Everything this entry says — ports, access, any
                    // declaration below — is not what is enforced. Said
                    // against the entry itself, naming the one that is, so
                    // the operator can find both lines in the file.
                    if let Some(w) = winner {
                        let _ = writeln!(
                            out,
                            "        \u{26A0} superseded — NOT in force: a later entry for this \
                             host ({}) replaces this one wholesale; the last entry for an exact \
                             host wins — remove the duplicate",
                            summary(w)
                        );
                    }
```

(The existing `let specs = e.port_specs();`, `let ports = …;` and `let access_str = …;` bindings that preceded the old `writeln!` are now inside `summary`; delete them. `specs` is still needed by the declaration loop below, hence the `let specs` kept above.)

Then, in the `match s.protocol` just below, add ONE arm immediately after the `Some(Protocol::Http)` arm and BEFORE `Some(Protocol::Tcp) if !cfg.enforce`:

```rust
                            // Superseded outranks both branches below: their
                            // remedies ("turn enforcement on", "widen to
                            // read-write") would not pin an entry the compile
                            // never reads.
                            Some(Protocol::Tcp) if winner.is_some() => format!(
                                "\u{26A0} :{} protocol: tcp — pinning passthrough NOT in \
                                 effect: this entry is superseded by a later entry for the \
                                 same host, so its declaration is never read; declare it on \
                                 the later entry (or remove that entry) to pin",
                                s.port
                            ),
```

Do not change any other arm or any other string.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p izba-cli`
Expected: all pass — the nine new tests, the Step 1 guard, and every pre-existing `render_policy_*` / `show_*` test unchanged.

- [ ] **Step 6: Update the docs**

1. `CLAUDE.md` — in the "Inspectability is DECLARED per PORT" bullet, find the sentence ending `…so a pinning client still sees izba's certificate — the two revealing surfaces must not disagree about posture.` and insert immediately after it (same paragraph, re-wrap at ~80 columns with the bullet's two-space continuation indent):

   > A duplicate entry for one EXACT host is superseded wholesale by the later one (the compile's per-host map overwrite), and `izba policy show` says so (#243): the earlier entry is marked `superseded — NOT in force` and a `protocol: tcp` on it reads `NOT in effect`. Which entry wins is decided by `EgressPolicyConfig::superseded_by` and NOWHERE else — `InspectionTable::from_config` builds its passthrough set from the same call, and a guard test pins it against `to_rego_data_json` — so do not fold duplicates in a renderer. The desktop app's Policy tab still lists a superseded row as if in force (#312), the one place the two surfaces currently disagree.

2. `README.md` — in the "**Auditing for exemptions: `izba policy show`.**" paragraph, append after the sentence ending `ask \`izba policy show\` (or the desktop app's Policy tab).`:

   > If `policy.yaml` names the same exact host twice, the later entry replaces the earlier one wholesale; `policy show` marks the earlier one `superseded — NOT in force`, so a passthrough declared only there is reported as not in effect.

3. `docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md`, §13 — append to the end of the bullet that begins `- **A superseded \`protocol: tcp\` disappears silently.**`:

   > **Closed by #243**, at the reveal surface rather than as a separate `policy lint`: `izba policy show` marks the superseded entry and reports its declaration as not in effect (`docs/superpowers/specs/2026-10-01-policy-show-superseded-entry-design.md`).

   and in the later paragraph that ends `…and the superseded-declaration warning is still a \`policy lint\` job.` replace that final clause with `…and the superseded-declaration warning has since landed in \`izba policy show\` (#243).`

- [ ] **Step 7: Lint, format, full gates for the touched crates**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p izba-cli && cargo test -p izba-core --lib daemon::egress`
Expected: clean, all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-cli/src/commands/policy.rs CLAUDE.md README.md docs/superpowers/specs/2026-08-17-m5-credential-vault-design.md
git status --short
git commit -m "fix(cli): policy show marks a superseded duplicate entry as not in force" \
  -m "Two allow entries for one exact host do not add up: the later one wins wholesale. policy show walked the raw list and printed the earlier entry's pinning passthrough as in force. It now marks the earlier entry superseded, names the entry that wins, and reports a protocol: tcp on it as not in effect. The fact comes from EgressPolicyConfig::superseded_by, the fold InspectionTable already uses. A duplicate-free policy renders byte-identically.

Refs #243

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
