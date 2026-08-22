// SPDX-License-Identifier: Apache-2.0
//! The **inspectability axis** compiled out of an allow-list (M5 spec §5).
//!
//! Held beside the Rego engine rather than inside it: `protocol` is decided in
//! typed Rust and never reaches the data document (D6), so `to_rego_data_json`
//! stays byte-identical whether or not an entry declares one.
//!
//! Two rules make this table safe to consult from the datapath:
//!
//! 1. `inspects` may only ever WIDEN against the pre-M5 `matches!(port, 80|443)`
//!    baseline (DP-1). Inspection is a security control; it must not shrink
//!    because an allow-list shrank.
//! 2. Only an EXPLICIT `protocol: tcp` registers a passthrough (D12). A value
//!    derived from a port number is a convenience, never an operator decision
//!    to disable a control.

use std::collections::{BTreeMap, BTreeSet};

use super::config::{
    is_wildcard_host, normalize_policy_host, AllowEntry, EgressPolicyConfig, Protocol,
};

/// Which ports izbad terminates at L7, and which exact hosts hold the
/// operator's pinning passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionTable {
    inspect_ports: BTreeSet<u16>,
    passthrough: BTreeSet<(String, u16)>,
}

/// **Not derived.** A derived `Default` would produce an EMPTY port set, which
/// reads as "inspect nothing" — so every `RegoPolicy` built without an explicit
/// table (`embedded`, `with_data`, and every test that uses them) would silently
/// stop terminating :80/:443. The default IS the pre-M5 baseline.
impl Default for InspectionTable {
    fn default() -> Self {
        Self {
            inspect_ports: AllowEntry::DEFAULT_PORTS.into_iter().collect(),
            passthrough: BTreeSet::new(),
        }
    }
}

impl InspectionTable {
    /// Compile the axis from a policy config.
    ///
    /// `inspect_ports` and `passthrough` are compiled by two DIFFERENT folds
    /// over the same `cfg.allow`, on purpose, because they answer different
    /// questions with different safe defaults:
    ///
    /// - `inspect_ports` UNIONS across every entry — correct, because
    ///   inspection may only ever WIDEN (DP-1) and the set is keyed on ports,
    ///   not on any one entry's host rule.
    /// - `passthrough` must instead mirror `to_rego_data_json`'s
    ///   `sandbox_host_rules` — a JSON MAP keyed by normalized exact host,
    ///   where a later entry's `Map::insert` OVERWRITES an earlier one under
    ///   the same key wholesale (not just adds to it). `EgressPolicyConfig`
    ///   does not collapse duplicate hosts at parse time (only its mutation
    ///   methods do — see `collapse_duplicate_hosts`'s doc), so a hand-edited
    ///   or hand-constructed config CAN carry two entries for the same exact
    ///   host reaching `into_policy` unmerged. Folding `passthrough` as a
    ///   UNION over that input (as an earlier version of this function did)
    ///   diverges from what `RegoPolicy::check` actually evaluates for that
    ///   host: `passthrough_host` could answer `true` for a
    ///   (host, port) pair whose LAST entry never declared `protocol: tcp`
    ///   for that port at all — data-model host H, port P authorized only by
    ///   an EARLIER, overwritten entry. That is a live no-certificate-
    ///   verification hatch on a host the allow-list denies (M5 P1 review,
    ///   task 3, finding 1) — closed here at the source; `router::
    ///   passthrough_names`'s per-name `policy.check` filter is kept as a
    ///   second, independent layer (see its comment) in case these two folds
    ///   ever diverge again.
    pub fn from_config(cfg: &EgressPolicyConfig) -> Self {
        // Starts from the unconditional baseline (DP-1) and only ever adds.
        let Self {
            mut inspect_ports,
            mut passthrough,
        } = Self::default();

        // inspect_ports: UNION across every entry (may only widen).
        for e in &cfg.allow {
            for port in e.ports() {
                if e.protocol_for(port) == Protocol::Http {
                    inspect_ports.insert(port);
                }
            }
        }

        // passthrough: LAST-WINS per exact host, mirroring `to_rego_data_json`.
        // Wildcards are excluded from this map entirely — `parse_allow_entry`
        // refuses an explicit `tcp` on a wildcard (DP-3), and this guard keeps
        // the invariant true for a config built in code rather than parsed —
        // so "exact host, last-wins" is the whole rule; no wildcard ever
        // reaches it.
        let mut winner_by_host: BTreeMap<String, usize> = BTreeMap::new();
        for (idx, e) in cfg.allow.iter().enumerate() {
            let host = normalize_policy_host(e.host());
            if !is_wildcard_host(&host) {
                winner_by_host.insert(host, idx); // later idx overwrites earlier
            }
        }
        for (host, idx) in &winner_by_host {
            let e = &cfg.allow[*idx];
            if e.declared_protocol() == Some(Protocol::Tcp) {
                for port in e.ports() {
                    passthrough.insert((host.clone(), port));
                }
            }
        }

        Self {
            inspect_ports,
            passthrough,
        }
    }

    /// Which of `ports` granting `host` would newly turn into pinning
    /// passthroughs — i.e. the ports that would land in the passthrough set
    /// only because an EXISTING entry for `host` already declares
    /// `protocol: tcp` (#235).
    ///
    /// Empty means the grant costs no inspection: either the host carries no
    /// declared hatch, or every named port already had one.
    ///
    /// The answer is computed by comparing this table BEFORE and AFTER a
    /// simulated `EgressPolicyConfig::allow`, so it is the same fold the
    /// datapath consults — deliberately NOT a second reading of
    /// `declared_protocol()`. The inspectability axis is computed in
    /// `InspectionTable` and nowhere else (CLAUDE.md, M5 P1); a caller that
    /// re-derived "is this host pinned?" for itself would be exactly the
    /// third, independent fold whose earlier appearance opened a live
    /// no-certificate-verification bypass. Going through `from_config` also
    /// inherits last-wins supersession and the wildcard exclusion for free.
    pub fn widening_ports(cfg: &EgressPolicyConfig, host: &str, ports: &[u16]) -> Vec<u16> {
        let before = Self::from_config(cfg);
        let mut after_cfg = cfg.clone();
        for &port in ports {
            after_cfg.allow(host, port);
        }
        let after = Self::from_config(&after_cfg);
        ports
            .iter()
            .copied()
            .filter(|&port| {
                !before.passthrough_host(host, port) && after.passthrough_host(host, port)
            })
            .collect()
    }

    /// Whether a connection to `port` is terminated and policed at L7.
    pub fn inspects(&self, port: u16) -> bool {
        self.inspect_ports.contains(&port)
    }

    /// Whether `host` on `port` carries the operator's explicit pinning
    /// passthrough. `host` is the observed ClientHello SNI; it is normalized
    /// with the same identity the allow-list is keyed on (#170).
    pub fn passthrough_host(&self, host: &str, port: u16) -> bool {
        self.passthrough
            .contains(&(normalize_policy_host(host), port))
    }

    /// Whether any passthrough is declared at all. `router::passthrough_names`
    /// consults this (via `Policy::has_passthrough`) to short-circuit its
    /// candidate computation BEFORE any Rego evaluation (`decide_tier2`) for
    /// the overwhelmingly common policy that never writes `protocol: tcp`
    /// anywhere — keeping that path zero-cost. A second, independent
    /// short-circuit lives at a different layer: `mitm_runtime`'s per-flow
    /// accept loop only takes the larger `peek_client_hello` read when the
    /// CANDIDATE LIST `passthrough_names` already computed for this flow is
    /// non-empty — it does not re-consult this table method, since the
    /// candidate list is what actually gates the hatch.
    pub fn has_passthrough(&self) -> bool {
        !self.passthrough.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{Access, EgressPolicyConfig};

    fn table(yaml: &str) -> InspectionTable {
        InspectionTable::from_config(&EgressPolicyConfig::from_yaml(yaml).expect("parses"))
    }

    // --- #235: which ports a grant would newly turn into pinning passthroughs ---

    /// The exact reported sequence: an entry declaring `protocol: tcp` for
    /// [443], then `izba policy allow pinned.vendor.com:8080`. The new port
    /// lands in the passthrough set even though the operator only named the
    /// hatch for 443 — `widening_ports` is what lets the caller say so.
    #[test]
    fn adding_a_port_to_a_pinned_entry_is_reported_as_widening() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .expect("parses");
        assert_eq!(
            InspectionTable::widening_ports(&cfg, "pinned.vendor.com", &[8080]),
            vec![8080],
        );
    }

    /// A port whose inspectability is only DERIVED (no `protocol:` anywhere)
    /// is not the operator's hatch, so granting it costs nothing to announce.
    /// Guards an implementation that asked `protocol_for` (which derives
    /// `tcp` off the web ports) instead of the table's declared-only fold.
    #[test]
    fn adding_a_port_to_an_undeclared_entry_is_not_widening() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: plain.example.com\n    ports: [443]\n",
        )
        .expect("parses");
        assert!(
            InspectionTable::widening_ports(&cfg, "plain.example.com", &[8080]).is_empty(),
            "a derived tcp is a convenience, never a declared passthrough"
        );
    }

    /// A port the pinned entry ALREADY names was exempted by the operator, so
    /// re-granting it announces nothing new. Guards an implementation that
    /// echoed back every requested port on a pinned host.
    #[test]
    fn re_adding_a_port_the_pinned_entry_already_names_is_not_widening() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .expect("parses");
        assert!(
            InspectionTable::widening_ports(&cfg, "pinned.vendor.com", &[443]).is_empty(),
            "443 already carried the hatch the operator declared"
        );
    }

    /// A bare `izba policy allow <host>` grants BOTH web ports at once, so the
    /// report must cover every port of the grant, not just the first.
    #[test]
    fn a_bare_host_grant_reports_every_newly_pinned_port() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [8443]\n    protocol: tcp\n",
        )
        .expect("parses");
        assert_eq!(
            InspectionTable::widening_ports(&cfg, "pinned.vendor.com", &AllowEntry::DEFAULT_PORTS),
            vec![80, 443],
        );
    }

    /// A wildcard never registers a passthrough key (DP-3), so a grant against
    /// one can never widen the hatch. Guards an implementation that peeked at
    /// `declared_protocol()` directly and so skipped the wildcard exclusion
    /// `from_config` applies.
    #[test]
    fn a_wildcard_host_grant_is_never_widening() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "*.vendor.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Tcp),
            }],
            git: vec![],
        };
        assert!(
            InspectionTable::widening_ports(&cfg, "*.vendor.com", &[8080]).is_empty(),
            "a wildcard holds no passthrough key to widen"
        );
    }

    /// The M5 P1 review's finding-1 shape: an earlier `protocol: tcp` entry
    /// superseded by a later plain one for the same exact host. The winning
    /// entry declares nothing, so the grant is not a widening — an
    /// implementation that scanned for ANY matching entry would report one.
    #[test]
    fn a_superseded_tcp_declaration_is_not_a_widening() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [9999]\n",
        )
        .expect("parses");
        assert!(
            InspectionTable::widening_ports(&cfg, "pinned.vendor.com", &[8080]).is_empty(),
            "the winning entry for this host declares no hatch to widen"
        );
    }

    // DP-1: the axis may only WIDEN against today's `matches!(port, 80 | 443)`.
    #[test]
    fn web_ports_are_inspected_even_when_no_entry_names_them() {
        let t = table("enforce: true\nallow:\n  - host: db.internal\n    ports: [5432]\n");
        assert!(t.inspects(80), "the 80/443 baseline is unconditional");
        assert!(t.inspects(443), "the 80/443 baseline is unconditional");
        assert!(!t.inspects(5432), "a derived-tcp port is not inspected");
    }

    #[test]
    fn a_declared_http_port_becomes_inspected() {
        let t = table(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        assert!(t.inspects(8000));
    }

    // The hatch is host-keyed, so it must NOT remove the port from the
    // inspected set — another host may still need L7 on it.
    #[test]
    fn an_explicit_tcp_entry_does_not_uninspect_its_port() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(t.inspects(443), "443 stays inspected for every other host");
        assert!(t.passthrough_host("pinned.vendor.com", 443));
    }

    #[test]
    fn passthrough_is_scoped_to_the_declared_ports() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(
            !t.passthrough_host("pinned.vendor.com", 80),
            "port 80 was not declared"
        );
    }

    // DP-5: only an EXPLICIT declaration opens the hatch (D12).
    #[test]
    fn a_derived_tcp_never_opens_the_hatch() {
        let t = table("enforce: true\nallow:\n  - host: db.internal\n    ports: [5432]\n");
        assert!(
            !t.passthrough_host("db.internal", 5432),
            "an omitted protocol is a derivation, not an operator decision"
        );
    }

    #[test]
    fn passthrough_matching_uses_the_policy_host_normalization() {
        let t = table(
            "enforce: true\nallow:\n  - host: Pinned.Vendor.COM\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(
            t.passthrough_host("pinned.vendor.com", 443),
            "case-insensitive"
        );
        assert!(
            t.passthrough_host("pinned.vendor.com.", 443),
            "trailing dot stripped"
        );
    }

    // The trap this catches: a derived Default would be an EMPTY port set, and
    // `RegoPolicy::embedded()` / `with_data()` — both test-only constructors,
    // used by the whole existing test suite, but also the shape any future
    // production caller of `with_data` would inherit — would stop inspecting.
    #[test]
    fn the_default_table_is_the_pre_m5_baseline_not_an_empty_set() {
        let t = InspectionTable::default();
        assert!(t.inspects(80) && t.inspects(443));
        assert!(!t.inspects(8000));
        assert!(!t.has_passthrough());
    }

    /// The two statements of "which ports are HTTP by default" must agree:
    /// this table's unconditional baseline (policy-global, DP-1) and
    /// `Protocol::implied_for_port` (per-entry, the grammar's implicit
    /// default). They are different facts over the same constant, and this
    /// PR's review flagged exactly that pairing as drift-prone — so the
    /// agreement is asserted rather than assumed. If someone widens the
    /// baseline without widening the implied rule (or vice versa), this fails.
    #[test]
    fn baseline_agrees_with_the_implied_rule() {
        let t = InspectionTable::default();
        for port in AllowEntry::DEFAULT_PORTS {
            assert_eq!(
                Protocol::implied_for_port(port),
                Protocol::Http,
                "port {port} is in the baseline, so an undeclared entry on it must imply http"
            );
            assert!(t.inspects(port), "port {port} must be in the baseline");
        }
        // And the converse, so the test cannot pass by admitting everything.
        for port in [22u16, 8000, 5432, 15001] {
            assert_eq!(Protocol::implied_for_port(port), Protocol::Tcp);
            assert!(!t.inspects(port));
        }
    }

    #[test]
    fn an_unknown_host_never_passes_through() {
        let t = table(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(!t.passthrough_host("evil.example.com", 443));
    }

    // Review round 1, finding 1: `from_config`'s `&& !is_wildcard_host(&host)`
    // guard has no test that can actually reach it through `table(...)`, since
    // every YAML-driven wildcard-plus-`protocol: tcp` entry is refused at
    // parse time by DP-3 (`parse_allow_entry`) before `from_config` ever sees
    // it. `AllowEntry::Scoped`'s fields are public, so the only way to reach
    // the guard is to hand-construct the config in Rust — the same necessity
    // that produced Task 1's
    // `wildcard_collapse_never_propagates_a_hand_constructed_tcp_declaration`
    // (`config.rs`). Do NOT "simplify" this into a `from_yaml`/`table(...)`
    // test: that would silently drop the coverage, since the parser refuses
    // the input before this code path is ever exercised.
    #[test]
    fn a_hand_constructed_wildcard_tcp_declaration_never_opens_the_hatch() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "*.vendor.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: Some(Protocol::Tcp),
            }],
            git: vec![],
        };
        let t = InspectionTable::from_config(&cfg);
        assert!(
            !t.passthrough_host("anything.vendor.com", 443),
            "a wildcard host must never register a passthrough key, even hand-constructed"
        );
        assert!(
            !t.has_passthrough(),
            "no passthrough key at all should have been registered — pins the absence \
             of the key, not just one lookup missing it"
        );
    }

    // M5 P1 review, task 3, finding 1: `EgressPolicyConfig` does not collapse
    // duplicate exact hosts at parse time (`from_yaml` never calls
    // `collapse_duplicate_hosts` — only the mutation methods do), so two
    // entries naming the SAME exact host can reach `from_config` unmerged.
    // `to_rego_data_json` compiles those into `sandbox_host_rules`, a JSON MAP
    // keyed by normalized host — the LAST entry's `Map::insert` overwrites the
    // FIRST's `{ports, access}` wholesale. The reviewer's exact reproduction:
    // an early entry declares `protocol: tcp` on port 443, a LATER entry for
    // the same host declares a different port with no protocol at all (so the
    // 443/tcp declaration is entirely superseded), and a third, unrelated
    // entry allow-lists the address itself as a raw IP on port 443. Before
    // this fix, `passthrough` UNIONED across entries, so
    // `passthrough_host("pinned.vendor.com", 443)` answered `true` even
    // though the host's WINNING entry never declared `protocol: tcp` for
    // port 443 at all — `RegoPolicy::check` denies that exact (host, port),
    // while `decide_tier2` still allows the FLOW via the unrelated raw-IP
    // rule. Only `router::passthrough_names`'s per-name `policy.check` filter
    // caught this before; now `from_config` itself never produces the stale
    // key.
    #[test]
    fn a_later_duplicate_host_entry_supersedes_an_earlier_tcp_declaration() {
        let t = table(
            "enforce: true\n\
             allow:\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [443]\n\
             \x20   protocol: tcp\n\
             \x20 - host: pinned.vendor.com\n\
             \x20   ports: [9999]\n\
             \x20 - host: 1.2.3.4\n\
             \x20   ports: [443]\n",
        );
        assert!(
            !t.passthrough_host("pinned.vendor.com", 443),
            "the winning (last) entry for this host never declared protocol: tcp \
             on port 443 — the superseded first entry's declaration must not survive"
        );
        assert!(
            !t.has_passthrough(),
            "no exact host in this config has a live protocol: tcp declaration"
        );
    }
}
