# Coverage map — per-port `protocol:` inspectability / TLS-pinning passthrough

Feature tip: `314925ef` (branch `fix/gui-passthrough-host-lock`), carrying #233 +
#238 + #239/PR #262.

Anchors read while compiling (privileged — never exposed to the swarm):
`docs/superpowers/plans/2026-08-18-m5-p1-inspectability.md`,
`docs/superpowers/plans/2026-08-25-gui-passthrough-host-lock.md`,
`CLAUDE.md`'s "Inspectability is DECLARED per PORT" paragraph,
`crates/izba-core/src/daemon/egress/{config,inspect,router}.rs`,
`crates/izba-cli/src/commands/policy.rs`, `crates/izba-core/src/manifest/diff.rs`,
`app/src/components/PolicyEditor.tsx`, issues #238/#239/#261, PR #262.

39 journeys: 6 smoke / 14 core / 19 deep; 31 CLI / 8 GUI.

## Promise → journey

### A. Declaration & parse (#233 + #238, `config.rs`)

| # | Promise (anchor) | Journey(s) |
| - | - | - |
| A1 | A port may carry `protocol: http` — a non-web port is then policed at L7 (`InspectionTable::from_config`; README example) | `core-police-a-non-web-port`, `core-inspection-may-be-asked-for-on-a-wildcard` |
| A2 | An explicit `protocol: tcp` on an exact host is the pinning passthrough (DP-5, D12) | `smoke-declare-pinned-port-accepted`, `deep-pinned-host-keeps-the-vendor-certificate` |
| A3 | A bare port number declares nothing and is inspected (`PortSpec::bare`, CLAUDE.md) | `smoke-docs-bare-port-is-inspected`, `core-show-attributes-declaration-to-its-port` |
| A4 | `protocol: tcp` on a wildcard host is a parse error naming the fix (DP-3, `parse_allow_entry`) | `core-refuse-pinning-on-a-wildcard-host` |
| A5 | `protocol: http` on a wildcard IS accepted (widening only) | `core-inspection-may-be-asked-for-on-a-wildcard` |
| A6 | An unknown `protocol:` value is refused naming `'http' or 'tcp'` (`parse_protocol`) | `core-refuse-an-unknown-protocol-value` |
| A7 | An unknown key inside a port mapping is refused naming `port, protocol` (`parse_port_spec`) | `core-refuse-a-typo-in-the-port-mapping` |
| A8 | One port listed twice with conflicting declarations is refused naming both (`dedup_port_specs`, #260) | `core-refuse-one-port-declared-two-ways` |
| A9 | The pre-#238 ENTRY-level `protocol:` key still parses and normalizes down onto that entry's ports, preserving posture (#238 back-compat) | `core-older-entry-level-declaration-still-works` |
| A10 | A declaration round-trips: an undeclared port stays a bare number in the persisted file | `core-declaration-survives-an-unrelated-cli-edit`, `gui-saving-an-unrelated-edit-preserves-the-declaration` |
| A11 | The declaration rides `spec.egress` in `izba.yml` verbatim (DP-7) | `core-author-the-exception-through-the-review-flow`, all 8 GUI journeys (seeded manifests) |
| A12 | A `--policy` file is accepted at `create`/`run` (capability floor) | `smoke-create-with-policy-file` (gating) |

### B. Non-inheritance (#238 — the structural promise)

| # | Promise | Journey(s) |
| - | - | - |
| B1 | `izba policy allow HOST:PORT` on a host with a pinned port adds a BARE (inspected) port (`EgressPolicyConfig::allow`, `policy allow --help`) | `core-granting-a-port-does-not-inherit-the-exception` |
| B2 | The same holds for the GUI mutator: a port added in the Policy tab carries no declaration (`addPort`, #238) | `gui-saving-an-unrelated-edit-preserves-the-declaration` |
| B3 | An unrelated CLI edit (allow/block elsewhere) neither drops nor relocates a declaration | `core-declaration-survives-an-unrelated-cli-edit` |
| B4 | The set of pinned ports is exactly the set someone wrote one for (CLAUDE.md) | B1 + B2 + B3 + `core-show-attributes-declaration-to-its-port` |

### C. Rendering / the audit surface (`render_policy`)

| # | Promise | Journey(s) |
| - | - | - |
| C1 | `policy show` marks a declared `http` port as inspected | `core-police-a-non-web-port` |
| C2 | `policy show` is LOUD about a live passthrough and names what it gives up | `smoke-declare-pinned-port-accepted` |
| C3 | The marker is rendered against the specific PORT, not the host (#238) | `core-show-attributes-declaration-to-its-port` |
| C4 | A policy declaring nothing renders with no added noise | `core-show-stays-quiet-for-a-plain-policy` |
| C5 | A pinned port on an entry narrower than `read-write` renders the "NOT in effect … widen to read-write to pin" variant | `core-pinned-port-under-read-only-access` (+ wire check in `deep-dormant-exception-still-intercepts`) |
| C6 | With `enforce: false` the posture reported is "all egress allowed", not a firewall with one hole | `core-declared-exception-with-the-firewall-off` |
| C7 | `policy show` (and the desktop Policy tab) are the only revealing surfaces; `izba status` renders no egress posture | probed indirectly by `smoke-docs-find-authoring-surface` + flag **D7**; NOT asserted as an `izba status` negative (see "Not covered") |

### D. Datapath (`router.rs`, `inspect.rs`, `mitm_runtime.rs`)

| # | Promise | Journey(s) |
| - | - | - |
| D1 | A pinned host reaches its own upstream unterminated — the client sees the vendor's certificate | `deep-pinned-host-keeps-the-vendor-certificate` |
| D2 | An explicit `tcp` entry does NOT un-inspect its port for other hosts | `deep-two-hosts-one-port-only-one-passes-through` |
| D3 | The hatch is bound to a DNS-snooped name, never a guest-chosen address: a raw-IP dial never splices (DP-2) | `deep-exception-does-not-follow-a-raw-address` |
| D4 | A dormant (`access: read`) declaration really does not pass anything through (`passthrough_names`'s per-name `check` filter) | `deep-dormant-exception-still-intercepts` |
| D5 | Passthrough is a subset of tier-2 reachability — declaring one never grants reach | `deep-exception-for-a-host-never-allowed` |
| D6 | A declaration applies to a running sandbox on reload, no restart | `deep-declare-the-exception-on-a-running-sandbox` |
| D7 | The declaration survives a stop/start cycle | `deep-declaration-survives-a-restart` |

### E. The weakening gate (`manifest::diff::egress_weakens`)

| # | Promise | Journey(s) |
| - | - | - |
| E1 | A newly-declared passthrough is flagged `⚠ weakens egress` | `deep-review-flags-a-new-exception-as-weakening` |
| E2 | A still-reachable port losing global inspection is flagged | `deep-review-flags-losing-inspection-on-a-shared-port` |
| E3 | Removing a passthrough / declaring an already-implied `http` is NOT flagged | `deep-review-is-quiet-when-posture-tightens` |
| E4 | `izba policy allow` deliberately bypasses that gate (CLAUDE.md) | `deep-command-line-grants-skip-the-review-gate` |
| E5 | The manifest path is the gated authoring route | `core-author-the-exception-through-the-review-flow`, `smoke-manifest-egress-review-available` |

### F. Desktop app (#239 / PR #262)

| # | Promise | Journey(s) |
| - | - | - |
| F1 | A pinned port renders with a VISIBLE marker (not only an aria-label), carrying the CLI's substance | `gui-pinned-port-is-visible-in-the-policy-tab` |
| F2 | `http` and undeclared ports render without that marker; the marker names the port | `gui-only-the-declared-port-is-marked` |
| F3 | The dormant variant is rendered as NOT in effect (GUI/CLI must not disagree) | `gui-dormant-exception-is-not-claimed-as-live` |
| F4 | The Host input of a pinned row is read-only and the rename is refused in the reducer | `gui-cannot-move-the-exception-to-another-host` |
| F5 | Access may be tightened but not widened into `read-write` on a pinned row | `gui-cannot-activate-a-dormant-exception` |
| F6 | Save never drops or moves the declaration (AC-5 regression) | `gui-saving-an-unrelated-edit-preserves-the-declaration` |
| F7 | Removing the pinned port unlocks both restrictions (the escape valve) | `gui-removing-the-exempt-port-unlocks-the-row` |
| F8 | The editor authors nothing: no control can open a hatch, and the row names where one can be | `gui-app-cannot-author-a-new-exception` |

### G. Documentation / discoverability (Mandate 5 probes)

| # | Promise | Journey(s) |
| - | - | - |
| G1 | A user can learn the per-port shape and what `tcp` costs from README + `--help` | `smoke-docs-find-pinning-exception` |
| G2 | A user can learn there is NO CLI flag and where to declare it instead | `smoke-docs-find-authoring-surface` |
| G3 | A user can learn that a bare port is inspected and nothing inherits | `smoke-docs-bare-port-is-inspected` |

## Tier / capability wiring

- **Gating (2):** `smoke-create-with-policy-file` (`policy-file-at-create`,
  `policy-show-renders`) and `smoke-declare-pinned-port-accepted`
  (`hatch-declared`, `hatch-visible-in-show`). If a user cannot get a policy file
  in and see it back, everything below is noise.
- Capability tokens: `docs-explain-hatch`, `docs-name-authoring-path`,
  `docs-explain-non-inheritance`, `policy-file-at-create`, `policy-show-renders`,
  `hatch-declared`, `hatch-visible-in-show`, `manifest-egress-review`,
  `hatch-via-manifest`, `gui-pinned-row-visible`. Every `requires` is established
  by an earlier-tier journey (checked programmatically).
- The doc-probe smoke journeys establish tokens that no journey *requires* on
  purpose: a documentation gap is a finding, not a reason to defer functional
  coverage. (`docs-explain-hatch` / `docs-name-authoring-path` /
  `docs-explain-non-inheritance` are reporting handles for the skeptic.)
- The 8 GUI journeys all `require` `gui-pinned-row-visible`, established by
  `gui-pinned-port-is-visible-in-the-policy-tab`. If the seeded manifest → Promote
  → Policy-tab route does not work at all, the remaining 7 defer rather than each
  burning a full create+boot budget proving the same blocker.

## Deliberately NOT covered, and why

1. **`InspectionTable` being the single fold; `to_rego_data_json` byte-identity;
   `passthrough_names`'s second `check` filter.** Internal-structure promises with
   no user-observable surface. They are covered by unit/guard tests; asserting them
   through the swarm would require leaking source knowledge into `intent`.
2. **ClientHello robustness (`peek_sni` totality: truncation, record fragmentation,
   absent SNI, hostile bytes).** Reachable only by writing a malformed TLS client
   inside the guest — an adversarial-code exercise, not a user journey, and the
   fail-closed direction is already unit-tested exhaustively.
3. **Issue #261 (`replace_allow` persisting a lone wildcard + `tcp`).** Explicitly
   LATENT after the Host lock — there is no user-visible route to it on this tip,
   so a journey would either fail for the wrong reason or require prescribing an
   API call. Left to the skeptic as a known open item.
4. **`izba status` showing no egress posture.** A deliberate absence; asserting
   "X does not appear anywhere in an unrelated command" produces a trivially-true
   journey (the false-green class from the ledger). Recorded as flag **D7** instead.
5. **Concurrency (a policy reload racing a config edit / `sandbox is busy`).**
   Belongs to the `edit_sandbox_config` contract, not to this feature; no code in
   this feature adds a config-edit verb.
6. **Credential injection wording ("no credential injection" in the CLI line).**
   The capability it names does not exist yet (M5 P2), so there is nothing to
   verify — but the fact that the CLI advertises it *instead of* the certificate
   loss is recorded as flag **D1**.
7. **Windows/OpenVMM parity for the egress datapath.** Platform-orthogonal; the
   deep egress journeys are written platform-neutrally and run wherever the swarm
   runs.
8. **Observed-traffic seeding (`izba policy enable`) never inheriting a hatch.**
   Same structural promise as B1 through the same mutator; covered by B1 rather
   than duplicated with a journey that needs live traffic to seed from.
