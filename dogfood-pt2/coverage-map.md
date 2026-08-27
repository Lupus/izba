# Coverage map — per-port `protocol:` inspectability / TLS-pinning passthrough (run 2)

Feature tip: `481dbe27` (branch `dogfood-fixes/passthrough-docs`, PR #264's head) —
31 commits ahead of `main`, carrying #233 + #238 + #239/PR #262 **plus** every
in-place doc/help/GUI honesty fix that the 2026-08-26 campaign
(`dogfood-passthrough/`) produced.

Anchors read while compiling (privileged — none of this reaches the swarm):
`CLAUDE.md`'s "Inspectability is DECLARED per PORT" block;
`docs/superpowers/plans/2026-08-18-m5-p1-inspectability.md`;
`docs/superpowers/plans/2026-08-25-gui-passthrough-host-lock.md`;
`crates/izba-core/src/daemon/egress/{config,inspect,router,mitm_runtime,audit}.rs`;
`crates/izba-cli/src/commands/{policy,diff,netlog}.rs`;
`crates/izba-core/src/manifest/{diff,promote}.rs`;
`app/src/components/{PolicyEditor,EnforceToggle,NetlogView}.tsx`;
the in-place fix commits `4656462b`, `b7580a3f`, `415b6131`, `63c26d99`,
`2ba19121`, `f21a4dfe`, `db009e31`, `e0d6010e`, `26551393`, `aeabe172`,
`094ff190`; and the prior campaign's four skeptic verdicts.

**43 journeys: 6 smoke / 19 core / 18 deep · 34 CLI / 9 GUI.**

The fair-test surface handed to the swarm is `dogfood-pt2/context-pack.md`
(README + recursive `--help`, regenerated from this tip's binary). The GUI
surface is `dogfood-app-guide.md` + README.

---

## What changed versus run 1, and why

Run 1's headline was that **0 of 32 deep candidates survived triage as a product
bug**, while its single real P1 came from auditing a *passing* journey. Three
structural weaknesses caused that, and this set is compiled against all three:

1. **The CLI Actor discarded the journey-level `seed_files` fixture in 11 of 11
   CLI journeys**, so most reds were "the fixture the oracle grades was never on
   disk". *Response:* **no CLI journey in this set ships `seed_files` at all.*
   Every CLI journey asks the user to *author* the policy file or `izba.yml`
   from what the docs say — which is simultaneously the documentation test this
   run is for — and is graded on izba's own managed truth
   (`expect_state.policy`) plus `expect_stdout_re`/`expect_stderr_re` on the
   product's own words. `seed_files` survives only on the 9 GUI journeys, where
   run 1 proved the seeded workspace *does* reach managed truth
   (`state_evidence.per_sandbox.pin-gui*.policy_yaml`).
2. **Docs-only journeys had no answer channel** — Actors burned their whole
   budget `cat`-ing README copies that are already in their system prompt.
   *Response:* there are **no "find the doc" journeys**. Every documentation
   promise is probed as a *task the user can only complete if the doc says the
   right thing*, graded on a product action
   (`smoke-find-the-surface-that-answers-bypass`,
   `core-an-older-policy-file-keeps-its-meaning`,
   `core-inspection-may-be-asked-for-on-a-wildcard`).
3. **The five datapath journeys pointed at hosts that could not resolve**, so an
   absent netlog row was indistinguishable from "the client never ran".
   *Response:* the datapath journeys use **`example.com` / `example.net`** (real,
   public, TLS-serving) on the **`alpine:3.20`** image, whose busybox `wget`
   verifies TLS with no package install under enforce, and each is graded on a
   **positive** netlog assertion that discriminates the two outcomes
   (`ALLOW l3 … example.com:443` = spliced vs `ALLOW l7 … example.com:443` =
   terminated and inspected). The behaviour was reproduced deterministically on
   a real VM in `094ff190`; per the "e2e never subtracts journeys" rule the
   journeys stay, because the swarm reaching them from the docs alone is the
   differential this method measures.

Run 1's per-tier corrections (from `skeptic-verdict-deep.json`'s
`deep-datapath-and-lock-journeys-do-not-exercise-their-promise`) are each
applied:

| Run-1 correction | Applied in |
| - | - |
| "build the A/B: same host, same port, differing only by the declaration" | `deep-pinned-host-reaches-its-own-tls-untouched` + `deep-the-same-host-without-the-declaration-is-inspected` |
| "a *loses inspection* fixture is only valid if the removed entry declares `protocol: http` on a NON-web port" | `deep-review-flags-losing-inspection-on-a-shared-port` (two hosts sharing **8443**, one declaring http) |
| "the *new exception* journey needs a base asserting `pinned:false` and a drift that adds no new (host,port) and no widened access" | `deep-review-flags-a-new-exception-as-weakening` (step 1 asserts `enforcing:true` + `access:read-write` + `443 pinned:false`; step 2 changes only the declaration) |
| "make the Access click decisive" | `gui-cannot-activate-a-dormant-exception` — the widening is paired with a *legitimate* edit so the Save really lands, and the refusal is graded as `access:"read"` surviving in the saved policy |
| "drop the mandatory Save from the rename journey / grade the saved policy" | `gui-cannot-move-the-exception-to-another-host` — the Save is now genuine (it carries a legitimate second edit) and is graded on `moved.vendor.example present:false` plus the original host still carrying the declaration |

---

## Promise → journey

### A. Declaration & parse (`config.rs`)

| # | Promise (anchor) | Journey(s) |
| - | - | - |
| A1 | A policy file is accepted at `create` and read back (capability floor) | `smoke-firewall-file-accepted-at-create` **(gating)** |
| A2 | An explicit `protocol: tcp` on an EXACT host, on one named port, is the pinning passthrough (README example; `--policy` help) | `smoke-declare-a-pinning-exception` **(gating)** |
| A3 | A bare port number declares nothing and is inspected (`PortSpec::bare`; CLAUDE.md) | `core-a-granted-port-does-not-inherit-the-exception`, `deep-the-same-host-without-the-declaration-is-inspected` |
| A4 | `protocol: tcp` on a wildcard host is a parse error naming the fix (`parse_allow_entry`; "Name each pinned host explicitly") | `core-refuse-pinning-on-a-wildcard-host` |
| A5 | `protocol: http` on a wildcard IS accepted — the axis may only widen | `core-inspection-may-be-asked-for-on-a-wildcard` |
| A6 | An unknown `protocol:` value is refused naming `'http' or 'tcp'` (`parse_protocol`) | `core-refuse-an-unknown-declaration-value` |
| A7 | An unknown key in a port mapping is refused naming `port, protocol` (`parse_port_spec`) | `core-refuse-a-typo-in-the-port-mapping` |
| A8 | One port listed twice with conflicting declarations is refused naming both (`dedup_port_specs`, `f21a4dfe`/#260) | `core-refuse-one-port-declared-two-ways` |
| A9 | The pre-#238 ENTRY-level `protocol:` still parses and normalizes down onto the entry's ports, preserving posture | `core-an-older-policy-file-keeps-its-meaning` |
| A10 | `protocol: http` polices a non-web port at L7 | `core-police-an-unusual-port-at-http` |
| A11 | The declaration rides `spec.egress` in `izba.yml` verbatim | the four `deep-review-*` / `deep-promote-*` journeys; all 9 GUI journeys (seeded manifests) |
| A12 | A hand-edited managed `policy.yaml` + `reload` is the documented authoring route, and `reload` names the file it read (`db009e31`) | `core-edit-the-managed-file-and-reload` |

### B. Non-inheritance — the structural promise of #238

| # | Promise | Journey(s) |
| - | - | - |
| B1 | `izba policy allow HOST:PORT` on a host with a pinned port adds a BARE port (`EgressPolicyConfig::allow`; `policy allow` help states it verbatim) | `core-a-granted-port-does-not-inherit-the-exception` |
| B2 | The GUI mutator behaves identically — a port added in the app carries no declaration, and Save never drops the existing one | `gui-adding-a-port-here-never-inherits-the-exception` |
| B3 | Observed-traffic seeding (`izba policy enable`) goes through the same mutator | `deep-seeding-from-observed-traffic-keeps-the-declaration` |
| B4 | An unrelated grant neither drops nor relocates a declaration | `core-declaration-survives-an-unrelated-grant` |
| B5 | The asymmetry: an exemption can be retired from the CLI even though it cannot be authored there | `core-retire-the-exception-from-the-command-line` |

### C. The audit surface (`render_policy`) — and the honesty fixes on it

| # | Promise | Journey(s) |
| - | - | - |
| C1 | `policy show` is loud about a live passthrough and names **the certificate-verification loss** (`4656462b`) | `smoke-declare-a-pinning-exception` (`expect_stdout_re: no upstream certificate verification`) |
| C2 | The marker is rendered against the specific PORT, not the host | `core-police-an-unusual-port-at-http`, `core-an-older-policy-file-keeps-its-meaning`, `core-a-granted-port-does-not-inherit-the-exception` |
| C3 | A pinned port on a narrower-than-read-write row renders "NOT in effect … widen to read-write to pin" | `core-audit-surface-under-a-narrower-access` |
| C4 | With `enforce: false` the posture reported is "all egress allowed … not in force" and the declaration is **inert**, not a hole (`415b6131` CORE-1) | `core-firewall-off-does-not-read-as-one-hole` |
| C5 | A policy that declares nothing renders with no added noise | `core-a-plain-policy-renders-without-warnings` |
| C6 | `policy allow --read` narrows the WHOLE entry and the grant echo says so at the moment it happens (`415b6131` CORE-2) | `core-narrowing-access-says-the-exception-went-dormant` |
| C7 | `policy show` (or the desktop Policy tab) is the surface that answers "is anything bypassing my firewall?"; `izba status` answers nothing (`b7580a3f`) | `smoke-find-the-surface-that-answers-bypass` |

### D. Datapath (`router.rs`, `inspect.rs`, `mitm_runtime.rs`)

| # | Promise | Journey(s) |
| - | - | - |
| D0 | An enforcing sandbox boots and reaches an allowed host, and izba logs it (capability floor) | `smoke-enforcing-sandbox-can-reach-an-allowed-site` **(gating)** |
| D1 | A pinned host+port is spliced opaquely — logged as tier `l3`, `passthrough (protocol: tcp)` | `deep-pinned-host-reaches-its-own-tls-untouched` |
| D2 | The same host+port with no declaration is terminated and inspected — logged as tier `l7` | `deep-the-same-host-without-the-declaration-is-inspected` |
| D3 | An explicit `tcp` entry does NOT un-inspect its port for other hosts | `deep-two-hosts-one-port-only-one-passes-through` |
| D4 | A dormant (`access: read`) declaration really stays intercepted — the wording and the datapath agree | `deep-dormant-exception-really-stays-intercepted` |
| D5 | The hatch is bound to a DNS-snooped name, never a guest-chosen address | `deep-exception-does-not-follow-a-raw-address` |
| D6 | A declaration applies to a running sandbox on reload, no restart | `deep-declaration-applies-without-a-restart` |
| D7 | The declaration survives a stop/start cycle and the firewall is still on afterwards | `deep-declaration-survives-a-restart` |

### E. The weakening gate (`manifest::diff::egress_weakens`, `promote.rs`)

| # | Promise | Journey(s) |
| - | - | - |
| E1 | A newly-declared passthrough is flagged `⚠ weakens egress` even though no host, port or access changed | `deep-review-flags-a-new-exception-as-weakening` |
| E2 | A still-reachable port losing global inspection is flagged, even though the change only *removes* a host | `deep-review-flags-losing-inspection-on-a-shared-port` |
| E3 | Retiring a passthrough is NOT flagged (the warning has to mean something) | `deep-review-is-quiet-when-the-posture-tightens` |
| E4 | The reviewed route works end to end and `promote` warns on stderr | `deep-promote-the-exception-through-the-review-gate` |
| E5 | `promote` refuses an unreviewed weakening, naming the skipped step | `deep-promote-refuses-without-a-review` |
| E6 | `izba policy allow` deliberately bypasses that gate — observable as the managed side drifting ahead of `izba.yml` | `core-command-line-grants-skip-the-review-gate` |

### F. Desktop app (#239 / PR #262 / PR #264)

| # | Promise | Journey(s) |
| - | - | - |
| F0 | The Policy tab loads a real posture before claiming one (`e0d6010e`) | `smoke-gui-policy-tab-reports-a-real-posture` **(gating)** |
| F1 | A pinned port renders with a VISIBLE marker carrying the CLI's substance, including the certificate loss | `smoke-gui-policy-tab-reports-a-real-posture` |
| F2 | `http` and undeclared ports render without that marker; the marker names the port | `gui-only-the-declared-port-is-marked` |
| F3 | The dormant variant is rendered as NOT in effect (GUI/CLI must not disagree) | `gui-dormant-exception-is-not-claimed-as-live` |
| F4 | A declaration on a non-enforcing sandbox renders as **inert**, in the CLI's order (`63c26d99`) | `gui-inert-when-the-firewall-is-off` |
| F5 | The Host input of a pinned row is locked and the rename is refused in the reducer, surviving a real Save | `gui-cannot-move-the-exception-to-another-host` |
| F6 | Access may be tightened but never widened into `read-write` on a pinned row | `gui-cannot-activate-a-dormant-exception` |
| F7 | Removing the pinned port unlocks both restrictions | `gui-removing-the-exempt-port-unlocks-the-row` |
| F8 | The editor authors nothing: a port added here is plain, and Save never drops the declaration | `gui-adding-a-port-here-never-inherits-the-exception` |
| F9 | Switching sandboxes never presents one sandbox's posture under another's name (`26551393`, `aeabe172`) | `gui-switching-sandboxes-never-shows-the-previous-posture` |

---

## Tier / capability wiring

**Capability vocabulary (10 tokens):** `firewall-file-accepted`,
`posture-readable`, `hatch-declared`, `hatch-revealed`,
`audit-surface-discoverable`, `manifest-egress-authoring`, `hatch-via-manifest`,
`enforcing-sandbox-reaches-an-allowed-host`, `gui-policy-tab-loads`,
`gui-pinned-row-visible`.

**Gating (4, deliberately few):**

- `smoke-firewall-file-accepted-at-create` → `firewall-file-accepted`,
  `posture-readable`. If a user cannot hand izba a policy file and read it back,
  nothing below means anything.
- `smoke-declare-a-pinning-exception` → `hatch-declared`, `hatch-revealed`.
  27 journeys presuppose that a per-port declaration can be authored from the
  docs at all; if that fails, it is one finding, not 27.
- `smoke-enforcing-sandbox-can-reach-an-allowed-site` →
  `enforcing-sandbox-reaches-an-allowed-host`. The datapath floor behind all
  seven deep datapath journeys. A booted-VM budget spent proving the same
  blocker seven times is the failure mode this gate exists to prevent.
- `smoke-gui-policy-tab-reports-a-real-posture` → `gui-policy-tab-loads`,
  `gui-pinned-row-visible`. The seeded-manifest → Policy-tab route behind the
  other 8 GUI journeys.

Every `requires` token is established by a journey in a strictly earlier-or-equal
tier (checked programmatically). `hatch-revealed`,
`audit-surface-discoverable` and `hatch-via-manifest` are established but not
required by anything: they are reporting handles for the skeptic, because a
documentation gap is a finding, never a reason to defer functional coverage.

---

## Deliberately NOT covered, and why

Everything in this section is a conscious omission, most of it because run 1
already settled it.

1. **`InspectionTable` being the single fold; `to_rego_data_json` byte-identity;
   `router::passthrough_names`'s second `check` filter.** Internal-structure
   promises with no user-observable surface; unit/guard-tested. Probing them
   through the swarm would require leaking source knowledge into `intent`.
2. **ClientHello robustness (`peek_sni` totality: truncation, record
   fragmentation, absent SNI, hostile bytes).** Reachable only by writing a
   malformed TLS client inside the guest — an adversarial-code exercise, not a
   user journey. The fail-closed direction is exhaustively unit-tested.
3. **`izba status` rendering no egress posture.** Run 1 recorded this correctly:
   asserting "X never appears in an unrelated command" is a trivially-true
   journey (the known false-green class). The *useful* half — can a user find
   the surface that DOES answer? — is covered positively by
   `smoke-find-the-surface-that-answers-bypass`.
4. **"An exemption for a host the firewall never allows grants no reach"**
   (run 1's `deep-exception-for-a-host-never-allowed`). Run 1 verified nothing
   here and the reason is structural: declaring the host in the allow-list *is*
   allowing it, so the journey degenerates into a plain deny test with no
   differential attributable to this feature.
5. **Issue #261 (`replace_allow` persisting a lone wildcard + `tcp`).** Still
   LATENT behind the Host lock on this tip — there is no user-visible route to
   it, so a journey would fail for the wrong reason or require prescribing an
   internal call. Left to the skeptic as a known open item.
6. **Concurrency (a policy reload racing a config edit, `sandbox is busy`).**
   Belongs to the `edit_sandbox_config` contract, not to this feature; this
   feature adds no config-edit verb.
7. **Credential injection wording.** `4656462b` removed the "no credential
   injection" clause that advertised an M5 P2 capability; there is nothing left
   to verify and nothing to flag.
8. **Windows/OpenVMM parity for the egress datapath.** Platform-orthogonal; the
   deep journeys are written platform-neutrally and run wherever the swarm runs.
9. **`izba netlog --follow` never returning** (run 1's DEEP-3, fixed in
   `db009e31` as help text). Covered only implicitly: every netlog-grading step
   carries `expect_cmd_re: izba netlog`, and the runner now reaps a timed-out
   process group, so a `--follow` hang is visible as harness evidence rather
   than needing its own journey.
10. **The `--summary` rendering of the audit log.** The tier token (`l3`/`l7`)
    is identical in both forms, so every datapath assertion holds whichever the
    Actor picks; a dedicated `--summary` journey would add cost and no signal.

---

## Grading-hook inventory (what makes each decisive step decisive)

- **`expect_state.policy`** (the sandbox's managed `policy.yaml` — host-only
  authority, never the rendered text) is the primary oracle on **33 of the 67** decisive
  steps. It is the only machine-checkable answer to "the refusal held" and to
  "the declaration is attached to *this* port".
- **`expect_stdout_re`** grades izba's own words where the *voice* is the promise
  (`no upstream certificate verification`, `widen to read-write to pin`,
  `declaration is inert`, `re-grant without --read to restore it`,
  `:8443 protocol: http (inspected)`, `reloaded egress policy for '…' from
  …policy.yaml`, `ALLOW l3|l7 … example.com:443`,
  `egress:  [live]  ⚠ weakens egress`, and — as a genuine negative-as-positive —
  `egress:  [live]\n` for the "review stays quiet" journey).
- **`expect_stderr_re`** grades the four refusals whose message is the product
  (`needs an exact host`, `expected 'http' or 'tcp'`,
  `valid keys: port, protocol`, `listed twice with different declarations`) and
  the two review-gate voices (`WARNING: weakens egress`, `no reviewed diff`).
- **`expect_cmd_re`** is set on every decisive step, anchored to a full product
  invocation (`izba policy show`, `izba policy allow`, `izba diff`,
  `izba promote`, `izba netlog`, `izba (create|run|policy reload)`) and never to
  a bare token, so a trailing verify command cannot capture the verdict and a
  decisive assertion satisfied earlier can be credited rather than flagged
  `unreached_decisive`.
- **GUI** decisive steps carry `expect_text` on an *outcome* string only
  (`no upstream certificate verification`, `Port 443: TLS-pinning passthrough`,
  `access never authorizes one`, `this declaration is inert until enforcement is
  turned on`, `widening Access to read-write here is refused`,
  `saved · reloaded`, `open.other.example`) — never a heading, tab or button
  label — composed with `expect_state.policy`, which the DOM cannot express.
