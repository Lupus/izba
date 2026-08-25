# Predicted discoverability findings — per-port `protocol:` / TLS-pinning passthrough

Each entry is a gap between SHIPPED behaviour (anchor: privileged source) and the
FAIR-TEST surface the swarm gets (`context-pack.md` = README + recursive `--help`;
`dogfood-app-guide.md` for GUI runs). None of these were closed by editing the
context pack — the point is to see whether the swarm trips on them.

Severity: **P1** = a user can silently get the wrong security posture;
**P2** = a user cannot accomplish the task from the docs; **P3** = friction.

---

## D1 (P1) — the CLI's passthrough warning omits the loss that matters most, and advertises one that does not exist

**Shipped:** `crates/izba-cli/src/commands/policy.rs` renders
`⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules, no
request audit, **no credential injection**`.

**Surface:** the desktop app says `… no L7 rules, no request audit and **no
upstream certificate verification**` (`PolicyEditor.tsx::portDeclarationLabel`),
and README line 88 says only "spliced opaquely — no L7 rules, no request audit."

So the single most security-relevant consequence — **izba stops verifying the
upstream certificate** (DP-2: "a passthrough has no upstream certificate
verification by construction") — appears on the GUI and nowhere on the CLI or in
the README. In its place the CLI names "no credential injection", a capability
that does not ship until M5 P2 and means nothing to a user today.

**Should have said it:** `render_policy`'s `Some(Protocol::Tcp)` live branch and
the README example comment. Issue #239 AC-2 explicitly requires the GUI wording to
match the CLI "in substance"; the two disagree in the direction that matters.

Journeys that will surface it: `smoke-docs-find-pinning-exception` (step 2),
`smoke-declare-pinned-port-accepted`, `gui-pinned-port-is-visible-in-the-policy-tab`.

---

## D2 (P1) — the dormant-hatch rule (access must be `read-write` to pin) is documented nowhere a user would look

**Shipped:** a `protocol: tcp` port on an entry whose `access` is narrower than
`read-write` never pins — `router::passthrough_names`'s per-name `policy.check`
filter drops it, so the flow stays terminated and a pinning client still sees
izba's certificate. Both `render_policy` and `PolicyEditor` have a whole
NOT-in-effect branch for it, and PR #262 calls the reverse transition an
"activation" worth refusing in the GUI.

**Surface:** nothing. The README's `pinned.vendor.com` example carries no
`access:` key and says nothing about the interaction; neither
`izba policy allow --help`, `izba policy reload --help` nor `--policy`'s help
mention it. A user who follows README's `access: read` advice ("HTTP GET/HEAD
only; writes blocked") for a vendor and then adds the pinning exception gets a
declaration that silently does nothing — and only finds out by reading
`izba policy show`'s output very carefully, or by watching their pinning client
fail with no explanation.

**Should have said it:** the README policy-file example (one comment line on the
`pinned.vendor.com` block) and/or the `--policy` help text.

Journeys: `core-pinned-port-under-read-only-access`,
`deep-dormant-exception-still-intercepts`,
`gui-dormant-exception-is-not-claimed-as-live`.

---

## D3 (P1) — `izba create/run --help` still describes the pre-#238 per-HOST shape

**Shipped:** #238 moved the declaration onto the individual PORT precisely so a
grant cannot inherit a sibling port's hatch. The entry-level key is still accepted
and is normalized down onto **every port of that entry**.

**Surface:** `izba create --help` / `izba run --help` (`--policy`) say: "hosts/
ports, plus optional `git:` rules and **per-host** `access:` / `protocol:` keys —
`protocol: http` polices a non-web port at L7, `protocol: tcp` on an exact host is
the TLS-pinning passthrough". A user reading only `--help` will write the
entry-level form, which parses — and thereby applies the passthrough to every port
of that entry, which is the exact hazard #238 exists to remove. README's example
shows the per-port form; the two disagree.

**Should have said it:** the `--policy` long help (say "per-port `protocol:`", and
that the entry-level spelling is legacy and applies to every port of the entry).

Journeys: `smoke-docs-find-pinning-exception`,
`core-older-entry-level-declaration-still-works`.

---

## D4 (P2) — the README's list of "what counts as weakening egress" omits both inspection transitions

**Shipped:** `manifest::diff::egress_weakens` flags two more transitions than the
README lists: (1) a newly-declared passthrough on an exact `(host, port)`, and
(2) a still-reachable port losing global inspection.

**Surface:** README: "Any change that weakens the egress jail — adding `allow`
entries, flipping `enforce: true → false`, widening `access:` scope — is marked
`⚠ weakens egress`." A user who sees `⚠ weakens egress` on a diff that adds no
host, changes no access and leaves `enforce: true` will believe the tool is wrong.

**Should have said it:** the README `⚠ weakens egress` paragraph.

Journeys: `deep-review-flags-a-new-exception-as-weakening`,
`deep-review-flags-losing-inspection-on-a-shared-port`.

---

## D5 (P2) — the only *reviewed* authoring path is undocumented at the place a user would look

**Shipped:** `spec.egress` in `izba.yml` deserializes through the same
`EgressPolicyConfig`, so the per-port `protocol:` is authorable there (DP-7) — and
that is the ONLY authoring route with the weakening gate in front of it.

**Surface:** README's `izba.yml` example `spec.egress` block shows only
`host` / `ports: [443]` / `access:` and never says it accepts the same shape as
`policy.yaml`. `izba policy reload --help` points a user at `policy.yaml`
(ungated) but not at the manifest. A user therefore learns the ungated route and
not the gated one.

**Should have said it:** the README `izba.yml` example (one `protocol:` line, or a
sentence that `spec.egress` is the same schema as `policy.yaml`).

Journeys: `core-author-the-exception-through-the-review-flow`,
`smoke-docs-find-authoring-surface`.

---

## D6 (P2) — the desktop app guide says nothing about pinned rows, the Host lock or the refused Access widening

**Shipped:** on a row carrying a pinned port the Host input is read-only and an
Access widening into `read-write` is **silently ignored by the reducer** — the
component's own comment concedes "the picker gives no visible feedback when the
click is silently ignored".

**Surface:** `dogfood-app-guide.md`'s Policy section says only that the tab is a
form and "anything the form has no field for cannot be authored here". Nothing
about a row that cannot be renamed, an Access click that does nothing, or a
warning banner. A GUI user meeting a dead control has no documented explanation
outside the row's own notice text.

**Should have said it:** the app guide's "Policy / egress firewall" section.

Journeys: `gui-cannot-move-the-exception-to-another-host`,
`gui-cannot-activate-a-dormant-exception`,
`gui-removing-the-exempt-port-unlocks-the-row`.

---

## D7 (P2) — nothing tells an operator WHICH surface answers "is anything bypassing my firewall?"

**Shipped:** `izba policy show` and the desktop Policy tab are the only surfaces
that reveal a hatch; `izba status` deliberately renders no egress posture at all
(CLAUDE.md; DP-8).

**Surface:** `izba policy show --help` says it prints "the effective allow-list
(host + ports) and enforce posture (on/off)" — it never mentions inspection or
exemptions. Nothing warns that `izba status` is silent on egress. An operator
auditing with `izba status` will reach a false "nothing unusual" conclusion, which
is exactly the failure mode issue #239 was filed about for the GUI.

**Should have said it:** `policy show`'s long help, and a line in the README
firewall section.

Journeys: `smoke-docs-find-authoring-surface`,
`core-declared-exception-with-the-firewall-off`.

---

## D8 (P3) — "the exception needs an exact host" is only discoverable by triggering the error

**Shipped:** `protocol: tcp` on a wildcard host is a parse error (DP-3), and the
error is genuinely actionable ("Name each pinned host explicitly"). The asymmetry
— `protocol: http` on a wildcard is fine — is not obvious.

**Surface:** README's wildcard rules paragraph says nothing about it; the README
example happens to use an exact host but never states the rule. `--help` says
"`protocol: tcp` on an exact host", which hints at it without stating that a
wildcard is refused rather than ignored.

**Should have said it:** the README wildcard paragraph.

Journeys: `core-refuse-pinning-on-a-wildcard-host`,
`core-inspection-may-be-asked-for-on-a-wildcard`.

---

## D9 (P3) — the back-compat promise is invisible

**Shipped:** an existing `policy.yaml` carrying the pre-#238 entry-level
`protocol:` keeps parsing and keeps its meaning (#238 In-Scope, "no shipped policy
changes posture on upgrade").

**Surface:** no README or `--help` text says the older spelling is still accepted,
what it means now, or that it is legacy. An upgrading operator cannot tell whether
their file still means what it did — and (see D3) `--help` still teaches the old
form as if it were current.

**Should have said it:** README policy-file section, one sentence.

Journey: `core-older-entry-level-declaration-still-works`.

---

## D10 (P3) — nothing says a command-line grant is unreviewed while the same change via the manifest is gated

**Shipped:** `izba policy allow` writes `policy.yaml` directly without passing the
`izba diff`/`izba promote` weakening gate (CLAUDE.md, verbatim).

**Surface:** `policy allow --help` documents the grant's semantics thoroughly
(including the non-inheritance rule — the one place the feature is well
documented) but never notes that this path has no review; the README's review-loop
section never notes that CLI mutations skip it. A user can reasonably believe the
`⚠ weakens egress` gate protects every path.

**Should have said it:** `policy allow`'s long help, or the README review-loop
paragraph.

Journey: `deep-command-line-grants-skip-the-review-gate`.

---

## Non-flag: what the surface DOES get right

Worth recording so the skeptic does not over-credit findings:

- `izba policy allow --help` states the non-inheritance rule explicitly and points
  at `policy.yaml` for declaring one — the #238 promise is genuinely discoverable.
- `izba policy reload --help` names the "settings this CLI has no flag for, such
  as an entry's `protocol:`" escape route.
- The README example shows the full per-port shape, including "a bare port
  declares nothing → inspected" and "Declared per PORT: adding another port here
  never inherits the hatch".
- Parse errors (unknown value, unknown key, wildcard `tcp`, duplicate port) all
  name the field and the valid alternatives, so a user who guesses wrong is
  corrected rather than silently accommodated.
