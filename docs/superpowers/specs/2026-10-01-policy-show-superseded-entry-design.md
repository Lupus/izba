# `izba policy show`: render a superseded duplicate entry honestly (#243)

Status: approved for implementation (2026-10-01). Issue: #243.

## 1. Problem

A `policy.yaml` allow-list may name the same exact host twice. The compile
(`EgressPolicyConfig::to_rego_data_json`) keys exact hosts in a JSON map, so
the LATER entry overwrites the earlier one wholesale — ports, access and all.
`InspectionTable::from_config` mirrors that fold for the passthrough set.

`izba policy show` (`render_policy`, `crates/izba-cli/src/commands/policy.rs`)
does not: it walks `cfg.allow` raw and annotates each entry from its own
declaration. For

```yaml
- host: pinned.vendor.com
  ports: [443]
  protocol: tcp
- pinned.vendor.com
```

it prints `⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; …`
against the first entry, although no passthrough is in force. The failure
direction is over-claim only (the winning entry always renders its own correct
annotation), but `policy show` is a reveal surface the M5 P1 contract makes
load-bearing, so an over-claim is a mis-audit and makes a failing pinning
client undiagnosable.

The same raw walk over-claims the superseded entry's ports and access too: a
superseded `ports: [8443]` is listed although 8443 is not reachable on that
host.

## 2. Decision

**Render effective posture in `policy show`** — keep listing the raw entries
(the operator must be able to find the offending line in the file), and mark
every superseded entry as such.

- Each superseded entry gets one extra line directly under its host line:
  `⚠ superseded — NOT in force: a later entry for this host (<winner>)
  replaces this one wholesale; the last entry for an exact host wins — remove
  the duplicate`, where `<winner>` is the winning entry rendered exactly like a
  host line (`host  [ports] (access)`).
- A `protocol: tcp` port on a superseded entry prints
  `⚠ :<port> protocol: tcp — pinning passthrough NOT in effect: this entry is
  superseded by a later entry for the same host, so its declaration is never
  read; declare it on the later entry (or remove that entry) to pin`.
  This branch outranks the existing enforce-off and narrow-access branches:
  their remedies ("turn enforcement on", "widen to read-write") would be false
  for an entry that is never read.
- A `protocol: http` port on a superseded entry keeps its `(inspected)` line:
  `inspect_ports` unions over every entry, superseded ones included, so the
  statement stays true.
- A policy without duplicate exact hosts renders byte-identically to today.

**One fold, not two.** The supersession fact comes from a new core primitive,
`EgressPolicyConfig::superseded_by() -> Vec<Option<usize>>`, and
`InspectionTable::from_config` is refactored to build its passthrough set from
that same primitive. The renderer never folds on its own — a second,
independent fold of this axis is what produced the live
no-certificate-verification bypass during M5 P1. A guard test pins the
primitive against `to_rego_data_json`'s compiled `sandbox_host_rules`.

Wildcard entries are never superseded: they compile into a list where every
rule grants independently.

## 3. Rejected directions

- **Refuse duplicate exact hosts at parse time.** A breaking change: every
  `policy.yaml` that carries a duplicate today — and loads, compiles and
  enforces correctly — would stop loading, which fails `start`/`reload` for a
  sandbox whose enforcement was never wrong. It would also make such a file
  un-healable through izba's own mutation verbs, which is exactly what
  `collapse_duplicate_hosts` exists to do (it runs at the top of every
  mutation and collapses last-wins).
- **A parse-time lint/warning.** Additive, but it does not fix the reported
  defect on its own: a warning printed at `create`/`reload` time is gone by
  the time an operator audits posture, and `policy show` would still print
  the in-force claim. It also needs a surfacing decision per entry point
  (`create`, `promote`, daemon reload). The M5 spec §13 named a `policy lint`;
  marking the entry on the reveal surface is that lint, delivered where the
  audit happens.

## 4. Answers to the issue's open questions

- *Can `izba policy allow` itself produce a duplicate exact host?* No. Every
  mutation method (`allow`, `revoke`, `set_host_access`, `replace_allow`)
  starts with `collapse_duplicate_hosts`, so izba never writes one; duplicates
  come only from hand-edited or externally generated files.
- *Do other consumers of the axis owe the same honesty?*
  `manifest::diff::egress_weakens` reads `InspectionTable` and the
  compile-faithful `allow_index` — already folded. The desktop app's Policy
  tab reads `cfg.allow` raw and has the same over-claim; the issue scopes the
  app out, so it is tracked as #312.

## 5. Out of scope

Changing any fold semantics; wildcard entries; the router; `manifest::diff`;
the desktop app (#312).

## 6. Testing

- Core: unit tests for `superseded_by` (no duplicates, several duplicates,
  normalize-equal spellings, wildcards), the guard against
  `to_rego_data_json`, and the existing `InspectionTable` suite unchanged.
- CLI: `render_policy` tests asserting whole-output strings for the issue's
  reproducer, the inverse ordering, three duplicates, both-declare-tcp,
  enforce-off and narrow-access combinations, wildcard duplicates, spelling
  variants, and a byte-identity guard for a duplicate-free policy.
