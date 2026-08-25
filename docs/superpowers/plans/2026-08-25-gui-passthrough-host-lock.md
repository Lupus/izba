# Plan — #239: make a TLS-pinning passthrough visible and unrelocatable in the desktop policy editor

Spec / authority: GitHub issue #239 (Acceptance Criteria are binding), plus the
M5 P1 inspectability contract paragraph in `CLAUDE.md`.

## Context

PR #233 introduced the `protocol: http | tcp` inspectability axis; #238 moved the
declaration from the allow-ENTRY down onto the individual PORT and taught
`app/src/components/PolicyEditor.tsx` to round-trip it per port and to render a
`⚠ tcp` badge on the pinned port chip.

Two of #239's acceptance criteria are still open on `main`:

- **AC 4** — the read-only-vs-editable question for a row carrying `protocol: tcp`
  is undecided, and the Host input of such a row is freely editable. Because the
  GUI's Save path (`policySetFull` → `EgressPolicyConfig::replace_allow`) never
  passes the `izba diff`/`izba promote` weakening gate, renaming a pinned host
  RELOCATES the hatch onto a host that never declared one — an unflagged security
  weakening authored by the GUI. Renaming it to a wildcard additionally persists a
  shape `parse_allow_entry` refuses (DP-3), leaving an unparseable `policy.yaml`.
- **AC 8** — `CLAUDE.md` still asserts `izba policy show` is the ONLY surface that
  reveals a hatch, two lines above a sentence saying the desktop policy editor
  marks a declared port. The paragraph contradicts itself.

AC 2 is only weakly met: the full substance of the passthrough lives in the port
chip's `aria-label`/`title`, with no visible text an operator scanning the Policy
tab would read.

## Decision (recorded here and in the PR body)

**Rows stay editable, but the GUI can never author, relocate, or activate a hatch.**

The Host input of a row carrying at least one `protocol: tcp` port is rendered
read-only, with a visible explanation of what the passthrough gives up and where
it can be changed. Ports and Access stay editable; the declaration keeps
round-tripping untouched. Removing the pinned port chip (a strictly narrowing
edit) unlocks the Host input again, so the GUI still offers a way out without
ever widening posture.

**Amendment (final-review round, human-confirmed):** the same Save-path gap
that motivated the Host lock also lets a single click ACTIVATE a dormant
passthrough. A pinned row loaded with `access: read` never actually pins
(an opaque splice carries no HTTP method, so `read` never authorizes one —
`router::passthrough_names` drops the host and the connection stays
terminated at L7); but the Access picker was left fully editable, so widening
`read` → `read-write` on that row turns the hatch live with the same
unflagged-weakening property the Host lock exists to close
(`manifest::diff::egress_weakens` would flag exactly that `Read → ReadWrite`
transition on the `izba.yml`/diff/promote path — a gate `policySetFull` never
reaches). Ruling: refuse the widening transition INTO `read-write` on a
pinned row, in the reducer (`setHostAccess`), the same way `setHost` refuses
a rename. Narrowing (`read-write` → `read`, or any transition that isn't
INTO `read-write`) stays allowed — the picker is not locked outright, only
the one direction that would activate a dormant hatch. The escape valve is
the same as the Host lock's: remove the pinned port, then widen freely. The
visible notice also became access-aware in the same round: a pinned row with
`access: read` renders a NOT-in-effect variant (matching the CLI's own
`Some(Protocol::Tcp) if e.access() != Access::ReadWrite` branch in
`crates/izba-cli/src/commands/policy.rs`) instead of claiming the live
substance it doesn't have.

Rejected: whole-row read-only (blocks harmless narrowing edits like tightening
Access, and forces users out of the GUI for unrelated changes to that host);
a GUI control that authors `protocol` (would make the desktop app a place a
hatch can be OPENED, not just seen — wider than #239 assumes, and contrary to
the `CLAUDE.md` contract that the editor "authors nothing").

## Global Constraints

- **No new derivation of the inspectability axis.** `InspectionTable`
  (`crates/izba-core/src/daemon/egress/inspect.rs`) stays the single site.
  The GUI only READS `protocol` off the port it was loaded from. No second fold.
- **A port that never declared a protocol must still round-trip as a BARE
  number**, and an added port must never inherit a sibling's declaration
  (#238 behaviour — existing tests guard this; do not regress it).
- The declaration belongs to its OWN port. Never annotate at host level in a way
  that misreports which port gave a control up.
- Rust is untouched. This is `app/src` + `CLAUDE.md` only.
- Wording for the passthrough substance must match the CLI's `⚠ protocol: tcp`
  line in substance: spliced opaquely, no L7 rules, no request audit, no upstream
  certificate verification.
- TDD: every behaviour change gets a test that was watched to fail first.
- Gate: `cd app && npm ci && npm run build && npm test` must be green, and
  `cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

## Task 1 — passthrough notice, Host lock, tests, and the CLAUDE.md amendment

All in ONE commit: AC 8 requires the doc change to land with the code.

### 1a. Tests first (`app/src/test/policyEditor.test.tsx`)

Write these, run them, and confirm each fails for the right reason before
touching the component:

1. `renders a visible passthrough notice on a row carrying a pinned port` — load
   `allow: [{host: "pinned.vendor.com", ports: [80, {port: 443, protocol: "tcp"}]}]`;
   assert visible text (not just an aria-label) naming port 443 and carrying the
   substance: opaque splice, no L7 rules, no request audit, no upstream
   certificate verification.
2. `renders no passthrough notice for a port declared http` — `[{port: 8000,
   protocol: "http"}]`; assert the notice is absent AND the `⚠ tcp` passthrough
   marker is absent (AC 3, explicit).
3. `renders no passthrough notice for an undeclared port` — `ports: [443]`; same
   two absences (AC 3).
4. `locks the Host field of a row carrying a pinned port` — assert the host
   `Input` for `pinned.vendor.com` is read-only, and that an ordinary row's host
   Input in the same policy is NOT.
5. `unlocks the Host field once the pinned port is removed` — click
   `Remove port 443`, assert the host Input becomes editable and the notice
   disappears.
6. `preserves protocol: tcp when an unrelated field on the row is edited and
   saved` — change Access on the pinned row, Save, assert `policySetFull` still
   receives `[80, {port: 443, protocol: "tcp"}]` (AC 5 regression guard for the
   PR #233 silent-drop defect).

Use the existing file's idioms: `api.policyShow` mocked via `vi.fn()`,
`render(<PolicyEditor name="web" />)`, `await screen.findByDisplayValue(...)`.

### 1b. Implementation (`app/src/components/PolicyEditor.tsx`)

- A helper that answers whether a `Row` carries any `protocol: "tcp"` port, and
  which ports those are. One site; the rest reads it.
- Render a visible, warning-styled notice on such a row, naming the pinned
  port(s) and stating the substance plus where the declaration can be changed
  (`policy.yaml`, or `izba.yml` + `izba diff`/`izba promote`).
- Pass `readOnly` on that row's host `Input`, with a title/hint explaining why.
  `setHost` must be inert for a locked row, so the lock is behavioural and not
  merely visual.
- Do not touch `toPortSpec`, `addPort`, or the save fold.

### 1c. `CLAUDE.md`

Rewrite the "ONLY surface" sentence in the M5 P1 contract paragraph (around
line 274) so it names both revealing surfaces — `izba policy show` and the
desktop app's Policy tab — states that `izba status` still renders no egress
posture, and keeps the standing fact that NEITHER surface can author a hatch,
with the desktop editor's Host field locked while a row is pinned so it cannot
relocate one either.

## Out of scope (do not touch)

- `izba policy show`, `izba status`, the CLI's hatch rendering.
- The `izba diff`/`izba promote` weakening gate, `izba policy allow`.
- `EgressPolicyConfig::replace_allow`'s acceptance of a lone wildcard entry
  carrying `protocol: tcp` (latent once the Host lock lands — filed separately).
- The other findings from the same dogfooding pass (silent port extension,
  duplicate-entry supersession, the drift banner, the missing accessible name).
