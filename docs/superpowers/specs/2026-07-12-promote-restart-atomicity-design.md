# Promote restart-leg atomicity (issue #131) — design

**Issue:** [#131](https://github.com/Lupus/izba/issues/131) — an image-class
`promote` that fails during its restart leg (Stop → scratch reset → Start)
commits the managed config (`config.json`/`policy.yaml`) BEFORE advancing the
manifest base (`manifest.base.yaml`), and never rolls back. The sandbox lands
in a persistent `diverged` drift state that no user edit explains, and the
review token is left un-consumed. Found by the GUI LLM-dogfooding acceptance
loop (PR #130, run 4 skeptic report).

## Decision

**Advance the base and clear the review token together with `write_managed`,
before the restart leg** (issue direction 1). `config.json` + `policy.yaml` +
`manifest.base.yaml` + the consumed review token together record one fact —
"this manifest revision was promoted" — so they move as one commit unit. The
restart leg is a *lifecycle* action executed on already-committed config: its
failure must not corrupt drift bookkeeping, only report honestly.

Rejected alternatives:

- **Roll back `write_managed` on restart failure** — by the time Start fails,
  Stop has already run and (with the default `--reset-scratch`) the rw overlay
  is already wiped for the new image. Restoring the old `config.json` would
  claim "nothing was promoted" over a sandbox that was visibly stopped and
  scratch-reset by the promote, and a rolled-back config over a blank overlay
  built for the *new* image re-creates the exact unbootable-mismatch problem
  Fix 2 (`image change requires --restart`) exists to prevent.
- **Only surface the partial state** — keeps the structural lie (`diverged`
  attributable to nobody) and just annotates it.

### Resulting failure-mode semantics

With the reorder, any restart-leg failure leaves `repo == managed == base`
(drift: **in sync**), review token consumed, sandbox stopped (or still running
old config if Stop itself failed). This is exactly the same durable state as a
successful `promote` *without* `--restart` — config applies on the next start
— so `izba diff` stays truthful. Re-running `promote` is NOT a no-op, though:
the review token was already consumed by the commit unit, so a bare re-promote
bails `no reviewed diff — run `izba diff` first (or --force)`. The actual
recovery is `izba start <name>` (config is already committed; starting it
applies the promoted config), or — if the manifest needs another look — a
fresh `izba diff`, which will correctly report **in sync** rather than a
lingering divergence.

The Start-failure error already says "config already committed; run
`izba start <name>` to retry" — now that hint is fully accurate (previously a
retry-start left the base stale forever). Stop and scratch-reset failures gain
the same honest context (currently they propagate raw, with no hint that the
promote itself is committed).

## Changes

### 1. `crates/izba-core/src/manifest/promote.rs` (core fix, TDD)

- Move `store::write_base(&dir_managed, &m)?` and
  `store::clear_review(&dir_managed)?` from the end of `run_with_client` to
  immediately after `apply::write_managed(paths, name, &repo, &digest)?`,
  before the restart branch.
- Event/message ordering on the **success path is byte-identical**: the
  `promoted {name}` Info stays the last event; only the *disk write* moves.
- Wrap the two restart-leg failures that previously propagated raw:
  - `Stop` failure → error context: `failed to stop sandbox for restart
    (the promote itself is committed; restart manually to apply): {err}`
  - `reset_rw_scratch` failure → error context:
    ``failed to reset the rw scratch disk after promote (config already
    committed; the OLD scratch overlay was kept — `izba start {name}` will
    boot the NEW image over the OLD overlay and may misbehave or fail to
    boot — if so, recreate the sandbox or revert the image change and
    re-promote): {err}`` — `reset_rw_scratch` is atomic (tmp+rename), so a
    mid-reset failure never touches the old file; the honest hazard isn't
    "retry the reset", it's "the new digest is already committed over an
    overlay built for the old one."
  - `Start` failure keeps its existing message (already accurate post-fix).
- Update the atomicity doc-comment (the "enact live effects FIRST" block) to
  document the two-phase contract: live RPCs → commit unit (managed + base +
  token) → lifecycle leg, citing #131.

**New fake-daemon tests** (same `UnixStream::pair()` harness as the existing
`run_with_client_*` tests):

- `run_with_client_start_failure_still_advances_base` — running sandbox,
  image change, `restart: true`; fake daemon Oks Stop, replies `Error` to
  Start. Assert: `Err` containing the retry hint; `store::read_base` now
  parses to the *repo* manifest (image == new); `store::read_review` is
  `None`; `classify(base, repo, managed)` == `DriftState::InSync`.
- `run_with_client_stop_failure_still_advances_base` — same setup; fake
  daemon replies `Error` to Stop. Assert: `Err` with the "promote itself is
  committed" context; base advanced; review cleared.

Final-review follow-ups (upper-bound pin + honest scratch-reset hint):

- `run_with_client_live_rpc_failure_leaves_commit_unit_unwritten` — running
  sandbox, egress delta, fake daemon Oks `Inspect` then errors `ReloadPolicy`.
  Pins the ordering contract's UPPER bound (the mirror image of the two tests
  above, which pin the lower bound): `store::read_base` stays `None`,
  `store::read_review` stays `Some`, and `config.json`'s `image_digest` stays
  at the seeded placeholder — `write_managed` never ran, because it sits
  strictly after the live-RPC block.
- `run_with_client_scratch_reset_failure_gives_honest_recovery_hint` —
  running sandbox, image change, `restart: true`; no `rw.img` seeded so
  `reset_rw_scratch` fails hermetically at its first step (reading the file
  size), before `Start` is ever sent. Asserts the new message text and that
  the commit unit (base/review) still landed.

### 2. GUI error copy (`app/src/components/ManifestTab.tsx`)

`mapPromoteError` gains two belt-and-braces substring mappings so the new
core errors don't leak CLI-speak (`izba start <name>`) into the app:

- `"failed to start sandbox after promote"` → `Promoted, but the sandbox
  failed to start on the new configuration. Use Start on the sandbox to
  retry.`
- `"failed to stop sandbox for restart"` → `Promoted, but the sandbox could
  not be stopped to apply restart-class changes. Stop and Start it manually.`

Covered by the existing Playwright mock-driven `manifest.spec.ts` pattern
(mock `manifest_promote` rejection → assert the mapped copy renders).

`hack/dogfood/gui/gui_oracles.py` `_ERROR_COPY_MAP` gets the same two
entries (it is a hand-maintained mirror of ManifestTab copy — documented
silent-drift risk).

## Out of scope

- The *hang* half of the #131 evidence (the promote RPC never returning
  because the daemon's Start stalled) is an RPC-timeout concern, orthogonal
  to config integrity; not addressed here.
- A real-VM e2e for a failing Start (hard to arrange deterministically); the
  fake-daemon tests pin the ordering contract, and `daemon_e2e` [9]-[11]
  keep pinning the live success path.

## Gates

The six workspace gates + the app gate (`cd app && npm ci && npm run build`,
`src-tauri` fmt/clippy/test), all green before PR; then greploop to
Greptile 5/5 + zero unresolved, SonarCloud quality gate, full CI.
