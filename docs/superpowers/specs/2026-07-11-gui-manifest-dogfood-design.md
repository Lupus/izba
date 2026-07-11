# GUI manifest surface + GUI dogfood deep-sprint — design

**Date:** 2026-07-11
**Status:** approved for implementation (owner-directed autonomous sprint)
**Anchors:** PR #119 (manifest diff/promote/export), PR #121 (GUI dogfooding
harness), PR #125/#127/#128 (harness depth + honesty + modality split),
PR #129 (CLI deep-sprint: #122/#123/#124 fixes),
`docs/superpowers/specs/2026-06-30-gui-dogfooding-design.md`,
`docs/superpowers/specs/2026-07-10-dogfood-deep-sprint-design.md`.

## 1. Goal

One PR that (a) builds the missing **frontend surface for izba.yml
diff/promote/export in the Tauri app**, and (b) extends the **GUI dogfooding
harness** far enough to drive and honestly grade that surface — then iterates
branch-based GUI swarm runs until the journeys run through and the UX holds up
for a user who has NOT read the README. Mirrors the CLI deep-sprint (PR #129)
approach: product fixes and harness reach travel together so each swarm run
exercises the fixed product.

## 2. Verified current state (ground truth, `origin/main` = 8c9fd99)

- `manifest_diff`/`manifest_export` Tauri commands exist
  (`app/src-tauri/src/lib.rs:317-329`, registered `:549-550`) over
  `commands::manifest_diff_core`/`manifest_export_core`
  (`app/src-tauri/src/commands.rs:230-245`) and a tested `DiffView` view model
  (`views.rs:246-295`). **No React component, no `ipc.ts` bridge, no TS types,
  no Detail tab renders any of it.** The feature is unreachable from the UI.
- **No promote exists in the app** — `commands.rs:227` marks it "a deferred
  follow-up". Promote orchestration (review-token gate, daemon RPC sequencing,
  egress-weakening warnings) lives only in
  `crates/izba-cli/src/commands/promote.rs` (434 lines, uses `DaemonClient`).
- The app's `manifest_diff_core` **drops the review token** that
  `ops::compute_diff` returns; the CLI persists it (`diff.rs:29`
  `store::write_review`). Promote's gate reads that token from disk.
- The headless dogfood bridge (`app_lib::dispatch`, `lib.rs:462-497`) covers
  12 of 34 IPC commands; `manifest_*` falls into the `unknown command`
  catch-all. `real-bridge.js` forwards any `invoke` verbatim, so only the
  dispatch arm is missing.
- The GUI runner (`hack/dogfood/gui/run_gui_journeys.py`) has **no
  `seed_files` support and no decisive-step grading** — GUI oracles
  (`console`, `dom_expect`, `silent_failure`, `ui_daemon_diff`) emit no
  `functional` candidates, so a GUI journey can never flip negative through
  the decisive mechanism.
- Modality split and GUI-job skip in `dogfood.yml` are DONE (dynamic
  matrices, `has_gui` gate, `select_cli_journeys`) — no work needed there.
- NewSandbox P1 from the first GUI run is still unfixed: `NewSandbox.tsx:145`
  computes `canCreate`, `:365` renders `<Button disabled={!canCreate}>` with
  no hint why Create is inert. Never filed as an issue.
- The frontend already knows each sandbox's `workspace`
  (`views.rs:43`, `types.ts:73`) and `CreateOpts` carries `workspace`.

## 3. Product design

### 3.1 Manifest tab (new, in per-sandbox Detail)

Add `manifest` to the Detail tab bar (`Detail.tsx:22,77-85`), rendered by a
new `ManifestTab` component. On mount (and on Refresh) it calls
`manifest_diff` and renders:

- **Drift banner** — one of four states with plain-language copy and the next
  action: `in_sync` ("izba.yml and managed settings match"), `repo_ahead`
  ("izba.yml has changes not yet applied — review below and Promote"),
  `managed_ahead` ("live settings drifted from izba.yml — Export to capture
  them"), `diverged` ("both changed — review carefully; Promote applies
  izba.yml, Export overwrites it").
- **Delta table** — per `DeltaView`: field, `from` → `to`, class chip
  ("live" = applies immediately, "restart" = applies on next start,
  "image" = image change, restart required), and a prominent
  **"⚠ weakens egress"** marker row-level when `weakens_egress` is true, with
  one line explaining what that means.
- **Buttons:** `Refresh`; `Promote` enabled when state is `repo_ahead` or
  `diverged`; `Export to izba.yml` enabled when `managed_ahead` or
  `diverged`. Disabled buttons carry a tooltip/hint explaining why.
- **Empty/missing-manifest state:** when the workspace has no `izba.yml`, the
  tab shows guidance (what `izba.yml` is, where it goes, a minimal example
  pointer) instead of a raw error. This is the discoverability surface the
  swarm will test.

### 3.2 Promote in the app

- Extract the CLI promote orchestration into
  `crates/izba-core/src/manifest/promote.rs`: a function taking
  (`Paths`, workspace dir, resolved name, `force: bool`, a connected
  `DaemonClient`) and returning a structured `PromoteOutcome`
  { gate outcome, warnings (incl. egress-weakening), applied field deltas,
  restart-needed flag, skipped-because-stopped note }. The CLI command becomes
  a thin renderer over it — **stdout text, warnings, and exit codes stay
  byte-identical** (existing CLI tests + daemon_e2e steps [9]-[11] pin this).
- New app command `manifest_promote(name)` → `PromoteView` (serialized
  outcome), plus a dispatch arm. `force` is **not** exposed in the GUI: a
  stale/missing token surfaces as an actionable error ("izba.yml changed
  since you viewed the diff — Refresh and review again" / "review the diff
  first"). Re-viewing the diff is the GUI's re-review; no silent bypass
  (consistent with the loud-on-security-degradation rule).
- **Review-token parity:** the app's `manifest_diff` gains the CLI behavior —
  it persists the review token (`store::write_review`) because rendering the
  diff *is* the review. Promote consumes it through the same `gate()` — the
  TOCTOU guard (token covers exact manifest+Dockerfile bytes) is preserved
  verbatim.
- **Confirm dialog** before promote: lists the deltas about to apply, states
  restart implications ("N change(s) apply on next start" when the sandbox is
  stopped or restart-class fields exist), and when any delta weakens egress
  the dialog requires an explicit checkbox acknowledgment before the Promote
  button arms.
- After promote: render the outcome (applied fields, warnings, restart note)
  and refresh the diff.

### 3.3 Command signature change (name-only)

`manifest_diff`/`manifest_export`/`manifest_promote` take **`name` only**; the
backend resolves the workspace from the managed config
(`SandboxConfig.workspace`), exactly like the CLI's bare-name resolution from
PR #129. Rationale: managed truth is host-only authority; the frontend should
not supply the path the backend trusts. No frontend callers exist yet, so the
signature change is free. (The Tauri shims and dispatch arms share the same
core fns.)

### 3.4 NewSandbox feedback fix (P1 from first GUI run)

When `canCreate` is false, render inline hints naming the missing/invalid
fields (name, image, workspace) instead of a silently disabled button. Small,
test-covered; unblocks GUI journeys that start from sandbox creation.

### 3.5 Frontend plumbing

TS types `DiffView`/`DeltaView`/`PromoteOutcome` in `app/src/lib/types.ts`
mirroring `views.rs`; `ipc.ts` bridge methods; `tauri-mock.js` cases for e2e;
`FakeDaemon` untouched (manifest cores are daemon-free except promote — the
fake seam for promote is stubbed at the dispatch/mock layer, not DaemonApi).
Vitest unit tests for `ManifestTab` (all four states, weakens-egress ack flow,
error surfaces) and a Playwright e2e spec against the mock.

## 4. Harness design

- **Dispatch arms** for `manifest_diff`, `manifest_export`,
  `manifest_promote` in `app_lib::dispatch` (name-only args, same core fns).
  No other new arms (ports/volumes/netlog stay out of scope — YAGNI for this
  surface).
- **Step-level `seed_files`** in the journey schema, honored by BOTH runners:
  files written into the journey workspace before the step executes. This is
  the primitive that lets a GUI journey create drift mid-journey (create
  sandbox → seed a modified `izba.yml` → open Manifest tab → promote) and
  lets stale-token journeys exist (view diff → seed changed manifest →
  promote must refuse). CLI runner: seeding moves from journey-start-only to
  per-step union (journey-level stays supported). GUI runner: gains a
  per-journey workspace dir, seeds files there, and substitutes a
  `{workspace}` placeholder in step intents so the Actor can type the real
  path into the NewSandbox form.
- **Honest grading for GUI manifest journeys:** a new `manifest_truth` oracle
  in `gui_oracles.py` — after the decisive step it recomputes ground truth
  via `izba_core`-equivalent CLI (`izba diff --name <name>` in the journey
  workspace against the shared `IZBA_DATA_DIR`) and compares against what the
  UI showed (drift state + delta fields extracted from the rendered marks,
  plus the invoke log). It emits **`functional` candidates**, and the GUI
  runner adopts the CLI runner's decisive-step grading for functional
  candidates (a GUI journey whose decisive step never produced honest
  evidence grades unreached, not green). `real-bridge.js` additionally
  records a small result digest for `manifest_*` invokes (drift state, delta
  count, weakens flags) in `__DF_INVOKE_LOG__` for the oracle and skeptic.
- **Fair-test docs:** extend `app/dogfood/dogfood-app-guide.md` (the swarm's
  user-visible app guide) with a Manifest-tab section written as user docs —
  no spec leakage. The swarm's navigability struggle remains a finding.
- **Durable corpus:** commit the final acceptance journey set as
  `hack/dogfood/journeys/manifest-gui.json` (PR #121 backlog item), so
  `hack/dogfood/gui/smoke.sh` and future runs have a checked-in GUI corpus.

## 5. Testing & gates

TDD throughout (tests first per component). Required green before merge:

1. The six workspace gates (promote extraction touches izba-core + izba-cli).
2. The app gate: `cd app && npm ci && npm run build && (cd src-tauri && cargo
   fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
3. Dogfood py tests (`hack/dogfood` pytest CI gate) — new runner/oracle logic
   test-covered.
4. Vitest coverage feeding Sonar (new frontend code must not trip the
   new-code coverage gate); SonarCloud quality gate incl. Security Rating A.
5. `hack/dogfood/gui/smoke.sh` locally (fake-model, no KVM) for the bridge +
   journey plumbing.
6. Full CI on the PR (20 checks) + greploop to Greptile 5/5 with zero
   unresolved.

## 6. Acceptance loop (the sprint's core)

Iterate until clean, autonomously:

1. journey-compiler (Opus, privileged) compiles GUI-modality journeys for the
   manifest surface. Coverage targets: cold-start discoverability (find the
   tab), drift rendering per state, weakens-egress acknowledgment, promote
   happy path (live-class field, no restart), promote on stopped sandbox,
   export flow, stale-token refusal, missing-manifest guidance, NewSandbox
   validation feedback.
2. `dispatch-swarm.sh` with `DOGFOOD_BASE=origin/worktree-gui-dogfood-sprint`
   (dogfood.yml builds the app + bridge from the branch), GUI shards.
3. trajectory-skeptic (Opus) triages: refute reds, audit greens for cheating.
4. Product/UX findings → fix in this PR; harness gaps → fix in this PR;
   re-run. Stop when the skeptic reports no product bugs and the journeys
   reach their decisive assertions honestly.

## 7. Out of scope

- Ports/volumes/netlog/policy-editing dispatch arms (separate backlog).
- Interactive shell streaming through the bridge (deferred since #121).
- tauri-driver/WebKitGTK smoke (deferred since #121).
- CLI behavior changes beyond the promote-core extraction (byte-identical
  output pinned by existing tests).
