# Fix main-branch e2e failures: registry tick clobber + coverage-job chromium

## Context

Two distinct e2e failures on main:

1. **`cli_surface_lifecycle` flake** (daemon_e2e, KVM leg, run 29184527023):
   panicked "running after start" at `crates/izba-cli/tests/daemon_e2e.rs:949` —
   `izba ls` right after a successful `izba start` did not show "running".
   Root cause: `supervisor::tick` computes `sandbox::list` (a disk+probe scan
   whose `control_answers` probe can block ~7s against a dying VM: 5s vsock
   CONNECT read timeout + 2s control RPC timeout) and then calls
   `registry.replace_all(infos)`, wholesale-publishing a snapshot that can be
   seconds stale. Lifecycle handlers (`start`/`stop`/`rm`/`create`) that
   completed AFTER the scan began get clobbered back to their pre-op liveness
   for up to one tick (2s). `DaemonRequest::List` (= `izba ls`) reads this
   registry. The clobber is even documented in `registry.rs` ("may be clobbered
   for ≤1 tick — acceptable for a cache") — it is not acceptable: it makes
   `ls` contradict a just-completed lifecycle op (stale-stopped after start,
   resurrected entry after rm, missing entry after create).

2. **Frontend-coverage step failure** (e2e.yml `linux-kvm-coverage` job, runs
   28767946420 + 29085153097): `npm ci --ignore-scripts` skips Playwright's
   browser download and, unlike `coverage.yml` (which fixed this), e2e.yml's
   "Frontend coverage (vitest lcov)" step never installs chromium — the
   vitest browser-mode project fails with "Executable doesn't exist at
   …chromium_headless_shell…" every time the job runs.

Out of scope (file as GitHub issue, do not fix here): the tick's side-effect
loop can also `egress.stop`/`relays.stop_all` a *starting* sandbox off the
same stale snapshot (the egress vsock-1027 listener is bound pre-boot by
`handle_start`; a tick that scanned pre-launch kills it mid-boot; heals ≤1
tick after boot).

## Global constraints

- Registry changes are in-memory only: NO wire/proto changes, NO
  `DAEMON_PROTO_VERSION` bump, no change to `SandboxSummary`.
- `replace_all` callers: `supervisor::tick` (supervisor.rs:41) and adoption
  (`server.rs:739`). Both must pass a snapshot taken BEFORE their
  `sandbox::list` call. No other callers exist (verified by grep).
- Tombstone trimming relies on `replace_all` calls being serialized (adoption
  runs before the supervisor thread spawns; only the supervisor thread calls
  tick). Document this invariant at the trim site.
- TDD: every new registry behavior lands as a failing unit test first.
  Unit tests must not bind unix/vsock listeners (CLAUDE.md constraint).
- All six workspace gates must pass (cargo test/clippy/fmt + musl izba-init +
  windows-gnu check/clippy). App gate not needed (app does not use registry —
  verified by grep).
- Conventional commits.

## Task 1: generation-guarded Registry::replace_all (izba-core)

**Files:** `crates/izba-core/src/daemon/registry.rs`,
`crates/izba-core/src/daemon/supervisor.rs`,
`crates/izba-core/src/daemon/server.rs` (adoption site ~line 739).

**Design:**

- `Registry` inner state becomes `Mutex<Inner>` where
  `Inner { entries: HashMap<String, Entry>, removed: HashMap<String, u64>, gen: u64 }`
  and `Entry` gains `mutated: u64`.
- `pub fn snapshot(&self) -> u64` — returns current `gen`.
- Every mutation (`set`, `set_liveness`, `remove`) increments `gen` and stamps
  the affected entry (`mutated = gen`); `remove` records
  `removed.insert(name, gen)` and drops any tombstone-shadowing on later `set`
  (a `set` for a name clears its tombstone — re-created sandboxes must live).
- `pub fn replace_all(&self, snapshot: u64, infos: Vec<SandboxInfo>)` merge
  semantics (replaces the current wholesale swap):
  1. incoming info for a name whose existing entry has `mutated > snapshot` →
     keep the existing entry (handler wrote it after the scan began; the scan
     is stale for this name);
  2. incoming info for a name whose tombstone gen `> snapshot` → skip it (the
     sandbox was removed after the scan began; do not resurrect);
  3. existing entries NOT present in `infos` with `mutated > snapshot` → keep
     (created/registered after the scan began; do not drop);
  4. everything else → take the incoming info (normal refresh; stale cache
     entries for sandboxes that died still get corrected);
  5. trim tombstones with gen ≤ snapshot (safe because replace_all calls are
     serialized — document).
- Update the now-wrong "clobbered for ≤1 tick — acceptable" doc comment on
  both `replace_all` and the module header to describe the guard.
- `supervisor::tick`: `let snap = registry.snapshot();` BEFORE
  `sandbox::list(...)`; pass to `replace_all(snap, infos)`.
- Adoption in `server.rs`: same pattern around its `sandbox::list` +
  `replace_all` pair.

**Tests (write first, in registry.rs `mod tests`):**

1. `replace_all_keeps_entry_mutated_after_snapshot` — set(web, Stopped);
   snap; set_liveness(web, Running); replace_all(snap, [web Stopped]) →
   liveness(web) == Running.
2. `replace_all_applies_stale_free_updates` — set(web, Running); snap;
   replace_all(snap, [web Stopped]) → Stopped (normal refresh still works).
3. `replace_all_does_not_resurrect_removed` — set(web, …); snap; remove(web);
   replace_all(snap, [web …]) → liveness(web) == None, summaries empty.
4. `replace_all_keeps_entry_created_after_snapshot` — snap; set(new, Stopped);
   replace_all(snap, []) → entry still present.
5. `replace_all_converges_on_next_tick` — after test 1's preserved entry, a
   second snapshot + replace_all with fresh disk truth applies it (guard does
   not pin entries forever).
6. `set_after_remove_clears_tombstone` — remove(web); snap; set(web, …);
   replace_all with [web …] at an older snapshot must NOT drop the re-created
   entry (tombstone gen < entry.mutated; rule 1 wins over rule 2 — make the
   precedence explicit: an entry existing in `entries` with `mutated > snapshot`
   is kept regardless of tombstones).
7. Existing tests (`set_summaries_remove`, `replace_all_swaps_the_view`,
   supervisor `tick_reflects_disk_state` etc.) updated for the new signature
   and still passing.

**Verify:** `cargo test -p izba-core daemon::registry daemon::supervisor` then
full `cargo test --workspace`.

## Task 2: e2e.yml frontend-coverage chromium install

**File:** `.github/workflows/e2e.yml` (step "Frontend coverage (vitest lcov)",
~line 446).

Add `npm run e2e:install:chromium:deps` between `npm ci --ignore-scripts` and
`npm run test:coverage`, with the same explanatory comment as
`coverage.yml:145-149` (browser-mode project needs the lock-pinned chromium;
`--ignore-scripts` skips Playwright's download; npm script not npx — Sonar
S8543 bans npx in workflow YAML). Verify with `python3 -c "import yaml,sys;
yaml.safe_load(open('.github/workflows/e2e.yml'))"` or equivalent.

## Task 3: daemon_e2e lifecycle assert diagnostics

**File:** `crates/izba-cli/tests/daemon_e2e.rs` (`cli_surface_lifecycle`).

The asserts at [6] ("stopped after stop"), [6b] ("running after start"), and
[7] ("removed sandbox is gone") drop the `ls` output, so a CI failure log says
nothing about the observed state. Restructure each to capture the output in a
local and include it in the panic message, exactly like the [4] assert
("sandbox running after run: {}") already does. Test-only change; the test is
KVM-gated so compile-check it: `cargo test -p izba-cli --test daemon_e2e
--no-run`.

## Final

- Full six-gate run, commit(s), push branch, draft PR.
- File the out-of-scope tick-vs-starting-sandbox egress issue on GitHub.
- Trigger e2e.yml workflow_dispatch on the branch; greploop + SonarCloud green.
