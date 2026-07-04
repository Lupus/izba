# Dogfood instrument honesty + flow upgrades — design

**Date:** 2026-07-04
**Status:** approved (owner, 2026-07-04)
**Anchors:** the 2026-07-03 capability review (three deep-dives over
`hack/dogfood/`, `hack/dogfood/gui/`, `.github/workflows/dogfood.yml`, the
`llm-dogfooding` skill + agents, run/issue history), issues #126, #111,
#116, and the owner's placement decisions recorded in §1.

## 0. Problem

The LLM dogfooding capability works — 26 real swarm runs, ~11 real findings,
10 harness PRs — but its **greens are not trustworthy**. Three code paths let
a run tally positive while measuring nothing:

1. Every model/API failure (retry exhaustion, malformed JSON, missing
   content, dead API key) collapses into `{"done": true}` in
   `hack/dogfood/model.py`. Zero-action journeys have zero candidates, and
   `collect-trajectories.py` counts a journey positive iff it has no flipping
   candidate — so a fully broken run reports all-green.
2. A decisive (`core: true`) step the actor never reaches produces no
   candidate → positive (#126, confirmed in code).
3. The `violations` array from `izba __reconcile` is captured into every
   action and read by nobody; a *failed* snapshot returns `{}`,
   indistinguishable from a clean one.

Additionally: the "rubric judge" referenced four times in code/schema does
not exist; the functional oracle grades the step's *last* action rather than
the intent-bearing one; guest `console.log` is never scraped by any oracle;
`OpenRouterModel` has zero tests; the runner's own `--model` default is a
model the team already concluded is too weak; sandboxes are never torn down
between journeys; and known CI plumbing defects lose evidence (failure-log
artifact path points at a stale dir; GUI `gui-traj-*.json` bundles never
match the collector's `traj-*.json` glob; the hardcoded 3-shard matrices
killed the 2026-07-02 runs; `max_usd` is documented "cumulative" but passed
per-shard).

## 1. Placement: what this harness is FOR (owner-locked, 2026-07-03/04)

These decisions steer this design and all future harness work. They are
captured durably in a new **`docs/dogfooding-value.md`** (deliverable D1)
linked from the CLAUDE.md documentation map and the skill's methodology:

- **e2e tests assert what the product does; the swarm measures what a user
  can get the product to do.** e2e = behavior under perfect knowledge
  (deterministic, gateable, pins regressions). Dogfooding = behavior under
  *realistic ignorance* (README + `--help` only); the delta between
  possible-per-spec and achievable-from-the-surface is the product's UX/docs
  debt, and it is inexpressible as a deterministic test.
- **The cheap swarm model is the instrument, not a cost compromise** —
  calibrated ignorance. A smarter model would paper over the docs gaps an
  expert user papers over. Opus phases (compile/skeptic/fixer) run locally
  on the owner's Claude Max subscription — near-free; moving them to
  API-billed CI is a cost regression, not an upgrade.
- **The fair-test boundary is the anti-overlap mechanism.** Journeys carry
  intent in user language, never exact commands, so a journey structurally
  cannot degrade into a unit test.
- **No e2e exclusion map** (owner-rejected): e2e coverage must never
  subtract journeys. The swarm failing a scenario that e2e proves wired is
  exactly the differential the method exists to measure — e2e can happily
  pin a confusing UX.
- **Graduation, not accretion:** a confirmed *behavioral* finding lands as a
  fix + a distilled deterministic e2e test (the trajectory is the repro);
  a *UX/docs* finding lands as a docs/help fix or an issue. The dogfood
  corpus never becomes a frozen regression suite.
- **Freshness principle:** deep/core journeys are disposable by design —
  recompiled against today's surface when a feature is dogfooded. What
  persists: findings→issues, graduated e2e tests, the signal/noise ledger,
  and one small standing **novice smoke corpus** whose only oracle is
  "could an ignorant agent reach the core goals from the public surface".
- **Instrument honesty over determinism:** the harness need not be
  deterministic (usability is a distribution), but a green must mean "the
  assertion was reached and corroborated", and infra failure must be
  distinguishable from success. That is what this change delivers.

## 2. Scope

One branch/PR (`worktree-dogfood-instrument-honesty`) carrying §3–§8.

**Out of scope** (file as issues where not already filed): GUI Phase-3 deep
work — completing headless `dispatch` beyond its 12 commands, a real
bidirectional UI-vs-daemon status differential, act→settle→snapshot, marks
with `disabled`/state, event streaming (all tracked for a follow-up); #116
cross-shard capability isolation; any push-triggered swarm (owner chose
manual/weekly only); the e2e exclusion map (rejected).

## 3. Harness trust fixes (`hack/dogfood/`, Python, TDD, pytest CI gate)

### 3.1 `infra` candidate kind + catastrophic exit (owner decision)

- `model.py::_parse_reply` returns `{"error": "<reason>"}` (never
  `{"done": true}`) on malformed/unparseable replies; `next_command`
  returns `{"error": …}` on retry exhaustion and missing
  `choices[0].message.content`.
- `run_journeys.py::_next_command` converts `{"error"}` into a **flipping
  candidate `kind: "infra"`** (detail = the reason) and ends the step (the
  actor cannot proceed without a model).
- Run-end accounting: a journey is **degraded** if it produced zero actions
  or carries ≥1 `infra` candidate. If >50% of journeys in the run are
  degraded, the runner exits with a distinct non-zero code (document: `3`)
  so the CI shard fails per the existing "only infra failures fail a job"
  contract. Below the threshold: report-only (transient blips don't kill a
  40-minute shard).
- `collect-trajectories.py`: `infra` is explicitly flipping (it already
  would flip via the unknown-kind fail-loud rule; make it explicit) and gets
  its own bucket in the totals so triage sees "N journeys infra-degraded".

### 3.2 `unreached_decisive` candidate (#126)

After the step loop in `run_journeys.py::run_journey`, for each decisive
step (per `_decisive_step_indices`) that executed **zero actions**, emit a
flipping candidate `kind: "unreached_decisive"` (detail names the step
index/intent). Collector: distinct `unreached` bucket, never positive.
Acceptance (from #126): a replay of the `review-gate-refuses-stale-token`
shape — budget exhausted before the core step — tallies unreached, not
positive.

### 3.3 Reconcile violations graded; failed snapshots visible

- `_collect_candidates`: non-empty `action.reconcile["violations"]` → one
  flipping candidate `kind: "reconcile_violation"` carrying the violation
  objects verbatim.
- `oracles.py::_snapshot_reconcile`: on error return
  `{"error": "<reason>"}` instead of the empty-clean shape; the seq oracle
  skips error snapshots; if **every** snapshot in a journey errored, emit
  one `infra` candidate ("reconciler unusable").

### 3.4 `expect_cmd_re` — grade the intent-bearing action

New optional step field `expect_cmd_re` (regex) in
`journeys.schema.json`. Functional/`expect_exit` grading
(`_grade_step_functional`) picks the **last action whose command matches**;
fallback = last action (today's behavior). Every functional candidate now
records the graded command (`graded_cmd`) so the skeptic can see *what* was
graded. `journey-compiler` agent doc gains authoring guidance.

### 3.5 Guest console oracle

`capture_state_evidence` additionally tails (last 8 KiB) each sandbox's
`<data_dir>/sandboxes/<name>/logs/console.log`, stores the tail in
`state_evidence`, and runs the implicit crash-marker regex over it →
flipping candidate `kind: "guest_console"`. Guest-side panics currently
have no oracle at all.

### 3.6 Teardown between journeys

At journey end (after evidence capture): best-effort, timeout-bounded
`izba rm -f <name>` for each sandbox in the final reconcile, then a
best-effort daemon shutdown for the journey's isolated data dir
(implementer verifies the exact CLI verb). Failures are logged, never
candidates — teardown is hygiene, not an oracle.

### 3.7 Rubric-judge cleanup + model default + model tests

- Reword the four "rubric judge" references (`oracles.py` ×3,
  `run_journeys.py` ×1, `journeys.schema.json`) to "graded by the Phase-3
  trajectory-skeptic". Evidence capture is unchanged — judgment stays with
  the local Opus skeptic (owner's cost architecture).
- Runner `--model` default → `google/gemini-2.5-flash` (parity with CI;
  today's default is the admitted-broken `deepseek-chat`).
- New `test_model.py`: seam over `urllib.request.urlopen` covering
  retry-then-success, retry exhaustion → `{"error"}`, malformed JSON →
  `{"error"}`, missing content → `{"error"}`, `usage.cost` preferred over
  token-estimate fallback, and prompt assembly. This is currently the only
  untested module and the most failure-prone one.

### 3.8 Schemas + write-time validation

`trajectory.schema.json` gains the new candidate kinds (`infra`,
`unreached_decisive`, `reconcile_violation`, `guest_console`) + `graded_cmd`;
`journeys.schema.json` gains `expect_cmd_re`. `run_journeys.py::main`
validates the emitted bundle against the schema when `jsonschema` is
importable (report-only warning otherwise); `test_runner.py` asserts a full
fixture run validates.

## 4. CI fixes (`.github/workflows/dogfood.yml`, skill scripts)

- **Failure-log artifact path** repointed at the real data dirs
  (`/tmp/izd-*/**/sandboxes/*/logs/*` — implementer verifies the per-journey
  layout); today's `${{ runner.temp }}/izba-dogfood-*` glob matches nothing.
- **Collector glob** widened to `*traj-*.json` so `gui-traj-N.json` bundles
  reach Phase-3 collection (GUI kinds are already handled in the collector).
- **`max_usd` re-documented as per-shard** (no silent division); the input
  description and `dispatch-swarm.sh` state the worst-case total
  (`max_usd × (cli_shards + gui_shards)`).
- **Dynamic matrices via a setup job:** a cheap first job reads
  `inputs.shards`/`inputs.gui_shards` and the dispatched journey set (the
  file at `inputs.journeys_path`, see §5), emits `fromJSON` matrices, and **skips the GUI job when the set has no
  `modality:"gui"` journeys** (kills the hardcoded-3 guard that failed both
  2026-07-02 runs, and the 3× wasted Tauri builds on CLI-only tiers).
- **Job summary:** a step renders per-journey tallies (positive / flipped /
  unreached / infra) into `$GITHUB_STEP_SUMMARY` so a run is eyeballable
  without downloading bundles.

## 5. Standing smoke corpus (owner decision: manual/weekly only)

- `hack/dogfood/journeys/smoke-core-cli.json` committed on `main`: seeded
  from `fixtures/journeys.smoke-core-cli.json`, extended toward one journey
  per top-level user workflow (bring-up, exec, stop/start, port publish,
  volume, firewall/netlog view), novice-goal-achievement oracles only.
  Schema-validated in pytest.
- `dogfood.yml` gains a `journeys_path` input (default: repo-root
  `journeys.json`, today's convention) and a **weekly `schedule:` cron** on
  `main` running the committed corpus report-only with the §4 job summary.
  No push trigger.

## 6. Skill / agents / flow

- **D1 `docs/dogfooding-value.md`** — the §1 placement model, written for
  future contributors (human or agent): what the harness uniquely measures,
  the division of labor vs e2e, the synergy loops (graduation, freshness,
  smoke probe, ledger), the rejected exclusion map with rationale, the cost
  architecture. Linked from the CLAUDE.md documentation map and from
  `references/methodology.md`.
- **SKILL.md + methodology:** Phase 4 gains the **graduation step**
  (behavioral finding → fix + distilled e2e test; UX finding → docs/help fix
  or issue) and the **ledger append**; new candidate kinds documented; smoke
  corpus role documented.
- **Signal/noise ledger:** `hack/dogfood/ledger.jsonl` (one JSON line per
  run: date, feature, tier, journey totals per bucket, post-skeptic
  kept/refuted counts), appended in Phase 4 via a small
  `scripts/append-ledger.py` fed by the collector totals + skeptic verdict.
- **Structured skeptic output:** `trajectory-skeptic` emits
  `skeptic-verdict.json` (alongside the human `report.md`) conforming to new
  `hack/dogfood/schema/skeptic-verdict.schema.json` — findings[] with
  id/severity/class (real | intended | self-inflicted | discoverability |
  cheating | inconclusive)/fix-routing (auto-fixable | escalate)/journey
  refs/anchor citations, plus the capability verdict
  (established/blocked[]) and per-bucket counts. The orchestrator and
  `dogfood-gap-fixer` consume the JSON instead of parsing prose;
  `append-ledger.py` reads its counts.
- **Agent docs:** `journey-compiler` — `expect_cmd_re` guidance + the
  explicit "e2e coverage never subtracts journeys" rule; `trajectory-skeptic`
  — new kinds (`infra`/`unreached_decisive`/`reconcile_violation`/
  `guest_console` are harness-verified, not refutable claims) + JSON output
  contract; `dogfood-gap-fixer` — consumes one finding object from the JSON.
- **`local-harness.md`:** stale inline skeptic template replaced by a
  pointer to the agent + schema; new exit-code table (0 ok, 2 usage, 3
  catastrophic-infra); smoke-corpus + ledger usage.

## 7. GUI evidence fixes (cheap, Python-side only)

- Persist the per-journey **invoke log** into the GUI trajectory bundle
  (today `run_gui_journeys.py` reads it for `silent_failure` and drops it —
  the skeptic cannot audit those verdicts).
- **Per-action console-error deltas** (offset tracking) instead of re-reading
  the cumulative `__DF_CONSOLE_ERRORS__` array every action (fixes
  double-counting).
- No `app/` changes; the deep oracle work stays out of scope.

## 8. Verification (after PR checks are green)

1. **Bad-key canary (local, unsandboxed KVM):** run the smoke corpus with a
   bogus `OPENROUTER_API_KEY` → expect exit 3 + `infra` candidates in the
   bundle, zero positives.
2. **Unreached-decisive (local fake-model):** a scripted actor that burns
   its budget before the core step → journey tallies `unreached`, not
   positive (also pinned in pytest).
3. **Real swarm dispatch** off the PR branch with the smoke corpus →
   honest tallies in the job summary; bundles validate against the schema.
4. **GUI dispatch** (gui-skeleton set) → `gui-traj-*.json` collected by the
   widened glob; invoke logs present in bundles.
5. **Fresh-context skill e2e:** subagents that read only the updated
   SKILL.md/methodology drive a mini loop (compile → sequence → dispatch →
   collect → skeptic JSON) to prove the documented flow is followable
   without this session's context.

## 9. Testing strategy

TDD throughout (repo convention): every §3/§7 behavior lands with a failing
test first in `test_model.py`/`test_oracles.py`/`test_runner.py`/
`test_run_gui_journeys.py`; the dogfood pytest suite is already a required
CI gate. No Rust changes → the six workspace gates must stay green but are
untouched; no `app/` changes → app gate untouched. Workflow changes are
exercised by the §8 dispatches (dogfood.yml is `workflow_dispatch`; it must
be dispatched off the PR branch to test, which §8.3/8.4 do).

## 10. Risks / notes

- The >50% degraded threshold is a heuristic; it only needs to catch
  catastrophic failure (dead key ⇒ 100% degraded). Threshold is a named
  constant with a test at the boundary.
- Widening the collector glob makes CLI+GUI bundles land in one collection;
  bucket totals gain a `modality` split so tallies stay interpretable.
- The weekly cron spends ~$1–2 OpenRouter + free public-repo runner minutes
  per firing; report-only, so a red weekly run means infra, not findings.
- `sequence-journeys.py` and the tier fields stay orchestrator-facing
  (documented as such); enforcing `requires`/`establishes` in the runner is
  #116's scope, not this PR's.
