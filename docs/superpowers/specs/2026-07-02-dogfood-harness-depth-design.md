# Dogfood harness: unblock deeper journeys — design

**Date:** 2026-07-02
**Status:** approved (implementation)
**Closes:** #111 (oracle can't express expect-non-zero + setup-noise masks core
assertions) and the depth follow-ups recorded on #111 from the PR-119
(diff/promote) dogfooding run.

## Problem

The LLM-dogfooding harness (`hack/dogfood/`) systematically mis-grades journeys
and cannot reach a feature's deep surface. Three compounding defects, all
code-confirmed against the PR-119 run:

1. **Setup/recovery noise buries the core assertion.**
   `collect-trajectories.py` marks a journey positive **iff it has zero
   candidates**, and `run_journeys.py::_collect_candidates` runs
   `functional_oracle` on **every action of every step** using that step's
   `expect`. So a single non-zero exit in a *setup* step, or an *intermediate
   recovery* action inside an otherwise-passing step, emits a `functional`
   candidate and flips the whole journey to negative. In the PR-119 run this
   produced **0/20 positive** while ~13 journeys had actually satisfied their
   decisive assertion (including two security wins: `⚠ weakens egress` verified
   in both `diff` and `promote`; `export` leaks no key material).

2. **No way to assert an expected failure.** `functional_oracle` only infers
   "a refusal is expected" from fragile English keywords (`_EXPECT_FAILURE_RE`).
   A journey that legitimately expects `izba ssh NAME -- false` → exit 1 has no
   declarative way to say so, so a correct non-zero exit is flagged as a bug.

3. **Deep journeys never reach the gate.** Security-gate journeys
   (review-token/TOCTOU, never-reviewed refusal, `--force`-loud, image-change
   `--restart`) require a **valid `izba.yml`** to exist first. With no way to
   seed one, every such journey burned its steps authoring a manifest and died
   on the #122 required-fields wall before reaching the assertion — the entire
   review-gate surface got **zero** signal.

Two smaller defects ride along:

4. **exit-255 mis-map.** `implicit_oracle` maps any `code > 128` to
   `Signal(code-128)`, so ssh/scp's `255` (a transport/connection failure)
   becomes the nonsensical `Signal(127)`.

5. **cwd resets between actions.** `run_journey` pins `workdir = <data>/proj`
   and passes it to *every* `run_action`; each `bash -c` starts fresh, so
   `mkdir X && cd X` never persists. This caused the `proj`-vs-`metadata.name`
   name-resolution noise (a `cd` in one action, then `izba run .` in the parent
   dir in the next).

## Goals / non-goals

**Goals.** Restore the deterministic gate's fidelity (no human re-triage to
recover signal) and let journeys reach a feature's deep surface, while keeping
the fair-test boundary intact.

**Non-goals.** No change to the "LLM proposes, oracle disposes" architecture, the
swarm model selection, or the fair-test boundary itself. The `sleep infinity`
keep-alive action cap (#111 AC#5) is **explicitly deferred** — noted here, not
built.

## Design

One cohesive change to the `hack/dogfood/` signal path, five parts.

### A. Decisive-step grading (schema + runner + collector)

- **Schema (`journeys.schema.json`, `step`):** add optional `core: boolean`
  (default false). A journey's **decisive steps** are the `core`-marked ones, or
  — if none is marked — **the last step** (the "grade the decisive (last/core)
  step" rule).
- **Runner grading restructure.** Today `functional_oracle` fires per action.
  Change it to fire **once per step, on that step's final action** (the action
  the step actually ended on). Intermediate recovery actions no longer emit
  `functional` candidates. `implicit` (crash markers / exit-code contract),
  `latency`, and `reconcile_seq` stay per-action (a crash anywhere is still a
  crash).
- **Decisiveness tag.** Each `functional` candidate is tagged `decisive: bool`
  (true iff it came from a decisive step). `trajectory.schema.json`'s
  `candidate` gains an optional `decisive` field.
- **Collector tally (`collect-trajectories.py`).** A journey flips to **negative**
  only on a **flipping** candidate: any `implicit`/`reconcile_seq`, or a
  **decisive** `functional`. Non-decisive `functional` and all `latency`
  candidates become **soft** — still recorded and surfaced to the skeptic (they
  are real UX signal), but they do not bury the journey. `positive_journeys`
  counts journeys with no flipping candidate.

  Rationale for `latency` always-soft: an over-budget latency is a UX finding
  worth surfacing, but it is never the pass/fail of the user's goal; burying a
  whole journey on it was pure noise.

### B. Declarative `expect_exit` (schema + oracle)

- **Schema (`step`):** add optional `expect_exit`: an integer, or the string
  `"nonzero"`.
- **Oracle.** When `expect_exit` is present it drives `functional_oracle`:
  `"nonzero"` → candidate iff exit == 0; integer `N` → candidate iff exit != N.
  It supersedes the keyword heuristic. When absent, the existing `expect`
  keyword path (`expects_failure`) is the fallback — backward compatible.
- Satisfies #111 AC#1: a step declaring `expect_exit: "nonzero"` (or `1`) grades
  `izba ssh NAME -- false` → exit 1 as a **PASS**, zero false candidates.

### C. exit-255 mapping (oracle)

`implicit_oracle` special-cases `exit_code == 255` **before** the `>128` arm →
a candidate described as an "SSH/scp transport-or-connection failure (exit 255)",
never `Signal(127)`. (255 = 128+127 can never be a real signal.) The detail
notes the ssh/scp family when the command is one.

### D. cwd persistence (runner + oracle)

- `run_action` gains an optional `cwd_file: Optional[str]`. When set, it runs
  the command **starting from the saved cwd** and writes the resulting `$PWD`
  back:

  ```
  bash -c 'cd "$START" 2>/dev/null || cd "$WORKDIR"; { <command>; }; __rc=$?;
           printf "%s" "$PWD" > "$CWD_FILE"; exit $__rc'
  ```

  The command's own exit code is preserved (`__rc`). When `cwd_file` is `None`
  (the default, and every existing test) behavior is unchanged: fresh `workdir`
  each action.
- `run_journey` allocates one `cwd_file` per journey (seeded to `workdir`) and
  threads it through, so cwd persists across actions like a real shell.

### E. Precondition seeding (schema + runner) — the depth enabler

- **Schema (`journey`):** add optional `seed_files`: an object mapping a
  **relative** path → file **content** (string).
- **Runner.** Before a journey's first action, `run_journey` writes each
  `seed_files` entry into `workdir`, creating parent dirs. Paths are
  traversal-guarded exactly like `_journey_data_dir` (reject absolute paths and
  any `..` segment); a rejected/failed write is logged and skipped (report-only).

**Fair-test boundary (why this is not cheating).** The swarm's knowledge surface
is unchanged — seed content lives in `journeys.json`, which the Actor **never
sees** (only README + `--help` + context-pack reach the model). `seed_files`
models a **precondition of the environment**, the same contract the schema
already encodes with `establishes`/`requires`: a deep journey legitimately
assumes a prior journey (or a fixture) established its prerequisite. The
**manifest-authoring discoverability** journeys deliberately do **not** seed and
keep measuring exactly the #122 signal ("can a user write a valid `izba.yml`
from the docs alone?"). The rule the journey-compiler must follow: **seed
preconditions, never the thing under test.** Seeding a valid `izba.yml` for a
*review-gate* journey is a precondition; seeding it for a *manifest-authoring*
journey would destroy the test and is forbidden.

## Testing / proof it goes deeper

**Offline (CI-green, deterministic, no KVM / no API).** A new FakeModel
integration test replays the PR-119 masking scenario as a single deep journey:

- `seed_files` provides a valid `izba.yml` (Part E) → the journey starts at the
  gate.
- Step 1 (setup, non-`core`): a command that exits non-zero **then a recovery
  action that succeeds** — under the old harness this alone buried the journey.
- A `cd` into a subdir in one action, then a command in the next that only works
  if cwd persisted (Part D).
- Step 2 (`core: true`): the review-gate assertion, graded on its final action;
  one variant uses `expect_exit: "nonzero"` to prove Part B.

Assertions: the collector reports the journey **positive**; the setup-step
non-zero exit appears only as a **soft** candidate; the decisive assertion is the
one that governs the tally. This is precisely #111's acceptance test ("replay
the loop-4 artifact under the updated oracle → corrected positive/negative
tally"). Plus focused unit tests for each oracle/schema change.

**Live micro-swarm (required gate before declaring success).** Dispatch
`dogfood.yml` **on the feature branch** (so the swarm runs against the *new*
harness) with a capped `max_usd`, on 1–2 deep **seeded** security-gate journeys.
Success = the swarm's trajectories reach the review-gate/TOCTOU surface the old
harness masked (visible in the downloaded bundles), and the collector tallies
them without the setup-noise false negatives. This is the empirical proof the
harness now goes deeper, not just the unit-level proof.

## Acceptance criteria

- [ ] A step can declare `expect_exit` (`"nonzero"` or an int); `izba ssh NAME
      -- false` → exit 1 grades as PASS, zero false candidates.
- [ ] A step can be marked `core: true`; the collector's `positive_journeys`
      increments when the decisive step passes, regardless of non-zero exits in
      preceding setup/recovery actions. With no `core` mark, the last step is
      decisive.
- [ ] Replaying the PR-119 masking scenario under the new harness reports the
      journey positive (offline test).
- [ ] exit 255 from ssh/scp is reported as a transport/connection failure, not
      `Signal(127)`.
- [ ] `seed_files` materializes a valid `izba.yml` into the workdir before the
      first action, traversal-guarded; the Actor's knowledge surface is
      unchanged.
- [ ] cwd persists across actions within a journey; `cwd_file=None` preserves
      existing behavior (all current tests pass unmodified).
- [ ] `sleep infinity` cap explicitly deferred (this doc) — does not block merge.
- [ ] A live micro-swarm on the feature branch reaches a deep seeded
      security-gate surface and is tallied without setup-noise false negatives.

## Risks / trade-offs

- **Grading only the decisive step's final action** could miss a mid-step
  regression that the Actor "recovered" from by changing goals. Accepted: the
  skeptic still sees every action and every soft candidate; the tally is about
  *whether the user's goal was met*, and recovery from an actionable error is
  normal user behavior (the exact false-negative class #111 targets).
- **`seed_files` is a foot-gun** if misused to seed the thing under test. Guarded
  by the documented compiler rule + the fair-test note; the discoverability
  journeys demonstrate the correct non-seeding pattern.
