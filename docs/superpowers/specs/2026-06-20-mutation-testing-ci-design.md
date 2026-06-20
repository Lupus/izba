# Mutation testing in CI — design

**Status:** approved design (2026-06-20)
**Topic:** integrate `cargo-mutants` into izba CI — a blocking incremental gate on
new code, plus a scheduled full run that publishes a machine-readable worklist an
LLM agent can address iteratively in the background.

## Motivation

Line/branch coverage (already published report-only via `coverage.yml`) tells us
which lines *executed* under test, not whether the tests would *notice if those
lines were wrong*. Mutation testing closes that gap: `cargo-mutants` rewrites the
code in small, behavior-changing ways (a `+` becomes `-`, a `>` becomes `>=`, a
function body is replaced with a default) and reruns the test suite against each
mutant. A mutant that the suite still passes ("survives" / "missed") marks a real
assertion gap. We want two things from this:

1. **Discipline on new code** — a PR may not introduce changed lines whose
   behavior no test pins down. This is a blocking gate.
2. **A steady backlog of existing gaps** — a scheduled full run that produces a
   worklist an LLM harness (Claude Code) can pull from and chip away at via
   test-only PRs, iteratively, in the background.

## The izba-specific constraint that shapes everything

`cargo-mutants` runs the **host** test suite against each mutant. A large fraction
of `izba-core` (≈18.8k LOC) is KVM/VMM/integration code exercised **only** by
env-gated tests (`IZBA_INTEGRATION=1`, real `/dev/kvm`, real artifacts) that
**self-skip** on hosted CI runners. A mutant planted in such code can never be
killed on a hosted runner — not because the tests are weak, but because the tests
that would catch it never run. Mutating that code produces guaranteed-survivor
noise in the full run and **false blocks** in the incremental gate.

The design therefore treats *scoping* as the central concern, solved once by a
shared skip-list (§1) that both pipelines consume.

> **Revision (2026-06-20): cross-platform model.** The original design excluded
> platform-specific (`#[cfg(windows)]`) code by path, treating it like KVM code.
> That under-covers it: cargo-mutants **cannot see `#[cfg]`**
> ([upstream limitation](https://mutants.rs/limitations.html)) and reports
> another platform's code as "missed" wherever it is cfg'd out — but the Windows
> *tests* genuinely cover that code. So instead of excluding platform-cfg code,
> we run the **same mutant set on BOTH Linux and Windows** (gate *and* full run)
> and reconcile with the **caught-nowhere rule**: a mutant is a real survivor
> only if **no platform caught it**. A `#[cfg(windows)]` mutant is "missed" on
> Linux (cfg'd out, false positive) but "caught" on Windows → dropped; a
> genuine gap is missed on both → kept. The shared skip-list (§1) now excludes
> **only** real-VM (KVM/WHP) code — *not* platform-cfg code. The cross-platform
> reconciliation lives in the shared reporter (`hack/mutants-report.py`) and
> serves both the gate aggregator and the full-run collect job. Sections below
> that say "exclude platform glue" are superseded by this rule.

## 1. Unifying mechanism: one skip-list, two consumers

A single committed `.cargo/mutants.toml` is the source of truth for *what is
mutable*. `cargo-mutants` applies its `exclude_globs` / `exclude_re` filters in
**every** mode of operation — full run, `--in-diff`, and `--shard` alike — so the
same config governs both pipelines. Consequences:

- A PR that touches excluded KVM/VMM code generates **zero** mutants on those
  lines → no false block, and no divergence between "what the gate checks" and
  "what the full run reports".
- There is exactly one place to curate as the codebase grows.

Config shape (illustrative — exact globs finalized during implementation):

```toml
# .cargo/mutants.toml
# Code only reachable by env-gated (KVM/real-VM) tests cannot be killed on a
# hosted runner; excluding it keeps both the PR gate and the full run honest.
exclude_globs = [
    "crates/izba-core/src/vmm/**",        # Cloud Hypervisor / OpenVMM drivers
    "crates/izba-core/tests/**",          # integration harness
    # ... seeded from the initial local full run (see "Seeding" below)
]

# Give the suite headroom; some host tests spawn processes / do timed I/O.
timeout_multiplier = 3.0
minimum_test_timeout = 60   # seconds
```

Per-item escape hatch: `#[mutants::skip]` on a function, **always accompanied by a
one-line justification comment** explaining why the mutant is not worth a test
(e.g. trivial `Debug` impl, untestable platform glue). This is documented in the
contributing guide so reviewers can hold the line on justifications.

### Seeding the skip-list

Before the gate is flipped to blocking, run one local full mutation pass and
triage every survivor into exactly one bucket:

- **Genuinely untestable on host** (KVM-only, platform-glue) → `exclude_globs`
  entry or `#[mutants::skip]` with justification.
- **Real test gap** → leave mutable; it becomes the first worklist for the agent.

This guarantees a clean baseline: once seeded, every *remaining* survivor is a
genuine, host-addressable gap.

## 2. Incremental PR gate (blocking)

Lives in a dedicated workflow `mutants.yml`, triggered `on: pull_request`. Added to
branch protection as a required check.

Steps:

1. `actions/checkout` with enough history to reach the base branch
   (`fetch-depth: 0`, mirroring `coverage.yml`).
2. Compute the merge-base diff of the PR:

   ```sh
   git fetch origin "$GITHUB_BASE_REF"
   git diff "origin/$GITHUB_BASE_REF...HEAD" > pr.diff   # 3-dot = merge-base diff
   ```

3. `Swatinem/rust-cache` (own `prefix-key`), install `cargo-mutants` via
   `taiki-e/install-action`.
4. `cargo mutants --in-diff pr.diff` (workspace).

Outcome contract:

- **Zero surviving mutants on changed lines → pass.**
- **Any survivor → fail**, with the missed-mutant list rendered into the GitHub
  Actions **step summary** so the author sees exactly which changed lines lack a
  pinning assertion, and can either add a test or apply `#[mutants::skip]` with
  justification.
- A PR whose diff touches only excluded files yields an empty mutant set →
  passes trivially (no special-casing needed).
- A **baseline failure** (the unmutated build/test fails, e.g. a flaky test)
  is reported as a distinct, clearly-labeled failure mode — not conflated with
  "you have surviving mutants".

## 3. Scheduled full run (worklist producer)

Same `mutants.yml`, triggered `on: schedule` (weekly cron, consistent with
`e2e.yml`) plus `workflow_dispatch` for on-demand runs.

### Sharded matrix

A single unsharded full run over a workspace this size is multi-hour and risks the
job time limit as the code grows. Instead:

- **Matrix of ~6 shards**: each job runs `cargo mutants --shard k/N` (k = matrix
  index, N = shard count), with `Swatinem/rust-cache` and a generous
  `timeout-minutes`.
- Each shard uploads its `mutants.out/` directory (containing `outcomes.json` and
  the missed/caught/timeout/unviable lists) as a per-shard artifact.

### Collect job

A final `collect` job (`needs:` all shards) downloads every shard artifact and:

1. **Merges + dedups** the surviving ("missed") mutants across shards into one
   ordered list. Each mutant gets a **stable id-hash** derived from
   `file:line:function:mutation-text` so the same gap is identifiable run-to-run.
2. Produces a **report artifact**:
   - `mutants-report.json` — machine-readable: for each survivor, the file, line,
     function, mutation text, crate, and id-hash.
   - a ranked markdown summary (grouped by crate/file, ordered by impact) also
     written to the job **step summary** (mirrors the `coverage.yml` gap-report
     convention).
3. **Upserts the tracking issue** (see §3.1).

### 3.1 Tracking issue (the agent's worklist)

A single pinned GitHub issue labeled `mutation-gaps` holds the live worklist.

- The issue **body is regenerated from ground truth on every scheduled run** — it
  lists *only currently-surviving* mutants, as a checklist grouped by crate/file
  and ordered by impact, with each item carrying its file:line, mutation text, and
  id-hash.
- Killed mutants simply disappear from next run's body — there is **no persistent
  checkmark / in-progress state to reconcile**. The source of truth is always "what
  still survives right now", which keeps the bookkeeping trivial and self-healing.
- `gh issue edit <n> --body-file …` if the labeled issue exists, else
  `gh issue create --label mutation-gaps …`.

Rationale for "regenerate from ground truth" over preserving checkbox/in-progress
state: mutation results are fully derivable from the code at any commit, so the
weekly run is authoritative. An agent PR that lands a killing test removes the item
next run automatically; an agent PR still in flight leaves the item present, which
is harmless (the agent dedups against its own open PRs via the `mutation-gaps` PR
label, §4). This avoids a whole class of stale-state bugs.

## 4. The agent loop (scheduled cloud routine + runbook)

### Runbook / skill

A documented loop (committed as a runbook, optionally promoted to a skill) that the
agent follows precisely:

1. Read the `mutation-gaps` tracking issue; pull `mutants-report.json` from the
   latest scheduled-run artifact for detail.
2. Dedup against already-open PRs labeled `mutation-gaps` (don't re-attempt a
   mutant a still-open PR already targets).
3. Pick a batch (capped per run).
4. For each mutant: write a **killing test** following TDD — confirm the test
   *fails* against the mutation's intent and *passes* against the real code.
5. Run the six workspace gates (fmt, clippy, test, musl init build, windows-gnu
   check, windows-gnu clippy) before proposing.
6. Open **one PR per batch**, labeled `mutation-gaps`, linking the issue items it
   addresses.

**Hard guardrail:** the agent **only adds tests** (and, with a written
justification, `#[mutants::skip]`). It must **never** alter production logic to
make a mutant unviable or to satisfy the suite. The incremental PR gate (§2) then
validates the agent's own PRs, closing the loop.

### Scheduled cloud routine

A `/schedule` cloud routine runs a few days after the weekly mutation run (so the
worklist is fresh), executes the runbook autonomously, caps PRs per run, and stops
when the issue is empty. Guardrails: tests-only (above), per-run PR cap, and the
gate re-validating every PR it opens.

## 5. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Full-run wall-clock explosion | Sharded matrix + `rust-cache` + skip-list; weekly cadence; generous per-shard `timeout-minutes`. |
| KVM-only code → guaranteed survivors / false blocks | Structurally handled by the shared skip-list (§1); seeded once, curated in one place. |
| Baseline flakiness aborts the run | `minimum_test_timeout` + `timeout_multiplier` in config; gate reports baseline failure distinctly from survivors. |
| Agent scope creep (editing prod logic) | Tests-only guardrail + per-run PR cap + the incremental gate re-validating agent PRs. |
| Stale worklist state | Issue regenerated from ground truth each run; no checkmark reconciliation. |
| Gate friction on legitimately-hard-to-test diffs | `#[mutants::skip]` + justification, documented escape hatch. |

## 6. Deliverables

- `.cargo/mutants.toml` — shared skip-list + timeouts, seeded from an initial
  local full run.
- `.github/workflows/mutants.yml` — incremental gate job (`on: pull_request`,
  branch-protection required) + sharded full-run matrix and collect job
  (`on: schedule` weekly + `workflow_dispatch`).
- Tracking-issue upsert script (used by the collect job).
- Agent runbook/skill documenting the tests-only iterative loop.
- A `/schedule` cloud routine wiring the runbook to run after the weekly mutation
  run.
- Contributing-guide note documenting `#[mutants::skip]` + justification.

## 7. Out of scope (for now)

- Running mutants under KVM on the e2e runners (booting a VM per mutant is
  impractical); KVM-only code stays excluded.
- Mutating the Tauri app (`app/src-tauri`, outside the cargo workspace) — a later
  phase, paralleling how `coverage.yml` defers the app.
- A fixed survivor "budget" / threshold gate — the gate is zero-survivors with
  explicit skips, not a fuzzy count.
