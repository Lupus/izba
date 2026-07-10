# Local dogfooding harness — Phase 1 & Phase 3 (Claude Code, strong model)

Operator runbook for the two strong-model phases of the spec-anchored dogfooding
pipeline. Run these locally in Claude Code on the owner's subscription. Phase 2
(the cheap-model journey loop) runs in CI between them — see
[`README.md`](README.md).

- **Phase 1** turns the feature's anchors (spec + PR + Greptile + `--help`) into
  a `journeys.json`, then dispatches the CI fan-out.
- **Phase 3** loads the downloaded trajectory bundles, runs an adversarial
  skeptic over every candidate finding, and synthesizes the survivors into
  `report.md`.

Design rationale: [`docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md`](../../docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md).

---

## Phase 1 — intent extraction

Goal: produce a `journeys.json` conforming to
[`schema/journeys.schema.json`](schema/journeys.schema.json), then hand it to CI.

### 1.1 Gather the anchors

Read all four; the spec is primary, the rest disambiguate the *real* current
surface. The anchor is mandatory — a thin anchor means a weak oracle and more
slop. Refuse to invent journeys for behavior no anchor promises.

- [ ] **Spec** — the feature's superpowers spec under `docs/superpowers/specs/`.
      This is the promised behavior; it is the source of truth for every
      `expect`.
- [ ] **PR description** — what the author claims was built:

  ```bash
  gh pr view <n> --json title,body
  ```

- [ ] **Greptile review summary** — the independent reviewer's description of the
      *actual* change (state graphs, not author framing). Pull it via the
      Greptile MCP tools. List what is available, then fetch the latest review
      for this PR. Generically:
  - find the MR/PR Greptile tracks: a list tool such as
    `mcp__greptile__list_pull_requests` / `mcp__greptile__list_merge_requests`
    (match the PR number / branch);
  - fetch the latest review: `mcp__greptile__get_code_review` (or
    `mcp__greptile__list_code_reviews` then take the newest);
  - optionally `mcp__greptile__list_merge_request_comments` /
    `mcp__greptile__search_greptile_comments` for per-finding detail.
  - If Greptile has no review yet, trigger one (`mcp__greptile__trigger_code_review`)
    and wait, or proceed spec-only (PR/Greptile are optional anchors).
- [ ] **Command surface** — `--help` for every touched subcommand, so journeys
      use real flags/verbs:

  ```bash
  izba --help
  izba <cmd> --help        # for each subcommand the PR touches
  ```

  Cross-check against the relevant README sections.

### 1.2 Write `journeys.json`

A *journey* is a goal a real user would have given the spec's promises,
decomposed into ordered intent steps. Journeys are **intent, not literal
commands** (the Phase-2 Actor chooses the actual `izba` invocations) and are
**independent** (that independence is what makes Phase 2 shardable). Each step
carries an `expect`; each journey carries the `source` of its expectation so the
skeptic can trace it.

Conform to [`schema/journeys.schema.json`](schema/journeys.schema.json). Object
shape:

```jsonc
{
  "feature": "publish-ports",
  "journeys": [
    {
      "journey_id": "publish-port-and-reach-it",
      "rationale": "Spec §4 promises `-p HOST:GUEST` makes a guest service reachable from the host.",
      "source": { "kind": "spec", "ref": "2026-06-12-...-design.md §4" },
      "steps": [
        { "intent": "create a sandbox publishing 8080->80", "expect": "create succeeds, `ls` shows the port" },
        { "intent": "run an http server in the guest on :80", "expect": "exec returns, server is listening" },
        { "intent": "curl localhost:8080 from the host",      "expect": "HTTP 200 within a few seconds" }
      ]
    }
  ]
}
```

- `source.kind` is one of `spec | pr | greptile | help | readme`; `source.ref` points at
  the exact section / PR / review the expectation comes from.
- Every `expect` must be traceable to an anchor. If you cannot cite a source for
  an outcome, do not assert it.
- Keep journeys small and orthogonal; favor breadth (the boring permutations the
  owner skips) over depth.
- Mark the journey's decisive assertion(s) `"core": true` and give it an
  `expect_cmd_re`: besides pinning which action gets graded, it lets the runner
  credit the assertion if the swarm satisfies it under an earlier step instead
  of flagging `unreached_decisive`.
- [ ] Validate the file against the schema before pushing (any JSON-schema
      checker, e.g. `python3 -c "import json,jsonschema,sys; jsonschema.validate(json.load(open('journeys.json')), json.load(open('hack/dogfood/schema/journeys.schema.json')))"`).

### 1.3 Dispatch into CI — dispatch branch, NO PR

The journeys ride into CI on a throwaway branch. **Do not open a PR.** A PR off
this branch would fire the `pull_request` gates (`ci.yml`, `app.yml`,
`coverage.yml`) — wasteful and noisy. A bare push to `dogfood-run/*` triggers
**nothing** (push triggers are `main`-only); `dogfood.yml` runs only via
`workflow_dispatch`. Branch from `main` so `dogfood.yml` is present on the ref.

```bash
# 1. fresh branch off main (so the dispatched ref carries dogfood.yml)
git fetch origin
git switch -c dogfood-run/<feature> origin/main

# 2. drop the journeys in at the repo root and commit
cp /path/to/journeys.json journeys.json
git add journeys.json
git commit -m "dogfood: journeys for <feature>"

# 3. push the branch — NO PR (a PR would trigger pull_request gates)
git push -u origin dogfood-run/<feature>

# 4. dispatch the CI fan-out against that ref
gh workflow run dogfood.yml \
  --ref dogfood-run/<feature> \
  -f shards=3 \
  -f max_usd=2

# 5. watch the run to completion
gh run watch        # or: gh run list --workflow=dogfood.yml --branch dogfood-run/<feature>

# 6. download the per-shard trajectory artifacts (traj-0.json, traj-1.json, ...)
gh run download <run-id> --dir ./dogfood-artifacts
```

- [ ] Confirm the branch is off **current** `origin/main` (rebase if behind).
- [ ] Never push to `main`; never open a PR for a `dogfood-run/*` branch.
- [ ] After the run, the branch can be deleted — it carries no reviewable work.

### 1.4 Run outcomes — the honest exit codes

The run is **report-only**: findings never fail a shard. Both runners
(`run_journeys.py` and `gui/run_gui_journeys.py`) use the same exit codes to
distinguish "ran" from "couldn't measure", so a CI shard fails loudly only when
the run was not a measurement:

| exit | meaning |
|---|---|
| `0` | ran to completion — findings are report-only, a green shard is not "no bugs" |
| `2` | usage / startup error (bad args, missing model config) |
| `3` | **catastrophic infra** — more than half the journeys degraded (zero actions or an `infra` candidate). Check `OPENROUTER_API_KEY` first; a dead key degrades every journey. |

Exit 3 is the instrument-honesty backstop: below the threshold a transient model
blip stays report-only (it must not kill a 40-minute shard); above it, the run
verified nothing and must not read as a green void.

### 1.5 The standing smoke corpus (weekly cron)

Most journey sets are throwaway (recompiled per feature). The **one** committed
exception is `hack/dogfood/journeys/smoke-core-cli.json` — a novice smoke set, one
journey per top-level workflow, whose only oracle is goal achievement. It rides a
weekly Monday cron in `dogfood.yml` (report-only), and any manual dispatch can
point at a committed journeys file via the `journeys_path` input (default: the
smoke corpus). Everything deeper stays fresh; see
[`docs/dogfooding-value.md`](../../docs/dogfooding-value.md) §5–6.

---

## Phase 3 — skeptic + synthesis

Goal: turn the downloaded trajectory bundles into a deduped `report.md` of
**real** findings. This adversarial pass is the single biggest quality lever —
expect ~20-50% precision *before* it; its whole job is to refute the rest.

### 3.1 Load the bundles

- [ ] Read every per-shard bundle (`dogfood-artifacts/**/*traj-*.json` — the
      CLI shards' `traj-*.json` and the GUI shards' `gui-traj-*.json`),
      conforming to
      [`schema/trajectory.schema.json`](schema/trajectory.schema.json). Each
      bundle has `results[].candidates[]` (candidate findings) and
      `results[].actions[]` (the trajectory: command, exit_code, stdout/stderr
      tails, latency_ms, reconcile snapshot).
- [ ] Flatten all candidates across all shards into one working list, each tagged
      with its originating `journey_id`, shard, and `trajectory_ref`. (The CI job
      already renders a per-bundle tally into the run summary via
      `summarize_bundle.py <traj.json> [...]` — read it for a quick
      journeys/positive/flip/infra/unreached overview before you dig in.)

### 3.2 Run the adversarial skeptic on each candidate

For every candidate, *try to disprove it* using the anchors. Classify as exactly
one of:

- **real** — observed behavior contradicts a traceable expectation (the
  candidate's `violated_expectation` + `source` check out against the spec/PR/
  Greptile/help). → **keep**.
- **intended** — the behavior is actually documented or specified; the agent
  misread it as a bug. → **drop**.
- **self-inflicted** — the failure was caused by the agent's *own* input, not by
  izba. Canonical example: an infinite `bash` loop *inside* `izba exec` makes the
  action hang and trips the latency oracle — that is the agent's command
  hanging, **not** izba. → **drop**.

Bias toward dropping: only keep a candidate you can tie to a concrete,
anchor-traceable expectation.

#### Run the skeptic agent, not an inline prompt

Dispatch the `trajectory-skeptic` agent (`.claude/agents/trajectory-skeptic.md`) —
it emits `report.md` + `skeptic-verdict.json` (schema:
`hack/dogfood/schema/skeptic-verdict.schema.json`). The old inline template
predates the discoverability class, the Direction-B green audit, and the JSON
contract.

### 3.3 Synthesize survivors into `report.md`

- [ ] **Dedup** near-identical findings: collapse candidates that share the same
      **surface** (touched subcommand / state object) **and** the same
      **violated expectation** into one entry, keeping the clearest trajectory.
- [ ] For each surviving finding, write an entry:

  ```markdown
  ## <short title>

  - **Violated expectation:** <the `expect` that did not hold>
  - **Source:** <source.kind §ref — spec / PR / Greptile / help>
  - **Description:** <1-3 sentences: what a user tried and what actually happened>
  - **Trajectory:** <ordered commands + key outputs/exit codes/latency/reconcile
    snapshot — enough to reproduce; reference the shard + journey_id>
  ```

- [ ] Output is `report.md`. Findings are **candidates for the owner**, not
      verified bugs — minimization is out of scope here (the owner does that
      locally). Report-only; never a merge gate.

### 3.4 Append the run to the signal/noise ledger

- [ ] Record the run's tallies so signal-quality drift is tracked across runs
      instead of from memory:

  ```bash
  scripts/append-ledger.py \
    --collected collected.json \
    --verdict   skeptic-verdict.json \
    --feature   <feature> --tier <smoke|core|deep>
  ```

  `--collected` is the `collect-trajectories.py --json` output (per-bucket journey
  tallies); `--verdict` is the skeptic's `skeptic-verdict.json` (its kept/refuted
  counts). One JSON line is appended to `hack/dogfood/ledger.jsonl` (report-only;
  never mutates existing lines).
