# LLM dogfooding — methodology & field notes

Depth behind [SKILL.md](../SKILL.md). Read when designing journeys, tuning the
oracle, or interpreting a run. Grounded in real izba runs (the harness lives in
`hack/dogfood/`; the original design is
`docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md`).

## Why this exists

Fuzzing, mutation, property, and e2e tests prove the product is *wired*
correctly. They do not prove it is *usable* — that a person (or an agent) trying
to accomplish a real goal from the documented surface can actually succeed. That
gap — "I tried to use it as intended and it broke / wasn't obvious" — is what
this finds. The output is a **bug description + trajectory**, not a minimized
repro; minimization is cheap to do locally afterward.

## The three-way information boundary

The method is an experiment with three roles holding deliberately different
knowledge:

- **Compiler (privileged)** knows the spec → writes journeys and *citable*
  expectations, and launders all privileged knowledge out of the swarm's inputs.
- **Swarm (fair)** knows only the user-visible surface (README + `--help` + docs)
  → attempts the goals. Its struggles are data.
- **Skeptic (privileged)** knows the spec → judges both failures and successes
  against ground truth.

The payoff: the delta between *possible-per-spec* and *achievable-from-the-user-
surface* is exactly the product's discoverability/UX debt. You only measure it if
the swarm is kept fair. Helping the swarm collapses the experiment.

## Anchor hierarchy (for the compiler)

Source of truth for `expect`, in order: **spec** (what was promised) → **PR body**
(what the author claims was built) → **code review** (independent description of
the actual change — often the most honest) → **`--help`/README** (the user-visible
surface). Use all of them for *coverage*; use only the user-visible subset for the
*swarm's context pack*.

## The deterministic oracle — "LLM proposes, harness disposes"

After every action the harness runs checks the LLM cannot fake. These gate the
swarm's candidates and are the anti-slop spine (see `hack/dogfood/oracles.py`):

- **Reconcile snapshot** — a single-shot consistency check of declared-vs-real
  state (list == reality, disk == live, no orphan relays/volumes). Independent of
  the swarm's narration; the skeptic uses it to corroborate claims.
- **Implicit** — scrape output for crash markers (`panic`, `assertion failed`,
  anchored `ERROR`/`FATAL`, sanitizer) and decode the exit-code contract
  (e.g. 127 → command-not-found, 128+n → signal n).
- **Latency** — flag actions slower than a human would tolerate (a hang is a
  finding) — but a hang *inside* the swarm's own command (infinite loop in
  `exec`) is self-inflicted, not the product's fault.
- **Functional (two-sided)** — compare exit code to the step's `expect`:
  expected-success + non-zero = candidate; **expected-failure + exit 0 = candidate**
  (a guard that should have fired silently didn't); expected-failure + non-zero =
  pass (this two-sidedness removes the bulk of rejection-journey false-positives).

Sequence invariants the single-shot reconciler can't see (idempotency, monotonic
restart identity, legal transitions) are the harness's job, computed by diffing
consecutive snapshots.

## Candidate taxonomy — NEGATIVE trajectories (the skeptic's Direction A)

- **real** — contradicts a traceable expectation. Keep. (cite anchor + line)
- **intended** — an anchor documents it; the swarm misread. Drop.
- **self-inflicted** — the swarm's own input caused it (bad value, wrong name,
  shell-quoting botch, infinite loop tripping latency). Drop.
- **discoverability** — the swarm couldn't use the feature because the user-visible
  surface genuinely lacks the info (verb missing from `--help`, undocumented value
  grammar, unexplained ordering). Keep as a **UX finding** — this is a headline
  output, not noise.

Bias toward dropping. Expect 20–50% precision *before* the skeptic; refuting the
rest is its whole job.

## Cheating taxonomy — POSITIVE trajectories (the skeptic's Direction B)

A green is a claim, not a result. Audit every "successful" journey for:

- **unverified success** — asserted an outcome, never ran the confirming command;
  snapshot/exit don't corroborate.
- **cheated / wrong mechanism** — hit the surface condition via a path that
  bypasses the feature (persistence "verified" without a real remove+recreate;
  port reachability tested inside the guest not the host; an exit-code reached via
  a different cause; an `expect` substring matched coincidentally).
- **tautological / premature done** — declared done before reaching the assertion.
- **hidden failure** — exit 0 but output shows a no-op / ignored / warned action.

Verdicts: genuinely-achieved (cite lines + independent corroboration) |
cheated/unverified (a finding or coverage gap) | inconclusive (the journey is too
weak to verify its promise → **coverage finding**: tighten the journey).

## The loop — find → improve → re-find

Every run produces two kinds of output; act on both:

- **Product findings** → file issues (crisp description + trajectory). See the
  `github-backlog-management` skill for proper INVEST-shaped issues.
- **Harness/coverage gaps** → fix and re-run: oracle false-positives, journeys
  that derailed before their assertion, caps that tripped early, context-pack gaps
  (which, if the swarm needed them, are themselves discoverability findings).

**Signal/noise maturation is how you know it's working.** Track candidate count
and classification across runs. A maturing pipeline shows fewer candidates,
higher precision, and *deeper* coverage (more journeys actually reaching their
assertions). A real izba sequence ran 18 → 13 → 6 candidates across three runs as
harness and product fixes landed — the drop wasn't fewer bugs hidden, it was less
noise and journeys finally reaching the assertions that surfaced a genuine
durability edge. Don't declare done on a single run; iterate until it stabilizes.

## Progressive, gated, self-improving loop

Running the whole journey set in one big swarm wastes budget when a single
shallow gap blocks many journeys at once — e.g. an undocumented prerequisite (CA
trust, "allow-list your mirror") that makes 30+ deep journeys fail the same way.
Real izba run: loop-3 spent ~35 candidates on "guest tooling missing / didn't
know to allow-list the mirror" — one shallow gap, paid for 35 times. Test the
basics first; go deep only once the swarm demonstrably reaches the needed depth.

**Separate compile from sequence.** Phase 1 (`journey-compiler`) compiles for
COMPLETENESS — the whole set, every promise — and tags each journey with
`tier`/`establishes`/`requires`/`gating`. Phase 2 (`sequence-journeys.py`)
deterministically rearranges that set into ordered tiers + a capability/gate
plan. Keeping them separate lets you re-sequence or re-gate without recompiling.

**Tiers.** `smoke` — few, cheap, shallow: happy-path + the **capability probes**
deeper tiers depend on (the obvious-gap detector). `core` — the bulk of feature
coverage. `deep` — adversarial / edge / multi-step / cross-entity, presupposing
the smoke capabilities already work.

**The gate — advance / fix / defer.** After each tier's swarm + a per-tier
`trajectory-skeptic` pass:

1. For each **gating** journey not genuinely-achieved, read the finding's
   fix-routing:
   - **auto-fixable** → dispatch `dogfood-gap-fixer` (one finding at a time —
     shared working tree), it commits on the CI branch; then **re-run the tier**
     off the new tip (`DOGFOOD_BASE=HEAD`), bounded to ~2 retries so a stubborn
     gap can't loop forever.
   - **escalate** → record a blocker; mark the capabilities it would have
     `established` as **blocked**.
2. `established` capabilities = union of `establishes` across genuinely-achieved
   journeys (read from the skeptic's capability verdict).
3. Before the next tier, **defer** (never silently drop) any journey whose
   `requires` names a blocked capability — log each deferral with its blocker, so
   the report shows exactly what the swarm couldn't reach and why.
4. Advance when the tier's gating journeys pass (or are escalated with their
   dependents deferred).

This is what makes the loop **self-clearing**: each tier's well-scoped gaps are
fixed in-place so the next tier explores deeper instead of re-stumbling.

### In-place auto-fix safety boundary (the load-bearing guardrail)

Autonomous in-place fixing is safe ONLY because it is strictly bounded. The rule:
**change what the product SAYS, never what it DOES; when in doubt, escalate.**

| AUTO-FIX (well-scoped, no behavior change) | ESCALATE (blocker — never auto-edit) |
|---|---|
| README / `docs/**` / `*.md` prose (document an undiscoverable-but-shipped behavior) | Control flow, datapath, defaults, policy/enforcement **semantics** |
| `--help` / clap doc-comment & `help=` **text** | Anything touching a **trust boundary / security posture** (`docs/security/`) |
| Human-facing error/log message **wording** (not the trigger, not exit codes) | New/changed **public contract**: flag, subcommand, RPC, wire/JSON schema, renamed field (CLAUDE.md "load-bearing contracts") |
| The dogfood **harness** (`hack/dogfood/**`, the skill, journeys/oracles/schema/context-pack) | **Validation logic** that changes what is accepted/rejected (e.g. tightening a name-length check — that is behavior; *file* it) |
| Comments / typos | Dependency bumps; anything needing a **design decision** or spec change; anything ambiguous |

The canonical escalate is the SUN_LEN name-length finding: it looks like a small
fix but tightening `validate_name` changes what's accepted → file an issue, don't
auto-fix. The fixer agent (`dogfood-gap-fixer`) re-checks this boundary itself and
refuses anything outside it — the orchestrator's routing is a hint, not a license.

### CI-branch hygiene (where fixes land)

Two kinds of branch — don't confuse them:

- **`dogfood-run/<feature>` (+ optional `-tier` suffix)** — throwaway dispatch
  branches, journeys-only, force-pushed, NEVER a PR (the gates `branches-ignore`
  them). Cut each from the **fixes-branch tip** via `DOGFOOD_BASE` so the swarm
  reads the latest in-place fixes. Delete them when done.
- **`dogfood-fixes/<feature>`** (or a descriptive `docs/…`/`fix/…` branch) — the
  REAL branch the in-place fixes accumulate on, which becomes a PR.

When the loop settles, before reporting: ensure the **SonarQube / SonarCloud**
gate is green (exclude daemon-wired harness glue from the coverage gate and
`#[mutants::skip]` it — see the "Harness code in the product repo" gotcha; new
pure helpers should stay covered), open/refresh the PR, then run **`/greploop`**
to clear Greptile. Only report once both are green.

### The comprehensive report (what to hand back)

One report, not a pile of per-tier dumps:

- **Discovered** — confirmed findings per tier (product bugs + UX/discoverability),
  each with severity + trajectory ref.
- **Fixed in-place** — the auto-fixes applied, with commits / the PR link.
- **Blockers** — escalated findings (need a design/behavior/security decision):
  these are *why the swarm can't go deeper*. Offer to file them
  (`github-backlog-management`); don't auto-file during the loop (issue spam).
- **Depth reached** — per tier: ran / passed-gate / deferred (+ the blocking
  capability), so the ceiling the swarm hit is explicit.
- **Signal/noise trend** — candidate counts + precision across tiers/re-runs.

## Cost & scale

Cheap model for the swarm (set via `dogfood.yml`'s `model` input — e.g.
`google/gemini-2.5-flash`; `deepseek-chat` was too weak to drive the shell-agent
loop), strong **Opus** for compile + skeptic + fixer (run locally as subagents on
your subscription). Progressive scaling: a **tiny smoke tier** (a few journeys,
1–3 shards) for instant obvious-gap feedback, then scale shards with journey
count for `core`/`deep`. `--max-usd` is a hard budget cap — spend it on depth you
can actually reach, not on journeys blocked by a known gap.

## Field gotchas (paid for in real runs)

- **Short paths.** Per-shard/per-journey state dirs must stay short — a deep
  `IZBA_DATA_DIR` blows the ~108-byte AF_UNIX `sun_path` limit and breaks the
  runtime socket (izba#71). Isolate per-journey state, but keep the path short
  (capped prefix + hash).
- **Seed `--help` by discovery + recursion**, not a hardcoded list — the swarm
  missed `volume attach` until nested subcommand help was seeded. (Done in
  `run_journeys.py:gather_cli_help`.)
- **Caps are mandatory.** `--max-turns`, `--step-cap`, `--max-usd`,
  `--action-timeout-s`, and per-step loop-dedup. Without them a confused swarm
  loops forever and drains the budget.
- **Dispatch discipline.** Branch `dogfood-run/<feature>` off the base, push only,
  NEVER open a PR (the `ci`/`app`/`coverage` workflows have
  `branches-ignore: ['dogfood-run/**']`; `dogfood.yml` is `workflow_dispatch`
  only). The run is report-only — only infra failures (build/boot/fetch) fail a
  job; findings never do. In a progressive run set `DOGFOOD_BASE=HEAD` (or the
  fixes-branch tip) so each tier's dispatch carries the in-place fixes already
  landed — otherwise the swarm re-stumbles on a gap you just fixed. Default base
  stays `origin/main` for a one-shot run.
- **Cheap-model weakness is dual-natured.** It guesses bad sizes/names and botches
  `sh -c` redirects/pipes. That's noise *unless* the fumble is the product being
  unusable from the documented surface — then it's a UX finding. The skeptic
  disentangles; don't pre-filter it away.
- **Harness code in the product repo.** If you add CLI/daemon-wired glue while
  improving the harness, it won't be unit-coverable (the daemon spawns) and its
  mutants won't die — exclude such files from the coverage gate (precedent:
  `sonar.coverage.exclusions`) and `#[mutants::skip]` the daemon glue with a
  justification (see `CONTRIBUTING.md`). Keep the *testable* decision logic
  (pure helpers) covered and mutation-gated.

## Extending to the UI

The same shape applies to the Tauri app: the swarm drives the UI (e.g. via the
Playwright MCP), the oracle is the same reconcile snapshot plus DOM/console
assertions, and a cross-platform differential oracle (Linux vs Windows) catches
platform-specific breakage. Increment after the CLI/daemon loop is stable.
