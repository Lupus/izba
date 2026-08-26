# LLM dogfooding — methodology & field notes

Depth behind [SKILL.md](../SKILL.md). Read when designing journeys, tuning the
oracle, or interpreting a run. Grounded in real izba runs (the harness lives in
`hack/dogfood/`; the original design is
`docs/superpowers/specs/2026-06-20-llm-dogfooding-agent-design.md`).
For *why* this method exists and where it sits relative to the e2e suite — the
placement model this method serves — see
[`docs/dogfooding-value.md`](../../../../docs/dogfooding-value.md).

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
  (128+n → signal n; a missing command inside the container is crun's honest
  non-zero — rc 1 with `executable file ... not found` on stderr, docker-parity,
  NOT a synthetic 127; see the exit-code mapping contract in CLAUDE.md).
- **Latency** — flag actions slower than a human would tolerate (a hang is a
  finding) — but a hang *inside* the swarm's own command (infinite loop in
  `exec`) is self-inflicted, not the product's fault.
- **Functional (two-sided)** — compare exit code to the step's `expect`:
  expected-success + non-zero = candidate; **expected-failure + exit 0 = candidate**
  (a guard that should have fired silently didn't); expected-failure + non-zero =
  pass (this two-sidedness removes the bulk of rejection-journey false-positives).
  Which action gets graded is intent-directed: a step may carry `expect_cmd_re`,
  a regex anchoring the distinctive token of the command under test, and the
  functional oracle grades the *last* action whose command matches it (falling
  back to the step's final action). Every functional candidate records the
  `graded_cmd` it actually judged, so the skeptic sees *what* was scored rather
  than assuming it was the step's last line.
- **Declared assertions (the decisive hooks)** — an exit code is a weak oracle: it
  is 0 whichever way the product actually went, and non-zero for causes that have
  nothing to do with the promise. A decisive step may therefore declare what must
  be *true*, graded by the harness and invisible to the actor:
  `expect_stdout_re` / `expect_stderr_re` (regex over the graded action's captured
  stream — a refusal or a security warning usually prints on **stderr**, which a
  stdout-only hook structurally cannot see) and `expect_state` (daemon ground
  truth: `exists`/`status`/`volume`/`port`/`sandboxes_exact`, plus `policy`, read
  from the sandbox's managed `policy.yaml` — the oracle for a *refused* edit,
  where the UI and the rendered text prove nothing). All declared hooks must hold;
  an ungradable one degrades the journey (`infra`), never passes it.

The instrument-honesty kinds (a green must mean reached-and-corroborated, not a
silent void — see [`docs/dogfooding-value.md`](../../../../docs/dogfooding-value.md) §7):

- **`infra`** — a model/API/transport failure (dead key, malformed model output):
  the journey verified nothing, so it emits a *flipping* candidate carrying the
  reason instead of tallying a phantom positive. This is a harness-verified fact,
  not a product claim. When more than half a run's journeys are degraded the
  runner exits **3** (catastrophic infra) so the CI shard fails loudly instead of
  reporting a green void.
- **`unreached_decisive`** — a decisive (core) step the actor never reached (budget
  exhausted before it) flips the journey as *unreached* rather than letting the
  absence of a candidate read as *passed* (izba#126).
- **`reconcile_violation`** — the `violations` array from `izba __reconcile` (once
  captured and read by nobody) now flips the journey and carries the violation
  objects verbatim; a *failed* reconcile snapshot is recorded as an error, not
  masqueraded as clean.
- **`guest_console`** — each sandbox's guest `console.log` is tailed and scanned
  for crash markers, giving guest-side panics an oracle they never had.

Sequence invariants the single-shot reconciler can't see (idempotency, monotonic
restart identity, legal transitions) are the harness's job, computed by diffing
consecutive snapshots.

## How an oracle lies

The oracle is code, and a *wrong* oracle is worse than none: it converts a
regression into a green check that nobody re-reads. These are the recurring
mechanisms — audit any grader you add against them, and treat one written during
the campaign it is judging as unproven until its verdicts are checked against raw
ground truth.

| Mechanism | The rule it implies |
|---|---|
| An assertion credited from an action taken **before** the state under test existed | Watermark every mid-journey fixture/drift injection; refuse credits from below it and fall through to the flipping candidate. Fail closed. |
| A cheap rung-1 oracle silently **preempting** a hook the journey declared | A declared assertion is graded ON TOP of any ground-truth verdict, never substituted for. Auto-firing UI (a tab that fetches on mount) is what arms the preempting rung, so "this journey touches that tab" is no reason to omit hooks. |
| An oracle folding a domain rule **differently than the product does** | Reuse the product's fold, or mirror it arm for arm and pin it with a test; where no single assertion can express the product's posture, return *no evidence* rather than guess. One such second fold certified `access: read` while read-write was still enforced — a manufactured green on a security widening. |
| A step the actor **never reached** still emitting a product-bug candidate | A harness that fabricates findings is indistinguishable, in the bundle, from one that finds them. An unreached decisive step yields the unreached flip ALONE. Two runners must SHARE one reach predicate, not resemble each other. |
| An internal id (`journey_id`) reaching the actor | Ids are written in English and routinely state the answer. Keep them — and every path fragment derived from them — out of everything the actor sees. |
| A refusal graded on the actor's later successful **retry** | Selecting the *last* matching action inverts a step that already passed. Grade the action that satisfies the declared expectation, if any does. |
| A timed-out or truncated capture read as silence | Losing stdout on timeout, or truncating with no marker, makes "never printed" and "not captured" identical. Mark truncation, reap the process group, re-drain. |

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
- **unattempted control** — a journey asserting a refusal ("the field is locked",
  "the widening is rejected") went green while the actor never operated the
  control: the credited text renders unconditionally and the unchanged state is
  what an idle run produces anyway.

Verdicts: genuinely-achieved (cite lines + independent corroboration) |
cheated/unverified (a finding or coverage gap) | inconclusive (the journey is too
weak to verify its promise → **coverage finding**: tighten the journey).

**Audit greens at least as hard as reds — the reds are usually not where the bug
is.** The intuition runs the other way, and it is backwards: a red is a candidate
someone already flagged, so it gets refuted; a green is a claim nobody will read
again. One deep tier of 19 journeys produced 32 candidates of which **zero**
were kept as product bugs (22 refuted, 10 inconclusive) — and its one real P1
came out of auditing a *passing* journey, one of the two that turned out to be
passing for the wrong reason. Budget the skeptic's attention
accordingly, and demand the same evidence from a green as from a red: which
action exercised the promise, and what independent truth corroborates it.

## Journeys that can actually fail

An assertion earns its cost only if the *opposite* outcome would have produced a
different observation. Four shapes routinely fail that test — check each journey
against them before spending a tier's budget on it.

- **A refusal must prove the ATTEMPT.** For "X was refused / nothing happened",
  the oracle must show (a) the actor attempted X and (b) persisted truth is
  unchanged. Absence of change is not evidence when absence of action produces the
  identical observation — and the very notice that says a control is inert
  ("…never authorizes one") is usually rendered unconditionally by the fixture, so
  it credits a journey that never touched the control.
- **An absence assertion fails OPEN.** "This warning was not printed" also passes
  when the stream was truncated, when the command never ran, and when the fixture
  never landed. Pair a quiet assertion with a positive twin the same run must
  print, require the capture to carry a truncation marker, and check mechanically
  that the quiet assertion sits on the code path that *could* have printed it (a
  command with no such gate could never emit the string ⇒ a permanent fabricated
  green).
- **The asserted end state must be unreachable from the setup.** If `create` — or
  any earlier step — can produce the state the decisive step asserts, the journey
  grades the fixture, not the behaviour. Write that constraint into the journey's
  `rationale` and verify it survived the actor's improvisation; a decisive
  `expect_state` that was already true at create time is a tautological credit.
- **Grade on product truth, not a proxy exit code.** A guest command exits 0
  whichever certificate it was served, and non-zero for both a policy refusal and
  a missing client (the 127 trap). Anchor on the product's own record of what it
  did — an audit-log row, the saved policy file — captured by the harness
  independently of the actor.

**A seeded fixture is not safe from the actor.** In one tier the actor
`cat >`-overwrote the seeded file in **11 of 11** CLI journeys, authoring its own
from an example in the context pack, so every assertion graded a fixture nobody
planted. The runner can now detect a clobbered seed and flip the journey (a corpus
that loses every fixture fails the shard), but detection is the runner's ceiling:
the durable fix is corpus-side — **assert on content the actor could not have
invented**. Do not resolve it by naming the seed in the step text; telling the
actor what is already on disk trades the fair-test boundary for a fixture.

## The loop — find → improve → re-find

Every run produces two kinds of output; act on both:

- **Product findings** → file issues (crisp description + trajectory). See the
  `github-backlog-management` skill for proper INVEST-shaped issues.
- **Harness/coverage gaps** → fix and re-run: oracle false-positives, journeys
  that derailed before their assertion, caps that tripped early, context-pack gaps
  (which, if the swarm needed them, are themselves discoverability findings).

**Mine the trajectories for evidence no oracle scored.** A wandering actor
sometimes performs, by accident, the exact comparison the tier was designed to
make — in one run the cleanest proof of a datapath promise came from a journey
graded on something else entirely, an unplanned same-host A/B whose two arms sat
in two different bundles. Only a reader of raw actions finds that; a tally never
will. Treat it as unrepeatable: graduate it into a deterministic e2e test and
rewrite the journey around it.

**Signal/noise maturation is how you know it's working.** Track candidate count
and classification across runs. A maturing pipeline shows fewer candidates,
higher precision, and *deeper* coverage (more journeys actually reaching their
assertions). A real izba sequence ran 18 → 13 → 6 candidates across three runs as
harness and product fixes landed — the drop wasn't fewer bugs hidden, it was less
noise and journeys finally reaching the assertions that surfaced a genuine
durability edge. Don't declare done on a single run; iterate until it stabilizes.

That trend is no longer tracked from memory: each run appends one line to the
signal/noise ledger (`hack/dogfood/ledger.jsonl`) via
`scripts/append-ledger.py --collected collected.json --verdict skeptic-verdict.json --feature <f> --tier <t>` —
the per-bucket journey tallies plus the skeptic's kept/refuted counts, so drift
in signal quality is visible across runs instead of recalled as an "18 → 13 → 6"
anecdote.

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

### Pre-register the confounds (before the tier is dispatched)

Before a tier runs, write down the alternative explanations you already expect for
its results — the environment failures, the journey defects you suspect, the
oracle you built this week — plus the instrument's known ceilings, as stated by
whoever last touched the harness and the corpus. Hand the list to the skeptic as:
*test these first, and do not let them become an excuse to dismiss a real
finding.* Written beforehand it is a **control**; written afterwards the identical
reasoning is **rationalisation**, and it will absorb whatever the run produced.

It pays in both directions, which is why it is worth the minutes it costs. In one
deep tier four hypotheses were pre-registered: two were CONFIRMED, which correctly
kept a whole cluster of reds out of the findings list as *inconclusive* rather
than reporting bugs the evidence could not support (the actor's own tooling
install had failed, so an absent audit row proved nothing); two were REFUTED, one
of them a candidate that would otherwise have read as a real product bug —
against a documented contract, no less — when in fact the actor's improvised input
never created the transition the journey wanted. Note the third dividend: one
hypothesis existed only because a brand-new oracle was doing decisive grading, and
refuting it is what licensed that oracle's verdicts.

**The gate — advance / fix / defer.** After each tier's swarm + a per-tier
`trajectory-skeptic` pass:

1. For each **gating** journey not genuinely-achieved, read the finding's
   fix-routing:
   - **auto-fixable** → dispatch `dogfood-gap-fixer` (one finding at a time, or
     one isolated worktree per agent — concurrent agents committing into a single
     working tree race the git index and absorb each other's staged files), it
     commits on the CI branch; then **re-run the tier**
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

The harness sits on the auto-fix side of the table with one qualifier: **a harness
edit may only make the instrument stricter.** A change that could turn a red green
— loosening a grader, widening a match, silently re-planting a fixture, dropping a
declared hook — is a change to the measurement, not a fix to it, and deserves the
scrutiny of a product change (RED first, a discrimination check that the new test
really dies when the guard is removed, and an independent review). Strictness is
what makes it safe to repair the instrument mid-campaign at all.

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

## The GUI modality (Tauri app)

The same shape covers the desktop app — only Phase-2's act/observe layer swaps
(see `docs/superpowers/specs/2026-06-30-gui-dogfooding-design.md`).

- **Driver:** the cheap Actor drives the real React frontend in headless
  Chromium via `agent-browser` (Apache-2.0, pinned `v0.31.1`) called as a
  `--json` subprocess — observations are its accessibility set-of-marks
  (`[@e2] button "Create"`), actions are `{click|fill|press|select|read}`.
- **Real backend:** an in-page `real-bridge.js` forwards `invoke()` over a
  WebSocket to a headless `izba-app` sidecar (`bin/headless`, `app_lib::dispatch`)
  that reuses the app's real command/view/daemon layer against real microVMs.
- **Oracles:** daemon state-evidence + reconcile (reused), plus GUI oracles —
  `ui_daemon_diff` (UI disagrees with daemon truth), `console`, `silent_failure`,
  `dom_expect`. The UI-vs-daemon differential is the headline: it catches a UI
  that lies about state.
- **Run it:** `run_gui_journeys.py` selects `modality:"gui"` journeys; the
  `dogfood-gui` job in `dogfood.yml` fans it across KVM shards. Manual smoke:
  `hack/dogfood/gui/smoke.sh`.
- A cross-engine smoke (real WebKitGTK window via tauri-driver) is the deferred
  fidelity bump for the macro-glue/render gap.
