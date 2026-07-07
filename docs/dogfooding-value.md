# The LLM-dogfooding value model

This doc captures *why* the LLM-dogfooding harness exists and *what it is for*,
so future contributors — human or agent — evolve it along its design instead of
re-deriving (or quietly breaking) the value model. The `llm-dogfooding` skill
documents the **how**; this doc is the **why** and the **placement**: where
dogfooding sits relative to the e2e suite, what it uniquely measures, and the
guarantees that make a green trustworthy. These are owner-locked decisions
(2026-07-03/04). Read this before changing `hack/dogfood/` or the
`llm-dogfooding` skill.

## 1. What the harness measures

The e2e suite and the dogfood swarm answer two different questions. **e2e
asserts what the product *does*** — behavior under perfect knowledge: a
deterministic, gateable test that pins a regression forever because its author
knew the exact command, the exact flag, the exact expected output. **The swarm
measures what a user can *get the product to do*** — behavior under realistic
ignorance, where the actor knows only the README and `--help` (the fair-test
boundary of §3), never the spec or the source. The delta between what is
possible-per-spec and what is achievable-from-the-surface is the product's
UX/docs debt, and it is inexpressible as a deterministic test: you cannot write
an assertion for "a competent user could not figure out how to do this", because
the moment you encode the working command you have destroyed the ignorance that
was the measurement.

That delta shows up as five finding classes deterministic tests structurally
cannot produce. **Discoverability gaps** — a capability the product has but the
surface never reveals (izba#73: `--volume` requires a `g`/`m` size suffix that
`--help` never mentions). **Error-message quality** — the Actor's *next move
after an error* is the measurement: a good error teaches the recovery and the
swarm recovers; a bad one strands it, and the strand is the finding.
**Workflow friction** — the intended path exists but is awkward or asymmetric
(izba#66: `stop` had no matching `start`; izba#109: no discoverable way to bring
a sandbox up and leave it running). **First-contact bugs on unanticipated
paths** — a real defect that only fires because a user did something the author
never scripted (izba#71: `izba run` crashed with `path must be shorter than
SUN_LEN` when `IZBA_DATA_DIR` was deep enough to push the runtime socket past
the 108-char unix limit — no e2e exercised that path). **UI-lies-about-state** —
the interface reports a status that does not match reality. None of these are
things the product does *wrong* in a way a spec-author would predict; they are
things a real user hits, which is exactly why the swarm — not the test suite —
is the instrument that finds them.

## 2. The cheap model is the instrument

The swarm runs on a cheap model *on purpose*. This is calibrated ignorance, not
a cost compromise. A weak model fumbles exactly where a novice human fumbles:
it guesses a wrong flag, botches shell quoting, misreads a confusing error. When
those fumbles trace to the product being unusable from `--help` alone, that is
the signal we are hunting. A smarter swarm model would *paper over* the docs
gaps the same way an expert user papers over them — inferring the missing flag
from experience, quietly working around the awkward path — and the gap would go
unmeasured. Making the actor smarter makes the instrument *less* sensitive to
the debt it exists to detect.

The judgment phases are the opposite: the compile, skeptic, and fixer phases run
a strong model (Opus) locally on the owner's Claude Max subscription, where they
are effectively free. That split is a deliberate cost architecture, not an
accident of what was lying around. Moving the Opus phases to API-billed CI would
be a **cost regression**, not an upgrade — it would spend real money to make the
expensive-judgment half of the loop no better while removing the near-free
local run. When you touch where a phase executes, preserve the split: cheap
model in CI as the actor, strong model local as the judge.

## 3. The fair-test boundary is the anti-overlap mechanism

The one structural rule that keeps dogfooding from collapsing into a redundant
copy of the e2e suite is the **fair-test boundary**: journeys carry *intent* in
user language, never exact commands. A journey says "bring up a sandbox and run
a command in it", not `izba run --name foo …`. The swarm is handed only the
user-visible surface (README, `--help`, published docs); the spec, the PR, and
the source stay with the privileged compile/skeptic phases and are laundered out
of everything the actor sees.

Because a journey never contains the command, it *cannot* degrade into a unit
test — there is nothing to pin. If someone "helps" the swarm by writing the
working invocation into a journey to stop it struggling, they have not made the
test more reliable; they have deleted the measurement. The struggle is the
data. This boundary is why the two suites do not overlap even when they exercise
the same feature: e2e knows the answer and checks the behavior; the swarm is
denied the answer and measures whether the surface reveals it.

## 4. No e2e exclusion map (decision record, 2026-07-03)

A tempting-looking optimization was proposed and **rejected**: an "exclusion
map" that would subtract a journey from the swarm once an e2e test proves that
scenario is wired, on the theory that testing it twice is wasteful. This
misunderstands what the two suites measure. The swarm failing a scenario that
e2e proves is wired is not redundancy — it is *precisely the differential the
method exists to surface*. e2e proving the path works means the product **does**
the thing; the swarm failing to reach it means a user **cannot get** the product
to do the thing. That divergence is the UX/docs debt, and an exclusion map would
delete exactly the signal we built the harness for.

The rule, therefore: **e2e coverage never subtracts journeys.** e2e can happily
pin a confusing UX forever — a green e2e test on an awkward, undiscoverable flow
is entirely consistent with a swarm that cannot navigate it, and both readings
are correct simultaneously. Keep every journey the compiler emits regardless of
what e2e already covers; the overlap is the point, not the waste.

## 5. Graduation, not accretion

Findings leave the harness; they do not accumulate inside it. When the skeptic
confirms a **behavioral** finding — a real bug — it graduates: the fix lands
together with a distilled, deterministic e2e test, and the swarm trajectory that
found it is the ready-made repro. izba#71 is the model: a first-contact swarm
crash becomes a permanent e2e assertion on deep-`IZBA_DATA_DIR` socket paths,
and thereafter the *e2e suite* owns that regression, not the swarm. When the
finding is **UX/docs** — a discoverability or wording gap — it graduates the
other way: into a docs/`--help` fix or a filed issue, closing the gap at the
surface the swarm reads.

The consequence is a hard constraint on how the corpus is allowed to grow: **the
dogfood corpus must never become a frozen regression suite.** Deep journeys are
not retained to re-prove old fixes on every run — that job belongs to the
graduated e2e tests, which are cheaper, deterministic, and gateable. If you find
yourself keeping a deep journey around "so we never regress this", stop: that is
accretion, and it means the finding did not actually graduate. Convert it to an
e2e test and let the journey go.

## 6. The freshness principle and the one standing corpus

Deep and core journeys are **disposable by design**. They are recompiled against
*today's* user-visible surface each time a feature is dogfooded, because a
journey's whole value is that it reflects the current README and `--help` — a
journey compiled against last quarter's surface measures a product that no
longer exists. Do not treat a journey file as an artifact to preserve and re-run
verbatim; treat it as a snapshot the `journey-compiler` regenerates on demand.
What actually *persists* across runs is four things: findings promoted to issues,
graduated e2e tests, the signal/noise ledger (`hack/dogfood/ledger.jsonl` — one
JSON line per run recording the per-bucket journey tallies and the skeptic's
kept/refuted counts, so drift in signal quality is visible over time), and the
one small standing corpus.

That standing corpus is `hack/dogfood/journeys/smoke-core-cli.json`: a novice
smoke set, one journey per top-level user workflow (bring-up, exec, stop/start,
port publish, volume, firewall/netlog view), committed on `main` and run
report-only on a weekly cron. Its *only* oracle is goal achievement — "could an
ignorant agent reach the core goals from the public surface" — deliberately not
the deep behavioral oracles of a full dogfood pass. It is the one place the
harness keeps a fixed, re-run-verbatim journey set, and it earns that exception
by staying shallow: it is a smoke probe of first-contact usability, not a
regression suite. Everything deeper stays fresh.

## 7. Instrument honesty over determinism

The harness is **not** required to be deterministic — usability is a
distribution, and the same journey can legitimately succeed on one run and
stumble on the next depending on what the cheap model guesses. What *is*
required is instrument honesty: a green must mean "the assertion was reached and
corroborated", and an infrastructure failure must be distinguishable from a
success. The original harness violated this — a dead API key, malformed model
output, or a decisive step the actor never reached all collapsed into a
zero-candidate journey that tallied *positive*, so a fully broken run reported
all-green. A non-deterministic instrument is fine; a *dishonest* one is not.

The guarantees that make a green trustworthy are named, so future changes can be
checked against them. **`infra` candidates + exit 3:** any model/API failure
becomes a flipping `infra` candidate carrying the reason instead of a silent
`{"done": true}`, and when more than half a run's journeys are degraded the
runner — CLI and GUI alike — exits with a distinct code (`3`) so the CI shard
fails loudly rather than reporting a green void. **`unreached_decisive`:** a decisive (core) step the
actor never reached emits a flipping candidate instead of a phantom positive
(izba#126), so budget exhausted before the core step tallies as *unreached*, not
*passed*. **`reconcile_violation`:** the `violations` array from
`izba __reconcile`, previously captured and read by nobody, now flips a journey
and carries the violation objects verbatim, and a *failed* reconcile snapshot is
recorded as an error rather than masquerading as a clean one.
**`guest_console`:** each sandbox's guest `console.log` is tailed and scanned for
crash markers, giving guest-side panics an oracle they never had.
**`expect_cmd_re` / `graded_cmd`:** functional grading targets the last action
whose command matches the intent-bearing regex rather than blindly grading the
step's *last* action, and every functional candidate records the command it
actually graded so the skeptic can see *what* was judged. Together these ensure a
green is reached-and-corroborated, and a broken run is visibly broken.

## 8. Where things live

| Piece | Location | Role |
|---|---|---|
| Skill (the method) | `.claude/skills/llm-dogfooding/` | the *how* — phases, agents, fair-test boundary, oracle catalog |
| Harness (the runner) | `hack/dogfood/` | Python actor loop + deterministic oracles (`run_journeys.py`, `oracles.py`, `model.py`) |
| CI workflow | `.github/workflows/dogfood.yml` | `workflow_dispatch` swarm + weekly `schedule:` cron for the smoke corpus |
| Schemas | `hack/dogfood/schema/*.schema.json` | journey / trajectory / skeptic-verdict contracts (candidate kinds, `expect_cmd_re`, `graded_cmd`) |
| Signal/noise ledger | `hack/dogfood/ledger.jsonl` | one line per run: per-bucket tallies + skeptic kept/refuted; tracks signal drift |
| Standing smoke corpus | `hack/dogfood/journeys/smoke-core-cli.json` | the one persistent novice journey set (weekly cron, goal-achievement oracle only) |
| This doc | `docs/dogfooding-value.md` | the *why* — the value model future harness work is checked against |

Future harness work MUST be checked against this model — a proposal that turns
journeys into frozen regression tests, moves the Opus phases to API-billed CI,
or subtracts journeys because e2e covers them is fighting the design, not
improving it.
