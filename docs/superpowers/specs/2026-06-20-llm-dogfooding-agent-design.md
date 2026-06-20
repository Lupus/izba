# LLM dogfooding agent — spec-anchored exploratory bug hunting — design

**Status:** draft 2026-06-20, awaiting owner review.

## Goal

Automate the manual step the owner does today: **after an LLM ships a feature,
actually use izba the way a user would and notice the "this obviously doesn't
work / is inconsistent" flaws that no assertion was ever written for.**

This is *not* another deterministic bug-finder. Fuzzing, mutation testing, and
Playwright e2e are already folded in or in flight; they answer "does this
codepath crash / regress against a written assertion." This pipeline answers a
different question: **"I tried to use this product as intended and it didn't
work."** That class of bug — a feature that ships with an obvious functional or
state-consistency flaw — is what currently only gets caught by the owner
hand-testing.

The pipeline is **on-demand**, **report-only** (never a merge gate), and its
output is a **short bug description + the trajectory that triggered it** —
minimization is deliberately *out of scope* (the owner does that locally with a
Claude Code subscription, far cheaper than re-running the pipeline).

## Why this is feasible (and where it would fail) — read before building

The honest research read (full citations in §Prior art) is that an LLM
exploring an app works in exactly one mode and turns to slop in another:

- ✅ **Spec-grounded verification of a specific change.** Give the agent *what
  was built and what it was supposed to do*, and have it verify reality matches
  that claim. There is a concrete **intent anchor** to diverge from. This is the
  mode Google's Big Sleep succeeded in (variant analysis seeded with a diff) and
  the non-crash functional oracle of VisionDroid. izba has *better* anchors than
  any of those projects: a written spec, a PR description, and an independent
  Greptile review.
- ⚠️ **Unanchored "wander and find inconsistencies."** No spec to compare
  against, so the model reports intended behavior it misread as bugs. This is
  the curl failure mode (>95% invalid AI reports → bug-bounty program suspended
  Feb 2026). The *same model class* powers both Big Sleep and the slop; **the
  anchor plus an adversarial verification pass is the entire difference.**

Therefore this design is **strictly anchored** (no unanchored mode in increment
1) and every candidate finding passes an adversarial **skeptic** before it is
reported.

**Calibrated expectations.** Even in the good mode this is a *candidate
generator*, not an oracle — plan for ~20–50% precision after the skeptic pass.
The honest field numbers (VisionDroid: 31 of 43 reported bugs fixed; an
independent MLLM-oracle study: only 4 of 24 *new* bugs confirmed) say "useful,
not autonomous." Because the pipeline is on-demand + report-only, a false
positive costs ~30s of reading, never a broken gate. Where it beats hand-testing
is breadth (the boring permutations the owner skips) and stamina; where it
won't is subtle UX judgment and — for now — the GUI.

The one structural risk: if the spec/PR/Greptile anchor for a given feature is
thin, the oracle is weak and slop rises. Mitigation is built in: the anchor is
mandatory input, and the skeptic refutes anything not traceable to it.

## Orchestration — strong phases local, cheap loop fanned out in CI

The pipeline splits along a natural seam exposed by *who needs what*:

- **The strong-model phases (1 intent-extraction, 3 skeptic+synthesis) are
  token-light** — a handful of calls, not a per-action loop — but need a strong
  model, the repo, and the Greptile review. **Local Claude Code has all three
  and runs on the owner's subscription**, so it is the harness for Phases 1 & 3
  (near-free vs paying OpenRouter strong-tier tokens).
- **The journey-execution loop (Phase 2) is token-heavy but cheap-model**, and
  has a hard requirement — a **KVM runner + real izba**. That is CI's *only*
  job: **fan out workers, each running a shard of the journeys against a fresh,
  isolated izba, uploading a trajectory bundle.** CI needs no strong model and
  no Greptile access.

Phases communicate through two **versioned file contracts** — `journeys.json`
in, a per-shard **trajectory bundle** out — so phase placement is a deployment
knob, not a structural choice (see §Future increments for moving 1 & 3 to a
scheduled cloud Claude Code later).

```
LOCAL  ── Claude Code (strong model, Greptile MCP, owner's sub) ──────────────┐
  Phase 1 · Intent extraction                                                  │
    consume: superpowers spec (anchor) + PR description                        │
             + Greptile review summary + relevant `--help`/README              │
    produce: journeys.json  (user journeys, each with expected outcome         │
             + the SOURCE of that expectation)                                 │
└───────────────┬─────────────────────────────────────────────────────────────┘
                │  commit journeys.json on a `dogfood-run/*` branch (no PR),
                │  `gh workflow run dogfood.yml --ref dogfood-run/<feature>`
                ▼
CI  ── dogfood.yml, workflow_dispatch only ───────────────────────────────────┐
  Phase 2 · Journey execution loop  (CHEAP OpenRouter model + harness)         │
    shard journeys.json across a matrix of KVM workers; each worker:           │
      • fresh, isolated izba (own IZBA_DATA_DIR)                               │
      • Actor (cheap model) drives REAL izba/izbad per its journey shard       │
      • after each action the harness captures + checks:                       │
          stdout/stderr/exit-code/console.log · action latency ·              │
          reconciler assert_invariants() (GROUND TRUTH) ·                     │
          functional oracle (observed vs expected)                            │
      • hard caps: max-turns, max-$, step-cap, per-action timeout, loop-dedup │
      • upload trajectory bundle (candidates + trajectories) as an artifact    │
└───────────────┬─────────────────────────────────────────────────────────────┘
                │  local Claude Code downloads all shard artifacts
                ▼
LOCAL  ── Claude Code (strong model, owner's sub) ────────────────────────────┐
  Phase 3 · Skeptic + synthesis                                                │
    for each candidate, try to REFUTE it (intended? self-inflicted?);          │
    survivors → report.md (bug + violated expectation + source + trajectory);  │
    dedup near-identical findings.                                             │
└───────────────────────────────────────────────────────────────────────────┘
```

## Non-goals (increment 1)

- **Linux-only PoC.** Cross-platform fan-out is increment 2 (§Future
  increments) — first-class goal, deferred not dropped.
- **No unattended / scheduled runs.** Increment 1 is human-driven (owner runs
  the local harness, which dispatches CI). A future increment moves Phases 1 & 3
  to a scheduled cloud Claude Code via `/schedule`.
- **No GUI / Tauri exploration.** Deferred (see §Future increments).
- **No minimization / shrinking machine.** Output is the raw trajectory; the
  owner minimizes locally with Claude Code.
- **No auto-filed issues, no CI failure.** Report-only.
- **No kill-9 / fault injection in the agent.** Crash-recovery robustness is a
  deterministic concern; it belongs in e2e/unit tests with a mock VMM, not here.
- **No fuzzing / mutation / property testing.** Already covered elsewhere.

## Phase 1 — Intent extraction (local, stronger model)

The anchor is the **superpowers spec** for the feature (the project already
starts every feature with a spec under `docs/superpowers/specs/`). Local Claude
Code reads:

1. the spec (primary — the promised behavior);
2. the PR description (what the author claims was done);
3. the **Greptile review summary** (independent reviewer; describes the actual
   change with state graphs, not the author's own framing) — pulled via the
   Greptile MCP for the given PR;
4. supporting `izba <cmd> --help` output and relevant README sections, so
   journeys reflect the *real* current command surface.

Output `journeys.json` is a structured list of **user journeys**. A journey is a
goal a real user would have given the spec's promises, decomposed into ordered
steps, each with an expected observable outcome and the **source** of that
expectation:

```jsonc
{
  "journey_id": "publish-port-and-reach-it",
  "rationale": "Spec §4 promises `-p HOST:GUEST` makes a guest service reachable from host.",
  "source": { "kind": "spec", "ref": "2026-06-12-...-design.md §4" },
  "steps": [
    { "intent": "create a sandbox publishing 8080->80", "expect": "create succeeds, `ls` shows the port" },
    { "intent": "run an http server in the guest on :80", "expect": "exec returns, server is listening" },
    { "intent": "curl localhost:8080 from the host", "expect": "HTTP 200 within a few seconds" }
  ]
}
```

Journeys are intent, not literal commands — the Actor (Phase 2) chooses the
actual `izba` invocations. This keeps the expensive model out of the per-action
loop. Journeys are **independent**, which is what makes Phase 2 shardable.

## Phase 2 — Journey execution loop (CI fan-out, cheap model + harness)

The `dogfood.yml` workflow shards `journeys.json` across a **matrix of KVM
workers**. Each worker installs the dev build, runs its journey subset against a
**fresh, isolated izba** (its own `IZBA_DATA_DIR`, its own daemon), and uploads
a trajectory bundle. The cheap OpenRouter model is the **Actor**: read the
current step's intent + latest observations, decide the next concrete `izba`
command, run it. The harness (not the model) deterministically captures and
checks after every action:

- **Implicit oracles (always on, cheap):** scrape stderr + `console.log` tail
  for `panic`, `assertion failed`, `ERROR`/`FATAL`, `thread '...' panicked`;
  decode exit codes against izba's contract (`CommandNotFound`→127,
  `Signal(n)`→128+n).
- **The reconciler — `assert_invariants()` — the ground truth** (see §The
  reconciler). This is what lets the agent catch state-consistency bugs it would
  otherwise gloss over ("daemon reports healthy, but `/proc` says the VM is
  dead").
- **Latency / hang oracle.** Each action has a *human-normal* time budget; if an
  action exceeds it (or hits the per-action hard timeout) it is flagged as a
  candidate — "slower than a user would tolerate" is a real bug class. **Caveat
  resolved in Phase 3:** a hang the *agent itself* caused (an infinite `bash`
  loop inside `izba exec`) is not izba's fault.
- **Functional oracle (cheap model judgment, grounded):** does the observed
  result match the step's `expect`? A divergence is a candidate, recorded with
  the violated expectation and its source.

Each candidate carries its **trajectory**: the ordered actions, their outputs,
the reconciler state snapshots, and timings — enough for the owner (or local
Claude Code) to reproduce and minimize.

**Cost & loop guards (mandatory — the $47k-runaway lesson):** every worker
enforces `--max-turns`, a USD budget cap, a per-journey step cap, a per-action
timeout, and input-hash loop-dedup so the Actor can't re-issue the same failing
command forever. Models route via **OpenRouter** so the cheap tier is config,
not code. (No prompt-caching dependency in CI; the Actor's per-call context is
small.)

## Phase 3 — Skeptic + synthesis (local, stronger model)

The single most important quality lever, run locally over the aggregated shard
bundles. For each candidate, local Claude Code runs an **adversarial
refutation** — prompted to *disprove* the finding using the anchor — classifying
it as one of:

- **real** — observed behavior contradicts a traceable expectation → keep;
- **intended** — the behavior is actually documented/specified; agent misread →
  drop;
- **self-inflicted** — the failure was caused by the agent's own input, not izba
  (the infinite-loop-in-`exec` case) → drop.

Survivors → `report.md`: bug description + violated expectation + its source +
trajectory. Near-identical findings (same surface + same violated expectation)
are deduped.

## The reconciler (`assert_invariants()`) — the one real Rust artifact

A standalone, independently testable component that builds **ground truth from
disk + `/proc` + the live daemon** and returns a list of invariant violations.
Reusable by the agent harness *and* by ordinary e2e tests. Exposed as a hidden
CLI subcommand emitting JSON (e.g. `izba __reconcile --json`) so the
out-of-process harness can call it between actions; the same logic is callable
in-process from Rust tests.

All six invariants derive directly from izba's existing load-bearing contracts
(CLAUDE.md), so they encode knowledge the team already has — no Daikon-style
invariant *mining* (greenfield code; mining yields mostly false positives):

| Invariant | izba mapping |
| --- | --- |
| **list == reality** | `izbad.list()` set == sandboxes-dir scan ∩ `/proc` pid+starttime liveness |
| **no orphaned resources** | no relay/port-rule for a dead sandbox; no dangling named-volume image; no helper process whose sandbox is gone |
| **idempotency** | double `stop`, `rm` of an already-removed sandbox, re-`publish` of an existing port rule → state unchanged |
| **monotonic** | pid **starttime** strictly changes on respawn; `DAEMON_PROTO_VERSION` never decreases |
| **legal transition** | `created → running → stopped → removed` (+ `unhealthy` from `running`); no `created → running` without a real boot |
| **disk == live** | after every op, `state.json` reconciles with re-probed `/proc` pid+starttime — izba's core "disk-state-authoritative, liveness never trusted from state.json" contract, now machine-checked |

The reconciler is the increment-1 substrate in full — **no kill-9, no
replay/shrink, no fuzz.** On Windows (increment 2) the `/proc` probe is replaced
by the equivalent platform liveness check the daemon already uses; the
invariants themselves are platform-agnostic.

## Handoff & CI wiring

**File contracts (the real design surface):**
- `journeys.json` — Phase 1 → Phase 2 input.
- per-shard **trajectory bundle** (candidates + trajectories + timings +
  reconciler snapshots) — Phase 2 → Phase 3 output, a CI artifact.

**Getting `journeys.json` into CI — dispatch branch, no PR.** Local Phase 1
branches from `main` (so `dogfood.yml` is present on the ref), adds
`journeys.json`, pushes as `dogfood-run/<feature>`, then
`gh workflow run dogfood.yml --ref dogfood-run/<feature>`. **No PR is opened.**

The existing workflow triggers make this quiet *by construction* (verified
2026-06-20): `ci.yml`/`app.yml`/`coverage.yml` push-trigger on `branches:
[main]` only and otherwise fire on `pull_request`; `e2e.yml`/`artifacts.yml`/
`conpty-diag.yml`/`release.yml` are main/tag/dispatch/schedule-scoped. So a
`dogfood-run/*` push triggers **nothing**, and the `pull_request` gates fire
only if a PR is opened — which this flow never does. *Optional hardening:* add
`branches-ignore: ['dogfood-run/**']` to those three `pull_request` triggers so
even an accidental PR stays silent.

**`dogfood.yml`** is `workflow_dispatch` only, takes the journey-shard count as
an input, runs a **matrix of KVM jobs** (mirrors the real-VM legs in
`e2e.yml`), each: install dev build → run its shard → upload trajectory bundle.
Hard `timeout-minutes` + a concurrency group with `cancel-in-progress` on top of
the in-harness caps. Only new secret: **OpenRouter API key** (CI side). Greptile
and the strong model live entirely on the local side.

## Future increments

- **Increment 2 — cross-platform fan-out (Linux + Windows in parallel).** Extend
  the Phase-2 matrix with a WHP (Windows) leg alongside KVM, exactly like the
  existing `e2e.yml` real-VM legs. Beyond per-platform coverage this unlocks a
  **differential oracle**: run the *same journey set* on both platforms and treat
  a divergence in normalized outcome (sandbox set, statuses, published ports,
  exit-code mapping) as a finding — "the same documented action behaves
  differently on Windows vs Linux" is by construction a bug in at least one
  platform. Use a **lenient** comparison so legitimate platform differences
  (path separators, the OpenVMM-vs-CH disk-port layout) aren't flagged. Requires
  the reconciler's Windows liveness path.
- **Increment 3 — unattended / scheduled.** Move Phases 1 & 3 to a scheduled
  cloud Claude Code via `/schedule`; the file contracts are unchanged, so CI's
  Phase-2 fan-out is untouched.
- **Increment 4 — GUI.** Add a Tauri leg via `tauri-driver` (Linux
  WebKitWebDriver + xvfb; Windows msedgedriver, version-pinned to avoid the
  silent connect-hang). Feed the model `page.ariaSnapshot()` YAML; selector-level
  actions only. A cheap deterministic baseline (Playwright against the frontend
  with the existing `FakeDaemon` seam) should land first for `trace.zip`
  artifacts.

## Open questions / deferred

- **Anchor without a PR.** Spec-only runs are supported (PR/Greptile optional);
  whole-product unanchored runs are intentionally excluded (slop risk).
- **Latency thresholds.** The "human-normal" budgets per action class
  (create/boot vs exec vs ls) need calibration from real timings during
  implementation.
- **Local harness shape.** Phases 1 & 3 are most naturally a Claude Code
  skill/command driving the Greptile MCP + file contracts; the CI Phase-2 runner
  is a standalone script (Python/TS) calling OpenRouter. Only the reconciler must
  be Rust. To be pinned in the implementation plan.

## Prior art (research basis)

- **Spec-grounded agent bug-finding works; unanchored doesn't.** Google Project
  Zero *Naptime → Big Sleep* (debugger-verified, diff-seeded variant analysis;
  found a SQLite bug fuzzing missed). VisionDroid (non-crash functional oracle
  from inferred state-transition logic). Counter-example: curl suspended its
  bug-bounty over >95%-invalid AI reports — the difference is the anchor + a
  deterministic/adversarial gate.
- **"LLM proposes, harness disposes."** Every verified success (OSS-Fuzz-Gen's
  20-year-old OpenSSL CVE via an LLM-*written harness* + libFuzzer) gates the LLM
  behind a deterministic oracle.
- **Tarpit / cost discipline.** Use the expensive model surgically (Phases 1/3),
  cheap model for the loop; enforce step/budget/loop caps (the documented $47k
  unbounded-loop postmortem).
- **Oracle problem & invariants.** The reconciler is a reference-model + fsck-style
  consistency oracle; invariants are hand-written from known contracts rather
  than mined (Daikon yields mostly false positives on well-understood code).
- **Cross-platform parity as a differential oracle.** Same input → two
  implementations (Linux/Windows) of one spec; a divergence is a bug in at least
  one (McKeeman differential testing), with a lenient comparator for benign
  platform differences.
- **GUI = DOM, not pixels.** Tauri's only cross-platform automation path is
  `tauri-driver` (WebDriver); WebKitGTK has no CDP, so Playwright/CDP is
  Windows-only. Feed the model an accessibility snapshot; emit selectors.
