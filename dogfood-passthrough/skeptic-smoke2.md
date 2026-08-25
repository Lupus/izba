# Phase 3 — adversarial triage, SMOKE tier RE-RUN

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough (#233 + #238 + #239/PR #262)
Tip under test: `dogfood-fixes/passthrough-docs` @ `3d13f936` (carries `a2a107d1` D1 wording fix + `3d13f936` journey tightening)
Bundles: `dogfood-artifacts/smoke2/traj-0/traj-0.json`, `dogfood-artifacts/smoke2/traj-1/traj-1.json`
Harness tally: 6 journeys | 2 soft `functional` candidates | 0 flipping | 0 unreached_decisive | 0 infra

**Headline:** both gating journeys genuinely passed, both journey fixes took, both
candidates refute. Every capability required by the `core` and `deep` tiers is
now ESTABLISHED — the orchestrator may advance, and the four manifest-dependent
journeys deferred after run 1 are unblocked. Zero new product defects; three
harness findings (two unfixed from run 1, one new and serious for instrument
honesty) and two documentation/discoverability findings.

---

## 1. Confirmed findings

No product **defect** was confirmed. Confirmed items are two documentation/UX
findings and three harness findings.

### F1 (product / discoverability, P3, auto-fixable) — the one authoring pointer a user finds teaches the LEGACY entry-level spelling

`izba policy reload --help` is the only place the product tells a user where the
declaration can be authored, and it names the pre-#238 shape:

> `crates/izba-cli/src/commands/policy.rs:49` — "…to change settings this CLI has
> no flag for, such as **an entry's** `protocol:`"

The privileged anchor is explicit that the axis is not an entry-level one:

> CLAUDE.md — "**Inspectability is DECLARED per PORT, not derived from the port**
> … **Do not reintroduce an entry-level field:** it was the shape that let a
> one-port grant silently drop L7 inspection and upstream certificate
> verification."

Trajectory: shard 1 / `smoke-docs-find-authoring-surface` / action[1] — that
sentence is *literally the whole evidence* the journey produced. A user following
it writes the entry-level form, which parses and applies the passthrough to
**every** port of the entry — the exact hazard #238 exists to remove.
Same class as predicted flag **D3** (`crates/izba-cli/src/main.rs:61`, "per-host
`access:` / `protocol:` keys"), different file/line; D3's own site was not
exercised this run. Wording only ⇒ auto-fixable: `policy.rs:49` (+ `main.rs:61`).

### F2 (product / discoverability, P2, auto-fixable) — the user learns the UNGATED authoring route and never the reviewed one (predicted D5, now evidenced)

The actor's complete discovery of "how do I author this" (shard 1 /
`smoke-docs-find-authoring-surface`, both actions) yielded exactly two pointers,
both to the ungated path: `policy allow --help` → "(edit policy.yaml to declare
one)" and `policy reload --help` → "edit it there and reload… kept host-side at
`<izba data dir>/sandboxes/<name>/policy.yaml`". Nothing named `izba.yml`
`spec.egress` + `izba diff`/`izba promote`.

Anchor: CLAUDE.md — "`izba promote` is the human-gated bridge… Security-weakening
deltas are flagged `⚠ weakens egress`" and "`izba policy allow` writes
`policy.yaml` **without passing the diff/promote gate**". The product therefore
teaches only the route with no weakening gate in front of it. Corroborating
negative: `smoke-manifest-egress-review-available` reached the manifest route
only because the *journey* told it to, never because a surface named it.
Fix: README `izba.yml` `spec.egress` example + one clause in `policy reload`'s
long help. Wording only ⇒ auto-fixable.

### F3 (harness, P1 for instrument honesty, auto-fixable) — the fair-test surface is STALE relative to the tip under test

`context-pack.md:92-99` still carries the **pre-`a2a107d1`** README example:

```
        - port: 443
          protocol: tcp          # ⚠ escape hatch for a TLS-pinning client:
                                 # spliced opaquely — no L7 rules, no request audit.
```

while `README.md:88-90` at the tip under test says "…no L7 rules, no request
audit, **no upstream certificate verification**." The pack is untracked
(`git status --porcelain context-pack.md` → `?? context-pack.md`) and was not
regenerated between the fix commit and this re-run. Consequence: a docs journey
can *never* validate a README fix, and — worse — would have reported a
**false negative** ("the docs do not mention certificate verification") against a
tip where they do. The pack must be recompiled from the tip at the start of every
tier dispatch. Files: `context-pack.md` (regeneration step in the
`llm-dogfooding` orchestration).

### F4 (harness, P2, auto-fixable) — the functional oracle still grades the wrong action; two new flavours

Unfixed from run 1 (`functional-oracle-grades-non-izba-shell-commands`), and this
run shows it is worse than "non-izba commands":

1. *Non-izba shell command graded as a product failure* — `graded_cmd`
   `cat ./README.md`, exit 1, "No such file or directory" (shard 0 /
   `smoke-docs-find-pinning-exception` / action[9]).
2. **New flavour — a redundant retry graded instead of the action that satisfied
   the step.** `smoke-create-with-policy-file` step 0 ("the sandbox is created
   with no error") was satisfied at action[1] (`izba create --name pin1 --policy
   policy.yaml`, **exit 0**, reconcile: `{"name":"pin1", …}`). The oracle graded
   the step's *last* action, action[11], where the actor re-created the same name
   and got the correct refusal "sandbox 'pin1' already exists". A step whose
   objective was demonstrably met is scored as a **gating** failure.

Fix: prefer the *best-outcome* izba invocation in the step's range (or the first
action satisfying the step), and never grade a non-izba command. Files:
`hack/dogfood/oracles.py`, `hack/dogfood/run_journeys.py`.

### F5 (harness, P2, auto-fixable) — docs journeys still have no answer channel, and the README is genuinely unreachable from the workdir

`smoke-docs-find-pinning-exception` burned **9 of 10 actions** on
`cat README.md` / `cat ../README.md` / `cat ../../README.md` / `cat ./README.md`
/ `cat CLAUDE.md` / `cat docs/design-lineage.md` / `cat
docs/superpowers/specs/2026-06-10-izba-v1-design.md`, every one exit 1. The
question asked in the task — *does the swarm have ANY way to locate the README
from its working directory?* — resolves definitively **no**:
`hack/dogfood/run_journeys.py:600` sets `workdir = os.path.join(data_dir,
"proj")` and `os.makedirs(...)` it fresh; there is no repo checkout anywhere
under it, and nothing in `context-pack.md` says so. The README text is only ever
in the Actor's *system prompt* (`hack/dogfood/model.py:85-86`), which the actor
cannot `cat`. Fixes: (a) one line in the context pack stating there is no
checkout on disk and the docs live in the prompt; (b) compile docs journeys into
`--help` probes plus an explicit graded answer action. Unfixed from run 1.

---

## 2. Rejected candidates (Direction A) — 2 of 2 refuted, 0 kept

### C1 — `smoke-docs-find-pinning-exception`: `cat ./README.md` exited 1 → **self-inflicted** (+ harness, F4/F5)

> `"graded_cmd": "cat ./README.md"` … `ERR: cat: ./README.md: No such file or directory`

Not a product invocation at all; the product was never asked anything. The actor
chose to hunt the filesystem for a document that exists only in its prompt.
Dropped as a product finding; the *reason* it could not succeed is F5, and the
*reason* it was flagged is F4.

### C2 — `smoke-create-with-policy-file`: `izba create --name pin1 --policy policy.yaml .` exited 1 → **self-inflicted** (expected refusal), and the exit 100 is the firewall working

Definitive resolution of the gating candidate, as requested:

- **The exit 1 is a duplicate-name refusal, not a `--policy` failure.** The
  create that mattered is action[1]: `izba create --name pin1 --policy
  policy.yaml` → **exit 0**, stdout `pin1`, reconcile `{"name": "pin1",
  "status_daemon": "stopped"}`. Action[11] re-ran create for the *same name*
  eleven actions later and got `izba: error: sandbox 'pin1' already exists` —
  a correct, documented refusal, graded only because it happened to be the step's
  last action (F4). Nothing about the policy file was rejected: action[4]
  `izba policy show pin1` printed `'pin1' egress policy (enforce: on): example.com
  [80, 443] (read-write)`, and the end-of-journey `state_evidence.per_sandbox.pin1
  .policy_show` reproduces it independently. Not malformed policy, not a
  misleading error, not a product defect.
- **The exit 100 is `apt-get`'s own exit code, passed through by design, and it is
  evidence the firewall did exactly what it promises.** Action[7]
  `izba exec pin1 -- apt-get update && apt-get install -y curl` →
  `Err:1 http://archive.ubuntu.com/ubuntu noble InRelease  Could not resolve
  'archive.ubuntu.com'` … exit 100 (apt's standard "error" code). The sandbox's
  allow-list at that moment held only `example.com` with `enforce: on`. Ground
  truth from the reconciler, not the actor's prose —
  `state_evidence.per_sandbox.pin1.netlog`:
  `DENY  l3  archive.ubuntu.com:53  a0/d2` … then, after action[8] granted the
  hosts, `ALLOW l7  archive.ubuntu.com:80  a35/d0  GET /ubuntu/pool/…`.
  Anchor: CLAUDE.md — "the workload runs inside the crun container, so crun
  PROPAGATES its exit status and izba passes it straight through (no re-encode)"
  and "on (default-deny: only allow-listed egress)". The actor diagnosed it,
  granted the two hosts and completed the install — one recovery step, no
  misdirection. **Refuted: intended behaviour, self-inflicted trigger.**

---

## 3. Positive-trajectory audit (Direction B) — 6 journeys

| journey | verdict | proof |
|---|---|---|
| `smoke-create-with-policy-file` (gating) | **genuinely-achieved** | action[1] exit 0 + reconcile `pin1`; action[4] `izba policy show pin1` → `enforce: on`, `example.com [80, 443]`; reproduced in `state_evidence`. The `decisive_credits` entry (`step_index 1, action_index 4, graded_cmd "izba policy show pin1"`) is an **honest** credit — I checked the credited action myself. |
| `smoke-declare-pinned-port-accepted` (gating) | **genuinely-achieved** | action[0] writes a per-PORT policy (`- 80` bare, `- port: 443 / protocol: tcp`); action[1] `izba create --name pin2 --policy policy.yaml` exit 0 + reconcile `pin2`; action[2] `izba policy show pin2` renders the hatch **attributed to :443** and not to :80. Independent: `state_evidence.per_sandbox.pin2.policy_show` byte-identical. |
| `smoke-manifest-egress-review-available` | **genuinely-achieved — the tightening WORKED** | see below |
| `smoke-docs-bare-port-is-inspected` | **genuinely-achieved (partial)** | see below |
| `smoke-docs-find-authoring-surface` | **genuinely-achieved** | both actions print product text that answers the promise: `policy reload --help` → "to change settings this CLI has no flag for"; `policy allow --help` → "(edit policy.yaml to declare one)". Product output, not narration. (What it *taught* is F1/F2.) |
| `smoke-docs-find-pinning-exception` | **inconclusive (coverage gap)** | 10 actions, 9 failed `cat`s, 1 `izba --help`; neither step's assertion was exercised. Verified nothing. Cause is F5, not the product. |

### `smoke-manifest-egress-review-available` — the fix took; the promise is now real

The three things asked:

1. **Was there a real pending delta when `izba diff` ran?** Yes. The sandbox was
   born with no egress: action[1] `izba create --name pin3 .` (stderr `resolving
   alpine:3.20` — the manifest's image, so the manifest *was* consumed), then
   action[2] `izba policy show pin3` → **`'pin3' has no egress policy (all egress
   allowed)`**. Only afterwards did the manifest gain the egress block
   (action[3]). Action[4] `izba diff pin3` then printed a genuine delta:
   `state: repo ahead (promotable)` / `egress: [live]` / `from: enforce: false` →
   `to: enforce: true, allow: [example.com]`. Contrast run 1, where diff printed
   "in sync / no field changes" three times.
2. **Did the final assertion depend on `promote` rather than `create`?** Yes, and
   the before/after is independently witnessed by the product itself: `policy
   show` said "**no egress policy**" at action[2] and, after action[5]
   `izba promote pin3` → `promoted pin3`, said `enforce: on` + `example.com [80,
   443]` at action[6] (reproduced in `state_evidence.per_sandbox.pin3
   .policy_show`). `create` demonstrably did not put that host there.
3. **Is it still satisfiable without a genuine review?** No. The only path from
   "no egress policy" to "enforce: on" in this trajectory runs through
   `izba diff` → `izba promote`, and promote is gated on a prior diff
   (CLAUDE.md: "`izba promote` is the human-gated bridge… review token in
   `manifest.review`").

⇒ `manifest-egress-review` is **ESTABLISHED**. The four downstream journeys
deferred after run 1 (`core-author-the-exception-through-the-review-flow`,
`deep-review-flags-a-new-exception-as-weakening`,
`deep-review-flags-losing-inspection-on-a-shared-port`,
`deep-review-is-quiet-when-posture-tightens`) are unblocked.

Minor note, not a finding: the diff correctly printed **no** `⚠ weakens egress`
banner — this delta turns enforcement *on*, a tightening.

### `smoke-docs-bare-port-is-inspected` — no longer 0-action; genuine on the load-bearing half, still echo-shaped on the other

11 actions, all exit 0. Actions[0-8] print the product's real help surface
(`policy --help`, `policy allow --help`, `block`, `git`, `enforce`, `show`,
`reload`, `enable`). The graded action (`expect_cmd_re: "izba policy .*--help"`)
is action[8], a genuine help print — **not** an echo, so the grading is no longer
tautological. And the non-inheritance promise really is on that printed surface:

> action[1]/[8] — "A granted port is always inspected: it never inherits a
> `protocol: tcp` pinning passthrough declared for some other port of the same
> host (edit policy.yaml to declare one)."

Two honest caveats:

- Action[9]'s echo is a faithful quote of that printed line, but the actor used
  double quotes around backticks, so the shell ate the words: stderr
  `bash: line 1: protocol:: command not found`, and the transcript line silently
  reads "it never inherits a ␣ pinning passthrough". Exit 0 — self-inflicted,
  cosmetic, but an **evidence-integrity** wrinkle: the quoting step can drop the
  very token under test. Worth a harness note (tell the Actor to single-quote
  echoed quotations).
- Action[10] echoes "A bare port declares nothing → inspected". That sentence is
  **not** backed by anything printed in this journey — it is a verbatim quote of
  `README.md:86`, which lives in the actor's prompt. The journey's own expect
  requires "product text that was actually printed during this journey", so this
  half of the answer is an **unverified echo** (a new, smaller way to be
  tautological). It happens to be true; it is just not evidenced in-trajectory.
  Net: the non-inheritance promise is genuinely established from printed product
  text; the "bare port declares nothing" promise is not.

---

## 4. Direction C — the 10 predicted flags, and did the D1 fix take

**Did the D1 fix take? YES on the CLI, and a fair user saw it this run.**
Shard 0 / `smoke-declare-pinned-port-accepted` / action[2], and independently in
`state_evidence.per_sandbox.pin2.policy_show`:

> `⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules,
>  no request audit, **no upstream certificate verification**`

The "no credential injection" clause is gone; the loss that matters is named on
the CLI audit surface, matching `PolicyEditor.tsx` per #239 AC-2. `README.md:88-90`
carries the same fact at tip. **Caveat (F3):** the swarm's packaged fair-test
surface `context-pack.md` still holds the *old* README text, so only the CLI half
of the fix was actually testable this run.

| flag | verdict this tier | evidence |
|---|---|---|
| **D1** (CLI warning omits cert verification) | **REFUTED — fixed and observed** (CLI half); README half **NOT EXERCISED** (stale pack, F3) | shard 0 / `smoke-declare-pinned-port-accepted` / action[2] |
| **D2** (dormant hatch: access must be read-write) | NOT EXERCISED | no journey wrote a narrow-access pinned entry |
| **D3** (`create/run --help` teaches the per-HOST shape) | NOT EXERCISED at its own site — but the **class is confirmed** at `policy reload --help` (see F1) | shard 1 / `smoke-docs-find-authoring-surface` / action[1] |
| **D4** (README's weakening list omits both inspection transitions) | NOT EXERCISED | no weakening diff ran (the one diff was a tightening) |
| **D5** (reviewed authoring path undocumented) | **CONFIRMED** (= F2) | shard 1 / `smoke-docs-find-authoring-surface` / actions[0-1]: both pointers go to `policy.yaml`, none to `izba.yml`+diff/promote |
| **D6** (app guide silent on pinned rows / Host lock) | NOT EXERCISED (no GUI journeys in this tier) | — |
| **D7** (nothing says WHICH surface answers "is anything bypassing my firewall?") | **CONFIRMED at the surface, not tripped** | `izba policy show --help` (shard 0 / `smoke-docs-bare-port-is-inspected` / action[5]) says only "Print the effective allow-list (host + ports) and enforce posture (on/off)" — no mention of inspection or exemptions; and `izba status pin1` (shard 1 / action[2]) prints no egress line at all. No actor drew a wrong conclusion from it this tier. |
| **D8** (pinning needs an exact host) | NOT EXERCISED | no wildcard+`tcp` attempt |
| **D9** (back-compat of the entry-level spelling is invisible) | NOT EXERCISED | — |
| **D10** (CLI grants skip the review gate) | NOT EXERCISED as a docs gap — though the actor *used* the ungated path twice (`izba policy allow pin1 …`, shard 1 / action[8]) with no hint it bypassed review | — |

Split: **1 refuted (D1)**, **2 confirmed (D5, D7 — plus the D3 class via F1)**,
**7 not exercised** (D2, D3-at-site, D4, D6, D8, D9, D10).

**Known prior art (#243 superseded-duplicate advertising a dead passthrough; #259
`policy allow --read` on a pinned host contradicting `policy show`): NOT
re-sighted this tier** — no journey created a duplicate entry or ran
`policy allow --read` against a pinned host. Their re-sighting remains a `core`-
tier question.

---

## 5. Harness & coverage recommendations

1. **Regenerate `context-pack.md` from the tip at each tier dispatch** (F3). A
   stale pack silently converts a shipped docs fix into a false negative. This is
   the single most damaging instrument problem in this run.
2. **Fix the functional oracle's action selection** (F4): never grade a non-izba
   command; within a step, prefer the best-outcome izba invocation rather than the
   textually last action. Both of this run's candidates are artifacts of this.
3. **Give docs journeys a real channel** (F5): state in the pack that no repo
   checkout exists on disk, and compile docs journeys into `--help` probes + one
   explicitly graded answer action. `smoke-docs-find-pinning-exception` is the
   only journey in this tier that verified nothing; it should be recompiled
   before the next run rather than re-dispatched as-is.
4. **Tighten `smoke-docs-bare-port-is-inspected` one more notch**: require the
   echoed quotation to be traceable to text printed *in the journey*, and instruct
   the Actor to single-quote echoed quotations (action[9] lost the token
   `protocol: tcp` to backtick substitution).
5. **Suppress as cheap-model noise:** the repeated `cat <docfile>` flailing and
   the duplicate `izba create` retry. Neither is signal about the product; both
   are budget burn (9/10 and 8/12 actions respectively).
6. **Coverage note:** this tier exercised only the tightening direction of the
   review flow. `⚠ weakens egress` — the reason the gate exists — is untested
   until the `deep` tier.

---

## 6. Capability verdict (progressive gate)

Gating journeys, both **genuinely passed**:
`smoke-create-with-policy-file` ✔, `smoke-declare-pinned-port-accepted` ✔.

| capability | verdict | citation |
|---|---|---|
| `policy-file-at-create` | **established** | `smoke-create-with-policy-file` action[1] exit 0 + reconcile `pin1` |
| `policy-show-renders` | **established** | same journey action[4] + `state_evidence` |
| `hatch-declared` | **established** | `smoke-declare-pinned-port-accepted` actions[0-1] |
| `hatch-visible-in-show` | **established** | same journey action[2] — hatch rendered against `:443` |
| `manifest-egress-review` | **established** (was blocked in run 1) | `smoke-manifest-egress-review-available` actions[2]→[4]→[5]→[6] |
| `docs-name-authoring-path` | **established** | `smoke-docs-find-authoring-surface` actions[0-1] |
| `docs-explain-non-inheritance` | **established** | `smoke-docs-bare-port-is-inspected` action[1]/[8] (printed product text) |
| `docs-explain-hatch` | **blocked (harness, F5)** — no journey reached any docs surface; `required_by: []`, so it gates nothing | `smoke-docs-find-pinning-exception`, 9/10 actions exit 1 |

**Orchestrator signal: ADVANCE.** Every capability in `required_by` for the
`core` and `deep` tiers is established; nothing needs deferring. The one blocked
capability blocks no journey and is a harness gap, not a product gap.

## 7. Fix routing

| id | class | severity | routing | files |
|---|---|---|---|---|
| `reload-help-teaches-entry-level-protocol` (F1) | discoverability | P3 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs:49`, `crates/izba-cli/src/main.rs:61` |
| `reviewed-authoring-path-unnamed` (F2, =D5) | discoverability | P2 | **auto-fixable** | `README.md` (`izba.yml` `spec.egress` example), `crates/izba-cli/src/commands/policy.rs:49` |
| `context-pack-stale-vs-tip` (F3) | harness | P1 | **auto-fixable** | `context-pack.md` + the pack-regeneration step in `.claude/skills/llm-dogfooding/` |
| `functional-oracle-grades-wrong-action` (F4) | harness | P2 | **auto-fixable** | `hack/dogfood/oracles.py`, `hack/dogfood/run_journeys.py` |
| `docs-journeys-have-no-answer-channel` (F5) | harness | P2 | **auto-fixable** | `hack/dogfood/run_journeys.py`, the journey compiler, `context-pack.md` |
| `docs-bare-port-echo-not-journey-backed` | inconclusive | P3 | **auto-fixable** | `dogfood-passthrough/tier-smoke.json` |

No escalations. Nothing in this tier required a behaviour, datapath, default,
policy-semantics, trust-boundary or public-contract change.
