# Phase 3 — adversarial triage, SMOKE tier

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough (#233 + #238 + #239/PR #262)
Tree: `dogfood-fixes/passthrough-docs` (= `fix/gui-passthrough-host-lock` tip `314925ef`)
Bundles: `dogfood-artifacts/smoke/traj-0/traj-0.json`, `dogfood-artifacts/smoke/traj-1/traj-1.json`
(the requested `dogfood-artifacts/smoke/collected.json` does not exist; triage is from the raw bundles.)

Raw harness tally: 6 journeys, 2 candidates (1 `functional` soft, 1 `unreached_decisive`), 0 infra.
After triage: **0 of 2 candidates kept**, **1 product (discoverability) finding raised from artifact
inspection**, **1 positive journey cheated**, **2 capabilities not established**.

---

## 1. Confirmed product findings

### F1 (P1, discoverability) — the CLI audit surface and the README omit the one loss that matters: a passthrough performs **no upstream certificate verification**

The operator-facing audit line the swarm actually got:

> `⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules, no request audit, no credential injection`
> — shard 0, `smoke-declare-pinned-port-accepted`, action[2] (`izba policy show pin2`), reproduced
> independently by the harness in `state_evidence.per_sandbox.pin2.policy_show`.

The README the swarm was given as its whole doc surface says no more:

> `protocol: tcp          # ⚠ escape hatch for a TLS-pinning client:` /
> `# spliced opaquely — no L7 rules, no request audit.`
> — `context-pack.md:88-89` (= `README.md:88-89`)

Privileged anchor — the shipped behaviour:

> "a passthrough has no upstream certificate verification by construction, since the point is that
> only the *guest* validates the certificate"
> — `docs/superpowers/plans/2026-08-18-m5-p1-inspectability.md:68` (DP-2); same sentence at
> `crates/izba-core/src/daemon/egress/router.rs:400`, and `router.rs:1800`: "straight through with no
> upstream certificate verification at all".

Grep of the shipped tree confirms the asymmetry is total: the only **user-facing** string in the
product that names this loss is the desktop app —
`app/src/components/PolicyEditor.tsx:106`: "…no L7 rules, no request audit and no upstream
certificate verification". Outside `daemon/egress/` internals the phrase occurs elsewhere only in a
test assertion message (`crates/izba-core/src/manifest/diff.rs:463`). In its place the CLI names
"no credential injection" — a capability that does not ship until M5 P2 and is meaningless to a user
today (`crates/izba-cli/src/commands/policy.rs:368-371`, asserted at `policy.rs:1166`).

Issue #239 AC-2 requires the GUI wording to match the CLI "in substance"; they disagree in the
direction that matters — the *less* alarming text is on the surface an operator audits from a
terminal. This is exactly predicted flag **D1**, and it is confirmed here at artifact level (the
rendered line is in the trajectory), NOT by the actor's reasoning — the actor never got to answer the
question, see F3.

Severity hint: **P1** — a user choosing the hatch is giving up izba's verification of the vendor's
certificate and no CLI/README surface tells them.
Trajectory ref: shard 0 / `smoke-declare-pinned-port-accepted` / action[2].
Fix routing: **auto-fixable** — `crates/izba-cli/src/commands/policy.rs` (the `Some(Protocol::Tcp)`
live branch string) + `README.md:88-89`. NOTE for the fixer: `policy.rs:1166` and `policy.rs:1217`
assert the current string verbatim and must be updated in the same edit; keep "no credential
injection" or drop it, but ADD the certificate-verification clause so CLI ≡ GUI in substance.
Not new-issue-worthy on its own if folded into #239's AC-2 follow-up.

### No re-sighting of #243 or #259

Neither open issue re-surfaced: this tier declared exactly one entry with one pinned port and never
used `access: read` or a duplicate host entry. Both classes remain **not exercised** by smoke.

---

## 2. Rejected candidates (both raw candidates dropped)

| candidate | kind | verdict | refutation |
|---|---|---|---|
| `smoke-docs-find-pinning-exception` action[8] — `cat ../../README.md` exited 1 | `functional` (soft) | **self-inflicted + oracle false positive** | The swarm had the README verbatim in its own prompt: `context-pack.md:6` "## README.md", with the pinned-port example at lines 84-91. It nevertheless spent 8 of its 9 actions catting files that do not exist in a scratch workspace (`cat README.md`, `cat ../README.md`, `cat ../../README.md`, `cat CLAUDE.md`, `cat docs/design-lineage.md`, …), all `No such file or directory`. Nothing about the product failed; a shell `cat` of an absent path was scored as a product failure because the step carried no `expect_cmd_re` and the last action of the step was graded (`graded_cmd: "cat ../../README.md"`). → drop; see H1. |
| `smoke-docs-bare-port-is-inspected` — decisive step 0 produced no actions | `unreached_decisive` | **inconclusive (coverage gap)** | Harness-verified fact, not re-litigated: the journey emitted zero actions, so its assertion was never exercised. Not budget exhaustion — the same shard ran 3 actions in the journey *after* it. It is the structural problem in H2: a docs-only journey whose answer lives in the context pack has no command to run and no channel to state an answer. Note the adjacent evidence that the surface *does* carry the promise: shard 1 / `smoke-docs-find-authoring-surface` / action[0] printed `izba policy allow --help` — "A granted port is always inspected: it never inherits a `protocol: tcp` pinning passthrough declared for some other port of the same host (edit policy.yaml to declare one)". That is the journey's exact expectation, printed in a *different* journey — so predicted flag D-non-inheritance is very likely refuted, but this tier did not prove it. |

Kept 0 / refuted 1 / inconclusive 1.

---

## 3. Positive-trajectory audit (all 5 greens)

### 3.1 `smoke-create-with-policy-file` — **GATING** — genuinely-achieved

- action[0] wrote `enforce: true / allow: - example.com`; action[1] `izba create --name pin1 --policy policy.yaml .` → exit 0, stdout `pin1`.
- Independent corroboration #1: the post-action reconcile snapshot flips from `"sandboxes": []` to `[{"name":"pin1","status_daemon":"stopped","status_disk":"stopped"}]` — disk **and** daemon agree, `violations: []`.
- Independent corroboration #2 (the read-back the audit demands): action[2] `izba policy show pin1` → `'pin1' egress policy (enforce: on):` / `example.com  [80, 443] (read-write)` — the posture and the bare-host→[80,443] expansion both match what was authored, i.e. the file was really consumed, not ignored.
- Independent corroboration #3: `state_evidence.per_sandbox.pin1.policy_show` is a **separate process invocation made after the journey ended** and reproduces the same output byte-for-byte — so the render is re-read from the managed `policy.yaml`, not from an in-process cache.
- Not cheated: no alternative path could have produced `enforce: on` (a bare sandbox is off — README "Off by default").
- Honest scope limit: the sandbox was never started, so this establishes *authoring + rendering*, which is precisely what it claims (`policy-file-at-create`, `policy-show-renders`) — no enforcement claim is smuggled in.

### 3.2 `smoke-declare-pinned-port-accepted` — **GATING** — genuinely-achieved

"exit 0 three times" was not accepted on its own; here is the corroboration:

- action[0] authored the **per-port** shape (`- 80` and `- port: 443 / protocol: tcp`) — the #238 form, not the legacy entry-level one.
- action[1] `izba create --name pin2 --policy policy.yaml .` exit 0; reconcile flips to `[{"name":"pin2",…}]`, `violations: []`.
- action[2] `izba policy show pin2` exit 0 and — decisively — renders the declaration **attributed to its port**: `⚠ :443 protocol: tcp — pinning passthrough: …`, with `vendor.com  [80, 443] (read-write)` above it. Port 80 carries no marker, so the "declared per PORT" promise is visible in the output, not merely asserted.
- Independent corroboration: `state_evidence.per_sandbox.pin2.policy_show` (separate invocation, post-journey) reproduces the identical two lines including the `:443` attribution → the declaration survived to disk and is re-read from `policy.yaml`.
- Branch check against the source: the rendered text is `policy.rs:367-372`'s **live** branch, which is the correct branch for `access: read-write` (the dormant branch at `policy.rs:359-366` would have said "NOT in effect"). So `show` is not merely echoing a string; it evaluated the in-force condition.
- Honest scope limit: this proves *declared + accepted + revealed*. It proves **nothing** about the datapath — no VM was started, no TLS flow, no SNI. `hatch-declared` / `hatch-visible-in-show` are established at exactly that strength; every deep "does the splice actually happen" promise is still unproven.

### 3.3 `smoke-docs-find-authoring-surface` — genuinely-achieved (with a caveat)

The expectation ("the help states there is no CLI flag for it and names where it can be declared
instead") is met **inside the trajectory's own stdout**, which is objective evidence independent of
the actor's narration: shard 1 / action[1] `izba policy --help` printed reload's long description —
"That file is the managed truth, kept host-side at `<izba data dir>/sandboxes/<name>/policy.yaml`;
edit it there and reload to change settings this CLI has no flag for, such as an entry's
`protocol:`". action[0] `izba policy allow --help` additionally printed "(edit policy.yaml to declare
one)". The actor reached this without ever running `izba policy reload --help` — the information is
discoverable one level up, which is stronger than the journey required.
Caveat (coverage, not a finding): the actor emitted no conclusion, and the help never mentions the
**manifest** route; the journey's `and/or` phrasing lets `policy.yaml` alone satisfy it, so D5 was
neither confirmed nor refuted here.

### 3.4 `smoke-manifest-egress-review-available` — **CHEATED / WRONG MECHANISM**

This green is a lie about the mechanism, and it matters because 4 downstream journeys require the
capability it claims.

- Step 1 expected "the drift listing shows the manifest's egress settings as a **pending change**".
  Observed, three times (actions[2],[3],[4] — `izba diff pin3`, `izba diff --name pin3 .`,
  `izba diff .`): `state: in sync` / `no field changes between manifest and managed truth.`
  The step is not `core` and carries no `expect_cmd_re`, so the exit-0 functional oracle never looked
  at the text — **hidden failure of step 1, invisible to the harness.**
- Why: action[1] was `izba create --name pin3 .` **from the folder containing `izba.yml`**, so create
  consumed the manifest (`resolving alpine:3.20` — the manifest's image, proving it was read). The
  sandbox was therefore born in sync; there was never any drift for the review flow to review.
- action[5] `izba promote .` → `promoted pin3`, stderr `sandbox not running — changes apply on next
  start`. Promoting an in-sync manifest is a **no-op**; nothing was applied.
- The `core` step (graded on `izba policy show`) then "passed": action[6] shows
  `example.com  [80, 443] (read-write)`. But that host reached the managed truth via **`izba create`**,
  not via `diff` → `promote`. The journey's surface condition was satisfied by a path that bypasses
  the feature under test — textbook wrong-mechanism.
- Verdict: `manifest-egress-review` is **NOT established**. No product bug is implied (in-sync is the
  correct answer to that input); this is a coverage finding — see F4.

### 3.5 `smoke-docs-find-pinning-exception` — not a green (see §2), and its second half was never answered

Step 2 asked precisely the F1 question ("whether the sandbox still checks the vendor's certificate for
you"). The actor burned actions[5]-[8] on four more failed `cat`s and produced no answer. The
question is answered in §1 by inspecting the fair-test surface directly: **the docs do not state it.**
`docs-explain-hatch` is therefore not established by the swarm.

---

## 4. Direction C — the compiler's 10 predicted flags, confirmed vs not exercised

The human asked: *is this properly documented, can it be used, does it work as expected?* Smoke can
answer "can it be used" and part of "documented"; it cannot answer "does it work" at all (no sandbox
was ever started).

| flag | verdict | evidence |
|---|---|---|
| **D1** — CLI/README omit "no upstream certificate verification", advertise "no credential injection" | **CONFIRMED (artifact-level)** | `izba policy show pin2` output, shard 0 `smoke-declare-pinned-port-accepted` action[2]; README text at `context-pack.md:88-89`; the loss named only in `PolicyEditor.tsx:106`. Confirmed by inspecting the surface + the rendered line, NOT by the actor answering — it never read the docs (§3.5). |
| **D2** — dormant-hatch rule (`access` must be read-write) documented nowhere | **NOT EXERCISED** | Every policy this tier wrote used the default read-write; the dormant branch (`policy.rs:359`) was never rendered. |
| **D3** — `create/run --help` still teaches the pre-#238 per-HOST shape | **NOT EXERCISED** | The swarm never ran `izba create --help` / `izba run --help`. It wrote the correct per-PORT form because the README example was in its pack, so the wrong teaching was never reached. |
| **D4** — README's "what weakens egress" list omits both inspection transitions | **NOT EXERCISED** | The only diff run was `state: in sync`; no `⚠ weakens egress` line was ever produced. |
| **D5** — the manifest (the only *reviewed* authoring route) is undocumented where a user looks | **NOT EXERCISED** (weak corroboration only) | `izba policy --help` (shard 1 action[1]) names `policy.yaml` and never the manifest — consistent with D5 — but the actor was satisfied and never looked for a reviewed route. |
| **D6** — app guide silent on pinned rows / Host lock / refused Access widening | **NOT EXERCISED** | No GUI journeys in the smoke tier. |
| **D7** — nothing says WHICH surface answers "is anything bypassing my firewall?" | **NOT EXERCISED** | The actor was *told* to use `izba policy show` by the journey intent, so the discovery problem was bypassed; nobody ran `izba status` or `izba policy show --help`. |
| **D8** — "pinning needs an exact host" only discoverable by triggering the error | **NOT EXERCISED** | No wildcard was declared. |
| **D9** — the back-compat promise (legacy entry-level `protocol:`) is invisible | **NOT EXERCISED** | Only the new shape was authored. |
| **D10** — nothing says a CLI grant is unreviewed while the manifest route is gated | **NOT EXERCISED** | No `izba policy allow` was ever run. |

**1 confirmed, 9 not exercised, 0 refuted-as-predicted.** One *non-flag* prediction is close to
refuted: the compiler's "what the surface gets right" note that `policy allow --help` states the
non-inheritance rule is visible verbatim in shard 1 action[0] — but the journey meant to establish it
ran zero actions, so it stays unproven.

---

## 5. Harness & coverage recommendations

- **H1 (oracle false positive, auto-fixable)** — the functional oracle graded `cat ../../README.md`,
  a plain shell command that never touched the product, as a candidate against a product
  expectation (`graded_cmd: "cat ../../README.md"`). Restrict the functional oracle to actions that
  invoke the izba binary (or prefer the last izba-invoking action of the step when no
  `expect_cmd_re` is given). This is the same class already recorded in memory as "a shell 127
  scored as a refusal". File: `hack/dogfood/oracles.py` / `hack/dogfood/run_journeys.py`.
- **H2 (structural, auto-fixable) — docs-only journeys have no answer channel and no docs on disk.**
  2 of the 3 docs journeys produced zero usable evidence: one emitted no actions at all, the other
  spent 8/9 actions catting files that cannot exist in `<data_dir>/proj`. A docs journey needs either
  (a) a compiled `echo "<conclusion>"` answer action graded with a text hook, or (b) compilation into
  `--help` probes only, plus (c) one line in `context-pack.md` stating that the README text is
  reproduced in the pack and there is **no repo checkout in the workspace**. Files:
  `hack/dogfood/run_journeys.py` (`_grade_decisive_from_observed`), the journey compiler, `context-pack.md`.
- **H3 (journey tightening, auto-fixable) — `smoke-manifest-egress-review-available` is tautological.**
  Creating the sandbox from the same folder as `izba.yml` guarantees `state: in sync`, so `promote`
  is a no-op and the core assertion is satisfied by `create`. Tighten: create the sandbox *without*
  the manifest (or with a deliberately different egress block), then require `izba diff` to print a
  pending egress change **and** `izba policy show` to gain the host only after `promote`. File:
  `dogfood-passthrough/tier-smoke.json` (and `journeys.json`).
- **H4 (grading gap)** — step 1 of that journey expected specific *text* ("shows … as a pending
  change") and had no `expect_cmd_re`/text hook, so a plainly-wrong output passed silently. Any step
  whose expectation is about rendered text needs a text hook, not an exit code.
- **H5 (scope note, not a defect)** — smoke ran entirely against stopped sandboxes. Nothing in this
  tier speaks to whether the hatch *works*; do not let a green smoke tier read as "the feature works".
- Pure cheap-model weakness to suppress next run: the repeated `cat` of non-existent docs, and the
  three redundant `izba diff` spellings (`izba diff pin3` / `izba diff --name pin3 .` / `izba diff .`,
  all exit 0 — a resolver probe, no finding).

---

## 6. Capability verdict (progressive gate)

Tier `smoke` `establishes` 8 capabilities:

| capability | verdict | basis |
|---|---|---|
| `policy-file-at-create` | **established** | §3.1 — `smoke-create-with-policy-file`, reconcile + post-journey `policy show` re-read |
| `policy-show-renders` | **established** | §3.1 — same journey, action[2] |
| `hatch-declared` | **established** | §3.2 — `smoke-declare-pinned-port-accepted` actions[0-1], reconcile flip |
| `hatch-visible-in-show` | **established** | §3.2 — action[2] `⚠ :443 protocol: tcp …`, reproduced in `state_evidence` |
| `docs-name-authoring-path` | **established** | §3.3 — `izba policy --help` names `policy.yaml` + "settings this CLI has no flag for, such as an entry's `protocol:`" |
| `docs-explain-hatch` | **blocked (actor never read the docs; partially refuted by inspection)** | §3.5 — half the promise holds (README shows the per-port shape and names two losses), half does not (F1) |
| `docs-explain-non-inheritance` | **not-exercised** | §2 — zero actions; adjacent evidence suggests the surface does carry it |
| `manifest-egress-review` | **NOT established (cheated/wrong mechanism)** | §3.4 |

**Gating journeys:** both `smoke-create-with-policy-file` and `smoke-declare-pinned-port-accepted`
**genuinely passed**, with independent corroboration. → **Advance to the core tier.**

**Defer/fix before running the dependents of `manifest-egress-review`:**
`core-author-the-exception-through-the-review-flow`, `deep-review-flags-a-new-exception-as-weakening`,
`deep-review-flags-losing-inspection-on-a-shared-port`, `deep-review-is-quiet-when-posture-tightens`
(and transitively `hatch-via-manifest` → `gui-pinned-port-is-visible-in-the-policy-tab`). Either
apply H3 and re-run the one smoke journey, or run those journeys knowing their prerequisite is
unproven.

---

## 7. Fix routing summary

| id | class | severity | routing | where |
|---|---|---|---|---|
| `passthrough-warning-omits-cert-verification` | discoverability | P1 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs` (live `Protocol::Tcp` branch + its two test assertions at :1166/:1217), `README.md:88-89` |
| `functional-oracle-grades-non-izba-shell-commands` | harness | P2 | **auto-fixable** | `hack/dogfood/oracles.py`, `hack/dogfood/run_journeys.py` |
| `docs-journeys-have-no-answer-channel` | harness | P2 | **auto-fixable** | `hack/dogfood/run_journeys.py`, journey compiler, `context-pack.md` |
| `manifest-review-journey-is-tautological` | inconclusive (coverage) | P2 | **auto-fixable** | `dogfood-passthrough/tier-smoke.json`, `dogfood-passthrough/journeys.json` |

Nothing in this tier requires **escalate**: no behaviour, datapath, default, enforcement semantic,
trust boundary or public contract is implicated. F1 changes what the product *says*, not what it
*does* — but the fixer must keep CLI and GUI equivalent "in substance" per #239 AC-2 and update the
two verbatim string assertions in the same commit.
