# Phase 3 — adversarial triage, **core tier**, dogfooding run 2

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough
(M5 P1 — #233 + #238 + #239/PR #262), run on this branch's tip `e3e7d78e`
(`dogfood-fixes/passthrough-docs`) — **not** `main`.

Inputs: `dogfood-pt2/collected-core.json`, raw bundles under
`dogfood-pt2/art-core/{traj-0..3,gui-traj-0..2}/`, `sequence-plan.json`,
`tier-core.json`, `coverage-map.md`, `discoverability-flags.md`,
`context-pack.md`, and `skeptic-smoke.md` (the smoke triage, whose
`apk`-under-enforce verdict I re-used rather than re-litigated).

**Tally: 11 candidates → 1 kept (converted to a P3 doc finding), 10 refuted.
14 positives audited → 14 genuinely-achieved, 0 cheated, 0 unverified;
1 journey inconclusive (verified nothing). 2 confirmed product findings —
one P2 found ONLY by auditing a green, one P3 discoverability.
8 harness/coverage findings, all auto-fixable. 0 escalations.
No capability blocked — ADVANCE to the deep tier (with one readiness caveat).**

---

## 1. Confirmed product findings (2)

### P-1 (P2, **real**, auto-fixable) — `izba policy allow`'s dormant-pin echo prints a remediation that does nothing

When a `--read` grant narrows a host entry that carries a `protocol: tcp` port,
izba correctly reports the hatch went dormant — and then tells the operator how
to undo it:

> `⚠ :443 protocol: tcp — pinning passthrough NOT in effect at access: read (an
> opaque splice carries no HTTP method); re-grant without --read to restore it`

**Re-granting without `--read` restores nothing.** `apply_allow_edit`
(`crates/izba-cli/src/commands/policy.rs:217-230`) calls
`cfg.set_host_access(host, Access::Read)` **only when `read` is true**, and
`EgressPolicyConfig::allow` (`config.rs:942-956`) preserves `entry.access()` on
an existing entry (`Access::ReadWrite` is used only when creating a brand-new
host entry). `policy allow` has no widening flag at all, so the advertised
escape hatch is unreachable through the command that advertises it.

**Trajectory (shard 0, `core-a-granted-port-does-not-inherit-the-exception`):**

- action 5 — `izba policy allow inherit-no pinned.vendor.example:9000 --read`
  → `access: read (HTTP GET/HEAD only)` + `… re-grant without --read to restore it`
- action 7 — the Actor does exactly that: `izba policy allow inherit-no
  pinned.vendor.example:9000` → `allowed pinned.vendor.example  [443, 9000]
  access: read (HTTP GET/HEAD only)` **and the identical advice again**.

Independent corroboration (not narration): the journey's end-of-run managed
truth is `{"host": "pinned.vendor.example", "ports": [{"port": 443, "protocol":
"tcp"}, 9000], "access": "read"}` — the entry is still `read` after the
"restoring" re-grant. `reconcile.violations: []`.

**Anchors.**
- The message itself, introduced on this branch by `415b6131`
  (*"fix(cli): stop stating an egress posture the firewall is not enforcing"* —
  the run-1 CORE-2 fix), `policy.rs:283-289`.
- `izba policy allow --help`: *"access is read-write unless `--read`"* — untrue
  for an existing entry, which keeps whatever access it already had.
- Open issue **#259** already verified the same fact against the built binary:
  *"`izba policy allow` has no widening flag — it only narrows, via `--read`.
  … a subsequent plain `izba policy allow web pinned.vendor.com:443` on a read
  entry leaves `access: read` untouched."* #259 filed it as a wrong **code
  comment**; `415b6131` has since promoted that same falsehood into the
  product's **user-facing output**. This report is the new instance, not a
  duplicate of the filed one.
- The two sibling surfaces already say the true thing, so the correct wording
  is already determined: `izba policy show` → *"— widen to read-write to pin"*;
  the app's Policy tab → *"To pin, widen access in policy.yaml, or in izba.yml
  followed by izba diff / izba promote."*

**Severity P2, not P1:** the failure direction is safe (the posture stays
narrower than declared, the hatch stays shut) and `izba policy show` tells the
truth. The damage is that izba's most-trusted surface — its security-posture
messaging — instructs a loop the user cannot exit.

**Fix routing: auto-fixable** — it is human-facing message wording, one
`writeln!` at `crates/izba-cli/src/commands/policy.rs:283-289`. Mirror
`policy show`'s wording. **Note for the fixer:** the unit test at
`policy.rs:872` (`assert!(out.contains("--read"), "say how to restore it")`)
encodes the false claim and must be updated in the same commit.
**Out of the auto-fix boundary (escalate, and already #259's territory):**
adding a widening verb (`policy allow --write`, symmetric with
`policy git allow --write`) — that is a public CLI contract change.

### P-2 (P3, **discoverability**, auto-fixable) — `policy reload --help` names `<izba data dir>` and nothing resolves the placeholder

`izba policy reload --help` is the surface that sends a user to the managed
file: *"That file is the managed truth, kept host-side at `<izba data
dir>/sandboxes/<name>/policy.yaml`; edit it there and reload to change settings
this CLI has no flag for, such as a PORT's `protocol:`"*. Nothing in that help —
or in any other `--help` — says what `<izba data dir>` is or how to print it.

**Trajectory (shard 3, `core-edit-the-managed-file-and-reload`, action 9)** —
the Actor's last two turns went entirely into resolving the placeholder:

```
IZBA_DATA_DIR=$(izba version --json | jq -r '.daemon.data_dir') && cat > "$IZBA_DATA_DIR/sandboxes/reload-pin/policy.yaml" <<'EOF'
…
bash: line 1: null/sandboxes/reload-pin/policy.yaml: No such file or directory   (exit 1)
```

It invented a `version --json` field that does not exist, wrote to `null/…`, and
the journey ended there — the only journey in the tier that verified nothing.

**Honest scoping:** the concrete default path *is* in the context pack, but in
the manifest chapter (`context-pack.md:451`, "**managed truth** lives host-only
at `~/.local/share/izba/sandboxes/<name>/`"), which a user reaching for
`policy reload --help` has no reason to have read. This is the F5 shape from
`discoverability-flags.md` ("the fact is stated, but not where a user meets
it"), one rung lower in value. P3.

**Fix routing: auto-fixable** — one clause in `policy reload`'s long help
(`crates/izba-cli/src/commands/policy.rs`, the `Reload` doc comment), e.g.
"`<izba data dir>` is `$IZBA_DATA_DIR`, default `~/.local/share/izba`".
**Out of the auto-fix boundary (escalate):** adding `data_dir` to
`izba version --json` — that is a public schema change.

---

## 2. Rejected candidates (10 of 11)

### R1–R3 — three `infra` "expect_state declared on non-decisive step(s) [0]" → **harness: a journey-authoring defect, not a product bug**

`core-retire-the-exception-from-the-command-line`,
`core-audit-surface-under-a-narrower-access`,
`core-firewall-off-does-not-read-as-one-hole`.

The tasking's reading is confirmed against the corpus and the runner. In all
three journeys step 0 carries an `expect_state` and **is not marked `core`**:

```json
{"intent": "create a sandbox called retire-pin …", "expect": "…",
 "expect_cmd_re": "izba (create|run)",
 "expect_state": {"sandbox": "retire-pin", "policy": {…"pinned": true}}}   ← no "core": true
```

and `run_journeys.py:1226` grades `expect_state` only over `decisive_idx`. So
the instrument is honestly reporting that an assertion the journey declared was
never checked. **No product claim is involved.** Routed as harness finding
**H1**.

One nuance the fix must respect: in `core-firewall-off-does-not-read-as-one-hole`
the step-0 assertion is `{"enforcing": false}`, and the Actor legitimately ran
`izba policy enforce logonly on` at action 3. Grading that assertion against the
**end-of-journey** snapshot would manufacture a false red. Marking the step
`core: true` is the right fix precisely because it also turns on the
step-boundary capture (`pending_state`, `run_journeys.py:1157-1165`).

### R4 — `core-a-plain-policy-renders-without-warnings`, functional → **self-inflicted**

The candidate: `expect_stdout_re 'registry\.other\.example  \[80, 443\]
\(read-write\)'` did not match `izba policy show plain-fw`. It could not: the
journey's step 0 said *"allows just the two hosts api.vendor.example and
registry.other.example"* and the Actor authored

```
izba run --name plain-fw --policy <(cat <<EOF
enforce: true
allow:
  - example.com
  - example.org
EOF
) -- sleep infinity
```

Managed truth agrees: `{"enforce": true, "allow": ["example.com",
"example.org"]}`. izba rendered exactly what it was given, plainly and with no
warning markers — which is the promise the journey was written to test. The
premise, not the product, is what failed. Routed as coverage finding **C1**
(a decisive `expect_stdout_re` naming values the Actor must type in an earlier,
unasserted step).

### R5, R6 — two `infra` "model starved: unparseable model reply" → **harness / cheap-model weakness**

`core-a-plain-policy-renders-without-warnings` (`'{"command": "cat > policy.yaml <<'EOF'`)
and `core-edit-the-managed-file-and-reload` (`'{"command": "IZBA_DATA_DIR=$(izba version …`).
Both truncate mid-heredoc: the model could not carry a heredoc through the JSON
reply channel. That is the transport, not izba — every izba invocation in the
tier that *did* reach the shell returned in single-digit milliseconds. Routed as
harness finding **H4**.

### R7, R8 — `core-edit-the-managed-file-and-reload`'s `unreached_decisive` + `functional expect_state` → **one fact, and NOT a product bug**

This is the candidate the tasking asked me to spend effort on. Verdict: **(a) —
the Actor never got as far as writing the declaration.** There is no product
claim here. Evidence, from the bundle rather than narration:

- The journey's ten actions contain **exactly one** attempt to write a
  `protocol: tcp` port into the managed file — action 9 — and it **failed**,
  exit 1, `bash: line 1: null/sandboxes/reload-pin/policy.yaml: No such file or
  directory` (see P-2). Nothing was written anywhere.
- `izba policy reload` was **never run** (hence the `unreached_decisive`); the
  only reloads in the trajectory are the implicit ones `policy allow`
  auto-fires (`reloaded egress policy for 'reload-pin' (applies to new
  connections)`, actions 6 and 8).
- The end-of-journey managed truth is
  `{"host": "pinned.vendor.example", "ports": [80, 443]}` — bare ports 80 and
  443, which is **exactly and only** what `izba policy allow reload-pin
  pinned.vendor.example` (action 8) writes: a bare-host grant opening 80+443
  with no declaration, per `policy allow --help`. No `protocol:` was dropped or
  mangled, because none was ever stored.
- `reconcile.violations: []`; `policy show` and `policy.yaml` agree.

So the `expect_state` divergence ("the managed policy.yaml declares None") and
the `unreached_decisive` are **the same fact reported twice**: the decisive step
was never performed. **Not a P1. Not a product finding.** Its value is P-2
(§1) plus coverage finding **C2**.

### R9 (soft) — `core-retire-the-exception-from-the-command-line`, `izba run … -- sh -c 'apk add curl && …'` exited 1 → **self-inflicted** (+ a harness note)

The `apk`-under-enforce class the smoke triage already settled: default-deny
denied the un-allow-listed mirror (`izba netlog` for this sandbox records
`DENY  l3  dl-cdn.alpinelinux.org:53  a0/d4`), the context pack states the rule
twice, and the Actor recovered unaided (`izba policy allow retire-pin
dl-cdn.alpinelinux.org` → next `apk add` → `OK: 13 MiB in 24 packages`). The
step was non-decisive (`"decisive": false`).

Worth recording separately: the exit code graded here is **the guest command's**,
not izba's. `expect_cmd_re: "izba (create|run)"` matches `izba run NAME -- <guest
cmd>`, whose exit status izba passes through by contract ("crun PROPAGATES its
exit status and izba passes it straight through"). Harness finding **H2**.

### R10, R11 (soft, latency) — both self-inflicted; and the process-substitution suspicion is **refuted**

- `core-police-an-unusual-port-at-http`: 120 101 ms on `izba exec probe-8000 --
  sh -c 'apk add … && while true; do curl …; sleep 1; done'`. The Actor wrote an
  infinite loop. Self-inflicted.
- `core-a-plain-policy-renders-without-warnings`: 120 064 ms on
  `izba run --name plain-fw --policy <(cat <<EOF …)  -- sleep infinity`.
  **izba did not hang on the process-substitution policy path.** Positive proof:
  the sandbox was created and booted inside that window (stderr `resolving
  ubuntu:24.04 …` / `starting 'plain-fw'…`) and the policy read from `/dev/fd/N`
  landed on disk in full (`policy_yaml = {"enforce": true, "allow":
  ["example.com", "example.org"]}`), after which the Actor's own foreground
  `sleep infinity` ran until the harness timeout. `--policy <(…)` works.
  Self-inflicted.

---

## 3. Positive-trajectory audit (Direction B) — 14 journeys

**14 genuinely-achieved, 0 cheated, 0 unverified.** One of them nevertheless
produced this tier's most valuable finding (§1 P-1) — see §3.6.

### 3.1 The three GUI greens — all genuinely-achieved, and the PR #264 class did NOT reappear

`e3e7d78e`'s `final_observation` (`marks` + `page_text`) closes smoke finding H4:
each credit is now auditable from the bundle alone. All three tabs had **loaded**
— the captures carry `Firewall on` / `Firewall off`, real host rows and the
`⚠ tcp` chip, never PR #264's guard copy (`Firewall posture unknown` /
`Loading this sandbox's policy…`). `console_errors: []`, `candidates: []`,
`reconcile.violations: []`, and every `invoke_log` entry `ok: true` (each journey
shows `policy_show` invoked twice).

| journey | credit | independent corroboration |
| - | - | - |
| `gui-only-the-declared-port-is-marked` | `expect_text 'Port 443: TLS-pinning passthrough' (matched)` | final capture marks **only** 443: host 1 renders `80 / 443 ⚠ tcp` with the passthrough notice, host 2 renders `8000 http` with **no** notice. Managed truth: `[{"host":"pinned.vendor.example","ports":[80,{"port":443,"protocol":"tcp"}]},{"host":"api.vendor.example","ports":[{"port":8000,"protocol":"http"}]}]`. `expect_state` on `api.vendor.example:8000 pinned=false` matched. |
| `gui-dormant-exception-is-not-claimed-as-live` | `expect_text 'access never authorizes one' (matched)` | see 3.2 |
| `gui-inert-when-the-firewall-is-off` | `expect_text 'this declaration is inert until enforcement is turned on' (matched)` | page shows `Firewall off`; managed truth `{"enforce": false, …{"port":443,"protocol":"tcp"}}`; CLI `policy show` on the same sandbox prints the enforce-off wording. |

### 3.2 `gui-dormant-exception-is-not-claimed-as-live` — the contract's cross-surface agreement test, and both surfaces agree verbatim

The contract requires that *"both render a pinned port on a NARROWER-than-read-write
row as NOT in effect rather than live"*. This tier proves it across **two
independent shards and two different surfaces on the same policy shape**:

- GUI (`gui-traj-1` final capture): *"Port 443: TLS-pinning passthrough **NOT in
  effect** — an opaque splice carries no HTTP method, so this row's "read"
  access never authorizes one; the connection stays terminated at L7 and a
  pinning client still sees izba's certificate. To pin, widen access in
  policy.yaml, or in izba.yml followed by izba diff / izba promote."*
- CLI (`traj-2`, `core-audit-surface-under-a-narrower-access` action 2):
  *"⚠ :443 protocol: tcp — pinning passthrough **NOT in effect**: an opaque
  splice carries no HTTP method, so this entry's access level never authorizes
  one; the connection stays terminated at L7 (a pinning client still sees izba's
  certificate) — widen to read-write to pin"*

Both sit on managed truth carrying `access: read` + `{"port":443,"protocol":
"tcp"}`, and the GUI journey's own state evidence contains the CLI rendering for
the *same* sandbox (`gui-pin3`), so the agreement is checked on one policy, not
two lookalikes. The row is also correctly locked (`textbox "Locked: this row
carries a TLS-pinning passthrough port — …"`). No cheat vector applies: the
phrase occurs nowhere else in the page text, and `ui_daemon_diff` produced
nothing.

*Caveat (coverage, not product):* in `gui-inert-when-the-firewall-is-off` the
**Actor's** last observation (action 5) is still the loading state — its marks
list has no `switch "Enforce firewall"` and no `▾ Hosts`; only the harness's
post-settle capture sees the loaded tab. Smoke finding C2 is 2/3 closed, not
closed. Routed as **C3**.

*Dedup note:* the unlocked Host input's accessible name is its **placeholder**
(`textbox "api.example.com or *.example.com"`) because the row's `<label>Host</label>`
is not associated with the `Input` (`PolicyEditor.tsx:576-585`). I did **not**
raise this: `docs/superpowers/plans/2026-08-25-gui-passthrough-host-lock.md`
"Out of scope" already lists *"the missing accessible name"* as separately filed
from an earlier pass.

### 3.3 The four refusal journeys — all four guards fired for the RIGHT reason

Each exits non-zero, and in each the message identifies the specific guard, not
a generic YAML/arity error:

| journey | exit | the message proves the guard under test fired |
| - | - | - |
| `core-refuse-pinning-on-a-wildcard-host` | 1 | *"`protocol: tcp` (the TLS-pinning passthrough) needs an exact host, but `'*.vendor.example'` is a wildcard pattern — the hatch is matched against the observed ClientHello SNI. Name each pinned host explicitly."* — the exact CLAUDE.md rule. |
| `core-refuse-one-port-declared-two-ways` | 1 | *"allow[0].ports: port 443 is listed twice with different declarations (no protocol and protocol: tcp) — one port cannot be both inspected at L7 and spliced opaquely. Name it once, with the declaration you mean."* — names the port **and both readings**, as `f21a4dfe` promises. |
| `core-refuse-an-unknown-declaration-value` | 1 | *"allow[0].ports[0].protocol: expected 'http' or 'tcp', got 'ssl'"* — names the valid set. |
| `core-refuse-a-typo-in-the-port-mapping` | 1 | *"invalid egress policy policy.yaml: allow[0].ports[0]: unknown key 'protokol' (valid keys: port, protocol)"* — the single-action journey the tasking flagged: its one action is a compound `heredoc + izba run --name bad-key --image alpine:3.20 --policy policy.yaml .`, argv parsed fine (no clap usage error), and the non-zero exit comes from the policy parser naming the key and its alternatives. Genuine. |

No sandbox was created in any of the four (`state_evidence.sandboxes` empty),
so no refusal was faked by an unrelated failure earlier in the pipeline.

### 3.4 `core-a-granted-port-does-not-inherit-the-exception` — the structural promise of #238, verified on disk

The whole point of per-port declaration, and it holds against managed truth, not
rendered text. After `izba policy allow inherit-no pinned.vendor.example:9000`
(action 3) the file reads:

```json
{"host": "pinned.vendor.example", "ports": [{"port": 443, "protocol": "tcp"}, 9000], "access": "read"}
```

The new port is appended **bare** — structurally incapable of carrying the
sibling's declaration, exactly as `EgressPolicyConfig::allow` is documented to
do. `policy show` at action 4 marks only `:443`. Both decisive `expect_state`
hooks (`443 pinned=true`, `9000 pinned=false`) matched. Genuinely-achieved.

### 3.5 `core-declaration-survives-an-unrelated-grant` — genuinely-achieved, and stronger than the smoke pre-corroboration

The smoke triage pre-corroborated this incidentally (a grant on the *same* host
left the hatch alone). Here it is tested as written and then some: two unrelated
grants (`registry.other.example`, then `registry.other.example:8080`) and the
final managed truth is
`[{"host":"pinned.vendor.example","ports":[{"port":443,"protocol":"tcp"}]},
{"host":"registry.other.example","ports":[80,443,8080]}]` — hatch intact, new
host entirely bare. Both decisive `expect_state` hooks matched.

### 3.6 `core-narrowing-access-says-the-exception-went-dormant` — the promise it asserts is kept; the promise it *implies* is broken

The journey asserts that the echo names the dormant port and how to restore it,
and it passed on the real command (action 4,
`izba policy allow dormant-echo pinned.vendor.example:9000 --read`, printing the
literal `re-grant without --read to restore it`). **Genuinely-achieved as
written.** But no journey in the corpus then *follows* that instruction —
`core-a-granted-port-does-not-inherit-the-exception` did, incidentally, and that
is how P-1 surfaced. This is the tier's headline lesson: the corpus certifies
that a remediation is *printed*, never that it *works*. Routed as coverage
finding **C4**.

### 3.7 The remaining greens

- **`core-an-older-policy-file-keeps-its-meaning` → genuinely-achieved.**
  Credited on a real `izba policy show legacy-pin` (`decisive_credits`
  `action_index: 2`). The legacy entry-level spelling stays verbatim on disk
  (`{"host":"pinned.vendor.example","ports":[443],"protocol":"tcp"}`) while the
  renderer resolves it **down onto the port** (`⚠ :443 protocol: tcp`) — the
  contract's "keeps its posture, single in-memory representation", proven from
  both ends.
- **`core-inspection-may-be-asked-for-on-a-wildcard` → genuinely-achieved.**
  `*.svc.example` with `{"port":8443,"protocol":"http"}` accepted (managed truth)
  and rendered `:8443 protocol: http (inspected)`. The "axis may only widen"
  asymmetry against `core-refuse-pinning-on-a-wildcard-host` is now demonstrated
  on the same tip. (F3's paired prediction — hesitation about whether `http` is
  allowed on a wildcard — is **refuted**: the Actor wrote it first try, action 0.)
- **`core-command-line-grants-skip-the-review-gate` → genuinely-achieved.**
  `izba diff ungated` → `state: managed ahead (export to capture)` on the real
  `izba diff`, corroborated by the divergence between managed truth (3 hosts)
  and `izba.yml` (1 host). The README's "unreviewed" claim is exercised
  end-to-end.
- **`core-firewall-off-does-not-read-as-one-hole` → genuinely-achieved, and its
  `rescue` is CORRECT.** This is the tier's audit of the new rescue rule. The
  credit is `action_index 2` with `"rescue": "re-observation"` and
  `superseded_by: {action_index: 4}`. Action 2 (`izba policy show logonly`,
  enforce off) printed *"http: all egress allowed (enforce off) — the allow-list
  below is not in force"* and *"…this declaration is inert — turn enforcement on
  to pin"*, satisfying `(?s)all egress allowed \(enforce off\).*declaration is
  inert` in full. Action 4 is the byte-identical command **after the Actor ran
  `izba policy enforce logonly on` at action 3** — so the different output is the
  world legitimately moving on, not a regression. Rescue upheld; the divergence
  is fully explained by the trajectory.
- **`core-audit-surface-under-a-narrower-access` → genuinely-achieved** (action
  2, `widen to read-write to pin`, on the `expect_cmd_re`-selected command;
  managed truth carries `access: read` + the pinned port).
- **`core-retire-the-exception-from-the-command-line` → genuinely-achieved.**
  `izba policy block retire-pin pinned.vendor.example` removed the host; final
  managed truth contains only `dl-cdn.alpinelinux.org`; `policy show` reports no
  bypass; the decisive `expect_state {present: false}` matched. Independent
  datapath corroboration that the removal took effect: `izba netlog` records
  `DENY  l3  pinned.vendor.example:53  a0/d2` *after* the block, alongside
  `ALLOW l7  dl-cdn.alpinelinux.org:443 … GET …curl-8.14.1-r2.apk` for the host
  that stayed granted.
- **`core-police-an-unusual-port-at-http` → genuinely-achieved for what it
  asserts** (`:8000 protocol: http (inspected)` on two separate real
  `izba policy show` runs, actions 3 and 10; managed truth
  `{"host":"internal.svc.example","ports":[{"port":8000,"protocol":"http"}]}`).
  **It does not verify policing.** The Actor's two attempts to generate traffic
  went to `internal.svc.example`, a `.example` host that cannot resolve; the
  netlog contains no flow to it, and the 124 is the Actor's own `while true`
  loop. The journey's `expect` only ever claimed the report, so this is not a
  false green — but the journey name oversells it. Routed as **C5**.

---

## 4. Harness & coverage recommendations

Both harness fixes dispatched between smoke and core **worked**, and I verified
each rather than assuming:

- `5854940e` (stop reading the guest's stderr as izba's): the tier contains
  **six** actions whose relayed stderr carries `ERROR: unable to select
  packages:` and **zero** `implicit` candidates. The dominant noise class of run
  1 and of the smoke tier is gone by construction.
- `5854940e` (grade the command the assertion is about): a declared
  `expect_cmd_re` that matched nothing now flips `unreached_decisive`
  (`core-edit-the-managed-file-and-reload`) instead of grading an unrelated
  command — smoke H2 closed.
- `e3e7d78e` (persist the GUI capture): all three GUI credits are now auditable
  from the bundle — smoke H4 closed.
- The rescue rule fired exactly once and survives audit (§3.7).

| id | what | where | routing |
| - | - | - | - |
| **H1** | The compiler emits `expect_state` on steps that are not `core: true`, so the assertion is **silently never graded** (3 of 19 core journeys). The runner is right to flag it. Fix in the corpus/compiler: any step carrying `expect_state` must be `core: true` — which also enables the step-boundary snapshot, mandatory for `core-firewall-off-does-not-read-as-one-hole` whose Actor legitimately flips `enforce` after step 0. | `dogfood-pt2/tier-core.json` + the journey-compiler templates | auto-fixable |
| **H2** | Exit-code grading conflates the **guest** command's status with izba's. `expect_cmd_re "izba (create\|run)"` matches `izba run NAME -- <guest cmd>`, whose exit izba passes through by contract, so any `apk`/`curl` failure flips a functional candidate on the create step. Either exclude actions carrying a `--` workload from `expect_exit` grading, or make the create step's `expect_cmd_re` reject them. | `hack/dogfood/run_journeys.py` (`_eligible_targets` / `_grade_target`) | auto-fixable |
| **H3** | **Fair-test gap.** The harness exports a per-journey `IZBA_DATA_DIR` (`oracles.py:123`) but never tells the Actor, while the context pack teaches the default `~/.local/share/izba/…`. Any journey that must touch managed state on disk is therefore unwinnable *and* the documented path is actively wrong in-harness. Name `$IZBA_DATA_DIR` in the Actor's environment preamble. | `hack/dogfood/run_journeys.py` (Actor preamble) / `dogfood-pt2/context-pack.md` | auto-fixable |
| **H4** | The model reply channel cannot carry a **heredoc**: both `infra` starvations truncate at `cat > … <<'EOF'`, and every CLI journey in this corpus opens with one. Harden the reply parser, or instruct the Actor toward `printf`/`seed_files`. | `hack/dogfood/run_journeys.py` (`_next_command`) | auto-fixable |
| **C1** | `core-a-plain-policy-renders-without-warnings` puts host strings the Actor must type in step 0 into a **decisive `expect_stdout_re`** in step 1, with no premise check in between — Actor drift reads as a product failure. Add a step-0 `expect_state` (marking it `core`), or seed the policy with `seed_files`. | `dogfood-pt2/tier-core.json` | auto-fixable |
| **C2** | `core-edit-the-managed-file-and-reload` is the only journey requiring an edit to managed state on disk, and it has no route to that path (see H3/P-2). Give it a `seed_files`-written policy plus an explicit "the file is at `$IZBA_DATA_DIR/sandboxes/<name>/policy.yaml`" in the step intent, or the `izba policy reload` promise stays untested. | `dogfood-pt2/tier-core.json` | auto-fixable |
| **C3** | GUI journeys still end one poll short **1 time in 3** (`gui-inert-when-the-firewall-is-off`): the credit rests solely on the harness's post-settle capture, not on anything the Actor saw. Smoke's C2 is improved, not closed — add an explicit settle/re-read action. | `dogfood-pt2/tier-core.json` + `hack/dogfood/gui/run_gui_journeys.py` | auto-fixable |
| **C4** | The corpus certifies that remediation text is **printed**, never that following it **works** — which is exactly the gap P-1 lives in, and it took an unrelated journey's Actor to trip over. Add a journey that *follows* the printed instruction and asserts the resulting state. Generalize: for any message that tells the user to run something, assert the effect, not the string. | `dogfood-pt2/tier-core.json` (new journey) | auto-fixable |
| **C5** | `core-police-an-unusual-port-at-http` verifies only the **rendering** of `protocol: http`; its two traffic attempts went to a non-resolving `.example` host. Rename it to what it tests, or move the policing claim to a deep journey against a real host. | `dogfood-pt2/tier-core.json` | auto-fixable |
| **C6** | **Unobserved in any trajectory — code reading only, recorded so it is not lost:** `apply_block_edit` discards `cfg.block`'s changed-bool (`let _ = cfg.block(...)`, `policy.rs:243`), so `izba policy block NAME typo.example` prints the same `reloaded egress policy for '<name>'` line as a successful removal. A user who mistypes believes they revoked access they still grant. No journey covers a no-op block; propose one for deep. | `dogfood-pt2/tier-deep.json` | auto-fixable (journey) |
| **C7** | **Deep-tier readiness.** Every deep datapath journey needs curl inside `alpine:3.20`, i.e. `apk add` under enforce, i.e. `dl-cdn.alpinelinux.org` allow-listed — and `tier-deep.json` mentions neither the mirror nor curl. In this tier that recovery cost **2–4 actions in every CLI journey**; deep's decisive step is the last of three. Seed the mirror into the create intent (or use a curl-bearing image) before dispatching deep, or decisive steps will go unreached on budget. | `dogfood-pt2/tier-deep.json` | auto-fixable |

**Predicted discoverability flags — what this tier settled.**

- **F3** — the wildcard-refusal asymmetry: the refusal message is excellent and
  actionable, and the paired probe shows the Actor wrote `protocol: http` on a
  wildcard first try with no hesitation. The predicted *hesitation* half is
  **refuted**; the "one wasted attempt" half cannot be measured by a journey
  that instructs the wildcard.
- **F4** — the duplicate-port rule: the message names the port and both readings.
  Docs gap stands; nothing new observed.
- **F5** — `policy allow --help` silent on being unreviewed:
  `core-command-line-grants-skip-the-review-gate` completed cleanly and the
  trajectory shows no confusion. **Not confirmed** by this run.
- **F1, F2, F6** — **not exercised** (all target deep journeys). F6 (the
  undefined `l7`/`l3` tier vocabulary) remains the highest-risk one: every deep
  datapath journey grades on that column, and core Actors ran `izba netlog` four
  times without ever needing to interpret it.

**Noise to suppress next run:** the `apk`-under-enforce class survives only as
an *exit-code* flip now (H2); with H2 fixed it stops reaching triage entirely.

**Caps/infra:** no `reconcile_violation`, no `guest_console` marker, no
`reconciler unusable`, no `ui_daemon_diff`, no `console` candidate; every
sandbox in all 19 journeys reconciled with `violations: []`. Two 120 s latency
caps, both the Actor's own foreground loops. Two model starvations, both
heredoc-shaped.

---

## 5. Capability verdict (the progressive gate)

`sequence-plan.json` gives the core tier `"gating": []` and `"establishes": []`
— core consumes capabilities, it does not mint them. So the verdict here is
whether the smoke-established capabilities **held** under core's 19 journeys,
and whether deep may proceed.

**Every `requires` capability of the core tier is re-corroborated, none blocked:**

| capability | re-corroborated by | evidence |
| - | - | - |
| `hatch-declared` | 7 journeys (`inherit-no`, `dormant-echo`, `dormant-show`, `survive-edit`, `legacy-pin`, `logonly`, `gui-pin2/3/4`) | managed `policy.yaml` carries `{"port":443,"protocol":"tcp"}` per port in every one |
| `posture-readable` | 10 journeys | `izba policy show` answered on the `expect_cmd_re`-selected command, in all **three** not-in-effect wordings (live / dormant-by-access / inert-by-enforce-off) |
| `firewall-file-accepted` | `legacy-pin`, `logonly`, `reload-pin`, `bad-key`, `plain-fw` | `--policy FILE` accepted at `create` and `run`, including via `<(…)` process substitution and the legacy entry-level spelling |
| `manifest-egress-authoring` | 8 journeys | `izba create .` consumed `spec.egress` verbatim into managed truth; `izba diff ungated` → `state: managed ahead` |
| `gui-pinned-row-visible` | all 3 GUI journeys | loaded Policy tab with the per-port `⚠ tcp` chip and row notice, cross-checked against `izba policy show` on the same sandbox |
| `enforcing-sandbox-reaches-an-allowed-host` | incidental, 5 journeys | `ALLOW l7  dl-cdn.alpinelinux.org:443  a12/d0  GET /alpine/v3.20/main/x86_64/curl-8.14.1-r2.apk` after allow-listing, with the pre-grant `DENY l3 …:53` in the same log |

**Established:** the six above.
**Blocked:** none.
**Not-exercised:** `hatch-revealed`, `audit-surface-discoverable`,
`gui-policy-tab-loads` (smoke's, not required by core) and `hatch-via-manifest`
(deep establishes it).

**Orchestrator signal: ADVANCE to the deep tier.** Neither confirmed finding
gates it — P-1 is a message on `izba policy allow`, a verb no deep journey
invokes; P-2 is a help clause. No fix-and-retry is required.

**One readiness caveat, not a gate:** apply **C7** (seed the package mirror /
use a curl-bearing image) before dispatching deep. Every deep datapath journey
puts its decisive assertion in step 3 of 3 behind an `apk add` that will fail
under enforce, and this tier measured that recovery at 2–4 actions.

---

## 6. Fix routing summary

| finding | class | severity | routing | target |
| - | - | - | - | - |
| **P-1** — "re-grant without `--read` to restore it" restores nothing | real | P2 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs:283-289` (message) + `:872` (the test asserting the false claim); mirror `policy show`'s "widen to read-write" wording. *Adding a widening verb is **escalate** and belongs to open issue #259.* |
| **P-2** — `<izba data dir>` placeholder unresolved | discoverability | P3 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs`, `Reload`'s long help. *Adding `data_dir` to `izba version --json` is **escalate** (public schema).* |
| H1–H4, C1–C7 | harness | P2/P3 | **auto-fixable** | `hack/dogfood/**`, `dogfood-pt2/tier-{core,deep}.json`, `context-pack.md` |

**Escalations: 0.**
