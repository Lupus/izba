# Phase 3 — adversarial triage, CORE tier

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough (#233 + #238 + #239/PR #262)
Branch: `dogfood-fixes/passthrough-docs` @ `86520798`
Bundles: `dogfood-artifacts/core/traj-{0,1,2,3}/traj-*.json` — 14 journeys, 4 shards,
3 oracle candidates (2 `implicit`, 1 `functional`), 0 infra, 0 `unreached_decisive`.

**Headline:** 0 candidates survive triage. But the green side is not clean:
**2 of 14 greens are false** — one is a product finding the oracle could not see
(`core-declared-exception-with-the-firewall-off`), one is a harness false-green that
leaves the tier's only `establishes` capability unproven
(`core-author-the-exception-through-the-review-flow`). A third journey
(`core-granting-a-port-does-not-inherit-the-exception`) *passed its promise* and, on the
way, produced the most interesting product evidence of the run.

---

## 1. Confirmed product findings

### CORE-1 (P2, real) — `policy show` announces a LIVE pinning hatch on a sandbox whose firewall is off

`izba policy show pin17` prints the full live-hatch warning under an `enforce: off`
header, and never says that all egress is allowed:

```
shard 1 / core-declared-exception-with-the-firewall-off / action[2]  (exit 0)
'pin17' egress policy (enforce: off):
  http allow-list:
    pinned.vendor.com  [443] (read-write)
        ⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules, no request audit, no upstream certificate verification
```

The claim is false in both halves. `EgressPolicyConfig::compile`
(`crates/izba-core/src/daemon/egress/config.rs:832-836`): *"When `enforce` is `false`,
returns an `AllowAll`"* — the allow-list restricts nothing. And
`router::passthrough_names` (`crates/izba-core/src/daemon/egress/router.rs:416-419`):
*"A bare sandbox is never terminated, so it has nothing to pass through. `if
!policy.enforces() { return Vec::new(); }`"* — there is no splice, opaque or otherwise;
the flow is an ordinary tier-2 dial. An operator reading this output sees what looks like
a default-deny firewall with exactly one hole, when in fact **nothing is filtered at all**.

`render_policy` already knows this argument — it applies it only to the empty-list case
(`crates/izba-cli/src/commands/policy.rs:311-321`): *"Reporting 'deny all' for a bare
sandbox … would misstate the posture in the safe-looking direction, on the one surface
that reveals it."* The identical hazard for a NON-empty list is unhandled: the
`Some(Protocol::Tcp)` branch keys on `e.access() != Access::ReadWrite` and never on
`cfg.enforce`.

- Anchor: `router.rs:416-419` + `config.rs:832-836` + `render_policy`'s own empty-list
  rationale; `policy show --help` ("the effective allow-list …, the enforce posture …,
  and each port's declared inspectability").
- Trajectory: shard 1 / `core-declared-exception-with-the-firewall-off` / action[2];
  corroborated by the journey-end state evidence (identical `policy_show` stdout).
- Fix routing: **auto-fixable** — pure renderer text/branch, no policy or datapath
  semantics change. `crates/izba-cli/src/commands/policy.rs::render_policy` (print
  `all egress allowed (enforce off)` for a non-empty list too, and mark any declaration
  as "not in force — enforce off" rather than as a live splice). Check the GUI twin
  `app/src/components/PolicyEditor.tsx::portDeclarationLabel` in the same edit — it also
  keys only on `access`, and #239 requires the two revealing surfaces not to disagree.
- Why the oracle missed it: the journey has no `expect_text`; exit 0 was the whole test.

### CORE-2 (P2, discoverability) — an unrelated `policy allow … --read` silently deactivates a LIVE hatch on another port; nothing warns, and no doc mentions the rule

Observed end-to-end inside a journey that otherwise passed:

```
shard 0 / core-granting-a-port-does-not-inherit-the-exception
action[3]  izba policy show pin12          → pinned.vendor.com [80,443,8080] (read-write)
                                              ⚠ :443 … pinning passthrough: spliced opaquely …   ← LIVE
action[4]  izba policy allow pin12 pinned.vendor.com:8443 --read   (exit 0)
           "allowed pinned.vendor.com  [80, 443, 8080, 8443]  access: read (HTTP GET/HEAD only)"
action[5]  izba policy show pin12          → pinned.vendor.com [80,443,8080,8443] (read)
                                              ⚠ :443 … pinning passthrough NOT in effect …        ← DORMANT
```

`--read` narrows access **entry-wide** (`set_host_access` rewrites the whole entry), so a
grant aimed at `:8443` turned off the vendor's pinning passthrough on `:443`. That is a
real, user-visible functional change (the pinning client will now be handed izba's
certificate and fail), and the only surface that says so is a `policy show` the user has
no reason to run. The grant echo mentions only `access: read (HTTP GET/HEAD only)`.

Two doc/UX gaps compound it — this is predicted flag **D2**, now evidenced:
the dormant-hatch rule appears **nowhere** in `context-pack.md` (README example at
lines 94-105 carries no `access:` on the `pinned.vendor.com` block; neither `--policy`,
`policy allow --help` nor `policy reload --help` mention the interaction), so a user who
follows README's own `access: read` advice for a vendor gets a declaration that silently
does nothing.

- Anchor: `render_policy`'s dormant branch comment (`policy.rs:~355-372`) — *"A narrower
  access level CANCELS the hatch … `router::passthrough_names` drops the host and the
  connection stays terminated"* — vs `policy allow`'s echo, which says nothing; and
  `izba policy allow --help`, which documents the non-inheritance rule but not this one.
- Trajectory: shard 0 / `core-granting-a-port-does-not-inherit-the-exception` /
  actions[3,4,5]; persisted state confirmed by the journey-end `policy_show` (`(read)` +
  NOT-in-effect line).
- Fix routing: **auto-fixable** (wording only): one conditional line on the `policy allow`
  echo when the resulting entry access is `read` and the host still carries a declared
  `protocol: tcp` port, plus one comment line on the README `pinned.vendor.com` example
  and a clause in `--policy` help. Constraint from #259's own scoping: derive the
  *wording* from the access verb at the CLI site — do **not** add a second fold of
  inspectability outside `InspectionTable`.

*(Not escalated: the behaviour itself is intended and test-pinned —
`a_read_grant_preserves_the_declared_port_and_pins_nothing_new` — and it errs toward MORE
inspection, so it is not a security weakening. The defect is silence, not semantics.)*

---

## 2. Rejected candidates (all 3)

| # | journey | verdict | refutation |
|---|---|---|---|
| 1 | `core-author-the-exception-through-the-review-flow` — `implicit`: "crash marker 'ERROR' in stderr of `izba exec pin16 -- apk add --no-cache curl`" | **self-inflicted + oracle FP** | The marker is **apk's own** output, not izba's: `"WARNING: fetching https://dl-cdn.alpinelinux.org/…: DNS lookup error / ERROR: unable to select packages: curl (no such package)"` (shard 0, action[6]). The firewall was doing its job — journey-end netlog: `DENY l3 dl-cdn.alpinelinux.org:53 a0/d4`. The swarm then ran `izba policy allow pin16 dl-cdn.alpinelinux.org` (action[7]) and the same command succeeded (action[8], exit 0, `OK: 13 MiB in 24 packages`), with netlog `ALLOW l7 dl-cdn.alpinelinux.org:443 … GET /alpine/…/curl-8.14.1-r2.apk`. No izba panic, no abort. |
| 2 | `core-older-entry-level-declaration-still-works` — `implicit`: "exit 127 (CommandNotFound) from `izba exec pin14 -- sh -c 'curl …'`" | **self-inflicted + oracle FP** | Not izba's `CommandNotFound` wire frame: stderr is `sh: 1: curl: not found` (shard 2, action[6]) — the **guest shell's own** 127, propagated by crun exactly as the exit-code contract requires. That exec reached the workload fine: the immediately preceding `izba exec pin14 -- sh -c 'getent hosts example.com'` returned exit 0 with two A/AAAA records (action[5]). `ubuntu:24.04` simply ships no curl. |
| 3 | `core-declaration-survives-an-unrelated-cli-edit` — `functional` soft: "`izba exec pin13 -- sudo apt-get update && …` exited 1 while step expected 'the sandbox is created with no error'" | **self-inflicted + oracle mis-attribution** | stderr: `executable file 'sudo' not found in $PATH: No such file or directory` (shard 1, action[7]) — crun's honest rc-1 for a missing binary, per the exit-code contract, on a guest image with no `sudo`. Separately the oracle graded an `izba exec` against step 0's expect ("the sandbox is created with no error"); the sandbox had been created 6 actions earlier (action[1], exit 0, reconcile shows `pin13`). |

Both `implicit` misfires and the mis-attribution are logged as harness findings (§4).

---

## 3. Positive-trajectory audit (all 14 journeys)

**Genuinely achieved (10).**

| journey | proof |
|---|---|
| `core-show-attributes-declaration-to-its-port` | shard 0 action[1]: `pinned.vendor.com  [80, 443] (read-write)` followed by exactly ONE marker line, `⚠ :443 protocol: tcp — …`. The host carries two ports; only `:443` is named. **Yes — this proves port attribution, not host attribution**: the same host's `:80` appears in the ports list with no marker of its own. (Scope note: it proves the *audit surface* attributes per port; the datapath binding is deep-tier.) |
| `core-show-stays-quiet-for-a-plain-policy` | shard 2 action[2]: two hosts, zero occurrences of `inspected`/`passthrough`/`pinning`. Signal value preserved. |
| `core-refuse-pinning-on-a-wildcard-host` | exit 1 **with the right message**: `allow[0]: 'protocol: tcp' (the TLS-pinning passthrough) needs an exact host, but '*.example.com' is a wildcard pattern — the hatch is matched against the observed ClientHello SNI. Name each pinned host explicitly.` Names the entry, the offending value, the reason, and the remedy. |
| `core-refuse-an-unknown-protocol-value` | exit 1: `allow[0].ports[0].protocol: expected 'http' or 'tcp', got 'unknown'` — names the field path, the bad value, and both valid values. |
| `core-refuse-a-typo-in-the-port-mapping` | exit 1: `allow[0].ports[1]: unknown key 'protcol' (valid keys: port, protocol)` — names the unknown key and the full key set. |
| `core-refuse-one-port-declared-two-ways` | exit 1: `allow[0].ports: port 443 is listed twice with different declarations (no protocol and protocol: tcp) — one port cannot be both inspected at L7 and spliced opaquely. Name it once, with the declaration you mean.` Names the port AND both declarations; does not silently resolve. |
| `core-inspection-may-be-asked-for-on-a-wildcard` | shard 3 actions[1,3]: `izba create --name pin11 --policy policy.yaml` exit 0 for `*.example.com` + `port: 8000 / protocol: http`, rendered `:8000 protocol: http (inspected)`. The asymmetry holds in both directions in the same tier (cf. the wildcard refusal above). Bonus corroboration at action[10]: `izba policy allow pin11 '*.example.com:8000'` (exit 0) re-granted an already-declared port and the journey-end state still shows `:8000 protocol: http (inspected)` — a CLI grant does not drop an existing declaration. |
| `core-granting-a-port-does-not-inherit-the-exception` | **Yes, it proves non-inheritance, not merely that a grant succeeded.** action[2] `izba policy allow pin12 pinned.vendor.com:8080` (exit 0, echo `[80, 443, 8080] access: read-write`) → action[3] `policy show` renders `[80, 443, 8080] (read-write)` with the marker line still naming ONLY `:443`. The new port is present and unmarked in the same rendering that marks the declared one. (Also see CORE-2 for what actions[4,5] then exposed.) |
| `core-older-entry-level-declaration-still-works` | shard 2 action[1] `izba create --name pin14 --policy policy.yaml` exit 0 for the entry-level `protocol: tcp` + `ports: [1443]`; action[3] `policy show` → `example.com [1443] (read-write)` + `⚠ :1443 protocol: tcp — pinning passthrough: spliced opaquely; …`. Accepted, not dropped, and normalized down onto the entry's port with unchanged meaning. Journey-end state agrees. |
| `core-pinned-port-under-read-only-access` | see the dedicated audit below. |

**Inconclusive → coverage gaps (2).**

- `core-police-a-non-web-port` — the promise ("policed at L7 rather than passed through")
  is asserted only by the rendering `:8000 protocol: http (inspected)` (shard 1,
  action[2]). No traffic ever crossed `internal.example.com:8000`; journey-end netlog:
  `izba: no egress recorded yet for 'pin5'`. The audit surface is verified; the datapath
  is not. Tighten by pointing the journey at a reachable host/port and asserting a netlog
  `ALLOW l7` line.
- `core-declaration-survives-an-unrelated-cli-edit` — **half the journey never ran.** The
  step-1 intent was "allow one more unrelated host **and remove a port from the ordinary
  host**"; the swarm only ever ran `izba policy allow` (actions[9,10]) — `izba policy
  block` was never invoked, so the *removal* half of the promise is unexercised. The
  additive half IS corroborated, but by the harness's independent journey-end snapshot,
  not by the swarm: after both grants, `policy show pin13` shows
  `pinned.vendor.com [443] (read-write)` + `⚠ :443 …` intact and NO marker on
  `example.com`, `archive.ubuntu.com` or `security.ubuntu.com`. The swarm's own decisive
  credit is bogus (see CORE-3).

**Cheated / hidden failure (2).**

- `core-author-the-exception-through-the-review-flow` — **unverified success; the tier's
  only `establishes` capability is NOT established.** The decisive step 2 ("apply the
  reviewed change and then print the effective policy") produced **zero actions**. The
  swarm burned actions 0-8 on step 0 (create, status, start, and two rounds of installing
  curl), wrote its edited manifest to the WRONG path at action[9] (`cat > izba.yml` in the
  shell cwd `…/proj`, while `izba status pin16` at action[3] had already printed
  `workspace: /tmp/izd-0/core-author-the--6ebb2c89/proj/pin16`), and its `izba diff pin16`
  (action[10]) consequently diffed the ORIGINAL manifest: `to: enforce: true / allow:
  [example.com]` — no `vendor.com`, no `protocol: tcp`. **No `izba promote` was ever run.**
  Ground truth at journey end: `'pin16' egress policy (enforce: on): example.com …,
  dl-cdn.alpinelinux.org …` — no vendor host, no hatch anywhere. The green is an artifact
  of `_grade_decisive_from_observed` crediting action[5], an `izba policy show pin16` run
  *before* the manifest was even edited (see CORE-3). Verdict: **cheated/unverified**;
  `hatch-via-manifest` → **blocked**. Root cause is swarm fumbling (wrong directory), not
  a product defect — `izba diff` behaved correctly on the file that actually existed.
- `core-declared-exception-with-the-firewall-off` — **hidden failure.** Exit 0, but the
  observed output contradicts the journey's own expect ("reports … that all egress is
  allowed, so an operator cannot mistake it for an enforcing policy with a single
  exception"). This is finding CORE-1.

### The dormant-hatch journey, audited hardest (`core-pinned-port-under-read-only-access`)

Three actions, all exit 0 — but **not** a trivial pass. The swarm authored exactly the
shape under test (shard 3, action[0]):

```yaml
allow:
  - host: pinned.vendor.com
    access: read
    ports:
      - 80
      - port: 443
        protocol: tcp
```

created `pin15` (action[1], exit 0, reconcile shows the sandbox), and ran the one command
the step asks for (action[2], `izba policy show pin15`), whose stdout is:

```
    pinned.vendor.com  [80, 443] (read)
        ⚠ :443 protocol: tcp — pinning passthrough NOT in effect: an opaque splice carries
        no HTTP method, so this entry's access level never authorizes one; the connection
        stays terminated at L7 (a pinning client still sees izba's certificate) —
        widen to read-write to pin
```

Every clause of the step's `expect` is satisfied by that one line: it distinguishes the
case ("NOT in effect"), gives the mechanism ("an opaque splice carries no HTTP method"),
states the user-visible consequence ("a pinning client still sees izba's certificate"),
and prescribes the remedy ("widen to read-write to pin"). It is also **true** —
`router::passthrough_names` runs `decide_tier2` as a ceiling and drops a name whose
`policy.check` fails, which `access: read` guarantees for a methodless flow.

The swarm neither passed trivially nor drew the wrong conclusion: it stopped, having got a
complete answer, and took no follow-on action premised on a live hatch (contrast the
`--read` sequence in `core-granting-a-port-does-not-inherit-the-exception`, where the same
NOT-in-effect line appeared as a *consequence* the swarm did not seek — and the product
still told the truth about it, unprompted). CLI trajectories carry no narration channel,
so the swarm's *comprehension* is formally unobservable; the product side is not.

**Was the fair user misled? At `izba policy show`: NO.** The rendering is explicit,
mechanistic and actionable, and it fires in both journeys that reached the state.
**Before running it: YES, twice over** — the rule is absent from every doc the user has
(D2), and the surface that *creates* the state (`policy allow … --read`) says nothing
(CORE-2). Net: izba's audit surface is honest; its authoring surfaces are silent.

---

## 4. Harness & coverage recommendations

- **CORE-3 (P1, harness) — a decisive step can be credited by an action that predates the
  change under test.** `_grade_decisive_from_observed`
  (`hack/dogfood/run_journeys.py:518-577`) scans **all** journey actions for the LAST
  `expect_cmd_re` match, with no ordering constraint. Two journeys this tier were graded
  from an action belonging to an EARLIER step:
  `core-author-the-exception-through-the-review-flow` → `{"step_index": 2,
  "action_index": 5, "graded_cmd": "izba policy show pin16"}` (a pre-edit show — the
  journey's entire point was what a *later* promote would change), and
  `core-declaration-survives-an-unrelated-cli-edit` → `{"step_index": 2,
  "action_index": 3, "graded_cmd": "izba policy show pin13"}` (a pre-edit show, in a
  journey about surviving edits). Since `functional_oracle` only looks at the exit code,
  both credits passed silently. Concrete fix: only credit an action whose index is greater
  than the last action of the decisive step's preceding step (both bogus credits sit
  inside step 0's range, while the intervening steps ran at actions 8-10 and 8-10
  respectively); otherwise emit `unreached_decisive`. Files:
  `hack/dogfood/run_journeys.py`.
- **CORE-4 (P2, harness) — the `implicit` oracle mis-reads guest output as izba failure.**
  (a) It greps guest command stderr for the token `ERROR` and calls it a crash marker —
  `apk`'s `ERROR: unable to select packages` produced this run's only "crash". (b) It maps
  any exit 127 to izba's `CommandNotFound` wire frame, but `izba exec … -- sh -c '…'`
  returns the *shell's* 127 (`sh: 1: curl: not found`). Scope the crash-marker scan to
  izba's own stderr (or require a panic/abort signature), and treat 127 as the izba frame
  only when the command is not a shell wrapper / when stderr lacks a `<shell>: … not
  found` line. Also: `functional_oracle` graded an `izba exec` against the *create* step's
  expect — when a step's actions drift far from its intent, prefer the best-outcome izba
  invocation, or grade nothing. Files: `hack/dogfood/oracles.py`,
  `hack/dogfood/run_journeys.py`.
- **CORE-5 (P2, coverage) — greens that only test a renderer.** Every CORE journey asserts
  on `policy show` text and exit codes; the only journeys that produced real egress did so
  by accident (installing curl). `core-declared-exception-with-the-firewall-off` shipped a
  *wrong* rendering as a pass purely because it had no `expect_text`. Add `expect_text`
  hooks to the render journeys (e.g. `NOT in effect`, `all egress allowed (enforce off)`,
  `(inspected)`), and mark the datapath claims as deep-tier-only.
- **CORE-6 (P2, coverage) — the manifest journey needs a seeded manifest and an explicit
  cwd.** `core-author-the-exception-through-the-review-flow` lost its decisive step to
  guest-tooling detours and a wrong-directory write. Give it `seed_files` containing the
  pre-edited `izba.yml` inside the project dir, an explicit "from inside the project
  folder" instruction, and an image that already carries curl (or drop the curl step
  entirely — nothing in the journey needs it). Re-run it standalone before dispatching the
  deep tier.
- **Cheap-model weakness to suppress, not to fix in the product:** three shards
  independently tried `izba policy allow <name> hostA hostB` and got clap's
  `error: unexpected argument 'security.ubuntu.com' found` + the correct `Usage:` line
  (pin11 action[6], pin13 action[8], pin14 action[8]). The error is exact and
  self-correcting; each shard recovered on the next action. Noise — but if it recurs, one
  clause in `policy allow`'s help ("one target per invocation") would end it. Out of this
  feature's scope.
- **Context pack is fresh this tier** (unlike smoke run 2): the CLI hatch line the swarm
  saw carries "no upstream certificate verification", and the `--policy` help carries the
  per-port + legacy wording. The `context-pack-stale-vs-tip` harness finding from
  `skeptic-smoke2` is **closed**.
- **Known prior art — re-sighting check.**
  - **#243** (a superseded duplicate entry leaves `policy show` advertising a passthrough
    not in force): **NOT re-sighted, and NOT exercised.** No CORE journey produced a
    second entry for the same host — `policy allow` folded every grant into the existing
    entry (`entries_for_host`), so the duplicate-entry shape never arose. The class
    remains unfixed and untested; it needs a journey that authors two entries for one host
    in `policy.yaml`.
  - **#259** (`policy allow --read` on a pinned host refuses with a message contradicting
    `policy show`): **premise obsolete.** The refusal gate is gone — dropped in `004cbbf2`
    ("drop the passthrough-widening gate"), documented at
    `crates/izba-cli/src/commands/policy.rs:477-484`: *"These replace #235's
    refuse-unless-`--passthrough` gate … the declaration is per-PORT now, so a granted port
    carries none and there is nothing left to refuse."* Trajectory confirms: `izba policy
    allow pin12 pinned.vendor.com:8443 --read` **exits 0** and lands (shard 0, action[4]).
    There is no contradicting refusal left to sight. #259 should be closed/re-scoped; its
    residue is CORE-2 (the grant is now silent where it used to be loud).

---

## 5. Capability verdict (progressive gate)

Tier `core` declares `gating: []` and `establishes: ["hatch-via-manifest"]`.

| capability | verdict | evidence |
|---|---|---|
| `hatch-via-manifest` | **BLOCKED** | `core-author-the-exception-through-the-review-flow` never ran `izba promote`; its decisive step produced zero actions and was credited from a pre-edit `policy show` (shard 0, action[5]). Journey-end ground truth: pin16's effective policy contains no vendor host and no `protocol: tcp`. Cause is swarm/journey fumbling, not a product defect. |
| `hatch-declared` | **established (re-confirmed)** | pin4/pin12/pin13/pin15 all created with a per-port `protocol: tcp` policy, exit 0, reconcile shows each sandbox. |
| `hatch-visible-in-show` | **established (re-confirmed)** | pin4 action[1] and pin15 action[2] — marker rendered against the declaring port, in both live and dormant forms. |
| `policy-file-at-create` | **established (re-confirmed)** | 11 `izba create/run --policy` invocations across 4 shards, all exit 0 or a correct refusal. |
| `policy-show-renders` | **established (re-confirmed)** | 12 `izba policy show` invocations, all exit 0, all with well-formed output. |
| `manifest-egress-review` | **established (re-confirmed)** | shard 0 action[10] `izba diff pin16` exit 0, rendering an `egress: [live]` section with a from/to body. |

**Orchestrator guidance.** No gating journey failed, so the tier does not block on a
product fix. But `hatch-via-manifest` is unproven, and the deep tier's
`deep-review-flags-a-new-exception-as-weakening`,
`deep-review-is-quiet-when-posture-tightens` and `gui-pinned-port-is-visible-in-the-policy-tab`
(plus the 7 `gui-*` journeys transitively gated on `gui-pinned-row-visible`) all require
it. **Re-run `core-author-the-exception-through-the-review-flow` alone, with the CORE-6
tightening, before dispatching deep** — otherwise 10 of 19 deep journeys start from an
unestablished premise.

---

## 6. Fix routing summary

| id | class | severity | routing | files |
|---|---|---|---|---|
| CORE-1 | real | P2 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs` (`render_policy`); check twin `app/src/components/PolicyEditor.tsx` |
| CORE-2 | discoverability | P2 | **auto-fixable** | `crates/izba-cli/src/commands/policy.rs` (`policy allow` echo + `--policy`/`policy allow` help), `README.md` (policy-file example) |
| CORE-3 | harness | P1 | **auto-fixable** | `hack/dogfood/run_journeys.py` |
| CORE-4 | harness | P2 | **auto-fixable** | `hack/dogfood/oracles.py`, `hack/dogfood/run_journeys.py` |
| CORE-5 | inconclusive | P2 | **auto-fixable** | `dogfood-passthrough/tier-core.json` (add `expect_text`) |
| CORE-6 | unverified | P1 | **auto-fixable** | `dogfood-passthrough/tier-core.json` (`seed_files` + cwd instruction) |

Nothing this tier requires **escalate**: CORE-1 and CORE-2 are both surface text (what the
product *says*), and the underlying enforcement semantics — dormant-hatch cancellation,
per-port non-inheritance, wildcard refusal, duplicate-port refusal, back-compat
normalization — behaved exactly as specified everywhere they were exercised.

---

## 7. Direction C — documented / usable / works as expected (CLI half)

### 7a. The 10 predicted flags, adjudicated against this tier

| flag | verdict | evidence |
|---|---|---|
| **D1** (CLI warning omits cert-verification loss) | **REFUTED — closed** | Every live-hatch line in the run reads `… no L7 rules, no request audit, no upstream certificate verification` (pin4 action[1], pin13 action[3], pin14 action[3], pin17 action[2]). `a2a107d1` landed. |
| **D2** (dormant-hatch rule undocumented) | **CONFIRMED (P2, downgraded from P1)** | The rule is in no doc the swarm had, and the surface that creates the state is silent (CORE-2, pin12 action[4]). **But** the P1 premise — "a user silently gets the wrong posture" — is refuted: `policy show` states it exactly and actionably (pin15 action[2], pin12 action[5]). Doc gap + grant-echo gap, not a posture lie. |
| **D3** (`create/run --help` teaches the per-HOST shape) | **REFUTED — closed** | Help now says "a per-PORT `protocol:` key … The legacy entry-level spelling still parses and applies to EVERY port of that entry" (`context-pack.md:627,688`). Behavioural evidence: **7/7 journeys that authored a hatch wrote the per-PORT form correctly on the first attempt** (pin4, pin7, pin9, pin10, pin12, pin13, pin15) with zero syntax retries; the only entry-level file in the run was the one `core-older-entry-level-declaration-still-works` explicitly asked for. `86520798` landed. |
| **D4** (README weakening list omits both inspection transitions) | **NOT EXERCISED** | No CORE journey ran a `⚠ weakens egress` diff; deep tier owns it. The context-pack text (line 474) is unchanged, so the flag stands as a hypothesis. |
| **D5** (reviewed authoring path undocumented) | **REFUTED as a doc gap** | `context-pack.md:432-437` now states `spec.egress` takes "the **same schema as `policy.yaml`** … including a per-port `protocol:` … the only authoring route with the `⚠ weakens egress` gate in front of it". The swarm authored a correct per-port `protocol: tcp` block inside `spec.egress` unaided (shard 0, action[9]). Its failure was a wrong *directory*, not a wrong *shape*. |
| **D6** (app guide silent on pinned rows) | **NOT EXERCISED** | GUI journeys are deep-tier. |
| **D7** (nothing says WHICH surface reveals a hatch) | **REFUTED — closed** | `policy show --help` now names itself as the audit surface and warns `izba status` renders no egress posture (`context-pack.md:74-79, 998`). Behavioural: four journeys ran `izba status` (pin11, pin13, pin14, pin16) and **not one** treated it as an egress answer — each went on to `izba policy show`. |
| **D8** (wildcard-`tcp` refusal only discoverable by triggering it) | **CONFIRMED but mitigated (P3)** | Still absent from the README wildcard paragraph (`context-pack.md:125-131`). Mitigation is strong and now evidenced: the error itself teaches the rule *and* the remedy (pin7 action[1]), and the complementary permission is real (pin11: `protocol: http` on `*.example.com` accepted). Cost is one wasted attempt, self-corrected. |
| **D9** (back-compat promise invisible) | **REFUTED — closed** | Now stated in both `--policy` and `policy reload` help (`context-pack.md:627,1068`), and proven true: pin14's entry-level file parsed and rendered against `:1443` with unchanged meaning. |
| **D10** (nothing says CLI grants are unreviewed) | **REFUTED — closed** | `context-pack.md:435-437`: "`izba policy allow` and a hand-edited `policy.yaml` both apply immediately, unreviewed", echoed in `policy reload --help` (line 1068). |

Split: **2 confirmed** (D2 as P2, D8 as P3-mitigated), **6 refuted/closed** (D1, D3, D5,
D7, D9, D10), **2 not exercised** (D4, D6 — both deep-tier).

### 7b. Plain answers, CLI half of the feature

**Is it documented? — Yes, now, with one hole.** After `a2a107d1`/`86520798` the fair-test
surface teaches: the per-PORT shape (with a worked `pinned.vendor.com` example), what the
hatch costs *including* upstream certificate verification, that the legacy entry-level
spelling is legacy and entry-wide, that `policy show` (not `izba status`) is the audit
surface, that a granted port never inherits the hatch, and that `izba.yml` + `diff`/
`promote` is the only reviewed authoring route. The hole is **D2**: nothing warns, in
advance, that `access:` narrower than `read-write` makes the declaration dormant — despite
README itself recommending `access: read` for exactly the kind of vendor host a user would
pin.

**Can a fair user use it? — Yes.** Seven independent journeys, across all four shards, authored a valid
per-port `protocol: tcp` policy from the docs alone, first try, with no syntax fumbling; the one
entry-level file in the run was deliberate. When a user guesses wrong, the product
corrects them precisely rather than accommodating them silently — all four refusal paths
name the offending key/value, the field path, and the valid alternatives (§3), and each is
recoverable in one edit. The one genuine usability trap is CORE-2: an ordinary
`policy allow … --read` on a pinned host changes that host's pinning posture with no
mention in its own output.

**Does it behave as specified? — Yes, everywhere the tier could reach; the specified
behaviour is just not always described correctly.** Verified against spec/CLAUDE.md:
declaration attributed to the declaring port and not the host (pin4); a CLI grant adds an
inspected port and never inherits the hatch (pin12 actions[2,3]) and never drops an
existing declaration (pin11 action[10], pin13 end-state); `protocol: tcp` refused on a
wildcard while `protocol: http` is accepted on one (pin7 vs pin11); a port declared twice
with conflicting protocols refused naming both (pin10); unknown key and unknown value both
refused with valid alternatives (pin9, pin8); the legacy entry-level spelling parses and
keeps its meaning (pin14); a hatch under narrow access is reported dormant, truthfully and
actionably (pin15). The single behavioural-report defect is CORE-1 — with the firewall
off, `policy show` describes a splice that `router::passthrough_names` will never perform.
The datapath itself (does a live hatch actually splice, does a dormant one actually stay
terminated) was **not** exercised by this tier and remains a deep-tier obligation.
