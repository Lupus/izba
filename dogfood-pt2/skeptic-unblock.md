# Phase-3 triage — **unblock tier** (run 2, tip `f159160a` + `0bd633dc`)

Feature: TLS-passthrough / per-port inspectability (`protocol: http|tcp`).
Surface under test: branch `dogfood-fixes/passthrough-docs`.
Inputs: `dogfood-pt2/collected-unblock.json`, `dogfood-pt2/art-unblock/**`,
`tier-unblock.json`, prior triage `skeptic-{smoke,core,deep}.md`,
fair-test surface `context-pack.md` / `dogfood-app-guide.md`.

**Headline: 10 journeys, 7 candidates, 0 product bugs, 0 escalations, 1 confirmed
discoverability finding — and it was found by auditing a GREEN, not a red.**
Every one of the 7 reds is refuted. Four of the ten journeys still verified
nothing, for reasons the three "fixes" did not address.

---

## 0. Verdict on the three fixes (asked for first, answered first)

| fix | verdict | evidence |
|---|---|---|
| **D1** — rewrite `deep-exception-does-not-follow-a-raw-address`'s expectation from `DENY` to a line-anchored `ALLOW l7 … example.com:443` | **WORKED — the expectation is now correct.** It still did not match, but for a reason that is *not* the expectation. | The rewritten regex is the right observable; §1.4 shows the product did the right thing for a premise the Actor destroyed. No false security red was manufactured this round — the whole point of D1. |
| **D2** — mark 7 journeys' create-time `expect_state` steps decisive | **WORKED.** | 5 of the 7 `decisive_credits` entries recorded across the tier are `expect_state: … (matched)` on a create step that previously graded nothing — e.g. `deep-two-hosts` step 0 `{"host":"example.net","port":{"number":443,"pinned":false}}` matched, `core-edit-the-managed-file-and-reload` step 1 `{"host":"pinned.vendor.example","port":{"number":443,"pinned":true}}` matched. Declared assertions are now actually graded. |
| **D3** — refund the first 3 consecutive GUI `read`s (`_FREE_CONSECUTIVE_READS`) | **PARTIALLY WORKED, and it was aimed at the wrong mechanism.** It bought one journey two extra actions and killed two false reds; it did not and *cannot* fix the thing that makes all three GUI journeys unreached. | See §1.1–1.3. |

### Why D3 could never have worked

The deep-tier skeptic diagnosed budget starvation (**H6**) *and* separately
recommended **C3**: "`gui-cannot-move-…` / `gui-adding-a-port-…` both spend their
last budget on a separate 're-read the saved settings' step that never runs. Fold
that assertion into the save step's `expect_state`." **H6 was implemented; C3 was
not.** C3 was the correct diagnosis.

The mechanism, from the harness source and the bundles:

- All three journeys end with a decisive step whose intent is *"re-read … and
  check/confirm …"* and whose only hook is `expect_state`. That step requires
  **zero browser actions** — the assertion is graded against end-of-journey
  daemon truth.
- In `run_gui_journeys.py`, a `read` reply does `continue` **without appending to
  `actions`** (line ~795). `step_action_start` / `step_actions` count only real
  actions. So an observation-only step has, structurally, `step_actions[i] == 0`.
- `state_hooks.step_was_entered` therefore returns `False`, and
  `_grade_core_step_hooks` (`run_gui_journeys.py:491-504`) emits
  `unentered_step_candidate` **before** ever consulting the state hook.
  `_observed_rescue` only rescues an `expect_text`; these steps declare none.

D3 makes reads *free*, which makes it **strictly more likely** the Actor spends an
observation-only step on refunded, unrecorded `read`s and then answers `done` —
i.e. D3 slightly worsened the specific failure it was meant to fix. The guard's own
docstring names these journeys ("the PR #262 journeys' exact shape"); it is working
as designed. **The journeys are mis-shaped, not the budget.**

Where D3 *did* help — `gui-removing-the-exempt-port-unlocks-the-row`:

| | deep tier | unblock tier |
|---|---|---|
| actions | 8, ended mid-step-1 | 10, step 1 completed |
| last action | `click @e25` = *"Remove port 80"* (wrong port) | `click @e26` = *"Remove port 443"* (correct), then `fill @e24 renamed.vendor.example`, then `click @e12` Save |
| candidates | 2 × `functional` (both FALSE: `'saved · reloaded' absent`, `'renamed.vendor.example' … absent`) + 1 unreached | 1 × unreached only |
| step-1 hooks | both failed | both **matched** |

That is two false product reds eliminated. Credit D3 with that and nothing more.

---

## 1. Rejected candidates (7 of 7)

### 1.1 `gui-cannot-move-the-exception-to-another-host` — `unreached_decisive` → **harness**

The product did exactly what PR #262 promises; the harness refuses to say so.
End-of-journey `state_evidence.per_sandbox["gui-pin5"].policy_yaml`:

```json
{"enforce": true, "allow": [
  {"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}]},
  {"host": "api.vendor.example",    "ports": [443, 8080]}]}
```

The decisive assertion was `{"host":"pinned.vendor.example","port":{"number":443,"pinned":true}}`
— **satisfied**. `moved.vendor.example` is absent — **the rename did not take**, as
step 2's `expect_state {"host":"moved.vendor.example","present":false}` already
credited. The row is visibly locked in the final snapshot:
`[@e24] textbox "Locked: this row carries a TLS-pinning passthrough port — remove the pinned port, or edit policy.yaml, or izba.yml followed by izba diff / izba promote."`
`invoke_log` shows `policy_set_full` `ok: true` with **zero** rejected invokes.

**Second-order Actor defect, new this round:** action 7 is `fill @e11 moved.vendor.example`
where the snapshot renders `[@e11] LabelText ""` — an *unnamed label node*, not the
host field (`@e24`). In the deep run the Actor targeted `@e24` correctly. So the
rename was not merely refused, it was never aimed at the control. Offering a
role-`LabelText`, empty-name node as an actionable `@e` ref is a snapshot-quality
defect that invites exactly this (**H-U7**).

### 1.2 `gui-removing-the-exempt-port-unlocks-the-row` — `unreached_decisive` → **harness**

`policy_yaml`: `{"enforce": true, "allow": [{"host": "renamed.vendor.example", "ports": [80]}]}`.
Decisive assertion `{"host":"pinned.vendor.example","present":false}` — **satisfied**.
Removing the pinned port unlocked the Host field, the rename took, and no `protocol: tcp`
survived. PR #262: *"Removing the pinned port is the escape valve for BOTH the Host lock
and the Access-widening refusal"* — **confirmed**. Same §0 mechanism blocks the credit.

### 1.3 `gui-adding-a-port-here-never-inherits-the-exception` — `unreached_decisive` → **harness**

`policy_yaml`: `{"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}, 9000]}`.
Decisive assertion `{"number":443,"pinned":true}` — **satisfied**; the new port 9000 is a
bare number, inheriting nothing. `policy show` renders `⚠ :443 protocol: tcp` and nothing
on 9000. CLAUDE.md: *"appends a port that structurally cannot inherit a sibling port's
hatch"* — **confirmed**. Note this step's assertion is graded against the *same*
end-of-journey evidence that already credited step 1 — it is redundant by construction,
which is precisely why C3 said to fold it in.

### 1.4 `deep-exception-does-not-follow-a-raw-address` — `functional` → **self-inflicted (premise destroyed)**

D1's expectation is right. The Actor never established "an address izba never resolved
for this sandbox".

- **Action 5** — `izba exec raw-addr -- sh -c 'apk add curl && curl -v … https://example.com'`
  — a **name-based** fetch. curl's own trace: `* Host example.com:443 was resolved. … * IPv4: 172.66.147.243, 104.20.23.154`.
  That resolution went through izba's stub resolver, so **izba snooped
  `172.66.147.243 → example.com` for this sandbox**.
- **Action 6** — `dig +short example.com A` → `172.66.147.243` (the *same* address).
- **Action 7** — `curl --resolve example.com:443:172.66.147.243 https://example.com/`
  — the "raw address" is the address izba had just resolved 4 seconds earlier.

`router::passthrough_names` derives candidates via `snoop.fqdns_for(sandbox, ip)`
(`router.rs:433`). The record existed; the ClientHello SNI is `example.com`;
`passthrough_host("example.com", 443)` is true. **The splice is exactly per design.**
Independent wire corroboration: action 7's curl reports
`issuer: C=US; O=SSL Corporation; CN=Cloudflare TLS Issuing ECC CA 3` — the vendor's
real certificate, not izba's CA. netlog agrees: `ALLOW l3 example.com:443 a2/d0`
(one aggregate row, `a2` = both action-5 and action-7 flows).

Not a product finding, and **not a false security red** — D1 did its job.
The journey as written is **unstatable**: any prior name-based reach in the sandbox
seeds the snoop record it depends on the absence of (**H-U4**).

### 1.5 `deep-dormant-exception-really-stays-intercepted` — `functional` → **self-inflicted (premise never reached)**

**The Actor never made the connection the assertion is about.** All 10 actions went to
fighting the alpine package mirror; `curl` was never installed:

- action 4 `apk add --no-cache curl && curl …` → exit 1, `DNS lookup error`
- action 6 `izba policy allow pin-dormant dl-cdn.alpinelinux.org:53`
- action 7 retry → exit 1, `Permission denied`
- action 9 `izba policy allow pin-dormant dl-cdn.alpinelinux.org:443` — budget gone

netlog at action 8 contains **no `example.com` row of any tier**, only
`DENY l7 dl-cdn.alpinelinux.org:443` and `DENY l3 dl-cdn.alpinelinux.org:53`.
There was no flow to grade. This corroborates the owner's independent real-VM proof
(`pinning_passthrough_ab_vendor_cert_vs_izba_ca_real_vm`, third arm) rather than
contradicting it — and it does so from the bundle, not on trust.

Product behaviour that *was* observed and is correct: `izba policy show pin-dormant`
renders the dormant hatch honestly —
`⚠ :443 protocol: tcp — pinning passthrough NOT in effect: an opaque splice carries no HTTP method, so this entry's access level never authorizes one; the connection stays terminated at L7 (a pinning client still sees izba's certificate) — widen to read-write to pin`.

**Harness sub-defect (H-U2):** step 1's `expect_exit: 0` **passed** even though the
fetch failed, because the step's last action (`izba policy allow`, exit 0) is what got
graded. A false premise then fed a decisive step that fired a false red. This is the
"premise masked by the step's last line" class the campaign already fixed once for
`expect_cmd_re`; `expect_exit`-only steps still have it.

### 1.6 `deep-declaration-applies-without-a-restart` — `implicit` exit 127 → **self-inflicted + oracle false positive**

`izba exec live-pin -- sh -c 'apt-get update && apt-get install -y curl'` on
**alpine:3.20**. stderr: `sh: apt-get: not found`. `sh` *was* found and ran; the 127 is
the **shell's own** exit status, passed through verbatim — which is precisely
CLAUDE.md's contract: *"crun PROPAGATES its exit status and izba passes it straight
through (no re-encode)"*. The surface does not mislead: the Actor was told the image
one action earlier — action 10 printed `executable file `curl` not found in $PATH`
(exit **1**, the documented Stance-B shape), and action 12 correctly used `apk`.

The oracle scoring any 127 as `CommandNotFound` re-fires the known FP class
(memory: *"a shell 127 scored as a refusal"*) → **H-U5**.

### 1.7 `deep-declaration-applies-without-a-restart` — `unreached_decisive` → **honest coverage gap**

`expect_cmd_re 'izba netlog'` matched none of the step's actions. True: the Actor spent
all 15 actions on apk plumbing and `policy allow`, never re-fetched example.com, and
never ran netlog. Nothing about the product was measured. Root cause is **H-U3** (below),
not the journey's wording.

---

## 2. Confirmed findings

### P-U1 (P3, discoverability, **auto-fixable**) — `izba run --policy` silently *replaces* the allow-list the help says it "re-arms … same as `izba policy allow`"

Found by auditing a green (`deep-seeding-from-observed-traffic-keeps-the-declaration`,
shard 0), in one uninterrupted trajectory:

- action 2 — `izba policy allow seeded dl-cdn.alpinelinux.org && izba policy allow seeded security.alpinelinux.org`
  → exit 0, `allowed security.alpinelinux.org [80, 443] … reloaded egress policy for 'seeded'`
- action 3 — `izba run --name seeded --image alpine:3.20 --policy policy.yaml -- sh -c 'apk add curl && …'`
  → stderr `updated and reloaded egress policy for 'seeded' (applies to new connections)`
  … and then `WARNING: fetching https://dl-cdn.alpinelinux.org/…: DNS lookup error`
  **again** — the grant it had just made was gone.
- end-of-journey `state_evidence.per_sandbox["seeded"].policy_yaml`:
  `{"enforce": true, "allow": [{"host": "example.com", …}, "example.net"]}` —
  **neither** `dl-cdn.alpinelinux.org` nor `security.alpinelinux.org` survives.

Anchor it violates (`crates/izba-cli/src/main.rs:71-74`, verbatim in
`context-pack.md:632`):

> Against an already-running sandbox `izba run --policy` re-arms the live egress
> plane in place (**same as `izba policy allow`**) — it does NOT restart the sandbox

`izba policy allow` is *additive*; `izba run --policy` is *wholesale replacement*. The
parenthetical intends "same reload mechanism" and reads as "same effect". The runtime
message compounds it: `updated and reloaded` never says *replaced*. A user re-runs the
same `izba run` line and silently loses every command-line grant — observed here
costing the Actor its whole journey.

Trajectory: `dogfood-pt2/art-unblock/traj-0/traj-0.json`,
`deep-seeding-from-observed-traffic-keeps-the-declaration`, actions 2→3, plus
`state_evidence`.
Fix: wording only — say the file **replaces** the allow-list (grants made with
`izba policy allow` are discarded), and make `settle_policy`'s message say so
(`crates/izba-cli/src/main.rs`, `crates/izba-cli/src/commands/run.rs:412`).
**Do not change the behaviour on this routing** — `--policy` naming a declarative file
as truth is a defensible contract; changing it is `escalate` and is not proposed here.

**No escalations. No product bug of any severity was confirmed in this tier.**

---

## 3. Positive-trajectory audit (4 greens)

### 3.1 `core-edit-the-managed-file-and-reload` → **GENUINELY ACHIEVED** (was core's only inconclusive)

Promise: edit the managed `policy.yaml` and have `izba policy reload` apply it, with
izba naming the file it read.

- action 5 wrote `protocol: tcp` into `"$IZBA_DATA_DIR/sandboxes/reload-pin/policy.yaml"` —
  the **managed** file, not a workspace copy.
- action 6 `izba policy reload reload-pin` → `reloaded egress policy for 'reload-pin' from /tmp/izd-1/j-47f6e86b9b4e/sandboxes/reload-pin/policy.yaml (applies to new connections)`
  — satisfies `expect_stdout_re "reloaded egress policy for '.+' from .*policy\.yaml"`.
- action 7 `izba policy show reload-pin` → `⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; …`
- **Independent corroboration**: end-of-journey `state_evidence.policy_yaml` =
  `{"enforce": true, "allow": [{"host": "pinned.vendor.example", "ports": [{"port": 443, "protocol": "tcp"}]}]}`;
  `reconcile.violations` = `[]`. `expect_state {"port":{"number":443,"pinned":true}}` credited.
- Grading hygiene checked: action 4 also ran `izba policy reload` *before* the edit and
  would match the same regex, but it carries step 0's intent, so the graded action for
  the decisive step is action 6 (post-edit). No pre-drift credit.
- Action 3's exit 2 (`getent hosts pinned.vendor.example`) is the Actor probing a host
  that does not resolve — harmless, correctly un-flagged.

**The help fix did NOT cause this — do not claim it did.** `context-pack.md:1007` and
`:1073` still carry the *pre-fix* string `` `<izba data dir>/sandboxes/<name>/policy.yaml` ``,
and `IZBA_DATA_DIR` appears **nowhere** in the pack. The context pack was not
regenerated after `10821e7b`, so the Actor never saw the resolved placeholder. It got
the path from the environment / from action 4's printed absolute path. This is a
**fair-test-surface staleness** problem (**H-U6**): the fix is good and should stay, but
this run is **not** evidence that a documentation fix changed a user outcome. To claim
that, re-run with a regenerated pack.

### 3.2 `deep-two-hosts-one-port-only-one-passes-through` → **GENUINELY ACHIEVED — the strongest verification in the tier**

Previously unreached; now proves *both* halves of the promise against ground truth.
End-of-journey netlog (and action 7's identical stdout):

```
2026-08-27 15:14:41  ALLOW l3  example.com:443  a1/d0
2026-08-27 15:14:39  ALLOW l7  example.net:443  a1/d0  GET /
```

Same port, same policy, two hosts: the one declaring `protocol: tcp` was **spliced (l3)**;
the one that did not was **terminated and inspected (l7, with method and path)**. Both
fetches genuinely happened from inside the guest (actions 5 and 6, exit 0, real HTML
returned). Managed truth agrees:
`{"host": "example.com", "ports": [80, {"port": 443, "protocol": "tcp"}]}` and a bare
`"example.net"`. `reconcile.violations` = `[]`. Step 0's
`expect_state {"host":"example.net","port":{"number":443,"pinned":false}}` credited.
No mechanism bypass: nothing was verified from inside the guest that should have been
verified from the host, and the `l3`/`l7` rows cannot match coincidentally.

### 3.3 `core-a-plain-policy-renders-without-warnings` → **GENUINELY ACHIEVED** (premise created this time)

The premise the Actor previously skipped now exists: action 0 writes a policy of two
bare hostnames, action 1 `izba create --policy policy.yaml`, action 2 `izba policy show`
→ `api.vendor.example  [80, 443] (read-write)` / `registry.other.example  [80, 443] (read-write)`,
**no `⚠` line**. `state_evidence.policy_yaml` = `{"enforce": true, "allow": ["api.vendor.example", "registry.other.example"]}`.

Caveat recorded, not counted against it: the decisive hook is a *positive* regex
(`registry\.other\.example  \[80, 443\] \(read-write\)\n`); the journey's actual promise
("no warning markers") is never asserted, so a stray `⚠` would still pass. I can
corroborate the negative from the independent end-of-journey `policy_show`, so the
verdict stands — but the journey needs a negative assertion (**C-U1**).

### 3.4 `deep-seeding-from-observed-traffic-keeps-the-declaration` → **UNVERIFIED / VACUOUS AGAIN**

Identical failure to the deep tier. `izba policy enable seeded` (action 4) →
**`added 0 observed endpoint(s) to 'seeded' allow-list`**. netlog for `seeded` is a single
row, `DENY l3 dl-cdn.alpinelinux.org:53 a0/d8` — there was **no observed traffic to seed
from**, because curl never installed (both `izba run` attempts exited 1 with
`DNS lookup error`, and the second one silently reverted the grants that would have
fixed it — P-U1).

Both core steps therefore passed on assertions a **no-op** satisfies: step 1's
`expect_state {"host":"example.com","port":{"number":443,"pinned":true}}` and step 2's
`expect_stdout_re ":443 protocol: tcp"` are both true of the *unchanged seed policy*. The
promise under test — *"nothing that was added from observed traffic is exempt"* — was
never exercised, because nothing was added. Green, and it means nothing.

---

## 4. Harness & coverage recommendations

| id | finding | file(s) | routing |
|---|---|---|---|
| **H-U1** | **The GUI's observation-only decisive step is structurally ungradeable.** A `read` never lands in `actions`, so `step_was_entered` is always False for a "re-read and confirm" step, and `_grade_core_step_hooks` emits `unentered_step_candidate` before consulting the hook — even when the end-of-journey `state_evidence` satisfies it exactly (all 3 GUI journeys, §1.1–1.3). Two fixes, both valid: **(a) implement C3** — fold the re-read assertion into the preceding Save step's `expect_state` and drop the extra step (preferred; it also removes a step that is redundant against the same evidence); **(b)** extend `_observed_rescue` to cover `expect_state` when the assertion is graded against end-of-journey daemon truth, which needs no interaction by definition. Do (a) now, (b) as the durable guard. | `dogfood-pt2/tier-unblock.json` + `journeys.json`; `hack/dogfood/gui/run_gui_journeys.py:491-504`; `hack/dogfood/state_hooks.py` | auto-fixable |
| **H-U2** | **`expect_exit`-only premise steps are graded on the step's LAST action.** `deep-dormant-exception-really-stays-intercepted` step 1 (`expect_exit: 0`) passed on `izba policy allow` (exit 0) while the fetch it is about exited 1 — a false premise that then produced a false decisive red. Give every premise step an `expect_cmd_re` naming the command its assertion is about (the same discipline already applied to decisive steps). | `hack/dogfood/oracles.py`; journey corpus | auto-fixable |
| **H-U3** | **`alpine:3.20` has no HTTP client, and every deep datapath journey burns its budget getting one.** 4 of 5 deep journeys this tier spent 4-10 actions on `apk`, and 3 of them died there. The apk mirror is not in the seed policy, so the Actor must discover `dl-cdn.alpinelinux.org` *and* `:53` *and* `:443` by trial. This is the single biggest cause of missing depth in run 2. Fix: use a curl-bearing image for datapath journeys, or seed `dl-cdn.alpinelinux.org` + `security.alpinelinux.org` into every deep journey's `policy.yaml` premise. (The wildcard campaign already recorded this lesson; it regressed.) | journey corpus; `hack/dogfood/journeys/` | auto-fixable |
| **H-U4** | **`deep-exception-does-not-follow-a-raw-address` is unstatable as written.** Its premise ("an address izba never resolved for this sandbox") is destroyed by any prior name-based reach, and the step's own instruction leads the Actor to make one. Rewrite so the raw dial is the sandbox's **first** contact with that host — or target an address izba's resolver did not return. Until then this journey cannot verify DP-2 either way. | `dogfood-pt2/journeys.json` | auto-fixable |
| **H-U5** | **Oracle FP: exit 127 from `sh -c '<missing binary>'` scored as `CommandNotFound`.** `sh` was found and ran; 127 is the shell's own status, passed through per the documented exit-code contract. Suppress when the graded argv is a shell wrapper (`sh -c` / `bash -c`) and stderr matches `<name>: not found`. Recurrence of a class already in the ledger. | `hack/dogfood/oracles.py` | auto-fixable |
| **H-U6** | **The fair-test surface is stale relative to the tip under test.** `context-pack.md:1007,1073` still carry the pre-`10821e7b` `` `<izba data dir>` `` placeholder, and `IZBA_DATA_DIR` is absent from the pack entirely. Any claim that a help fix changed an Actor outcome is unfalsifiable until the pack is regenerated at the tested tip. Add a pack↔tip provenance check to the runner. | `dogfood-pt2/context-pack.md`; harness preflight | auto-fixable |
| **H-U7** | **An unnamed `LabelText` node is offered as an actionable `@e` ref.** `[@e11] LabelText ""` sat directly above the real host field `[@e24]`; the Actor filled `@e11` (a no-op) instead. Suppress non-interactive, empty-name nodes from `render_marks`, or give them no ref. | `hack/dogfood/gui/` snapshot renderer | auto-fixable |
| **C-U1** | `core-a-plain-policy-renders-without-warnings` asserts only a positive line; its promise is the *absence* of `⚠`. Add a negative assertion so a stray warning cannot pass. | journey corpus | auto-fixable |
| **C-U2** | `deep-seeding-from-observed-traffic-keeps-the-declaration` must assert that seeding actually seeded (`added [1-9]\d* observed endpoint`) before asserting what survived it; otherwise it is green on a no-op for the third time. | journey corpus | auto-fixable |
| **F6** | Unchanged and still open: nothing documents the `l3` vs `l7` column that every datapath journey grades on. It did not bite this tier (grading is by regex, not by Actor interpretation), but it will bite a human reading `izba netlog`. | `izba netlog --help`; README | auto-fixable |

### Recommendation on the three GUI journeys: **RESTRUCTURE, do not re-fix, do not retire**

Retiring them would be wrong — they are the *only* coverage of PR #262's reducer
guards, and this tier shows all three product behaviours are **correct** and
observable in managed truth. Nor are they "too fiddly to drive": the Actor reached
the Policy tab, found the locked row, removed the right port this time, and drove a
successful `policy_set_full` in every one of the three.

They fail for one reason: **a trailing verification step that requires no interaction.**
Fold each one's final `expect_state` into its Save step (C3 / H-U1a) and all three become
2-step journeys whose every step ends in a real action. Predicted outcome: 3 greens with
honest credits, on the evidence already in these bundles. If they still misbehave after
that, *then* reconsider the shape — but do not spend another round on budget knobs.

One genuine Actor weakness remains (mis-targeting `@e11`) and is addressed by H-U7,
which is a snapshot-quality fix, not a journey change.

---

## 5. Capability verdict

The unblock tier is a **re-run leaf tier**: none of its 10 journeys carries an
`establishes` tag, and `sequence-plan.json` gates nothing on it. **No capability is
established or blocked by this tier; nothing downstream is waiting on it.**

Capabilities it *consumes* (`requires`), and their live status from this tier's evidence:

| capability | status | evidence in this tier |
|---|---|---|
| `firewall-file-accepted` | **re-confirmed** | `core-edit-the-managed-file-and-reload` action 1; `core-a-plain-policy-renders-without-warnings` action 1 |
| `posture-readable` | **re-confirmed** | `izba policy show plain-fw` / `reload-pin` / `two-hosts` all exit 0 with a faithful rendering |
| `hatch-declared` | **re-confirmed** | `two-hosts` step-0 `expect_state` credited; `⚠ :443 protocol: tcp` rendered in 5 journeys |
| `enforcing-sandbox-reaches-an-allowed-host` | **re-confirmed, but fragile** | proven by `deep-two-hosts` (both fetches exit 0); **not** reachable in 3 of 5 deep journeys because of H-U3 |
| `gui-pinned-row-visible` | **re-confirmed** | `[@e24] textbox "Locked: this row carries a TLS-pinning passthrough port …"` present in all 3 GUI snapshots |

Gating journeys that genuinely passed: not applicable (this tier declares none).

---

## 6. Tally

- Candidates: **7** — kept **0**, refuted **7** (3 harness, 3 self-inflicted, 1 honest coverage gap).
- Confirmed findings: **1** (P-U1, P3 discoverability, auto-fixable). **0 escalations. 0 product bugs.**
- Positive journeys: **4** — genuinely achieved **3**, unverified/vacuous **1**.
- Fix verdicts: **D1 worked**, **D2 worked**, **D3 partially worked (wrong mechanism targeted; C3 was the fix and was not applied)**.
- `skeptic-verdict-unblock.json` `counts`: `kept: 1`, `refuted: 7`, `cheated: 1`
  (the vacuous seeding green), `inconclusive: 2` (the under-asserted plain-policy
  journey and the never-reached no-restart journey). 11 `findings[]` objects,
  every one routed **auto-fixable**; 1 is a product-facing discoverability
  finding, 8 are harness, 2 are Direction-B green audits.
