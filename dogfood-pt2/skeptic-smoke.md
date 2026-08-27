# Phase 3 — adversarial triage, **smoke tier**, dogfooding run 2

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough
(M5 P1 — #233 + #238 + #239/PR #262), re-run on PR #264's tip `481dbe27`.

Inputs: `dogfood-pt2/collected-smoke.json`, raw bundles under
`dogfood-pt2/art-smoke/{traj-0,traj-1,gui-traj-0}/`, `sequence-plan.json`,
`tier-smoke.json`, `coverage-map.md`, `discoverability-flags.md`,
`context-pack.md`. Judged against the worktree tip, not `main`.

**Tally: 5 candidates → 0 kept, 5 refuted. 2 positives audited → 2
genuinely-achieved, 0 cheated, 0 inconclusive. 0 product findings.
5 harness findings (all auto-fixable). All 4 gating journeys pass — the tier
advances.**

---

## 1. Confirmed product findings

**None.** No candidate in this tier survived refutation, and neither green
collapsed under audit. Everything the tier exercised behaved as the anchors
promise, and in three places the trajectories are *positive* evidence for
promises the journeys did not even claim to test (§3.3).

---

## 2. Rejected candidates (5 of 5)

### R1–R3 — the three `implicit` "crash marker 'ERROR' in stderr" candidates → **self-inflicted** (and an oracle false-positive)

- `smoke-firewall-file-accepted-at-create` action 7
- `smoke-find-the-surface-that-answers-bypass` action 5
- `smoke-enforcing-sandbox-can-reach-an-allowed-site` action 3

All three are the same line, produced by **`apk` inside the guest**, not by izba:

```
ERROR: unable to select packages:
  curl (no such package):
    required by: world[curl]
```

preceded by `WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.20/main: DNS lookup error`.

Three independent reasons to drop:

1. **The oracle's expectation is not the observed fact.** The candidate's
   `violated_expectation` is *"izba must not panic/abort on a user command"*
   (`source: contract: clean exit, no panics`). izba did not panic: it relayed
   the exit status and the stderr of the guest command the swarm asked it to
   run, which is the documented exec contract ("crun PROPAGATES its exit status
   and izba passes it straight through"). The marker belongs to `apk`.
2. **The product behaved exactly as designed, and its own oracle says so.** The
   independent reconcile snapshot for `fw-basic` records
   `netlog: "2026-08-27 13:38:37  DENY  l3  dl-cdn.alpinelinux.org:53  a0/d4"` —
   the enforcing firewall denied a mirror that was not on the allow-list. A
   default-deny jail denying a non-allow-listed host is the feature working.
3. **The swarm was told, in its own context pack, not to do this.**
   `context-pack.md` §"Working under enforce: allow-list what your tooling
   needs":

   > Default-deny means a fresh enforcing sandbox can reach *nothing* —
   > including your package mirror — so installs and fetches fail until you
   > grant the hosts. Add them first … or pre-seed them in `policy.yaml`.

   and again at the "Your tooling comes from the image" paragraph:

   > Under an **enforcing** egress policy the sandbox reaches nothing by
   > default, so allow-list your package mirror first … or the install itself
   > fails.

   So this is **not** a discoverability finding: the fact is present, verbatim,
   twice, in the exact surface the swarm was allowed to read. Confirmatory: the
   Actor **recovered unaided in all three journeys** — it read the failure, ran
   `izba policy allow <name> dl-cdn.alpinelinux.org`, and the next `apk add`
   succeeded (`OK: 13 MiB in 24 packages`). A gap a user closes from the error
   message in one step is not a gap.

Routed instead as harness finding **H1**: the implicit oracle must not scrape a
guest program's relayed stderr for izba crash markers.

### R4 — `smoke-find-the-surface-that-answers-bypass`, functional flip on `izba policy allow` → **self-inflicted / mis-anchored grade**

The candidate:

> `expect_stdout_re 'pinning passthrough'` did not match the stdout of
> `'izba policy allow audit-me pinned.vendor.example'`
> — `graded_cmd: izba policy allow audit-me pinned.vendor.example`

The step declares `expect_cmd_re: "izba policy show"`. `izba policy allow` does
not match that regex. What happened is `_eligible_targets`
(`hack/dogfood/run_journeys.py:410`) — *"Neither yielding anything falls back to
the step's final action"* — so with **no `policy show` inside step 1**, the
harness graded the step's last line, which the assertion was never about.

The product surface itself is fine, and this same trajectory proves it. Action 3:

```
$ izba policy show audit-me
'audit-me' egress policy (enforce: on):
  http allow-list:
    pinned.vendor.example  [80, 443] (read-write)
        ⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules, no request audit, no upstream certificate verification
```

which is exactly what C7 in the coverage map promises ("`policy show` … is the
surface that answers 'is anything bypassing my firewall?'") and exactly what the
`expect_stdout_re` was looking for. The end-of-journey state evidence carries the
same line. So: the audit surface answered; the Actor simply spent step 1 doing
something else (installing curl, then misreading an NXDOMAIN for
`pinned.vendor.example` — a `.example` host that cannot resolve — as a policy
denial, and re-granting an already-granted host).

Not a product bug. Routed as harness findings **H2** (the fallback should flip
`unreached_decisive`, never a functional candidate on an unrelated command) and
**C1** (the journey cannot distinguish discovery from recall — see §4).

### R5 — `smoke-manifest-can-carry-the-firewall`, `izba diff` "state: in sync" → **harness false-positive (the assertion already passed)**

The candidate is graded on **action 5**. The step's assertion passed on
**action 3**:

```
$ izba diff mani-egress
state: repo ahead (promotable)
  egress:  [live]
    from:
      enforce: false
    to:
      enforce: true
      allow:
      - api.vendor.example
```

That matches `expect_stdout_re "(?s)state: repo ahead.*egress"` exactly. The
Actor then went **past** the assertion — `izba promote mani-egress` → `promoted
mani-egress`, then a second `izba diff` (action 5) which correctly reported
`state: in sync`, because the change had just been applied. `expect_cmd_re
"izba diff"` matched actions 3 and 5, and `_grade_step_functional` grades the
**last** match ("last-match is right for the common shape 'the Actor got it
wrong, then got it right'"). Here the shape is the opposite: right, then moved
on.

Corroborated end-state: `policy_yaml` for `mani-egress` is
`{"enforce": true, "allow": ["api.vendor.example"]}` and `policy show` prints
`enforce: on` with `api.vendor.example [80, 443]`. The manifest→diff→promote
round trip worked end to end. Refuted; routed as harness finding **H3**.

*(The premise in the tasking — "almost certainly the Actor never edited
`izba.yml`" — is disproven: it wrote `izba.yml` at action 2 and again at action
7. The red is purely a grading-window artifact.)*

---

## 3. Positive-trajectory audit (Direction B)

### 3.1 `smoke-declare-a-pinning-exception` (gating, CLI, 3 actions) → **genuinely-achieved**

The headline promise, and it is honest on every axis I can check.

- The hatch was authored through the feature under test — `izba.yml`'s
  `spec.egress` with the **per-port** shape (`- 80` bare, then
  `- port: 443 / protocol: tcp`), consumed by `izba create --name pin-basic .`
  (exit 0). No `--policy`, no other route.
- It reached the assertion **through the declared command**: `decisive_credits`
  records `{"step_index": 1, "action_index": 2, "graded_cmd": "izba policy show pin-basic"}`
  — a real action, not a fallback — and that action printed
  `⚠ :443 protocol: tcp — pinning passthrough: … no upstream certificate verification`.
- **Independent corroboration from izba's own managed truth**, not narration:
  the end-of-journey `policy_yaml` capture (parsed from the host-only
  `policy.yaml`, which is what `expect_state.policy` grades against —
  `gui_oracles.py:717` "the sandbox's MANAGED `policy.yaml` … never from
  `izba policy show`'s rendered text") reads
  `{"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}]}`.
  The per-port scoping is real on disk: 80 bare, 443 declared. The hook is
  non-vacuous — `gui_oracles.py:678` asserts `(ports[number] == "tcp") == want_pinned`.
- `reconcile.violations: []`.

Cheating checks that came back clean: the exemption is not host-wide (80 stayed
bare); the reveal was not read out of the file the Actor wrote (it came from
`policy show` over managed truth in a different directory); the `expect` string
did not match coincidentally (the phrase only occurs on a `tcp` port's row).

### 3.2 `smoke-gui-policy-tab-reports-a-real-posture` (gating, GUI, 6 actions) → **genuinely-achieved**, with an auditability caveat

This is the one I tried hardest to break, because PR #264's whole class is "a
component renders its unloaded state as fact". The trajectory *looks* like that
bug reappearing and is not.

What the bundle shows. The Actor created `gui-pin1` from the seeded workspace
(action 4, `invoke_log` `{"cmd":"create","ok":true}`), then clicked into the
Policy tab (action 5). The post-action page text is:

```
… Overview Ports Volumes USB Logs Netlog Policy Manifest Display Shell
Firewall posture unknown

Loading this sandbox's policy… its allowed hosts, git rules and enforcement posture are not known yet.

Save
```

That is **PR #264's guard rendering correctly** — `PolicyEditor.tsx:545`
("Firewall posture unknown", shown instead of the `EnforceToggle` while
`load.kind !== "ready"`) and `PolicyEditor.tsx:663` ("Loading this sandbox's
policy…", deliberately *not* "No allowed hosts"). The `Save` button is present
by design (`aria-disabled`, "deliberately NOT the native `disabled` attribute:
the click must still reach `save()`, which is where the refusal actually
lives"). So the last thing the Actor personally observed was the honest
unloaded state, 7 ms after the click.

Why the green is nevertheless real, not a false credit:

1. `decisive_credits` carries `expect_text: 'no upstream certificate
   verification' (matched)`. `expect_text_oracle` **only ever reads captured
   page text** (`gui_oracles.py:303`, `page_texts: List[str]`); it cannot see
   the daemon state evidence. The phrase appears in no per-action capture, so
   the match can only have come from the one capture the window contains and
   the bundle does not persist — `page_text_history.append(final_page_text)` at
   `run_gui_journeys.py:864`, taken after the settle and the state-evidence
   pass. Had the tab *still* been loading then, that hook would have flipped a
   functional candidate instead. It matched ⇒ the tab finished loading and
   rendered the row.
2. The app has that exact sentence as **visible** text, not just an
   `aria-label`: `PolicyEditor.tsx:115` builds `Port 443: TLS-pinning
   passthrough — spliced opaquely, with no L7 rules, no request audit and no
   upstream certificate verification`, and `passthroughNotice`
   (`PolicyEditor.tsx:152`) is documented as *"Visible (not just aria-label)
   text for the notice rendered on a pinned row"*. A page-text match is the
   right kind of evidence for F1's "VISIBLE marker carrying the CLI's
   substance".
3. `invoke_log` shows `policy_show` invoked twice, `ok: true` both times — the
   posture was actually read, not invented.
4. `expect_state` matched against managed truth: `policy_yaml` for `gui-pin1` is
   `{"enforce": true, "allow": [{"host":"pinned.vendor.example","ports":[80,{"port":443,"protocol":"tcp"}]}, {"host":"api.vendor.example","ports":[{"port":8000,"protocol":"http"}]}]}` —
   i.e. the GUI create honoured the workspace's `izba.yml` `spec.egress`
   verbatim, per-port declarations intact.
5. `ui_daemon_diff` produced no candidate — the UI never claimed a state the
   daemon disagreed with. `reconcile.violations: []`.

Caveat, routed as harness finding **H4**: the capture that justifies the
credit is **not in the bundle**. I could only close this by reading the runner
source to prove the oracle's input set. A skeptic should not need the harness
source to audit a credit — persist the final capture.

Second caveat, routed as coverage rec **C2**: the *Actor* never saw the loaded
row. Its budget ended one poll short. The journey proves the product renders it;
it does not prove a *user* gets there without waiting through a blank tab, and
the 8 downstream GUI journeys that build on `gui-pinned-row-visible` will each
open on that same loading state.

### 3.3 Non-flagged journeys audited anyway (they carried refuted reds, so nobody else would)

- **`smoke-firewall-file-accepted-at-create` (gating) → genuinely-achieved.**
  Step 0 credited via `expect_state` against managed truth
  (`{"enforce": true, "allow": ["api.vendor.example", …]}`); step 1's
  `izba policy show fw-basic` (action 9) matched
  `api\.vendor\.example\s+\[80, 443\]` on a real, `expect_cmd_re`-selected
  command; `reconcile` shows `status_daemon: running` / `status_disk: running`
  with a live pid+starttime. Both core steps honest.
- **`smoke-enforcing-sandbox-can-reach-an-allowed-site` (gating) → genuinely-achieved,
  and this is the strongest evidence in the tier.** The guest completed a *real*
  TLS request to a *real* public host from inside an enforcing sandbox — action
  5 shows `HTTP/2 200`, `server: cloudflare`, `cf-ray: …-ORD`, 559 bytes
  transferred — and izba's own audit log independently recorded it (action 6,
  and again in the end-of-journey state evidence):
  `2026-08-27 13:39:17  ALLOW l7  example.com:443  a1/d0  GET /`.
  No cheating vectors apply: this was not curled inside the guest against
  itself, the `ALLOW l7` row is izba's host-side verdict, and the same log
  discriminates it from the `DENY l3 dl-cdn.alpinelinux.org:53` row six seconds
  earlier. The datapath floor is real.
- **`smoke-manifest-can-carry-the-firewall` → the promise held** (see R5); its
  red is a grading window, and the promoted result is corroborated on disk.

Three side-observations from these trajectories, each *supporting* a contract,
recorded so the core tier need not re-derive them:

- **`izba policy allow` on a host carrying a hatch did not disturb it.** In
  `smoke-find-the-surface-that-answers-bypass` the Actor ran
  `izba policy allow audit-me pinned.vendor.example` (action 8) against an entry
  that already had `[80, {443, tcp}]`. Final `policy_yaml` is unchanged —
  `{"host":"pinned.vendor.example","ports":[80,{"port":443,"protocol":"tcp"}]}` —
  and `policy show` still renders the ⚠ row. That matches
  `EgressPolicyConfig::allow` (`config.rs:931`), which returns `false` for an
  already-granted port. Incidental confirmation of the
  `core-declaration-survives-an-unrelated-grant` promise.
- I checked and **dropped** a candidate finding of my own here: that the
  `policy allow` echo (`allowed pinned.vendor.example [80, 443] access:
  read-write`) is silent about `:443` being a passthrough, and reports "allowed"
  for a no-op grant. Anchored refutation — the contract names exactly two
  revealing surfaces ("`izba policy show` and the desktop app's Policy tab are
  the two surfaces that reveal a hatch"), and `policy allow --help` promises
  only that "Every invocation echoes the effective **access** level granted".
  Not a promise broken. **Intended.**
- **A create-time hatch bypasses the review gate by design** — `izba create
  --name pin-basic .` wrote the hatch into managed truth with no
  `diff`/`promote`. Per the daemon contract, `create` "is the only legitimate
  direct writer (a first write, not a read-modify-write)". **Intended**, not a
  hole.

---

## 4. Harness & coverage recommendations

| id | what | where | routing |
| - | - | - | - |
| **H1** | The implicit crash-marker oracle scrapes the **guest program's** relayed stderr. Any `apk`/`apt`/`make` that prints `ERROR:` through `izba exec` fabricates an "izba must not panic/abort" candidate. 3 of this tier's 5 candidates; the dominant noise class in run 1 too. Scope the scan to izba's own output (or exclude the stream of an `izba exec … -- <guest cmd>` action). | `hack/dogfood/oracles.py` (`implicit_oracle`, `_IMPLICIT_RE`) | auto-fixable |
| **H2** | `_eligible_targets` falls back to the step's **last action** when `expect_cmd_re` matched nothing in the step, then grades `expect_stdout_re` against a command the assertion was never about (`'pinning passthrough'` vs `izba policy allow`). A step whose declared command never ran is an **`unreached_decisive`**, not a functional flip. | `hack/dogfood/run_journeys.py:410` | auto-fixable |
| **H3** | Last-match grading **inverts a step that already passed**: `izba diff` matched at action 3, the Actor promoted, and action 5's honest `state: in sync` was graded as the failure. The `DEEP-H1` refusal exception covers the nonzero-exit shape; the same "already satisfied by an earlier eligible target" rescue is missing for stream assertions. | `hack/dogfood/run_journeys.py` (`_grade_step_functional`) | auto-fixable |
| **H4** | The GUI bundle does not persist the **final post-settle capture**, yet that capture is the sole evidence behind an `expect_text` credit (and behind `dom_expect` / `silent_failure`). A credit whose evidence is absent from the bundle is unauditable — I had to read the runner to accept this tier's GUI green. Record `final_page_text` + final marks on the result. | `hack/dogfood/gui/run_gui_journeys.py:864` | auto-fixable |
| **C1** | `smoke-find-the-surface-that-answers-bypass` cannot distinguish **discovery from recall**: the Actor ran `izba policy show` in step 0 (to verify its own create), so step 1's "you have inherited this machine, find izba's answer" was posed to an Actor that had already seen the answer. Either pose the audit question against a sandbox the Actor did not just create, or make step 0's expect not invite a `policy show`. | `dogfood-pt2/tier-smoke.json` | auto-fixable |
| **C2** | `smoke-gui-policy-tab-reports-a-real-posture` ends **one poll short**: the Actor's last observation is the loading state, and only the harness's post-settle capture sees the loaded row. Add a `read`/settle step after opening the tab so the *Actor* observes what the assertion claims. Relevant to the 8 GUI journeys downstream of `gui-pinned-row-visible`. | `dogfood-pt2/tier-smoke.json` | auto-fixable |
| — | **Predicted flags not exercised.** F1–F6 in `discoverability-flags.md` all target core/deep journeys; none was reachable in smoke. **F6** (nothing documents the `l7`/`l3` tier column) is now the highest-value one to watch: every deep datapath journey grades on that column, and this tier's `netlog` output (`ALLOW l7 …` vs `DENY l3 …`) is already the exact vocabulary the docs never define. | — | — |
| — | **Noise to suppress next run:** the `apk`-under-enforce class (R1–R3). It is documented twice in the context pack and the Actor self-recovers every time; with H1 fixed it stops reaching triage at all. | — | — |

Caps/infra: no `infra` candidates, no `unreached_decisive`, no
`reconcile_violation`, no `guest_console` markers. The tier ran clean — 6/6
journeys produced actions, every sandbox reconciled without violations. No
budget exhaustion observed.

---

## 5. Capability verdict (the progressive gate)

### Gating journeys — all four genuinely passed

| gating journey | verdict | proof |
| - | - | - |
| `smoke-firewall-file-accepted-at-create` | **genuinely-achieved** | step 0 `expect_state` credit vs managed `policy.yaml`; step 1 `izba policy show fw-basic` (action 9) matched on the `expect_cmd_re`-selected command; sandbox running, no violations |
| `smoke-declare-a-pinning-exception` | **genuinely-achieved** | `decisive_credits` action_index 2 on the real `izba policy show pin-basic`; managed truth carries `{"port": 443, "protocol": "tcp"}` per-port |
| `smoke-enforcing-sandbox-can-reach-an-allowed-site` | **genuinely-achieved** | guest got `HTTP/2 200` from real `example.com` under enforce; izba's own log: `ALLOW l7  example.com:443  a1/d0  GET /` |
| `smoke-gui-policy-tab-reports-a-real-posture` | **genuinely-achieved** (with H4/C2 caveats) | `expect_text` matched over page text only — provably the loaded tab; `policy_show` invoked ok ×2; `expect_state` vs managed `policy.yaml`; `ui_daemon_diff` empty |

### Capabilities

**Established (9):**

- `firewall-file-accepted` — `smoke-firewall-file-accepted-at-create`
- `posture-readable` — same, step 1
- `hatch-declared` — `smoke-declare-a-pinning-exception` *(gates 24 core/deep journeys — established with high confidence: on-disk per-port declaration, credited on the declared command)*
- `hatch-revealed` — same, step 1
- `enforcing-sandbox-reaches-an-allowed-host` — `smoke-enforcing-sandbox-can-reach-an-allowed-site` *(gates all 7 deep datapath journeys — established with high confidence: a real 200 over real TLS plus izba's independent `ALLOW l7` row)*
- `manifest-egress-authoring` — `smoke-manifest-can-carry-the-firewall` action 3, despite the refuted red; corroborated by the promoted on-disk policy
- `audit-surface-discoverable` — `smoke-find-the-surface-that-answers-bypass` action 3; established, **weakly** (see C1: the Actor found the surface unprompted, but in the previous step, so the journey cannot separate discovery from recall). It is `required_by: []`, so this weakness defers nothing.
- `gui-policy-tab-loads` — `smoke-gui-policy-tab-reports-a-real-posture`; the loading-guard copy is directly on record in the bundle
- `gui-pinned-row-visible` — same *(gates 7 GUI journeys)*

**Blocked: none.** **Not-exercised: none** — every capability the smoke tier
`establishes` was reached.

**Orchestrator signal: ADVANCE to the core tier.** No fix-and-retry is required
before advancing; the five harness fixes (H1–H4, C1–C2) improve signal quality
and should be applied in place but do not gate.

---

## 6. Fix routing

Every item is **auto-fixable** and lives in the dogfood harness or the journey
corpus — none changes product behaviour, a datapath, policy semantics, a trust
boundary or a public contract. **Zero escalations.**

- H1 → `hack/dogfood/oracles.py`
- H2, H3 → `hack/dogfood/run_journeys.py`
- H4 → `hack/dogfood/gui/run_gui_journeys.py`
- C1, C2 → `dogfood-pt2/tier-smoke.json` (and the journey compiler's templates)
