# Phase 3 — adversarial triage, DEEP tier

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough (#233 + #238 + #239/PR #262)
Bundles: `dogfood-artifacts/deep/{traj-0..3, gui-traj-0..2}` · collected: `dogfood-passthrough/collected-deep.json`
Headline: 19 journeys · 32 candidates (18 functional, 11 implicit, 2 unreached_decisive, 1 latency) · 8 positives
Result: **1 confirmed product bug (P1, escalate)** · 2 auto-fixable wording findings · 6 harness/coverage findings
· 22 candidates refuted · 10 inconclusive · 2 greens found cheated/unverified.

**Reading `counts` in `skeptic-verdict-deep.json`:** per the schema, `kept`/`refuted`/
`inconclusive` count *oracle candidates*, so `kept: 0` — **zero of the 32 reds survived
triage as a product bug**. The three confirmed product findings below came from elsewhere:
DEEP-1 from auditing a GREEN journey's trajectory, DEEP-2 and DEEP-3 as wording gaps attached
to candidates that were themselves refuted. Route from `findings[]`, not from `counts.kept`.

**The tier's dominant fact: the CLI Actor discarded the seeded fixture in 11 of 11 CLI
journeys.** Every CLI journey ships `seed_files` placing `policy.yaml` / `izba.yml` in the
Actor's cwd, and every intent says "the policy file that is already in your working
directory". In every case the Actor's FIRST action was `cat > policy.yaml <<'EOF'` /
`cat > izba.yml <<'EOF'` with content it invented from the context pack's example
(`pinned.vendor.com`, `api.anthropic.com`), never `ls`/`cat`-ing what was there. The
seeding mechanism itself is fine — the GUI journeys, which hand the Actor the same
workspace, all created sandboxes carrying the seeded hatch (`state_evidence.per_sandbox.
pin-gui*.policy_yaml` = `{"host":"pinned.vendor.com","ports":[80,{"port":443,"protocol":
"tcp"}]}`). The consequence is that most of this tier's reds are "the fixture the oracle
grades was never on disk", and its two CLI greens pass on a fixture the Actor chose.

---

## 1. Confirmed product findings

### DEEP-1 (P1, **ESCALATE**) — the desktop Policy tab renders an *unloaded* policy as "Firewall off / no allowed hosts", with Save live: one click writes an EMPTY allow-list over the managed `policy.yaml`

`PolicyEditor` starts at `useState<Row[]>([])` / `useState(false)` for `enforcing` and fills
them from an **async** `api.policyShow(name)` inside `useEffect`. There is no loading state,
no skeleton and no gate on the Save button:

```tsx
// app/src/components/PolicyEditor.tsx:312-315, 328-346
const [hosts, setHosts] = useState<Row[]>([]);
const [enforcing, setEnforcing] = useState(false);
useEffect(() => { ... const p = await api.policyShow(name); ... }, [name]);
// :578-589 — the footer, unconditionally:
<Button type="button" onClick={() => void save()}>Save</Button>
```

`save()` (`:430-466`) has no "loaded" guard: it maps whatever `hosts` currently is and calls
`api.policySetFull(name, allow, git)`. With `hosts === []` that is a wholesale write of an
empty allow-list to the sandbox's managed `policy.yaml`.

Two independent trajectories caught the window rendered:

- `gui-cannot-activate-a-dormant-exception` (shard 1) action[5] `click @e16`, `page_text`:
  `… Policy | Manifest | Display | Shell | **Firewall off** | ▾ | Hosts | … |
  **No allowed hosts — add one to permit egress.** | Add host | … | Save`
  — for a sandbox whose managed truth at that moment is
  `enforce: true` + `pinned.vendor.com [80, {443, tcp}]` (`state_evidence…policy_yaml`).
  The Actor then clicked that very Save at action[6] (`invoke_log`: `{"cmd":
  "policy_set_full","ok":true}`). The write happened to land AFTER hydration, so nothing was
  lost this run — the same action's page then reads `Firewall on` with the full row.
- `gui-saving-an-unrelated-edit-preserves-the-declaration` (shard 2) action[5]: the identical
  `Firewall off` + `No allowed hosts` frame.

Why this is a product bug and not a rendering nit:

1. It **misreports security posture on one of the only two surfaces that reveal it.** An
   operator opening the Policy tab of an enforcing sandbox is shown "Firewall off". CLAUDE.md's
   own rule for this feature is that "the two revealing surfaces must not disagree about
   posture"; `render_policy` already refuses to misstate posture "in the safe-looking
   direction, on the one surface that reveals it" (`crates/izba-cli/src/commands/policy.rs`).
2. The destructive click is **one control away and gives no feedback that data is missing** —
   the empty state is worded as a normal empty policy ("add one to permit egress"), which is
   exactly what a fresh sandbox looks like.
3. The write path is `policySetFull`, which by design **skips the `izba diff`/`izba promote`
   weakening gate** (PolicyEditor.tsx:144; CLAUDE.md). There is no `⚠ weakens egress`
   backstop and no confirmation; `policy.yaml` is the host-only managed authority and the
   previous contents are simply gone.
4. The same hole is open on the **error** path: the `catch` sets `error` and leaves
   `hosts === []`, so after a failed load the editor sits permanently in the wipe-ready state.
5. No test covers it — `app/src/test/policyEditor.test.tsx` has no loading/disabled assertion.

Anchor: CLAUDE.md "Inspectability is DECLARED per PORT" — "`izba policy show` and the desktop
app's Policy tab are the two surfaces that reveal a hatch … the two revealing surfaces must
not disagree about posture"; and the `izba.yml` trust-boundary contract — "the managed truth
(`config.json` + `policy.yaml` …) is host-only authority".
Trajectory: `gui-traj-1` / `gui-cannot-activate-a-dormant-exception` / action[5]→[6];
`gui-traj-2` / `gui-saving-an-unrelated-edit-preserves-the-declaration` / action[5].
Routing: **ESCALATE** — the fix is behavior (a `loaded` state that gates the render and the
Save control, or a load-failure refusal), not wording, and it sits on a policy-write path.
Related but distinct from the already-known #239/PR #262 class ("every editable control on a
pinned row can author an unflagged weakening"): this one needs no control at all.

### DEEP-2 (P3, UX, auto-fixable) — `izba policy reload` reports success without naming the file it read

`deep-declare-the-exception-on-a-running-sandbox`, shard 0 action[13]: the Actor wrote its
edit into `./policy.yaml` (its shell cwd) and ran `izba policy reload pin22`, which printed
`reloaded egress policy for 'pin22' (applies to new connections)` — exit 0. The managed file
at `<data>/sandboxes/pin22/policy.yaml` was untouched, and action[14] `izba policy show pin22`
still shows `example.com [80, 443]` + `dl-cdn.alpinelinux.org [53, 443]`, no `protocol: tcp`.
Journey-end `policy_yaml` confirms: `{"enforce":true,"allow":["example.com",{"host":
"dl-cdn.alpinelinux.org","ports":[53,443]}]}`.

**Not a doc gap** — the context pack DOES carry the path (`izba policy reload --help`: "That
file is the managed truth, kept host-side at `<izba data dir>/sandboxes/<name>/policy.yaml`;
edit it there and reload"). The finding is that the success line gives an operator who edited
the wrong copy nothing to notice. One string: echo the path that was re-read.
Routing: **auto-fixable** — `crates/izba-cli/src/commands/policy.rs` (the reload echo).

### DEEP-3 (P3, discoverability, auto-fixable) — `netlog --follow`'s help does not say it runs until interrupted

`--follow`'s clap help is "Keep printing new records as they arrive (ignored with
`--summary`)"; the implementation (`crates/izba-cli/src/commands/netlog.rs:44-60`) prints the
backlog and then polls forever, "Ends on Ctrl-C". Nothing in the help says the command does
not terminate. The shard-2 Actor ran `izba netlog pin24 --follow` as its final, decisive
action and hung to the 120 s cap (see §2 — the *candidate* is a journey defect, but the
missing clause is real). Add "(runs until interrupted)".
Routing: **auto-fixable** — `crates/izba-cli/src/main.rs` (the `Netlog { follow }` doc comment).

---

## 2. Rejected candidates (22 of 32)

### Pre-registered hypotheses — verdicts first

**H1 — the client-never-ran confound: CONFIRMED, and it is the correct reading of every
netlog red.** The `ERROR` "crash markers" are **apk's own stderr**, verbatim:
`WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.20/main: DNS lookup error /
ERROR: unable to select packages: curl (no such package): required by: world[curl]`. Not one
izba panic or abort anywhere in the tier. The two `exit 127`s are the guest shell's
(`sh: curl: not found`, `sh: apt-get: not found`), passed through by crun exactly as the
exit-code contract requires — not izba's `CommandNotFound` frame.
**Why apk failed:** the enforcing firewall did its job on the Actor's OWN policy, which did
not allow the mirror. The progression is legible and self-correcting: `DNS lookup error`
(netlog `DENY l3 dl-cdn.alpinelinux.org:53 (DNS: not in allow-list)`) → after
`izba policy allow <n> dl-cdn.alpinelinux.org:53`, `Permission denied` (pin22 action[9] —
DNS now resolves, TCP still denied) → after `:443`, `OK: 13 MiB in 24 packages`. Four shards
each recovered unaided. The context pack documents exactly this ("… or pre-seed them in
`policy.yaml`"). **No usability finding here** — the firewall is behaving as designed and the
guest's own error text plus `izba netlog` names the cause.
Per instruction, every netlog-anchored red that cannot be separated from "the client never
ran" is reported **INCONCLUSIVE** below, never as a product bug.

**H2 — `deep-command-line-grants-skip-the-review-gate`: SELF-INFLICTED, and the product
promise was actually DEMONSTRATED; the oracle graded the wrong action.**
Action[6] `izba promote pin21` → **exit 1**, stderr exactly
``izba: error: no reviewed diff — run `izba diff` first (or --force)``. That IS the asserted
refusal, and it names the remedy. The Actor then ran `izba promote pin21 --force` (action[7],
exit 0) — which the *step intent itself* invites ("You are in a hurry and do not want to spend
time looking at the difference first — just apply … straight away"), which the error text
advertises, and which the context pack documents ("Use `--force`"). It also warned twice:
`WARNING: --force: promoting changes that were never reviewed` /
`WARNING: weakens egress: egress`. **Was the Actor ever in a position to see `--force` was the
wrong tool? No — and it wasn't the wrong tool.** Given that intent, `--force` is the correct
answer; the *journey* is defective (it asks the Actor to be in a hurry and then grades it for
not stopping). Not a discoverability finding.
The oracle failure is a harness defect: `expect_cmd_re` selected the **last** matching action
(`--force`) rather than the first, inverting a step that had already passed (→ DEEP-H1).

**H3 — the `expect_state.policy` cluster: the ORACLE IS CORRECT in every single case. There
is no harness bug here.** Verified against `state_evidence.per_sandbox.<n>.policy_yaml`
(daemon truth) in the raw bundles:

| journey | oracle asserted | managed `policy.yaml` at journey end | oracle right? |
|---|---|---|---|
| pin22 | `pinned.vendor.com` :80/:443 | `["example.com", {dl-cdn:[53,443]}]` | yes — host absent |
| pin23 | `pinned.vendor.com` :443 pinned | `["example.com", {dl-cdn:[80,443]}, {vendor.com:[80], access:read}]` | yes |
| pin24 | `example.org` :443 pinned | `["example.com", {dl-cdn:[80,443]}]` | yes |
| pin25 | `example.org` access read, :443 pinned | `[{pinned.vendor.com:[80,{443,tcp}]}, {dl-cdn…}]` | yes — graded host absent |
| pin28 | `example.com` **absent** | `[{example.com:[80,{443,tcp}]}, {dl-cdn…}]` | yes — present |
| pin21 | `api.example.net` **present** | `[{api.example.**org**}, {example.com}]` | yes — Actor typo'd `.org` |
| pin18/19/20 | (matched) | — | yes |

All are the fixture-never-landed consequence. Triage: **INCONCLUSIVE** (coverage), not product.

**H4 — `deep-review-flags-losing-inspection-on-a-shared-port`: REFUTED. The product is
right; the Actor's substituted manifest could not produce the transition.**
The seeded baseline was `metrics.example.net ports:[{port: 8000, protocol: http}]` +
`reports.example.net ports:[8000]`, and the seeded drift deletes the first entry — which drops
8000 out of `inspect_ports` while `reports.example.net` still reaches it. The Actor instead
wrote (action[0]) `example.com ports:[8000]` + `example.org ports:[8000]` — **both bare** —
and (action[3]) deleted the first. `AllowEntry::protocol_for` →
`Protocol::implied_for_port(8000)` → **`Tcp`** (`crates/izba-core/src/daemon/egress/config.rs:
256-284`: `if AllowEntry::DEFAULT_PORTS.contains(&port) { Http } else { Tcp }`), so neither
entry ever put 8000 into `inspect_ports`. `InspectionTable::from_config` therefore returns
`{80,443}` before and after — **no inspection was lost**, and a removal-only delta with no new
(host,port) and no widened access is a pure tightening. `egress_weakens`
(`crates/izba-core/src/manifest/diff.rs:207-227`) is right to print nothing:

```rust
for p in candidate_ports {
    if from_insp.inspects(p) && !to_insp.inspects(p)
        && to.allow.iter().any(|e| e.ports().contains(&p)) { return true; }
}
```

The arm exists, is correct, and is unit-pinned. Verdict **self-inflicted**; the promise is
**not exercised** (coverage gap → §4).

### The rest

| # | journey / candidate | verdict | refutation |
|---|---|---|---|
| 1-11 | 9 × `implicit` crash marker `ERROR` (pin22 ×2, pin23, pin24, pin25, pin26, pin27, pin28) + 2 × `implicit` exit 127 (pin26, pin27 ×2) | **self-inflicted + oracle FP** | apk's own `ERROR: unable to select packages` / the guest shell's `sh: curl: not found`. **Re-sighting of CORE-4, still unfixed.** |
| 12 | `gui-saving-an-unrelated-edit-preserves-the-declaration` — "`pinned.vendor.com` does not authorize port 8443 (authorized: [80,443])" | **self-inflicted** | The Actor added 8443 to the **wrong row**: action[8] `fill @e33 8443` where `@e33` is the *second* row's "add port" box. Saved truth: `api.example.com [{8000,http}, 8443]`, vendor row untouched. |
| 13 | pin22 — `expect_stdout_re ':443 protocol: tcp … spliced opaquely'` on `izba policy show pin22` | **self-inflicted** | The Actor edited `./policy.yaml`, not the managed copy (see DEEP-2). `policy show` printed the truth. |
| 14-15 | pin19 — diff missing `⚠ weakens egress`; promote missing `WARNING: weakens egress` | **self-inflicted** | H4 above. The transition was never created. |
| 16-17 | pin24 — `izba netlog pin24 --follow` exit 124; and its `ALLOW l3 example.org:443` miss on empty stdout | **self-inflicted (journey defect)** | `--follow` is `tail -f` semantics by design (`netlog.rs:44-60` prints the backlog, then polls, "Ends on Ctrl-C") — a decisive assertion must never be anchored on it. The empty stdout is a harness artifact, not product silence: `izba netlog pin24` two actions earlier printed 4 rows. → DEEP-H4, DEEP-3. |
| 18 | pin28 — `DENY l\d … example.com:(53|443)` miss | **self-inflicted** | The Actor's own policy **allows** `example.com` (`[80,{443,tcp}]`) — the journey's premise was "a site that pin28's policy does not mention at all". There is nothing to deny. curl was also never installed. |
| 19-21 | pin21 — `promote --force` exit 0; `no reviewed diff` stderr miss; `api.example.net` absent | **self-inflicted + harness mis-grading** | H2 above. The refusal fired at action[6]; the graded action was the deliberate `--force` retry. The state miss is the Actor's `.org`/`.net` typo, graded at journey end after a legitimate promote (→ DEEP-H2). |
| 22 | pin24 — `latency` (soft): `izba netlog pin24 --follow` 120 085 ms vs 30 000 ms | **self-inflicted (journey defect)** | Same as 16-17. Not a hang. |

---

## 3. Positive-trajectory audit (8 greens + the 2 unreached)

### Genuinely achieved (5)

| journey | proof (independent of the Actor's narration) |
|---|---|
| `gui-pinned-port-is-visible-in-the-policy-tab` **(gating)** | shard 0 action[5]'s own `page_text` renders `Port 443: TLS-pinning passthrough — spliced opaquely, with no L7 rules, no request audit and **no upstream certificate verification**.` on the vendor row, with `Ports \| 80 \| 443 \| ⚠ tcp` — `:80` unmarked and `api.example.com`'s `8000 \| http` unmarked. Daemon truth agrees: `policy_yaml` = `{pinned.vendor.com:[80,{443,tcp}]}`. Not a final-capture credit: the string is in the action's own capture. |
| `gui-only-the-declared-port-is-marked` | shard 1 action[6] page: one `Port 443:` message, two ports on that row, and a sibling host row whose `8000 \| http` chip carries no marker. Per-PORT attribution proven on the render surface. |
| `gui-dormant-exception-is-not-claimed-as-live` | shard 2 action[5] page: `Port 443: TLS-pinning passthrough **NOT in effect** — an opaque splice carries no HTTP method, so this row's "read" access never authorizes one; the connection stays terminated at L7 and a pinning client still sees izba's certificate.` Daemon truth: `{pinned.vendor.com, access: read, ports:[80,{443,tcp}]}`. Posture correctly rendered as dormant. |
| `gui-removing-the-exempt-port-unlocks-the-row` | **The tier's strongest green.** action[6] snapshot: the Host control is `textbox "Locked: this row carries a TLS-pinning passthrough port — remove the pinned port, or edit policy.yaml, or izba.yml followed by izba diff / izba promote."` → action[7] `click @e26` = `button "Remove port 443"` → the SAME control is now `textbox "api.example.com or *.example.com"` (unlocked) and the footer shows `● unsaved changes` → action[8] `fill @e24 renamed.vendor.example` is **accepted** → action[9] Save → footer `saved · reloaded`. Daemon truth: `policy_yaml` = `[{"host":"renamed.vendor.example","ports":[80]}, {api.example.com…}]`. Lock → unlock → rename, end to end, on the file, not the render. |
| `gui-app-cannot-author-a-new-exception` | The Actor genuinely authored a new row: `Add host` (action[6]) → `fill second.vendor.com` (7) → `Add` port (8-9) → Save (10, `saved · reloaded`) → Overview→Policy re-read (11-12). The re-read renders the new row's ports **with no `⚠ tcp`** beside the seeded row that has one, and daemon truth is `{"host":"second.vendor.com","ports":[80,443]}` — bare numbers, no `protocol` key. The GUI offers no control that can author a hatch, proven against the saved file. |
| `deep-review-is-quiet-when-posture-tightens` | The Actor's substituted manifest happened to be equivalent to the seeded one: baseline `pinned.vendor.com [80, {443,tcp}]` → drift `[{80,http}, 443]`. `izba diff pin20` (action[4]) printed the egress delta with **no** `⚠ weakens egress`; `izba promote pin20` (action[5]) stderr carries only `sandbox not running — changes apply on next start`. `policy_yaml` after: `[{"port":80,"protocol":"http"},443]`, and `policy show` renders `:80 protocol: http (inspected)` and **no** `⚠` line. A tightening that removes a hatch is silent — and the discrimination is real, since a naive "any protocol change is a weakening" implementation would have flagged it. |

### Cheated / unverified (2)

- **`deep-review-flags-a-new-exception-as-weakening` — the marker proves the wrong arm.**
  The journey's own grading note requires that "the seeded baseline and the seeded drift
  differ ONLY by `protocol: tcp` on an already-allowed port … so `egress_weakens`'s
  new-(host,port) and widened-access arms are structurally unreachable". The Actor destroyed
  exactly that: its baseline (action[0]) **already carried** `pinned.vendor.com … port: 443 /
  protocol: tcp`, and its drift (action[3]) **added a whole new host**,
  `vendor.client.com ports:[{port: 8443, protocol: tcp}]`. That trips `egress_weakens`'s
  FIRST arm — `None => return true, // new (host, port) allowed` (diff.rs:176-185) — which is
  pre-#233 behavior and fires regardless of `protocol`. The `⚠ weakens egress` on action[4]
  and the `WARNING: weakens egress: egress` on action[5] are therefore **not evidence for the
  passthrough arm**. Worse, the `expect_state` (`pinned.vendor.com` :443 `pinned: true`) was
  true **from `izba create`** — the journey's rationale explicitly says "Creating the sandbox
  cannot produce the asserted result: the hatch is absent from the file `create` consumed",
  and the Actor put it in that file. Tautological credit.
  *(The `⚠ weakens egress` / `WARNING: weakens egress` surfaces themselves DO work — pin21's
  action[7] and action[11] show both, and pin20 shows their correct absence. It is the
  `http → tcp` arm specifically that is unverified.)*
- **`gui-cannot-activate-a-dormant-exception` — a lock journey that never touched the lock.**
  Step 1's intent is "try to move the vendor row's Access from read-only to read-write". The
  Actor's 9 actions are: create (0-4), open the tab (5), **click Save** (6), Overview (7),
  Policy (8). `radio "read-write"` was present as `@e35` in action[6]'s snapshot and was
  **never clicked**. `setHostAccess`'s refusal (`if (access === "read-write" &&
  pinnedPorts(r).length > 0) return r;`, PolicyEditor.tsx:404-408) was never exercised. The
  green rests on `expect_text: "access never authorizes one"`, which the NOT-in-effect notice
  renders **unconditionally** on any dormant pinned row — an outcome the fixture alone
  produces — plus an `expect_state` that merely re-asserts the unchanged fixture.
  What the run *does* honestly prove is weaker but real: a `policy_set_full` Save round-trip
  on an unmodified editor preserved `access: read` AND `{443, tcp}` in `policy.yaml`.

### Inconclusive → coverage (1 green + 10 reds + 2 unreached)

- **`gui-saving-an-unrelated-edit-preserves-the-declaration`** — the *pinned* row was never
  edited (see rejected #12), so "adding a port to the pinned row does not disturb its
  declaration" is unexercised. The adjacent promise IS proven: an unrelated edit + Save
  round-tripped the hatch intact, and the new 8443 landed as a **bare** number next to a
  declared `{8000, http}` on the same entry — #238 non-inheritance holding on the GUI write
  path.
- **pin22, pin23, pin24, pin25, pin27, pin28** (the `expect_state` + netlog reds) — every one
  is "the graded host was never in the policy and/or the HTTPS client never ran". None
  proves or disproves anything about the datapath. Per H1's rule: inconclusive.
- **`gui-cannot-move-the-exception-to-another-host` (`unreached_decisive` step 2)** —
  **journey defect, not budget and not a product gap.** The lock worked *perfectly*: action[6]
  `fill @e24 moved.vendor.example` targeted the `textbox "Locked: this row carries a
  TLS-pinning passthrough port…"` and after the fill the snapshot shows the SAME locked label
  and the footer shows **no** `● unsaved changes` — the reducer rejected the edit and the
  editor stayed clean. `invoke_log` has **no `policy_set_full`**, and journey-end truth is the
  untouched `{pinned.vendor.com:[80,{443,tcp}]}`. Step 2 ("click Save … the footer reports the
  policy was written") presupposes a dirty editor, which a working lock guarantees will never
  exist. Fix the journey, not the product.
- **`deep-exception-does-not-follow-a-raw-address` (`unreached_decisive` step 3)** —
  **attention/budget exhaustion plus Actor drift.** 17 actions, 12 of them curl variations
  chasing certificate output (`--cert-status`, `--trace-ascii`, four successive `grep -E`
  refinements); step 2 ("reach the same destination by its numeric address") was never
  attempted either, and `izba netlog` was never run. Not a product gap.

### Bonus: the tier's best datapath evidence came from a journey nobody graded

A same-run A/B on the **same host, same port**, differing only by the per-port declaration:

- `deep-exception-does-not-follow-a-raw-address` / pin26, policy
  `{"host":"example.com","ports":[{"port":443,"protocol":"tcp"}]}` — action[15]
  `curl -v --cacert /etc/izba/ca-bundle.pem --cert-status https://example.com`:
  `*  subject: CN=example.com` / `*  issuer: C=US; O=SSL Corporation; CN=Cloudflare TLS
  Issuing ECC CA 3` / `* SSL certificate verify ok.` — **the vendor's real certificate**.
- `deep-two-hosts-one-port-only-one-passes-through` / pin27, `example.com` allowed as a bare
  host (no declaration) — action[11] `curl -v https://example.com`:
  `*  subject: CN=example.com` / `*  issuer: **CN=izba egress CA; O=izba**`, and
  `izba netlog pin27` records `ALLOW l7 example.com:443 GET / (allow-list)`.

That is an end-to-end confirmation that an explicit per-port `protocol: tcp` really does
splice opaquely (no MITM, vendor cert preserved) while the identical host without it is
terminated at L7 and audited — i.e. `deep-pinned-host-keeps-the-vendor-certificate`'s promise
holds, evidenced in a different journey. It was pure luck (the Actor's substitution happened
to pin `example.com`), it is unrepeatable as written, and no oracle scored it. **Turn this
exact A/B into the journey.**

---

## 4. Harness & coverage recommendations

- **DEEP-H0 (P1, harness) — `seed_files` are being silently discarded by the CLI Actor in
  11/11 journeys.** Every CLI Actor's first act was to author its own `policy.yaml`/`izba.yml`
  from the context-pack example, and step-level drift seeds were clobbered the same way (pin19
  action[3], pin21 action[5], pin18 action[3]). The mechanism works — the GUI journeys' created
  sandboxes all carry the seeded hatch — so this is a *prompting* defect, and it is the single
  reason this tier verified so little. Three cheap fixes, in order of strength: (a) have
  `_run_step` name the seeded paths in the step text it hands the Actor ("`policy.yaml` is
  already in your working directory — do not create it"); (b) make the runner detect an Actor
  write to a seeded relpath and re-seed + log it (or refuse the action); (c) name the fixture's
  hosts in the intent so a substitution is at least detectable. Files:
  `hack/dogfood/run_journeys.py` (`_run_step`, `_write_seeds`), `dogfood-passthrough/tier-deep.json`.
- **DEEP-H1 (P1, harness) — a step expecting a refusal is graded on the Actor's later retry.**
  `expect_cmd_re` selects the LAST matching action in the step; pin21's step 2 matched both
  `izba promote pin21` (exit 1, `no reviewed diff` — a PASS) and `izba promote pin21 --force`
  (exit 0), and scored the second. For a step declaring `expect_exit: "nonzero"` (or any
  `expect_stderr_re` describing a refusal), grade the FIRST match, or grade the match whose
  outcome satisfies the declared expectation if any does. Files: `hack/dogfood/run_journeys.py`,
  `hack/dogfood/oracles.py`.
- **DEEP-H2 (P2, harness) — a mid-journey `expect_state` is graded against the END-of-journey
  snapshot.** `_grade_decisive_state_hooks` runs once, after `capture_state_evidence`
  (`run_journeys.py:726-740, 920-935`). pin21's step-1 assertion (`api.example.net` present)
  was satisfied at action[3]/[4] and then legitimately undone by the step-2 promote — the
  journey's own next step. Either snapshot per decisive step, or reject `expect_state` on a
  non-final decisive step whose later steps mutate the same surface (a corpus lint).
- **DEEP-H3 (P2, harness) — CORE-4 is still open and cost 11 of this tier's 32 candidates.**
  The `implicit` oracle greps guest-command stderr for `ERROR` and maps any 127 to izba's
  `CommandNotFound` frame. Scope the crash-marker scan to izba's own stderr (require a
  panic/abort signature), and treat 127 as the izba frame only when stderr lacks a
  `<shell>: … not found` line. File: `hack/dogfood/oracles.py`.
- **DEEP-H4 (P2, harness) — a timed-out action loses its stdout, and may orphan the process.**
  `run_action`'s `TimeoutExpired` path takes `e.stdout` (`oracles.py:235-241`), which came back
  empty for `izba netlog pin24 --follow` even though the CLI prints its backlog before polling;
  and `subprocess.run` kills only the `bash -c` wrapper, so a streaming child can survive.
  Capture incrementally, and kill the process group.
- **Journeys to tighten (from the inconclusive verdicts):**
  - `deep-review-flags-losing-inspection-on-a-shared-port` — the promise is genuinely
    unexercised. It also needs a corpus lint: a "loses inspection" fixture is only valid if
    the removed entry declares `protocol: http` on a NON-web port (a bare non-web port implies
    `Tcp` and contributes nothing to `inspect_ports`).
  - `deep-review-flags-a-new-exception-as-weakening` — add `expect_state` on the BASE
    (assert `pinned: false` before the drift) so a hatch present at `create` cannot satisfy it,
    and lint the drift for "no new (host,port), no widened access".
  - `gui-cannot-activate-a-dormant-exception` — make step 1 decisive and assert the
    `radiogroup "access"` rendered selection is still `read` after a click on `read-write`;
    an unattempted lock must not tally green.
  - `gui-cannot-move-the-exception-to-another-host` — drop the mandatory Save step (a working
    lock leaves nothing to save); assert on the Host control's accessible name and on the
    absence of `● unsaved changes` after the fill.
  - **The five netlog journeys** — replace the unreachable placeholder hosts
    (`pinned.vendor.com`, `example.org` pinned, `www.iana.org`) with hosts that actually
    resolve, and use a curl-bearing image so the client cannot fail to install. Build the
    A/B from §3's bonus: one host declared `protocol: tcp` and one not, both fetched, asserting
    both the netlog tier AND the observed certificate issuer (`CN=izba egress CA` vs the real
    one). That single journey would establish the datapath promise the whole tier missed.
  - `deep-declaration-survives-a-restart` — pin23 never had a hatch; the seeded fixture is
    right, DEEP-H0 is the blocker.
- **Known observability gap re-sighted (P3, coverage, not a new bug):** an **allowed** DNS
  query is never audit-recorded — `dns_loop` calls `audit.record` only on the deny arm
  (`crates/izba-core/src/daemon/egress/router.rs:636-651`). So a host that IS allow-listed but
  does not resolve (pin25's `pinned.vendor.com` → `curl: (6) Could not resolve host`) leaves
  **no netlog line at all**, and `izba netlog` answers the question "what did izba handle?"
  with silence. Same family as the already-established "a no-SNI TLS handshake writes no audit
  line" M5 diagnosability follow-up. Not escalated here; noted because it defeated two
  journeys' oracles.
- **Discoverability flags — status this tier.** **D1 CLOSED**: the CLI line the swarm saw is
  `⚠ :443 protocol: tcp — pinning passthrough: spliced opaquely; no L7 rules, no request
  audit, no upstream certificate verification`, matching the GUI in substance. **D6 partially
  closed**: PR #262's row notice does explain both the Host lock and the refused Access
  widening in the rendered text (`gui-dormant-exception-is-not-claimed-as-live` action[5]);
  what remains unverified is D6's specific claim that the *picker itself* gives no feedback —
  no Actor clicked it. **D2, D4, D5, D7-D9 not exercised** — no Actor consulted docs this tier.
- **Pure cheap-model weakness (suppress, do not fix in the product):** fixture substitution
  (DEEP-H0), the `.net`→`.org` typo (pin21), adding a port to the wrong GUI row (pin-gui6),
  and the four-round `grep -E` refinement loop that burned pin26's budget.

---

## 5. Capability verdict (progressive gate)

Deep tier `establishes`: **`gui-pinned-row-visible`**; `gating`:
**`gui-pinned-port-is-visible-in-the-policy-tab`**.

| capability | verdict | evidence |
|---|---|---|
| `gui-pinned-row-visible` | **ESTABLISHED** | `gui-pinned-port-is-visible-in-the-policy-tab` genuinely achieved — shard 0 action[5] renders the per-port passthrough notice on the vendor row, corroborated by `state_evidence…policy_yaml` = `{pinned.vendor.com:[80,{443,tcp}]}` and `invoke_log` `policy_show ok:true`. The gating journey **genuinely passed.** |
| `hatch-via-manifest` (was **blocked** after core) | **ESTABLISHED (retroactively)** | Two deep journeys authored a hatch through `izba.yml` + `izba diff` + `izba promote` and it landed in managed truth: pin18 `policy_yaml` = `[…,{"host":"vendor.client.com","ports":[{"port":8443,"protocol":"tcp"}]}]` after `promoted pin18`; pin20 promoted the inverse and `policy show` renders `:80 protocol: http (inspected)`. The core-tier block was swarm fumbling (wrong directory), not a product gap. |
| `policy-file-at-create`, `policy-show-renders`, `hatch-declared`, `hatch-visible-in-show`, `manifest-egress-review` | already established (smoke/core) — **re-confirmed** | Every deep journey created a sandbox from a `--policy` file / manifest, and `izba policy show` rendered the declaration correctly in all 11. |

**Gating journeys that genuinely passed: 1 of 1.** No capability is blocked. The deep tier is
the last tier in `sequence-plan.json`, so there is nothing to advance to; the actionable output
is the fix list below.

---

## 6. Fix routing

| id | class | severity | routing | files |
|---|---|---|---|---|
| DEEP-1 | real | P1 | **escalate** | `app/src/components/PolicyEditor.tsx` (load state + Save gate), `app/src/test/policyEditor.test.tsx` |
| DEEP-2 | discoverability (UX) | P3 | auto-fixable | `crates/izba-cli/src/commands/policy.rs` (reload echo) |
| DEEP-3 | discoverability | P3 | auto-fixable | `crates/izba-cli/src/main.rs` (`Netlog { follow }` doc comment) |
| DEEP-H0 | harness | P1 | auto-fixable | `hack/dogfood/run_journeys.py`, `dogfood-passthrough/tier-deep.json` |
| DEEP-H1 | harness | P1 | auto-fixable | `hack/dogfood/run_journeys.py`, `hack/dogfood/oracles.py` |
| DEEP-H2 | harness | P2 | auto-fixable | `hack/dogfood/run_journeys.py` |
| DEEP-H3 | harness | P2 | auto-fixable | `hack/dogfood/oracles.py` |
| DEEP-H4 | harness | P2 | auto-fixable | `hack/dogfood/oracles.py` |
| DEEP-C1 | inconclusive (coverage) | P1 | auto-fixable | `dogfood-passthrough/tier-deep.json` — the 5 netlog journeys + the 2 weakening journeys + the 2 GUI lock journeys |

**Blocker for the human: DEEP-1 only.**
