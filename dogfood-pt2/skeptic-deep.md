# Phase 3 — adversarial triage, **deep tier**, dogfooding run 2

Feature: per-port `protocol:` inspectability / TLS-pinning passthrough
(M5 P1 — #233 + #238 + #239/PR #262), on the worktree tip `e3e7d78e`
(branch `dogfood-fixes/passthrough-docs`) — **not** `main`.

Inputs: `dogfood-pt2/collected-deep.json`, raw bundles under
`dogfood-pt2/art-deep/{traj-0..3, gui-traj-0..2}/`, `journeys.json`,
`sequence-plan.json`, `coverage-map.md`, `discoverability-flags.md`,
`context-pack.md`, and `skeptic-smoke.md` (whose settled classes I do not
re-litigate). Privileged anchors: CLAUDE.md "Inspectability is DECLARED per
PORT", `docs/superpowers/plans/2026-08-18-m5-p1-inspectability.md` (DP-2…DP-8),
`crates/izba-core/src/daemon/egress/{router,mitm_runtime,inspect}.rs`,
`crates/izba-core/src/vmm/cloud_hypervisor.rs`, `crates/izba-core/src/sandbox.rs`.

**Tally: 27 candidates → 0 kept, 27 refuted. 8 positives audited → 7
genuinely-achieved, 0 cheated, 1 inconclusive. 0 confirmed product findings.
9 harness/coverage findings (all auto-fixable). 0 escalations.**

The headline result is in §3: the swarm **independently reproduced the
A/B that the local real-VM test proves** — a declared `protocol: tcp` port
delivered the *vendor's* Cloudflare certificate to the guest and audited as
`ALLOW l3`, while the same host without the declaration delivered
`CN=izba egress CA` and audited as `ALLOW l7… GET /`. The datapath is real,
observed end-to-end, from two different shards.

---

## 1. Confirmed product findings

**None.** No candidate in this tier survived refutation and no green collapsed
under audit. Every red traces to one of four non-product causes, in descending
volume:

1. **shard 3's runner could not boot a microVM at all** (11 candidates),
2. **the Actor's own shell** (`&&` splitting host-side, `--rm` then reload,
   an IPv6 literal in an IPv4-only guest, a duplicate `create`) (8),
3. **the harness honestly reporting an ungraded/unreached assertion** (7),
4. **a journey whose expectation contradicts its own anchor** (1).

§4 routes all nine consequent fixes. Two things I *considered* promoting to
findings and deliberately did not are recorded in §3.5, with the reason.

---

## 2. Rejected candidates (27 of 27)

### 2.1 The five 120 000 ms `izba run` timeouts + the exit-124 flip → **infra (environment), not a product hang** (6 candidates)

The tasking asks whether `izba run --detach` can genuinely block ~2 minutes.
**It cannot, and it did not.** Evidence, in the order that closes it:

**(a) The 120 s is exactly izba's configured boot budget, not an unbounded
hang.** `.github/workflows/dogfood.yml:293` sets `IZBA_BOOT_TIMEOUT_SECS: '120'`
and the same job passes `--action-timeout-s 120`. `sandbox.rs:46
boot_timeout_from_env` reads that env var; `wait_for_boot` (`sandbox.rs:1174`)
polls the guest control port until it elapses and then bails with
`sandbox '<name>' did not become healthy within 120s`. The harness's SIGKILL
lands at the same instant. So izba was inside its documented, bounded boot wait
the whole time — `--detach` waits for the guest to become *healthy* before
returning (which is what "leaving it RUNNING" means), and on the three healthy
shards that same call returned in **2 092 ms** (`deep-declaration-applies…`
action 10) and **2 775 ms** (`deep-declaration-survives-a-restart` action 1).

**(b) It is a property of one runner, not of the product or of load.** The
matrix job `dogfood (KVM shard N)` is `runs-on: ubuntu-latest` — **each shard is
its own hosted runner**, so cross-journey/cross-shard contention cannot explain
it. Shards 0/1/2 booted VMs **eight** times between them at 0.5–3.8 s each.
Shard 3 attempted **five** boots — the very first one, before any other journey
had run — and got zero. `izba create` on shard 3 was normal (930 ms, 964 ms),
as were every daemon RPC (`policy enable` 102 ms, `policy show` 3 ms,
`rm --force` 24 ms). Only `start` failed, and it failed from the first attempt.

**(c) The guest never emitted a byte, and CH *did* launch.** Every timed-out
action's stderr is:

```
starting 'two-hosts'...

[harness] console.log tail (two-hosts):

[harness] action timed out after 120.0s
```

The tail is **empty but present**. `oracles.py:_console_tails` only emits the
`console.log tail (<name>):` header for a path its `glob` found and `open()`
succeeded on, and izba creates only the log *directory*
(`cloud_hypervisor.rs:174 create_dir_all(log_dir)`) — the file itself is created
by cloud-hypervisor's `--serial file=…`. So **cloud-hypervisor started and
opened the serial file, and the guest printed nothing at all** — no
`[    0.000000] Linux version …`, which the healthy shard's evidence has in
full (`restart-pin`'s `console_tail`: `TCP bind hash table entries: 32768 …`).
That is a below-the-kernel failure (KVM unusable / image unloadable on that
host), not an izba control-flow one.

**(d) The `--policy <(…)` process-substitution hypothesis is directly
refuted.** Action 9 used
`izba run --policy <(cat <<'EOF' … protocol: tcp … EOF) two-hosts -- …`. The
end-of-journey managed truth for `two-hosts` is
`{"enforce": true, "allow": [{"host": "example.com", "ports": [{"port": 443, "protocol": "tcp"}]}]}`
— i.e. izba **read the whole policy off the non-seekable `/dev/fd` pipe and
wrote it into `policy.yaml`** before the hang. Three of the five hangs used no
`--policy` at all (`izba run --detach --name seeded .`,
`izba run --name seeded --detach`, `izba run two-hosts -- sh -c …`). The pipe is
exonerated.

**(e) Independent ground truth agrees.** `pinning_passthrough_ab_vendor_cert_vs_izba_ca_real_vm`
passes locally at this tip, and three other shards booted the same binary
against the same artifacts minutes apart.

The one interesting side-effect: after the killed run, `izba rm --force
two-hosts` answered `sandbox 'two-hosts' is busy (another operation in
progress)` and succeeded on the retry — the daemon thread was still holding the
`try_lock` across the boot the CLI had been killed out of. That is the
documented behaviour (CLAUDE.md: "the loser fails with `sandbox '<name>' is
busy` … a loud refusal the caller can retry, never a false success"), so it is
**intended**, not a leak.

→ Routed as harness findings **H1** (the run destroyed the only evidence that
would have named the cause) and coverage **C1** (re-run the tier).

### 2.2 `deep-dormant-exception-really-stays-intercepted`, `izba create … exited 1` → **self-inflicted (duplicate name)**

The tasking asks whether izba refuses to *create* a sandbox carrying a dormant
hatch. It does not. The actual stderr:

```
$ izba create --name pin-dormant --image alpine:3.20 --policy policy.yaml .
resolving alpine:3.20 (pulls if not cached)...
izba: error: sandbox 'pin-dormant' already exists
```

The Actor had already created `pin-dormant` at action 1 (`izba create --name
pin-dormant .`, exit 0). It then ran `izba rm --force pin-dormant` (action 9,
exit 0) and re-ran the **byte-identical** command at action 10 → **exit 0,
`pin-dormant`**, with the same `policy.yaml` carrying
`access: read` + `- port: 443 / protocol: tcp`. The resulting managed truth is
`{"host": "example.com", "ports": [80, {"port": 443, "protocol": "tcp"}], "access": "read"}`.

So a dormant hatch is accepted at create, exactly as the contract requires
("a pinned port on a NARROWER-than-read-write row [renders] as NOT in effect
rather than live"), and `izba policy show` said so at action 2 in the wording
D2 shipped:

```
⚠ :443 protocol: tcp — pinning passthrough NOT in effect: an opaque splice
carries no HTTP method, so this entry's access level never authorizes one …
— widen to read-write to pin
```

### 2.3 Same journey, the decisive `ALLOW l7 example.com:443` miss → **self-inflicted (the fetch ran on the HOST)**

```
$ izba run pin-dormant -- apk add curl && curl -v https://example.com/
```

The `&&` is consumed by the **harness's host shell**, not the guest: `apk add
curl` ran in the sandbox, `curl -v https://example.com/` ran on the CI runner.
The proof is in the same action's own stderr — the certificate chain it printed
is `issuer: C=US; O=SSL Corporation; CN=Cloudflare TLS Issuing ECC CA 3` with
`CAfile: /etc/ssl/certs/ca-certificates.crt`, whereas every genuinely in-guest
fetch in this tier prints `CAfile: /etc/izba/ca-bundle.pem`. Consistently,
`izba netlog pin-dormant --summary` contains **no `example.com` row at all** —
only the `dl-cdn` apk rows — because no such connection ever entered the
sandbox. Nothing about the dormant-hatch promise was exercised.

→ The promise itself is unverified (coverage **C2**), and the Actor's shell
shape is routed as **H2**.

### 2.4 `deep-declaration-applies-without-a-restart`, `policy reload` + `netlog` exit 1 → **self-inflicted (`--rm` deleted the sandbox)**

```
$ izba run --name live-pin … --rm -- sh -c 'apk add --no-cache curl && curl …'
$ izba policy reload live-pin
izba: error: no such sandbox 'live-pin'
$ izba rm --force live-pin
izba: error: no sandbox named 'live-pin' and no ./live-pin/izba.yml …
```

The Actor chose `--rm` (documented: "`--rm` reaps on exit"), so the sandbox was
gone before the reload. `izba netlog live-pin --summary` failed for the same
reason (`no such sandbox: live-pin`) — which is why its stdout was empty, and
why the paired `ALLOW l3` regex candidate is the same single cause counted
twice. No reload defect: the journey never got a live sandbox to reload against.
It later started a *fresh* sandbox at action 10 with the pinned policy already
in place, which tests startup, not live reload.

→ The no-restart promise is unverified (coverage **C2**).

### 2.5 `deep-exception-does-not-follow-a-raw-address` → **self-inflicted AND the journey's expectation contradicts its own anchor**

This is the subtle one, and it cuts two ways. **There is no leak.**

*What happened:* the Actor read an address on the **host** (`getent hosts
example.com` → `2606:4700:10::6814:179a`, an **IPv6**) and pinned it inside an
**IPv4-only guest** (`net.rs` brings up `lo` + `dummy0` `192.168.127.2/24`; no
IPv6 route). curl's own output:

```
* Added example.com:443:2606:4700:10::6814:179a to DNS cache
*   Trying [2606:4700:10::6814:179a]:443...
* Immediate connect fail for 2606:4700:10::6814:179a: Network unreachable
curl: (7) Failed to connect to example.com port 443 after 0 ms
```

The connection **never left the guest**, so izbad never saw it. Accordingly
`izba netlog raw-addr --summary` has *no* `example.com` row of any tier; the
`ALLOW l7` line the oracle quoted is
`dl-cdn.alpinelinux.org:443 … GET /alpine/v3.20/main/x86_64/curl-8.14.1-r2.apk`
— the apk fetch, an unrelated host. Nothing about the hatch is implicated.

*The second, more valuable half:* the journey asserts
`expect_stdout_re "DENY\s+l[37]\s.*:443"`, and **no anchor promises a DENY
here.** The plan's DP-2 says only that the hatch is bound by DNS-snoop:

> the candidate set is derived from what izbad's OWN resolver answered for this
> address … *"no snoop record ⇒ no passthrough, so a raw-IP dial can never
> splice"* (`inspectability.md`, `passthrough_candidates_require_a_snoop_binding`)

`router.rs:254` gates tier-1 on `policy.enforces() && policy.inspects(port)`, and
443 is always inspected — so a raw-IP dial to an **allow-listed host** is
terminated at L7, the SNI/Host is checked against the allow-list, and the
correct observable outcome is `ALLOW l7 example.com:443 GET /` (izba's own
certificate), i.e. *the flow was inspected, not spliced*. Had the Actor picked
the IPv4 literal, this journey would have flipped a **false security red on
correct behaviour**. Also note the journey's title over-claims: the hatch is not
refused because the destination is "a raw address", it is refused because that
address has **no izbad-resolver binding** — a `--resolve` to an IP izbad had
itself previously answered for that name would legitimately splice, by design.

→ Routed as **H3** (rewrite the assertion to `ALLOW l7 … example\.com:443`,
force an IPv4 literal, and rename the journey to name the snoop binding). This
is the single most valuable harness fix in the tier: it removes a false-positive
that would have read as a security finding.

### 2.6 The four `expect_state declared on non-decisive step(s) [0] … were NOT checked` infra candidates → **harness-verified fact; journey-authoring defect**

Affects `deep-pinned-host-reaches-its-own-tls-untouched`,
`deep-the-same-host-without-the-declaration-is-inspected`,
`deep-dormant-exception-really-stays-intercepted`,
`deep-two-hosts-one-port-only-one-passes-through`. In all four, step 0 carries
`expect_state {policy: {port: {number: 443, pinned: …}}}` but is **not** marked
`core: true`, and `_decisive_step_indices` grades only core steps. The
instrument is being honest about an assertion it never graded — exactly the
class the core tier hit. Not a product bug.

For the record, I checked all four against the end-of-journey managed truth and
**every one of the ungraded assertions actually held**:

| journey | ungraded assertion | managed `policy.yaml` at journey end |
| - | - | - |
| pinned-host | `example.com:443` pinned | `[80, {"port": 443, "protocol": "tcp"}]` ✓ |
| same-host-without | `example.com:443` **not** pinned | `{"host": "example.com", "access": "read"}` (bare ⇒ [80,443], undeclared) ✓ |
| dormant | `example.com` access `read`, 443 pinned | `{… "ports": [80, {"port":443,"protocol":"tcp"}], "access": "read"}` ✓ |
| two-hosts | `example.net:443` **not** pinned | (policy replaced by the last `run`; unverifiable) |

→ **H4**: mark those steps `core: true` (or move the assertion onto the
decisive step) in `dogfood-pt2/tier-deep.json` and in the compiler template.

### 2.7 `deep-two-hosts-one-port-only-one-passes-through`, unreached decisive → **inconclusive, caused by 2.1**

`expect_cmd_re "izba netlog"` matched none of step 2's actions because step 2
never got a running sandbox: all three of its `izba run`s were the shard-3
boot failures. The cross-host non-extension promise ("an explicit `tcp` entry
does not remove its own port from the inspected set") is **not verified by this
run**. → coverage **C1**.

### 2.8 The four `deep-seeding…` soft reds → **self-inflicted (wrong file for `--policy`), plus 2.1**

```
$ izba run --name seeded --policy izba.yml -- …
izba: error: invalid egress policy izba.yml: unknown key 'apiVersion' in egress
policy (valid keys: enforce, allow, git); see the egress-policy section in README.md

$ izba run --name seeded --policy izba.yml -- …          # after rewriting it as a bare policy
izba: error: /tmp/izd-3/j-ea53ddb58822/proj/izba.yml (izba reads a workspace izba.yml
automatically): parsing izba.yml: unknown field `enforce`, expected one of
`apiVersion`, `kind`, `metadata`, `spec`
```

The Actor pointed `--policy` (which takes an *egress-policy* document) at a full
*Sandbox manifest*, then over-corrected and wrote an egress document into the
one filename izba reads automatically as a manifest. **Both refusals are
correct, and both messages are unusually good** — the first names the valid keys
and the doc section, the second names the file *and* explains why izba is
reading it (`(izba reads a workspace izba.yml automatically)`). This is the
collision working as designed; I credit the wording rather than flag it.

### 2.9 GUI: `gui-switching-sandboxes-never-shows-the-previous-posture` (2 candidates) → **self-inflicted (only one of the two sandboxes was ever created)**

Step 0 asks for **two** creates (`gui-armed` from `{workspace}`, `gui-unarmed`
from `{workspace}/bare`). The Actor performed one: the final page shows
`SANDBOXES · 1`, and `state_evidence.sandboxes == ["gui-armed"]`. So
`expect_text 'open.other.example'` could not match and the `expect_state`
against `gui-unarmed` was structurally unverifiable — hence the honest `infra`
candidate. Nothing about PR #264's cross-sandbox guard was exercised.

Note the grading weakness this exposes: step 0's `expect_state` names only
`gui-armed`, so **a step that did half its work was still credited**.
→ **H5**.

### 2.10 GUI: `gui-removing-the-exempt-port-unlocks-the-row` (3 candidates) → **Actor fumble + turn-budget starvation**

The journey ended after 8 actions with `● unsaved changes` on screen and the
managed `policy.yaml` byte-unchanged
(`{"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}]}`).
So neither `saved · reloaded` nor `renamed.vendor.example` could exist. Two
compounding causes, neither a product defect:

- **The Actor removed the wrong port.** Action 7 is `click @e25`. In the
  sibling shard's identical form, `@e25` is `button "Remove port 80"` and
  `@e26` is `"Remove port 443"`; the post-click page text confirms it — the row
  went from `80 / 443 ⚠ tcp` to `443 ⚠ tcp`. It deleted the *unpinned* port,
  so the row stayed locked and the rename could never land.
- **It then ran out of turns.** `--max-turns 18` counts `read` observations as
  turns (`run_gui_journeys.py:750`, `turns += 1` before every
  `model.next_command`, and a `read` reply `continue`s), and `e3e7d78e`'s new
  settle instruction ("give the view a moment to finish loading, looking again
  if it is not ready yet") makes the Actor spend turns reading. 8 actions + ~10
  reads = 18. The journey's step 1 needs ≥5 interactions and got 3.

**The GUI settle fix in `e3e7d78e` is therefore only half-effective, and I say
so plainly:** it removed the stale-snapshot failure (the sibling GUI journeys
now do reach the loaded form and save successfully) but it converted part of
that budget into read-turns, and this journey starved. → **H6**.

The unlock-and-rename escape valve is consequently **unverified this run**;
its inverse (the lock *holding*) is proven twice over in §3.

### 2.11 GUI: the two `gui-traj-0` unreached-decisive candidates → **budget artefact; the product behaved correctly**

Both journeys did their substantive work and were credited on the save
(`expect_text 'saved · reloaded'` + `expect_state`), then ran out of actions
before the "re-read the saved settings" verification step. That step's assertion
is nevertheless **satisfied by the independent end-of-journey managed truth**:

- `gui-pin5` (cannot-move): `{"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}]}`,
  `moved.vendor.example` **absent**, and the *other* row correctly gained 8080 →
  the rename was refused, the hatch did not relocate, and the Save was live.
- `gui-pin8` (never-inherits): `{"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}, 9000]}`
  → 443 keeps its declaration, the newly added 9000 is a **bare** number. The
  non-inheritance rule holds through the GUI mutator.

→ coverage **C3** (add the re-read as an assertion on the same step, not a new
one).

### 2.12 The remaining soft reds (apk-under-enforce ×2) → **settled class, dropped**

`deep-exception-does-not-follow-a-raw-address` action 4 and
`deep-declaration-applies-without-a-restart` action 1 are the
`apk`-under-enforce class `skeptic-smoke.md` §R1–R3 settled: the mirror grant is
documented twice in the context pack, and the Actor self-recovered in both cases
via `izba policy allow <name> dl-cdn.alpinelinux.org`. Not re-litigated.

---

## 3. Positive-trajectory audit (Direction B)

8 positives → **7 genuinely-achieved, 0 cheated, 1 inconclusive.** I also audit
four non-positive journeys (§3.3–3.4) because they carry the tier's most
important results and their reds are refuted.

### 3.1 `gui-cannot-activate-a-dormant-exception` → **genuinely-achieved** — the strongest green in the tier

This is #262's central security guard, and the tasking is right that a green
here is worthless unless the widening was actually **attempted and refused**. It
was. Chain of evidence, all independent of the Actor's narration:

1. **The attempt is on record.** Action 6 is `click @e41`. The ref map captured
   at that action lists `[@e40] radio "read"`, `[@e41] radio "read-write"` for
   **host 1** — the pinned row (the same snapshot carries
   `[@e24] textbox "Locked: this row carries a TLS-pinning passthrough port …"`,
   `[@e25] button "Remove port 80"`, `[@e26] button "Remove port 443"`). So the
   click was the read → read-write transition on the row carrying the hatch,
   which is precisely `setHostAccess`'s refusal case.
2. **The refusal is visible in the post-click capture.** The page text after
   action 6 still reads *"this row's "read" access never authorizes one"* — the
   NOT-in-effect wording. Had the radio taken, the row would have flipped to the
   in-effect wording (which the sibling `gui-pin5`/`gui-pin7` captures show
   verbatim for a read-write pinned row). The row did not move.
3. **The form was live, not dead.** The same journey added port 8080 to the
   *other* row and saved: `invoke_log` records
   `{"cmd": "policy_set_full", "ok": true}` and the final page text ends
   `saved · reloaded`. A refusal that is really "the whole editor was inert"
   is excluded.
4. **Daemon-side ground truth after the save-and-reload round trip:**

```json
{"enforce": true, "allow": [
  {"host": "pinned.vendor.example", "ports": [80, {"port": 443, "protocol": "tcp"}], "access": "read"},
  {"host": "api.vendor.example",    "ports": [443, 8080]}]}
```

   `access` is still `read`; the `{port: 443, protocol: tcp}` declaration
   survived the write; the unrelated edit landed. `izba policy show` renders the
   same. `ui_daemon_diff` produced no candidate; `reconcile.violations: []`.

Anchor: CLAUDE.md — "`setHostAccess` refuses a transition INTO `read-write` on a
pinned row (widening cannot silently turn a dormant passthrough live)". Verified
through the UI, end to end.

### 3.2 The five review-gate / promote / restart positives → **genuinely-achieved**

| journey | what proves it |
| - | - |
| `deep-review-flags-a-new-exception-as-weakening` | `izba diff flag-new` printed `egress:  [live]  ⚠ weakens egress` for exactly the `- 443` → `- port: 443 / protocol: tcp` transition, with the from/to blocks rendered. Non-vacuous: the diff adds no host, opens no port, widens no access, leaves `enforce: true`. |
| `deep-review-flags-losing-inspection-on-a-shared-port` | the same marker for the *second* transition — the manifest **only removes** `svc-a.internal.example` (which carried `port: 8443 / protocol: http`), leaving `svc-b` still reaching 8443, which therefore loses global inspection. Exactly CLAUDE.md's "losing inspection on a still-reachable port". |
| `deep-review-is-quiet-when-the-posture-tightens` | **not vacuous.** The diff is non-empty (`state: repo ahead (promotable)`, from `protocol: tcp` → bare `443`) and the `egress:  [live]` line carries **no** marker. The manifest genuinely changed and the tool genuinely stayed quiet. |
| `deep-promote-the-exception-through-the-review-gate` | full round trip in order: `izba diff` → `state: in sync`; edit; `izba diff` → `⚠ weakens egress`; `izba promote gated-pin` → `promoted gated-pin` on stdout **and `WARNING: weakens egress: egress` on stderr**. Managed truth afterwards: `{"host": "pinned.vendor.example", "ports": [{"port": 443, "protocol": "tcp"}]}`. |
| `deep-promote-refuses-without-a-review` | the refusal fired for the **right** reason — `izba: error: no reviewed diff — run 'izba diff' first (or --force)`, exit 1, with `izba diff` never having been run for that edit. Corroborated by managed truth still holding the *unpinned* `{"host": "pinned.vendor.example", "ports": [443]}`: the promote applied nothing. |
| `deep-declaration-survives-a-restart` | a **genuine** stop/start: `izba stop restart-pin` (exit 0) then `izba start restart-pin` (exit 0), and the post-journey reconcile shows a live VMM `{"pid": 3350, "starttime": 26157}` with `status_daemon/status_disk: running`. `izba policy show` after the restart still renders the `⚠ :443 protocol: tcp` row, and managed `policy.yaml` still holds `{"port": 443, "protocol": "tcp"}`. Not a never-restarted read-back. |

Caveat on the last one, recorded not as a defect but as depth: the journey
re-reads the *declaration* after restart, never the *datapath*. The `ALLOW l3
example.com:443` row in its state evidence is timestamped 14:28:33, i.e. from
the pre-restart `izba exec`. → coverage **C4**.

### 3.3 `deep-pinned-host-reaches-its-own-tls-untouched` + `deep-the-same-host-without-the-declaration-is-inspected` → **genuinely-achieved** (the tier's headline)

Not in the positives list (each carries the refuted §2.6 infra candidate), but
together they are the whole feature, observed from two independent shards under
identical conditions:

| | `pin-live` (shard 0) — `- port: 443 / protocol: tcp` | `pin-none` (shard 1) — bare `- example.com` |
| - | - | - |
| certificate the guest saw | `issuer: C=US; O=SSL Corporation; CN=Cloudflare TLS Issuing ECC CA 3` | `issuer: CN=izba egress CA; O=izba` |
| izba's own audit row | `ALLOW l3  example.com:443  a1/d0` (no method) | `ALLOW l7  example.com:443  a1/d0  GET /` |
| managed truth | `[80, {"port": 443, "protocol": "tcp"}]` | `{"host": "example.com", "access": "read"}` (undeclared) |

Both fetches ran **inside** the guest (`izba exec … -- curl -v https://example.com/`,
`CAfile: /etc/izba/ca-bundle.pem`), both returned the real Example Domain body,
and the verdict rows are izba's host-side records, not the guest's narration.
The A/B discriminates the two mechanisms on the one axis that cannot be faked:
whose certificate reached the client. This is the swarm independently
reproducing `pinning_passthrough_ab_vendor_cert_vs_izba_ca_real_vm`.

One residual auditability gap, routed as **H7**: the journeys grade on
`izba netlog --summary`, whose `l3` column alone does **not** distinguish a
passthrough splice from an ordinary tier-2 allow. The discriminator exists — a
splice audits with the rule string `passthrough (protocol: tcp)`
(`mitm_runtime.rs:367`), which the *non*-summary `izba netlog <name>` renders in
parentheses — and no journey asked for it. Here the certificate issuer closes
the gap; a future run should not have to rely on that.

Incidental confirmations from the same two trajectories (recorded so nobody
re-derives them): `izba policy allow pin-live dl-cdn.alpinelinux.org` appended
`{"host": "dl-cdn.alpinelinux.org", "ports": [80, 443]}` — a **bare** pair,
inheriting nothing from the sibling entry's hatch, which is the CLI half of the
non-inheritance rule; and `izba policy allow pin-none example.com:443 --read`
correctly collapsed into the existing bare entry and echoed `[80, 443] access:
read`.

### 3.4 `deep-seeding-from-observed-traffic-keeps-the-declaration` → **inconclusive (coverage finding)**

The tasking's suspicion is correct: this "positive" verifies almost nothing. Its
exits are `[0,124,0,1,0,1,0,1,124,0,0,0]` — both `izba run`s were shard-3 boot
failures, so **no traffic was ever observed**. Consequently:

```
$ izba policy enable seeded
added 0 observed endpoint(s) to 'seeded' allow-list
reloaded egress policy for 'seeded' (applies to new connections)
```

The mutator under test ran against an empty observation set — a no-op. It is
true that the declaration survived it (`policy show` still renders the pinned
443, managed truth still holds `{"port": 443, "protocol": "tcp"}`), but
"observed-traffic seeding cannot inherit a sibling port's hatch" was never
exercised, because nothing was seeded. Its two `core` steps passed on assertions
(`izba policy enable` exit 0; `policy show` matching `:443 protocol: tcp`) that a
no-op satisfies. → coverage **C1** (re-run) and **C5** (tighten the assertion to
require `added N≥1 observed endpoint(s)`).

### 3.5 Two findings I built and then dropped

- **"`izba run --detach` blocks for two minutes."** Dropped — §2.1(a). The wait
  is the configured, bounded boot budget and is ~2 s on every healthy runner.
  The one wording nit (`run --help`: "-d, --detach: … start the sandbox and
  **return immediately**", which in fact returns after the guest reports
  healthy) is too marginal to bill as a finding: the same sentence continues
  "leaving it RUNNING", which is only true *because* it waited.
- **"The boot-failure diagnostic points at an empty file."** izba's bail text
  (`sandbox.rs:1195`) says `check <console.log> for boot output`, and when the
  failure is *below* the guest that file is empty while the VMM's own stderr sits
  unmentioned in the sibling `logs/vmm.log` (`cloud_hypervisor.rs:247-249`).
  I stopped short of calling this a confirmed finding because **the swarm never
  saw that message** — the harness's SIGKILL landed at the same instant izba
  would have printed it (§2.1a), so promoting it would mean asserting output I
  did not observe. It is recorded as a *recommendation* under H1 instead: fix
  the harness first, so the next run can observe the message and judge it on
  evidence.

---

## 4. Harness & coverage recommendations

| id | what | where | routing |
| - | - | - | - |
| **H1** | **The run destroyed the only evidence that could name a boot failure, twice.** (a) `--action-timeout-s 120` equals `IZBA_BOOT_TIMEOUT_SECS: '120'`, so the harness SIGKILLs `izba` at the exact instant it would have printed `did not become healthy within 120s; check …` — the diagnostic is structurally unobservable. Make the action timeout strictly greater (e.g. boot budget + 30 s). (b) `_console_tails` tails only `logs/console.log`; when the VMM fails below the guest that file is empty and the cause is in the sibling `logs/vmm.log` (cloud-hypervisor's own stderr). Tail both. (c) Add a one-shot boot preflight to the job so a runner that cannot boot a microVM fails loudly instead of emitting five silent 120 s timeouts that read like a product hang. *Related product-side recommendation (unobserved, see §3.5): name `logs/vmm.log` in `wait_for_boot`'s bail text.* | `.github/workflows/dogfood.yml:293,411`; `hack/dogfood/oracles.py` (`_console_tails`) | auto-fixable |
| **H2** | The Actor writes `izba run <name> -- apk add curl && curl …`; the `&&` is consumed by the **host** shell, so the decisive fetch runs on the runner and izbad never sees it — twice in this tier, and it produced a decisive red on a promise that was never probed. Add the rule to the Actor's operating notes ("everything after `--` must be a single `sh -c '…'`"), and/or flag an action whose command contains an unquoted `&&`/`;` after an `izba run|exec … --` as a *self-inflicted* candidate rather than a functional one. | `hack/dogfood/run_journeys.py` (model prompt / oracles) | auto-fixable |
| **H3** | **`deep-exception-does-not-follow-a-raw-address` asserts an outcome no anchor promises.** `expect_stdout_re "DENY\s+l[37]\s.*:443"` — but a raw-IP dial to an *allow-listed* host on an inspected port is **terminated at L7 and allowed by name** (`router.rs:254`; plan DP-2 promises only "no snoop record ⇒ no passthrough", i.e. *not spliced*). As written the journey manufactures a false security red from correct behaviour. Change the assertion to `ALLOW l7\s.*example\.com:443`, force an IPv4 literal (`getent ahostsv4`, since the guest is IPv4-only), and rename it to name the real rule (the hatch follows the **snoop binding**, not the literal). | `dogfood-pt2/tier-deep.json` + compiler template | auto-fixable |
| **H4** | Four deep journeys declare `expect_state` on step 0 while marking only step 2 `core: true`, so the create-time declaration assertion is never graded (the harness says so honestly). Mark those steps `core: true` or move the assertion. All four assertions in fact held (§2.6). | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **H5** | A step that asks for **two** sandboxes is credited on `expect_state` naming only the **first**: `gui-switching-sandboxes…` created `gui-armed`, never `gui-unarmed`, and step 0 still passed. Either split the creates into two steps or assert both names. | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **H6** | **The `e3e7d78e` GUI settle fix is only half-effective.** `--max-turns 18` counts `read` observations as turns, and the new "look again if it is not ready yet" instruction spends them: `gui-removing-the-exempt-port-unlocks-the-row` ended mid-step-1 after 8 actions + ~10 reads, with `● unsaved changes` on screen. Either exclude `read` replies from `max_turns` (cap them separately), or raise `--max-turns` for GUI journeys whose steps need ≥5 interactions. The sibling journeys that *did* finish needed 10–11 actions. | `hack/dogfood/gui/run_gui_journeys.py:750`; `.github/workflows/dogfood.yml:551` | auto-fixable |
| **H7** | Every datapath journey grades the splice on `izba netlog --summary`, whose `l3` tier alone **cannot** distinguish a pinning passthrough from an ordinary tier-2 allow. The discriminator is the rule string `passthrough (protocol: tcp)` (`mitm_runtime.rs:367`), rendered only by the non-summary `izba netlog <name>`. Assert on that line. (This is the harness-side half of predicted flag **F6**.) | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **C1** | **Re-run the deep datapath journeys.** Shard 3's runner booted zero microVMs, costing `deep-two-hosts-one-port-only-one-passes-through` (cross-host non-extension — the one InspectionTable property no other journey covers) and `deep-seeding-from-observed-traffic-keeps-the-declaration` entirely. Neither is a product signal; both are unverified. | re-dispatch | auto-fixable |
| **C2** | Three deep promises were never exercised for Actor-side reasons and should be re-run with tightened steps: the **dormant hatch really stays intercepted** (§2.3, host-shell `&&`), the **live reload without restart** (§2.4, `--rm`), and the **GUI unlock-after-removing-the-pinned-port** escape valve (§2.10). For the first two, seed the mirror grant in the journey's `policy.yaml` so the Actor never has to detour through `apk` recovery. | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **C3** | `gui-cannot-move-…` / `gui-adding-a-port-…` both spend their last budget on a separate "re-read the saved settings" step that never runs. Fold that assertion into the save step's `expect_state` (both were satisfiable from the end-of-journey managed truth). | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **C4** | `deep-declaration-survives-a-restart` re-reads the declaration but not the datapath after the restart. Add a post-restart `izba exec … curl` + `izba netlog` so "survives a restart" means the splice still happens, not just that the file still says so. | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **C5** | `deep-seeding-…` step 1 passes on `added 0 observed endpoint(s)`. Require `added [1-9]` so a no-op cannot satisfy the seeding promise. | `dogfood-pt2/tier-deep.json` | auto-fixable |
| **D1** | `dogfood-app-guide.md`'s Policy section still says nothing about conditionally-inert controls (predicted flag **F1**). Observed exactly as predicted: `gui-cannot-move-…` action 7 is `fill @e24 moved.vendor.example` into the field whose accessible name literally begins `Locked: this row carries a TLS-pinning passthrough port …`. The Actor typed, nothing changed, it moved on and saved correctly — so this is fixture friction, not a product dead end (the app self-explains in visible text). Still worth closing so a future GUI red here is attributable to the product. | `dogfood-app-guide.md` | auto-fixable |
| — | **Predicted flag F6 — not confirmed here.** Nothing documents `netlog`'s `l7`/`l3` column (verified absent: `izba netlog --help` in `context-pack.md:843-853` says only "Show the egress audit log" / "Aggregate into a per-endpoint summary"), but **no deep Actor was observably blocked by it** — the tier grades the column mechanically, so it structurally cannot confirm the flag. Do not bill it from this tier's evidence. | — | — |
| — | **Noise to suppress next run:** the `apk`-under-enforce class (settled in `skeptic-smoke.md` R1–R3, 2 more sightings here); and the five latency candidates, which with H1(c) in place would never have been produced. | — | — |

Caps/infra actually hit: 5 `infra` (4 × ungraded non-decisive hook, 1 × missing
second sandbox), 4 `unreached_decisive` (3 GUI budget, 1 boot failure), 5
`latency` (all the same boot failure), 0 `reconcile_violation`, 0
`guest_console` markers. `reconcile.violations` was empty in **every** action of
every journey.

---

## 5. Capability verdict (the progressive gate)

Deep is the terminal tier: `sequence-plan.json` gives it `"gating": []`, it
`establishes` exactly one capability, and that capability's `required_by` is
empty. Nothing downstream is gated on this verdict.

**Established (1):**

- **`hatch-via-manifest`** — established by
  `deep-promote-the-exception-through-the-review-gate`, **genuinely-achieved**
  (§3.2): the hatch was authored only in `izba.yml`, reviewed through
  `izba diff` (which flagged `⚠ weakens egress`), applied through
  `izba promote gated-pin` (which warned again on stderr), and the result is on
  disk in host-only managed truth as
  `{"host": "pinned.vendor.example", "ports": [{"port": 443, "protocol": "tcp"}]}`.

**Blocked: none. Not-exercised: none** of the capabilities this tier
`establishes`.

Capabilities this tier *consumed* (`hatch-declared`,
`enforcing-sandbox-reaches-an-allowed-host`, `manifest-egress-authoring`,
`gui-pinned-row-visible`, `gui-policy-tab-loads`) were all established in smoke
and all held up here — `enforcing-sandbox-reaches-an-allowed-host` in
particular was re-demonstrated on three separate shards.

**Orchestrator signal: the tier is COMPLETE, with a partial re-run
recommended.** No product fix gates anything. The recommended re-dispatch is
narrow: the two journeys lost to shard 3 (C1) plus the three whose promise the
Actor never reached (C2), after H1–H3 and H6 land.

---

## 6. Fix routing

Every item is **auto-fixable** — harness code, workflow inputs, the journey
corpus, or a fixture doc. **Zero escalations. Zero product-behaviour changes.**

- H1 → `.github/workflows/dogfood.yml`, `hack/dogfood/oracles.py`
  *(plus an optional, currently-unobserved wording change in
  `crates/izba-core/src/sandbox.rs` `wait_for_boot` — hold until a run can
  observe the message)*
- H2 → `hack/dogfood/run_journeys.py` (Actor notes / oracle classification)
- H3, H4, H5, H7, C1–C5 → `dogfood-pt2/tier-deep.json` (+ the journey-compiler
  templates that generated these shapes)
- H6 → `hack/dogfood/gui/run_gui_journeys.py`, `.github/workflows/dogfood.yml`
- D1 → `dogfood-app-guide.md`
