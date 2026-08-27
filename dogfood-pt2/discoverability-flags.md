# Predicted discoverability findings — run 2 (tip `481dbe27`)

Method (Mandate 5): for every promise I could state only because I read the spec,
the plans, the PRs or the source, I asked — **could a user holding only
`dogfood-pt2/context-pack.md` (README + recursive `--help`) plus, for the desktop
half, `dogfood-app-guide.md`, discover this and invoke it correctly?** Where the
answer is no, it is recorded here as a predicted UX finding to prime the skeptic.

This tip already absorbed run 1's doc fixes, so this file is deliberately
**short**. Section 0 records what is now genuinely well documented — a run that
reports the same gap twice after it was fixed is a worse instrument than one that
reports nothing.

---

## 0. Closed since run 1 — do NOT re-report these

| Run-1 flag | Closed by | Where it now lives in the context pack |
| - | - | - |
| **D1** — the passthrough warning omitted the certificate-verification loss and advertised a nonexistent one | `4656462b` | README `pinned.vendor.com` example; `izba policy show` help; the live `policy show` line |
| **D2** — "a pin needs read-write access" documented nowhere | `415b6131` | README example comment; `--policy` help ("an opaque splice carries no HTTP method, so a narrower access leaves the hatch dormant") |
| **D3** — `create/run --help` still taught the pre-#238 per-HOST shape | `b7580a3f` | `--policy` help now says **per-PORT** and names the entry-level form as legacy |
| **D5** — the only *reviewed* authoring path was undocumented | `b7580a3f` | README izba.yml section ("`spec.egress` takes the same schema as `policy.yaml` … the only authoring route with the `⚠ weakens egress` gate"); `policy reload` help |
| **D7** — nothing said WHICH surface answers "is anything bypassing my firewall?" | `b7580a3f` | README "Auditing for exemptions: `izba policy show`" + the explicit "`izba status` renders no egress posture at all, so 'nothing unusual in `izba status`' is *not* evidence" |
| **D10 (partly)** — nothing said a command-line grant is unreviewed | `b7580a3f` | README izba.yml section: "`izba policy allow` and a hand-edited `policy.yaml` both apply immediately, unreviewed" — see **F5** below for the half that is still open |

Journeys `smoke-declare-a-pinning-exception`,
`core-audit-surface-under-a-narrower-access`,
`core-an-older-policy-file-keeps-its-meaning`,
`smoke-find-the-surface-that-answers-bypass` and
`core-command-line-grants-skip-the-review-gate` each re-verify that a *user* can
now get past the gap that motivated the corresponding fix. A red on one of those
is a regression of a shipped doc promise, not a fresh discovery.

---

## F1 (P2) — the desktop app guide still says nothing about a locked row, a refused Access click, or the exempt-port marker

**Shipped:** on a row carrying a `protocol: tcp` port the Host input is
read-only, widening Access into `read-write` is refused by the reducer, and the
port renders a `⚠ tcp` chip plus a red row notice. Removing that port lifts both
restrictions.

**Surface:** `dogfood-app-guide.md`'s "Policy / egress firewall" section is six
sentences and says only that the tab is a form and that "anything the form has
no field for cannot be authored here". Nothing about a host field that will not
accept typing, an Access control that ignores a click in one direction, or what
the `⚠ tcp` chip means. `git log -- dogfood-app-guide.md` shows no commit on this
branch — every other run-1 flag was fixed in place; this one was not.

**Prediction:** the GUI Actor will type into the locked Host field, observe
nothing change, and either retry or give up. It has an in-app explanation (the
row notice is visible, not just an `aria-label`), so this is a P2 friction
finding rather than a dead end — but a user who reads the guide first is told
the tab is "a form" with no hint that two of its controls are conditionally
inert.

**Should have said it:** the app guide's Policy section.

Journeys likely to surface it: `gui-cannot-move-the-exception-to-another-host`,
`gui-cannot-activate-a-dormant-exception`,
`gui-removing-the-exempt-port-unlocks-the-row`.

---

## F2 (P2) — the README's "what counts as weakening egress" list still omits both inspection transitions

**Shipped:** `manifest::diff::egress_weakens` flags two transitions the README
does not mention: (1) a newly-declared passthrough on an exact `(host, port)`,
and (2) a still-reachable port losing global inspection.

**Surface:** README:

> Any change that **weakens** the egress jail — adding `allow` entries, flipping
> `enforce: true → false`, widening `access:` scope — is marked `⚠ weakens
> egress` in `diff` and `promote` output. You cannot miss a loosened firewall.

All three listed causes are about *reachability*. A user who sees `⚠ weakens
egress` on a diff that adds no host, opens no port, widens no access and leaves
`enforce: true` will reasonably conclude the tool is wrong — and the second case
is worse, because the diff *only removes a host* and is still flagged.

**Prediction:** `deep-review-flags-a-new-exception-as-weakening` and
`deep-review-flags-losing-inspection-on-a-shared-port` will produce the flag
correctly and the Actor will read it as a false alarm. The skeptic should treat
"the Actor doubted a correct warning" as the finding, not the warning.

**Should have said it:** the README `⚠ weakens egress` paragraph, and/or
`izba diff --help`.

---

## F3 (P2) — "the exemption needs an exact host" is still only discoverable by triggering the error

**Shipped:** `protocol: tcp` on a wildcard host is a **parse error** (the SNI is
matched exactly; honouring a wildcard would fork the semantics that live in the
policy engine). The asymmetry is deliberate: `protocol: http` on a wildcard is
fine, because more inspection may only narrow.

**Surface:** the README wildcard paragraph is thorough about `*.`/`**.`/apex
semantics and says nothing about this. The README example happens to use an
exact host but never states the rule. `--policy` help says "`protocol: tcp` on an
exact host", which *hints* without saying that a wildcard is **refused** rather
than ignored — and gives no clue that `protocol: http` on a wildcard is
accepted.

**Prediction:** the Actor in `core-refuse-pinning-on-a-wildcard-host` will write
the wildcard, be refused, and — because the refusal is genuinely actionable
("Name each pinned host explicitly") — recover. The cost is one wasted attempt
per user, every time. `core-inspection-may-be-asked-for-on-a-wildcard` is the
paired probe: a user who has just met the refusal has nothing telling them the
*other* per-port value still works there, so I expect hesitation or an
unnecessary rewrite.

**Should have said it:** one clause in the README wildcard paragraph.

---

## F4 (P3) — the conflicting-duplicate-port rule exists only as an error message

**Shipped:** `f21a4dfe` refuses a `ports:` list naming the same port twice with
different declarations, naming the port and both readings. Redundant repeats
(`[443, 443]`) still collapse silently.

**Surface:** nothing in README or any `--help` says a port may be named once
only, or that a redundant repeat is tolerated while a contradictory one is not.
The README's "Unknown keys … are rejected with an error naming the key and its
valid alternatives" covers key typos, not this.

**Prediction:** low-frequency — a user has to write the contradiction to meet it.
Recorded for completeness because the refusal exists to close a security bug (the
two folds disagreeing), so the *rule* is load-bearing even if the *message* is
where users will meet it. `core-refuse-one-port-declared-two-ways` is the probe.

---

## F5 (P3) — `izba policy allow --help` still does not say the grant is unreviewed

**Shipped:** `policy allow` writes `policy.yaml` directly and never passes the
`izba diff`/`izba promote` weakening gate. Since #238 it can no longer open a
hatch, so this is a *reporting* gap, not a security one — but it is still the
difference between two authoring routes.

**Surface:** the fact is now stated in the README's `izba.yml` section (see
section 0) — i.e. in the *manifest* chapter, which a user reaching for
`izba policy allow --help` has no reason to have read. `policy allow`'s own long
help is otherwise excellent (it is the one place the non-inheritance rule is
stated verbatim) and says nothing about review. `policy reload --help` *does*
carry the sentence for the hand-edit route.

**Prediction:** `core-command-line-grants-skip-the-review-gate` will complete —
the consequence (`izba diff` reporting "managed ahead") is discoverable — but the
Actor is unlikely to *expect* it. The finding, if it lands, is "a user cannot
learn from the command's own help that this path is ungated".

**Should have said it:** one clause in `policy allow`'s long help, mirroring the
one already in `policy reload`'s.

---

## F6 (P3) — nothing names the tier vocabulary the audit log answers in

**Shipped:** `izba netlog` is the only surface that says whether a given flow was
*spliced* or *inspected*: a passthrough is written as tier `l3` with the rule
`passthrough (protocol: tcp)`, an inspected flow as tier `l7` with the method and
path.

**Surface:** `izba netlog --help` says only "Show the egress audit log (every
allowed/denied connection)" and, for `--summary`, "Aggregate into a per-endpoint
summary". Neither the help nor the README explains the `l7`/`l3` column, so an
operator holding a log line cannot tell from the documentation that `l3` is the
column that answers "did my exemption actually take effect?".

**Prediction:** every deep datapath journey grades on exactly this column. I
expect the Actor to *reach* `izba netlog` (the README names it repeatedly) and
then be unable to interpret the tier without guessing. This is the one gap that
could make an otherwise-correct datapath journey read as a failure, so the
skeptic should check the trajectory for "ran netlog, could not decide" before
routing anything as a product bug.

**Should have said it:** a legend line in `izba netlog --help`, or one sentence
in the README audit paragraph.

---

## Non-flag: what this surface now gets right

Recorded so the skeptic does not manufacture findings out of things that work.

- **The non-inheritance rule is stated verbatim where a user meets it.**
  `policy allow --help`: "A granted port is always inspected: it never inherits a
  `protocol: tcp` pinning passthrough declared for some other port of the same
  host (edit policy.yaml to declare one)."
- **The README policy example is now a complete teaching example**: it shows a
  bare port ("declares nothing → inspected"), a `protocol: http` port, a
  `protocol: tcp` port with all three losses named, the per-port scoping rule,
  and the read-write requirement — in one block.
- **Both revealing surfaces name their own limits.** `policy show --help` says
  `izba status` renders no egress posture; the README repeats it as "'nothing
  unusual in `izba status`' is *not* evidence".
- **Three distinct not-in-effect wordings exist and are ordered identically on
  both surfaces** (enforcement off → access too narrow → live), which is what
  makes `core-firewall-off-does-not-read-as-one-hole` and
  `gui-inert-when-the-firewall-is-off` a genuine agreement test rather than a
  spelling test.
- **`policy reload` names the file it re-read**, so an operator who edited a
  stray copy sees the mismatch instead of a bare success.
