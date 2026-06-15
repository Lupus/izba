# izba Security Assurance Methodology

> How izba is security-audited, and **how a spec-first, no-human-in-the-loop,
> TDD project keeps that audit honest.** This is the "how"; the
> [threat-model.md](threat-model.md) is the "what can go wrong" and
> [findings-2026-06-15.md](findings-2026-06-15.md) is "what we found."

This document does three things, matching the questions that motivated it:
1. **§A** — the classical (pre-LLM) audit methodology, flow, and required
   artifacts, and which standards we compose.
2. **§B** — the 2024–2026 SOTA on LLM-driven security analysis: what it changes,
   and how to get good results instead of confident hallucinations.
3. **§C** — the assurance program for izba specifically, given that its code
   *and its tests* are AI-authored with no human writing code.

---

## §A. The classical methodology (and what we adopt)

No serious program picks one framework; mature audits **layer** a lifecycle, a
threat-enumeration method, and a scoring scheme. izba composes:

| Layer | Standard | Role here |
| --- | --- | --- |
| Engagement lifecycle | **PTES** (+ NIST SP 800-115 for the planning/attack/report spine) | The phase scaffolding (below). |
| Threat enumeration | **STRIDE per DFD element** | Design-phase default; drives the threat model. |
| Privacy (when relevant) | LINDDUN | Future credential-vault / data-handling work. |
| Targeted analysis | **Attack trees** | For the one high-value goal: guest→host escape. |
| Adversary framing | microVM-sandbox threat model (Firecracker/gVisor/Kata) | The "guest is hostile" assumption (A1). |
| Severity | **CVSS v3.1 base + environmental**, plus exploitability × blast-radius triage | Portable, comparable, defensible scoring. |

**The end-to-end flow** (every finding traces back to a phase):

1. **Scope & rules of engagement** — what's in/out, authorization, success
   criteria. (For izba: the whole workspace, all six trust boundaries.)
2. **Asset & trust-boundary identification** — build the asset register and
   the DFD with trust boundaries. *This is the highest-leverage step* — most
   missed bugs are missed because the boundary wasn't drawn.
3. **Threat modeling** — STRIDE per element → enumerated threats + assumptions.
4. **Attack-surface enumeration** — every entry point that parses
   attacker-influenced bytes, catalogued (see threat-model §4).
5. **Analysis — static + dynamic + manual** — SAST + SCA on code/deps, fuzzing
   at untrusted-input boundaries, and (critically) **manual review** of
   business/security logic. Tools alone miss authz gaps and chained bugs.
6. **Exploitation / PoC** — validate each candidate by triggering it. *A
   finding without a reproduction is a hypothesis, not a finding.*
7. **Risk rating** — CVSS vector + environmental context; rank.
8. **Reporting & remediation** — findings report with evidence, root-cause
   fixes, owners.
9. **Re-test & residual-risk acceptance** — verify the fix actually closes it;
   record (and sign off) anything not fixed.

**Required documentation artifacts** (the paper trail a rigorous audit leaves):

| Artifact | In this repo |
| --- | --- |
| Asset register + trust-boundary inventory | [threat-model.md](threat-model.md) §4–5 |
| Data-flow diagram with trust boundaries | [threat-model.md](threat-model.md) §3 |
| Threat model document | [threat-model.md](threat-model.md) |
| Attack-surface inventory | [threat-model.md](threat-model.md) §4 |
| Findings report (with severity + repro status) | [findings-2026-06-15.md](findings-2026-06-15.md) |
| Remediation plan | findings report, "Fix" column |
| Re-test / residual-risk record | findings report, "Status" column |

**Classical pitfalls we explicitly guard against:** scoping too narrowly
(define boundaries *before* scope); tool-only coverage (manual review is
mandatory); treating SAST/DAST output as findings without a PoC; letting the
threat model go stale (it's a living doc, revisited per boundary change);
subjective scoring (CVSS vectors recorded, not just a label); ignoring the
supply chain (SCA/SBOM gate).

---

## §B. What LLM-driven analysis changes (2024–2026 SOTA)

By 2024–2026 LLM security analysis crossed from demos to measured results —
**but only where models are wrapped in deterministic tooling and forced to
prove findings.** The evidence:

- **Google Big Sleep** (ex-Naptime) found a real exploitable SQLite memory bug
  via variant analysis. **OSS-Fuzz-Gen** used LLMs to synthesize fuzz harnesses
  that surfaced 26+ bugs including a 20-year-old OpenSSL flaw (CVE-2024-9143).
- **DARPA AIxCC final (Aug 2025):** autonomous "cyber reasoning systems" found
  86% of synthetic vulns and patched 68%, plus 18 real bugs — *the hybrid
  (LLM + SAST + fuzzer) systems won.*
- Offensively, UIUC agents exploited **87% of one-day CVEs given the CVE text**;
  multi-agent teams (HPTSA) beat single agents; **XBOW** briefly topped
  HackerOne's US leaderboard.
- The honest counterweight: bare LLMs hallucinate exploits (a documented case:
  an "XSS" sub-agent that logged to its own console and declared victory) and
  miss cross-file logic. Measured **false-positive rates run 10–50%**, ~50%
  even for capable commercial tools.

**The shift:** LLMs are best as a *force multiplier on recall and triage*, not
as the detector of record. The reliable pattern:

> **Deterministic tools own detection; the LLM owns breadth, triage,
> business-logic reasoning, and explanation — and every finding must carry a
> reproduction before it is trusted.**

**The LLM-augmented flow we use:**

1. **Scope to one trust boundary at a time** — never "find bugs in the repo."
   One module/parser/data-flow path that fits the context window, with a build
   and a runnable target. (This audit ran one agent per boundary — see the
   workflow in the audit log.)
2. **Ground the model** — feed call graphs, cross-file caller/callee context,
   and known prior bugs (for variant analysis). **Sanitize attacker-controlled
   text** in the target so it can't prompt-inject the analyzer.
3. **Run deterministic tools first** — SAST (Semgrep/CodeQL), fuzzing
   (optionally LLM-drafted harnesses via OSS-Fuzz-Gen). The LLM expands
   harnesses and triages results; it is not the sole detector.
4. **Multiple detection runs** — exploit non-determinism for recall; aggregate.
5. **Adversarial verification gate** — route every candidate through an
   *independent* verifier agent prompted to **refute**, with multi-agent
   voting. Drop anything the verifier can't defend. (This is how the
   "unvalidated sandbox name → path traversal" candidate was correctly
   downgraded in this audit: a verifier checked `validate_name` and found it
   blocks the traversal.)
6. **Require a PoC** — for memory/logic bugs, an actual crash/assertion in a
   debugger; for web/egress, a tool-confirmed request/response. **No PoC ⇒
   "needs verification", never "confirmed."**
7. **Human or deterministic-tool sign-off** — before a finding is reported or
   any auto-fix is merged. Never auto-merge a security fix.

**LLM-specific pitfalls + mitigations** (these are program requirements, not
advice): hallucinated findings → mandatory PoC; high FP rate → deterministic
detection + adversarial verification + track FP rate on an eval set; false
confidence → independent verifier + voting + sign-off gate; missing
whole-program reasoning → pre-computed call graphs + cross-file context;
context-window limits → scope per boundary; non-determinism → multi-run
aggregation; **prompt injection of the analyzer** → treat code/issues/strings
as untrusted, sandbox the agent, deny it write/network powers; over-automation
of fixes → propose in-PR, human-review before merge.

---

## §C. Assurance for spec-first / no-human-in-loop / TDD code

izba is doubly exposed: **both the code and the tests are AI-authored.** Two
facts drive the whole program:

- **AI-generated code is measurably less secure.** NYU found ~40% of Copilot
  completions in security-relevant scenarios were vulnerable; Veracode found AI
  code introduced flaws at a ~45% rate that **did not improve with model
  scale**; Stanford found developers using AI assistants wrote *more* insecure
  code while being *more confident* it was secure.
- **TDD cannot establish security.** Tests encode *intended* behavior — the
  happy path plus anticipated edge cases. Security bugs live in the
  **unspecified negative space**: malformed input, adversarial sequencing,
  resource exhaustion, boundary confusion. The spec and tests can be perfectly
  satisfied while the threat model is wholly unmet (Dijkstra: tests show the
  presence of behavior, never its absence). Worse, when the *same author*
  (here, an LLM) writes both the code and the tests, the tests inherit the
  code's blind spots — confirmation bias, doubled.

So TDD's green suite is **necessary but not remotely sufficient.** The program
layers in what TDD structurally misses, and — critically — enforces
**independence**: the auditor is never the author.

### The two principles

1. **Independence.** Security verification is done by an agent (or tooling)
   that did *not* write the code or the spec, in a separate context, framed
   "assume hostile, try to break it / refute the claim," with multi-agent
   voting to suppress hallucinations. The spec-writer proving its own code
   secure is the failure mode to design out.
2. **Negative-space coverage.** For every trust boundary, the unspecified
   adversarial inputs are made *first-class*: abuse-case tests, fuzzing,
   property tests, sanitizers — the things author-written happy-path tests
   never cover.

### Where security gates slot into the spec → TDD → implement pipeline

```
  ┌─ SPEC ──────────────┐   Threat model is a REQUIRED spec input.
  │  + threat-model.md   │   Each new trust boundary → enumerated threats +
  │  + security DoD       │   security invariants (threat-model §7) written
  └──────────┬───────────┘   BEFORE implementation.
             ▼
  ┌─ TDD (tests first) ──┐   Abuse/misuse cases are REQUIRED tests, not
  │  happy-path tests     │   optional. A missed threat = a failing test.
  │  + ABUSE-CASE tests   │   (e.g. "guest tar with `x→/etc`, then `x/p`
  └──────────┬───────────┘    must NOT write outside unpack root".)
             ▼
  ┌─ IMPLEMENT (AI) ─────┐
  └──────────┬───────────┘
             ▼
  ┌─ PRE-MERGE GATES ────┐   Deterministic, green-before-commit:
  │  cargo-audit/deny     │     • RUSTSEC advisory + license/ban (deny.toml)
  │  SAST (Semgrep/CodeQL)│     • unsafe-block review log
  │  fuzz smoke + sanitizer    • cargo fuzz targets for every parser/wire fmt,
  │  property tests        │      run under ASan/Miri
  └──────────┬───────────┘
             ▼
  ┌─ INDEPENDENT REVIEW ─┐   A non-author agent, "assume hostile, refute",
  │  adversarial audit     │   multi-agent vote, PoC required. (This audit.)
  └──────────┬───────────┘
             ▼
  ┌─ CONTINUOUS ─────────┐   Nightly fuzz (corpus persists as regressions),
  │  nightly fuzz/mutation │   mutation testing (does the suite actually catch
  │  SCA watch + CVE pins  │   negative-space mutants?), VMM-CVE pin ledger,
  └──────────────────────┘   periodic full independent red-team audit.
```

### Verification techniques that catch what TDD misses (priority order for izba)

1. **Fuzzing of every untrusted parser / wire format** — `izba-proto` codec +
   message enums, the DNS framing, OCI tar layers, the cp tar receiver, the
   MITM HTTP head reader. `cargo fuzz` + libFuzzer, run under **ASan**; the
   corpus is checked in as durable, deterministic coverage. LLM-drafted
   harnesses (OSS-Fuzz-Gen style) are fine, iterated against coverage.
2. **Abuse-case tests as invariants** — encode threat-model §7 as failing-first
   tests (no-FS-escape, fail-closed egress, no-SSRF, domain+port allow-list,
   bounded parsers). These become the regression wall.
3. **Sanitizers + Miri for `unsafe`** — every `unsafe` block (FFI, vsock, mmap)
   reviewed and logged with justification; run the suite under Miri where it
   applies, ASan/UBSan on the fuzz/integration paths.
4. **Property-based tests** — for path-sanitization, frame round-tripping,
   policy decisions (`proptest`): assert invariants over generated inputs, not
   just example cases.
5. **Differential testing** — guest-side cp receiver (hardened, openat2) vs
   host-side cp unpack should make the *same* containment decision; today they
   diverge (F-08). Differential tests surface exactly this asymmetry.
6. **SAST + SCA** — Semgrep/CodeQL for taint into the dangerous sinks;
   cargo-audit/cargo-deny as a CI gate (currently absent — F-22).
7. **Mutation testing** (`cargo-mutants`) — measures whether the AI-authored
   suite actually *detects* injected faults; the antidote to same-author test
   bias.
8. **Independent adversarial agent audits** — periodic, scoped per boundary,
   refute-framed, PoC-required (the program in §B).

### Security Definition-of-Done (per feature touching a trust boundary)

- [ ] Threat model updated; new boundary's threats + invariants enumerated.
- [ ] Abuse-case tests written (failing first) for the enumerated threats.
- [ ] Every new parser of untrusted input has a fuzz target + seed corpus.
- [ ] `unsafe` blocks reviewed and logged.
- [ ] `cargo-audit`/`cargo-deny` green; no new advisories.
- [ ] Independent (non-author) adversarial review pass, findings triaged with
      PoCs, residual risk recorded.

---

## How this audit was run (reproducibility)

This first audit was executed as a multi-agent workflow: four web-grounded
research streams (classical methodology, LLM-security SOTA, hypervisor/sandbox
domain, auditing-AI-code) and four codebase attack-surface surveys, one per
trust-boundary cluster, each returning structured findings. The orchestrator
then **independently re-verified every HIGH candidate against the actual source
lines** before recording it (see findings, "Repro" column) — the §B
adversarial-verification gate. The survey was static/manual; the next pass owes
PoCs (fuzzing + exploit attempts) for the HIGH findings, per the flow §A.6.
