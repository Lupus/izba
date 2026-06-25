# izba Security

Security-assurance program for izba. izba sandboxes **hostile code** (untrusted
AI-agent workloads) inside microVMs, so this is load-bearing, not paperwork.

| Doc | What it holds |
| --- | --- |
| [methodology.md](methodology.md) | **How** izba is audited — the classical methodology + standards we compose, the 2024–2026 LLM-driven-analysis SOTA and how to get good results from it, and the assurance program for a spec-first / no-human-in-the-loop / TDD codebase (where security gates slot into the pipeline; what TDD structurally misses). |
| [threat-model.md](threat-model.md) | **The living threat model** — attacker model ("the guest is hostile from instruction zero"), data-flow diagram with trust boundaries, trust-boundary inventory, asset register, STRIDE-per-boundary, and the security invariants the design must uphold. Revisit on every trust-boundary change. |
| [findings-2026-06-15.md](findings-2026-06-15.md) | **Findings register** from the first audit pass (code-confirmed candidate findings + remediation + status + a balanced list of strengths). |
| [policy-state-guest-isolation.md](policy-state-guest-isolation.md) | **F-30 deep-dive** — where the egress policy / control-plane state may live vs the guest-writable workspace, under a hostile *kernel*: the A (host-pin) / B (in-guest RO — null under A1) / C (host-only) trade-off, a virtiofs-trick enumeration, and DX prior art (docker-compose / k8s / terraform / direnv / Claude Code). Read before designing the compose manifest or M5 vault. |

## The one assumption everything rests on

> **The guest is hostile from the first instruction** (Firecracker/gVisor/Kata
> model). Everything reachable from inside the microVM is attacker-controlled.
> A VMM/virtiofsd compromise is *expected* over the product's lifetime and must
> be contained below host-user privilege.

## Status (2026-06-15)

First audit pass complete: threat model + methodology + findings register
established (the repo previously had no security docs). The pass was a
multi-agent static/manual survey with independent re-verification of every HIGH
finding. **Owed next:** PoCs for the HIGH guest→host leads (F-08 host-side cp
tar unpack; F-06/F-07 unjailed VMM + `--sandbox none` virtiofsd; F-02/F-03 MITM
allow-list bypass), and the deterministic CI gates (fuzzing under ASan,
`cargo-deny`, mutation testing) described in [methodology.md](methodology.md) §C.
