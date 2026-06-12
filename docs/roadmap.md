# izba roadmap

> Product roadmap toward the [vision](vision.md) ("compose-for-microVMs +
> service mesh + credential vault"). Technical rationale lives in the
> [mesh networking design](superpowers/specs/2026-06-12-izba-mesh-networking-design.md)
> (its §8 staging is the engineering skeleton this roadmap re-cuts into
> user-value milestones). Updated **2026-06-12**.

## Where we are

v1 is **done and daemon-first** on both platforms: per-project microVM
sandboxes with lifecycle, `exec -it`, `cp`, port publishing, OCI→erofs images,
and `izbad` (disk-state adoption, stream splicing, upgrade dance). Linux/KVM
via Cloud Hypervisor and Windows/WHP via OpenVMM both pass their gates (KVM
integration 15/15, daemon e2e, tty harness, Windows PS validation).

What does **not** exist yet:

- Any of the mesh staging steps — no `StreamOpen::TcpConnect`, no egress stub,
  no manifest, no policy, no vault. Guest egress still rides passt/consomme
  (the host-autodetect bug class is contained, not killed).
- A fix for the **OpenVMM vsock-assert crash** under stream churn
  (`virtio_vsock connections.rs:1093`, reproduced by `ttystorm floodfast`) —
  the declared hard gate for putting all traffic on vsock.
- **Adoption infrastructure**: no CI, no releases, no published kernel/initramfs
  artifacts, no install story beyond building from source.

## Principles

1. **Every milestone ships user-visible value**, not just plumbing. Where the
   design staging is infrastructure-shaped, we pull a thin slice of the
   security story forward to make the milestone demoable.
2. **Linux-first, Windows-parity-follows.** The OpenVMM vsock crash gates
   *Windows* mesh traffic, not Linux (the assert is OpenVMM-side). Windows may
   trail a milestone behind a flag; it never forks the design (one network
   story is the point).
3. **Locked decisions stay locked** (vision §"Locked product decisions").
   Open questions land in §Open decisions below, with a forum (working
   session), not relitigated inline.
4. **Adoption work is product work.** An OSS substrate nobody can install is
   a design doc. Track T runs continuously alongside the milestones.

## Milestones

Sizes are relative (S/M/L) — recent velocity makes weeks the natural unit, not
quarters. Order is dependency order; M3 and Track T run in parallel.

### M0 — Stability gate: vsock under churn (S–M)

Fix the OpenVMM vsock-assert crash (mitigation already identified: graceful
`shutdown(Write)` + drain instead of abrupt drop; upstream issue if it's
theirs to fix). **Exit:** `ttystorm floodfast` clean on OpenVMM; KVM suite
unaffected. **Timebox it** — if the mitigation doesn't hold, M1+ proceeds
Linux-first and Windows mesh waits on upstream (mirrors the v1 S1 fallback
posture).

### M1 — One network story: izbad-owned egress (M)

Design steps 1–3 as one cut: `StreamOpen::TcpConnect` + izbad host dial-out
(opt-in at first, coexisting with passt/consomme), the guest egress stub in
izba-init (`nft` REDIRECT, `SO_ORIGINAL_DST`, DNS interception to izbad's
resolver), then flip the default route and **retire passt/consomme from the
egress path**. **Exit:** all suites green with stub-only egress on both
platforms; the WSL+VPN and Tailscale topologies that produced `ea9e413` and
`30e5c67` work with zero host sniffing; consomme/passt gone from the datapath
(and `izba.ipv4only=1` with them).

### M2 — Agent firewall: egress policy + audit log (S–M)

The pulled-forward slice of design step 5, north–south plane only, **for
single sandboxes** — because once M1 lands, izbad already sees every flow and
this is the headline feature for the target user: *"my agent can only reach
`api.anthropic.com` and `github.com`, and I can see every connection it
tried."* Per-sandbox allow-list (CLI/config), default-deny **when a policy is
declared** (bare sandboxes keep allow-all until the project era — see Open
decisions), allow/deny decisions in an audit log with an `izba netlog`-style
view. **Exit:** the one-liner demo above, on both platforms. This is the first
release-tag moment (see Track T).

### M3 — Sized & stateful sandboxes: resources + volumes (M) — parallel

Per-sandbox `resources` (cpus/memory) and **user-declared persistent block
devices** (design §3.4). Independent of the mesh (can start alongside M1) and
a hard prerequisite for M4's stateful members: a dockerd-in-VM needs a sized
`/var/lib/docker`. Touches the load-bearing **Disk order** contract — change
all ends (driver enumeration, OpenVMM per-disk PCIe routing, init mount plan)
in one milestone with integration coverage before anything builds on it.
**Exit:** a sandbox with a sized docker-state volume runs a real in-guest
compose stack; data survives stop/start; both platforms.

### M4 — Projects: izba.yaml + lifecycle + mesh (L)

Design step 4 plus the east–west half of step 5 (in this architecture
"brokering only declared edges" *is* the policy engine — they don't split).
The `izba.yaml` manifest (vms/expose/depends_on/healthcheck/resources/volumes
+ both policy planes), project disk layout + izbad adoption, member start
ordering and readiness gates, name resolution (bare member names + `.izba`
FQDN), east–west splice of declared edges, per-member egress lists from the
manifest, audit log extended to east–west. **Exit:** the canonical
research-agent demo — agent VM + graphiti/neo4j VM from one manifest; agent
reaches `graphiti:8000` and *cannot* address neo4j; each member has its own
scoped egress; full flow log. Consider cutting as 4a (project object +
lifecycle) / 4b (mesh wiring) if it sprawls.

### M5 — Credential vault: per-role MITM injection (M–L)

Design step 6. izbad CA (`rustls` + `rcgen`), CA baked into guest trust
stores at boot, SNI-based detection, **per-role credential injection** at
dial-out. Scope guardrails for v-first: HTTPS header injection for known SaaS
APIs (Anthropic, OpenAI, GitHub); everything else passes through MITM-free
but logged; cert-pinning clients are a documented limitation, not a fight we
pick. **Exit:** agent calls `api.anthropic.com` with **no key anywhere in the
guest**; graphiti uses its own scoped key the agent can never read; keys
independently revocable/meterable.

### Track T — Adoption & release engineering (continuous)

Runs parallel to everything; first slice lands during M0/M1.

- **CI for the six gates** (fmt, clippy×2, test, musl init, win cross-check) —
  cheap, immediate; KVM-gated suites stay local/self-hosted for now.
- **Published kernel + initramfs artifacts** (the long-deferred item) so users
  don't build a kernel to try izba.
- **Versioned releases** with prebuilt binaries (Linux + Windows) — first tag
  at M2, the agent-firewall moment, when izba first has a story no container
  sandbox can match.
- **Quickstart that works from a clean machine**, refreshed each milestone;
  `izba.yaml` reference when M4 lands.

## Risk register

| # | Risk | Exposure | Mitigation |
| --- | --- | --- | --- |
| 1 | OpenVMM vsock assert survives the graceful-shutdown fix | Windows mesh blocked | M0 timebox; Linux-first fallback; upstream issue early |
| 2 | izbad becomes a traffic SPOF — every byte through userspace splices; daemon restart/upgrade now severs *all* flows, not just port relays | UX regression vs v1 | Define restart/upgrade semantics before M1 ships defaults; add a throughput benchmark gate |
| 3 | DNS interception edge cases (resolver behaviors, search domains, TCP DNS) | M1 flakiness | Scope: UDP :53 only at first; conservative resolver; integration tests per topology |
| 4 | MITM vs cert pinning / h2 / websockets | M5 value narrower than hoped | Scoped injection + passthrough-and-log default; document limits honestly |
| 5 | Disk-order contract change ripples (M3) | Subtle cross-platform boot breakage | One-milestone "change all ends" rule + KVM/Windows gates before M4 consumes it |
| 6 | izbad scope creep (router + DNS + policy + MITM + vault in one binary) | Maintainability | Keep planes as separable modules with the daemon proto as the seam |

## Open decisions (resolve in working sessions, not ad hoc)

- **Bare-sandbox policy default** — proposal embedded in M2: allow-all with no
  policy declared, default-deny the moment one is; projects are always
  default-deny. Needs a yes/no.
- **Manifest grammar finalization** (design §9): exact key names, `volumes`
  lifecycle verbs (create/resize/prune), schema **versioning from day one**.
- **Static vs runtime-mutable policy** (design §4 OPEN) — static-only is the
  cheaper M4 default; mutability is a control-plane feature.
- **UDP beyond DNS** (design §9) — default stays "deny"; revisit on a concrete
  need only.

## Explicitly not on this roadmap

Org-level / cross-project control plane, non-TCP fidelity (raw sockets / ICMP /
arbitrary UDP), snapshot/resume of a project, erofs layer dedup **across
members**, and a docker-enabled convenience base image (a future nicety,
never a requirement). All noted in the vision's "not yet" list.
