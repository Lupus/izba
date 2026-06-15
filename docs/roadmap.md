# izba roadmap

> Product roadmap toward the [vision](vision.md) ("compose-for-microVMs +
> service mesh + credential vault"). Technical rationale lives in the
> [mesh networking design](superpowers/specs/2026-06-12-izba-mesh-networking-design.md)
> (its §8 staging is the engineering skeleton this roadmap re-cuts into
> user-value milestones). Updated **2026-06-13**.

## Where we are

v1 is **done and daemon-first** on both platforms: per-project microVM
sandboxes with lifecycle, `exec -it`, `cp`, port publishing, OCI→erofs images,
and `izbad` (disk-state adoption, stream splicing, upgrade dance). Linux/KVM
via Cloud Hypervisor and Windows/WHP via OpenVMM both pass their gates.

**Networking is now unified on izbad** (mesh staging steps 1–3 done, M1
2026-06-13): all guest egress — TCP and DNS — flows through izbad over
guest-initiated vsock streams; the guest is a NIC-less vsock island and
passt/consomme/`izba.ipv4only` are gone from the datapath. See M1 below.

**The agent firewall (M2) has since shipped** (MITM L7 + allow-list +
DNS-snoop + `izba netlog`): `crates/izba-core/src/daemon/egress/{mitm,
mitm_runtime,dns_snoop,audit,policy}.rs` + `ca.rs` + guest `trust.rs` are
in-tree. **Adoption infrastructure (Track T) also landed**: CI six gates +
real-VM e2e, published artifacts, and `.deb`/Windows installers on `v*` tags.

What does **not** exist yet:

- The mesh/governance staging steps beyond the firewall — no manifest, no
  project object, no credential vault (M4/M5).
- **Sized & stateful sandboxes (M3)** is the in-flight milestone: per-member
  resources are already wired; user-declared **persistent volumes** are landing
  now (see M3).

The **OpenVMM vsock-assert crash** under stream churn (the declared hard gate
for putting all traffic on vsock) is **fixed** as of 2026-06-12 — see M0 below.

## Principles

1. **Every milestone ships user-visible value**, not just plumbing. Where the
   design staging is infrastructure-shaped, we pull a thin slice of the
   security story forward to make the milestone demoable.
2. **Platform parity is the bar** (decided 2026-06-12). The OpenVMM vsock
   crash is fixed *first*, untimeboxed — no Linux-first mesh work ships while
   Windows would be left behind. One network story means one schedule.
3. **Locked decisions stay locked** (vision §"Locked product decisions").
   Open questions land in §Open decisions below, with a forum (working
   session), not relitigated inline.
4. **Adoption work is product work.** An OSS substrate nobody can install is
   a design doc. Track T runs continuously alongside the milestones.

## Milestones

Sizes are relative (S/M/L) — recent velocity makes weeks the natural unit, not
quarters. Order is dependency order; M3 and Track T run in parallel.

### M0 — Stability gate: vsock under churn (S–M) — ✅ DONE (2026-06-12)

Fixed the OpenVMM vsock-assert crash. The mitigation is the graceful
`shutdown(Write)` + **drain** teardown: `copy_until_eof` now keeps consuming
the vsock leg after the peer write fails (instead of dropping the socket with
guest TX buffered), so the VMM relay socket is never force-closed mid-TX — the
exact condition that tripped the assert. Hardened at both host sites
(`portfwd.rs` relay, `daemon/server.rs` splice) with socketpair TDD tests.

**Exit — met:** `ttystorm` (now routed through izbad, the production datapath)
runs `floodfast 20×2MiB` and `chop 30×` clean on OpenVMM with the VM alive
afterward; KVM suite unaffected (15/15). The `--direct` control path still
reproduces the assert and kills the VM (`connections.rs:1093`,
`code=0xc0000409`) — confirming the bug is real and the drain is what protects;
the VM-death is honest and `izba run` recovers.

**Plan B prepared (not needed, kept ready):** the assert has a clean two-line
fix (remove the connection before queueing `SendReset` in the two error arms
that don't) — patch at `hack/openvmm-vsock-assert.patch` against the pinned
commit, upstream-issue draft at
`docs/superpowers/specs/2026-06-12-openvmm-vsock-assert-issue.md` (upstream
`main` still affected). If a future path force-closes a relay mid-TX anyway,
apply the patch and self-build a pinned fork (same pinning shape as
`hack/fetch-openvmm.sh`).

### M1 — One network story: izbad-owned egress (M) — ✅ DONE (2026-06-13)

Design steps 1–3 landed as one cut: `StreamOpen::TcpConnect`/`Dns` +
guest-initiated vsock 1027 + izbad host dial-out and a system-upstream DNS
forwarder (`crates/izba-core/src/daemon/egress/` — router/dns/policy/manager
seams), the guest egress stub in izba-init (`nft` REDIRECT to `:15001`,
`SO_ORIGINAL_DST`, DNS UDP:53 → `Dns` stream; `crates/izba-init/src/egress.rs`
+ `net.rs`), then the cutover that removed virtio-net entirely. The guest is
now a NIC-less vsock island (dummy0 static config, vendored static `/sbin/nft`,
netfilter/`DUMMY` kernel config). The baked-in decisions held: daemon
restart/upgrade **severs live flows — no drain logic**; throughput is
**measured, not gated**. The izbad-internal **module seams** exist as designed
(roadmap risk #6 retired for egress).

**Exit — met (2026-06-13):**

- KVM integration **18/18** with stub-only egress; daemon e2e green; tty_e2e
  **2/2**.
- Throughput baseline **279.3 MiB/s** (measured in the integration suite, not
  gated).
- Windows PS validation suite **ALL PASS** — run on the same
  VPN-topology host that produced the original consomme guest-egress failure;
  that failure is **retired with consomme**.
- `passt`, `consomme`, `ip=dhcp` and `izba.ipv4only=1` are **gone from the
  datapath**; WSL+VPN and Tailscale topologies (the `ea9e413` / `30e5c67`
  bug class) work with zero host sniffing.

**Known gap (carried forward):** apps that hardcode an *external UDP* resolver
(e.g. `dig @8.8.8.8`) get no answer — the `udp dport 53` REDIRECT reply path
doesn't work (transparent-UDP-proxy source-mismatch). `resolv.conf` points at
loopback, which works. Flagged as a docker-in-VM (M3/M4) prerequisite — see
risk #3 and Open decisions.

### M2 — Agent firewall: merged MITM L7 + allow-list + audit (M) — ✅ DONE

Shipped: TLS-MITM datapath + two-tier policy plane (regorus L7 + DNS-snoop) +
`izba netlog` audit + per-sandbox `--policy` + CA-in-guest, daemon-activated and
failing **closed** for enforcing sandboxes. Code: `daemon/egress/{mitm,
mitm_runtime,dns_snoop,audit,policy}.rs`, `ca.rs`, init `trust.rs`,
`crates/izba-cli/src/commands/netlog.rs`. This was the first release-tag moment.

**Restructured 2026-06-14 (the M5 leapfrog):** M2 absorbs M5's MITM datapath —
the OpenShell-salvage spike proved it cheap (compiles, tests green, Windows
cross-check green). North–south plane, **single sandboxes**, the headline
feature: *"my agent can only reach `api.anthropic.com` and `github.com`, every
connection it tried is in `izba netlog`, and there are no uninspectable
channels."* This is the first release-tag moment (see Track T).

Scope: a TLS-MITM datapath in izbad (terminate guest HTTPS, mint per-SNI leaves
under an izba CA, re-originate upstream — salvaged from the spike), reached via a
**loopback-hop bridge** that leaves the blocking vsock egress plane + the
OpenVMM churn invariant untouched; a **two-tier policy plane** (one `regorus`
engine, default-deny when declared): tier 1 = hard L7 on the decrypted
`{host,method,path}` for HTTP(S), tier 2 = soft **DNS-snoop** FQDN allow-list for
the non-HTTP tail (raw-IP-with-no-snoop-record ⇒ deny); an **audit log + `izba
netlog`**; and **CA-in-guest** (bake the izba CA into the guest trust store at
boot). Force http/1.1 (ALPN); h2 deferred. **Decided (2026-06-12):** per-sandbox
allow-list, default-deny when declared, bare sandboxes allow-all; presets
(open/balanced/closed) postponed (no credible "balanced" artifact yet).
**Decided (2026-06-13):** credential injection is **not** here — moved to M5.
**Exit:** the one-liner demo on both platforms (KVM + OpenVMM/WHP), automated.

Full design: [specs/2026-06-14-m2-agent-firewall-merged-design.md](superpowers/specs/2026-06-14-m2-agent-firewall-merged-design.md).
Building-block decisions (regorus, DNS-snoop, OpenShell salvage map):
[egress-firewall-building-blocks.md](egress-firewall-building-blocks.md).

**M2.1 — Port-aware allow-list (2026-06-15):** tightened the allow-list
grammar: a bare host entry now authorizes web ports (80/443) only; any other
port must be listed explicitly with `{host, ports: [...]}`. Explicit ports
replace (not extend) the web default. This closes the port loophole where an
allow-listed host was reachable on every TCP port. Existing string-list
`policy.yaml` files keep parsing unchanged and now mean "80/443 only".

**M2.1 Step 3 — interactive firewall (2026-06-15):** made the port-aware
allow-list usable end-to-end. New CLI surface `izba policy show/allow/block/
enable/reload` edits `policy.yaml` and live-reloads a running sandbox, and
`izba netlog --summary` aggregates the audit log per endpoint (host/IP + port,
allow/deny counts, latest verdict). The desktop app gains P4 Netlog + Policy
tabs: click-to-allow/block, a disabled Allow on raw-IP rows (SSRF guard), and
"Enable firewall" that seeds the allow-list from observed allowed traffic. All
edits route through one core grammar helper (`EgressPolicyConfig::{allow,block,
to_yaml}` + `edit_policy_file`/`seed_from_summaries`), so the CLI and app stay
consistent. Host-side pure logic + UI only — no datapath change.

### M3 — Sized & stateful sandboxes: resources + volumes (M) — 🚧 IN FLIGHT

Per-sandbox `resources` (cpus/memory) **already ship** (CLI → daemon → both
drivers' memory/processor knobs). The in-flight slice is **user-declared
persistent block devices** (design §3.4, spec
[2026-06-15-izba-m3-volumes-design.md](superpowers/specs/2026-06-15-izba-m3-volumes-design.md)):
two inline volume classes — ephemeral (anonymous, in the sandbox dir) and
persistent (named, `<data>/volumes/<name>.img`, survive `rm`, single-writer) —
each an extra virtio-blk disk appended after `rw.img` (vdc, vdd, …), formatted
ext4 and mounted at a declared guest path. Independent of the mesh and a hard
prerequisite for M4's stateful members: a dockerd-in-VM needs a sized
`/var/lib/docker`. Touches the load-bearing **Disk order** contract — changed
at all ends (host disk assembly, the `izba.volumes` cmdline channel, the guest
mount plan; both drivers were already order-driven) in one milestone with
integration coverage. `izba volume prune` reaps unreferenced persistent images.
**Exit:** a sandbox with a sized docker-state volume runs a real in-guest
compose stack; data survives stop/start; both platforms.

### M4 — Projects: izba.yaml + lifecycle + mesh (L)

Design step 4 plus the east–west half of step 5 (in this architecture
"brokering only declared edges" *is* the policy engine — they don't split).
The `izba.yaml` manifest (vms/expose/depends_on/healthcheck/resources/volumes
+ both policy planes), project disk layout + izbad adoption, member start
ordering and readiness gates, name resolution (bare member names + `.izba`
FQDN), east–west splice of declared edges, per-member egress lists from the
manifest, audit log extended to east–west. **Policy mutability decided
(2026-06-12): static + reload verb** — `izba project reload` re-reads
`izba.yaml` and applies new rules to *new* flows, no runtime policy API, no
VM restarts. **UDP decided: deny everything except the :53 resolver path**
(dropped + logged); revisit only on a concrete need. **Exit:** the canonical
research-agent demo — agent VM + graphiti/neo4j VM from one manifest; agent
reaches `graphiti:8000` and *cannot* address neo4j; each member has its own
scoped egress; full flow log. Consider cutting as 4a (project object +
lifecycle) / 4b (mesh wiring) if it sprawls.

### M5 — Credential vault: per-role injection + identity (L)

**Restructured 2026-06-14:** the MITM datapath + L7 policy + CA-in-guest moved
*down* to M2 (the leapfrog). M5 is now the credential vault **only**, hanging off
the MITM branch M2 already built. Design step 6, narrowed. **Credential injection
for arbitrary endpoints** (not a known-SaaS shortlist): the M4 manifest maps a
member role + destination pattern to a secret + injection shape
(header/bearer/etc.); izbad strips the caller's credential and injects the
backend one at the MITM branch — *no key anywhere in the guest* (stronger than
the env-placeholder model: the credential lives only in izbad's vault, keyed by
`(role, host\tport\tpath)`). Depends on M4's manifest for the role→secret
mapping. **Two areas to explore here (decided 2026-06-14):** a real **OCSF**
audit-event schema for the credential/flow log (beyond M2's structured netlog),
and **SPIFFE/SVID** identity for the per-role vault (the `TokenGrantResolver`
trait seam M2 leaves in place). The injection *logic* is a clean pure-function
reimplement from OpenShell's design (strip+inject, RFC-7230 validation, CWE-113
guard, specificity scorer — no OCSF/SPIFFE drag); OCSF/SPIFFE are the
deliberately-additive exploration. Cert-pinning clients knowingly broken (the
posture is already set in M2). **Exit:** agent calls `api.anthropic.com` with no
key in the guest; graphiti uses its own scoped key the agent can never read; a
URL/method-level rule blocks one API route while allowing another on the same
domain; keys independently revocable/meterable; credential decisions in the OCSF
flow log. See [egress-firewall-building-blocks.md](egress-firewall-building-blocks.md)
(salvage map: `secrets.rs`/`token_grant_injection.rs` assessment).

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

Reviewed with the owner 2026-06-12; ★ = elevated (gets a written plan before
its milestone starts).

| # | Risk | Exposure | Mitigation |
| --- | --- | --- | --- |
| 1★ | OpenVMM vsock assert survives the graceful-shutdown fix | The whole roadmap blocked (M0 is untimeboxed, parity sacred) | **Plan B prepared up front:** patch the assert + self-build a pinned OpenVMM fork (same pinning shape as today's fetched binary); upstream issue filed in parallel |
| 2 | izbad is a traffic SPOF — restart/upgrade severs *all* flows, not just port relays | UX regression vs v1 | **Decided:** accepted + documented honest behavior, no drain logic (apps retry). Throughput: **measure, don't gate** — baseline number in the integration suite |
| 3 | DNS interception edge cases (resolver behaviors, search domains, TCP DNS) | M1 flakiness | Largely closed in M1 (loopback resolv.conf + raw-UDP forwarder; TCP :53 routes to the same resolver). **Concrete realized instance:** the `udp dport 53` REDIRECT *reply* path doesn't work (stub's wildcard-socket source mismatches; conntrack never un-NATs) — so hardcoded external UDP resolvers get no answer. Mitigation: resolv.conf points at loopback (exempt from REDIRECT, works); the gap is flagged as a docker-in-VM (M3/M4) prerequisite (`IP_ORIGDSTADDR` transparent-reply fix) |
| 4 | MITM datapath risk: cert-pinning breakage, h2/websocket, the vsock↔tokio bridge, OpenVMM churn under the hop | MITM moved *up* to M2 (the leapfrog) — largest part of M2 | **Largely retired by the 2026-06-13 OpenShell-salvage spike** (compiles, 164/164 tests incl. e2e MITM, Windows cross-check green). Pinning breakage = accepted posture. h2 deferred (force http/1.1). Bridge = loopback-hop reusing the proven blocking pump, so the churn invariant is untouched (re-proven by a dedicated integration test). See [specs/2026-06-14-m2-agent-firewall-merged-design.md](superpowers/specs/2026-06-14-m2-agent-firewall-merged-design.md) |
| 5★ | Disk-order contract change ripples (M3) across driver enum, OpenVMM PCIe routing, init mount plan | Subtle cross-platform boot breakage | **Contract-change spec written before any M3 code**; one-milestone "change all ends" rule; KVM + Windows gates green before M4 consumes volumes |
| 6★ | izbad scope creep (router + DNS + policy + MITM + vault in one binary) | Maintainability | **Module seams defined in the M1 design doc** (separable planes, daemon proto as the seam) rather than refactored out later |

## Decisions log (owner-reviewed 2026-06-12)

- **Bare-sandbox policy default:** allow-all until a policy is declared, then
  default-deny; projects always default-deny. Future shape: sbx-style policy
  **presets at create** (open/balanced/closed) — postponed post-release, no
  credible "balanced" artifact exists yet.
- **Policy mutability:** static + `izba project reload` (new flows only); no
  runtime policy API.
- **UDP beyond DNS:** deny (drop + log). Revisit only on a concrete need.
- **M0 posture:** untimeboxed hard gate; plan-B is a self-built pinned
  OpenVMM fork.
- **izbad restart semantics:** severed flows accepted + documented; no drain.
- **Performance:** measured baseline in the suite; no gate.
- **MITM posture:** intercept everything; L7 policy (URL/method/body);
  injection for arbitrary endpoints; cert-pinning clients knowingly broken.

## Open decisions (resolve in working sessions, not ad hoc)

- **Manifest grammar finalization** (design §9): exact key names, `volumes`
  lifecycle verbs (create/resize/prune), schema **versioning from day one** —
  now also carries the M5 credential-mapping grammar (role + destination
  pattern → secret + injection shape).
- **Hardcoded external-UDP-resolver DNS** (forum: before M3/M4 docker-in-VM
  work). The M1 `udp dport 53` REDIRECT reply path is broken (source-mismatch;
  see risk #3). Decide the `IP_ORIGDSTADDR`/`IP_PKTINFO` transparent-reply fix
  vs. an alternative before docker-in-VM lands, since dockerd strips loopback
  resolvers from container `resolv.conf` and falls back to `8.8.8.8`.

## Explicitly not on this roadmap

Org-level / cross-project control plane, non-TCP fidelity (raw sockets / ICMP /
arbitrary UDP), snapshot/resume of a project, erofs layer dedup **across
members**, and a docker-enabled convenience base image (a future nicety,
never a requirement). All noted in the vision's "not yet" list.
