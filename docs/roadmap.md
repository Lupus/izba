# izba roadmap

> Product roadmap toward the [vision](vision.md) ("compose-for-microVMs +
> service mesh + credential vault"). Technical rationale lives in the
> [mesh networking design](superpowers/specs/2026-06-12-izba-mesh-networking-design.md)
> (its §8 staging is the engineering skeleton this roadmap re-cuts into
> user-value milestones). Updated **2026-06-18**.

## Where we are

v1 is **done and daemon-first** on both platforms: per-project microVM
sandboxes with lifecycle, `exec -it`, `cp`, port publishing, OCI→erofs images,
and `izbad` (disk-state adoption, stream splicing, upgrade dance). Linux/KVM
via Cloud Hypervisor and Windows/WHP via OpenVMM both pass their gates.

**M0–M3 are all done and merged to `main`:**

- **M1 — one network story** (2026-06-13): all guest egress — TCP and DNS —
  flows through izbad over guest-initiated vsock streams; the guest is a
  NIC-less vsock island and passt/consomme/`izba.ipv4only` are gone.
- **M2 — agent firewall** (+ M2.1): MITM L7 (now a hyper-util h1+h2+WebSocket
  service, classified by wire peek not port) + port-aware allow-list +
  DNS-snoop + `izba netlog`, plus the interactive `izba policy show/allow/block/
  enable/reload` surface and the app's Netlog/Policy tabs.
- **M3 — sized & stateful sandboxes**: per-member `resources` *and*
  user-declared **persistent + ephemeral volumes** shipped (PR #19), with
  KVM + WHP volume persistence/reattach/prune coverage. The Disk-order contract
  change landed all-ends in one milestone.

**A security-assurance program now exists and is actively burning down**
(Track S, new): threat model + methodology + a findings register (F-01..F-26)
on `main`, and the first wave of fixes merged — egress SSRF + MITM bypasses
(F-01/F-02/F-03), Windows VMM confinement (F-06), host-side `cp` tar
containment (F-08), 0700 data dirs (F-15), cargo-deny supply-chain gate (F-22),
CH path-comma rejection (F-24). DNS also hardened: a self-healing
`SystemResolver` with live config reload (supersedes the start-time-captured
forwarder), DNS-over-TCP for >512-byte answers, and metric-ordered Windows
upstream selection.

**Adoption infrastructure (Track T) is largely in place**: CI six gates +
real-VM e2e, published artifacts, coverage + SonarCloud gates, build-version
reporting, on-demand devbuild installers. **The first real release tag is held
back deliberately** — `v0.1.0-rc1`/`-dev1` were validation prereleases; rather
than tag at M2/M3, the tag now follows the **MVP bundle** below (fine-grained
policy + real host confinement + verified ports/volumes), so the first release
is a defensible product, not a demo.

What does **not** exist yet:

- The mesh/governance staging steps beyond the firewall — no `izba.yaml`
  manifest, no project object, no east–west mesh, no credential vault (M4/M5).
- A few security findings remain open — the two open **HIGH**s are **F-06
  (Linux half)** (unjailed VMM + virtiofsd as the full host user, = MVP-C) and
  **F-07** (virtiofsd `--sandbox none`), plus F-09 (no izbad peer-cred) and
  F-05 (DNS resolve-and-pin, now unblocked by the hickory adoption). See
  Track S.

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
quarters. Order is dependency order. **M0–M3 are done.** The **MVP bundle**
(MVP-A..D, below) is next and gates the first release tag; **M4** follows the
tag. Track S (security hardening) and Track T (adoption) run continuously
alongside.

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

### M3 — Sized & stateful sandboxes: resources + volumes (M) — ✅ DONE (2026-06-15)

Per-sandbox `resources` (cpus/memory) ship (CLI → daemon → both drivers'
memory/processor knobs) and **user-declared block devices** landed (PR #19,
design §3.4, spec
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

**Exit — met:** `izba run --volume` + `izba volume prune` shipped; KVM volume
persistence/reattach/prune tests + a WHP parity case are in-tree (PR `test(m3)`).
Risk #5 (disk-order contract ripple) is **retired** — the contract change is in
and both platform gates are green. **Not yet exercised:** a full in-guest docker
compose stack on a sized `/var/lib/docker` volume — that lands as part of M4's
docker-in-VM bring-up (and is gated on the hardcoded-external-UDP-resolver DNS
fix; see risk #3).

### MVP bundle — production-ready single sandbox (pre-tag) — ⏭️ NEXT

Decided 2026-06-18 (owner). Before the first release tag and before M4, ship the
cut that makes **one** sandbox genuinely defensible and genuinely usable — a real
product, not a demo: fine-grained egress control, host confinement that actually
contains a hostile guest on **both** platforms, and the half-built features made
real in the UI and owner-verified. **First tag follows this bundle; M4 follows
the tag.** Four sub-projects, each specced separately (the owner runs a
dedicated session per piece). They touch different subsystems and largely run
**in parallel**; the only ordering constraints are the two spikes called out
below.

```
   ┌─ MVP-A  L7 git-aware egress policy ──────────────┐
   ├─ MVP-B  ports + volumes: UI wiring + e2e verify ─┤
   │                                                   ├──▶ first tag ──▶ M4
   ├─ MVP-C  Linux host confinement ──────────────────┤
   │   (scope-gated by WSL2-userns spike)              │
   └─ MVP-D  Windows per-sandbox identity ────────────┘
       (build-gated by WHP-under-account spike)
```

**MVP-A — L7 git-aware egress policy (S–M).** The headline differentiator and
the smallest effort, because the engine already exists: the hyper-util MITM
service already passes `{host, method, path}` into regorus (`mitm.rs:587/652`,
`mitm_runtime.rs:95`, `policy.rs:131`); only the user-facing grammar (`AllowEntry`
is host+ports only) and the rego rules need extending. Reference design: the
owner's `Lupus/docker-mitm-bridge` (`opa-policies/policy.rego` + `data.yml`) —
`allowed_domains` (GET/HEAD), `unrestricted_domains` (all methods), and
git-smart-HTTP read/write detection (`/info/refs?service=git-upload-pack` vs
`git-receive-pack`, parse `user/repo` from path). **Must NOT hard-marry GitHub** —
the grammar must generalize to gitlab/bitbucket/any HTTP git endpoint (host +
operation + repo-pattern, not a github-only branch). izba additions: pass the
**query string** into the rego `input` (needed for `service=`); the owner's PoC
rego was "short-sighted" and gets reworked. **Research first (owner ask):**
security/UX/best-practices for the rego + `data.yml` shape, and how L7 "smart
firewalls" organize allow/deny rules UX-wise — to structure the grammar so the
**YAML editor, the block/unblock buttons, and the netlog tab all click together**
(this overlaps the in-flight app-UX work). **Consolidation/bug debt to fold in**
(on `main` the policy is already single-source; these are the residual smells):
the default-ports `[80,443]` triple-literal (config.rs:43 / router.rs:121 /
egress_data.json — drift = silent tier-1 bypass) → one constant; remove or
activate the inert `_upstream_tiers_for_M5` rego stub so M5 doesn't fork a second
rego; make the empty-vs-missing `policy.yaml` semantics explicit. **Sets up M5**
(same path-scoping mechanism the credential vault needs).

**MVP-B — ports + volumes: UI wiring + end-to-end verification (M).** The CLI +
daemon + driver sides shipped (M3 volumes; `izba port` relays) but neither is
wired into the desktop app, and **neither was owner-verified end-to-end on a real
build**. Wire ports publishing and volume management into the app (create wizard +
management views), then the owner runs a real devbuild and confirms both flows
work. Closes the "built but not real / not verified" debt. Shares the app surface
with MVP-A's policy-UX work — coordinate to avoid app-tab conflicts.

**MVP-C — Linux host confinement (M–L).** Today the Linux side is **bare**:
cloud-hypervisor + virtiofsd launch with no `--seccomp`, no `--landlock`,
virtiofsd `--sandbox none`, running as the full host user (only `setsid()`). This
is the open Linux half of F-06 + all of F-07 (see Track S). Stage it: **built-ins
first** (confirm/pin CH's seccomp, add `--landlock` for filesystem scoping,
switch virtiofsd to `--sandbox chroot`/namespace), then the optional **per-sandbox
uid jailer** (dedicated uid/gid + cgroups — the Linux mirror of MVP-D's dedicated
principal). **Spike first:** the WSL2 unprivileged-user-namespace constraint (the
same `apparmor_restrict_unprivileged_userns` that bit passt) determines how far
the namespace/jailer path can go and whether a sysctl is a hard requirement.

**MVP-D — Windows per-sandbox identity confinement (L).** The owner's model: a
dedicated local **account** per sandbox, ACL-granting it only that sandbox's
resources, running the VMM as it; a **"lock down" button (UAC shield)** that
prompts elevation to create the identity, and tears it down on `rm` or "unlock."
This **layers on top of** the existing restricted-token + Low-IL + job confinement
(PR #37, F-06-Windows) as an opt-in *elevation* — the strongest tier: a sandbox
that is a distinct security principal owning nothing by default. **Build-gated by
a spike:** does WHP (`WHvCreatePartition`) actually work when the VMM runs as a
separate standard local account? (The prior probe showed WHP denied in
AppContainer but fine under restricted-token+Low-IL — a dedicated account is an
untested third case.) If WHP needs the interactive user's context, the model
needs rethinking before any build.

### M4 — Projects: izba.yaml + lifecycle + mesh (L) — after the MVP bundle + first tag

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

### Track S — Security hardening (continuous, since 2026-06-15)

The security-assurance program (`docs/security/`: threat model, methodology,
findings register F-01..F-26) is now live and is a standing track — izba's whole
pitch is a *hostile-guest* sandbox, so the findings burn-down is product work,
not cleanup. **Fixed + merged:** F-01/F-02/F-03 (egress SSRF floor + MITM
SNI/Host/keep-alive bypasses), F-06 (Windows VMM confinement), F-08 (host-side
`cp` tar containment), F-15 (0700 data dirs), F-22 (cargo-deny gate), F-24 (CH
path-comma reject). **Still open — the near-term floor:**

- **Linux host confinement epic (= MVP-C).** The whole host-side Linux
  confinement is missing, so the register is widened from the two atomic findings
  to an epic: **F-06 (Linux half, HIGH — still open)** unjailed VMM + virtiofsd
  as the full host user; **F-07 (HIGH)** virtiofsd `--sandbox none`; plus new
  sub-findings **F-27** host-process privilege drop / dedicated uid+gid, **F-28**
  cgroup resource bounding, **F-29** landlock/seccomp filesystem confinement.
  Built-ins first, then a per-uid jailer (see MVP-C; numbers tentative until
  written into the register).
- **Windows host confinement epic.** F-06-Windows is **done** (PR #37: restricted
  token + Low IL + job + mitigations). The dedicated-identity model (MVP-D) is a
  *hardening enhancement* beyond the finding — the next confinement tier, not a
  new gap.
- **F-09 (MED):** izbad's AF_UNIX control socket has no `SO_PEERCRED` check —
  any local process gets full sandbox control. Cheap, high-value; good to land
  alongside the MVP confinement work.
- **F-05 (MED):** DNS resolve-and-pin + QNAME-gate + rate-limit. **Now
  unblocked** by the hickory-resolver adoption (the two DNS efforts no longer
  collide); context stub in `docs/security/egress-firewall-p3-dns-resolve-and-pin.md`.
  Pairs naturally with M4's hardcoded-external-UDP-resolver fix (risk #3).
- The remaining mediums/lows (F-04/F-10/F-12/F-13/F-17/F-23, F-16/F-18/F-25)
  batch into a later pass. **Owed across the board:** PoCs for the HIGH
  guest→host leads + deterministic gates (cargo-fuzz under ASan for the codec/
  dns/tar parsers, cargo-mutants).

### Track T — Adoption & release engineering (continuous)

Runs parallel to everything; first slice landed during M0/M1.

- **CI for the six gates** (fmt, clippy×2, test, musl init, win cross-check) —
  **done**, plus real-VM e2e, coverage + SonarCloud gates, build-version
  reporting, on-demand devbuild installers.
- **Published kernel + initramfs artifacts** — **done** (CI artifact jobs).
- **Versioned releases** with prebuilt binaries (Linux + Windows) — **the open
  item, now gated behind the MVP bundle.** `v0.1.0-rc1`/`-dev1` were validation
  prereleases; the first real tag follows MVP-A..D so the release ships
  fine-grained policy + real host confinement + verified ports/volumes (see
  Next steps).
- **Quickstart that works from a clean machine**, refreshed each milestone;
  `izba.yaml` reference when M4 lands.

## Next steps (groomed 2026-06-18)

The MVP bundle (above) is the next focus and **redefines the first release** —
M2+M3 plus fine-grained policy + real host confinement + verified ports/volumes,
*then* tag, *then* M4. The owner runs a dedicated session per sub-project; they
touch different subsystems and run **in parallel**, with two spikes as the only
hard gates:

1. **Kick off the two spikes first** (cheap, they gate scope/build):
   - **WHP-under-dedicated-account** (gates MVP-D's whole model).
   - **WSL2 unprivileged-userns** (gates how far MVP-C's namespace/jailer goes).
2. **Run MVP-A..D in parallel.** Recommended emphasis: **MVP-B** (ports/volumes
   UI + verify) is the cheapest and makes the product verifiable — good to land
   early. **MVP-A** (L7 git policy) is the headline — start with the rego/UX
   research and the vendor-neutral (not github-married) grammar. **MVP-C/D** are
   the security floor; build once their spikes clear. Coordinate MVP-A and MVP-B
   on the shared app surface (both touch the desktop app). Land **F-09**
   (izbad peer-cred) alongside the confinement work.
3. **Cut the first release tag** once the bundle lands — the installer/artifact
   pipeline already exists.
4. **M4 — Projects: `izba.yaml` + lifecycle + mesh (L) — the next headline build
   after the tag.** Begin with the **manifest-grammar working session** (the one
   open design decision; it now also carries M5's credential-mapping grammar) so
   M4 and M5 share one schema. Fold the **hardcoded-external-UDP-resolver DNS
   fix** (risk #3) in here — the docker-in-VM prerequisite, pairing with F-05.
   Consider cutting as 4a (project object + lifecycle) / 4b (mesh wiring).
5. **M5 — Credential vault (L) — after M4.** Depends on M4's manifest; MVP-A's
   path-scoped L7 mechanism is the same machinery, so it's already de-risked.

**Postpone / not now:** the remaining medium/low findings batch; presets
(open/balanced/closed) and org-level governance (explicitly off-roadmap). The
in-flight app UX papercuts (side branch `worktree-app-ux-improvements`) fold
into MVP-A/B's app work rather than standing alone.

## Risk register

Reviewed with the owner 2026-06-12; ★ = elevated (gets a written plan before
its milestone starts).

| # | Risk | Exposure | Mitigation |
| --- | --- | --- | --- |
| 1★ | OpenVMM vsock assert survives the graceful-shutdown fix | The whole roadmap blocked (M0 is untimeboxed, parity sacred) | **Plan B prepared up front:** patch the assert + self-build a pinned OpenVMM fork (same pinning shape as today's fetched binary); upstream issue filed in parallel |
| 2 | izbad is a traffic SPOF — restart/upgrade severs *all* flows, not just port relays | UX regression vs v1 | **Decided:** accepted + documented honest behavior, no drain logic (apps retry). Throughput: **measure, don't gate** — baseline number in the integration suite |
| 3 | DNS interception edge cases (resolver behaviors, search domains, TCP DNS) | M1 flakiness → M4 docker-in-VM blocker | Mostly closed: loopback resolv.conf + a self-healing `SystemResolver` with live config reload (replaced the start-time forwarder that went stale on VPN reconnect), DNS-over-TCP for >512-byte answers, metric-ordered Windows upstreams. **Still open — the one realized gap:** the `udp dport 53` REDIRECT *reply* path doesn't work (stub's wildcard-socket source mismatches; conntrack never un-NATs), so apps hardcoding an external UDP resolver get no answer. Mitigation today: resolv.conf points at loopback. **This is the docker-in-VM prerequisite** (dockerd strips loopback resolvers, falls back to `8.8.8.8`) — fold the `IP_ORIGDSTADDR` transparent-reply fix into M4, paired with F-05 |
| 4 | MITM datapath risk: cert-pinning breakage, h2/websocket, the vsock↔tokio bridge, OpenVMM churn under the hop | Was the largest part of M2 | **Retired.** M2 shipped and the datapath was since rebuilt on a hyper-util h1+h2+WebSocket service (PR #32), with the SSRF floor + SNI/Host bypasses closed (F-01/02/03). Pinning breakage = accepted posture. Bridge churn invariant held under the integration gates |
| 5★ | Disk-order contract change ripples (M3) across driver enum, OpenVMM PCIe routing, init mount plan | Subtle cross-platform boot breakage | **Retired.** Contract change landed all-ends in M3; KVM + WHP volume tests green |
| 6★ | izbad scope creep (router + DNS + policy + MITM + vault in one binary) | Maintainability | **Holding.** Module seams from the M1 design doc held through M2's MITM + DNS rewrites (separable planes, daemon proto as the seam). Re-check before M4 folds in the mesh plane + M5 the vault |

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
