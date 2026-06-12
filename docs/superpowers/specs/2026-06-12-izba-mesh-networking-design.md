# izba mesh networking — v2 design (decisions + rationale)

Status: **direction approved, details open.** This spec captures the agreed
architecture for izba's networking past v1 and the extension of a "sandbox" into
a governed *set* of sandboxes. Product framing and the locked steering decisions
live in [../../vision.md](../../vision.md); this doc is the technical "how" and
the open questions. Several sub-areas are deliberately left as open sections for
a future working session (flagged **OPEN** inline).

Grounding research that produced this design (2026-06-12): how the sbx agent
sandbox structures networking, a full inventory of izba's current networking
touchpoints, the real state of
OpenVMM-as-a-library + the `consomme` crate, and the Rust userspace-netstack
landscape.

---

## 1. Problem

Two pressures converge.

**(a) The host-autodetect bug class.** izba delegates guest NAT to a component
that *inspects the host network environment and guesses*: passt copies the first
default route's interface (broke on WSL + VPN dual default routes, fixed by
pinning a static subnet, `ea9e413`); consomme advertises IPv6 whenever the host
has any non-link-local v6 address (broke on a Tailscale ULA with no v6 route,
worked around with `izba.ipv4only=1`, `30e5c67`). These are the same bug in two
costumes. Every host topology we haven't seen is a new way for the guess to be
wrong. The list will keep growing until we stop guessing.

**(b) Multi-sandbox governance.** We want a "sandbox" to become a *project*: an
agent microVM plus stateful service microVMs (MCP servers, databases), each with
its own egress firewall rules, plus governance of which service may talk to
which. See [../../vision.md](../../vision.md).

Both pressures resolve to the same answer: **stop delegating connectivity to a
host-environment-sensing NAT, and make `izbad` own it.** Owning egress fixes (a)
because there is no host environment to misread; owning the inter-VM path makes
(b) a microsegmented mesh by construction.

## 2. Core architecture — `izbad` as the vsock mesh hub

There is **no L2 network anywhere** — not between the guest and the internet, not
between guests. Each microVM is an island whose only connection is vsock to the
host. `izbad` is the sole router and policy enforcement point. This single idea
serves both north–south (internet egress) and east–west (inter-service) traffic.

```
   ┌─ agent VM ──────┐         ┌─ host: izbad ─────────────────┐        ┌─ graphiti VM ──┐
   │ app dials       │  vsock  │  policy engine (PEP)          │  vsock │ graphiti :8000 │
   │ graphiti:8000   │────────►│  ├ name resolver (DNS)        │───────►│ (loopback)     │
   │  → REDIRECT     │ TcpConn │  ├ egress allow-list (N-S)    │ TcpDial│ neo4j :7687    │
   │  → egress stub  │         │  ├ adjacency matrix  (E-W)    │        │ (loopback,     │
   │                 │  vsock  │  ├ credential vault (MITM)    │        │  not exposed)  │
   │ app dials       │────────►│  └ audit log                  │───────►│  internet via  │
   │ api.anthropic   │ TcpConn │                               │  dial  │  izbad only    │
   └─────────────────┘         └───────────────────────────────┘  out  └────────────────┘
```

### 2.1 North–south (egress) datapath

Mirror of izba's existing **port-publish** path, in the opposite direction.

- Guest: a small **egress stub** (in izba-init) receives outbound TCP via
  `nft`/iptables `REDIRECT`, recovers the original destination with
  `SO_ORIGINAL_DST`, and opens one vsock stream per flow carrying a new
  `StreamOpen::TcpConnect{ addr, port }` — the exact mirror of today's
  `StreamOpen::TcpDial{ port }`.
- `izbad`: terminates the stream, applies the egress allow-list (and later the
  MITM/credential branch), and dials out from the host.
- DNS (:53) is intercepted the same way and answered by `izbad`'s resolver —
  which is also how intra-project names resolve (§3.2).

This retires passt and consomme from the egress path entirely. The guest needs
no real NIC: a static private IP on a dummy interface plus a default route into
the stub is enough (we already pin a static subnet for passt today). The whole
host-autodetect bug class disappears because `izbad` *defines* connectivity
instead of inferring it.

### 2.2 East–west (inter-service) datapath — already half-built

An east–west connection decomposes into two halves we already have or are
already building:

| Half | Who | Mechanism | Status |
| --- | --- | --- | --- |
| Caller (agent) | client VM | egress stub → `StreamOpen::TcpConnect` | new (same stub as §2.1) |
| Callee (graphiti) | server VM | `StreamOpen::TcpDial{port}` → dial `127.0.0.1:port` in-guest | **exists** (the `izba port` ingress handler) |

So east–west = the §2.1 egress stub on the caller + the **existing** port-publish
ingress handler on the callee, **brokered and policy-checked by `izbad` in the
middle**. `izbad` takes a stream that arrived on the agent's vsock and opens a
stream on graphiti's vsock — no cross-VM vsock CIDs, no bridge; `izbad` is the
bridge. The callee needs no new guest code to be a server; it listens on
loopback.

### 2.3 Why this is structurally default-deny

In an L2/bridged world every VM is reachable until a firewall rule blocks it, and
isolation is only as good as the rule set. Here the inverse holds: agent-A
*cannot* reach neo4j unless `izbad` chooses to splice a stream. Microsegmentation
is not a policy layered on a network — it is the *absence* of a network plus
explicit, audited exceptions.

## 3. The project / group object model

A new top-level abstraction sits above `sandbox`: a **project** (a.k.a. group/pod)
— a named set of member VMs, each a trust domain with a **role**, declared by a
single **compose-shaped manifest** (§3.3). It extends the existing disk-state
invariant: a project = a directory + its member sandboxes + the manifest, and
`izbad` adopts projects from disk exactly as it adopts sandboxes today (no
authoritative daemon state).

The manifest is **the single host-side declaration surface** — members, start
order/readiness, the one `service:port` each exposes to the mesh, and both policy
planes (§4). `izbad` reads only this; it **never** reads a member's *in-guest*
compose (§6). The izba↔member contract is just a port number, which is exactly
why an in-guest compose label could not have carried mesh metadata outward — the
guest is an opaque island to `izbad` by design, so the declaration lives on the
host.

### 3.1 Lifecycle

Stateful members (neo4j/graphiti) are **long-lived and persistent**; agent
members are **ephemeral and churn**. The "never auto-restart, adopt from disk,
persistent rw disk" model already supports long-lived members; the project layer
adds bring-up ordering (stateful members first, then agents attach to the
project's mesh).

### 3.2 Naming / discovery

Because DNS already transits `izbad`, intra-project name resolution is free:
`izbad` answers member names with synthetic IPs it then routes to the owning
member. Each guest gets a project-scoped view (its `/etc/hosts` or a DNS view) so
apps address members by name.

**Name scheme (locked) — least surprise = compose's model:**

- **Primary: bare member name** (`http://graphiti:8000`), exactly like docker
  compose, since members are declared in `izba.yaml` like compose services. This
  is the muscle memory users already have.
- **Reserved `.izba` TLD as the explicit FQDN escape hatch:** `graphiti.izba`
  always means "the project member," is never forwarded to public DNS, and lets a
  member still reach a real external `graphiti.com` by its true name. `izbad`
  resolves member names + `*.izba` locally and forwards everything else upstream
  (through its own brokered egress).

A member declares the port it exposes to the mesh in the manifest (§3.3), **not**
in-guest — resolving the earlier open question.

### 3.3 The project manifest (compose-shaped)

The manifest is **`izba.yaml`** (locked) at the project root. Loosely modeled on
docker compose so it is instantly familiar, but each top-level entry is a **VM /
trust domain**, not a container. Illustrative shape (key names not final):

```yaml
project: research-agent

vms:                          # each entry = one microVM (trust domain)
  agent:
    image: ghcr.io/acme/agent:latest    # or build: ./agent
    resources: { cpus: 4, memory: 8g }  # per-member sizing
    # the agent's own environment; no exposed mesh port (it's a client)

  graphiti:
    compose: ./graphiti        # YOUR compose project, brought up by the guest's
                               # own dockerd — izba never parses it
    expose: 8000               # the ONE loopback port offered to the mesh
    resources: { cpus: 8, memory: 16g }
    volumes:                   # user-declared PERSISTENT block devices
      - { size: 100g, mount: /var/lib/docker }   # docker image/container state
      - { size: 50g,  mount: /data/neo4j }       # the stack's own data
    depends_on: [neo4j]        # izba-level member start ordering
    healthcheck:               # izba-level member-readiness gate (§6)
      http: http://localhost:8000/health   # or: port: 8000 | exec: ["..."]
      interval: 2s
      retries: 30

policy:
  east_west:                   # adjacency matrix; default-deny otherwise
    - from: agent
      to: graphiti:8000
  north_south:                 # per-member egress allow-list; default-deny
    agent:
      allow: [api.anthropic.com:443, github.com:443]
    graphiti:
      allow: [api.openai.com:443]     # graphiti's OWN scoped LLM key, agent never sees it
```

Notes / decisions baked in:

- **`vms:` not `services:`** to avoid colliding with the *inner* compose's
  `services:` — an izba VM may itself contain a multi-service compose stack.
- **`expose:` is the single mesh endpoint**, published by the member on its guest
  loopback; `izbad` reaches it via the existing `TcpDial` ingress (§2.2).
  Everything else in the member's inner compose (e.g. `neo4j`) is unaddressable
  from outside — internal to the trust domain.
- **`image:` vs `compose:` vs `build:`** — "your image, your rules": a member is a
  plain image (single workload) or a compose project (multi-service, brought up by
  the guest's own dockerd, §6). izba mandates no base image.
- **`healthcheck:` is compose-modeled and izba-level** — `http:`/`port:` are
  izba-native probes; `exec:` runs a user command *inside the guest* (izba doesn't
  care what it inspects — `docker compose ps`, a socket, anything). izba gates
  *member* readiness on this; the inner compose independently gates its own
  *container* readiness via its own `depends_on`/healthchecks. **Both levels, by
  design** (resolves the §6 open question).
- **`resources:` + user-declared `volumes:`** — per-member CPU/memory, and **any
  persistent block devices the user wants** (size + mount). This is needed up
  front, not deferred: a dockerd-in-VM needs real room for image layers +
  container state (a dockerd-in-VM needs a dedicated docker-state volume for
  exactly this). See §3.4.
- **Policy is co-located** with the topology in the same file (§4), so a project's
  network governance is reviewable in one place. Absent any rule ⇒ denied.

### 3.4 Resources & persistent storage

Per-member `resources` map onto the driver's existing `--processors`/`--memory`
knobs. `volumes` are **user-configurable persistent block devices** — each becomes
an additional virtio-blk disk attached to that member's VM, formatted + mounted at
its declared path, and persisted in the member's sandbox dir across restarts
(same durability model as today's `rw.img`). This is a first-class need, not a
nicety: without a sized `/var/lib/docker` volume a compose stack of any weight
fills the default scratch disk.

**Contract interaction (must change all ends or none):** extra volumes extend the
disk enumeration past today's fixed `[rootfs.erofs=vda, rw.img=vdb]` order (the
load-bearing **Disk order** contract in `CLAUDE.md`), and on OpenVMM each disk
needs its own PCIe root port (the driver already routes per-disk to avoid VPCI
device-id collisions). The init mount plan must place user volumes *after* the
overlay roots so vda/vdb identity is preserved.

**OPEN:** exact key names/grammar; volume lifecycle verbs (create/resize/prune);
whether `volumes` can be shared between members (default: no — sharing a block
device breaks the island model; cross-member data goes over the brokered mesh).

## 4. Policy — two planes, one enforcement point

Both planes are declared in the project manifest (§3.3), enforce at `izbad` (the
only path for both), and both default-deny.

| Plane | Question | Mechanism |
| --- | --- | --- |
| North–south (egress) | Which external domains/ports may this member reach? | per-member `north_south.allow` list, enforced at dial-out (the sbx model) |
| East–west (governance) | Which member may initiate to which member:port? | the `east_west` adjacency list; `izbad` brokers only permitted edges |

Because every flow transits one daemon, the **audit log is free** — every
brokered connection tagged with source member, destination service, allow/deny.
This is full egress + east–west flow logging without any in-guest eBPF.

**Decided (2026-06-12, see [../../roadmap.md](../../roadmap.md) decisions log):**
policy is **static + reload verb** — `izba project reload` re-reads the manifest
and applies to new flows; no runtime policy API. **OPEN:** whether roles are
per-VM or can be finer; org-level / cross-project governance (a central control
plane `izbad` subscribes to) — noted as beyond this horizon in the vision doc.

## 5. Credentials — per-role vault at the MITM branch

`izbad` already receives, per flow, the original `(dst, port)` plus the byte
stream. The MITM is one branch before dial-out: for :443/:80, terminate TLS with
a leaf minted by an `izbad` CA (`rustls` + `rcgen`), do SNI-based service
detection + domain allow/deny, and inject **per-role** credentials outbound.
**Posture update (2026-06-12, roadmap M5):** intercept *everything* — no
passthrough-encrypted tier; policy is L7 (URL, method, body where practical);
injection targets arbitrary endpoints via manifest mapping, not a known-SaaS
shortlist; cert-pinning clients are knowingly broken under interception. The
agent's egress to `api.anthropic.com` gets the agent's key; graphiti's *own* LLM
calls get a different, scoped key the agent never sees (or are denied/metered
separately). Guest-side prerequisite is identical to sbx: bake the `izbad` CA
into each guest's trust store at boot (the same kind of step izba-init already
does for resolv.conf/hostname).

This is the v2 egress-proxy deliverable from the v1 spec §9 — the mesh just makes
the insertion point fall out of the architecture.

## 6. In-VM orchestration (per-trust-domain) — guest-owned docker compose

Granularity is **per-trust-domain** (locked, see vision §"Locked product
decisions"). For a trust domain that is itself a multi-service stack, izba
**boots the microVM and lets the guest's own docker engine + `docker compose`
bring the stack up** — izba does *not* orchestrate the inner containers and does
*not* adopt a host-side container engine. **Locked (2026-06-12).**

### 6.1 The three docker layers (why izba uses only one)

Docker can sit at up to three layers in a microVM agent sandbox; conflating them
is the trap this decision avoids:

1. **Host control-plane engine** — a host-side container engine that *creates
   and runs the sandbox VMs themselves*. The heavyweight path izba does not take.
2. **Guest-side container runtime** — a guest init that runs the sandbox's
   *workload container* (e.g. `crun` over a containerd Task API on vsock).
   Invisible infrastructure; no daemon you query.
3. **In-guest `dockerd`** — a full Docker daemon living in the sandbox *image's
   userland*, which is what answers `docker ps` after you exec and runs
   *nested* containers. Completely orthogonal to layers 1–2.

izba runs the workload **directly**: izba-init is PID 1, with no host-side
container engine and no layer-1/2 split to adopt. So for multi-service trust
domains we lean entirely on **layer 3**: a docker daemon inside the guest,
driven by the user's compose file. We deliberately skip layers 1–2.

### 6.2 Model — "a VM that runs this compose project"

A stateful member is defined by a **compose project** (a dir with
`docker-compose.yml` + build context) or a single image. Delivery is free: the
compose project rides in through the **existing `/workspace` virtiofs share**,
exactly like a normal project directory today. izba's only added jobs:

- **Run the member's stack** — **your image, your rules** (locked): the member's
  image ships its own `dockerd` and its entrypoint runs `docker compose up`. izba
  mandates **no** base image and no in-guest layout; it only requires that the
  member surface its mesh endpoint on the guest loopback port named by `expose:`
  (§3.3). A no-friction docker-enabled base image is a possible future
  *convenience*, never a requirement — this keeps izba flexible rather than
  opinionated like sbx.
- **Broker/govern the exposed port** named in the manifest (`expose:`), reached
  via the existing `TcpDial` ingress (§2.2). Everything else in the member's inner
  compose (e.g. neo4j) stays internal and is never addressable from outside —
  microsegmentation at the trust boundary, for free.

Rationale: a large amount of dev software already ships as compose for quick
deployment; fighting that to reimplement orchestration is wasted effort and a
dependency we don't want. Leverage it — izba boots VMs, the guest runs the user's
compose, and `izbad` brokers/governs the network. The agent member is the same
shape (its environment is an image/compose too).

Member readiness is the manifest `healthcheck:` (§3.3): `http:`/`port:` are
izba-native probes, `exec:` is a user command run in-guest — izba gates *member*
readiness on it while the inner compose gates its own *container* readiness
(both levels, resolved). VM sizing + persistent docker-state storage are the
manifest's `resources:`/`volumes:` (§3.4), tackled up front.

**OPEN (deferred):** image/layer reuse across members — a nice optimization (and
the erofs content-addressed store already shares layers across single sandboxes)
but explicitly postponed to a later iteration.

## 7. Rejected alternatives

- **Embed OpenVMM as a Rust library.** The OpenVMM Guide explicitly calls
  standalone/embedded use unsupported and points at Cloud Hypervisor; nothing is
  on crates.io — it's a git dep on a ~400-crate workspace tracking edition 2024 /
  Rust 1.95 with ~800 commits in six months, and `config::Config` / `ConsommeParams`
  (exactly what we'd consume) are among the churniest files. Disproportionate;
  rejected. (If consomme's IPv6 knob is ever the *only* need, a one-line upstream
  PR exposing `advertise_routable_ipv6`/`skip_ipv6_checks` on the CLI is the
  cheap fix — upstream PR #3701 already moves there — but we've already worked
  around it guest-side.)

- **One L2 netstack inside `izbad`, shared via raw frames.** Breaks on Windows:
  there is **no way to get ethernet frames out of `openvmm.exe`** into an
  external process (its net backends read guest physical memory directly;
  vhost-user is Linux-only and structurally impossible on Windows — no
  `SCM_RIGHTS`, no eventfd, no shareable guest-RAM memfd). The only symmetric
  variant is L2-over-vsock (the gvisor-tap-vsock model), which makes the open
  OpenVMM vsock-assert crash load-bearing for *all* traffic and is a from-scratch
  Rust netstack (nothing reusable: gvisor-tap-vsock is Go; `consomme` is
  MIT/cross-platform but drags the whole openvmm git-dep tree and *is* the SLAAC
  code that bit us). Its only advantage — full UDP/ICMP fidelity — is something an
  agent sandbox mostly wants to *deny*. Rejected as the primary path; revisit
  only if a concrete need for non-TCP fidelity appears.

- **Host bridge / SDN with per-VM firewall rules.** Reintroduces exactly the
  host-environment heuristics we're escaping, diverges the platforms (no bridge
  story on Windows/OpenVMM), and makes isolation a rule set you must get
  perfectly right. The vsock hub gives default-deny for free. Rejected.

## 8. Complexity & staging

All additions are **host-side, in `izbad`** — no new VMM or per-platform work —
except the guest egress stub. Multi-container per trust domain needs *no* izba
work: it's the guest's own dockerd/compose (§6).

0. **Prerequisite — fix the OpenVMM vsock-assert crash first.** This design puts
   *all* traffic on many short-lived vsock streams — precisely the churn that
   trips `virtio_vsock connections.rs:1093` and panics the VM (reproduced via
   `ttystorm floodfast`). Mitigation already identified: graceful `shutdown(Write)`
   + drain instead of abrupt drop. **Hard gate.**
1. **`StreamOpen::TcpConnect`** in izba-proto + the `izbad` splice + host
   dial-out. Small; mirror of `TcpDial`. Can coexist with passt/consomme
   initially (opt-in) to de-risk.
2. **Guest egress stub + transparent REDIRECT + DNS interception** in izba-init.
   The real new guest work (`nft` rules, `SO_ORIGINAL_DST`, DNS path). We control
   the kernel config, so adding the netfilter bits is straightforward.
3. **Flip the default route through the stub; retire passt/consomme egress.**
   Optionally remove virtio-net.
4. **Project object + manifest** (compose-shaped parse, disk layout, adoption,
   member lifecycle/readiness) + **intra-project name resolution** + **east–west
   brokering** (route name→member; reuse TcpConnect + existing TcpDial).
5. **Policy engine** (manifest-driven, PEP, default-deny both planes, audit log).
6. **Per-role credential vault / MITM** (CA mint + inject + allow/deny) — the v2
   egress-proxy deliverable.

Steps 1–3 unify networking and kill the bug class; 4–5 deliver the mesh +
governance; 6 is the credential vault. Multi-service trust domains require no izba
step — the guest's own compose handles it (§6).

**Independent of the above:** per-member `resources:` + user-configurable
persistent `volumes:` (§3.4) are VM-local — they don't depend on the mesh and can
land early (even for single sandboxes today), since a dockerd-in-VM needs the
sized docker-state volume regardless of when the mesh ships. Touches the
**Disk order** contract, so it's a "change all ends" item (driver disk
enumeration + OpenVMM PCIe routing + init mount plan).

## 9. Open sections (for the next working session)

- **KVM/passt vs OpenVMM/consomme datapath details** during the transition —
  exactly how the dummy-NIC + REDIRECT guest config differs (if at all) per
  driver, and the cutover sequence per platform.
- **Manifest grammar finalization** (§3.3 — exact key names; `volumes` lifecycle
  verbs) and **org-level governance** (§4 OPEN). Filename, DNS name scheme,
  readiness contract, and resources/volumes are now decided.
- ~~**UDP handling** beyond DNS name resolution~~ — **decided 2026-06-12:
  deny all non-DNS UDP** (drop + log); revisit only on a concrete need.
- **Image/layer reuse across members** (§6 — deferred to a later iteration).
