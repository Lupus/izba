# izba — product North Star

> This is the durable steering doc: *what* izba is becoming and *why*. It
> changes rarely. Technical "how" lives in the dated design specs under
> [superpowers/specs/](superpowers/specs/); the nearest-term architecture for
> the direction below is
> [2026-06-12-izba-mesh-networking-design.md](superpowers/specs/2026-06-12-izba-mesh-networking-design.md).

## One line

**Docker Compose on steroids: microVM-isolated, microsegmented, policy-governed,
and audited — purpose-built for running autonomous agents.**

## The shape

izba v1 is a single per-project microVM sandbox for an AI coding agent. The
product izba is *becoming* is a step up the abstraction ladder: a **project** is
a *set* of microVMs — the agent plus the stateful services it depends on (MCP
servers, databases, tool backends) — wired together by a host-side daemon
(`izbad`) that is the only path between them.

Mentally:

- **docker-compose-for-microVMs** — you declare a set of services; each runs in
  its own hardware-isolated microVM instead of a shared-kernel container.
- **+ a service mesh** — there is *no* network between the VMs. They are islands
  connected only by vsock to the host. `izbad` brokers every flow, so
  default-deny is the physical default and connectivity is the audited
  exception.
- **+ a per-service credential vault** — secrets never enter a guest. `izbad`
  injects the right credential, scoped to the right destination, on the way out,
  per service role. The agent's Anthropic key, the MCP's own LLM key, and the
  database's egress are independently scoped and metered.

For the agentic world this is the missing substrate: you can hand an autonomous
agent a real, capable environment (a whole stack of services) while keeping a
hard, observable boundary around *what each part is allowed to reach*.

## Locked product decisions

These are settled steering decisions. Rationale and mechanics are in the design
spec; this list is the "don't relitigate" set.

1. **Per-trust-domain microVM granularity.** The unit of isolation and
   governance is the *trust boundary*, not the process or the service. A stack
   of mutually-trusting services (e.g. graphiti + its neo4j) shares one microVM;
   the agent that consumes it lives in another. Governance happens at the
   boundary that matters — the agent reaches the MCP's endpoint and nothing
   else; the database isn't even addressable to it.

2. **In-VM orchestration is the guest's own docker compose — we leverage, not
   reimplement.** A trust domain that is itself a multi-service stack is just *a
   VM that runs a compose project*: izba boots the microVM, the guest's own
   `dockerd` + `docker compose up` brings the stack up (the compose project rides
   in over the existing `/workspace` share). So much dev software already ships
   as compose for quick deployment that fighting it to reimplement orchestration
   is wasted effort and an unwanted dependency. We do **not** adopt a host-side
   container engine and do **not** orchestrate inner containers.
   **Your image, your rules:** izba mandates no base image and no in-guest
   layout; a member that wants nested containers brings its own `dockerd`. (A
   no-friction docker-enabled base is a possible future *convenience*, never a
   requirement.)

3. **The izba project manifest is the single host-side declaration surface.**
   Loosely modeled on docker compose, it defines the member VMs, their start
   order + readiness, the one `service:port` each exposes to the mesh, and the
   east–west + north–south network policy for every member. izbad reads this; it
   never reads a member's in-guest compose. The izba↔member contract is just a
   port. The same manifest carries per-member resources and **user-configurable
   persistent block devices** (bring your own volumes — e.g. a sized
   `/var/lib/docker`), so members are right-sized for real workloads. This is
   what makes izba **flexible but secure-by-default**: bring any image and any
   storage you like, but nothing is reachable unless the manifest declares it.

4. **`izbad` is the policy enforcement point.** All egress (north–south, to the
   internet) and all inter-service traffic (east–west) transits the host daemon
   over vsock. One enforcement point, two policy planes (egress allow-lists +
   an east–west adjacency matrix), default-deny on both, with a built-in audit
   log of every brokered connection.

5. **Drop dependencies that only add surface.** We do not embed OpenVMM as a
   library, do not run a host bridge / SDN, and do not carry per-platform NAT
   backends (passt/consomme) into the egress path. The vsock-hub model gives us
   one networking story identical on Linux and Windows with fewer moving parts —
   *and* it is the natural insertion point for the MITM/credential layer, so the
   security feature and the simplification are the same piece of work.

## Why this is defensible

- **Isolation is structural, not configured.** Competing "agent sandbox"
  approaches layer firewall rules on top of a shared network and hope the rules
  are complete. Here there is nothing to misconfigure: a flow that `izbad`
  didn't broker physically cannot happen.
- **Credentials never touch the agent.** The agent operates with capability, not
  secrets — it holds a placeholder while `izbad` injects the real credential per
  destination. This capability-not-secrets model is the pattern NVIDIA OpenShell
  ships (and that the agent-sandbox category converged on); izba generalizes it
  to a whole service graph with per-role scoping.
- **Everything is observable.** Because every flow transits one daemon, the
  audit log is free — full north–south and east–west visibility without
  in-guest agents or eBPF.

## What this is not (yet)

Org-level / cross-project governance (a central policy control plane many
projects subscribe to), non-TCP fidelity (raw sockets / ICMP / arbitrary UDP —
deliberately denied by default), and snapshot/resume of a whole project are
explicitly beyond this horizon. They are notes for later, not commitments.
