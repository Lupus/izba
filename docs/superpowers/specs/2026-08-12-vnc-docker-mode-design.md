# VNC × docker mode + VNC sprint cleanups — design

**Date:** 2026-08-12
**Status:** approved
**Issues:** #216 (docker+vnc), #221 (relay port collision), #219 (coverage
staging), #220 (tcp_dial test flake)
**Prior specs:** `2026-08-09-vnc-display-design.md` (VNC v1),
`2026-08-11-vnc-desktop-environment-design.md` (LXDE-lite session),
`2026-08-09-docker-uid-fidelity-design.md` (docker-mode netns/idmap).

One PR, four items. Item 1 is the feature; 2–4 are small VNC-subsystem
cleanups that ride along.

## 1. #216 — docker+vnc via wildcard bind

### Problem

A docker-mode sandbox gives the workload container its OWN network namespace
(docker uid-fidelity spec §3); every other sandbox shares init's. KasmVNC is
`crun exec`'d inside the container, so its `-interface 127.0.0.1` listener
lands on the CONTAINER's private loopback. Init's `server::tcp_dial` first
dials its own `127.0.0.1:6901` (nothing there), then falls back to
`net::GUEST_IP` = `192.168.127.2` (the container's veth address) — where
nothing is bound either. Relay and liveness probe both fail: a silently dead
URL. PR #215 therefore shipped `--docker --vnc` refused loudly at four gates.

### Decision: bind the wildcard address in docker mode

`izba-init`'s `vnc::desktop_exec_argvs` gains a `docker: bool` parameter
(threaded from `main.rs`, which already holds the flag at the
`vnc::start_desktop()` call site). In docker mode the X server binds
`-interface 0.0.0.0`. A guard test (the `egress::output_chain(false)`
pattern) asserts the two modes' argvs differ **only** in the `-interface`
value — the RFB-listener hardening below, if needed, lands in both modes, so
"docker off" never silently drifts from the shipped behavior beyond that one
deliberate flag.

Why wildcard and not the alternatives:

- **`-interface 192.168.127.2`** races `veth::apply`: the address does not
  exist in the container netns until after crun reports `running` and init
  applies the veth pair — the same window in which the X server is spawned.
  A bind to a not-yet-present address fails; wildcard has no such race. And
  it buys nothing: nested containers reach a local address either way.
- **An init-owned forwarder in the container netns** (loopback bind kept,
  extra process bridging veth→loopback) is another fire-and-forget process
  to keep honest, for no security gain over wildcard in a netns that only
  contains this sandbox's own workload.

Exposure analysis: the container netns holds `lo`, `veth1` (peer is init) and
whatever bridges the nested engine creates. Everything that can reach a
wildcard listener there is *inside this sandbox* — the same trust zone that
already owns the display outright via `-ac` and the X socket. HTTP/ws stays
behind BasicAuth (`-KasmPasswordFile`) exactly as before.

### Listener-posture hardening (both modes)

`-SecurityTypes None` (load-bearing since PR #215 — see the vnc.rs doc
comment) makes any **raw RFB** TCP listener an unauthenticated desktop.
Xkasmvnc's TigerVNC heritage defaults an RFB listener to `5900 + display`
(`:5901` for display `:1`); today `-interface 127.0.0.1` masks the question,
wildcard un-masks it.

Implementation MUST:

1. Verify on a live VM what Xkasmvnc 1.5.0 actually listens on (`/proc/net/tcp`
   inside the container) — never guess flags (the compiled-in-path lesson,
   LXDE spec).
2. If a raw RFB listener exists, disable or loopback-pin it with a flag
   **verified live** (candidate: `-rfbport -1`; TigerVNC lineage treats a
   negative port as "do not listen"), applied in **both** modes so the two
   argvs differ only in `-interface`.
3. Pin the outcome three ways: a unit test on the argv, and the docker e2e
   asserting via in-container `/proc/net/tcp` that **the only wildcard
   listener is `:6901`**.

`-publicIP 127.0.0.1` stays as-is in both modes: it only suppresses KasmVNC's
WebRTC public-IP egress lookup, it is not a bind address.

### Host side: zero datapath changes

Everything the host needs already exists:

- `server::tcp_dial`'s docker-mode fallback dials `net::GUEST_IP` after
  loopback refuses (built for docker-published ports; loopback refusal is an
  instant RST, so added latency is negligible).
- init's nft output chain already carries the docker-only
  `ip daddr 192.168.127.2 return` exemption, so init's own veth dial is
  never swallowed by the egress REDIRECT.
- The daemon's liveness probe and the VNC relay both ride
  `StreamOpen::TcpDial{6901}` — unchanged framing.

**No wire change, no `DAEMON_PROTO_VERSION` bump.**

### Remove the four refusal gates

- CLI preflights in `commands/create.rs` and `commands/run.rs`
  (`merged.vnc && merged.docker` bails).
- Daemon `handle_create` (`c.vnc && docker` bail).
- Daemon `VncSet` (docker-mode bail).

Their refusal tests flip into acceptance tests (create/VncSet succeed on a
docker-mode sandbox; the `builder`-forces-docker-off tests keep their current
meaning). GUI needs **no change**: it has no docker-specific handling — the
refusal string came from the daemon, so removing it makes the Display tab
work as-is. Docs: drop/replace the refusal mentions (CLAUDE.md gotcha note,
VNC specs' refusal references), close #216.

Bundle/secrets plumbing is already docker-ready by design (PR #215): the
erofs bundle and secrets dir are init-root paths OUTSIDE `/rootfs`, bound RO
into the container un-idmapped (present as `nobody`, which is why the hash
file is deliberately 0644 in a 0755 dir — the vnc.rs doc comment says so
explicitly). No changes expected; the e2e is what proves it.

### e2e: `vnc_docker_e2e`

New KVM-gated test alongside `vnc_desktop_e2e` (same integration file, same
gating, same production-discovery rule — `IZBA_KASMVNC_EROFS` asserted absent):

1. Create `--docker --vnc` (curl-bearing image per the dogfood lessons),
   start, `izba vnc url`.
2. Full session proof: unauthenticated GET → 401, credentialed GET → 200,
   real websocket upgrade + RFB greeting (`"RFB "` + sectype 1) through the
   relay.
3. Listener-posture assert: in-container `/proc/net/tcp` shows `:6901` as
   the only wildcard listener.
4. Coexistence: nested docker engine answers (`docker info` via exec) with
   the desktop up.
5. **Restart phase**: stop/start, full auth + RFB re-proof (the stale-X-lock
   class — a fresh-boot-only e2e is blind to it).

Run locally on KVM before pushing (the USB post-mortem: a green static board
shipped a feature that could not work).

## 2. #221 — relay port collision avoidance

### Problem

`publish_vnc_relay` binds `host_port: 0` (kernel-chosen ephemeral). If the
kernel picks a port some OTHER sandbox has persisted as a fixed rule in its
`ports.json`, that sandbox's next start fails the publish with a warning and
**drops the persisted rule** (pre-existing conflict behavior) — a user-visible
loss from a cosmetic collision.

### Decision: avoid-set + bounded rebind at allocation time

- New helper `persisted_host_ports(paths) -> HashSet<u16>`: every fixed host
  port across all sandboxes' `ports.json` (unit-tested).
- `publish_vnc_relay` retry loop: `publish_bound` → if the returned port is
  in the avoid-set, unpublish and rebind, up to ~10 attempts. If every
  attempt collides (pathological — the ephemeral range is ~28k ports), keep
  the last port and warn loudly rather than killing the display.
- TDD seam: the retry logic takes a bind-attempt closure so unit tests can
  script collide-then-succeed sequences without real sockets.

The reverse window — a user publishes a fixed rule on a port a live VNC relay
currently holds — already fails honestly at request time (EADDRINUSE surfaces
in the response, the rule is not silently dropped later). Accepted and
documented; no code.

## 3. #219 — coverage jobs stage kasmvnc.erofs

`linux-kvm-coverage` and `windows-whp-coverage` in `.github/workflows/e2e.yml`
don't stage the bundle, so `vnc_desktop_e2e` (and the Windows VNC validation
section) self-skip there — report-only coverage parity gap.

Fix (verbatim mirror of the gate jobs): add `kasmvnc-erofs` to both jobs'
`needs`, download the artifact, stage at `target/artifacts/kasmvnc.erofs`
**strictly AFTER** `Swatinem/rust-cache` (the restore replaces `target/`
wholesale — the trap that silently deleted the staged file on PR #215's first
run), followed by the fail-loud `test -f` verify step.

Proof: dispatch `e2e.yml` on the branch during CI iteration and grep the
coverage-job logs for the VNC e2e actually PASSing, not SKIPping (job-green ≠
test-ran).

## 4. #220 — tcp_dial test flake

`tcp_dial_without_fallback_reports_connect_failed` obtains a "free" port by
bind-and-drop; under parallel execution another test can bind that port in
the window, the dial then SUCCEEDS and the assert panics. Fix: when the dial
unexpectedly succeeds, treat it as a raced port — pick a fresh one and retry,
bounded (~5 attempts), failing loudly only if every attempt lands on a
listener. The sandbox `PermissionDenied` skip stays.

## Testing & delivery

- TDD throughout, subagent-driven (per-task implementer + reviewer, the
  PR #224 campaign shape).
- Gates: the six workspace gates + the app gate is untouched (no core public
  type changes) — still run it once since daemon behavior changed.
- Local KVM: `vnc_desktop_e2e` (regression), new `vnc_docker_e2e`, docker e2e
  (regression), unsandboxed.
- Delivery: push branch → PR (ready, never draft) → CI iteration to CLEAN
  (Actions + Sonar + Greptile), `e2e.yml` dispatch for the coverage-job
  proof, `hack/devbuild.sh` for manual-test installers.
