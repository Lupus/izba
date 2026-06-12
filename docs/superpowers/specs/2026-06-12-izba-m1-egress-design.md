# izba M1 — one network story: izbad-owned egress (design)

Status: **approved 2026-06-12.** This is the milestone design doc for
[roadmap](../../roadmap.md) M1, cutting the
[mesh design](2026-06-12-izba-mesh-networking-design.md) §8 staging steps 1–3
into one implementation: `StreamOpen::TcpConnect` + izbad dial-out (opt-in),
the guest egress stub (nft REDIRECT + DNS), then the cutover that retires
passt/consomme from the egress path. It also defines the izbad-internal
**module seams** (roadmap risk #6) before the daemon accretes the mesh planes.

Decisions inherited from the roadmap (2026-06-12, not relitigated here):
daemon restart **severs live flows** (documented, no drain logic); throughput
is **measured, not gated**; non-DNS UDP is **denied**; platform parity is the
bar (M0's vsock-churn fix is in on both platforms).

Decisions made in this design's review (owner-approved 2026-06-12):

- **Redirect mechanism: vendored static `nft` binary** in the initramfs
  (the existing `mke2fs` embedding pattern), applied by izba-init against a
  fixed ruleset. Rejected: hand-rolled nfnetlink (fragile binary protocol,
  GPL crates off-limits under Apache-2.0), smoltcp TUN (the mesh design
  already rejected userspace netstacks).
- **Cutover removes virtio-net entirely.** End state: the guest is a pure
  vsock island — dummy interface with a static IP, no DHCP, no NIC, and the
  consomme/`izba.ipv4only` machinery deleted.

## 1. Datapath

### 1.1 TCP egress (end state)

```
guest app ──connect()──► kernel route (dummy0 default) ──► nft nat output REDIRECT
  ──► stub listener 127.0.0.1:15001 (izba-init)
  ──► getsockopt(SO_ORIGINAL_DST) = (orig_ip, orig_port)
  ──► vsock dial CID 2 : 1027 ──► VMM connects unix "run/vsock.sock_1027" (izbad)
  ──► StreamOpen::TcpConnect{addr, port} ──► policy check (M1: allow-all + audit seam)
  ──► izbad dials out from the host ──► Response::Ok ──► raw splice both ways
```

Teardown on every leg is the M0 contract: `shutdown(Write)` once TX is done,
then **drain** the other direction to EOF — never a force-close with peer TX
buffered (the OpenVMM assert condition).

This is izba's first **guest-initiated** vsock direction. Both VMMs follow
the Firecracker-style hybrid-vsock convention: a guest `connect(CID 2, port
P)` makes the VMM dial the host unix socket at `<vsock.sock>_<P>`. Documented
for Cloud Hypervisor; **code-confirmed but never runtime-validated for
OpenVMM** (S1 spike read `support/hybrid_vsock` + `connections.rs`). Phase A
validates this first on both platforms — it is the one unverified
load-bearing assumption. If OpenVMM's side is broken, that is Plan-B
territory (the pinned-fork patch shape from M0) before anything builds on it.

### 1.2 DNS

- izba-init writes `resolv.conf` → `nameserver 192.168.127.1`, an address
  carried by dummy0, where the stub binds UDP `:53` directly — the primary
  path needs no interception.
- An `nft udp dport 53 redirect to :53` rule additionally catches hardcoded
  resolvers (e.g. 8.8.8.8). Conntrack un-NATs the reply source for UDP
  REDIRECT, so answers appear to come from the address the client queried.
- The stub forwards each query over a per-query `StreamOpen::Dns` vsock
  stream; izbad's resolver answers. TCP `:53` rides the normal TCP REDIRECT
  and izbad routes port-53 `TcpConnect`s to the same resolver instead of
  dialing out.
- M1's resolver is a pure forwarder using the host's system resolver
  configuration (hickory-resolver, MIT/Apache dual, handles system config on
  both platforms). M4 puts member-name resolution in front of it.
- All other UDP: nft drop (the decided posture). Audit-logging of drops is
  M2 scope.

### 1.3 Guest network config (end state)

dummy0 carries `192.168.127.2/24` plus the resolver address `192.168.127.1`,
with an on-link default route into it (same subnet the passt static config
uses today, gvisor-tap-vsock-compatible). Locally-originated packets need
only a route to exist for the nat-output hook to see them; nothing is ever
emitted — dummy0 is the deny. IPv6: the guest has no v6 address or route, so
v6 connects fail instantly with unreachable and clients fall back to v4. The
whole SLAAC-race bug class and `izba.ipv4only` die with consomme.

## 2. Wire protocol (izba-proto)

```rust
pub enum StreamOpen {
    // ... existing variants unchanged ...
    /// Guest egress: izbad dials `addr:port` on the host and replies one
    /// `Response` frame (`Ok` | `Error{ConnectFailed}`); on `Ok` the
    /// connection becomes a raw bidirectional byte pipe. `addr` is an IP
    /// literal in M1 (SO_ORIGINAL_DST); a name-carrying form is M5 scope.
    TcpConnect { addr: String, port: u16 },   // tag: "tcp_connect"
    /// Guest DNS: DNS-over-TCP framing follows (2-byte big-endian length
    /// prefix per message, RFC 1035 §4.2.2), request/response alternating;
    /// sequential queries allowed; EOF closes.
    Dns,                                       // tag: "dns"
}

pub const EGRESS_PORT: u32 = 1027;  // guest-dialed; host listener vsock.sock_1027
```

The reply contract for `TcpConnect` is deliberately identical to `TcpDial`'s
so the splice/pump shapes are shared. Direction is inverted: these frames are
written by the **guest** and read by **izbad**.

## 3. izbad module seams (`crates/izba-core/src/daemon/egress/`)

The mesh planes get separable modules now, before they exist, so M2/M4/M5
extend instead of refactor (roadmap risk #6):

| Module | Responsibility | M1 content |
| --- | --- | --- |
| `mod.rs` (`EgressManager`) | Per-sandbox listener lifecycle: bind `run/vsock.sock_1027` at start/adopt for `egress=izbad` sandboxes, accept-loop thread per sandbox, teardown on stop/rm | full |
| `router.rs` | Read the `StreamOpen` frame, dispatch: `TcpConnect` → policy → dial-out → splice; `Dns` / port-53 `TcpConnect` → resolver. The M5 MITM/vault branch hangs off this dispatch | full |
| `dns.rs` | `Resolver` trait (`handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>>`); production = hickory forwarder, tests = fakes. M4 member names slot in front | forwarder |
| `policy.rs` | `Policy` trait: allow/deny per (sandbox, dst) + audit-event hook with event types defined | allow-all stub |

izbad restart: listeners rebound during adopt; live flows sever (decided).
Splicing reuses `copy_until_eof` + the drain teardown. All seams run over
`UnixStream::pair()` fakes in unit tests; anything binding a real listener
runtime-skips on `PermissionDenied` (house pattern).

## 4. Guest stub (`crates/izba-init/src/egress.rs`)

Gated by cmdline `izba.egress=1` (driver-appended for opted-in sandboxes;
unconditional after phase C):

- **TCP:** listener on `127.0.0.1:15001`; per-connection thread extracts
  `SO_ORIGINAL_DST`, dials vsock `CID 2:1027`, writes `TcpConnect`, awaits
  the `Response`, then splices with the standard pump + graceful-teardown
  shapes (mirrors `tcp_dial`). On `Error`/dial failure the accepted socket is
  closed → the app sees a reset (honest refusal). The original-dst
  `getsockopt` is one tiny isolated unsafe fn (integration-covered); the
  handler is unit-tested over socketpairs with an injected `(conn, orig_dst)`.
- **DNS:** UDP socket on `:53`; per-query forward over a `Dns` stream.
- **nft:** init execs `/sbin/nft -f` on a fixed `const` ruleset:
  nat output chain — TCP `ip daddr != 127.0.0.0/8` redirect to `:15001`,
  `udp dport 53` redirect to `:53`; filter chain — drop other UDP. The stub's
  own egress is AF_VSOCK (not IP), so no exclusion rules are needed and no
  redirect loop is possible.

**Kernel config additions** (`hack/kernel.config`): `NETFILTER`, `NF_TABLES`
(+ IPv4 family), `NFT_NAT`, `NFT_REDIR`, `NF_CONNTRACK`, `NF_NAT`, `DUMMY`
(plus whatever dependencies `olddefconfig` pulls). **Artifacts:**
`hack/build-initramfs.sh` gains an `IZBA_NFT` embedding hook (the `IZBA_MKE2FS`
pattern → `/sbin/nft`), plus a fetch/build script for the static binary.

## 5. Opt-in plumbing

`SandboxConfig` gains `egress: EgressMode` (`Passt` | `Izbad`), serde-default
`Passt` so existing configs deserialize; `izba create --egress izbad|passt`
in the CLI; threaded through `VmSpec` to both drivers. After phase C the
default flips to `Izbad` and the `Passt` arm + flag are removed (the field
had two phases of life; deleting it then is part of the cutover).

## 6. Staging

- **Phase A — wire + daemon (step 1).** Proto variants + `EGRESS_PORT`;
  `egress/` module tree with allow-all policy and forwarder resolver;
  listener lifecycle in start/adopt/stop. **First task: runtime-validate
  guest-initiated vsock on both platforms** (KVM integration + Windows PS
  check). Exit: a guest-side dial (test harness, no stub yet) reaches izbad
  and round-trips bytes on both platforms.
- **Phase B — guest stub (step 2).** Kernel config + rebuilt artifacts,
  vendored `nft`, `egress.rs`, `izba.egress=1` end to end. Interim guest
  config: an opted-in sandbox still boots with eth0 + DHCP (passt/consomme
  attached), but the nft REDIRECT makes the stub authoritative for all TCP
  and the `:53` redirect captures the DHCP-provided resolver — the NIC is
  bypassed, not yet removed. Exit: KVM integration test where an opted-in
  sandbox resolves DNS and fetches HTTP through izbad while passt remains
  the default for everyone else.
- **Phase C — cutover (step 3).** Default flips to izbad; passt/consomme
  spawn paths, `spec.net`, `ip=dhcp`, `izba.ipv4only`, and the v6-disable
  code are deleted; dummy0 static config + static resolv.conf; virtio-net
  removed from both drivers' invocations. Throughput baseline (measured, not
  gated) added to the integration suite. Docs updated: CLAUDE.md load-bearing
  contracts (cmdline chain, vsock ports incl. 1027, egress contract),
  testing.md, README, roadmap tick. The Windows PS suite's open consomme
  guest-egress failure is **retired with consomme** and replaced by izbad
  egress checks.

Backout: until phase C, `--egress passt` is the escape hatch; phase C itself
is one revertable cut.

## 7. Error handling

- Dial-out fails → `Error{ConnectFailed}` → stub closes the redirected
  socket → app sees RST. izbad down or listener unbound → the VMM refuses the
  guest's vsock connect → same RST. Apps retry; consistent with the
  no-auto-restart philosophy.
- Daemon restart/upgrade severs all live egress flows; new flows work once
  adopt rebinds the listeners. Documented honest behavior, no drain logic.
- Resolver errors → SERVFAIL response (not a dropped query) so clients fail
  fast instead of timing out.

## 8. Testing

- **izba-proto:** roundtrip + stable-wire-tag tests for the new variants.
- **izbad egress:** socketpair-driven router tests (TcpConnect happy path,
  refused dial, Dns via fake resolver, port-53 TcpConnect routed to
  resolver, policy seam consulted + audit event emitted); listener lifecycle
  tests with the runtime-skip-on-EPERM pattern.
- **izba-init:** stub handler tests over socketpairs (injected orig-dst);
  nft ruleset content assertion; DNS forward path with a fake vsock dialer.
- **KVM integration:** guest-initiated vsock smoke (phase A); opted-in
  sandbox does DNS + HTTP through izbad (phase B); stub-only egress with
  non-53 UDP denied + throughput baseline print (phase C).
- **Daemon e2e / CLI:** `--egress` flag persisted and honored.
- **Windows PS suite:** guest-initiated vsock check (phase A), izbad egress
  checks replacing the consomme ones (phase C).

All six commit gates stay green at every phase boundary.

## 9. Exit criteria (from the roadmap, restated)

All suites green with stub-only egress on both platforms; the WSL+VPN and
Tailscale topologies that produced `ea9e413` and `30e5c67` work with zero
host sniffing; consomme/passt (and `izba.ipv4only=1`) gone from the egress
datapath.
