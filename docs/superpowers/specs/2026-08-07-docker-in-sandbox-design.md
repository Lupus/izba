# Docker-in-sandbox ("docker mode") — design

**Status:** approved 2026-08-07 (repo owner) · **Issue:** #198 · **Follow-ups:** #199 (manifest key), #200 (egress datapath unification)

Make `docker/sandbox-templates:<agent>-docker` images — and any image bringing
its own Docker Engine — work inside an izba sandbox at sbx parity: stock
dockerd, real bridge networking (`docker run -p`, compose networks), engine
auto-started from the `com.docker.sandboxes.start-docker=true` label, with the
egress policy plane still seeing and governing every inner-container byte.

Empirical baseline (issue #198, live probes 2026-08-07): dockerd reaches
`Server Version: 29.7.1` inside the workload container but dies on (1) no mount
namespace + no `CAP_SYS_ADMIN` in the container's bounding set (layer
extraction EPERM), and (2) a shared netns it does not own (bridge/iptables
EPERM) on a kernel without `BRIDGE`/`VETH`. A third blocker sits behind those:
docker's overlay2 storage driver refuses an overlayfs backing store, and the
workload rootfs *is* izba's erofs+ext4 overlay.

## 1. Enablement — the `docker` flag

A per-sandbox boolean `docker` on `SandboxConfig` (`#[serde(default)]`), set at
`create` time when the image config is in hand, resolved in precedence order:

1. `izba create --no-docker` → off (overrides the label).
2. `izba create --docker` → on (custom images without the label).
3. Image label `com.docker.sandboxes.start-docker=true` → on (sbx parity,
   zero-config for the `-docker` templates). Labels are already deserialized
   into `ConfigFile.config.labels` (oci-client) and currently unused.
4. Default off.

Wire: an additive `#[serde(default)]` field on the daemon `Create` request,
exactly the `builder` precedent — **no `DAEMON_PROTO_VERSION` bump** (a
pre-feature client's frame deserializes to `false`).

Docker mode is a create/start-time decision (it selects the OCI spec profile,
the guest datapath, and an auto-volume); toggling it means recreating or at
least restarting the sandbox. `izba status` and `inspect` surface it.

Deferred (#199): an `izba.yml` manifest key. The manifest is an untrusted
proposal behind `izba promote`; docker mode is a capability grant, so the
diff/promote path must flag it like a security-weakening delta. Out of scope
here.

## 2. Security posture

**Nothing gains capabilities in the guest's initial namespaces.** The workload
container keeps its user namespace (Option A); every addition below is scoped
inside it. The microVM remains the real security boundary; within the guest,
the assets being protected from the workload are izba-init, the vsock planes,
and the egress enforcement point — and none of them become reachable.

In docker mode the container's OCI spec adds:

- **A mount namespace** owned by the container's userns. dockerd can
  bind/overlay/tmpfs-mount freely inside its own tree; init's mount table is in
  a different namespace and untouchable. (Non-docker sandboxes keep the
  documented v1 "no mount namespace, chroot only" trade-off.)
- **A network namespace** owned by the container's userns (§3) — replacing
  D1's netns sharing for docker-mode sandboxes only.
- **Bounding-set caps**: the docker-default set plus `CAP_SYS_ADMIN`,
  `CAP_NET_ADMIN`, `CAP_SYS_CHROOT`, `CAP_MKNOD`, `CAP_SETFCAP`,
  `CAP_NET_RAW`, `CAP_SYS_PTRACE` (the set dockerd + runc need for nested
  containers; the exact list is pinned by a unit test). A userns-scoped
  `SYS_ADMIN` cannot mount real block devices, cannot touch init's namespaces
  or fds, and cannot edit init's nft rules — it is admin of the workload's own
  namespaces only, the same posture rootless docker runs under. For
  calibration: the shipped `izba build` privileged mode drops the userns
  entirely and grants **all** caps; docker mode is strictly weaker.
- **Cgroup delegation**: init (guest root) creates a cgroup subtree, enables
  controllers in `subtree_control`, chowns the subtree to the workload's mapped
  root uid, and points crun's `cgroupsPath` into it — the standard rootless
  delegation systemd normally performs. The workload manages cgroups only under
  its own subtree. The container also gets the rw cgroupfs treatment currently
  gated behind `privileged` (nested runc/containerd must create sub-cgroups).
- Seccomp stays off (already is for the workload container).

Net effect on isolation: **stronger**, not weaker, where it matters — the nft
egress rules move from "same netns as the workload, protected by userns
ownership" to "a namespace the workload cannot name" (§3).

## 3. Guest networking — child netns + veth

Today the workload shares init's netns (that is how the nft `output`-hook
REDIRECT sees its traffic), so dockerd can never own a bridge there. Docker
mode changes the topology; **non-docker sandboxes keep the current shared-netns
datapath untouched** (unification is #200).

- The container's OCI spec includes a fresh `network` namespace (owned by its
  userns). Inside it dockerd is fully at home: `docker0`, per-container veths,
  its own iptables/MASQUERADE, `-p` port publishing, compose networks — stock,
  no daemon flags, no image changes.
- After crun reports the container running, init wires a **veth pair** between
  its netns and the container's (via `/proc/<container-pid>/ns/net`):
  `192.168.127.1/24` init-side, `192.168.127.2/24` container-side, default
  route via `.1` — the same addresses as today's dummy0 arrangement, so the
  workload-visible network contract is unchanged. `dummy0` is not created in
  the container netns; the veth is the only exit.
- **Interception moves to init's side of the veth**: the nft ruleset gains a
  `prerouting` nat chain (the current chain uses only the `output` hook, which
  forwarded traffic never traverses): DNS (tcp/udp dport 53) → `redirect
  to :53`, other TCP → `redirect to :15001`. Same stubs, same
  `StreamOpen::{Dns,DnsTcp,TcpConnect}` frames, same vsock-1027 plane, same
  policy engine and `izba netlog`. The `output` chain stays (it still covers
  init-local traffic and the non-docker datapath).
- Listener adjustments: the `:15001` TCP-redirect listener binds `0.0.0.0`
  instead of `127.0.0.1` (prerouting REDIRECT rewrites the destination to the
  ingress interface's address, `192.168.127.1`; wildcard is harmless on a
  NIC-less island and keeps one code path). The DNS stubs already bind
  `0.0.0.0:53` and already source replies via `IP_ORIGDSTADDR`/`IP_PKTINFO`.
- **resolv.conf in docker mode** points at `192.168.127.1` (not loopback — the
  container's loopback no longer hosts the stub). The loopback-nameserver
  requirement documented in `net.rs`/`egress.rs` is an artifact of REDIRECTing
  in the *same* netns; a query delivered across the veth to a real local
  address of init's netns has a clean reply path. docker's embedded DNS
  (127.0.0.11 in inner containers) forwards to this resolver automatically.
- **Structural deny preserved**: anything the prerouting chain does not
  intercept is routed nowhere (init's netns has no NIC and no forward path) —
  same deny-by-topology as today, now enforced one namespace away from the
  workload. Inner-container traffic is MASQUERADEd by dockerd to `.2`, crosses
  the veth, and hits the same policy as everything else; there is no bypass.
- **`TcpDial` (port relays, ssh)**: init dials `127.0.0.1:port` today. In
  docker mode workload listeners (including docker-proxy's published ports)
  live in the container netns, so `tcp_dial` tries loopback first (sshd binds
  `127.0.0.1:22` in init's netns and keeps working) and on failure falls back
  to `192.168.127.2`. `izba port publish` therefore reaches
  `docker run -p`-published ports with no wire change.
- **Plumbing**: creating a veth requires netlink (ioctl cannot; `net.rs` is
  ioctl-only by design). A static iproute2 `ip` is vendored — sha-pinned
  `hack/build-ip.sh`, embedded into the initramfs via `IZBA_IP` — exactly the
  vendored-nft pattern. init shells out to it for link/addr/route setup in
  both namespaces.

Failure honesty: if veth setup fails (e.g. a stale `IZBA_KERNEL` override
without `VETH`), init logs a loud console error naming the cause; the sandbox
stays alive and diagnosable with the container network-dead — fail-honest, no
silent fallback to the shared-netns datapath (which would silently change the
isolation story).

## 4. Storage — `/var/lib/docker`

overlay2-on-overlayfs is refused by docker. Docker mode auto-attaches an
**anonymous ext4 volume at `/var/lib/docker`** (sparse, 10 GB) during `create`,
unless the user already declared a volume at that path (a named volume then
provides persistence across `izba rm`). This rides the existing volume
mechanism end-to-end (cmdline `izba.volumes=`, `vd{c…}` ordering,
format-if-blank) — no new machinery, and the 24-volume cap is unaffected in
practice.

## 5. Engine auto-start

Docker mode ⇒ after the container reaches `running` and the veth + cgroup
delegation are up, init starts the engine: a detached `crun exec` as
container-root running `dockerd` (stock args — bridge networking works now),
stdout/stderr to a log file inside the container (`/var/log/izba-dockerd.log`).
If the image ships no `dockerd`, init logs that honestly and continues — the
sandbox is otherwise a normal sandbox.

Consistent with izba's no-auto-restart philosophy: a dead dockerd stays dead
with an honest reason (visible via the log + `docker` client errors); restart =
restart the sandbox. The auto-start runs on every boot, so `izba stop && izba
start` recovers it.

## 6. Supplementary groups (all sandboxes, not just docker mode)

The exec path currently applies only `uid:gid`; the image's `/etc/group`
member list is parsed past (field 4 dropped), so `agent` loses its `docker`
group and plain `docker ps` fails on the socket. Fix, benefiting every
sandbox:

- `parse_group` reads the member list; `UserDb` resolves supplementary gids
  for the image `USER` (including the numeric-uid case via reverse passwd
  lookup, as docker does).
- The OCI spec's `process.user` gains `additionalGids`; each gid must fall
  inside the container's gid map (checked against `compute_userns_mappings`).
- Default-user execs (no `--user` override) inherit the config's process user
  — gids included — so ssh/exec sessions are in the `docker` group. Explicit
  `--user` execs get no supplementary groups, same as `docker exec -u`.

## 7. Guest kernel — base fragment, not a variant

Add to `hack/kernel.config` (base): `CONFIG_VETH`, `CONFIG_BRIDGE`,
`CONFIG_BRIDGE_NETFILTER`, masquerade + xtables/nft-compat symbols for docker's
iptables (`NFT_MASQ`/`NF_NAT_MASQUERADE`, `NETFILTER_XT_*` matches docker
requires, iptables-nft compat), plus any cgroup controllers docker's
`check-config.sh` reports missing. The exact list is enumerated during
implementation against `check-config.sh` and locked in by `build-kernel.sh`'s
fragment-survival verification.

Base, not a `KernelVariant`, because: (a) there is no D4-style structural-deny
argument (unlike USB, where a grant-less sandbox must boot a kernel physically
unable to speak USB); (b) variants combine multiplicatively (usb+docker); and
(c) — the USB-feature lesson — base means the shipped `.deb`'s `vmlinux` has
it, and e2e must run against the shipped artifact rather than hand-carrying a
special kernel. CI cache keys already hash the fragment, so all workflows
rebuild automatically.

## 8. Testing

TDD throughout; every rule gets a call-site test or a justified
`#[mutants::skip]` (the recurring defect class from the USB feature).

Host units: label→mode resolution and `--docker`/`--no-docker` precedence;
docker-profile spec generation (namespaces, caps, cgroup path, additionalGids
inside the gid map); cmdline `izba.docker=1`; auto-volume injection (and
non-injection when the user declared `/var/lib/docker`); nft ruleset text
(prerouting chain present iff docker mode); `tcp_dial` fallback order;
`parse_group` member lists; veth argv construction for the vendored `ip`.

KVM e2e (shipped-artifact discipline — no env-var kernel hand-offs): boot a
DinD-capable image with `--docker`; `docker run hello-world`; `docker run -p`
+ `izba port publish` reach-through; inner-container egress appears in `izba
netlog` (policy honesty — the whole point); label auto-detect boots a real
`-docker` template end-to-end. Windows/WHP: no driver changes (all guest-side
+ host spec-gen), covered by the existing validation suite.

Post-merge: an llm-dogfooding journey campaign on the docker surface.

## 9. Delivery — two PRs

- **PR 1 — foundations** (independently shippable, no behavior flag): kernel
  fragment additions; vendored static `ip` (`hack/build-ip.sh` + initramfs
  embed); supplementary-groups fix (§6); wildcard `:15001` bind.
- **PR 2 — docker mode**: config/label/flag; OCI docker profile (§2); veth
  datapath + prerouting nft (§3); auto volume (§4); engine auto-start (§5);
  `tcp_dial` fallback; e2e.

Each PR: six workspace gates + app gate, devbuild artifacts for manual
testing, CI iterated to CLEAN (checks + Sonar + Greptile).

## Deliberately out of scope

- `izba.yml` manifest key for docker mode — #199.
- Unifying all sandboxes onto the veth datapath — #200.
- IPv6 for inner containers (egress plane is v4).
- sbx's engine-supervision semantics beyond start-at-boot (no auto-restart).
- Vendoring dockerd/containerd into izba (the image brings its own engine —
  `docs/vision.md` stance).
