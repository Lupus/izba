# izba v1 — Design

> **izba** — a small self-contained log cabin; cozy, isolated, ownable.
>
> An open-source reimplementation of the agent-sandbox model popularized by
> Docker Desktop's `sbx`: per-project microVMs for running AI coding agents,
> with the workspace shared in and a tightly controlled boundary around
> everything else. Background: `docs/design-lineage.md` (how each subsystem
> maps to its public OSS building blocks; `sbx` as the UX reference).

## 1. Goals and non-goals

### v1 goals

- `izba create / run / exec / ls / stop / rm`: boot a per-project microVM in
  ~2 s, share the project directory into it live, run commands (interactive or
  not) inside, with clean lifecycle management.
- **Two host platforms:** Linux/KVM (including WSL2 with nested
  virtualization) and native Windows via WHP. Both demos are part of v1; the
  WSL2 demo is contingent on nested-KVM quirks not being a hard blocker
  (spike S2).
- Fully **unprivileged**: no root, no host TAP/bridge, no daemon to install.
- Any OCI image as the guest environment.

### Explicit non-goals for v1 (later milestones)

- Egress MITM proxy, domain allow-lists, credential injection (the security
  crux of sbx — this is v2, and the v2 daemon `izbad` is anticipated in the
  process model).
- Docker engine inside the guest; crun/OCI-container workloads.
- erofs per-layer dedup / VMDK-style layer stitching (v1 flattens each image
  to a single erofs).
- Snapshot/suspend/resume; macOS host; port publishing; policy engine;
  supervision/auto-restart of dead sandboxes; image cache GC; re-attach to a
  live exec after disconnect.

## 2. Decisions made (with rationale)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Host platforms | Linux/KVM + Windows/WHP, both in v1 | User requirement; per-platform driver abstraction becomes a first-class deliverable |
| VMM strategy | Per-platform off-the-shelf VMMs behind a thin izba-owned driver trait: **Cloud Hypervisor** on Linux, **OpenVMM** on Windows | Fastest path to a solid Linux experience; isolates OpenVMM's desktop-VMM immaturity to the Windows port; either side swappable later. Rejected: OpenVMM everywhere (inherits its immaturity on Linux where better options exist); building our own VMM (months of work before any product) |
| Language | Rust everywhere | One toolchain/workspace; guest init builds as tiny static musl binary; keeps the door open to embedding VMM pieces later |
| Process model | **Library-first, daemonless CLI** (approach C) | `izba-core` is a clean library with no CLI assumptions; `izba` is a thin daemonless binary; v2's `izbad` becomes a second thin binary over the same core. Rejected: daemon from day one (pure overhead at v1 scope); plain daemonless without the library discipline (painful daemon retrofit) |
| Guest rootfs | OCI image → flattened **erofs** (RO) + ext4 rw disk + overlayfs in guest | Reuses the OCI ecosystem for customization; flattened to a single erofs (no layer-stitching subsystem) |
| Networking | User-mode NAT: **passt --vhost-user** (Linux), **consomme** (OpenVMM's built-in stack, Windows) | No TAP/bridge, no root — user-mode networking |
| Control plane | Hand-rolled length-prefixed JSON frames over vsock; ports **1025** (control RPC) and **1026** (stdio streams), following the Firecracker hybrid-vsock convention | Six verbs don't justify a protobuf/ttrpc toolchain; both sides share `izba-proto` so the framing is swappable later |

## 3. Architecture overview

Cargo workspace, three binaries + one core library:

```
izba/
  crates/
    izba-core/    # the product: sandbox lifecycle, VMM driver trait + 2 drivers,
                  #   OCI image → rootfs pipeline, guest control-plane client
    izba-cli/     # `izba` binary — thin, daemonless wrapper over izba-core
    izba-init/    # guest PID 1 agent (static musl x86_64): boot, mounts, exec
    izba-proto/   # host↔guest protocol types, shared by core and init
```

Runtime picture on Linux (Windows analogous, different processes behind the
same trait):

```
 izba CLI ──spawns──► cloud-hypervisor (per sandbox)     ┌─ microVM ──────────────┐
          ──spawns──► virtiofsd  (workspace share)  ◄────┤ izba-init (PID 1)      │
          ──spawns──► passt      (user-mode NAT)    ◄────┤  ├ overlay rootfs      │
          ──connects─► vsock port 1025 (control RPC) ◄───┤  ├ /workspace virtiofs │
                       vsock port 1026 (stdio streams)◄──┤  └ spawns workloads    │
                                                         └────────────────────────┘
```

Key properties (deliberately inherited from sbx):

- **One VMM process per sandbox, owned by nobody.** The CLI spawns it detached
  and exits. A running sandbox is fully described by its state directory
  (`~/.local/share/izba/sandboxes/<name>/`) plus live processes; any later CLI
  invocation reconstructs everything from disk. This invariant is what makes
  the daemonless→daemon transition free in v2.
- **Exactly two guest vsock ports** (1025 control, 1026 streams). The host
  reaches them through whatever the VMM exposes (Cloud Hypervisor:
  hybrid-vsock unix socket with `CONNECT <port>\n` handshake; OpenVMM: its
  vsock bridging — spike S1), abstracted by the driver as "give me a byte
  stream to guest port N."
- **Unprivileged user-mode networking**, no host network configuration.

## 4. Components

### 4.1 `izba-core::vmm` — driver trait + two drivers

The interface is tiny and **create-time-frozen** (no hot-plug):

```rust
trait VmmDriver {
    fn launch(&self, spec: &VmSpec) -> Result<Box<dyn VmHandle>>;
}
// VmSpec: kernel, initrd, cmdline, cpus, mem_mb,
//         disks: Vec<BlockDisk>, shares: Vec<FsShare>, vsock: VsockConfig
trait VmHandle {
    fn connect(&self, port: u32) -> Result<Box<dyn IoStream>>; // host→guest vsock
    fn is_alive(&self) -> bool;
    fn kill(&mut self) -> Result<()>;   // hard stop; graceful goes via RPC
}
```

- **`CloudHypervisorDriver` (Linux/KVM):** spawns `cloud-hypervisor` with
  direct kernel boot, plus `virtiofsd` per share (vhost-user-fs) and
  `passt --vhost-user` for the NIC. `connect()` speaks the hybrid-vsock
  handshake on the per-sandbox unix socket.
- **`OpenVmmDriver` (Windows/WHP):** spawns `openvmm` with its virtio-fs share
  and consomme user-mode NAT. vsock-to-host bridging details determined by
  spike S1.
- A single **driver contract test suite** (see §7) runs against both.

### 4.2 `izba-init` — guest PID 1

Static musl binary in a ~2 MB initramfs. Boot sequence:

1. Mount `/proc`, `/sys`, `/dev`.
2. If the rw disk is blank (first boot), format it ext4 **inside the guest** —
   this is why the host needs no e2fsprogs on any platform.
3. Assemble `overlayfs(lowerdir=erofs rootfs, upperdir=rw disk)`.
4. Mount virtiofs at `/workspace`.
5. Bring up `eth0` via DHCP (served by passt/consomme).
6. Listen on vsock 1025 (control) and 1026 (streams).

Workloads are spawned chrooted + mount-namespaced into the overlay —
micro-containers without crun. izba-init reaps zombies, forwards signals, and
on `Shutdown` kills workloads, syncs, and powers off. It also has a
`--self-check` mode used during bring-up and testing.

### 4.3 `izba-proto` — control plane

Length-prefixed JSON frames over vsock byte streams; serde types shared by
core and init. v1 API:

| Verb | Purpose |
| --- | --- |
| `Health` | readiness probe (boot polling) + basic guest info |
| `Exec` | spawn process: argv, env, cwd (default `/workspace`), tty flag, uid → returns `exec_id` |
| `Wait` | block until `exec_id` exits → exit code |
| `Kill` | signal an `exec_id` |
| `Resize` | tty window size change |
| `Shutdown` | graceful guest poweroff |

Port 1026 connections begin with a one-line handshake attaching the stream to
an exec: with tty, one combined PTY stream; without, separate
stdin/stdout/stderr streams. The protocol distinguishes "command not found"
(CLI exits 127) vs "process exited nonzero" vs "init internal error".

### 4.4 `izba-core::image` — OCI → rootfs pipeline

1. Pull manifest + layers with the `oci-client` crate into a
   content-addressed cache (`~/.local/share/izba/images/`).
2. **Flatten layers as a pure-Rust tar-merge**: apply layer order, handle
   whiteouts (`.wh.` entries, opaque dirs) in memory, emit one merged tar —
   never materializing files on the host FS (critical on Windows, where
   unpacking Linux tars loses symlinks/modes/ownership).
3. Pipe the merged tar into `mkfs.erofs --tar` → `images/<digest>/rootfs.erofs`.

`mkfs.erofs` is the single external host tool (distro package on Linux;
shipped binary on Windows — Docker proved it builds; fallback is spike S4).
The rw layer is a sparse raw file created by the host and formatted by
izba-init (§4.2).

### 4.5 Kernel

One minimal custom config (virtio-blk/net/fs/vsock, erofs, ext4, overlayfs,
essentially module-free) built in CI from kernel.org stable, published as a
release artifact, fetched into the cache on first run. Boots direct
(PVH/bzImage) on both VMMs.

## 5. Data flow

### `izba create [--image ubuntu:24.04] [--cpus N] [--mem 4g] [dir]`

1. Resolve image → if not cached: pull, tar-merge, `mkfs.erofs`.
2. Make `sandboxes/<name>/`: `config.json` (image digest, cpus, mem, workspace
   path), sparse `rw.img`, empty `logs/` and `run/`. The erofs is referenced
   from the cache, not copied. Nothing boots; `create` is pure host-side prep.
   (`run` on a nonexistent sandbox does create+start in one go.)

### `izba run <name>` — start phase

1. `flock` the sandbox dir; verify not already running (liveness = pidfile +
   process identity + control socket answers).
2. Driver builds `VmSpec` — kernel + izba-init initramfs, `rootfs.erofs` (RO)
   and `rw.img` (RW) as virtio-blk, workspace as virtiofs share, vsock — and
   spawns the VMM detached (plus virtiofsd/passt on Linux), serial console
   teed to `logs/console.log`. PIDs land in `run/`.
3. Poll `connect(1025)` → `Health` until init answers (timeout 10 s). Record
   `state.json`. Then `run` continues into exec with its initial command.

### `izba exec <name> [-it] -- cmd...`

1. Connect 1025, send `Exec` → `exec_id`.
2. Open 1026 stream connection(s); raw terminal mode for tty; pump bytes;
   `Resize` on SIGWINCH.
3. `Wait` returns the exit code → CLI exits with it. Disconnect ≠ kill: the
   guest process keeps running (re-attach to it is out of v1 scope).

### `izba stop <name>`

`Shutdown` RPC → wait for VMM exit (10 s timeout, then `kill()`) → reap
sidecars → clear `run/`. Workspace changes are already on the host (virtiofs
is live); guest-side changes persist in `rw.img` for the next run.

### `izba ls` / `izba rm`

`ls` walks the sandboxes dir doing liveness checks — this is also where dead
VMMs get noticed and `state.json` corrected. `rm` refuses on running unless
`--force` (kills first), then deletes the sandbox dir.

## 6. Error handling

Unifying principle: **disk state is the source of truth, and every "running"
claim is verified against live processes, never trusted.** Crash recovery is
the same code path as normal operation.

- **Boot failure:** if `Health` doesn't answer in 10 s, kill VMM + sidecars
  and print the tail of `logs/console.log`. The serial console is *always*
  captured — kernel panics, init failures, and bad disks are always visible.
- **VMM dies mid-session:** EOF/ECONNRESET → re-check liveness → report
  "sandbox died (see logs/console.log)" and correct `state.json`. Stale
  pidfiles guarded by process-identity check (PID reuse after host reboot).
- **Sidecar death (virtiofsd/passt):** liveness covers all pids in `run/`;
  a dead sidecar marks the sandbox unhealthy with a specific message. No
  auto-restart in v1 (vhost-user reconnection is a rabbit hole).
- **Connect retries:** short backoff, bounded by the liveness check — never
  retry against a dead VMM.
- **Concurrency:** per-sandbox `flock` around state transitions
  (start/stop/rm); read-only ops don't take it. Second simultaneous `run`
  reports "already starting".
- **Partial create:** pull/flatten in a temp dir, renamed into the
  content-addressed cache only on success; half-created sandbox dirs removed
  on failure.
- **Stop escalation ladder:** `Shutdown` RPC → 10 s → `kill()` → reap.
  `rm --force` jumps to the end. Nothing ever requires manual pidfile surgery.
- **Deliberate non-goal:** no supervision/auto-restart. Dead sandboxes are
  reported honestly with logs; the fix is `stop`/`run`. Supervision arrives
  with `izbad` in v2.

## 7. Testing

### Unit tests (pure, no KVM, run anywhere)

- **tar-merge/flatten** — layer ordering, whiteouts, opaque dirs, symlinks,
  hardlinks, device nodes; golden-file tests with hand-built layer fixtures.
  (Most bug-prone pure-logic component.)
- **izba-proto** — frame encode/decode roundtrips, torn reads, partial frames.
- **VmSpec construction per driver** — snapshot-test the exact
  `cloud-hypervisor`/`openvmm` command lines and sidecar invocations.
- **State machine** — liveness/staleness decisions with fake pid/socket probes.

### Integration tests (real microVMs, gated by env var / feature flag)

Written against the **driver trait**, so the suite is the per-platform
contract: runs on Linux+KVM (locally in WSL2 and in CI — GitHub's standard
Linux runners support KVM) and unchanged against `OpenVmmDriver` on a Windows
runner when it lands:

- boot-to-healthy under 5 s (budgeted ~2 s typical, with CI slack); exit codes (`true`/`false`/127);
  stdin→stdout echo through the stream port; tty mode + resize;
  workspace roundtrip (host write → guest sees, guest write → host sees);
  rw-layer persistence across stop/start; first-boot rw format;
  guest networking (`curl` through passt); concurrent sandboxes;
  stop-while-running; kill-VMM-then-observe-honest-`ls`.

`izba-init` gets almost no unit testing (it's PID 1; mocking that lies) — it
is covered by the integration suite plus its `--self-check` mode.

## 8. Risks and early spikes

Do these **before** committing to the implementation plan's ordering:

| # | Spike | Question | Fallback |
| --- | --- | --- | --- |
| S1 | OpenVMM standalone | Do direct Linux boot + virtio-fs share + vsock-to-host bridging work from the shipped `openvmm` CLI on Windows? | Shapes the whole Windows half; worst case the Windows port slips and v1 ships Linux-first |
| S2 | WSL2 nested KVM | Do `/dev/kvm` + cloud-hypervisor + passt work in the user's WSL2? | Bare Linux box / Hyper-V Linux VM for the demo; WSL2 documented as best-effort |
| S3 | passt `--vhost-user` + Cloud Hypervisor | Is the newer vhost-user path stable? | Privileged TAP setup (worse UX) or alternative virtio-net backends |
| S4 | `mkfs.erofs` on Windows | Can we reproduce Docker's Windows build of erofs-utils? | Guest-side provisioning: ship the flattened tar as a raw disk, init unpacks onto ext4 at first boot (slower create, zero host tooling) |

## 9. v2+ horizon (anticipated, not designed)

In rough order: `izbad` daemon (same core, second thin binary) → egress MITM
proxy with domain allow-lists + credential injection → port publishing →
erofs layer dedup → snapshot/suspend/resume → policy engine. The §3 invariant
(sandbox = disk state + live processes) and the §4.1 driver trait are the two
load-bearing walls this future leans on.

**Update (2026-06-12):** this horizon has since been steered into a larger
product shape — a "sandbox" becomes a governed *set* of microVMs (a project), with
`izbad` as a vsock policy/mesh hub that owns egress, brokers inter-service
traffic, and injects per-role credentials. The egress MITM proxy above is now the
credential-vault layer of that mesh. See [../../vision.md](../../vision.md) and
[2026-06-12-izba-mesh-networking-design.md](2026-06-12-izba-mesh-networking-design.md).
