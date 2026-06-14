# izba

> *izba* — a small self-contained log cabin; cozy, isolated, ownable.

Open-source per-project microVM sandboxes for AI coding agents, inspired by
Docker Desktop's agent sandboxes (`sbx`). Each sandbox is a lightweight KVM
virtual machine: your project directory is shared in live, the guest
environment is any OCI image, and everything outside that boundary is isolated.
Background on izba's architecture and where each piece comes from: [`docs/design-lineage.md`](docs/design-lineage.md).

## Status

v1 in active development. Linux/KVM (including WSL2 nested virtualization)
works end-to-end (gated integration suite green). Windows/WHP via OpenVMM
works end-to-end as well (experimental): a natively cross-built `izba.exe`
pulls, builds erofs with the bundled native `mkfs.erofs.exe`, and boots
sandboxes under OpenVMM — full CLI parity is script-validated on Windows 11
24H2. See the
[Windows-port design + bring-up findings](docs/superpowers/specs/2026-06-10-izba-windows-port-design.md)
and the staging runbook in [hack/README.md](hack/README.md); there is no
installer yet (binaries are staged by script).

## How it works

```
 izba CLI ──spawns──► cloud-hypervisor (per sandbox)     ┌─ microVM ──────────────┐
          ──spawns──► virtiofsd  (workspace share)  ◄────┤ izba-init (PID 1)      │
          ──connects─► vsock port 1025 (control RPC) ◄───┤  ├ overlay rootfs      │
                       vsock port 1026 (stdio streams)◄──┤  ├ /workspace virtiofs │
       izbad ◄─dials── vsock port 1027 (egress: TCP/DNS) ┤  └ spawns workloads    │
                                                         └────────────────────────┘
```

Key properties:

- **Daemon-first, daemonless soul.** Every `izba` command auto-starts `izbad`
  (the same binary, via `izba daemon run`, socket
  `~/.local/share/izba/daemon/izbad.sock`) — no install or service step
  required. The daemon rebuilds all state from disk at startup, so you can kill
  or upgrade it at any time without harming running sandboxes.
- **Disk-state as source of truth.** `state.json` records every PID with its
  `starttime` field from `/proc/<pid>/stat` to defeat PID reuse.
- **Three vsock ports.** Port 1025 carries length-prefixed JSON control RPCs
  (Health, Exec, Wait, Resize, Shutdown). Port 1026 carries raw stdio/tty
  streams. Port 1027 carries **guest egress** — the guest dials out and `izbad`
  bridges it.
- **One network story: all egress through izbad.** The guest is a NIC-less
  vsock island — no `passt`, no `consomme`, no host-side user-mode NAT. The
  in-guest stub redirects all outbound TCP (nftables + `SO_ORIGINAL_DST`) and
  DNS to `izbad` over vsock 1027; `izbad` is the single point that dials the
  outside world. Because every flow already passes through `izbad`, the
  agent-firewall (per-sandbox egress allow-lists + an audit log of every
  connection tried) is the next milestone.
- **OCI → erofs + overlay rootfs.** Images are pulled, flattened to a single
  erofs image (read-only), and combined with a sparse ext4 rw disk via
  overlayfs inside the guest. The erofs is content-addressed and shared across
  sandboxes.

## Quickstart

**1. Install runtime dependencies**

```sh
hack/fetch-artifacts.sh
```

This fetches `cloud-hypervisor` and `virtiofsd` static binaries into
`~/.local/bin` and checks for `mkfs.erofs` (install via your distro package
manager if missing). No `passt` — egress is izbad-owned over vsock.

**2. Build the kernel and initramfs**

```sh
hack/build-kernel.sh
hack/build-initramfs.sh
```

**3. Run a sandbox**

```sh
izba run --image alpine:3.20 .
```

This creates (if needed), starts, and drops you into a shell inside the
sandbox, with your current directory shared at `/workspace`.

See [`docs/testing.md`](docs/testing.md) for the full runbook and the
integration test suite.

## Commands

```
izba create [--image IMG] [--cpus N] [--mem MiB] [--rw-size-gb G] [-p [BIND:]HOST:GUEST]... [--volume [NAME:]GUEST_PATH:SIZE]... [DIR]
izba run    [--image IMG] [NAME_OR_DIR] [-- CMD...]
izba exec   NAME [-it] [-- CMD...]
izba cp     HOST_PATH NAME:GUEST_PATH   # or NAME:GUEST_PATH HOST_PATH; recursive
izba port   publish|unpublish|ls NAME [RULE]   # TCP, runtime or create-time -p
izba volume prune [-f]                  # remove persistent volumes no sandbox uses
izba ls
izba stop   NAME
izba rm     [--force] NAME
izba daemon run                         # run the daemon in the foreground (auto-started on demand otherwise)
izba daemon status                      # daemon health + supervised sandboxes
izba daemon stop                        # stop the daemon; sandboxes keep running, published ports pause
```

## Project layout

```
crates/
  izba-core/   # sandbox lifecycle, VMM driver trait + Cloud Hypervisor driver,
               #   OCI image → rootfs pipeline, guest control-plane client
  izba-cli/    # `izba` binary — thin wrapper over izba-core; auto-starts izbad
  izba-init/   # guest PID 1 agent (static musl x86_64); boots, mounts,
               #   and serves the control + stream ports
  izba-proto/  # host↔guest protocol types shared by core and init
  izba-ttytest/ # dev-support: PTY/ConPTY harness driving the real izba binary
               #   through a pseudo-terminal for automated exec -it tests
hack/          # scripts to fetch binaries and build the kernel/initramfs
docs/          # architecture notes, design spec, testing runbook
```

## Documentation

| Doc | Read it for |
| --- | --- |
| [docs/superpowers/specs/2026-06-10-izba-v1-design.md](docs/superpowers/specs/2026-06-10-izba-v1-design.md) | The v1 design: every decision with its rationale, deferred scope, open spikes |
| [docs/design-lineage.md](docs/design-lineage.md) | Design lineage & prior art — how each subsystem maps to its public OSS building blocks |
| [docs/testing.md](docs/testing.md) | End-to-end testing runbook (WSL2/KVM setup, integration suite) |
| [hack/README.md](hack/README.md) | Building the kernel/initramfs and fetching runtime binaries |
| [CLAUDE.md](CLAUDE.md) | Contributor/agent crash course: build gates, crate map, load-bearing contracts |

## License

[Apache-2.0](LICENSE).
