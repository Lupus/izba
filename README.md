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
          ──spawns──► passt      (user-mode NAT)    ◄────┤  ├ overlay rootfs      │
          ──connects─► vsock port 1025 (control RPC) ◄───┤  ├ /workspace virtiofs │
                       vsock port 1026 (stdio streams)◄──┤  └ spawns workloads    │
                                                         └────────────────────────┘
```

Key properties:

- **Daemonless.** The CLI spawns the VMM detached and exits. A running sandbox
  is fully described by its state directory
  (`~/.local/share/izba/sandboxes/<name>/`); any later invocation reconstructs
  everything from disk — no background service required.
- **Disk-state as source of truth.** `state.json` records every PID with its
  `starttime` field from `/proc/<pid>/stat` to defeat PID reuse.
- **Two vsock ports.** Port 1025 carries length-prefixed JSON control RPCs
  (Health, Exec, Wait, Resize, Shutdown). Port 1026 carries raw stdio/tty
  streams.
- **Unprivileged user-mode networking.** `passt --vhost-user` provides NAT
  with no TAP device, no bridge, and no root on the host.
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
`~/.local/bin` and checks for `passt` and `mkfs.erofs` (install via your
distro package manager if missing).

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
izba create [--image IMG] [--cpus N] [--mem MiB] [--rw-size-gb G] [-p [BIND:]HOST:GUEST]... [DIR]
izba run    [--image IMG] [NAME_OR_DIR] [-- CMD...]
izba exec   NAME [-it] [-- CMD...]
izba cp     HOST_PATH NAME:GUEST_PATH   # or NAME:GUEST_PATH HOST_PATH; recursive
izba port   publish|unpublish|ls NAME [RULE]   # TCP, runtime or create-time -p
izba ls
izba stop   NAME
izba rm     [--force] NAME
```

## Project layout

```
crates/
  izba-core/   # sandbox lifecycle, VMM driver trait + Cloud Hypervisor driver,
               #   OCI image → rootfs pipeline, guest control-plane client
  izba-cli/    # `izba` binary — thin, daemonless wrapper over izba-core
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
