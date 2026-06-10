# izba — design lineage & prior art

Where izba's architecture comes from. izba is an **independent open-source
implementation** assembled from public, permissively-licensed building blocks;
this document maps each subsystem to the prior art it is grounded in, so any
design choice can be traced to its open-source lineage rather than to any single
product.

Docker Desktop's agent sandboxes (`sbx`) are acknowledged as the product that
**proved the per-project-microVM model for AI coding agents and set the UX bar**
— izba's motivation and ergonomic reference point. izba does not use or derive
from any Docker code; the architecture below is built from the OSS substrate that
predates and underlies that whole category (rust-vmm, Firecracker, Cloud
Hypervisor, virtiofs, the containerd erofs snapshotter, and NVIDIA OpenShell).

## Subsystem → prior art

| izba subsystem | Choice | Public prior art / lineage |
| --- | --- | --- |
| VMM (Linux/KVM) | **Cloud Hypervisor** behind a thin driver trait | Cloud Hypervisor + the [rust-vmm](https://github.com/rust-vmm) ecosystem (the shared substrate behind Cloud Hypervisor, Firecracker, crosvm) |
| VMM (Windows/WHP) | **OpenVMM** | [microsoft/openvmm](https://github.com/microsoft/openvmm) (MIT) on the Windows Hypervisor Platform |
| virtio device models, vsock | virtio-blk / -fs / -vsock; hybrid-vsock UDS bridge | rust-vmm `vm-virtio`; the Firecracker hybrid-vsock host convention (shared by CH and OpenVMM) |
| Workspace share | **virtiofs** (FUSE-over-virtio), `/workspace` | virtiofs / [virtiofsd](https://virtio-fs.gitlab.io/) — a ratified OASIS VIRTIO 1.2 standard, mainline since Linux 5.4 / QEMU 4.2 (originated at Red Hat) |
| Rootfs | OCI → **erofs** (read-only) + ext4 **overlay** | the [containerd erofs snapshotter](https://github.com/containerd/containerd/blob/main/docs/snapshotters/erofs.md) and the composefs/erofs image model ([containers/storage](https://github.com/containers/storage/pull/1646), Red Hat) |
| Snapshot / resume *(future)* | COW memory + on-demand page fault | the [Firecracker snapshot model](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md) (MAP_PRIVATE COW, Apache-2.0, AWS) |
| Egress firewall + credential injection *(M2/M5)* | in-process Rust policy proxy on `izbad`, per-service credential injection (the guest never holds the secret) | **[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)** (Apache-2.0) — the directly comparable shipped design and a permissively-licensed salvage source; [regorus](https://github.com/microsoft/regorus) (Microsoft) for policy; DNS-snoop modeled on Cilium toFQDNs + Azure Firewall. See [egress-firewall-building-blocks.md](egress-firewall-building-blocks.md). |
| Guest control plane | length-prefixed JSON frames over vsock (ports 1025/1026/1027) | containerd/ttrpc-style framed RPC over vsock; izba hand-rolls its own minimal framing |

## What izba does independently (and differently)

izba is not a port of any one system, and it diverges from `sbx` in several
load-bearing ways:

- **Off-the-shelf VMMs, not a bespoke one.** izba uses Cloud Hypervisor and
  OpenVMM behind a driver trait, rather than a from-scratch VMM.
- **Two plain virtio-blk disks, not a stitched descriptor.** The rootfs is
  `rootfs.erofs` (RO) + `rw.img` (RW) enumerated as vda/vdb and overlaid in the
  guest — no VMDK-descriptor layer-stitching.
- **Egress is an inverted vsock plane, not an HTTP proxy.** The guest is a
  NIC-less vsock island; all egress is *guest-initiated* over vsock 1027 to
  `izbad`, which is the sole point that dials out. This is structurally
  default-deny (the `dummy0` interface gives un-brokered traffic nowhere to go)
  rather than relying on `HTTP_PROXY` env or host NAT — a different mechanism
  from both `sbx` and OpenShell, even where the policy/credential logic is
  shared with OpenShell.
- **No host-side container engine.** izba runs the workload directly; a member
  that wants nested containers brings its own in-guest `dockerd`.

## Method

izba's design was developed against the public sources above. No Docker source
code is used or derived; subsystem choices, contracts, and code are izba's own
or lifted (with attribution) from compatibly-licensed open source — notably
Apache-2.0 modules from NVIDIA OpenShell for the egress/credential plane, vendored
per-file with their SPDX headers and a `NOTICE` stanza (see
[egress-firewall-building-blocks.md](egress-firewall-building-blocks.md) §3).
