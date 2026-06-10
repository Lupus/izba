# Spike S1+: OpenVMM on the Windows host — design

**Status:** approved
**Date:** 2026-06-10
**Parent:** [izba v1 design](2026-06-10-izba-v1-design.md) §8 (spikes S1, S4)

The v1 design gates the entire Windows/WHP half of izba on spike S1: prove,
from the shipped `openvmm` CLI on Windows, that the three capabilities the
`OpenVmmDriver` needs actually work — direct Linux boot, virtio-fs share,
vsock-to-host bridging. This spec designs that spike. Scope was extended
(user decision) to also cover consomme networking, serial console capture,
and S4 (`mkfs.erofs` on Windows). No driver code is written during the spike;
its output is a findings doc that feeds the `OpenVmmDriver` design.

## 1. Questions the spike answers

| # | Question | Why it matters |
| --- | --- | --- |
| Q1 | Can we obtain a working `openvmm.exe` (CI artifact or source build), and what does that cost? | Shapes izba's artifact-distribution story on Windows (`hack/fetch-artifacts.sh` equivalent) |
| Q2 | Does our existing `vmlinux` (built by `hack/build-kernel.sh` for Cloud Hypervisor) direct-boot under OpenVMM, or does `hack/kernel.config` need changes? | One kernel artifact for both platforms vs per-platform kernels |
| Q3 | Does the in-process `--virtio-fs` server share a host directory read/write into the guest? | The `/workspace` contract; replaces virtiofsd entirely on Windows |
| Q4 | Does `--virtio-vsock-path` give a host-reachable bridge compatible with izba's `CONNECT <port>\n` client? | The whole control plane (ports 1025/1026) rides on this |
| Q5 | Does consomme give the guest DHCP + DNS + outbound TCP? | The spec's chosen Windows networking path (no passt on Windows) |
| Q6 | Can the serial console be captured to a file headlessly? | izba's `logs/console.log` debuggability contract |
| Q7 | (S4) Can `mkfs.erofs` run on Windows? | Image pipeline; fallback (guest-side ext4 provisioning) already specced |
| Q8 | Does the **unmodified** izba guest stack (erofs + rw disk + virtiofs + izba-init + izba-proto) come up under OpenVMM? | If yes, the Windows port is host-side integration glue only |

## 2. Facts already established (2026-06-10 research, not spike questions)

Verified against `microsoft/openvmm` HEAD (Guide + source):

- **No GitHub releases.** Prebuilts are CI artifacts of the `openvmm-ci.yaml`
  workflow; downloading requires GitHub auth (`gh run download`). Source build
  needs rustup + MSVC Build Tools on Windows.
- **Direct Linux boot:** `--kernel <PATH>` (uncompressed ELF vmlinux, not
  bzImage), `--initrd <PATH>`, `-c <STRING>` for extra cmdline. OpenVMM uses
  its own loader — PVH is irrelevant here (the CH-motivated `CONFIG_PVH=y`
  is harmless).
- **PCI is opt-in for direct boot:** without `--pcie-root-complex` +
  `--pcie-root-port`, the DSDT exposes no PCI bus and virtio-pci devices are
  invisible to the guest. The Alpine guide documents the working recipe;
  devices take a `pcie_port=<name>:` prefix.
- **virtio-fs server is in-process:** `--virtio-fs tag,root_path[,options]`
  (uid/gid mapping options exist; also `--virtio-fs-bus pci|mmio|auto`).
  No virtiofsd sidecar exists on Windows.
- **Hybrid vsock is wire-compatible with Cloud Hypervisor**
  (`support/hybrid_vsock`, `vm/devices/virtio/virtio_vsock/connections.rs`):
  `--virtio-vsock-path <PATH>` creates a UDS listener; host connects, sends
  `CONNECT <port>\n`, gets `OK <port>\n` once the guest accepts; raw bytes
  after. Guest-initiated connections land on `<PATH>_<port>` listeners —
  the same Firecracker-style convention CH uses. izba's `vsock.rs` protocol
  logic should apply verbatim.
- **Caveat for the future driver, not the spike:** Rust `std` has no AF_UNIX
  on Windows; the host side will need `uds_windows` or equivalent. The spike
  tests the bridge with a script client instead.
- **Serial:** `--com1 (console | stderr | listen=<path> | file=<path> |
  term | none)` — `file=` is the `console.log` contract directly. Quit via
  interactive console: `ctrl-q`, then `q`.
- **Networking:** `--virtio-net pcie_port=<port>:consomme` — user-mode NAT
  with built-in DHCP server, gateway DNS proxy, outbound-only by default
  (`hostfwd` exists for inbound; izba doesn't need it).
- **OpenVMM's own disclaimer:** host-VMM mode is the less-trodden path —
  "not yet ready to run end-user workloads", no CLI stability guarantees.
  The spike exists to find where that bites; findings must record the exact
  commit/run the binary came from.

## 3. Execution environment

- **Driver:** Claude in WSL2 drives the Windows side via interop
  (`/mnt/c/...` for files, `powershell.exe` / direct `.exe` for processes),
  handing commands to the user only where sandbox or interop blocks.
- **Windows workspace:** `C:\izba-spike\` — openvmm binary, kernel, initramfs
  images, `share\` directory for virtio-fs, logs. Disposable; not a repo.
- **Guest artifacts** are built in WSL with existing `hack/` tooling and
  copied to `C:\izba-spike\`.
- **Precondition check:** the *Windows Hypervisor Platform* optional feature
  must be enabled (`Get-WindowsOptionalFeature -Online -FeatureName
  HypervisorPlatform`); enable + reboot if not.
- **Install policy (user-approved):** Windows-side tooling (gh artifacts,
  rustup, MSVC Build Tools, MSYS2 for S4) may be installed as needed; every
  install is logged in the findings doc.

## 4. The capability ladder

Approach: strict ladder (approved as "Approach A") — each rung isolates one
risk so failures are attributable to a single layer. Rungs run in order;
a rung's exact flags are refined from the previous rung's working command
line. S4 (§5) runs in parallel, it shares nothing with the ladder.

New repo artifacts needed by the ladder (committed under `hack/`):

- **Spike busybox initramfs:** a static busybox + `rdinit=/bin/sh` cpio —
  gives rungs 2–5 a shell, `mount`, `udhcpc`, `wget`. (The production
  initramfs contains only izba-init, which needs the full disk layout.)
- **`vsock-echo` helper:** a tiny static-musl binary that listens on
  AF_VSOCK port 1025 and echoes lines; dropped into the spike initramfs
  for rung 4. (Reusing the musl toolchain we already require.)

| # | Rung | Command sketch | Pass criterion | On failure |
| --- | --- | --- | --- | --- |
| 0 | Acquire `openvmm.exe` | `gh run download` from `openvmm-ci.yaml` artifacts; else clone + `cargo build` on Windows | `openvmm.exe --help` runs | Source build. If that also fails: spike blocked, reassess with findings so far |
| 1 | Smoke boot, *their* guest | their sample kernel + initrd from `openvmm-deps` (as used by `cargo run` defaults) | interactive shell on COM1 | Host/WHP problem, not our artifacts: debug Windows feature, binary deps |
| 2 | Direct-boot *our* kernel | `--kernel vmlinux --initrd spike-initramfs.cpio.gz -c "rdinit=/bin/sh console=ttyS0"` | shell prompt from our kernel | Diff `hack/kernel.config` against their sample kernel config (virtio transport, console); rebuild via `hack/build-kernel.sh` — an expected detour, not a spike failure |
| 3 | virtio-fs share | rung-2 cmd + `--pcie-root-complex --pcie-root-port ws` + `--virtio-fs pcie_port=ws:ws,C:\izba-spike\share`; guest: `mount -t virtiofs ws /mnt` | files written on either side visible on the other | Try `--virtio-fs-bus mmio`; try uid/gid options; record semantics gaps (symlinks, case sensitivity) |
| 4 | vsock bridge | rung-2 cmd + `--virtio-vsock-path C:\izba-spike\vsock`; guest runs `vsock-echo`; host script connects to the UDS, sends `CONNECT 1025\n` | `OK 1025` reply + echo roundtrip | Confirm guest kernel has `CONFIG_VIRTIO_VSOCKETS`; try GUID-form CONNECT; last resort: vmbus hvsocket path (needs `CONFIG_HYPERV_VSOCKETS` — kernel change, document cost) |
| 5 | consomme networking | rung-3 PCIe flags + `--virtio-net pcie_port=net:consomme`; guest: `udhcpc` then `wget http://example.com` | DHCP lease acquired; HTTP fetch succeeds (proves DNS + TCP) | Document the gap precisely; try legacy `--nic`; networking has no easy fallback on Windows — a hard failure here is a real driver-design problem |
| 6 | Headless serial capture | rung-2 cmd with `--com1 file=C:\izba-spike\console.log` | boot messages land in the file; VM can be killed without a console | Try `listen=`/`stderr` variants; some capture mode must work for `console.log` parity |
| 7 | **Integration preview** | full izba guest: `--virtio-blk` rootfs.erofs (RO) + rw.img, `--virtio-fs` tag `workspace`, real production initramfs, izba cmdline contract; host script speaks izba-proto over the vsock bridge | `Health` answered; `Exec` of a command in `/workspace` returns its output and exit code | Whichever single capability regressed under combination is the divergence point; record it — this rung failing while 2–6 pass still leaves S1 substantially answered |

Rung 7 passing means the guest half of izba ships on Windows **unchanged**
and the port is host-side glue only — the strongest possible S1 outcome.

Note: disk attachment flag specifics for rung 7 (`--virtio-blk` vs
vmbus-scsi `--disk`, raw-image support on Windows hosts, read-only flags)
are resolved during rung 7 itself from the Alpine-guide recipe; both device
paths exist in the CLI.

## 5. S4 parallel track: `mkfs.erofs` on Windows

1. Survey existing Windows binaries of erofs-utils (erofs-utils releases,
   MSYS2 packages, anything Docker's sbx ships that's redistributable).
2. If none usable: attempt an MSYS2/MinGW build of erofs-utils (+ liblz4).
   Docker demonstrably builds it for Windows, so this should be possible.
3. Output: feasibility verdict + effort estimate + (if built) the recipe.

S4 failing is not blocking: the v1 design already specs the fallback (ship
the flattened tar on a raw disk; init unpacks onto ext4 at first boot —
slower `create`, zero host tooling).

## 6. Outputs and exit criteria

The spike produces **one findings document**
(`docs/superpowers/specs/<completion-date>-openvmm-spike-s1-findings.md`)
containing:

- per-rung verdict (pass / pass-with-caveats / fail) with the **exact working
  command lines** (these become `OpenVmmDriver::build_invocations` test
  fixtures),
- the OpenVMM commit/CI run the binary came from, and the build recipe if
  built from source,
- every Windows-side install performed,
- kernel-config deltas if rung 2 forced any,
- S4 verdict,
- a **go/no-go recommendation** for the `OpenVmmDriver`, naming which spec
  §4.1 assumptions held and which need revision.

The spike is **done** when rungs 0–6 each have a verdict (rung 7 is
best-effort but expected), S4 has a verdict, and the findings doc exists.
It is a **go** if rungs 2, 3, 4 pass (boot, virtio-fs, vsock — the original
S1 trio); networking/serial caveats shape the driver design but don't block
it. Per the parent spec, a no-go means the Windows port slips and v1 ships
Linux-first — that decision returns to the user, not the spike.

Repo changes from the spike are limited to: this spec, the findings doc,
and `hack/` additions for the spike guest (busybox initramfs builder,
`vsock-echo` helper). The `OpenVmmDriver` itself gets its own design + plan
after the findings are in.
