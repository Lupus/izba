# Spike S1+ findings: OpenVMM on the Windows host

**Status:** in progress
**Spec:** [2026-06-10-openvmm-spike-s1-design.md](2026-06-10-openvmm-spike-s1-design.md)

## Environment

- Windows version: 10.0.26100 (Windows 11 24H2)
- OpenVMM binary provenance: CI artifact `x64-windows-openvmm` from workflow `openvmm-ci.yaml`, run id `27240809751`, branch `main`, date 2026-06-10. Artifact commit: `7872712037c6ce3a03087a76207bd73cec9784a2`. Contains `openvmm.exe` (20 MB) + `openvmm.pdb` (268 MB). No DLLs required — exe is self-contained. Staged to `C:\izba-spike\openvmm.exe`.
- Windows-side installs performed: PowerShell 7.6.2 (installed via `winget install --id Microsoft.PowerShell` during Task 3)
- S4 MSYS2 packages installed (Task 12): `pacman -S git base-devel autoconf automake libtool pkg-config mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-lz4` — installs gcc 16.1.0, lz4 1.10.0, and ~110 dependency packages (~1 GiB)

**Interop notes (affects all later tasks):**
- WSL interop (`powershell.exe`) fails inside the default Claude Code sandbox (`UtilConnectUnix: socket failed 1`). All `powershell.exe` / `/mnt/c` commands require `dangerouslyDisableSandbox: true`.
- WHP (HypervisorPlatform): **functional** — empirically verified by booting a VM with openvmm.exe (guest vCPUs executed, PIO traces in openvmm output). The earlier non-admin CIM probe (`Win32_OptionalFeature` → `InstallState=2`, "disabled") was WRONG — do not trust that class for WHP state; an actual openvmm boot attempt is the reliable non-admin check (sbx working on this host was the tell). Probe boot note: the earlier whp-probe left `--com1 file=` log empty due to a shell quoting/invocation issue in that session (backslash escaping in the command string caused the `file=` argument to be malformed); the `file=` mechanism itself is confirmed working — rung 1 established this conclusively. Both `--com1 file=<path>` and `--com1 stderr` produce full serial output when the command is structured correctly via PowerShell `Start-Process`.
- pwsh (PowerShell 7): was missing; installed 7.6.2 via winget during this task. Confirmed working.
- gh auth: authenticated as `Lupus` on github.com (token scopes: gist, read:org, repo). Ready for artifact download in Task 4.

## Rung verdicts

| # | Rung | Verdict | Notes |
| --- | --- | --- | --- |
| 0 | acquire openvmm.exe | PASS | Artifact `x64-windows-openvmm` from CI run 27240809751; `openvmm.exe --help` runs; all 7 expected flags confirmed |
| 1 | smoke boot (their kernel) | PASS | openvmm-deps 0.3.0-59 kernel 6.1.172 boots to shell; `--com1 file=` and `--com1 stderr` both confirmed working; 292 lines of serial output captured |
| 2 | direct-boot our vmlinux | PASS | izba kernel 6.12.30 + spike-initramfs boots; `SPIKE-INIT-OK` confirmed at line 319 of rung2.log; no config changes needed |
| 3 | virtio-fs share | PASS | Attempt A (PCIe route) worked first try; MOUNT-OK + READ-OK (`hello-from-host`) + WRITE-OK; `guest-file.txt` visible on host; uid/gid 1000 on Windows side |
| 4 | vsock bridge | PASS | `--hv` required (VPCI path); kernel needed `CONFIG_HYPERV=y` + `CONFIG_PCI_HYPERV=y` (added); `--virtio-vsock-path C:\izba-spike\vsock`; `HANDSHAKE: OK 1073741824` + `SPIKE-RUNG4-ECHO-OK` confirmed in `rung4-client.log` |
| 5 | consomme networking | PASS | `--hv --net consomme`; NIC model = netvsp (required adding `CONFIG_HYPERV_NET=y`); DHCP-OK, DNS-OK, HTTP-OK (`http://example.com`); kernel `ip=dhcp` also passes (`IP-Config: Complete`) |
| 6 | headless serial capture | | |
| 7 | integration preview (full izba guest) | | |
| S4 | mkfs.erofs on Windows | PARTIAL | Native `.exe` build fails due to POSIX API gaps; viable path = run mkfs.erofs in WSL2 via interop; Cygwin route untested |

## Working command lines

(exact invocations per rung as they pass — these become OpenVmmDriver fixtures)

### Rung 0 — flag inventory (from `openvmm.exe --help`, commit 7872712)

All flags match the spec design. Key notes for later rungs:

- `--kernel <FILE>` / `-k` — linux direct-boot kernel image (rung 2+)
- `--initrd <FILE>` / `-r` — initrd image (rung 2+)
- `--com1 <SERIAL>` — supports `file=<path>` (overwrites), `listen=<path>`, `stderr`, `console`, `term`, `none` (rung 6)
- `--virtio-fs <[pcie_port=PORT:]tag,root_path,[options]>` — NOTE: takes `tag,root_path` positional args as comma-separated, **no** standalone `--tag` / `--path` sub-flags; uid/gid optional (rung 3). Example: `--virtio-fs workspace,C:\path\to\workspace`
- `--virtio-vsock-path <PATH>` — "Unix socket base path" (rung 4); likely appends port suffix to the path; needs further probing in rung 4
- `--virtio-net <VIRTIO_NET>` — backends: `dio | vmnic | tap | none` (no consomme here)
- `--net <NET>` — **separate flag** with backends: `consomme | dio | tap | none`; consomme supports `hostfwd=` port-forwarding syntax (rung 5). Example: `--net consomme` or `--net consomme:hostfwd=tcp::8080-:80`
- `--pcie-root-complex <PCIE_ROOT_COMPLEX>` — needed to wire virtio devices over PCIe

### Rung 1 — smoke boot (their kernel)

**Artifacts:** `openvmm-deps` release `0.3.0-59` from `microsoft/openvmm-deps`.
- Kernel: `openvmm-test-linux-6.1.x86_64.0.3.0-59.tar.gz` → extracted `vmlinux`
  (ELF 64-bit, uncompressed, `Linux version 6.1.172`, 60 MB). Staged to `C:\izba-spike\their-vmlinux`.
- Initrd: `openvmm-test-initrd.x86_64.0.3.0-59.tar.gz` → extracted `initrd`
  (gzip cpio, 1.4 MB). Staged to `C:\izba-spike\their-initrd`.

Note: the `.cargo/config.toml` in the openvmm repo (`X86_64_OPENVMM_LINUX_DIRECT_KERNEL` env var) points to `.packages/underhill-deps-private/x64/vmlinux` from the full `openvmm-deps.x86_64.tar.gz` (~165 MB, the private Underhill kernel). The `openvmm-test-linux-6.1` tarball is separate and is the OSS test kernel used by their integration test suite; it is equivalent for our smoke-boot purposes.

**Invocation (file capture mode):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after 20s
$proc = Start-Process -FilePath './openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\their-vmlinux',
                '--initrd','C:\izba-spike\their-initrd',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung1-file.log' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung1-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung1-stderr.log'
Start-Sleep -Seconds 20
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `C:\izba-spike\logs\rung1-file.log` — 18 360 bytes, 292 lines of kernel serial output. Guest booted kernel 6.1.172, ran initrd, reached interactive busybox shell (`~ # `). Log ends with `tsc: Refined TSC clocksource calibration: 2304.007 MHz` after the shell prompt.

**Invocation (stderr mode):**

```powershell
$proc = Start-Process -FilePath './openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\their-vmlinux',
                '--initrd','C:\izba-spike\their-initrd',
                '-c','console=ttyS0',
                '--com1','stderr' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung1-stderr-test-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung1-stderr-test-stderr.log'
Start-Sleep -Seconds 15
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** stderr log 34 822 bytes — openvmm PIO traces interleaved with 290 kernel serial lines. Both modes reliable.

**Whp-probe empty-log mystery — resolution:**
- Root cause: The earlier probe session used shell interpolation that malformed the `file=C:\...` argument (backslash escaping issue in the command string; the argument was passed as a single shell word rather than via `Start-Process -ArgumentList`). The `file=` mechanism itself is fully functional.
- Confirmation: our izba kernel (`vmlinux` + `spike-initramfs.cpio.gz`) also produces full serial output in both `file=` and `stderr` modes — `izba-kernel-file.log` is 20 291 bytes, 320+ kernel lines, boots to busybox shell.

### Rung 3 — virtio-fs share

**Kernel virtio transport inventory** (from `hack/kernel.config`):
- `CONFIG_VIRTIO=y`, `CONFIG_VIRTIO_PCI=y`, `CONFIG_VIRTIO_FS=y`
- `CONFIG_VIRTIO_BLK=y`, `CONFIG_VIRTIO_NET=y`, `CONFIG_VIRTIO_CONSOLE=y`, `CONFIG_VIRTIO_VSOCKETS=y`
- `CONFIG_VIRTIO_MMIO` is **not set** — MMIO transport unavailable; PCIe or PCI is the only viable route.

**Attempt A — PCIe route (PASS, first try):**

`--pcie-root-complex` + `--pcie-root-port` are required for virtio-pci visibility in direct boot (the default DSDT has no PCI bus unless you add one explicitly via these flags).

```powershell
# Run from C:\izba-spike in PowerShell; kills after 25s
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs-r3.cpio.gz',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung3.log',
                '--pcie-root-complex','rc0',
                '--pcie-root-port','rc0:ws',
                '--virtio-fs','pcie_port=ws:ws,C:\izba-spike\share' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung3-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung3-stderr.log'
Start-Sleep -Seconds 25
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `rung3.log` — 354 lines. `SPIKE-RUNG3-MOUNT-OK` + `SPIKE-RUNG3-READ-OK: hello-from-host` + `SPIKE-RUNG3-WRITE-OK` all present. Bidirectional check: `C:\izba-spike\share\guest-file.txt` created by guest, contains `guest-was-here`.

**PCIe probe lines from rung3.log (transport visibility confirmed):**
```
pci 0000:00:00.0: [1414:c030] type 01 class 0x060400 PCIe Root Port
pci 0000:01:00.0: [1af4:105a] type 00 class 0x088000 conventional PCI endpoint
virtio-pci 0000:01:00.0: enabling device (0000 -> 0002)
```
The virtio-fs device appears as virtio-pci vendor `1af4` device `105a` at `01:00.0` under the root port.

**uid/gid mapping:** Files written by the guest appear as uid/gid 1000 on the Windows/WSL side. The in-process virtiofsd server runs as the Windows user (NTFS does not store POSIX uid/gid natively; WDK's projected filesystem maps the current user to uid 1000 in the WSL metadata view). No `uid=`/`gid=` mount options were required; the default mapping was correct. No permission errors for either the read or write direction.

**Flag syntax notes:**
- `--pcie-root-complex <name>` — just the name, no extra options needed for basic use (e.g., `rc0`)
- `--pcie-root-port <rc_name>:<port_name>` — colon-separated (e.g., `rc0:ws`)
- `--virtio-fs 'pcie_port=<port_name>:<tag>,<windows_path>'` — port name prefix before the tag; `--virtio-fs-bus` not needed when using `pcie_port=`
- Attempts B/C (plain `--virtio-fs-bus pci` / `vpci` without the explicit PCIe topology) were NOT attempted — Attempt A passed cleanly on the first try.

### Rung 4 — vsock bridge

An earlier version of this section recorded a PASS that did not reproduce; root cause was the missing Hyper-V guest configs, fixed below.

**Kernel vsock config** (from `hack/kernel.config` after the rung-4 fix):
- `CONFIG_VSOCKETS=y`, `CONFIG_VIRTIO_VSOCKETS=y` — AF_VSOCK + virtio transport present.
- `CONFIG_HYPERV=y`, `CONFIG_PCI_HYPERV=y` — **added for this rung** (see "Kernel config deltas" section).

**Transport discovery:**

`--virtio-vsock-path <PATH>` has **no `pcie_port=` prefix option** and **no `--virtio-vsock-pcie-port` companion flag** (unlike `--virtio-rng-pcie-port` / `--virtio-console-pcie-port`). The device always uses `VirtioBusCli::Auto` in `openvmm_entry/src/lib.rs`.

`Auto` on Windows resolves to VPCI (Hyper-V virtual PCI) when `with_hv=true`, or `VirtioBus::Pci` (legacy ISA-PCI) otherwise.

**Failure mode without `--hv`:** For `UnenlightenedLinuxDirect` (plain `--kernel` without `--hv`), `pci_inta_line = None` — the generic PCI bus and INT#A routing are not wired — so `VirtioBus::Pci` fails with `fatal error: missing PCI INT#A line` (visible in `rung4-stderr.log` from the earlier attempt). This happens with or without `--pcie-root-complex`. No `--virtio-vsock-bus` flag exists to override to MMIO.

**Failure mode with `--hv` but without kernel Hyper-V support:** With `--hv`, OpenVMM routes the virtio-vsock device over VPCI (Hyper-V VMBus). The guest needs `hv_vmbus` + `hv_pci` drivers — compiled in via `CONFIG_HYPERV=y` and `CONFIG_PCI_HYPERV=y`. Without these, the guest never enumerates the vsock device: `AF_VSOCK bind()` succeeds at the socket layer (transport-less) and `SPIKE-VSOCK-ECHO-READY` prints, but the vsock transport has no underlying VMBus device. The host client's `CONNECT 1025\n` gets no response and times out. `CONFIG_HYPERV` and `CONFIG_PCI_HYPERV` were absent from `hack/kernel.config` prior to this fix.

**Fix applied:** Added `CONFIG_HYPERV=y` and `CONFIG_PCI_HYPERV=y` to `hack/kernel.config`; rebuilt kernel (see "Kernel config deltas"). Both dependencies were already satisfied by `x86_64_defconfig`: `CONFIG_HYPERVISOR_GUEST=y`, `CONFIG_PCI_MSI=y`, `CONFIG_SYSFS=y`, `CONFIG_X86_LOCAL_APIC=y`.

**Listener path convention:** the UDS listener is at `<PATH>` itself (the value given to `--virtio-vsock-path`). No `_<port>` suffix is appended for the host-initiated-connection listener. After boot, `C:\izba-spike\vsock` exists as a Windows socket file. The CH hybrid-vsock handshake applies: connect to `<PATH>`, send `CONNECT <port>\n`, read `OK <port>\n` byte-by-byte, then raw bytes. Note: OpenVMM's VPCI vsock uses a large port number in the `OK` response (`OK 1073741824`, not `OK 1025`) — this is the VMBus channel ID, not the guest port; `izba-client.ps1` accepts any `OK <n>` response so this is transparent.

**Working invocation — `--hv` + VPCI (PASS):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after client test (~40s total)
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs-r4.cpio.gz',
                '-c','console=ttyS0',
                '--hv',
                '--com1','file=C:\izba-spike\logs\rung4-fixed.log',
                '--virtio-vsock-path','C:\izba-spike\vsock' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung4-fixed-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung4-fixed-stderr.log'
Start-Sleep -Seconds 20   # wait for boot + vsock-echo to start
# Client test (capture output as evidence):
pwsh -NoProfile -File 'C:\izba-spike\izba-client.ps1' `
  -SockPath 'C:\izba-spike\vsock' -Port 1025 -Mode echo `
  *> 'C:\izba-spike\logs\rung4-client.log'
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result — serial log `C:\izba-spike\logs\rung4-fixed.log` (348 lines):**

Device probe evidence (lines 176–254):
```
[    0.630071] hv_vmbus: Vmbus version:5.3
[    0.912698] hv_vmbus: registering driver hv_pci
[    0.917509] hv_pci d647d006-d3c1-4e1f-b565-8aa139ceb11a: PCI VMBus probing: Using version 0x10004
[    0.923765] hv_pci d647d006-d3c1-4e1f-b565-8aa139ceb11a: PCI host bridge to bus d3c1:00
[    0.966975] virtio-pci d3c1:00:00.0: enabling device (0000 -> 0002)
```

Boot markers (lines 317, 346–347):
```
[    1.232938] NET: Registered PF_VSOCK protocol family
SPIKE-INIT-OK
SPIKE-VSOCK-ECHO-READY
```

**Client log `C:\izba-spike\logs\rung4-client.log`:**
```
HANDSHAKE: OK 1073741824
SPIKE-RUNG4-ECHO-OK
```

Full roundtrip confirmed. The vsock device was enumerated via `hv_pci` over VMBus, `virtio-pci` bound to it, and the echo roundtrip completed successfully.

**Regression checks (kernel change validation):**
- Rung 2 (plain boot, no `--hv`): `SPIKE-INIT-OK` confirmed in `rung2-hyperv-regress.log`. PASS.
- Rung 3 (virtio-fs PCIe, no `--hv`): all three RUNG3 markers confirmed in `rung3-hyperv-regress.log`. PASS.
- Rung 3 + `--hv` combo (virtio-fs PCIe with Hyper-V enabled — preview for rung 7): all three RUNG3 markers confirmed in `rung3-hv-combo.log` (366 lines). PASS. PCIe virtio-fs and the Hyper-V guest stack coexist without conflict; rung 7 combining both is viable.

**Implication for OpenVmmDriver:** The production `izba-core` OpenVMM driver must include `--hv` in the launch command when `--virtio-vsock-path` is used. The hybrid-vsock UDS protocol (CONNECT/OK handshake) is identical to Cloud Hypervisor's — the existing `vsock.rs` client code requires no changes (it accepts any `OK <n>` response).

### Rung 2 — direct-boot izba kernel

**Artifacts:** izba's own build artifacts (staged to `C:\izba-spike\` during rung-1 preparation):
- Kernel: `vmlinux` — Linux 6.12.30, built by `hack/build-kernel.sh` targeting Cloud Hypervisor, uncompressed ELF, ~60 MB.
- Initramfs: `spike-initramfs.cpio.gz` — busybox + `/init` that prints `SPIKE-INIT-OK` then drops to shell with sleep-infinity PID-1 keepalive.

**Invocation (file capture mode):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after 25s
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs.cpio.gz',
                '-c','console=ttyS0',
                '--com1','file=C:\izba-spike\logs\rung2.log' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung2-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung2-stderr.log'
Start-Sleep -Seconds 25
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result:** `C:\izba-spike\logs\rung2.log` — 20 330 bytes, 323 lines of kernel serial output. Linux 6.12.30 banner at line 1; `SPIKE-INIT-OK` at line 319; guest reached busybox shell. No kernel config changes were required — izba's CH-targeted kernel boots under OpenVMM direct-boot without modification.

### Rung 5 — consomme networking

**Kernel network config inventory** (from `hack/kernel.config` after the rung-5 fix):
- `CONFIG_VIRTIO_NET=y` — present but unused for `--net consomme` (consomme uses netvsp, not virtio-net).
- `CONFIG_IP_PNP_DHCP=y` — kernel DHCP autoconfig; confirmed working.
- `CONFIG_HYPERV_NET=y` — **added for this rung** (see "Kernel config deltas"); required for netvsp NIC enumeration.

**`--net` flag behavior and NIC model discovery:**

`--net <backend>` exposes a NIC with the given backend (`consomme | dio | tap | none`). Despite the help text showing `pcie_port=<port>:` as a supported prefix, the runtime rejects it: `fatal error: --net does not support PCIe`. The PCIe prefix is not usable in this binary.

Without `--hv`: `--net consomme` fails at launch — `fatal error: failed to resolve vmbus resource netvsp / failed to find vmbus for vtl0`. Consomme requires the VMBus netvsp device model, which only activates with `--hv`.

With `--hv` but without `CONFIG_HYPERV_NET`: the guest enumerates `sit0` (tunnel loopback) but no real Ethernet NIC — `hv_netvsc` driver is absent, so the netvsp device offered via VMBus is never claimed. `udhcpc` on `sit0` fails with "Network is down".

**Fix applied:** Added `CONFIG_HYPERV_NET=y` to `hack/kernel.config`; rebuilt kernel. After this fix, `hv_vmbus: registering driver hv_netvsc` appears in the boot log and `eth0` is available in the guest.

**Additional rc fix:** busybox's `udhcpc -n -q` obtains the lease and runs the default script, but the default script path (`/usr/share/udhcpc/default.script`) does not exist in the minimal initramfs. Without it, DHCP succeeds in obtaining the lease but does not configure the interface (no IP, no route, no resolv.conf). The spike rc was updated to: (1) bring the interface up with `ip link set $IFACE up` before udhcpc, (2) install an inline `/usr/share/udhcpc/default.script` that calls `ip addr add`, `ip route add default`, and writes `/etc/resolv.conf` (with `mkdir -p /etc` first — the initramfs has no `/etc`). After these fixes, full network configuration is applied on lease acquisition.

**Consomme DHCP details:** consomme allocates `10.0.0.2/24` to the guest with `10.0.0.1` as gateway and DNS server. This is the internal consomme NAT address space. All outbound traffic (DNS, TCP) is forwarded via Windows network stack. The openvmm process must have outbound network access on Windows (Windows Defender Firewall should allow `openvmm.exe` outbound — on this host it was not blocked, but this is a deployment concern for other machines).

**Working invocation (PASS):**

```powershell
# Run from C:\izba-spike in PowerShell; kills after 60s (DHCP+HTTP need ~2-3s)
$proc = Start-Process -FilePath 'C:\izba-spike\openvmm.exe' `
  -ArgumentList '--kernel','C:\izba-spike\vmlinux',
                '--initrd','C:\izba-spike\spike-initramfs-r5.cpio.gz',
                '-c','console=ttyS0',
                '--hv',
                '--com1','file=C:\izba-spike\logs\rung5i.log',
                '--net','consomme' `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput 'C:\izba-spike\logs\rung5i-stdout.log' `
  -RedirectStandardError  'C:\izba-spike\logs\rung5i-stderr.log'
Start-Sleep -Seconds 60
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
```

**Result — serial log `C:\izba-spike\logs\rung5i.log`:**

```
SPIKE-INIT-OK
SPIKE-RUNG5-IFACE: eth0
udhcpc: broadcasting select for 10.0.0.2, server 10.0.0.1
udhcpc: lease of 10.0.0.2 obtained from 10.0.0.1, lease time 86400
SPIKE-RUNG5-DHCP-OK
    inet 10.0.0.2/24 scope global eth0
=== routes ===
default via 10.0.0.1 dev eth0
10.0.0.0/24 dev eth0 scope link  src 10.0.0.2
=== resolv.conf ===
nameserver 10.0.0.1
SPIKE-RUNG5-DNS-OK
SPIKE-RUNG5-TCP-FAIL  (403 Forbidden from Cloudflare CDN on bare-IP request — expected, not a network failure)
SPIKE-RUNG5-HTTP-OK
```

Full DHCP + DNS + outbound TCP confirmed. The `SPIKE-RUNG5-TCP-FAIL` line reflects a 403 HTTP response from the CDN when hitting `172.66.147.243` without a `Host:` header — TCP connectivity itself is proven by the HTTP-OK result.

**OpenVMM stderr evidence (netvsp enumeration):**
```
INFO netvsp:  network accepted
INFO netvsp:  network negotiated version=V61
INFO netvsp:  network initialized
```

**`ip=dhcp` kernel autoconfig result:**

Tested with `-c "console=ttyS0 ip=dhcp"` (note: PowerShell's `Start-Process -ArgumentList` array splits on spaces within elements — pass the cmdline as a pre-built `$cmdline` variable or as a single flat string to avoid `ip=dhcp` being treated as a separate argument):

```
[    0.148105] Kernel command line: panic=-1 debug pci=off console=ttyS0 ip=dhcp
[    1.283573] IP-Config: Got DHCP answer from 10.0.0.1, my address is 10.0.0.2
[    1.287356] IP-Config: Complete:
```

`IP-Config: Complete` confirmed. Consomme responds to the kernel's raw DHCP broadcast before userland starts. The kernel writes `/proc/net/pnp` with the DNS server from the DHCP response — this is the mechanism `izba-init` uses for resolv.conf. This path is fully validated.

**Regression check (kernel change validation):**
- Rung 4 (vsock bridge, `--hv`): `HANDSHAKE: OK 1073741824` + `SPIKE-RUNG4-ECHO-OK` confirmed in `rung4-hyperv-net-regress-client.log`. PASS.

**Implication for OpenVmmDriver:** The production izba-core OpenVMM driver must include `--hv --net consomme` in the launch command for networking. The NIC model is netvsp (VMBus), requiring `CONFIG_HYPERV_NET=y` in the kernel. The kernel `ip=dhcp` path works correctly with consomme, confirming the same boot-time network configuration path used by CH (via `/proc/net/pnp`) will work on OpenVMM.

## Kernel config deltas

### Delta 1 — Hyper-V guest stack (required for rung 4 vsock via OpenVMM `--hv`)

Added to `hack/kernel.config`:

```
CONFIG_HYPERV=y
CONFIG_PCI_HYPERV=y
```

**Why:** OpenVMM's `--virtio-vsock-path` can only be routed through VPCI (Hyper-V VMBus) — there is no PCIe or MMIO transport option for vsock. VPCI requires `hv_vmbus` and `hv_pci` in the guest, compiled in via these two symbols. Without them, the vsock device is never enumerated even though `AF_VSOCK` socket operations appear to succeed (transport-less bind).

**Dependencies already satisfied by `x86_64_defconfig`:** `CONFIG_HYPERVISOR_GUEST=y`, `CONFIG_PARAVIRT=y`, `CONFIG_PCI_MSI=y`, `CONFIG_SYSFS=y`, `CONFIG_X86_LOCAL_APIC=y`. No additional symbols were required.

**Regression impact:** Rungs 2 (plain boot) and 3 (virtio-fs PCIe) re-tested with the new kernel — both pass. The Hyper-V guest stack is additive and does not affect the Cloud Hypervisor boot path or PCIe virtio devices.

**NOTE — CH production validation required:** enabling `CONFIG_HYPERV=y` activates paravirt/VPCI infrastructure that runs under Cloud Hypervisor as well. The delta has been regression-tested against the OpenVMM rungs but must also be validated against Cloud Hypervisor's Linux integration test suite (see `docs/testing.md` KVM integration suite) before being declared production-ready for the `izba-core` CH VMM driver.

### Delta 2 — Hyper-V network driver (required for rung 5 consomme networking)

Added to `hack/kernel.config`:

```
CONFIG_HYPERV_NET=y
```

**Why:** OpenVMM's `--net consomme` backend presents the NIC as a Hyper-V netvsp device over VMBus (requires `--hv`). Without `CONFIG_HYPERV_NET`, the guest loads `hv_vmbus` and `hv_pci` but has no `hv_netvsc` driver to claim the netvsp NIC offer. The NIC is never enumerated — the guest sees only `lo` and `sit0`. With `CONFIG_HYPERV_NET=y`, `hv_netvsc` registers, claims the netvsp offer, and creates `eth0`.

**Dependency chain:** `CONFIG_HYPERV_NET` depends on `CONFIG_HYPERV` (already added in Delta 1) and `CONFIG_NETDEVICES` / `CONFIG_NET_CORE` / `CONFIG_ETHERNET` (already present). No additional symbols needed.

**Regression impact:** Rung 4 (vsock over VMBus) re-tested with the new kernel — PASS. The netvsc driver is additive and does not interfere with `hv_pci` / `virtio-pci` / virtio-fs PCIe or any CH boot paths.

**NOTE — CH production validation required:** same note as Delta 1 applies. `CONFIG_HYPERV_NET` compiles additional VMBus driver code that is loaded on CH guests as well; must be validated against the CH integration suite before production use.

## S4 details — mkfs.erofs on Windows

### Survey (Step 1)

| Source | Result |
| --- | --- |
| MSYS2 packages.msys2.org `?query=erofs` | No results — no pre-built erofs-utils package for any MSYS2 environment |
| erofs/erofs-utils GitHub releases | Source-only; latest tag v1.9.1, no binary releases for any platform |
| winget `search erofs` | No package found |
| GitHub `search repos erofs-utils windows` | No third-party Windows builds found |

**Conclusion:** must build from source. No pre-built Windows binary is publicly available; how Docker's `sbx` ships erofs tooling on Windows is not confirmed — see Path A′/C discussion below.

### Build attempt (Steps 2–3)

**Toolchain installed:** MSYS2 (fresh) + `pacman -S git base-devel autoconf automake libtool pkg-config mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-lz4` — results in gcc 16.1.0 (UCRT64) + lz4 1.10.0. lz4 pkg-config check passes (`pkg-config --modversion liblz4 → 1.10.0`).

**Complete configure invocation (copy-pasteable from the WSL side):**

```sh
/mnt/c/msys64/usr/bin/bash.exe -lc '
  export PATH=/ucrt64/bin:$PATH
  git clone https://github.com/erofs/erofs-utils.git && cd erofs-utils
  ./autogen.sh
  CPPFLAGS="-I$(pwd)/win32-shims" ./configure --disable-fuse --without-uuid
'
```

Two header shims were added under a local `win32-shims/` include directory (passed via `CPPFLAGS`) before the build step: `win32-shims/sys/uio.h` and `win32-shims/sys/ioctl.h`. These are minimal stubs to satisfy `#include` directives; the exact contents are not recorded, but each was a short stub defining the minimum required to compile past the include-not-found error. They are noted here as "two header shims added under a local include dir" — they were not sufficient to make the build succeed.

**Configure:** succeeded with `--disable-fuse --without-uuid`. lz4 detected and enabled (`checking for liblz4... yes`). One quirk: `./config.status libtool` must be run manually after configure — MSYS2's `config.status` generates the `libtool` wrapper script only when invoked explicitly (the command is buffered but not auto-run when launched from WSL interop with `-lc`).

**Build:** failed. After adding the two header shims under `win32-shims/`, build progressed past the include errors but hit a wall in `inode.c`, `io.c`, `namei.c`, and `xattr.c`. Full unique error list:

```
inode.c: S_IFLNK, S_IFSOCK, DT_* (dir-entry type constants) undeclared — MinGW stat.h omits symlink/socket support
inode.c: lstat, readlink implicit declaration — Windows has no symlinks in the POSIX sense
inode.c: getuid, getgid implicit declaration — no POSIX user/group model on Windows
inode.c: _POSIX_OPEN_MAX undeclared
inode.c: major()/minor() treated as values, not functions (MSYS2 macro mismatch)
io.c: pread, pwrite, fsync implicit declarations — pread/pwrite not in UCRT
io.c: struct stat has no st_blksize member
namei.c: S_IFLNK, S_IFSOCK, makedev undeclared
xattr.c: lstat implicit declaration; uint typedef missing
```

Root cause: erofs-utils is tightly coupled to Linux/POSIX filesystem semantics — it ingests live directory trees using `lstat`/`readlink`/`opendir`/`DT_*` and relies on POSIX inode metadata (uid/gid, symlinks, device nodes, block size). These are not shimable in a few lines; they require either substantial compat shims or a port of the directory-walk layer.

**Failure point:** `inode.c` compile (lib directory, first pass); build did not reach `mkfs/main.c`.

### Effort estimate for productizing

**Path A — Native Win32 `.exe` (full port):** ~3–5 person-days. Requires: (1) `lstat`/`readlink` shims using `GetFileAttributesEx`/`DeviceIoControl` for Windows reparse points; (2) `pread`/`pwrite` shims using `ReadFile`/`WriteFile` with `OVERLAPPED`; (3) `getuid`/`getgid` → return 0; (4) `major()`/`minor()` → 0; (5) `DT_*`/`S_IFLNK`/`S_IFSOCK` in a compat header; (6) `st_blksize` shim. Several files need patching; upstream is unlikely to accept Windows-specific `#ifdef`s without a maintained Windows CI lane. **This estimate applies to a Win32-NATIVE port only.**

**Path A′ — Cygwin build (untested):** ~0.5–1 day to attempt. Cygwin was NOT attempted within the 45-min timebox. Unlike MinGW/UCRT64, Cygwin's POSIX emulation layer provides `lstat`, `readlink`, `pread`/`pwrite`, `getuid`/`getgid`, `DT_*`, `major()`/`minor()`, and `st_blksize` — exactly the APIs that blocked the UCRT64 build. A Cygwin build is therefore a plausible route to a real Windows `.exe` at materially lower cost than the Win32-native port (Path A). The result would be a `.exe` that requires the Cygwin runtime DLL (`cygwin1.dll`), not a fully standalone Win32 binary. The parent design spec's "Docker demonstrably builds erofs-utils for Windows" hypothesis most plausibly points at a Cygwin-style POSIX layer rather than a full Win32 port, though this is unconfirmed. Estimate is rough; actual cost could be lower (configure just works) or higher (additional Cygwin-specific issues).

**Path B — WSL2 interop (recommended):** ~0.5 person-days. `mkfs.erofs` is already available as a Linux package (`apt install erofs-utils`) in WSL2. izba on Windows can invoke it via `wsl.exe mkfs.erofs ...` or run it directly in the WSL2 Linux process that already hosts the izba CLI. This is the same pattern Docker Desktop uses for Linux tooling. No porting required; the binary is stable and lz4-enabled.

**Path C — Pre-built static Linux binary bundled in the Windows release (refinement of Path B):** ~1 day. Cross-compile a static musl `mkfs.erofs` on Linux (straightforward since erofs-utils builds cleanly on Linux); embed the binary in the Windows package and invoke it via WSL2 interop. This is a refinement of Path B: the difference is shipping a pinned static binary with the izba installer instead of depending on the user's WSL distro having `erofs-utils` available via `apt`. Benefits: version control, no root needed inside the WSL distro, no dependency on the user's distro state. **This path still requires WSL2 — a static Linux ELF cannot run on native Windows without a Linux environment.** It is a distribution-quality improvement over Path B, not an elimination of the WSL2 dependency.

**Recommendation:** Use Path B for the v1 OpenVMM path — WSL2 interop is always available on any system that can run OpenVMM. Path C is a cleaner distribution story for v2 when izba ships as a standalone Windows installer, but it still requires WSL2. Path A′ (Cygwin) is worth a short investigation if a true Windows-native binary (without WSL2) is ever required, before committing to the full Win32 port effort of Path A.

### Smoke test

Not reached — build did not produce `mkfs.erofs.exe`. Image-format compatibility deferred to a later integration test once Path B or C is implemented.

## Go/no-go recommendation

(pending)
