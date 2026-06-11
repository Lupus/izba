# izba end-to-end testing runbook

The integration suite (`crates/izba-core/tests/integration.rs`) boots real
cloud-hypervisor microVMs, so it needs KVM and the runtime binaries. The
tests are gated: without `IZBA_INTEGRATION=1` every test prints a `SKIP` note
and passes, so plain `cargo test` stays green everywhere.

This runbook targets WSL2 Ubuntu on Windows 11, but everything except §1
applies to any Linux host with KVM.

Artifact tooling details live in [../hack/README.md](../hack/README.md); the
design behind what these tests assert is in
[superpowers/specs/2026-06-10-izba-v1-design.md](superpowers/specs/2026-06-10-izba-v1-design.md) §7.

---

## 1. One-time WSL2 setup (nested virtualization → /dev/kvm)

On the **Windows** side, create or edit `%UserProfile%\.wslconfig`:

```ini
[wsl2]
nestedVirtualization=true
```

Then restart WSL from a Windows terminal:

```powershell
wsl --shutdown
```

Reopen your WSL shell and verify the KVM device exists:

```sh
ls -l /dev/kvm
```

If it exists but you get permission errors, add yourself to the `kvm` group
(then log out and back in, or `wsl --shutdown` again):

```sh
sudo usermod -aG kvm $USER
```

On some distros `/dev/kvm` is root-only regardless of group; the quick fix
is:

```sh
sudo chmod 666 /dev/kvm
```

(That resets on reboot; for something permanent add a udev rule:
`echo 'KERNEL=="kvm", GROUP="kvm", MODE="0660"' | sudo tee /etc/udev/rules.d/99-kvm.rules`.)

Final check — this must succeed without sudo:

```sh
[ -r /dev/kvm ] && [ -w /dev/kvm ] && echo kvm-ok
```

## 2. Host dependencies

Distro packages (passt for user-mode networking, erofs-utils for image
conversion, cpio for the initramfs build):

```sh
sudo apt install -y passt erofs-utils cpio
```

Static binaries (cloud-hypervisor + virtiofsd, installed to
`~/.local/bin` — make sure that is on your `PATH`):

```sh
hack/fetch-artifacts.sh
```

Re-run with `--check` at any time to see what is present vs. missing:

```sh
hack/fetch-artifacts.sh --check
```

Optional but recommended: `e2fsprogs` provides the host-side `mkfs.ext4`,
which lets `create` pre-format the sandbox scratch disk (it is preinstalled
on Ubuntu).

## 3. Boot artifacts (kernel + initramfs)

Build the guest kernel (one-time, ~5–10 min; needs a C toolchain):

```sh
sudo apt install -y build-essential flex bison bc libelf-dev
hack/build-kernel.sh          # → dist/vmlinux
```

Build the initramfs containing the static izba-init (needs the
`x86_64-unknown-linux-musl` Rust target):

```sh
rustup target add x86_64-unknown-linux-musl
hack/build-initramfs.sh       # → dist/initramfs.cpio.gz
```

Optionally embed a static `mke2fs` so the guest can format a blank scratch
disk on first boot (this is what the `first_boot_formats_blank_rw` test
exercises; without it that test self-skips):

```sh
IZBA_MKE2FS=/path/to/static/mke2fs hack/build-initramfs.sh
```

Install the artifacts where the CLI looks for them by default:

```sh
mkdir -p ~/.local/share/izba/artifacts
cp dist/vmlinux               ~/.local/share/izba/artifacts/vmlinux
cp dist/initramfs.cpio.gz     ~/.local/share/izba/artifacts/initramfs.cpio.gz
```

…or skip the copy and point the env vars straight at `dist/` (the
integration suite requires the env vars either way; see below).

## 4. Running the integration suite

```sh
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
cargo test -p izba-core --test integration -- --test-threads=1 --nocapture
```

Notes:

- `--test-threads=1` is recommended, not required: each test boots its own
  VM (1 vCPU / 1 GiB) plus a virtiofsd and passt sidecar, and serial
  execution keeps the `--nocapture` output readable. Parallel runs work if
  you have the RAM.
- The test image (default `alpine:3.20`, override with `IZBA_TEST_IMAGE`)
  is pulled from the registry **once per run** into a shared cache. Set
  `IZBA_TEST_CACHE=$HOME/.cache/izba-itest` to persist that cache across
  runs and skip the pull entirely.
- With `IZBA_INTEGRATION=1` set but the host not ready, the first test
  panics with a list of **all** missing pieces (kvm, binaries, env vars) at
  once.
- Each test creates its sandboxes under a private tempdir and force-removes
  them on the way out (even on panic), so failed runs do not pollute
  `~/.local/share/izba`.

## 5. Manual smoke test

```sh
cargo build --release
target/release/izba run --image alpine:3.20 .
```

Expected flow (first run):

```text
pulling alpine:3.20...
/workspace # echo $((6*7))
42
/workspace # cat /etc/alpine-release
3.20.x
/workspace # exit
```

The prompt is a root shell inside the microVM; the current host directory is
mounted at `/workspace`. Other quick checks:

```sh
target/release/izba ls                       # sandbox should show as running
target/release/izba exec <name> -- uname -a  # one-shot exec
target/release/izba stop <name>
target/release/izba rm <name>
```

(`<name>` is the sanitized basename of the workspace directory; `izba ls`
shows it.)

## 6. Troubleshooting

**Where to look first:** the guest serial console is written to
`<root>/sandboxes/<name>/logs/console.log` (`<root>` is
`~/.local/share/izba` for the CLI, or the test's tempdir — boot-failure
panics in the suite print the console tail automatically). Sidecar logs sit
next to it: `vmm.log`, `passt.log`, `virtiofsd-workspace.log`.

| Symptom | Cause / fix |
| --- | --- |
| `boot ... did not become healthy` and `vmm.log` mentions `/dev/kvm` | No KVM. Re-do §1; verify `[ -w /dev/kvm ]`. |
| start error naming `net.sock` (`passt did not create ... within 3s` or spawn failure) | `passt` missing or too old (needs `--vhost-user`). `sudo apt install passt`; Ubuntu ≤ 22.04 may need a backport. |
| `mkfs.erofs not found ... — install it or set IZBA_MKFS_EROFS` from `ensure_image` | `sudo apt install erofs-utils` (needs ≥ 1.8 for `--tar=f`; build from source on older distros). |
| start error naming `fs-workspace.sock` | `virtiofsd` missing/failed — check `virtiofsd-workspace.log`, re-run `hack/fetch-artifacts.sh`. |
| console.log: `rw disk is blank and initramfs has no mke2fs` | Neither host `mkfs.ext4` nor guest `mke2fs` available. Install `e2fsprogs`, or rebuild the initramfs with `IZBA_MKE2FS=...`. |
| console.log stops after kernel lines, no izba-init output | Kernel/initramfs mismatch or missing config — rebuild both with the `hack/` scripts (the kernel needs the `hack/kernel.config` fragment: virtio, vsock, erofs, overlayfs built-in). |
| Guest has no network (the `guest_networking` test fails) | Check `passt.log`; DHCP inside the guest comes from passt. Corporate VPNs/firewalls on the Windows host can also block WSL2 egress. |
| `sandbox '<name>' is busy` | Another izba process holds the per-sandbox flock; wait for it or find it with `fuser '<root>/sandboxes/.<name>.lock'` (the lock lives beside the sandbox dir). |
| Boot consistently > 5 s warning in `boot_to_healthy_under_5s` | Expected on slow/loaded machines; the hard budget is 10 s. Investigate console.log timestamps if it is near 10 s. |

## 7. Windows validation (manual, spike host)

The Windows port has no CI; validation is script-driven on a Windows 11
host with WHP enabled. Build + stage from WSL, then run the parity suite:

```sh
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
hack/fetch-openvmm.sh && hack/build-mkfs-erofs-windows.sh   # if dist/ is stale
hack/stage-izba-windows.sh
# Windows side (PowerShell 7):
pwsh -NoProfile -File hack/spike/validate-izba-windows.ps1
```

Expected: `ALL PASS` (15 checks — boot, exec, exit codes, stdin, network,
console capture, stop/restart/rm lifecycle). The interactive `exec -it`
checklist (PTY, VT rendering, resize, Ctrl-C, mode restore) is in the
[Plan 2 doc](superpowers/plans/2026-06-10-izba-windows-port-p2.md), Task 5.
