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

**CI coverage:** the same suites run on GitHub-hosted runners via
`.github/workflows/e2e.yml` (KVM on ubuntu-latest, OpenVMM/WHP on
windows-latest) on every push to main, weekly, and on manual dispatch — see
`docs/superpowers/specs/2026-06-12-e2e-ci-design.md`. This runbook remains
the local-development path. Historic hosted-runner gap: ConPTY child output
did not flow in the Windows runner's session, so the tty Tier-1/Tier-2 tests
auto-skipped there behind a ConPTY canary (a trivial echo-through-ConPTY smoke
test). The windows-whp job now sideloads a modern, sha-pinned ConPTY backend
(`hack/ci/stage-conpty.ps1` drops `conpty.dll` + `OpenConsole.exe` next to the
test exe, which portable-pty's `load_conpty()` prefers over the host's stale
system conhost); if the canary then passes, the tty tests run for real. The
canary still gates them, so a runner that still loses output skips rather than
fails. `.github/workflows/conpty-diag.yml` is a standalone, VM-free probe that
captures `CONPTY-ENV`/`CONPTY-DIAG` evidence and reports the fix verdict.
Linux tty steps stay unconditional; the manual spike-host route (§8) is
unaffected.

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

Distro packages (erofs-utils for image conversion, cpio for the initramfs
build). **passt is no longer required** — as of M1 all guest egress flows
through izbad over vsock; there is no host-side user-mode NIC:

```sh
sudo apt install -y erofs-utils cpio
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

Build the guest kernel (one-time, ~5–10 min; needs a C toolchain). The
`hack/kernel.config` fragment now also carries the M1 egress bits —
netfilter/nftables (`NF_TABLES`/`NFT_NAT`/`NFT_REDIR`/`NF_CONNTRACK`) for the
guest TCP REDIRECT stub and `CONFIG_DUMMY` for the NIC-less `dummy0` interface:

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

The initramfs needs a static `nft` for the M1 egress stub's TCP REDIRECT
ruleset — build it with `hack/build-nft.sh` (writes `dist/nft`) and embed it
via `IZBA_NFT`. Optionally also embed a static `mke2fs` (`IZBA_MKE2FS`) so the
guest can format a blank scratch disk on first boot (the
`first_boot_formats_blank_rw` test; self-skips without it):

```sh
hack/build-nft.sh                                       # → dist/nft (needs Docker)
IZBA_NFT=dist/nft \
IZBA_MKE2FS=/path/to/static/mke2fs \
  hack/build-initramfs.sh
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
  VM (1 vCPU / 1 GiB) plus a virtiofsd sidecar (no passt — egress rides izbad
  over vsock now), and serial execution keeps the `--nocapture` output
  readable. Parallel runs work if you have the RAM.
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

## 5. Daemon e2e

Tests in `crates/izba-cli/tests/daemon_e2e.rs` exercise auto-start, kill-adopt,
stop-survival, idle-timeout, and upgrade-dance using a real KVM sandbox. Same
prerequisites as §4 (KVM + artifacts + env vars).

```sh
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 --nocapture
```

Env knobs available for the daemon tests:

- `IZBA_DAEMON_IDLE_SECS` — seconds of inactivity before the daemon self-exits
  (default 900; set to `0` to disable idle-exit).
- `IZBA_DAEMON_TICK_MS` — supervision tick interval in milliseconds (default 2000).
- `IZBA_DAEMON_VERSION` — version string override, used by upgrade-dance tests.

The Windows PowerShell gate (`hack/spike/validate-izba-windows.ps1`) also
validates daemon kill-adopt + stop-survival on Windows.

## 6. Manual smoke test

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

## 7. Troubleshooting

**Where to look first:** the guest serial console is written to
`<root>/sandboxes/<name>/logs/console.log` (`<root>` is
`~/.local/share/izba` for the CLI, or the test's tempdir — boot-failure
panics in the suite print the console tail automatically). Sidecar logs sit
next to it: `vmm.log`, `virtiofsd-workspace.log` (there is no `passt.log` —
egress is izbad-owned; egress decisions land in the izbad/daemon log).

| Symptom | Cause / fix |
| --- | --- |
| `boot ... did not become healthy` and `vmm.log` mentions `/dev/kvm` | No KVM. Re-do §1; verify `[ -w /dev/kvm ]`. |
| `mkfs.erofs not found ... — install it or set IZBA_MKFS_EROFS` from `ensure_image` | `sudo apt install erofs-utils` (needs ≥ 1.8 for `--tar=f`; build from source on older distros). |
| start error naming `fs-workspace.sock` | `virtiofsd` missing/failed — check `virtiofsd-workspace.log`, re-run `hack/fetch-artifacts.sh`. |
| console.log: `rw disk is blank and initramfs has no mke2fs` | Neither host `mkfs.ext4` nor guest `mke2fs` available. Install `e2fsprogs`, or rebuild the initramfs with `IZBA_MKE2FS=...`. |
| console.log stops after kernel lines, no izba-init output | Kernel/initramfs mismatch or missing config — rebuild both with the `hack/` scripts (the kernel needs the `hack/kernel.config` fragment: virtio, vsock, erofs, overlayfs, plus M1's netfilter/nftables + `CONFIG_DUMMY`, built-in). |
| Guest can't reach the network (DNS/HTTP egress fails) | Egress flows through izbad over vsock 1027 — check the izbad/daemon log for `egress allow ...` lines and dial-out errors; confirm the guest stub bound (`/sbin/nft` present in the initramfs, `IZBA_NFT` set at build). An app that hardcodes an external UDP resolver (e.g. `8.8.8.8`) is a known M1 gap — use `resolv.conf` (loopback). |
| `sandbox '<name>' is busy` | Another izba process holds the per-sandbox flock; wait for it or find it with `fuser '<root>/sandboxes/.<name>.lock'` (the lock lives beside the sandbox dir). |
| Boot consistently > 5 s warning in `boot_to_healthy_under_5s` | Expected on slow/loaded machines; the hard budget is 10 s. Investigate console.log timestamps if it is near 10 s. |

## 8. Windows validation (manual, spike host)

The Windows port is CI-validated by the `windows-whp` job in
`.github/workflows/e2e.yml`; this section is the manual spike-host route.
Validation is script-driven on a Windows 11 host with WHP enabled. Build +
stage from WSL, then run the parity suite:

```sh
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
hack/fetch-openvmm.sh && hack/build-mkfs-erofs-windows.sh   # if dist/ is stale
hack/stage-izba-windows.sh
# Windows side (PowerShell 7):
pwsh -NoProfile -File hack/spike/validate-izba-windows.ps1
```

Expected: `ALL PASS` (25 checks — boot, exec, exit codes, stdin, izbad egress
(DNS + HTTP through vsock 1027), console capture, daemon lifecycle,
stop/restart/rm). Validated on the VPN-topology host that produced the
original consomme guest-egress failure — that failure is retired with
consomme. The interactive `exec -it` checklist (PTY, VT rendering, resize,
Ctrl-C, mode restore) is in the
[Plan 2 doc](superpowers/plans/2026-06-10-izba-windows-port-p2.md), Task 5.

**Historical (pre-M1, no longer applies).** Guest egress on Windows used to
ride OpenVMM's consomme NAT, which advertised IPv6 (SLAAC) to the guest
whenever the host had *any* non-link-local IPv6 address — a Tailscale/VPN ULA
was enough — and guest IPv6 connects then died host-side as instant RSTs
(`Connection refused`, racing SLAAC). The fix at the time was the OpenVMM
driver appending `izba.ipv4only=1` and izba-init disabling eth0 IPv6. **M1
removed consomme entirely**: there is no guest NIC, all egress flows through
izbad over vsock, and both `consomme` and `izba.ipv4only=1` are gone from the
datapath — the whole SLAAC-race bug class is structurally eliminated, on both
platforms.

## exec -it terminal harness

Automated replacement for the manual `exec -it` operator checklist
(`crates/izba-ttytest`; design:
docs/superpowers/specs/2026-06-11-izba-tty-test-harness-design.md). It drives the
real `izba` binary through a real PTY (Linux) / ConPTY (Windows) and asserts on
the rendered screen, so vim rendering, arrow-key/VT input, Ctrl-C, window
resize, and exit-code mapping are checked automatically instead of by hand.

- **Tier 1 (no VM, both OSes, CI):** drives the real `izba` binary through a
  PTY/ConPTY against a scripted fake guest (no KVM/OpenVMM, no artifacts).
  Includes the vim `0xbd` width-probe regression guard for the Windows console
  byte bug.

  ```sh
  cargo test -p izba-cli --features ttytests --test tty_scripted -- --test-threads=1
  ```

  Self-skips where a PTY cannot be allocated. The scripted guest binds a Unix
  socket, so in restrictive sandboxes that deny `bind` the tests runtime-skip.

- **Tier 2 (real sandbox, env-gated):** full end-to-end against KVM (Linux) or
  the OpenVMM spike host (Windows) — the only tier where real Ctrl-C->SIGINT and
  real vim reflow happen.

  ```sh
  IZBA_TTY_E2E=1 IZBA_DATA_DIR=<dir> \
    cargo test -p izba-cli --features ttytests --test tty_e2e -- --test-threads=1
  ```

  Self-skips unless `IZBA_TTY_E2E=1`.

The harness is feature-gated (`ttytests`, off by default) so the six standard
build gates never run or lint these tests.

## vsock churn stressor (ttystorm)

`crates/izba-core/examples/ttystorm.rs` drives real `tty: true` exec streams
under load — the diagnostic that localized both the Windows vim-hang and the
OpenVMM vsock-assert crash. By default it goes through izbad (the production
datapath: `GuestRpc` + `OpenStream` splice); `--direct` dials `run/vsock.sock`
itself (the pre-daemon shape) to stress the raw VMM. It needs a *running*
sandbox and never auto-starts a daemon (its `current_exe` is not `izba`).

```sh
# Linux/KVM, via izbad (run a sandbox first):
cargo run -p izba-core --example ttystorm -- <name> floodfast 5 1024
# Windows/OpenVMM (staged binary):
C:\izba\bin\ttystorm.exe <name> floodfast 20 2048
```

Modes: `burst|bidi|mixed|inonly|bidiecho|floodfast|reactive|vim|chop`. A 15 s
watchdog exits 2 on a stall (`WEDGED`). `floodfast` keeps reading until the
writer drains (loopback backpressure otherwise self-deadlocks); `chop` is the
assert reproducer — read once, stop, drop while the relay write is wedged.

**M0 gate (OpenVMM vsock under churn) — exit criteria, validated 2026-06-12.**
The crash is `virtio_vsock connections.rs:1093` ("connection should have been
removed"); it aborts the whole VM (`mesh child ... code=0xc0000409`). Root
cause + upstream-issue draft + Plan-B patch:
`docs/superpowers/specs/2026-06-12-openvmm-vsock-assert-issue.md` and
`hack/openvmm-vsock-assert.patch`. The izba-side mitigation is the
`shutdown(Write)`+**drain** teardown in `portfwd.rs`/`daemon/server.rs`
(`copy_until_eof` keeps consuming the vsock leg after a peer write fails, so
the relay socket is never force-closed with guest TX buffered).

- **Via izbad (production):** `floodfast 20 2048` and `chop 30 256` run clean,
  VM stays alive (`izba exec ... -- echo` after the run succeeds). This is the
  gate.
- **Control, `--direct`:** `chop --direct` reproduces the assert and kills the
  VM (`openvmm` process gone, `izba ls` shows `stopped`) — proves the bug is
  real and the mitigation is what protects. The VM-death is honest (disk-state
  invariant): `izba run <name>` recovers cleanly.
