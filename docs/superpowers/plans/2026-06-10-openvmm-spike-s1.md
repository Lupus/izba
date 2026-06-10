# OpenVMM Spike S1+ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the approved spike design ([spec](../specs/2026-06-10-openvmm-spike-s1-design.md)): prove (or disprove) that OpenVMM on the Windows 11 host can boot izba's kernel, share a directory via virtio-fs, bridge vsock to the host, provide consomme networking and serial capture — culminating in the unmodified izba guest stack answering izba-proto over the bridge; plus the S4 `mkfs.erofs`-on-Windows feasibility check.

**Architecture:** A strict capability ladder (rungs 0–7), each rung isolating one risk. Guest test workloads are non-interactive: a spike busybox initramfs runs an embedded `/spike.rc` script that prints grep-able `SPIKE-...` markers to the serial console, so every rung is verifiable from captured console output without interactive TTY plumbing through WSL interop. Findings are recorded per rung in a findings doc as they happen, not at the end.

**Tech Stack:** OpenVMM (WHP), WSL2↔Windows interop (`powershell.exe`, `/mnt/c`), existing `hack/` artifact tooling, static-musl Rust for the guest vsock helper, PowerShell 7 for the host-side UDS test client, MSYS2/MinGW for S4.

**Execution notes (read first):**

- This is a spike, not product code. The repo gains only: `hack/spike/` tooling, `hack/build-spike-initramfs.sh`, this plan, and the findings doc. No changes to `crates/`.
- **Every rung ends by appending its verdict to the findings doc** (created in Task 3). A failed rung is a *result*, not a blocker: record it, attempt the listed fallbacks, and continue to whatever rungs don't depend on it.
- Windows-side processes: launch `openvmm.exe` from WSL via interop with output captured; tear down with `powershell.exe -Command "Stop-Process -Name openvmm -Force"`. If interop swallows console output, add `--com1 file=C:\izba-spike\logs\<rung>.log` early (it's the rung-6 test anyway) and read the file instead.
- Windows paths in commands use `C:\izba-spike\...`; the same files are visible from WSL at `/mnt/c/izba-spike/...`.
- Per user-approved policy, Windows-side installs are allowed; log each one in the findings doc.

---

### Task 1: `vsock-echo` guest helper

A tiny static binary that listens on AF_VSOCK port 1025 and echoes bytes — the rung-4 guest endpoint. Standalone cargo workspace so the main workspace's gates (`cargo test/clippy --workspace`) are unaffected.

**Files:**
- Create: `hack/spike/vsock-echo/Cargo.toml`
- Create: `hack/spike/vsock-echo/src/main.rs`
- Create: `hack/spike/vsock-echo/.gitignore`

No unit tests: binding a vsock listener is impossible off-guest and the repo's test-design constraint forbids listener binds in tests anyway (CLAUDE.md). Verification is "builds static" here and the echo roundtrip in Task 8.

- [ ] **Step 1: Write the crate**

`hack/spike/vsock-echo/Cargo.toml`:

```toml
# Spike-only guest helper (see docs/superpowers/specs/2026-06-10-openvmm-spike-s1-design.md).
# Standalone workspace: intentionally NOT a member of the root izba workspace.
[workspace]

[package]
name = "vsock-echo"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
vsock = "0.5"
libc = "0.2"

[profile.release]
strip = true
```

`hack/spike/vsock-echo/src/main.rs`:

```rust
//! Spike rung-4 guest endpoint: echo every byte received on vsock port 1025.
//! Prints SPIKE-VSOCK-ECHO-READY once listening so the console log proves liveness.

use std::io::{Read, Write};

fn main() {
    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, 1025)
        .expect("bind vsock port 1025");
    println!("SPIKE-VSOCK-ECHO-READY");
    for conn in listener.incoming() {
        let mut conn = match conn {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    }
}
```

`hack/spike/vsock-echo/.gitignore`:

```
target/
Cargo.lock
```

- [ ] **Step 2: Build static and verify**

```sh
[ -f .cargo-env ] && source .cargo-env
cargo build --manifest-path hack/spike/vsock-echo/Cargo.toml \
  --target x86_64-unknown-linux-musl --release
file hack/spike/vsock-echo/target/x86_64-unknown-linux-musl/release/vsock-echo
```

Expected: `... statically linked` (or `static-pie linked`).

- [ ] **Step 3: Commit**

```sh
git add hack/spike/vsock-echo
git commit -m "feat(hack): vsock-echo guest helper for OpenVMM spike rung 4"
```

---

### Task 2: Spike initramfs builder + per-rung rc scripts

A busybox initramfs whose `/init` mounts pseudo-filesystems, runs an embedded `/spike.rc` if present, then drops to a shell. Each rung gets its own rc; rebuilding per rung is seconds.

**Files:**
- Create: `hack/build-spike-initramfs.sh`
- Create: `hack/spike/rc/rung3-virtiofs.sh`
- Create: `hack/spike/rc/rung4-vsock.sh`
- Create: `hack/spike/rc/rung5-net.sh`

- [ ] **Step 1: Write the builder**

`hack/build-spike-initramfs.sh`:

```sh
#!/usr/bin/env bash
# Build the SPIKE busybox initramfs (NOT the production izba-init one).
#
# Usage:
#   hack/build-spike-initramfs.sh OUTPUT [RC_FILE]
#   OUTPUT   e.g. dist/spike-initramfs.cpio.gz
#   RC_FILE  optional shell script embedded as /spike.rc, run by /init before
#            dropping to a shell (per-rung test payloads live in hack/spike/rc/)
#
# Environment:
#   BUSYBOX_URL  override the static-busybox download URL.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
[ -f .cargo-env ] && source .cargo-env

OUTPUT="${1:?usage: build-spike-initramfs.sh OUTPUT [RC_FILE]}"
RC_FILE="${2:-}"
mkdir -p "$(dirname "$OUTPUT")"

# Static busybox from the docker-library dist branch (musl, amd64).
BUSYBOX_URL="${BUSYBOX_URL:-https://raw.githubusercontent.com/docker-library/busybox/dist-amd64/stable/musl/busybox.tar.xz}"
CACHE="dist/.busybox"
if [ ! -x "$CACHE/bin/busybox" ]; then
    echo "Fetching static busybox..."
    mkdir -p "$CACHE"
    curl -fsSL "$BUSYBOX_URL" | tar -xJ -C "$CACHE"
    [ -x "$CACHE/bin/busybox" ] || { echo "error: no bin/busybox in archive" >&2; exit 1; }
fi

echo "Building vsock-echo (musl static)..."
cargo build --manifest-path hack/spike/vsock-echo/Cargo.toml \
    --target x86_64-unknown-linux-musl --release

WORK="$(mktemp -d)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/proc" "$WORK/sys" "$WORK/dev" "$WORK/tmp" "$WORK/mnt"
cp "$CACHE/bin/busybox" "$WORK/bin/busybox"
cp hack/spike/vsock-echo/target/x86_64-unknown-linux-musl/release/vsock-echo \
   "$WORK/bin/vsock-echo"
chmod 755 "$WORK/bin/busybox" "$WORK/bin/vsock-echo"

cat > "$WORK/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox --install -s /bin
echo SPIKE-INIT-OK
[ -f /spike.rc ] && /bin/busybox sh /spike.rc
# Try an interactive shell; with a file-backed serial console sh may exit
# instantly on EOF — keep PID 1 alive regardless (PID 1 exit = kernel panic,
# and rung 4 needs the VM running for the host-side echo test).
/bin/busybox sh
exec /bin/busybox sleep infinity
EOF
chmod 755 "$WORK/init"

if [ -n "$RC_FILE" ]; then
    cp "$RC_FILE" "$WORK/spike.rc"
    chmod 644 "$WORK/spike.rc"
fi

echo "Packing spike initramfs..."
( cd "$WORK" && find . | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -9 ) > "$OUTPUT"
echo "wrote $OUTPUT  ($(du -sh "$OUTPUT" | cut -f1))"
```

- [ ] **Step 2: Write the rung rc scripts**

`hack/spike/rc/rung3-virtiofs.sh`:

```sh
# Rung 3: mount the virtio-fs share (tag "ws"), prove both directions.
if mount -t virtiofs ws /mnt; then
    echo SPIKE-RUNG3-MOUNT-OK
    if [ -f /mnt/host-file.txt ]; then
        echo "SPIKE-RUNG3-READ-OK: $(cat /mnt/host-file.txt)"
    else
        echo SPIKE-RUNG3-READ-FAIL
    fi
    echo guest-was-here > /mnt/guest-file.txt \
        && echo SPIKE-RUNG3-WRITE-OK || echo SPIKE-RUNG3-WRITE-FAIL
else
    echo SPIKE-RUNG3-MOUNT-FAIL
fi
```

`hack/spike/rc/rung4-vsock.sh`:

```sh
# Rung 4: serve vsock echo on port 1025 (host connects via the UDS bridge).
# Stays in foreground in the background job; init still drops to a shell after.
vsock-echo &
```

`hack/spike/rc/rung5-net.sh`:

```sh
# Rung 5: DHCP lease from consomme, then DNS + outbound TCP via HTTP fetch.
IFACE=$(ls /sys/class/net | grep -v lo | head -1)
if [ -z "$IFACE" ]; then echo SPIKE-RUNG5-NODEV; exit 0; fi
echo "SPIKE-RUNG5-IFACE: $IFACE"
if udhcpc -i "$IFACE" -n -q; then
    echo SPIKE-RUNG5-DHCP-OK
    ip addr show "$IFACE" | grep 'inet '
    if wget -q -O - http://example.com >/dev/null 2>&1; then
        echo SPIKE-RUNG5-HTTP-OK
    else
        echo SPIKE-RUNG5-HTTP-FAIL
    fi
else
    echo SPIKE-RUNG5-DHCP-FAIL
fi
```

- [ ] **Step 3: Build the base (no-rc) image and verify contents**

```sh
chmod +x hack/build-spike-initramfs.sh
hack/build-spike-initramfs.sh dist/spike-initramfs.cpio.gz
zcat dist/spike-initramfs.cpio.gz | cpio -t | sort | head -20
```

Expected listing includes `init`, `bin/busybox`, `bin/vsock-echo`, `proc`, `sys`, `dev`, `mnt`.

- [ ] **Step 4: Commit**

```sh
git add hack/build-spike-initramfs.sh hack/spike/rc
git commit -m "feat(hack): spike busybox initramfs builder with per-rung rc payloads"
```

---

### Task 3: Windows preconditions, workspace, findings doc

**Files:**
- Create: `docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md` (rename date at completion if it slips)

- [ ] **Step 1: Verify interop works at all**

```sh
powershell.exe -NoProfile -Command "Get-Date; [Environment]::OSVersion.Version" 
```

Expected: a date + a `10.0.2xxxx`-class version. If this fails, STOP — the whole execution model is broken; switch to the "user runs, Claude guides" fallback from the spec §3.

- [ ] **Step 2: Check WHP + pwsh7 + gh**

```sh
powershell.exe -NoProfile -Command \
  "Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform | Select State"
powershell.exe -NoProfile -Command "pwsh -Version" || echo "pwsh7 MISSING"
gh auth status
```

Expected: `State : Enabled`; a PowerShell 7 version; gh authenticated.
- WHP disabled → ask the user before enabling (needs reboot): `Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform` (elevated).
- pwsh missing → `powershell.exe -Command "winget install --id Microsoft.PowerShell -e"` (log the install).
- gh unauthenticated → ask the user to run `! gh auth login` (rung 0 artifact download needs it; source build does not).

- [ ] **Step 3: Create the Windows workspace**

```sh
mkdir -p /mnt/c/izba-spike/share /mnt/c/izba-spike/logs
echo "hello-from-host" > /mnt/c/izba-spike/share/host-file.txt
```

- [ ] **Step 4: Create the findings doc skeleton and commit**

Create `docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md`:

```markdown
# Spike S1+ findings: OpenVMM on the Windows host

**Status:** in progress
**Spec:** [2026-06-10-openvmm-spike-s1-design.md](2026-06-10-openvmm-spike-s1-design.md)

## Environment

- Windows version:
- OpenVMM binary provenance (CI run / commit, or source-build recipe):
- Windows-side installs performed:

## Rung verdicts

| # | Rung | Verdict | Notes |
| --- | --- | --- | --- |
| 0 | acquire openvmm.exe | | |
| 1 | smoke boot (their kernel) | | |
| 2 | direct-boot our vmlinux | | |
| 3 | virtio-fs share | | |
| 4 | vsock bridge | | |
| 5 | consomme networking | | |
| 6 | headless serial capture | | |
| 7 | integration preview (full izba guest) | | |
| S4 | mkfs.erofs on Windows | | |

## Working command lines

(exact invocations per rung as they pass — these become OpenVmmDriver fixtures)

## Kernel config deltas

(none yet)

## Go/no-go recommendation

(pending)
```

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs: findings skeleton for OpenVMM spike S1+"
```

---

### Task 4: Rung 0 — acquire `openvmm.exe`

- [ ] **Step 1: Find the latest successful CI run and its artifact names**

```sh
RUN_ID=$(gh run list -R microsoft/openvmm -w openvmm-ci.yaml -b main -s success \
         -L 1 --json databaseId -q '.[0].databaseId')
echo "run: $RUN_ID"
gh api "repos/microsoft/openvmm/actions/runs/$RUN_ID/artifacts" \
  --jq '.artifacts[].name'
```

Expected: artifact names including something matching `*windows*` + `*openvmm*` for x64 (exact naming TBD by the listing — pick the x64 Windows openvmm artifact, NOT aarch64, NOT openhcl/igvm ones).

- [ ] **Step 2: Download, extract, stage**

```sh
gh run download "$RUN_ID" -R microsoft/openvmm -n "<ARTIFACT_NAME_FROM_STEP_1>" \
  -D /tmp/openvmm-artifact
find /tmp/openvmm-artifact -name 'openvmm*.exe'
cp "$(find /tmp/openvmm-artifact -name 'openvmm*.exe' | head -1)" /mnt/c/izba-spike/openvmm.exe
```

- [ ] **Step 3: Verify it runs**

```sh
/mnt/c/izba-spike/openvmm.exe --help 2>&1 | head -30
```

Expected: clap help text listing flags from the spec (`--kernel`, `--virtio-fs`, `--virtio-vsock-path`, `--com1`, ...). A missing-DLL dialog/error means runtime deps are absent — note which, fetch them (the CI artifact may bundle DLLs; keep them next to the exe).

- [ ] **Step 4 (only if Steps 1–3 fail): source build on Windows**

```sh
# rustup (if absent):
powershell.exe -Command "winget install --id Rustlang.Rustup -e"
# MSVC Build Tools (if absent; ~6 GB):
powershell.exe -Command "winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override '--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive'"
# clone + build (in a Windows shell so cargo uses the MSVC toolchain):
powershell.exe -Command "git clone --depth 50 https://github.com/microsoft/openvmm C:\izba-spike\openvmm-src"
powershell.exe -Command "cd C:\izba-spike\openvmm-src; cargo build -p openvmm --release"
cp /mnt/c/izba-spike/openvmm-src/target/release/openvmm.exe /mnt/c/izba-spike/openvmm.exe
```

Log every install + the exact commit (`git -C /mnt/c/izba-spike/openvmm-src rev-parse HEAD`) in the findings doc.

- [ ] **Step 5: Record rung-0 verdict** (provenance: CI run id or commit) in the findings doc; commit the doc update.

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 0 verdict — openvmm.exe acquisition"
```

---

### Task 5: Rung 1 — smoke boot with OpenVMM's own guest (best-effort)

Purpose: separate "WHP/binary broken" from "our artifacts broken". Their sample kernel/initrd live in `microsoft/openvmm-deps` releases.

- [ ] **Step 1: Try to fetch their test kernel + initrd**

```sh
gh release list -R microsoft/openvmm-deps -L 5
# pick the latest release, list assets:
gh release view -R microsoft/openvmm-deps <TAG> --json assets -q '.assets[].name'
# download the x64 linux kernel + initrd assets (names from the listing):
gh release download -R microsoft/openvmm-deps <TAG> -p '<kernel-asset>' -p '<initrd-asset>' -D /tmp/ovmm-deps
```

If asset naming is opaque or the kernel ships only inside bigger bundles, **timebox to ~15 minutes**, mark rung 1 `skipped (deps unavailable)` in findings, and move on — rung 2 failure analysis then covers both hypotheses.

- [ ] **Step 2: Boot it**

```sh
cp /tmp/ovmm-deps/<kernel> /mnt/c/izba-spike/their-vmlinux
cp /tmp/ovmm-deps/<initrd> /mnt/c/izba-spike/their-initrd
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\their-vmlinux' \
  --initrd 'C:\izba-spike\their-initrd' \
  -c 'console=ttyS0' \
  --com1 'file=C:\izba-spike\logs\rung1.log' &
sleep 15 && powershell.exe -Command "Stop-Process -Name openvmm -Force" 
grep -m5 -E 'Linux version|/ #|sh:' /mnt/c/izba-spike/logs/rung1.log
```

Pass: kernel boot messages (and ideally a shell prompt string) in the log. Note: this also pre-tests `--com1 file=` (rung 6) — if file capture itself misbehaves, retry with the VM attached to the terminal (drop the `--com1` flag and read stdout) and note it for rung 6.

- [ ] **Step 3: Record rung-1 verdict in findings; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 1 verdict — smoke boot"
```

---

### Task 6: Rung 2 — direct-boot izba's kernel

- [ ] **Step 1: Stage our artifacts**

```sh
cp ~/.local/share/izba/artifacts/vmlinux /mnt/c/izba-spike/vmlinux
hack/build-spike-initramfs.sh dist/spike-initramfs.cpio.gz
cp dist/spike-initramfs.cpio.gz /mnt/c/izba-spike/
```

- [ ] **Step 2: Boot**

```sh
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\spike-initramfs.cpio.gz' \
  -c 'console=ttyS0' \
  --com1 'file=C:\izba-spike\logs\rung2.log' &
sleep 15 && powershell.exe -Command "Stop-Process -Name openvmm -Force"
grep -E 'SPIKE-INIT-OK|Linux version' /mnt/c/izba-spike/logs/rung2.log
```

Pass: both `Linux version ...` (our kernel banner) and `SPIKE-INIT-OK`.

- [ ] **Step 3 (on failure): diagnose with the standard ladder**

In order: (a) empty log → loader rejected the kernel; capture openvmm stderr. (b) kernel banner but no `SPIKE-INIT-OK` → console or initramfs issue; try `-c 'console=ttyS0 earlyprintk=serial'`; compare against rung-1's working cmdline. (c) suspect missing kernel config → diff `hack/kernel.config` against the openvmm-deps kernel's config (`/tmp/ovmm-deps`, configs usually ship alongside); rebuild via `hack/build-kernel.sh` with the delta and re-run. Any delta goes in the findings doc's *Kernel config deltas* section.

- [ ] **Step 4: Record rung-2 verdict + exact working command line in findings; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 2 verdict — izba kernel direct boot"
```

---

### Task 7: Rung 3 — virtio-fs share

- [ ] **Step 1: Rebuild initramfs with the rung-3 payload**

```sh
hack/build-spike-initramfs.sh dist/spike-initramfs-r3.cpio.gz hack/spike/rc/rung3-virtiofs.sh
cp dist/spike-initramfs-r3.cpio.gz /mnt/c/izba-spike/
```

- [ ] **Step 2: Boot with the share (PCIe flags are mandatory — spec §2)**

```sh
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\spike-initramfs-r3.cpio.gz' \
  -c 'console=ttyS0' \
  --pcie-root-complex --pcie-root-port ws \
  --virtio-fs 'pcie_port=ws:ws,C:\izba-spike\share' \
  --com1 'file=C:\izba-spike\logs\rung3.log' &
sleep 20 && powershell.exe -Command "Stop-Process -Name openvmm -Force"
grep 'SPIKE-RUNG3' /mnt/c/izba-spike/logs/rung3.log
cat /mnt/c/izba-spike/share/guest-file.txt
```

Pass: `SPIKE-RUNG3-MOUNT-OK`, `SPIKE-RUNG3-READ-OK: hello-from-host`, `SPIKE-RUNG3-WRITE-OK`, and `guest-was-here` visible on the host.

- [ ] **Step 3 (on failure):** `MOUNT-FAIL` → check guest sees the device (`--virtio-fs-bus mmio` variant; verify `CONFIG_VIRTIO_FS`/`CONFIG_FUSE_FS` in `hack/kernel.config` — if missing, that's a kernel delta, rebuild). PCIe flag syntax errors → consult `openvmm.exe --help` actual syntax and record the corrected form. WRITE-FAIL → try uid/gid options (`,uid=0,gid=0`).

- [ ] **Step 4: Record rung-3 verdict + working command + any semantics caveats (case sensitivity, symlinks) in findings; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 3 verdict — virtio-fs share"
```

---

### Task 8: Rung 4 — vsock bridge

**Files:**
- Create: `hack/spike/izba-client.ps1` (PowerShell 7; UDS + CONNECT handshake + izba-proto framing — also used by rung 7)

- [ ] **Step 1: Write the host-side client**

`hack/spike/izba-client.ps1`:

```powershell
#!/usr/bin/env pwsh
# Spike host-side client for OpenVMM hybrid vsock (CONNECT/OK handshake,
# CH-compatible) + izba-proto u32-LE length-prefixed JSON frames.
# Requires PowerShell 7 (UnixDomainSocketEndPoint).
#
# Usage:
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode echo
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode health
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode exec -Argv 'uname','-a'
param(
    [Parameter(Mandatory)] [string]$SockPath,
    [uint32]$Port = 1025,
    [ValidateSet('echo','health','exec')] [string]$Mode = 'health',
    [string[]]$Argv = @('true')
)
$ErrorActionPreference = 'Stop'

function Connect-Vsock([string]$Path, [uint32]$VPort) {
    $sock = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::Unix,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Unspecified)
    $sock.Connect([System.Net.Sockets.UnixDomainSocketEndPoint]::new($Path))
    $stream = [System.Net.Sockets.NetworkStream]::new($sock, $true)
    $req = [System.Text.Encoding]::ASCII.GetBytes("CONNECT $VPort`n")
    $stream.Write($req, 0, $req.Length)
    # Read the OK line byte-by-byte (buffering would eat stream data).
    $line = ''
    while ($true) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { throw 'EOF before OK line' }
        if ($b -eq 10) { break }
        $line += [char]$b
    }
    if ($line -notmatch '^OK ') { throw "expected OK, got: $line" }
    Write-Host "HANDSHAKE: $line"
    return $stream
}

function Write-Frame($Stream, $Obj) {
    $json = [System.Text.Encoding]::UTF8.GetBytes(($Obj | ConvertTo-Json -Compress -Depth 5))
    $len = [BitConverter]::GetBytes([uint32]$json.Length)  # little-endian on x64
    $Stream.Write($len, 0, 4); $Stream.Write($json, 0, $json.Length)
}

function Read-Frame($Stream) {
    $hdr = [byte[]]::new(4); $got = 0
    while ($got -lt 4) {
        $n = $Stream.Read($hdr, $got, 4 - $got)
        if ($n -le 0) { throw 'EOF in frame header' }
        $got += $n
    }
    $len = [BitConverter]::ToUInt32($hdr, 0)
    $body = [byte[]]::new($len); $got = 0
    while ($got -lt $len) {
        $n = $Stream.Read($body, $got, $len - $got)
        if ($n -le 0) { throw 'EOF in frame body' }
        $got += $n
    }
    return [System.Text.Encoding]::UTF8.GetString($body)
}

$stream = Connect-Vsock $SockPath $Port
switch ($Mode) {
    'echo' {
        $msg = [System.Text.Encoding]::ASCII.GetBytes("ping-roundtrip`n")
        $stream.Write($msg, 0, $msg.Length)
        $buf = [byte[]]::new($msg.Length); $got = 0
        while ($got -lt $buf.Length) {
            $n = $stream.Read($buf, $got, $buf.Length - $got)
            if ($n -le 0) { throw 'EOF during echo' }
            $got += $n
        }
        $back = [System.Text.Encoding]::ASCII.GetString($buf)
        if ($back -eq "ping-roundtrip`n") { Write-Host 'SPIKE-RUNG4-ECHO-OK' }
        else { Write-Host "SPIKE-RUNG4-ECHO-MISMATCH: $back" }
    }
    'health' {
        Write-Frame $stream @{ type = 'health' }
        Write-Host "RESPONSE: $(Read-Frame $stream)"
    }
    'exec' {
        Write-Frame $stream @{
            type = 'exec'; argv = $Argv; env = @()
            cwd = '/workspace'; tty = $false; uid = 0; gid = 0
        }
        $started = Read-Frame $stream
        Write-Host "EXEC-STARTED: $started"
        $execId = ($started | ConvertFrom-Json).exec_id
        Write-Frame $stream @{ type = 'wait'; exec_id = $execId }
        Write-Host "WAIT: $(Read-Frame $stream)"
    }
}
$stream.Dispose()
```

Note on `exec` JSON: izba-proto's `env: Vec<(String,String)>` serializes as a JSON array of 2-element arrays; an empty `@()` is correct for "no env". `Request::Exec` is internally tagged (`{"type":"exec","argv":...}` — fields inline, matching serde's `tag = "type"`).

- [ ] **Step 2: Boot with the vsock device and the rung-4 payload**

```sh
hack/build-spike-initramfs.sh dist/spike-initramfs-r4.cpio.gz hack/spike/rc/rung4-vsock.sh
cp dist/spike-initramfs-r4.cpio.gz /mnt/c/izba-spike/
cp hack/spike/izba-client.ps1 /mnt/c/izba-spike/
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\spike-initramfs-r4.cpio.gz' \
  -c 'console=ttyS0' \
  --virtio-vsock-path 'C:\izba-spike\vsock' \
  --com1 'file=C:\izba-spike\logs\rung4.log' &
sleep 15 && grep 'SPIKE-VSOCK-ECHO-READY' /mnt/c/izba-spike/logs/rung4.log
```

(If the vsock device also needs the PCIe flags — likely, it's virtio — add `--pcie-root-complex --pcie-root-port vs` and whatever port-attachment syntax `--help` shows for vsock; record the working form.)

- [ ] **Step 3: Echo roundtrip from the host**

```sh
powershell.exe -NoProfile -Command \
  "pwsh -File C:\izba-spike\izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode echo"
powershell.exe -Command "Stop-Process -Name openvmm -Force"
```

Pass: `HANDSHAKE: OK 1025` + `SPIKE-RUNG4-ECHO-OK`.

- [ ] **Step 4 (on failure):** no `ECHO-READY` → guest lacks `CONFIG_VIRTIO_VSOCKETS`, or the device sits on a transport the kernel can't see — unlike virtio-fs, vsock may attach via MMIO, needing `CONFIG_VIRTIO_MMIO` (check `hack/kernel.config` for both; kernel delta if missing). Handshake refused → inspect what listener path OpenVMM actually created (`dir C:\izba-spike\vsock*`); try the GUID CONNECT form from spec §2. Total dead end → document the vmbus/hvsocket alternative (`--vmbus-vsock-path` + `CONFIG_HYPERV_VSOCKETS`) as the driver-design consequence.

- [ ] **Step 5: Commit client + record rung-4 verdict.**

```sh
git add hack/spike/izba-client.ps1 docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "feat(hack): pwsh vsock/izba-proto spike client; rung 4 verdict"
```

---

### Task 9: Rung 5 — consomme networking

- [ ] **Step 1: Boot with virtio-net + the rung-5 payload**

```sh
hack/build-spike-initramfs.sh dist/spike-initramfs-r5.cpio.gz hack/spike/rc/rung5-net.sh
cp dist/spike-initramfs-r5.cpio.gz /mnt/c/izba-spike/
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\spike-initramfs-r5.cpio.gz' \
  -c 'console=ttyS0' \
  --pcie-root-complex --pcie-root-port net \
  --virtio-net 'pcie_port=net:consomme' \
  --com1 'file=C:\izba-spike\logs\rung5.log' &
sleep 30 && powershell.exe -Command "Stop-Process -Name openvmm -Force"
grep 'SPIKE-RUNG5' /mnt/c/izba-spike/logs/rung5.log
```

Pass: `SPIKE-RUNG5-DHCP-OK` + `SPIKE-RUNG5-HTTP-OK`.

- [ ] **Step 2 (on failure):** `NODEV` → kernel needs `CONFIG_VIRTIO_NET` (check config; delta if missing) or the device needs different attachment syntax. `DHCP-OK` but `HTTP-FAIL` → split DNS from TCP: add `nslookup example.com` and `wget -q -O- http://93.184.215.14/` probes to the rc and rerun; record which half is broken.

- [ ] **Step 3: Also probe kernel-level `ip=dhcp`** (izba's actual contract — init reads `/proc/net/pnp`): rerun with `-c 'console=ttyS0 ip=dhcp'` and check the log for `IP-Config: Complete`. Record separately — busybox-`udhcpc` passing while `ip=dhcp` fails is a real finding (izba relies on the latter).

- [ ] **Step 4: Record rung-5 verdict; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 5 verdict — consomme networking"
```

---

### Task 10: Rung 6 — headless serial capture

Largely pre-proven by rungs 1–5 (every boot used `--com1 file=`). This rung formalizes it.

- [ ] **Step 1: Verify the file-capture properties izba needs**

Using the rung-2 log run: (a) file exists and contains the full boot transcript; (b) openvmm ran fully detached (no console window dependency); (c) the file is readable while the VM runs (open `/mnt/c/izba-spike/logs/rung2.log` during a live boot — tail it) — izba tails console.log on boot failure while CH is still up.

```sh
/mnt/c/izba-spike/openvmm.exe --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\spike-initramfs.cpio.gz' -c 'console=ttyS0' \
  --com1 'file=C:\izba-spike\logs\rung6.log' &
sleep 8 && tail -5 /mnt/c/izba-spike/logs/rung6.log   # read WHILE running
powershell.exe -Command "Stop-Process -Name openvmm -Force"
```

Pass: live tail shows boot output. If Windows file locking blocks concurrent reads, try `listen=<path>` (UDS serial) as the alternative and record which mode the driver design should use.

- [ ] **Step 2: Record rung-6 verdict; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 6 verdict — serial capture"
```

---

### Task 11: Rung 7 — integration preview (full izba guest stack)

The unmodified production guest: rootfs.erofs + rw.img disks, virtiofs tag `workspace`, real izba-init initramfs, izba cmdline contract — host speaks izba-proto through the bridge.

- [ ] **Step 1: Stage production guest artifacts from WSL**

```sh
# production initramfs + an existing cached image:
cp ~/.local/share/izba/artifacts/initramfs.cpio.gz /mnt/c/izba-spike/izba-initramfs.cpio.gz
IMG_DIR=$(ls -d ~/.local/share/izba/images/sha256-* | head -1)
cp "$IMG_DIR/rootfs.erofs" /mnt/c/izba-spike/rootfs.erofs
# pre-formatted rw disk (host-side format, the documented fallback path):
truncate -s 1G /tmp/rw.img && mkfs.ext4 -q /tmp/rw.img
cp /tmp/rw.img /mnt/c/izba-spike/rw.img
```

- [ ] **Step 2: Boot the full stack**

Flag syntax for virtio-blk comes from rung 3/4 experience + `--help` (`--virtio-blk [pcie_port=PORT:]<path>[,ro]` per the Alpine guide; disk ORDER must put rootfs.erofs first = vda, rw.img second = vdb — izba's disk-order contract):

```sh
/mnt/c/izba-spike/openvmm.exe \
  --kernel 'C:\izba-spike\vmlinux' \
  --initrd 'C:\izba-spike\izba-initramfs.cpio.gz' \
  -c 'console=ttyS0 ip=dhcp izba.hostname=spike-win' \
  --pcie-root-complex \
  --pcie-root-port d0 --virtio-blk 'pcie_port=d0:C:\izba-spike\rootfs.erofs,ro' \
  --pcie-root-port d1 --virtio-blk 'pcie_port=d1:C:\izba-spike\rw.img' \
  --pcie-root-port ws --virtio-fs 'pcie_port=ws:workspace,C:\izba-spike\share' \
  --pcie-root-port net --virtio-net 'pcie_port=net:consomme' \
  --virtio-vsock-path 'C:\izba-spike\vsock' \
  --com1 'file=C:\izba-spike\logs\rung7.log' &
sleep 25
```

(If rung 5's `ip=dhcp` probe failed, drop `ip=dhcp` — init tolerates missing `/proc/net/pnp`; the finding is already recorded.)

- [ ] **Step 3: Health + exec through the bridge**

```sh
powershell.exe -NoProfile -Command \
  "pwsh -File C:\izba-spike\izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode health"
powershell.exe -NoProfile -Command \
  "pwsh -File C:\izba-spike\izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode exec -Argv 'sh','-c','echo from-guest > /workspace/exec-was-here && uname -a'"
cat /mnt/c/izba-spike/share/exec-was-here
powershell.exe -Command "Stop-Process -Name openvmm -Force"
```

Pass: Health responds with `{"type":"health",...}`; exec's Wait returns `{"type":"wait","status":{"code":0}}`; `from-guest` appears in the host share. That's boot + overlay + virtiofs + vsock + izba-proto, end to end.

- [ ] **Step 4 (on failure):** read `rung7.log` — izba-init logs its mount plan and failures. Disk enumeration not vda/vdb → record actual names (driver-design consequence). Overlay/erofs mount failure → check `CONFIG_EROFS_FS` made it into the boot (it's in `hack/kernel.config`; if rung 2 forced a config rebuild, re-verify the delta kept it).

- [ ] **Step 5: Record rung-7 verdict + full working command line; commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): rung 7 verdict — full izba guest under OpenVMM"
```

---

### Task 12: S4 — `mkfs.erofs` on Windows (parallel track, any time after Task 3)

- [ ] **Step 1: Survey existing binaries**

Check, in order, recording results: (a) MSYS2 package repos (`https://packages.msys2.org/search?q=erofs`); (b) erofs-utils GitHub releases (`gh release list -R erofs/erofs-utils`) for any Windows assets; (c) winget (`powershell.exe -Command "winget search erofs"`).

- [ ] **Step 2 (if nothing usable): MSYS2 build attempt**

```sh
powershell.exe -Command "winget install --id MSYS2.MSYS2 -e"   # log install
# In the MSYS2 UCRT64 shell (driven via C:\msys64\usr\bin\bash.exe -lc '...'):
/mnt/c/msys64/usr/bin/bash.exe -lc "pacman -S --noconfirm base-devel autoconf automake libtool mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-lz4"
/mnt/c/msys64/usr/bin/bash.exe -lc "git clone --depth 1 https://github.com/erofs/erofs-utils && cd erofs-utils && ./autogen.sh && ./configure --disable-fuse && make -j"
```

Timebox: ~45 minutes of debugging. Success = `mkfs.erofs.exe` exists and `mkfs.erofs --version` runs.

- [ ] **Step 3 (if built): smoke-test output compatibility**

```sh
# build an erofs from a trivial tree on Windows, then verify IN WSL that the
# kernel-facing format is sane:
/mnt/c/msys64/usr/bin/bash.exe -lc "mkdir -p /tmp/tree && echo hi > /tmp/tree/f && ./erofs-utils/mkfs.erofs /tmp/spike.erofs /tmp/tree"
cp /mnt/c/msys64/tmp/spike.erofs /tmp/ && dump.erofs /tmp/spike.erofs || fsck.erofs /tmp/spike.erofs
```

- [ ] **Step 4: Record S4 verdict (feasibility + effort estimate + recipe if built); commit.**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): S4 verdict — mkfs.erofs on Windows"
```

---

### Task 13: Findings synthesis + go/no-go

- [ ] **Step 1: Complete the findings doc** — fill *Environment*, verify every rung row has a verdict, every passing rung has its exact command line, all installs are listed, kernel deltas section is accurate. Set **Status: complete**, write the *Go/no-go recommendation* naming which v1-design §4.1 `OpenVmmDriver` assumptions held (in-process virtio-fs? CONNECT-compatible vsock? consomme?) and which need revision.

- [ ] **Step 2: Quality gates on the repo** (spike code touches no crates, but the gates are cheap insurance):

```sh
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
```

Expected: all green (unchanged from pre-spike).

- [ ] **Step 3: Final commit**

```sh
git add docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md
git commit -m "docs(spike): S1+ findings complete with go/no-go recommendation"
```

- [ ] **Step 4: Report to the user** — verdict summary table + the go/no-go recommendation. The decision (proceed to `OpenVmmDriver` design vs ship Linux-first) is the user's, per the parent spec.
