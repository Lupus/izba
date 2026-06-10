# izba Windows port, Plan 2 (spike-host bring-up) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Prerequisites:** Plan 1 merged (cross-built `izba.exe` exists). Every
> Windows-side step runs via WSL interop (`/mnt/c`, `powershell.exe`) and
> needs `dangerouslyDisableSandbox` + the user present (interop fails inside
> the default sandbox).

**Goal:** Prove full CLI parity on the Windows spike host: `izba.exe` pulls an
OCI image, builds erofs natively, boots under OpenVMM, execs (incl. `-it`),
and the daemonless lifecycle (`ls`/`stop`/`rm`, liveness across invocations)
holds — plus close the inherited deferred erofs gate.

**Architecture:** No new product code expected — this plan stages artifacts,
verifies the two spike-unverified flags, and runs CI-compatible validation
scripts. Any code fix it forces (e.g. a flag-name correction) lands as a
normal TDD change against Plan 1's golden tests.

**Tech Stack:** bash (WSL side), PowerShell 7 (`pwsh`, Windows side), `gh`
CLI for the pinned OpenVMM artifact.

**Staging layout on the Windows host** (installer-shaped, exercises the
libexec discovery path):

```
C:\izba\bin\izba.exe
C:\izba\bin\libexec\openvmm.exe
C:\izba\bin\libexec\mkfs.erofs.exe
%LOCALAPPDATA%\izba\artifacts\vmlinux
%LOCALAPPDATA%\izba\artifacts\initramfs.cpio.gz
```

---

### Task 1: `hack/fetch-openvmm.sh` — pinned OpenVMM artifact fetch

**Files:**
- Create: `hack/fetch-openvmm.sh` (mode 755)

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Fetch the pinned OpenVMM CI artifact (Windows x64) into dist/.
#
# OpenVMM ships no binary releases; we pin a CI run of microsoft/openvmm.
# GitHub artifacts EXPIRE (~90 days). Re-pin procedure when the download 404s:
#   1. gh run list -R microsoft/openvmm -w openvmm-ci.yaml -b main -L 5
#   2. pick the newest green run, update RUN_ID + COMMIT below
#   3. run this script, paste the printed sha256 into SHA256 below
#   4. re-run the Plan-2 validation suite before committing the new pin
set -euo pipefail

# Pin: spike S1+ provenance (2026-06-10), branch main.
RUN_ID="27240809751"
COMMIT="7872712037c6ce3a03087a76207bd73cec9784a2"
ARTIFACT="x64-windows-openvmm"
# sha256 of openvmm.exe from this run; empty = first fetch, record it.
SHA256=""

cd "$(dirname "$0")/.."
DIST="dist"
mkdir -p "$DIST"

command -v gh >/dev/null || { echo "error: gh CLI not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "error: gh not authenticated" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching $ARTIFACT from microsoft/openvmm run $RUN_ID (commit ${COMMIT:0:9})..."
gh run download "$RUN_ID" -R microsoft/openvmm -n "$ARTIFACT" -D "$TMP" \
    || { echo "error: artifact download failed — likely EXPIRED; see re-pin procedure in this script's header" >&2; exit 1; }

EXE="$(find "$TMP" -name openvmm.exe | head -1)"
[ -n "$EXE" ] || { echo "error: openvmm.exe not found in artifact" >&2; exit 1; }

GOT="$(sha256sum "$EXE" | cut -d' ' -f1)"
if [ -z "$SHA256" ]; then
    echo "NOTE: no pinned sha256 yet — record this in fetch-openvmm.sh:"
    echo "  SHA256=\"$GOT\""
elif [ "$GOT" != "$SHA256" ]; then
    echo "error: sha256 mismatch: got $GOT want $SHA256" >&2
    exit 1
fi

cp "$EXE" "$DIST/openvmm.exe"
echo "OK: $DIST/openvmm.exe ($(stat -c%s "$DIST/openvmm.exe") bytes, sha256 $GOT)"
```

- [ ] **Step 2: Run it and pin the hash**

Run: `hack/fetch-openvmm.sh` (needs network + gh auth — outside the sandbox).
Expected: `dist/openvmm.exe` appears; the script prints the sha256.
Paste the printed value into `SHA256=""` in the script, re-run, expect clean
`OK:` line with no NOTE.

- [ ] **Step 3: Commit**

```bash
chmod 755 hack/fetch-openvmm.sh
git add hack/fetch-openvmm.sh
git commit -m "feat(hack): pinned OpenVMM CI-artifact fetch with sha256 + re-pin runbook"
```

---

### Task 2: `hack/stage-izba-windows.sh` — stage the Windows tree

**Files:**
- Create: `hack/stage-izba-windows.sh` (mode 755)

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Stage izba.exe + tools + boot artifacts onto the Windows host (from WSL).
# Layout: $WIN_ROOT\bin\{izba.exe, libexec\{openvmm.exe, mkfs.erofs.exe}}
# and the boot artifacts into %LOCALAPPDATA%\izba\artifacts.
# Override WIN_ROOT (default /mnt/c/izba) and WIN_LOCALAPPDATA if needed.
set -euo pipefail
cd "$(dirname "$0")/.."

WIN_ROOT="${WIN_ROOT:-/mnt/c/izba}"
# %LOCALAPPDATA% as seen from WSL; derive from the Windows user if not given.
if [ -z "${WIN_LOCALAPPDATA:-}" ]; then
    WINUSER="$(powershell.exe -NoProfile -Command '$env:UserName' | tr -d '\r')"
    WIN_LOCALAPPDATA="/mnt/c/Users/$WINUSER/AppData/Local"
fi

IZBA_EXE="target/x86_64-pc-windows-gnu/release/izba.exe"
for f in "$IZBA_EXE" dist/openvmm.exe dist/mkfs.erofs.exe dist/vmlinux dist/initramfs.cpio.gz; do
    [ -f "$f" ] || { echo "error: missing $f (build/fetch it first)" >&2; exit 1; }
done

mkdir -p "$WIN_ROOT/bin/libexec" "$WIN_LOCALAPPDATA/izba/artifacts"
cp "$IZBA_EXE"            "$WIN_ROOT/bin/izba.exe"
cp dist/openvmm.exe       "$WIN_ROOT/bin/libexec/openvmm.exe"
cp dist/mkfs.erofs.exe    "$WIN_ROOT/bin/libexec/mkfs.erofs.exe"
cp dist/vmlinux           "$WIN_LOCALAPPDATA/izba/artifacts/vmlinux"
cp dist/initramfs.cpio.gz "$WIN_LOCALAPPDATA/izba/artifacts/initramfs.cpio.gz"

echo "OK: staged to $WIN_ROOT (bin + libexec) and $WIN_LOCALAPPDATA/izba/artifacts"
echo "Windows-side smoke: C:\\izba\\bin\\izba.exe --help"
```

- [ ] **Step 2: Ensure dist/ holds the current kernel + initramfs**

The post-delta kernel/initramfs already live in `dist/` (KVM-revalidated).
Verify: `ls -la dist/vmlinux dist/initramfs.cpio.gz dist/mkfs.erofs.exe`.
If missing, rebuild via `hack/build-kernel.sh` / `hack/build-initramfs.sh`
and `hack/build-mkfs-erofs-windows.sh`.

- [ ] **Step 3: Build izba.exe, run the staging, smoke it**

```sh
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
hack/stage-izba-windows.sh
powershell.exe -NoProfile -Command 'C:\izba\bin\izba.exe --help'
```

Expected: clap help text printed from the native Windows binary.

- [ ] **Step 4: Commit**

```bash
chmod 755 hack/stage-izba-windows.sh
git add hack/stage-izba-windows.sh
git commit -m "feat(hack): Windows staging script — installer-shaped bin/libexec layout"
```

---

### Task 3: Verify the two spike-unverified flags

`--processors` / `--memory` were never passed during the spike (defaults).
Confirm names/syntax before the first boot.

- [ ] **Step 1: Dump the help text**

```sh
powershell.exe -NoProfile -Command 'C:\izba\bin\libexec\openvmm.exe --help' > /tmp/openvmm-help.txt
grep -iE "processor|memory|cpu" /tmp/openvmm-help.txt
```

- [ ] **Step 2: If the names differ, fix builder + golden tests together**

Adjust `build_invocation` in `crates/izba-core/src/vmm/openvmm.rs` AND the
golden argv in its tests in the same commit; run the full gate set; commit as
`fix(core): correct openvmm cpu/memory flag names per --help`. If they match,
record "confirmed" in the Task 6 findings notes — no commit.

---

### Task 4: Close the inherited erofs gate (real-Windows leg)

Deferred from the mkfs.erofs design §3.4 on the strength of wine parity.

- [ ] **Step 1: Regenerate the verification bundle**

Run (on WSL): `hack/verify-mkfs-erofs-parity.sh` on a host **without** wine
interference is not needed — instead force the bundle path:
`WINE=/nonexistent hack/verify-mkfs-erofs-parity.sh` if the script honors it,
otherwise run it normally (wine present → it already proves parity) AND copy
`dist/erofs-parity-bundle/` to the Windows host:

```sh
mkdir -p /mnt/c/izba-spike/erofs-parity
cp dist/erofs-parity-bundle/* /mnt/c/izba-spike/erofs-parity/
```

(If `dist/erofs-parity-bundle/` does not exist because the wine leg ran,
temporarily hide wine from PATH per the script's no-wine branch, or build the
bundle by hand from the script's fixture steps — the bundle is just
`mkfs.erofs.exe`, `fixture.tar`, `reference.sha256`, `mkfs-flags.txt`.)

- [ ] **Step 2: Run the PowerShell leg on real Windows**

```sh
powershell.exe -NoProfile -Command \
  'pwsh -NoProfile -File C:\izba-spike\erofs-parity\..\..\..\..\path\to\repo\hack\spike\verify-mkfs-erofs-parity.ps1 -BundleDir C:\izba-spike\erofs-parity'
```

(Adjust to the ps1's actual parameter surface — it consumes the bundle dir.)
Expected: PASS — native-Windows image sha256 == Linux reference.

- [ ] **Step 3: Flip the deferral records**

- `docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md` §3.4:
  append "**CLOSED (date):** ps1 parity PASS on the spike host (Windows
  10.0.26100); rung-7-with-Windows-rootfs covered by the Plan-2 validation
  run."
- `docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md`
  follow-up #2: note the real-Windows leg is done.

Commit: `docs(spec): close erofs §3.4 — real-Windows parity leg PASS`.

---

### Task 5: Full CLI-parity validation on the spike host

**Files:**
- Create: `hack/spike/validate-izba-windows.ps1`

- [ ] **Step 1: Write the validation script**

CI-compatible: non-interactive, exit-code-driven (0 pass / 1 fail), env-var
overridable paths. The interactive `-it` check is the one manual step and is
NOT in the script (see Step 3).

```powershell
# Full CLI-parity validation for izba.exe on Windows (OpenVMM/WHP).
# Usage: pwsh -NoProfile -File validate-izba-windows.ps1
# Env overrides: IZBA_EXE (default C:\izba\bin\izba.exe), IZBA_IMAGE
# (default alpine:3.20), IZBA_WS (default C:\izba-spike\ws-validate)
$ErrorActionPreference = 'Stop'
$exe   = if ($env:IZBA_EXE)   { $env:IZBA_EXE }   else { 'C:\izba\bin\izba.exe' }
$image = if ($env:IZBA_IMAGE) { $env:IZBA_IMAGE } else { 'alpine:3.20' }
$ws    = if ($env:IZBA_WS)    { $env:IZBA_WS }    else { 'C:\izba-spike\ws-validate' }
$fails = 0

function Check($name, $ok) {
    if ($ok) { Write-Output "PASS: $name" }
    else     { [Console]::Error.WriteLine("FAIL: $name"); $script:fails++ }
}

# Fresh workspace
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory -Path $ws | Out-Null

# [1] run: create-on-first-use + pull + erofs + boot + exec, non-interactive
& $exe run --image $image --name valid8 $ws -- /bin/sh -c 'echo booted > /workspace/marker && uname -s'
Check 'run exits 0' ($LASTEXITCODE -eq 0)
Check 'workspace write visible on host' ((Get-Content "$ws\marker" -ErrorAction SilentlyContinue) -eq 'booted')

# [2] liveness across CLI invocations (daemonless invariant)
$ls = & $exe ls | Out-String
Check 'ls shows sandbox running' ($ls -match 'valid8' -and $ls -match '(?i)running')

# [3] exec: exit-code mapping
& $exe exec valid8 -- /bin/true;  Check 'exec true → 0'   ($LASTEXITCODE -eq 0)
& $exe exec valid8 -- /bin/false; Check 'exec false → 1'  ($LASTEXITCODE -eq 1)
& $exe exec valid8 -- /no/such/cmd 2>$null; Check 'CommandNotFound → 127' ($LASTEXITCODE -eq 127)

# [4] exec: stdin plumbing (-i)
$out = 'ping' | & $exe exec -i valid8 -- /bin/cat
Check 'exec -i round-trips stdin' ($out -eq 'ping')

# [5] networking (consomme): DNS + outbound
& $exe exec valid8 -- /bin/sh -c 'wget -q -O /dev/null http://example.com'
Check 'guest outbound HTTP' ($LASTEXITCODE -eq 0)

# [6] console log captured
$console = Get-ChildItem "$env:LOCALAPPDATA\izba\sandboxes\valid8\logs\console.log" -ErrorAction SilentlyContinue
Check 'console.log exists and is non-empty' ($console -and $console.Length -gt 0)

# [7] stop → Stopped, restart works, rm cleans up
& $exe stop valid8; Check 'stop exits 0' ($LASTEXITCODE -eq 0)
$ls = & $exe ls | Out-String
Check 'ls shows stopped' ($ls -match 'valid8' -and $ls -notmatch '(?i)running')
& $exe run --name valid8 $ws -- /bin/true
Check 'restart after stop' ($LASTEXITCODE -eq 0)
& $exe stop valid8 | Out-Null
& $exe rm valid8;  Check 'rm exits 0' ($LASTEXITCODE -eq 0)
Check 'sandbox dir removed' (-not (Test-Path "$env:LOCALAPPDATA\izba\sandboxes\valid8"))

Write-Output "---"
if ($fails -eq 0) { Write-Output 'ALL PASS'; exit 0 }
else { [Console]::Error.WriteLine("$fails check(s) FAILED"); exit 1 }
```

(Adapt the `run`/flag spellings to the actual clap surface — `--name` lives
on the shared SandboxOpts; check `izba.exe run --help` first. Also confirm
the `ls` output wording for the liveness columns and adjust the regexes.)

- [ ] **Step 2: Run it**

```sh
powershell.exe -NoProfile -Command 'pwsh -NoProfile -File C:\path\to\repo\hack\spike\validate-izba-windows.ps1'
```

(Copy the ps1 to the Windows side or invoke through `\\wsl$` — match how the
erofs ps1 was run.) Expected: `ALL PASS`, exit 0. Debug failures via the
sandbox `console.log` and `vmm.log` — every boot failure mode seen in the
spike is documented in the findings doc.

- [ ] **Step 3: Manual interactive check (the one human step)**

From a real Windows Terminal (not via interop):

```
C:\izba\bin\izba.exe run C:\izba-spike\ws-validate
```

Checklist (operator confirms each):
- lands in a guest `/bin/sh -l` prompt (PTY allocated, raw mode on)
- arrow keys / line editing work (VT input)
- `vi /workspace/x` renders fullscreen and resizes when the window resizes
- Ctrl-C interrupts a `sleep 100` in the guest without killing izba.exe
- exiting the shell restores the console (no garbled mode)

- [ ] **Step 4: Commit**

```bash
git add hack/spike/validate-izba-windows.ps1
git commit -m "feat(hack): Windows full-CLI-parity validation script"
```

---

### Task 6: Findings, docs, promotion

- [ ] **Step 1: Findings addendum**

Append a "Windows bring-up (Plan 2)" section to
`docs/superpowers/specs/2026-06-10-izba-windows-port-design.md` (or a small
findings doc beside it): validation transcript summary, flag-verification
outcome, any deviations + fixes, environment (Windows build, openvmm pin).

- [ ] **Step 2: README + docs**

- `README.md`: Windows support status line (experimental; WHP/OpenVMM; how to
  stage — link hack/README).
- `docs/testing.md`: short "Windows validation" section pointing at
  `validate-izba-windows.ps1`.

- [ ] **Step 3: Promote artifacts**

Refresh `~/.local/share/izba/artifacts/` on the WSL side from `dist/` (the
staged Windows side already got them in Task 2) — closes the stale-artifacts
note from the spike findings (follow-up #1 parenthetical).

- [ ] **Step 4: Commit + memory**

```bash
git add README.md docs/testing.md docs/superpowers/specs/2026-06-10-izba-windows-port-design.md
git commit -m "docs: Windows bring-up findings — full CLI parity validated on spike host"
```

Update the project memory files (Windows port state, what's validated, what
remains: installer/packaging, upstream virtiofs issue).
