# Full CLI-parity validation for izba.exe on Windows (OpenVMM/WHP).
# Usage: pwsh -NoProfile -File validate-izba-windows.ps1
# Env overrides: IZBA_EXE (default C:\izba\bin\izba.exe), IZBA_IMAGE
# (default alpine:3.20), IZBA_WS (default C:\izba-spike\ws-validate)
# Exit 0 = all checks pass; exit 1 = at least one failure.
# The interactive `exec -it` check is intentionally NOT here (needs a human
# at a real console) — see the manual checklist in the Plan-2 doc.
# Sections: [1] run/boot/exec, [2] liveness, [3] exec exit-codes,
#           [4] exec stdin, [5] networking, [6] console log,
#           [7] daemon lifecycle (status/kill-adopt/stop-survival),
#           [8] stop/restart/rm, [9] M3 persistent volume + prune (vdc parity),
#           [10] VMM confinement (differential PoC + live status),
#           [11] lock-down: per-sandbox account + read-deny + net-block.
$ErrorActionPreference = 'Continue'
$exe   = if ($env:IZBA_EXE)   { $env:IZBA_EXE }   else { 'C:\izba\bin\izba.exe' }
$image = if ($env:IZBA_IMAGE) { $env:IZBA_IMAGE } else { 'alpine:3.20' }
$ws    = if ($env:IZBA_WS)    { $env:IZBA_WS }    else { 'C:\izba-spike\ws-validate' }
$fails = 0

function Check($name, $ok) {
    $t = (Get-Date).ToString('HH:mm:ss')
    if ($ok) { Write-Output "PASS [$t]: $name" }
    else     { [Console]::Error.WriteLine("FAIL [$t]: $name"); $script:fails++ }
}

# Best-effort: dump the tail of a sandbox's vmm.log AND console.log to stderr so
# a "did not become healthy" boot failure shows WHY in the CI log — even when
# console.log is empty (e.g. the VMM never started, or hit an access-denied
# HRESULT writing its scratch). vmm.log = openvmm's own stdout/stderr;
# console.log = the guest serial. Purely diagnostic; never changes pass/fail.
function Dump-BootLogs($name) {
    $logs = "$env:LOCALAPPDATA\izba\sandboxes\$name\logs"
    foreach ($f in @('vmm.log', 'console.log')) {
        $p = Join-Path $logs $f
        if (Test-Path $p) {
            [Console]::Error.WriteLine("  --- $name $f tail (boot failure diag) ---")
            Get-Content $p -Tail 40 -ErrorAction SilentlyContinue |
                ForEach-Object { [Console]::Error.WriteLine("  $_") }
        } else {
            [Console]::Error.WriteLine("  ($name $f absent at $p)")
        }
    }
}

# Fresh workspace + no leftover sandbox from a previous run
& $exe stop valid8 2>$null | Out-Null
& $exe rm --force valid8 2>$null | Out-Null
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory -Path $ws | Out-Null

# [1] run: create-on-first-use + pull + erofs + boot + exec, non-interactive
& $exe run --image $image --name valid8 $ws -- /bin/sh -c 'echo booted > /workspace/marker && uname -s'
$valid8Boot = ($LASTEXITCODE -eq 0)
Check 'run exits 0' $valid8Boot
if (-not $valid8Boot) { Dump-BootLogs 'valid8' }
Check 'workspace write visible on host' ((Get-Content "$ws\marker" -ErrorAction SilentlyContinue) -eq 'booted')

# [2] liveness across CLI invocations (daemonless invariant)
$ls = & $exe ls | Out-String
Check 'ls shows sandbox running' ($ls -match 'valid8' -and $ls -match 'running')

# [3] exec: exit-code mapping
& $exe exec valid8 -- /bin/true | Out-Null
Check 'exec true -> 0' ($LASTEXITCODE -eq 0)
& $exe exec valid8 -- /bin/false | Out-Null
Check 'exec false -> 1' ($LASTEXITCODE -eq 1)
& $exe exec valid8 -- /no/such/cmd 2>$null | Out-Null
Check 'CommandNotFound -> 127' ($LASTEXITCODE -eq 127)

# [4] exec: stdin plumbing (-i)
$out = 'ping' | & $exe exec -i valid8 -- /bin/cat
Check 'exec -i round-trips stdin' ("$out".Trim() -eq 'ping')

# [5] networking — izbad-owned vsock egress (the ONLY network story since M1
# phase C: passt/consomme/--net are gone, the guest is a NIC-less vsock island
# with dummy0 static addressing + an in-guest nft REDIRECT stub). The old
# consomme `guest outbound HTTP` check is retired with consomme — there is no
# host NIC path left to test. [5a]/[5b] below ARE the networking checks now,
# and they are exactly the WSL/VPN-topology bug-class that consomme failed on
# this host: izbad's vsock plane must PASS here regardless of the VPN.

# [5a] M1 phase A: egress DNS via izbad (runtime exercise of OpenVMM
# guest-initiated hybrid vsock — guest connect(CID 2, 1027) must reach
# izbad's run\vsock.sock_1027 listener, which izbad binds before VM boot).
$egFailsBefore = $fails
# egress-a is the SECOND concurrent nested microVM (valid8 is still running).
# On hosted GitHub Windows runners the nested WHP partition occasionally fails
# to start: the VM emits zero console output and never reaches health within
# the boot budget. A manual re-run from the same commit reliably passes, so a
# from-scratch retry (the programmatic equivalent of that re-run) absorbs the
# flake without masking a real regression — a genuine boot break fails all
# attempts. KVM never exhibits this; it is specific to nested virt on hosted
# Windows runners. See e2e.yml / izba CI flake notes.
$bootOk = $false
foreach ($attempt in 1..3) {
    & $exe stop egress-a 2>$null | Out-Null
    & $exe rm --force egress-a 2>$null | Out-Null
    & $exe run --image $image --name egress-a $ws -- /bin/true | Out-Null
    if ($LASTEXITCODE -eq 0) { $bootOk = $true; break }
    [Console]::Error.WriteLine("  egress-a boot attempt $attempt/3 timed out (nested-WHP flake); retrying from scratch")
}
Check 'izbad-egress sandbox boots (run exits 0)' $bootOk
if (-not $bootOk) { Dump-BootLogs 'egress-a' }
$egOut = (& $exe exec egress-a -- /bin/sh -lc 'getent hosts example.com' 2>&1 | Out-String)
$egRc  = $LASTEXITCODE
Check 'egress DNS via izbad resolves example.com' ($egRc -eq 0 -and $egOut -match 'example\.com')
if (-not ($egRc -eq 0 -and $egOut -match 'example\.com')) {
    [Console]::Error.WriteLine("  egress-a getent rc=$egRc out='$($egOut.Trim())'")
    $egConsole = "$env:LOCALAPPDATA\izba\sandboxes\egress-a\logs\console.log"
    if (Test-Path $egConsole) {
        [Console]::Error.WriteLine("  --- egress-a console.log tail ---")
        Get-Content $egConsole -Tail 25 | ForEach-Object { [Console]::Error.WriteLine("  $_") }
    }
    $egListener = "$env:LOCALAPPDATA\izba\sandboxes\egress-a\run\vsock.sock_1027"
    [Console]::Error.WriteLine("  vsock.sock_1027 present: $(Test-Path $egListener)")
}

# [5b] M1 phase B: TCP egress via the in-guest nft REDIRECT stub on OpenVMM.
# Guest connect()s out → nft REDIRECTs to the init listener → SO_ORIGINAL_DST →
# vsock TcpConnect splice → izbad dials the real host. This is a real-internet
# fetch (http://example.com): the WSL/VPN-topology bug-class check that the old
# consomme path failed under VPN. The izbad vsock path must PASS on the same host.
# Exercises the B1 netfilter kernel + B3/B4 vendored nft in the initramfs:
# an `izba-init: applying nft ruleset` error in console.log = kernel/nft mismatch.
$tcpOut = (& $exe exec egress-a -- /bin/sh -lc 'wget -qO- http://example.com/ | head -c 64' 2>&1 | Out-String)
$tcpRc  = $LASTEXITCODE
# Content match, not mere non-emptiness: busybox wget's stderr (merged by 2>&1)
# would otherwise count as "output" even when the fetch failed (head exits 0).
$tcpOk = ($tcpRc -eq 0 -and $tcpOut -match '(?i)<html|doctype')
Check 'TCP egress via izbad fetches http://example.com' $tcpOk
if (-not $tcpOk) {
    [Console]::Error.WriteLine("  egress-a wget rc=$tcpRc out='$($tcpOut.Trim())'")
    $egConsole = "$env:LOCALAPPDATA\izba\sandboxes\egress-a\logs\console.log"
    if (Test-Path $egConsole) {
        [Console]::Error.WriteLine("  --- egress-a console.log tail ---")
        Get-Content $egConsole -Tail 25 | ForEach-Object { [Console]::Error.WriteLine("  $_") }
    }
}

& $exe stop egress-a 2>$null | Out-Null
# Only purge the sandbox dir when the egress checks passed. On failure, keep it
# so the `windows-whp-failure-logs` artifact step can upload egress-a's
# console.log — otherwise every sandbox is rm'd before that step runs and the
# upload finds no files (as it did on the nested-WHP boot flake).
if ($fails -eq $egFailsBefore) {
    & $exe rm --force egress-a 2>$null | Out-Null
} else {
    [Console]::Error.WriteLine("  (keeping egress-a sandbox dir for the failure-log artifact upload)")
}

# [6] console log captured + NIC-less boot sanity. Since M1 phase C the guest
# brings up lo + dummy0 statically (no DHCP, no eth0): assert the console shows
# no DHCP/eth0 chatter and no init network/nft errors. This is the boot-time
# proof that the NIC-less init runs clean under OpenVMM/WHP (its device surface
# differs from KVM, so we verify here rather than assume parity).
$console = Get-Item "$env:LOCALAPPDATA\izba\sandboxes\valid8\logs\console.log" -ErrorAction SilentlyContinue
Check 'console.log exists and is non-empty' ($null -ne $console -and $console.Length -gt 0)
$conTxt = if ($null -ne $console) { Get-Content $console.FullName -Raw } else { '' }
Check 'no DHCP/eth0 chatter in console (NIC-less boot)' (-not ($conTxt -match '(?im)dhcp|eth0'))
$netErr = $conTxt -match '(?im)izba-init: (network configure|applying nft ruleset):'
Check 'no init network/nft errors in console' (-not $netErr)
if ($netErr) {
    [Console]::Error.WriteLine("  --- valid8 console.log net lines ---")
    ($conTxt -split "`n") | Where-Object { $_ -match '(?i)izba-init:.*(net|nft|dummy|resolv)' } |
        ForEach-Object { [Console]::Error.WriteLine("  $_") }
}

# [7] daemon: status, kill-and-adopt, stop-survival (daemon-first CLI)
$st = & $exe daemon status | Out-String
Check 'daemon status reports running' ($st -match 'daemon: running \(pid (\d+)')
$daemonPid = [int][regex]::Match($st, 'pid (\d+)').Groups[1].Value

# kill -9 equivalent: the next command must auto-start a fresh daemon that
# adopts the running sandbox from disk (stateless-restartable invariant).
Stop-Process -Id $daemonPid -Force
Start-Sleep -Seconds 1
$ls = & $exe ls | Out-String
Check 'ls after daemon kill still shows sandbox running' ($ls -match 'valid8' -and $ls -match 'running')
$st2 = & $exe daemon status | Out-String
$daemonPid2 = [int][regex]::Match($st2, 'pid (\d+)').Groups[1].Value
Check 'a fresh daemon was auto-started' ($daemonPid2 -ne 0 -and $daemonPid2 -ne $daemonPid)

# daemon stop leaves the sandbox running; the next command revives it.
& $exe daemon stop | Out-Null
Check 'daemon stop exits 0' ($LASTEXITCODE -eq 0)
$st3 = & $exe daemon status | Out-String
Check 'daemon reports not running after stop' ($st3 -match 'not running')
$ls2 = & $exe ls | Out-String
Check 'sandbox survives daemon stop' ($ls2 -match 'valid8' -and $ls2 -match 'running')

# [8] stop -> stopped, restart works, rm cleans up
& $exe stop valid8 | Out-Null
Check 'stop exits 0' ($LASTEXITCODE -eq 0)
$ls = & $exe ls | Out-String
Check 'ls shows stopped' ($ls -match 'valid8' -and $ls -match 'stopped')
$vmms = @(Get-Process openvmm -ErrorAction SilentlyContinue)
Check 'no openvmm process survives stop' ($vmms.Count -eq 0)
if ($vmms.Count -gt 0) { $vmms | ForEach-Object { Write-Output "  survivor pid=$($_.Id)" } }
& $exe run --name valid8 $ws -- /bin/true | Out-Null
Check 'restart after stop' ($LASTEXITCODE -eq 0)
& $exe stop valid8 | Out-Null
& $exe rm valid8 | Out-Null
Check 'rm exits 0' ($LASTEXITCODE -eq 0)
Check 'sandbox dir removed' (-not (Test-Path "$env:LOCALAPPDATA\izba\sandboxes\valid8"))

# [8a] Workspace integrity restored. A confined VMM runs at Low IL, so izba
# Low-labels the workspace share to let its in-process virtiofs write /workspace
# (proven by [1]'s host-visible marker). Teardown (stop/rm) must raise the user's
# project dir back to Medium so it is not left at Low. The dir ($ws) is the
# user's own — outside the removed sandbox dir — so it still exists here.
$wsLabel = (& icacls $ws 2>$null) -join "`n"
Check 'workspace integrity restored to Medium after teardown (no residual Low label)' `
    ($wsLabel -notmatch 'Low Mandatory Level')

# [9] M3 volumes parity: a named persistent volume is an extra virtio-blk disk
# (vdc) the OpenVMM driver routes to its own PCIe root port; it must format +
# mount, survive a stop/start, persist past rm, and be reaped by prune. This is
# the WHP analogue of the KVM `volumes_persist_reattach_and_prune` test and the
# proof the per-disk PCIe routing carries disks beyond vda/vdb on Windows.
$wsv = "$env:TEMP\izba-validate-vol"
& $exe stop volc 2>$null | Out-Null
& $exe rm --force volc 2>$null | Out-Null
& $exe volume prune -f 2>$null | Out-Null
if (Test-Path $wsv) { Remove-Item -Recurse -Force $wsv }
New-Item -ItemType Directory -Path $wsv | Out-Null

& $exe run --image $image --name volc --volume "vdata:/data:128m" $wsv -- /bin/sh -c 'echo persisted > /data/s && sync'
Check 'volume run exits 0' ($LASTEXITCODE -eq 0)
& $exe stop volc | Out-Null
& $exe run --name volc $wsv -- /bin/sh -c 'cat /data/s' | Out-Null
$volRead = & $exe run --name volc $wsv -- /bin/sh -c 'cat /data/s' | Out-String
Check 'volume survives stop/start' ("$volRead".Trim() -eq 'persisted')
& $exe stop volc | Out-Null
& $exe rm volc | Out-Null
Check 'persistent volume image survives rm' (Test-Path "$env:LOCALAPPDATA\izba\volumes\vdata.img")
& $exe volume prune -f | Out-Null
Check 'prune exits 0' ($LASTEXITCODE -eq 0)
Check 'prune reaps unreferenced volume' (-not (Test-Path "$env:LOCALAPPDATA\izba\volumes\vdata.img"))

# [10] VMM confinement: the real OpenVMM process is launched confined by default
# (restricted token + Low IL + job). This is the F-06 hardening proof and it must
# FAIL the run on regression — a skipped security proof must NOT look green.
#
# (10a) Differential PoC: the confine_probe harness spawns each abuse case
# confined-vs-unconfined on real WHP hardware and exits 0 iff every protection
# holds (write-up/acquire-priv DENIED confined + OK unconfined; self-il Low vs
# Medium; whp OK both, or SKIPPED if WHP absent). A missing probe path is a FAIL,
# never a silent skip.
if (-not $env:IZBA_CONFINE_PROBE) {
    Check 'confine_probe harness exits 0 (differential PoC)' $false
    [Console]::Error.WriteLine("  IZBA_CONFINE_PROBE is unset — refusing to skip the confinement proof")
} elseif (-not (Test-Path $env:IZBA_CONFINE_PROBE)) {
    Check 'confine_probe harness exits 0 (differential PoC)' $false
    [Console]::Error.WriteLine("  IZBA_CONFINE_PROBE='$($env:IZBA_CONFINE_PROBE)' does not exist — refusing to skip the confinement proof")
} else {
    $probeOut = (& $env:IZBA_CONFINE_PROBE harness 2>&1 | Out-String)
    $probeRc  = $LASTEXITCODE
    Check 'confine_probe harness exits 0 (differential PoC)' ($probeRc -eq 0)
    if ($probeRc -ne 0) {
        [Console]::Error.WriteLine("  confine_probe harness rc=$probeRc")
        ($probeOut -split "`n") | ForEach-Object { [Console]::Error.WriteLine("  $_") }
    }
}

# (10b) Live product status: a real confined VMM must be honestly reported. The
# earlier checks rm'd valid8, so boot a fresh one and assert `izba status` shows
# a `confinement:` line that says `confined` and NOT `UNCONFINED`.
& $exe run --image $image --name valid8 $ws -- /bin/true | Out-Null
Check 'confinement status sandbox boots (run exits 0)' ($LASTEXITCODE -eq 0)
$stConf = & $exe status valid8 | Out-String
$confOk = ($stConf -match 'confinement:' -and $stConf -match 'confined' -and -not ($stConf -match 'UNCONFINED'))
Check 'izba status reports the VMM as confined' $confOk
if (-not $confOk) {
    [Console]::Error.WriteLine("  --- izba status valid8 ---")
    ($stConf -split "`n") | ForEach-Object { [Console]::Error.WriteLine("  $_") }
}
& $exe stop valid8 2>$null | Out-Null
& $exe rm --force valid8 2>$null | Out-Null

# [11] lock-down: per-sandbox account + read-deny + net-block.
#
# Validates the MVP-D lock-down end-to-end on the real WHP runner:
#   izba lockdown lk-validate  ->  restart  ->  VMM runs as account,
#   account is network-dead (firewall rules present)  ->  izba unlock
#   ->  account + rules gone, no orphan.
#
# The CI runner is already elevated (admin), so the helper's ShellExecuteExW
# runas launches WITHOUT a UAC dialog. If lockdown times out or returns
# "windows-only" the whole section fails loudly (we ARE on Windows here).
$lkName    = 'lk-validate'
$lkAcct    = 'izba-spk-lk-validate'
$lkRule    = 'izba-deny-lk-validate'
$lkWs      = "$env:TEMP\izba-lk-validate-ws"
$lkFails0  = $fails

# Pre-cleanup: remove any leftover from a previous aborted run.
& $exe stop $lkName 2>$null | Out-Null
& $exe rm --force $lkName 2>$null | Out-Null
if (Test-Path $lkWs) { Remove-Item -Recurse -Force $lkWs -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $lkWs -ErrorAction SilentlyContinue | Out-Null
# Remove any leftover account/rules from a previous aborted run (best-effort).
Remove-LocalUser $lkAcct -ErrorAction SilentlyContinue
powershell.exe -NoProfile -NonInteractive -Command `
    "Get-NetFirewallRule -DisplayName '$lkRule' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; Get-NetFirewallRule -DisplayName '$lkRule-in' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" 2>$null | Out-Null

# Step 1: create the sandbox so lockdown has a config.json to find.
& $exe run --image $image --name $lkName $lkWs -- /bin/true | Out-Null
$lkBootOk = ($LASTEXITCODE -eq 0)
Check 'lock-down: initial sandbox boot (run exits 0)' $lkBootOk
if (-not $lkBootOk) { Dump-BootLogs $lkName }
& $exe stop $lkName 2>$null | Out-Null

# Step 2: lockdown -- provision per-sandbox account + firewall rule.
# On an already-elevated runner ShellExecuteExW runas returns immediately.
# Guard with a job timeout so a hang does not block CI indefinitely.
$lkJob = Start-Job -ScriptBlock {
    param($e, $n)
    $out = & $e lockdown $n 2>&1 | Out-String
    [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
} -ArgumentList $exe, $lkName
$lkDone = $lkJob | Wait-Job -Timeout 120
if ($null -eq $lkDone) {
    $lkJob | Stop-Job
    Check 'lock-down: izba lockdown exits 0' $false
    [Console]::Error.WriteLine("  izba lockdown $lkName HUNG after 120s (elevated runner; unexpected UAC?)")
    Dump-BootLogs $lkName
} else {
    $lkResult = Receive-Job $lkJob
    $lkExitRc = $lkResult.ExitCode
    $lkOutStr = $lkResult.Output.Trim()
    $lkOk     = ($lkExitRc -eq 0)
    Check 'lock-down: izba lockdown exits 0' $lkOk
    if (-not $lkOk) {
        [Console]::Error.WriteLine("  izba lockdown rc=$lkExitRc out='$lkOutStr'")
        # Fail loudly if we got a "windows-only" error -- we ARE on Windows.
        if ($lkOutStr -match 'windows-only') {
            [Console]::Error.WriteLine("  ERROR: lockdown returned 'windows-only' on a Windows runner -- build/packaging problem")
        }
    }
}
Remove-Job $lkJob -ErrorAction SilentlyContinue

# Step 3: restart the sandbox so the VMM relaunches as the per-sandbox account.
$lkStartOk = $false
foreach ($attempt in 1..3) {
    & $exe run --name $lkName $lkWs -- /bin/true | Out-Null
    if ($LASTEXITCODE -eq 0) { $lkStartOk = $true; break }
    [Console]::Error.WriteLine("  lk-validate restart attempt $attempt/3 timed out (nested-WHP flake); retrying")
    & $exe stop $lkName 2>$null | Out-Null
}
Check 'lock-down: sandbox boots after lockdown (run exits 0)' $lkStartOk
if (-not $lkStartOk) { Dump-BootLogs $lkName }

# Step 4: assert VMM process runs AS the per-sandbox account.
# Read the sandbox state.json for the VMM pid, then ask WMI for its owner.
$lkVmmOwnerOk = $false
$lkStateFile  = "$env:LOCALAPPDATA\izba\sandboxes\$lkName\state.json"
if (Test-Path $lkStateFile) {
    $lkState = Get-Content $lkStateFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
    # state.json's vmm_pid is a PidIdentity object { pid, starttime }; WMI wants
    # the integer pid. (Tolerate a bare int too, for forward-compat.)
    $lkVmmPid = if ($null -ne $lkState.vmm_pid.pid) { $lkState.vmm_pid.pid } else { $lkState.vmm_pid }
    if ($lkVmmPid) {
        $lkProc = Get-CimInstance Win32_Process -Filter "ProcessId=$lkVmmPid" -ErrorAction SilentlyContinue
        if ($lkProc) {
            $lkOwnerResult = Invoke-CimMethod -InputObject $lkProc -MethodName GetOwner -ErrorAction SilentlyContinue
            $lkOwner       = $lkOwnerResult.User
            $lkVmmOwnerOk  = ($lkOwner -like 'izba-spk-*')
            if (-not $lkVmmOwnerOk) {
                [Console]::Error.WriteLine("  VMM pid=$lkVmmPid owner='$lkOwner' (expected izba-spk-*)")
            }
        } else {
            [Console]::Error.WriteLine("  Win32_Process pid=$lkVmmPid not found (VMM may have exited)")
        }
    } else {
        [Console]::Error.WriteLine("  state.json has no vmm_pid field: $(Get-Content $lkStateFile -Raw -ErrorAction SilentlyContinue)")
    }
} else {
    [Console]::Error.WriteLine("  state.json absent at $lkStateFile")
}
Check 'lock-down: VMM runs as per-sandbox account (izba-spk-*)' $lkVmmOwnerOk

# Step 5: assert firewall net-block -- outbound + inbound BLOCK rules exist.
$lkFwOut = @(Get-NetFirewallRule -DisplayName $lkRule    -ErrorAction SilentlyContinue)
$lkFwIn  = @(Get-NetFirewallRule -DisplayName "$lkRule-in" -ErrorAction SilentlyContinue)
$lkFwOk  = ($lkFwOut.Count -ge 1 -and $lkFwIn.Count -ge 1)
Check 'lock-down: firewall BLOCK rules exist (outbound + inbound)' $lkFwOk
if (-not $lkFwOk) {
    [Console]::Error.WriteLine("  outbound rules: $($lkFwOut.Count)  inbound rules: $($lkFwIn.Count)")
}

# Step 6: assert account exists as a local user.
$lkAcctExists = $null -ne (Get-LocalUser $lkAcct -ErrorAction SilentlyContinue)
Check 'lock-down: per-sandbox local account exists' $lkAcctExists
if (-not $lkAcctExists) {
    [Console]::Error.WriteLine("  Get-LocalUser $lkAcct returned nothing")
}

# Step 6b: structural read-confinement assertion.
# Assert the account is NOT granted on a path outside its sandbox grants
# (negative control), and IS granted on its own sandbox dir (positive control).
# This does not require running code as the account -- icacls output suffices.
$lkOutsideFile = Join-Path $env:TEMP 'izba-lk-outside.txt'
Set-Content $lkOutsideFile 'x' -NoNewline
$lkSbDir = "$env:LOCALAPPDATA\izba\sandboxes\$lkName"
$lkIcaclsOutside = (icacls $lkOutsideFile 2>$null) -join "`n"
$lkIcaclsSbDir   = (icacls $lkSbDir   2>$null) -join "`n"
Check 'lock-down account is NOT granted an out-of-grant path (read-confined)' `
    (-not ($lkIcaclsOutside -match [regex]::Escape($lkAcct)))
Check 'lock-down account IS granted its own sandbox dir' `
    ($lkIcaclsSbDir -match [regex]::Escape($lkAcct))
if (Test-Path $lkOutsideFile) { Remove-Item $lkOutsideFile -Force -ErrorAction SilentlyContinue }

# Step 7: izba unlock -- should remove account + firewall rules.
& $exe stop $lkName 2>$null | Out-Null
$lkUnlockJob = Start-Job -ScriptBlock {
    param($e, $n)
    $out = & $e unlock $n 2>&1 | Out-String
    [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
} -ArgumentList $exe, $lkName
$lkUnlockDone = $lkUnlockJob | Wait-Job -Timeout 120
if ($null -eq $lkUnlockDone) {
    $lkUnlockJob | Stop-Job
    Check 'lock-down: izba unlock exits 0' $false
    [Console]::Error.WriteLine("  izba unlock $lkName HUNG after 120s")
} else {
    $lkUnlockResult = Receive-Job $lkUnlockJob
    $lkUnlockRc     = $lkUnlockResult.ExitCode
    $lkUnlockOk     = ($lkUnlockRc -eq 0)
    Check 'lock-down: izba unlock exits 0' $lkUnlockOk
    if (-not $lkUnlockOk) {
        [Console]::Error.WriteLine("  izba unlock rc=$lkUnlockRc out='$($lkUnlockResult.Output.Trim())'")
    }
}
Remove-Job $lkUnlockJob -ErrorAction SilentlyContinue

# Assert account + rules are gone after unlock.
$lkAcctGone   = $null -eq (Get-LocalUser $lkAcct -ErrorAction SilentlyContinue)
$lkFwOutGone  = (@(Get-NetFirewallRule -DisplayName $lkRule    -ErrorAction SilentlyContinue)).Count -eq 0
$lkFwInGone   = (@(Get-NetFirewallRule -DisplayName "$lkRule-in" -ErrorAction SilentlyContinue)).Count -eq 0
Check 'lock-down: unlock removed account + both firewall rules' ($lkAcctGone -and $lkFwOutGone -and $lkFwInGone)
if (-not $lkAcctGone)  { [Console]::Error.WriteLine("  account $lkAcct still exists after unlock") }
if (-not $lkFwOutGone) { [Console]::Error.WriteLine("  outbound firewall rule $lkRule still exists after unlock") }
if (-not $lkFwInGone)  { [Console]::Error.WriteLine("  inbound firewall rule $lkRule-in still exists after unlock") }

# Step 8: clean up the sandbox dir.
& $exe rm --force $lkName 2>$null | Out-Null
Check 'lock-down: sandbox dir removed after rm' (-not (Test-Path "$env:LOCALAPPDATA\izba\sandboxes\$lkName"))

# Best-effort teardown: ensure no orphan account/rules/sandbox remain
# even if an earlier step failed.  Safe to re-run -- all calls are idempotent.
& $exe stop  $lkName 2>$null | Out-Null
& $exe rm --force $lkName 2>$null | Out-Null
& $exe unlock $lkName 2>$null | Out-Null
Remove-LocalUser $lkAcct -ErrorAction SilentlyContinue
powershell.exe -NoProfile -NonInteractive -Command `
    "Get-NetFirewallRule -DisplayName '$lkRule' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; Get-NetFirewallRule -DisplayName '$lkRule-in' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" 2>$null | Out-Null
if (Test-Path $lkWs) { Remove-Item -Recurse -Force $lkWs -ErrorAction SilentlyContinue }

$lkSectionFails = $fails - $lkFails0
if ($lkSectionFails -gt 0) {
    [Console]::Error.WriteLine("  [11] lock-down section: $lkSectionFails check(s) failed")
}

# Best-effort daemon cleanup so the validation run leaves no daemon behind.
& $exe daemon stop 2>$null | Out-Null

Write-Output "---"
if ($fails -eq 0) { Write-Output 'ALL PASS'; exit 0 }
else { [Console]::Error.WriteLine("$fails check(s) FAILED"); exit 1 }
