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
#           [8] stop/restart/rm.
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

# Fresh workspace + no leftover sandbox from a previous run
& $exe stop valid8 2>$null | Out-Null
& $exe rm --force valid8 2>$null | Out-Null
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory -Path $ws | Out-Null

# [1] run: create-on-first-use + pull + erofs + boot + exec, non-interactive
& $exe run --image $image --name valid8 $ws -- /bin/sh -c 'echo booted > /workspace/marker && uname -s'
Check 'run exits 0' ($LASTEXITCODE -eq 0)
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
& $exe stop egress-a 2>$null | Out-Null
& $exe rm --force egress-a 2>$null | Out-Null
& $exe run --image $image --name egress-a $ws -- /bin/true | Out-Null
Check 'izbad-egress sandbox boots (run exits 0)' ($LASTEXITCODE -eq 0)
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
& $exe rm --force egress-a 2>$null | Out-Null

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

# Best-effort daemon cleanup so the validation run leaves no daemon behind.
& $exe daemon stop 2>$null | Out-Null

Write-Output "---"
if ($fails -eq 0) { Write-Output 'ALL PASS'; exit 0 }
else { [Console]::Error.WriteLine("$fails check(s) FAILED"); exit 1 }
