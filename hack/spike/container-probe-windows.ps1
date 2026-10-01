# Spike #249 -- container-state probe on Windows/OpenVMM: what does the
# `container:` line say for a running workload, and how long does the probe
# behind it take compared with its 5 s bound?
#
# Findings: docs/spikes/0002-windows-container-probe-latency.md
#
# One sandbox in its OWN data root (nothing under %LOCALAPPDATA%\izba is
# touched), driven through the #193 scenario -- ubuntu, a USB grant (so it
# boots the USB kernel), a device attached over the usbip plane -- and then
# through the states a fresh-boot check cannot see: the boot window, overlapping
# probes, a restarted daemon that has to adopt the running sandbox from disk,
# saturated vCPUs, heavy writeback, and a few hundred probes in a row.
#
# Two instruments, because `izba status` cannot tell them apart:
#   * `izba status`         -> the rendered `container:` line (None and a
#                              guest-reported Unknown both print "unknown");
#   * hack/spike/probe-latency -> the raw guest reply and per-phase timings of
#                              the exact sequence the daemon's probe performs,
#                              for both the Health probe (`izba status`) and
#                              the Stats probe (the desktop app's Overview).
#
# Env (required): IZBA_EXE             izba.exe, installer-shaped tree
#                 IZBA_PROBE_LATENCY   built hack/spike/probe-latency
#                 IZBA_FAKE_USBIPD     built hack/fake-usbipd
# Env (optional): IZBA_IMAGE           default ubuntu:24.04
#                 IZBA_DATA_DIR        default: a per-run dir under %TEMP%. Must
#                                      not exist yet (or be empty): this run
#                                      owns its data root -- it sets the usbip
#                                      upstream there, restarts that root's
#                                      daemon and removes the sandbox it made
#                 IZBA_OUT_DIR         where the JSONL evidence lands
#                 IZBA_MEM_MB          guest RAM, default 1024
#                 IZBA_STATUS_SOAK     sequential `izba status` calls, default 300
#                 IZBA_USB_TRAFFIC=1   also probe during a 40 s write flood
#                                      through the attached device (see the
#                                      findings: the one run that did this was
#                                      followed by a VMM that never finished
#                                      exiting)
# IZBA_KERNEL_USB + IZBA_INITRAMFS are deliberately NOT cleared: set the pair
# to boot other artifacts (e.g. the ones from the date of a bug report) under
# the izba.exe being tested.
#
# Exit code: the number of failed checks (0 = every reading was `running`);
# 100 when a prerequisite is missing and nothing was run.
$ErrorActionPreference = 'Continue'

$exe    = $env:IZBA_EXE
$probe  = $env:IZBA_PROBE_LATENCY
$fake   = $env:IZBA_FAKE_USBIPD
$image  = if ($env:IZBA_IMAGE) { $env:IZBA_IMAGE } else { 'ubuntu:24.04' }
$memMb  = if ($env:IZBA_MEM_MB) { $env:IZBA_MEM_MB } else { '1024' }
$soak   = if ($env:IZBA_STATUS_SOAK) { [int]$env:IZBA_STATUS_SOAK } else { 300 }
$device = '0403:6001'
$name   = 'probe249'
$boundMs = 5000   # CONTAINER_PROBE_TIMEOUT / STATS_PROBE_TIMEOUT in daemon/server.rs
$tmp    = [System.IO.Path]::GetTempPath()
$data   = if ($env:IZBA_DATA_DIR) { $env:IZBA_DATA_DIR } else { Join-Path $tmp "i249-$PID" }
$out    = if ($env:IZBA_OUT_DIR) { $env:IZBA_OUT_DIR } else { Join-Path $tmp "izba-probe249-$PID" }
$ws     = Join-Path $tmp "i249-ws-$PID"
$fails  = 0
$worst  = @{ health = 0.0; stats = 0.0 }

function Say($text) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $text) }

function Check($what, $ok) {
    if ($ok) { Say "PASS  $what" } else { Say "FAIL  $what"; $script:fails++ }
}

function Fail-Preflight($why) {
    [Console]::Error.WriteLine("container-probe spike cannot run: $why")
    exit 100
}

# Run an izba command, report rc + wall time, return its combined output.
function Invoke-Izba($label, [string[]] $izbaArgs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lines = @(& $exe @izbaArgs 2>&1 | ForEach-Object { "$_" })
    $sw.Stop()
    Say ("{0}: rc={1} elapsed_ms={2}" -f $label, $LASTEXITCODE, $sw.ElapsedMilliseconds)
    $lines | Where-Object { $_.Trim() } | ForEach-Object { Write-Output ("    " + $_.TrimEnd()) }
}

# One `izba status`, reduced to the two lines that matter plus its wall time.
function Read-Status {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lines = @(& $exe status $name 2>&1 | ForEach-Object { "$_" })
    $sw.Stop()
    $field = {
        param($key)
        $hit = $lines | Where-Object { $_ -match "^${key}:" } | Select-Object -First 1
        if ($hit) { ($hit -replace "^${key}:\s*", '').Trim() } else { '' }
    }
    return [pscustomobject]@{
        Ms        = $sw.ElapsedMilliseconds
        Status    = (& $field 'status')
        Container = (& $field 'container')
    }
}

# N status readings; every one must say running/running.
function Assert-StatusRunning($label, [int] $count) {
    $bad = 0; $max = 0
    for ($i = 1; $i -le $count; $i++) {
        $s = Read-Status
        if ($s.Ms -gt $max) { $max = $s.Ms }
        if ($s.Status -ne 'running' -or $s.Container -ne 'running') {
            $bad++
            Say ("  {0} #{1}: status='{2}' container='{3}' elapsed_ms={4}" -f $label, $i, $s.Status, $s.Container, $s.Ms)
        }
    }
    Check ("{0}: {1}/{2} 'izba status' readings say container: running (max {3} ms)" -f $label, ($count - $bad), $count, $max) ($bad -eq 0)
}

# One probe-latency run. The tool exits 0 only when every probe replica and
# every direct round trip came back `some:running`.
function Measure-Probe($label, [string[]] $toolArgs) {
    $jsonl = Join-Path $out "$label.jsonl"
    $p = Start-Process -FilePath $probe -ArgumentList (@($name) + $toolArgs) -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $jsonl -RedirectStandardError (Join-Path $out "$label.err")
    $summary = $null
    try { $summary = (Get-Content $jsonl -Tail 1 | ConvertFrom-Json).summary } catch { $summary = $null }
    if ($null -eq $summary) {
        Check "${label}: probe-latency produced a summary (rc=$($p.ExitCode))" $false
        return
    }
    $t = $summary.probe.total_us
    $d = $summary.direct.total_us
    $kind = if ($toolArgs -contains 'stats') { 'stats' } else { 'health' }
    if ($null -ne $t.max -and ($t.max / 1000.0) -gt $script:worst[$kind]) { $script:worst[$kind] = $t.max / 1000.0 }
    $tally = ($summary.probe.inspect_container.PSObject.Properties | ForEach-Object { "$($_.Name) x$($_.Value)" }) -join ', '
    # A timing is null when no exchange completed (e.g. a guest without the RPC).
    $ms = { param($us) if ($null -eq $us) { 'n/a' } else { '{0:N1}' -f ($us / 1000.0) } }
    Say ("  {0}: completed={1} failed={2} | probe ms p50={3} p95={4} max={5} | one round trip ms p50={6} p95={7} max={8} | {9}" -f `
            $label, $t.count, $summary.probe.failures, (& $ms $t.p50), (& $ms $t.p95), (& $ms $t.max), `
            (& $ms $d.p50), (& $ms $d.p95), (& $ms $d.max), $tally)
    Check "${label}: every probe returned some:running" ($p.ExitCode -eq 0)
}

# Background `sh /workspace/<script>` inside the container. Guest workloads are
# files in the workspace so no argument quoting is involved (Start-Process
# joins its argument list with spaces and does not quote).
function Start-GuestScript($script) {
    return Start-Process -FilePath $exe -ArgumentList 'exec', $name, '--', 'sh', "/workspace/$script" -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $out "$script.out") -RedirectStandardError (Join-Path $out "$script.err")
}

# A guest workload only counts as "the condition under test" if it was still
# running when the probes finished: probe-latency takes seconds to start, and a
# workload that ended first would leave idle numbers under a busy label.
function Stop-GuestWorkload($label, $proc, $stopFile) {
    Check "${label}: the guest workload was still running when the probes finished" (-not $proc.HasExited)
    & $exe exec $name -- touch $stopFile 2>&1 | Out-Null
    if (-not $proc.HasExited) { $proc.WaitForExit(120000) | Out-Null }
}

# Every openvmm.exe on the host, as pid -> one-line description.
function Get-VmmProcesses {
    $found = @{}
    Get-CimInstance Win32_Process -Filter "Name='openvmm.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        $found[[int]$_.ProcessId] = ("pid={0} ppid={1} threads={2} handles={3} working_set_mb={4}" -f `
                $_.ProcessId, $_.ParentProcessId, $_.ThreadCount, $_.HandleCount, [int]($_.WorkingSetSize / 1MB))
    }
    return $found
}

function Set-GuestScript($file, $body) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $ws $file), ($body -replace "`r`n", "`n"), $utf8)
}

# --- preflight -------------------------------------------------------------
foreach ($req in @(@('IZBA_EXE', $exe), @('IZBA_PROBE_LATENCY', $probe), @('IZBA_FAKE_USBIPD', $fake))) {
    if (-not $req[1] -or -not (Test-Path $req[1] -PathType Leaf)) {
        Fail-Preflight "$($req[0]) must point at an existing file (got '$($req[1])')"
    }
}
# The data root must be this run's own. Pointed at a root that already holds
# sandboxes, the teardown below would stop that root's daemon and could remove
# a sandbox this run never created.
if ((Test-Path $data) -and @(Get-ChildItem -LiteralPath $data -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    Fail-Preflight "data root $data already exists and is not empty -- give this run a fresh IZBA_DATA_DIR"
}
New-Item -ItemType Directory -Path $data, $out, $ws -Force | Out-Null
$env:IZBA_DATA_DIR = $data

# Both workloads run until told to stop (or 5 minutes), so they outlast the
# probes taken under them.
Set-GuestScript 'burn.sh' @'
rm -f /tmp/burn.stop
for i in 1 2 3 4 5 6; do
  ( end=$(( $(date +%s) + 300 ))
    while [ ! -e /tmp/burn.stop ] && [ "$(date +%s)" -lt "$end" ]; do j=0; while [ "$j" -lt 20000 ]; do j=$((j+1)); done; done ) &
done
wait
'@
Set-GuestScript 'io.sh' @'
rm -f /tmp/io.stop
end=$(( $(date +%s) + 300 )); n=0
while [ ! -e /tmp/io.stop ] && [ "$(date +%s)" -lt "$end" ]; do
  dd if=/dev/zero of=/var/tmp/izba249.bin bs=1M count=1024 conv=fsync 2>/dev/null && n=$((n+1))
done
rm -f /var/tmp/izba249.bin
echo "$n x 1 GiB written with fsync"
'@
Set-GuestScript 'usb-flood.sh' @'
n=$(ls /dev/izba | head -1)
cat "/dev/izba/$n" > /dev/null &
r=$!
end=$(( $(date +%s) + 40 )); c=0
while [ "$(date +%s)" -lt "$end" ]; do echo "izba249 probe traffic $c" > "/dev/izba/$n" && c=$((c+1)); done
kill $r
echo "$c writes through /dev/izba/$n succeeded"
'@

Say "exe=$exe"
Say "data=$data out=$out image=$image mem=${memMb}MiB"
Say ("boot-artifact override: IZBA_KERNEL_USB='{0}' IZBA_INITRAMFS='{1}'" -f $env:IZBA_KERNEL_USB, $env:IZBA_INITRAMFS)
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Say "host: Windows build $($os.CurrentBuild).$($os.UBR) $($os.DisplayVersion), elevated=$admin"
Invoke-Izba 'version' @('version')

$fakeProc = $null
$vmmBefore = Get-VmmProcesses
$vmmOurs = @()
$created = $false
try {
    $fakeOut = Join-Path $out 'fake-usbipd.out'
    $fakeProc = Start-Process -FilePath $fake -ArgumentList '127.0.0.1:0' -RedirectStandardOutput $fakeOut -NoNewWindow -PassThru
    $addr = $null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $addr -and (Get-Date) -lt $deadline) {
        $line = Get-Content $fakeOut -TotalCount 1 -ErrorAction SilentlyContinue
        if ($line -match '^\s*(127\.0\.0\.1:\d+)\s*$') { $addr = $Matches[1] } else { Start-Sleep -Milliseconds 200 }
    }
    Check 'fake usbip server announced its address' ($null -ne $addr)
    if ($null -eq $addr) { throw 'no usbip upstream' }

    Invoke-Izba 'usb upstream set' @('usb', 'upstream', 'set', $addr)
    Invoke-Izba 'create' @('create', $ws, '--name', $name, '--image', $image, '--mem', $memMb)
    $created = ($LASTEXITCODE -eq 0)
    Check 'create exits 0' $created
    if (-not $created) { throw 'the sandbox was not created' }
    Invoke-Izba 'usb allow' @('usb', 'allow', $name, '--device', $device, '--confirm', $device)

    # --- 1. the boot window: poll status as fast as it answers while `start` runs
    $start = Start-Process -FilePath $exe -ArgumentList 'start', $name -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $out 'start.out') -RedirectStandardError (Join-Path $out 'start.err')
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $prev = $null; $returnedAt = $null; $runningUnknown = 0; $bootReadings = 0
    while ($clock.ElapsedMilliseconds -lt 60000) {
        $at = $clock.ElapsedMilliseconds
        $s = Read-Status
        $bootReadings++
        $key = "status='$($s.Status)' container='$($s.Container)'"
        # Anything but "stopped" is a sandbox the daemon believes is up.
        if ($s.Status -ne 'stopped' -and $s.Container -ne 'running') { $runningUnknown++ }
        if ($key -ne $prev) { Say ("boot window t+{0} ms: {1}" -f $at, $key); $prev = $key }
        if ($start.HasExited -and $null -eq $returnedAt) {
            $returnedAt = $clock.ElapsedMilliseconds
            Say "boot window: 'izba start' returned at t+$returnedAt ms"
        }
        if ($null -ne $returnedAt -and ($clock.ElapsedMilliseconds - $returnedAt) -gt 3000) { break }
    }
    Check 'sandbox booted' ((Read-Status).Status -eq 'running')
    Check "boot window: none of $bootReadings readings showed a non-stopped sandbox without container: running" ($runningUnknown -eq 0)
    $state = Get-Content (Join-Path $data "sandboxes\$name\state.json") -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($state) { Say "state.json: vmm pid=$($state.vmm_pid.pid) usb_kernel=$($state.usb_kernel)" }
    # Every openvmm.exe this start created -- the pid in state.json and any
    # process it spawned -- so teardown can check that ALL of them went away.
    $vmmNow = Get-VmmProcesses
    $vmmOurs = @($vmmNow.Keys | Where-Object { -not $vmmBefore.ContainsKey($_) })
    $vmmOurs | ForEach-Object { Say "openvmm.exe started by this run: $($vmmNow[$_])" }

    # --- 2. idle
    Assert-StatusRunning 'idle' 10
    Measure-Probe 'health-idle' @('--iterations', '300', '--interval-ms', '20')
    Measure-Probe 'stats-idle' @('--request', 'stats', '--iterations', '40', '--interval-ms', '20')

    # --- 3. overlapping probes
    Measure-Probe 'health-parallel8' @('--iterations', '100', '--interval-ms', '0', '--parallel', '8')

    # --- 4. a USB device attached (the #193 scenario)
    Invoke-Izba 'usb attach' @('usb', 'attach', $name, '--device', $device)
    $listing = ''
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $listing = (& $exe exec $name -- ls /dev/izba/ 2>&1 | Out-String).Trim()
        if ($listing -notmatch 'tty') { Start-Sleep -Milliseconds 500 }
    } while ($listing -notmatch 'tty' -and (Get-Date) -lt $deadline)
    Check "the attached device's node is in the container (/dev/izba: '$listing')" ($listing -match 'tty')
    Assert-StatusRunning 'usb attached' 5
    Measure-Probe 'health-usb-attached' @('--iterations', '100', '--interval-ms', '20')
    Measure-Probe 'stats-usb-attached' @('--request', 'stats', '--iterations', '20', '--interval-ms', '20')
    # The readings above only count if the device stayed attached throughout.
    $listing = (& $exe exec $name -- ls /dev/izba/ 2>&1 | Out-String).Trim()
    Check "the device is still attached after those probes (/dev/izba: '$listing')" ($listing -match 'tty')
    if ($env:IZBA_USB_TRAFFIC -eq '1') {
        $flood = Start-GuestScript 'usb-flood.sh'
        Start-Sleep -Seconds 3
        Assert-StatusRunning 'usb write flood' 5
        Measure-Probe 'health-usb-flood' @('--iterations', '300', '--interval-ms', '20')
        if (-not $flood.HasExited) { $flood.WaitForExit(60000) | Out-Null }
        Say ('usb flood: ' + ((Get-Content (Join-Path $out 'usb-flood.sh.out') -ErrorAction SilentlyContinue) -join ' / '))
    }

    # --- 5. a restarted daemon. izbad holds no authoritative state: the next
    # client respawns it and it adopts the running sandbox from disk. A registry
    # that came back saying "stopped" would skip the probe and print unknown.
    Invoke-Izba 'daemon stop (sandbox keeps running)' @('daemon', 'stop')
    Assert-StatusRunning 'after a daemon restart (adopted from disk)' 10
    Invoke-Izba 'exec after the daemon restart' @('exec', $name, '--', 'echo', 'exec-works')

    # --- 6. a busy guest: 6 busy loops on the vCPUs, then heavy writeback
    $burn = Start-GuestScript 'burn.sh'
    Start-Sleep -Seconds 8
    Invoke-Izba 'guest: loadavg, nproc' @('exec', $name, '--', 'sh', '-c', 'cat /proc/loadavg; nproc')
    Assert-StatusRunning 'cpu saturated' 5
    Measure-Probe 'health-cpu-saturated' @('--iterations', '300', '--interval-ms', '20')
    Measure-Probe 'stats-cpu-saturated' @('--request', 'stats', '--iterations', '20', '--interval-ms', '20')
    Invoke-Izba 'guest: loadavg at the end of the saturated probes' @('exec', $name, '--', 'cat', '/proc/loadavg')
    Stop-GuestWorkload 'cpu saturated' $burn '/tmp/burn.stop'

    $io = Start-GuestScript 'io.sh'
    Start-Sleep -Seconds 2
    Assert-StatusRunning 'writeback' 5
    Measure-Probe 'health-writeback' @('--iterations', '300', '--interval-ms', '20')
    Stop-GuestWorkload 'writeback' $io '/tmp/io.stop'
    Say ('writeback: ' + ((Get-Content (Join-Path $out 'io.sh.out') -ErrorAction SilentlyContinue) -join ' / '))

    # --- 7. many probes in a row (does the answer degrade with the count?)
    Assert-StatusRunning "soak of $soak sequential probes" $soak

    Say '--- console.log (kernel + container lines)'
    Get-Content (Join-Path $data "sandboxes\$name\logs\console.log") -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '\[OCI\]|Linux version|Kernel command line' } |
        Select-Object -Last 5 | ForEach-Object { Write-Output ("    " + $_) }
} finally {
    # --- 8. teardown, and whether every VMM process really went away. Only a
    # sandbox this run created is stopped and removed.
    if ($created) {
        Invoke-Izba 'usb detach' @('usb', 'detach', $name, '--device', $device)
        Invoke-Izba 'stop' @('stop', $name)
        $after = Read-Status
        Say "after stop: status='$($after.Status)' container='$($after.Container)' (unknown is the expected answer for a stopped sandbox)"
        $poweredDown = [bool](Get-Content (Join-Path $data "sandboxes\$name\logs\console.log") -Tail 5 -ErrorAction SilentlyContinue |
                Where-Object { $_ -match 'Power down' })
        Say "guest console ends with 'Power down': $poweredDown"
        $vmmAfter = Get-VmmProcesses
        $ghosts = @($vmmOurs | Where-Object { $vmmAfter.ContainsKey($_) })
        $ghosts | ForEach-Object { Say "openvmm.exe still present after stop: $($vmmAfter[$_])" }
        Check ("all {0} openvmm.exe process(es) this run started are gone after 'izba stop'" -f $vmmOurs.Count) `
            ($vmmOurs.Count -gt 0 -and $ghosts.Count -eq 0)
        Invoke-Izba 'rm' @('rm', $name, '--force')
        Check 'rm exits 0' ($LASTEXITCODE -eq 0)
    }
    Invoke-Izba 'daemon stop' @('daemon', 'stop')
    if ($fakeProc -and -not $fakeProc.HasExited) { Stop-Process -Id $fakeProc.Id -Force -ErrorAction SilentlyContinue }
}

# "Slowest" is over the probes that COMPLETED; one that never completed has
# already failed its own check above.
foreach ($kind in 'health', 'stats') {
    $ms = $worst[$kind]
    Say ("slowest completed {0} probe: {1:N1} ms = {2:P2} of the {3} ms bound" -f $kind, $ms, ($ms / $boundMs), $boundMs)
    Check "the slowest completed $kind probe finished well inside the bound (< 10% of $boundMs ms)" ($ms -gt 0 -and $ms -lt ($boundMs / 10))
}
Say "evidence: $out"
if ($fails -eq 0) { Say 'VERDICT: every reading of the running sandbox was container: running' }
else { Say "VERDICT: $fails check(s) failed" }
exit $fails
