# #319 -- real-host check: does izba refuse to call a sandbox stopped while a
# terminated openvmm.exe of its VMM tree has not finished teardown?
#
# Inputs (env):  IZBA_EXE       path to izba.exe under test
#                IZBA_DATA_DIR  the data root holding the sandbox
#                IZBA_SANDBOX   the sandbox name
#                IZBA_CHECK_RM  set to 1 to also run the destructive
#                               `izba rm --force` step (see below)
# It never creates or starts anything. It runs `izba status` and `izba stop`
# against the given sandbox, which is what a user would do, and reports
# PASS/FAIL per #319 acceptance criterion.
#
# DESTRUCTIVE, OPT-IN: `izba rm --force` runs only when IZBA_CHECK_RM=1 AND
# `izba stop` was refused BECAUSE the disks are held. Even then it REALLY
# DELETES the sandbox if the worker finishes exiting between the refused stop
# and the rm (or during rm's own re-sweep) -- point it only at a DISPOSABLE
# sandbox. Without the opt-in the three rm checks are reported as SKIP and do
# not count as failures.
#
# Exit code: number of failed checks; 100 when a prerequisite is missing.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$exe  = $env:IZBA_EXE
$data = $env:IZBA_DATA_DIR
$name = $env:IZBA_SANDBOX
$fails = 0

function Say($text) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $text) }
function Check($what, $ok) {
    if ($ok) { Say "PASS  $what" } else { Say "FAIL  $what"; $script:fails++ }
}
function Skip($what) { Say "SKIP  $what" }

foreach ($req in @(@('IZBA_EXE', $exe), @('IZBA_DATA_DIR', $data), @('IZBA_SANDBOX', $name))) {
    if ([string]::IsNullOrEmpty($req[1])) {
        [Console]::Error.WriteLine("stuck-vmm-teardown-check: set $($req[0])")
        exit 100
    }
}
if (-not (Test-Path $exe)) { [Console]::Error.WriteLine("no such izba.exe: $exe"); exit 100 }
$sandboxDir = Join-Path $data "sandboxes\$name"
if (-not (Test-Path $sandboxDir)) { [Console]::Error.WriteLine("no such sandbox dir: $sandboxDir"); exit 100 }

# Run izba with the data root under test; return rc + combined output.
function Invoke-Izba([string[]] $izbaArgs) {
    $env:IZBA_DATA_DIR = $data
    $out = & $exe @izbaArgs 2>&1 | ForEach-Object { "$_" } | Out-String -Width 4096
    return @{ rc = $LASTEXITCODE; out = $out.Trim() }
}

# --- 1. census: every openvmm.exe, and which of them are exited-but-present.
Say 'openvmm.exe processes on the host:'
$vmms = @(Get-CimInstance Win32_Process -Filter "Name='openvmm.exe'" -ErrorAction SilentlyContinue)
foreach ($p in $vmms) {
    $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
    $exited = 'n/a'
    if ($null -ne $proc) {
        try { $exited = $proc.HasExited } catch { $exited = 'n/a' }
    }
    Say ("  pid={0} ppid={1} exited={2} threads={3} handles={4} working_set_mb={5}" -f `
        $p.ProcessId, $p.ParentProcessId, $exited, $p.ThreadCount, $p.HandleCount, [int]($p.WorkingSetSize / 1MB))
}
if ($vmms.Count -eq 0) { Say '  (none)' }

# --- 2. is the writable disk exclusively held?
$rw = Join-Path $sandboxDir 'rw.img'
$held = $false
if (Test-Path $rw) {
    try {
        $fs = [System.IO.File]::Open($rw, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        $held = $true
    }
}
Say "rw.img exclusively held by another process: $held"

# --- 3. the #319 contract through the CLI.
$status = Invoke-Izba @('status', $name)
Say "izba status: rc=$($status.rc)"
Say ("  " + ($status.out -replace "`r?`n", "`n  "))
Check 'status does not report a clean stop (no bare "stopped" line)' ($status.out -notmatch '(?m)^\s*status:\s*stopped\s*$')
Check 'status reports the stuck teardown (degraded ... outlived its launcher and still holds the disks)' ($status.out -match 'degraded \(vmm process(es)? [0-9, ]+ outlived (its|their) launcher and still holds? the disks\)')

$stop = Invoke-Izba @('stop', $name)
Say "izba stop: rc=$($stop.rc)"
Say ("  " + ($stop.out -replace "`r?`n", "`n  "))
Check 'stop exits non-zero' ($stop.rc -ne 0)
Check 'stop names a pid and says the disks are still held' ($stop.out -match 'VMM process(es)? [0-9, ]+ from its last run (is|are) still present and holds? the sandbox''s disks')
Check 'stop says what to do (run stop again / host reboot)' ($stop.out -match 'Run `izba stop' -and $stop.out -match 'host reboot')
Check 'state.json is preserved after the refused stop' (Test-Path (Join-Path $sandboxDir 'state.json'))

$stopRefusedForDisks = ($stop.rc -ne 0 -and $stop.out -match 'holds? the sandbox''s disks')
$rmOptIn = ($env:IZBA_CHECK_RM -eq '1')
if (-not $rmOptIn) {
    Say 'rm --force: skipped -- set IZBA_CHECK_RM=1 to run it against a DISPOSABLE sandbox; it really deletes the sandbox if the worker finishes exiting meanwhile'
    Skip 'rm --force exits non-zero'
    Skip 'rm --force gives the same explanation, not a raw Access is denied'
    Skip 'sandbox dir still exists after the refused rm'
}
elseif ($stopRefusedForDisks) {
    $rm = Invoke-Izba @('rm', $name, '--force')
    Say "izba rm --force: rc=$($rm.rc)"
    Say ("  " + ($rm.out -replace "`r?`n", "`n  "))
    Check 'rm --force exits non-zero' ($rm.rc -ne 0)
    Check 'rm --force gives the same explanation, not a raw Access is denied' ($rm.out -match 'holds? the sandbox''s disks' -and $rm.out -notmatch 'Access is denied')
    Check 'sandbox dir still exists after the refused rm' (Test-Path $sandboxDir)
}
else {
    Say 'izba rm --force: skipped, because stop was not refused for held disks (rm --force would really delete the sandbox)'
    Check 'rm --force exits non-zero' $false
    Check 'rm --force gives the same explanation, not a raw Access is denied' $false
    Check 'sandbox dir still exists after the refused rm' $false
}

if ($fails -eq 0) { Say 'VERDICT: izba reports the stuck teardown honestly on every surface' }
else { Say "VERDICT: $fails check(s) failed" }
exit $fails
