# #319 -- real-host check: does izba refuse to call a sandbox stopped while a
# terminated openvmm.exe of its VMM tree has not finished teardown?
#
# Inputs (env):  IZBA_EXE       path to izba.exe under test
#                IZBA_DATA_DIR  the data root holding the sandbox
#                IZBA_SANDBOX   the sandbox name
# It never creates or starts anything. It runs `izba status`, `izba stop` and
# `izba rm --force` against the given sandbox, which is what a user would do,
# and reports PASS/FAIL per #319 acceptance criterion.
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
    $out = & $exe @izbaArgs 2>&1 | Out-String
    return @{ rc = $LASTEXITCODE; out = $out.Trim() }
}

# --- 1. census: every openvmm.exe, and which of them are exited-but-present.
Say 'openvmm.exe processes on the host:'
$vmms = @(Get-CimInstance Win32_Process -Filter "Name='openvmm.exe'" -ErrorAction SilentlyContinue)
foreach ($p in $vmms) {
    $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
    $exited = if ($null -ne $proc) { $proc.HasExited } else { 'n/a' }
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
Check 'status reports the stuck teardown (degraded ... not torn down, disks still held)' ($status.out -match 'degraded \(vmm process(es)? [0-9, ]+ terminated but not torn down, disks still held\)')

$stop = Invoke-Izba @('stop', $name)
Say "izba stop: rc=$($stop.rc)"
Say ("  " + ($stop.out -replace "`r?`n", "`n  "))
Check 'stop exits non-zero' ($stop.rc -ne 0)
Check 'stop names a pid and says the disks are still held' ($stop.out -match 'VMM process(es)? [0-9, ]+ ha(s|ve) been terminated' -and $stop.out -match 'still holds the sandbox''s disks')
Check 'stop says what to do (retry / host reboot)' ($stop.out -match 'Retry `izba stop' -and $stop.out -match 'host reboot')
Check 'state.json is preserved after the refused stop' (Test-Path (Join-Path $sandboxDir 'state.json'))

$rm = Invoke-Izba @('rm', $name, '--force')
Say "izba rm --force: rc=$($rm.rc)"
Say ("  " + ($rm.out -replace "`r?`n", "`n  "))
Check 'rm --force exits non-zero' ($rm.rc -ne 0)
Check 'rm --force gives the same explanation, not a raw Access is denied' ($rm.out -match 'still holds the sandbox''s disks' -and $rm.out -notmatch 'Access is denied')
Check 'sandbox dir still exists after the refused rm' (Test-Path $sandboxDir)

if ($fails -eq 0) { Say 'VERDICT: izba reports the stuck teardown honestly on every surface' }
else { Say "VERDICT: $fails check(s) failed" }
exit $fails
