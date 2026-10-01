# USB passthrough gate (Windows/OpenVMM): a granted device must reach the
# workload over vhci -> vsock 1028 -> OpenVMM's hybrid-vsock bridge -> izbad ->
# TCP -> a usbip server, and carry bytes both ways (#191).
#
# Windows is the platform this feature exists for (usbipd-win runs here), so
# this is the counterpart of crates/izba-cli/tests/usb_attach_e2e.rs for the
# one VMM that suite cannot reach. The upstream is hack/fake-usbipd: one
# CDC-ACM device (0403:6001) that echoes what it is sent.
#
# It also resolves the kernel the way an INSTALLED build does. Every boot
# artifact override is removed from this process before the first izba call
# (the one that spawns izbad, which inherits our environment), and the data
# root is fresh, so the only place a kernel can come from is
# <exe-dir>\..\artifacts -- where the installer puts it. A build that ships no
# vmlinux-usb (#189) fails here instead of passing on an injected kernel.
#
# Env: IZBA_EXE, IZBA_FAKE_USBIPD (required); IZBA_IMAGE (default alpine:3.20);
#      IZBA_DATA_DIR (default: a per-run dir under %TEMP%).
$ErrorActionPreference = 'Continue'

$exe    = $env:IZBA_EXE
$fake   = $env:IZBA_FAKE_USBIPD
$image  = if ($env:IZBA_IMAGE) { $env:IZBA_IMAGE } else { 'alpine:3.20' }
$device = '0403:6001'
$name   = 'usbgate'
$tmp    = [System.IO.Path]::GetTempPath()
$data   = if ($env:IZBA_DATA_DIR) { $env:IZBA_DATA_DIR } else { Join-Path $tmp "izba-usb-$PID" }
$ws     = Join-Path $tmp "izba-usb-ws-$PID"
$fakeOut = Join-Path $tmp "izba-fake-usbipd-$PID.out"
$fails  = 0

function Check($what, $ok) {
    if ($ok) {
        Write-Output "PASS  $what"
    } else {
        [Console]::Error.WriteLine("FAIL  $what")
        $script:fails++
    }
}

function Fail-Preflight($why) {
    [Console]::Error.WriteLine("usb gate cannot run: $why")
    exit 1
}

# --- preflight: everything this needs, named when absent. A USB gate that
# quietly passes because it never ran is worse than no gate.
if (-not $exe -or -not (Test-Path $exe -PathType Leaf)) {
    Fail-Preflight "IZBA_EXE must point at izba.exe (got '$exe')"
}
if (-not $fake -or -not (Test-Path $fake -PathType Leaf)) {
    Fail-Preflight "IZBA_FAKE_USBIPD must point at the built hack/fake-usbipd binary (got '$fake')"
}

# Installed-layout resolution: no overrides, no data-root artifacts.
foreach ($var in 'IZBA_KERNEL', 'IZBA_KERNEL_USB', 'IZBA_INITRAMFS') {
    Remove-Item "Env:$var" -ErrorAction SilentlyContinue
    if (Test-Path "Env:$var") { Fail-Preflight "could not clear $var" }
}
$artifacts = Join-Path (Split-Path (Split-Path $exe -Parent) -Parent) 'artifacts'
foreach ($f in 'vmlinux-usb', 'initramfs.cpio.gz') {
    $p = Join-Path $artifacts $f
    if (-not (Test-Path $p -PathType Leaf)) {
        Fail-Preflight "$p is not staged -- this gate boots from the installed layout (<exe-dir>\..\artifacts), never from an override"
    }
}
if (Test-Path (Join-Path $data 'artifacts')) {
    Fail-Preflight "data root $data already has an artifacts dir -- the kernel lookup could be satisfied there instead of next to the binary"
}
New-Item -ItemType Directory -Path $data -Force | Out-Null
New-Item -ItemType Directory -Path $ws -Force | Out-Null
$env:IZBA_DATA_DIR = $data

function Show-Diagnostics {
    foreach ($log in @(
            (Join-Path $data "sandboxes\$name\logs\console.log"),
            (Join-Path $data "sandboxes\$name\logs\vmm.log"),
            (Join-Path $data 'daemon\daemon.log'))) {
        [Console]::Error.WriteLine("  --- tail $log ---")
        Get-Content $log -Tail 25 -ErrorAction SilentlyContinue |
            ForEach-Object { [Console]::Error.WriteLine("    $_") }
    }
}

# Boot an already-created sandbox, retrying the documented hosted-runner
# nested-WHP stall. Stop-only between attempts: the grant lives in the config
# and must survive.
function Start-WithRetry([int] $Attempts = 3) {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        & $exe start $name | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        [Console]::Error.WriteLine("  start attempt $attempt/$Attempts failed (exit $LASTEXITCODE)")
        Show-Diagnostics
        & $exe stop $name 2>$null | Out-Null
    }
    return $false
}

$fakeProc = $null
try {
    # The server announces the address it bound as its first line; an ephemeral
    # port keeps a real usbipd on 3240 (this is a usbipd-win host) out of it.
    $fakeProc = Start-Process -FilePath $fake -ArgumentList '127.0.0.1:0' `
        -RedirectStandardOutput $fakeOut -NoNewWindow -PassThru
    $addr = $null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $addr -and (Get-Date) -lt $deadline) {
        $line = Get-Content $fakeOut -TotalCount 1 -ErrorAction SilentlyContinue
        if ($line -match '^\s*(127\.0\.0\.1:\d+)\s*$') { $addr = $Matches[1] }
        elseif ($fakeProc.HasExited) { break }
        else { Start-Sleep -Milliseconds 200 }
    }
    Check 'fake usbip server announced its address' ($null -ne $addr)
    if ($null -eq $addr) { throw 'no upstream to attach from' }

    & $exe usb upstream set $addr | Out-Null
    Check 'usb upstream set exits 0' ($LASTEXITCODE -eq 0)

    & $exe create $ws --name $name --image $image | Out-Null
    Check 'create exits 0' ($LASTEXITCODE -eq 0)

    # The grant must exist BEFORE the start: it is what selects the USB kernel.
    & $exe usb allow $name --device $device --confirm $device | Out-Null
    Check 'usb allow exits 0' ($LASTEXITCODE -eq 0)

    $booted = Start-WithRetry
    Check 'sandbox boots on the USB kernel resolved from the installed layout' $booted
    if (-not $booted) { throw 'sandbox did not boot' }

    $state = Get-Content (Join-Path $data "sandboxes\$name\state.json") -Raw -ErrorAction SilentlyContinue |
        ConvertFrom-Json -ErrorAction SilentlyContinue
    Check 'state.json records the USB kernel as the one booted' ($null -ne $state -and $state.usb_kernel -eq $true)

    # izbad's half of the plane: the AF_UNIX listener OpenVMM bridges vsock
    # 1028 to. Enumerated, not Test-Path'd: an AF_UNIX socket is a reparse
    # point some APIs refuse to stat.
    $plane = @(Get-ChildItem (Join-Path $data 'run') -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'vsock.sock_1028' })
    Check 'izbad bound the USB plane (vsock.sock_1028)' ($plane.Count -ge 1)

    $attachOut = (& $exe usb attach $name --device $device 2>&1 | Out-String)
    $attachRc  = $LASTEXITCODE
    Check 'usb attach exits 0' ($attachRc -eq 0)
    if ($attachRc -ne 0) { [Console]::Error.WriteLine("  attach said: $($attachOut.Trim())") }

    # The node must appear inside the CONTAINER, not merely in the guest.
    $listing = ''
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $listing = (& $exe exec $name -- sh -c 'ls /dev/izba/' 2>&1 | Out-String)
        if ($listing -match 'ttyACM') { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    Check 'the device node appears inside the container (/dev/izba/ttyACM*)' ($listing -match 'ttyACM')

    # The behavioural assertion: bytes written come back. Raw mode first -- a
    # canonical tty holds input until a newline -- and `timeout` so a reply
    # that never arrives fails instead of hanging the job.
    $echo = (& $exe exec $name -- sh -c 'stty -F /dev/izba/ttyACM0 raw -echo && exec 3<>/dev/izba/ttyACM0 && printf hello >&3 && timeout 10 head -c5 <&3' 2>&1 | Out-String).Trim()
    $echoRc = $LASTEXITCODE
    Check 'bytes written to the device come back (hello)' ($echoRc -eq 0 -and $echo -eq 'hello')
    if ($echoRc -ne 0 -or $echo -ne 'hello') {
        [Console]::Error.WriteLine("  echo rc=$echoRc out='$echo'")
    }

    & $exe usb detach $name --device $device | Out-Null
    Check 'usb detach exits 0' ($LASTEXITCODE -eq 0)
    # Absence has to be OBSERVED: the probe itself must succeed. A dead VM or
    # a broken exec also makes a plain `ls` fail, and must not read as "gone".
    $gone = $false
    $deadline = (Get-Date).AddSeconds(15)
    do {
        & $exe exec $name -- sh -c 'test ! -e /dev/izba/ttyACM0' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $gone = $true; break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    Check 'the device node is gone after detach (observed by a successful probe)' $gone
}
catch {
    [Console]::Error.WriteLine("usb gate aborted: $($_.Exception.Message)")
    # An abort after a failed Check is already counted; an exception with no
    # failed Check before it must still fail the gate.
    if ($fails -eq 0) { $fails++ }
}
finally {
    if ($fails -gt 0) {
        Show-Diagnostics
        # `izba rm` deletes the sandbox dir, logs included. Set them aside
        # first: on a failure they are the evidence, and the workflow uploads
        # this directory.
        $logs = Join-Path $data "sandboxes\$name\logs"
        if (Test-Path $logs) {
            Copy-Item $logs (Join-Path $data 'kept-logs') -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    & $exe rm --force $name 2>$null | Out-Null
    & $exe daemon stop 2>$null | Out-Null
    if ($null -ne $fakeProc -and -not $fakeProc.HasExited) {
        Stop-Process -Id $fakeProc.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $fakeOut -Force -ErrorAction SilentlyContinue
    Remove-Item $ws -Recurse -Force -ErrorAction SilentlyContinue
    # Keep the data root on failure: kept-logs\ and daemon\daemon.log are the evidence.
    if ($fails -eq 0) { Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Output '---'
if ($fails -eq 0) { Write-Output 'ALL PASS'; exit 0 }
[Console]::Error.WriteLine("$fails check(s) FAILED (data root kept at $data)")
exit 1
