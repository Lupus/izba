<#
.SYNOPSIS
    Quiesce izba before (un)installation: stop sandboxes + daemon, then
    force-kill anything still running from the install dir.

.DESCRIPTION
    Run by the Inno Setup installer (PrepareToInstall) and uninstaller so a
    file replacement never trips "Setup was unable to automatically close all
    applications" — the Windows Restart Manager cannot gracefully close
    console/background processes like `izba daemon run` or per-sandbox
    openvmm.exe VMMs.

    Order matters and mirrors the product contract:
      1. `izba stop --all`   — gracefully stops every running/degraded sandbox
                               (a plain `izba daemon stop` deliberately leaves
                               sandboxes running).
      2. `izba daemon stop`  — stops the daemon.
      3. Force-kill leftovers matched by EXECUTABLE PATH under the install
         dir (never by name), so unrelated processes are never touched.

    Every step is best-effort with a timeout; the script always exits 0 —
    the installer's CloseApplications=force is the final backstop.

.PARAMETER InstallDir
    The izba install directory (Inno's {app}), e.g. C:\Program Files\izba.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallDir
)

$ErrorActionPreference = 'Continue'

function Invoke-WithTimeout {
    param(
        [string]   $File,
        [string[]] $CmdArgs,
        [int]      $TimeoutSec
    )
    try {
        $p = Start-Process -FilePath $File -ArgumentList $CmdArgs `
            -NoNewWindow -PassThru -ErrorAction Stop
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    } catch {
        # Best-effort: a missing/old binary (e.g. pre-`stop --all` izba) or a
        # wedged daemon must never block the installer.
    }
}

$izba = Join-Path $InstallDir 'bin\izba.exe'
if (Test-Path -LiteralPath $izba) {
    # Graceful first: VMs sync + exit cleanly. Generous timeout — stopping
    # several sandboxes takes a few seconds each.
    Invoke-WithTimeout -File $izba -CmdArgs @('stop', '--all') -TimeoutSec 120
    Invoke-WithTimeout -File $izba -CmdArgs @('daemon', 'stop') -TimeoutSec 30
}

# Force-kill anything still executing from under the install dir: a wedged
# daemon, orphaned openvmm.exe VMMs, the GUI app, the jail helper. Path
# prefix match with a trailing separator so 'izba' never matches 'izba2'.
$prefix = $InstallDir.TrimEnd('\') + '\'
Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and
    $_.Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -and
    $_.ProcessName -notlike 'unins*'   # never kill the Inno uninstaller
} | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

exit 0
