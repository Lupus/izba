<#
.SYNOPSIS
    Quiesce izba before (un)installation: close the desktop app, stop
    sandboxes + daemon, then force-kill anything still running from the
    install dir - reporting progress for the installer to display.

.DESCRIPTION
    Run by the Inno Setup installer (PrepareToInstall) and uninstaller so a
    file replacement never trips "Setup was unable to automatically close all
    applications" - the Windows Restart Manager cannot gracefully close
    console/background processes like `izba daemon run` or per-sandbox
    openvmm.exe VMMs.

    Order matters and mirrors the product contract:
      1. Close the desktop app (izba-app.exe) FIRST - its daemon polling
         auto-respawns `izba daemon run` (connect_spawning_izba), so a live
         app would resurrect the daemon between step 3 and the Restart
         Manager scan that follows this script, putting the "applications
         need to be closed" page right back.
      2. `izba stop --all`   - gracefully stops every running/degraded sandbox
                               (a plain `izba daemon stop` deliberately leaves
                               sandboxes running).
      3. `izba daemon stop`  - stops the daemon (waits for it to exit).
      4. Force-kill leftovers matched by EXECUTABLE PATH under the install
         dir (never by name), re-scanning until no leftovers remain so a
         late respawn cannot slip past a one-shot sweep.

    Every step is best-effort with a timeout; the script always exits 0 -
    the installer's CloseApplications=force is the final backstop.

.PARAMETER InstallDir
    The izba install directory (Inno's {app}), e.g. C:\Program Files\izba.

.PARAMETER StatusFile
    Optional: a file this script overwrites with a one-line progress message
    as it works. The installer polls it onto the "Preparing to Install" page
    so a multi-minute quiesce is never a blank screen.

.PARAMETER DoneFile
    Optional: a file created when the quiesce is finished (success or not).
    The installer polls for its existence instead of blocking on this
    process, which keeps its UI updatable while we work. The path also
    doubles as the installer's kill marker: if the polling ceiling expires
    first, it tree-kills whatever process carries this unique path on its
    command line - i.e. this script - so file replacement never races a
    still-running quiesce.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallDir,

    [string] $StatusFile,

    [string] $DoneFile
)

$ErrorActionPreference = 'Continue'

function Write-Status {
    param([string] $Message)
    if (-not $StatusFile) { return }
    try {
        [System.IO.File]::WriteAllText($StatusFile, $Message)
    } catch {
        # Best-effort UI plumbing: a locked/unwritable status file must never
        # fail the quiesce itself.
        Write-Debug "status write failed: $_"
    }
}

function Get-ProcessesByPath {
    # One WMI query for every process's executable path. Get-Process's .Path
    # walks each process's module list and measures ~30 s per sweep on a busy
    # host (the bulk of the old blank-screen stall); this takes ~1 s.
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock] $PathFilter
    )
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and (& $PathFilter $_.ExecutablePath) }
}

function Invoke-WithTimeout {
    param(
        [string]   $File,
        [string[]] $CmdArgs,
        [int]      $TimeoutSec,
        [string]   $StatusPrefix
    )
    # stdout is captured so per-sandbox progress lines (`stopped <name>` from
    # `izba stop --all`) can be relayed live to the installer UI.
    $outFile = [System.IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $File -ArgumentList $CmdArgs `
            -NoNewWindow -PassThru -RedirectStandardOutput $outFile -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
        while (-not $p.WaitForExit(250)) {
            if ([DateTime]::UtcNow -gt $deadline) {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                break
            }
            if ($StatusPrefix) {
                $line = Get-Content -LiteralPath $outFile -Tail 1 -ErrorAction SilentlyContinue
                if ($line) { Write-Status "$StatusPrefix $line" }
            }
        }
    } catch {
        # Best-effort: a missing/old binary (e.g. pre-`stop --all` izba) or a
        # wedged daemon must never block the installer.
        Write-Warning "izba shutdown step '$File $CmdArgs' failed: $_"
    } finally {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
}

try {
    # 1. Desktop app first (see DESCRIPTION for why the order matters).
    #    Exact-path match so unrelated processes are never touched.
    $appExe = Join-Path $InstallDir 'bin\izba-app.exe'
    $apps = Get-ProcessesByPath {
        param($path) $path.Equals($appExe, [System.StringComparison]::OrdinalIgnoreCase)
    }
    if ($apps) {
        Write-Status 'Closing the izba desktop app...'
        foreach ($p in $apps) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Wait-Process -Id ($apps | ForEach-Object { $_.ProcessId }) `
            -Timeout 5 -ErrorAction SilentlyContinue
    }

    $izba = Join-Path $InstallDir 'bin\izba.exe'
    if (Test-Path -LiteralPath $izba) {
        # Graceful first: VMs sync + exit cleanly. Generous timeout - stopping
        # several sandboxes takes a few seconds each.
        Write-Status 'Stopping izba sandboxes (this can take a few minutes)...'
        Invoke-WithTimeout -File $izba -CmdArgs @('stop', '--all') -TimeoutSec 120 `
            -StatusPrefix 'Stopping izba sandboxes:'
        Write-Status 'Stopping the izba daemon...'
        Invoke-WithTimeout -File $izba -CmdArgs @('daemon', 'stop') -TimeoutSec 30
    }

    # 2. Force-kill anything still executing from under the install dir: a
    #    wedged daemon, orphaned openvmm.exe VMMs, the jail helper. Path
    #    prefix match with a trailing separator so 'izba' never matches
    #    'izba2'. Re-scan until clean: anything that respawned a process
    #    after the first pass must not survive into the Restart Manager scan.
    Write-Status 'Cleaning up leftover izba processes...'
    $prefix = $InstallDir.TrimEnd('\') + '\'
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $leftovers = Get-ProcessesByPath {
            param($path) $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
        } | Where-Object { $_.Name -notlike 'unins*' }   # never kill the Inno uninstaller
        if (-not $leftovers) { break }
        foreach ($p in $leftovers) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500
    }
} finally {
    # Always mark completion - the installer stops polling on the done file,
    # and a quiesce that failed halfway must not stall it for the full
    # timeout on top.
    Write-Status 'izba shutdown complete.'
    if ($DoneFile) {
        try {
            [System.IO.File]::WriteAllText($DoneFile, 'done')
        } catch {
            Write-Warning "done-marker write failed: $_"
        }
    }
}

exit 0
