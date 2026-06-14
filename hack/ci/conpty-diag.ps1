# ConPTY environment diagnostics. Prints facts about the runner session that
# determine whether ConPTY child output can flow: session id (0 == service /
# non-interactive), window station, OS build, and which conhost/ConPTY backend
# is available. Non-fatal — pure evidence gathering for the canary that follows.
$ErrorActionPreference = 'Continue'

function Line($k, $v) { Write-Host ("CONPTY-ENV {0}={1}" -f $k, $v) }

# Session id of THIS process: GitHub-hosted runners may run the job in a
# non-interactive session where ConPTY cannot bridge child output.
$sid = (Get-Process -Id $PID).SessionId
Line 'session_id' $sid

# Window station + desktop. Interactive sessions have WinSta0\Default.
try {
    $sig = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinSta {
    [DllImport("user32.dll")] public static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern bool GetUserObjectInformation(IntPtr h, int idx, StringBuilder p, int n, out int need);
    public static string Name() {
        var sb = new StringBuilder(256); int need;
        return GetUserObjectInformation(GetProcessWindowStation(), 2, sb, 256, out need) ? sb.ToString() : "<err>";
    }
}
'@
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    Line 'window_station' ([WinSta]::Name())
} catch { Line 'window_station' "<probe-failed: $($_.Exception.Message)>" }

# OS build (Server 2022 = 20348 ships an older conhost than client 11).
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Line 'os_build' ("{0}.{1}" -f $cv.CurrentBuildNumber, $cv.UBR)
Line 'os_product' $cv.ProductName

# System conhost version, and whether a modern ConPTY backend exists.
$conhost = Get-Item C:\Windows\System32\conhost.exe -ErrorAction SilentlyContinue
if ($conhost) { Line 'system_conhost_version' $conhost.VersionInfo.ProductVersion }
Line 'system_conpty_dll'      (Test-Path C:\Windows\System32\conpty.dll)
Line 'system_openconsole_exe' (Test-Path C:\Windows\System32\OpenConsole.exe)

# Any conpty.dll resolvable on PATH (portable-pty sideloads it by bare name).
$onPath = $env:PATH -split ';' | ForEach-Object {
    if ($_ -and (Test-Path (Join-Path $_ 'conpty.dll') -ErrorAction SilentlyContinue)) { Join-Path $_ 'conpty.dll' }
} | Select-Object -First 1
Line 'conpty_dll_on_path' ($(if ($onPath) { $onPath } else { '<none>' }))
