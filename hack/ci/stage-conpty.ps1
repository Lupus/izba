# Stage a modern, sha-pinned ConPTY backend (conpty.dll + OpenConsole.exe) next
# to a target executable so portable-pty's load_conpty() sideloads it instead of
# the host's system conhost. This is the wezterm-blessed fix for stale/broken
# system ConPTY (e.g. Windows Server 2022's conhost). conpty.dll launches
# OpenConsole.exe from its OWN directory, so BOTH must land in -TargetDir.
#
# Source: Microsoft.Windows.Console.ConPTY (official redist from
# microsoft/terminal), pinned by version + nupkg sha256.
param(
    [Parameter(Mandatory = $true)] [string] $TargetDir
)
$ErrorActionPreference = 'Stop'

$version    = '1.24.260512001'
$sha256     = 'f889a9272a8b257dc6d5be7525626fdb0f7ca6b5ce7e13093fc4bc979d24f484'
$url        = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.console.conpty/$version/microsoft.windows.console.conpty.$version.nupkg"
$dllEntry   = 'runtimes/win-x64/native/conpty.dll'
$exeEntry   = 'build/native/runtimes/x64/OpenConsole.exe'

$work  = Join-Path ([System.IO.Path]::GetTempPath()) "conpty-redist-$version"
New-Item -ItemType Directory -Force -Path $work, $TargetDir | Out-Null
$nupkg = Join-Path $work "conpty.$version.nupkg"

Write-Host "stage-conpty: fetching $url"
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $nupkg

$got = (Get-FileHash $nupkg -Algorithm SHA256).Hash.ToLower()
if ($got -ne $sha256) {
    throw "stage-conpty: nupkg sha256 mismatch`n  expected $sha256`n  got      $got"
}
Write-Host "stage-conpty: sha256 verified ($sha256)"

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
try {
    foreach ($pair in @(@($dllEntry, 'conpty.dll'), @($exeEntry, 'OpenConsole.exe'))) {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq $pair[0] }
        if (-not $entry) { throw "stage-conpty: entry not found in nupkg: $($pair[0])" }
        $dest = Join-Path $TargetDir $pair[1]
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        Write-Host "stage-conpty: wrote $dest"
    }
} finally { $zip.Dispose() }
