# Windows leg of the mkfs.erofs parity gate.  Copy dist/erofs-parity-bundle/
# from the WSL side, then:   pwsh -File verify-mkfs-erofs-parity.ps1 <bundle-dir>
# Exit 0 = byte parity proven on real Windows; exit 1 = divergence/error.
param([Parameter(Mandatory = $true)][string]$BundleDir)
$ErrorActionPreference = 'Stop'

$exe   = Join-Path $BundleDir 'mkfs.erofs.exe'
$tar   = Join-Path $BundleDir 'fixture.tar'
$want  = (Get-Content (Join-Path $BundleDir 'reference.sha256')).Trim()
$flags = Get-Content (Join-Path $BundleDir 'mkfs-flags.txt')
$out   = Join-Path ([System.IO.Path]::GetTempPath()) 'izba-win.erofs'
Remove-Item -Force -ErrorAction SilentlyContinue $out

& $exe @flags $out $tar
if ($LASTEXITCODE -ne 0) { Write-Error "mkfs.erofs.exe failed: $LASTEXITCODE"; exit 1 }

$got = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLower()
Remove-Item -Force $out
if ($got -eq $want) {
    Write-Host "PASS: byte-identical to the Linux reference ($got)"
    exit 0
}
Write-Error "FAIL: sha256 $got != reference $want"
exit 1
