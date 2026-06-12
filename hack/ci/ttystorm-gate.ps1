# M0 churn gate (Windows/OpenVMM): izbad-path vsock churn must not kill the VM.
# Env: IZBA_EXE, TTYSTORM_EXE (required); IZBA_IMAGE (default alpine:3.20).
# Boot artifacts come from IZBA_KERNEL/IZBA_INITRAMFS or the default data dir.
$ErrorActionPreference = 'Stop'

$exe   = if ($env:IZBA_EXE)      { $env:IZBA_EXE }      else { 'izba' }
$storm = if ($env:TTYSTORM_EXE)  { $env:TTYSTORM_EXE }  else { 'ttystorm' }
$image = if ($env:IZBA_IMAGE)    { $env:IZBA_IMAGE }    else { 'alpine:3.20' }
$name  = 'stormgate'
$ws    = Join-Path ([System.IO.Path]::GetTempPath()) "stormgate-ws-$PID"

function Cleanup {
    # Guarded: a bad $exe path must not throw here and mask the original
    # failure (Cleanup runs from `finally` under EAP=Stop).
    try { & $exe rm --force $name 2>$null | Out-Null } catch {}
    if (Test-Path $ws) { Remove-Item -Recurse -Force $ws -ErrorAction SilentlyContinue }
}

try {
    New-Item -ItemType Directory -Path $ws -Force | Out-Null

    Write-Host "=== ttystorm gate: boot sandbox '$name' ==="
    & $exe run --image $image --name $name $ws -- /bin/true
    if ($LASTEXITCODE -ne 0) { throw "izba run failed ($LASTEXITCODE)" }

    Write-Host "=== ttystorm gate: floodfast 20 2048 ==="
    & $storm $name floodfast 20 2048
    if ($LASTEXITCODE -ne 0) { throw "floodfast failed ($LASTEXITCODE)" }

    Write-Host "=== ttystorm gate: chop 30 256 ==="
    & $storm $name chop 30 256
    if ($LASTEXITCODE -ne 0) { throw "chop failed ($LASTEXITCODE)" }

    Write-Host "=== ttystorm gate: VM survived? ==="
    $out = (& $exe exec $name -- echo alive | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $out -ne 'alive') {
        throw "exec after churn returned '$out' exit=$LASTEXITCODE (VM dead or wedged)"
    }
    Write-Host "PASS: VM alive after izbad-path churn"
}
finally {
    Cleanup
}
