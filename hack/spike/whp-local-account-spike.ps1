<#
  izba MVP-D gating spike -- does WHP survive a SEPARATE standard local account?

  Layered on the PR #37 restricted-token/Low-IL confinement, MVP-D proposes a
  dedicated per-sandbox Windows local account as the principal the VMM runs
  under. That is only viable if WHvCreatePartition still SUCCEEDS for such an
  account. This script answers that empirically using the existing
  `confine_probe` binary (WHvCreatePartition -> exit 0/13, verdict OK/DENIED).

  It creates a throwaway standard local account, runs the probe under it across
  a minimal-grant matrix, and TEARS THE ACCOUNT DOWN in a finally block.

  Matrix (baseline leg 0 = current user is run separately, before this script):
    leg1  bare standard local account (Users only)              -> whp
    leg3  account + restricted-token + Low-IL (full MVP-D stack) -> confined-whp
    leg2  account added to Hyper-V Administrators                -> whp
    leg2c same, full confined stack                              -> confined-whp

  REQUIRES ELEVATION (creating a local account needs Administrator). Safe to
  re-run: the account name is randomized and removed on exit.
#>
$ErrorActionPreference = 'Stop'

$stage = 'C:\Users\Public\izba-spike'
$exe   = Join-Path $stage 'confine_probe.exe'
$run   = Join-Path $stage 'run'
$transcript = Join-Path $run 'spike-transcript.txt'

if (-not (Test-Path $exe)) { throw "probe exe missing: $exe -- stage it first" }
New-Item -ItemType Directory -Force -Path $run | Out-Null

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "must run ELEVATED (Administrator) to create a local account"
}

Start-Transcript -Path $transcript -Force | Out-Null
Write-Output "izba MVP-D WHP gating spike -- host $env:COMPUTERNAME -- $(Get-Date -Format o)"

# Randomized account name + a complexity-meeting random password (no external
# assembly dependency so this works on Windows PowerShell 5.1 cleanly).
$acct = 'izba-spk-' + (Get-Random -Minimum 10000 -Maximum 99999)
$pwRaw = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 18 | ForEach-Object {[char]$_})
$pwRaw = $pwRaw + 'aZ9!'   # guarantee upper/lower/digit/symbol
$sec = ConvertTo-SecureString $pwRaw -AsPlainText -Force

$created = $false
$inHv    = $false
$fwName  = $null   # firewall rule DisplayName, set once added (for finally cleanup)
try {
  Write-Output "== creating standard local account $acct (Users only) =="
  New-LocalUser -Name $acct -Password $sec -FullName 'izba WHP spike' `
    -Description 'izba MVP-D WHP spike - safe to delete' `
    -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
  $created = $true
  Add-LocalGroupMember -Group 'Users' -Member $acct -ErrorAction SilentlyContinue

  $cred = New-Object System.Management.Automation.PSCredential ("$env:COMPUTERNAME\$acct", $sec)

  # Grant the account read+exec on the probe and FullControl (inherited) on the
  # run dir, so both the leg's own --result file AND the confined grandchild's
  # Low-IL temp dir (TEMP is pointed here) are writable by the account.
  & icacls $exe /grant "${acct}:(RX)"        | Out-Null
  & icacls $run /grant "${acct}:(OI)(CI)F"   | Out-Null

  function Run-Leg([string]$label,[string]$attempt,[string]$nonce,[string]$target) {
    $res = Join-Path $run "$label.txt"
    Remove-Item -Force $res -ErrorAction SilentlyContinue
    # cmd wrapper points TEMP/TMP at the account-writable run dir so the
    # confined grandchild (Low IL) can create + write its result dir there.
    $tgt = if ($target) { " --target $target" } else { "" }
    $inner = "set TEMP=$run&& set TMP=$run&& `"$exe`" child --attempt $attempt --result `"$res`" --nonce $nonce$tgt"
    $p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', $inner `
           -Credential $cred -WorkingDirectory $run -Wait -PassThru
    Start-Sleep -Milliseconds 250
    $raw = (Get-Content $res -ErrorAction SilentlyContinue) -join ''
    $verdict = if ($raw -match ':') { ($raw -split ':',2)[1] } else { '<NO-RESULT>' }
    Write-Output ("{0,-26} exit={1,-4} verdict={2}" -f $label, $p.ExitCode, $verdict)
    return $verdict
  }

  Write-Output "== LEG 1: bare standard local account (Users only) -- whp =="
  $leg1 = Run-Leg 'leg1-bare-whp' 'whp' 'spk10001'

  Write-Output "== LEG 3: account + restricted-token + Low-IL (full MVP-D stack) -- confined-whp =="
  $leg3 = Run-Leg 'leg3-confined-whp' 'confined-whp' 'spk30001'

  Write-Output "== LEG 2: add account to Hyper-V Administrators, re-run =="
  $leg2 = '<group-absent>'
  $leg2c = '<group-absent>'
  try {
    Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member $acct -ErrorAction Stop
    $inHv = $true
    # Group membership lands in the NEXT logon; Start-Process -Credential does a
    # fresh CreateProcessWithLogonW each call, so these tokens include it.
    $leg2  = Run-Leg 'leg2-hvadmin-whp'          'whp'          'spk20001'
    $leg2c = Run-Leg 'leg2c-hvadmin-confined-whp' 'confined-whp' 'spk20002'
  } catch {
    Write-Output "   (Hyper-V Administrators group unavailable: $($_.Exception.Message))"
  }

  # ---- Firewall legs: can a per-account WFP/Firewall rule kill ALL its net? ----
  # A WFP ALE outbound block scoped to the account SID makes connect() fail with
  # WSAEACCES (10013) -> probe reports BLOCKED. Target is a fixed public IP; we
  # rely on the WSAEACCES signature, NOT on reachability, so corporate/VPN
  # filtering can't produce a false BLOCKED (that shows as ALLOWED-ERR:<code>).
  $tgt = '8.8.8.8:443'
  Write-Output "== LEG F0: outbound TCP connect as account, NO firewall rule (control) =="
  $legF0 = Run-Leg 'legF0-net-norule' 'net-connect' 'spkF0001' $tgt

  $sid = (Get-LocalUser -Name $acct).SID.Value
  Write-Output "== adding per-SID outbound BLOCK rule (-LocalUser) for $sid =="
  $fwName = "izba-spike-deny-$acct"
  New-NetFirewallRule -DisplayName $fwName -Direction Outbound -Action Block `
    -Profile Any -LocalUser "D:(A;;CC;;;$sid)" -ErrorAction Stop | Out-Null
  Start-Sleep -Milliseconds 500
  Write-Output "== LEG F1: same connect, WITH per-SID outbound block =="
  $legF1 = Run-Leg 'legF1-net-blocked' 'net-connect' 'spkF1001' $tgt

  Write-Output ""
  Write-Output "==================== SUMMARY ===================="
  Write-Output ("leg1  bare standard local account   whp          : {0}" -f $leg1)
  Write-Output ("leg3  + restricted-token + Low-IL   confined-whp  : {0}" -f $leg3)
  Write-Output ("leg2  + Hyper-V Administrators       whp          : {0}" -f $leg2)
  Write-Output ("leg2c + Hyper-V Administrators       confined-whp  : {0}" -f $leg2c)
  Write-Output ("legF0 net connect, NO rule (control)             : {0}" -f $legF0)
  Write-Output ("legF1 net connect, per-SID outbound BLOCK         : {0}" -f $legF1)
  Write-Output "================================================="
  Write-Output "(whp: OK=WHvCreatePartition succeeded, DENIED=refused)"
  Write-Output "(net: ALLOWED=connected, BLOCKED=WFP denied [WSAEACCES], ALLOWED-ERR:n=not firewall-blocked)"
  if ($legF1 -eq 'BLOCKED' -and $legF0 -ne 'BLOCKED') {
    Write-Output "FIREWALL VERDICT: per-SID outbound block WORKS (control not blocked, rule blocked)."
  } elseif ($legF0 -eq 'BLOCKED') {
    Write-Output "FIREWALL VERDICT: INCONCLUSIVE -- control was BLOCKED too (WSAEACCES unreliable on this host)."
  } else {
    Write-Output "FIREWALL VERDICT: per-SID block did NOT take ($legF1) -- -LocalUser ALE filter may not apply; investigate -Owner / raw WFP."
  }
}
finally {
  if ($fwName)  { Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
  if ($inHv)    { Remove-LocalGroupMember -Group 'Hyper-V Administrators' -Member $acct -ErrorAction SilentlyContinue }
  if ($created) {
    Remove-LocalUser -Name $acct -ErrorAction SilentlyContinue
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
      Where-Object { $_.LocalPath -like "*\$acct" } |
      ForEach-Object { Remove-CimInstance $_ -ErrorAction SilentlyContinue }
    Write-Output "== torn down account $acct =="
  }
  Stop-Transcript | Out-Null
}
