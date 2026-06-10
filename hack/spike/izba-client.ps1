#!/usr/bin/env pwsh
# Spike host-side client for OpenVMM hybrid vsock (CONNECT/OK handshake,
# CH-compatible) + izba-proto u32-LE length-prefixed JSON frames.
# Requires PowerShell 7 (UnixDomainSocketEndPoint).
#
# Usage:
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode echo
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode health
#   izba-client.ps1 -SockPath C:\izba-spike\vsock -Port 1025 -Mode exec -Argv 'uname','-a'
param(
    [Parameter(Mandatory)] [string]$SockPath,
    [uint32]$Port = 1025,
    [ValidateSet('echo','health','exec')] [string]$Mode = 'health',
    [string[]]$Argv = @('true')
)
$ErrorActionPreference = 'Stop'

function Connect-Vsock([string]$Path, [uint32]$VPort) {
    $sock = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::Unix,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Unspecified)
    $sock.Connect([System.Net.Sockets.UnixDomainSocketEndPoint]::new($Path))
    $stream = [System.Net.Sockets.NetworkStream]::new($sock, $true)
    $req = [System.Text.Encoding]::ASCII.GetBytes("CONNECT $VPort`n")
    $stream.Write($req, 0, $req.Length)
    # Read the OK line byte-by-byte (buffering would eat stream data).
    $line = ''
    while ($true) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { throw 'EOF before OK line' }
        if ($b -eq 10) { break }
        $line += [char]$b
    }
    if ($line -notmatch '^OK ') { throw "expected OK, got: $line" }
    Write-Host "HANDSHAKE: $line"
    return $stream
}

function Write-Frame($Stream, $Obj) {
    $json = [System.Text.Encoding]::UTF8.GetBytes(($Obj | ConvertTo-Json -Compress -Depth 5))
    $len = [BitConverter]::GetBytes([uint32]$json.Length)  # little-endian on x64
    $Stream.Write($len, 0, 4); $Stream.Write($json, 0, $json.Length)
}

function Read-Frame($Stream) {
    $hdr = [byte[]]::new(4); $got = 0
    while ($got -lt 4) {
        $n = $Stream.Read($hdr, $got, 4 - $got)
        if ($n -le 0) { throw 'EOF in frame header' }
        $got += $n
    }
    $len = [BitConverter]::ToUInt32($hdr, 0)
    $body = [byte[]]::new($len); $got = 0
    while ($got -lt $len) {
        $n = $Stream.Read($body, $got, $len - $got)
        if ($n -le 0) { throw 'EOF in frame body' }
        $got += $n
    }
    return [System.Text.Encoding]::UTF8.GetString($body)
}

$stream = Connect-Vsock $SockPath $Port
switch ($Mode) {
    'echo' {
        $msg = [System.Text.Encoding]::ASCII.GetBytes("ping-roundtrip`n")
        $stream.Write($msg, 0, $msg.Length)
        $buf = [byte[]]::new($msg.Length); $got = 0
        while ($got -lt $buf.Length) {
            $n = $stream.Read($buf, $got, $buf.Length - $got)
            if ($n -le 0) { throw 'EOF during echo' }
            $got += $n
        }
        $back = [System.Text.Encoding]::ASCII.GetString($buf)
        if ($back -eq "ping-roundtrip`n") { Write-Host 'SPIKE-RUNG4-ECHO-OK' }
        else { Write-Host "SPIKE-RUNG4-ECHO-MISMATCH: $back" }
    }
    'health' {
        Write-Frame $stream @{ type = 'health' }
        Write-Host "RESPONSE: $(Read-Frame $stream)"
    }
    'exec' {
        Write-Frame $stream @{
            type = 'exec'; argv = $Argv; env = @()
            cwd = '/workspace'; tty = $false; uid = 0; gid = 0
        }
        $started = Read-Frame $stream
        Write-Host "EXEC-STARTED: $started"
        $execId = ($started | ConvertFrom-Json).exec_id
        Write-Frame $stream @{ type = 'wait'; exec_id = $execId }
        Write-Host "WAIT: $(Read-Frame $stream)"
    }
}
$stream.Dispose()
