<#
.SYNOPSIS
    Start tsr (the Rust Tailscale client).

.DESCRIPTION
    Re-launches itself as Administrator when needed. While tsr runs, it pauses
    the official Tailscale service, which would otherwise route all 100.x
    traffic to its own adapter. It starts the service again when tsr exits.
    It looks for tsr.exe next to this script, then in your Downloads folder.
    Keys stay in tsr.state.json next to tsr.exe, so after the first run
    no auth key is needed.

.EXAMPLE
    Right-click start-tsr.ps1 and choose "Run with PowerShell".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start-tsr.ps1

.EXAMPLE
    .\start-tsr.ps1 -AuthKey tskey-auth-...    # first run on a new machine only
#>
param(
    # Folder that holds tsr.exe (and tsr.state.json).
    [string]$TsrDir = '',
    [string]$LoginServer = 'https://controlplane.tailscale.com',
    [string]$AuthKey = ''
)

$ErrorActionPreference = 'Stop'

if (-not $TsrDir) {
    $TsrDir = if (Test-Path (Join-Path $PSScriptRoot 'tsr.exe')) { $PSScriptRoot }
              else { Join-Path $env:USERPROFILE 'Downloads' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Pass the folder explicitly: an elevated session may see a different profile.
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-TsrDir', "`"$TsrDir`"",
        '-LoginServer', $LoginServer
    )
    if ($AuthKey) { $argList += @('-AuthKey', $AuthKey) }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

$exe = Join-Path $TsrDir 'tsr.exe'
if (-not (Test-Path $exe)) {
    Write-Host "tsr.exe not found in $TsrDir" -ForegroundColor Red
    Write-Host 'Download it from https://github.com/partham20/rustnet/releases/latest'
    Read-Host 'Press Enter to close'
    exit 1
}

$service = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
$restartService = $service -and $service.Status -eq 'Running'
if ($restartService) {
    Write-Host 'Pausing the official Tailscale service while tsr runs...'
    Stop-Service -Name 'Tailscale'
}

$tsrArgs = @('up', '--login-server', $LoginServer, '--state', (Join-Path $TsrDir 'tsr.state.json'))
if ($AuthKey) { $tsrArgs += @('--auth-key', $AuthKey) }

$Host.UI.RawUI.WindowTitle = 'tsr (Tailscale in Rust)'
Set-Location $TsrDir
Write-Host "Starting tsr. Press Ctrl+C to stop.`n"
try {
    & $exe @tsrArgs
}
finally {
    if ($restartService) {
        Write-Host 'Starting the official Tailscale service again...'
        Start-Service -Name 'Tailscale'
    }
}
Read-Host "`ntsr has stopped. Press Enter to close"
