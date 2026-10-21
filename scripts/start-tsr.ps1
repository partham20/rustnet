<#
.SYNOPSIS
    Start tsr (the Rust Tailscale client), in a window or in the background.

.DESCRIPTION
    Without a switch, runs tsr in this window until you press Ctrl+C.
    It pauses the official Tailscale service while tsr runs, because that
    service would otherwise route all 100.x traffic to its own adapter, and
    starts it again when tsr exits. Keys stay in tsr.state.json next to
    tsr.exe, so after the first run no auth key is needed.

    -Install sets tsr up to run in the background: no window, starts when
    Windows boots (before anyone signs in), and restarts if it stops. It
    copies tsr.exe and this script to C:\Program Files\tsr, keeps keys and
    the log in C:\ProgramData\tsr (readable only by Administrators), and
    turns off the official Tailscale service. Run -Install again to update
    tsr.exe. -Uninstall undoes all of it, apart from the keys and log.

    Every mode asks for Administrator rights if it doesn't have them.
    tsr.exe is looked for next to this script, then in your Downloads folder.

.EXAMPLE
    Right-click start-tsr.ps1 and choose "Run with PowerShell".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start-tsr.ps1 -Install

.EXAMPLE
    .\start-tsr.ps1 -Status      # is it running? shows the last log lines

.EXAMPLE
    .\start-tsr.ps1 -AuthKey tskey-auth-...    # first run on a new machine only
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    # Folder that holds tsr.exe (and, when running in a window, tsr.state.json).
    [string]$TsrDir = '',
    [string]$LoginServer = 'https://controlplane.tailscale.com',
    [string]$AuthKey = '',

    # Run in the background at every boot.
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    # Stop running in the background and remove the startup task.
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall,
    # Show whether the background tsr is running, and its latest log lines.
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    # Used by the startup task: keep tsr running, logging to a file.
    [Parameter(ParameterSetName = 'Background')][switch]$Background,

    # Set when this script re-launched itself as Administrator.
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'

$TaskName = 'tsr'
$InstallDir = Join-Path $env:ProgramFiles 'tsr'
$DataDir = Join-Path $env:ProgramData 'tsr'
$StateFile = Join-Path $DataDir 'tsr.state.json'
$LogFile = Join-Path $DataDir 'tsr.log'
# Remembers how the official Tailscale service started, so -Uninstall can restore it.
$ServiceMarker = Join-Path $DataDir 'tailscale-service-startup.txt'

if (-not $TsrDir) {
    $TsrDir = if (Test-Path (Join-Path $PSScriptRoot 'tsr.exe')) { $PSScriptRoot }
              else { Join-Path $env:USERPROFILE 'Downloads' }
}

function Wait-BeforeClosing {
    # A window opened by the elevation prompt would otherwise vanish before
    # its output can be read.
    if ($Elevated) { Read-Host "`nPress Enter to close" | Out-Null }
}

function Stop-Tsr {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName
    }
    # Stopping the task doesn't always stop the tsr.exe it started.
    $procs = Get-Process -Name 'tsr' -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force
        # Wait until tsr.exe and wintun.dll can be replaced or deleted.
        $procs | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }
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
        '-LoginServer', $LoginServer,
        '-Elevated'
    )
    if ($AuthKey) { $argList += @('-AuthKey', $AuthKey) }
    if ($PSCmdlet.ParameterSetName -ne 'Run') { $argList += "-$($PSCmdlet.ParameterSetName)" }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

switch ($PSCmdlet.ParameterSetName) {

'Background' {
    $exe = Join-Path $PSScriptRoot 'tsr.exe'
    while (Test-Path $exe) {
        # tsr reconnects by itself once it is up. It exits when it can't get
        # that far (no network yet at boot, a bad login), so try again.
        & $exe up --login-server $LoginServer --state $StateFile --log-file $LogFile
        Start-Sleep -Seconds 10
    }
    exit 1
}

'Install' {
    $exe = Join-Path $TsrDir 'tsr.exe'
    if (-not (Test-Path $exe)) {
        Write-Host "tsr.exe not found in $TsrDir" -ForegroundColor Red
        Write-Host 'Download it from https://github.com/partham20/rustnet/releases/latest'
        Wait-BeforeClosing
        exit 1
    }

    Write-Host "Copying tsr to $InstallDir..."
    Stop-Tsr
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $here = (Resolve-Path $TsrDir).Path.TrimEnd('\')
    if ($here -ne $InstallDir.TrimEnd('\')) {
        Copy-Item -Force $exe (Join-Path $InstallDir 'tsr.exe')
    }
    if ($PSCommandPath -ne (Join-Path $InstallDir 'start-tsr.ps1')) {
        Copy-Item -Force $PSCommandPath (Join-Path $InstallDir 'start-tsr.ps1')
    }
    # Drop the "downloaded from the internet" mark the copies inherited.
    Get-ChildItem $InstallDir | Unblock-File

    # Keys and log: SYSTEM and Administrators only, nothing inherited.
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to restrict $DataDir" }

    $oldState = Join-Path $TsrDir 'tsr.state.json'
    if (-not (Test-Path $StateFile) -and (Test-Path $oldState)) {
        Write-Host "Reusing the keys in $oldState, so this PC keeps its name and address."
        Copy-Item $oldState $StateFile
    }
    if (-not (Test-Path $StateFile)) {
        Write-Host 'Logging in to the tailnet...'
        $loginArgs = @('login', '--login-server', $LoginServer, '--state', $StateFile)
        if ($AuthKey) { $loginArgs += @('--auth-key', $AuthKey) }
        & (Join-Path $InstallDir 'tsr.exe') @loginArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'Login failed, so nothing was set to start. Fix the error above and run -Install again.' -ForegroundColor Red
            Remove-Item -Force $StateFile -ErrorAction SilentlyContinue
            Wait-BeforeClosing
            exit 1
        }
    }

    $service = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host 'Turning off the official Tailscale service (-Uninstall turns it back on)...'
        if (-not (Test-Path $ServiceMarker)) {
            $service.StartType.ToString() | Set-Content $ServiceMarker
        }
        Stop-Service -Name 'Tailscale'
        Set-Service -Name 'Tailscale' -StartupType Disabled
    }

    # A SYSTEM process gets no firewall prompt, so allow WireGuard in up front.
    Remove-NetFirewallRule -DisplayName 'tsr' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'tsr' -Direction Inbound -Action Allow -Protocol UDP `
        -Program (Join-Path $InstallDir 'tsr.exe') -Profile Any | Out-Null

    $taskScript = Join-Path $InstallDir 'start-tsr.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $InstallDir `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$taskScript`" -Background -LoginServer `"$LoginServer`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # No time limit, run on battery, and restart the task itself if it dies.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force `
        -Description 'tsr: Tailscale client in Rust (https://github.com/partham20/rustnet)' | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "`nInstalled. tsr is starting in the background and will start with Windows from now on." -ForegroundColor Green
    Write-Host "Log: $LogFile"
    Write-Host 'Check on it with:  start-tsr.ps1 -Status'
    Write-Host 'Remove it with:    start-tsr.ps1 -Uninstall'
    Wait-BeforeClosing
}

'Uninstall' {
    Write-Host 'Stopping tsr and removing the startup task...'
    Stop-Tsr
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Remove-NetFirewallRule -DisplayName 'tsr' -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }

    if ((Test-Path $ServiceMarker) -and (Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue)) {
        $startType = (Get-Content $ServiceMarker -Raw).Trim()
        Write-Host "Turning the official Tailscale service back on ($startType)..."
        Set-Service -Name 'Tailscale' -StartupType $startType
        if ($startType -eq 'Automatic') { Start-Service -Name 'Tailscale' }
    }
    Remove-Item -Force $ServiceMarker -ErrorAction SilentlyContinue

    Write-Host "`nUninstalled." -ForegroundColor Green
    Write-Host "Keys and log are still in $DataDir. Delete that folder to forget this PC's tailnet identity."
    Wait-BeforeClosing
}

'Status' {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host 'tsr is not installed to run in the background. Run start-tsr.ps1 -Install.'
        Wait-BeforeClosing
        return
    }
    $info = $task | Get-ScheduledTaskInfo
    Write-Host "Startup task: $($task.State), last started $($info.LastRunTime)"
    $proc = Get-Process -Name 'tsr' -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "tsr.exe: running (PID $($proc.Id -join ', '))" -ForegroundColor Green
    } else {
        Write-Host 'tsr.exe: not running right now (the task retries every 10 seconds)' -ForegroundColor Yellow
    }
    if (Test-Path $LogFile) {
        Write-Host "`nLast lines of $LogFile`:"
        Get-Content $LogFile -Tail 20
    }
    Wait-BeforeClosing
}

'Run' {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') {
        Write-Host 'tsr is already running in the background. Use -Status to check on it, or -Uninstall to stop it for good.'
        Wait-BeforeClosing
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
}

}
