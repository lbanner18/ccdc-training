<#
.SYNOPSIS
    Independently check that the Guardian task is still present and correctly wired.

.DESCRIPTION
    Guardian repairs the watchdog. This separate SYSTEM task checks the next
    link in that chain: that Guardian itself is still registered, running, and
    launched from its expected private payload. It writes only when that state
    changes, so integrity.log is an alert history rather than a line every
    minute.

    This is detection plus evidence, not tamper-proofing. An Administrator can
    delete or redirect all three tasks and their private files. Guardian repairs this
    checker's private copy and scheduled task while Guardian itself still runs.

.EXAMPLE
    .\windows\integrity.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
.EXAMPLE
    .\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Install -Apply
    Installs this checker as part of the Guardian chain.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [int]$IntervalSeconds = 60,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Apply,
    [switch]$Run,
    [string]$TaskName = '',
    [string]$GuardianTaskName = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']
$configPath = [string]$cfg['_ConfigPath']
$TaskName = if ([string]::IsNullOrWhiteSpace($TaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_TASK' -Default 'Continuity-Audit'
} else {
    Get-CcdcTaskName -Config @{ Override = $TaskName } -Name 'Override' -Default $TaskName
}
$GuardianTaskName = if ([string]::IsNullOrWhiteSpace($GuardianTaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_TASK' -Default 'Maintenance-Check'
} else {
    Get-CcdcTaskName -Config @{ Override = $GuardianTaskName } -Name 'Override' -Default $GuardianTaskName
}
$privateLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance'
$guardianLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_FILE' -Default 'health-check.ps1' -PowerShellFile
$privateDir = Get-CcdcPath $privateLeaf
$privateGuardian = Join-Path $privateDir $guardianLeaf
$scriptPath = (Resolve-Path -LiteralPath $MyInvocation.MyCommand.Path).Path
$stateFile = Get-CcdcPath 'state\guardian-integrity.last'
$logName = 'integrity.log'

function I { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Get-GuardianState {
    $task = Get-ScheduledTask -TaskName $GuardianTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return [pscustomobject]@{ Code = 'MISSING'; Detail = "guardian-task=$GuardianTaskName" } }
    $arguments = @($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' '
    if ($arguments -notlike ('*' + $privateGuardian + '*')) {
        return [pscustomobject]@{ Code = 'REDIRECTED'; Detail = "guardian-task=$GuardianTaskName expected=$privateGuardian" }
    }
    if ($task.State -ne 'Running') {
        return [pscustomobject]@{ Code = 'STOPPED'; Detail = "guardian-task=$GuardianTaskName state=$($task.State)" }
    }
    if (-not (Test-Path -LiteralPath $privateGuardian -PathType Leaf)) {
        return [pscustomobject]@{ Code = 'PAYLOAD-MISSING'; Detail = "guardian-payload=$privateGuardian" }
    }
    return [pscustomobject]@{ Code = 'OK'; Detail = "guardian-task=$GuardianTaskName private-payload=$privateGuardian" }
}

function Record-GuardianState {
    param([Parameter(Mandatory)]$State)
    $prior = ''
    try { if (Test-Path -LiteralPath $stateFile -PathType Leaf) { $prior = (Get-Content -LiteralPath $stateFile -Raw -ErrorAction Stop).Trim() } } catch { }
    $current = '{0}|{1}' -f $State.Code, $State.Detail
    if ($current -ne $prior) {
        try { Set-Content -LiteralPath $stateFile -Value $current -Encoding UTF8 -ErrorAction Stop } catch { }
        if ($State.Code -eq 'OK') { I "INTEGRITY-OK $($State.Detail)" }
        else { I "INTEGRITY-GAP code=$($State.Code) $($State.Detail)" }
    }
}

function Stop-AndUnregisterTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
    if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop; Start-Sleep -Milliseconds 250 }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}

function Register-IntegrityTask {
    param([Parameter(Mandatory)][string]$ConfigPath)
    $args = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Config "{1}" -Run -IntervalSeconds {2} -TaskName "{3}" -GuardianTaskName "{4}"' -f `
        $scriptPath, $ConfigPath, $IntervalSeconds, $TaskName, $GuardianTaskName
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    Stop-AndUnregisterTask
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'CCDC Guardian integrity check (Administrator can still remove it)' | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

if ($IntervalSeconds -lt 15) { Write-CcdcDie '-IntervalSeconds must be at least 15' }

if ($Install) {
    Assert-CcdcAdmin
    Assert-CcdcPacketEntered -Config $cfg
    if (-not $Apply) {
        Write-Host ('  would install SYSTEM task {0}; it checks Guardian task {1}' -f $TaskName, $GuardianTaskName)
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        exit 0
    }
    $expectedMe = Join-Path $privateDir (Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_FILE' -Default 'continuity-audit.ps1' -PowerShellFile)
    if ($scriptPath -ne $expectedMe) {
        Write-CcdcDie 'install this through guardian.ps1 so the SYSTEM task uses the hash-protected private copy'
    }
    try { Register-IntegrityTask -ConfigPath $configPath; I "installed integrity-task=$TaskName guardian-task=$GuardianTaskName" }
    catch { Write-CcdcDie "could not install integrity task: $($_.Exception.Message)" }
    exit 0
}

if ($Uninstall) {
    Assert-CcdcAdmin
    if (-not $Apply) { Write-Host ('  would stop and remove {0}' -f $TaskName); Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow; exit 0 }
    try { Stop-AndUnregisterTask; I "removed integrity-task=$TaskName" } catch { Write-CcdcDie "could not remove integrity task: $($_.Exception.Message)" }
    exit 0
}

if ($Status) {
    $s = Get-GuardianState
    Write-Host ('  {0}: {1}' -f $GuardianTaskName, $s.Code)
    Write-Host ('      {0}' -f $s.Detail)
    Write-Host '  LIMIT: an Administrator can remove or redirect this task and Guardian.' -ForegroundColor Yellow
    if ($s.Code -eq 'OK') { exit 0 }
    exit 2
}

if ($Run) {
    Assert-CcdcAdmin
    while ($true) { Record-GuardianState -State (Get-GuardianState); Start-Sleep -Seconds $IntervalSeconds }
}

Write-Host '  integrity.ps1 needs one of: -Install, -Status, -Uninstall'
exit 1
