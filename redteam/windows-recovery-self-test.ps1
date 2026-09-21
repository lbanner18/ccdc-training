<#
.SYNOPSIS
    Prove the Windows Guardian recovery chain on a disposable lab VM.

.DESCRIPTION
    This is a lab drill, not a hardening tool. It deletes one private watchdog
    payload and one watchdog task, removes Guardian's task, then corrupts the
    repair authority. Each result is checked from the actual task/file/log
    state. It finishes by reinstalling Guardian so the three-task chain is
    healthy again.

    It requires both CCDC_WIN_LAB=1 and -IAcceptThisBoxIsDisposable because it
    deliberately interrupts the monitoring chain. Take a snapshot first.

.EXAMPLE
    $env:CCDC_WIN_LAB = 1
    .\redteam\windows-recovery-self-test.ps1 -Config C:\ProgramData\CCDC\ccdc.env -IAcceptThisBoxIsDisposable
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [switch]$IAcceptThisBoxIsDisposable,
    [int]$TimeoutSeconds = 150
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

function Die { param([string]$Message) Write-Host ''; Write-Host "  REFUSING: $Message" -ForegroundColor Red; Write-Host ''; exit 1 }
if ($env:CCDC_WIN_LAB -ne '1') {
    Die 'this removes monitoring files and tasks. Set CCDC_WIN_LAB=1 only on a disposable snapshot.'
}
if (-not $IAcceptThisBoxIsDisposable) {
    Die 'CCDC_WIN_LAB is one confirmation. Add -IAcceptThisBoxIsDisposable as the second.'
}
if ($TimeoutSeconds -lt 30) { Die '-TimeoutSeconds must be at least 30.' }

$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Die 'needs to run elevated.' }

$windowsRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\windows')).Path
. (Join-Path $windowsRoot 'lib\Common.ps1')
$configPath = (Resolve-Path -LiteralPath $Config).Path
$cfg = Import-CcdcConfig -Path $configPath
Assert-CcdcPacketEntered -Config $cfg

$guardianTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_TASK' -Default 'Maintenance-Check'
$watchdogTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_TASK' -Default 'Operations-Monitor'
$integrityTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_TASK' -Default 'Continuity-Audit'
$privateDir = Get-CcdcPath (Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance')
$watchdogFile = Join-Path $privateDir (Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_FILE' -Default 'service-monitor.ps1' -PowerShellFile)
$repairWatchdog = Join-Path (Join-Path $privateDir '.repair') (Split-Path -Leaf $watchdogFile)
$guardian = Join-Path $windowsRoot 'guardian.ps1'
$integrity = Join-Path $windowsRoot 'integrity.ps1'
$guardianLog = Get-CcdcPath 'guardian.log'
$integrityLog = Get-CcdcPath 'integrity.log'
$pass = 0; $fail = 0

function Pass { param([string]$Message) $script:pass++; Write-Host ("  PASS  {0}" -f $Message) -ForegroundColor Green }
function Fail { param([string]$Message) $script:fail++; Write-Host ("  FAIL  {0}" -f $Message) -ForegroundColor Red }
function LogText { param([string]$Path) if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue) }; return '' }
function NewLogHas {
    param([string]$Before, [string]$Path, [string]$Pattern)
    $after = LogText $Path
    if ($after.Length -le $Before.Length) { return $false }
    return $after.Substring($Before.Length) -match $Pattern
}
function Wait-For {
    param([scriptblock]$Test, [string]$What)
    $until = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $until) {
        try { if (& $Test) { return $true } } catch { }
        Start-Sleep -Seconds 3
    }
    Write-Host ("    timed out waiting for {0}" -f $What) -ForegroundColor Yellow
    return $false
}
function WatchdogTaskCorrect {
    $task = Get-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    $args = @($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' '
    return $task.State -eq 'Running' -and $args -like ('*' + $watchdogFile + '*')
}
function Install-HealthyChain {
    & $guardian -Config $configPath -Install -Apply 2>&1 | Out-Null
    return (WatchdogTaskCorrect) -and ($null -ne (Get-ScheduledTask -TaskName $guardianTask -ErrorAction SilentlyContinue)) -and ($null -ne (Get-ScheduledTask -TaskName $integrityTask -ErrorAction SilentlyContinue))
}

Write-Host ''
Write-Host '  Windows Guardian recovery drill: this deliberately interrupts monitoring.' -ForegroundColor Yellow
Write-Host ''

if (Install-HealthyChain) { Pass 'started with Guardian, watchdog, and integrity tasks installed' }
else { Fail 'could not install a healthy starting chain'; exit 1 }

$expectedHash = (Get-FileHash -LiteralPath $repairWatchdog -Algorithm SHA256).Hash
$before = LogText $guardianLog
Remove-Item -LiteralPath $watchdogFile -Force -ErrorAction Stop
if ((Wait-For { (Test-Path -LiteralPath $watchdogFile -PathType Leaf) -and ((Get-FileHash -LiteralPath $watchdogFile -Algorithm SHA256).Hash -eq $expectedHash) } 'the deleted watchdog payload to return') -and
    (NewLogHas -Before $before -Path $guardianLog -Pattern 'INTEGRITY-REPAIRED payload=')) { Pass 'deleted watchdog payload was restored from verified repair authority' }
else { Fail 'deleted watchdog payload was not proven restored' }

$before = LogText $guardianLog
$task = Get-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName $watchdogTask -Confirm:$false -ErrorAction SilentlyContinue
if ((Wait-For { WatchdogTaskCorrect } 'the deleted watchdog task to return') -and
    (NewLogHas -Before $before -Path $guardianLog -Pattern ('REPAIR watchdog-task=' + [regex]::Escape($watchdogTask)))) { Pass 'deleted watchdog task was recreated with its private action' }
else { Fail 'deleted watchdog task was not proven recreated' }

$before = LogText $integrityLog
$task = Get-ScheduledTask -TaskName $guardianTask -ErrorAction SilentlyContinue
if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $guardianTask -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName $guardianTask -Confirm:$false -ErrorAction SilentlyContinue
$missing = Wait-For {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $integrity -Config $configPath -Status 2>&1 | Out-Null
    return $LASTEXITCODE -eq 2
} 'Continuity-Audit to detect missing Guardian'
if ($missing -and (Wait-For { NewLogHas -Before $before -Path $integrityLog -Pattern 'INTEGRITY-GAP code=MISSING' } 'the missing-Guardian integrity log')) { Pass 'missing Guardian was reported as an integrity gap, not silently repaired' }
else { Fail 'missing Guardian was not proven reported' }

if (Install-HealthyChain) { Pass 'reinstalled the healthy chain before the repair-authority test' }
else { Fail 'could not reinstall the healthy chain'; exit 1 }
$before = LogText $guardianLog
Add-Content -LiteralPath $repairWatchdog -Value '# CCDC recovery drill: altered repair authority' -Encoding UTF8
Remove-Item -LiteralPath $watchdogFile -Force -ErrorAction Stop
$gap = Wait-For { NewLogHas -Before $before -Path $guardianLog -Pattern 'INTEGRITY-GAP altered repair authority=' } 'Guardian to reject altered repair authority'
if ($gap -and -not (Test-Path -LiteralPath $watchdogFile -PathType Leaf)) { Pass 'altered repair authority was rejected and was not copied back' }
else { Fail 'altered repair authority was not proven rejected' }

if (Install-HealthyChain) { Pass 'finished with Guardian, watchdog, and integrity tasks healthy' }
else { Fail 'final reinstall did not restore the healthy chain' }

Write-Host ''
Write-Host ("windows recovery drill: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
