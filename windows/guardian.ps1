<#
.SYNOPSIS
    Keep the Windows watchdog task present and running.

.DESCRIPTION
    This installs a second SYSTEM task with private copies of the guardian,
    watchdog, and common payloads under the configured CCDC private directory.
    Every pass it verifies that the configured monitor task still points at its
    private watchdog payload and is running; if not, it registers and starts it.

    This is redundancy, not tamper-proofing. An Administrator can stop/delete
    all three tasks, edit their private copies, or take ownership of their ACLs.
    The value is catching an ordinary watchdog kill while you are handling an
    inject, and leaving an evidence log when it repairs one.

.EXAMPLE
    .\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Install -Apply
.EXAMPLE
    .\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
.EXAMPLE
    .\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Uninstall -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [int]$IntervalSeconds = 60,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Apply,
    [switch]$Run,
    [string]$TaskName = '',
    [string]$WatchdogTaskName = '',
    [string]$IntegrityTaskName = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$TaskName = if ([string]::IsNullOrWhiteSpace($TaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_TASK' -Default 'Maintenance-Check'
} else {
    Get-CcdcTaskName -Config @{ Override = $TaskName } -Name 'Override' -Default $TaskName
}
$WatchdogTaskName = if ([string]::IsNullOrWhiteSpace($WatchdogTaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_TASK' -Default 'Operations-Monitor'
} else {
    Get-CcdcTaskName -Config @{ Override = $WatchdogTaskName } -Name 'Override' -Default $WatchdogTaskName
}
$IntegrityTaskName = if ([string]::IsNullOrWhiteSpace($IntegrityTaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_TASK' -Default 'Continuity-Audit'
} else {
    Get-CcdcTaskName -Config @{ Override = $IntegrityTaskName } -Name 'Override' -Default $IntegrityTaskName
}
$privateLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance'
$guardianLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_FILE' -Default 'health-check.ps1' -PowerShellFile
$watchdogLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_FILE' -Default 'service-monitor.ps1' -PowerShellFile
$canaryLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_CANARY_FILE' -Default 'integrity-check.ps1' -PowerShellFile
$integrityLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_FILE' -Default 'continuity-audit.ps1' -PowerShellFile
$privatePayloads = @($guardianLeaf, $watchdogLeaf, $canaryLeaf, $integrityLeaf)
if (@($privatePayloads | Select-Object -Unique).Count -ne 4) {
    Write-CcdcDie 'CCDC_WINDOWS_GUARDIAN_FILE, CCDC_WINDOWS_WATCHDOG_FILE, CCDC_WINDOWS_CANARY_FILE, and CCDC_WINDOWS_INTEGRITY_FILE must be different filenames'
}
$privateDir = Get-CcdcPath $privateLeaf
$manifest = Join-Path $privateDir 'SHA256SUMS.csv'
$repairDir = Join-Path $privateDir '.repair'
$repairManifest = Join-Path $repairDir 'SHA256SUMS.csv'
$logName = 'guardian.log'

function G { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Assert-GuardianArguments {
    if ($IntervalSeconds -lt 15) { Write-CcdcDie '-IntervalSeconds must be at least 15' }
    foreach ($name in @($TaskName, $WatchdogTaskName, $IntegrityTaskName)) {
        if ($name -notmatch '^[A-Za-z0-9_-]+$') {
            Write-CcdcDie "task names must contain only letters, digits, underscore or hyphen: $name"
        }
    }
}

function Stop-AndUnregisterTask {
    param([Parameter(Mandatory)][string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
    if ($task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $Name -ErrorAction Stop
        Start-Sleep -Milliseconds 250
    }
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop
}

function Get-PrivateCopyMap {
    return @(
        [pscustomobject]@{ Source = 'guardian.ps1'; Destination = $guardianLeaf },
        [pscustomobject]@{ Source = 'watchdog.ps1'; Destination = $watchdogLeaf },
        [pscustomobject]@{ Source = 'canary.ps1'; Destination = $canaryLeaf },
        [pscustomobject]@{ Source = 'integrity.ps1'; Destination = $integrityLeaf },
        [pscustomobject]@{ Source = 'lib\Common.ps1'; Destination = 'lib\Common.ps1' }
    )
}

function Assert-NoLegacyTaskPair {
    # Versions before configurable task names installed this exact pair. Do not
    # let a new neutral-name install leave their always-running loops behind;
    # an operator must remove the known legacy pair deliberately first.
    if ($TaskName -eq 'CCDC-Guardian' -or $WatchdogTaskName -eq 'CCDC-Watchdog') { return }
    $oldGuardian = Get-ScheduledTask -TaskName 'CCDC-Guardian' -ErrorAction SilentlyContinue
    $oldWatchdog = Get-ScheduledTask -TaskName 'CCDC-Watchdog' -ErrorAction SilentlyContinue
    if ($oldGuardian -or $oldWatchdog) {
        Write-CcdcDie @"
legacy CCDC-named scheduled task(s) are still installed.

  Remove the old pair before installing differently named replacements:
      .\windows\guardian.ps1 -Config $Config -Uninstall -Apply -TaskName CCDC-Guardian -WatchdogTaskName CCDC-Watchdog

  Then run this install again. This prevents two independent SYSTEM loops from
  restarting the same scored service or repairing each other's task.
"@
    }
}

function Write-PrivateCopies {
    param([Parameter(Mandatory)][string]$SourceRoot)
    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
        throw "source directory is missing: $SourceRoot"
    }
    New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
    New-Item -ItemType Directory -Path $repairDir -Force | Out-Null
    foreach ($copy in (Get-PrivateCopyMap)) {
        $source = Join-Path $SourceRoot $copy.Source
        $repair = Join-Path $repairDir $copy.Destination
        $dest = Join-Path $privateDir $copy.Destination
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "cannot install guardian: missing $source"
        }
        foreach ($parent in @((Split-Path -Parent $repair), (Split-Path -Parent $dest))) {
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        }
        Copy-Item -LiteralPath $source -Destination $repair -Force -ErrorAction Stop
        Copy-Item -LiteralPath $repair -Destination $dest -Force -ErrorAction Stop
    }
    Get-ChildItem -LiteralPath $repairDir -Recurse -File |
        Where-Object { $_.FullName -ne $repairManifest } | Get-FileHash -Algorithm SHA256 |
        Select-Object Hash, @{n='File';e={ $_.Path.Substring($repairDir.Length).TrimStart('\') }} |
        Export-Csv -LiteralPath $repairManifest -NoTypeInformation -Encoding UTF8
    Get-ChildItem -LiteralPath $privateDir -Recurse -File |
        Where-Object { $_.FullName -ne $manifest -and $_.FullName -notlike ($repairDir + '\*') } | Get-FileHash -Algorithm SHA256 |
        Select-Object Hash, @{n='File';e={ $_.Path.Substring($privateDir.Length).TrimStart('\') }} |
        Export-Csv -LiteralPath $manifest -NoTypeInformation -Encoding UTF8
}

function Repair-PrivateCopies {
    # The repair tree is written only by explicit -Install. A pass validates it
    # against its frozen manifest before trusting it; otherwise an attacker who
    # changed both a live script and its backup would be silently promoted.
    if (-not (Test-Path -LiteralPath $repairManifest -PathType Leaf)) {
        G "INTEGRITY-GAP missing repair manifest=$repairManifest"
        return $false
    }
    $expected = @{}
    try {
        foreach ($row in @(Import-Csv -LiteralPath $repairManifest -ErrorAction Stop)) {
            $expected[[string]$row.File] = [string]$row.Hash
        }
    } catch {
        G "INTEGRITY-GAP unreadable repair manifest err=$($_.Exception.Message)"
        return $false
    }
    foreach ($copy in (Get-PrivateCopyMap)) {
        $repair = Join-Path $repairDir $copy.Destination
        $live = Join-Path $privateDir $copy.Destination
        if (-not $expected.ContainsKey($copy.Destination) -or -not (Test-Path -LiteralPath $repair -PathType Leaf)) {
            G "INTEGRITY-GAP missing repair authority=$repair"
            return $false
        }
        $actual = ''
        try { $actual = (Get-FileHash -LiteralPath $repair -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        if ($actual -ne $expected[$copy.Destination]) {
            G "INTEGRITY-GAP altered repair authority=$repair"
            return $false
        }
        $liveHash = ''
        try { if (Test-Path -LiteralPath $live -PathType Leaf) { $liveHash = (Get-FileHash -LiteralPath $live -Algorithm SHA256 -ErrorAction Stop).Hash } } catch { }
        if ($liveHash -ne $actual) {
            try {
                $stage = "$live.repair.$PID"
                Copy-Item -LiteralPath $repair -Destination $stage -Force -ErrorAction Stop
                Move-Item -LiteralPath $stage -Destination $live -Force -ErrorAction Stop
                G "INTEGRITY-REPAIRED payload=$live"
            } catch {
                G "INTEGRITY-REPAIR-FAILED payload=$live err=$($_.Exception.Message)"
                return $false
            }
        }
    }
    return $true
}

function Register-GuardianTask {
    param([Parameter(Mandatory)][string]$ConfigPath)
    $privateGuardian = Join-Path $privateDir $guardianLeaf
    $args = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Config "{1}" -Run -IntervalSeconds {2} -TaskName "{3}" -WatchdogTaskName "{4}" -IntegrityTaskName "{5}"' -f `
        $privateGuardian, $ConfigPath, $IntervalSeconds, $TaskName, $WatchdogTaskName, $IntegrityTaskName
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    Stop-AndUnregisterTask -Name $TaskName
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'CCDC watchdog task guardian (Administrator can still remove it)' | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

function Test-WatchdogTaskCorrect {
    $task = Get-ScheduledTask -TaskName $WatchdogTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    $privateWatchdog = Join-Path $privateDir $watchdogLeaf
    $arguments = @($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' '
    return ($arguments -like ('*' + $privateWatchdog + '*'))
}

function Ensure-Watchdog {
    param([Parameter(Mandatory)][string]$ConfigPath)
    if (-not (Repair-PrivateCopies)) { return }
    $privateWatchdog = Join-Path $privateDir $watchdogLeaf
    if (-not (Test-Path -LiteralPath $privateWatchdog -PathType Leaf)) {
        G "CANNOT-REPAIR missing private watchdog=$privateWatchdog"
        return
    }
    if (-not (Test-WatchdogTaskCorrect)) {
        G "REPAIR watchdog-task=$WatchdogTaskName reason=missing-or-altered"
        & $privateWatchdog -Config $ConfigPath -IntervalSeconds 30 -Install -TaskName $WatchdogTaskName 2>&1 | Out-Null
        if (-not (Test-WatchdogTaskCorrect)) { G "REPAIR-FAILED watchdog-task=$WatchdogTaskName" }
        return
    }
    $task = Get-ScheduledTask -TaskName $WatchdogTaskName -ErrorAction SilentlyContinue
    if ($task.State -ne 'Running') {
        try {
            Start-ScheduledTask -TaskName $WatchdogTaskName -ErrorAction Stop
            G "RESTARTED watchdog-task=$WatchdogTaskName prior-state=$($task.State)"
        } catch { G "RESTART-FAILED watchdog-task=$WatchdogTaskName err=$($_.Exception.Message)" }
    }
}

function Ensure-IntegrityTask {
    param([Parameter(Mandatory)][string]$ConfigPath)
    $privateIntegrity = Join-Path $privateDir $integrityLeaf
    if (-not (Test-Path -LiteralPath $privateIntegrity -PathType Leaf)) {
        G "CANNOT-REPAIR missing private integrity checker=$privateIntegrity"
        return
    }
    $task = Get-ScheduledTask -TaskName $IntegrityTaskName -ErrorAction SilentlyContinue
    $arguments = if ($task) { @($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' ' } else { '' }
    if ($null -eq $task -or $task.State -ne 'Running' -or $arguments -notlike ('*' + $privateIntegrity + '*')) {
        try {
            & $privateIntegrity -Config $ConfigPath -IntervalSeconds $IntervalSeconds -Install -Apply -TaskName $IntegrityTaskName -GuardianTaskName $TaskName 2>&1 | Out-Null
            G "REPAIR integrity-task=$IntegrityTaskName reason=missing-or-altered"
        } catch { G "REPAIR-FAILED integrity-task=$IntegrityTaskName err=$($_.Exception.Message)" }
    }
}

Assert-GuardianArguments

if ($Install) {
    Assert-CcdcAdmin
    Assert-CcdcPacketEntered -Config $cfg
    Assert-NoLegacyTaskPair
    $configPath = (Resolve-Path -LiteralPath $Config).Path
    if (-not $Apply) {
        Write-Host ''
        Write-Host ('  would copy Guardian, watchdog, canary, and integrity files under {0}' -f $privateDir)
        Write-Host ('  would install SYSTEM tasks {0}, {1}, and {2}' -f $TaskName, $WatchdogTaskName, $IntegrityTaskName)
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }
    Initialize-CcdcRoot
    try {
        Write-PrivateCopies -SourceRoot $PSScriptRoot
        $privateWatchdog = Join-Path $privateDir $watchdogLeaf
        & $privateWatchdog -Config $configPath -IntervalSeconds 30 -Install -TaskName $WatchdogTaskName 2>&1 | Out-Null
        $privateIntegrity = Join-Path $privateDir $integrityLeaf
        & $privateIntegrity -Config $configPath -IntervalSeconds $IntervalSeconds -Install -Apply -TaskName $IntegrityTaskName -GuardianTaskName $TaskName 2>&1 | Out-Null
        Register-GuardianTask -ConfigPath $configPath
        G "installed guardian-task=$TaskName watchdog-task=$WatchdogTaskName integrity-task=$IntegrityTaskName"
        Write-CcdcInfo "installed '$TaskName' as SYSTEM; it repairs '$WatchdogTaskName' and keeps '$IntegrityTaskName' present every $IntervalSeconds seconds"
        Write-Host ''
        Write-Host '  This is redundancy, not tamper-proofing. An Administrator can remove all three tasks.' -ForegroundColor Yellow
        Write-Host ('  status: .\windows\guardian.ps1 -Config {0} -Status' -f $Config)
        Write-Host ''
    } catch { Write-CcdcDie "could not install guardian: $($_.Exception.Message)" }
    exit 0
}

if ($Uninstall) {
    Assert-CcdcAdmin
    if (-not $Apply) {
        Write-Host ''
        Write-Host ('  would stop and remove SYSTEM tasks {0}, {1}, and {2}' -f $TaskName, $WatchdogTaskName, $IntegrityTaskName)
        Write-Host ('  would remove private copies under {0}' -f $privateDir)
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }
    try {
        Stop-AndUnregisterTask -Name $TaskName
        $privateIntegrity = Join-Path $privateDir $integrityLeaf
        if (Test-Path -LiteralPath $privateIntegrity -PathType Leaf) {
            & $privateIntegrity -Config $Config -Uninstall -Apply -TaskName $IntegrityTaskName 2>&1 | Out-Null
        } else { Stop-AndUnregisterTask -Name $IntegrityTaskName }
        $privateWatchdog = Join-Path $privateDir $watchdogLeaf
        if (Test-Path -LiteralPath $privateWatchdog -PathType Leaf) {
            & $privateWatchdog -Config $Config -Uninstall -TaskName $WatchdogTaskName 2>&1 | Out-Null
        } else { Stop-AndUnregisterTask -Name $WatchdogTaskName }
        if (Test-Path -LiteralPath $privateDir) { Remove-Item -LiteralPath $privateDir -Recurse -Force -ErrorAction Stop }
        Write-CcdcInfo "removed guardian task, watchdog task, and private copies. Log retained: $(Get-CcdcPath $logName)"
    } catch { Write-CcdcDie "could not remove guardian: $($_.Exception.Message)" }
    exit 0
}

if ($Status) {
    Write-Host ''
    foreach ($name in @($TaskName, $WatchdogTaskName, $IntegrityTaskName)) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $task) { Write-Host ('  {0}: NOT INSTALLED' -f $name) }
        else {
            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction SilentlyContinue
            Write-Host ('  {0}: {1}' -f $name, $task.State)
            if ($info) { Write-Host ('      last run {0}, result {1}' -f $info.LastRunTime, $info.LastTaskResult) }
        }
    }
    if (Test-Path -LiteralPath $manifest -and (Test-Path -LiteralPath $repairManifest)) { Write-Host ('  private copies + repair authority: {0}' -f $privateDir) }
    else { Write-Host '  private copies: MISSING' -ForegroundColor Yellow }
    Write-Host ''
    Write-Host '  LIMIT: an Administrator can remove or alter all three scheduled tasks and their files.' -ForegroundColor Yellow
    Write-Host ''
    exit 0
}

if ($Run) {
    # Internal task mode. It is intentionally not armed by -Apply: this is the
    # installed SYSTEM task doing the repair the operator explicitly installed.
    Assert-CcdcAdmin
    $configPath = (Resolve-Path -LiteralPath $Config).Path
    G "guardian started interval=${IntervalSeconds}s watchdog-task=$WatchdogTaskName"
    while ($true) {
        Ensure-Watchdog -ConfigPath $configPath
        Ensure-IntegrityTask -ConfigPath $configPath
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Write-Host ''
Write-Host '  guardian.ps1 needs one of: -Install, -Status, -Uninstall'
Write-Host ''
Write-Host ('    .\windows\guardian.ps1 -Config {0} -Install -Apply' -f $Config)
Write-Host ''
exit 1
