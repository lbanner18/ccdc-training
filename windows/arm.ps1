<#
.SYNOPSIS
    Put Windows detection and recovery on duty after you finish hardening.

.DESCRIPTION
    This is the Windows counterpart to Linux arm.sh. It does the small set of
    changes that are safe to make as one decision:

      1. lay the canary tripwires and enable their File System audit policy;
      2. install the three-task Guardian chain as SYSTEM; and
      3. verify the canary manifest, private repair authority, and task wiring.

    It intentionally does NOT change passwords, firewall policy, services, or
    accounts. Those are packet decisions. It also does not choose an off-box
    evidence destination: use evidence.ps1 with a team UNC share after the
    baseline below has been frozen.

    Run this after harden.ps1 and before baseline.ps1. The baseline will then
    include the three monitoring tasks you deliberately installed. Bless only
    after the quiet-window review succeeds.

.EXAMPLE
    .\arm.ps1 -Config C:\ProgramData\CCDC\ccdc.env
    Show exactly what would be installed. Changes nothing.

.EXAMPLE
    .\arm.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Apply
    Lay canaries, install Guardian/Watchdog/Continuity-Audit, and verify them.

.EXAMPLE
    .\arm.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
    Read the current chain without changing it.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [int]$GuardianIntervalSeconds = 60,
    [switch]$Apply,
    [switch]$Status
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$configPath = (Resolve-Path -LiteralPath $Config).Path
$guardianTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_TASK' -Default 'Maintenance-Check'
$watchdogTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_TASK' -Default 'Operations-Monitor'
$integrityTask = Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_TASK' -Default 'Continuity-Audit'
$privateLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance'
$guardianLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_GUARDIAN_FILE' -Default 'health-check.ps1' -PowerShellFile
$watchdogLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_FILE' -Default 'service-monitor.ps1' -PowerShellFile
$integrityLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_INTEGRITY_FILE' -Default 'continuity-audit.ps1' -PowerShellFile
$privateDir = Get-CcdcPath $privateLeaf
$canaryManifest = Get-CcdcPath 'state\canaries.txt'
$repairManifest = Join-Path $privateDir '.repair\SHA256SUMS.csv'

function Invoke-CcdcArmChild {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "cannot ${Label}: missing kit file $Path"
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with PowerShell exit code $LASTEXITCODE"
    }
}

function Test-ExpectedTask {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Payload
    )
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { return "MISSING task=$Name" }
    $arguments = @($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' '
    if ($arguments -notlike ('*' + $Payload + '*')) {
        return "REDIRECTED task=$Name expected=$Payload"
    }
    if ($task.State -ne 'Running') { return "STOPPED task=$Name state=$($task.State)" }
    return ''
}

function Show-CcdcArmStatus {
    $problems = New-Object System.Collections.ArrayList
    $expected = @(
        [pscustomobject]@{ Name = $guardianTask; Payload = (Join-Path $privateDir $guardianLeaf) },
        [pscustomobject]@{ Name = $watchdogTask; Payload = (Join-Path $privateDir $watchdogLeaf) },
        [pscustomobject]@{ Name = $integrityTask; Payload = (Join-Path $privateDir $integrityLeaf) }
    )

    Write-Host ''
    Write-Host ('arm.ps1 - is the Windows protection chain actually on?')
    foreach ($row in $expected) {
        $problem = Test-ExpectedTask -Name $row.Name -Payload $row.Payload
        if ($problem) {
            [void]$problems.Add($problem)
            Write-Host ('  PROBLEM {0}' -f $problem) -ForegroundColor Red
        } else {
            Write-Host ('  ok      task running and wired correctly: {0}' -f $row.Name) -ForegroundColor Green
        }
    }

    if (Test-Path -LiteralPath $canaryManifest -PathType Leaf) {
        $rows = @(Get-Content -LiteralPath $canaryManifest -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
        if (@($rows).Count -gt 0) {
            Write-Host ('  ok      canary manifest present ({0} tripwire(s))' -f @($rows).Count) -ForegroundColor Green
        } else {
            [void]$problems.Add('EMPTY canary manifest')
            Write-Host '  PROBLEM canary manifest is empty' -ForegroundColor Red
        }
    } else {
        [void]$problems.Add('MISSING canary manifest')
        Write-Host '  PROBLEM no canary manifest; tripwires are not armed' -ForegroundColor Red
    }

    if (Test-Path -LiteralPath $repairManifest -PathType Leaf) {
        Write-Host ('  ok      private repair authority present: {0}' -f $repairManifest) -ForegroundColor Green
    } else {
        [void]$problems.Add('MISSING private repair authority')
        Write-Host '  PROBLEM private repair authority is missing' -ForegroundColor Red
    }

    $auditPolicy = (& auditpol.exe /get /subcategory:"File System" 2>&1 | Out-String)
    if ($auditPolicy -match 'Success') {
        Write-Host '  ok      File System auditing is on; canary reads can be recorded' -ForegroundColor Green
    } else {
        [void]$problems.Add('File System auditing is off')
        Write-Host '  PROBLEM File System auditing is off; canary reads will not be recorded' -ForegroundColor Red
    }

    Write-Host ''
    if (@($problems).Count -eq 0) {
        Write-Host '  armed. Guardian can repair ordinary watchdog/file tampering while you work.' -ForegroundColor Green
        return $true
    }
    Write-Host '  Do not call this healthy yet. Read the first PROBLEM, preserve its log, then rerun -Apply.' -ForegroundColor Yellow
    return $false
}

if ($GuardianIntervalSeconds -lt 15) { Write-CcdcDie '-GuardianIntervalSeconds must be at least 15' }
if ($Apply -and $Status) { Write-CcdcDie 'use -Apply to arm, or -Status to inspect; not both' }

if ($Status) {
    Assert-CcdcAdmin
    if (Show-CcdcArmStatus) { exit 0 }
    exit 2
}

Assert-CcdcAdmin
Assert-CcdcPacketEntered -Config $cfg

if (-not $Apply) {
    Write-Host ''
    Write-Host ('  would lay canary tripwires and enable their File System audit policy')
    Write-Host ('  would install SYSTEM tasks {0}, {1}, and {2}' -f $watchdogTask, $guardianTask, $integrityTask)
    Write-Host ('  would create a private repair authority under {0}' -f $privateDir)
    Write-Host ''
    Write-Host '  Does NOT touch passwords, firewall policy, accounts, or scored-service settings.'
    Write-Host '  Does NOT choose an off-box evidence share.'
    Write-Host '  DRY RUN. Add -Apply to arm.' -ForegroundColor Yellow
    Write-Host ''
    exit 0
}

try {
    $canary = Join-Path $PSScriptRoot 'canary.ps1'
    $guardian = Join-Path $PSScriptRoot 'guardian.ps1'

    Write-Host ''
    Write-Host '[1] tripwires (canary.ps1 -Deploy)'
    Invoke-CcdcArmChild -Path $canary -Arguments @('-Config', $configPath, '-Deploy', '-Apply') -Label 'lay canaries'

    Write-Host ''
    Write-Host '[2] supervised recovery (guardian.ps1 -Install)'
    Invoke-CcdcArmChild -Path $guardian -Arguments @('-Config', $configPath, '-Install', '-Apply', '-IntervalSeconds', ([string]$GuardianIntervalSeconds)) -Label 'install Guardian'

    # Give Task Scheduler one moment to transition the just-started infinite
    # task loops to Running before checking their identity.
    Start-Sleep -Seconds 2
    Write-Host ''
    Write-Host '[3] verify what is actually running'
    if (-not (Show-CcdcArmStatus)) { exit 2 }

    Write-Host ''
    Write-Host '  Next, freeze the clean state you deliberately kept:'
    Write-Host ('    .\windows\baseline.ps1 -Config {0} -Bless -StableForSeconds 20 -Apply' -f $Config)
    Write-Host '  Then copy your baseline, manifests, and logs to a team-controlled UNC share:'
    Write-Host ('    .\windows\evidence.ps1 -Config {0} -Destination \\workstation\evidence -Bundle -Apply' -f $Config)
    Write-Host ''
} catch {
    Write-CcdcDie "could not arm the Windows protection chain: $($_.Exception.Message)"
}
