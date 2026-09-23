<#
.SYNOPSIS
    Check whether Windows can still prove what happened, then capture that proof.

.DESCRIPTION
    harden.ps1 turns useful auditing on. This tool answers the later question:
    did it stay on, are the important logs large enough, and can this account
    still read them? -Check changes nothing. -Repair deliberately delegates to
    harden.ps1's Logging step, so there is one definition of the settings.

    -Capture writes a small, hash-manifested evidence case: current audit
    policy, logging registry values, event-log configuration, and the latest
    high-signal event rows. It does not clear, rotate, or reconfigure a log.

.EXAMPLE
    .\audit.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Check
.EXAMPLE
    .\audit.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Repair -Apply
.EXAMPLE
    .\audit.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Capture -Apply
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Check,
    [switch]$Repair,
    [switch]$Capture,
    [switch]$Apply
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$configPath = (Resolve-Path -LiteralPath $Config).Path
$logName = 'audit.log'
function A { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Get-RegistryValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Test-AuditPolicy {
    param([Parameter(Mandatory)][string]$Argument, [Parameter(Mandatory)][string]$Needle)
    try {
        $text = (& auditpol.exe /get $Argument 2>&1 | Out-String)
        return ($text -match [regex]::Escape($Needle))
    } catch { return $false }
}

function Test-EventLogSize {
    param([Parameter(Mandatory)][string]$LogName)
    try {
        $text = (& wevtutil.exe gl $LogName 2>&1 | Out-String)
        # `-notmatch` does not populate $Matches in Windows PowerShell. A
        # prior version therefore read a stale (or empty) capture after a
        # successful `wevtutil` query and called every correctly sized log
        # too small.
        if ($text -match '(?im)^\s*maxSize:\s*(\d+)') {
            return ([int64]$Matches[1] -ge 268435456)
        }
        return $false
    } catch { return $false }
}

function Test-EventLogReadable {
    param([Parameter(Mandatory)][string]$LogName)
    try {
        [void](Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop)
        return $true
    } catch {
        # A completely empty operational log is still readable. Get-WinEvent
        # calls that an error, so distinguish it from access denied or a gone log.
        return ($_.Exception.Message -match '^No events were found')
    }
}

function Add-Result {
    param([Parameter(Mandatory)][bool]$Good, [Parameter(Mandatory)][string]$Message)
    if ($Good) { Write-Host ('  ok      {0}' -f $Message) -ForegroundColor Green }
    else { Write-Host ('  AUDIT   {0}' -f $Message) -ForegroundColor Red }
    return $Good
}

function Invoke-AuditCheck {
    $bad = 0
    Write-Host ''
    Write-Host 'audit.ps1 - can this box still prove what happened?'
    Write-Host ('read-only. {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-Host ''

    $scriptBlock = (Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging') -eq 1
    if (-not (Add-Result -Good $scriptBlock -Message 'PowerShell script block logging is on (event 4104)')) { $bad++ }
    $module = (Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging') -eq 1
    $moduleNames = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*'
    if (-not (Add-Result -Good ($module -and $moduleNames -eq '*') -Message 'PowerShell module logging covers every module')) { $bad++ }
    $cmdLine = (Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
    if (-not (Add-Result -Good $cmdLine -Message 'process-creation events include the command line')) { $bad++ }

    foreach ($category in @('Logon/Logoff','Account Management','Policy Change','Account Logon')) {
        if (-not (Add-Result -Good (Test-AuditPolicy -Argument ('/category:"' + $category + '"') -Needle 'Success and Failure') -Message ('audit category has success and failure: ' + $category))) { $bad++ }
    }
    if (-not (Add-Result -Good (Test-AuditPolicy -Argument '/subcategory:"Process Creation"' -Needle 'Success') -Message 'Process Creation auditing is on')) { $bad++ }

    foreach ($eventLog in @('Security','System','Application')) {
        if (-not (Add-Result -Good (Test-EventLogSize -LogName $eventLog) -Message ($eventLog + ' event log holds at least 256 MB'))) { $bad++ }
        if (-not (Add-Result -Good (Test-EventLogReadable -LogName $eventLog) -Message ($eventLog + ' event log is readable'))) { $bad++ }
    }
    if (-not (Add-Result -Good (Test-EventLogReadable -LogName 'Microsoft-Windows-PowerShell/Operational') -Message 'PowerShell Operational event log is readable')) { $bad++ }

    try {
        $clears = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 1 -ErrorAction Stop)
        if (@($clears).Count -gt 0) {
            Write-Host ('  AUDIT   Security log was cleared at {0:u}; preserve and report that gap' -f $clears[0].TimeCreated) -ForegroundColor Red
            $bad++
        }
    } catch { }

    Write-Host ''
    if ($bad -eq 0) {
        Write-Host '  Audit and logging look healthy.' -ForegroundColor Green
        return $true
    }
    Write-Host ('  {0} audit/logging finding(s). Repair settings with:' -f $bad) -ForegroundColor Yellow
    Write-Host ('    .\windows\audit.ps1 -Config {0} -Repair -Apply' -f $Config)
    return $false
}

function Save-AuditEvidence {
    $dir = New-CcdcEvidenceDir -Label 'audit-capture'
    $sources = @(
        [pscustomobject]@{ Name = 'audit-policy.txt'; Command = { & auditpol.exe /get /category:* 2>&1 } },
        [pscustomobject]@{ Name = 'event-log-config.txt'; Command = { foreach ($l in @('Security','System','Application','Microsoft-Windows-PowerShell/Operational')) { "=== $l ==="; & wevtutil.exe gl $l 2>&1 } } },
        [pscustomobject]@{ Name = 'logging-registry.txt'; Command = { Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue | Format-List } },
        [pscustomobject]@{ Name = 'recent-security-events.txt'; Command = { Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102,4624,4625,4672,4688,4697,4698,4702,4719,4720,4722,4728,4732 } -MaxEvents 500 -ErrorAction Stop | Select-Object TimeCreated,Id,Message | Format-List } },
        [pscustomobject]@{ Name = 'recent-powershell-events.txt'; Command = { Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4103,4104 } -MaxEvents 300 -ErrorAction Stop | Select-Object TimeCreated,Id,Message | Format-List } }
    )
    foreach ($source in $sources) {
        $path = Join-Path $dir $source.Name
        try { & $source.Command 2>&1 | Out-String -Width 4096 | Set-Content -LiteralPath $path -Encoding UTF8 }
        catch { Set-Content -LiteralPath $path -Value ("NOT COLLECTED: " + $_.Exception.Message) -Encoding UTF8 }
    }
    $hashes = Join-Path $dir 'SHA256SUMS.csv'
    # Export-Csv opens $hashes before its upstream pipeline has enumerated the
    # directory. Exclude the output file itself or a real Windows run races
    # into an attempt to hash a manifest that it is still writing.
    Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -ne 'SHA256SUMS.csv' } |
        Get-FileHash -Algorithm SHA256 |
        Select-Object Hash, @{n='File';e={ Split-Path -Leaf $_.Path }} |
        Export-Csv -LiteralPath $hashes -NoTypeInformation -Encoding UTF8
    A "CAPTURED dir=$dir"
    Write-CcdcInfo "captured logging evidence: $dir"
    Write-Host ('  hashes: {0}' -f $hashes)
}

$modes = @($Check, $Repair, $Capture)
if (@($modes | Where-Object { $_ }).Count -gt 1) { Write-CcdcDie 'choose one: -Check, -Repair, or -Capture' }
if (-not $Check -and -not $Repair -and -not $Capture) { $Check = $true }
Assert-CcdcAdmin

if ($Check) { if (Invoke-AuditCheck) { exit 0 }; exit 2 }
if ($Repair) {
    if (-not $Apply) {
        Write-Host ('  would run the existing Logging hardening step, then re-check it')
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        exit 0
    }
    $harden = Join-Path $PSScriptRoot 'harden.ps1'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $harden -Config $configPath -Only Logging -Apply
    if ($LASTEXITCODE -ne 0) { Write-CcdcDie "Logging repair failed with PowerShell exit code $LASTEXITCODE" }
    if (Invoke-AuditCheck) { exit 0 }; exit 2
}
if (-not $Apply) {
    Write-Host '  would capture audit policy, log configuration, and recent high-signal events.'
    Write-Host '  -Capture writes evidence only; it never changes the logs.'
    Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
    exit 0
}
Save-AuditEvidence
