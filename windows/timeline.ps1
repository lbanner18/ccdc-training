<#
.SYNOPSIS
    Build one time-ordered Windows incident timeline from the event logs.

.DESCRIPTION
    Recon saves raw slices of important logs. This tool answers the next
    question: what happened first, across logons, process starts, services,
    scheduled tasks, PowerShell, and Defender? It is read-only. A log that is
    unavailable becomes a GAP row in the output; an empty log is recorded as
    collected with no matching events.

.EXAMPLE
    .\windows\timeline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Hours 6
.EXAMPLE
    .\windows\timeline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Since '2026-09-21T18:00:00Z' -OutputDir D:\evidence
#>
[CmdletBinding()]
param(
    [string]$Config,
    [int]$Hours = 6,
    [datetime]$Since,
    [string]$OutputDir,
    [int]$MaxEventsPerSource = 500,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

if ($Hours -lt 1 -or $Hours -gt 168) { Write-CcdcDie '-Hours must be between 1 and 168.' }
if ($MaxEventsPerSource -lt 10 -or $MaxEventsPerSource -gt 5000) { Write-CcdcDie '-MaxEventsPerSource must be between 10 and 5000.' }
if ($Config) { [void](Import-CcdcConfig -Path $Config) }
Initialize-CcdcRoot

$start = if ($PSBoundParameters.ContainsKey('Since')) { $Since.ToUniversalTime() } else { (Get-Date).ToUniversalTime().AddHours(-$Hours) }
$end = (Get-Date).ToUniversalTime()
if ($start -ge $end) { Write-CcdcDie '-Since must be in the past.' }
$facts = Get-CcdcBoxFacts
if ($OutputDir) {
    $stamp = $end.ToString('yyyyMMddTHHmmssZ')
    $dir = Join-Path $OutputDir ("windows-timeline-" + $stamp)
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
} else { $dir = New-CcdcEvidenceDir -Label 'timeline' }

$rows = New-Object System.Collections.ArrayList
$gaps = New-Object System.Collections.ArrayList
function OneLine {
    param([object]$Value)
    $text = ([string]$Value -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
    if ($text.Length -gt 700) { return $text.Substring(0, 700) + ' [truncated]' }
    return $text
}
function Add-Events {
    param([string]$Source, [string]$LogName, [int[]]$Ids, [string]$Why)
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $start } -MaxEvents $MaxEventsPerSource -ErrorAction Stop)
        foreach ($event in $events) {
            [void]$script:rows.Add([pscustomobject]@{
                TimeUtc = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                Source = $Source
                Log = $LogName
                Id = [int]$event.Id
                Summary = OneLine $event.Message
            })
        }
        if (-not $Quiet) { Write-Host ('  ok      {0}: {1} matching event(s)' -f $Source, @($events).Count) }
    } catch {
        $message = OneLine $_.Exception.Message
        # Get-WinEvent uses a terminating error for an ordinary empty query.
        # That is a successful collection with zero matching events, not a
        # missing log or permission problem. Treating it as a GAP would make a
        # quiet lab box look less observable than it is.
        if ($message -match '^No events were found') {
            if (-not $Quiet) { Write-Host ('  ok      {0}: 0 matching event(s)' -f $Source) }
            return
        }
        [void]$script:gaps.Add([pscustomobject]@{ Source = $Source; Log = $LogName; Reason = $message; Why = $Why })
        if (-not $Quiet) { Write-Host ('  GAP     {0}: {1}' -f $Source, $message) -ForegroundColor Yellow }
    }
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host ('timeline.ps1 - read-only timeline from {0} to {1}' -f $start.ToString('u'), $end.ToString('u'))
    Write-CcdcBoxBanner -Facts $facts
}

Add-Events 'security-account-and-logon' 'Security' @(4624,4625,4648,4672,4720,4722,4728,4732,4697,4698,4702,4719,1102) 'Security audit evidence may require elevation and enabled audit policy.'
Add-Events 'security-processes' 'Security' @(4688) 'Process Creation events exist only after process-creation auditing is enabled.'
Add-Events 'system-services' 'System' @(7031,7034,7036,7040,7045) 'System records service stops, starts, configuration changes, and installs.'
Add-Events 'powershell' 'Microsoft-Windows-PowerShell/Operational' @(4103,4104) 'PowerShell script-block and module events exist only after logging is enabled.'
Add-Events 'scheduled-tasks' 'Microsoft-Windows-TaskScheduler/Operational' @(106,140,141,200,201) 'Task Scheduler Operational can be disabled or unavailable on older images.'
Add-Events 'defender' 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117,5001,5007) 'Defender may be absent, disabled, or managed by another endpoint product.'

$timeline = @($rows | Sort-Object TimeUtc, Source, Id)
$csv = Join-Path $dir 'timeline.csv'
$markdown = Join-Path $dir 'timeline.md'
$gapFile = Join-Path $dir 'collection-gaps.csv'
$timeline | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
$gaps | Export-Csv -LiteralPath $gapFile -NoTypeInformation -Encoding UTF8

$md = New-Object System.Collections.ArrayList
[void]$md.Add('# Windows incident timeline')
[void]$md.Add('')
[void]$md.Add(('Window: {0} through {1}' -f $start.ToString('u'), $end.ToString('u')))
[void]$md.Add(('Host: {0}' -f $facts['Host']))
[void]$md.Add(('Events: {0}; collection gaps: {1}' -f @($timeline).Count, @($gaps).Count))
[void]$md.Add('')
[void]$md.Add('| UTC | source | event | summary |')
[void]$md.Add('| --- | --- | --- | --- |')
foreach ($row in $timeline) {
    $summary = ([string]$row.Summary).Replace('|', '\|')
    [void]$md.Add(('| {0} | {1} | {2} ({3}) | {4} |' -f $row.TimeUtc, $row.Source, $row.Id, $row.Log, $summary))
}
if (@($gaps).Count -gt 0) {
    [void]$md.Add('')
    [void]$md.Add('## Collection gaps')
    [void]$md.Add('')
    [void]$md.Add('A gap means this timeline cannot speak about that source. It does not mean nothing happened.')
    [void]$md.Add('')
    foreach ($gap in $gaps) { [void]$md.Add(('- **{0}** ({1}): {2}' -f $gap.Source, $gap.Log, $gap.Reason)) }
}
Set-Content -LiteralPath $markdown -Value $md -Encoding UTF8

$sums = Join-Path $dir 'SHA256SUMS.csv'
Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -ne 'SHA256SUMS.csv' } |
    Get-FileHash -Algorithm SHA256 | Select-Object Hash, @{n='File';e={ Split-Path -Leaf $_.Path }} |
    Export-Csv -LiteralPath $sums -NoTypeInformation -Encoding UTF8

if (-not $Quiet) {
    Write-Host ''
    Write-Host ('  {0} event(s) saved to {1}' -f @($timeline).Count, $dir)
    Write-Host ('  read: {0}' -f $markdown)
    if (@($gaps).Count -gt 0) { Write-Host ('  {0} source gap(s): read {1}' -f @($gaps).Count, $gapFile) -ForegroundColor Yellow }
    Write-Host '  This is evidence, not a verdict. Preserve it off-box before editing the host.'
    Write-Host ''
}
