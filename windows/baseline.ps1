<#
.SYNOPSIS
    Freeze what this box is, then answer the only question that matters later:
    what changed, and is it explained?

.DESCRIPTION
    The Linux half of this kit hashes the filesystem, because `dpkg -V` gives it
    a complete manifest of every distro-owned file to compare against. Windows
    has no such manifest, and taking one is expensive: the System32 tree alone
    is ~14,000 files, which is about five minutes to hash and signature-check.
    Twice - once to freeze, once to compare - is ten minutes of a six-hour round
    spent not doing injects, and most of the diff would be Windows Update.

    So this asks a different, cheaper, better-aimed question.

    WHAT IS FROZEN

      Configuration, which is where Windows attacks actually live and which has
      no real-time equivalent of a signature: services and their binary paths
      and logon accounts, scheduled tasks, autostart entries, local accounts
      and group membership, listening ports, inbound firewall rules, shares and
      their access lists, WMI event subscriptions, Defender exclusions.

      The executable surface - every binary wired to run by one of the above.
      Measured on a stock Server 2022 that is about 250 unique files, six
      seconds, rather than 14,000 files and five minutes.

    WHAT IS NOT FROZEN, AND WHY

      The filesystem. Authenticode already answers "is this file explained?" in
      real time and does not need a baseline to do it - and it answers better
      than a hash would, because a status of HashMismatch means a signed file
      has been ALTERED. See lib\Provenance.ps1.

.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Bless -Apply
    Freeze the box as it is now. Do this once you have hardened it and believe
    it - NOT on arrival, when whatever they left behind is still running.

.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
    What has changed since.

.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Explain 4
.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Allow 'service:MyApp' -Reason 'our web app, added minute 40' -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [switch]$Bless,
    [switch]$Status,
    [int]$Explain,
    [string]$Allow,
    [string]$Reason,
    [switch]$All,
    [switch]$Apply,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"
. "$PSScriptRoot\lib\Provenance.ps1"

Initialize-CcdcRoot
$cfg = Import-CcdcConfig -Path $Config

$script:manifestFile = Get-CcdcPath 'state\baseline.json'
$script:allowFile    = Get-CcdcPath 'state\baseline-allow.txt'
$script:driftFile    = Get-CcdcPath 'state\drift.txt'
$script:logName      = 'baseline.log'
function B { param([string]$m) Write-CcdcLog -Message $m -LogName $script:logName }

function Get-StateDir {
    $d = Get-CcdcPath 'state'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

# =============================================================================
# TAKING THE PICTURE
#
# Every collector returns a hashtable of key -> descriptive string. The key is
# the identity of the thing; the value is everything about it that, if it
# changed, you would want to be told. Comparing two of these is then a set
# operation rather than a pile of special cases.
# =============================================================================

function Get-ServiceState {
    $h = @{}
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $h[$s.Name] = 'path={0}; account={1}; start={2}' -f $s.PathName, $s.StartName, $s.StartMode
    }
    return $h
}

function Get-TaskState {
    $h = @{}
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $acts = @()
        try {
            foreach ($a in $t.Actions) {
                $e = ''; $g = ''
                try { $e = [string]$a.Execute }   catch { }
                try { $g = [string]$a.Arguments } catch { }
                $acts += ("$e $g").Trim()
            }
        } catch { }
        $key = ('{0}{1}' -f $t.TaskPath, $t.TaskName)
        $h[$key] = 'runs={0}; state={1}' -f (($acts | Where-Object { $_ }) -join ' ; '), $t.State
    }
    return $h
}

function Get-AutostartState {
    $h = @{}
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
        try {
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
            foreach ($n in $p.PSObject.Properties.Name) {
                if ($n -like 'PS*') { continue }
                $h["$k\$n"] = [string]$p.$n
            }
        } catch { }
    }
    foreach ($d in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                     "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) {
            $h[$f.FullName] = 'startup folder item'
        }
    }
    # The long tail belongs to somebody else. Autoruns knows ~200 autostart
    # locations; the four above are the ones worth hard-coding. If the operator
    # brought autorunsc.exe, use it and say so - rebuilding it badly would be
    # the worst of both.
    $ar = Get-Command 'autorunsc.exe' -ErrorAction SilentlyContinue
    if ($ar) {
        try {
            $csv = & $ar.Source -accepteula -nobanner -a * -c -h 2>$null | ConvertFrom-Csv
            foreach ($row in $csv) {
                $entry = ''; $loc = ''; $img = ''
                try { $entry = [string]$row.'Entry'; $loc = [string]$row.'Entry Location'; $img = [string]$row.'Image Path' } catch { }
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                $h["autoruns:$loc\$entry"] = $img
            }
        } catch { }
    }
    return $h
}

function Get-AccountState {
    $h = @{}
    foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
        $h["user:$($u.Name)"] = 'enabled={0}; sid={1}' -f $u.Enabled, $u.SID.Value
    }
    foreach ($g in (Get-LocalGroup -ErrorAction SilentlyContinue)) {
        $members = @()
        try { $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { }
        if (@($members).Count -eq 0) { continue }
        $h["group:$($g.Name)"] = (($members | Sort-Object) -join ', ')
    }
    return $h
}

function Get-ListenerState {
    $h = @{}
    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $proc = ''
        try { $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } catch { }
        $h["tcp/$($c.LocalPort)"] = "held by $proc"
    }
    return $h
}

function Get-FirewallState {
    $h = @{}
    foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $h["profile:$($p.Name)"] = 'enabled={0}; inbound={1}; logblocked={2}' -f $p.Enabled, $p.DefaultInboundAction, $p.LogBlocked
    }
    foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)) {
        $ports = ''
        try { $ports = (@((Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).LocalPort) -join ',') } catch { }
        $h["rule:$($r.DisplayName)"] = "ports=$ports"
    }
    return $h
}

function Get-ShareState {
    $h = @{}
    foreach ($s in (Get-SmbShare -ErrorAction SilentlyContinue)) {
        $acl = @()
        try { $acl = @(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop |
                       ForEach-Object { '{0}:{1}' -f $_.AccountName, $_.AccessRight }) } catch { }
        $h["share:$($s.Name)"] = 'path={0}; access={1}' -f $s.Path, (($acl | Sort-Object) -join ', ')
    }
    return $h
}

function Get-WmiState {
    $h = @{}
    foreach ($cls in @('CommandLineEventConsumer','ActiveScriptEventConsumer','__EventFilter')) {
        foreach ($o in (Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue)) {
            $n = ''
            try { $n = [string]$o.Name } catch { }
            if (-not $n) { continue }
            $h["wmi:$cls\$n"] = $cls
        }
    }
    return $h
}

function Get-DefenderState {
    $h = @{}
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        foreach ($e in @($mp.ExclusionPath))      { if ($e) { $h["exclusion:path:$e"] = 'Defender ignores this path' } }
        foreach ($e in @($mp.ExclusionProcess))   { if ($e) { $h["exclusion:proc:$e"] = 'Defender ignores this process' } }
        foreach ($e in @($mp.ExclusionExtension)) { if ($e) { $h["exclusion:ext:$e"]  = 'Defender ignores this extension' } }
    } catch { }
    return $h
}

function Get-ExecutableSurface {
    <#
        Every binary the configuration above wires to run, deduplicated. This
        is the set worth hashing: ~250 files rather than ~14,000, and it is the
        set somebody has to change in order to run code on this box.
    #>
    param([hashtable]$Services, [hashtable]$Tasks, [hashtable]$Autostart)
    $paths = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($v in $Services.Values) {
        if ($v -match 'path=(.+?); account=') { [void]$paths.Add((Get-CcdcExecutablePath $Matches[1])) }
    }
    foreach ($v in $Tasks.Values) {
        if ($v -match 'runs=(.*?); state=') {
            foreach ($one in ($Matches[1] -split ' ; ')) {
                $p = Get-CcdcExecutablePath $one
                if ($p) { [void]$paths.Add($p) }
            }
        }
    }
    foreach ($v in $Autostart.Values) {
        $p = Get-CcdcExecutablePath $v
        if ($p) { [void]$paths.Add($p) }
    }

    $h = @{}
    foreach ($p in $paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        # Expand %SystemRoot% and friends, or every one of these misses.
        $full = [Environment]::ExpandEnvironmentVariables($p)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        $f = Get-CcdcFileFacts -Path $full
        $h[$full.ToLowerInvariant()] = '{0}|{1}|{2}' -f $f.Sha256, $f.SigStatus, $f.Publisher
    }
    return $h
}

function Get-BoxSnapshot {
    if (-not $Quiet) { Write-Host '  looking at services, tasks, autostarts, accounts, ports, firewall, shares, WMI...' }
    $svc = Get-ServiceState
    $tsk = Get-TaskState
    $aut = Get-AutostartState
    if (-not $Quiet) { Write-Host '  hashing every executable those wire to run...' }
    return [ordered]@{
        meta = [ordered]@{
            host    = $env:COMPUTERNAME
            taken   = (Get-Date).ToUniversalTime().ToString('u')
            os      = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        }
        services   = $svc
        tasks      = $tsk
        autostart  = $aut
        accounts   = Get-AccountState
        listeners  = Get-ListenerState
        firewall   = Get-FirewallState
        shares     = Get-ShareState
        wmi        = Get-WmiState
        defender   = Get-DefenderState
        files      = (Get-ExecutableSurface -Services $svc -Tasks $tsk -Autostart $aut)
    }
}

# =============================================================================
# THE ALLOWLIST
# =============================================================================

function Get-AllowList {
    if (-not (Test-Path -LiteralPath $script:allowFile)) { return @() }
    $out = @()
    foreach ($l in (Get-Content -LiteralPath $script:allowFile -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($l) -or $l -match '^\s*#') { continue }
        $p = $l -split '\|', 2
        $out += [pscustomobject]@{ Pattern = $p[0]; Reason = $(if (@($p).Count -gt 1) { $p[1] } else { '' }) }
    }
    return @($out)
}

function Test-Allowed {
    param([string]$Key)
    foreach ($a in (Get-AllowList)) {
        if ($Key -eq $a.Pattern) { return $a }
        if ($Key -like $a.Pattern) { return $a }
    }
    return $null
}

# =============================================================================
# BLESS
# =============================================================================
if ($Bless) {
    Assert-CcdcAdmin
    Assert-CcdcPacketEntered -Config $cfg
    Get-StateDir | Out-Null

    Write-Host ''
    Write-Host ('baseline.ps1 - freezing {0}' -f $env:COMPUTERNAME)
    Write-Host ''
    if (Test-Path -LiteralPath $script:manifestFile) {
        Write-Host '  A baseline already exists. Blessing again REPLACES it, and anything' -ForegroundColor Yellow
        Write-Host '  wrong with the box right now becomes the new definition of normal.' -ForegroundColor Yellow
        Write-Host ''
    }
    $snap = Get-BoxSnapshot

    $counts = @()
    foreach ($k in @('services','tasks','autostart','accounts','listeners','firewall','shares','wmi','defender','files')) {
        $counts += ('{0} {1}' -f @($snap[$k].Keys).Count, $k)
    }
    Write-Host ''
    Write-Host ('  captured: {0}' -f ($counts -join ', '))

    if (-not $Apply) {
        Write-Host ''
        Write-Host '  DRY RUN. Nothing was written. Add -Apply to freeze this.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }
    # -Depth matters: PowerShell 5.1 defaults to 2 and silently writes the
    # string "System.Collections.Hashtable" for anything deeper, which would
    # make every section of this manifest an identical useless value.
    $json = $snap | ConvertTo-Json -Depth 6
    $tmp = "$($script:manifestFile).tmp"
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $script:manifestFile -Force
    B "blessed: $($counts -join ', ')"

    Write-Host ''
    Write-Host ('  frozen: {0}' -f $script:manifestFile) -ForegroundColor Green
    Write-Host ''
    Write-Host '  From now on this is what "normal" means on this box.'
    Write-Host ('     .\windows\baseline.ps1 -Config {0} -Status' -f $Config)
    Write-Host ''
    Write-Host '  Take a copy off the box. A baseline that lives only where the attacker'
    Write-Host '  is, is a baseline the attacker can edit.'
    Write-Host ''
    exit 0
}

# =============================================================================
# STATUS - the diff
# =============================================================================
if ($Status -or $PSBoundParameters.ContainsKey('Explain')) {
    Assert-CcdcAdmin
    if (-not (Test-Path -LiteralPath $script:manifestFile)) {
        Write-CcdcDie @"
no baseline to compare against.

  Harden the box first, satisfy yourself it is clean, THEN freeze it:
      .\windows\baseline.ps1 -Config $Config -Bless -Apply

  Blessing on arrival freezes whatever they left behind as normal.
"@
    }
    $old = $null
    try {
        $old = Get-Content -LiteralPath $script:manifestFile -Raw | ConvertFrom-Json
    } catch {
        Write-CcdcDie "the baseline file is unreadable: $($_.Exception.Message)"
    }
    $new = Get-BoxSnapshot

    $sections = @('services','tasks','autostart','accounts','listeners','firewall','shares','wmi','defender','files')
    $items = New-Object System.Collections.ArrayList

    foreach ($sec in $sections) {
        $oldSec = @{}
        if ($old.PSObject.Properties.Name -contains $sec -and $null -ne $old.$sec) {
            foreach ($p in $old.$sec.PSObject.Properties) { $oldSec[$p.Name] = [string]$p.Value }
        }
        $newSec = $new[$sec]

        foreach ($k in $newSec.Keys) {
            if (-not $oldSec.ContainsKey($k)) {
                [void]$items.Add([pscustomobject]@{
                    Kind='ADDED'; Section=$sec; Key=$k; Now=$newSec[$k]; Was='' })
            } elseif ($oldSec[$k] -ne $newSec[$k]) {
                [void]$items.Add([pscustomobject]@{
                    Kind='CHANGED'; Section=$sec; Key=$k; Now=$newSec[$k]; Was=$oldSec[$k] })
            }
        }
        foreach ($k in $oldSec.Keys) {
            if (-not $newSec.ContainsKey($k)) {
                [void]$items.Add([pscustomobject]@{
                    Kind='REMOVED'; Section=$sec; Key=$k; Now=''; Was=$oldSec[$k] })
            }
        }
    }

    # An explicit allowlist entry is the operator saying "that one is mine".
    $shown = New-Object System.Collections.ArrayList
    $allowedCount = 0
    foreach ($i in $items) {
        $a = Test-Allowed -Key ('{0}:{1}' -f $i.Section, $i.Key)
        if ($null -ne $a -and -not $All) { $allowedCount++; continue }
        if ($null -ne $a) { $i | Add-Member -NotePropertyName AllowedBecause -NotePropertyValue $a.Reason -Force }
        [void]$shown.Add($i)
    }

    # -Explain N wants the detail for one item, so the numbering has to be the
    # same one -Status printed. Same list, same order, same numbers.
    if ($PSBoundParameters.ContainsKey('Explain')) {
        $n = 0; $found = $null
        foreach ($i in $shown) { $n++; if ($n -eq $Explain) { $found = $i; break } }
        if ($null -eq $found) { Write-CcdcDie "there is no item $Explain in the current drift report" }
        Write-Host ''
        Write-Host ('  [{0}] {1} {2}' -f $Explain, $found.Kind, $found.Section)
        Write-Host ('       {0}' -f $found.Key)
        Write-Host ''
        if ($found.Was) { Write-Host ('  was:  {0}' -f $found.Was) }
        if ($found.Now) { Write-Host ('  now:  {0}' -f $found.Now) }
        if ($found.Section -eq 'files') {
            $path = $found.Key
            Write-Host ''
            Write-Host '  asking what accounts for this file:'
            $facts = Get-CcdcFileFacts -Path $path
            $frozen = @{}
            if ($old.PSObject.Properties.Name -contains 'files' -and $null -ne $old.files) {
                foreach ($p in $old.files.PSObject.Properties) {
                    $frozen[$p.Name] = ([string]$p.Value -split '\|')[0]
                }
            }
            # Assign, then pipe. `return ,@()` survives an assignment as an
            # empty array, but piping it hands ForEach-Object the empty array
            # as a single item - so the body runs once with $_ = @() and
            # $_.Pattern throws under StrictMode.
            $allowRows = @(Get-AllowList)
            $allowPatterns = @()
            foreach ($row in $allowRows) { $allowPatterns += [string]$row.Pattern }
            $v = Test-CcdcExplained -Facts $facts -Frozen $frozen -Allowed $allowPatterns
            Write-Host ('    verdict:   {0}' -f $v.Verdict) -ForegroundColor $(if ($v.Severity -eq 'RED') { 'Red' } elseif ($v.Severity -eq 'OK') { 'Green' } else { 'Yellow' })
            Write-Host ('    signature: {0}  {1}' -f $facts.SigStatus, $facts.SigType)
            Write-Host ('    publisher: {0}' -f $facts.Publisher)
            Write-Host ('    company:   {0}' -f $facts.Company)
            Write-Host ('    sha256:    {0}' -f $facts.Sha256)
            Write-Host ('    {0}' -f $v.Detail)
        }
        Write-Host ''
        Write-Host '  if this is yours:'
        Write-Host ('    .\windows\baseline.ps1 -Config {0} -Allow ''{1}:{2}'' -Reason ''why'' -Apply' -f $Config, $found.Section, $found.Key)
        Write-Host ''
        exit 0
    }

    Write-Host ''
    Write-Host ('baseline.ps1 - what changed on {0} since you froze it' -f $env:COMPUTERNAME)
    Write-Host ('  frozen {0}, compared {1}' -f $old.meta.taken, (Get-Date).ToUniversalTime().ToString('u'))

    if (@($shown).Count -eq 0) {
        Write-Host ''
        Write-Host '  Nothing has changed.' -ForegroundColor Green
        if ($allowedCount -gt 0) { Write-Host ('  ({0} change(s) hidden by your allowlist; -All shows them)' -f $allowedCount) }
        Write-Host ''
        Write-Host '  That is a real answer, not a guess - but it only covers what was'
        Write-Host '  frozen. A file nothing wires to run is not in the baseline.'
        Write-Host ''
        exit 0
    }

    $n = 0
    foreach ($i in $shown) {
        $n++
        $colour = switch ($i.Kind) { 'ADDED' { 'Yellow' } 'CHANGED' { 'Red' } default { 'DarkGray' } }
        Write-Host ''
        Write-Host ('  [{0}] {1,-8} {2,-10} {3}' -f $n, $i.Kind, $i.Section, $i.Key) -ForegroundColor $colour
        if ($i.Was) { Write-Host ('        was: {0}' -f $i.Was) }
        if ($i.Now) { Write-Host ('        now: {0}' -f $i.Now) }
        if ($i.PSObject.Properties.Name -contains 'AllowedBecause') {
            Write-Host ('        allowed: {0}' -f $i.AllowedBecause) -ForegroundColor DarkGray
        }
    }

    $added   = @($shown | Where-Object { $_.Kind -eq 'ADDED' }).Count
    $changed = @($shown | Where-Object { $_.Kind -eq 'CHANGED' }).Count
    $removed = @($shown | Where-Object { $_.Kind -eq 'REMOVED' }).Count
    Write-Host ''
    Write-Host ('  {0} change(s): {1} added, {2} changed, {3} removed.' -f @($shown).Count, $added, $changed, $removed)
    if ($allowedCount -gt 0) { Write-Host ('  {0} more hidden by your allowlist (-All shows them).' -f $allowedCount) }
    Write-Host ''
    Write-Host ('     .\windows\baseline.ps1 -Config {0} -Explain N' -f $Config)
    Write-Host '       everything known about item N, including what accounts for it'
    Write-Host ('     .\windows\baseline.ps1 -Config {0} -Allow ''section:key'' -Reason ''why'' -Apply' -f $Config)
    Write-Host '       stop reporting one you have decided is yours'
    Write-Host ''
    Write-Host '  A CHANGED service path or a CHANGED file is worth more of your attention'
    Write-Host '  than an ADDED anything: adding is what installers do, changing what was'
    Write-Host '  already there is what somebody does to keep access.'
    Write-Host ''

    $shown | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Kind, $_.Section, $_.Key, $_.Now } |
        Set-Content -LiteralPath $script:driftFile -Encoding UTF8
    exit 0
}

# =============================================================================
# ALLOW
# =============================================================================
if ($Allow) {
    Assert-CcdcAdmin
    if ([string]::IsNullOrWhiteSpace($Reason)) {
        Write-CcdcDie @"
-Allow needs -Reason.

  An allowlist entry with no reason is indistinguishable, an hour later, from
  a thing you never looked at. Write the sentence you would want to read.

      .\windows\baseline.ps1 -Config $Config -Allow '$Allow' -Reason 'our web app, added minute 40' -Apply
"@
    }
    Get-StateDir | Out-Null
    if (-not $Apply) {
        Write-Host ''
        Write-Host ('  would allow: {0}' -f $Allow)
        Write-Host ('  because:     {0}' -f $Reason)
        Write-Host ''
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }
    ('{0}|{1}  (added {2})' -f $Allow, $Reason, (Get-Date).ToUniversalTime().ToString('u')) |
        Add-Content -LiteralPath $script:allowFile -Encoding UTF8
    B "allowed $Allow because $Reason"
    Write-CcdcInfo "allowed: $Allow"
    Write-Host ('  reason recorded: {0}' -f $Reason)
    Write-Host ('  list: {0}' -f $script:allowFile)
    exit 0
}

Write-Host ''
Write-Host '  baseline.ps1 needs one of: -Bless, -Status, -Explain N, -Allow'
Write-Host ''
Write-Host ('    .\windows\baseline.ps1 -Config {0} -Bless -Apply     freeze this box' -f $Config)
Write-Host ('    .\windows\baseline.ps1 -Config {0} -Status           what changed since' -f $Config)
Write-Host ''
exit 1
