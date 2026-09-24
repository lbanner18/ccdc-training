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
.\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Bless -StableForSeconds 20 -Apply
    Freeze the box only after its monitored state stays unchanged for 20
    seconds. Do this once you have hardened it and believe it - NOT on
    arrival, when whatever they left behind is still running.

.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
    What has changed since.

.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Explain 4
.EXAMPLE
    .\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Allow 'services:MyApp' -Reason 'our web app, added minute 40' -Apply
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Bless,
    [ValidateRange(0,300)][int]$StableForSeconds = 0,
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
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']

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
    param([Parameter(Mandatory)][hashtable]$Config)
    $h = @{}
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
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
    try {
        $wl = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        foreach ($n in @('Shell', 'Userinit')) {
            if ($wl.PSObject.Properties.Name -contains $n) { $h["winlogon:$n"] = [string]$wl.$n }
        }
    } catch { }
    try {
        $ai = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction Stop
        $dlls = if ($ai.PSObject.Properties.Name -contains 'AppInit_DLLs') { [string]$ai.AppInit_DLLs } else { '' }
        $load = if ($ai.PSObject.Properties.Name -contains 'LoadAppInit_DLLs') { [string]$ai.LoadAppInit_DLLs } else { '?' }
        if (-not [string]::IsNullOrWhiteSpace($dlls) -or $load -eq '1') { $h['appinit'] = "load=$load; dlls=$dlls" }
    } catch { }
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $debug = Get-ItemProperty -LiteralPath $child.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue
                if ($debug -and ($debug.PSObject.Properties.Name -contains 'Debugger') -and -not [string]::IsNullOrWhiteSpace([string]$debug.Debugger)) {
                    $h["ifeo:$($child.PSPath)"] = [string]$debug.Debugger
                }
            }
        } catch { }
    }
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                         'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
        try {
            foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $stub = Get-ItemProperty -LiteralPath $child.PSPath -Name 'StubPath' -ErrorAction SilentlyContinue
                if ($stub -and ($stub.PSObject.Properties.Name -contains 'StubPath') -and -not [string]::IsNullOrWhiteSpace([string]$stub.StubPath)) {
                    $h["activesetup:$($child.PSPath)"] = [string]$stub.StubPath
                }
            }
        } catch { }
    }
    try {
        foreach ($consumer in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -OperationTimeoutSec 8 -ErrorAction Stop)) {
            $className = if ($consumer.PSObject.Properties.Name -contains '__CLASS') { [string]$consumer.__CLASS } else { 'consumer' }
            $name = if ($consumer.PSObject.Properties.Name -contains 'Name') { [string]$consumer.Name } else { '(unnamed)' }
            $command = if ($consumer.PSObject.Properties.Name -contains 'CommandLineTemplate') { [string]$consumer.CommandLineTemplate } elseif ($consumer.PSObject.Properties.Name -contains 'ExecutablePath') { [string]$consumer.ExecutablePath } else { '' }
            $h["wmiconsumer:$className/$name"] = $command
        }
    } catch { }
    # Wider persistence evidence is opt-in. Do not discover a binary from PATH
    # or accept its EULA invisibly: both decisions belong to the operator.
    $autorunsc = Invoke-CcdcAutorunsc -Config $Config
    $script:AutorunscStatus = $autorunsc.Reason
    if ($autorunsc.Ran) {
        foreach ($row in @($autorunsc.Rows)) {
            $entry = ''; $loc = ''; $img = ''
            try { $entry = [string]$row.'Entry'; $loc = [string]$row.'Entry Location'; $img = [string]$row.'Image Path' } catch { }
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $h["autoruns:$loc\$entry"] = $img
        }
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
    param([Parameter(Mandatory)][hashtable]$Config)
    if (-not $Quiet) { Write-Host '  looking at services, tasks, autostarts, accounts, ports, firewall, shares, WMI...' }
    $svc = Get-ServiceState
    $tsk = Get-TaskState
    $aut = Get-AutostartState -Config $Config
    if (-not $Quiet -and -not [string]::IsNullOrWhiteSpace($script:AutorunscStatus)) {
        Write-CcdcWarn "Autorunsc optional collection skipped: $($script:AutorunscStatus)"
    }
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

function Compare-BoxSnapshots {
    <#
        Return one short line per meaningful difference. The `meta` section is
        deliberately excluded: its timestamp must change between the two
        samples, and says nothing about whether the box changed.
    #>
    param(
        [Parameter(Mandatory)]$First,
        [Parameter(Mandatory)]$Second
    )
    $differences = New-Object System.Collections.ArrayList
    foreach ($section in @('services','tasks','autostart','accounts','listeners','firewall','shares','wmi','defender','files')) {
        $firstRows = $First[$section]
        $secondRows = $Second[$section]
        $keys = @((@($firstRows.Keys) + @($secondRows.Keys)) | Sort-Object -Unique)
        foreach ($key in $keys) {
            $inFirst = $firstRows.ContainsKey($key)
            $inSecond = $secondRows.ContainsKey($key)
            if (-not $inFirst) {
                [void]$differences.Add("ADDED $section $key")
            } elseif (-not $inSecond) {
                [void]$differences.Add("REMOVED $section $key")
            } elseif ([string]$firstRows[$key] -ne [string]$secondRows[$key]) {
                [void]$differences.Add("CHANGED $section $key")
            }
        }
    }
    return @($differences)
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

# What to run when a drift item is NOT yours. Found live on ccdc-win: after an
# attack, -Explain said only "if this is yours, allow it", and nothing in the
# kit printed how to remove an added service. Evidence first, then the change
# that stops it running; disabling beats deleting wherever deleting loses what
# the incident report needs.
function Get-DriftRemoval {
    param([Parameter(Mandatory)]$Item)
    function QS { param([string]$s) "'" + ($s -replace "'", "''") + "'" }
    $k = [string]$Item.Key
    $out = @()
    if ($Item.Kind -eq 'REMOVED') {
        return @('# it was there when you froze the box. If it is scored, put it back:',
                 '# CARD W9 (backups, and getting a service back) in playbooks\windows-cards.md')
    }
    switch ($Item.Section) {
        'services' {
            $out += ('sc.exe qc {0}' -f $k)
            $out += ('Stop-Service -Name {0} -Force' -f (QS $k))
            $out += ('sc.exe delete {0}' -f $k)
            $out += '# the program it ran stays on disk: Get-FileHash it for the report'
        }
        'tasks' {
            $out += ('$t = Get-ScheduledTask | Where-Object {{ ($_.TaskPath + $_.TaskName) -eq {0} }}' -f (QS $k))
            $out += ('$t | Export-ScheduledTask | Out-File {0}' -f (QS (Get-CcdcPath 'evidence\task-removed.xml')))
            $out += '$t | Disable-ScheduledTask'
        }
        'autostart' {
            if ($k -match '^(HK(LM|CU):\\.+)\\([^\\]+)$' -and $k -notmatch '^(ifeo|winlogon|wmiconsumer|activesetup|autoruns):') {
                $out += ('Get-ItemProperty -Path {0} -Name {1}' -f (QS $Matches[1]), (QS $Matches[3]))
                $out += ('Remove-ItemProperty -Path {0} -Name {1}' -f (QS $Matches[1]), (QS $Matches[3]))
            } elseif ($k -match '^ifeo:(.+)$') {
                $out += ('Remove-ItemProperty -LiteralPath {0} -Name Debugger' -f (QS $Matches[1]))
            } elseif ($k -match '^winlogon:(Userinit|Shell)$') {
                $stock = if ($Matches[1] -eq 'Shell') { 'explorer.exe' } else { 'C:\Windows\system32\userinit.exe,' }
                $out += ("Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name {0} -Value {1}" -f $Matches[1], (QS $stock))
            } elseif ($k -match '^wmiconsumer:') {
                $out += '# a WMI consumer: remove it with its filter and binding - see the wmi item, or CARD W11'
            } elseif ([System.IO.File]::Exists($k)) {
                $out += ('Get-FileHash -LiteralPath {0}' -f (QS $k))
                $out += ('Move-Item -LiteralPath {0} -Destination {1}' -f (QS $k), (QS (Get-CcdcPath 'evidence')))
            } else {
                $out += '# CARD W4 (autostart, registry, and the login-screen backdoors)'
            }
        }
        'accounts' {
            if ($k -match '^user:(.+)$') {
                $out += ('Disable-LocalUser -Name {0}     # disable, do not delete: the account is evidence' -f (QS $Matches[1]))
            } elseif ($k -match '^group:(.+)$') {
                $g = $Matches[1]
                $was = @(([string]$Item.Was) -split ',\s*' | Where-Object { $_ })
                foreach ($m in @(([string]$Item.Now) -split ',\s*' | Where-Object { $_ -and $was -notcontains $_ })) {
                    $out += ('Remove-LocalGroupMember -Group {0} -Member {1}' -f (QS $g), (QS $m))
                }
                if (@($out).Count -eq 0) { $out += ('Get-LocalGroupMember -Group {0}' -f (QS $g)) }
            }
        }
        'listeners' {
            if ($k -match '^tcp/(\d+)$') {
                $out += ('Get-NetTCPConnection -State Listen -LocalPort {0} | Select-Object OwningProcess' -f $Matches[1])
                $out += ("New-NetFirewallRule -DisplayName 'CCDC block {0}' -Direction Inbound -LocalPort {0} -Protocol TCP -Action Block   # only if it is not scored" -f $Matches[1])
            }
        }
        'firewall' {
            if ($k -match '^rule:(.+)$') { $out += ('Disable-NetFirewallRule -DisplayName {0}' -f (QS $Matches[1])) }
            else { $out += '.\windows\harden.ps1 -Only Firewall -Apply' }
        }
        'shares' {
            if ($k -match '^share:(.+)$') {
                $out += ('Get-SmbShareAccess -Name {0}' -f (QS $Matches[1]))
                $out += ('Remove-SmbShare -Name {0} -Force     # the folder itself stays, as evidence' -f (QS $Matches[1]))
            }
        }
        'wmi' {
            if ($k -match '^wmi:([^\\]+)\\(.+)$') {
                $out += ("Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object {{ `$_.Consumer -match {0} -or `$_.Filter -match {0} }} | Remove-CimInstance" -f (QS $Matches[2]))
                $out += ("Get-CimInstance -Namespace root/subscription -ClassName {0} -Filter ""Name='{1}'"" | Remove-CimInstance" -f $Matches[1], $Matches[2])
            }
        }
        'defender' {
            if ($k -match '^exclusion:(path|proc|ext):(.+)$') {
                $flag = @{ path = 'ExclusionPath'; proc = 'ExclusionProcess'; ext = 'ExclusionExtension' }[$Matches[1]]
                $out += ('Remove-MpPreference -{0} {1}' -f $flag, (QS $Matches[2]))
            }
        }
        'files' {
            $out += ('Get-FileHash -LiteralPath {0}' -f (QS $k))
            $out += '# remove what RUNS it first (the service, task or Run key above); the file can then stay as evidence'
        }
    }
    return @($out)
}

# =============================================================================
# BLESS
# =============================================================================
if ($StableForSeconds -gt 0 -and -not $Bless) {
    Write-CcdcDie '-StableForSeconds is only valid with -Bless'
}
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
    $snap = Get-BoxSnapshot -Config $cfg

    if ($StableForSeconds -gt 0) {
        Write-Host ''
        Write-Host ('  first inventory captured; waiting {0}s for a quiet blessing window...' -f $StableForSeconds)
        Start-Sleep -Seconds $StableForSeconds
        $secondSnap = Get-BoxSnapshot -Config $cfg
        $changes = @(Compare-BoxSnapshots -First $snap -Second $secondSnap)
        if (@($changes).Count -gt 0) {
            $recorded = '  Dry run: no file was written.'
            if ($Apply) {
                $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
                $raceFile = Join-Path (Get-StateDir) ("baseline-bless-changed-$stamp.txt")
                Set-Content -LiteralPath $raceFile -Value $changes -Encoding UTF8
                $recorded = "  Recorded the changed rows in:`r`n      $raceFile"
            }
            Write-CcdcDie @"
the box changed during the $StableForSeconds-second blessing window. Nothing was frozen.

  This is exactly the gap the quiet window is meant to catch: inspect the
  changes, remove or explain them, then try again.
$recorded
"@
        }
        $snap = $secondSnap
        Write-Host ('  inventory stayed unchanged for {0}s; blessing that reviewed state.' -f $StableForSeconds) -ForegroundColor Green
    }

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
      .\windows\baseline.ps1 -Config $Config -Bless -StableForSeconds 20 -Apply

  Blessing on arrival freezes whatever they left behind as normal.
"@
    }
    $old = $null
    try {
        $old = Get-Content -LiteralPath $script:manifestFile -Raw | ConvertFrom-Json
    } catch {
        Write-CcdcDie "the baseline file is unreadable: $($_.Exception.Message)"
    }
    $new = Get-BoxSnapshot -Config $cfg

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
        $removal = @(Get-DriftRemoval -Item $found)
        if ($removal.Count -gt 0) {
            Write-Host ''
            Write-Host '  if this is NOT yours:' -ForegroundColor Yellow
            foreach ($line in $removal) { Write-Host ('    {0}' -f $line) }
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
        # A clean comparison clears the drift record; a stale one read later
        # (by sentry -Watch, or a person) would report changes long undone.
        if (Test-Path -LiteralPath $script:driftFile) { Remove-Item -LiteralPath $script:driftFile -Force -ErrorAction SilentlyContinue }
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
    Write-Host '       everything known about item N, and how to remove it if it is not yours'
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
Write-Host ('    .\windows\baseline.ps1 -Config {0} -Bless -StableForSeconds 20 -Apply     freeze this box' -f $Config)
Write-Host ('    .\windows\baseline.ps1 -Config {0} -Status           what changed since' -f $Config)
Write-Host ''
exit 1
