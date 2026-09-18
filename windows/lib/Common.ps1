<#
    Common.ps1 - the shared floor every Windows tool in this kit stands on.

    Dot-source it, never run it:
        . "$PSScriptRoot\lib\Common.ps1"

    THREE THINGS TO KNOW BEFORE READING FURTHER

    1. Windows PowerShell 5.1 is the target. That is what ships with Windows 10
       and Server 2019, which is what the practice lab ran, and it is what you
       will get on a box you did not build. No ternaries, no ?? operator, no
       ForEach-Object -Parallel, no Get-LocalUser on a domain controller. If it
       does not run in 5.1 it does not run when it matters.

    2. The config file is THE SAME FILE the Linux kit uses. One worksheet, one
       format, both boxes - because a competition where you keep two different
       config formats straight at hour four is a competition you lose to your
       own notes. KEY="value", # comments, lists separated by whitespace.

    3. Nothing mutates without -Apply. Every tool prints what it WOULD do and
       exits. That is not timidity: the fastest way to lose uptime points is a
       defender's own command, and the second fastest is a script that ran
       before you finished reading it.
#>

Set-StrictMode -Version 2.0

# --- where things live -------------------------------------------------------
# ProgramData, not the user profile: a scheduled task running as SYSTEM has to
# be able to read and write it, and the operator's profile may not exist by the
# time it runs.
# Overridable by CCDC_WIN_ROOT for two reasons. The self-test needs somewhere
# to work that is not the real box, and a box whose system drive is not C: is
# not a hypothetical - a Server image built from a template often is not.
if ($env:CCDC_WIN_ROOT) {
    $script:CcdcRoot = $env:CCDC_WIN_ROOT
} elseif ($env:ProgramData) {
    $script:CcdcRoot = Join-Path $env:ProgramData 'CCDC'
} else {
    $script:CcdcRoot = 'C:\ProgramData\CCDC'
}

function Get-CcdcPath {
    param([Parameter(Mandatory)][string]$Leaf)
    Join-Path $script:CcdcRoot $Leaf
}

function Initialize-CcdcRoot {
    foreach ($d in @($script:CcdcRoot,
                     (Get-CcdcPath 'evidence'),
                     (Get-CcdcPath 'state'),
                     (Get-CcdcPath 'backup'))) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    # Administrators + SYSTEM only. Evidence can contain credential material
    # from a compromised box, and a world-readable evidence directory is a
    # second finding rather than a record of the first.
    try {
        $acl = Get-Acl -LiteralPath $script:CcdcRoot
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
        foreach ($id in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $script:CcdcRoot -AclObject $acl
    } catch {
        # Only worth saying on a real Windows box. Where Get-Acl does not exist
        # at all we are in the self-test harness, and saying it every run
        # teaches the operator to ignore the warning that matters.
        if (Test-CcdcHasCommand -Name 'Get-Acl') {
            Write-CcdcWarn "could not lock down $($script:CcdcRoot): $($_.Exception.Message)"
        }
    }
}

# --- talking to the operator -------------------------------------------------
# Colour is a hint, never the only carrier: the report is read over RDP, in a
# console that may have no colour at all, and printed on paper in the real
# event. Every severity says its own name.

function Write-CcdcInfo  { param([string]$Message) Write-Host "ccdc: $Message" }
function Write-CcdcWarn  { param([string]$Message) Write-Host "ccdc: warning: $Message" -ForegroundColor Yellow }
function Write-CcdcErr   { param([string]$Message) Write-Host "ccdc: error: $Message" -ForegroundColor Red }
function Write-CcdcDie   {
    param([string]$Message)
    Write-CcdcErr $Message
    exit 1
}

function Write-CcdcLog {
    param([Parameter(Mandatory)][string]$Message,
          [string]$LogName = 'ccdc.log')
    $line = '{0:yyyy-MM-ddTHH:mm:ssZ} {1}' -f (Get-Date).ToUniversalTime(), $Message
    try { Add-Content -LiteralPath (Get-CcdcPath $LogName) -Value $line -Encoding UTF8 } catch { }
}

# --- elevation ---------------------------------------------------------------
# Checked up front and said plainly. Half of these commands return partial or
# silently empty results without elevation rather than failing - Get-LocalUser
# works, Get-LocalGroupMember on a domain-joined box often does not, reading the
# Security log does not - and a report that is quietly missing half the box is
# worse than one that refused to run.

function Test-CcdcAdmin {
    if ($env:CCDC_WIN_FAKE_ADMIN) { return $true }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Assert-CcdcAdmin {
    if (-not (Test-CcdcAdmin)) {
        Write-CcdcDie @"
this must run elevated, and it is not.

  Close this window. Open PowerShell with Start -> type 'powershell' ->
  Ctrl+Shift+Enter (or right-click -> Run as administrator), then run it again.

  Not a formality: without elevation this reads an empty Security log, cannot
  see other users' scheduled tasks, and returns a shorter list of services -
  so it would report a clean box that is not clean.
"@
    }
}

# --- config ------------------------------------------------------------------
# The same KEY="value" file the Linux tools read. Parsed rather than executed:
# this file may have been edited by someone who is not you.

function Import-CcdcConfig {
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { Write-CcdcDie "no config given (-Config FILE)" }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-CcdcDie @"
config file not found: $Path

  Copy the template and fill it in from the team packet:
      copy .\config\example.env C:\ProgramData\CCDC\ccdc.env
      notepad C:\ProgramData\CCDC\ccdc.env

  It is the same file the Linux box uses. Fill it in once.
"@
    }

    $cfg = @{}
    $key = $null
    $buf = $null

    foreach ($raw in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $line = $raw

        # Inside a multi-line value (CCDC_HASH_FILES="..." spanning lines).
        if ($null -ne $buf) {
            if ($line -match '^(.*)"\s*$') {
                $buf += "`n" + $Matches[1]
                $cfg[$key] = $buf.Trim()
                $key = $null; $buf = $null
            } else {
                $buf += "`n" + $line
            }
            continue
        }

        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -notmatch '^(?<k>[A-Za-z_][A-Za-z0-9_]*)=(?<v>.*)$') { continue }

        $k = $Matches['k']
        $v = $Matches['v']

        if ($v -match '^"(.*)"\s*(#.*)?$') {
            $cfg[$k] = $Matches[1]
        } elseif ($v.StartsWith('"')) {
            $key = $k
            $buf = $v.Substring(1)
        } else {
            # Unquoted: strip a trailing comment, then whitespace.
            $cfg[$k] = ($v -replace '\s+#.*$', '').Trim()
        }
    }
    if ($null -ne $buf) { $cfg[$key] = $buf.Trim() }

    $cfg['_ConfigPath'] = (Resolve-Path -LiteralPath $Path).Path
    return $cfg
}

function Get-CcdcValue {
    param([Parameter(Mandatory)][hashtable]$Config,
          [Parameter(Mandatory)][string]$Name,
          [string]$Default = '')
    if ($Config.ContainsKey($Name) -and -not [string]::IsNullOrWhiteSpace([string]$Config[$Name])) {
        return [string]$Config[$Name]
    }
    return $Default
}

# A whitespace/newline separated list, as an array with the blanks dropped.
function Get-CcdcList {
    param([Parameter(Mandatory)][hashtable]$Config,
          [Parameter(Mandatory)][string]$Name)
    $v = Get-CcdcValue -Config $Config -Name $Name
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    return @($v -split '[\s,]+' | Where-Object { $_ -ne '' })
}

function Test-CcdcListContains {
    param([string]$Needle, [string[]]$List)
    if ([string]::IsNullOrWhiteSpace($Needle)) { return $false }
    foreach ($i in $List) { if ($i -eq $Needle) { return $true } }
    return $false
}

# The packet lists. Refusing to act while these are empty is deliberate: an
# empty protect list does not mean "nothing is protected", it means nobody has
# told the tool what is scored, and acting on that is how you lock the account
# the scoring engine logs in with.
function Assert-CcdcPacketEntered {
    param([Parameter(Mandatory)][hashtable]$Config)
    $u = Get-CcdcList -Config $Config -Name 'CCDC_ALLOWED_USERS'
    $s = Get-CcdcList -Config $Config -Name 'CCDC_WINDOWS_SERVICES'
    if ($u.Count -eq 0 -or $s.Count -eq 0) {
        Write-CcdcDie @"
refusing to act: the packet lists are empty.

  CCDC_ALLOWED_USERS     accounts that are supposed to exist (found: $($u.Count))
  CCDC_WINDOWS_SERVICES  services you are scored on        (found: $($s.Count))

  in $($Config['_ConfigPath'])

  An empty list does not mean "nothing is protected". It means nothing has told
  this tool what is scored - and the account you did not mean to disable is
  usually the one the scoring engine logs in with.

  Read it off the team packet. It takes two minutes and it is the difference
  between a tool that helps and a tool that takes the box down.
"@
    }
}

# --- findings ----------------------------------------------------------------
# One line per finding: SEV|check|subject|description. Identical to the Linux
# kit's format on purpose, so the two boxes produce one vocabulary and the
# incident report writes itself from both.

$script:CcdcFindings = New-Object System.Collections.ArrayList

function Add-CcdcFinding {
    param(
        [Parameter(Mandatory)][ValidateSet('RED','AMBER','NOTE')][string]$Severity,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Description
    )
    # A pipe in an attacker-controlled subject would split the record and hand
    # the remediation side a different target than the one detected. Findings
    # whose subject cannot be represented are reported to the human and kept
    # out of the machine queue.
    if ($Subject -match '[\|\r\n]') {
        Write-CcdcWarn "omitted a $Check finding from the machine queue: its subject contains a delimiter. Inspect it by hand: $Subject"
        return
    }
    [void]$script:CcdcFindings.Add([pscustomobject]@{
        Severity = $Severity; Check = $Check; Subject = $Subject; Description = $Description
    })
}

function Get-CcdcFindings { return $script:CcdcFindings }
function Clear-CcdcFindings { $script:CcdcFindings = New-Object System.Collections.ArrayList }

function Save-CcdcFindings {
    param([string]$Path = (Get-CcdcPath 'state\findings.txt'))
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Written to a temporary file and moved into place, so a reader never sees
    # half a pass: the queue is either the complete previous one or this one.
    $tmp = "$Path.tmp"
    $script:CcdcFindings | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.Severity, $_.Check, $_.Subject, $_.Description
    } | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# --- evidence ----------------------------------------------------------------

function New-CcdcEvidenceDir {
    param([string]$Label = 'pass')
    Initialize-CcdcRoot
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $dir = Get-CcdcPath ("evidence\$Label-$stamp-$PID")
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Save-CcdcEvidence {
    param([Parameter(Mandatory)][string]$Dir,
          [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][scriptblock]$Command)
    $out = Join-Path $Dir "$Name.txt"
    try { & $Command 2>&1 | Out-String -Width 4096 | Set-Content -LiteralPath $out -Encoding UTF8 }
    catch { $_ | Out-String | Set-Content -LiteralPath $out -Encoding UTF8 }
}

# Copy a file into an evidence case before anything touches it, and return
# where it went. Every destructive action in this kit calls this first.
function Copy-CcdcIntoCase {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$CaseDir)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $dest = Join-Path $CaseDir ('{0}-{1}' -f (Get-Random -Maximum 99999), (Split-Path -Leaf $Path))
    try { Copy-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop; return $dest }
    catch { Write-CcdcWarn "could not preserve $Path : $($_.Exception.Message)"; return $null }
}

# --- are the scored services still answering? --------------------------------
#
# Called after anything that could take one down, so a wrong call reverses
# itself in seconds rather than at the next scoring round. It asks three ways
# because they fail differently: a service can be Running while its port is
# shut, and a port can accept a connection while the site behind it 500s.
#
# It cannot tell you whether the SCORER can reach you. Nothing on the box can.
# Check that from somewhere else.

function Test-CcdcScoredServices {
    param([Parameter(Mandatory)][hashtable]$Config,
          [int]$TimeoutSeconds = 12)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    foreach ($svc in (Get-CcdcList -Config $Config -Name 'CCDC_WINDOWS_SERVICES')) {
        $ok = $false
        do {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($null -eq $s) { $ok = $true; break }   # not installed here: not our business
            if ($s.Status -eq 'Running') { $ok = $true; break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        if (-not $ok) { Write-CcdcWarn "scored service $svc is not running"; return $false }
    }

    foreach ($chk in (Get-CcdcTcpChecks -Config $Config)) {
        $ok = $false
        do {
            if (Test-CcdcTcpPort -ComputerName $chk.Host -Port $chk.Port) { $ok = $true; break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        if (-not $ok) { Write-CcdcWarn "scored TCP check failed: $($chk.Host):$($chk.Port)"; return $false }
    }

    foreach ($url in (Get-CcdcHttpChecks -Config $Config)) {
        $ok = $false
        do {
            try {
                $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { $ok = $true; break }
            } catch { }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        if (-not $ok) { Write-CcdcWarn "scored HTTP check failed: $url"; return $false }
    }
    return $true
}

# Test-NetConnection is far too slow to call in a loop and prints a progress
# bar into the report. A raw socket with an explicit timeout is what is wanted.
function Test-CcdcTcpPort {
    param([Parameter(Mandatory)][string]$ComputerName,
          [Parameter(Mandatory)][int]$Port,
          [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch { return $false }
    finally { $client.Close() }
}

# Accept both the documented name|host|port|service form and the bare
# host:port people actually type. Permissive about shape, strict about
# content - a port that is not a number is a typo, and a typo that silently
# disables a check is how a scored service goes down unnoticed.
function Get-CcdcTcpChecks {
    param([Parameter(Mandatory)][hashtable]$Config)
    $out = @()
    foreach ($tok in (Get-CcdcList -Config $Config -Name 'CCDC_TCP_CHECKS')) {
        if ($tok -match '\|') {
            $f = $tok -split '\|'
            if ($f.Count -lt 3) { Write-CcdcWarn "CCDC_TCP_CHECKS: '$tok' wants name|host|port|service"; continue }
            $h = $f[1]; $p = $f[2]
        } elseif ($tok -match '^(?<h>.+):(?<p>[^:]+)$') {
            $h = $Matches['h']; $p = $Matches['p']
        } else {
            Write-CcdcWarn "CCDC_TCP_CHECKS: cannot read '$tok' as host:port or name|host|port|service"; continue
        }
        if ($p -notmatch '^\d+$') { Write-CcdcWarn "CCDC_TCP_CHECKS: '$p' is not a port number in '$tok'"; continue }
        $out += [pscustomobject]@{ Host = $h; Port = [int]$p }
    }
    return $out
}

function Get-CcdcHttpChecks {
    param([Parameter(Mandatory)][hashtable]$Config)
    $out = @()
    foreach ($tok in (Get-CcdcList -Config $Config -Name 'CCDC_HTTP_CHECKS')) {
        $u = $tok
        if ($tok -match '\|') { $u = ($tok -split '\|')[1] }
        if ($u -notmatch '^https?://') { Write-CcdcWarn "CCDC_HTTP_CHECKS: '$tok' is not an http:// or https:// URL"; continue }
        $out += $u
    }
    return $out
}

# --- the apply boundary ------------------------------------------------------

function Invoke-CcdcAction {
    param([Parameter(Mandatory)][string]$Describe,
          [Parameter(Mandatory)][scriptblock]$Action,
          [Parameter(Mandatory)][bool]$Apply)
    if (-not $Apply) {
        Write-Host ("    [would] {0}" -f $Describe)
        return $true
    }
    try {
        & $Action | Out-Null
        Write-Host ("    [done]  {0}" -f $Describe)
        Write-CcdcLog "applied: $Describe"
        return $true
    } catch {
        Write-CcdcErr ("FAILED  {0}`n            {1}" -f $Describe, $_.Exception.Message)
        Write-CcdcLog "FAILED: $Describe :: $($_.Exception.Message)"
        return $false
    }
}

# --- domain awareness --------------------------------------------------------
# Get-LocalUser on a domain controller throws, because a DC has no local
# account database. Half the account checks in this kit have to ask a different
# question there, and asking the wrong one returns an error the operator reads
# as "no findings".

function Get-CcdcMachineRole {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        switch ($cs.DomainRole) {
            0 { return 'StandaloneWorkstation' }
            1 { return 'MemberWorkstation' }
            2 { return 'StandaloneServer' }
            3 { return 'MemberServer' }
            4 { return 'BackupDomainController' }
            5 { return 'PrimaryDomainController' }
            default { return 'Unknown' }
        }
    } catch { return 'Unknown' }
}

function Test-CcdcIsDomainController {
    $r = Get-CcdcMachineRole
    return ($r -eq 'BackupDomainController' -or $r -eq 'PrimaryDomainController')
}

function Test-CcdcHasCommand {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

# --- what box did we actually land on? ---------------------------------------
#
# The practice lab was Windows 10. The tryout box is not announced, and "server
# or workstation, domain-joined or not, 2016 through 11" is a wide enough range
# that guessing is not a strategy. So every tool asks first, prints the answer,
# and says which checks it cannot perform here - because a check that silently
# returned nothing reads exactly like a check that found nothing.
#
# Degrade honestly, never pretend.

function Get-CcdcBoxFacts {
    $facts = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $facts['OS']      = $os.Caption
        $facts['Version'] = '{0} (build {1})' -f $os.Version, $os.BuildNumber
        $facts['Installed'] = if ($os.InstallDate) { ([datetime]$os.InstallDate).ToString('yyyy-MM-dd HH:mm') } else { 'unknown' }
        $facts['LastBoot']  = if ($os.LastBootUpTime) { ([datetime]$os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm') } else { 'unknown' }
    } catch {
        $facts['OS'] = 'unknown'; $facts['Version'] = 'unknown'
        $facts['Installed'] = 'unknown'; $facts['LastBoot'] = 'unknown'
    }
    $facts['Host']      = $env:COMPUTERNAME
    $facts['Role']      = Get-CcdcMachineRole
    try { $facts['Domain'] = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { $facts['Domain'] = 'unknown' }
    $facts['PSVersion'] = $PSVersionTable.PSVersion.ToString()
    $facts['Elevated']  = Test-CcdcAdmin

    # Module availability, asked once. Every one of these is missing somewhere
    # that matters: NetSecurity on very old builds, Defender on Server core and
    # on boxes where a third-party AV replaced it, ScheduledTasks almost never
    # but ActiveDirectory only on a DC or with RSAT installed.
    # CCDC_WIN_FAKE_MODULES exists for the self-test, which runs on a machine
    # with none of these modules. Without it every module-gated check is
    # skipped and the test proves only that the skip path works.
    if ($env:CCDC_WIN_FAKE_MODULES) {
        foreach ($m in 'HasNetSecurity','HasNetTCPIP','HasDefender','HasScheduledTasks','HasLocalAccounts','HasActiveDirectory') {
            $facts[$m] = $true
        }
        return $facts
    }
    $facts['HasNetSecurity']    = $null -ne (Get-Module -ListAvailable -Name NetSecurity     -ErrorAction SilentlyContinue)
    $facts['HasNetTCPIP']       = $null -ne (Get-Module -ListAvailable -Name NetTCPIP        -ErrorAction SilentlyContinue)
    $facts['HasDefender']       = $null -ne (Get-Module -ListAvailable -Name Defender        -ErrorAction SilentlyContinue)
    $facts['HasScheduledTasks'] = $null -ne (Get-Module -ListAvailable -Name ScheduledTasks  -ErrorAction SilentlyContinue)
    $facts['HasLocalAccounts']  = $null -ne (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue)
    $facts['HasActiveDirectory']= $null -ne (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
    return $facts
}

# The gaps, in the operator's words rather than a module list. Empty array
# means every check in this kit can run here.
function Get-CcdcCapabilityGaps {
    param([hashtable]$Facts)
    if (-not $Facts) { $Facts = Get-CcdcBoxFacts }
    $gaps = @()

    if (-not $Facts['Elevated']) {
        $gaps += 'NOT ELEVATED - the Security event log, other users'' scheduled tasks and full service detail are all unreadable. Re-run as administrator.'
    }
    if (-not $Facts['HasNetSecurity']) {
        $gaps += 'no NetSecurity module - firewall profiles and rules cannot be read or set from PowerShell here. Use: netsh advfirewall show allprofiles'
    }
    if (-not $Facts['HasNetTCPIP']) {
        $gaps += 'no NetTCPIP module - listening ports come from netstat instead, without the owning process name.'
    }
    if (-not $Facts['HasDefender']) {
        $gaps += 'no Defender module - exclusions and real-time protection cannot be checked from PowerShell. Check the GUI: Start -> Windows Security. A MISSING Defender module can itself mean a third-party AV, or that someone removed it.'
    }
    if (-not $Facts['HasScheduledTasks']) {
        $gaps += 'no ScheduledTasks module - scheduled task persistence is read with schtasks.exe instead, in less detail.'
    }
    if ((Test-CcdcIsDomainController) -and -not $Facts['HasActiveDirectory']) {
        $gaps += 'this is a DOMAIN CONTROLLER with no ActiveDirectory module - domain accounts cannot be audited from here. Install RSAT, or audit from a box that has it.'
    }
    if ((Test-CcdcIsDomainController)) {
        $gaps += 'this is a DOMAIN CONTROLLER - it has NO local accounts. Every account here is a domain account, and disabling one affects every machine in the domain.'
    }
    return $gaps
}

function Write-CcdcBoxBanner {
    param([hashtable]$Facts)
    if (-not $Facts) { $Facts = Get-CcdcBoxFacts }
    Write-Host ''
    Write-Host ('  {0}   {1}' -f $Facts['Host'], $Facts['OS'])
    Write-Host ('  {0} - {1}, PowerShell {2}{3}' -f $Facts['Version'], $Facts['Role'],
                $Facts['PSVersion'], $(if ($Facts['Elevated']) { ', elevated' } else { ', NOT elevated' }))
    if ($Facts['Domain'] -and $Facts['Domain'] -ne 'WORKGROUP') {
        Write-Host ('  domain: {0}' -f $Facts['Domain'])
    }
    Write-Host ('  built {0}, last booted {1}' -f $Facts['Installed'], $Facts['LastBoot'])

    $gaps = Get-CcdcCapabilityGaps -Facts $Facts
    if ($gaps.Count -gt 0) {
        Write-Host ''
        Write-Host '  WHAT THIS BOX WILL NOT LET ME CHECK:' -ForegroundColor Yellow
        foreach ($g in $gaps) { Write-Host ("    - {0}" -f $g) -ForegroundColor Yellow }
        Write-Host ''
        Write-Host '  Everything below is what remains. A check that cannot run is'
        Write-Host '  listed here rather than silently passing.'
    }
    Write-Host ''
}

# Was this box built before the event started? Anything created after the image
# was laid down is a different claim from something that shipped with it, and
# almost every Windows persistence check turns on that difference.
#
# The install date is the marker: it needs no package database, it is set once,
# and nothing an attacker does in six hours changes it.
function Get-CcdcBoxBuiltTime {
    try { return ([datetime](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).InstallDate) }
    catch { return (Get-Date).AddYears(-1) }
}

function Test-CcdcNewerThanBox {
    param([datetime]$When)
    if (-not $When) { return $false }
    return $When -gt (Get-CcdcBoxBuiltTime)
}
