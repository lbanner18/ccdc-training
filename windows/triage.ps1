<#
.SYNOPSIS
    What should alarm you on this Windows box, right now. Read-only.

.DESCRIPTION
    The Windows counterpart to linux/triage.sh, and it answers the same
    question in the same order: what is wrong, worst first, with the command
    that fixes each thing printed underneath it.

    READ-ONLY. It writes evidence and a findings file under C:\ProgramData\CCDC
    and changes nothing else. There is no -Apply, on purpose: this is the tool
    you run while you are still deciding.

    Severity means what it says.

      RED    act on this now. Something is here that nothing explains, and the
             ordinary explanations have already been checked and ruled out.
      AMBER  this may well be yours. It is reported because the box cannot
             tell, and you can.
      NOTE   context. Not a problem by itself.

    The ranking is not cosmetic. You have six hours, half your points are
    injects, and the single most expensive thing you can do is spend twenty
    minutes on an AMBER while a RED is still live.

.EXAMPLE
    .\triage.ps1 -Config C:\ProgramData\CCDC\ccdc.env
.EXAMPLE
    .\triage.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Quiet   # findings file only
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Quiet,
    [switch]$NoEvidence
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']
Initialize-CcdcRoot
Clear-CcdcFindings

$facts     = Get-CcdcBoxFacts
$builtTime = Get-CcdcBoxBuiltTime
$allowedUsers    = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS'
$allowedTcpPorts = @(Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_TCP_PORTS')
# Scored RDP is accounted for by CCDC_RDP_SCORED, read exactly as harden.ps1
# reads it: only "0" means not scored. Without this, triage told the operator to
# add a Block rule for 3389 - and a Block rule beats every Allow, so pasting it
# took down the scored service and the operator's own session with it.
if ((Get-CcdcValue -Config $cfg -Name 'CCDC_RDP_SCORED') -ne '0') { $allowedTcpPorts += '3389' }
$allowedUdpPorts = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_UDP_PORTS'
$scoredServices  = Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_SERVICES'

$script:checks = 0
$script:redCount = 0
$script:amberCount = 0

# --- how a finding reaches the screen ----------------------------------------
# Buffered by severity, not printed as found. A busy box interleaves them, and
# the "run this" block under one heading then sits beneath a different
# finding's heading - which on a screen you are reading in a hurry is not a
# cosmetic problem.
$script:redBuf   = New-Object System.Collections.ArrayList
$script:amberBuf = New-Object System.Collections.ArrayList
$script:noteBuf  = New-Object System.Collections.ArrayList

function Begin-Check { param([string]$Name) $script:checks++ }

function Report {
    param(
        [ValidateSet('RED','AMBER','NOTE')][string]$Severity,
        [string]$Check,
        [string]$Subject,
        [string]$Description,
        [string[]]$Detail = @(),
        [string[]]$Fix = @(),
        [string]$Card = ''
    )
    Add-CcdcFinding -Severity $Severity -Check $Check -Subject $Subject -Description $Description

    $b = New-Object System.Collections.ArrayList
    [void]$b.Add(('  {0,-6} {1,-16} {2}' -f $Severity, $Check, $Subject))
    [void]$b.Add(('         {0}' -f $Description))
    foreach ($d in $Detail) { [void]$b.Add(('         {0}' -f $d)) }
    if (@($Fix).Count -gt 0) {
        [void]$b.Add('         ---- run this ----------------------------------------')
        foreach ($f in $Fix) { [void]$b.Add(('           {0}' -f $f)) }
    }
    if ($Card) { [void]$b.Add(('         more: playbooks\windows-cards.md  {0}' -f $Card)) }
    [void]$b.Add('')

    switch ($Severity) {
        'RED'   { $script:redCount++;   foreach ($l in $b) { [void]$script:redBuf.Add($l) } }
        'AMBER' { $script:amberCount++; foreach ($l in $b) { [void]$script:amberBuf.Add($l) } }
        'NOTE'  { foreach ($l in $b) { [void]$script:noteBuf.Add($l) } }
    }
}

function Clean { param([string]$Message) if (-not $Quiet) { Write-Host ('  ok     {0}' -f $Message) } }

# Quote a value for pasting into a PowerShell command. An attacker picks the
# account and file names on this box; a name with a space or a quote in it must
# not turn a printed command into a different command.
function Q { param([string]$s) return ("'" + ($s -replace "'", "''") + "'") }

# PSPath comes back as 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\...',
# which works but is unreadable in a command you are about to paste under time
# pressure. Print the drive form people actually recognise.
function ConvertTo-CcdcRegPath {
    param([string]$Path)
    $p = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $p = $p -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
    $p = $p -replace '^HKEY_CURRENT_USER', 'HKCU:'
    $p = $p -replace '^HKEY_USERS', 'HKU:'
    $p = $p -replace '^HKEY_CLASSES_ROOT', 'HKCR:'
    return $p
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host ('triage.ps1 - what should alarm you on {0}, right now' -f $facts['Host'])
    Write-Host ('read-only. {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-CcdcBoxBanner -Facts $facts
}

# =============================================================================
# 1. ACCOUNTS - who can log in, and who can become administrator
#
# Stated first in the course material and it is right: "Generally the #1
# priority is to change passwords. The red team knows the default passwords."
# Everything else on this list is an attacker keeping access they already have.
# This section is about the access itself.
# =============================================================================

Begin-Check 'administrators'
$isDC = Test-CcdcIsDomainController
$adminMembers = @()
try {
    $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
} catch {
    # A domain controller has no local groups, and some builds fail this call
    # when a member SID no longer resolves. net.exe answers anyway.
    try {
        $raw = & net localgroup Administrators 2>$null
        $inList = $false
        foreach ($l in $raw) {
            if ($l -match '^-{3,}') { $inList = $true; continue }
            if ($l -match '^The command completed') { $inList = $false; continue }
            if ($inList -and $l.Trim()) { $adminMembers += [pscustomobject]@{ Name = $l.Trim(); ObjectClass = 'Unknown' } }
        }
    } catch { }
}

if (@($adminMembers).Count -eq 0) {
    Report -Severity 'AMBER' -Check 'admincheck' -Subject 'Administrators' `
        -Description 'could not read the Administrators group' `
        -Detail @('This is the single most important group on the box and nothing here could list it.',
                  'Do it by hand before you go any further.') `
        -Fix @('net localgroup Administrators') -Card 'CARD W1'
} else {
    $unexpected = @()
    foreach ($m in $adminMembers) {
        $short = ($m.Name -split '\\')[-1]
        if (Test-CcdcListContains -Needle $short -List $allowedUsers) { continue }
        # Domain Admins nested in local Administrators is how a domain-joined
        # box is supposed to work; reporting it every pass teaches you to skim.
        if ($short -match '^(Domain Admins|Enterprise Admins|Administrator)$') { continue }
        $unexpected += $m.Name
    }
    if (@($unexpected).Count -gt 0) {
        foreach ($u in $unexpected) {
            $short = ($u -split '\\')[-1]
            Report -Severity 'RED' -Check 'rogueadmin' -Subject $u `
                -Description 'has administrator rights and is not in the packet' `
                -Detail @('Administrator on this box means administrator over everything on it,',
                          'including the tools you are using to look for them.') `
                -Fix @(("net localgroup Administrators {0} /delete" -f $short),
                       ("net user {0}                  # confirm what it is first" -f $short),
                       '# if it IS supposed to be here, add it to CCDC_ALLOWED_USERS in your config') `
                -Card 'CARD W1'
        }
    } else {
        Clean ("Administrators group holds only accounts the packet names ({0})" -f @($adminMembers).Count)
    }
}

# On a domain controller the local Administrators group holds GROUPS - Domain
# Admins, Enterprise Admins - and the check above skips those by design. So an
# account added to Domain Admins, which is control of the whole domain and the
# first thing anyone does with a DC, was invisible: measured on a 2016 DC with
# a planted member, this check said "only accounts the packet names".
if ($isDC) {
    Begin-Check 'domainadmins'
    $adLoaded = $true
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { $adLoaded = $false }
    if (-not $adLoaded) {
        Report -Severity 'AMBER' -Check 'admincheck' -Subject 'ActiveDirectory' `
            -Description 'domain controller, but the ActiveDirectory module would not load - domain groups were NOT checked' `
            -Fix @('net group "Domain Admins" /domain', 'net group "Enterprise Admins" /domain') -Card 'CARD W1'
    } else {
        $privGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
                        'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
                        'DnsAdmins', 'Group Policy Creator Owners')
        $held = @{}
        foreach ($g in $privGroups) {
            $members = @()
            try { $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }) } catch { continue }
            foreach ($m in $members) {
                $sam = [string]$m.SamAccountName
                if ($sam -eq 'Administrator' -or (Test-CcdcListContains -Needle $sam -List $allowedUsers)) { continue }
                if (-not $held.ContainsKey($sam)) { $held[$sam] = New-Object System.Collections.ArrayList }
                [void]$held[$sam].Add($g)
            }
        }
        foreach ($sam in @($held.Keys | Sort-Object)) {
            $direct = @()
            try {
                $direct = @(Get-ADPrincipalGroupMembership -Identity $sam -ErrorAction Stop |
                            Where-Object { $privGroups -contains $_.Name } | ForEach-Object { $_.Name })
            } catch { }
            $fix = New-Object System.Collections.ArrayList
            foreach ($g in $direct) { [void]$fix.Add(("Remove-ADGroupMember -Identity '{0}' -Members {1} -Confirm:`$false" -f $g, $sam)) }
            [void]$fix.Add(("Disable-ADAccount -Identity {0}      # keep it as evidence; do not delete" -f $sam))
            [void]$fix.Add(("Get-ADUser {0} -Properties whenCreated,MemberOf    # when, and what else" -f $sam))
            Report -Severity 'RED' -Check 'domainadmin' -Subject $sam `
                -Description ('holds {0} and is not in the packet' -f (($held[$sam] | Sort-Object -Unique) -join ', ')) `
                -Detail @('On a domain controller this is control of the whole domain: every',
                          'account, the scored AD service, and the tools you are using now.') `
                -Fix @($fix) -Card 'CARD W1'
        }
        if ($held.Count -eq 0) { Clean 'no privileged domain group holds an account the packet does not name' }

        Begin-Check 'domainusers'
        $extra = 0
        foreach ($u in @(Get-ADUser -Filter 'Enabled -eq $true' -Properties whenCreated -ErrorAction SilentlyContinue)) {
            $sam = [string]$u.SamAccountName
            if ($sam -in @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount')) { continue }
            if (Test-CcdcListContains -Needle $sam -List $allowedUsers) { continue }
            $extra++
            $new = ($u.whenCreated -and (Test-CcdcNewerThanBox -When $u.whenCreated))
            Report -Severity $(if ($new) { 'RED' } else { 'AMBER' }) -Check 'domainuser' -Subject $sam `
                -Description ('enabled domain account the packet does not name (created {0})' -f $u.whenCreated.ToString('yyyy-MM-dd HH:mm')) `
                -Detail @('The packet lists every account these devices should have.',
                          'Disable, do not delete: the account is evidence for the incident report.') `
                -Fix @(("Get-ADUser {0} -Properties whenCreated,MemberOf,LastLogonDate" -f $sam),
                       ("Disable-ADAccount -Identity {0}" -f $sam),
                       '# if it IS the packet''s, add it to CCDC_ALLOWED_USERS in your config') `
                -Card 'CARD W1'
        }
        if ($extra -eq 0) { Clean 'every enabled domain account is one the packet names' }
    }
}

Begin-Check 'localusers'
$localUsers = @()
if (-not $isDC) {
    try { $localUsers = @(Get-LocalUser -ErrorAction Stop) } catch { }
}
if (@($localUsers).Count -gt 0) {
    foreach ($u in $localUsers) {
        if (-not $u.Enabled) { continue }
        $short = $u.Name

        # An account that appeared after the image was laid down.
        if ($u.PSObject.Properties.Name -contains 'PasswordLastSet' -and $u.PasswordLastSet -and (Test-CcdcNewerThanBox -When $u.PasswordLastSet)) {
            if (-not (Test-CcdcListContains -Needle $short -List $allowedUsers)) {
                Report -Severity 'RED' -Check 'newuser' -Subject $short `
                    -Description ('enabled account whose password was set AFTER this box was built ({0})' -f $u.PasswordLastSet.ToString('yyyy-MM-dd HH:mm')) `
                    -Detail @('Either somebody created it during the event, or somebody changed its',
                              'password during the event. Both are worth five minutes right now.') `
                    -Fix @(("net user {0}" -f $short),
                           ("net user {0} *                 # set a password only you know" -f $short),
                           ("net user {0} /active:no        # or take it out of service" -f $short)) `
                    -Card 'CARD W1'
                continue
            }
        }

        # Blank-password logon is still possible on a stock Windows 10 image.
        if ($u.PSObject.Properties.Name -contains 'PasswordRequired' -and -not $u.PasswordRequired) {
            Report -Severity 'RED' -Check 'nopassword' -Subject $short `
                -Description 'enabled account that does not require a password' `
                -Detail @('It may have no password at all, and even if it has one, anyone who can',
                          'reset it can make it blank. New-LocalUser leaves this flag off by default.') `
                -Fix @(("net user {0} /passwordreq:yes" -f $short),
                       ("# if it has no password yet, also:  net user {0} *   (prompted, not echoed)" -f $short)) `
                -Card 'CARD W1'
        }
    }
    Clean ("{0} local account(s) reviewed" -f @($localUsers).Count)
}

Begin-Check 'guest'
try {
    $g = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    if ($g.Enabled) {
        Report -Severity 'RED' -Check 'guest' -Subject 'Guest' `
            -Description 'the Guest account is enabled' `
            -Detail @('It is disabled on every stock image. Enabled means somebody enabled it.') `
            -Fix @('net user Guest /active:no') -Card 'CARD W1'
    } else { Clean 'Guest account is disabled' }
} catch { }

# The scored users have to keep working. This is uptime, not hardening: the
# course notes say it outright - "We have scored users in addition to scored
# services. We have to make sure scoring users are available." An account the
# red team disables or locks out costs points exactly like a stopped service,
# and nothing else on this box is watching for it.
Begin-Check 'scoreduser'
foreach ($name in $allowedUsers) {
    if ($name -eq 'SYSTEM') { continue }
    $u = $null
    try { $u = Get-LocalUser -Name $name -ErrorAction Stop } catch { }
    if ($null -eq $u) {
        if (-not $isDC) {
            Report -Severity 'AMBER' -Check 'scoreduser' -Subject $name `
                -Description 'named in the packet but not a local account here' `
                -Detail @('Either it is a domain account (fine, check there), or it is gone.') `
                -Fix @(("net user {0}" -f $name), ("net user {0} /domain" -f $name)) -Card 'CARD W1'
        }
        continue
    }
    if (-not $u.Enabled) {
        Report -Severity 'RED' -Check 'scoreduser' -Subject $name `
            -Description 'a SCORED account is disabled - this costs uptime points right now' `
            -Detail @('The packet says this account has to work. It does not.',
                      'Turn it back on before you do anything else on this list.') `
            -Fix @(("net user {0} /active:yes" -f $name)) -Card 'CARD W1'
    }
}
Clean ("{0} scored account(s) checked for availability" -f @($allowedUsers).Count)

# =============================================================================
# 2. SERVICES - the thing you are scored on, and a favourite place to hide
#
# A service is the most durable foothold on Windows: it survives reboot, it
# runs as SYSTEM by default, and it sits in a list nobody reads because it is
# four hundred entries long. So do not read the list. Ask three questions that
# a legitimate service always answers the same way.
# =============================================================================

Begin-Check 'services'
$services = @()
try { $services = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch { }

if (@($services).Count -eq 0) {
    Report -Severity 'AMBER' -Check 'svccheck' -Subject 'Win32_Service' `
        -Description 'could not enumerate services' `
        -Fix @('Get-Service | Where-Object Status -eq Running') -Card 'CARD W2'
} else {
    foreach ($s in $services) {
        $path = $s.PathName
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        # The executable, dug out of a command line that may carry arguments.
        $exe = $path.Trim()
        if ($exe.StartsWith('"')) { $exe = ($exe -split '"')[1] }
        else { $exe = ($exe -split '\s+')[0] }

        # (a) Running from somewhere a normal service never runs from.
        if ($exe -match '\\(Temp|Tmp|AppData|Downloads|Public|Users\\[^\\]+\\)' -or
            $exe -match '^[A-Za-z]:\\(Users|Temp|Windows\\Temp|ProgramData\\[^\\]*\\Temp)\\') {
            Report -Severity 'RED' -Check 'svcpath' -Subject $s.Name `
                -Description ('service runs from a user-writable directory: {0}' -f $exe) `
                -Detail @('No shipped service does this. A directory a normal user can write to is',
                          'a directory where the service binary can be swapped for another one.') `
                -Fix @(("sc.exe qc {0}" -f $s.Name),
                       ("Get-Item {0} | Select-Object FullName,CreationTime,Length" -f (Q $exe)),
                       ("Stop-Service {0}; Set-Service {0} -StartupType Disabled" -f (Q $s.Name)),
                       '# preserve the binary BEFORE you delete anything:',
                       ("Copy-Item {0} C:\ProgramData\CCDC\evidence\ -Force" -f (Q $exe))) `
                -Card 'CARD W2'
            continue
        }

        # (b) The unquoted service path problem. Windows will try
        # C:\Program.exe before C:\Program Files\Thing\svc.exe, so anyone who
        # can write to C:\ gets SYSTEM on the next start.
        # The space has to be looked for in the PATH, not in $exe. $exe is built
        # by splitting on whitespace, so it can never contain a space - the
        # first version tested $exe and therefore never fired at all.
        $upToExe = ''
        if ($path -match '(?i)^(?<p>.*?\.exe)') { $upToExe = $Matches['p'] }
        if (-not $path.Trim().StartsWith('"') -and $upToExe -match '\s') {
            Report -Severity 'AMBER' -Check 'svcunquoted' -Subject $s.Name `
                -Description ('unquoted service path containing a space: {0}' -f $path) `
                -Detail @('Windows resolves this left to right, so C:\Program.exe runs before',
                          'C:\Program Files\... does. Whoever can write the parent gets SYSTEM.',
                          'Often a vendor bug rather than an attacker, which is why it is amber.') `
                -Fix @(("sc.exe config {0} binPath= ""\""{1}\""""   # quote the path" -f $s.Name, $exe)) `
                -Card 'CARD W2'
        }

        # (c) Running as a named account that is not one of the three the
        # system uses. A service logging on as a user account is how an
        # attacker gets their credentials used automatically on every boot.
        $acct = $s.StartName
        if ($acct -and $acct -notmatch '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService|System)|NT Service\\.*)$') {
            $short = ($acct -split '\\')[-1]
            if (-not (Test-CcdcListContains -Needle $short -List $allowedUsers)) {
                Report -Severity 'AMBER' -Check 'svcaccount' -Subject $s.Name `
                    -Description ('service logs on as {0}, which the packet does not name' -f $acct) `
                    -Detail @('Legitimate for some applications. Also a way to have the box supply',
                              'an attacker''s credentials on every start without them logging in.') `
                    -Fix @(("sc.exe qc {0}" -f $s.Name), ("net user {0}" -f $short)) `
                    -Card 'CARD W2'
            }
        }
    }
    Clean ("{0} service(s) reviewed for path, quoting and logon account" -f @($services).Count)
}

# The scored services themselves. Same reasoning as the scored accounts: this
# is the thing being graded, and it is worth saying plainly when it is down.
Begin-Check 'scoredservice'
foreach ($name in $scoredServices) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $s) {
        Report -Severity 'AMBER' -Check 'scoredservice' -Subject $name `
            -Description 'named in the packet as scored, but no such service on this box' `
            -Detail @('Check the spelling against the packet - a scored service you are not',
                      'watching is worse than one you are.') `
            -Fix @(("Get-Service | Where-Object Name -like '*{0}*'" -f $name)) -Card 'CARD W2'
        continue
    }
    if ($s.Status -ne 'Running') {
        Report -Severity 'RED' -Check 'scoredservice' -Subject $name `
            -Description ('a SCORED service is {0} - you are losing uptime points right now' -f $s.Status) `
            -Detail @('Start it first, then find out why it stopped. The points are per-check,',
                      'so every minute spent diagnosing before starting is a minute of zeros.') `
            -Fix @(("Start-Service {0}" -f (Q $name)),
                   ("Get-WinEvent -LogName System -MaxEvents 40 | Where-Object Message -match {0}" -f (Q $name)),
                   ("sc.exe qc {0}                 # did the binary path change?" -f $name)) `
            -Card 'CARD W2'
    }
}
if (@($scoredServices).Count -gt 0) { Clean ("{0} scored service(s) checked" -f @($scoredServices).Count) }

# =============================================================================
# 3. SCHEDULED TASKS - persistence that does not need a service
# =============================================================================

Begin-Check 'tasks'
$tasks = @()
if ($facts['HasScheduledTasks']) {
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { }
}
if (@($tasks).Count -gt 0) {
    # What a payload looks like in a task action, regardless of what the task
    # is called. Names are chosen to blend in; these strings are chosen to work.
    $badAction = '(?i)(-enc\b|-encodedcommand|downloadstring|downloadfile|iex\b|invoke-expression|frombase64string|-w\s+hidden|-windowstyle\s+hidden|-nop\b|bitsadmin|certutil.*-urlcache|mshta|rundll32.*javascript|\\Temp\\|\\AppData\\|/c\s+powershell|cmd\.exe\s+/c.*http)'
    foreach ($t in $tasks) {
        $actions = ''
        try { $actions = (($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ') } catch { }
        $full = ('{0}{1}' -f $t.TaskPath, $t.TaskName)

        $isNew = $false
        try {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            # A task's own registration time is not exposed; the XML is.
            $xml = [xml](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop)
            if ($xml.Task.RegistrationInfo.Date) {
                $isNew = Test-CcdcNewerThanBox -When ([datetime]$xml.Task.RegistrationInfo.Date)
            }
        } catch { }

        if ($actions -match $badAction) {
            Report -Severity 'RED' -Check 'taskcmd' -Subject $full `
                -Description 'scheduled task whose action looks like a payload, not a job' `
                -Detail @(('  runs: {0}' -f ($actions.Substring(0, [Math]::Min(150, $actions.Length)))),
                          'Encoded commands, hidden windows, downloads piped into an interpreter,',
                          'or anything executing out of Temp or AppData. None of that is a',
                          'maintenance task.') `
                -Fix @(("Export-ScheduledTask -TaskName {0} -TaskPath {1}     # read it ALL first" -f (Q $t.TaskName), (Q $t.TaskPath)),
                       ("Disable-ScheduledTask -TaskName {0} -TaskPath {1}" -f (Q $t.TaskName), (Q $t.TaskPath)),
                       ("Unregister-ScheduledTask -TaskName {0} -TaskPath {1} -Confirm:`$false" -f (Q $t.TaskName), (Q $t.TaskPath)),
                       '# then find what it ran, and whether that is still on disk') `
                -Card 'CARD W3'
        } elseif ($isNew -and $t.TaskPath -notmatch '^\\Microsoft\\') {
            Report -Severity 'AMBER' -Check 'newtask' -Subject $full `
                -Description 'scheduled task registered AFTER this box was built' `
                -Detail @(('  runs: {0}' -f ($actions.Substring(0, [Math]::Min(150, $actions.Length)))),
                          'Might be yours. Might be theirs. The registration date is the reason',
                          'it is here; the action is the reason it is only amber.') `
                -Fix @(("Export-ScheduledTask -TaskName {0} -TaskPath {1}" -f (Q $t.TaskName), (Q $t.TaskPath))) `
                -Card 'CARD W3'
        }
    }
    Clean ("{0} scheduled task(s) reviewed" -f @($tasks).Count)
} elseif (-not $facts['HasScheduledTasks']) {
    Report -Severity 'AMBER' -Check 'taskcheck' -Subject 'ScheduledTasks' `
        -Description 'no ScheduledTasks module here, so tasks were not checked' `
        -Fix @('schtasks /query /fo LIST /v | more') -Card 'CARD W3'
}

# =============================================================================
# 4. AUTOSTART AND REGISTRY - the checklist item that says "harden GPO,
#    Registry, startup and Task Scheduler configurations"
#
# Everything here runs without anyone logging in, or the moment somebody does.
# The Image File Execution Options entries are the ones worth knowing by heart:
# they are how a login screen becomes a SYSTEM shell with no password at all.
# =============================================================================

Begin-Check 'autorun'
# The program a Run value starts: the quoted path, or everything up to .exe.
function Get-RunKeyExe {
    param([string]$Command)
    $c = $Command.Trim()
    if ($c -match '^"([^"]+)"') { return [Environment]::ExpandEnvironmentVariables($Matches[1]) }
    if ($c -match '^(.+?\.exe)\b') { return [Environment]::ExpandEnvironmentVariables($Matches[1]) }
    return ''
}
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$suspectCmd = '(?i)(-enc\b|-encodedcommand|downloadstring|iex\b|invoke-expression|frombase64string|-w\s+hidden|-windowstyle\s+hidden|\\Temp\\|\\AppData\\|\\Public\\|mshta|rundll32.*javascript|certutil)'
foreach ($k in $runKeys) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    try {
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $val = [string]$p.Value
            if ($val -match $suspectCmd) {
                Report -Severity 'RED' -Check 'runkey' -Subject ('{0}\{1}' -f $k, $p.Name) `
                    -Description 'autostart entry whose command looks like a payload' `
                    -Detail @(('  runs: {0}' -f $val), 'This executes at logon, every logon.') `
                    -Fix @(("Get-ItemProperty -Path {0} -Name {1}" -f (Q $k), (Q $p.Name)),
                           ("Remove-ItemProperty -Path {0} -Name {1}" -f (Q $k), (Q $p.Name))) `
                    -Card 'CARD W4'
            } elseif (($exe = Get-RunKeyExe -Command $val) -and
                      $exe -notmatch '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\))\\') {
                # A plain path can still be the payload. Found live: a Run value
                # pointing at C:\RT_LAB_PLANT_bin\svc.exe was only a NOTE here,
                # and only the baseline diff showed it. Installers put programs
                # under Windows or Program Files; anything else gets a look, and
                # a binary created after the box was built is RED.
                $created = $null
                try { if ([System.IO.File]::Exists($exe)) { $created = [System.IO.File]::GetCreationTime($exe) } } catch { }
                $isNew = ($null -ne $created -and $facts['BoxBuilt'] -and $created -gt $facts['BoxBuilt'].AddHours(2))
                $sev = if ($isNew) { 'RED' } else { 'AMBER' }
                $why = if ($isNew) { ('the program was created {0}, after this box was built' -f $created.ToString('yyyy-MM-dd HH:mm')) }
                       else { 'installers put programs under C:\Windows or C:\Program Files, not here' }
                Report -Severity $sev -Check 'runkey' -Subject ('{0}\{1}' -f $k, $p.Name) `
                    -Description 'autostart entry runs a program from outside Windows and Program Files' `
                    -Detail @(('  runs: {0}' -f $val), ('  {0}' -f $why), 'This executes at logon, every logon.') `
                    -Fix @(("Get-FileHash -LiteralPath {0}" -f (Q $exe)),
                           ("Get-ItemProperty -Path {0} -Name {1}" -f (Q $k), (Q $p.Name)),
                           ("Remove-ItemProperty -Path {0} -Name {1}" -f (Q $k), (Q $p.Name))) `
                    -Card 'CARD W4'
            } else {
                Report -Severity 'NOTE' -Check 'autorun' -Subject ('{0}\{1}' -f $k, $p.Name) `
                    -Description $val -Card 'CARD W4'
            }
        }
    } catch { }
}

# Filesystem Startup directories: anything placed here runs at logon
    $startupDirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')
    $userProfiles = 'C:\Users'
    if (Test-Path -LiteralPath $userProfiles) {
        foreach ($uDir in (Get-ChildItem -LiteralPath $userProfiles -Directory -ErrorAction SilentlyContinue)) {
            $pStartup = Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            if (Test-Path -LiteralPath $pStartup) { $startupDirs += $pStartup }
        }
    }
    foreach ($sd in $startupDirs) {
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        try {
            $sFiles = @(Get-ChildItem -LiteralPath $sd -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '(?i)^desktop\.ini$' })
            foreach ($sf in $sFiles) {
                Report -Severity 'AMBER' -Check 'startupfile' -Subject $sf.FullName `
                    -Description ('file in Startup folder executes at logon: {0}' -f $sf.Name) `
                    -Detail @(('  path: {0} ({1} bytes)' -f $sf.FullName, $sf.Length),
                              ('  last write: {0}' -f $sf.LastWriteTime),
                              'Files in this folder execute automatically when a user logs on.') `
                    -Fix @(("Get-Item -LiteralPath {0} | Format-List FullName,Length,CreationTime,LastWriteTime" -f (Q $sf.FullName)),
                           ("Get-FileHash -Algorithm SHA256 -LiteralPath {0}" -f (Q $sf.FullName)),
                           '# Preserve and identify the file before you decide whether the packet needs it.') `
                    -Card 'CARD W4'
            }
        } catch { }
    }

# Image File Execution Options "Debugger" - the accessibility backdoor.
# Set a debugger on sethc.exe and five shifts at the lock screen is SYSTEM.
Begin-Check 'ifeo'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path -LiteralPath $ifeo) {
    foreach ($sub in (Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
        $dbg = $null
        try { $dbg = (Get-ItemProperty -LiteralPath $sub.PSPath -Name Debugger -ErrorAction Stop).Debugger } catch { }

        # An accessibility binary with an IFEO subkey but NO Debugger value is
        # not nothing. Windows does not create these, and Defender strips the
        # Debugger value while leaving the empty key behind - so this is the
        # footprint of an attempt that was blocked. It belongs in the incident
        # report, and it says somebody had administrator on this box.
        if (-not $dbg -and $sub.PSChildName -match '(?i)^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') {
            Report -Severity 'AMBER' -Check 'ifeoempty' -Subject $sub.PSChildName `
                -Description 'an IFEO key exists for an accessibility binary, with no debugger set' `
                -Detail @('Windows does not ship this key. Either the debugger was removed -',
                          'by you, or by Defender blocking the attempt - or it is being set up.',
                          'Check Defender first: a block here is evidence for the incident',
                          'report, and it means somebody already had administrator.') `
                -Fix @('Get-MpThreatDetection | Where-Object { $_.Resources -match ''Image File Execution'' } | Format-List',
                       ("Remove-Item -LiteralPath {0} -Recurse" -f (Q (ConvertTo-CcdcRegPath $sub.PSPath)))) `
                -Card 'CARD W4'
        }

        if ($dbg) {
            Report -Severity 'RED' -Check 'ifeo' -Subject $sub.PSChildName `
                -Description ('a debugger is attached to {0}: {1}' -f $sub.PSChildName, $dbg) `
                -Detail @('This runs INSTEAD of the program, as whoever launched it. On sethc.exe,',
                          'utilman.exe, osk.exe or magnify.exe that means a SYSTEM shell from the',
                          'lock screen with no credentials at all.',
                          'There is no legitimate reason for one of these on a competition box.') `
                -Fix @(("Remove-ItemProperty -Path {0} -Name Debugger" -f (Q $sub.PSPath)),
                       '# then check the accessibility binaries were not replaced outright:',
                       'Get-FileHash C:\Windows\System32\sethc.exe,C:\Windows\System32\utilman.exe') `
                -Card 'CARD W4'
        }
    }
    Clean 'no debugger hijacks on the accessibility binaries'
}

# Accessibility binaries replaced on disk (e.g. cmd.exe copied over sethc.exe)
Begin-Check 'accessibility'
$accBins = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
$cmdPath = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'System32\cmd.exe' } else { 'C:\Windows\System32\cmd.exe' }
$cmdHash = $null
if (Test-Path -LiteralPath $cmdPath) {
    try { $cmdHash = (Get-FileHash -LiteralPath $cmdPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
}
foreach ($b in $accBins) {
    $p = if ($env:SystemRoot) { Join-Path $env:SystemRoot "System32\$b" } else { "C:\Windows\System32\$b" }
    if (Test-Path -LiteralPath $p) {
        $binHash = $null
        try { $binHash = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        if ($cmdHash -and $binHash -and ($cmdHash -eq $binHash)) {
            Report -Severity 'RED' -Check 'accessibility' -Subject $b `
                -Description ("accessibility binary {0} is a copy of cmd.exe (lock-screen backdoor)" -f $b) `
                -Detail @(("The file hash of {0} matches cmd.exe." -f $p),
                          'Invoking accessibility features at the login screen gives a SYSTEM shell.',
                          'Restore the original file or run System File Checker.') `
                -Fix @(("sfc /scanfile={0}" -f $p)) `
                -Card 'CARD W4'
        } else {
            $sig = $null
            try { $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop } catch { }
            if ($null -ne $sig -and $sig.Status -ne 'Valid') {
                Report -Severity 'RED' -Check 'accessibility' -Subject $b `
                    -Description ("accessibility binary {0} signature status is {1} (tampered file)" -f $b, $sig.Status) `
                    -Detail @(("The digital signature on {0} is invalid ({1})." -f $p, $sig.Status),
                              'Windows system binaries are signed by Microsoft. This binary may be a backdoor.') `
                    -Fix @(("sfc /scanfile={0}" -f $p)) `
                    -Card 'CARD W4'
            }
        }
    }
}
Clean 'accessibility binaries on disk are valid and untampered'

# Winlogon Userinit/Shell - the other classic, and a single appended comma is
# all it takes.
Begin-Check 'winlogon'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
try {
    $w = Get-ItemProperty -LiteralPath $wl -ErrorAction Stop
    if ($w.PSObject.Properties.Name -contains 'Userinit' -and
        $w.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?\s*$') {
        Report -Severity 'RED' -Check 'winlogon' -Subject 'Winlogon\Userinit' `
            -Description ('Userinit is not the stock value: {0}' -f $w.Userinit) `
            -Detail @('Stock is exactly "C:\Windows\system32\userinit.exe,". Anything appended',
                      'after that comma runs at every interactive logon.') `
            -Fix @(("Set-ItemProperty -Path {0} -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'" -f (Q $wl))) `
            -Card 'CARD W4'
    }
    if ($w.PSObject.Properties.Name -contains 'Shell' -and $w.Shell -notmatch '^explorer\.exe\s*$') {
        Report -Severity 'RED' -Check 'winlogon' -Subject 'Winlogon\Shell' `
            -Description ('Shell is not the stock value: {0}' -f $w.Shell) `
            -Fix @(("Set-ItemProperty -Path {0} -Name Shell -Value 'explorer.exe'" -f (Q $wl))) `
            -Card 'CARD W4'
    }
    Clean 'Winlogon Userinit and Shell are stock'
} catch { }

# =============================================================================
# 5. PROCESSES AND LISTENING PORTS
#
# A port is how they reach in and how data leaves. The course notes put it
# plainly: "If a process is listening on a port, people can reach it from
# outside your computer."
# =============================================================================

Begin-Check 'listeners'
$listeners = @()
if ($facts['HasNetTCPIP']) {
    try { $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { }
}
# A domain controller's own listeners, keyed to the process that should hold
# each. The packet's Windows box is a DC (AD/DNS are scored), and without this
# the first triage there offered to firewall-block AD Web Services (9389) and
# the RPC-over-HTTP endpoint mapper (593) - both stock on every DC. A port is
# only accepted when the EXPECTED binary holds it, so a listener planted on
# 9389 is still a finding.
$dcListeners = @{}
if (Test-CcdcIsDomainController) {
    $dcListeners = @{
        '53' = 'dns'; '88' = 'lsass'; '464' = 'lsass'; '389' = 'lsass'; '636' = 'lsass';
        '3268' = 'lsass'; '3269' = 'lsass'; '593' = 'svchost';
        '9389' = 'Microsoft.ActiveDirectory.WebServices'; '5722' = 'dfsrs'
    }
}
if (@($listeners).Count -gt 0) {
    $byPort = $listeners | Sort-Object LocalPort -Unique
    foreach ($l in $byPort) {
        $port = [string]$l.LocalPort
        if (Test-CcdcListContains -Needle $port -List $allowedTcpPorts) { continue }
        # 135/139/445 and the ephemeral RPC range are stock Windows noise. They
        # are attack surface, but they are not a finding - reporting them every
        # pass is how a list stops being read.
        if ($port -in @('135','139','445','5985','5986','47001','49664','49665','49666','49667','49668','49669','49670')) { continue }
        if ([int]$port -ge 49152) { continue }

        $procName = 'unknown'; $procPath = ''
        try {
            $p = Get-Process -Id $l.OwningProcess -ErrorAction Stop
            $procName = $p.ProcessName
            try { $procPath = $p.Path } catch { }
        } catch { }
        if ($dcListeners.ContainsKey($port) -and $procName -eq $dcListeners[$port] -and
            ($procPath -eq '' -or ($env:SystemRoot -and $procPath -like "$env:SystemRoot\*"))) { continue }

        # An interpreter holding a listening port is the Windows shape of the
        # same finding the Linux side calls netprocsvc: a scored service
        # written in python looks exactly like a web shell from here.
        $isInterpreter = $procName -match '(?i)^(powershell|pwsh|cmd|python[0-9.]*|perl|ruby|php|node|wscript|cscript|mshta|rundll32|regsvr32)$'
        if ($isInterpreter) {
            Report -Severity 'RED' -Check 'netproc' -Subject ('{0}:{1}' -f $procName, $port) `
                -Description ('{0} is listening on port {1} - that is an interpreter, not a service' -f $procName, $port) `
                -Detail @(('  pid {0}  {1}' -f $l.OwningProcess, $procPath),
                          'A shell that accepts connections is a bind shell. Read the command line',
                          'before you kill it - the command line is the evidence.') `
                -Fix @(("Get-CimInstance Win32_Process -Filter 'ProcessId={0}' | Select-Object ProcessId,ParentProcessId,CommandLine | Format-List" -f $l.OwningProcess),
                       ("Stop-Process -Id {0} -Force" -f $l.OwningProcess),
                       '# then find its PARENT - that is how it comes back') `
                -Card 'CARD W5'
        } else {
            Report -Severity 'AMBER' -Check 'listener' -Subject ('tcp/{0}' -f $port) `
                -Description ('listening port the packet does not account for, held by {0}' -f $procName) `
                -Detail @(('  pid {0}  {1}' -f $l.OwningProcess, $procPath),
                          'If this is a service you are scored on, add the port to',
                          'CCDC_ALLOWED_TCP_PORTS. If it is not, close it at the firewall first -',
                          'that is reversible and killing the process is not.') `
                -Fix @(("Get-Process -Id {0} | Select-Object Name,Path,StartTime" -f $l.OwningProcess),
                       ("New-NetFirewallRule -DisplayName 'CCDC block {0}' -Direction Inbound -LocalPort {0} -Protocol TCP -Action {1}" -f $port, 'Block')) `
                -Card 'CARD W5'
        }
    }
    Clean ("{0} listening TCP port(s) reviewed" -f @($byPort).Count)
} elseif (-not $facts['HasNetTCPIP']) {
    Report -Severity 'AMBER' -Check 'netcheck' -Subject 'NetTCPIP' `
        -Description 'no NetTCPIP module, so listening ports were not checked from PowerShell' `
        -Fix @('netstat -ano -p TCP | findstr LISTENING') -Card 'CARD W5'
}

Begin-Check 'tmpproc'
try {
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $ep = $p.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($ep)) { continue }
        if ($ep -match '(?i)\\(Temp|AppData\\Local\\Temp|Downloads|Public|Windows\\Temp)\\') {
            Report -Severity 'RED' -Check 'tmpproc' -Subject ('pid{0}:{1}' -f $p.ProcessId, $ep) `
                -Description 'a process is running from a temporary directory' `
                -Detail @(('  cmdline: {0}' -f ([string]$p.CommandLine).Substring(0, [Math]::Min(140, ([string]$p.CommandLine).Length))),
                          'Installers do this for a few seconds. Nothing legitimate does it for long.') `
                -Fix @(("Get-CimInstance Win32_Process -Filter 'ProcessId={0}' | Format-List ProcessId,ParentProcessId,CommandLine,CreationDate" -f $p.ProcessId),
                       ("Copy-Item {0} C:\ProgramData\CCDC\evidence\ -Force    # evidence FIRST" -f (Q $ep)),
                       ("Stop-Process -Id {0} -Force" -f $p.ProcessId)) `
                -Card 'CARD W5'
        }
    }
    Clean 'no processes running out of temporary directories'
} catch { }

# =============================================================================
# 6. DEFENDER AND FIREWALL - the two controls the red team turns off first
#
# From the training: "Red Team likes to mess with this, such as setting
# exclusion paths." An exclusion is better than disabling Defender outright,
# because the icon stays green.
# =============================================================================

Begin-Check 'defender'
if ($facts['HasDefender']) {
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $st = Get-MpComputerStatus -ErrorAction Stop

        if (-not $st.RealTimeProtectionEnabled) {
            Report -Severity 'RED' -Check 'defenderoff' -Subject 'RealTimeProtection' `
                -Description 'Defender real-time protection is OFF' `
                -Fix @('Set-MpPreference -DisableRealtimeMonitoring $false',
                       'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled') `
                -Card 'CARD W6'
        }
        if ($st.PSObject.Properties.Name -contains 'AntispywareEnabled' -and -not $st.AntispywareEnabled) {
            Report -Severity 'RED' -Check 'defenderoff' -Subject 'Antispyware' `
                -Description 'Defender antispyware is OFF' `
                -Fix @('Set-MpPreference -DisableAntiSpyware $false') -Card 'CARD W6'
        }

        # Exclusions. Every one is a directory or extension Defender has been
        # told to ignore. On a competition box the correct number is usually
        # zero, and any of them is somewhere to park a payload.
        foreach ($grp in @(@{n='ExclusionPath';v=$mp.ExclusionPath},
                           @{n='ExclusionProcess';v=$mp.ExclusionProcess},
                           @{n='ExclusionExtension';v=$mp.ExclusionExtension})) {
            if ($null -eq $grp.v) { continue }
            foreach ($e in @($grp.v)) {
                if ([string]::IsNullOrWhiteSpace($e)) { continue }
                Report -Severity 'RED' -Check 'defenderexcl' -Subject ('{0}={1}' -f $grp.n, $e) `
                    -Description 'Defender has been told to ignore something' `
                    -Detail @('This is the quiet version of turning antivirus off: the icon stays',
                              'green and one directory stops being scanned.',
                              'Read it, then remove it unless the packet asked for it.') `
                    -Fix @(("Remove-MpPreference -{0} {1}" -f $grp.n, (Q $e)),
                           'Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension',
                           ("Get-ChildItem -Recurse {0} -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,CreationTime" -f (Q $e))) `
                    -Card 'CARD W6'
            }
        }
        if ($st.PSObject.Properties.Name -contains 'AntivirusSignatureAge' -and $st.AntivirusSignatureAge -gt 7) {
            Report -Severity 'AMBER' -Check 'defendersig' -Subject 'signatures' `
                -Description ('Defender signatures are {0} days old' -f $st.AntivirusSignatureAge) `
                -Fix @('Update-MpSignature',
                       '# error 0x8024402c/0x80072ee7 with internet up usually means a WSUS policy points elsewhere:',
                       'Update-MpSignature -UpdateSource MicrosoftUpdateServer',
                       '# "completed with errors" on an old Server 2016 image: straight from Microsoft',
                       '& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate -MMPC') -Card 'CARD W6'
        }
        Clean 'Defender status and exclusions reviewed'
    } catch {
        Report -Severity 'AMBER' -Check 'defendercheck' -Subject 'Defender' `
            -Description ('Defender module present but would not answer: {0}' -f $_.Exception.Message) `
            -Detail @('A third-party AV may have displaced it, or somebody disabled the service.') `
            -Fix @('Get-Service WinDefend | Select-Object Status,StartType',
                   'Start -> Windows Security   # the GUI still tells you the truth') `
            -Card 'CARD W6'
    }
}

Begin-Check 'firewall'
if ($facts['HasNetSecurity']) {
    try {
        foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $p.Enabled) {
                Report -Severity 'RED' -Check 'fwoff' -Subject $p.Name `
                    -Description ('the {0} firewall profile is OFF' -f $p.Name) `
                    -Detail @('All three profiles have to be on. A box moves between them without',
                              'telling you, and the one that is off is the one that matters.') `
                    -Fix @(("Set-NetFirewallProfile -Profile {0} -Enabled True" -f $p.Name),
                           'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True') `
                    -Card 'CARD W7'
            }
            if ($p.DefaultInboundAction -ne 'Block') {
                Report -Severity 'RED' -Check 'fwinbound' -Subject $p.Name `
                    -Description ('{0} profile default inbound action is {1}, not Block' -f $p.Name, $p.DefaultInboundAction) `
                    -Detail @('Default-allow inbound means every rule you write is a patch over a',
                              'hole rather than an exception to a wall.') `
                    -Fix @(("Set-NetFirewallProfile -Profile {0} -DefaultInboundAction Block" -f $p.Name)) `
                    -Card 'CARD W7'
            }
            if ($p.LogAllowed -ne 'True' -and $p.LogBlocked -ne 'True') {
                Report -Severity 'AMBER' -Check 'fwlog' -Subject $p.Name `
                    -Description ('{0} profile is not logging dropped packets' -f $p.Name) `
                    -Detail @('Without this you cannot answer "what did they try" in the incident',
                              'report, and incident reports are worth points.') `
                    -Fix @(("Set-NetFirewallProfile -Profile {0} -LogBlocked True -LogMaxSizeKilobytes 16384" -f $p.Name)) `
                    -Card 'CARD W7'
            }
        }

        # An inbound allow rule that appeared after the box was built, for a
        # port nobody put in the packet, is a door somebody propped open.
        #
        # A stock Windows install ships ~50 enabled inbound allow rules. Naming
        # them all made a clean box report 25 AMBER findings, which teaches you
        # to skim past the section that matters. The discriminator is Group:
        # Windows' own rules carry a resource-string group ('@FirewallAPI.dll,-28502'),
        # an installer's rule carries a plain-text group ('Microsoft Edge'), and a
        # rule somebody typed has NO group at all. The last kind is the one worth
        # your attention, and it is what both you and an attacker produce.
        $fwBuiltin = 0; $fwApp = 0
        foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)) {
            $ports = @()
            try { $ports = @((Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).LocalPort) } catch { }
            foreach ($pt in $ports) {
                if ([string]::IsNullOrWhiteSpace($pt) -or $pt -eq 'Any') { continue }
                if ($pt -notmatch '^\d+$') { continue }
                if (Test-CcdcListContains -Needle $pt -List $allowedTcpPorts) { continue }
                if (Test-CcdcListContains -Needle $pt -List $allowedUdpPorts) { continue }

                $grp = ''
                try { if ($null -ne $r.Group) { $grp = [string]$r.Group } } catch { }
                if ($grp.StartsWith('@')) { $fwBuiltin++; continue }
                if (-not [string]::IsNullOrWhiteSpace($grp)) { $fwApp++; continue }

                Report -Severity 'AMBER' -Check 'fwallow' -Subject ('{0} -> {1}' -f $r.DisplayName, $pt) `
                    -Description 'a hand-made inbound ALLOW rule for a port the packet does not name' `
                    -Detail @('This rule has no group, so it was typed rather than shipped with',
                              'Windows or an installer. Either you opened it for a scored service',
                              'and have not written it into the config, or somebody else opened it.') `
                    -Fix @(("Get-NetFirewallRule -DisplayName {0} | Format-List DisplayName,Description,Enabled,Profile" -f (Q $r.DisplayName)),
                           ("Disable-NetFirewallRule -DisplayName {0}" -f (Q $r.DisplayName))) `
                    -Card 'CARD W7'
            }
        }
        if (($fwBuiltin + $fwApp) -gt 0) {
            Report -Severity 'NOTE' -Check 'fwstock' -Subject 'built-in allow rules' `
                -Description ('{0} Windows and {1} installer inbound allow rule(s) not listed individually' -f $fwBuiltin, $fwApp) `
                -Detail @('These ship with Windows or with installed software. They are not',
                          'clean by definition - just not evidence of anything on their own.',
                          'harden.ps1 -Only Firewall sets default-deny inbound, which makes',
                          'the whole set moot. To read them yourself:') `
                -Fix @('Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Sort-Object Group | Format-Table DisplayName,Group -AutoSize') `
                -Card 'CARD W7'
        }
        Clean 'firewall profiles and inbound allow rules reviewed'
    } catch {
        Report -Severity 'AMBER' -Check 'fwcheck' -Subject 'firewall' `
            -Description ('could not read the firewall: {0}' -f $_.Exception.Message) `
            -Fix @('netsh advfirewall show allprofiles') -Card 'CARD W7'
    }
} else {
    Report -Severity 'AMBER' -Check 'fwcheck' -Subject 'NetSecurity' `
        -Description 'no NetSecurity module here, so the firewall was not checked' `
        -Fix @('netsh advfirewall show allprofiles',
               'netsh advfirewall set allprofiles state on') -Card 'CARD W7'
}

# =============================================================================
# 7. LOGGING - you cannot write an incident report from logs that were cleared
#    or never turned on. Incident reports are worth points.
# =============================================================================

Begin-Check 'logs'
try {
    $cleared = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction Stop)
    foreach ($e in $cleared) {
        Report -Severity 'RED' -Check 'logcleared' -Subject ('Security @ {0}' -f $e.TimeCreated.ToString('HH:mm:ss')) `
            -Description 'the Security event log was CLEARED' `
            -Detail @('Nothing legitimate clears the Security log during an event. Everything',
                      'before that timestamp is gone; say so in the incident report, with the',
                      'timestamp - a cleared log is itself a reportable event.') `
            -Fix @('Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=1102} -MaxEvents 5 | Format-List TimeCreated,Message',
                   '# and check whether it is still being written to now:',
                   'Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated,Id') `
            -Card 'CARD W8'
    }
} catch { }

try {
    $sb = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction Stop
    if ($sb.EnableScriptBlockLogging -ne 1) { throw 'off' }
    Clean 'PowerShell script block logging is on'
} catch {
    Report -Severity 'AMBER' -Check 'psloggingoff' -Subject 'ScriptBlockLogging' `
        -Description 'PowerShell script block logging is not enabled' `
        -Detail @('With it on, every PowerShell command run on this box lands in',
                  'Microsoft-Windows-PowerShell/Operational as event 4104 - including the',
                  'attacker''s. It is the single highest-value log on Windows and it is off',
                  'by default.') `
        -Fix @('New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' -Force',
               'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' -Name EnableScriptBlockLogging -Value 1',
               '# or let the kit do it, with the rest of the logging setup:',
               ('.\windows\harden.ps1 -Config ' + $Config + ' -Only Logging -Apply')) `
        -Card 'CARD W8'
}

# =============================================================================
# 8. CREDENTIAL EXPOSURE - the Windows-only problem Linux does not have
#
# On Linux a password is a hash in /etc/shadow. On Windows it is also material
# sitting in LSASS memory that a local administrator can read and replay on
# another machine WITHOUT ever cracking it. These three settings decide how
# much is sitting there. They are registry writes and they cost nothing.
# =============================================================================
Begin-Check 'credentials'

function Get-RegValue {
    # StrictMode 2.0 throws on a property that is not there, so never touch one
    # without checking. Returns $null when the key or value does not exist.
    param([string]$Path, [string]$Name)
    try {
        $k = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $k) { return $null }
        if (-not ($k.PSObject.Properties.Name -contains $Name)) { return $null }
        return $k.$Name
    } catch { return $null }
}

$wdigest = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
if ($null -ne $wdigest -and [int]$wdigest -eq 1) {
    Report -Severity 'RED' -Check 'wdigest' -Subject 'UseLogonCredential=1' `
        -Description 'WDigest is storing cleartext passwords in memory' `
        -Detail @('Nothing needs this. It is off by default on anything since 2012 R2,',
                  'so somebody turned it ON, and the reason to turn it on is to read',
                  'plaintext passwords out of LSASS. Treat every password used on this',
                  'box since as known to them.') `
        -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'' -Name UseLogonCredential -Value 0',
               ('# then rotate: .\windows\users.ps1 -Config {0} -RotateAll -Apply' -f $Config)) `
        -Card 'CARD W13'
} else {
    Clean 'WDigest is not caching cleartext credentials'
}

$ppl = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
if ($null -eq $ppl -or [int]$ppl -eq 0) {
    Report -Severity 'AMBER' -Check 'lsappl' -Subject 'RunAsPPL' `
        -Description 'LSA is not running as a protected process' `
        -Detail @('With RunAsPPL on, the ordinary ways of reading LSASS memory stop',
                  'working and the attempt is logged. It needs a reboot to take effect,',
                  'so decide early or not at all - do NOT reboot a scored box at minute',
                  '50 for this.') `
        -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name RunAsPPL -Value 1 -Type DWord',
               '# takes effect on next reboot') `
        -Card 'CARD W13'
} else {
    Clean 'LSA is running protected (RunAsPPL)'
}

$restrict = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
$restrictSam = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'
if (($null -eq $restrictSam -or [int]$restrictSam -eq 0)) {
    Report -Severity 'AMBER' -Check 'nullsession' -Subject 'RestrictAnonymousSAM' `
        -Description 'anonymous users are not blocked from enumerating SAM accounts' `
        -Detail @('This is how an unauthenticated host on the same segment gets your',
                  'user list to spray against.') `
        -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name RestrictAnonymousSAM -Value 1 -Type DWord',
               'Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name RestrictAnonymous -Value 1 -Type DWord') `
        -Card 'CARD W13'
} else {
    Clean 'anonymous SAM enumeration is restricted'
}

$lmCompat = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
if ($null -eq $lmCompat -or [int]$lmCompat -lt 5) {
    Report -Severity 'AMBER' -Check 'lmcompat' -Subject 'LmCompatibilityLevel' `
        -Description 'NTLMv1 or LM authentication is not refused (LmCompatibilityLevel < 5)' `
        -Detail @('LmCompatibilityLevel should be 5 to refuse LM/NTLMv1 and send NTLMv2 only.',
                  'NTLMv1 is trivial to crack or relay.') `
        -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name LmCompatibilityLevel -Value 5 -Type DWord') `
        -Card 'CARD W13'
} else {
    Clean 'NTLMv2 is enforced (LmCompatibilityLevel = 5)'
}

# =============================================================================
# 9. SERVICE PERMISSIONS - a service can pass every other check and still be
#    yours to take over
#
# Sections 2 checked WHERE a service runs from and WHO it runs as. Neither says
# anything about who is allowed to CHANGE it. A service running as SYSTEM from
# C:\Windows\System32 that Authenticated Users may reconfigure is a one-command
# privilege escalation, and it looks perfectly clean in every other view.
# =============================================================================
Begin-Check 'serviceacl'

# In SDDL, 'WD' means Everyone when it appears as the PRINCIPAL and WRITE_DAC
# when it appears in the RIGHTS. They are different fields - parse by position,
# never by searching the whole ACE string.
$riskyPrincipals = @{
    'WD' = 'Everyone';            'AU' = 'Authenticated Users'
    'IU' = 'Interactive Users';   'BU' = 'Users'
    'BG' = 'Guests';              'AN' = 'Anonymous'
    'S-1-1-0' = 'Everyone';       'S-1-5-11' = 'Authenticated Users'
    'S-1-5-32-545' = 'Users'
}
$dangerousRights = @{
    'DC' = 'change its configuration (binary path, logon account)'
    'WD' = 'rewrite its permissions'
    'WO' = 'take ownership of it'
    'SD' = 'delete it'
}

$svcAclFindings = 0
$svcAclChecked  = 0
$svcDirsChecked = @{}
$allSvc = @()
try { $allSvc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) } catch { }

foreach ($svc in $allSvc) {
    $svcName = ''
    try { $svcName = [string]$svc.Name } catch { continue }
    if ([string]::IsNullOrWhiteSpace($svcName)) { continue }

    $sddl = ''
    try { $sddl = (& sc.exe sdshow $svcName 2>$null | Where-Object { $_ -match '^D:' }) -join '' } catch { }
    if ([string]::IsNullOrWhiteSpace($sddl)) { continue }
    $svcAclChecked++

    # Only the DACL. Everything from S: on is the audit list and grants nothing.
    $dacl = $sddl
    $sIdx = $sddl.IndexOf('S:')
    if ($sIdx -gt 0) { $dacl = $sddl.Substring(0, $sIdx) }

    foreach ($m in [regex]::Matches($dacl, '\(([^)]*)\)')) {
        $f = $m.Groups[1].Value -split ';'
        if (@($f).Count -lt 6) { continue }
        if ($f[0] -notmatch '^A') { continue }          # allow ACEs only
        $rights = $f[2]
        $who    = $f[5]
        if (-not $riskyPrincipals.ContainsKey($who)) { continue }

        $granted = @()
        foreach ($r in $dangerousRights.Keys) {
            if ($rights -match $r) { $granted += $dangerousRights[$r] }
        }
        if (@($granted).Count -eq 0) { continue }

        $svcAclFindings++
        Report -Severity 'RED' -Check 'svcacl' -Subject $svcName `
            -Description ('{0} may {1}' -f $riskyPrincipals[$who], ($granted -join ', ')) `
            -Detail @(('This service runs as {0}. Anyone in that group can point it at' -f $svc.StartName),
                      'their own binary and restart it, and the binary runs with the',
                      'service''s privileges. The service itself looks completely normal.',
                      ('  current binary: {0}' -f $svc.PathName)) `
            -Fix @(("sc.exe sdshow {0}" -f $svcName),
                   "# restore the stock DACL for a service (SY=SYSTEM, BA=Administrators):",
                   ("sc.exe sdset {0} ""D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)""" -f $svcName)) `
            -Card 'CARD W11'
    }

    # The other half of the same question: the binary's DIRECTORY. Write access
    # there is the same takeover without touching the service config at all.
    $exe = ''
    try {
        $pn = [string]$svc.PathName
        if ($pn -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
        elseif ($pn -match '^\s*(\S+\.exe)') { $exe = $Matches[1] }
    } catch { }
    if ([string]::IsNullOrWhiteSpace($exe)) { continue }
    $dir = ''
    try { $dir = Split-Path -Parent $exe } catch { }
    if ([string]::IsNullOrWhiteSpace($dir) -or $svcDirsChecked.ContainsKey($dir.ToLower())) { continue }
    $svcDirsChecked[$dir.ToLower()] = $true
    if (-not (Test-Path -LiteralPath $dir)) { continue }

    try {
        $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $id = [string]$ace.IdentityReference
            if ($id -notmatch '(?i)\\(Users|Authenticated Users|Everyone|INTERACTIVE|Guests)$' -and
                $id -notmatch '(?i)^(Everyone|NT AUTHORITY\\Authenticated Users|BUILTIN\\Users)$') { continue }
            $rights = [string]$ace.FileSystemRights
            if ($rights -notmatch '(?i)FullControl|Modify|Write(Data)?|CreateFiles|TakeOwnership|ChangePermissions') { continue }
            Report -Severity 'RED' -Check 'svcdiracl' -Subject $dir `
                -Description ('{0} can write into a directory that service binaries run from' -f $id) `
                -Detail @(('rights: {0}' -f $rights),
                          'Replace the .exe, restart the service, and their code runs as the',
                          'service account. No service configuration is changed, so nothing',
                          'that watches service config will notice.',
                          ('  first service found here: {0}' -f $svcName)) `
                -Fix @(("icacls ""{0}"" /remove:g ""{1}""" -f $dir, $id),
                       ("icacls ""{0}""" -f $dir)) `
                -Card 'CARD W11'
            break
        }
    } catch { }
}
if ($svcAclFindings -eq 0) {
    Clean ("{0} service ACL(s) reviewed, none writable by non-administrators" -f $svcAclChecked)
}

# =============================================================================
# 10. WMI PERSISTENCE - the one that survives everything else on this list
#
# A WMI permanent event subscription is three objects in a namespace nothing
# else on this box looks at. It is not a service, not a task, not a registry
# run key and not a file on disk, so every other section here misses it. It
# fires on a condition you never see and it survives reboots.
# =============================================================================
Begin-Check 'wmi'

# Windows and a few Microsoft products ship subscriptions of their own.
$stockWmi = @('SCM Event Log Filter', 'SCM Event Log Consumer', 'BVTFilter', 'BVTConsumer',
              'TSLogonFilter', 'TSLogonConsumer', 'RmAssistEventFilter', 'RmAssistEventConsumer',
              'NTEventLogConsumer', 'DellCommandMonitor')
$wmiFound = 0
$wmiTotal = 0
try {
    $consumers = @()
    foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'ScriptingStandardConsumerSetting')) {
        try { $consumers += @(Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction Stop) } catch { }
    }
    $wmiTotal = @($consumers).Count
    foreach ($c in $consumers) {
        $cname = ''
        try { $cname = [string]$c.Name } catch { }
        if ($stockWmi -contains $cname) { continue }

        $what = ''
        try {
            if ($c.PSObject.Properties.Name -contains 'CommandLineTemplate' -and $c.CommandLineTemplate) {
                $what = 'runs: ' + [string]$c.CommandLineTemplate
            } elseif ($c.PSObject.Properties.Name -contains 'ScriptText' -and $c.ScriptText) {
                $what = 'script: ' + (([string]$c.ScriptText) -replace '\s+', ' ')
                if ($what.Length -gt 160) { $what = $what.Substring(0, 160) + ' ...' }
            }
        } catch { }

        $wmiFound++
        Report -Severity 'RED' -Check 'wmisub' -Subject $cname `
            -Description 'a WMI event consumer that did not ship with Windows' `
            -Detail @(('class: {0}' -f $c.CimClass.CimClassName),
                      $what,
                      'Nothing else in this report would have found this. Look at what',
                      'triggers it before you delete it - the filter tells you what they',
                      'were waiting for, and that belongs in the incident report.') `
            -Fix @(("Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object {{ `$_.Consumer -match {0} }}" -f (Q $cname)),
                   ("Get-CimInstance -Namespace root/subscription -ClassName {0} -Filter ""Name='{1}'"" | Remove-CimInstance" -f $c.CimClass.CimClassName, $cname),
                   '# remove the binding and the filter too, or it comes back:',
                   'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Format-List Name,Query') `
            -Card 'CARD W11'
    }
    if ($wmiFound -eq 0) { Clean ("{0} WMI event consumer(s) reviewed, all stock" -f $wmiTotal) }
} catch {
    Report -Severity 'AMBER' -Check 'wmicheck' -Subject 'root/subscription' `
        -Description 'WMI subscriptions could not be read, so this persistence class was not checked' `
        -Fix @('Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer') `
        -Card 'CARD W11'
}

# =============================================================================
# 11. SMB AND RDP - on Linux these are optional services. Here they are the OS.
# =============================================================================
Begin-Check 'smb'

$smbCfg = $null
try { $smbCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
if ($null -ne $smbCfg) {
    try {
        if ($smbCfg.EnableSMB1Protocol) {
            Report -Severity 'RED' -Check 'smbv1' -Subject 'SMB1' `
                -Description 'SMBv1 is enabled' `
                -Detail @('Unauthenticated, unsigned, and the transport for every wormable SMB',
                          'bug there has ever been. Nothing made this decade needs it.') `
                -Fix @('Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force') `
                -Card 'CARD W12'
        } else { Clean 'SMBv1 is disabled' }
    } catch { }
    try {
        if (-not $smbCfg.RequireSecuritySignature) {
            Report -Severity 'AMBER' -Check 'smbsign' -Subject 'RequireSecuritySignature' `
                -Description 'SMB signing is not required' `
                -Detail @('Without it, an attacker who can get a machine to authenticate to',
                          'them relays that authentication to this box and acts as that',
                          'account. No password or hash is ever cracked.') `
                -Fix @('Set-SmbServerConfiguration -RequireSecuritySignature $true -Force') `
                -Card 'CARD W12'
        } else { Clean 'SMB signing is required' }
    } catch { }
}

$shares = @()
try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' }) } catch { }
# SYSVOL and NETLOGON are how a domain controller serves Group Policy and logon
# scripts. "Authenticated Users: Full" is Microsoft's default SHARE permission
# on them - the NTFS permissions underneath are what stop writes. The first run
# on a 2016 DC printed Remove-SmbShare -Name SYSVOL as the fix, which breaks
# Group Policy and can stop the DC advertising itself at all.
$isDcBox = Test-CcdcIsDomainController
$sysvolRoot = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'SYSVOL\sysvol' } else { '' }
foreach ($sh in $shares) {
    if ($isDcBox -and $sysvolRoot -and $sh.Name -in @('SYSVOL', 'NETLOGON') -and [string]$sh.Path -like "$sysvolRoot*") {
        Clean ("{0} is this domain controller's own share (required - leave it)" -f $sh.Name)
        continue
    }
    try {
        foreach ($a in (Get-SmbShareAccess -Name $sh.Name -ErrorAction Stop)) {
            if ($a.AccessControlType -ne 'Allow') { continue }
            $acct = [string]$a.AccountName
            if ($acct -notmatch '(?i)^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users|ANONYMOUS LOGON)$') { continue }
            if ($a.AccessRight -notmatch '(?i)Full|Change') { continue }
            Report -Severity 'RED' -Check 'share' -Subject ('{0} ({1})' -f $sh.Name, $sh.Path) `
                -Description ('shared to {0} with {1} access' -f $acct, $a.AccessRight) `
                -Detail @('Anyone who can reach port 445 can write here. If anything on this',
                          'path is ever executed, that is remote code execution with no',
                          'credential at all.') `
                -Fix @(("Get-SmbShareAccess -Name {0}" -f (Q $sh.Name)),
                       ("Revoke-SmbShareAccess -Name {0} -AccountName {1} -Force" -f (Q $sh.Name), (Q $acct)),
                       ("# or remove the share: Remove-SmbShare -Name {0} -Force" -f (Q $sh.Name))) `
                -Card 'CARD W12'
        }
    } catch { }
}
if (@($shares).Count -gt 0) { Clean ("{0} non-administrative share(s) reviewed" -f @($shares).Count) }

# Domain Controller specific checks (Netlogon secure channel, LDAP signing, Spooler, MachineAccountQuota)
if ($isDcBox) {
    Begin-Check 'dcspooler'
    $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
    if ($null -ne $spooler -and $spooler.Status -eq 'Running') {
        Report -Severity 'AMBER' -Check 'dcspooler' -Subject 'Spooler' `
            -Description 'Print Spooler is running on a Domain Controller (PrintNightmare & NTLM relay coercion)' `
            -Detail @('Print Spooler on a DC allows PrintNightmare (CVE-2021-34527) and MS-RPRN NTLM relay attacks (PetitPotam).',
                      'DCs rarely need to host printers in a competition setting.') `
            -Fix @('Stop-Service -Name Spooler -Force',
                   'Set-Service -Name Spooler -StartupType Disabled') `
            -Card 'CARD W2'
    } else { Clean 'Print Spooler is stopped or disabled on this Domain Controller' }

    Begin-Check 'dczerologon'
    $fscp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection'
    if ($null -eq $fscp -or [int]$fscp -ne 1) {
        Report -Severity 'AMBER' -Check 'dczerologon' -Subject 'FullSecureChannelProtection' `
            -Description 'Netlogon secure channel is not strictly enforced (Zerologon CVE-2020-1472 risk)' `
            -Detail @('Without FullSecureChannelProtection=1, vulnerable domain controllers can permit unsecure Netlogon channels.') `
            -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'' -Name ''FullSecureChannelProtection'' -Value 1 -Type DWord') `
            -Card 'CARD W10'
    } else { Clean 'Netlogon FullSecureChannelProtection is enforced' }

    Begin-Check 'dcldapsign'
    # The scoring-breaking direction is the one to report. The packet scores AD
    # with "an LDAP login using a valid username and password"; a DC that
    # REQUIRES signing refuses every plain LDAP bind outside TLS. Measured on a
    # 2016 DC: LDAPServerIntegrity=2 made `ldapwhoami -x` fail "Strong(er)
    # authentication required (8)"; back at 1 it worked at once. An earlier
    # version of this check told you to SET 2 - an AMBER that took AD down.
    $ldapsign = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
    $ldapcbt  = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding'
    if ($null -ne $ldapsign -and [int]$ldapsign -ge 2) {
        Report -Severity 'RED' -Check 'dcldapsign' -Subject 'LDAPServerIntegrity' `
            -Description 'LDAP signing is REQUIRED: plain LDAP logins are refused, and that is very likely how AD is scored' `
            -Detail @('With LDAPServerIntegrity=2 the DC rejects every simple bind that is not inside TLS.',
                      'Unless the packet says the scorer uses LDAPS or signed binds, put it back to negotiate (1).',
                      'Somebody set this - you, a hardening script, or the red team denying your AD points.') `
            -Fix @('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'' -Name LDAPServerIntegrity -Value 1 -Type DWord',
                   'Remove-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue',
                   '# takes effect at once; check with an LDAP login as a scored account') `
            -Card 'CARD W10'
    } elseif ($null -ne $ldapcbt -and [int]$ldapcbt -ge 2) {
        Report -Severity 'AMBER' -Check 'dcldapcbt' -Subject 'LdapEnforceChannelBinding' `
            -Description 'LDAP channel binding is ALWAYS enforced: LDAPS logins from clients without channel binding are refused' `
            -Fix @('Remove-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'' -Name LdapEnforceChannelBinding') `
            -Card 'CARD W10'
    } else { Clean 'LDAP signing is negotiated, not required - plain LDAP logins (the likely AD score check) are accepted' }

    Begin-Check 'dcmachinequota'
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $dn = $rootDse.defaultNamingContext
        if ($dn) {
            $domainObj = [ADSI]"LDAP://$dn"
            $quota = $domainObj.Get('ms-DS-MachineAccountQuota')
            if ($null -ne $quota -and [int]$quota -gt 0) {
                Report -Severity 'AMBER' -Check 'dcmachinequota' -Subject ('ms-DS-MachineAccountQuota={0}' -f $quota) `
                    -Description ('unprivileged domain users can create {0} machine accounts (MachineAccountQuota > 0)' -f $quota) `
                    -Detail @(('ms-DS-MachineAccountQuota is currently {0}.' -f $quota),
                              'Any standard domain user can join computer accounts, enabling RBCD and NTLM relay attacks.') `
                    -Fix @('$d = [ADSI]("LDAP://" + ([ADSI]"LDAP://RootDSE").defaultNamingContext); $d.Put("ms-DS-MachineAccountQuota", 0); $d.SetInfo()') `
                    -Card 'CARD W10'
            } else { Clean 'Active Directory MachineAccountQuota is 0' }
        }
    } catch { }
}

$tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpDeny = Get-RegValue -Path $tsPath -Name 'fDenyTSConnections'
$rdpOn   = ($null -ne $rdpDeny -and [int]$rdpDeny -eq 0)
if ($rdpOn) {
    $nla = Get-RegValue -Path ($tsPath + '\WinStations\RDP-Tcp') -Name 'UserAuthentication'
    if ($null -eq $nla -or [int]$nla -ne 1) {
        Report -Severity 'RED' -Check 'rdpnla' -Subject 'UserAuthentication' `
            -Description 'RDP is enabled without Network Level Authentication' `
            -Detail @('Without NLA the box builds a full desktop session BEFORE anyone',
                      'proves who they are. That is both a way in and a way to exhaust',
                      'the box with connections.') `
            -Fix @(("Set-ItemProperty -Path '{0}\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" -f $tsPath)) `
            -Card 'CARD W10'
    } else { Clean 'RDP requires Network Level Authentication' }

    $rdu = @()
    try { $rdu = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop) } catch { }
    foreach ($m in $rdu) {
        $mn = ''
        try { $mn = ([string]$m.Name -split '\\')[-1] } catch { }
        if ([string]::IsNullOrWhiteSpace($mn)) { continue }
        if (Test-CcdcListContains -Needle $mn -List $allowedUsers) { continue }
        Report -Severity 'AMBER' -Check 'rdpusers' -Subject $mn `
            -Description 'can log in over RDP but is not named in the packet' `
            -Detail @('Remote Desktop Users is a quieter place to hide access than',
                      'Administrators, and it is rarely looked at.') `
            -Fix @(("Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member {0}" -f (Q $mn))) `
            -Card 'CARD W10'
    }
    if (@($rdu).Count -gt 0) { Clean ("{0} member(s) of Remote Desktop Users reviewed" -f @($rdu).Count) }
}

# =============================================================================
# 12. NETWORK BROADCAST POISONING (LLMNR / NetBIOS)
# =============================================================================
Begin-Check 'broadcast'
$dnsClientKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$llmnrVal = Get-RegValue -Path $dnsClientKey -Name 'EnableMulticast'
if ($null -eq $llmnrVal -or [int]$llmnrVal -ne 0) {
    Report -Severity 'AMBER' -Check 'llmnr' -Subject 'EnableMulticast' `
        -Description 'LLMNR is enabled; susceptible to Responder NTLMv2 hash poisoning' `
        -Detail @('When DNS resolution fails, Windows broadcasts on UDP 5355.',
                  'Responder or Inveigh answers these requests on the subnet to capture NTLMv2 hashes.') `
        -Fix @(("if (-not (Test-Path -LiteralPath '{0}')) {{ New-Item -Path '{0}' -Force | Out-Null }}" -f $dnsClientKey),
               ("Set-ItemProperty -Path '{0}' -Name EnableMulticast -Value 0 -Type DWord" -f $dnsClientKey)) `
        -Card 'CARD W10'
} else { Clean 'LLMNR multicast resolution is disabled' }

$netbiosEnabled = $false
try {
    $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)
    foreach ($nic in $adapters) {
        if ($null -ne $nic.TcpipNetbiosOptions -and [uint32]$nic.TcpipNetbiosOptions -ne 2) {
            $netbiosEnabled = $true; break
        }
    }
} catch { }
if ($netbiosEnabled) {
    Report -Severity 'AMBER' -Check 'netbios' -Subject 'NetBT' `
        -Description 'NetBIOS over TCP/IP is active; susceptible to NBT-NS spoofing' `
        -Detail @('NetBIOS name service broadcasts on UDP 137 can be spoofed by attackers on the local subnet.') `
        -Fix @('Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ''IPEnabled=True'' | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } }') `
        -Card 'CARD W10'
} else { Clean 'NetBIOS over TCP/IP is disabled on active adapters' }

# =============================================================================
# 13. WEB ROOT / WEBSHELLS (IIS / W3SVC)
# =============================================================================
Begin-Check 'webroot'
$webRoots = @()
if (Test-Path -LiteralPath 'C:\inetpub\wwwroot') { $webRoots += 'C:\inetpub\wwwroot' }
$customWeb = Get-CcdcValue -Config $cfg -Name 'CCDC_WINDOWS_WEB_ROOT'
if ($customWeb -and (Test-Path -LiteralPath $customWeb) -and ($webRoots -notcontains $customWeb)) {
    $webRoots += $customWeb
}
if ($webRoots.Count -gt 0) {
    # Inspect only scripts that a web server might execute. Do not read arbitrary
    # binaries or enormous uploads into memory during a triage pass.
    $webScriptExtensions = @('.asp','.aspx','.ashx','.asmx','.php','.jsp','.jspx','.cgi','.pl','.py','.rb','.ps1','.bat','.cmd','.vbs')
    $webMaxBytes = 2MB
    # Execution primitives only. Reading Request.Form or Request[...] is what
    # every ordinary ASP.NET page does; flagging it RED sends the operator to
    # delete the scored site. A webshell must run something, so match that.
    $webshellSig = '(?i)(eval\s*\(|cmd\.exe|powershell(\.exe)?|ProcessStartInfo|System\.Diagnostics\.Process|base64_decode|shell_exec|passthru|exec\s*\()'
    $webFilesChecked = 0
    $webFilesSkippedLarge = 0
    foreach ($root in $webRoots) {
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)
        } catch { }
        foreach ($f in $files) {
            $webFilesChecked++
            # Skip known canaries.
            if ($f.Name -match '(?i)^web\.config\.bak$') { continue }
            if ($webScriptExtensions -contains $f.Extension.ToLowerInvariant()) {
                if ($f.Length -gt $webMaxBytes) { $webFilesSkippedLarge++; continue }
                $isMalicious = $false
                $matchedSnippet = ''
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName)
                    if ($content -match $webshellSig) {
                        $isMalicious = $true
                        $matchedSnippet = $Matches[0]
                    }
                } catch { }

                if ($isMalicious) {
                    Report -Severity 'RED' -Check 'webshell' -Subject $f.FullName `
                        -Description ('web script matches webshell signature or command execution pattern: {0}' -f $f.Name) `
                        -Detail @(('  file: {0} ({1} bytes)' -f $f.FullName, $f.Length),
                                  ('  matched pattern: {0}' -f $matchedSnippet),
                                  'Webshells in wwwroot provide remote unauthenticated command execution.') `
                        -Fix @(("Get-FileHash -Algorithm SHA256 -LiteralPath {0}" -f (Q $f.FullName)),
                               ("Get-Content -LiteralPath {0} -TotalCount 80" -f (Q $f.FullName)),
                               '# Preserve the file and confirm it is not a legitimate application handler before removal.') `
                        -Card 'CARD W3'
                } elseif ($facts['BoxBuilt'] -and $f.LastWriteTimeUtc -gt $facts['BoxBuilt'].AddHours(2)) {
                    Report -Severity 'AMBER' -Check 'newwebfile' -Subject $f.FullName `
                        -Description ('executable web script placed in web root after box installation: {0}' -f $f.Name) `
                        -Detail @(('  file: {0} ({1} bytes)' -f $f.FullName, $f.Length),
                                  ('  last write time: {0}' -f $f.LastWriteTime)) `
                        -Fix @(("Get-FileHash -Algorithm SHA256 -LiteralPath {0}" -f (Q $f.FullName)),
                               ("Get-Content -LiteralPath {0} -TotalCount 80" -f (Q $f.FullName)),
                               '# This is a date-based lead, not proof. Preserve and review it before removal.') `
                        -Card 'CARD W3'
                }
            }
        }
    }
    if ($webFilesSkippedLarge -gt 0) {
        Report -Severity 'NOTE' -Check 'webroot' -Subject ($webFilesSkippedLarge.ToString() + ' oversized scripts') `
            -Description 'web scripts larger than 2 MiB were not read during triage' `
            -Detail @('This limit avoids loading unbounded content. Review these files manually if the packet makes them important.')
    }
    Clean ("web root reviewed ({0} file(s) checked; scripts are capped at 2 MiB)" -f $webFilesChecked)
}

# =============================================================================
# THE REPORT
# =============================================================================

if (-not $NoEvidence) {
    $ev = New-CcdcEvidenceDir -Label 'triage'
    Save-CcdcEvidence -Dir $ev -Name 'admins'    -Command { $adminMembers | Format-Table -AutoSize }
    Save-CcdcEvidence -Dir $ev -Name 'services'  -Command { $services | Select-Object Name,State,StartMode,StartName,PathName | Format-Table -AutoSize }
    Save-CcdcEvidence -Dir $ev -Name 'listening' -Command { $listeners | Format-Table -AutoSize }
    Save-CcdcEvidence -Dir $ev -Name 'facts'     -Command { $facts.GetEnumerator() | Format-Table -AutoSize }
}
Save-CcdcFindings

if (-not $Quiet) {
    Write-Host ''
    Write-Host '=================================================================='
    if (@($script:redBuf).Count -gt 0) {
        Write-Host ''
        Write-Host ('  RED - act on these now ({0})' -f $script:redCount) -ForegroundColor Red
        Write-Host ''
        foreach ($l in $script:redBuf) { Write-Host $l }
    }
    if (@($script:amberBuf).Count -gt 0) {
        Write-Host ''
        Write-Host ('  AMBER - this may well be yours; you decide ({0})' -f $script:amberCount) -ForegroundColor Yellow
        Write-Host ''
        foreach ($l in $script:amberBuf) { Write-Host $l }
    }
    if ($script:redCount -eq 0 -and $script:amberCount -eq 0) {
        Write-Host ''
        Write-Host '  Nothing this tool knows how to look for is wrong on this box.'
        Write-Host '  That is not the same as clean. It is the same as "not one of these".'
    }

    Write-Host ''
    Write-Host ('  {0} check(s) run: {1} RED, {2} AMBER.' -f $script:checks, $script:redCount, $script:amberCount)
    Write-Host ('  findings file: {0}' -f (Get-CcdcPath 'state\findings.txt'))
    if (-not $NoEvidence) { Write-Host ('  evidence:      {0}' -f $ev) }
    Write-Host ''
    Write-Host '  Verify your scored services FROM ANOTHER MACHINE. Nothing running on'
    Write-Host '  this box can tell you whether the scoring engine can reach it.'
    Write-Host ''
}

if ($script:redCount -gt 0) { exit 3 }
exit 0
