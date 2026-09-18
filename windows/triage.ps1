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
    [Parameter(Mandatory)][string]$Config,
    [switch]$Quiet,
    [switch]$NoEvidence
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
Initialize-CcdcRoot
Clear-CcdcFindings

$facts     = Get-CcdcBoxFacts
$builtTime = Get-CcdcBoxBuiltTime
$allowedUsers    = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS'
$allowedTcpPorts = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_TCP_PORTS'
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
    if ($Fix.Count -gt 0) {
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

if ($adminMembers.Count -eq 0) {
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
    if ($unexpected.Count -gt 0) {
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
        Clean ("Administrators group holds only accounts the packet names ({0})" -f $adminMembers.Count)
    }
}

Begin-Check 'localusers'
$localUsers = @()
if (-not $isDC) {
    try { $localUsers = @(Get-LocalUser -ErrorAction Stop) } catch { }
}
if ($localUsers.Count -gt 0) {
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
                -Detail @('Anyone at the console, and anyone who can reach a network logon,',
                          'is this account.') `
                -Fix @(("net user {0} *        # you will be prompted; it is not echoed" -f $short)) `
                -Card 'CARD W1'
        }
    }
    Clean ("{0} local account(s) reviewed" -f $localUsers.Count)
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
Clean ("{0} scored account(s) checked for availability" -f $allowedUsers.Count)

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

if ($services.Count -eq 0) {
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
    Clean ("{0} service(s) reviewed for path, quoting and logon account" -f $services.Count)
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
if ($scoredServices.Count -gt 0) { Clean ("{0} scored service(s) checked" -f $scoredServices.Count) }

# =============================================================================
# 3. SCHEDULED TASKS - persistence that does not need a service
# =============================================================================

Begin-Check 'tasks'
$tasks = @()
if ($facts['HasScheduledTasks']) {
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { }
}
if ($tasks.Count -gt 0) {
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
    Clean ("{0} scheduled task(s) reviewed" -f $tasks.Count)
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
            } else {
                Report -Severity 'NOTE' -Check 'autorun' -Subject ('{0}\{1}' -f $k, $p.Name) `
                    -Description $val -Card 'CARD W4'
            }
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
if ($listeners.Count -gt 0) {
    $byPort = $listeners | Sort-Object LocalPort -Unique
    foreach ($l in $byPort) {
        $port = [string]$l.LocalPort
        if (Test-CcdcListContains -Needle $port -List $allowedTcpPorts) { continue }
        # 135/139/445 and the ephemeral RPC range are stock Windows noise. They
        # are attack surface, but they are not a finding - reporting them every
        # pass is how a list stops being read.
        if ($port -in @('135','139','445','5985','49664','49665','49666','49667','49668','49669','49670')) { continue }
        if ([int]$port -ge 49152) { continue }

        $procName = 'unknown'; $procPath = ''
        try {
            $p = Get-Process -Id $l.OwningProcess -ErrorAction Stop
            $procName = $p.ProcessName
            try { $procPath = $p.Path } catch { }
        } catch { }

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
                       ("New-NetFirewallRule -DisplayName 'CCDC block {0}' -Direction Inbound -LocalPort {0} -Protocol TCP -Action Block" -f $port)) `
                -Card 'CARD W5'
        }
    }
    Clean ("{0} listening TCP port(s) reviewed" -f $byPort.Count)
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
                -Fix @('Update-MpSignature') -Card 'CARD W6'
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
        foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)) {
            $ports = @()
            try { $ports = @((Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).LocalPort) } catch { }
            foreach ($pt in $ports) {
                if ([string]::IsNullOrWhiteSpace($pt) -or $pt -eq 'Any') { continue }
                if ($pt -notmatch '^\d+$') { continue }
                if (Test-CcdcListContains -Needle $pt -List $allowedTcpPorts) { continue }
                if (Test-CcdcListContains -Needle $pt -List $allowedUdpPorts) { continue }
                if ($r.DisplayName -match '(?i)^(Core Networking|File and Printer|Windows Defender|Remote Assistance|mDNS|Network Discovery|Windows Remote Management)') { continue }
                Report -Severity 'AMBER' -Check 'fwallow' -Subject ('{0} -> {1}' -f $r.DisplayName, $pt) `
                    -Description 'an inbound ALLOW rule for a port the packet does not name' `
                    -Detail @('Either you opened it for a scored service and have not written it',
                              'into the config, or somebody else opened it.') `
                    -Fix @(("Get-NetFirewallRule -DisplayName {0} | Format-List DisplayName,Description,Enabled,Profile" -f (Q $r.DisplayName)),
                           ("Disable-NetFirewallRule -DisplayName {0}" -f (Q $r.DisplayName))) `
                    -Card 'CARD W7'
            }
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
               '.\windows\audit.ps1 -Config CONFIG -Apply') `
        -Card 'CARD W8'
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
    if ($script:redBuf.Count -gt 0) {
        Write-Host ''
        Write-Host ('  RED - act on these now ({0})' -f $script:redCount) -ForegroundColor Red
        Write-Host ''
        foreach ($l in $script:redBuf) { Write-Host $l }
    }
    if ($script:amberBuf.Count -gt 0) {
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
