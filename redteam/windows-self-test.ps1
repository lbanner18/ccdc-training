<#
    windows-self-test.ps1 - exercise the Windows tools without a Windows box.

    WHY THIS EXISTS

    The Windows half of this kit was written on a Linux host with no Windows
    machine to try it on. Parsing a script proves it is syntactically valid; it
    proves nothing about whether the detection logic fires, whether a finding
    comes out with the right severity, or whether the "run this" block names the
    thing that was actually found.

    So the Windows cmdlets are stubbed here and fed known-bad fixtures - a rogue
    administrator, a service running out of Temp, an accessibility debugger, a
    Defender exclusion - and the test asserts the findings that must come back.
    That is the same shape as the Linux self-tests: plant something, run the
    detector, insist it is found.

    WHAT IT DOES NOT PROVE

    That the real cmdlets return what these stubs return. The stubs are written
    from the documented shapes, and a real box will differ in ways this cannot
    see. Treat a green run as "the logic is right", never as "it works on
    Windows". The only thing that proves the second one is a Windows box.

    Run:  pwsh -NoProfile -File redteam/windows-self-test.ps1
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
$pass = 0; $fail = 0
function ok   { param([string]$m) $script:pass++; Write-Host ("ok     - {0}" -f $m) }
function nope { param([string]$m) $script:fail++; Write-Host ("not ok - {0}" -f $m) -ForegroundColor Red }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("ccdc-wintest-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:CCDC_WIN_ROOT = $work
$env:CCDC_WIN_FAKE_ADMIN = '1'
$env:CCDC_WIN_FAKE_MODULES = '1'

$cfgPath = Join-Path $work 'test.env'
@'
CCDC_BOX_NAME="win-target"
CCDC_ALLOWED_USERS="Administrator banneluk svc_web"
CCDC_WINDOWS_SERVICES="W3SVC"
CCDC_ALLOWED_TCP_PORTS="80 443 3389"
CCDC_ALLOWED_UDP_PORTS="53"
CCDC_TCP_CHECKS="127.0.0.1:80"
CCDC_HTTP_CHECKS="http://127.0.0.1/"
'@ | Set-Content -LiteralPath $cfgPath -Encoding UTF8

# =============================================================================
# THE FIXTURES - one planted thing per detector, and a decoy for each that must
# NOT be reported, because a detector that fires on everything is not a
# detector.
# =============================================================================

function Get-LocalGroupMember {
    param($Group, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    @(
        [pscustomobject]@{ Name = 'WIN-TARGET\Administrator'; ObjectClass = 'User' },
        [pscustomobject]@{ Name = 'WIN-TARGET\banneluk';      ObjectClass = 'User' },
        [pscustomobject]@{ Name = 'WIN-TARGET\sqlsvc_';       ObjectClass = 'User' }   # PLANT
    )
}

# $global:, not $script:. A stub defined here but CALLED from triage.ps1 runs
# with triage.ps1 as its script scope, so $global:boxBuilt is undefined there,
# StrictMode throws, triage's try/catch swallows it, and four detectors look
# like they simply found nothing. That cost four false failures.
$global:boxBuilt = (Get-Date).AddDays(-30)

function Get-LocalUser {
    param([string]$Name, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    $all = @(
        [pscustomobject]@{ Name='Administrator'; Enabled=$true;  PasswordLastSet=$global:boxBuilt; PasswordRequired=$true },
        [pscustomobject]@{ Name='banneluk';      Enabled=$true;  PasswordLastSet=$global:boxBuilt; PasswordRequired=$true },
        [pscustomobject]@{ Name='svc_web';       Enabled=$false; PasswordLastSet=$global:boxBuilt; PasswordRequired=$true },  # PLANT: scored + disabled
        [pscustomobject]@{ Name='sqlsvc_';       Enabled=$true;  PasswordLastSet=(Get-Date);       PasswordRequired=$true },  # PLANT: new
        [pscustomobject]@{ Name='kiosk';         Enabled=$true;  PasswordLastSet=$global:boxBuilt; PasswordRequired=$false }, # PLANT: no password
        [pscustomobject]@{ Name='Guest';         Enabled=$true;  PasswordLastSet=$global:boxBuilt; PasswordRequired=$true }   # PLANT: guest on
    )
    if ($Name) {
        $hit = $all | Where-Object { $_.Name -eq $Name }
        if (-not $hit) { throw "User $Name was not found." }
        return $hit
    }
    return $all
}

function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    switch -Regex ($ClassName) {
        'Win32_OperatingSystem' {
            return [pscustomobject]@{
                Caption='Microsoft Windows Server 2019 Standard'; Version='10.0.17763'
                BuildNumber='17763'; InstallDate=$global:boxBuilt; LastBootUpTime=(Get-Date).AddHours(-3)
            }
        }
        'Win32_ComputerSystem' { return [pscustomobject]@{ DomainRole = 3; Domain = 'udder.local' } }
        'Win32_Service' {
            return @(
                [pscustomobject]@{ Name='W3SVC';     State='Running'; StartMode='Auto'; StartName='LocalSystem';
                                   PathName='C:\Windows\system32\svchost.exe -k iissvcs' },
                [pscustomobject]@{ Name='UpdaterSvc'; State='Running'; StartMode='Auto'; StartName='LocalSystem';
                                   PathName='C:\Users\Public\AppData\update.exe' },                    # PLANT: temp path
                [pscustomobject]@{ Name='LegacyApp'; State='Running'; StartMode='Auto'; StartName='LocalSystem';
                                   PathName='C:\Program Files\Legacy App\svc.exe -run' },             # PLANT: unquoted
                [pscustomobject]@{ Name='BackupSvc'; State='Running'; StartMode='Auto'; StartName='WIN-TARGET\sqlsvc_';
                                   PathName='"C:\Program Files\Backup\b.exe"' }                        # PLANT: odd account
            )
        }
        'Win32_Process' {
            return @(
                [pscustomobject]@{ ProcessId=4;    ExecutablePath='C:\Windows\System32\svchost.exe'; CommandLine='svchost.exe -k netsvcs' },
                [pscustomobject]@{ ProcessId=6612; ExecutablePath='C:\Users\banneluk\AppData\Local\Temp\rt.exe';
                                   CommandLine='rt.exe -connect 10.0.0.5:443' }                        # PLANT
            )
        }
    }
    return @()
}

function Get-Service {
    param([string]$Name, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    $all = @(
        [pscustomobject]@{ Name='W3SVC'; Status='Stopped'; StartType='Automatic' }   # PLANT: scored + stopped
    )
    if ($Name) { return ($all | Where-Object { $_.Name -eq $Name }) }
    return $all
}

function Get-NetTCPConnection {
    param([string]$State, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    @(
        [pscustomobject]@{ LocalPort=80;   OwningProcess=4;    LocalAddress='0.0.0.0' },
        [pscustomobject]@{ LocalPort=445;  OwningProcess=4;    LocalAddress='0.0.0.0' },
        [pscustomobject]@{ LocalPort=4444; OwningProcess=7710; LocalAddress='0.0.0.0' },  # PLANT: interpreter
        [pscustomobject]@{ LocalPort=8888; OwningProcess=7720; LocalAddress='0.0.0.0' }   # PLANT: unknown listener
    )
}

function Get-Process {
    param([int]$Id, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    switch ($Id) {
        7710 { return [pscustomobject]@{ ProcessName='powershell'; Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Id=7710 } }
        7720 { return [pscustomobject]@{ ProcessName='nginx';      Path='C:\nginx\nginx.exe'; Id=7720 } }
        4    { return [pscustomobject]@{ ProcessName='svchost';    Path='C:\Windows\System32\svchost.exe'; Id=4 } }
    }
    throw "no process $Id"
}

function Get-MpPreference {
    [pscustomobject]@{
        ExclusionPath      = @('C:\Users\Public\Downloads')     # PLANT
        ExclusionProcess   = @()
        ExclusionExtension = @()
    }
}
function Get-MpComputerStatus {
    [pscustomobject]@{ RealTimeProtectionEnabled=$false; AntivirusEnabled=$true;   # PLANT: RTP off
                       AntispywareEnabled=$true; AntivirusSignatureAge=1 }
}

function Get-NetFirewallProfile {
    param([Parameter(ValueFromRemainingArguments=$true)]$Rest)
    @(
        [pscustomobject]@{ Name='Domain';  Enabled=$true;  DefaultInboundAction='Block'; LogAllowed='False'; LogBlocked='True' },
        [pscustomobject]@{ Name='Private'; Enabled=$true;  DefaultInboundAction='Block'; LogAllowed='False'; LogBlocked='True' },
        [pscustomobject]@{ Name='Public';  Enabled=$false; DefaultInboundAction='Allow'; LogAllowed='False'; LogBlocked='False' }  # PLANT x3
    )
}
function Get-NetFirewallRule { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) @() }
function Get-NetFirewallPortFilter { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) @() }
function Get-ScheduledTask { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) @() }
function Get-WinEvent { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) throw 'no events' }
function Get-Acl { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) throw 'not on linux' }
function Set-Acl { param([Parameter(ValueFromRemainingArguments=$true)]$Rest) }

# Registry: PLANT an IFEO debugger on sethc.exe and a bad Run key.
function Test-Path {
    param([Parameter(ValueFromPipeline=$true)]$Path, $LiteralPath, $PathType,
          [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -is [string] -and $p -match '^HK(LM|CU):') {
        return ($p -match 'CurrentVersion\\Run$' -or $p -match 'Image File Execution Options$' -or $p -match 'Winlogon$')
    }
    return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)
}
function Get-ItemProperty {
    param($LiteralPath, $Path, $Name, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -match 'Winlogon$') {
        return [pscustomobject]@{ Userinit='C:\Windows\system32\userinit.exe,C:\Users\Public\b.exe'; Shell='explorer.exe' }  # PLANT
    }
    if ($p -match 'CurrentVersion\\Run$') {
        return [pscustomobject]@{ OneDrive='C:\Program Files\OneDrive\OneDrive.exe /background'
                                  Updater='powershell -w hidden -enc SQBFAFgA' }   # PLANT
    }
    if ($p -match 'ScriptBlockLogging') { throw 'missing' }
    if ($p -match 'sethc') { return [pscustomobject]@{ Debugger='C:\Windows\System32\cmd.exe' } }   # PLANT
    throw 'missing'
}
function Get-ChildItem {
    param($LiteralPath, $Path, $Recurse, $File, $Filter,
          [Parameter(ValueFromRemainingArguments=$true)]$Rest)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -is [string] -and $p -match 'Image File Execution Options$') {
        return @([pscustomobject]@{ PSChildName='sethc.exe'; PSPath='HKLM:\...\sethc.exe' })
    }
    if ($LiteralPath) { return @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -ErrorAction SilentlyContinue) }
    return @()
}

# =============================================================================
# RUN IT
# =============================================================================

Write-Host ''
Write-Host '== windows triage, against planted fixtures =='
$out = & (Join-Path $root 'windows\triage.ps1') -Config $cfgPath -Quiet -NoEvidence 2>&1
$findingsFile = Join-Path $work 'state\findings.txt'

if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $findingsFile)) {
    nope 'triage wrote a findings file'
    Write-Host ($out | Out-String)
} else {
    ok 'triage wrote a findings file'
    $findings = @(Get-Content -LiteralPath $findingsFile | Where-Object { $_ -ne '' } | ForEach-Object {
        $f = $_ -split '\|', 4
        [pscustomobject]@{ Severity=$f[0]; Check=$f[1]; Subject=$f[2]; Description=$f[3] }
    })

    function Want {
        param([string]$Sev, [string]$Check, [string]$SubjectLike, [string]$Why)
        $hit = $findings | Where-Object { $_.Severity -eq $Sev -and $_.Check -eq $Check -and $_.Subject -like $SubjectLike }
        if ($hit) { ok $Why } else { nope ("{0} :: wanted {1} {2} like '{3}'" -f $Why, $Sev, $Check, $SubjectLike) }
    }
    function WantNot {
        param([string]$Check, [string]$SubjectLike, [string]$Why)
        $hit = $findings | Where-Object { $_.Check -eq $Check -and $_.Subject -like $SubjectLike }
        if ($hit) { nope ("{0} :: {1} {2} should NOT have been reported" -f $Why, $Check, $hit[0].Subject) } else { ok $Why }
    }

    Want 'RED'   'rogueadmin'    '*sqlsvc_*'      'an administrator the packet does not name is RED'
    WantNot      'rogueadmin'    '*banneluk*'     'an administrator the packet DOES name is not reported'
    Want 'RED'   'scoreduser'    'svc_web'        'a disabled SCORED account is RED - that is lost uptime'
    Want 'RED'   'newuser'       'sqlsvc_'        'an account whose password was set after the box was built is RED'
    Want 'RED'   'nopassword'    'kiosk'          'an account that needs no password is RED'
    Want 'RED'   'guest'         'Guest'          'an enabled Guest account is RED'
    Want 'RED'   'scoredservice' 'W3SVC'          'a stopped SCORED service is RED'
    Want 'RED'   'svcpath'       'UpdaterSvc'     'a service running out of a user-writable directory is RED'
    Want 'AMBER' 'svcunquoted'   'LegacyApp'      'an unquoted service path with a space is AMBER'
    Want 'AMBER' 'svcaccount'    'BackupSvc'      'a service logging on as an unnamed account is AMBER'
    WantNot      'svcpath'       'W3SVC'          'a stock svchost service is not reported as a bad path'
    Want 'RED'   'netproc'       'powershell:4444' 'an interpreter holding a listening port is RED'
    Want 'AMBER' 'listener'      'tcp/8888'       'an unaccounted listening port is AMBER'
    WantNot      'listener'      'tcp/445'        'stock Windows ports are not reported as unexpected listeners'
    WantNot      'listener'      'tcp/80'         'a port named in the packet is not reported'
    Want 'RED'   'tmpproc'       '*Temp\rt.exe'   'a process running from Temp is RED'
    Want 'RED'   'ifeo'          'sethc.exe'      'a debugger on sethc.exe is RED'
    Want 'RED'   'winlogon'      '*Userinit*'     'a modified Winlogon Userinit is RED'
    Want 'RED'   'runkey'        '*Updater*'      'an encoded-command Run key is RED'
    WantNot      'runkey'        '*OneDrive*'     'an ordinary Run key is not reported as a payload'
    Want 'RED'   'defenderoff'   'RealTimeProtection' 'Defender real-time protection off is RED'
    Want 'RED'   'defenderexcl'  '*Public\Downloads' 'a Defender exclusion is RED'
    Want 'RED'   'fwoff'         'Public'         'a firewall profile that is off is RED'
    Want 'RED'   'fwinbound'     'Public'         'default-allow inbound is RED'
    Want 'AMBER' 'psloggingoff'  'ScriptBlockLogging' 'script block logging being off is AMBER'

    # The contract every finding has to keep, whatever it is about.
    $badSubject = $findings | Where-Object { $_.Subject -match '\|' }
    if ($badSubject) { nope 'a finding subject contains the field delimiter' } else { ok 'no finding subject can split its own record' }
    $emptyDesc = $findings | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) }
    if ($emptyDesc) { nope ("{0} finding(s) have no description" -f $emptyDesc.Count) } else { ok 'every finding says what is wrong in words' }
    $badSev = $findings | Where-Object { $_.Severity -notin @('RED','AMBER','NOTE') }
    if ($badSev) { nope 'a finding has a severity outside RED/AMBER/NOTE' } else { ok 'every finding has a known severity' }
}

# =============================================================================
# THE CONTRACTS THAT HOLD WHATEVER THE FIXTURES ARE
# =============================================================================

# Every card a tool names has to exist. A reference pointing at nothing costs a
# page-turn to discover, mid-event, which is worse than no reference at all.
$cardFile = Join-Path $root 'playbooks\windows-cards.md'
if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $cardFile)) {
    nope 'playbooks\windows-cards.md exists'
} else {
    $haveCards = @([regex]::Matches((Get-Content -LiteralPath $cardFile -Raw), '(?m)^## (CARD W\d+)') |
                   ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique
    $named = @()
    foreach ($f in (Microsoft.PowerShell.Management\Get-ChildItem -Path (Join-Path $root 'windows') -Recurse -Filter *.ps1)) {
        $named += [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), 'CARD W\d+') |
                  ForEach-Object { $_.Value }
    }
    $named = @($named | Sort-Object -Unique)
    $missing = @($named | Where-Object { $_ -notin $haveCards })
    if ($missing.Count -eq 0) {
        ok ("every card the tools name exists ({0} named, {1} written)" -f $named.Count, $haveCards.Count)
    } else {
        nope ("tools point at cards that do not exist: {0}" -f ($missing -join ', '))
    }
}

# Windows PowerShell 5.1 is the floor. PS7-only syntax parses on the host that
# wrote it and is a syntax error on the box that has to run it.
$ps7 = @()
foreach ($f in (Microsoft.PowerShell.Management\Get-ChildItem -Path (Join-Path $root 'windows') -Recurse -Filter *.ps1)) {
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    if ($err -and $err.Count) { $ps7 += ("{0}: {1} syntax error(s)" -f $f.Name, $err.Count); continue }
    foreach ($t in ($tok | Where-Object { $_.Kind -ne 'Comment' })) {
        if ($t.Kind -in 'QuestionQuestion','QuestionQuestionEquals','QuestionDot','AndAnd','OrOr') {
            $ps7 += ("{0} line {1}: {2} needs PS7" -f $f.Name, $t.Extent.StartLineNumber, $t.Kind)
        }
    }
}
if ($ps7.Count -eq 0) { ok 'every Windows script parses and stays within PowerShell 5.1' }
else { nope ("PowerShell 5.1 problems: {0}" -f ($ps7 -join '; ')) }

# Nothing may change the box without -Apply. The whole kit's bargain.
foreach ($t in @('harden.ps1','users.ps1')) {
    $txt = Get-Content -LiteralPath (Join-Path $root "windows\$t") -Raw
    if ($txt -match '\[switch\]\$Apply') { ok "$t cannot change anything without -Apply" }
    else { nope "$t has no -Apply gate" }
}
# triage is read-only and must have no -Apply at all.
$triageTxt = Get-Content -LiteralPath (Join-Path $root 'windows\triage.ps1') -Raw
if ($triageTxt -notmatch '\[switch\]\$Apply') { ok 'triage.ps1 has no -Apply: it is read-only by construction' }
else { nope 'triage.ps1 grew an -Apply switch; it is supposed to be the tool you run while deciding' }

# The scored lists gate everything. An empty list must stop the tool, not be
# read as "nothing is protected".
foreach ($t in @('harden.ps1','watchdog.ps1')) {
    $txt = Get-Content -LiteralPath (Join-Path $root "windows\$t") -Raw
    if ($txt -match 'Assert-CcdcPacketEntered') { ok "$t refuses to act on an empty packet list" }
    else { nope "$t acts without checking that the packet lists are filled in" }
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ("windows self-test: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
