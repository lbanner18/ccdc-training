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
$findingsFile = Join-Path (Join-Path $work 'state') 'findings.txt'

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

# A path helper that returns nothing on failure writes files into whatever the
# current directory happens to be. This one got as far as committing a findings
# file called ".tmp" to the repo root.
$stray = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $root -Filter '*.tmp' -File -ErrorAction SilentlyContinue)
if ($stray.Count -eq 0) { ok 'no tool wrote a stray temp file into the repo' }
else { nope ("a tool wrote into the repo root: {0}" -f (($stray | ForEach-Object Name) -join ', ')) }

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

# =============================================================================
# sentry.ps1 - the only Windows tool that applies a batch of changes from a list
#
# Its safety rests on four properties. None of them is visible in a normal run,
# because a run where they hold looks exactly like a run where they do not
# until the day a sweep disables the account the scoring engine logs in with.
# =============================================================================
$sentryPath = Join-Path $root 'windows\sentry.ps1'
if (-not (Test-Path -LiteralPath $sentryPath)) {
    nope 'windows\sentry.ps1 is missing'
} else {
    $sentryTxt = Get-Content -LiteralPath $sentryPath -Raw

    if ($sentryTxt -match '\[switch\]\$Apply') { ok 'sentry.ps1 cannot change anything without -Apply' }
    else { nope 'sentry.ps1 has no -Apply gate' }

    if ($sentryTxt -match 'Assert-CcdcPacketEntered') { ok 'sentry.ps1 refuses to act on an empty packet list' }
    else { nope 'sentry.ps1 applies changes without checking the packet lists are filled in' }

    # THE property. A sweep must never take an AMBER-tier action: those stop a
    # port, disable an account or remove a group membership, and on a box you
    # do not fully understand yet that is the self-inflicted outage the whole
    # kit exists to avoid. Named by number they apply like anything else.
    if ($sentryTxt -match '\$null -eq \$wanted -and \$tier -ne ''RED''') {
        ok 'a bulk approve cannot apply an AMBER-tier action'
    } else {
        nope 'the guard that stops a sweep taking AMBER actions is gone or changed shape'
    }

    # The approved item is re-verified by IDENTITY against a fresh scan, so a
    # finding that appeared after -Status cannot inherit a number.
    if ($sentryTxt -match '\$_\.Check -eq \$check -and \$_\.Subject -eq \$subject') {
        ok 'an approved item is re-verified by check and subject, not by position'
    } else {
        nope 'sentry.ps1 no longer re-verifies the approved identity against a fresh scan'
    }

    # Every action must be complete, correctly tiered, and name a check that
    # triage.ps1 can actually emit - a Do with no matching detector is an action
    # that can never run, and a typo'd key is silently never offered.
    $triageSrc = Get-Content -LiteralPath (Join-Path $root 'windows\triage.ps1') -Raw
    # [a-z0-9], not [a-z]: check names carry digits (smbv1), and a charset that
    # cannot match one makes a real action look like a typo.
    $triageChecks = @([regex]::Matches($triageSrc, "Check\s+'([a-z0-9]+)'") |
                      ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    $tokens = $null; $errs = $null
    $sentryAst = [System.Management.Automation.Language.Parser]::ParseFile($sentryPath, [ref]$tokens, [ref]$errs)
    $tableAst = $sentryAst.Find({
        param($n) $n -is [System.Management.Automation.Language.HashtableAst] -and
                  $n.KeyValuePairs.Count -gt 6 }, $true)
    $bad = @()
    $actionNames = @()
    if ($null -eq $tableAst) {
        $bad += 'could not find the action table'
    } else {
        foreach ($kv in $tableAst.KeyValuePairs) {
            $name = $kv.Item1.Extent.Text.Trim("'", '"')
            $actionNames += $name
            $body = $kv.Item2.Extent.Text
            if ($body -notmatch "Tier\s*=\s*'(RED|AMBER)'") { $bad += "$name has no RED/AMBER tier" }
            if ($body -notmatch 'What\s*=') { $bad += "$name has no What (the sentence shown before applying)" }
            if ($body -notmatch 'Do\s*=')   { $bad += "$name has no Do" }
            if ($triageChecks -notcontains $name) { $bad += "$name is not a check triage.ps1 emits" }
        }
    }
    if ($bad.Count -eq 0) {
        ok ("all {0} sentry actions are complete, tiered, and match a real triage check" -f $actionNames.Count)
    } else {
        nope ("sentry action table problems: {0}" -f ($bad -join '; '))
    }

    # The four findings deliberately left un-automatable. If one of these grows
    # an action, it should be a decision somebody argued for, not a drive-by.
    $neverAuto = @('fwinbound','lsappl','svcpath','svcdiracl')
    $grew = @($neverAuto | Where-Object { $actionNames -contains $_ })
    if ($grew.Count -eq 0) {
        ok 'the findings with no safe automatic fix are still not offered'
    } else {
        nope ("these became automatable without a decision: {0}" -f ($grew -join ', '))
    }

    $expectedNewActions = @('taskcmd','newtask','winlogon','svcaccount')
    $missingNewActions = @($expectedNewActions | Where-Object { $actionNames -notcontains $_ })
    if ($missingNewActions.Count -eq 0 -and $sentryTxt -match 'Export-ScheduledTask' -and $sentryTxt -match 'winlogon-before\.txt') {
        ok 'sentry offers the four evidenced scheduled-task, Winlogon, and service-account actions'
    } else {
        nope ("sentry is missing an evidenced action for: {0}" -f ($missingNewActions -join ', '))
    }
}

# =============================================================================
# baseline.ps1 - the drift tool
# =============================================================================
$blPath = Join-Path $root 'windows\baseline.ps1'
if (-not (Test-Path -LiteralPath $blPath)) {
    nope 'windows\baseline.ps1 is missing'
} else {
    $blTxt = Get-Content -LiteralPath $blPath -Raw

    if ($blTxt -match '\[switch\]\$Apply') { ok 'baseline.ps1 cannot freeze or allowlist without -Apply' }
    else { nope 'baseline.ps1 has no -Apply gate' }

    # An allowlist entry with no reason is indistinguishable an hour later from
    # a thing nobody looked at.
    if ($blTxt -match '-Allow needs -Reason') { ok 'baseline.ps1 refuses to allowlist without a reason' }
    else { nope 'baseline.ps1 will allowlist something without recording why' }

    # ConvertTo-Json defaults to -Depth 2 in PowerShell 5.1 and silently writes
    # "System.Collections.Hashtable" for anything deeper - which would make
    # every section of the manifest the same useless string, and the diff that
    # reads it would report nothing wrong forever.
    if ($blTxt -match 'ConvertTo-Json\s+-Depth\s+[3-9]') { ok 'the baseline manifest is serialised with an explicit -Depth' }
    else { nope 'ConvertTo-Json without -Depth: PowerShell 5.1 truncates at 2 and the manifest becomes uniform junk' }

    # Freezing on arrival makes whatever they left behind the definition of
    # normal. The tool has to say so where it will be read.
    if ($blTxt -match 'NOT on arrival' -or $blTxt -match 'becomes the new definition of normal') {
        ok 'baseline.ps1 warns that blessing a dirty box freezes the intrusion as normal'
    } else {
        nope 'baseline.ps1 no longer warns about blessing before you have cleaned the box'
    }
}

# =============================================================================
# guardian.ps1 - honest task redundancy, not magic
# =============================================================================
$guardianPath = Join-Path $root 'windows\guardian.ps1'
if (-not (Test-Path -LiteralPath $guardianPath)) {
    nope 'windows\guardian.ps1 is missing'
} else {
    $guardianTxt = Get-Content -LiteralPath $guardianPath -Raw
    if ($guardianTxt -match '\[switch\]\$Apply' -and $guardianTxt -match 'Write-PrivateCopies' -and
        $guardianTxt -match 'Repair-PrivateCopies' -and $guardianTxt -match 'Ensure-Watchdog') {
        ok 'guardian.ps1 gates installation and verifies a private watchdog repair authority'
    } else {
        nope 'guardian.ps1 lacks its apply gate, repair authority, or watchdog repair path'
    }
    if ($guardianTxt -match 'Administrator can remove or alter all three scheduled tasks') {
        ok 'guardian.ps1 states that an Administrator can defeat its redundancy'
    } else {
        nope 'guardian.ps1 overclaims tamper-proofing against Administrator'
    }
    if ($guardianTxt -match 'CCDC_WINDOWS_GUARDIAN_TASK' -and $guardianTxt -match 'CCDC_WINDOWS_WATCHDOG_TASK' -and $guardianTxt -match 'CCDC_WINDOWS_INTEGRITY_TASK' -and
        $guardianTxt -match 'CCDC_WINDOWS_GUARDIAN_FILE' -and $guardianTxt -match 'CCDC_WINDOWS_WATCHDOG_FILE' -and
        $guardianTxt -match 'CCDC_WINDOWS_CANARY_FILE' -and $guardianTxt -match 'CCDC_WINDOWS_INTEGRITY_FILE' -and
        $guardianTxt -match 'Ensure-IntegrityTask') {
        ok 'guardian.ps1 keeps task and private runtime names in the packet config'
    } else {
        nope 'guardian.ps1 hard-codes a conspicuous task or private runtime name'
    }
}

# =============================================================================
# integrity.ps1 - separate Guardian-chain check
# =============================================================================
$integrityPath = Join-Path $root 'windows\integrity.ps1'
if (-not (Test-Path -LiteralPath $integrityPath)) {
    nope 'windows\integrity.ps1 is missing'
} else {
    $integrityTxt = Get-Content -LiteralPath $integrityPath -Raw
    if ($integrityTxt -match '\[switch\]\$Apply' -and $integrityTxt -match 'Assert-CcdcPacketEntered') {
        ok 'integrity.ps1 requires an explicit apply and packet facts before installing its task'
    } else {
        nope 'integrity.ps1 can install a SYSTEM task without the normal safety gates'
    }
    if ($integrityTxt -match 'Get-ScheduledTask' -and $integrityTxt -match '\$privateGuardian' -and
        $integrityTxt -match 'REDIRECTED' -and $integrityTxt -match 'INTEGRITY-GAP') {
        ok 'integrity.ps1 detects a missing, stopped, or redirected Guardian task and records a gap'
    } else {
        nope 'integrity.ps1 does not check Guardian task identity and report an integrity gap'
    }
    if ($integrityTxt -match 'install this through guardian\.ps1' -and $integrityTxt -match 'CCDC_WINDOWS_INTEGRITY_TASK') {
        ok 'integrity.ps1 schedules only its private Guardian-installed copy'
    } else {
        nope 'integrity.ps1 can schedule an unprotected source-tree copy'
    }
}

# =============================================================================
# evidence.ps1 - off-box copy stays explicit and verified
# =============================================================================
$evidencePath = Join-Path $root 'windows\evidence.ps1'
if (-not (Test-Path -LiteralPath $evidencePath)) {
    nope 'windows\evidence.ps1 is missing'
} else {
    $evidenceTxt = Get-Content -LiteralPath $evidencePath -Raw
    if ($evidenceTxt -match '\[switch\]\$Apply' -and $evidenceTxt -match 'Destination must be a UNC share' -and
        $evidenceTxt -match 'Assert-CcdcAdmin') {
        ok 'evidence.ps1 requires apply, elevation, and an explicit off-box UNC destination'
    } else {
        nope 'evidence.ps1 can export without an explicit trusted off-box destination'
    }
    if ($evidenceTxt -match 'SHA256SUMS\.csv' -and $evidenceTxt -match 'Get-FileHash -LiteralPath \$remoteArchive' -and
        $evidenceTxt -match 'OFFBOX-EXPORTED') {
        ok 'evidence.ps1 packages manifests and verifies the copied ZIP before logging success'
    } else {
        nope 'evidence.ps1 does not verify its off-box archive copy'
    }
}

# =============================================================================
# timeline.ps1 - evidence has to be bounded, read-only, and honest about gaps
# =============================================================================
$timelinePath = Join-Path $root 'windows\timeline.ps1'
if (-not (Test-Path -LiteralPath $timelinePath)) {
    nope 'windows\timeline.ps1 is missing'
} else {
    $timelineTxt = Get-Content -LiteralPath $timelinePath -Raw
    if ($timelineTxt -notmatch '\[switch\]\$Apply') { ok 'timeline.ps1 is read-only by construction' }
    else { nope 'timeline.ps1 grew an -Apply switch; evidence collection must not mutate the box' }
    if ($timelineTxt -match '\[int\]\$Hours' -and $timelineTxt -match 'between 1 and 168' -and $timelineTxt -match 'MaxEventsPerSource') {
        ok 'timeline.ps1 bounds both its time window and per-source event volume'
    } else { nope 'timeline.ps1 can collect an unbounded event-log dump' }
    if ($timelineTxt -match 'Microsoft-Windows-PowerShell/Operational' -and $timelineTxt -match 'Microsoft-Windows-TaskScheduler/Operational' -and $timelineTxt -match 'Windows Defender/Operational') {
        ok 'timeline.ps1 joins the high-value PowerShell, task, and Defender evidence sources'
    } else { nope 'timeline.ps1 is missing a high-value incident evidence source' }
    if ($timelineTxt -match 'collection-gaps\.csv' -and $timelineTxt -match 'No events were found' -and $timelineTxt -match 'SHA256SUMS\.csv') {
        ok 'timeline.ps1 distinguishes an empty log from a collection gap and hashes its evidence'
    } else { nope 'timeline.ps1 can confuse empty logs, failed collection, or unhashed evidence' }
}

# =============================================================================
# surface.ps1 - the inject-ready execution table
# =============================================================================
$surfacePath = Join-Path $root 'windows\surface.ps1'
$commonPath = Join-Path $root 'windows\lib\Common.ps1'
$baselinePath = Join-Path $root 'windows\baseline.ps1'
$reconPath = Join-Path $root 'windows\recon.ps1'
if (-not (Test-Path -LiteralPath $surfacePath)) {
    nope 'windows\surface.ps1 is missing'
} else {
    $surfaceTxt = Get-Content -LiteralPath $surfacePath -Raw
    if ($surfaceTxt -notmatch '\[switch\]\$Apply') { ok 'surface.ps1 is read-only by construction' }
    else { nope 'surface.ps1 grew an -Apply switch; reporting the surface must not mutate it' }
    if ($surfaceTxt -match 'Get-NetTCPConnection' -and $surfaceTxt -match 'Get-ScheduledTask' -and
        $surfaceTxt -match 'Get-ItemProperty' -and $surfaceTxt -match 'REVIEW') {
        ok 'surface.ps1 joins listeners and the main Windows autostarts into a verdict table'
    } else {
        nope 'surface.ps1 is missing a listener, autostart, or REVIEW branch'
    }
    if ($surfaceTxt -match '\[switch\]\$Table' -and $surfaceTxt -match 'Write-MarkdownTable') {
        ok 'surface.ps1 offers an explicit markdown table mode for injects'
    } else {
        nope 'surface.ps1 has no inject-ready table mode'
    }
    if ($surfaceTxt -match '\$ownerPid' -and $surfaceTxt -notmatch '(?im)^\s*\$pid\s*=') {
        ok 'surface.ps1 does not assign PowerShell''s read-only automatic $PID variable'
    } else {
        nope 'surface.ps1 assigns $PID, so its listener owner column cannot run on real Windows'
    }
    if ($surfaceTxt -match 'Image File Execution Options' -and $surfaceTxt -match 'Active Setup' -and
        $surfaceTxt -match '__EventConsumer' -and $surfaceTxt -match 'AppInit_DLLs') {
        ok 'surface.ps1 covers selected high-value logon mechanisms beyond Run keys without claiming full Autoruns coverage'
    } else {
        nope 'surface.ps1 did not add the selected IFEO, Active Setup, WMI, and AppInit logon mechanisms'
    }
    if ($surfaceTxt -match 'Get-AutorunscRows' -and $surfaceTxt -match 'Invoke-CcdcAutorunsc') {
        ok 'surface.ps1 can add explicitly configured Autorunsc evidence without an apply path'
    } else {
        nope 'surface.ps1 does not wire optional Autorunsc evidence into its table'
    }
}
if (-not (Test-Path -LiteralPath $commonPath) -or -not (Test-Path -LiteralPath $baselinePath) -or -not (Test-Path -LiteralPath $reconPath)) {
    nope 'optional Autorunsc collector files are missing'
} else {
    $commonTxt = Get-Content -LiteralPath $commonPath -Raw
    $baselineTxt = Get-Content -LiteralPath $baselinePath -Raw
    $reconTxt = Get-Content -LiteralPath $reconPath -Raw
    if ($commonTxt -match 'function Invoke-CcdcAutorunsc' -and $commonTxt -match 'CCDC_AUTORUNSC_PATH' -and
        $commonTxt -match 'Get-AuthenticodeSignature' -and $commonTxt -match 'PATH lookup is intentionally disabled') {
        ok 'Autorunsc collector requires an explicit path and verifies its publisher'
    } else {
        nope 'Autorunsc collector can still discover or run an unverified binary'
    }
    if ($commonTxt -match 'CCDC_AUTORUNSC_ACCEPT_EULA' -and $commonTxt -match "'-accepteula'" -and
        $commonTxt -match 'EULA is not accepted') {
        ok 'Autorunsc EULA acceptance is an explicit config choice'
    } else {
        nope 'Autorunsc EULA handling is missing or implicit'
    }
    if ($baselineTxt -match 'Invoke-CcdcAutorunsc' -and $baselineTxt -notmatch "Get-Command 'autorunsc.exe'" -and
        $baselineTxt -notmatch '\-accepteula' -and $reconTxt -match "Save-Command 'autorunsc'") {
        ok 'baseline and recon share the constrained Autorunsc evidence collector'
    } else {
        nope 'baseline or recon bypasses the constrained Autorunsc collector'
    }
}

# =============================================================================
# canary.ps1 - the tripwires
# =============================================================================
$cnPath = Join-Path $root 'windows\canary.ps1'
if (-not (Test-Path -LiteralPath $cnPath)) {
    nope 'windows\canary.ps1 is missing'
} else {
    $cnTxt = Get-Content -LiteralPath $cnPath -Raw

    if ($cnTxt -match '\[switch\]\$Apply') { ok 'canary.ps1 cannot lay or remove tripwires without -Apply' }
    else { nope 'canary.ps1 has no -Apply gate' }

    # A SACL with the audit policy off produces no records at all, silently.
    if ($cnTxt -match 'auditpol' -and $cnTxt -match 'FileSystemAuditRule') {
        ok 'canary.ps1 sets both the SACL and the audit policy a SACL needs'
    } else {
        nope 'canary.ps1 sets one of the SACL / audit policy pair but not the other'
    }

    # -Check must never read a canary while auditing is on: reading it produces
    # the same 4663 an attacker's read does, and the tool reports its own
    # footprints for ever. Two filtering approaches failed on the lab box before
    # this became "do not make the read".
    if ($cnTxt -match 'if \(\$auditOn\) \{ continue \}') {
        ok 'canary.ps1 -Check does not read the files it is watching while auditing is on'
    } else {
        nope 'canary.ps1 hashes its canaries during -Check again; it will report its own reads as trips'
    }

    if ($cnTxt -match 'AddSeconds\(10\)') { ok 'canary.ps1 leaves Windows time to commit deployment audit events' }
    else { nope 'canary.ps1 can immediately report its own delayed deployment audit events as a trip' }

    # Every decoy has to be obviously a decoy to the operator, on line one.
    $bodies = [regex]::Matches($cnTxt, "Body = @'\r?\n(.*?)'@", 'Singleline')
    $unmarked = @()
    foreach ($m in $bodies) {
        $first = ($m.Groups[1].Value -split "`r?`n")[0]
        if ($first -notmatch '(?i)canary|decoy') { $unmarked += $first }
    }
    if ($bodies.Count -gt 0 -and $unmarked.Count -eq 0) {
        ok ("all {0} decoys say they are decoys on their first line" -f $bodies.Count)
    } else {
        nope ("a decoy does not identify itself, so it reads as a real credential file you forgot: {0}" -f ($unmarked -join '; '))
    }

    # -Check is the loopable one. It must have no way to change the box.
    if ($cnTxt -match '-Check never changes anything') { ok 'canary.ps1 documents -Check as read-only and loopable' }
    else { nope 'canary.ps1 no longer promises -Check is safe to run in a loop' }
}

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

# Canary exits 2 on a trip. The watchdog must run it in a child process, record
# that outcome, and keep its own scheduled loop alive rather than exiting too.
$watchdogTxt = Get-Content -LiteralPath (Join-Path $root 'windows\watchdog.ps1') -Raw
if ($watchdogTxt -match 'canary\.ps1' -and $watchdogTxt -match 'CANARY-TRIPPED' -and $watchdogTxt -match '\$canaryExit -eq 2') {
    ok 'watchdog.ps1 checks laid canaries and survives canary exit 2'
} else {
    nope 'watchdog.ps1 does not safely turn a canary trip into a durable alert'
}
if ($watchdogTxt -match 'Stop-ScheduledTask[\s\S]*Unregister-ScheduledTask') {
    ok 'watchdog.ps1 stops a running task before replacing or uninstalling it'
} else {
    nope 'watchdog.ps1 can leave a running loop behind after task removal'
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ("windows self-test: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
