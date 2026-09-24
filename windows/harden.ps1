<#
.SYNOPSIS
    Work the Windows hardening checklist, in order, one command.

.DESCRIPTION
    This is the "just run it" tool. It walks the checklist from the team
    training material, in the order that does not lock you out of your own box,
    and it re-checks your scored services after every step that could affect
    them.

        Basic Windows Hardening Checklist
          1  Secure admin credentials                 -> users.ps1 (not here)
          2  Take backups of services and files       -> STEP: Backup
          3  Create a backup admin                    -> users.ps1 (not here)
          4  Secure user & service passwords          -> users.ps1 (not here)
          5  Audit users, remove unauthorized         -> triage.ps1 + users.ps1
          6  Set & enforce a password policy          -> STEP: PasswordPolicy
          7  Disable vulnerable services              -> STEP: Services
          8  Remove unneeded remote access            -> STEP: RemoteAccess
          9  Harden SSH / RDP                         -> STEP: RemoteAccess
          10 Enable and configure the firewall        -> STEP: Firewall
          11 Enable logging and monitoring            -> STEP: Logging
          12 Run a scan with Defender                 -> STEP: Defender
          13 Harden GPO/Registry/startup/tasks        -> STEP: Persistence

    The four checklist items about accounts are deliberately NOT here. Changing
    passwords is interactive, it is the single most destructive thing you can
    get wrong, and it belongs in a tool you run deliberately: users.ps1.

    NOTHING HAPPENS WITHOUT -Apply. With no -Apply this prints the entire plan,
    every command it would run, and changes not one thing.

.PARAMETER Only
    Run just one step. Backup, PasswordPolicy, Services, RemoteAccess,
    Firewall, Logging, Defender, Persistence.

.EXAMPLE
    .\harden.ps1 -Config C:\ProgramData\CCDC\ccdc.env
    Read the whole plan. Start here. Always.

.EXAMPLE
    .\harden.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Apply

.EXAMPLE
    .\harden.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Only Firewall -Apply
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Apply,
    [ValidateSet('Backup','PasswordPolicy','Services','RemoteAccess','Firewall','Logging','Defender','Persistence')]
    [string[]]$Only,
    # Say yes in advance to the one step that can cut your own session.
    [switch]$IHaveConsoleAccess
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']
Assert-CcdcAdmin
Initialize-CcdcRoot
$facts = Get-CcdcBoxFacts

$allSteps = @('Backup','PasswordPolicy','Services','RemoteAccess','Firewall','Logging','Defender','Persistence')
$steps = if ($Only) { @($Only) } else { $allSteps }

$script:planned = 0
$script:changed = 0
$script:failed  = 0
$script:notes   = New-Object System.Collections.ArrayList

function Step-Header {
    param([string]$Number, [string]$Name, [string]$Why)
    Write-Host ''
    Write-Host ('  [{0}] {1}' -f $Number, $Name) -ForegroundColor Cyan
    Write-Host ('       {0}' -f $Why)
    Write-Host ''
}

function Do-Change {
    param([string]$Describe, [scriptblock]$Action, [string]$Card = '')
    $script:planned++
    if (-not $Apply) {
        Write-Host ('    [would] {0}' -f $Describe)
        if ($Card) { Write-Host ('            more: playbooks\windows-cards.md  {0}' -f $Card) }
        return
    }
    try {
        & $Action | Out-Null
        Write-Host ('    [done]  {0}' -f $Describe) -ForegroundColor Green
        Write-CcdcLog "harden: $Describe"
        $script:changed++
    } catch {
        Write-Host ('    [FAIL]  {0}' -f $Describe) -ForegroundColor Red
        Write-Host ('            {0}' -f $_.Exception.Message)
        Write-CcdcLog "harden FAILED: $Describe :: $($_.Exception.Message)"
        $script:failed++
    }
}

function Note { param([string]$m) Write-Host ('    note:   {0}' -f $m); [void]$script:notes.Add($m) }

# After any step that could take a scored service down. The point of checking
# here rather than at the end is that you learn WHICH step did it.
function Assert-StillUp {
    param([string]$AfterStep)
    if (-not $Apply) { return $true }
    # Whole lines only: -NoNewline is dropped when the run is redirected to a
    # file, which splits the message across two lines in the transcript people
    # actually keep.
    Write-Host '    ...re-checking scored services'
    if (Test-CcdcScoredServices -Config $cfg) {
        Write-Host '    still answering.' -ForegroundColor Green
        return $true
    }
    Write-Host ''
    Write-Host ('  A SCORED SERVICE STOPPED ANSWERING AFTER: {0}' -f $AfterStep) -ForegroundColor Red
    Write-Host '  Stopping here rather than continuing down the list and making it' -ForegroundColor Red
    Write-Host '  harder to tell what did it.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Undo the most likely culprits, in this order:'
    Write-Host '      netsh advfirewall import C:\ProgramData\CCDC\backup\firewall-before.wfw'
    Write-Host '      Get-Service | Where-Object Status -eq Stopped | Select-Object Name,StartType'
    Write-Host ''
    Write-Host '  Then check from ANOTHER machine, because an on-box probe cannot see'
    Write-Host '  what the scoring engine sees.'
    return $false
}

Write-Host ''
Write-Host 'harden.ps1 - the Windows hardening checklist, in order'
Write-CcdcBoxBanner -Facts $facts
if (-not $Apply) {
    Write-Host '  DRY RUN. Nothing below will happen. Read it, then add -Apply.' -ForegroundColor Yellow
    Write-Host ''
}
Assert-CcdcPacketEntered -Config $cfg

# =============================================================================
# STEP: Backup   (checklist 2)
# First, always. Everything after this is easier to undo because of it.
# =============================================================================
if ($steps -contains 'Backup') {
    Step-Header '2' 'BACKUP - before anything changes' `
        'A revert costs points. Restoring one file does not. This is the cheapest insurance on the list.'
    $bk = Get-CcdcPath 'backup'
    Do-Change "export the firewall rule set to $bk\firewall-before.wfw" {
        & netsh advfirewall export (Join-Path $bk 'firewall-before.wfw') | Out-Null
    } 'CARD W9'
    Do-Change "export the local security policy to $bk\secpol-before.inf" {
        & secedit /export /cfg (Join-Path $bk 'secpol-before.inf') | Out-Null
    } 'CARD W9'
    Do-Change "export the service definitions to $bk\services.reg" {
        & reg export 'HKLM\SYSTEM\CurrentControlSet\Services' (Join-Path $bk 'services.reg') /y | Out-Null
    } 'CARD W9'
    Do-Change "save the account list to $bk\users.csv" {
        Get-LocalUser | Export-Csv (Join-Path $bk 'users.csv') -NoTypeInformation
    } 'CARD W9'
    Do-Change "save the scheduled tasks to $bk\tasks.xml" {
        Get-ScheduledTask | Export-Clixml (Join-Path $bk 'tasks.xml')
    } 'CARD W9'
    Note 'Copy this folder OFF the box. The training warned that backups get attacked too.'
}

# =============================================================================
# STEP: Firewall   (checklist 10)
# Before services, because a service you are about to disable may be the only
# reason a port is open - and after backup, because this is the step most
# likely to cut your own session.
# =============================================================================
if ($steps -contains 'Firewall') {
    Step-Header '10' 'FIREWALL - on, default deny inbound, logging' `
        '"If attackers can communicate with your box at all, they are going to get in."'

    if (-not $facts['HasNetSecurity']) {
        Note 'no NetSecurity module here - using netsh instead'
        Do-Change 'turn all three firewall profiles on (netsh)' {
            & netsh advfirewall set allprofiles state on | Out-Null
        } 'CARD W7'
        Do-Change 'default inbound = block, outbound = allow (netsh)' {
            & netsh advfirewall set allprofiles firewallpolicy 'blockinbound,allowoutbound' | Out-Null
        } 'CARD W7'
    } else {
        # The access rules go in FIRST. Setting default-inbound to Block while
        # working over RDP or SSH, with no rule permitting it, ends the session
        # and the box is then only reachable from the console.
        $myPorts = @()
        if ((Get-CcdcValue -Config $cfg -Name 'CCDC_RDP_SCORED') -ne '0') { $myPorts += 3389 }
        # SSH only when an SSH server is actually installed. Opening 22 on a box
        # with no sshd protects nothing and pre-opens the port for whatever the
        # red team starts listening on it - triage then reports our own rule.
        if (Get-Service -Name sshd -ErrorAction SilentlyContinue) { $myPorts += 22 }
        foreach ($p in $myPorts) {
            $nm = "CCDC allow $p (your way in)"
            Do-Change "allow inbound TCP $p FIRST, so hardening cannot lock you out" {
                if (-not (Get-NetFirewallRule -DisplayName $nm -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $nm -Direction Inbound -LocalPort $p `
                        -Protocol TCP -Action Allow -Profile Any | Out-Null
                }
            } 'CARD W7'
        }
        foreach ($p in (Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_TCP_PORTS')) {
            if ($p -notmatch '^\d+$') { continue }
            $nm = "CCDC allow scored TCP $p"
            Do-Change "allow inbound TCP $p (named in your config as scored)" {
                if (-not (Get-NetFirewallRule -DisplayName $nm -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $nm -Direction Inbound -LocalPort $p `
                        -Protocol TCP -Action Allow -Profile Any | Out-Null
                }
            } 'CARD W7'
        }
        foreach ($p in (Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_UDP_PORTS')) {
            if ($p -notmatch '^\d+$') { continue }
            $nm = "CCDC allow scored UDP $p"
            Do-Change "allow inbound UDP $p (named in your config as scored)" {
                if (-not (Get-NetFirewallRule -DisplayName $nm -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $nm -Direction Inbound -LocalPort $p `
                        -Protocol UDP -Action Allow -Profile Any | Out-Null
                }
            } 'CARD W7'
        }
        Do-Change 'enable all three profiles, default inbound Block, outbound Allow, log dropped packets' {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
                -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -LogBlocked True -LogMaxSizeKilobytes 16384
        } 'CARD W7'
        Note 'Outbound stays ALLOW on purpose. A deny-all-outbound policy breaks scored services in ways that take twenty minutes to find.'
    }
    if (-not (Assert-StillUp -AfterStep 'Firewall')) { exit 2 }
}

# =============================================================================
# STEP: Defender   (checklist 12)
# =============================================================================
if ($steps -contains 'Defender') {
    Step-Header '12' 'DEFENDER - back on, exclusions removed, then scan' `
        'An exclusion is the quiet way to disable antivirus: the icon stays green.'

    if (-not $facts['HasDefender']) {
        Note 'no Defender module here. Check the GUI: Start -> Windows Security.'
        Note 'A MISSING Defender module can itself mean somebody removed it, or a third-party AV replaced it.'
    } else {
        Do-Change 'turn real-time monitoring back on' { Set-MpPreference -DisableRealtimeMonitoring $false } 'CARD W6'
        Do-Change 'turn script scanning back on'      { Set-MpPreference -DisableScriptScanning $false }     'CARD W6'
        Do-Change 'turn downloaded-file scanning back on' { Set-MpPreference -DisableIOAVProtection $false } 'CARD W6'

        try {
            $mp = Get-MpPreference
            foreach ($e in @($mp.ExclusionPath))      { if ($e) { Do-Change "remove Defender path exclusion: $e"      { Remove-MpPreference -ExclusionPath $e }      'CARD W6' } }
            foreach ($e in @($mp.ExclusionProcess))   { if ($e) { Do-Change "remove Defender process exclusion: $e"   { Remove-MpPreference -ExclusionProcess $e }   'CARD W6' } }
            foreach ($e in @($mp.ExclusionExtension)) { if ($e) { Do-Change "remove Defender extension exclusion: $e" { Remove-MpPreference -ExclusionExtension $e } 'CARD W6' } }
            Note 'Look at what was parked in each excluded path before you move on - that is where the payload lives.'
        } catch { Note "could not read Defender exclusions: $($_.Exception.Message)" }

        # A domain policy often points Defender at a WSUS server the event does
        # not provide; with the internet up, going direct is what works.
        Do-Change 'update signatures (falls back to Microsoft directly if the default source fails)' {
            try { Update-MpSignature -ErrorAction Stop }
            catch { Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop }
        } 'CARD W6'
        Do-Change 'run a quick scan (runs in the background; check the GUI for results)' {
            Start-MpScan -ScanType QuickScan -AsJob | Out-Null
        } 'CARD W6'
    }
}

# =============================================================================
# STEP: Logging   (checklist 11)
# =============================================================================
if ($steps -contains 'Logging') {
    Step-Header '11' 'LOGGING - turn on what you will need for the incident report' `
        'Incident reports earn points. You cannot write one from logs that were never enabled.'

    $sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    Do-Change 'enable PowerShell script block logging (event 4104 - the best log on Windows)' {
        if (-not (Test-Path -LiteralPath $sbl)) { New-Item -Path $sbl -Force | Out-Null }
        Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1
    } 'CARD W8'

    $mod = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Do-Change 'enable PowerShell module logging' {
        if (-not (Test-Path -LiteralPath $mod)) { New-Item -Path $mod -Force | Out-Null }
        Set-ItemProperty -Path $mod -Name EnableModuleLogging -Value 1
        if (-not (Test-Path -LiteralPath "$mod\ModuleNames")) { New-Item -Path "$mod\ModuleNames" -Force | Out-Null }
        Set-ItemProperty -Path "$mod\ModuleNames" -Name '*' -Value '*'
    } 'CARD W8'

    $trans = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $transDir = Get-CcdcPath 'logs\transcripts'
    Do-Change 'enable PowerShell transcription logging' {
        if (-not (Test-Path -LiteralPath $trans)) { New-Item -Path $trans -Force | Out-Null }
        if (-not (Test-Path -LiteralPath $transDir)) { New-Item -Path $transDir -ItemType Directory -Force | Out-Null }
        Set-ItemProperty -Path $trans -Name 'EnableTranscripting' -Value 1 -Type DWord
        Set-ItemProperty -Path $trans -Name 'OutputDirectory' -Value $transDir
        Set-ItemProperty -Path $trans -Name 'EnableInvocationHeader' -Value 1 -Type DWord
    } 'CARD W8'

    $audKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Do-Change 'record the FULL COMMAND LINE with every process-creation event' {
        if (-not (Test-Path -LiteralPath $audKey)) { New-Item -Path $audKey -Force | Out-Null }
        Set-ItemProperty -Path $audKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
    } 'CARD W8'

    foreach ($c in @('Logon/Logoff','Account Management','Policy Change','Account Logon')) {
        Do-Change "audit category on (success+failure): $c" {
            & auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null
        } 'CARD W8'
    }
    Do-Change 'audit subcategory on: Process Creation' {
        & auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    } 'CARD W8'

    foreach ($log in @('Security','System','Application')) {
        Do-Change "grow the $log event log to 256MB so it is not rotated away" {
            & wevtutil sl $log /ms:268435456 | Out-Null
        } 'CARD W8'
    }
    Note 'These take effect for NEW events. Nothing recovers what was not logged before now.'
}

# =============================================================================
# STEP: PasswordPolicy   (checklist 6)  - also the shape of inject 1
# =============================================================================
if ($steps -contains 'PasswordPolicy') {
    Step-Header '6' 'PASSWORD POLICY' `
        'Also an inject in its own right. Whatever you set here, write down WHY - the inject asks for the standard you based it on.'

    if (Test-CcdcIsDomainController) {
        Note 'This is a DOMAIN CONTROLLER. net accounts changes the DEFAULT DOMAIN POLICY,'
        Note 'which applies to every machine in the domain. That is usually what you want,'
        Note 'and it is definitely not something to do by accident. Read it before -Apply.'
    }
    $minLen = Get-CcdcValue -Config $cfg -Name 'CCDC_PW_MIN_LENGTH' -Default '14'
    $maxAge = Get-CcdcValue -Config $cfg -Name 'CCDC_PW_MAX_AGE'    -Default '0'
    $hist   = Get-CcdcValue -Config $cfg -Name 'CCDC_PW_HISTORY'    -Default '10'
    $lockTh = Get-CcdcValue -Config $cfg -Name 'CCDC_LOCKOUT_THRESHOLD' -Default '10'
    $lockDur= Get-CcdcValue -Config $cfg -Name 'CCDC_LOCKOUT_DURATION'  -Default '15'

    Do-Change "minimum password length = $minLen" { & net accounts "/minpwlen:$minLen" | Out-Null } 'CARD W1'
    Do-Change "password history = $hist"          { & net accounts "/uniquepw:$hist"   | Out-Null } 'CARD W1'
    Do-Change "maximum password age = $maxAge (0 = never expire, which is current NIST guidance)" {
        if ($maxAge -eq '0') { & net accounts '/maxpwage:unlimited' | Out-Null }
        else { & net accounts "/maxpwage:$maxAge" | Out-Null }
    } 'CARD W1'
    Do-Change "account lockout after $lockTh bad attempts, for $lockDur minutes" {
        & net accounts "/lockoutthreshold:$lockTh" | Out-Null
        & net accounts "/lockoutduration:$lockDur" | Out-Null
        & net accounts "/lockoutwindow:$lockDur"   | Out-Null
    } 'CARD W1'
    Note 'Lockout is a trade: it stops password guessing and it is also how someone locks your SCORED accounts out on purpose. A threshold of 10 and a short duration is the compromise.'
    Note 'Modern standard (NIST SP 800-63B): length over complexity, no forced rotation, block known-breached passwords. Say that in the inject response.'
}

# =============================================================================
# STEP: Services   (checklist 7)
# =============================================================================
if ($steps -contains 'Services') {
    Step-Header '7' 'SERVICES - turn off what nothing needs' `
        'Every daemon you do not need is attack surface you are defending for no points.'

    # Named explicitly, never inferred. The disable list is a decision the
    # operator makes from the packet; a tool that guesses which service is
    # unnecessary eventually guesses the scored one.
    $disable = Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_DISABLE_SERVICES'
    $protect = @()
    $protect += Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_SERVICES'
    $protect += Get-CcdcList -Config $cfg -Name 'CCDC_PROTECT_SERVICES'

    if (@($disable).Count -eq 0) {
        Note 'CCDC_WINDOWS_DISABLE_SERVICES is empty, so nothing is disabled here.'
        Note 'That is the safe default. Candidates worth considering, if the packet does not need them:'
        Note '   RemoteRegistry  Spooler(PrintNightmare)  SSDPSRV  upnphost  WinRM  Fax  TapiSrv'
        Note 'Put the ones you want gone in that list, then re-run. Read what each one does first.'
    }
    foreach ($svc in $disable) {
        if (Test-CcdcListContains -Needle $svc -List $protect) {
            Note "REFUSING to disable $svc - it is in your scored/protect list. Fix one list or the other."
            continue
        }
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($null -eq $s) { Note "$svc is not installed here - nothing to do"; continue }
        Do-Change "stop and disable $svc" {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svc -StartupType Disabled
        } 'CARD W2'
        if (-not (Assert-StillUp -AfterStep "disabling $svc")) { exit 2 }
    }
}

# =============================================================================
# STEP: RemoteAccess   (checklist 8 and 9)
# =============================================================================
if ($steps -contains 'RemoteAccess') {
    Step-Header '8/9' 'REMOTE ACCESS - harden the doors that are supposed to be there' `
        'RDP and SSH are how you work and how they work. Hardening beats disabling when it is scored.'

    $tsRoot = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = "$tsRoot\WinStations\RDP-Tcp"
    if (Test-Path -LiteralPath $rdpTcp) {
        Do-Change 'require Network Level Authentication for RDP (stops a whole class of pre-auth attack)' {
            Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 1
        } 'CARD W10'
        Do-Change 'require a high encryption level for RDP' {
            Set-ItemProperty -Path $rdpTcp -Name 'MinEncryptionLevel' -Value 3
        } 'CARD W10'
    } else { Note 'no RDP-Tcp station here - RDP may not be installed' }

    Do-Change 'disable SMBv1 (obsolete, unauthenticated, and still on some images)' {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    } 'CARD W10'
    Do-Change 'require SMB signing, so a session cannot be relayed' {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    } 'CARD W10'

    # Anonymous enumeration: how an attacker gets your user list without a
    # credential. Off by default on newer builds, on for some older ones.
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Do-Change 'block anonymous enumeration of accounts and shares' {
        Set-ItemProperty -Path $lsa -Name 'RestrictAnonymous'    -Value 1
        Set-ItemProperty -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1
        Set-ItemProperty -Path $lsa -Name 'EveryoneIncludesAnonymous' -Value 0
    } 'CARD W10'

    # These controls can change name resolution, RDP authentication behaviour,
    # and cached domain sign-ins. They are useful only when the packet confirms
    # they fit this box, so a broad hardening pass must not guess.
    $networkNameHardening = (Get-CcdcValue -Config $cfg -Name 'CCDC_ACK_NETWORK_NAME_RESOLUTION_HARDENING' -Default '0') -eq '1'
    if ($networkNameHardening) {
        # Windows DNS Server hardening.
        $dnsCmd = Get-Command -Name 'Set-DnsServerGlobalQueryBlockList' -ErrorAction SilentlyContinue
        if ($null -ne $dnsCmd) {
            $dnsSvc = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
            if ($null -ne $dnsSvc -and $dnsSvc.Status -eq 'Running') {
                Do-Change 'block WPAD and ISATAP queries on this DNS server' {
                    Set-DnsServerGlobalQueryBlockList -List 'wpad','isatap' -ErrorAction SilentlyContinue
                } 'CARD W10'
            }
        }
    }

    Do-Change 'enable LSA Protection (RunAsPPL) to prevent LSASS credential dumping' {
        Set-ItemProperty -Path $lsa -Name 'RunAsPPL' -Value 1 -Type DWord
    } 'CARD W10'

    $wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    Do-Change 'disable WDigest plaintext credential caching in memory' {
        if (-not (Test-Path -LiteralPath $wdigest)) { New-Item -Path $wdigest -Force | Out-Null }
        Set-ItemProperty -Path $wdigest -Name 'UseLogonCredential' -Value 0 -Type DWord
    } 'CARD W10'

    if ($networkNameHardening) {
        Do-Change 'allow Restricted Admin mode for incoming RDP sessions' {
            Set-ItemProperty -Path $lsa -Name 'DisableRestrictedAdmin' -Value 0 -Type DWord
        } 'CARD W10'

        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Do-Change 'limit cached domain credentials to 1' {
            Set-ItemProperty -Path $winlogon -Name 'CachedLogonsCount' -Value '1'
        } 'CARD W10'

        $dnsClient = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        Do-Change 'disable LLMNR' {
            if (-not (Test-Path -LiteralPath $dnsClient)) { New-Item -Path $dnsClient -Force | Out-Null }
            Set-ItemProperty -Path $dnsClient -Name 'EnableMulticast' -Value 0 -Type DWord
        } 'CARD W10'

        Do-Change 'disable NetBIOS over TCP/IP on active network adapters' {
            Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null } catch { }
                }
        } 'CARD W10'
    } else {
        Note 'Network-name-resolution controls were not changed. Set CCDC_ACK_NETWORK_NAME_RESOLUTION_HARDENING="1" only after the packet confirms they fit this box.'
    }

    if (-not $IHaveConsoleAccess) {
        Note 'Not touching whether RDP is ENABLED. If you are working over RDP, turning it'
        Note 'off ends your session and the box is console-only after that. Decide deliberately:'
        Note ('    .\harden.ps1 -Config {0} -Only RemoteAccess -Apply -IHaveConsoleAccess' -f $Config)
    } elseif ((Get-CcdcValue -Config $cfg -Name 'CCDC_RDP_SCORED') -eq '0') {
        Do-Change 'DISABLE RDP entirely (your config says it is not scored, and you said you have console access)' {
            Set-ItemProperty -Path $tsRoot -Name 'fDenyTSConnections' -Value 1
        } 'CARD W10'
    }
    if (-not (Assert-StillUp -AfterStep 'RemoteAccess')) { exit 2 }
}

# =============================================================================
# STEP: Persistence   (checklist 13)
# Reports only. Removing persistence is a judgement call with evidence
# attached, and it belongs in triage + the cards, not in a bulk run.
# =============================================================================
if ($steps -contains 'Persistence') {
    Step-Header '13' 'PERSISTENCE - registry, startup and tasks' `
        'This step REPORTS. It does not remove: each one needs evidence captured first, and a look at what it ran.'

    $found = 0
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path -LiteralPath $ifeo) {
        foreach ($sub in (Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
            $dbg = $null
            try { $dbg = (Get-ItemProperty -LiteralPath $sub.PSPath -Name Debugger -ErrorAction Stop).Debugger } catch { }
            if ($dbg) {
                $found++
                Write-Host ("    FOUND   debugger on {0} -> {1}" -f $sub.PSChildName, $dbg) -ForegroundColor Red
                Write-Host  '            this is a login-screen backdoor. See CARD W4.'
            }
        }
    }
    try {
        $w = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        if ($w.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?\s*$') {
            $found++
            Write-Host ("    FOUND   Winlogon Userinit is not stock: {0}" -f $w.Userinit) -ForegroundColor Red
        }
    } catch { }
    if ($found -eq 0) {
        Write-Host '    nothing on the two highest-signal registry persistence paths.'
    }
    Note ('That is two checks, not thirteen. For the full sweep run:  .\windows\triage.ps1 -Config {0}' -f $Config)
}

# =============================================================================
Write-Host ''
Write-Host '=================================================================='
if ($Apply) {
    Write-Host ('  {0} change(s) applied, {1} failed, out of {2} planned.' -f $script:changed, $script:failed, $script:planned)
} else {
    Write-Host ('  DRY RUN: {0} change(s) would be made. Nothing happened.' -f $script:planned)
    Write-Host ''
    Write-Host '  Run it for real:'
    Write-Host ("      .\windows\harden.ps1 -Config {0} -Apply" -f $Config)
}
Write-Host ''
Write-Host '  NOT covered here, on purpose - accounts and passwords:'
Write-Host ("      .\windows\users.ps1 -Config {0}" -f $Config)
Write-Host '  The four checklist items about credentials are interactive and are the'
Write-Host '  most destructive thing to get wrong. They get their own tool.'
Write-Host ''
Write-Host '  Then look for what is already here:'
Write-Host ("      .\windows\triage.ps1 -Config {0}" -f $Config)
Write-Host ''
Write-Host '  Verify your scored services FROM ANOTHER MACHINE. Nothing on this box'
Write-Host '  can see what the scoring engine sees.'
Write-Host ''
if ($script:failed -gt 0) { exit 1 }
exit 0
