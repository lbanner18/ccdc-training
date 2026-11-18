<#
.SYNOPSIS
    The image-scoring checklist (HIVESTORM / CyberPatriot style). READ-ONLY.
.DESCRIPTION
    Changes nothing. Every FAIL prints the command that fixes it; paste the
    ones the README allows. triage.ps1 hunts an attacker; this hunts the
    misconfigurations a scoring engine plants and checks for.

    Reads CCDC_ALLOWED_USERS / CCDC_ALLOWED_ADMINS / CCDC_WINDOWS_SERVICES /
    CCDC_RDP_SCORED from C:\ProgramData\CCDC\ccdc.env (or -Config) so it does
    not flag what the README requires.
.EXAMPLE
    .\windows\hivestorm.ps1
#>
[CmdletBinding()]
param([string]$Config = 'C:\ProgramData\CCDC\ccdc.env')
$ErrorActionPreference = 'SilentlyContinue'

function CfgVal([string]$Name) {
    if (-not (Test-Path -LiteralPath $Config)) { return '' }
    $v = ''
    foreach ($line in Get-Content -LiteralPath $Config) {
        if ($line -match ('^' + $Name + '="?([^"]*)"?\s*$')) { $v = $Matches[1] }
    }
    return $v
}
function Words([string]$s) { return @($s -split '\s+' | Where-Object { $_ }) }

$allowedUsers  = @(Words (CfgVal 'CCDC_ALLOWED_USERS'))
$allowedAdmins = @(Words (CfgVal 'CCDC_ALLOWED_ADMINS'))
if ($allowedAdmins.Count -eq 0) { $allowedAdmins = $allowedUsers }
$required      = @(Words ((CfgVal 'CCDC_WINDOWS_SERVICES') + ' ' + (CfgVal 'CCDC_PROTECT_SERVICES')))
$rdpRequired   = (CfgVal 'CCDC_RDP_SCORED') -eq '1'

$script:fails = 0
function Fail([string]$What, [string[]]$Fix) {
    $script:fails++
    Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline; Write-Host $What
    foreach ($f in $Fix) { Write-Host "       $f" -ForegroundColor DarkGray }
}
function Look([string]$What, [string[]]$Fix) {
    Write-Host '[LOOK] ' -ForegroundColor Yellow -NoNewline; Write-Host $What
    foreach ($f in $Fix) { Write-Host "       $f" -ForegroundColor DarkGray }
}
function Ok([string]$What) { Write-Host '[ ok ] ' -ForegroundColor Green -NoNewline; Write-Host $What }
function Sec([string]$t) { Write-Host ''; Write-Host "== $t ==" -ForegroundColor Cyan }
function RegVal([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host '(not elevated: some checks will be wrong - run as Administrator)' -ForegroundColor Yellow }
Write-Host 'Forensic questions FIRST: anything below you delete may be an answer.' -ForegroundColor Yellow

# ---------------------------------------------------------------------------
Sec 'accounts'
$builtin = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
$users = @(Get-LocalUser)
foreach ($u in $users) {
    $n = [string]$u.Name
    if ($n -eq 'Guest') {
        if ($u.Enabled) { Fail 'Guest account is enabled' @('net user Guest /active:no') } else { Ok 'Guest is disabled' }
        continue
    }
    if ($builtin -contains $n) { continue }
    if ($allowedUsers.Count -gt 0 -and -not ($allowedUsers -contains $n)) {
        Fail "$n is not in the README (CCDC_ALLOWED_USERS)" @("net user $n /delete    # forensics first")
        continue
    }
    if ($u.Enabled -and -not $u.PasswordRequired) { Fail "$n does not require a password" @("net user $n /passwordreq:yes") }
    if ($u.Enabled -and $null -eq $u.PasswordExpires) { Fail "$n password never expires" @("Set-LocalUser -Name $n -PasswordNeverExpires `$false") }
}
if ($allowedUsers.Count -eq 0) { Look 'no config: compare these accounts with the README' @(($users | ForEach-Object { $_.Name }) -join ' ') }

$admins = @()
try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) }
catch { $admins = @(net localgroup Administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }) }
foreach ($a in $admins) {
    if ($a -match '^(Administrator|Domain Admins|Enterprise Admins)$') { continue }
    if ($allowedAdmins.Count -gt 0 -and -not ($allowedAdmins -contains $a)) {
        Fail "$a is in Administrators but is not a README admin" @("net localgroup Administrators $a /delete")
    }
}
if ($allowedAdmins.Count -gt 0) { Ok ("Administrators checked against: " + ($allowedAdmins -join ' ')) }
foreach ($g in @('Remote Desktop Users','Backup Operators','Power Users')) {
    $m = @(Get-LocalGroupMember -Group $g | ForEach-Object { ($_.Name -split '\\')[-1] })
    if ($m.Count -gt 0) { Look "$g has: $($m -join ', ')" @("net localgroup `"$g`" <name> /delete    # if the README does not need it") }
}

# ---------------------------------------------------------------------------
Sec 'password and lockout policy (net accounts)'
$na = @{}
foreach ($line in (net accounts)) { if ($line -match '^(.+?):\s+(.+)$') { $na[$Matches[1].Trim()] = $Matches[2].Trim() } }
function NaNum([string]$k) { $v = $na[$k]; if ($v -match '^\d+$') { return [int]$v } return -1 }
$minLen = NaNum 'Minimum password length'
$maxAge = NaNum 'Maximum password age (days)'
$minAge = NaNum 'Minimum password age (days)'
$hist   = NaNum 'Length of password history maintained'
$thr    = NaNum 'Lockout threshold'
$dur    = NaNum 'Lockout duration (minutes)'
if ($minLen -ge 10) { Ok "minimum length $minLen" } else { Fail "minimum password length is $minLen" @('net accounts /minpwlen:12') }
if ($maxAge -ge 1 -and $maxAge -le 90) { Ok "maximum age $maxAge" } else { Fail "maximum password age is $($na['Maximum password age (days)'])" @('net accounts /maxpwage:90') }
if ($minAge -ge 1) { Ok "minimum age $minAge" } else { Fail "minimum password age is $minAge" @('net accounts /minpwage:1') }
if ($hist -ge 5) { Ok "history $hist" } else { Fail "password history is $($na['Length of password history maintained'])" @('net accounts /uniquepw:5') }
if ($thr -ge 1 -and $thr -le 10) { Ok "lockout threshold $thr" } else { Fail "lockout threshold is $($na['Lockout threshold'])" @('net accounts /lockoutthreshold:5') }
if ($dur -ge 15) { Ok "lockout duration $dur" } else { Fail "lockout duration is $dur" @('net accounts /lockoutduration:30 /lockoutwindow:30') }
# Complexity and reversible encryption are only in secedit.
$sec = Join-Path $env:TEMP 'hive-secpol.inf'
secedit /export /cfg $sec /quiet | Out-Null
if (Test-Path $sec) {
    $s = Get-Content $sec
    if ($s -match '^PasswordComplexity\s*=\s*1') { Ok 'password complexity on' } else { Fail 'password complexity is off' @('secpol.msc > Account Policies > Password Policy > complexity: Enabled') }
    if ($s -match '^ClearTextPassword\s*=\s*1') { Fail 'passwords stored with reversible encryption' @('secpol.msc > Password Policy > reversible encryption: Disabled') }
    if ($s -match '^LSAAnonymousNameLookup\s*=\s*1') { Fail 'anonymous SID/name translation allowed' @('secpol.msc > Security Options > Network access: Allow anonymous SID/Name translation: Disabled') }
    if ($s -match '^EnableGuestAccount\s*=\s*1') { Fail 'Guest enabled in security policy' @('net user Guest /active:no') }
    Remove-Item $sec -Force
}

# ---------------------------------------------------------------------------
Sec 'security settings'
foreach ($p in @(Get-NetFirewallProfile)) {
    if ($p.Enabled) { Ok "firewall $($p.Name) on" } else { Fail "firewall $($p.Name) profile is OFF" @("Set-NetFirewallProfile -Profile $($p.Name) -Enabled True") }
}
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ((RegVal $sys 'EnableLUA') -eq 0) { Fail 'UAC is off' @("Set-ItemProperty '$sys' EnableLUA 1   # reboot") } else { Ok 'UAC on' }
$cpba = RegVal $sys 'ConsentPromptBehaviorAdmin'
if ($cpba -eq 0) { Fail 'UAC elevates admins without prompting' @("Set-ItemProperty '$sys' ConsentPromptBehaviorAdmin 2") }
if ((RegVal $sys 'PromptOnSecureDesktop') -eq 0) { Fail 'UAC prompt is not on the secure desktop' @("Set-ItemProperty '$sys' PromptOnSecureDesktop 1") }
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if ((RegVal $lsa 'NoLMHash') -ne 1) { Fail 'LM hashes are stored' @("Set-ItemProperty '$lsa' NoLMHash 1") }
$lmc = RegVal $lsa 'LmCompatibilityLevel'
if ($null -ne $lmc -and $lmc -lt 3) { Fail "LmCompatibilityLevel is $lmc (LM/NTLMv1 allowed)" @("Set-ItemProperty '$lsa' LmCompatibilityLevel 5") }
if ((RegVal $lsa 'RestrictAnonymous') -ne 1) { Fail 'anonymous enumeration of shares is allowed' @("Set-ItemProperty '$lsa' RestrictAnonymous 1") }
if ((RegVal $lsa 'RestrictAnonymousSAM') -ne 1) { Fail 'anonymous enumeration of accounts is allowed' @("Set-ItemProperty '$lsa' RestrictAnonymousSAM 1") }
if ((RegVal $lsa 'LimitBlankPasswordUse') -eq 0) { Fail 'blank passwords work over the network' @("Set-ItemProperty '$lsa' LimitBlankPasswordUse 1") }
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ((RegVal $wl 'AutoAdminLogon') -eq '1') { Fail 'automatic logon is on' @("Set-ItemProperty '$wl' AutoAdminLogon 0; Remove-ItemProperty '$wl' DefaultPassword") }
if ($null -ne (RegVal $wl 'DefaultPassword')) { Fail 'a plaintext DefaultPassword is in Winlogon (forensics?)' @("Remove-ItemProperty '$wl' DefaultPassword") }
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ($smb.EnableSMB1Protocol) { Fail 'SMBv1 is on' @('Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force') } else { Ok 'SMBv1 off' }
    if (-not $smb.RequireSecuritySignature) { Look 'SMB signing not required' @('Set-SmbServerConfiguration -RequireSecuritySignature $true -Force') }
} catch {}
$ts = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($ts -eq 0 -and -not $rdpRequired) { Fail 'Remote Desktop is on and the README does not require it (CCDC_RDP_SCORED=0)' @("Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1") }
if ($ts -eq 0 -and $rdpRequired) {
    $nla = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($nla -ne 1) { Fail 'RDP is required but Network Level Authentication is off' @("Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1") }
}
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.RealTimeProtectionEnabled) { Ok 'Defender real-time on' } else { Fail 'Defender real-time protection is off' @('Set-MpPreference -DisableRealtimeMonitoring $false') }
    $ex = @(@((Get-MpPreference).ExclusionPath) + @((Get-MpPreference).ExclusionProcess) | Where-Object { $_ })
    if ($ex.Count -gt 0) { Fail ("Defender exclusions: " + ($ex -join ', ')) @('Remove-MpPreference -ExclusionPath <path>   # / -ExclusionProcess') }
} catch { Look 'could not read Defender status' @() }
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if ((RegVal $au 'NoAutoUpdate') -eq 1) { Fail 'automatic updates disabled by policy' @("Set-ItemProperty '$au' NoAutoUpdate 0") }

# Audit policy: the scorer usually wants success+failure on these.
$ap = auditpol /get /category:* 2>$null
foreach ($sub in @('Logon','Credential Validation','User Account Management','Security Group Management','Audit Policy Change','Process Creation')) {
    $line = $ap | Where-Object { $_ -match ('^\s+' + [regex]::Escape($sub) + '\s{2,}') } | Select-Object -First 1
    if ($line -and $line -match 'Success and Failure') { Ok "audit $sub" }
    elseif ($line) { $now = (([string]$line).Trim() -split '\s{2,}')[-1]; Fail "audit '$sub' is: $now" @("auditpol /set /subcategory:`"$sub`" /success:enable /failure:enable") }
}

# ---------------------------------------------------------------------------
Sec 'services'
$risky = @{ 'TlntSvr'='Telnet'; 'RemoteRegistry'='Remote Registry'; 'SNMP'='SNMP'; 'ftpsvc'='FTP (IIS)';
            'W3SVC'='IIS web'; 'SSDPSRV'='SSDP discovery'; 'upnphost'='UPnP host'; 'Spooler'='Print Spooler';
            'SharedAccess'='Internet Connection Sharing'; 'RemoteAccess'='Routing and Remote Access';
            'simptcp'='Simple TCP/IP'; 'LanmanServer'='File sharing (Server)'; 'TermService'='Remote Desktop';
            'WinRM'='WinRM'; 'Fax'='Fax'; 'XblGameSave'='Xbox'; 'MSFTPSVC'='FTP' }
foreach ($k in $risky.Keys) {
    $svc = Get-Service -Name $k
    if (-not $svc) { continue }
    if ($required -contains $k) { continue }
    if ($svc.Status -eq 'Running') {
        Look "$($risky[$k]) ($k) is running - stop it ONLY if the README does not require it" @("Stop-Service $k -Force; Set-Service $k -StartupType Disabled")
    }
}
foreach ($k in @('wuauserv','WinDefend','mpssvc','EventLog')) {
    $svc = Get-Service -Name $k
    if ($svc -and ($svc.StartType -eq 'Disabled' -or $svc.Status -ne 'Running')) {
        Fail "$k ($($svc.DisplayName)) is $($svc.Status)/$($svc.StartType)" @("Set-Service $k -StartupType Automatic; Start-Service $k")
    }
}

Sec 'shares'
foreach ($sh in @(Get-SmbShare)) {
    if ($sh.Name -match '^(ADMIN\$|C\$|IPC\$|[A-Z]\$|print\$|NETLOGON|SYSVOL)$') { continue }
    Look "share '$($sh.Name)' -> $($sh.Path)" @("Remove-SmbShare -Name '$($sh.Name)' -Force   # if the README does not need it")
}

# ---------------------------------------------------------------------------
Sec 'software (forensics FIRST)'
$bad = 'wireshark|nmap|zenmap|john|hashcat|cain|ophcrack|l0phtcrack|hydra|metasploit|netcat|ncat|aircrack|nikto|burp|angry ip|advanced port scanner|utorrent|bittorrent|qbittorrent|frostwire|vuze|limewire|teamviewer|anydesk|tightvnc|realvnc|ultravnc|ccleaner|steam|minecraft|itunes|spotify|npcap|winpcap|pc cleaner|driver booster'
$apps = @()
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $apps += @(Get-ItemProperty $root | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName)
}
$hits = @($apps | Where-Object { $_ -match $bad } | Sort-Object -Unique)
if ($hits.Count -gt 0) { foreach ($h in $hits) { Fail "installed, likely banned: $h" @('appwiz.cpl  (Programs and Features) -> Uninstall') } } else { Ok 'no listed hacking tools / P2P / remote-access apps installed' }
$loose = @(Get-ChildItem -Path 'C:\Users','C:\Program Files','C:\Program Files (x86)' -Recurse -File -Include 'nc.exe','nc64.exe','ncat.exe','nmap.exe','john.exe','mimikatz.exe','psexec*.exe','procdump*.exe' -ErrorAction SilentlyContinue | Select-Object -First 15)
foreach ($f in $loose) { Fail "tool on disk: $($f.FullName)" @("Remove-Item '$($f.FullName)'") }

$ext = '*.mp3','*.mp4','*.wav','*.flac','*.ogg','*.m4a','*.wma','*.avi','*.mkv','*.mov','*.wmv'
$media = @(Get-ChildItem -Path 'C:\Users' -Recurse -File -Include $ext -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -notmatch '\\AppData\\' } | Select-Object -First 30)
if ($media.Count -gt 0) { foreach ($m in $media) { Look "media: $($m.FullName)" @("Remove-Item '$($m.FullName)'   # forensics first") } } else { Ok 'no media files under C:\Users' }

Sec 'startup and tasks (read these)'
foreach ($rk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    $p = Get-ItemProperty -LiteralPath $rk
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Look "Run key $($_.Name) = $($_.Value)" @("Remove-ItemProperty '$rk' -Name '$($_.Name)'   # unless it is the scoring engine") } }
}
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | ForEach-Object {
    $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    Look "task $($_.TaskPath)$($_.TaskName): $act" @("Disable-ScheduledTask -TaskPath '$($_.TaskPath)' -TaskName '$($_.TaskName)'   # NOT the scoring engine's")
}

Write-Host ''
if ($script:fails -gt 0) { Write-Host "$($script:fails) FAIL - paste the fixes the README allows, then re-run." -ForegroundColor Red; exit 3 }
Write-Host 'no FAIL - now the [LOOK] lines, by hand.' -ForegroundColor Green
