<#
.SYNOPSIS
    Set the scored accounts' passwords from the same user,password block you
    paste into Quotient's Password Change Request, and prove each one logs in.

.DESCRIPTION
    The packet gives every competitor the same default password for every
    account, and the red team has the packet. users.ps1 works on local accounts
    only and stops on a domain controller - which is exactly what the tryout's
    Windows box is - so the most important change on that box had no tool.

    On a domain controller this changes DOMAIN accounts (Set-ADAccountPassword)
    and proves each new password with an LDAP login, which is how the packet
    says AD is scored. Anywhere else it changes local accounts and proves them
    with a local logon check.

        .\windows\passwords.ps1                  # check the block, change nothing
        .\windows\passwords.ps1 -Apply           # paste the block, then an empty line
        .\windows\passwords.ps1 -Apply -InputFile C:\path\block.txt

    Pasted at the prompt, the passwords go to Read-Host, not to your command
    history. Then put the same block into Quotient: until you do, the scorer
    logs in with the old password and fails.
#>
param(
    [string]$Config = '',
    [switch]$Apply,
    [string]$InputFile = '',
    [switch]$Kick
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$Config = [string]$cfg['_ConfigPath']
if ($Apply) { Assert-CcdcAdmin }
$isDc = Test-CcdcIsDomainController
$minLen = 8
$v = Get-CcdcValue -Config $cfg -Name 'CCDC_PW_MIN_LENGTH'
if ($v -match '^\d+$') { $minLen = [int]$v }
$packetPw = [string](Get-CcdcValue -Config $cfg -Name 'CCDC_PACKET_PASSWORD')
$scored = @(Get-CcdcList -Config $cfg -Name 'CCDC_INTERACTIVE_USERS' | Where-Object { $_ -ne 'root' })

if ($isDc) {
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch { Write-CcdcDie "this is a domain controller but the ActiveDirectory module will not load: $($_.Exception.Message)" }
}

function Test-AccountExists {
    param([string]$Name)
    if ($isDc) {
        try { $null = Get-ADUser -Identity $Name -ErrorAction Stop; return $true } catch { return $false }
    }
    try { $null = Get-LocalUser -Name $Name -ErrorAction Stop; return $true } catch { return $false }
}

# --- read the block -----------------------------------------------------------------
$raw = New-Object System.Collections.ArrayList
if ($InputFile) {
    if (-not (Test-Path -LiteralPath $InputFile)) { Write-CcdcDie "no such file: $InputFile" }
    foreach ($l in (Get-Content -LiteralPath $InputFile)) { [void]$raw.Add([string]$l) }
} else {
    Write-Host 'Paste the block (user,password, one per line), then press Enter on an empty line:'
    while ($true) {
        $l = Read-Host
        if ([string]::IsNullOrWhiteSpace($l)) { break }
        [void]$raw.Add($l)
    }
}

$names = New-Object System.Collections.ArrayList
$secrets = New-Object System.Collections.ArrayList
$errors = New-Object System.Collections.ArrayList
$absent = New-Object System.Collections.ArrayList
$n = 0
foreach ($line in $raw) {
    $n++
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#') -or $t.StartsWith('=====')) { continue }
    # @() because one match is a bare [char], and StrictMode has no .Count on it.
    if (@($t.ToCharArray() | Where-Object { $_ -eq ',' }).Count -ne 1) {
        [void]$errors.Add("line ${n}: expected exactly one comma - Quotient reads user,password"); continue
    }
    if ($t -match '\s') { [void]$errors.Add("line ${n}: contains a space - Quotient's format has none"); continue }
    $u, $p = $t -split ',', 2
    if ($u -notmatch '^[A-Za-z0-9_.\-]+\$?$') { [void]$errors.Add("line ${n}: '$u' is not an account name"); continue }
    if ($p.Length -lt $minLen) { [void]$errors.Add("line ${n}: $u's password is $($p.Length) characters; the minimum is $minLen"); continue }
    if ($packetPw -and $p -ceq $packetPw) { [void]$errors.Add("line ${n}: $u is being set to the packet's default password, which the red team has"); continue }
    if (Test-CcdcListContains -Needle $u -List @($names)) { [void]$errors.Add("line ${n}: $u appears twice"); continue }
    # The same block goes on every box, and a box need not have every account:
    # skip, and say so, rather than refuse the accounts it does have.
    if (-not (Test-AccountExists -Name $u)) { [void]$absent.Add($u); continue }
    [void]$names.Add($u); [void]$secrets.Add($p)
}
if ($errors.Count -gt 0) {
    Write-Host 'Nothing was changed. Fix these and paste again:' -ForegroundColor Red
    foreach ($e in $errors) { Write-Host "  $e" }
    exit 1
}
if ($names.Count -eq 0) {
    $where = if ($isDc) { 'in the domain' } else { "on $env:COMPUTERNAME" }
    if ($absent.Count) { Write-CcdcDie ("none of these accounts exist {0}: {1} - is this the right box?" -f $where, ($absent -join ' ')) }
    Write-CcdcDie 'no user,password lines were read'
}
$missing = @($scored | Where-Object { -not (Test-CcdcListContains -Needle $_ -List @($names)) -and (Test-AccountExists -Name $_) })

if (-not $Apply) {
    Write-Host ("The block reads cleanly: {0} account(s): {1}" -f $names.Count, ($names -join ' '))
    if ($absent.Count) { Write-Host ("Not on this box, skipped: {0}" -f ($absent -join ' ')) }
    if ($missing.Count) { Write-Host ("NOT in the block, still on the packet password: {0}" -f ($missing -join ' ')) -ForegroundColor Yellow }
    Write-Host 'Nothing was changed. Re-run with -Apply and paste it again to set them.'
    exit 0
}

# --- apply ------------------------------------------------------------------------
$kind = if ($isDc) { 'DOMAIN' } else { 'LOCAL' }
Write-Host ''
Write-Host ("SETTING {0} {1} PASSWORD(S) on {2}" -f $names.Count, $kind, $env:COMPUTERNAME)
if ($absent.Count) { Write-Host ("  (not on this box, skipped: {0})" -f ($absent -join ' ')) }
Write-Host ''
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctxType = if ($isDc) { [System.DirectoryServices.AccountManagement.ContextType]::Domain } else { [System.DirectoryServices.AccountManagement.ContextType]::Machine }
$failed = New-Object System.Collections.ArrayList
$ldapOk = New-Object System.Collections.ArrayList
$ldapBad = New-Object System.Collections.ArrayList
$netbios = ''
if ($isDc) { try { $netbios = (Get-ADDomain).NetBIOSName } catch { } }

for ($i = 0; $i -lt $names.Count; $i++) {
    $u = [string]$names[$i]; $p = [string]$secrets[$i]
    $sec = ConvertTo-SecureString $p -AsPlainText -Force
    $notes = New-Object System.Collections.ArrayList
    try {
        if ($isDc) {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword $sec -ErrorAction Stop
            $a = Get-ADUser -Identity $u -Properties Enabled, LockedOut, PasswordExpired, AccountExpirationDate
            if ($a.LockedOut) {
                # Locked by failed logons - a password spray does this to scored
                # accounts. Unlocking restores service; it grants nothing new.
                Unlock-ADAccount -Identity $u -ErrorAction SilentlyContinue
                [void]$notes.Add('was LOCKED OUT (unlocked)')
            }
            if (-not $a.Enabled) { [void]$notes.Add("DISABLED - the scorer cannot log in: Enable-ADAccount $u") }
            if ($a.AccountExpirationDate -and $a.AccountExpirationDate -lt (Get-Date)) { [void]$notes.Add("EXPIRED: Clear-ADAccountExpiration $u") }
        } else {
            Set-LocalUser -Name $u -Password $sec -ErrorAction Stop
            $a = Get-LocalUser -Name $u
            if (-not $a.Enabled) { [void]$notes.Add("DISABLED - the scorer cannot log in: Enable-LocalUser $u") }
        }
        $line = '  ok      {0,-16} password set' -f $u
        if ($notes.Count) { $line += '   !! ' + ($notes -join '; ') }
        Write-Host $line
        Write-CcdcLog ("passwords: set $u" + $(if ($notes.Count) { ' (' + ($notes -join '; ') + ')' } else { '' }))
    } catch {
        Write-Host ('  FAILED  {0,-16} {1}' -f $u, $_.Exception.Message) -ForegroundColor Red
        Write-CcdcLog "passwords: FAILED $u"
        [void]$failed.Add($u)
        continue
    }
    # Prove it the way the scorer will.
    $good = $false
    try {
        $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ctxType)
        $good = $pc.ValidateCredentials($u, $p)
    } catch { }
    if ($isDc) {
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry('LDAP://127.0.0.1', ("{0}\{1}" -f $netbios, $u), $p)
            $null = $de.NativeObject
            [void]$ldapOk.Add($u)
        } catch { [void]$ldapBad.Add($u) }
    }
    if (-not $good) { Write-Host ('          {0,-16} set, but a logon with the new password FAILED - check the account' -f $u) -ForegroundColor Yellow }
}

if ($isDc) {
    Write-Host ''
    Write-Host 'CAN THE SCORER LOG IN? (an LDAP login to this DC, as the packet says AD is scored)'
    if ($ldapBad.Count -eq 0) {
        Write-Host ("  LDAP  port 389  accepts every new password ({0})" -f $ldapOk.Count) -ForegroundColor Green
    } else {
        Write-Host ("  LDAP  port 389  REJECTED: {0}" -f ($ldapBad -join ' ')) -ForegroundColor Red
        Write-Host '        a disabled, expired or locked account fails here exactly as it will for the scorer'
    }
}

# --- who else is logged in as these accounts? ----------------------------------------
$mine = (Get-Process -Id $PID).SessionId
$others = New-Object System.Collections.ArrayList
$q = @()
try { $q = @(quser 2>$null) } catch { }
foreach ($row in ($q | Select-Object -Skip 1)) {
    # USERNAME SESSIONNAME ID STATE IDLE LOGON-TIME; SESSIONNAME is blank for disconnected sessions.
    $cols = @(($row -replace '^[ >]', '').Trim() -split '\s+')
    if ($cols.Count -lt 3) { continue }
    $user = $cols[0]
    $id = $null
    foreach ($c in $cols[1..2]) { if ($c -match '^\d+$') { $id = [int]$c; break } }
    if ($null -eq $id -or $id -eq $mine) { continue }
    if (Test-CcdcListContains -Needle $user -List @($names)) { [void]$others.Add(@{ User = $user; Id = $id; Row = $row.Trim() }) }
}
if ($others.Count -gt 0) {
    Write-Host ''
    Write-Host ("OTHER SESSIONS OF THESE ACCOUNTS (yours is session {0})" -f $mine) -ForegroundColor Yellow
    Write-Host '  A session opened with the OLD password stays open after the change.'
    foreach ($o in $others) {
        Write-Host ('  {0}' -f $o.Row)
        if ($Kick) {
            logoff $o.Id 2>$null
            Write-Host ('    logged off session {0}' -f $o.Id)
        } else {
            Write-Host ('    end it:  logoff {0}' -f $o.Id)
        }
    }
    if (-not $Kick) { Write-Host '  or all of them at once: re-run with -Kick' }
}

Write-Host ''
if ($failed.Count) { Write-Host ("NOT CHANGED: {0} - they still have their old password. Fix and paste just those lines again." -f ($failed -join ' ')) -ForegroundColor Red }
if ($missing.Count) { Write-Host ("STILL ON THE PACKET PASSWORD (not in your block): {0}" -f ($missing -join ' ')) -ForegroundColor Yellow }
Write-Host '==== NOW, IN QUOTIENT ====' -ForegroundColor Cyan
Write-Host ("  Password Change Request for {0}: the same lines you pasted, for:" -f $env:COMPUTERNAME)
Write-Host ('  ' + ($names -join ' '))
Write-Host '  Until Quotient has them, the scorer logs in with the old ones and fails.'
if ($failed.Count) { exit 1 }
exit 0
