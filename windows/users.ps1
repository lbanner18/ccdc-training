<#
.SYNOPSIS
    Accounts and passwords - checklist items 1, 3, 4 and 5.

.DESCRIPTION
    Split out of harden.ps1 because these are the four things that can lose you
    the box in one keystroke, and they should never run as part of a bulk sweep.

        1  Secure admin credentials
        3  Create a backup admin
        4  Secure user & service passwords
        5  Audit users, remove / disable unauthorized accounts

    THE ONE THING TO UNDERSTAND BEFORE USING -RotateAll

    Some accounts are SCORED. The training notes say it plainly: "We have
    scored users in addition to scored services. We have to make sure scoring
    users are available." On many setups the scoring engine logs in as those
    accounts, with a password from the team packet.

    Change that password and you have taken a scored service down with a
    command that felt like hardening.

    So: by default this rotates every account EXCEPT the ones in
    CCDC_ALLOWED_USERS, and it will not touch a scored account unless you say
    -IncludeScoredUsers and mean it. Read your packet first. If it says to
    change them, there is usually a form to submit the new password on.

.EXAMPLE
    .\users.ps1 -Config C:\ProgramData\CCDC\ccdc.env
    Audit only. Read this first.

.EXAMPLE
    .\users.ps1 -Config CONFIG -CreateAdmin ops2 -Apply
    A second administrator, so losing one account does not lose you the box.

.EXAMPLE
    .\users.ps1 -Config CONFIG -RotateAll -Apply
    New random password for every LOCAL, NON-SCORED, enabled account.

.EXAMPLE
    .\users.ps1 -Config CONFIG -Rotate sqlsvc_ -Apply
    One named account. Named, never picked off a numbered list.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Apply,
    [string]$CreateAdmin,
    [string[]]$Rotate,
    [switch]$RotateAll,
    [switch]$IncludeScoredUsers,
    [string[]]$Disable,
    [int]$PasswordLength = 20
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
$allowed = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS'

Write-Host ''
Write-Host 'users.ps1 - accounts and passwords'
Write-CcdcBoxBanner -Facts $facts

if (Test-CcdcIsDomainController) {
    Write-Host '  THIS IS A DOMAIN CONTROLLER.' -ForegroundColor Yellow
    Write-Host '  It has no local accounts. Every account here is a DOMAIN account, and'
    Write-Host '  changing one changes it for every machine in the domain. This tool'
    Write-Host '  works on local accounts only and will not pretend otherwise.'
    Write-Host ''
    Write-Host '  Use these instead:'
    Write-Host '      Get-ADUser -Filter * -Properties Enabled,PasswordLastSet,whenCreated |'
    Write-Host '          Sort-Object whenCreated -Descending | Select-Object -First 25 Name,Enabled,whenCreated'
    Write-Host '      net group "Domain Admins" /domain'
    Write-Host '      Set-ADAccountPassword -Identity NAME -Reset'
    Write-Host ''
    exit 0
}

# Never both. -RotateAll plus a list is ambiguous, and an ambiguous command
# that touches every password on the box should not resolve itself quietly.
if ($RotateAll -and $Rotate) {
    Write-CcdcDie "use -RotateAll or -Rotate NAME, not both. One means 'everything', the other means 'exactly these'."
}

# --- where the new passwords go ----------------------------------------------
# To a file, immediately, before the change is attempted. A password that was
# set and not recorded is an account you have locked yourself out of.
$secretFile = Get-CcdcPath ('state\passwords-{0}.txt' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))

function New-CcdcPassword {
    param([int]$Length = 20)
    # Deliberately excludes characters that break `net user`, cmd quoting, or a
    # hand-copied password read off a screen: no space, no quote, no backtick,
    # no percent, and no l/I/1/O/0.
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnpqrstuvwxyz',
        '23456789',
        '!@#$^&*()-_=+[]{}:,.?'
    )
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 1
    $chars = New-Object System.Collections.ArrayList
    # One from each set first, so the result always satisfies a complexity
    # policy, then fill the rest from everything.
    foreach ($s in $sets) {
        $rng.GetBytes($bytes); [void]$chars.Add($s[$bytes[0] % $s.Length])
    }
    $all = -join $sets
    while (@($chars).Count -lt $Length) {
        $rng.GetBytes($bytes); [void]$chars.Add($all[$bytes[0] % $all.Length])
    }
    # Shuffle, so the first four are not always one-per-class.
    for ($i = @($chars).Count - 1; $i -gt 0; $i--) {
        $rng.GetBytes($bytes); $j = $bytes[0] % ($i + 1)
        $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
    }
    return (-join $chars)
}

function Record-Password {
    param([string]$User, [string]$Password)
    if (-not (Test-Path -LiteralPath $secretFile)) {
        @(
            '# CCDC password changes. Root/Administrator readable only.',
            ('# {0}  on {1}' -f (Get-Date).ToUniversalTime().ToString('u'), $env:COMPUTERNAME),
            '# WRITE THESE ON PAPER. This file is on the box an attacker is attacking.',
            ''
        ) | Set-Content -LiteralPath $secretFile -Encoding UTF8
    }
    ('{0,-24} {1}' -f $User, $Password) | Add-Content -LiteralPath $secretFile -Encoding UTF8
}

# --- 5. audit ----------------------------------------------------------------
$users = @()
try { $users = @(Get-LocalUser) } catch { Write-CcdcDie "could not read local accounts: $($_.Exception.Message)" }

$adminNames = @()
try {
    $adminNames = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { ($_.Name -split '\\')[-1] })
} catch { }

Write-Host '  ACCOUNTS ON THIS BOX'
Write-Host ''
Write-Host ('  {0,-22} {1,-9} {2,-7} {3,-20} {4}' -f 'NAME','ENABLED','ADMIN','PASSWORD SET','IN PACKET?')
Write-Host ('  {0}' -f ('-' * 78))
foreach ($u in ($users | Sort-Object Name)) {
    $isAdmin  = Test-CcdcListContains -Needle $u.Name -List $adminNames
    $inPacket = Test-CcdcListContains -Needle $u.Name -List $allowed
    $pls = 'unknown'
    try { if ($u.PasswordLastSet) { $pls = $u.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } } catch { }
    $flag = if ($inPacket) { 'yes - SCORED' } elseif ($u.Enabled) { '** NO **' } else { 'no' }
    Write-Host ('  {0,-22} {1,-9} {2,-7} {3,-20} {4}' -f `
        $u.Name, $(if ($u.Enabled) {'enabled'} else {'disabled'}), $(if ($isAdmin) {'ADMIN'} else {''}), $pls, $flag)
}
Write-Host ''
Write-Host '  "** NO **" means: enabled, and not named in CCDC_ALLOWED_USERS.'
Write-Host '  That is the column to read. Each one is either yours and missing from'
Write-Host '  your config, or it is not yours.'
Write-Host ''

# The backup admin has to be in the packet list, or every other tool reads it
# as an intruder: triage reports it RED rogueadmin, -RotateAll changes its
# password (so the one on paper stops working), and sentry offers to demote it.
# Found live on ccdc-win. Edits the LAST single-line definition, which is the
# one the loader keeps; anything else is left for the operator, and said so.
function Register-CcdcBackupAdmin {
    param([Parameter(Mandatory)][string]$Name)
    if (Test-CcdcListContains -Needle $Name -List @(Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS')) {
        Write-Host ('            {0} is already in CCDC_ALLOWED_USERS' -f $Name)
        return
    }
    $done = $false
    try {
        $lines = [System.IO.File]::ReadAllLines($Config)
        $at = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*CCDC_ALLOWED_USERS=') { $at = $i }
        }
        if ($at -ge 0 -and $lines[$at] -match '^\s*CCDC_ALLOWED_USERS="([^"]*)"\s*$') {
            $lines[$at] = 'CCDC_ALLOWED_USERS="{0}"' -f (($Matches[1].Trim() + ' ' + $Name).Trim())
            [System.IO.File]::WriteAllLines($Config, $lines)
            $done = $true
        }
    } catch { }
    if ($done) {
        Write-Host ('            added {0} to CCDC_ALLOWED_USERS in {1}, so triage and -RotateAll treat it as yours' -f $Name, $Config) -ForegroundColor Green
        Write-CcdcLog "added backup admin $Name to CCDC_ALLOWED_USERS"
    } else {
        Write-Host ('            ADD {0} TO CCDC_ALLOWED_USERS in {1} BY HAND.' -f $Name, $Config) -ForegroundColor Yellow
        Write-Host  '            Until you do, triage calls it a rogue admin and -RotateAll changes its password.' -ForegroundColor Yellow
    }
}

# --- 3. a second way in ------------------------------------------------------
if ($CreateAdmin) {
    Write-Host ('  BACKUP ADMINISTRATOR: {0}' -f $CreateAdmin)
    Write-Host '  The training said to make one. If the red team takes your account out of'
    Write-Host '  Administrators, this is the difference between ten bad minutes and a lost box.'
    Write-Host ''
    if ($CreateAdmin -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        Write-CcdcDie "refusing that name: use letters, digits, dot, underscore or hyphen, 20 characters or fewer"
    }
    $exists = $null
    try { $exists = Get-LocalUser -Name $CreateAdmin -ErrorAction Stop } catch { }
    $pw = New-CcdcPassword -Length $PasswordLength
    if (-not $Apply) {
        Write-Host ('    [would] create local account {0}, add it to Administrators,' -f $CreateAdmin)
        Write-Host  '            set a random 20-character password and write it to'
        Write-Host ('            {0}' -f $secretFile)
        Write-Host ('            and add {0} to CCDC_ALLOWED_USERS in {1}' -f $CreateAdmin, $Config)
    } elseif ($exists) {
        Write-Host ('    {0} already exists - not recreating it. Rotate it instead if you want a new password:' -f $CreateAdmin)
        Write-Host ('      .\windows\users.ps1 -Config {0} -Rotate {1} -IncludeScoredUsers -Apply' -f $Config, $CreateAdmin)
        Register-CcdcBackupAdmin -Name $CreateAdmin
    } else {
        Record-Password -User $CreateAdmin -Password $pw
        $sec = ConvertTo-SecureString $pw -AsPlainText -Force
        try {
            New-LocalUser -Name $CreateAdmin -Password $sec -FullName 'CCDC backup admin' `
                -Description 'second administrator - incident response' -PasswordNeverExpires -ErrorAction Stop | Out-Null
            Add-LocalGroupMember -Group 'Administrators' -Member $CreateAdmin -ErrorAction Stop
            Write-Host ('    [done]  created {0} and added it to Administrators' -f $CreateAdmin) -ForegroundColor Green
            Write-Host ('            password written to {0}' -f $secretFile)
            Write-Host  '            WRITE IT ON PAPER NOW. That file is on the box being attacked.' -ForegroundColor Yellow
            # Proven on ccdc-win: valid password, WinRM still refuses it.
            Write-Host  '            Use it at the console or over RDP. Remote PowerShell (WinRM) refuses local'
            Write-Host  '            admins other than Administrator by design (Remote UAC) - that is not a broken'
            Write-Host  '            account, and turning it off re-enables pass-the-hash. Leave it on.'
            Write-CcdcLog "created backup admin $CreateAdmin"
            Register-CcdcBackupAdmin -Name $CreateAdmin
        } catch {
            Write-Host ('    [FAIL]  {0}' -f $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host ''
}

# --- 4. passwords ------------------------------------------------------------
$targets = @()
$heldBack = @()
if ($RotateAll) {
    foreach ($u in $users) {
        if (-not $u.Enabled) { continue }
        if ($u.Name -match '^(DefaultAccount|WDAGUtilityAccount|Guest)$') { continue }
        if ((Test-CcdcListContains -Needle $u.Name -List $allowed) -and -not $IncludeScoredUsers) { $heldBack += $u.Name; continue }
        $targets += $u.Name
    }
    # Say what was NOT rotated. A silent -RotateAll on a box where every
    # enabled account is in the packet list looked like success and left the
    # administrator password - the red team's first guess - exactly as it was.
    if (@($targets).Count -eq 0) {
        Write-Host '  PASSWORD ROTATION: nothing to rotate. Every enabled account is in'
        Write-Host '  CCDC_ALLOWED_USERS, and -RotateAll leaves those alone.'
        Write-Host ''
    }
    if (@($heldBack).Count -gt 0) {
        Write-Host ('  NOT rotated, because the packet names them: {0}' -f ($heldBack -join ', ')) -ForegroundColor Yellow
        Write-Host  '  Your OWN admin password is the red team''s first guess - change it on purpose,'
        Write-Host  '  after -CreateAdmin, and write the new one down. For each account here:'
        Write-Host  '    the one YOU log in with:        net user NAME *     (you type the new password)'
        Write-Host ('    one the packet says to change:  .\windows\users.ps1 -Config {0} -Rotate NAME -IncludeScoredUsers -Apply' -f $Config)
        Write-Host  '    one the scoring engine uses:    leave it unless the packet says otherwise'
        Write-Host ''
    }
} elseif ($Rotate) {
    foreach ($n in $Rotate) {
        if ((Test-CcdcListContains -Needle $n -List $allowed) -and -not $IncludeScoredUsers) {
            Write-Host ('  REFUSING to rotate {0}: it is in CCDC_ALLOWED_USERS, which means the packet' -f $n) -ForegroundColor Yellow
            Write-Host  '  names it as an account that has to keep working. On many setups the scoring'
            Write-Host  '  engine logs in as exactly these accounts, so a new password is an outage.'
            Write-Host  ''
            Write-Host  '  If the packet says to change it anyway - and it often does, with a form to'
            Write-Host  '  submit the new one on - say so explicitly:'
            Write-Host ('      .\windows\users.ps1 -Config {0} -Rotate {1} -IncludeScoredUsers -Apply' -f $Config, $n)
            Write-Host  ''
            continue
        }
        $targets += $n
    }
}

if (@($targets).Count -gt 0) {
    Write-Host '  PASSWORD ROTATION'
    if ($IncludeScoredUsers) {
        Write-Host ''
        Write-Host '  -IncludeScoredUsers IS SET. Scored accounts are included below.' -ForegroundColor Yellow
        Write-Host '  If the scoring engine authenticates as one of these, you are about to' -ForegroundColor Yellow
        Write-Host '  take that check down until you submit the new password.' -ForegroundColor Yellow
    }
    Write-Host ''
    foreach ($n in $targets) {
        $pw = New-CcdcPassword -Length $PasswordLength
        if (-not $Apply) {
            Write-Host ('    [would] set a new random {0}-character password for {1}' -f $PasswordLength, $n)
            continue
        }
        # Recorded BEFORE the attempt. A password that was set and not written
        # down is an account nobody can use.
        Record-Password -User $n -Password $pw
        try {
            $sec = ConvertTo-SecureString $pw -AsPlainText -Force
            Set-LocalUser -Name $n -Password $sec -ErrorAction Stop
            Write-Host ('    [done]  {0}' -f $n) -ForegroundColor Green
            Write-CcdcLog "rotated password for $n"
        } catch {
            Write-Host ('    [FAIL]  {0}: {1}' -f $n, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host ''
    if ($Apply) {
        Write-Host ('  Passwords written to: {0}' -f $secretFile) -ForegroundColor Yellow
        Write-Host  '  WRITE THEM ON PAPER, then think about deleting that file. It is sitting'
        Write-Host  '  on the box somebody is attacking.'
        Write-Host ''
    }
}

# --- 5. disable ---------------------------------------------------------------
if ($Disable) {
    Write-Host '  DISABLING ACCOUNTS'
    Write-Host '  Disabled, not deleted: deleting destroys the evidence of what it did,'
    Write-Host '  and a deleted SID does not come back.'
    Write-Host ''
    foreach ($n in $Disable) {
        if (Test-CcdcListContains -Needle $n -List $allowed) {
            Write-Host ('    REFUSING {0}: the packet names it. Disabling a scored account is lost points.' -f $n) -ForegroundColor Yellow
            continue
        }
        if (-not $Apply) { Write-Host ('    [would] disable {0}' -f $n); continue }
        try {
            Disable-LocalUser -Name $n -ErrorAction Stop
            Write-Host ('    [done]  disabled {0}' -f $n) -ForegroundColor Green
            Write-CcdcLog "disabled account $n"
        } catch {
            Write-Host ('    [FAIL]  {0}: {1}' -f $n, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host ''
}

if (-not $Apply -and ($CreateAdmin -or @($targets).Count -gt 0 -or $Disable)) {
    Write-Host '  DRY RUN. Nothing above happened. Add -Apply.'
    Write-Host ''
}

Write-Host '  What to do next, in this order:'
Write-Host ('    1. a second administrator:  .\windows\users.ps1 -Config {0} -CreateAdmin ops2 -Apply' -f $Config)
Write-Host ('    2. rotate the rest:         .\windows\users.ps1 -Config {0} -RotateAll -Apply' -f $Config)
Write-Host ('    3. then look for what is already here: .\windows\triage.ps1 -Config {0}' -f $Config)
Write-Host ''
Write-Host '  more: playbooks\windows-cards.md  CARD W1 - accounts'
Write-Host ''
