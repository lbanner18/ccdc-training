<#
.SYNOPSIS
    Lay tripwires, and find out who touched them.

.DESCRIPTION
    Detection, not offense. This puts decoy files where somebody rummaging
    through the box would find them, asks Windows to log every read, and
    reports which ones were touched and BY WHICH ACCOUNT.

    WHY THIS IS NOT HASHING

    The Linux canary records a hash and an access time. On Windows the useful
    event is a READ - an attacker opening a file called "domain admin creds"
    learns everything they wanted and changes nothing, so a hash comparison
    would say the box is clean.

    So this uses what Windows actually has: a SACL on each decoy asking for an
    audit record on read, plus the File System audit subcategory turned on.
    A read then produces Security event 4663, which carries the account name
    and logon ID of whoever did it. Verified on the lab box - a single
    Get-Content produced one 4663 naming the account.

    Hashes are still recorded and still compared, because auditing can be
    switched off by somebody who has already got in, and a decoy that was
    MODIFIED is worth knowing about even when the audit trail is gone.

    -Check never changes anything. Run it from a loop.

    WHAT A TRIP MEANS

    Nothing legitimate reads these files. They are not referenced by any
    service, not in any path, and named so that only a person looking for
    credentials would open one. A trip is not a maybe.

.EXAMPLE
    .\canary.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Deploy -Apply
.EXAMPLE
    .\canary.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Check
.EXAMPLE
    .\canary.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Remove -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [switch]$Deploy,
    [switch]$Check,
    [switch]$Status,
    [switch]$Remove,
    [switch]$Apply,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

Initialize-CcdcRoot
$cfg = Import-CcdcConfig -Path $Config

$script:manifestFile = Get-CcdcPath 'state\canaries.txt'
$script:lastCheckFile = Get-CcdcPath 'state\canary-lastcheck.txt'
$script:logName = 'canary.log'
function C { param([string]$m) Write-CcdcLog -Message $m -LogName $script:logName }

function Get-StateDir {
    $d = Get-CcdcPath 'state'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

# =============================================================================
# WHERE THE DECOYS GO
#
# Each one has to survive two different readers. Somebody rummaging for
# credentials must find it plausible enough to open - that is the whole
# mechanism - and you, at hour four, must be able to tell instantly that it is
# a decoy and not panic about a real credential file you forgot about.
#
# So: plausible NAMES, and contents that say what they are on the first line.
# The name is the bait; the body is for you.
# =============================================================================

$script:Decoys = @(
    @{ Path = 'C:\Users\Public\Documents\backup-credentials.txt'
       Body = @'
# CCDC CANARY - THIS IS A DECOY. It contains no real credentials.
# Nothing legitimate reads this file. If it appears in a canary report,
# somebody opened it, and canary.ps1 -Check will name the account.
svc_backup / Wint3r2026!Backup
sql_reader / R3ad0nly#2026
'@ }
    @{ Path = 'C:\Users\Public\Documents\domain admin.txt'
       Body = @'
# CCDC CANARY - THIS IS A DECOY. It contains no real credentials.
DOMAIN\Administrator : Tr0ub4dor&3
recovery key: 4829-1047-5562-9981
'@ }
    @{ Path = 'C:\inetpub\wwwroot\web.config.bak'
       Body = @'
<!-- CCDC CANARY - THIS IS A DECOY. No real connection string is in here. -->
<configuration><connectionStrings>
  <add name="db" connectionString="Server=10.0.0.9;User Id=sa;Password=S4_p4ssw0rd!" />
</connectionStrings></configuration>
'@ }
    @{ Path = 'C:\ProgramData\network-diagram.txt'
       Body = @'
# CCDC CANARY - THIS IS A DECOY. None of these hosts are real.
10.0.0.9   SQL01    sa / S4_p4ssw0rd!
10.0.0.20  DC01     domain controller
'@ }
)

function Get-Manifest {
    if (-not (Test-Path -LiteralPath $script:manifestFile)) { return @() }
    $out = @()
    foreach ($l in (Get-Content -LiteralPath $script:manifestFile -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($l) -or $l -match '^\s*#') { continue }
        $f = $l -split '\|', 3
        if (@($f).Count -lt 2) { continue }
        $out += [pscustomobject]@{ Path = $f[0]; Sha256 = $f[1]; Laid = $(if (@($f).Count -gt 2) { $f[2] } else { '' }) }
    }
    return $out
}

function Enable-FileAuditing {
    <#
        The SACL says "audit reads of this file". The audit POLICY says whether
        Windows writes those records at all. Both are needed, and the policy is
        off by default - a SACL on its own produces exactly nothing, silently,
        which is the failure mode this whole kit is written against.
    #>
    $out = & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-CcdcWarn "could not enable File System auditing: $($out -join ' ')"
        return $false
    }
    return $true
}

function Set-CanarySacl {
    param([Parameter(Mandatory)][string]$Path)
    # ReadData catches the open. WriteData and Delete catch someone tidying up
    # after themselves, which is its own answer.
    $acl = Get-Acl -LiteralPath $Path -Audit -ErrorAction Stop
    foreach ($right in @('ReadData','WriteData','Delete')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            'Everyone', $right, 'Success,Failure')
        $acl.AddAuditRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

# =============================================================================
# DEPLOY
# =============================================================================
if ($Deploy) {
    Assert-CcdcAdmin
    Get-StateDir | Out-Null

    Write-Host ''
    Write-Host ('canary.ps1 - laying tripwires on {0}' -f $env:COMPUTERNAME)
    Write-Host ''

    if (-not $Apply) {
        foreach ($d in $script:Decoys) { Write-Host ('  would lay: {0}' -f $d.Path) }
        Write-Host ''
        Write-Host '  would also turn on the File System audit subcategory, without which'
        Write-Host '  a SACL produces no records at all.'
        Write-Host ''
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }

    $auditOn = Enable-FileAuditing
    if ($auditOn) { Write-Host '  File System auditing: on' -ForegroundColor Green }
    else {
        Write-Host '  File System auditing: COULD NOT ENABLE' -ForegroundColor Red
        Write-Host '  Decoys will still be laid and their hashes compared, but a READ will'
        Write-Host '  not be recorded - and reading is what a canary is for.'
    }

    $laid = @()
    foreach ($d in $script:Decoys) {
        $dir = Split-Path -Parent $d.Path
        try {
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -LiteralPath $d.Path -Value $d.Body -Encoding UTF8 -ErrorAction Stop
            # Backdated so it does not stand out as the newest file on the box.
            (Get-Item -LiteralPath $d.Path).LastWriteTime = (Get-Date).AddDays(-97)
            $h = (Get-FileHash -LiteralPath $d.Path -Algorithm SHA256).Hash
            try { Set-CanarySacl -Path $d.Path } catch {
                Write-CcdcWarn "no audit rule on $($d.Path): $($_.Exception.Message)"
            }
            $laid += ('{0}|{1}|{2}' -f $d.Path, $h, (Get-Date).ToUniversalTime().ToString('u'))
            Write-Host ('  laid: {0}' -f $d.Path)
        } catch {
            Write-CcdcWarn "could not lay $($d.Path): $($_.Exception.Message)"
        }
    }

    # Real files worth watching too, named in the config. Same SACL, no decoy.
    foreach ($w in (Get-CcdcList -Config $cfg -Name 'CCDC_WATCH_FILES')) {
        if (-not (Test-Path -LiteralPath $w -PathType Leaf)) { continue }
        try {
            Set-CanarySacl -Path $w
            $h = (Get-FileHash -LiteralPath $w -Algorithm SHA256).Hash
            $laid += ('{0}|{1}|{2}' -f $w, $h, (Get-Date).ToUniversalTime().ToString('u'))
            Write-Host ('  watching (real file): {0}' -f $w)
        } catch { Write-CcdcWarn "could not watch $w : $($_.Exception.Message)" }
    }

    $laid | Set-Content -LiteralPath $script:manifestFile -Encoding UTF8
    # Two seconds ahead: laying a decoy writes it and then reads it to hash it,
    # and both are audited. Without this the very first -Check reports the
    # deployment as a trip.
    (Get-Date).AddSeconds(2).ToUniversalTime().ToString('o') | Set-Content -LiteralPath $script:lastCheckFile -Encoding UTF8
    C "deployed $(@($laid).Count) canaries"

    Write-Host ''
    Write-Host ('  {0} tripwire(s) laid.' -f @($laid).Count) -ForegroundColor Green
    Write-Host ''
    Write-Host ('     .\windows\canary.ps1 -Config {0} -Check' -f $Config)
    Write-Host '       read-only, safe in a loop. Run it whenever you come up for air.'
    Write-Host ''
    Write-Host '  Nothing legitimate reads these. A trip is not a maybe.'
    Write-Host ''
    exit 0
}

# =============================================================================
# CHECK - read-only, loopable
# =============================================================================
if ($Check) {
    Assert-CcdcAdmin
    $manifest = Get-Manifest
    if (@($manifest).Count -eq 0) {
        Write-CcdcDie "no canaries are laid. Run -Deploy -Apply first."
    }

    $since = (Get-Date).AddHours(-12)
    if (Test-Path -LiteralPath $script:lastCheckFile) {
        try { $since = [datetime]::Parse((Get-Content -LiteralPath $script:lastCheckFile -Raw).Trim()) } catch { }
    }

    $paths = @{}
    foreach ($m in $manifest) { $paths[$m.Path.ToLowerInvariant()] = $m }

    # --- what the hashes say, when the audit trail cannot say it ---------------
    #
    # Reading a file in order to hash it produces exactly the 4663 record an
    # attacker's read produces, so hashing on every check makes this tool report
    # its own footprints as an intrusion. Two attempts to filter them out both
    # failed on the lab box: by PID alone, which also discarded a genuine read
    # made from the operator's own console - a false negative, far worse than
    # the false positive it fixed - and by PID plus a time window, which still
    # let -Deploy's hashing through on the next check.
    #
    # So do not filter the reads. Do not make them. When auditing is on, a
    # modification already arrives as a 4663 carrying WriteData and the hash
    # adds nothing it did not already know. The hash is only needed when
    # auditing is OFF - and then there are no events to be confused with.
    #
    # Test-Path does not open the file, so the existence check below is free.
    $auditOn = ((& auditpol.exe /get /subcategory:"File System" 2>&1 | Out-String) -match 'Success')
    $modified = New-Object System.Collections.ArrayList
    $missing  = New-Object System.Collections.ArrayList
    foreach ($m in $manifest) {
        if (-not (Test-Path -LiteralPath $m.Path -PathType Leaf)) { [void]$missing.Add($m.Path); continue }
        if ($auditOn) { continue }
        $h = ''
        try { $h = (Get-FileHash -LiteralPath $m.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        if ($h -and $h -ne $m.Sha256) { [void]$modified.Add($m.Path) }
    }

    # --- what the audit log saw ------------------------------------------------
    #
    # One Get-Content produces several 4663 records - ReadData, then
    # - ReadData, then ReadAttributes, and once per matching audit rule in the
    # SACL. Measured on the lab box: a single read of one file printed three
    # identical TRIPPED lines. They are collapsed per file and account.
    $raw = New-Object System.Collections.ArrayList
    $auditReadable = $true
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $since } -ErrorAction Stop)
        foreach ($e in $events) {
            $msg = [string]$e.Message
            foreach ($k in $paths.Keys) {
                if ($msg -notmatch [regex]::Escape($k)) { continue }
                $who = ''; $proc = ''
                if ($msg -match 'Account Name:\s*(\S+)')   { $who = $Matches[1] }
                if ($msg -match 'Process Name:\s*(.+)')    { $proc = $Matches[1].Trim() }
                [void]$raw.Add([pscustomobject]@{
                    When = $e.TimeCreated; Path = $paths[$k].Path; Who = $who; Process = $proc
                })
                break
            }
        }
    } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        $auditReadable = $false
    } catch {
        # "No events were found" is not an error worth alarming about, but an
        # unreadable log is - and they arrive as the same exception type.
        if ($_.Exception.Message -notmatch 'No events were found') { $auditReadable = $false }
    }

    $trips = New-Object System.Collections.ArrayList
    foreach ($g in ($raw | Group-Object Path, Who)) {
        $rows = @($g.Group | Sort-Object When)
        [void]$trips.Add([pscustomobject]@{
            Path    = $rows[0].Path
            Who     = $rows[0].Who
            Process = $rows[0].Process
            Count   = @($rows).Count
            First   = $rows[0].When
            Last    = $rows[-1].When
        })
    }

    Write-Host ''
    Write-Host ('canary.ps1 - {0}, {1} tripwire(s), since {2:u}' -f $env:COMPUTERNAME, @($manifest).Count, $since)

    if (-not $auditReadable) {
        Write-Host ''
        Write-Host '  THE SECURITY LOG COULD NOT BE READ.' -ForegroundColor Red
        Write-Host '  Reads cannot be detected right now, so "no trips" below means only'
        Write-Host '  "no file was modified". Somebody clearing this log is itself an event:'
        Write-Host '     .\windows\triage.ps1 -Config CONFIG      # check logcleared'
    }

    $total = @($trips).Count + @($modified).Count + @($missing).Count
    if ($total -eq 0) {
        Write-Host ''
        Write-Host '  No tripwire has been touched.' -ForegroundColor Green
        Write-Host ''
        if ($auditReadable) {
            (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath $script:lastCheckFile -Encoding UTF8
        }
        exit 0
    }

    foreach ($t in $trips) {
        Write-Host ''
        Write-Host ('  TRIPPED  {0}' -f $t.Path) -ForegroundColor Red
        if ($t.Count -gt 1 -and $t.First -ne $t.Last) {
            Write-Host ('           {0} accesses by {1}, {2:u} to {3:u}' -f $t.Count, $t.Who, $t.First, $t.Last)
        } else {
            Write-Host ('           at {0:u} by {1}' -f $t.First, $t.Who)
        }
        if ($t.Process) { Write-Host ('           process: {0}' -f $t.Process) }
    }
    foreach ($p in $modified) {
        Write-Host ''
        Write-Host ('  MODIFIED {0}' -f $p) -ForegroundColor Red
        Write-Host  '           the contents changed. Nothing legitimate writes these.'
    }
    foreach ($p in $missing) {
        Write-Host ''
        Write-Host ('  DELETED  {0}' -f $p) -ForegroundColor Red
        Write-Host  '           somebody removed a tripwire, which is itself the answer.'
    }

    Write-Host ''
    Write-Host ('  {0} tripwire event(s).' -f $total) -ForegroundColor Red
    Write-Host ''
    Write-Host '  Nothing on this box has any business reading these files. Take the'
    Write-Host '  account name above and find out what else it did:'
    Write-Host '     Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4624} -MaxEvents 50 |'
    Write-Host '       Select-Object TimeCreated,@{n=''msg'';e={($_.Message -split "`r?`n")[0]}}'
    Write-Host ''
    Write-Host '  Then write it down while it is fresh. An incident report is worth'
    Write-Host '  points; a memory of one is not.'
    Write-Host ''
    foreach ($t in $trips)    { C "TRIPPED $($t.Path) by $($t.Who) x$($t.Count) first=$($t.First)" }
    foreach ($p in $modified) { C "MODIFIED $p" }
    foreach ($p in $missing)  { C "DELETED $p" }
    exit 2
}

# =============================================================================
# STATUS
# =============================================================================
if ($Status) {
    $manifest = Get-Manifest
    Write-Host ''
    if (@($manifest).Count -eq 0) {
        Write-Host '  no tripwires are laid.'
        Write-Host ('     .\windows\canary.ps1 -Config {0} -Deploy -Apply' -f $Config)
        Write-Host ''
        exit 0
    }
    Write-Host ('  {0} tripwire(s):' -f @($manifest).Count)
    foreach ($m in $manifest) {
        $state = if (Test-Path -LiteralPath $m.Path) { 'present' } else { 'GONE' }
        Write-Host ('    {0,-8} {1}' -f $state, $m.Path)
    }
    $pol = & auditpol.exe /get /subcategory:"File System" 2>&1 | Out-String
    Write-Host ''
    if ($pol -match 'Success') { Write-Host '  File System auditing is on - reads will be recorded.' }
    else {
        Write-Host '  File System auditing is OFF. Reads will NOT be recorded.' -ForegroundColor Yellow
        Write-Host ('     .\windows\canary.ps1 -Config {0} -Deploy -Apply    # turns it back on' -f $Config)
    }
    Write-Host ''
    exit 0
}

# =============================================================================
# REMOVE
# =============================================================================
if ($Remove) {
    Assert-CcdcAdmin
    $manifest = Get-Manifest
    if (@($manifest).Count -eq 0) { Write-CcdcInfo 'nothing to remove'; exit 0 }
    if (-not $Apply) {
        foreach ($m in $manifest) { Write-Host ('  would remove: {0}' -f $m.Path) }
        Write-Host ''
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        exit 0
    }
    foreach ($m in $manifest) {
        # Only the decoys this tool created. A real file named in
        # CCDC_WATCH_FILES keeps existing - it was only ever being watched.
        $isDecoy = $false
        foreach ($d in $script:Decoys) { if ($d.Path -eq $m.Path) { $isDecoy = $true; break } }
        if ($isDecoy) {
            Remove-Item -LiteralPath $m.Path -Force -ErrorAction SilentlyContinue
            Write-Host ('  removed: {0}' -f $m.Path)
        } else {
            Write-Host ('  left in place (real file, only watched): {0}' -f $m.Path)
        }
    }
    Remove-Item -LiteralPath $script:manifestFile -Force -ErrorAction SilentlyContinue
    C 'removed all canaries'
    Write-Host ''
    Write-Host '  The File System audit policy is left ON. It costs nothing and it is'
    Write-Host '  useful on its own.'
    Write-Host ''
    exit 0
}

Write-Host ''
Write-Host '  canary.ps1 needs one of: -Deploy, -Check, -Status, -Remove'
Write-Host ''
Write-Host ('    .\windows\canary.ps1 -Config {0} -Deploy -Apply    lay them' -f $Config)
Write-Host ('    .\windows\canary.ps1 -Config {0} -Check            has anything been touched' -f $Config)
Write-Host ''
exit 1
