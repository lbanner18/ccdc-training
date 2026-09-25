<#
.SYNOPSIS
    Record what this box looked like BEFORE you changed anything.

.DESCRIPTION
    This is the evidence half of the kit. triage.ps1 tells you what is wrong
    right now; this tells you what was true at a moment in time, which is what
    an incident report is built out of and what you compare against later.

    It changes nothing. There is no -Apply, by construction.

    Run it FIRST, before harden.ps1 - once you have hardened, you can no longer
    prove what the box looked like when you got it, and "the account was already
    there when we arrived" is a very different sentence from "an account
    appeared".

    Every collection says whether it SUCCEEDED or FAILED. A command that could
    not run writes a file saying so rather than an empty one, because an empty
    file and a clean box look identical three hours later.

.EXAMPLE
    .\recon.ps1 -Config C:\ProgramData\CCDC\ccdc.env
.EXAMPLE
    .\recon.ps1 -Config C:\ProgramData\CCDC\ccdc.env -OutputDir D:\evidence
#>
[CmdletBinding()]
param(
    [string]$Config,
    [string]$OutputDir,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

Initialize-CcdcRoot
$cfg = @{}
if ($Config) { $cfg = Import-CcdcConfig -Path $Config }

$facts = Get-CcdcBoxFacts
if (-not $Quiet) {
    Write-Host ''
    Write-Host ('recon.ps1 - what {0} looked like before you touched it' -f $facts['Host'])
    Write-Host ('read-only. {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-CcdcBoxBanner -Facts $facts
}

# Not being administrator does not stop the run - most of this is readable
# either way, and a partial record beats none. It DOES change what the record
# is worth, so say so once, here, rather than letting each collection fail
# quietly into its own file.
if (-not $facts['Elevated']) {
    Write-CcdcWarn 'not elevated: the Security event log and other users'' tasks will be missing from this record.'
}

if ($OutputDir) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $dir = Join-Path $OutputDir ("windows-recon-" + $stamp)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
} else {
    $dir = New-CcdcEvidenceDir -Label 'recon'
}

$script:okCount = 0
$script:failed  = New-Object System.Collections.ArrayList

function Save-Command {
    <#
        Writes one file per collection, and records whether it worked.

        The original version of this wrote the exception text into the same
        file as the data and printed "evidence saved" regardless. A
        non-elevated run therefore produced a Security-log file containing
        "Access denied" and a cheerful success message - which three hours
        later, under pressure, reads as "there were no interesting events".
    #>
    param([string]$Name, [string]$What, [scriptblock]$Command)
    $path = Join-Path $dir "$Name.txt"
    try {
        $out = & $Command 2>&1 | Out-String -Width 4096
        if ([string]::IsNullOrWhiteSpace($out)) {
            # Genuinely empty is a real answer, but it must be distinguishable
            # from a command that never ran.
            $out = "(collected successfully; there were no results)`r`n"
        }
        $header = "# $What`r`n# collected $((Get-Date).ToUniversalTime().ToString('u')) on $($facts['Host'])`r`n`r`n"
        Set-Content -LiteralPath $path -Value ($header + $out) -Encoding UTF8
        $script:okCount++
        if (-not $Quiet) { Write-Host ('  ok      {0}' -f $What) }
    } catch {
        $msg = $_.Exception.Message
        Set-Content -LiteralPath $path -Value @"
# $What
# NOT COLLECTED - this command failed on $($facts['Host']) at $((Get-Date).ToUniversalTime().ToString('u'))
#
#   $msg
#
# This file is a record of a GAP, not of a clean result. Do not read the
# absence of findings here as the absence of the thing.
"@ -Encoding UTF8
        [void]$script:failed.Add(('{0}: {1}' -f $What, $msg))
        if (-not $Quiet) { Write-Host ('  FAILED  {0}' -f $What) -ForegroundColor Red }
    }
}

Save-Command 'system' 'operating system, build and install date' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, CSName
}
Save-Command 'accounts' 'local accounts' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired,
                                  PasswordExpires, UserMayChangePassword, Description
}
Save-Command 'groups' 'membership of every local group' {
    foreach ($g in (Get-LocalGroup)) {
        "=== $($g.Name) ==="
        try { Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | Select-Object -ExpandProperty Name }
        catch { "  (could not read: $($_.Exception.Message))" }
    }
}
Save-Command 'firewall' 'firewall profiles and every enabled rule' {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogFileName
    Get-NetFirewallRule -Enabled True |
        Select-Object DisplayName, Direction, Action, Profile, Group |
        Sort-Object Direction, DisplayName
}
Save-Command 'listening' 'listening TCP and UDP ports, with owning process' {
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess,
                      @{n='Process';e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }} |
        Sort-Object LocalPort
    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess,
                      @{n='Process';e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }} |
        Sort-Object LocalPort
}
Save-Command 'services' 'every service, with its binary and logon account' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Sort-Object Name
}
Save-Command 'service-acls' 'who may reconfigure each service' {
    # The question svcacl in triage.ps1 asks. Recorded here so that "it was
    # already like that" is something you can prove rather than remember.
    foreach ($s in (Get-CimInstance Win32_Service | Sort-Object Name)) {
        $sddl = (& sc.exe sdshow $s.Name 2>$null | Where-Object { $_ -match '^D:' }) -join ''
        if ($sddl) { '{0} {1}' -f $s.Name.PadRight(40), $sddl }
    }
}
Save-Command 'scheduled-tasks' 'scheduled tasks and what they run' {
    Get-ScheduledTask | ForEach-Object {
        [PSCustomObject]@{
            Path    = $_.TaskPath
            Name    = $_.TaskName
            State   = $_.State
            Author  = $_.Author
            Actions = ($_.Actions | ForEach-Object {
                          $e = ''; $a = ''
                          try { $e = [string]$_.Execute }   catch { }
                          try { $a = [string]$_.Arguments } catch { }
                          ($e + ' ' + $a).Trim()
                      }) -join ' ; '
        }
    } | Sort-Object Path, Name
}
Save-Command 'autostart' 'autostart entries' {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
        "=== $k ==="
        try { Get-ItemProperty -LiteralPath $k -ErrorAction Stop | Format-List }
        catch { "  (not present)" }
    }
}
Save-Command 'autorunsc' 'optional Sysinternals Autorunsc persistence inventory' {
    $capture = Invoke-CcdcAutorunsc -Config $cfg
    if (-not $capture.Ran) { throw $capture.Reason }
    foreach ($row in @($capture.Rows)) {
        [pscustomobject]@{
            Entry = [string]$row.'Entry'
            Location = [string]$row.'Entry Location'
            ImagePath = [string]$row.'Image Path'
            Description = [string]$row.'Description'
            Publisher = [string]$row.'Publisher'
        }
    }
}
Save-Command 'wmi-subscriptions' 'WMI permanent event subscriptions' {
    foreach ($cls in @('__EventFilter', 'CommandLineEventConsumer',
                       'ActiveScriptEventConsumer', '__FilterToConsumerBinding')) {
        "=== $cls ==="
        Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue | Format-List
    }
}
Save-Command 'shares' 'SMB shares, their paths and who may reach them' {
    Get-SmbShare | Select-Object Name, Path, Description
    foreach ($sh in (Get-SmbShare)) {
        "=== $($sh.Name) ==="
        Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue |
            Select-Object AccountName, AccessControlType, AccessRight
    }
}
Save-Command 'defender' 'Defender status and exclusions' {
    Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
}
Save-Command 'installed-software' 'installed software' {
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        # Not every uninstall key has a DisplayName, and under StrictMode 2.0
        # reaching for a property that is not there throws rather than
        # returning $null - so ask whether it exists first.
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
}
Save-Command 'security-events' 'recent security events worth keeping' {
    # 4624 logon, 4625 failed logon, 4720 account created, 4732 added to group,
    # 7045 service installed, 4698 task created, 1102 log cleared.
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624,4625,4720,4732,4698,1102 } `
                 -MaxEvents 300 -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{n='Summary';e={ ($_.Message -split "`r?`n")[0] }}
}
Save-Command 'system-events' 'service installs and unexpected stops' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045,7034,7031,7040 } `
                 -MaxEvents 200 -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{n='Summary';e={ ($_.Message -split "`r?`n")[0] }}
}

# The hashes are what make this evidence rather than notes: they are how you
# show afterwards that the record was not edited between collection and report.
$sumsFile = Join-Path $dir 'SHA256SUMS.csv'
try {
    # Materialise the file list BEFORE hashing. A streaming
    # Get-ChildItem | Get-FileHash | Export-Csv writes SHA256SUMS.csv into the
    # directory it is still enumerating, then tries to hash it while Export-Csv
    # holds it open - "cannot access the file because it is being used by
    # another process", on the last line of the run, after all the work.
    $files  = @(Get-ChildItem -File -LiteralPath $dir | Where-Object { $_.Name -ne 'SHA256SUMS.csv' })
    $hashes = @($files | Get-FileHash -Algorithm SHA256 |
                Select-Object Hash, @{n='File';e={ Split-Path -Leaf $_.Path }})
    $hashes | Export-Csv -LiteralPath $sumsFile -NoTypeInformation
} catch {
    Write-CcdcWarn "could not hash the evidence files: $($_.Exception.Message)"
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host ('  {0} collection(s) saved to {1}' -f $script:okCount, $dir)
    if (@($script:failed).Count -gt 0) {
        Write-Host ''
        Write-Host ('  {0} collection(s) FAILED. Each wrote a file saying so:' -f @($script:failed).Count) -ForegroundColor Yellow
        foreach ($f in $script:failed) { Write-Host ('    - {0}' -f $f) -ForegroundColor Yellow }
        if (-not $facts['Elevated']) {
            Write-Host ''
            Write-Host '  Most of these are because this is not an elevated session. Re-run as' -ForegroundColor Yellow
            Write-Host '  administrator to get a complete record.' -ForegroundColor Yellow
        }
    }
    Write-Host ''
    Write-Host '  This is the "before" picture. Take it off the box - evidence that lives'
    Write-Host '  only on the machine it describes is evidence somebody can edit.'
    Write-Host ''
    # Two short lines on purpose: one long line wraps in the console, and copying
    # it keeps the wrap as a newline inside the path.
    Write-Host '  Quickest over RDP: zip it with these two lines, then in File Explorer'
    Write-Host '  right-click the zip in C:\ -> Copy, and paste it on your own machine.'
    Write-Host ("    `$r = '{0}'" -f ((Split-Path -Leaf $dir) -replace "'", "''"))
    Write-Host ("    Compress-Archive `"{0}\`$r`" `"{1}\`$r.zip`" -Force" -f (Split-Path -Parent $dir), $env:SystemDrive)
    Write-Host ''
}
