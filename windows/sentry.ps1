<#
.SYNOPSIS
    The approval queue: numbered findings, and fixes that happen only when you
    say so, one at a time or in a batch you chose.

.DESCRIPTION
    triage.ps1 tells you what is wrong and prints the command. That is fine at
    minute five and useless at minute fifty, when there are thirty findings and
    you are writing an inject response. This numbers them and applies them.

    HOW IT IS SAFE

    -Status freezes a numbered snapshot. -Approve selects from THAT snapshot,
    not from a fresh scan, so a finding that appears between the two cannot
    inherit a number you already read. Before anything is applied the identity
    (check + subject) is re-verified against a fresh triage run: if it is gone,
    or no longer automatable, it is SKIPPED rather than guessed at.

    A bulk -Approve all applies RED only. AMBER means "this may well be yours"
    - a share your team published, a port your scored service listens on - and
    a sweep that took those would be the self-inflicted outage this kit exists
    to prevent. Named by number, they apply like anything else.

    Nothing changes without -Apply.

    WHAT IT WILL NOT DO

    Some findings have no safe automatic fix and are never offered:
      fwinbound   setting default-deny inbound can cut your own session. It is
                  in harden.ps1, which writes your allow rule FIRST.
      lsappl      needs a reboot. Rebooting a scored box is your decision.
      svcpath     a service binary in an odd place may be your application.
      svcdiracl   directory ACLs need judgement about what else lives there.

.EXAMPLE
    .\sentry.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
    Freeze and print the numbered queue.

.EXAMPLE
    .\sentry.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Approve all -Apply
    Apply every RED. AMBER items are listed with their own approve command.

.EXAMPLE
    .\sentry.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Approve 7 -Apply

.EXAMPLE
    .\sentry.ps1 -Watch
    Leave running in a second window. Every -IntervalSeconds (default 120) it
    re-runs triage, the baseline comparison, the canary check and Defender's
    detection list, and shouts - banner, beep, popup in every session - only
    about what is NEW since the last pass. Read-only: it never fixes anything.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Status,
    [string]$Approve,
    [switch]$Apply,
    [string]$Mute,
    [string]$Unmute,
    [switch]$Muted,
    [switch]$Undo,
    [switch]$Quiet,
    [switch]$Watch,
    [ValidateRange(30,3600)][int]$IntervalSeconds = 120,
    [switch]$NoPopup,
    [ValidateRange(0,100000)][int]$Passes = 0
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

Initialize-CcdcRoot
$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']

$script:findingsFile = Get-CcdcPath 'state\findings.txt'
$script:reviewedFile = Get-CcdcPath 'state\reviewed.txt'
$script:muteFile     = Get-CcdcPath 'state\muted.txt'
$script:undoFile     = Get-CcdcPath 'state\applied.txt'
$script:lockFile     = Get-CcdcPath 'state\sentry.lock'
$script:logName      = 'sentry.log'

function S { param([string]$m) Write-CcdcLog -Message $m -LogName $script:logName }

function Get-StateDir {
    $d = Get-CcdcPath 'state'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

# --- the lock ----------------------------------------------------------------
# Two sentry commands must not interleave: --status publishing a snapshot while
# --approve is reading it produces numbers that name different findings at each
# end. An exclusive file handle is the simplest thing that actually excludes.

function Lock-Sentry {
    Get-StateDir | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $script:lockHandle = [IO.File]::Open($script:lockFile, 'OpenOrCreate', 'ReadWrite', 'None')
            return $true
        } catch { Start-Sleep -Milliseconds 300 }
    }
    return $false
}
function Unlock-Sentry {
    if ($script:lockHandle) {
        try { $script:lockHandle.Close(); $script:lockHandle.Dispose() } catch { }
        $script:lockHandle = $null
    }
}

function Resolve-SentryTask {
    param([Parameter(Mandatory)][string]$Subject)
    # Triage's subject is TaskPath + TaskName. Resolve it back to exactly one
    # task instead of splitting on a character a task name is allowed to use.
    $matches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        ('{0}{1}' -f $_.TaskPath, $_.TaskName) -eq $Subject
    })
    if (@($matches).Count -ne 1) {
        throw "could not resolve '$Subject' to exactly one scheduled task"
    }
    return $matches[0]
}

# --- muting ------------------------------------------------------------------

function Get-MuteKeys {
    if (-not (Test-Path -LiteralPath $script:muteFile)) { return @() }
    return @(Get-Content -LiteralPath $script:muteFile -ErrorAction SilentlyContinue |
              Where-Object { $_ -and $_ -notmatch '^\s*#' })
}
function Test-Muted {
    param([string]$Check, [string]$Subject)
    $key = '{0}|{1}' -f $Check, $Subject
    return (@(Get-MuteKeys) -contains $key)
}

# =============================================================================
# WHAT CAN BE APPLIED, AND WHAT THAT COSTS
#
# Tier decides what a bulk approve may touch:
#   RED    safe, reversible, and no way to cut your own access. Swept.
#   AMBER  plausibly yours. Named by number only.
# A check absent from this table is never offered, however loudly triage
# reports it - printing a command you must read is the right answer for those.
# =============================================================================

$script:Actions = @{

    # ---- restoring things, which is the opposite of risky --------------------
    'scoredservice' = @{
        Tier = 'RED'
        # A filter that matches nothing returns nothing rather than an error, so
        # without this a missing service reached Do and failed on $null.StartMode.
        Can  = { param($s) $null -ne (Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue) }
        Why  = { param($s) "no service named '$s' on this box - check the spelling against the packet, or it is not installed here" }
        What = { param($s) "start the scored service '$s' and set it to start automatically" }
        Do   = { param($s, $ev)
            Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue |
                Select-Object Name, State, StartMode, PathName, StartName |
                Out-File (Join-Path $ev 'service-before.txt') -Encoding UTF8
            $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop
            if ($w.StartMode -eq 'Disabled') { Set-Service -Name $s -StartupType Automatic -ErrorAction Stop }
            Start-Service -Name $s -ErrorAction Stop
            $after = Get-Service -Name $s -ErrorAction Stop
            if ($after.Status -ne 'Running') { throw "service $s did not reach Running (it is $($after.Status))" }
        }
    }
    'scoreduser' = @{
        Tier = 'RED'
        # scoreduser fires for three different reasons - locked, expired, or
        # simply not here. Only the first two have anything to enable. On a
        # domain member "not a local account" is the normal case, and sweeping
        # it would mean every bulk approve ends with a failure that is not one.
        Can  = { param($s) $null -ne (Get-LocalUser -Name $s -ErrorAction SilentlyContinue) }
        Why  = { param($s) "'$s' is not a local account here - check the domain, there is nothing to enable on this box" }
        What = { param($s) "re-enable the scored account '$s' and clear any expiry" }
        Do   = { param($s, $ev)
            Get-LocalUser -Name $s -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled, AccountExpires, PasswordExpires |
                Out-File (Join-Path $ev 'account-before.txt') -Encoding UTF8
            Enable-LocalUser -Name $s -ErrorAction Stop
            try { Set-LocalUser -Name $s -AccountNeverExpires -ErrorAction Stop } catch { }
            $u = Get-LocalUser -Name $s -ErrorAction Stop
            if (-not $u.Enabled) { throw "account $s is still disabled" }
        }
    }

    # ---- turning defences back on -------------------------------------------
    'defenderoff' = @{
        Tier = 'RED'
        What = { param($s) "turn Defender '$s' back on" }
        Do   = { param($s, $ev)
            Get-MpComputerStatus | Out-File (Join-Path $ev 'defender-before.txt') -Encoding UTF8
            switch ($s) {
                'RealTimeProtection' { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
                'Antispyware'        { Set-MpPreference -DisableAntiSpyware        $false -ErrorAction Stop }
                default              { throw "unknown Defender setting '$s'" }
            }
        }
    }
    'defenderexcl' = @{
        Tier = 'RED'
        What = { param($s) "remove the Defender exclusion $s" }
        Do   = { param($s, $ev)
            Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension |
                Out-File (Join-Path $ev 'exclusions-before.txt') -Encoding UTF8
            $i = $s.IndexOf('=')
            if ($i -lt 1) { throw "cannot read exclusion subject '$s'" }
            # triage names the group exactly as Get-MpPreference does -
            # ExclusionPath, not Path. Matching on the short name silently sent
            # every exclusion to the default arm.
            $kind  = $s.Substring(0, $i)
            $value = $s.Substring($i + 1)
            switch ($kind) {
                'ExclusionPath'      { Remove-MpPreference -ExclusionPath      $value -ErrorAction Stop }
                'ExclusionProcess'   { Remove-MpPreference -ExclusionProcess   $value -ErrorAction Stop }
                'ExclusionExtension' { Remove-MpPreference -ExclusionExtension $value -ErrorAction Stop }
                default              { throw "unknown exclusion kind '$kind'" }
            }
        }
    }
    'fwlog' = @{
        Tier = 'RED'
        What = { param($s) "start logging dropped packets on the $s firewall profile" }
        Do   = { param($s, $ev)
            Get-NetFirewallProfile -Profile $s | Out-File (Join-Path $ev 'fwprofile-before.txt') -Encoding UTF8
            Set-NetFirewallProfile -Profile $s -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
        }
    }
    'psloggingoff' = @{
        Tier = 'RED'
        What = { param($s) "turn on PowerShell script block logging" }
        Do   = { param($s, $ev)
            $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            if (-not (Test-Path -LiteralPath $k)) { New-Item -Path $k -Force | Out-Null }
            Set-ItemProperty -LiteralPath $k -Name EnableScriptBlockLogging -Value 1 -Type DWord -ErrorAction Stop
            'EnableScriptBlockLogging set to 1' | Out-File (Join-Path $ev 'pslogging.txt') -Encoding UTF8
        }
    }
    'wdigest' = @{
        Tier = 'RED'
        What = { param($s) "stop WDigest caching cleartext passwords in memory" }
        Do   = { param($s, $ev)
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            if (-not (Test-Path -LiteralPath $k)) { New-Item -Path $k -Force | Out-Null }
            Set-ItemProperty -LiteralPath $k -Name UseLogonCredential -Value 0 -Type DWord -ErrorAction Stop
            'UseLogonCredential set to 0 - ROTATE PASSWORDS, they were readable' |
                Out-File (Join-Path $ev 'wdigest.txt') -Encoding UTF8
        }
    }
    'guest' = @{
        Tier = 'RED'
        What = { param($s) "disable the Guest account" }
        Do   = { param($s, $ev)
            Get-LocalUser -Name $s | Out-File (Join-Path $ev 'guest-before.txt') -Encoding UTF8
            Disable-LocalUser -Name $s -ErrorAction Stop
        }
    }
    'ifeo' = @{
        Tier = 'RED'
        What = { param($s) "remove the debugger hijack on $s" }
        Do   = { param($s, $ev)
            $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$s"
            Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue |
                Out-File (Join-Path $ev 'ifeo-before.txt') -Encoding UTF8
            Remove-ItemProperty -LiteralPath $k -Name Debugger -ErrorAction Stop
        }
    }
    'smbv1' = @{
        Tier = 'RED'
        What = { param($s) "disable SMBv1" }
        Do   = { param($s, $ev)
            Get-SmbServerConfiguration | Out-File (Join-Path $ev 'smb-before.txt') -Encoding UTF8
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        }
    }

    # ---- plausibly yours: by number only ------------------------------------
    'rogueadmin' = @{
        Tier = 'AMBER'
        What = { param($s) "remove '$s' from Administrators (the account itself is left alone)" }
        Do   = { param($s, $ev)
            Get-LocalGroupMember -Group 'Administrators' | Out-File (Join-Path $ev 'admins-before.txt') -Encoding UTF8
            Remove-LocalGroupMember -Group 'Administrators' -Member $s -ErrorAction Stop
        }
    }
    'newuser' = @{
        Tier = 'AMBER'
        What = { param($s) "disable the local account '$s' (not delete it - deleting destroys the evidence)" }
        Do   = { param($s, $ev)
            Get-LocalUser -Name $s | Select-Object * | Out-File (Join-Path $ev 'user-before.txt') -Encoding UTF8
            Disable-LocalUser -Name $s -ErrorAction Stop
        }
    }
    'rdpusers' = @{
        Tier = 'AMBER'
        What = { param($s) "remove '$s' from Remote Desktop Users" }
        Do   = { param($s, $ev)
            Get-LocalGroupMember -Group 'Remote Desktop Users' | Out-File (Join-Path $ev 'rdu-before.txt') -Encoding UTF8
            Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $s -ErrorAction Stop
        }
    }
    'runkey' = @{
        Tier = 'AMBER'
        What = { param($s) "remove the autostart value $s" }
        Do   = { param($s, $ev)
            $i = $s.LastIndexOf('\')
            if ($i -lt 1) { throw "cannot read run-key subject '$s'" }
            $key  = $s.Substring(0, $i)
            $name = $s.Substring($i + 1)
            Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue |
                Out-File (Join-Path $ev 'runkey-before.txt') -Encoding UTF8
            Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction Stop
        }
    }
    'wmisub' = @{
        Tier = 'AMBER'
        What = { param($s) "remove the WMI consumer '$s', its binding and its filter" }
        Do   = { param($s, $ev)
            # The filter says what they were waiting for. Keep it before it goes.
            foreach ($cls in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
                Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue |
                    Format-List | Out-File (Join-Path $ev 'wmi-before.txt') -Append -Encoding UTF8
            }
            Get-CimInstance -Namespace 'root/subscription' -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                Where-Object { $_.Consumer -match [regex]::Escape($s) } | Remove-CimInstance -ErrorAction SilentlyContinue
            foreach ($cls in @('CommandLineEventConsumer','ActiveScriptEventConsumer')) {
                Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq $s } | Remove-CimInstance -ErrorAction SilentlyContinue
            }
            Get-CimInstance -Namespace 'root/subscription' -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $s } | Remove-CimInstance -ErrorAction SilentlyContinue
        }
    }
    'svcacl' = @{
        Tier = 'AMBER'
        What = { param($s) "restore the stock permissions on service '$s'" }
        Do   = { param($s, $ev)
            $before = (& sc.exe sdshow $s 2>&1) -join "`r`n"
            $before | Out-File (Join-Path $ev 'svcacl-before.txt') -Encoding UTF8
            $stock = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
            $out = & sc.exe sdset $s $stock 2>&1
            if ($LASTEXITCODE -ne 0) { throw "sc sdset failed: $($out -join ' ')" }
        }
    }
    'svcdiracl' = @{
        Tier = 'AMBER'
        Can  = { param($s) Test-Path -LiteralPath $s -PathType Container }
        Why  = { param($s) "the directory '$s' is no longer there" }
        What = { param($s) "stop ordinary users writing into '$s' (read access is kept)" }
        Do   = { param($s, $ev)
            (& icacls.exe $s 2>&1) | Out-File (Join-Path $ev 'icacls-before.txt') -Encoding UTF8
            # /remove cannot touch an INHERITED grant: copy inheritance down first.
            $out = & icacls.exe $s /inheritance:d 2>&1
            if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:d failed: $($out -join ' ')" }
            foreach ($id in 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'Everyone', 'NT AUTHORITY\INTERACTIVE', 'BUILTIN\Guests') {
                & icacls.exe $s /remove:g $id 2>&1 | Out-Null
            }
            $out = & icacls.exe $s /grant 'BUILTIN\Users:(OI)(CI)RX' 2>&1
            if ($LASTEXITCODE -ne 0) { throw "icacls /grant failed: $($out -join ' ')" }
        }
    }
    'share' = @{
        Tier = 'AMBER'
        Can  = { param($s) $n = ($s -split ' \(')[0]; ($n -notmatch '(?i)^(NETLOGON|SYSVOL|IPC\$|ADMIN\$|[A-Z]\$)$') -and ($null -ne (Get-SmbShare -Name $n -ErrorAction SilentlyContinue)) }
        Why  = { param($s) "the share '$s' is a system share or no longer exists - not touched" }
        What = { param($s) "take Everyone / Users / Authenticated Users / Anonymous off the share $s (the share and its files stay)" }
        Do   = { param($s, $ev)
            $n = ($s -split ' \(')[0]
            Get-SmbShareAccess -Name $n -ErrorAction Stop | Out-File (Join-Path $ev 'share-before.txt') -Encoding UTF8
            foreach ($acct in 'Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'NT AUTHORITY\ANONYMOUS LOGON') {
                Revoke-SmbShareAccess -Name $n -AccountName $acct -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    'svcpath' = @{
        Tier = 'AMBER'
        # Never a service the packet scores, however odd its path looks.
        Can  = { param($s) ($null -ne (Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue)) -and
                           (@(([string]$cfg['CCDC_WINDOWS_SERVICES']) -split '\s+') -notcontains $s) }
        Why  = { param($s) "'$s' is gone, or it is listed in CCDC_WINDOWS_SERVICES as scored - not touched" }
        What = { param($s) "stop and disable service '$s', keeping a copy of its program as evidence (not deleted)" }
        Do   = { param($s, $ev)
            $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop
            $w | Select-Object Name, State, StartMode, PathName, StartName | Out-File (Join-Path $ev 'service-before.txt') -Encoding UTF8
            $exe = $w.PathName.Trim(); if ($exe.StartsWith('"')) { $exe = ($exe -split '"')[1] } else { $exe = ($exe -split '\s+')[0] }
            if (Test-Path -LiteralPath $exe) { Copy-Item -LiteralPath $exe -Destination $ev -Force -ErrorAction SilentlyContinue }
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
        }
    }
    'procshell' = @{
        Tier = 'RED'
        # The pid must still be the same program: pids are reused.
        Can  = { param($s) if ($s -notmatch '^pid(\d+):(.+)$') { return $false }
                           $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($Matches[1])" -ErrorAction SilentlyContinue
                           ($null -ne $p) -and ($p.ExecutablePath -eq $Matches[2]) }
        Why  = { param($s) "the process '$s' has already exited, or its pid now belongs to something else" }
        What = { param($s) "stop the renamed shell $s, after saving its command line and a copy of the program" }
        Do   = { param($s, $ev)
            if ($s -notmatch '^pid(\d+):(.+)$') { throw "cannot read process subject '$s'" }
            $procId = [int]$Matches[1]; $path = $Matches[2]
            Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop |
                Select-Object ProcessId, ParentProcessId, CommandLine, CreationDate | Format-List |
                Out-File (Join-Path $ev 'process-before.txt') -Encoding UTF8
            Copy-Item -LiteralPath $path -Destination $ev -Force -ErrorAction SilentlyContinue
            Stop-Process -Id $procId -Force -ErrorAction Stop
        }
    }
    'listener' = @{
        Tier = 'AMBER'
        What = { param($s) "block $s at the firewall (reversible; the process is left running)" }
        Do   = { param($s, $ev)
            if ($s -notmatch '^(tcp|udp)/(\d+)$') { throw "cannot read listener subject '$s'" }
            $proto = $Matches[1].ToUpper(); $port = $Matches[2]
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Out-File (Join-Path $ev 'listeners-before.txt') -Encoding UTF8
            New-NetFirewallRule -DisplayName ("CCDC block {0}" -f $s) -Direction Inbound `
                -LocalPort $port -Protocol $proto -Action Block -ErrorAction Stop | Out-Null
        }
    }
    'fwallow' = @{
        Tier = 'AMBER'
        What = { param($s) "disable the inbound allow rule $s" }
        Do   = { param($s, $ev)
            $name = ($s -split ' -> ')[0]
            Get-NetFirewallRule -DisplayName $name | Format-List |
                Out-File (Join-Path $ev 'fwrule-before.txt') -Encoding UTF8
            Disable-NetFirewallRule -DisplayName $name -ErrorAction Stop
        }
    }
    'smbsign' = @{
        Tier = 'AMBER'
        What = { param($s) "require SMB signing (can break very old clients)" }
        Do   = { param($s, $ev)
            Get-SmbServerConfiguration | Out-File (Join-Path $ev 'smb-before.txt') -Encoding UTF8
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
        }
    }
    'nullsession' = @{
        Tier = 'AMBER'
        What = { param($s) "block anonymous SAM enumeration" }
        Do   = { param($s, $ev)
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Get-ItemProperty -LiteralPath $k | Out-File (Join-Path $ev 'lsa-before.txt') -Encoding UTF8
            Set-ItemProperty -LiteralPath $k -Name RestrictAnonymousSAM -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -LiteralPath $k -Name RestrictAnonymous    -Value 1 -Type DWord -ErrorAction Stop
        }
    }
    'ifeoempty' = @{
        Tier = 'AMBER'
        What = { param($s) "remove the leftover IFEO key for $s" }
        Do   = { param($s, $ev)
            $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$s"
            Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue |
                Out-File (Join-Path $ev 'ifeo-before.txt') -Encoding UTF8
            Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop
        }
    }
    'taskcmd' = @{
        Tier = 'RED'
        What = { param($s) "export and disable the scheduled task '$s'" }
        Do   = { param($s, $ev)
            $task = Resolve-SentryTask -Subject $s
            Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop |
                Out-File (Join-Path $ev 'task-before.xml') -Encoding UTF8
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
            $after = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
            if ($after.State -ne 'Disabled') { throw "task '$s' is still $($after.State)" }
        }
    }
    'newtask' = @{
        Tier = 'AMBER'
        What = { param($s) "export and disable the newly registered task '$s'" }
        Do   = { param($s, $ev)
            $task = Resolve-SentryTask -Subject $s
            Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop |
                Out-File (Join-Path $ev 'task-before.xml') -Encoding UTF8
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
            $after = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
            if ($after.State -ne 'Disabled') { throw "task '$s' is still $($after.State)" }
        }
    }
    'winlogon' = @{
        Tier = 'RED'
        What = { param($s) "restore the stock Winlogon value '$s'" }
        Do   = { param($s, $ev)
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $name = switch ($s) {
                'Winlogon\Userinit' { 'Userinit'; break }
                'Winlogon\Shell'    { 'Shell'; break }
                default { throw "unknown Winlogon subject '$s'" }
            }
            $stock = if ($name -eq 'Userinit') { 'C:\Windows\system32\userinit.exe,' } else { 'explorer.exe' }
            Get-ItemProperty -LiteralPath $key -ErrorAction Stop |
                Select-Object Userinit, Shell | Out-File (Join-Path $ev 'winlogon-before.txt') -Encoding UTF8
            Set-ItemProperty -LiteralPath $key -Name $name -Value $stock -ErrorAction Stop
            $after = Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction Stop
            if ($after.$name -ne $stock) { throw "Winlogon $name did not return to its stock value" }
        }
    }
    'svcaccount' = @{
        Tier = 'AMBER'
        What = { param($s) "disable the service '$s' that logs on as an unnamed account" }
        Do   = { param($s, $ev)
            Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop |
                Select-Object Name, State, StartMode, StartName, PathName |
                Out-File (Join-Path $ev 'service-before.txt') -Encoding UTF8
            Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $s -ErrorAction Stop
            $after = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop
            if ($after.StartMode -ne 'Disabled') { throw "service '$s' is not disabled" }
        }
    }
}

# --- reading the queue -------------------------------------------------------

function Invoke-Triage {
    $t = Join-Path $PSScriptRoot 'triage.ps1'
    if (-not (Test-Path -LiteralPath $t)) { Write-CcdcDie "triage.ps1 is missing next to sentry.ps1" }
    & $t -Config $Config -Quiet -NoEvidence 2>&1 | Out-Null
    return (Test-Path -LiteralPath $script:findingsFile)
}

$script:notOffered = New-Object System.Collections.ArrayList

function Get-Queue {
    <# Findings that this tool can actually act on, in report order. #>
    $out = New-Object System.Collections.ArrayList
    $script:notOffered.Clear()
    if (-not (Test-Path -LiteralPath $script:findingsFile)) { return @() }
    foreach ($line in (Get-Content -LiteralPath $script:findingsFile -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = $line -split '\|', 4
        if (@($f).Count -lt 4) { continue }
        $sev = $f[0]; $check = $f[1]; $subject = $f[2]; $desc = $f[3]
        if ($sev -eq 'NOTE') { continue }
        if (-not $script:Actions.ContainsKey($check)) { continue }
        if (Test-Muted -Check $check -Subject $subject) { continue }
        # A precondition that fails means there is nothing here to apply. Say so
        # rather than queueing an action that can only fail.
        $act = $script:Actions[$check]
        if ($act.ContainsKey('Can')) {
            $can = $false
            try { $can = [bool](& $act.Can $subject) } catch { $can = $false }
            if (-not $can) {
                if (-not $Quiet -and $act.ContainsKey('Why')) {
                    [void]$script:notOffered.Add(('{0} {1}: {2}' -f $check, $subject, (& $act.Why $subject)))
                }
                continue
            }
        }
        [void]$out.Add([pscustomobject]@{
            Severity = $sev; Check = $check; Subject = $subject; Description = $desc
            Tier = $script:Actions[$check].Tier
        })
    }
    return @($out)
}

function Format-Item {
    param([int]$N, $Item)
    $what = & $script:Actions[$Item.Check].What $Item.Subject
    # The left column is the DECISION, not the severity. Printing triage's
    # severity here made every row read AMBER while the summary said five could
    # be swept, which left no way to tell which five. What the operator needs
    # from this column is one thing: will -Approve all take this?
    $tag = if ($Item.Tier -eq 'RED') { 'SWEEP' } else { 'LOOK ' }
    $colour = if ($Item.Tier -eq 'RED') { 'Green' } else { 'Yellow' }
    # One Write-Host per LINE, never per segment. -NoNewline does not survive
    # redirection: `sentry.ps1 -Status > report.txt` turns each segment into its
    # own line, and the numbered list stops being a list.
    Write-Host ''
    Write-Host ('  [{0}] {1}  {2,-14} {3}' -f $N, $tag, $Item.Check, $Item.Subject) -ForegroundColor $colour
    Write-Host ('        {0} - {1}' -f $Item.Severity, $Item.Description)
    Write-Host ('        WILL: {0}' -f $what) -ForegroundColor Cyan
    if ($Item.Tier -ne 'RED') {
        Write-Host '        -Approve all will NOT take this. Approve it by number.'
    }
}

# =============================================================================
# WATCH - the loop you leave running in a second window
# =============================================================================
# Windows has no always-on detector: the Guardian tasks keep the kit and the
# scored service alive, but nothing noticed a planted admin account until the
# operator ran triage by hand. Found live on ccdc-win. This re-runs the
# read-only checks on a timer and reports only what is NEW, so a solo operator
# working another box sees one popup instead of re-reading thirty findings.
# Each check runs as a child process: their `exit` codes must not end the loop.

function Invoke-WatchChild {
    param([Parameter(Mandatory)][string]$Script, [string[]]$Arguments = @())
    $path = Join-Path $PSScriptRoot $Script
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path -Config $Config @Arguments 2>&1 | Out-String
    return @{ Code = $LASTEXITCODE; Text = $out }
}

function Get-WatchSnapshot {
    # One key per thing worth telling the operator about, with the words to show.
    $snap = [ordered]@{}
    $muted = @(Get-MuteKeys)
    $triaged = $false
    if (Lock-Sentry) {
        try { [void](Invoke-WatchChild -Script 'triage.ps1' -Arguments @('-Quiet', '-NoEvidence')); $triaged = $true }
        finally { Unlock-Sentry }
    }
    if ($triaged -and (Test-Path -LiteralPath $script:findingsFile)) {
        foreach ($line in [System.IO.File]::ReadAllLines($script:findingsFile)) {
            $f = $line -split '\|', 4
            if ($f.Count -lt 4 -or $f[0] -notin @('RED', 'AMBER')) { continue }
            if ($muted -contains ('{0}|{1}' -f $f[1], $f[2])) { continue }
            $snap[('triage|{0}|{1}|{2}' -f $f[0], $f[1], $f[2])] = ('{0,-5} {1,-13} {2} - {3}' -f $f[0], $f[1], $f[2], $f[3])
        }
    }
    if (Test-Path -LiteralPath (Get-CcdcPath 'state\baseline.json')) {
        $b = Invoke-WatchChild -Script 'baseline.ps1' -Arguments @('-Status')
        if ($b.Text -notmatch 'Nothing has changed') {
            $drift = Get-CcdcPath 'state\drift.txt'
            if (Test-Path -LiteralPath $drift) {
                foreach ($line in [System.IO.File]::ReadAllLines($drift)) {
                    $f = $line -split '\|', 4
                    if ($f.Count -lt 3) { continue }
                    $snap[('drift|{0}|{1}|{2}' -f $f[0], $f[1], $f[2])] = ('DRIFT {0,-7} {1,-9} {2}' -f $f[0], $f[1], $f[2])
                }
            }
        }
    }
    $c = Invoke-WatchChild -Script 'canary.ps1' -Arguments @('-Check')
    if ($c.Code -eq 2) {
        # Key on the report itself, so a new trip is new and the same one is not.
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $h = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($c.Text))).Replace('-', '').Substring(0, 12)
        $snap[('canary|' + $h)] = 'CANARY tripwire touched, modified or deleted - run: .\windows\canary.ps1 -Check'
    }
    try {
        foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) {
            $name = [string]$d.ThreatID
            try { $name = [string](Get-MpThreat -ThreatID $d.ThreatID -ErrorAction Stop).ThreatName } catch { }
            $when = ''
            try { $when = $d.InitialDetectionTime.ToString('MM-dd HH:mm') } catch { }
            # Defender records one behaviour detection as several rows (the
            # process, then the thing it touched); one line per threat-minute.
            $key = 'defender|{0}|{1}' -f $name, $when
            $proc = [string]$d.ProcessName
            if ($snap.Contains($key) -and ($proc -eq '' -or $proc -eq 'Unknown')) { continue }
            $snap[$key] = ('DEFENDER caught {0} at {1} (process: {2})' -f $name, $when, $proc)
        }
    } catch { }
    return $snap
}

if ($Watch) {
    Assert-CcdcAdmin
    $host.UI.RawUI.WindowTitle = 'sentry watch - ' + $env:COMPUTERNAME
    Write-Host ''
    Write-Host ('  sentry watch on {0}: triage, baseline drift, canaries and Defender every {1}s.' -f $env:COMPUTERNAME, $IntervalSeconds)
    Write-Host  '  Read-only. It alerts on what is NEW. To FIX, in another elevated window:'
    Write-Host ('     powershell -ExecutionPolicy Bypass -File {0}' -f (Join-Path $PSScriptRoot 'fix.ps1')) -ForegroundColor White
    Write-Host  '  Do not click inside this window: a selection freezes it. Ctrl+C stops it.'
    Write-Host ''
    S "watch started interval=$IntervalSeconds"
    $seen = @{}
    $pass = 0
    while ($true) {
        $pass++
        $snap = Get-WatchSnapshot
        $stamp = (Get-Date).ToString('HH:mm:ss')
        $new = @($snap.Keys | Where-Object { -not $seen.ContainsKey($_) })
        $gone = @($seen.Keys | Where-Object { -not $snap.Contains($_) })
        $red = @($snap.Keys | Where-Object { $_ -like 'triage|RED|*' }).Count
        $drifts = @($snap.Keys | Where-Object { $_ -like 'drift|*' }).Count
        if ($pass -eq 1) {
            Write-Host ('  {0}  first look: {1} open item(s) - {2} RED, {3} baseline change(s)' -f $stamp, $snap.Count, $red, $drifts)
            foreach ($k in $snap.Keys) { Write-Host ('      {0}' -f $snap[$k]) -ForegroundColor Yellow }
            if ($snap.Count -gt 0) { Write-Host ('      (already there at start - these do not pop up. FIX: powershell -ExecutionPolicy Bypass -File {0})' -f (Join-Path $PSScriptRoot 'fix.ps1')) }
        } elseif ($new.Count -gt 0) {
            Write-Host ''
            Write-Host ('  ==== {0}  {1} NEW ====================================================' -f $stamp, $new.Count) -ForegroundColor Red
            foreach ($k in $new) { Write-Host ('      {0}' -f $snap[$k]) -ForegroundColor Red }
            Write-Host ('      FIX, in another elevated window:  powershell -ExecutionPolicy Bypass -File {0}' -f (Join-Path $PSScriptRoot 'fix.ps1')) -ForegroundColor Red
            Write-Host ''
            S ('watch NEW ' + (($new | ForEach-Object { $snap[$_] }) -join ' ;; '))
            try { [Console]::Beep(880, 300); [Console]::Beep(660, 300) } catch { }
            if (-not $NoPopup) {
                # msg.exe caps a message at 255 characters: keep the finding
                # short so the command to run next always fits.
                $first = ($snap[$new[0]] -replace '\s+', ' ').Trim()
                $fixCmd = 'powershell -ExecutionPolicy Bypass -File ' + (Join-Path $PSScriptRoot 'fix.ps1')
                # The fix command goes FIRST so msg.exe's 255-character cap can only cut the finding.
                $msg = ('CCDC {0} {1}: {2} NEW. FIX IT - elevated PowerShell: {3}  -- First: {4}' -f $env:COMPUTERNAME, $stamp, $new.Count, $fixCmd, $first)
                if ($msg.Length -gt 255) { $msg = $msg.Substring(0, 252) + '...' }
                try { & msg.exe * /TIME:300 $msg 2>&1 | Out-Null } catch { }
            }
        } else {
            Write-Host ('  {0}  quiet: nothing new ({1} RED, {2} baseline change(s) still open)' -f $stamp, $red, $drifts) -ForegroundColor DarkGray
        }
        foreach ($k in $gone) { Write-Host ('  {0}  resolved: {1}' -f $stamp, $seen[$k]) -ForegroundColor Green }
        $seen = @{}
        foreach ($k in $snap.Keys) { $seen[$k] = $snap[$k] }
        if ($Passes -gt 0 -and $pass -ge $Passes) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
    exit 0
}

# =============================================================================
# STATUS
# =============================================================================
if ($Status) {
    Assert-CcdcAdmin
    if (-not (Lock-Sentry)) { Write-CcdcDie "another sentry command is running; try again in a moment" }
    try {
        if (-not (Invoke-Triage)) { Write-CcdcDie "triage produced no findings file" }
        $q = Get-Queue
        # Freeze it. Approval reads this file, not a fresh scan, so the numbers
        # the operator is looking at cannot come to mean something else.
        Get-StateDir | Out-Null
        $tmp = "$($script:reviewedFile).tmp"
        $q | ForEach-Object { '{0}|{1}|{2}' -f $_.Severity, $_.Check, $_.Subject } |
            Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $script:reviewedFile -Force
    } finally { Unlock-Sentry }

    $facts = Get-CcdcBoxFacts
    Write-Host ''
    Write-Host ('sentry.ps1 - what is waiting for your sign-off on {0}' -f $facts['Host'])
    Write-Host ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))

    if (@($q).Count -eq 0) {
        Write-Host ''
        Write-Host '  Nothing waiting for your sign-off.'
        Write-Host ''
        Write-Host '  That is not the same as a clean box. It means nothing triage found'
        Write-Host '  has a fix safe enough to automate. Read the full report:'
        Write-Host ('     .\windows\triage.ps1 -Config {0}' -f $Config)
        Write-Host ''
        exit 0
    }

    $n = 0
    foreach ($i in $q) { $n++; Format-Item -N $n -Item $i }

    if (@($script:notOffered).Count -gt 0) {
        Write-Host ''
        Write-Host '  triage reported these, but there is nothing here to apply:'
        foreach ($r in $script:notOffered) { Write-Host ("    {0}" -f $r) }
    }

    $red   = @($q | Where-Object { $_.Tier -eq 'RED' }).Count
    $amber = @($q | Where-Object { $_.Tier -eq 'AMBER' }).Count
    Write-Host ''
    Write-Host ('  {0} item(s): {1} marked SWEEP, {2} marked LOOK.' -f @($q).Count, $red, $amber)
    Write-Host ''
    if ($red -gt 0) {
        Write-Host ('     .\windows\sentry.ps1 -Config {0} -Approve all -Apply' -f $Config) -ForegroundColor Green
        Write-Host '       applies the safe ones and hands the rest back by number'
    }
    Write-Host ('     .\windows\sentry.ps1 -Config {0} -Approve N -Apply' -f $Config)
    Write-Host '       applies exactly item N, whatever its colour'
    Write-Host ''
    Write-Host '  These numbers stay valid until the next -Status.'
    Write-Host ''
    exit 0
}

# =============================================================================
# APPROVE
# =============================================================================
if ($Approve) {
    Assert-CcdcAdmin
    Assert-CcdcPacketEntered -Config $cfg
    if (-not (Test-Path -LiteralPath $script:reviewedFile)) {
        Write-CcdcDie "no reviewed snapshot. Run -Status immediately before -Approve, so the numbers mean something."
    }
    $wanted = $null
    if ($Approve -ne 'all') {
        $parsed = 0
        if (-not [int]::TryParse($Approve, [ref]$parsed)) {
            Write-CcdcDie "-Approve takes a number or the word 'all', not '$Approve'"
        }
        $wanted = $parsed
    }

    if (-not (Lock-Sentry)) { Write-CcdcDie "another sentry command is running; try again in a moment" }
    $applied = 0; $skipped = 0; $failed = 0; $held = 0; $selected = 0
    try {
        $frozen = @(Get-Content -LiteralPath $script:reviewedFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -and $_ -match '\|' })
        # Re-scan. An item is applied only if the identity the operator approved
        # is STILL present and still automatable.
        if (-not (Invoke-Triage)) { Write-CcdcDie "fresh triage failed; nothing was applied" }
        $live = @(Get-Queue)

        $n = 0
        foreach ($line in $frozen) {
            $n++
            $f = $line -split '\|', 3
            if (@($f).Count -lt 3) { continue }
            $sev = $f[0]; $check = $f[1]; $subject = $f[2]
            if ($null -ne $wanted -and $n -ne $wanted) { continue }
            $selected++

            $item = $live | Where-Object { $_.Check -eq $check -and $_.Subject -eq $subject } | Select-Object -First 1
            $tier = if ($script:Actions.ContainsKey($check)) { $script:Actions[$check].Tier } else { 'AMBER' }
            $what = if ($script:Actions.ContainsKey($check)) { & $script:Actions[$check].What $subject } else { $check }

            Write-Host ''
            Write-Host ('  [{0}] {1,-6} {2,-14} {3}' -f $n, $sev, $check, $subject)
            Write-Host ('       WILL: {0}' -f $what)

            if ($null -eq $item) {
                Write-Host '       SKIPPED: no longer present, or now muted.' -ForegroundColor Yellow
                S "skipped stale check=$check subject=$subject"
                $skipped++; continue
            }
            # The safety property: a sweep never takes an AMBER.
            if ($null -eq $wanted -and $tier -ne 'RED') {
                Write-Host '       NOT APPLIED by a sweep: this may well be yours.' -ForegroundColor Yellow
                Write-Host ('       Look, then: .\windows\sentry.ps1 -Config {0} -Approve {1} -Apply' -f $Config, $n)
                $held++; continue
            }
            if (-not $Apply) {
                Write-Host '       [dry run] not executed. Add -Apply.' -ForegroundColor DarkGray
                continue
            }

            # The item number is in the label because New-CcdcEvidenceDir names
            # a directory by timestamp and PID: three fwlog approvals in the
            # same second shared one directory and each overwrote the previous
            # one's "before" state. Evidence you cannot tell apart is not
            # evidence.
            $ev = New-CcdcEvidenceDir -Label ("approve-{0:d3}-{1}" -f $n, $check)
            try {
                & $script:Actions[$check].Do $subject $ev
                Write-Host ('       done. evidence: {0}' -f $ev) -ForegroundColor Green
                ('{0}|{1}|{2}|{3}' -f (Get-Date).ToUniversalTime().ToString('u'), $check, $subject, $ev) |
                    Add-Content -LiteralPath $script:undoFile -Encoding UTF8
                S "applied check=$check subject=$subject evidence=$ev"
                $applied++
            } catch {
                Write-Host ('       FAILED: {0}' -f $_.Exception.Message) -ForegroundColor Red
                Write-Host ('       what was there first is in {0}' -f $ev)
                S "FAILED check=$check subject=$subject err=$($_.Exception.Message)"
                $failed++
            }
        }
        if ($selected -eq 0) {
            Write-CcdcDie "item $Approve is not in the reviewed snapshot; run -Status again"
        }
    } finally { Unlock-Sentry }

    Write-Host ''
    if (-not $Apply) {
        Write-Host '  DRY RUN. Nothing changed. Add -Apply to do it.' -ForegroundColor Yellow
    } else {
        Write-Host ('  {0} applied, {1} held for you, {2} skipped, {3} failed.' -f $applied, $held, $skipped, $failed)
    }
    if ($held -gt 0) {
        Write-Host ''
        Write-Host '  The held items are the ones worth two minutes of looking. An AMBER is'
        Write-Host '  usually a thing you did and have not written into the config yet.'
    }
    if ($applied -gt 0) {
        Write-Host ''
        Write-Host '  Check your scored services FROM ANOTHER MACHINE before moving on.'
        Write-Host ('  Then re-run: .\windows\sentry.ps1 -Config {0} -Status' -f $Config)
    }
    Write-Host ''
    exit 0
}

# =============================================================================
# MUTE / UNMUTE / MUTED / UNDO
# =============================================================================
if ($Mute -or $Unmute) {
    Assert-CcdcAdmin
    $key = if ($Mute) { $Mute } else { $Unmute }
    if ($key -notmatch '^[^|]+\|.+$') {
        Write-CcdcDie "-Mute takes 'check|subject', exactly as -Status prints them. Example: -Mute 'listener|tcp/8080'"
    }
    Get-StateDir | Out-Null
    $cur = @(Get-MuteKeys)
    if ($Mute) {
        if ($cur -contains $key) { Write-CcdcInfo "already muted: $key" }
        else {
            $key | Add-Content -LiteralPath $script:muteFile -Encoding UTF8
            Write-CcdcInfo "muted: $key"
            Write-Host '  It stays out of the queue until you unmute it. It is still in triage.'
            S "muted $key"
        }
    } else {
        $new = @($cur | Where-Object { $_ -ne $key })
        $new | Set-Content -LiteralPath $script:muteFile -Encoding UTF8
        Write-CcdcInfo "unmuted: $key"
        S "unmuted $key"
    }
    exit 0
}

if ($Muted) {
    $cur = @(Get-MuteKeys)
    Write-Host ''
    if (@($cur).Count -eq 0) { Write-Host '  nothing is muted.' }
    else {
        Write-Host ('  {0} muted finding(s) - these are hidden from the queue:' -f @($cur).Count)
        foreach ($m in $cur) { Write-Host ("    {0}" -f $m) }
        Write-Host ''
        Write-Host ('  unmute: .\windows\sentry.ps1 -Config {0} -Unmute ''check|subject''' -f $Config)
    }
    Write-Host ''
    exit 0
}

if ($Undo) {
    Write-Host ''
    if (-not (Test-Path -LiteralPath $script:undoFile)) {
        Write-Host '  nothing has been applied on this box.'
        Write-Host ''
        exit 0
    }
    Write-Host '  everything sentry has applied, newest last:'
    Write-Host ''
    foreach ($l in (Get-Content -LiteralPath $script:undoFile)) {
        $f = $l -split '\|', 4
        if (@($f).Count -lt 4) { continue }
        Write-Host ('    {0}  {1,-14} {2}' -f $f[0], $f[1], $f[2])
        Write-Host ('        what was there first: {0}' -f $f[3])
    }
    Write-Host ''
    Write-Host '  There is no automatic rollback. Each evidence directory holds the state'
    Write-Host '  before that one change, which is what you need to put it back by hand'
    Write-Host '  and what the incident report is written from.'
    Write-Host ''
    exit 0
}

Write-Host ''
Write-Host '  sentry.ps1 needs one of: -Status, -Approve N|all, -Mute, -Unmute, -Muted, -Undo'
Write-Host ''
Write-Host ('    .\windows\sentry.ps1 -Config {0} -Status' -f $Config)
Write-Host ''
exit 1
