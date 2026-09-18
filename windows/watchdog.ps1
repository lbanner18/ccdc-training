<#
.SYNOPSIS
    Keep the scored services running while you do something else.

.DESCRIPTION
    Half your points are injects. You cannot watch a service list and write an
    inject response at the same time, and the service list is the half a
    computer can do.

    This checks every scored service on an interval, starts anything that has
    stopped, and writes a line every time it had to - so afterwards you can say
    "it was restarted four times between 11:20 and 11:50", which is an incident
    report rather than a feeling.

    It does NOT hide the problem. A service that keeps stopping is a finding;
    the log is there so you notice the pattern.

    -Install registers it as a scheduled task running as SYSTEM, so it survives
    you logging out and starts again after a reboot.

    IT CANNOT SEE WHAT THE SCORING ENGINE SEES. A service can be Running while
    the port is firewalled off. It checks the TCP and HTTP checks from your
    config too, but all of that is from ON the box. Verify from somewhere else.

.EXAMPLE
    .\watchdog.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Once
    One pass, right now, so you can see what it would do.

.EXAMPLE
    .\watchdog.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Install
    Register it as a SYSTEM scheduled task and start it.

.EXAMPLE
    .\watchdog.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Uninstall
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [int]$IntervalSeconds = 30,
    [switch]$Once,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [string]$TaskName = 'CCDC-Watchdog'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
Initialize-CcdcRoot
$logName = 'watchdog.log'

function W { param([string]$m) Write-CcdcLog -Message $m -LogName $logName }

# --- install / uninstall -----------------------------------------------------

if ($Install) {
    Assert-CcdcAdmin
    Assert-CcdcPacketEntered -Config $cfg
    $me = $MyInvocation.MyCommand.Path
    $argline = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Config "{1}" -IntervalSeconds {2}' -f `
               $me, (Resolve-Path -LiteralPath $Config).Path, $IntervalSeconds
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argline
    # At startup AND now: at startup so it survives a reboot, now so you do not
    # have to reboot to get the protection you just asked for.
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description 'CCDC scored-service keep-alive' | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Write-CcdcInfo "installed and started scheduled task '$TaskName' (runs as SYSTEM, restarts at boot)"
        Write-Host ''
        Write-Host ('  log:     {0}' -f (Get-CcdcPath $logName))
        Write-Host ('  status:  .\windows\watchdog.ps1 -Config {0} -Status' -f $Config)
        Write-Host ('  stop it: .\windows\watchdog.ps1 -Config {0} -Uninstall' -f $Config)
        Write-Host ''
        Write-Host '  Your terminal is free. Go do an inject.'
    } catch {
        Write-CcdcDie "could not register the task: $($_.Exception.Message)"
    }
    exit 0
}

if ($Uninstall) {
    Assert-CcdcAdmin
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-CcdcInfo "removed scheduled task '$TaskName'. The log is kept: $(Get-CcdcPath $logName)"
    } catch { Write-CcdcWarn "could not remove '$TaskName': $($_.Exception.Message)" }
    exit 0
}

if ($Status) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $t) {
        Write-Host ('  NOT INSTALLED. Nothing is watching your scored services.')
        Write-Host ('      .\windows\watchdog.ps1 -Config {0} -Install' -f $Config)
    } else {
        $i = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host ('  task {0}: {1}' -f $TaskName, $t.State)
        if ($i) { Write-Host ('  last run {0}, result {1}' -f $i.LastRunTime, $i.LastTaskResult) }
    }
    $log = Get-CcdcPath $logName
    if (Test-Path -LiteralPath $log) {
        Write-Host ''
        Write-Host '  the last 15 things it did:'
        Get-Content -LiteralPath $log -Tail 15 | ForEach-Object { Write-Host ("    {0}" -f $_) }
        # A restart is not a success story. Surface the count so a service that
        # keeps dying reads as a finding rather than as the watchdog working.
        $restarts = @(Get-Content -LiteralPath $log | Where-Object { $_ -match 'RESTARTED' })
        if (@($restarts).Count -gt 0) {
            Write-Host ''
            Write-Host ('  {0} restart(s) so far. That is not the watchdog working - it is' -f @($restarts).Count) -ForegroundColor Yellow
            Write-Host  '  something stopping your scored service repeatedly. Find out what:' -ForegroundColor Yellow
            Write-Host ('      .\windows\triage.ps1 -Config {0}' -f $Config)
            Write-Host  '      Get-WinEvent -LogName System -MaxEvents 60 | Where-Object Id -in 7034,7031,7036,7045'
        }
    }
    exit 0
}

# --- the loop ----------------------------------------------------------------

Assert-CcdcPacketEntered -Config $cfg
$services = Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_SERVICES'
$users    = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS'

function Invoke-Pass {
    foreach ($name in $services) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $s) { W "MISSING service=$name (named in the packet, not installed here)"; continue }
        if ($s.Status -eq 'Running') { continue }

        W "DOWN service=$name status=$($s.Status)"
        # Disabled, then stopped, is somebody's deliberate work - starting it
        # without re-enabling it just means it is stopped again on reboot.
        try {
            $wmi = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            if ($wmi.StartMode -eq 'Disabled') {
                W "DISABLED service=$name - somebody set start mode to Disabled; re-enabling"
                Set-Service -Name $name -StartupType Automatic -ErrorAction Stop
            }
        } catch { }
        try {
            Start-Service -Name $name -ErrorAction Stop
            W "RESTARTED service=$name"
        } catch {
            W "FAILED-TO-START service=$name err=$($_.Exception.Message)"
        }
    }

    # A scored ACCOUNT that has been disabled costs exactly what a stopped
    # service costs, and nothing else on this box is watching for it.
    foreach ($u in $users) {
        if ($u -eq 'SYSTEM') { continue }
        try {
            $lu = Get-LocalUser -Name $u -ErrorAction Stop
            if (-not $lu.Enabled) {
                W "SCORED-ACCOUNT-DISABLED user=$u - re-enabling"
                try { Enable-LocalUser -Name $u -ErrorAction Stop; W "RE-ENABLED user=$u" }
                catch { W "FAILED-TO-ENABLE user=$u err=$($_.Exception.Message)" }
            }
        } catch { }   # not a local account here; that is normal on a domain member
    }

    # The checks that say whether it is actually serving, rather than merely
    # running. Reported, never acted on: what to do about a port that stopped
    # answering depends entirely on why.
    foreach ($c in (Get-CcdcTcpChecks -Config $cfg)) {
        if (-not (Test-CcdcTcpPort -ComputerName $c.Host -Port $c.Port)) {
            W "TCP-CHECK-FAILED $($c.Host):$($c.Port) - the service may be running and unreachable (firewall? bind address?)"
        }
    }
    foreach ($u in (Get-CcdcHttpChecks -Config $cfg)) {
        try {
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($r.StatusCode -ge 400) { W "HTTP-CHECK-FAILED $u status=$($r.StatusCode)" }
        } catch {
            W "HTTP-CHECK-FAILED $u err=$($_.Exception.Message)"
        }
    }
}

if ($Once) {
    Invoke-Pass
    Write-Host ('  one pass done. Log: {0}' -f (Get-CcdcPath $logName))
    Get-Content -LiteralPath (Get-CcdcPath $logName) -Tail 10 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("    {0}" -f $_) }
    exit 0
}

W "watchdog started interval=${IntervalSeconds}s services=$($services -join ',')"
while ($true) {
    Invoke-Pass
    Start-Sleep -Seconds $IntervalSeconds
}
