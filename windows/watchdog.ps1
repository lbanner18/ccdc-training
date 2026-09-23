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
    report rather than a feeling. Once canary.ps1 has laid tripwires, it also
    runs its read-only -Check on every pass and records a trip in this log.

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
    [string]$Config = '',
    [int]$IntervalSeconds = 30,
    [switch]$Once,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [string]$TaskName = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
Initialize-CcdcRoot
$TaskName = if ([string]::IsNullOrWhiteSpace($TaskName)) {
    Get-CcdcTaskName -Config $cfg -Name 'CCDC_WINDOWS_WATCHDOG_TASK' -Default 'Operations-Monitor'
} else {
    Get-CcdcTaskName -Config @{ Override = $TaskName } -Name 'Override' -Default $TaskName
}
$canaryLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_CANARY_FILE' -Default 'integrity-check.ps1' -PowerShellFile
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
        # Unregistering does not reliably stop an instance that is already
        # running. Stop it first or every re-install can leave another loop.
        $old = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($old -and $old.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            Start-Sleep -Milliseconds 250
        }
        if ($old) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description 'CCDC scored-service and canary keep-alive' | Out-Null
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
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            Start-Sleep -Milliseconds 250
        }
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

        $canaryTrips = @(Get-Content -LiteralPath $log | Where-Object { $_ -match 'CANARY-TRIPPED' })
        if (@($canaryTrips).Count -gt 0) {
            Write-Host ''
            Write-Host ('  {0} canary trip report(s) so far. A trip is not a maybe:' -f @($canaryTrips).Count) -ForegroundColor Red
            Write-Host ('      .\windows\canary.ps1 -Config {0} -Check' -f $Config)
            Write-Host ('      Get-Content -LiteralPath {0} -Tail 30' -f (Get-CcdcPath 'canary.log'))
        }
    }
    $canaryManifest = Get-CcdcPath 'state\canaries.txt'
    if (-not (Test-Path -LiteralPath $canaryManifest)) {
        Write-Host ''
        Write-Host '  Canaries are not laid, so there is nothing for this task to check.' -ForegroundColor Yellow
        Write-Host ('      .\windows\canary.ps1 -Config {0} -Deploy -Apply' -f $Config)
    }
    exit 0
}

# --- the loop ----------------------------------------------------------------

Assert-CcdcPacketEntered -Config $cfg
$services = Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_SERVICES'
$users    = Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_USERS'

function Invoke-CanaryCheck {
    # canary.ps1 deliberately exits 2 on a trip. Run it in a child PowerShell:
    # invoking that script directly would make its exit end this watchdog too.
    # No manifest means -Deploy has not happened yet, which is normal while the
    # operator is still stabilising the box. The next pass picks it up on its own.
    $manifest = Get-CcdcPath 'state\canaries.txt'
    if (-not (Test-Path -LiteralPath $manifest)) { return }

    $canary = Join-Path $PSScriptRoot $canaryLeaf
    # In the checkout the source keeps its useful descriptive filename. The
    # guardian's private copy uses the configured runtime filename instead.
    if (-not (Test-Path -LiteralPath $canary -PathType Leaf) -and $canaryLeaf -ne 'canary.ps1') {
        $canary = Join-Path $PSScriptRoot 'canary.ps1'
    }
    if (-not (Test-Path -LiteralPath $canary -PathType Leaf)) {
        W "CANARY-CHECK-FAILED missing=$canary"
        return
    }

    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $canary -Config $Config -Check 2>&1 | Out-Null
        $canaryExit = $LASTEXITCODE
    } catch {
        W "CANARY-CHECK-FAILED err=$($_.Exception.Message)"
        return
    }

    if ($canaryExit -eq 0) { return }
    if ($canaryExit -eq 2) {
        W "CANARY-TRIPPED see $(Get-CcdcPath 'canary.log') and run canary.ps1 -Check"
        return
    }
    W "CANARY-CHECK-FAILED exit=$canaryExit (see $(Get-CcdcPath 'canary.log'))"
}

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

    Invoke-CanaryCheck
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
