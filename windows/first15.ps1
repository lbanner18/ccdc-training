<#
.SYNOPSIS
    The "Windows at a glance" flow from playbooks\windows-first-15-minutes.md,
    run in order. Read-only steps run on their own; every step that changes the
    box asks first.

.DESCRIPTION
    This only calls the kit's own tools in playbook order - it adds no logic of
    its own beyond asking the Quotient questions and editing the config for you.

      -Phase 1   lock the doors: config, passwords, recon, triage, harden, alex
      -Phase 2   go deep: down to 0 RED, arm, freeze the baseline, lookout window

    Do Phase 1 on EVERY box before Phase 2 on any. Ten minutes in, all three
    boxes should have new passwords and be hardened - not one perfect and two
    untouched.

    Getting the kit and Set-ExecutionPolicy stay manual (this file is in the kit).

.EXAMPLE
    .\windows\first15.ps1 -Phase 1
.EXAMPLE
    .\windows\first15.ps1 -Phase 2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('1','2')][string]$Phase
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$kitRoot = Split-Path -Parent $PSScriptRoot
$cfgDir  = Join-Path $env:ProgramData 'CCDC'
$cfgPath = Join-Path $cfgDir 'ccdc.env'

function Die([string]$m) { Write-Host ''; Write-Host "  STOP: $m" -ForegroundColor Red; Write-Host ''; exit 1 }

function Step([string]$n, [string]$title) {
    Write-Host ''
    Write-Host ('=' * 76) -ForegroundColor Cyan
    Write-Host ("  STEP {0}  {1}" -f $n, $title) -ForegroundColor Cyan
    Write-Host ('=' * 76) -ForegroundColor Cyan
}

function Ask([string]$q, [switch]$DefaultYes) {
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host ("  {0} {1}" -f $q, $suffix)
    if ([string]::IsNullOrWhiteSpace($a)) { return [bool]$DefaultYes }
    return ($a.Trim() -match '^(y|yes)$')
}

function Pause-ForRead([string]$what) {
    [void](Read-Host ("  {0} - press Enter to continue" -f $what))
}

function Run([string]$Script, [hashtable]$Params = @{}) {
    $path = Join-Path $PSScriptRoot ($Script + '.ps1')
    if (-not (Test-Path -LiteralPath $path)) { Die "missing kit file $path" }
    Write-Host ("  > .\windows\{0}.ps1 {1}" -f $Script, (($Params.Keys | ForEach-Object {
        if ($Params[$_] -is [bool] -or $Params[$_] -is [switch]) { "-$_" } else { "-$_ $($Params[$_])" }
    }) -join ' ')) -ForegroundColor DarkGray
    & $path @Params
}

# KEY="a b c" lines only; tokens are appended if absent. Written without a BOM,
# exactly as the kit's config files are.
function Add-ConfigToken([string]$Key, [string[]]$Tokens) {
    $lines = @(Get-Content -LiteralPath $cfgPath)
    $found = $false
    $added = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ('^' + $Key + '="([^"]*)"(.*)$')) {
            $found = $true
            $tail = $Matches[2]
            $vals = @($Matches[1] -split '\s+' | Where-Object { $_ })
            foreach ($t in $Tokens) { if ($vals -notcontains $t) { $vals += $t; $added += $t } }
            $lines[$i] = '{0}="{1}"{2}' -f $Key, ($vals -join ' '), $tail
        }
    }
    if (-not $found) { Die "no $Key line in $cfgPath - edit it by hand in notepad" }
    if (@($added).Count -eq 0) { Write-Host ("  {0} already has {1}" -f $Key, ($Tokens -join ' ')); return }
    [IO.File]::WriteAllLines($cfgPath, [string[]]$lines)
    Write-Host ("  added {0} to {1}" -f ($added -join ' '), $Key) -ForegroundColor Green
}

# --- preflight -------------------------------------------------------------------
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Die @"
this is 32-bit PowerShell. The Defender, local-account and server-feature tools
  are invisible from here, and some registry changes land where Windows never reads
  them. Close this window and open Start -> "Windows PowerShell" (NOT the x86 one)
  with Ctrl+Shift+Enter.
"@
}
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "not elevated. Start -> type 'powershell' -> Ctrl+Shift+Enter, then run this again."
}
$isDc = $false
try { $isDc = ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4) } catch { }

Write-Host ''
Write-Host ("  first15 Phase {0} on {1}{2}" -f $Phase, $env:COMPUTERNAME, $(if ($isDc) { ' (domain controller)' } else { '' })) -ForegroundColor White
Write-Host  '  Steps that change the box ask first. Ctrl+C stops at any point; re-running is safe.'

# =============================================================================
if ($Phase -eq '1') {

    Step '1 of 6' 'the config, and what Quotient says is scored HERE'
    if (-not (Test-Path -LiteralPath $cfgPath)) {
        New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $kitRoot 'config\tryout-windows.env') -Destination $cfgPath
        Write-Host "  copied config\tryout-windows.env -> $cfgPath" -ForegroundColor Green
    } else {
        Write-Host "  using the existing $cfgPath"
    }
    Write-Host '  Look at Quotient''s service list for THIS box (AD/DNS are already in the config).'
    if (Ask 'Is HTTP scored on this box?') {
        Add-ConfigToken -Key 'CCDC_WINDOWS_SERVICES' -Tokens @('W3SVC')
        Add-ConfigToken -Key 'CCDC_ALLOWED_TCP_PORTS' -Tokens @('80')
    }
    if (Ask 'Is FTP scored on this box?') {
        Add-ConfigToken -Key 'CCDC_WINDOWS_SERVICES' -Tokens @('FTPSVC')
        Add-ConfigToken -Key 'CCDC_ALLOWED_TCP_PORTS' -Tokens @('21')
    }
    Write-Host "  Anything ELSE Quotient scores here: add its service and port to $cfgPath in notepad." -ForegroundColor Yellow

    Step '2 of 6' 'every default password (block 1 of the sheet)'
    if (Ask 'Change every default password now?' -DefaultYes) {
        Run 'passwords' @{ Config = $cfgPath; Apply = $true }
        Write-Host ''
        Write-Host '  Now the built-in Administrator (sheet section 4). Type it twice:' -ForegroundColor Yellow
        & net.exe user Administrator *
        Write-Host ''
        Write-Host '  Quotient -> Password Change Request: paste block 1. Until then the scorer' -ForegroundColor Yellow
        Write-Host '  uses the old passwords and every check fails.' -ForegroundColor Yellow
        Pause-ForRead 'Submitted the PCR (or will right after this)'
    }

    Step '3 of 6' 'the "before" picture (read-only)'
    Run 'recon' @{ Config = $cfgPath }
    Pause-ForRead 'Copy the zip off the box with the line printed above'

    Step '4 of 6' 'what is wrong right now (read-only) - scoreduser / scoredservice first'
    Run 'triage' @{ Config = $cfgPath }
    Pause-ForRead 'Read the REDs. Fix a scoreduser/scoredservice RED before hardening'

    Step '5 of 6' 'the hardening checklist - dry run first'
    Run 'harden' @{ Config = $cfgPath }
    if (Ask 'Apply the changes listed above?') {
        Run 'harden' @{ Config = $cfgPath; Apply = $true }
    } else {
        Write-Host '  skipped. Later: .\windows\harden.ps1 -Apply' -ForegroundColor Yellow
    }

    Step '6 of 6' 'backup admin: alex (in the packet - no new account)'
    $alexUser = (& net.exe user alex 2>&1 | Out-String)
    $group = if ($isDc) { & net.exe group 'Domain Admins' /domain 2>&1 } else { & net.exe localgroup Administrators 2>&1 }
    $inAdmins = (($group | Out-String) -match '(?im)(^|\s)alex(\s|$)')
    if ($alexUser -notmatch 'User name') {
        Write-Host '  alex does not exist on this box. The packet says it should - look before you fix.' -ForegroundColor Red
    } else {
        if ($alexUser -match 'Account active\s+Yes') { Write-Host '  alex is enabled' -ForegroundColor Green }
        else { Write-Host '  alex is DISABLED. It is a packet admin: net user alex /active:yes' -ForegroundColor Red }
        if ($inAdmins) { Write-Host ('  alex is in {0}' -f $(if ($isDc) { 'Domain Admins' } else { 'Administrators' })) -ForegroundColor Green }
        else { Write-Host ('  alex is NOT in {0}. The packet lists it as an administrator - check before you rely on it.' -f $(if ($isDc) { 'Domain Admins' } else { 'Administrators' })) -ForegroundColor Red }
        Write-Host '  Its password is the one from block 1. Keep that line of the sheet in front of you.'
    }

    Write-Host ''
    Write-Host ('  Phase 1 done on {0}.' -f $env:COMPUTERNAME) -ForegroundColor Green
    Write-Host '  Next: Phase 1 on the other boxes. Then come back and run:'
    Write-Host '     .\windows\first15.ps1 -Phase 2'
    Write-Host ''
    exit 0
}

# =============================================================================
Step '1 of 4' 'down to 0 RED'
Run 'triage' @{ Config = $cfgPath }
Run 'sentry' @{ Config = $cfgPath; Status = $true }
if (Ask 'Apply every automatic fix (sentry -Approve all)?') {
    Run 'sentry' @{ Config = $cfgPath; Approve = 'all'; Apply = $true }
}
while ($true) {
    $n = Read-Host '  Approve a held item you have READ - its number, or Enter to move on'
    if ([string]::IsNullOrWhiteSpace($n)) { break }
    if ($n.Trim() -notmatch '^\d+$') { Write-Host '  a number, or Enter'; continue }
    Run 'sentry' @{ Config = $cfgPath; Approve = $n.Trim(); Apply = $true }
}

Step '2 of 4' 'canaries and the self-repairing tasks'
if (Ask 'Arm them (arm.ps1 -Apply)?' -DefaultYes) {
    Run 'arm' @{ Config = $cfgPath; Apply = $true }
}

Step '3 of 4' 'freeze the clean box'
Write-Host '  Only bless a box you have looked at: 0 RED, and every AMBER yours or muted.' -ForegroundColor Yellow
if (Ask 'Bless the baseline now?') {
    Run 'baseline' @{ Config = $cfgPath; Bless = $true; StableForSeconds = 20; Apply = $true }
} else {
    Write-Host '  later: .\windows\baseline.ps1 -Bless -StableForSeconds 20 -Apply' -ForegroundColor Yellow
}

Step '4 of 4' 'the lookout, in a second window'
if (Ask 'Open the sentry -Watch window now?' -DefaultYes) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -WorkingDirectory $kitRoot `
        -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'sentry.ps1'), '-Config', $cfgPath, '-Watch')
    Write-Host '  opened. Do not click inside it - a selection freezes it.' -ForegroundColor Green
} else {
    Write-Host ("  later, in a second elevated window:  cd {0}; Set-ExecutionPolicy -Scope Process Bypass -Force; .\windows\sentry.ps1 -Watch" -f $kitRoot)
}

Write-Host ''
Write-Host ('  Phase 2 done on {0}. From here it is the loop section of the playbook, driven by the popups.' -f $env:COMPUTERNAME) -ForegroundColor Green
Write-Host ''
exit 0
