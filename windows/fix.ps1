<#
.SYNOPSIS
    The one command for the rest of the day: what is wrong on this box, numbered,
    and the fix for whatever you pick.

.DESCRIPTION
    Run it whenever a CCDC popup appears or you come back to this box, from any
    elevated PowerShell:

        powershell -ExecutionPolicy Bypass -File C:\ccdc-training-main\windows\fix.ps1

    -WrongOnly skips part 2 (what changed since the freeze); the runner uses it.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$WrongOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$cfgPath = if ($Config) { $Config } else { Join-Path $env:ProgramData 'CCDC\ccdc.env' }
$self    = Join-Path $PSScriptRoot 'fix.ps1'
$again   = "powershell -ExecutionPolicy Bypass -File $self"

function Hdr([string]$t) {
    Write-Host ''
    Write-Host ('=' * 76) -ForegroundColor Cyan
    Write-Host ("  {0}" -f $t) -ForegroundColor Cyan
    Write-Host ('=' * 76) -ForegroundColor Cyan
}
function Run([string]$Script, [hashtable]$Params) {
    $Params['Config'] = $cfgPath
    Write-Host ("  > {0}.ps1 {1}" -f $Script, (($Params.Keys | Where-Object { $_ -ne 'Config' } | ForEach-Object {
        if ($Params[$_] -is [bool]) { "-$_" } else { "-$_ $($Params[$_])" } }) -join ' ')) -ForegroundColor DarkGray
    & (Join-Path $PSScriptRoot ($Script + '.ps1')) @Params
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host ''
    Write-Host '  Needs an ELEVATED PowerShell: Start -> type powershell -> Ctrl+Shift+Enter, then:' -ForegroundColor Red
    Write-Host "     $again"
    Write-Host ''
    exit 1
}
if (-not (Test-Path -LiteralPath $cfgPath)) {
    Write-Host ''
    Write-Host "  No $cfgPath - run Phase 1 first:  $(Join-Path $PSScriptRoot 'first15.ps1') -Phase 1" -ForegroundColor Red
    Write-Host ''
    exit 1
}

# ---- part 1: what is wrong right now -----------------------------------------
Hdr '1 of 2  WHAT IS WRONG - fix by number'
Run 'sentry' @{ Status = $true }
while ($true) {
    Write-Host ''
    $a = Read-Host '  a = fix everything marked safe   NUMBER = fix that one (read a LOOK item first)   r = re-list   Enter = next'
    $a = ([string]$a).Trim()
    if ($a -eq '') { break }
    elseif ($a -match '^[rR]$') { Run 'sentry' @{ Status = $true } }
    elseif ($a -match '^[aA]$') { Run 'sentry' @{ Approve = 'all'; Apply = $true } }
    elseif ($a -match '^\d+$')  { Run 'sentry' @{ Approve = $a; Apply = $true } }
    else { Write-Host '  type a, a number, r, or just Enter' -ForegroundColor Yellow }
}

# ---- part 2: what changed since the box was frozen ---------------------------
$blessed = Join-Path $env:ProgramData 'CCDC\state\baseline.json'
if ($WrongOnly) {
} elseif (-not (Test-Path -LiteralPath $blessed)) {
    Write-Host ''
    Write-Host '  (part 2 - what changed since the freeze - starts once you bless the baseline in Phase 2)' -ForegroundColor Yellow
} else {
    Hdr '2 of 2  WHAT CHANGED since you froze this box'
    Run 'baseline' @{ Status = $true }
    while ($true) {
        Write-Host ''
        $a = Read-Host '  NUMBER = what it is and its exact fix   r = re-list   Enter = done'
        $a = ([string]$a).Trim()
        if ($a -eq '') { break }
        elseif ($a -match '^[rR]$') { Run 'baseline' @{ Status = $true } }
        elseif ($a -match '^\d+$') {
            Run 'baseline' @{ Explain = [int]$a }
            Write-Host ''
            Write-Host '  NOT yours -> copy its "if this is NOT yours" lines into your SECOND elevated window.' -ForegroundColor Yellow
            Write-Host '  Yours     -> copy its -Allow line there instead, with a real reason.' -ForegroundColor Yellow
        }
        else { Write-Host '  type a number, r, or just Enter' -ForegroundColor Yellow }
    }
}

Write-Host ''
Write-Host '  Run this again any time - a popup, or you come back to this box:' -ForegroundColor Green
Write-Host "     $again" -ForegroundColor White
Write-Host ''
exit 0
