param(
    [string[]]$Services = @(),
    [int]$IntervalSeconds = 60,
    [switch]$Once,
    [switch]$Apply,
    [string]$LogPath = "C:\ProgramData\CCDC\watchdog.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logDir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
function Log($Message) {
    "{0:u} {1}" -f (Get-Date).ToUniversalTime(), $Message | Add-Content -Path $LogPath
}
function Check {
    foreach ($serviceName in $Services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) { Log "service_missing name=$serviceName"; continue }
        if ($service.Status -eq 'Running') { Log "service_ok name=$serviceName"; continue }
        Log "service_unhealthy name=$serviceName"
        if ($Apply) {
            Start-Service -Name $serviceName
            Log "service_started name=$serviceName"
        } else {
            Log "dry_run would_start name=$serviceName"
        }
    }
}
do {
    Check
    if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
} while (-not $Once)
