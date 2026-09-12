param(
    [string]$OutputDir = "C:\ProgramData\CCDC\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$dir = Join-Path $OutputDir "windows-$stamp"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

function Save-Command {
    param([string]$Name, [scriptblock]$Command)
    try { & $Command 2>&1 | Out-File -FilePath (Join-Path $dir "$Name.txt") -Encoding utf8 }
    catch { $_ | Out-File -FilePath (Join-Path $dir "$Name.txt") -Encoding utf8 }
}

Save-Command 'system' { Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture,WindowsInstallDateFromRegistry }
Save-Command 'accounts' { Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,UserMayChangePassword }
Save-Command 'administrators' { Get-LocalGroupMember -Group Administrators }
Save-Command 'firewall' { Get-NetFirewallProfile; Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object DisplayName,Direction,Action,Profile }
Save-Command 'listening' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess; Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess }
Save-Command 'services' { Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName }
Save-Command 'scheduled-tasks' { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,Actions,Triggers }
Save-Command 'startup' { Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User }
Save-Command 'recent-events' { Get-WinEvent -LogName Security -MaxEvents 250 | Where-Object Id -in 4624,4625,4720,4732,7045,4698,1102 | Select-Object TimeCreated,Id,ProviderName,Message }

Get-ChildItem -File $dir | Get-FileHash -Algorithm SHA256 | Export-Csv (Join-Path $dir 'SHA256SUMS.csv') -NoTypeInformation
Write-Host "Windows recon evidence saved to $dir"
