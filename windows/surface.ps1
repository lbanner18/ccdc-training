<#
.SYNOPSIS
    Print the Windows execution and network surface, joined to the packet.

.DESCRIPTION
    A port list is not an inject response. The useful question is: what owns
    this listener, what launches it, and does the packet say it belongs here?
    This joins listeners to processes and services, then lists the common
    logon/startup mechanisms: scheduled tasks, Run-family keys, Startup
    folders, Winlogon, AppInit DLLs, IFEO debuggers, Active Setup, and permanent
    WMI event subscriptions. An operator can additionally configure a specific,
    verified Sysinternals Autorunsc binary for wider read-only evidence; without
    it, the GAP printed below names the locations this does not enumerate.

    It is read-only. REVIEW means the packet does not account for the row; it
    is a decision to make, not a removal instruction.

.EXAMPLE
    .\surface.ps1 -Config C:\ProgramData\CCDC\ccdc.env
.EXAMPLE
    .\surface.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Table
    Markdown ready to paste into a network/unnecessary-software inject.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Table
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']
$facts = Get-CcdcBoxFacts
$scoredServices = @(Get-CcdcList -Config $cfg -Name 'CCDC_WINDOWS_SERVICES')
$tcpAllowed = @(Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_TCP_PORTS')
# Same rule as triage and harden: scored RDP is accounted for unless the config says "0".
if ((Get-CcdcValue -Config $cfg -Name 'CCDC_RDP_SCORED') -ne '0') { $tcpAllowed += '3389' }
$udpAllowed = @(Get-CcdcList -Config $cfg -Name 'CCDC_ALLOWED_UDP_PORTS')
$surfaceGaps = New-Object System.Collections.ArrayList
if (-not $facts['HasNetTCPIP']) {
    [void]$surfaceGaps.Add('no NetTCPIP module: listener ownership cannot be collected on this box')
}
if (-not $facts['HasScheduledTasks']) {
    [void]$surfaceGaps.Add('no ScheduledTasks module: scheduled-task autostarts cannot be collected on this box')
}

function Short {
    param([AllowNull()][string]$Value, [int]$Length = 72)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '-' }
    $oneLine = ($Value -replace "`r?`n", ' ').Trim()
    if ($oneLine.Length -le $Length) { return $oneLine }
    return ($oneLine.Substring(0, $Length - 1) + [char]0x2026)
}

function Format-MarkdownCell {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '-' }
    return (($Value -replace "`r?`n", ' ' -replace '\|', '\|').Trim())
}

function Is-Loopback {
    param([string]$Address)
    return ($Address -eq '127.0.0.1' -or $Address -eq '::1' -or $Address -eq 'localhost')
}

function Verdict-ForPort {
    param([string]$Protocol, [int]$Port, [string]$Address)
    if (Is-Loopback $Address) { return 'local only' }
    $allowed = if ($Protocol -eq 'TCP') { $tcpAllowed } else { $udpAllowed }
    if (Test-CcdcListContains -Needle ([string]$Port) -List $allowed) { return 'yes - scored' }
    # High UDP ports are often client sockets. They still deserve a row, but
    # calling every resolver/NTP source port a server makes the decision list
    # unusable and changes on every run.
    if ($Protocol -eq 'UDP' -and $Port -ge 49152) { return 'client socket' }
    return 'REVIEW'
}

function Get-ProcessMap {
    $out = @{}
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $path = ''
            $cmd = ''
            if ($p.PSObject.Properties.Name -contains 'ExecutablePath') { $path = [string]$p.ExecutablePath }
            if ($p.PSObject.Properties.Name -contains 'CommandLine') { $cmd = [string]$p.CommandLine }
            $out[[int]$p.ProcessId] = [pscustomobject]@{ Path = $path; CommandLine = $cmd; Name = $p.Name }
        }
    } catch { }
    return $out
}

function Get-ServiceMap {
    $out = @{}
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            if ($s.ProcessId -and [int]$s.ProcessId -gt 0) {
                $out[[int]$s.ProcessId] = $s.Name
            }
        }
    } catch { }
    return $out
}

function Get-ListenerRows {
    param([hashtable]$Processes, [hashtable]$Services)
    $rows = New-Object System.Collections.ArrayList
    $sets = @(
        @{ Protocol = 'TCP'; Items = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) },
        @{ Protocol = 'UDP'; Items = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue) }
    )
    foreach ($set in $sets) {
        foreach ($e in $set.Items) {
            $ownerPid = [int]$e.OwningProcess
            $process = $null
            if ($Processes.ContainsKey($ownerPid)) { $process = $Processes[$ownerPid] }
            $service = if ($Services.ContainsKey($ownerPid)) { [string]$Services[$ownerPid] } else { '-' }
            $target = if ($process -and $process.Path) { $process.Path } elseif ($process) { $process.Name } else { '? (need admin)' }
            [void]$rows.Add([pscustomobject]@{
                Protocol = $set.Protocol; Address = [string]$e.LocalAddress; Port = [int]$e.LocalPort
                PID = $ownerPid; Process = (Short $target); Service = $service
                Needed = (Verdict-ForPort -Protocol $set.Protocol -Port ([int]$e.LocalPort) -Address ([string]$e.LocalAddress))
            })
        }
    }
    return @($rows | Sort-Object Protocol, Port, Address)
}

function Get-ServiceRows {
    $rows = New-Object System.Collections.ArrayList
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop | Sort-Object Name)) {
            $verdict = if (Test-CcdcListContains -Needle $s.Name -List $scoredServices) { 'yes - scored' } else { 'REVIEW' }
            [void]$rows.Add([pscustomobject]@{
                Name = $s.Name; State = $s.State; Start = $s.StartMode; Account = $s.StartName
                Image = (Short $s.PathName); Needed = $verdict
            })
        }
    } catch { }
    return @($rows)
}

function Get-AutostartRows {
    $rows = New-Object System.Collections.ArrayList
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            $action = (@($t.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' ; ')
            [void]$rows.Add([pscustomobject]@{
                Type = 'task'; Name = ('{0}{1}' -f $t.TaskPath, $t.TaskName)
                Command = (Short $action); State = [string]$t.State; Verdict = 'REVIEW'
            })
        }
    } catch { }

    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
        try {
            $item = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            foreach ($prop in @($item.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })) {
                [void]$rows.Add([pscustomobject]@{
                    Type = 'Run key'; Name = ('{0}\{1}' -f $key, $prop.Name)
                    Command = (Short ([string]$prop.Value)); State = 'at logon'; Verdict = 'REVIEW'
                })
            }
        } catch { }
    }

    # These are not ordinary Run values, but all cause a process or DLL to be
    # loaded at logon. Do not try to decide whether a stock shell extension is
    # good here; preserve the exact value and make the packet decision.
    try {
        $winlogon = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        foreach ($name in @('Shell', 'Userinit')) {
            if ($winlogon.PSObject.Properties.Name -contains $name) {
                [void]$rows.Add([pscustomobject]@{
                    Type = 'Winlogon'; Name = ('Winlogon\\{0}' -f $name)
                    Command = (Short ([string]$winlogon.$name)); State = 'at interactive logon'; Verdict = 'REVIEW'
                })
            }
        }
    } catch { }

    try {
        $appInit = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction Stop
        $dlls = if ($appInit.PSObject.Properties.Name -contains 'AppInit_DLLs') { [string]$appInit.AppInit_DLLs } else { '' }
        $enabled = if ($appInit.PSObject.Properties.Name -contains 'LoadAppInit_DLLs') { [string]$appInit.LoadAppInit_DLLs } else { '?' }
        if (-not [string]::IsNullOrWhiteSpace($dlls) -or $enabled -eq '1') {
            [void]$rows.Add([pscustomobject]@{
                Type = 'AppInit DLL'; Name = 'HKLM:\...\Windows\AppInit_DLLs'
                Command = (Short $dlls); State = ('LoadAppInit_DLLs={0}' -f $enabled); Verdict = 'REVIEW'
            })
        }
    } catch { }

    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $debug = Get-ItemProperty -LiteralPath $child.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue
                if ($debug -and ($debug.PSObject.Properties.Name -contains 'Debugger') -and -not [string]::IsNullOrWhiteSpace([string]$debug.Debugger)) {
                    [void]$rows.Add([pscustomobject]@{
                        Type = 'IFEO debugger'; Name = $child.PSChildName
                        Command = (Short ([string]$debug.Debugger)); State = 'when target starts'; Verdict = 'REVIEW'
                    })
                }
            }
        } catch { }
    }

    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                         'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
        try {
            foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $stub = Get-ItemProperty -LiteralPath $child.PSPath -Name 'StubPath' -ErrorAction SilentlyContinue
                if ($stub -and ($stub.PSObject.Properties.Name -contains 'StubPath') -and -not [string]::IsNullOrWhiteSpace([string]$stub.StubPath)) {
                    [void]$rows.Add([pscustomobject]@{
                        Type = 'Active Setup'; Name = $child.PSChildName
                        Command = (Short ([string]$stub.StubPath)); State = 'first user logon'; Verdict = 'REVIEW'
                    })
                }
            }
        } catch { }
    }

    $startupFolders = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')
    try {
        foreach ($profile in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })) {
            if (-not [string]::IsNullOrWhiteSpace([string]$profile.LocalPath)) {
                $startupFolders += (Join-Path ([string]$profile.LocalPath) 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
            }
        }
    } catch {
        if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
            $startupFolders += (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
        }
    }
    foreach ($folder in $startupFolders) {
        if ([string]::IsNullOrWhiteSpace($folder)) { continue }
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -ErrorAction Stop)) {
                [void]$rows.Add([pscustomobject]@{
                    Type = 'Startup folder'; Name = $file.FullName; Command = $file.FullName
                    State = 'at logon'; Verdict = 'REVIEW'
                })
            }
        } catch { }
    }

    try {
        # The WMI repository can be unhealthy or remote-provider backed. Bound
        # this one optional collector so a hung subscription namespace cannot
        # turn a read-only competition report into an indefinite wait.
        foreach ($consumer in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -OperationTimeoutSec 8 -ErrorAction Stop)) {
            $command = ''
            $className = if ($consumer.PSObject.Properties.Name -contains '__CLASS') { [string]$consumer.__CLASS } else { 'WMI consumer' }
            $name = if ($consumer.PSObject.Properties.Name -contains 'Name') { [string]$consumer.Name } else { '(unnamed)' }
            if ($consumer.PSObject.Properties.Name -contains 'CommandLineTemplate') { $command = [string]$consumer.CommandLineTemplate }
            if ([string]::IsNullOrWhiteSpace($command) -and ($consumer.PSObject.Properties.Name -contains 'ExecutablePath')) { $command = [string]$consumer.ExecutablePath }
            [void]$rows.Add([pscustomobject]@{
                Type = 'WMI consumer'; Name = ('{0}:{1}' -f $className, $name)
                Command = (Short $command); State = 'on WMI event'; Verdict = 'REVIEW'
            })
        }
    } catch {
        [void]$surfaceGaps.Add('could not enumerate permanent WMI event consumers (requires WMI repository access)')
    }
    return @($rows | Sort-Object Type, Name)
}

function Get-AutorunscRows {
    param([Parameter(Mandatory)][hashtable]$Config)
    $rows = New-Object System.Collections.ArrayList
    $capture = Invoke-CcdcAutorunsc -Config $Config
    if (-not $capture.Ran) {
        [void]$surfaceGaps.Add("Autorunsc wider persistence inventory not collected: $($capture.Reason)")
        return @($rows)
    }
    foreach ($entry in @($capture.Rows)) {
        $name = ''; $location = ''; $image = ''
        try { $name = [string]$entry.'Entry'; $location = [string]$entry.'Entry Location'; $image = [string]$entry.'Image Path' } catch { }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$rows.Add([pscustomobject]@{
            Type = 'Autorunsc'; Name = ('{0}\\{1}' -f $location, $name)
            Command = (Short $image); State = 'Sysinternals inventory'; Verdict = 'REVIEW'
        })
    }
    return @($rows | Sort-Object Name)
}

function Write-MarkdownTable {
    param([string[]]$Headers, [object[]]$Rows, [string[]]$Properties)
    Write-Host ('| {0} |' -f ($Headers -join ' | '))
    Write-Host ('| {0} |' -f (($Headers | ForEach-Object { '---' }) -join ' | '))
    foreach ($row in $Rows) {
        $cells = @()
        foreach ($property in $Properties) { $cells += (Format-MarkdownCell ([string]$row.$property)) }
        Write-Host ('| {0} |' -f ($cells -join ' | '))
    }
}

$processes = Get-ProcessMap
$services = Get-ServiceMap
$listeners = @(Get-ListenerRows -Processes $processes -Services $services)
$serviceRows = @(Get-ServiceRows | Where-Object {
    $_.State -eq 'Running' -or (Test-CcdcListContains -Needle $_.Name -List $scoredServices)
})
$autostarts = @()
$autostarts += @(Get-AutostartRows)
$autostarts += @(Get-AutorunscRows -Config $cfg)

if (-not $Table) {
    Write-Host ''
    Write-Host ('surface.ps1 - execution surface for {0}' -f $facts['Host'])
    Write-Host 'read-only. REVIEW means the packet does not explain it; decide before changing it.'
    if (-not $facts['Elevated']) {
        Write-Host 'WARNING: not elevated. Process ownership and other-user tasks may be incomplete.' -ForegroundColor Yellow
    }
    foreach ($gap in $surfaceGaps) {
        Write-Host ('GAP: {0}' -f $gap) -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  LISTENERS'
    if (@($listeners).Count -eq 0) { Write-Host '    none found (or the capability is unavailable)' }
    foreach ($r in $listeners) {
        Write-Host ('    {0,-3} {1,-18} {2,-5} pid {3,-6} {4,-28} {5,-18} {6}' -f $r.Protocol, $r.Address, $r.Port, $r.PID, $r.Process, $r.Service, $r.Needed)
    }
    Write-Host ''
    Write-Host '  SERVICES'
    foreach ($r in $serviceRows) {
        if ($r.Needed -eq 'yes - scored' -or $r.State -eq 'Running') {
            Write-Host ('    {0,-28} {1,-8} {2,-10} {3}' -f $r.Name, $r.State, $r.Start, $r.Needed)
        }
    }
    Write-Host ''
    Write-Host ('  AUTOSTARTS: {0} scheduled tasks, logon keys, folders, loaders, and WMI consumers' -f @($autostarts).Count)
    Write-Host '    Use -Table for the inject-ready detail.'
    Write-Host ''
    exit 0
}

Write-Host '<!-- generated by windows/surface.ps1 -Table; REVIEW is not a removal instruction -->'
foreach ($gap in $surfaceGaps) { Write-Host ('> GAP: {0}' -f $gap) }
Write-Host ''
Write-Host '## Windows network surface'
Write-Host ''
Write-MarkdownTable -Headers @('Protocol','Address','Port','PID','Process','Service','Needed?') `
    -Rows $listeners -Properties @('Protocol','Address','Port','PID','Process','Service','Needed')
Write-Host ''
Write-Host '## Windows services'
Write-Host ''
Write-MarkdownTable -Headers @('Service','State','Start','Account','Image','Packet verdict') `
    -Rows $serviceRows -Properties @('Name','State','Start','Account','Image','Needed')
Write-Host ''
Write-Host '## Windows execution at logon or on schedule'
Write-Host ''
Write-MarkdownTable -Headers @('Type','Name','Command','State','Packet verdict') `
    -Rows $autostarts -Properties @('Type','Name','Command','State','Verdict')
Write-Host ''
Write-Host 'REVIEW means it is not named in the packet. Preserve its command and decide it; this tool does not remove it.'
