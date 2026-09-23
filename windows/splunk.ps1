<#
.SYNOPSIS
    Is this Windows box actually shipping its event logs to Splunk, or does it
    just look like it is?

.DESCRIPTION
    A running forwarder proves nothing. It can be running with no output target,
    pointed at an indexer it cannot reach, collecting the Application log but
    not Security, or sending every event to an index the indexer does not have
    (the indexer drops those). In every one of those cases the service is green
    and the events are not arriving.

    -Check (the default) reads configuration and live connections. It changes
    nothing. -Inventory prints the markdown table a logging inject asks for.
    -TestEvent -Apply writes ONE tagged event to the Application log and prints
    the search that finds it. That is the only part that proves delivery:
    everything else reads configuration, and configuration is a claim.

    It never restarts the forwarder, never edits a .conf, and never touches an
    index. Mid-event, a forwarder that is up and misconfigured is worth more
    than one you just restarted into a state nobody has seen before. It prints
    the command instead.

    Effective settings come from `splunk btool`, which applies Splunk's own
    precedence rules. If btool cannot run, the .conf files are read directly in
    Splunk's precedence order and the report says so.

    Exit: 0 healthy, 3 findings, 1 the check could not run.

.EXAMPLE
    .\windows\splunk.ps1 -Config C:\ProgramData\CCDC\ccdc.env
.EXAMPLE
    .\windows\splunk.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Inventory
.EXAMPLE
    .\windows\splunk.ps1 -Config C:\ProgramData\CCDC\ccdc.env -TestEvent -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [switch]$Check,
    [switch]$Inventory,
    [switch]$TestEvent,
    [switch]$Apply
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$configPath = $cfg['_ConfigPath']
$logName = 'splunk.log'
function L { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

$modes = @($Check, $Inventory, $TestEvent)
if (@($modes | Where-Object { $_ }).Count -gt 1) { Write-CcdcDie 'choose one: -Check, -Inventory, or -TestEvent' }
if (-not $Inventory -and -not $TestEvent) { $Check = $true }

# The four logs an incident report leans on. PowerShell/Operational is where
# script-block logging (4104) lands; a default forwarder install does not
# collect it, and that is exactly the log an attacker's PowerShell writes to.
$defaultLogs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
$requiredLogs = @(Get-CcdcList -Config $cfg -Name 'CCDC_SPLUNK_WINDOWS_LOGS')
if ($requiredLogs.Count -eq 0) { $requiredLogs = $defaultLogs }
$testSource = 'CCDC-SplunkTest'
$tokenFile = Get-CcdcPath 'state\splunk.test-token'

# --- where is it ------------------------------------------------------------

function Get-SplunkService {
    # Filtered here rather than with -Filter so the answer does not depend on
    # WQL quoting, and so a renamed service with a splunkd image is still found.
    $all = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
    foreach ($s in $all) {
        if ($s.Name -eq 'SplunkForwarder' -or $s.Name -eq 'Splunkd') { return $s }
    }
    foreach ($s in $all) {
        if ($s.PSObject.Properties.Name -contains 'PathName' -and [string]$s.PathName -match '\\bin\\splunkd\.exe') { return $s }
    }
    return $null
}

function Get-HomeFromService {
    param($Service)
    if ($null -eq $Service) { return '' }
    $path = [string]$Service.PathName
    if ($path -match '^"?(?<home>.+?)\\bin\\splunkd\.exe') { return $Matches['home'] }
    return ''
}

$service = Get-SplunkService
$configuredHome = Get-CcdcValue -Config $cfg -Name 'CCDC_SPLUNK_HOME'
$homeBad = $false
$splunkHome = ''
# A configured path is used only if it is really there. Taking it on trust made
# a typo look like a working install that was merely "not running".
if ($configuredHome) {
    if ([System.IO.Directory]::Exists($configuredHome)) {
        $splunkHome = $configuredHome
    } else {
        $homeBad = $true
    }
} else {
    $splunkHome = Get-HomeFromService -Service $service
    if (-not $splunkHome) {
        foreach ($candidate in @('C:\Program Files\SplunkUniversalForwarder', 'C:\Program Files\Splunk')) {
            if ([System.IO.Directory]::Exists($candidate)) { $splunkHome = $candidate; break }
        }
    }
}
$splunkExe = if ($splunkHome) { Join-Path (Join-Path $splunkHome 'bin') 'splunk.exe' } else { '' }

# --- effective configuration -------------------------------------------------

function Read-ConfText {
    # [stanza] / key = value, into an ordered list of @{Stanza;Key;Value}.
    param([string[]]$Lines)
    $rows = New-Object System.Collections.ArrayList
    $stanza = 'default'
    foreach ($raw in $Lines) {
        $t = ([string]$raw).Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -match '^\[(?<s>.*)\]$') { $stanza = $Matches['s']; continue }
        if ($t -match '^(?<k>[^=]+?)\s*=\s*(?<v>.*)$') {
            [void]$rows.Add([pscustomobject]@{ Stanza = $stanza; Key = $Matches['k'].Trim(); Value = $Matches['v'].Trim() })
        }
    }
    return $rows
}

function Get-ConfFilesInPrecedence {
    # Global-context precedence, highest first: system/local, then every app's
    # local in ASCII order, then every app's default in ASCII order, then
    # system/default. The FIRST file to set a key wins.
    param([string]$Name)
    $files = New-Object System.Collections.ArrayList
    $etc = Join-Path $splunkHome 'etc'
    $sys = Join-Path $etc 'system'
    $apps = Join-Path $etc 'apps'
    $f = Join-Path (Join-Path $sys 'local') $Name
    if ([System.IO.File]::Exists($f)) { [void]$files.Add($f) }
    $appDirs = @()
    if ([System.IO.Directory]::Exists($apps)) {
        # Ordinal, not Sort-Object: Splunk ranks apps by ASCII order, and a
        # culture-aware sort puts "a_app" and "B_app" the other way round.
        $appDirs = [System.IO.Directory]::GetDirectories($apps)
        [Array]::Sort($appDirs, [System.StringComparer]::Ordinal)
    }
    foreach ($layer in @('local', 'default')) {
        foreach ($a in $appDirs) {
            $f = Join-Path (Join-Path $a $layer) $Name
            if ([System.IO.File]::Exists($f)) { [void]$files.Add($f) }
        }
    }
    $f = Join-Path (Join-Path $sys 'default') $Name
    if ([System.IO.File]::Exists($f)) { [void]$files.Add($f) }
    return $files
}

$script:SettingsSource = @{}
function Get-EffectiveConf {
    # Returns @{ stanza = @{ key = value } } with precedence already applied.
    param([string]$Name)
    $merged = @{}
    $conf = $Name + '.conf'
    if ($splunkExe -and [System.IO.File]::Exists($splunkExe)) {
        try {
            $out = @(& $splunkExe btool $Name list 2>$null)
            if ($LASTEXITCODE -eq 0 -and $out.Count -gt 0) {
                foreach ($r in @(Read-ConfText -Lines $out)) {
                    if (-not $merged.ContainsKey($r.Stanza)) { $merged[$r.Stanza] = @{} }
                    $merged[$r.Stanza][$r.Key] = $r.Value
                }
                $script:SettingsSource[$Name] = 'btool'
                return $merged
            }
        } catch { }
    }
    foreach ($file in @(Get-ConfFilesInPrecedence -Name $conf)) {
        $lines = @()
        try { $lines = [System.IO.File]::ReadAllLines($file) } catch { continue }
        foreach ($r in @(Read-ConfText -Lines $lines)) {
            if (-not $merged.ContainsKey($r.Stanza)) { $merged[$r.Stanza] = @{} }
            # First writer wins: files arrive highest-precedence first.
            if (-not $merged[$r.Stanza].ContainsKey($r.Key)) { $merged[$r.Stanza][$r.Key] = $r.Value }
        }
    }
    $script:SettingsSource[$Name] = 'files'
    return $merged
}

function Test-Truthy { param([string]$Value) return ($Value -match '^(1|true|t|yes|y|on)$') }

function Get-Setting {
    # A stanza's own value, else the conf-wide [default], else the fallback.
    param([hashtable]$Conf, [string]$Stanza, [string]$Key, [string]$Fallback = '')
    if ($Conf.ContainsKey($Stanza) -and $Conf[$Stanza].ContainsKey($Key)) { return [string]$Conf[$Stanza][$Key] }
    if ($Conf.ContainsKey('default') -and $Conf['default'].ContainsKey($Key)) { return [string]$Conf['default'][$Key] }
    return $Fallback
}

function Get-Targets {
    param([hashtable]$Outputs)
    $targets = New-Object System.Collections.ArrayList
    foreach ($stanza in @($Outputs.Keys)) {
        if ($stanza -notlike 'tcpout:*') { continue }
        if (Test-Truthy (Get-Setting -Conf $Outputs -Stanza $stanza -Key 'disabled')) { continue }
        foreach ($t in @(([string](Get-Setting -Conf $Outputs -Stanza $stanza -Key 'server')) -split ',')) {
            $t = $t.Trim()
            if ($t -and -not $targets.Contains($t)) { [void]$targets.Add($t) }
        }
    }
    return $targets
}

function Get-EventLogInputs {
    # One row per required log: is there a stanza, is it on, which index.
    param([hashtable]$Inputs)
    $rows = New-Object System.Collections.ArrayList
    foreach ($log in $requiredLogs) {
        $stanza = 'WinEventLog://' + $log
        $present = $Inputs.ContainsKey($stanza)
        $disabled = $true
        $index = ''
        if ($present) {
            $disabled = Test-Truthy (Get-Setting -Conf $Inputs -Stanza $stanza -Key 'disabled' -Fallback '0')
            $index = Get-Setting -Conf $Inputs -Stanza $stanza -Key 'index' -Fallback 'default'
        }
        [void]$rows.Add([pscustomobject]@{ Log = $log; Stanza = $stanza; Present = $present; Enabled = ($present -and -not $disabled); Index = $index })
    }
    return $rows
}

function Get-EstablishedTo {
    param([string]$HostName, [int]$Port)
    $ips = @()
    try { $ips = @([System.Net.Dns]::GetHostAddresses($HostName) | ForEach-Object { $_.IPAddressToString }) } catch { $ips = @($HostName) }
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        $_.PSObject.Properties.Name -contains 'RemotePort' -and $_.PSObject.Properties.Name -contains 'RemoteAddress' -and
        [int]$_.RemotePort -eq $Port -and $ips -contains [string]$_.RemoteAddress })
    return ($conns.Count -gt 0)
}

function Split-Target {
    param([string]$Target)
    if ($Target -match '^(?<h>.+):(?<p>\d+)$') { return @($Matches['h'], [int]$Matches['p']) }
    return @($Target, 9997)
}

function Get-FixIndex {
    # The index already proven to exist for this box's other event logs. An
    # input aimed at an index the indexer lacks is silently dropped THERE, so
    # the printed fix reuses a known-good one or leaves index unset (main).
    param($Rows)
    foreach ($r in @($Rows)) {
        if ($r.Enabled -and $r.Index -and $r.Index -ne 'default') { return $r.Index }
    }
    return ''
}

function Write-InputFix {
    param([string]$Stanza, [string]$Index)
    $local = Join-Path (Join-Path (Join-Path (Join-Path $splunkHome 'etc') 'system') 'local') 'inputs.conf'
    $lines = "'', '[{0}]', 'disabled = 0'" -f $Stanza
    if ($Index) { $lines += (", 'index = {0}'" -f $Index) }
    Write-Host '           ---- run this ----------------------------------------'
    Write-Host ("           Add-Content -LiteralPath '{0}' -Value {1}" -f $local, $lines)
    Write-Host ("           & '{0}' restart" -f $splunkExe)
}

# --- check ------------------------------------------------------------------

$script:findings = 0
function F { param([string]$Message) $script:findings++; Write-Host ('  SPLUNK {0}' -f $Message) -ForegroundColor Red }
function D { param([string]$Message) Write-Host ('         {0}' -f $Message) }
function Fix { param([string]$Message) Write-Host ('           {0}' -f $Message) }
function Ok { param([string]$Message) Write-Host ('  ok     {0}' -f $Message) -ForegroundColor Green }

function Invoke-SplunkCheck {
    Write-Host ''
    Write-Host 'splunk.ps1 - are the event logs actually leaving this box?'
    Write-Host ('read-only. {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-Host ''

    if ($homeBad) {
        F ('CCDC_SPLUNK_HOME is set to a path that does not exist: {0}' -f $configuredHome)
        D 'the config says there is a forwarder there and there is not'
    }
    if (-not $splunkHome) {
        F 'NOTHING on this box forwards event logs anywhere'
        D 'no SplunkForwarder service and no install under C:\Program Files'
        D 'every event log here is local, and local logs are clearable by whoever owns the box'
        D 'install steps: playbooks\splunk-setup.md, "Windows forwarder"'
        return
    }
    Ok ('forwarder found at {0}' -f $splunkHome)

    if ($null -eq $service) {
        F 'no Splunk service is registered - the files are here and nothing runs them'
    } else {
        if ([string]$service.State -eq 'Running') { Ok ('{0} service is running as {1}' -f $service.Name, $service.StartName) }
        else {
            F ('{0} service is {1} - nothing is being shipped right now' -f $service.Name, $service.State)
            Fix ('Start-Service {0}' -f $service.Name)
        }
        if ([string]$service.StartMode -eq 'Auto') { Ok 'the forwarder starts at boot' }
        else {
            F ('{0} start mode is {1} - a reboot silences it' -f $service.Name, $service.StartMode)
            Fix ('Set-Service {0} -StartupType Automatic' -f $service.Name)
        }
    }

    $outputs = Get-EffectiveConf -Name 'outputs'
    $inputs = Get-EffectiveConf -Name 'inputs'
    if ($script:SettingsSource['inputs'] -ne 'btool') {
        D 'btool did not run; settings were read from the .conf files in Splunk precedence order'
    }

    # The packet's indexers are measured too, but they never stand in for the
    # forwarder's own outputs: a packet entry with an empty outputs.conf is a
    # forwarder sending nowhere, and must say so.
    $targets = New-Object System.Collections.ArrayList
    $packetIndexers = @(Get-CcdcList -Config $cfg -Name 'CCDC_SPLUNK_INDEXERS')
    foreach ($t in @(Get-Targets -Outputs $outputs)) { [void]$targets.Add($t) }
    if ($targets.Count -eq 0) {
        F 'the forwarder has NO output target - it is running and sending to nowhere'
        $suggest = if ($packetIndexers.Count -gt 0) { $packetIndexers[0] } else { 'INDEXER:9997' }
        Fix ("& '{0}' add forward-server {1}" -f $splunkExe, $suggest)
    }
    foreach ($t in $packetIndexers) {
        if (-not $targets.Contains($t)) {
            if ($targets.Count -gt 0) { D ('the packet names indexer {0}, which outputs.conf does not' -f $t) }
            [void]$targets.Add($t)
        }
    }
    foreach ($t in $targets) {
        $parts = Split-Target -Target $t
        $h = [string]$parts[0]; $p = [int]$parts[1]
        if (Get-EstablishedTo -HostName $h -Port $p) { Ok ('connected to indexer {0}:{1} right now' -f $h, $p) }
        elseif (Test-CcdcTcpPort -ComputerName $h -Port $p) {
            F ('indexer {0}:{1} accepts connections, but this box has none open' -f $h, $p)
            D 'the port is reachable, so this is the forwarder''s problem, not the network''s'
            Fix ("& '{0}' list forward-server" -f $splunkExe)
            Fix ("Get-Content '{0}' -Tail 50 | Select-String 'TcpOutputProc'" -f (Join-Path $splunkHome 'var\log\splunk\splunkd.log'))
        } else {
            F ('indexer {0}:{1} is NOT REACHABLE from this box' -f $h, $p)
            D 'a forwarder that cannot reach its indexer queues, then drops'
            Fix ('Test-NetConnection {0} -Port {1}' -f $h, $p)
            D 'on the indexer: is "splunk enable listen 9997" done, and is 9997 open in ITS firewall?'
        }
    }

    $rows = @(Get-EventLogInputs -Inputs $inputs)
    $fixIndex = Get-FixIndex -Rows $rows
    foreach ($r in $rows) {
        if ($r.Enabled) {
            Ok ('{0} is collected (index={1})' -f $r.Log, $r.Index)
        } elseif ($r.Present) {
            F ('{0} is configured as an input but DISABLED' -f $r.Log)
            D 'it appears in every config dump and reads nothing'
            Write-InputFix -Stanza $r.Stanza -Index $fixIndex
        } else {
            F ('{0} is NOT collected' -f $r.Log)
            if ($r.Log -eq 'Microsoft-Windows-PowerShell/Operational') {
                D 'script-block logging (4104) lands here; the default forwarder install skips it'
            }
            Write-InputFix -Stanza $r.Stanza -Index $fixIndex
        }
    }
    $indexes = @($rows | Where-Object { $_.Enabled } | ForEach-Object { $_.Index } | Sort-Object -Unique)
    if ($indexes.Count -gt 0) {
        D ('these events go to index: {0}   ("default" means main)' -f ($indexes -join ', '))
        D 'an index the INDEXER does not have silently drops events: check Settings > Indexes there'
    }

    $splunkd = Join-Path $splunkHome 'var\log\splunk\splunkd.log'
    if ([System.IO.File]::Exists($splunkd)) {
        $tail = @()
        try { $tail = @(Get-Content -LiteralPath $splunkd -Tail 3000 -ErrorAction Stop) } catch { }
        $blocked = @($tail | Where-Object { $_ -match 'queue.*(full|blocked)|blocked.*queue' })
        if ($blocked.Count -gt 0) {
            F ('splunkd.log mentions blocked/full queues {0} time(s) in its last 3000 lines' -f $blocked.Count)
            D 'a blocked queue means events are being dropped, not delayed'
        } else { Ok 'no blocked-queue messages in recent splunkd.log' }
        # Connection trouble only. Every restart logs a benign multi-line
        # "Pipeline data does not have indexKey" WARN; printing it buried the
        # report on the lab box and taught the reader to skim.
        $tcpErr = @($tail | Where-Object { $_ -match 'TcpOutput' -and $_ -match '\b(WARN|ERROR)\b' -and
            $_ -match 'connect|timed out|refused|unreachable|blocked|Cooked' })
        if ($tcpErr.Count -gt 0) {
            $last = ([string]$tcpErr[-1]).Trim()
            if ($last.Length -gt 200) { $last = $last.Substring(0, 200) + ' ...' }
            D ('{0} recent TcpOutput connection warning/error line(s); the last one:' -f $tcpErr.Count)
            D $last
        }
        $wel = @($tail | Where-Object { $_ -match 'WinEventLog' -and $_ -match '\bERROR\b' })
        if ($wel.Count -gt 0) {
            F ('splunkd.log has {0} recent WinEventLog error(s); the last one:' -f $wel.Count)
            D ([string]$wel[-1]).Trim()
        }
    } else {
        D ('splunkd.log not found at {0}; queue health not checked' -f $splunkd)
    }

    if ([System.IO.File]::Exists($tokenFile)) {
        Ok ('an end-to-end test event was sent: {0}' -f ([System.IO.File]::ReadAllText($tokenFile).Trim()))
        D 'confirm it ARRIVED - a sent event nobody found in Splunk proves nothing'
    } else {
        F 'no end-to-end test event has ever been sent from this box'
        D 'every check above reads local configuration; only a test event proves delivery'
        Fix ('.\windows\splunk.ps1 -Config {0} -TestEvent -Apply' -f $configPath)
    }
}

function Invoke-SplunkInventory {
    $inputs = if ($splunkHome) { Get-EffectiveConf -Name 'inputs' } else { @{} }
    $outputs = if ($splunkHome) { Get-EffectiveConf -Name 'outputs' } else { @{} }
    $box = Get-CcdcValue -Config $cfg -Name 'CCDC_BOX_NAME' -Default $env:COMPUTERNAME
    Write-Host ('# Log forwarding inventory - {0}' -f $box)
    Write-Host ''
    Write-Host ('Collected {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Write-Host ''
    Write-Host '| Item | Value |'
    Write-Host '|---|---|'
    Write-Host ('| Forwarder home | {0} |' -f $(if ($splunkHome) { $splunkHome } else { 'not installed' }))
    $state = if ($null -eq $service) { 'no service' } else { '{0} ({1})' -f $service.State, $service.StartMode }
    Write-Host ('| Service | {0} |' -f $state)
    Write-Host ('| Indexer targets | {0} |' -f (@(Get-Targets -Outputs $outputs) -join ' '))
    Write-Host ''
    Write-Host '## Event logs that should be forwarded'
    Write-Host ''
    Write-Host '| Event log | Forwarded | Index |'
    Write-Host '|---|---|---|'
    foreach ($r in @(Get-EventLogInputs -Inputs $inputs)) {
        $fwd = if ($r.Enabled) { 'yes' } elseif ($r.Present) { '**NO - input disabled**' } else { '**NO**' }
        Write-Host ('| {0} | {1} | {2} |' -f $r.Log, $fwd, $(if ($r.Index) { $r.Index } else { '-' }))
    }
    Write-Host ''
    Write-Host 'Generated by windows\splunk.ps1 -Inventory. Verify the "Forwarded" column'
    Write-Host 'in Splunk itself before submitting: this reads local configuration only.'
}

function Invoke-SplunkTestEvent {
    if (-not $splunkHome) { Write-CcdcDie 'no forwarder on this box; a test event would prove nothing' }
    $inputs = Get-EffectiveConf -Name 'inputs'
    $app = 'WinEventLog://Application'
    $appOn = $inputs.ContainsKey($app) -and -not (Test-Truthy (Get-Setting -Conf $inputs -Stanza $app -Key 'disabled' -Fallback '0'))
    if (-not $appOn) {
        Write-CcdcDie ('the Application log is not a forwarded input, so a test event written there proves nothing. Run -Check for the fix.')
    }
    $index = Get-Setting -Conf $inputs -Stanza $app -Key 'index' -Fallback 'default'
    $token = 'ccdc-e2e-{0}-{1}-{2}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID, ([guid]::NewGuid().ToString('N').Substring(0, 8))
    if (-not $Apply) {
        Write-Host ('  would register event source {0} (once) and write ONE Application event carrying a token' -f $testSource)
        Write-Host '  Nothing else changes.'
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        return
    }
    Initialize-CcdcRoot
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($testSource)) {
            New-EventLog -LogName Application -Source $testSource -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source $testSource -EventId 999 -EntryType Information -Message ("{0} end-to-end forwarding test from {1}" -f $token, $env:COMPUTERNAME) -ErrorAction Stop
    } catch {
        Write-CcdcDie ('could not write the test event: {0}' -f $_.Exception.Message)
    }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Set-Content -LiteralPath $tokenFile -Value ('{0} {1}' -f $token, $stamp) -Encoding ASCII
    L ('TEST_EVENT token={0} log=Application index={1}' -f $token, $index)
    Write-Host ''
    Write-Host '  sent one test event to the Application log'
    Write-Host ''
    Write-Host ('  TOKEN: {0}' -f $token)
    Write-Host ''
    Write-Host '  Now go to Splunk and run this search over the last 15 minutes:'
    Write-Host ''
    Write-Host ('      index=* "{0}"' -f $token)
    Write-Host ''
    Write-Host ('  It should land in index={0} ("default" means main). A row means this box' -f $index)
    Write-Host '  is genuinely forwarding: the event left, crossed the network, was indexed.'
    Write-Host ''
    Write-Host '  If it returns nothing, work in this order:'
    Write-Host ('    1. .\windows\splunk.ps1 -Config {0}    (connected? inputs on?)' -f $configPath)
    Write-Host '    2. on the indexer: does that index exist? (Settings > Indexes)'
    Write-Host '    3. on the indexer: is it listening?  splunk display listen'
    Write-Host '    4. is the forwarder queue blocked? (splunkd.log)'
    Write-Host ''
    Write-Host '  Write the token and the time in your notes either way - "we verified'
    Write-Host '  forwarding at 14:03 with token X" is an inject answer.'
}

Assert-CcdcAdmin
if ($Inventory) { Invoke-SplunkInventory; exit 0 }
if ($TestEvent) { Invoke-SplunkTestEvent; exit 0 }
Invoke-SplunkCheck
Write-Host ''
if ($script:findings -eq 0) {
    Write-Host '  Forwarding configuration looks healthy.' -ForegroundColor Green
    Write-Host '  That is still a local claim. Prove it: -TestEvent -Apply'
    exit 0
}
Write-Host ('  {0} forwarding finding(s) above.' -f $script:findings) -ForegroundColor Yellow
Write-Host '  Logs that never leave are logs the attacker can clear. Fix these early:'
Write-Host '  after an incident is the wrong time to discover nothing was shipped.'
exit 3
