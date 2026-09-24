<#
.SYNOPSIS
    Package a small, verified Windows defense record for a trusted UNC share.

.DESCRIPTION
    A compromised host can edit its own logs, manifests, and baseline. This
    tool copies the selected config, Guardian manifests, Guardian/watchdog/
    integrity logs, baseline state, the newest built-in recon and timeline
    evidence cases, and a compact whole-kit recovery archive when present. It
    hashes the ZIP, copies both it and the hash to a UNC path supplied by the
    operator, then verifies the copied ZIP's hash.

    It does not discover a destination, save credentials, or send data anywhere
    by default. -Apply is required before any file is copied.
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [string]$Destination = '',
    [switch]$Bundle,
    [switch]$Apply
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
# From here on -Config is the file actually loaded. When it was omitted and
# the default was found, every printed command and child call would
# otherwise carry an empty -Config, which PowerShell refuses.
$Config = [string]$cfg['_ConfigPath']
$privateLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance'
$privateDir = Get-CcdcPath $privateLeaf
$logName = 'evidence-export.log'

function E { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Get-LatestEvidenceFiles {
    <#
        Keep the export useful rather than blindly recursive. Recon and
        timeline each write a self-contained, hash-manifested case directory;
        the newest one is what describes the current incident. A corrupted or
        accidentally enormous case must not make an otherwise small, urgent
        off-box export fail halfway through a competition round.
    #>
    param([Parameter(Mandatory)][string]$Label)
    $root = Get-CcdcPath 'evidence'
    $case = @(Get-ChildItem -LiteralPath $root -Directory -Filter ($Label + '-*') -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    if (@($case).Count -eq 0) { return @() }
    $files = @(Get-ChildItem -LiteralPath $case[0].FullName -Recurse -File -ErrorAction SilentlyContinue)
    $bytes = 0L
    foreach ($file in $files) { $bytes += [int64]$file.Length }
    if ($bytes -gt 50MB) {
        Write-CcdcWarn ('newest {0} evidence case is {1:N1} MB; left out of this compact export (copy it separately if needed): {2}' -f $Label, ($bytes / 1MB), $case[0].FullName)
        return @()
    }
    return @($files | ForEach-Object { $_.FullName })
}

function Get-KitRecoveryFiles {
    # The local recovery archive is useful against a deleted checkout, but not
    # against somebody deleting ProgramData too. Carry it off-box when it is a
    # reasonable size, alongside the record that proves it was the kit we made.
    $recovery = Get-CcdcPath 'backup\kit-recovery'
    $archive = Join-Path $recovery 'ccdc-kit-latest.zip'
    $sidecars = @(
        (Join-Path $recovery 'ccdc-kit-latest.zip.sha256'),
        (Join-Path $recovery 'ccdc-kit-latest.manifest.csv')
    )
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { return @() }
    $bytes = [int64](Get-Item -LiteralPath $archive -ErrorAction Stop).Length
    if ($bytes -gt 50MB) {
        Write-CcdcWarn ('kit recovery archive is {0:N1} MB; left out of this compact evidence export (copy it separately if needed): {1}' -f ($bytes / 1MB), $archive)
        return @()
    }
    $out = @($archive)
    foreach ($path in $sidecars) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $out += $path }
    }
    return @($out)
}

function Get-EvidenceInputs {
    $inputs = New-Object System.Collections.ArrayList
    foreach ($path in @(
        $cfg['_ConfigPath'],
        (Get-CcdcPath 'guardian.log'),
        (Get-CcdcPath 'watchdog.log'),
        (Get-CcdcPath 'integrity.log'),
        (Get-CcdcPath 'state\baseline.json'),
        (Join-Path $privateDir 'SHA256SUMS.csv'),
        (Join-Path $privateDir '.repair\SHA256SUMS.csv')
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { [void]$inputs.Add($path) }
    }
    foreach ($label in @('recon', 'timeline')) {
        foreach ($path in @(Get-LatestEvidenceFiles -Label $label)) { [void]$inputs.Add($path) }
    }
    foreach ($path in @(Get-KitRecoveryFiles)) { [void]$inputs.Add($path) }
    return @($inputs)
}

if (-not $Bundle) {
    Write-Host '  This packages the config, Guardian manifests, Guardian/watchdog/integrity logs, baseline state,'
    Write-Host '  newest built-in recon/timeline cases, and a kit-recovery archive when present (50 MB each).'
    Write-Host '  It copies only to a UNC share you name; it never chooses a network destination.'
    Write-Host '  Example: .\windows\evidence.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Destination \\workstation\evidence -Bundle -Apply'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Destination)) { Write-CcdcDie '-Bundle needs -Destination \\host\share' }
if ($Destination -notmatch '^\\\\[^\\]+\\[^\\]+') { Write-CcdcDie 'Destination must be a UNC share such as \\workstation\evidence, not a local path' }
if (-not $Apply) {
    Write-Host ('  would package selected defense records and copy the ZIP plus SHA-256 file to {0}' -f $Destination)
    Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
    exit 0
}

Assert-CcdcAdmin
if (-not (Test-Path -LiteralPath $Destination -PathType Container)) { Write-CcdcDie "destination is not an available folder: $Destination" }
Initialize-CcdcRoot
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$stage = Get-CcdcPath ("backup\offbox-$stamp-$PID")
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$n = 0
foreach ($source in (Get-EvidenceInputs)) {
    $n++
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage ('{0:D2}-{1}' -f $n, (Split-Path -Leaf $source))) -Force -ErrorAction Stop
}
if ($n -eq 0) { Write-CcdcDie 'there are no selected records yet; run recon, Guardian, or baseline first' }
$manifest = Join-Path $stage 'SHA256SUMS.csv'
Get-ChildItem -LiteralPath $stage -File | Where-Object { $_.Name -ne 'SHA256SUMS.csv' } | Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, @{n='File';e={ Split-Path -Leaf $_.Path }} |
    Export-Csv -LiteralPath $manifest -NoTypeInformation -Encoding UTF8
$archive = Join-Path $stage ("ccdc-defense-evidence-$stamp.zip")
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
$sum = Join-Path $stage ("ccdc-defense-evidence-$stamp.SHA256")
(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash | Set-Content -LiteralPath $sum -Encoding ASCII
$remoteArchive = Join-Path $Destination (Split-Path -Leaf $archive)
$remoteSum = Join-Path $Destination (Split-Path -Leaf $sum)
Copy-Item -LiteralPath $archive -Destination $remoteArchive -Force -ErrorAction Stop
Copy-Item -LiteralPath $sum -Destination $remoteSum -Force -ErrorAction Stop
$localHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
$remoteHash = (Get-FileHash -LiteralPath $remoteArchive -Algorithm SHA256).Hash
if ($localHash -ne $remoteHash) { Write-CcdcDie "off-box ZIP hash did not match after copy: $remoteArchive" }
E "OFFBOX-EXPORTED archive=$remoteArchive sha256=$localHash records=$n"
Write-CcdcInfo "verified off-box evidence copy: $remoteArchive"
Write-Host ('  SHA-256: {0}' -f $localHash)
Write-Host '  The local staging copy remains under C:\ProgramData\CCDC\backup for review.'
