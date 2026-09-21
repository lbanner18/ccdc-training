<#
.SYNOPSIS
    Package a small, verified Windows defense record for a trusted UNC share.

.DESCRIPTION
    A compromised host can edit its own logs, manifests, and baseline. This
    tool copies the selected config, Guardian manifests, Guardian/watchdog/
    integrity logs, and baseline state into a ZIP, hashes it, copies both to a
    UNC path supplied by the operator, then verifies the copied ZIP's hash.

    It does not discover a destination, save credentials, or send data anywhere
    by default. -Apply is required before any file is copied.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [string]$Destination = '',
    [switch]$Bundle,
    [switch]$Apply
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Import-CcdcConfig -Path $Config
$privateLeaf = Get-CcdcPrivateLeaf -Config $cfg -Name 'CCDC_WINDOWS_PRIVATE_DIR' -Default 'maintenance'
$privateDir = Get-CcdcPath $privateLeaf
$logName = 'evidence-export.log'

function E { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Get-EvidenceInputs {
    return @(
        $cfg['_ConfigPath'],
        (Get-CcdcPath 'guardian.log'),
        (Get-CcdcPath 'watchdog.log'),
        (Get-CcdcPath 'integrity.log'),
        (Get-CcdcPath 'state\baseline.json'),
        (Join-Path $privateDir 'SHA256SUMS.csv'),
        (Join-Path $privateDir '.repair\SHA256SUMS.csv')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
}

if (-not $Bundle) {
    Write-Host '  This packages the config, Guardian manifests, Guardian/watchdog/integrity logs, and baseline state.'
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
Get-ChildItem -LiteralPath $stage -File | Get-FileHash -Algorithm SHA256 |
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
