<#
.SYNOPSIS
    Keep a checksummed Windows kit recovery archive outside the checkout.

.DESCRIPTION
    Guardian repairs the small private runtime it owns. This tool covers a
    different failure: somebody deletes or alters the checkout you use to run
    triage, harden, cards, and recovery commands from.

    -Create copies the complete kit (except .git) into a ZIP under the protected
    CCDC ProgramData root and writes a SHA-256 sidecar plus a per-file manifest.
    -Restore verifies both before extracting, and refuses to write into an
    existing destination. It therefore recovers a second copy; it never
    overwrites the damaged checkout while you are deciding what happened.

    This is resilience, not tamper-proofing. An Administrator can delete or
    alter the checkout, archive, and its sidecars. Copy the resulting archive
    to a team-controlled share with evidence.ps1 when one is available.

.EXAMPLE
    .\recovery.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Create -Apply

.EXAMPLE
    .\recovery.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status

.EXAMPLE
    .\recovery.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Restore -Destination C:\ccdc-recovered -Apply
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Create,
    [switch]$Status,
    [switch]$Restore,
    [string]$Destination = '',
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
$sourceRoot = Split-Path -Parent $PSScriptRoot
$store = Get-CcdcPath 'backup\kit-recovery'
$archive = Join-Path $store 'ccdc-kit-latest.zip'
$hashFile = Join-Path $store 'ccdc-kit-latest.zip.sha256'
$manifestFile = Join-Path $store 'ccdc-kit-latest.manifest.csv'
$logName = 'kit-recovery.log'

# `r` is PowerShell's Invoke-History alias. Alias resolution wins over a
# function of the same short name on a real Windows host, so this must remain
# descriptive rather than using the one-letter logging helpers older scripts
# use.
function Write-RecoveryLog { param([string]$Message) Write-CcdcLog -Message $Message -LogName $logName }

function Get-KitFiles {
    if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
        throw "kit source directory is missing: $sourceRoot"
    }
    return @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Force -ErrorAction Stop |
        Where-Object { $_.FullName -notmatch '([\\/])\.git([\\/]|$)' })
}

function Get-RelativeKitPath {
    param([Parameter(Mandatory)][string]$Path)
    $prefix = $sourceRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to archive a file outside the kit: $Path"
    }
    return $Path.Substring($prefix.Length)
}

function Test-RecoveryArchive {
    $problems = New-Object System.Collections.ArrayList
    foreach ($path in @($archive, $hashFile, $manifestFile)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { [void]$problems.Add("missing $path") }
    }
    if (@($problems).Count -gt 0) { return [pscustomobject]@{ Good = $false; Problems = @($problems) } }
    $expected = (Get-Content -LiteralPath $hashFile -Raw -ErrorAction Stop).Trim()
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($expected -ne $actual) { [void]$problems.Add("archive SHA-256 does not match $hashFile") }
    try {
        $rows = @(Import-Csv -LiteralPath $manifestFile -ErrorAction Stop)
        if (@($rows).Count -eq 0) { [void]$problems.Add('per-file manifest is empty') }
    } catch { [void]$problems.Add("per-file manifest is unreadable: $($_.Exception.Message)") }
    return [pscustomobject]@{ Good = (@($problems).Count -eq 0); Problems = @($problems) }
}

function Test-RestoredKit {
    param([Parameter(Mandatory)][string]$Path)
    $rows = @(Import-Csv -LiteralPath $manifestFile -ErrorAction Stop)
    $problems = New-Object System.Collections.ArrayList
    foreach ($row in $rows) {
        $relative = [string]$row.File
        if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            [void]$problems.Add("unsafe manifest path: $relative")
            continue
        }
        $file = Join-Path $Path $relative
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            [void]$problems.Add("missing restored file: $relative")
            continue
        }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actual -ne [string]$row.Hash) { [void]$problems.Add("changed restored file: $relative") }
    }
    return @($problems)
}

$modes = @($Create, $Status, $Restore)
if (@($modes | Where-Object { $_ }).Count -ne 1) {
    Write-CcdcDie 'choose exactly one: -Create, -Status, or -Restore'
}

Assert-CcdcAdmin

if ($Status) {
    $check = Test-RecoveryArchive
    Write-Host ''
    if ($check.Good) {
        Write-Host ('  ok      kit recovery archive verifies: {0}' -f $archive) -ForegroundColor Green
        Write-Host ('  manifest: {0}' -f $manifestFile)
        exit 0
    }
    foreach ($problem in $check.Problems) { Write-Host ('  PROBLEM {0}' -f $problem) -ForegroundColor Red }
    Write-Host ('  rebuild from the checkout you trust: .\windows\recovery.ps1 -Config {0} -Create -Apply' -f $Config)
    exit 2
}

if ($Create) {
    if (-not $Apply) {
        Write-Host ''
        Write-Host ('  would archive the kit at {0}' -f $sourceRoot)
        Write-Host ('  would write the archive and its SHA-256 + per-file manifest under {0}' -f $store)
        Write-Host '  .git is deliberately excluded: history is not a recovery dependency.'
        Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
        exit 0
    }
    $stage = ''
    try {
        Initialize-CcdcRoot
        New-Item -ItemType Directory -Path $store -Force | Out-Null
        $files = @(Get-KitFiles)
        if (@($files).Count -eq 0) { throw 'the kit contains no files to archive' }
        $rows = New-Object System.Collections.ArrayList
        foreach ($file in $files) {
            [void]$rows.Add([pscustomobject]@{
                File = Get-RelativeKitPath -Path $file.FullName
                Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            })
        }
        $stage = Join-Path $store ("kit-stage-$PID")
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        foreach ($file in $files) {
            $relative = Get-RelativeKitPath -Path $file.FullName
            $destination = Join-Path $stage $relative
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Copy-Item -LiteralPath $file.FullName -Destination $destination -Force -ErrorAction Stop
        }
        $archiveTmp = Join-Path $store 'ccdc-kit-latest.tmp.zip'
        $hashTmp = "$hashFile.tmp"
        $manifestTmp = "$manifestFile.tmp"
        Remove-Item -LiteralPath $archiveTmp -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archiveTmp -CompressionLevel Optimal -Force -ErrorAction Stop
        (Get-FileHash -LiteralPath $archiveTmp -Algorithm SHA256 -ErrorAction Stop).Hash | Set-Content -LiteralPath $hashTmp -Encoding ASCII
        $rows | Export-Csv -LiteralPath $manifestTmp -NoTypeInformation -Encoding UTF8
        Move-Item -LiteralPath $archiveTmp -Destination $archive -Force
        Move-Item -LiteralPath $hashTmp -Destination $hashFile -Force
        Move-Item -LiteralPath $manifestTmp -Destination $manifestFile -Force
        Write-RecoveryLog "CREATED archive=$archive files=$(@($files).Count)"
        Write-CcdcInfo "created checksummed kit recovery archive ($(@($files).Count) files)"
        Write-Host ('  archive:  {0}' -f $archive)
        Write-Host ('  verify:   .\windows\recovery.ps1 -Config {0} -Status' -f $Config)
    } catch { Write-CcdcDie "could not create kit recovery archive: $($_.Exception.Message)" }
    finally {
        if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Destination)) { Write-CcdcDie '-Restore needs -Destination C:\new-empty-folder' }
if (-not [IO.Path]::IsPathRooted($Destination)) { Write-CcdcDie '-Destination must be an absolute path' }
if (Test-Path -LiteralPath $Destination) { Write-CcdcDie "refusing to restore into an existing path: $Destination" }
$check = Test-RecoveryArchive
if (-not $check.Good) { Write-CcdcDie ('refusing restore: ' + ($check.Problems -join '; ')) }

if (-not $Apply) {
    Write-Host ''
    Write-Host ('  would verify {0}, then extract it into new folder {1}' -f $archive, $Destination)
    Write-Host '  refuses existing destinations, so this cannot overwrite a checkout.'
    Write-Host '  DRY RUN. Add -Apply.' -ForegroundColor Yellow
    exit 0
}
try {
    Expand-Archive -LiteralPath $archive -DestinationPath $Destination -ErrorAction Stop
    $problems = @(Test-RestoredKit -Path $Destination)
    if (@($problems).Count -gt 0) {
        throw ('restored archive did not verify: ' + ($problems -join '; '))
    }
    Write-RecoveryLog "RESTORED archive=$archive destination=$Destination"
    Write-CcdcInfo "recovered verified kit into $Destination"
    Write-Host '  Keep the damaged checkout for evidence until you have recorded what changed.'
} catch {
    Write-CcdcDie "could not restore kit: $($_.Exception.Message)"
}
