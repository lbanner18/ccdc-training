<#
    Provenance.ps1 - "should this file be here at all?"

    The same bounded question lib/provenance.sh asks on Linux, answered with
    what Windows actually has.

    Asking what a file CONTAINS is unbounded: there are infinite ways to spell
    a reverse shell, and a check written that way only ever catches the
    spellings somebody thought of. Asking whether a file is EXPLAINED is
    bounded. It is signed, or it was here when we froze the box, or it is on an
    allowlist, or it is none of those and you should know about it.

    WHERE WINDOWS DIFFERS FROM THE LINUX VERSION

    Linux asks "does a package own this, and does its checksum still match?"
    Windows' nearest equivalent is Authenticode, and it is STRONGER in one way
    and WEAKER in another, both of which matter:

      Stronger - a signature covers the file's contents. `dpkg -V` tells you a
      packaged file changed; a signature tells you a file changed AND that
      nobody with the publisher's key stands behind the new version. A status
      of HashMismatch means the file was signed and has since been modified,
      which is a louder signal than anything on the Linux side.

      Weaker - ANYONE can buy a code-signing certificate. "Valid" means "not
      modified since signing", never "trustworthy". So nothing here reports a
      file as fine because it is signed; it reports WHO signed it and lets that
      be read. A signed binary from a publisher you have never heard of, in
      System32, is more alarming than an unsigned one, not less.

    THE TRAP, which is this file's merged-/usr

    Most of Windows is not signed in the file at all: it is CATALOG signed, and
    the signature lives in a .cat file in the component store. Get-Authenticode-
    Signature finds those and reports SignatureType 'Catalog'. But if somebody
    removes or corrupts the catalog entry, the very same untouched Microsoft
    binary reports NotSigned - and a checker that reads NotSigned as "suspicious
    file" would point at hundreds of innocent files and teach you to ignore it.
    So: NotSigned inside a system directory is reported as a CATALOG QUESTION,
    not as an unsigned binary, and it is separated from the same status outside
    one.

    Sourced, never executed. Requires lib/Common.ps1.
#>

# Directories whose contents Windows itself owns. A file here that cannot
# account for itself is a much bigger deal than one in C:\Users.
$script:CcdcSystemRoots = @(
    "$env:SystemRoot\System32"
    "$env:SystemRoot\SysWOW64"
    "$env:SystemRoot"
    "${env:ProgramFiles}"
    "${env:ProgramFiles(x86)}"
)

function Test-CcdcUnderSystemRoot {
    param([Parameter(Mandatory)][string]$Path)
    foreach ($r in $script:CcdcSystemRoots) {
        if ([string]::IsNullOrWhiteSpace($r)) { continue }
        if ($Path -like ($r + '\*')) { return $true }
    }
    return $false
}

function Get-CcdcPublisher {
    <#
        The signer's common name, or '' when there is not one. Kept separate
        because the subject line is a full X.500 string and nobody wants to
        read 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=...'
        in a report at 2am.
    #>
    param($Signature)
    if ($null -eq $Signature) { return '' }
    $cert = $null
    try { $cert = $Signature.SignerCertificate } catch { return '' }
    if ($null -eq $cert) { return '' }
    $subject = ''
    try { $subject = [string]$cert.Subject } catch { return '' }
    if ($subject -match 'CN=([^,]+)') { return $Matches[1].Trim('"', ' ') }
    return $subject
}

function Get-CcdcFileFacts {
    <#
        Everything provenance cares about, for one file, in one pass.

        Never throws: a path that cannot be read still produces a record
        saying so, because a file that is unreadable is itself a finding and
        losing the whole run to one of them is worse.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $facts = [ordered]@{
        Path      = $Path
        Exists    = $false
        Sha256    = ''
        Size      = 0
        Modified  = ''
        SigStatus = 'NotChecked'
        SigType   = ''
        Publisher = ''
        Company   = ''
        Error     = ''
    }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]$facts }
        $facts.Exists = $true
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $facts.Size = $item.Length
        $facts.Modified = $item.LastWriteTimeUtc.ToString('u')
        $facts.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        $facts.Error = $_.Exception.Message
        return [pscustomobject]$facts
    }

    # Only PE files and scripts carry signatures; asking about a .txt wastes
    # time and returns UnknownError, which reads like a problem and is not.
    if ($Path -match '\.(exe|dll|sys|ocx|scr|cpl|msi|ps1|psm1|psd1|vbs|js|cat)$') {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $facts.SigStatus = [string]$sig.Status
            try { $facts.SigType = [string]$sig.SignatureType } catch { }
            $facts.Publisher = Get-CcdcPublisher -Signature $sig
        } catch {
            $facts.SigStatus = 'UnknownError'
        }
    } else {
        $facts.SigStatus = 'NotApplicable'
    }
    try {
        $vi = $item.VersionInfo
        if ($null -ne $vi -and $vi.CompanyName) { $facts.Company = [string]$vi.CompanyName }
    } catch { }

    return [pscustomobject]$facts
}

function Test-CcdcExplained {
    <#
        The question. Returns a verdict object rather than a boolean, because
        "explained" and "explained BY WHAT" are different pieces of
        information and the second is the one that goes in the report.

        Verdict is one of:
          frozen        it was here, byte for byte, when the box was blessed
          signed        Authenticode says it has not changed since signing,
                        and names who signed it
          allowed       it is on the operator's allowlist, with their reason
          catalog-gap   under a system root, unsigned - which is usually a
                        missing catalog entry rather than a bad file
          MODIFIED      it was signed and has since been altered. The loudest
                        thing this file can say.
          unexplained   none of the above
    #>
    param(
        [Parameter(Mandatory)]$Facts,
        [hashtable]$Frozen = @{},
        [string[]]$Allowed = @()
    )

    $path = [string]$Facts.Path
    $verdict = [ordered]@{
        Verdict = 'unexplained'; By = ''; Detail = ''; Severity = 'AMBER'
    }

    if (-not $Facts.Exists) {
        $verdict.Verdict = 'missing'; $verdict.Severity = 'AMBER'
        $verdict.Detail  = 'the file named here is not on disk'
        return [pscustomobject]$verdict
    }

    # A signature that does not verify outranks everything else, including the
    # baseline: a file can be frozen AND subsequently tampered with, and the
    # tamper is what you need to hear about.
    if ($Facts.SigStatus -eq 'HashMismatch') {
        $verdict.Verdict  = 'MODIFIED'; $verdict.Severity = 'RED'
        $verdict.By       = $Facts.Publisher
        $verdict.Detail   = 'signed, and the contents have changed since. The publisher does not stand behind what is on disk now.'
        return [pscustomobject]$verdict
    }

    $key = $path.ToLowerInvariant()
    if ($Frozen.ContainsKey($key)) {
        if ($Frozen[$key] -eq $Facts.Sha256) {
            $verdict.Verdict = 'frozen'; $verdict.Severity = 'OK'
            $verdict.Detail  = 'byte for byte what it was when you blessed this box'
            return [pscustomobject]$verdict
        }
        $verdict.Verdict  = 'CHANGED'; $verdict.Severity = 'RED'
        $verdict.Detail   = 'this file is not what it was when you blessed this box'
        $verdict.By       = $Facts.Publisher
        return [pscustomobject]$verdict
    }

    foreach ($a in $Allowed) {
        if ([string]::IsNullOrWhiteSpace($a)) { continue }
        if ($key -eq $a.ToLowerInvariant() -or $path -like $a) {
            $verdict.Verdict = 'allowed'; $verdict.Severity = 'OK'
            $verdict.Detail  = 'on your allowlist'
            return [pscustomobject]$verdict
        }
    }

    if ($Facts.SigStatus -eq 'Valid') {
        $verdict.Verdict = 'signed'; $verdict.Severity = 'NOTE'
        $verdict.By      = $Facts.Publisher
        # Deliberately not "fine". Anyone can buy a certificate; what a valid
        # signature buys you is a NAME to disbelieve.
        $verdict.Detail  = "signed by $($Facts.Publisher) - valid means unmodified since signing, not trustworthy"
        return [pscustomobject]$verdict
    }

    if (Test-CcdcUnderSystemRoot -Path $path) {
        if ($Facts.SigStatus -eq 'NotSigned') {
            $verdict.Verdict = 'catalog-gap'; $verdict.Severity = 'AMBER'
            $verdict.Detail  = 'under a system directory and unsigned. Most of Windows is signed by CATALOG, so this is usually a missing catalog entry rather than a bad file - but it is also exactly where a replaced system binary would sit.'
            return [pscustomobject]$verdict
        }
        $verdict.Verdict = 'unexplained'; $verdict.Severity = 'RED'
        $verdict.Detail  = "in a system directory with signature status '$($Facts.SigStatus)'"
        return [pscustomobject]$verdict
    }

    $verdict.Verdict = 'unexplained'; $verdict.Severity = 'AMBER'
    $verdict.Detail  = 'nothing accounts for this file: not signed, not in your baseline, not allowlisted'
    return [pscustomobject]$verdict
}

function Get-CcdcExecutablePath {
    <#
        Pull the executable out of a service PathName or a task action.

        A service PathName is a COMMAND LINE, not a path: it may be quoted, may
        carry arguments, and may be an unquoted path containing spaces - which
        is the svcunquoted finding and the reason this cannot just split on the
        first space.
    #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $s = $CommandLine.Trim()
    if ($s -match '^"([^"]+)"') { return $Matches[1] }
    # Unquoted: take everything up to and including the first .exe, which is
    # right even when the path has spaces in it.
    if ($s -match '^(.+?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js))(\s|$)') { return $Matches[1] }
    $first = ($s -split '\s+')[0]
    return $first
}
