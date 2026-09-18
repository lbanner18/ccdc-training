# Runs once, at first logon, from the install media.
# LAB ONLY: authorises the lab host's SSH key for Administrator so the box can
# be driven without typing a password into a console window.
#
# The key is NOT stored here. make-unattended-iso.sh substitutes it while
# building the ISO, from $CCDC_LAB_SSH_KEY or your default public key, so this
# file carries nobody's identity into the repository.
$ErrorActionPreference = 'Continue'
$key = '@@CCDC_LAB_SSH_KEY@@'

# If the placeholder is still here, the ISO was assembled by hand or the
# substitution failed. Writing it literally would produce an authorized_keys
# file that silently authorises nothing, and the box would come up with SSH
# running and refusing every key - which looks like a networking problem and
# is not one. Say so instead, where the first-logon transcript will show it.
if ($key -like '*@@CCDC_LAB_SSH_KEY@@*' -or [string]::IsNullOrWhiteSpace($key)) {
    Write-Output 'CCDC LAB: no SSH key was substituted into provision.ps1.'
    Write-Output '          Build the ISO with lab/make-unattended-iso.sh, or set'
    Write-Output '          CCDC_LAB_SSH_KEY to a public key before building.'
    Write-Output '          SSH will start, but no key will be authorised.'
    return
}

$f = 'C:\ProgramData\ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Path 'C:\ProgramData\ssh' -Force | Out-Null
Set-Content -LiteralPath $f -Value $key -Encoding ascii
# OpenSSH refuses to use this file unless only Administrators and SYSTEM can write it.
icacls $f /inheritance:r | Out-Null
icacls $f /grant 'Administrators:F' | Out-Null
icacls $f /grant 'SYSTEM:F' | Out-Null
Restart-Service sshd -ErrorAction SilentlyContinue
