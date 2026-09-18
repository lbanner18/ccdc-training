# Runs once, at first logon, from the answer-file media (A:\).
# LAB ONLY: authorises the lab host's SSH key for Administrator so the box can
# be driven without typing a password into a console window.
$ErrorActionPreference = 'Continue'
$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPXtmppH9a4KgcSMGClHIHaujofeEsoedDmHC2CUSCqC banneluk@luke-banner-homelab'
$f = 'C:\ProgramData\ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Path 'C:\ProgramData\ssh' -Force | Out-Null
Set-Content -LiteralPath $f -Value $key -Encoding ascii
# OpenSSH refuses to use this file unless only Administrators and SYSTEM can write it.
icacls $f /inheritance:r | Out-Null
icacls $f /grant 'Administrators:F' | Out-Null
icacls $f /grant 'SYSTEM:F' | Out-Null
Restart-Service sshd -ErrorAction SilentlyContinue
