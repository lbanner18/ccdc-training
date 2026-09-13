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
sudoers_file=/etc/sudoers.d/rt-lab
service_home=/var/lib/rtsvc
web_probe=/var/www/html/.rt-health.jsp
plant_failures=0

plant() { printf '  planted: %s\n' "$1"; printf '%s\n' "$1" >>"$manifest"; }
plant_failed() { printf '  FAILED:  %s\n' "$1" >&2; plant_failures=$((plant_failures+1)); }

if [ "${1:-}" = "--clean" ]; then
  echo "[*] removing lab plants"
  systemctl disable --now rt-backdoor.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/rt-backdoor.service /etc/systemd/system/rt-backdoor.timer
  systemctl daemon-reload
  crontab -l 2>/dev/null | grep -v "$MARK" | crontab - 2>/dev/null || true
  rm -f /etc/cron.d/rt-cron /etc/profile.d/rt-profile.sh "$sudoers_file" "$web_probe"
  sed -i "/$MARK/d" /root/.bashrc 2>/dev/null || true
  userdel -r rtsvc 2>/dev/null || true
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
if id rtsvc >/dev/null 2>&1; then
  plant_failed "user:rtsvc already exists; refusing to modify an unowned lab account"
elif useradd -m -d "$service_home" -s /bin/bash rtsvc 2>/dev/null \
  && printf '%s\n' 'rtsvc:Sup3rSecret!' | chpasswd \
  && id rtsvc >/dev/null 2>&1; then
  plant "user:rtsvc|home=$service_home|uid=$(id -u rtsvc)"
else
  passwd -l rtsvc >/dev/null 2>&1 || true
  plant_failed "user:rtsvc"
fi

# 2. Sudoers drop-in - passwordless root for the rogue user.
sudoers_staged="${sudoers_file}.new.$$"
if printf '%s\n' "rtsvc ALL=(ALL) NOPASSWD:ALL # $MARK" >"$sudoers_staged" \
  && chmod 0440 "$sudoers_staged" \
  && visudo -cf "$sudoers_staged" >/dev/null 2>&1 \
  && mv -f "$sudoers_staged" "$sudoers_file" \
  && visudo -c >/dev/null 2>&1; then
  plant "sudoers:$sudoers_file|rtsvc NOPASSWD:ALL"
else
  rm -f "$sudoers_staged"
  plant_failed "sudoers:$sudoers_file"
fi

# 3. Extra key in a service-account home outside /home. This is where a sweep
# hard-coded to /root and /home/* used to miss it.
if mkdir -p "$service_home/.ssh" \
  && chmod 0700 "$service_home/.ssh" \
  && printf '%s\n' "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILABPLANTdummykeyforhuntdetection $MARK" >>"$service_home/.ssh/authorized_keys" \
  && chmod 0600 "$service_home/.ssh/authorized_keys"; then
  chown -R rtsvc:rtsvc "$service_home/.ssh" 2>/dev/null || true
  plant "ssh-key:$service_home/.ssh/authorized_keys|signature=LABPLANT"
else
  plant_failed "ssh-key:$service_home/.ssh/authorized_keys"
fi

# 4. The harmless implant stand-in is installed before schedulers reference it.
implant_staged=/usr/local/bin/rt-implant.new.$$
if { printf '%s\n' '#!/bin/sh' "# $MARK harmless beacon stand-in" ':' >"$implant_staged"; } \
  && chmod 0755 "$implant_staged" \
  && mv -f "$implant_staged" /usr/local/bin/rt-implant \
  && grep -q "$MARK" /usr/local/bin/rt-implant; then
  plant "binary:/usr/local/bin/rt-implant|signature=$MARK"
else
  rm -f "$implant_staged"
  plant_failed "binary:/usr/local/bin/rt-implant"
fi

# 5. Cron persistence (system cron.d).
cron_staged=/etc/cron.d/rt-cron.new.$$
if printf '%s\n' "*/5 * * * * root /usr/local/bin/rt-implant # $MARK" >"$cron_staged" \
  && chmod 0644 "$cron_staged" \
  && mv -f "$cron_staged" /etc/cron.d/rt-cron \
  && grep -q "$MARK" /etc/cron.d/rt-cron; then
  plant "cron-file:/etc/cron.d/rt-cron|signature=$MARK"
else
  rm -f "$cron_staged"
  plant_failed "cron-file:/etc/cron.d/rt-cron"
fi

# 6. Root crontab entry.
if { crontab -l 2>/dev/null; printf '%s\n' "*/10 * * * * /usr/local/bin/rt-implant # $MARK"; } | crontab - \
  && crontab -l 2>/dev/null | grep -q "$MARK"; then
  plant "root-crontab:root|signature=$MARK"
else
  plant_failed "root-crontab:root"
fi

# 7. systemd service + timer (the modern persistence).
unit_stage=$(mktemp -d /tmp/ccdc-plant-units.XXXXXX) \
  || { plant_failed "create systemd staging directory"; unit_stage=''; }
if [ -n "$unit_stage" ]; then
  service_staged="$unit_stage/rt-backdoor.service"
  timer_staged="$unit_stage/rt-backdoor.timer"
  cat >"$service_staged" <<UNIT
[Unit]
Description=System Logging Helper
[Service]
ExecStart=/usr/local/bin/rt-implant
UNIT
  cat >"$timer_staged" <<UNIT
[Unit]
Description=System Logging Helper Timer
[Timer]
OnBootSec=60
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
UNIT
  if systemd-analyze verify "$service_staged" "$timer_staged" >/dev/null 2>&1 \
    && mv -f "$service_staged" /etc/systemd/system/rt-backdoor.service \
    && mv -f "$timer_staged" /etc/systemd/system/rt-backdoor.timer \
    && systemctl daemon-reload \
    && systemctl enable --now rt-backdoor.timer >/dev/null 2>&1 \
    && systemctl is-active --quiet rt-backdoor.timer; then
    rmdir "$unit_stage" 2>/dev/null || true
    plant "systemd-timer:rt-backdoor.timer|description=System Logging Helper"
  else
    rm -f "$service_staged" "$timer_staged"
    rmdir "$unit_stage" 2>/dev/null || true
    plant_failed "systemd-timer:rt-backdoor.timer"
  fi
fi

# 8. Keyword-light profile and bashrc hooks. The marker gives the lab an exact
# cleanup key, but the executable lines themselves contain no suspicious word.
if printf '%s\n' ". /usr/local/lib/.session-env 2>/dev/null || : # $MARK" >/etc/profile.d/rt-profile.sh \
  && chmod 0644 /etc/profile.d/rt-profile.sh; then
  plant "profile:/etc/profile.d/rt-profile.sh|signature=$MARK"
else
  plant_failed "profile:/etc/profile.d/rt-profile.sh"
fi
if sed -i "1i. /usr/local/lib/.session-env 2>/dev/null || : # $MARK lab bashrc hook" /root/.bashrc \
  && head -n 1 /root/.bashrc | grep -q "$MARK"; then
  plant "bashrc:/root/.bashrc|position=first-line|signature=$MARK"
else
  plant_failed "bashrc:/root/.bashrc"
fi

# 9. SUID root shell - privilege-escalation foothold.
if cp /bin/bash /usr/local/bin/rootbash \
  && chmod 4755 /usr/local/bin/rootbash \
  && [ -u /usr/local/bin/rootbash ]; then
  plant "suid:/usr/local/bin/rootbash|mode=4755"
else
  plant_failed "suid:/usr/local/bin/rootbash"
fi

# 10. Payload in /dev/shm (fileless-ish location; it need not execute on noexec).
if cp /usr/local/bin/rt-implant /dev/shm/.rt 2>/dev/null \
  && chmod 0755 /dev/shm/.rt \
  && grep -q "$MARK" /dev/shm/.rt; then
  plant "tmpfile:/dev/shm/.rt|signature=$MARK"
else
  plant_failed "tmpfile:/dev/shm/.rt"
fi

# 11. Non-PHP web foothold, harmless but outside the old extension filter.
if [ -d /var/www/html ]; then
  if printf '%s\n' "<%-- $MARK harmless JSP stand-in --%>" >"$web_probe" \
    && chmod 0644 "$web_probe"; then
    plant "web-file:$web_probe|signature=$MARK"
  else
    plant_failed "web-file:$web_probe"
  fi
else
  printf '  skipped: web-file test (/var/www/html absent)\n'
fi

echo
echo "[*] GROUND TRUTH - $(wc -l <"$manifest") artifacts planted:"
cat "$manifest"
[ "$plant_failures" -eq 0 ] || { echo "[*] $plant_failures plant(s) failed" >&2; exit 1; }
