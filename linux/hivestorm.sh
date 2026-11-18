#!/usr/bin/env bash
# hivestorm.sh - the image-scoring checklist (HIVESTORM / CyberPatriot style).
#
# READ-ONLY. It changes nothing: every FAIL prints the command that fixes it,
# and you paste the ones the README allows. triage.sh hunts an attacker; this
# hunts the misconfigurations a scoring engine plants and checks for.
#
#   sudo ./linux/hivestorm.sh [--config FILE]
#
# With --config it reads CCDC_ALLOWED_USERS / CCDC_ALLOWED_ADMINS /
# CCDC_SYSTEMD_SERVICES so it does not flag what the README requires.
# Exit: 0 nothing failed, 3 something to fix.

set -u
cfg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --config) cfg=${2:-}; shift 2 || shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || echo "(not root: some checks will be skipped - run with sudo)" >&2

# Read KEY="value" from the config without executing it.
cfgval() {
  [ -n "$cfg" ] && [ -r "$cfg" ] || return 0
  sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" "$cfg" | tail -1
}
ALLOWED_USERS=$(cfgval CCDC_ALLOWED_USERS)
ALLOWED_ADMINS=$(cfgval CCDC_ALLOWED_ADMINS); [ -n "$ALLOWED_ADMINS" ] || ALLOWED_ADMINS=$ALLOWED_USERS
REQUIRED=$(cfgval CCDC_SYSTEMD_SERVICES)" "$(cfgval CCDC_PROTECT_SERVICES)
inlist() { local n=$1 x; for x in $2; do [ "$x" = "$n" ] && return 0; done; return 1; }

fails=0
R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; D=$'\033[2m'; N=$'\033[0m'
fail() { fails=$((fails+1)); printf '%s[FAIL]%s %s\n' "$R" "$N" "$1"; shift; for f in "$@"; do printf '       %s%s%s\n' "$D" "$f" "$N"; done; }
warn() { printf '%s[LOOK]%s %s\n' "$Y" "$N" "$1"; shift; for f in "$@"; do printf '       %s%s%s\n' "$D" "$f" "$N"; done; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$1"; }
sec()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

echo "Forensic questions FIRST: anything below you delete may be an answer."

# ---------------------------------------------------------------------------
sec "accounts"
uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
[ -z "$uid0" ] && ok "only root has UID 0" || for u in $uid0; do fail "$u has UID 0 (a hidden root)" "sudo userdel $u   # or: sudo usermod -u <free uid> $u"; done

if [ -r /etc/shadow ]; then
  empty=$(awk -F: '$2==""{print $1}' /etc/shadow)
  [ -z "$empty" ] && ok "no account has an empty password" || for u in $empty; do fail "$u has an EMPTY password" "sudo passwd $u"; done
  if awk -F: '$1=="root"{exit ($2 ~ /^[!*]/)?0:1}' /etc/shadow; then ok "root password is locked"
  else fail "root can log in with a password" "sudo passwd -l root"; fi
fi

humans=$(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd)
if [ -n "$ALLOWED_USERS" ]; then
  for u in $humans; do inlist "$u" "$ALLOWED_USERS" || fail "$u is not in the README (CCDC_ALLOWED_USERS)" "sudo deluser $u   # check forensics first; --remove-home only if no question needs it"; done
else
  warn "no --config: these are the human accounts, compare with the README" "$(echo $humans)"
fi
for g in sudo admin wheel; do
  mem=$(getent group "$g" | cut -d: -f4 | tr ',' ' ')
  for u in $mem; do
    if [ -n "$ALLOWED_ADMINS" ] && ! inlist "$u" "$ALLOWED_ADMINS"; then
      fail "$u is in group $g but is not a README admin" "sudo gpasswd -d $u $g"
    fi
  done
done
[ -n "$ALLOWED_ADMINS" ] && ok "group check done against: $ALLOWED_ADMINS"

if [ -r /etc/sudoers ]; then
  bad=$(grep -rhsE '^[^#].*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
  [ -z "$bad" ] && ok "no NOPASSWD / !authenticate in sudoers" || fail "sudoers lets someone skip the password:" "$bad" "sudo visudo   # and files in /etc/sudoers.d/"
fi

# ---------------------------------------------------------------------------
sec "password policy"
ld() { awk -v k="$1" '$1==k{v=$2} END{print v}' /etc/login.defs 2>/dev/null; }
mx=$(ld PASS_MAX_DAYS); mn=$(ld PASS_MIN_DAYS); wa=$(ld PASS_WARN_AGE)
[ -n "$mx" ] && [ "$mx" -le 90 ] 2>/dev/null && ok "PASS_MAX_DAYS $mx" || fail "PASS_MAX_DAYS is ${mx:-unset} (want 90)" "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
[ -n "$mn" ] && [ "$mn" -ge 1 ] 2>/dev/null && ok "PASS_MIN_DAYS $mn" || fail "PASS_MIN_DAYS is ${mn:-unset} (want 1+)" "sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs"
[ -n "$wa" ] && [ "$wa" -ge 7 ] 2>/dev/null && ok "PASS_WARN_AGE $wa" || fail "PASS_WARN_AGE is ${wa:-unset} (want 7+)" "sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs"
pam=/etc/pam.d/common-password; [ -f "$pam" ] || pam=/etc/pam.d/system-auth
if [ -f "$pam" ]; then
  grep -qE 'pam_(pwquality|cracklib)' "$pam" && ok "password complexity module in $pam" \
    || fail "no pam_pwquality in $pam" "sudo apt -y install libpam-pwquality   # then policy.sh prints the line"
  grep -qE 'remember=[0-9]' "$pam" && ok "password history (remember=) set" \
    || fail "no password history (remember=N) in $pam" "add  remember=5  to the pam_unix.so line in $pam"
  grep -q nullok "$pam" && fail "nullok in $pam: empty passwords accepted" "sudo sed -i 's/ nullok//' $pam"
  grep -qsE 'pam_(faillock|tally2)' /etc/pam.d/common-auth /etc/pam.d/system-auth && ok "account lockout module present" \
    || fail "no account lockout (pam_faillock)" "sudo ./linux/policy.sh --config \$CFG   # prints the faillock lines"
fi
q=/etc/security/pwquality.conf
if [ -f "$q" ]; then
  ml=$(sed -n 's/^\s*minlen\s*=\s*\([0-9]*\).*/\1/p' "$q" | tail -1)
  [ -n "$ml" ] && [ "$ml" -ge 10 ] && ok "pwquality minlen $ml" || fail "pwquality minlen is ${ml:-unset}" "echo 'minlen = 12' | sudo tee -a $q; printf 'ucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n' | sudo tee -a $q"
fi

# ---------------------------------------------------------------------------
sec "firewall, ssh, kernel"
if command -v ufw >/dev/null; then
  ufw status 2>/dev/null | grep -q 'Status: active' && ok "ufw is active" || fail "ufw is not active" "sudo ufw allow <README ports>; sudo ufw enable"
fi
if command -v sshd >/dev/null; then
  t=$(sshd -T 2>/dev/null)
  chk() { echo "$t" | grep -qi "^$1 $2\$" && ok "sshd $1 $2" || fail "sshd $1 is not $2" "echo '$1 $2' | sudo tee -a /etc/ssh/sshd_config.d/50-hive.conf; sudo systemctl reload ssh"; }
  if [ -n "$t" ]; then
    chk permitrootlogin no; chk permitemptypasswords no; chk x11forwarding no
  fi
fi
sc() { local v; v=$(sysctl -n "$1" 2>/dev/null) || return 0
  [ "$v" = "$2" ] && ok "$1 = $v" || fail "$1 = $v (want $2)" "echo '$1 = $2' | sudo tee -a /etc/sysctl.d/99-hive.conf && sudo sysctl -p /etc/sysctl.d/99-hive.conf"; }
sc net.ipv4.tcp_syncookies 1
sc net.ipv4.ip_forward 0
sc net.ipv4.conf.all.accept_redirects 0
sc net.ipv4.conf.all.send_redirects 0
sc net.ipv4.conf.all.accept_source_route 0
sc net.ipv4.icmp_echo_ignore_broadcasts 1
sc kernel.randomize_va_space 2

# ---------------------------------------------------------------------------
sec "file permissions"
pm() { [ -e "$1" ] || return 0; local m; m=$(stat -c %a "$1")
  [ "$m" -le "$2" ] 2>/dev/null && ok "$1 is $m" || fail "$1 is $m (want $2 or tighter)" "sudo chmod $2 $1"; }
pm /etc/shadow 640; pm /etc/gshadow 640; pm /etc/passwd 644; pm /etc/group 644
pm /etc/sudoers 440; pm /etc/ssh/sshd_config 644; pm /boot/grub/grub.cfg 600
ww=$(find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -10)
[ -z "$ww" ] && ok "no world-writable files in /etc or the bin dirs" || fail "world-writable system files:" $ww "sudo chmod o-w <file>"

# ---------------------------------------------------------------------------
sec "display manager"
for f in /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
  [ -f "$f" ] || continue
  grep -qiE '^\s*allow-guest\s*=\s*false' "$f" && ok "guest disabled in $f"
  grep -qiE '^\s*autologin-user\s*=\s*\S' "$f" && fail "autologin set in $f" "sudo sed -i 's/^\s*autologin-user.*/#&/' $f"
done
if [ -d /etc/lightdm ] && ! grep -rqisE '^\s*allow-guest\s*=\s*false' /etc/lightdm /usr/share/lightdm 2>/dev/null; then
  fail "lightdm guest account not disabled" "printf '[Seat:*]\nallow-guest=false\n' | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf"
fi
g=/etc/gdm3/custom.conf
[ -f "$g" ] && grep -qiE '^\s*AutomaticLoginEnable\s*=\s*true' "$g" && fail "GDM automatic login is on" "sudo sed -i 's/^\s*AutomaticLoginEnable.*/AutomaticLoginEnable=false/' $g"

# ---------------------------------------------------------------------------
sec "software"
tools="john hydra nmap zenmap wireshark tshark ophcrack aircrack-ng nikto netcat netcat-traditional netcat-openbsd ncat medusa sqlmap kismet ettercap-common ettercap-graphical dsniff hashcat crack fcrackzip deluge transmission-gtk transmission-daemon qbittorrent frostwire vuze freeciv minetest"
if command -v dpkg-query >/dev/null; then
  found=$(dpkg-query -W -f='${Package} ${Status}\n' $tools 2>/dev/null | awk '/install ok installed/{print $1}')
  [ -z "$found" ] && ok "no hacking tools / games / torrent clients from the list" \
    || fail "installed and likely banned: $(echo $found)" "sudo apt -y purge $(echo $found)   # netcat-openbsd may be a dependency: read apt's removal list"
fi
risky="telnetd inetutils-telnetd telnet rsh-server vsftpd pure-ftpd proftpd-basic tftpd-hpa nfs-kernel-server samba snmpd apache2 nginx bind9 postfix dovecot-core avahi-daemon cups xinetd"
if command -v dpkg-query >/dev/null; then
  for p in $(dpkg-query -W -f='${Package} ${Status}\n' $risky 2>/dev/null | awk '/install ok installed/{print $1}'); do
    inlist "$p" "$REQUIRED" && continue
    warn "$p is installed - remove it ONLY if the README does not require it" "sudo apt -y purge $p"
  done
fi
if [ -f /etc/vsftpd.conf ]; then
  grep -qiE '^\s*anonymous_enable\s*=\s*YES' /etc/vsftpd.conf && fail "vsftpd allows anonymous login" "sudo sed -i 's/^\s*anonymous_enable.*/anonymous_enable=NO/' /etc/vsftpd.conf; sudo systemctl restart vsftpd"
fi
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
  ok "automatic updates on"
elif command -v apt-get >/dev/null; then
  fail "automatic updates are off" "printf 'APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades"
fi
grep -rhsE '^\s*deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vE 'ubuntu.com|debian.org|canonical.com' \
  | while read -r l; do warn "non-standard apt source: $l" "check it; comment it out if the README does not explain it"; done

# ---------------------------------------------------------------------------
sec "files and scheduled jobs (forensics FIRST)"
media=$(find /home /root /srv /var/www /opt -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.m4a' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.wmv' -o -iname '*.jpg' -o -iname '*.png' -o -iname '*.gif' \) 2>/dev/null | grep -v '/\.cache/\|/\.local/share/icons\|/\.mozilla/\|/snap/' | head -30)
[ -z "$media" ] && ok "no media files under /home /root /srv /var/www /opt" || warn "media files (banned media scores; pictures may be forensics):" $media "sudo rm '<file>'"
for u in $(cut -d: -f1 /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')
  [ -n "$c" ] && warn "crontab of $u:" "$c" "sudo crontab -e -u $u"
done
other=$(grep -rhsvE '^\s*(#|$|SHELL|PATH|MAILTO)' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -vE 'run-parts|e2scrub|popularity-contest|anacron|sysstat|php|certbot')
[ -n "$other" ] && warn "system cron lines worth a read:" "$other"
for d in /etc/rc.local; do [ -s "$d" ] && grep -vqE '^\s*(#|$|exit 0)' "$d" && warn "$d has commands" "cat $d"; done

printf '\n'
if [ "$fails" -gt 0 ]; then printf '%s%d FAIL%s - paste the fixes the README allows, then re-run.\n' "$R" "$fails" "$N"; exit 3; fi
printf '%sno FAIL%s - now the [LOOK] lines, by hand.\n' "$G" "$N"
