#!/usr/bin/env bash
set -u

# The tryout packet's environment, 2026-09-26: Ubuntu 18.04 (iron), Rocky 9
# with Splunk (redstone), a Server 2016 domain controller (lapis), a VyOS
# router, ten scored accounts on one published default password.
#
# Every assertion here is something that went wrong on a replica of that
# environment built from the packet, and is run against the real code: the
# password generator and parser, fw.sh's generated rules, and the triage
# patterns and functions lifted out of the scripts themselves.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

work=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-packet-test.XXXXXX") || exit 1
case "$work" in /tmp/ccdc-packet-test.*|"${TMPDIR:-/tmp}"/ccdc-packet-test.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$work"' EXIT INT TERM HUP
pw="$ROOT/linux/passwords.sh"
tr_="$ROOT/linux/triage.sh"
users="steve alex enderman creeper villager zombie enderdragon irongolem chickenjockey ghast"

# --- passwords.sh --generate ------------------------------------------------------
"$pw" --generate --users "$users" >"$work/sheet" 2>&1
sed -n '/^===== 1/,/^$/p' "$work/sheet" | grep ',' >"$work/block"
bad_shape=$(grep -cvE '^[a-z]+,[A-HJ-NP-Za-km-z2-9]{4}(-[A-HJ-NP-Za-km-z2-9]{4}){3}$' "$work/block")
weak=0
while IFS=, read -r u p; do
  case "$p" in *[A-Z]*) ;; *) weak=$((weak + 1)); continue ;; esac
  case "$p" in *[a-z]*) ;; *) weak=$((weak + 1)); continue ;; esac
  case "$p" in *[0-9]*) ;; *) weak=$((weak + 1)); continue ;; esac
done <"$work/block"
if [ "$(wc -l <"$work/block")" -eq 10 ] && [ "$bad_shape" -eq 0 ] && [ "$weak" -eq 0 ] &&
   [ "$(cut -d, -f2 "$work/block" | sort -u | wc -l)" -eq 10 ]; then
  ok 'the generated Quotient block is one user,password line per account: 19 unambiguous characters, all classes, all different'
else
  no "the generated Quotient block is wrong (lines=$(wc -l <"$work/block") bad shape=$bad_shape weak=$weak)"
fi
if grep -q 'passwords.ps1 -Apply' "$work/sheet" && grep -q 'plaintext-password' "$work/sheet" &&
   grep -q 'splunk edit user admin' "$work/sheet" && ! grep -q -- '-Config \$cfg' "$work/sheet"; then
  ok 'the sheet says how to apply it on Linux, Windows, VyOS and Splunk'
else
  no 'the password sheet lost a destination, or prints a Windows command that needs a $cfg nobody set'
fi
if "$pw" --generate --users steve --out "$ROOT/leaked.txt" >/dev/null 2>&1 || [ -e "$ROOT/leaked.txt" ]; then
  rm -f "$ROOT/leaked.txt"
  no 'passwords.sh wrote a password sheet inside the kit - a public repo'
else
  ok 'passwords.sh refuses to write the sheet inside the kit'
fi
"$pw" --generate --users steve --out "$work/sheet2" >/dev/null 2>&1
if [ "$(stat -c %a "$work/sheet2" 2>/dev/null)" = 600 ]; then
  ok 'the sheet written outside the kit is mode 600'
else
  no "the sheet outside the kit is mode $(stat -c %a "$work/sheet2" 2>/dev/null)"
fi

# --- passwords.sh reading a block (check mode: changes nothing, needs no root) ---
me=$(id -un)
printf 'CCDC_EVIDENCE_DIR="%s/ev"\nCCDC_PACKET_PASSWORD="Packet-Default-9x!"\n' "$work" >"$work/cfg"
printf '%s,Ab3d-Ef4h-Jk5m-Np6q\nroot,Qr7s-Tu8v-Wx9y-Za2b\n' "$me" >"$work/good"
out=$("$pw" --config "$work/cfg" <"$work/good" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'reads cleanly: 2 account' && printf '%s' "$out" | grep -q 'Nothing was changed'; then
  ok 'a clean block is read and nothing changes without --apply'
else
  no "a clean block was not accepted (rc=$rc): $(printf '%s' "$out" | head -2)"
fi
printf '%s,Ab3d-Ef4h-Jk5m-Np6q\n%s,Ab3d-Ef4h-Jk5m-Np6q\nnosuchuser1,Ab3d-Ef4h-Jk5m-Np6q\nroot,short\nroot,Packet-Default-9x!\nroot Ab3d,x\na,b,c\n' "$me" "$me" >"$work/bad"
out=$("$pw" --config "$work/cfg" --apply <"$work/bad" 2>&1); rc=$?
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'Nothing was changed' &&
   printf '%s' "$out" | grep -q 'line 2: .* appears twice' &&
   printf '%s' "$out" | grep -q "line 3: there is no account 'nosuchuser1'" &&
   printf '%s' "$out" | grep -q 'line 4: .* minimum' &&
   printf '%s' "$out" | grep -q "line 5: .*packet's default password" &&
   printf '%s' "$out" | grep -q 'line 6: contains a space' &&
   printf '%s' "$out" | grep -q 'line 7: more than one comma' &&
   ! printf '%s' "$out" | grep -q 'SETTING'; then
  ok 'a bad block is refused whole, every bad line named, before root is even needed'
else
  no "a bad block was not refused line by line (rc=$rc): $(printf '%s' "$out" | head -3 | tr '\n' ' ')"
fi

# --- fw.sh: FTP keeps working through the firewall ---------------------------------
# A drop policy with 21 open passes the login and drops the listing; measured
# on the 18.04 replica, the passive LIST timed out until the helper was added.
fwc() { printf 'CCDC_EVIDENCE_DIR="%s/fw"\nCCDC_ALLOWED_TCP_PORTS="%s"\nCCDC_FIREWALL_BACKEND="%s"\n%s\n' "$work" "$1" "$2" "${3:-}" >"$work/fw.env"; "$ROOT/linux/fw.sh" --config "$work/fw.env" 2>/dev/null; }
nft21=$(fwc "22 21" nft); nft22=$(fwc "22" nft); nftoff=$(fwc "22 21" nft 'CCDC_FTP_HELPER=0')
if printf '%s' "$nft21" | grep -q 'ct helper set "ftp-standard"' && printf '%s' "$nft21" | grep -q 'type "ftp" protocol tcp' &&
   ! printf '%s' "$nft22" | grep -q 'ct helper' && ! printf '%s' "$nftoff" | grep -q 'ct helper'; then
  ok 'fw.sh (nft) attaches the FTP helper exactly when port 21 is allowed, and CCDC_FTP_HELPER=0 turns it off'
else
  no 'fw.sh (nft) lost the FTP helper, or adds it when 21 is not allowed'
fi
ipt21=$(fwc "22 21" iptables); ipt22=$(fwc "22" iptables)
if printf '%s' "$ipt21" | grep -q -- '-A PREROUTING -p tcp --dport 21 -j CT --helper ftp' &&
   printf '%s' "$ipt21" | grep -q '^\*raw' && ! printf '%s' "$ipt22" | grep -q -- '--helper ftp'; then
  ok 'fw.sh (iptables) attaches the FTP helper in the raw table, and names that table so a rollback clears it'
else
  no 'fw.sh (iptables) lost the raw-table FTP helper'
fi
if grep -q 'ip6tables-restore <"\$snapshot6"' "$ROOT/linux/fw.sh" && grep -q 'rules6' "$ROOT/linux/fw.sh" &&
   grep -q 'ipt_complete_snapshot' "$ROOT/linux/fw.sh"; then
  ok 'fw.sh (iptables) manages IPv6 with ip6tables instead of refusing, and snapshots every table it writes'
else
  no 'fw.sh (iptables) no longer manages IPv6 - Ubuntu 18.04 has no nft, so it would refuse there again'
fi
if grep -q 'backend=firewalld' "$ROOT/linux/fw.sh" && grep -q -- '--add-service=ftp' "$ROOT/linux/fw.sh" &&
   grep -q 'fwd_restore' "$ROOT/linux/fw.sh" && grep -q -- '--remove-rich-rule' "$ROOT/linux/fw.sh" &&
   ! grep -q -- '--runtime-to-permanent' "$ROOT/linux/fw.sh"; then
  ok 'fw.sh configures a running firewalld (Rocky) and snapshots without mutating live state'
else
  no 'fw.sh lost its firewalld backend or mutates state during snapshot'
fi

# --- triage: the replica's false alarms -----------------------------------------
# A line ENDING in && continues a condition; it launches nothing. Ubuntu's own
# cloud-image profile script tripped this, RED, on every login-file scan.
eval "$(grep -m1 '^rc_launch=' "$tr_")"
rc_hit() { printf '%s\n' "$1" | grep -qE "$rc_launch"; }
if ! rc_hit '  [ "$a" = "$b" ] &&' && ! rc_hit 'x && y' && rc_hit 'sleep 60 &' && rc_hit '( beacon & )' && rc_hit 'nohup x'; then
  ok 'triage: a line ending in && is a condition, a lone & is a launch'
else
  no 'triage: the start-up file pattern confuses && with backgrounding again'
fi
eval "$(grep -m1 '^rc_patterns=' "$ROOT/linux/sentry.sh")"
if ! printf 'cond &&\n' | grep -qE "$rc_patterns" && printf 'x &\n' | grep -qE "$rc_patterns"; then
  ok 'sentry: its copy of the start-up file pattern agrees'
else
  no "sentry's start-up file pattern still matches &&"
fi
# shutdown, halt and sync "log in" to one command each; every RHEL box has them.
svc_awk=$(grep -m1 "^svcshell=\$(awk -F: " "$tr_" | sed "s/^svcshell=\$(awk -F: '//; s/' \/etc\/passwd.*//")
printf '%s\n' 'shutdown:x:6:0::/sbin:/sbin/shutdown' 'halt:x:7:0::/sbin:/sbin/halt' 'sync:x:5:0::/sbin:/bin/sync' \
  'nobody:x:65534:65534::/:/usr/sbin/nologin' 'www-data:x:33:33::/var/www:/bin/bash' 'mail:x:8:8::/:/usr/bin/python3' >"$work/passwd"
flagged=$(awk -F: "$svc_awk" "$work/passwd" | cut -d: -f1 | tr '\n' ' ')
if [ "$flagged" = 'www-data mail ' ]; then
  ok 'triage: a service account with a real shell is flagged; shutdown, halt and sync are not'
else
  no "triage service-shell check flagged: '$flagged' (want: www-data mail)"
fi
# The package cache: every lookup after the first read the entry before it, so
# a packaged service listening on IPv4 and IPv6 was "unpackaged" the 2nd time.
awk "/^  pkg_cache='\\|'\$/{f=1} f{print} f&&/^  }\$/{exit}" "$tr_" >"$work/pkg.sh"
calls=0
pkg_owns() { calls=$((calls + 1)); case "$1" in /usr/sbin/dovecot|/usr/sbin/sshd) return 0 ;; *) return 1 ;; esac; }
ccdc_have() { command -v "$1" >/dev/null 2>&1 || [ "$1" = dpkg-query ]; }
# shellcheck disable=SC1090
. "$work/pkg.sh"
r=''
for exe in /usr/sbin/sshd /usr/sbin/dovecot /tmp/.implant /usr/sbin/dovecot /usr/sbin/sshd /tmp/.implant; do
  pkg_owned "$exe" && r="${r}Y" || r="${r}n"
done
if [ -s "$work/pkg.sh" ] && [ "$r" = YYnYYn ] && [ "$calls" -eq 3 ]; then
  ok 'triage: the package cache answers a repeat lookup with the SAME program'"'"'s answer'
else
  no "triage package cache: got $r with $calls lookups (want YYnYYn with 3)"
fi
# Splunk's daemons, by exact name under a Splunk tree - nothing else there.
awk '/^splunk_trees=/{f=1} f{print} f&&/^}$/{exit}' "$tr_" >"$work/splunk.sh"
readlink() { case "$1" in /proc/1/exe) printf '/opt/splunk/bin/splunkd' ;; /proc/2/exe) printf '/opt/splunk/bin/mongod-7.0' ;;
  /proc/3/exe) printf '/opt/splunkforwarder/bin/splunkd' ;; /proc/4/exe) printf '/opt/splunk/bin/python3.9' ;;
  /proc/5/exe) printf '/opt/splunk/bin/splunkd (deleted)' ;; /proc/6/exe) printf '/tmp/splunkd' ;; *) return 1 ;; esac; }
CCDC_SPLUNK_HOME=''
# shellcheck disable=SC1090
. "$work/splunk.sh"
r=''
for p in 1 2 3 4 5 6; do splunk_daemon_pid "$p" && r="${r}Y" || r="${r}n"; done
unset -f readlink
if [ "$r" = YYYnnn ]; then
  ok "triage: Splunk's own splunkd and mongod are accounted for; its python, a deleted binary and a lookalike are not"
else
  no "triage Splunk exemption: got $r (want YYYnnn)"
fi

# --- users.sh and discover.sh -------------------------------------------------------
if grep -q 'CCDC_INTERACTIVE_USERS' "$pw" && grep -q 'pkg_file_pristine' "$ROOT/linux/lib/provenance.sh" &&
   grep -q 'case "$f" in /etc/\*) pkg_file_pristine' "$tr_"; then
  ok 'unmodified package files under /etc are the distribution'"'"'s; an edited one is still read'
else
  no 'triage lost the unmodified-package-file rule for start-up files'
fi
awk '/^classify\(\) \{/{f=1} f{print} f&&/^}$/{exit}' "$ROOT/linux/discover.sh" >"$work/classify.sh"
# shellcheck disable=SC1090
. "$work/classify.sh"
got="$(classify ssh.service sshd 22) $(classify apache2.service apache2 80) $(classify vsftpd.service vsftpd 21) $(classify dovecot.service dovecot 110) $(classify named.service named 53) $(classify Splunkd.service '/opt/splunk/bin/mongod-7.0' 8191) $(classify mariadb.service mysqld 3306) $(classify none nc 4444)"
if [ "$got" = 'ssh http ftp mail dns splunk db unknown' ]; then
  ok 'discover.sh names each packet service kind, keeps databases and Splunk local, and leaves a stranger unknown'
else
  no "discover.sh classified: $got"
fi

# --- the hash list: one path per line, and the watchdog takes either -----------
# discover.sh wrote "/etc/ssh/sshd_config /var/www/html/index.html" on one line;
# the watchdog read that as ONE path with a space, exited, and guardian refused
# to arm - measured on the 18.04 replica.
printf 'CCDC_EVIDENCE_DIR="%s/wd"\nCCDC_HASH_FILES="/etc/hostname /etc/hosts"\n' "$work" >"$work/wd1.env"
out1=$(timeout 30 "$ROOT/linux/watchdog.sh" --config "$work/wd1.env" --once 2>&1); rc1=$?
printf 'CCDC_EVIDENCE_DIR="%s/wd"\nCCDC_HASH_FILES="\n/etc/hostname\n/etc/hosts\n"\n' "$work" >"$work/wd2.env"
out2=$(timeout 30 "$ROOT/linux/watchdog.sh" --config "$work/wd2.env" --once 2>&1); rc2=$?
if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && ! printf '%s%s' "$out1" "$out2" | grep -q 'contains whitespace'; then
  ok 'watchdog accepts the hash list on one line or one path per line'
else
  no "watchdog rejected a hash list (one-line rc=$rc1, per-line rc=$rc2): $(printf '%s' "$out1" | head -1)"
fi
if grep -q "printf 'CCDC_HASH_FILES=\"\\\\n%s\\\\n\"\\\\n'" "$ROOT/linux/discover.sh" &&
   grep -q "printf 'CCDC_BACKUP_PATHS=\"\\\\n%s\\\\n\"\\\\n'" "$ROOT/linux/discover.sh"; then
  ok 'discover.sh writes the hash and backup lists one path per line'
else
  no 'discover.sh writes a path list on one line again'
fi

# --- box-specific architectural hardening: SUID, FTP/Apache, and DC checks ----
if grep -q 'pkexec' "$tr_" && grep -E '/\(.*pkexec.*\)\$' "$tr_" >/dev/null; then
  ok 'triage flags pkexec as a dangerous SUID binary (PwnKit CVE-2021-4034)'
else
  no 'triage lost the pkexec SUID detection'
fi

if grep -q 'emit AMBER ftpanon' "$tr_" && grep -q 'anonymous_enable' "$tr_" && grep -q 'apacheindexes' "$tr_" &&
   grep -q 'the listing IS the scored page' "$tr_"; then
  ok 'triage audits vsftpd for anonymous login and Apache for directory indexing'
else
  no 'triage lost the FTP anonymous login or Apache directory indexing audit'
fi

# LDAP signing is the scoring-breaking direction: required, it refuses the plain
# LDAP login the packet scores AD with (measured on a 2016 DC). harden.ps1 must
# not require it unless opted in, and triage must flag it RED when it is on.
if grep -q 'FullSecureChannelProtection' "$ROOT/windows/harden.ps1" &&
   grep -q 'ms-DS-MachineAccountQuota' "$ROOT/windows/harden.ps1" &&
   grep -q "CCDC_ACK_LDAP_SIGNING' -Default '0') -eq '1'" "$ROOT/windows/harden.ps1" &&
   grep -q 'LDAP signing is REQUIRED: plain LDAP logins are refused' "$ROOT/windows/triage.ps1" &&
   grep -q 'dcspooler' "$ROOT/windows/triage.ps1"; then
  ok 'DC hardening (Zerologon, Spooler, MachineAccountQuota) never requires LDAP signing unless opted in, and triage flags it when on'
else
  no 'windows tools can require LDAP signing by default again - that refuses the scored LDAP login'
fi

printf 'packet self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
