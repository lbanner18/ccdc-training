#!/usr/bin/env bash
set -u

# triage.sh - the first thing you run, and the only one that RANKS.
#
# recon.sh and hunt.sh collect superbly and judge nothing. On the lab box they
# produced 5,359 lines across 22 files, and a real operator working the correct
# sequence found 1 of 3 planted footholds: the one he opened a file to read
# directly. The UID-0 account was one unremarkable row among 105. The
# /dev/tcp reverse shell in /etc/cron.d was line 53 of 4,008.
#
# Nobody reads 4,000 lines while the clock runs. So this does not collect
# anything new - it asks a short list of questions whose answers are almost
# never innocent, and prints only the answers that were not.
#
#   ./triage.sh --config FILE           everything below, ranked
#   ./triage.sh --config FILE --quiet   findings only, no "clean" lines
#
# READ-ONLY. Safe to run first, safe to run often, safe to run while panicking.
#
# The bar for a check appearing here is: when it fires on a competition box, it
# is wrong far more often than it is fine. A triage tool that cries wolf gets
# ignored by hour two, and then it is worth less than nothing, because you will
# believe you checked.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
quiet=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --quiet) quiet=1; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--quiet]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

findings=0
checks=0

# Severity is about what it means, not how the check is written:
#   RED    - this is an intrusion until proven otherwise. Act now.
#   AMBER  - legitimate on some boxes, so look, but do not assume.
red()   { findings=$((findings + 1)); printf '\n  \033[1;31mRED\033[0m    %s\n' "$1"; }
amber() { findings=$((findings + 1)); printf '\n  \033[1;33mAMBER\033[0m  %s\n' "$1"; }
detail(){ printf '         %s\n' "$1"; }
clean() { [ "$quiet" -eq 1 ] || printf '  ok     %s\n' "$1"; }
begin() { checks=$((checks + 1)); }

printf 'triage.sh - what should alarm you on %s, right now\n' "${CCDC_BOX_NAME:-this box}"
printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- 1. UID 0 accounts that are not root -------------------------------------
# The cheapest persistent root there is, and invisible in `who`, `sudo -l` and
# every "check for new users" habit that looks at UID >= 1000.
begin
uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
if [ -n "$uid0" ]; then
  red "account(s) with UID 0 other than root - this IS root access"
  for u in $uid0; do
    detail "$(grep "^$u:" /etc/passwd)"
  done
  detail "fix: userdel -r <name>  (confirm against the packet first)"
else
  clean "no UID-0 accounts besides root"
fi

# --- 2. Accounts with no password --------------------------------------------
begin
if [ -r /etc/shadow ]; then
  empty=$(awk -F: '($2=="" ) {print $1}' /etc/shadow 2>/dev/null)
  if [ -n "$empty" ]; then
    red "account(s) with an EMPTY password: $(printf '%s' "$empty" | tr '\n' ' ')"
    detail "anyone who can reach a login prompt is already in"
  else
    clean "no empty-password accounts"
  fi
else
  clean "/etc/shadow unreadable (run with sudo for the password checks)"
fi

# --- 3. SSH authorized_keys ---------------------------------------------------
# Never "clean": every key is access, so every key has to be one you recognise.
# The operator who found this one in the drill found it because he opened the
# file. This makes opening the file unnecessary.
begin
keyfiles=$(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null)
if [ -n "$keyfiles" ]; then
  total=0
  for f in $keyfiles; do
    n=$(grep -c '^[^#]' "$f" 2>/dev/null || printf '0')
    [ "$n" -gt 0 ] && total=$((total + n))
  done
  if [ "$total" -gt 0 ]; then
    amber "$total SSH key(s) grant login. Recognise EVERY one or remove it"
    for f in $keyfiles; do
      while IFS= read -r k; do
        [ -n "$k" ] || continue
        detail "$(printf '%s' "$f"): ...$(printf '%s' "$k" | tail -c 45)"
      done <<EOF
$(grep '^[^#]' "$f" 2>/dev/null)
EOF
    done
  else
    clean "no SSH authorized_keys entries"
  fi
else
  clean "no authorized_keys files"
fi

# --- 4. Scheduled jobs that call home ----------------------------------------
# Not "is there a cron entry" - there are always cron entries, and that is why
# the real one hid in 4,008 lines. This asks whether a scheduled job contains
# the shapes that only ever mean a shell.
begin
shells='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat'
cronhits=$(grep -rIlE "$shells" /etc/cron.d /etc/cron.daily /etc/cron.hourly \
  /etc/cron.weekly /etc/cron.monthly /etc/crontab /var/spool/cron 2>/dev/null)
if [ -n "$cronhits" ]; then
  red "scheduled job(s) containing reverse-shell or download-and-run patterns"
  for f in $cronhits; do
    detail "$f"
    while IFS= read -r l; do
      detail "    $(printf '%s' "$l" | cut -c1-96)"
    done <<EOF
$(grep -IhE "$shells" "$f" 2>/dev/null | head -3)
EOF
  done
else
  clean "no scheduled job matches a reverse-shell pattern"
fi

# --- 5. systemd units that call home -----------------------------------------
begin
unithits=$(grep -rIlE "$shells" /etc/systemd/system /run/systemd/system 2>/dev/null)
if [ -n "$unithits" ]; then
  red "systemd unit(s) containing reverse-shell or download-and-run patterns"
  for f in $unithits; do detail "$f"; done
else
  clean "no systemd unit matches a reverse-shell pattern"
fi

# Units executing out of a world-writable directory are a separate tell: the
# path is the finding, whatever the command looks like.
begin
tmpunits=$(grep -rIlE '^Exec[A-Za-z]*=.*(/tmp/|/var/tmp/|/dev/shm/)' \
  /etc/systemd/system /run/systemd/system 2>/dev/null)
if [ -n "$tmpunits" ]; then
  red "systemd unit(s) executing from a world-writable directory"
  for f in $tmpunits; do detail "$f"; done
else
  clean "no systemd unit executes from /tmp, /var/tmp or /dev/shm"
fi

# --- 6. Passwordless sudo -----------------------------------------------------
begin
nopw=$(grep -rIh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$')
if [ -n "$nopw" ]; then
  amber "passwordless sudo is configured - confirm each line is the packet's"
  while IFS= read -r l; do detail "$(printf '%s' "$l" | cut -c1-96)"; done <<EOF
$nopw
EOF
else
  clean "no NOPASSWD sudo rules"
fi

# --- 7. SUID interpreters -----------------------------------------------------
# A SUID shell or scripting language is not a configuration choice anyone makes.
# Distinguished from the general SUID list, which is long and mostly legitimate
# and therefore unreadable - which is how a SUID bash hides in it.
begin
suid=$(find / -xdev -perm -4000 -type f 2>/dev/null \
  | grep -E '/(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|awk|find|vim?|nano|less|more|tar|cp|env|node)$')
if [ -n "$suid" ]; then
  red "SUID interpreter(s)/utilities - instant root for any local user"
  for f in $suid; do detail "$(ls -l "$f" 2>/dev/null)"; done
else
  clean "no SUID shells or interpreters"
fi

# --- 8. Processes running from a world-writable directory ---------------------
begin
tmpproc=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/' | head -10)
if [ -n "$tmpproc" ]; then
  red "process(es) executing from /tmp, /var/tmp or /dev/shm"
  while IFS= read -r l; do detail "$(printf '%s' "$l" | cut -c1-110)"; done <<EOF
$tmpproc
EOF
else
  clean "no process runs from a world-writable directory"
fi

# Deleted-on-disk executables: the classic "drop it, run it, unlink it" so the
# payload exists only in memory and hunt.sh's file sweeps cannot see it.
begin
deleted=$(ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | grep -vE '/(systemd|dbus)' | head -5)
if [ -n "$deleted" ]; then
  amber "process(es) whose executable was deleted from disk"
  detail "sometimes a mid-upgrade daemon, sometimes a payload that unlinked itself"
  while IFS= read -r l; do detail "$(printf '%s' "$l" | cut -c1-110)"; done <<EOF
$deleted
EOF
else
  clean "no running process has a deleted executable"
fi

# --- 9. Listeners the packet does not account for -----------------------------
begin
if ccdc_have ss && [ -n "${CCDC_ALLOWED_TCP_PORTS:-}" ]; then
  unexpected=''
  # Loopback-only listeners are excluded deliberately. The standard this check
  # enforces is "nothing but scored services should show on an nmap scan", and
  # a socket bound to 127.0.0.x or ::1 shows on no scan from anywhere. Leaving
  # them in flagged systemd-resolved's 127.0.0.53:53 on every run, and a check
  # that is wrong on a stock box every time is a check you stop reading.
  while IFS= read -r port; do
    [ -n "$port" ] || continue
    ccdc_list_contains "$port" "${CCDC_ALLOWED_TCP_PORTS:-}" || unexpected="$unexpected $port"
  done <<EOF
$(ss -tlnH 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\]|::1)/ {print $4}' | sed 's/.*://' | sort -un)
EOF
  if [ -n "$unexpected" ]; then
    amber "listening TCP port(s) not in CCDC_ALLOWED_TCP_PORTS:$unexpected"
    detail "\"nothing but scored services should show on an nmap scan\""
    for p in $unexpected; do
      detail "$(ss -tlnpH "sport = :$p" 2>/dev/null | head -1 | cut -c1-100)"
    done
  else
    clean "no unexpected listening TCP ports"
  fi
else
  clean "port check skipped (need ss + CCDC_ALLOWED_TCP_PORTS)"
fi

# --- 10. Very recently modified /etc ------------------------------------------
# Last, and only AMBER, because early in an event most hits are yours. It earns
# its place later, when you know you changed nothing in the last ten minutes.
begin
recent=$(find /etc -xdev -type f -mmin -30 2>/dev/null | grep -vE '/(mtab|resolv.conf|adjtime|.*\.lock)$' | head -8)
if [ -n "$recent" ]; then
  amber "/etc file(s) modified in the last 30 minutes"
  detail "if you did not change these, someone else did"
  for f in $recent; do detail "$(date -r "$f" '+%H:%M') $f"; done
else
  clean "no /etc changes in the last 30 minutes"
fi

# --- verdict ------------------------------------------------------------------

printf '\n'
if [ "$findings" -eq 0 ]; then
  printf '  %s checks, nothing flagged.\n\n' "$checks"
  printf '  This is NOT "the box is clean". It means the high-confidence checks\n'
  printf '  found nothing. A competent attacker who is already root can pass all\n'
  printf '  of them. Keep watch.sh running and keep reading hunt.sh.\n'
else
  printf '  %s checks, %s finding(s) above.\n\n' "$checks" "$findings"
  printf '  Work RED first. For each one, find the way back in as well as the\n'
  printf '  artifact - an added user, a key, a cron entry, a unit - or you will\n'
  printf '  clean it up and meet it again in ten minutes.\n'
  printf '  Write down what you found and when. That is the incident-report\n'
  printf '  inject, already half-composed.\n'
fi
printf '\n  Full detail, if you want it: ./linux/hunt.sh and ./linux/recon.sh\n'
[ "$findings" -gt 0 ] && exit 3
exit 0
