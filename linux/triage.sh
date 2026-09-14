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

# Print the literal command to run, with this box's real values already in it.
#
# The card reference alone was not enough. Watching a real operator work a
# finding, he typed `sudo remove t-implant` - inventing a command - because the
# actual fix was a sed incantation inside a markdown file he was not looking at
# while the clock ran. A reference tells you where to go read; under pressure
# you need the command under your cursor. So triage now prints it.
#
# Nothing here is destructive-by-surprise: the ordering is lock-then-verify-
# then-remove, exactly as the cards describe, and the irreversible step is
# always last and always after something that shows you what you are about to
# remove.
# No "$" prefix. It looked like a prompt and read nicely - and the operator
# selected the block, pasted it, and got:
#
#     $: command not found
#     $: command not found
#
# because the prompt character came along with the text. Bash strips LEADING
# WHITESPACE from a command line, so an indented command pastes and runs
# exactly as written. The "run this" header above carries the meaning the "$"
# was carrying, without being a character the shell has to reject.
fix() { printf '           %s\n' "$1"; }
fixhdr(){ printf '         ---- run this ----------------------------------------\n'; }
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
  red "account(s) with UID 0 other than root - this IS root access   [CARD 1]"
  for u in $uid0; do
    detail "$(grep "^$u:" /etc/passwd)"
  done
  detail "confirm against the packet first - a scored account can have a bad UID"
  for u in $uid0; do
    fixhdr
    fix "sudo passwd -l $u"
    fix "sudo usermod -s /usr/sbin/nologin $u"
    fix "ps -ef | grep -w $u | grep -v grep      # kill these by PID, NOT by user"
    fix "sudo userdel -f -r $u                   # -f required; warns about PID 1"
  done
  detail "NEVER pkill -u on a UID-0 account: the name resolves to root and you"
  detail "would kill every root process on the box. See CARD 1."
else
  clean "no UID-0 accounts besides root"
fi

# --- 2. Accounts with no password --------------------------------------------
begin
if [ -r /etc/shadow ]; then
  empty=$(awk -F: '($2=="" ) {print $1}' /etc/shadow 2>/dev/null)
  if [ -n "$empty" ]; then
    red "account(s) with an EMPTY password: $(printf '%s' "$empty" | tr '\n' ' ')   [CARD 1]"
    detail "anyone who can reach a login prompt is already in"
    for u in $empty; do
      fixhdr
      fix "sudo passwd -l $u"
      fix "sudo usermod -s /usr/sbin/nologin $u"
      fix "sudo pkill -9 -u $u                     # safe here: this is NOT UID 0"
      fix "sudo userdel -r $u                      # only if the packet says it is not scored"
    done
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
    # `grep -c` PRINTS 0 and EXITS 1 when there are no matches, so a
    # `|| printf 0` fallback appends a second 0 and the test below then dies
    # with "integer expression expected". Check for empty instead.
    n=$(grep -c '^[^#]' "$f" 2>/dev/null)
    [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && total=$((total + n))
  done
  if [ "$total" -gt 0 ]; then
    amber "$total SSH key(s) grant login. Recognise EVERY one or remove it   [CARD 2]"
    for f in $keyfiles; do
      while IFS= read -r k; do
        [ -n "$k" ] || continue
        detail "$(printf '%s' "$f"): ...$(printf '%s' "$k" | tail -c 45)"
        # A ready-to-run deletion for THIS key, matched on the LAST 24 chars
        # of the key body.
        #
        # It must be the tail. The first 24 characters are the algorithm
        # prefix - every ed25519 key begins "AAAAC3NzaC1lZDI1NTE5AAAA" - so a
        # leading slice matches EVERY key of that type and the command would
        # empty the file, locking you out. Caught on the lab box only because
        # the generated command was read before it was run.
        #
        # The | delimiter is also deliberate: base64 contains / and would
        # terminate a /.../ expression early.
        slice=$(printf '%s' "$k" | awk '{print $2}' | tail -c 25 | tr -d '\n')
        [ -n "$slice" ] && fix "sudo cp $f $f.bak && sudo sed -i '\\|$slice|d' $f"
      done <<EOF
$(grep '^[^#]' "$f" 2>/dev/null)
EOF
    done
    detail "delete ONLY the lines you do not recognise - never truncate the file,"
    detail "your own key is probably in it. Keep this session open, then verify:"
    fix "sudo sshd -t && ssh banneluk@\$(hostname -I | awk '{print \$1}')   # from ANOTHER terminal"
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
  red "scheduled job(s) containing reverse-shell or download-and-run patterns   [CARD 3]"
  for f in $cronhits; do
    detail "$f"
    while IFS= read -r l; do
      detail "    $(printf '%s' "$l" | cut -c1-96)"
    done <<EOF
$(grep -IhE "$shells" "$f" 2>/dev/null | head -3)
EOF
    fixhdr
    fix "sudo cp $f /var/tmp/evidence-$(basename "$f")   # keep it, the IR inject wants it"
    fix "sudo rm -f $f"
  done
  detail "then follow what it CALLED - the cron line is the schedule, not the payload:"
  fix "sudo ss -tnp | grep -v 127.0.0.1        # is it connected right now?"
else
  clean "no scheduled job matches a reverse-shell pattern"
fi

# --- 5. systemd units that call home -----------------------------------------
begin
unithits=$(grep -rIlE "$shells" /etc/systemd/system /run/systemd/system 2>/dev/null)
if [ -n "$unithits" ]; then
  red "systemd unit(s) containing reverse-shell or download-and-run patterns   [CARD 4]"
  for f in $unithits; do
    detail "$f"
    u=$(basename "$f")
    fixhdr
    fix "sudo systemctl cat $u                  # read it before you delete it"
    fix "sudo systemctl disable --now $u"
    fix "sudo rm -f $f && sudo rm -rf $f.d      # .d holds drop-in overrides"
    fix "sudo systemctl daemon-reload && sudo systemctl reset-failed"
  done
else
  clean "no systemd unit matches a reverse-shell pattern"
fi

# Units executing out of a world-writable directory are a separate tell: the
# path is the finding, whatever the command looks like.
begin
tmpunits=$(grep -rIlE '^Exec[A-Za-z]*=.*(/tmp/|/var/tmp/|/dev/shm/)' \
  /etc/systemd/system /run/systemd/system 2>/dev/null)
if [ -n "$tmpunits" ]; then
  red "systemd unit(s) executing from a world-writable directory   [CARD 4]"
  for f in $tmpunits; do detail "$f"; done
else
  clean "no systemd unit executes from /tmp, /var/tmp or /dev/shm"
fi

# --- 6. Passwordless sudo -----------------------------------------------------
begin
nopw=$(grep -rIh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$')
if [ -n "$nopw" ]; then
  amber "passwordless sudo is configured - confirm each line is the packet's   [CARD 7]"
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
  red "SUID interpreter(s)/utilities - instant root for any local user   [CARD 5]"
  fixhdr
  for f in $suid; do
    detail "$(ls -l "$f" 2>/dev/null)"
    fix "sudo chmod u-s $f                      # strip SUID; do NOT delete the binary"
  done
else
  clean "no SUID shells or interpreters"
fi

# --- 8. Processes running from a world-writable directory ---------------------
begin
tmpproc=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/' | head -10)
if [ -n "$tmpproc" ]; then
  red "process(es) executing from /tmp, /var/tmp or /dev/shm   [CARD 6]"
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
  amber "process(es) whose executable was deleted from disk   [CARD 6]"
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
    amber "listening TCP port(s) not in CCDC_ALLOWED_TCP_PORTS:$unexpected   [CARD 8]"
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

# --- 9b. Service accounts that have been handed a login shell -----------------
# A system account (UID under 1000) exists to run a daemon; it has no reason to
# have a shell. Granting one is a quiet, durable foothold that survives password
# resets and appears in none of the checks above - not UID 0, not an empty
# password, not a new account at all. Found on the lab box only because the
# operator happened to run the right `getent` by hand.
begin
svcshell=$(awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync)$/ {print $1":"$3":"$7}' /etc/passwd 2>/dev/null)
if [ -n "$svcshell" ]; then
  red "service account(s) with a login shell   [CARD 10]"
  for e in $svcshell; do
    u=${e%%:*}
    detail "$e"
    fixhdr
    fix "sudo usermod -s /usr/sbin/nologin $u"
    fix "sudo pkill -u $u                     # the -u matters: plain 'pkill $u' matches process NAMES"
    fix "sudo crontab -u $u -l; sudo ls -la /home/$u/.ssh/ 2>/dev/null"
  done
  detail "do NOT userdel a service account - it probably owns the scored content."
  detail "take the shell away and leave the account."
else
  clean "no service account has a login shell"
fi

# --- 9c. Who can become root -------------------------------------------------
begin
admins=''
# sudo/wheel/admin grant ROOT. `adm` is deliberately not here: it grants log
# file read access, and `syslog` is in it on every stock Ubuntu, so including it
# made this check fire on a clean box - the exact "cries wolf" failure this
# tool is supposed to avoid.
for g in sudo wheel admin; do
  m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [ -n "$m" ] && admins="$admins $g:$m"
done
suspect=''
for entry in $admins; do
  g=${entry%%:*}
  for m in $(printf '%s' "${entry#*:}" | tr ',' ' '); do
    uid=$(id -u "$m" 2>/dev/null || printf '99999')
    # A SYSTEM account in an admin group is the tell. Human accounts belong
    # there and would only be noise.
    if [ "$uid" -lt 1000 ] 2>/dev/null; then suspect="$suspect $m/$g"; fi
  done
done
if [ -n "$suspect" ]; then
  red "system account(s) in an admin group:$suspect   [CARD 10]"
  fixhdr
  for e in $suspect; do fix "sudo gpasswd -d ${e%%/*} ${e#*/}"; done
else
  clean "no system account is in sudo/wheel/admin"
fi

# --- 9d. Shell start-up files ------------------------------------------------
# .bashrc, .profile and /etc/profile.d run every time anyone gets a shell -
# including you, the next time you `sudo -i`. A hook here is persistence that
# fires on the defender's own hands, and nothing above reads these files.
begin
rchits=''
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/bash.bashrc /etc/profile \
         /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/profile.d/*; do
  [ -f "$f" ] || continue
  grep -qIE "$shells|/usr/local/bin/|/tmp/|/dev/shm/" "$f" 2>/dev/null && rchits="$rchits $f"
done
if [ -n "$rchits" ]; then
  red "shell start-up file(s) launching something   [CARD 11]"
  detail "these run on EVERY login, including your next sudo -i"
  for f in $rchits; do
    detail "$f"
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-90)"; done <<EOF
$(grep -IhE "$shells|/usr/local/bin/|/tmp/|/dev/shm/" "$f" 2>/dev/null | head -3)
EOF
    fixhdr
    fix "sudo cp $f /var/tmp/evidence-$(basename "$f")"
    fix "sudo nano $f      # delete only the offending line, keep the rest"
  done
else
  clean "no shell start-up file launches anything unusual"
fi

# --- 9e. Units whose ExecStart TARGET is malicious ---------------------------
# Check 5 reads the unit. An attacker who puts a clean path in ExecStart and
# hides the payload one level down in that script passes it completely. On the
# lab box net-diag.service pointed at /usr/local/bin/net-diag - an ordinary
# path in an ordinary directory - and the reverse shell was inside the file.
# Following the path IS the check.
begin
deephits=''
for unit in /etc/systemd/system/*.service /run/systemd/system/*.service; do
  [ -f "$unit" ] || continue
  target=$(awk -F= '/^ExecStart=/ {print $2; exit}' "$unit" 2>/dev/null | awk '{print $1}' | sed 's/^[-@+!]*//')
  case "$target" in /*) ;; *) continue ;; esac
  [ -f "$target" ] || continue
  grep -qIE "$shells" "$target" 2>/dev/null && deephits="$deephits $unit|$target"
done
if [ -n "$deephits" ]; then
  red "unit(s) whose ExecStart script contains a reverse shell   [CARD 4]"
  detail "the unit itself looks clean - the payload is one level down"
  for e in $deephits; do
    unit=${e%%|*}; target=${e#*|}; u=$(basename "$unit"); base=${u%.service}
    detail "$u -> $target"
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-90)"; done <<EOF
$(grep -IhE "$shells" "$target" 2>/dev/null | head -2)
EOF
    fixhdr
    fix "sudo systemctl disable --now $base.timer $u"
    fix "sudo cp $target /var/tmp/evidence-$(basename "$target")"
    fix "sudo rm -f $unit /etc/systemd/system/$base.timer $target"
    fix "sudo systemctl daemon-reload && sudo systemctl reset-failed"
  done
else
  clean "no unit's ExecStart script contains a reverse shell"
fi

# --- 10. Very recently modified /etc ------------------------------------------
# Last, and only AMBER, because early in an event most hits are yours. It earns
# its place later, when you know you changed nothing in the last ten minutes.
begin
recent=$(find /etc -xdev -type f -mmin -30 2>/dev/null | grep -vE '/(mtab|resolv.conf|adjtime|.*\.lock)$' | head -8)
if [ -n "$recent" ]; then
  amber "/etc file(s) modified in the last 30 minutes   [CARD 9]"
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
  printf '\n  EXACT COMMANDS for each [CARD n] above:\n'
  printf '      ./linux/card.sh <n> <name-or-path>     e.g. ./linux/card.sh 1 backupsvc\n'
  printf '  Reads the card in this terminal with the real value filled in. Do NOT\n'
  printf '  cat or paste playbooks/remediation-cards.md - it is markdown, and bash\n'
  printf '  will try to execute the prose.\n'
fi
printf '\n  Full detail, if you want it: ./linux/hunt.sh and ./linux/recon.sh\n'
[ "$findings" -gt 0 ] && exit 3
exit 0
