#!/usr/bin/env bash
set -u

# sentry.sh - the always-on loop. It hunts so you can write injects.
#
# The kit's problem was never detection, it was that every tool needed you to
# run it AND read it. Nothing on the box would ever interrupt you. That is the
# wrong shape for an operator whose other half of the score is writing memos:
# an operator who finds every implant and submits two injects loses to one who
# finds half and submits six.
#
# So this runs triage on a loop, notices only what is NEW, works out the exact
# remediation, and puts it in a queue. You sign off; it types.
#
#   sudo ./sentry.sh --config FILE --interval 60      start the loop
#   ./sentry.sh --config FILE --status                what is waiting for me?
#   sudo ./sentry.sh --config FILE --approve --apply  do everything queued
#   sudo ./sentry.sh --config FILE --approve 3 --apply   just item 3
#   sudo ./sentry.sh --config FILE --revert --apply   undo what it did
#
# It NEVER acts without --approve. That is deliberate: the thing that decides
# whether an account is scored is the packet, and the packet lives in your head
# and in the config, not in a heuristic.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=loop
interval=60
apply=0
item=''
bell=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --interval) interval=${2:?missing interval}; shift 2 ;;
    --status) mode=status; shift ;;
    --approve) mode=approve; shift
               case "${1:-}" in ''|-*) ;; *) item=$1; shift ;; esac ;;
    --revert) mode=revert; shift ;;
    --once) mode=once; shift ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --no-bell) bell=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--interval N] [--status|--approve [N]|--revert|--once] [--apply]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"
case "$interval" in ''|*[!0-9]*) ccdc_die "--interval must be a whole number of seconds" ;; esac
[ "$interval" -ge 20 ] || ccdc_die "--interval below 20s is churn: a triage pass is not free"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
mkdir -p "$state_dir" 2>/dev/null || state_dir="${TMPDIR:-/tmp}/ccdc-evidence-$(id -un)"
mkdir -p "$state_dir" || ccdc_die "cannot create state directory"

alerts="$state_dir/ALERTS"          # short, human, cat it any time
queue="$state_dir/sentry.queue"     # pending actions: check|subject|command
seen="$state_dir/sentry.seen"       # findings already reported
log="$state_dir/sentry.log"
undo="$state_dir/sentry.undo"
findings="$state_dir/triage.findings"

# --- the safety invariant ----------------------------------------------------
#
# An empty protect list does not mean "nothing to protect". It means the packet
# has not been entered yet, which is the single most dangerous state to act
# from: every account looks disposable when you have not been told which ones
# are scored. So remediation is refused outright until the config shows real
# knowledge of this box.
#
# This is what makes the automation safe. Fill these in from the packet BEFORE
# the event, not during it.
packet_entered() {
  [ -n "${CCDC_ALLOWED_USERS:-}" ] && [ -n "${CCDC_SYSTEMD_SERVICES:-}" ]
}

# Things sentry must never touch, whatever triage says about them.
protected_user() {
  ccdc_list_contains "$1" "${CCDC_ALLOWED_USERS:-}" && return 0
  [ "$1" = root ] && return 0
  [ "$1" = "$(id -un)" ] && return 0            # never lock yourself out
  return 1
}
protected_unit() {
  local u=${1##*/}; u=${u%.service}; u=${u%.timer}
  ccdc_list_contains "$u" "${CCDC_SYSTEMD_SERVICES:-}" && return 0
  ccdc_list_contains "$u" "${CCDC_PROTECT_SERVICES:-}" && return 0
  local g=${CCDC_GUARDIAN_NAME:-node-health}
  for own in "${CCDC_GUARDIAN_WATCH_NAME:-$g-watch}" "${CCDC_GUARDIAN_TICKER_NAME:-$g}" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-$g-reconcile}" "${CCDC_GUARDIAN_CRON_NAME:-$g}"; do
    [ "$u" = "$own" ] && return 0
  done
  case "$u" in ssh|sshd|cron|crond|dbus|systemd-*|auditd|rsyslog|ufw|firewalld) return 0 ;; esac
  return 1
}

slog() { ccdc_append_log "$log" "$*"; }

# Must stay identical to the rc-file test in triage.sh, or sentry proposes
# removing lines triage never flagged (or misses ones it did).
rc_patterns='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat|nohup |setsid |disown|&[[:space:]]*\)|&[[:space:]]*$|/tmp/|/var/tmp/|/dev/shm/'

# --- turn a finding into a proposed command ----------------------------------
#
# Returns the command on stdout, or nothing if this finding is not something
# sentry should act on. HOLD findings (SSH keys, NOPASSWD sudo, ports, /etc
# changes) deliberately produce no command: telling your own key from theirs,
# or your own sudo rule from an implanted one, needs the packet and your
# memory. Those are reported and left for you.
propose() {
  local check=$1 subject=$2 u unit target base g lines_file
  case "$check" in
    uid0)
      u=$subject; protected_user "$u" && return 0
      printf 'passwd -l %s && usermod -s /usr/sbin/nologin %s && userdel -f -r %s' "$u" "$u" "$u" ;;
    emptypw)
      u=$subject; protected_user "$u" && return 0
      printf 'passwd -l %s && usermod -s /usr/sbin/nologin %s' "$u" "$u" ;;
    svcshell)
      u=$subject; protected_user "$u" && return 0
      printf 'usermod -s /usr/sbin/nologin %s && pkill -u %s' "$u" "$u" ;;
    admingroup)
      u=${subject%%/*}; g=${subject#*/}; protected_user "$u" && return 0
      printf 'gpasswd -d %s %s' "$u" "$g" ;;
    cron)
      printf 'cp %s %s/evidence-%s && rm -f %s' "$subject" "$state_dir" "$(basename "$subject")" "$subject" ;;
    unit|unittmp)
      unit=$subject; base=$(basename "$unit"); protected_unit "$base" && return 0
      printf 'systemctl disable --now %s; rm -f %s; rm -rf %s.d; systemctl daemon-reload; systemctl reset-failed' \
        "$base" "$unit" "$unit" ;;
    unitdeep)
      unit=${subject%%::*}; target=${subject#*::}
      base=$(basename "$unit"); protected_unit "$base" && return 0
      printf 'systemctl disable --now %s %s.timer 2>/dev/null; cp %s %s/evidence-%s; rm -f %s %s %s.timer; systemctl daemon-reload; systemctl reset-failed' \
        "$base" "${base%.service}" "$target" "$state_dir" "$(basename "$target")" \
        "$unit" "$target" "${unit%.service}" ;;
    suid)
      printf 'chmod u-s %s' "$subject" ;;
    rcdeep)
      # subject is "rcfile::payload". The rc line is handled by the rcfile
      # finding on the same file; this removes what it called.
      target=${subject#*::}
      printf 'cp %s %s/evidence-%s && rm -f %s' "$target" "$state_dir" "$(basename "$target")" "$target" ;;
    rcfile)
      # Remove the EXACT lines that triggered detection, by fixed-string
      # whole-line match - not by re-applying the detection regex with sed.
      #
      # That regex includes a bare "/usr/local/bin/", and a .bashrc or a
      # profile.d script very plausibly has a legitimate PATH line containing
      # it. Re-running the pattern as a delete would silently eat that line. On
      # the lab box it happened to remove exactly one line and nothing else;
      # that was luck. Matching the literal offending lines cannot over-reach.
      lines_file="$state_dir/.rcfile-$(basename "$subject").lines"
      grep -IhE "$rc_patterns" "$subject" 2>/dev/null >"$lines_file" || return 0
      [ -s "$lines_file" ] || return 0
      printf 'cp %s %s/evidence-%s && grep -vxFf %s %s >%s.new && cat %s.new >%s && rm -f %s.new' \
        "$subject" "$state_dir" "$(basename "$subject")" \
        "$lines_file" "$subject" "$lines_file" "$lines_file" "$subject" "$lines_file" ;;
    *) return 0 ;;
  esac
}

# --- one pass ----------------------------------------------------------------

run_pass() {
  local sev check subject desc cmd key new=0 newred=0
  "$SCRIPT_DIR/triage.sh" --config "$config" --quiet >/dev/null 2>&1 || true
  [ -f "$findings" ] || return 0
  touch "$seen" "$queue" 2>/dev/null || true

  while IFS='|' read -r sev check subject desc; do
    [ -n "${sev:-}" ] || continue
    key="$check|$subject"
    grep -qxF "$key" "$seen" 2>/dev/null && continue      # already reported
    printf '%s\n' "$key" >>"$seen"
    new=$((new + 1))
    [ "$sev" = RED ] && newred=$((newred + 1))

    cmd=$(propose "$check" "$subject")
    if [ -n "$cmd" ]; then
      printf '%s|%s|%s|%s\n' "$sev" "$check" "$subject" "$cmd" >>"$queue"
      slog "queued sev=$sev check=$check subject=$subject"
    else
      slog "reported sev=$sev check=$check subject=$subject (no automatic action)"
    fi
  done <"$findings"

  [ "$new" -gt 0 ] && write_alerts
  # Ring only for RED. A bell for every AMBER trains you to ignore the bell.
  # Guarded: with no controlling terminal (a --once run over ssh, or the loop
  # started detached) /dev/tty does not exist and the redirect itself errors
  # before the 2>/dev/null can suppress it.
  # `[ -w /dev/tty ]` is not enough: the device node exists and tests writable
  # even when this process has no controlling terminal, and the redirect then
  # fails before 2>/dev/null can suppress it. `[ -t 1 ]` asks the question that
  # actually matters - is anyone looking at my output.
  if [ "$newred" -gt 0 ] && [ "$bell" -eq 1 ] && [ -t 1 ]; then
    printf '\a' || true
  fi
  return 0
}

write_alerts() {
  local n sev check subject cmd
  n=$(grep -c . "$queue" 2>/dev/null); [ -n "$n" ] || n=0
  {
    printf 'ALERTS  %s  (sentry is watching, interval %ss)\n' "$(date -u '+%H:%M:%SZ')" "$interval"
    printf '=========================================================\n\n'
    if [ "$n" -eq 0 ]; then
      printf '  Nothing waiting for your sign-off.\n\n'
    else
      printf '  %s action(s) WAITING FOR SIGN-OFF. Review, then:\n' "$n"
      printf '      sudo ./linux/sentry.sh --config <cfg> --approve --apply\n\n'
      local i=0
      while IFS='|' read -r sev check subject cmd; do
        [ -n "${sev:-}" ] || continue
        i=$((i + 1))
        printf '  [%s] %-5s %s  %s\n' "$i" "$sev" "$check" "$subject"
        printf '        will run: %s\n\n' "$cmd"
      done <"$queue"
    fi
    # A RED finding sentry declined to act on must still be LOUD. Otherwise a
    # protect-list entry silently hides a real compromise: on the lab box
    # www-lab was in CCDC_ALLOWED_USERS, so a service account that had been
    # handed a shell and put in the sudo group produced no queue entry and no
    # alert line at all. Protection must narrow what sentry TOUCHES, never what
    # it TELLS you.
    local heldred=0
    while IFS='|' read -r sev check subject desc; do
      [ "${sev:-}" = RED ] || continue
      grep -qF "|$check|$subject|" "$queue" 2>/dev/null && continue
      if [ "$heldred" -eq 0 ]; then
        printf '  RED findings sentry will NOT touch - YOU must decide:\n'
        heldred=1
      fi
      printf '    %-12s %s\n' "$check" "$subject"
      printf '                 %s\n' "$desc"
      case "$check" in
        svcshell|admingroup|uid0|emptypw)
          printf '                 reason: named in CCDC_ALLOWED_USERS (or is root/you).\n'
          printf '                 If the packet does NOT score this account, remove it from\n'
          printf '                 CCDC_ALLOWED_USERS and sentry will queue the fix.\n' ;;
        unit|unittmp|unitdeep)
          printf '                 reason: named in CCDC_SYSTEMD_SERVICES/CCDC_PROTECT_SERVICES,\n'
          printf '                 or it is one of this kit own units.\n' ;;
      esac
      printf '\n'
    done <"$findings"
    [ "$heldred" -eq 1 ] && printf '\n'

    printf '  Reported but NOT actionable automatically (needs your judgement):\n'
    grep -E '^AMBER' "$findings" 2>/dev/null | while IFS='|' read -r sev check subject desc; do
      printf '    %-12s %s  - %s\n' "$check" "$subject" "$desc"
    done
    printf '\n  Full detail: sudo ./linux/triage.sh --config <cfg>\n'
  } >"$alerts.tmp" && mv "$alerts.tmp" "$alerts"
}

# --- modes -------------------------------------------------------------------

do_status() {
  [ -f "$alerts" ] && cat "$alerts" || printf 'sentry has not run yet.\n'
}

do_approve() {
  local sev check subject cmd i=0 done_n=0 skipped=0
  [ -s "$queue" ] || { printf 'sentry: nothing queued.\n'; return 0; }
  packet_entered || ccdc_die "refusing to act: CCDC_ALLOWED_USERS and CCDC_SYSTEMD_SERVICES are not both set.
An empty protect list does not mean nothing is protected - it means the packet
has not been entered, and every account looks disposable. Fill them in first."

  : >"$queue.next"
  while IFS='|' read -r sev check subject cmd; do
    [ -n "${sev:-}" ] || continue
    i=$((i + 1))
    if [ -n "$item" ] && [ "$item" != "$i" ]; then
      printf '%s|%s|%s|%s\n' "$sev" "$check" "$subject" "$cmd" >>"$queue.next"
      continue
    fi
    printf '\n[%s] %s %s  %s\n' "$i" "$sev" "$check" "$subject"
    printf '    %s\n' "$cmd"
    if ccdc_is_dry_run; then
      printf '    [dry-run] not executed. Add --apply.\n'
      printf '%s|%s|%s|%s\n' "$sev" "$check" "$subject" "$cmd" >>"$queue.next"
      skipped=$((skipped + 1))
      continue
    fi
    if sh -c "$cmd" >>"$log" 2>&1; then
      printf '    done\n'
      slog "applied check=$check subject=$subject cmd=$cmd"
      printf '%s|%s|%s\n' "$check" "$subject" "$cmd" >>"$undo"
      done_n=$((done_n + 1))
    else
      printf '    FAILED - see %s\n' "$log"
      slog "FAILED check=$check subject=$subject cmd=$cmd"
      printf '%s|%s|%s|%s\n' "$sev" "$check" "$subject" "$cmd" >>"$queue.next"
    fi
  done <"$queue"
  mv "$queue.next" "$queue"
  printf '\n'
  if ccdc_is_dry_run; then
    ccdc_info "dry run: $skipped action(s) would run. Re-run with --apply."
  else
    ccdc_info "$done_n action(s) applied. Record: $undo"
    printf '  Now verify the scored service FROM OFF THE BOX.\n'
    # The findings that produced these are stale now; let the next pass re-see
    # anything that did not actually clear.
    : >"$seen"
    write_alerts
  fi
}

do_revert() {
  printf 'sentry applied these, newest first:\n\n'
  [ -s "$undo" ] || { printf '  (nothing)\n'; return 0; }
  tac "$undo" 2>/dev/null || cat "$undo"
  printf '\nThere is no automatic undo: removing a unit and deleting an account\n'
  printf 'are not reversible by replaying a command backwards. Use your backups:\n'
  printf '  sudo ./linux/backup.sh --config <cfg> --list\n'
  printf 'Evidence copies of everything removed are in %s/evidence-*\n' "$state_dir"
}

case "$mode" in
  status) do_status ;;
  approve) [ "$apply" -eq 1 ] && ccdc_require_root; do_approve ;;
  revert) do_revert ;;
  once) ccdc_require_root; run_pass; do_status ;;
  loop)
    ccdc_require_root
    packet_entered || ccdc_warn "CCDC_ALLOWED_USERS / CCDC_SYSTEMD_SERVICES are not both set - sentry will detect and queue, but --approve will refuse to act until they are"
    printf 'sentry: watching every %ss. Findings queue for your sign-off.\n' "$interval"
    printf '  check it:   cat %s\n' "$alerts"
    printf '  sign off:   sudo ./linux/sentry.sh --config <cfg> --approve --apply\n'
    printf '  Ctrl-C to stop.\n\n'
    while :; do
      run_pass
      sleep "$interval"
    done ;;
esac
