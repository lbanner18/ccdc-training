#!/usr/bin/env bash
set -u

# sentry.sh - supervised detection, diagnosis, and approval-gated remediation.
#
# The standing service runs triage plus the broader change detector and keeps a
# current, structured queue. Queue records contain only severity/check/subject
# data; attacker-controlled paths are never saved and later evaluated as shell.
# Every approval refreshes triage and re-checks the packet protection lists
# immediately before invoking fixed remediation functions with quoted argv.
#
#   sudo ./sentry.sh --config FILE --install --apply   install/start service
#   sudo ./sentry.sh --config FILE --status            current findings
#   sudo ./sentry.sh --config FILE --approve --apply   approve current queue
#   sudo ./sentry.sh --config FILE --approve 3 --apply approve one item
#   sudo ./sentry.sh --config FILE --ack               acknowledge watch events
#   sudo ./sentry.sh --config FILE --uninstall --apply remove service/copy

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/provenance.sh"

umask 077

config=''
mode=loop
interval=''
watch_interval=''
triage_timeout=''
watch_timeout=''
apply=0
item=''
bell=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --interval) interval=${2:?missing interval}; shift 2 ;;
    --watch-interval) watch_interval=${2:?missing watch interval}; shift 2 ;;
    --triage-timeout) triage_timeout=${2:?missing triage timeout}; shift 2 ;;
    --watch-timeout) watch_timeout=${2:?missing watch timeout}; shift 2 ;;
    --status) mode=status; shift ;;
    --approve) mode=approve; shift
      case "${1:-}" in ''|-*) ;; *) item=$1; shift ;; esac ;;
    --ack) mode=ack; shift ;;
    --revert) mode=revert; shift ;;
    --once) mode=once; shift ;;
    --loop) mode=loop; shift ;;
    --install) mode=install; shift ;;
    --uninstall) mode=uninstall; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    --no-bell) bell=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--interval N] [--watch-interval N] [--triage-timeout N] [--watch-timeout N]\n' "$0"
      printf '\n'
      printf '  The supervision loop: refreshes triage every minute, runs the broader\n'
      printf '  sweep every two, and maintains a numbered queue of findings you can\n'
      printf '  approve one at a time.\n'
      printf '\n'
      printf '  Install it, do not run the loop by hand - systemd keeps it alive and\n'
      printf '  leaves your one terminal free:\n'
      printf '      sudo ./sentry.sh --config FILE --install\n'
      printf '      sudo ./sentry.sh --config FILE --status      what is queued now\n'
      printf '      sudo ./sentry.sh --config FILE --approve N   act on one finding\n'
      printf '\n'
      printf '  The queue is rebuilt from current findings rather than replayed from\n'
      printf '  stored shell, and approving re-runs detection before it touches\n'
      printf '  anything, so a finding that has already been fixed is not acted on\n'
      printf '  twice.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Commands this tool prints get pasted, so they carry the real config path.
# "<cfg>" is a shell redirect, not a placeholder: pasting it is a syntax error.
printf -v qconfig '%q' "$config"
printf -v qkit '%q' "$SCRIPT_DIR"

# A sourced config must not be able to turn a CLI dry-run into an apply.
if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi

interval=${interval:-${CCDC_SENTRY_INTERVAL:-60}}
watch_interval=${watch_interval:-${CCDC_WATCH_INTERVAL:-120}}
triage_timeout=${triage_timeout:-${CCDC_TRIAGE_TIMEOUT:-45}}
watch_timeout=${watch_timeout:-${CCDC_WATCH_TIMEOUT:-90}}
case "$interval" in ''|*[!0-9]*) ccdc_die "--interval must be a whole number of seconds" ;; esac
case "$watch_interval" in ''|*[!0-9]*) ccdc_die "--watch-interval must be a whole number of seconds" ;; esac
case "$triage_timeout" in ''|*[!0-9]*) ccdc_die "--triage-timeout must be a whole number of seconds" ;; esac
case "$watch_timeout" in ''|*[!0-9]*) ccdc_die "--watch-timeout must be a whole number of seconds" ;; esac
[ "$interval" -ge 20 ] || ccdc_die "--interval below 20s is churn: a triage pass is not free"
[ "$watch_interval" -ge 30 ] || ccdc_die "--watch-interval below 30s is churn: a full sweep is not free"
[ "$triage_timeout" -ge 10 ] && [ "$triage_timeout" -le 300 ] \
  || ccdc_die "--triage-timeout must be between 10 and 300 seconds"
[ "$watch_timeout" -ge 15 ] && [ "$watch_timeout" -le 600 ] \
  || ccdc_die "--watch-timeout must be between 15 and 600 seconds"
# Echo what arrived, not just what was wanted. The common way to get here is
# pasting the item's label - "[2]" - which bash leaves alone when no file
# matches the glob, so the tool sees two brackets and a digit.
item_error() {
  case "$1" in
    \[*\]) stripped=${1#\[}; stripped=${stripped%\]}
       ccdc_die "approval item must be a positive integer, got: $1
       the [N] in the item list is a label, not part of the command.
       try: --approve $stripped --apply" ;;
    *) ccdc_die "approval item must be a positive integer, got: $1" ;;
  esac
}
case "$item" in ''|*[!0-9]*) [ -z "$item" ] || item_error "$item" ;; esac
[ -z "$item" ] || [ "$item" -gt 0 ] || item_error "$item"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"

alerts="$state_dir/ALERTS"
queue="$state_dir/sentry.queue"             # SEVERITY|CHECK|SUBJECT only
reviewed="$state_dir/sentry.reviewed"       # immutable operator-reviewed queue snapshot
seen="$state_dir/sentry.seen"               # CHECK|SUBJECT for current pass
log="$state_dir/sentry.log"
undo="$state_dir/sentry.undo"               # time|check|subject|evidence-dir
findings="$state_dir/triage.findings"
triage_health="$state_dir/sentry.health.triage"
watch_health="$state_dir/sentry.health.watch"
last_pass="$state_dir/sentry.last-pass"
watch_last="$state_dir/sentry.watch.last"
watch_pending="$state_dir/sentry.watch.pending"
watch_pending_key="$state_dir/sentry.watch.pending.key"
lock_file="$state_dir/.sentry.lock"
artifact_seq=0
lock_held=0

ensure_state() {
  if [ "$(id -u)" -eq 0 ]; then
    ccdc_secure_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
  else
    [ -d "$state_dir" ] && [ ! -L "$state_dir" ] || ccdc_die "state directory is unavailable: $state_dir"
    [ -w "$state_dir" ] || ccdc_die "state directory is not writable by $(id -un): $state_dir"
  fi
}

release_lock() {
  if [ "$lock_held" -eq 1 ]; then
    flock -u 9 2>/dev/null || true
    exec 9>&-
    lock_held=0
  fi
}
trap release_lock EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock() {
  ccdc_have flock || ccdc_die "flock is required for sentry state coordination"
  [ ! -L "$lock_file" ] || ccdc_die "refusing symlink lock file: $lock_file"
  exec 9>"$lock_file" || ccdc_die "cannot open sentry lock: $lock_file"
  if ! flock -n 9; then
    exec 9>&-
    return 1
  fi
  lock_held=1
}

slog() { ccdc_append_log "$log" "$*" || printf 'sentry: cannot append %s\n' "$log" >&2; }

slog_subject() {
  local prefix=$1 subject=$2 quoted
  printf -v quoted '%q' "$subject"
  slog "$prefix subject=$quoted"
}

packet_entered() {
  [ -n "${CCDC_ALLOWED_USERS:-}" ] && [ -n "${CCDC_SYSTEMD_SERVICES:-}" ]
}

valid_name() {
  case "$1" in
    ''|*[!A-Za-z0-9_.@+-]*|.*|-*) return 1 ;;
    *) return 0 ;;
  esac
}

valid_path() {
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *'|'*|*$'\n'*|*$'\r'*|*'::'*|*[[:cntrl:]]*) return 1 ;; esac
  case "$1" in *'//'|*'//'*) return 1 ;; esac
  case "$1" in */./*|*/.|*/../*|*/..) return 1 ;; esac
  return 0
}

valid_compound() {
  local value=$1 left right
  case "$value" in *::* ) ;; *) return 1 ;; esac
  left=${value%%::*}; right=${value#*::}
  [ "$value" = "$left::$right" ] || return 1
  valid_path "$left" && valid_path "$right"
}

valid_cron_path() {
  valid_path "$1" || return 1
  case "$1" in
    /etc/crontab|/etc/cron.d/*|/etc/cron.daily/*|/etc/cron.hourly/*|\
    /etc/cron.weekly/*|/etc/cron.monthly/*|/var/spool/cron/*) return 0 ;;
    *) return 1 ;;
  esac
}

valid_unit_path() {
  valid_path "$1" || return 1
  case "$1" in
    /etc/systemd/system/*.service|/etc/systemd/system/*.timer|\
    /run/systemd/system/*.service|/run/systemd/system/*.timer|\
    /etc/systemd/system/*.service.d/*.conf|/etc/systemd/system/*.timer.d/*.conf|\
    /run/systemd/system/*.service.d/*.conf|/run/systemd/system/*.timer.d/*.conf) return 0 ;;
    *) return 1 ;;
  esac
}

unit_name_from_path() {
  local path=$1 parent
  case "$path" in
    *.service.d/*.conf|*.timer.d/*.conf)
      parent=$(basename -- "$(dirname -- "$path")")
      printf '%s\n' "${parent%.d}"
      ;;
    *) basename -- "$path" ;;
  esac
}

valid_dropin_subject() {
  local value=$1 owner path parent
  case "$value" in *::* ) ;; *) return 1 ;; esac
  owner=${value%%::*}; path=${value#*::}
  [ "$value" = "$owner::$path" ] || return 1
  valid_name "$owner" && valid_unit_path "$path" || return 1
  case "$owner" in *.service|*.timer) ;; *) return 1 ;; esac
  parent=$(basename -- "$(dirname -- "$path")")
  [ "${parent%.d}" = "$owner" ]
}

valid_dropin_deep_subject() {
  local value=$1 owner rest dropin target parent
  case "$value" in *::*::* ) ;; *) return 1 ;; esac
  owner=${value%%::*}; rest=${value#*::}; dropin=${rest%%::*}; target=${rest#*::}
  [ "$value" = "$owner::$dropin::$target" ] || return 1
  case "$target" in *::* ) return 1 ;; esac
  valid_name "$owner" && valid_unit_path "$dropin" && valid_path "$target" || return 1
  case "$owner" in *.service|*.timer) ;; *) return 1 ;; esac
  parent=$(basename -- "$(dirname -- "$dropin")")
  [ "${parent%.d}" = "$owner" ]
}

safe_root_owned_path() {
  local path=$1 parent mode owner
  valid_path "$path" && [ -f "$path" ] && [ ! -L "$path" ] || return 1
  owner=$(stat -Lc '%u' -- "$path" 2>/dev/null) || return 1
  [ "$owner" -eq 0 ] || return 1
  parent=$(dirname -- "$path")
  [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
  mode=$(stat -Lc '%a' -- "$parent" 2>/dev/null) || return 1
  case "$mode" in ''|*[!0-7]*) return 1 ;; esac
  [ $((8#$mode & 0022)) -eq 0 ]
}

list_contains_unit() {
  local needle=${1##*/} item
  needle=${needle%.service}; needle=${needle%.timer}
  for item in ${2:-}; do
    item=${item##*/}; item=${item%.service}; item=${item%.timer}
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

protected_user() {
  ccdc_list_contains "$1" "${CCDC_ALLOWED_USERS:-}" && return 0
  [ "$1" = root ] && return 0
  return 1
}

protected_unit() {
  local u=${1##*/} g own
  u=${u%.service}; u=${u%.timer}
  list_contains_unit "$u" "${CCDC_SYSTEMD_SERVICES:-}" && return 0
  list_contains_unit "$u" "${CCDC_PROTECT_SERVICES:-}" && return 0
  g=${CCDC_GUARDIAN_NAME:-node-health}
  for own in "${CCDC_GUARDIAN_WATCH_NAME:-$g-watch}" \
             "${CCDC_GUARDIAN_TICKER_NAME:-$g}" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-$g-reconcile}" \
             "${CCDC_GUARDIAN_CRON_NAME:-$g}" \
             "${CCDC_SENTRY_NAME:-ccdc-sentry}"; do
    [ "$u" = "$own" ] && return 0
  done
  case "$u" in ssh|sshd|cron|crond|dbus|auditd|rsyslog|ufw|firewalld) return 0 ;; esac
  return 1
}

# Guardian's third layer is a file in /etc/cron.d, and protected_unit() only
# ever sees systemd unit names - so nothing was checking cron paths against our
# own artifacts.
#
# Found on the lab VM: sentry queued "remove the dedicated schedule
# /etc/cron.d/drill-health" as a RED action. That file is guardian's layer 3,
# listed in its own manifest as layer3|/etc/cron.d/drill-health. Approving it
# deletes the keep-alive's scheduler; guardian rebuilds it within a tick;
# sentry flags it again next pass. An unclearable RED is worse than a missed
# one, because it teaches the operator that RED can be ignored.
protected_cron() {
  local f=${1##*/} g own
  g=${CCDC_GUARDIAN_NAME:-node-health}
  for own in "${CCDC_GUARDIAN_CRON_NAME:-$g}" \
             "${CCDC_GUARDIAN_WATCH_NAME:-$g-watch}" \
             "${CCDC_GUARDIAN_TICKER_NAME:-$g}" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-$g-reconcile}" \
             "${CCDC_SENTRY_NAME:-ccdc-sentry}"; do
    [ "$f" = "$own" ] && return 0
  done
  return 1
}

# Anything living inside our own payload directories is ours, whatever the
# detector thinks of its contents. guardian's reconcile script legitimately
# contains the shapes the reverse-shell detector looks for.
protected_payload() {
  local path=$1 g gdir sdir
  g=${CCDC_GUARDIAN_NAME:-node-health}
  gdir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/$g}
  sdir=${CCDC_SENTRY_DIR:-/usr/local/lib/${CCDC_SENTRY_NAME:-ccdc-sentry}}
  case "$path" in
    "$gdir"/*|"$sdir"/*) return 0 ;;
  esac
  return 1
}

# Must match triage.sh's rc-file detector. Remediation captures the literal
# matching lines and removes only exact whole-line matches.
rc_patterns='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat|nohup |setsid |disown|&[[:space:]]*\)|&[[:space:]]*$|/tmp/|/var/tmp/|/dev/shm/'

# --- what the network-facing actions all need to know -------------------------
#
# Every one of the remaining actions names either a port or a process, and on a
# scored box either of those may BE the thing you are being graded on. So they
# share one question - "could this be ours?" - asked four ways: the unit that
# owns the process, the binary behind it, the session it belongs to, and the
# port itself. A no from any of them is enough to refuse.

# Which systemd unit owns this pid? Empty when it belongs to none, and that
# emptiness is itself a discriminator: a scored service arrives as a unit, a
# web shell spawned by one does not.
pid_unit() {
  local pid=$1
  [ -r "/proc/$pid/cgroup" ] || return 1
  tr '/' '\n' <"/proc/$pid/cgroup" 2>/dev/null \
    | grep -E '\.(service|socket|scope)$' | tail -1
}

pid_exe() {
  local pid=$1 exe
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
  printf '%s' "${exe% (deleted)}"
}

# Is this pid ours, the system's, or a scored service's? Anything that cannot
# be resolved is treated as protected, because the failure mode of guessing
# wrong here is killing the service being graded.
# The second argument, "ignore-port", is used by exactly one caller and is
# explained at that caller: netprocsvc exists BECAUSE the port is one the
# packet accounts for, so the port test would disqualify every instance of it
# by construction. That caller substitutes a stricter test of its own.
pid_is_protected() {
  local pid=$1 mode=${2:-} unit exe mysid itssid
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  [ -d "/proc/$pid" ] || return 0
  if [ "$pid" -le 2 ]; then return 0; fi
  if [ "$pid" -eq "$$" ] || [ "$pid" -eq "${PPID:-0}" ]; then return 0; fi
  unit=$(pid_unit "$pid" 2>/dev/null) || unit=''
  if [ -n "$unit" ] && protected_unit "$unit"; then return 0; fi
  exe=$(pid_exe "$pid" 2>/dev/null) || exe=''
  case "$exe" in
    /usr/sbin/sshd|/usr/sbin/init|/sbin/init) return 0 ;;
    /lib/systemd/systemd|/usr/lib/systemd/systemd) return 0 ;;
  esac
  if [ -n "$exe" ] && protected_payload "$exe"; then return 0; fi
  if [ "$mode" != ignore-port ] && pid_holds_protected_port "$pid"; then return 0; fi
  # Our own login session: killing anything in it ends the shell that is doing
  # the approving, and the approval goes with it.
  mysid=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ')
  itssid=$(ps -o sid= -p "$pid" 2>/dev/null | tr -d ' ')
  if [ -n "$mysid" ] && [ "$mysid" = "$itssid" ]; then return 0; fi
  return 1
}

# Does this pid hold a listening port the packet or the watchdog accounts for?
#
# port_is_protected asks the same question from the port's side, and every
# action that starts from a port goes through it. A live-process action starts
# from a pid instead, and killing the process closes the port just as surely -
# so without this the two doors have different locks.
#
# Measured on the lab VM: a rollback correctly restored a rogue unit that held
# a scored TCP check port, and the netcat underneath it came straight back as a
# RED netproc finding that sentry offered to kill.
pid_holds_protected_port() {
  local pid=$1 addr port
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  ccdc_have ss || return 1
  while read -r addr; do
    port=${addr##*:}
    port_is_protected "$port" && return 0
  done < <(ss -H -lntupn 2>/dev/null | awk -v p="pid=$pid," 'index($0, p) { print $5 }')
  return 1
}

# Which protection mode does this check's live-process action run under?
#
# can_automate decides whether to offer an item; the action re-checks
# immediately before the kill, because the queue can be a minute old and pids
# are recycled. Those two checks must ask the SAME question. A second check
# that is stricter than the first is not extra safety - it is sentry offering
# an item, printing an approve command for it, and then refusing its own offer
# with "FAILED - partial changes may have occurred" and nothing to do next.
#
# Measured: can_automate cleared a netprocsvc item with ignore-port, the action
# re-checked without it, and the approval failed on a finding that was never
# going to be actionable no matter how many times the operator tried.
protection_mode_for() {
  case "$1" in
    netprocsvc) printf 'ignore-port' ;;
    *)          printf '' ;;
  esac
}

# Is this port one the packet accounts for, one the watchdog probes, or the one
# carrying this session? Any of those and nothing here touches it - the finding
# may simply be stale, and a stale finding must not close a scored port.
port_is_protected() {
  local port=$1 name host p svc
  case "$port" in ''|*[!0-9]*) return 0 ;; esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then return 0; fi
  ccdc_list_contains "$port" "${CCDC_ALLOWED_TCP_PORTS:-} ${CCDC_ALLOWED_UDP_PORTS:-}" && return 0
  [ "$port" = "${CCDC_SSH_PORT:-22}" ] && return 0
  [ "$port" = 22 ] && return 0
  while IFS='|' read -r name host p svc; do
    [ "$p" = "$port" ] && return 0
  done < <(ccdc_tcp_checks 2>/dev/null)
  return 1
}

# The pid holding a listening port, or empty. netid is tcp or udp.
holder_of_port() {
  local netid=$1 port=$2 flag=t
  case "$netid" in udp) flag=u ;; tcp) flag=t ;; *) return 1 ;; esac
  ccdc_have ss || return 1
  ss -H -ln"$flag"p "sport = :$port" 2>/dev/null \
    | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1
}

# Owned by no package - re-asked here rather than trusted from the finding,
# because a finding can be minutes old and the answer decides a deletion.
#
# Two shapes matter and both were got wrong once. dpkg-query's own status is
# read, not a pipeline's: an earlier version wrote
# `if dpkg-query -S "$f" | head -1; then` and read head's status, which is
# always zero, so every file looked package-owned. And the merged-/usr spelling
# is asked for too, which is lib/provenance.sh's pkg_owns()'s whole job -
# without it /usr/bin/nc.openbsd reads as owned by nothing, because dpkg
# recorded it as /bin/nc.openbsd. That library says in its own header that
# baseline, harden and sentry all ask the question through it; sentry was the
# one that never sourced it.
exe_is_unpackaged() {
  local path=$1
  [ -n "$path" ] || return 1
  ccdc_have dpkg-query || ccdc_have rpm || return 1
  pkg_owns "$path" && return 1
  return 0
}

# Only a .service or .socket - a .scope is a session, not a unit someone
# installed, and the difference is what decides netprocsvc.
pid_service() {
  local pid=$1
  [ -r "/proc/$pid/cgroup" ] || return 1
  tr '/' '\n' <"/proc/$pid/cgroup" 2>/dev/null \
    | grep -E '\.(service|socket)$' | tail -1
}

# The live pid behind a finding's subject, whether the subject names the pid
# (tmpproc says pid1234:/dev/shm/x) or only the executable (netproc says the
# path). Empty or dead means there is nothing left to act on.
subject_pid() {
  local subject=$1 pid path
  pid=$(printf '%s' "$subject" | sed -n 's/^pid\([0-9][0-9]*\):.*/\1/p')
  if [ -z "$pid" ]; then
    path=$(printf '%s' "$subject" | sed 's/^pid[0-9]*://; s/ (deleted)$//')
    pid=$(resolve_pid_for_exe "$path") || return 1
  fi
  [ -n "$pid" ] && [ -d "/proc/$pid" ] || return 1
  printf '%s' "$pid"
}

# A sudoers drop-in this box's own kit put there, or the main file. Never ours
# to remove automatically.
protected_sudoers() {
  local f=$1
  case "$f" in
    /etc/sudoers) return 0 ;;
    /etc/sudoers.d/*) ;;
    *) return 0 ;;
  esac
  case "${f##*/}" in
    "${CCDC_SENTRY_NAME:-ccdc-sentry}"*|"${CCDC_GUARDIAN_NAME:-node-health}"*) return 0 ;;
  esac
  return 1
}

# AMBER means "this may well be yours", and for most checks that is a reason to
# describe rather than offer. Two measured cases decide the list.
#
# An AMBER nopasswd is a sudoers drop-in that PREDATES the box - on the lab VM
# it was /etc/sudoers.d/90-cloud-init-users, cloud-init's own, and approving its
# removal would have taken the operator's passwordless sudo with it. An AMBER
# suidunpackaged predates the box too and triage says so in as many words:
# "most likely a packaging quirk". Neither is incident response.
#
# What IS listed here is either reversible - stopping and disabling a unit puts
# straight back - or a live process holding a port nothing in the packet
# accounts for, which is precisely the hand-over this tool exists to make.
offerable_at_amber() {
  case "$1" in
    port|udpport|rogueunit|netunpackaged|netprocsvc) return 0 ;;
    *) return 1 ;;
  esac
}

can_automate() {
  local check=$1 subject=$2 user group unit target owner rest dropin
  case "$check" in
    uid0|emptypw|svcshell)
      valid_name "$subject" || return 1
      getent passwd "$subject" >/dev/null 2>&1 || return 1
      protected_user "$subject" && return 1
      ;;
    admingroup)
      case "$subject" in */*) ;; *) return 1 ;; esac
      user=${subject%%/*}; group=${subject#*/}
      valid_name "$user" && valid_name "$group" || return 1
      getent passwd "$user" >/dev/null 2>&1 || return 1
      protected_user "$user" && return 1
      case "$group" in sudo|wheel|admin) ;; *) return 1 ;; esac
      ;;
    cron)
      valid_cron_path "$subject" && [ -e "$subject" ] || return 1
      # Shared system crontabs require line-level operator judgement. Dedicated
      # job files can be preserved and removed safely after explicit approval.
      case "$subject" in /etc/crontab|/var/spool/cron/*) return 1 ;; esac
      protected_cron "$subject" && return 1
      ;;
    crondeep)
      valid_compound "$subject" || return 1
      unit=${subject%%::*}; target=${subject#*::}
      valid_cron_path "$unit" && [ -e "$unit" ] && [ -f "$target" ] || return 1
      case "$unit" in /etc/crontab|/var/spool/cron/*) return 1 ;; esac
      protected_cron "$unit" && return 1
      protected_payload "$target" && return 1
      ;;
    unit|unittmp)
      valid_unit_path "$subject" && [ -e "$subject" ] || return 1
      protected_unit "$(unit_name_from_path "$subject")" && return 1
      ;;
    unitdeep)
      valid_compound "$subject" || return 1
      unit=${subject%%::*}; target=${subject#*::}
      valid_unit_path "$unit" && [ -e "$unit" ] && [ -f "$target" ] || return 1
      protected_unit "$(unit_name_from_path "$unit")" && return 1
      protected_payload "$target" && return 1
      ;;
    unitdropin)
      valid_dropin_subject "$subject" || return 1
      owner=${subject%%::*}; dropin=${subject#*::}
      [ -f "$dropin" ] && [ ! -L "$dropin" ] || return 1
      ;;
    unitdropindeep)
      valid_dropin_deep_subject "$subject" || return 1
      owner=${subject%%::*}; rest=${subject#*::}; dropin=${rest%%::*}; target=${rest#*::}
      [ -f "$dropin" ] && [ ! -L "$dropin" ] && [ -f "$target" ] || return 1
      protected_payload "$target" && return 1
      ;;
    suid)
      safe_root_owned_path "$subject" && [ -u "$subject" ] || return 1
      ;;
    # A sudoers drop-in written after the box was built. Only ever a file in
    # /etc/sudoers.d: a mistake in /etc/sudoers itself locks every account out
    # of root and the only way back is the console.
    nopasswd)
      safe_root_owned_path "$subject" || return 1
      protected_sudoers "$subject" && return 1
      ccdc_have visudo || return 1
      ;;

    # Setuid root and owned by no package. The package question is asked again
    # here rather than trusted from the finding, because the finding can be a
    # minute old and the answer decides a deletion.
    suidunpackaged)
      safe_root_owned_path "$subject" || return 1
      [ -u "$subject" ] || return 1
      protected_payload "$subject" && return 1
      exe_is_unpackaged "$subject" || return 1
      ;;

    # An enabled unit nothing accounts for. Same shape as `unit`, with the
    # scored re-check on top: removing a unit that a scored service quietly
    # pulls in takes the scored service with it.
    rogueunit)
      valid_unit_path "$subject" && [ -e "$subject" ] || return 1
      protected_unit "$(unit_name_from_path "$subject")" && return 1
      ;;

    # Live processes. The pid must still exist and must not be ours, the
    # system's, or a scored service's.
    tmpproc|netproc)
      target=$(subject_pid "$subject") || return 1
      pid_is_protected "$target" "$(protection_mode_for "$check")" && return 1
      ;;

    netunpackaged)
      target=$(subject_pid "$subject") || return 1
      pid_is_protected "$target" "$(protection_mode_for "$check")" && return 1
      exe_is_unpackaged "$(pid_exe "$target")" || return 1
      ;;

    # A listening port nothing in the packet accounts for. There is no such
    # thing as removing a port, so the subject of the action is whatever holds
    # it - and if that is a scored service, an allow-listed port, a watchdog
    # probe target or SSH, nothing here touches it.
    port|udpport)
      case "$subject" in ''|*[!0-9]*) return 1 ;; esac
      port_is_protected "$subject" && return 1
      if [ "$check" = udpport ]; then target=$(holder_of_port udp "$subject")
      else target=$(holder_of_port tcp "$subject"); fi
      [ -n "$target" ] || return 1
      pid_is_protected "$target" "$(protection_mode_for "$check")" && return 1
      ;;

    # An interpreter holding a socket. This is the genuinely ambiguous one -
    # a scored service written in python and a web shell look identical from
    # the process name - so it is automatable only in the case where the
    # ambiguity collapses: NO systemd unit owns it. A scored service arrives as
    # a unit. Anything with a unit stays held, and held_reason says what to read.
    netprocsvc)
      target=$(subject_pid "$subject") || return 1
      # The port test is deliberately skipped here, and the no-unit test below
      # is what replaces it.
      #
      # This finding is raised precisely when an interpreter holds a port the
      # packet DOES account for - that is the whole shape of it, and it is the
      # nastiest place to hide, because every port-based check waves it
      # through. Asking "is this port accounted for?" therefore disqualifies
      # every netprocsvc finding there will ever be, which is how this one
      # silently left the queue after pid_holds_protected_port was added.
      #
      # What is asked instead is stricter for this case: does a .service or
      # .socket own the process? A scored service arrives as a unit - the
      # packet names services, scored_still_answering iterates units, and
      # protected_unit is a list of unit names. An interpreter holding a
      # scored port under NO unit is not the scored service; if it were, the
      # unit would be failed and the operator has a louder problem than this.
      pid_is_protected "$target" "$(protection_mode_for "$check")" && return 1
      [ -z "$(pid_service "$target" 2>/dev/null)" ] || return 1
      ;;

    # Login startup files live in user-writable directories and deep payloads
    # can frame legitimate paths. Report them prominently, but do not race a
    # user-controlled parent or delete the referenced file automatically.
    rcdeep|rcfile) return 1 ;;
    *) return 1 ;;
  esac
  return 0
}

# Why this one needs you, in the voice agreed for NEEDS YOU items.
#
# What was here before was a single line - "held: this finding needs judgement
# or is not safely automatable" - printed under every held finding regardless of
# what it was. That is the finish line the operator kept falling off: detection
# is thorough, and then the tool says it will not help and does not say what to
# do instead.
#
# The shape, for every one of these: what I found and when, why I will not touch
# it, the one command that resolves the ambiguity, and what to do if the answer
# is surprising. Never a bare path - a path is not a command.
# Which printed card covers this finding?
#
# Every item carries one, approvable or not - and especially the ones that need
# a human, because those are the ones where the operator has to decide something
# and a reference is the difference between deciding and guessing. A reference
# that points at the WRONG card is worse than none: it costs a page-turn to
# discover it was wrong.
card_for() {
  case "$1" in
    uid0|emptypw|rootadj)   printf 'CARD 1 - UID-0 account that is not root' ;;
    sshkey)                 printf 'CARD 2 - SSH key you do not recognise' ;;
    cron|crondeep)          printf 'CARD 3 - scheduled job that calls home' ;;
    unit|unittmp|unitdeep|unitdropin|unitdropindeep|rogueunit)
                            printf 'CARD 4 - systemd unit that calls home, or runs from /tmp' ;;
    suid|suidunpackaged)    printf 'CARD 5 - SUID interpreter' ;;
    tmpproc|netproc)        printf 'CARD 6 - process running from /tmp, or with a deleted executable' ;;
    nopasswd)               printf 'CARD 7 - passwordless sudo you did not configure' ;;
    port|udpport)           printf 'CARD 8 - unexpected listening port' ;;
    # Not CARD 8. That card is about a port; this finding is about a file
    # nothing can account for, and it fires just as loudly for an OUTBOUND
    # connection, where there is no listening port to close at all.
    netunpackaged)          printf 'CARD 17 - a binary no package installed is talking on the network' ;;
    etcchange)              printf 'CARD 9 - /etc changed and it was not you' ;;
    svcshell|admingroup)    printf 'CARD 10 - service account with a shell, or in an admin group' ;;
    rcdeep|rcfile)          printf 'CARD 11 - shell start-up file that launches something' ;;
    netprocsvc)             printf 'CARD 12 - a shell or interpreter is holding a network connection' ;;
    sshrootlogin|sshemptypw) printf 'CARD 13 - SSH is configured to let them in' ;;
    *)                      printf 'playbooks/remediation-cards.md' ;;
  esac
}

# Is guardian currently holding sentry's tree to a frozen copy?
guardian_is_armed() {
  local g=${CCDC_GUARDIAN_DIR:-/usr/local/lib/node-health}
  [ -d "$g/.repair/sentry" ] || return 1
  systemctl is-active --quiet node-health.service 2>/dev/null && return 0
  systemctl is-active --quiet node-health-watch.service 2>/dev/null && return 0
  return 1
}

held_reason() {
  local check=$1 subject=$2 desc=$3 payload unit home f fp comment n pid
  case "$check" in

    sshkey)
      home=${subject%/.ssh/*}
      printf '\n       A key in this file can log in as that account. Recognise every\n'
      printf '       one of them or remove it.\n\n'
      n=0
      while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        comment=$(printf '%s' "$line" | awk '{print $NF}')
        n=$((n + 1))
        if [ -n "$fp" ]; then
          printf '         %-52s %s\n' "$fp" "$comment"
        else
          printf '         (line %s could not be parsed as a key - look at it yourself)\n' "$n"
        fi
      done <"$subject" 2>/dev/null
      printf '\n       I am not going to delete one for you, because deleting the wrong\n'
      printf '       line locks you out of a box you are being scored on.\n\n'
      printf '       You are logged in over SSH right now, and the key that let you in\n'
      printf '       is written in the SSH log. This prints its fingerprint:\n\n'
      printf '         sudo journalctl -u ssh | grep "Accepted publickey" | tail -1\n\n'
      printf '       That one is yours. To delete a DIFFERENT one, paste the command\n'
      printf '       printed under it below - each names its key by fingerprint, so you\n'
      printf '       are never translating a row into an action, and the list re-sorting\n'
      printf '       cannot change what a command deletes:\n\n'
      while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        [ -n "$fp" ] || continue
        comment=$(printf '%s' "$line" | awk '{print $NF}')
        printf '         to delete %s:\n' "$comment"
        printf '           sudo %s/baseline.sh --config %s \\\n' "$qkit" "$qconfig"
        printf '                --remove-key %s --apply\n\n' "$fp"
      done <"$subject" 2>/dev/null
      printf '       That command refuses to remove the key your own session is using,\n'
      printf '       so it cannot lock you out even if you paste the wrong one.\n'
      return 0 ;;

    crondeep)
      unit=${subject%%::*}; payload=${subject#*::}
      printf '\n       A scheduled job runs a file that contains a reverse shell.\n\n'
      printf '         the job:     %s\n' "$unit"
      printf '         it runs:     %s\n\n' "$payload"
      printf '       This is not automated because the job lives in a SHARED crontab,\n'
      printf '       where removing the file leaves the schedule behind and removing\n'
      printf '       the whole crontab takes your own entries with it.\n\n'
      printf '       Read both, then remove the payload and the line that calls it:\n\n'
      printf '         sudo cat %q\n' "$payload"
      printf '         sudo crontab -l -u %s\n\n' "$(basename -- "$unit")"
      printf '         sudo cp -a %q /var/tmp/ccdc-evidence/\n' "$payload"
      printf '         sudo rm -f %q\n' "$payload"
      printf '         sudo crontab -e -u %s     # delete the line that ran it\n\n' "$(basename -- "$unit")"
      printf '       Find what WROTE the job before you move on, or it comes back.\n'
      return 0 ;;

    tmpproc|netproc)
      # The subject carries the pid, so fill it in. Printing "--pid PID" next to
      # a finding that already names the pid is the same defect as printing
      # "[N]" - it asks the operator to translate, under time pressure, for no
      # reason.
      pid=$(printf '%s' "$subject" | sed -n 's/^pid\([0-9][0-9]*\):.*/\1/p')
      printf '\n       A process is running that should not be, and its evidence only\n'
      printf '       exists while it is alive: the socket to whoever is on the other\n'
      printf '       end, its parent - which is the way back in - and, if the file was\n'
      printf '       deleted, the only copy of the executable left in existence.\n\n'
      printf '       Kill it first and the incident report becomes "we found something\n'
      printf '       and removed it". Capture first and it names an address and a\n'
      printf '       parent process.\n\n'
      if [ -n "$pid" ]; then
        printf '       Capture it, then kill it BY PID - never by name, because this\n'
        printf '       box runs a scored python web server:\n\n'
        printf '         sudo %s/preserve.sh --config %s --pid %s --freeze --apply\n' \
          "$qkit" "$qconfig" "$pid"
        printf '         sudo kill -9 %s\n\n' "$pid"
        printf '       What started it, which is the part that stops it coming back:\n\n'
        printf '         sudo ps -o ppid= -p %s | xargs -r ps -o pid,user,cmd -p\n\n' "$pid"
      else
        printf '       Find it, then capture it, then kill it BY PID:\n\n'
        printf '         sudo ls -l /proc/*/exe 2>/dev/null | grep -E "/(tmp|var/tmp|dev/shm)/"\n'
        printf '         sudo %s/preserve.sh --config %s --pid PID --freeze --apply\n' "$qkit" "$qconfig"
        printf '         sudo kill -9 PID\n\n'
      fi
      printf '       Or let baseline.sh do the whole sequence, in order, and refuse to\n'
      printf '       kill anything it could not capture first:\n\n'
      printf '         sudo %s/baseline.sh --config %s\n' "$qkit" "$qconfig"
      return 0 ;;

    nopasswd)
      printf '\n       Passwordless sudo is configured. Every line of it is a way to\n'
      printf '       become root with no credential at all.\n\n'
      printf '       Not automated because a malformed sudoers file locks EVERY account\n'
      printf '       out of root, including yours, and the only way back is the console.\n\n'
      printf '       Read them, and compare against what the packet says should exist:\n\n'
      printf '         sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/\n\n'
      printf '       Change them with the editor that refuses to save a broken file:\n\n'
      printf '         sudo visudo                       # the main file\n'
      printf '         sudo visudo -f /etc/sudoers.d/THE_FILE\n'
      printf '         sudo visudo -c                    # MUST say "parsed OK"\n\n'
      printf '       Keep this shell open until visudo -c passes.\n'
      return 0 ;;

    netprocsvc)
      printf '\n       An interpreter is holding a listening port. That is normal for a\n'
      printf '       scored service written in python or php, and it is also exactly\n'
      printf '       what a web shell looks like. The two are indistinguishable from\n'
      printf '       the process name alone, which is why this needs you.\n\n'
      printf '       Read the command line and the unit that owns it:\n\n'
      printf '         sudo ss -tulnp | grep -i %q\n' "$(basename -- "$subject")"
      printf '         sudo ps -o pid,ppid,unit,cmd -C %q\n\n' "$(basename -- "$subject")"
      printf '       If the command line matches what the packet says you serve, it is\n'
      printf '       your service. If it serves a directory you do not recognise, or it\n'
      printf '       has no unit at all, it is not.\n'
      return 0 ;;

    etcchange)
      printf '\n       Files under /etc changed in the last half hour. Early in an event\n'
      printf '       most of these are yours, which is why it is amber and last.\n\n'
      printf '       What changed:\n\n'
      printf '         sudo find /etc -xdev -type f -mmin -30 -printf "%%TH:%%TM %%p\\n" | sort\n\n'
      printf '       For anything you did not do, compare it against what shipped and\n'
      printf '       against your own restore point:\n\n'
      printf '         sudo %s/baseline.sh --config %s --status\n' "$qkit" "$qconfig"
      printf '         sudo %s/backup.sh --config %s --list\n' "$qkit" "$qconfig"
      printf '         sudo %s/backup.sh --config %s --diff /etc/THE_FILE\n' "$qkit" "$qconfig"
      return 0 ;;

    sshrootlogin|sshemptypw)
      printf '\n       The SSH daemon is configured to allow a login it should not.\n\n'
      printf '       Never automated, and not because it is hard: this is the config you\n'
      printf '       are logged in THROUGH. A bad edit ends your session and the event.\n\n'
      printf '       Read what the daemon will ACTUALLY do - this resolves every Include\n'
      printf '       and names the file that set each value, so a drop-in enabling root\n'
      printf '       logins is found while sshd_config still says no:\n\n'
      printf '         sudo %s/sshd.sh --config %s\n\n' "$qkit" "$qconfig"
      printf '       Then change it transactionally. It validates with sshd -t, arms a\n'
      printf '       rollback, and only then reloads:\n\n'
      printf '         sudo %s/sshd.sh --config %s --apply\n' "$qkit" "$qconfig"
      printf '         # open a SECOND terminal and log in before the next line\n'
      printf '         sudo %s/sshd.sh --config %s --confirm\n' "$qkit" "$qconfig"
      return 0 ;;

    suidunpackaged)
      printf '\n       A setuid-root program that no package owns. Anyone who can run it\n'
      printf '       runs it as root.\n\n'
      printf '       Usually a packaging quirk, occasionally a backdoor, and the way to\n'
      printf '       tell is whether it is a copy of a shell:\n\n'
      printf '         sudo dpkg -S %q || sudo dpkg -S %q\n' "$subject" "${subject#/usr}"
      printf '         sudo cmp -s -- %q /bin/dash && echo "THIS IS DASH - treat as RED"\n\n' "$subject"
      printf '       If nothing owns it, clear the bit first - that neutralises it and\n'
      printf '       leaves the file for evidence:\n\n'
      printf '         sudo cp -a %q /var/tmp/ccdc-evidence/\n' "$subject"
      printf '         sudo chmod -s %q\n' "$subject"
      return 0 ;;

    netunpackaged)
      printf '\n       Something is listening on the network and no package owns the\n'
      printf '       program behind it.\n\n'
      printf '       Find the owner before you touch it - the unit, not the name:\n\n'
      printf '         sudo %s/surface.sh --config %s\n\n' "$qkit" "$qconfig"
      printf '       If the packet does not list that port as scored, it should not be\n'
      printf '       reachable. Close it at the firewall and stop the thing serving it,\n'
      printf '       in that order, so you are never relying on one of the two.\n'
      return 0 ;;

    port|udpport)
      printf '\n       Something is listening that your config does not account for.\n\n'
      printf '         %s\n\n' "$subject"
      printf '       Not automated because closing a port the scoring engine is\n'
      printf '       checking costs you that service for as long as it stays shut, and\n'
      printf '       from inside the box the two look identical.\n\n'
      printf '       Find what is holding it, by unit and package rather than by name:\n\n'
      printf '         sudo %s/surface.sh --config %s\n\n' "$qkit" "$qconfig"
      printf '       Then check that port against the packet. If the packet does not\n'
      printf '       list it, stop the thing serving it AND close it at the firewall -\n'
      printf '       in that order, so you are never relying on only one of the two:\n\n'
      printf '         sudo systemctl stop THE_UNIT\n'
      printf '         sudo %s/fw.sh --config %s --apply\n' "$qkit" "$qconfig"
      printf '         sudo %s/fw.sh --config %s --confirm   # from a NEW connection\n' "$qkit" "$qconfig"
      return 0 ;;

    rogueunit)
      printf '\n       A systemd unit that nothing accounts for.\n\n'
      printf '         %s\n\n' "$subject"
      printf '       Held rather than removed because a unit your scored service pulls\n'
      printf '       in also looks like this, and removing one takes the service with\n'
      printf '       it.\n\n'
      printf '       Read what it actually runs, and what depends on it:\n\n'
      printf '         sudo systemctl cat %s\n' "$(basename -- "$subject")"
      printf '         sudo systemctl list-dependencies --reverse %s\n\n' "$(basename -- "$subject")"
      printf '       If nothing scored depends on it and no package ships it, baseline\n'
      printf '       will remove it with an evidence copy and restart anything scored\n'
      printf '       that it touched:\n\n'
      printf '         sudo %s/baseline.sh --config %s --status\n' "$qkit" "$qconfig"
      return 0 ;;

    rcdeep|rcfile)
      printf '\n       A shell startup file runs something when that user logs in.\n\n'
      printf '       Not automated: these files live in a directory the user owns and\n'
      printf '       most of what is in them is legitimately theirs, so deleting the\n'
      printf '       file is wrong and deleting the right LINE needs eyes.\n\n'
      printf '       Look at the end of it, which is where an append lands:\n\n'
      printf '         sudo tail -20 %q\n' "${subject#*::}"
      printf '         diff /etc/skel/%s %q\n\n' "$(basename -- "${subject#*::}")" "${subject#*::}"
      printf '       Anything that RUNS a command rather than setting a variable - a\n'
      printf '       trap, a curl, a background job, a line ending in & - is the finding.\n'
      return 0 ;;
  esac
  return 1
}

render_action() {
  local check=$1 subject=$2 user group unit target base owner rest dropin pid
  case "$check" in
    uid0) printf 'lock account, remove login shell, then delete UID-0 alias while retaining its home (no pkill): %q' "$subject" ;;
    emptypw) printf 'lock account and remove login shell: %q' "$subject" ;;
    svcshell) printf 'remove service-account login shell and stop its current processes: %q' "$subject" ;;
    admingroup)
      user=${subject%%/*}; group=${subject#*/}
      printf 'remove %q from admin group %q' "$user" "$group" ;;
    cron) printf 'preserve evidence, then remove scheduled job %q' "$subject" ;;
    crondeep)
      unit=${subject%%::*}; target=${subject#*::}
      printf 'preserve both; strip the schedule lines naming %q from %q, then delete the payload' "$target" "$unit" ;;
    unit|unittmp)
      printf 'preserve unit/drop-ins; stop, disable, and remove %q; reload systemd' "$(basename -- "$subject")" ;;
    unitdeep)
      unit=${subject%%::*}; target=${subject#*::}; base=$(basename -- "$unit")
      printf 'preserve both; stop/disable %q, remove its unit, timer and drop-ins, then delete the payload %q' "$base" "$target" ;;
    unitdropin)
      owner=${subject%%::*}; dropin=${subject#*::}
      printf 'preserve and remove only malicious drop-in %q; reload systemd and try-restart %q' "$dropin" "$owner" ;;
    unitdropindeep)
      owner=${subject%%::*}; rest=${subject#*::}; dropin=${rest%%::*}; target=${rest#*::}
      printf 'preserve all; remove drop-in %q from %q, then delete the payload %q; reload and restart the unit' "$dropin" "$owner" "$target" ;;
    suid) printf 'strip the SUID bit from %q (do not delete it)' "$subject" ;;
    nopasswd)
      printf 'preserve and remove the sudoers drop-in %q, then run visudo -c and put it straight back if the ruleset no longer parses' "$subject" ;;
    suidunpackaged)
      printf 'preserve %q, clear its setuid/setgid bits FIRST so the escalation is dead even if the delete fails, then remove it' "$subject" ;;
    rogueunit)
      base=$(basename -- "$subject")
      printf 'preserve %q; stop, disable and remove it, reload systemd, then re-check every scored service and restore the unit if one stopped answering' "$base" ;;
    tmpproc|netproc|netunpackaged)
      pid=$(subject_pid "$subject" 2>/dev/null) || pid=''
      target=$(printf '%s' "$subject" | sed 's/^pid[0-9]*://')
      if [ -n "$pid" ]; then
        printf 'capture pid %s (%s) with preserve.sh - socket, parent and executable - and only then kill it' "$pid" "$target"
        # Say which of the two it will be. "delete the executable afterwards"
        # read as a promise about a file that, for a packaged interpreter, must
        # not be deleted at all.
        case "$target" in
          *' (deleted)')
            printf '. Its executable is already unlinked, so the capture is the only copy that will ever exist' ;;
          *)
            if exe_is_unpackaged "$target"; then
              printf '; then delete %s, which no package owns' "$target"
            else
              printf '; a package owns %s and the rest of the box shares it, so the file STAYS' "$target"
            fi ;;
        esac
      else
        printf 'capture and kill the process running %s - but nothing is running it now, so this will be skipped' "$target"
      fi ;;
    port|udpport)
      if [ "$check" = udpport ]; then target=$(holder_of_port udp "$subject"); else target=$(holder_of_port tcp "$subject"); fi
      if [ -n "$target" ]; then
        unit=$(pid_service "$target" 2>/dev/null) || unit=''
        owner=$(pid_exe "$target" 2>/dev/null) || owner='?'
        if [ -n "$unit" ]; then
          printf 'port %s is held by %s (pid %s, %s); stop and disable that unit, then re-check every scored service and start it again if one stopped answering' "$subject" "$unit" "$target" "$owner"
        else
          printf 'port %s is held by pid %s (%s) under no unit at all; capture it, kill it, then re-check every scored service' "$subject" "$target" "$owner"
        fi
      else
        printf 'nothing holds port %s any more - this will be skipped' "$subject"
      fi ;;
    netprocsvc)
      pid=$(subject_pid "$subject" 2>/dev/null) || pid=''
      printf 'no systemd unit owns pid %s (%s), so it is not a scored service; capture it, kill it, then re-check every scored service. The interpreter itself is package-owned and STAYS - what the attacker put here is the script it was told to run, and that is a different finding' "${pid:-?}" "${subject#pid*:}" ;;
    rcdeep) target=${subject#*::}; printf 'preserve and remove launched payload %q' "$target" ;;
    rcfile) printf 'preserve %q and remove only the exact lines that still match the detector' "$subject" ;;
    *) printf 'no automatic action' ;;
  esac
}

queue_has() {
  local want_check=$1 want_subject=$2 sev check subject
  [ -f "$queue" ] || return 1
  while IFS='|' read -r sev check subject; do
    [ "$check" = "$want_check" ] && [ "$subject" = "$want_subject" ] && return 0
  done <"$queue"
  return 1
}

new_state_file() {
  mktemp "$state_dir/.sentry-state.XXXXXX" \
    || ccdc_die "cannot create a private state file in $state_dir"
}

atomic_empty() {
  local target=$1 tmp
  tmp=$(new_state_file)
  mv -f -- "$tmp" "$target" || { rm -f -- "$tmp"; return 1; }
}

publish_review_snapshot() {
  local tmp
  tmp=$(new_state_file)
  if [ -f "$queue" ] && ! cp -- "$queue" "$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  mv -f -- "$tmp" "$reviewed" || { rm -f -- "$tmp"; return 1; }
}

write_alerts() {
  local n=0 sev check subject desc i=0 heldred=0 heldamber=0 action watch_count=0 tmp quoted
  tmp=$(new_state_file) || return 1
  [ -f "$queue" ] && n=$(wc -l <"$queue" 2>/dev/null | tr -d ' ') || true
  [ -n "$n" ] || n=0
  [ -f "$watch_pending" ] && watch_count=$(grep -c '^===== watch event ' "$watch_pending" 2>/dev/null || true)
  [ -n "$watch_count" ] || watch_count=0
  {
    printf 'ALERTS  %s  (supervised sentry, triage %ss / full sweep %ss)\n' "$(date -u '+%H:%M:%SZ')" "$interval" "$watch_interval"
    # Say when the thing producing this report is older than the kit it came
    # from. Sentry runs from its own copy on purpose - an attacker editing the
    # operator's tree must not be able to steer a root loop - but that means
    # fixes never arrive on their own, and a stale supervisor reports stale
    # findings in stale wording while looking exactly like a current one.
    drift=$(ccdc_tree_drift "$SCRIPT_DIR" "$install_dir" 2>/dev/null)
    if [ -n "$drift" ]; then
      printf '\n  THE RUNNING SENTRY IS OLDER THAN YOUR KIT (%s file(s) differ)\n' \
        "$(printf '%s\n' "$drift" | grep -c .)"
      printf '  It is executing a private copy taken when you installed it, so\n'
      printf '  nothing you have changed since has reached it:\n\n'
      printf '%s\n' "$drift" | head -8 | sed 's/^/      /'
      [ "$(printf '%s\n' "$drift" | grep -c .)" -gt 8 ] \
        && printf '      ... and %s more\n' "$(($(printf '%s\n' "$drift" | grep -c .) - 8))"
      printf '\n  Bring it up to date. Your approval queue and evidence are kept.\n\n'
      # Guardian repairs sentry's installed tree from a copy frozen when
      # GUARDIAN was installed, and it cannot tell your legitimate update from
      # someone tampering with sentry - that ambiguity is the entire point of
      # it. So reinstalling sentry underneath an armed guardian appears to
      # succeed and is silently reverted on the next tick. Measured: a fixed
      # triage.sh was installed at 05:25 and was back to the old one at 05:26.
      if guardian_is_armed; then
        printf '  Guardian is armed, and it restores sentry from a copy taken when\n'
        printf '  GUARDIAN was installed - so reinstalling sentry on its own looks\n'
        printf '  like it worked and is undone within a minute. Take guardian down\n'
        printf '  first, update, then put it back so it re-takes its copy:\n\n'
        printf '      sudo '"$qkit"'/guardian.sh --config '"$qconfig"' --uninstall --apply\n'
        printf '      sudo '"$qkit"'/sentry.sh   --config '"$qconfig"' --install   --apply\n'
        printf '      sudo '"$qkit"'/guardian.sh --config '"$qconfig"' --install   --apply\n\n'
        printf '  Nothing is watching for that gap. Do it in one go.\n'
      else
        printf '      sudo '"$qkit"'/sentry.sh --config '"$qconfig"' --install --apply\n'
      fi
    fi
    printf '==================================================================\n\n'
    if [ -s "$triage_health" ] || [ -s "$watch_health" ]; then
      printf '  MONITOR HEALTH PROBLEM - detection is not current:\n'
      [ ! -s "$triage_health" ] || sed 's/^/    /' "$triage_health"
      [ ! -s "$watch_health" ] || sed 's/^/    /' "$watch_health"
      health_age "$watch_health" "$watch_last" "$watch_interval" "full sweep"
      health_age "$triage_health" "" "$interval" "triage"
      [ ! -s "$triage_health" ] \
        || printf '\n  The action queue was cleared and cannot execute until triage refreshes cleanly.\n'
      printf '\n'
    fi
    if [ "$n" -eq 0 ]; then
      printf '  Nothing waiting for your sign-off.\n\n'
    else
      printf '  %s current action(s) WAITING FOR SIGN-OFF. Review each one, then run the\n' "$n"
      printf '  approve command printed under it.\n\n'
      while IFS='|' read -r sev check subject; do
        [ -n "${sev:-}" ] || continue
        i=$((i + 1)); action=$(render_action "$check" "$subject")
        printf -v quoted '%q' "$subject"
        printf '  [%s] %-5s %s  %s\n' "$i" "$sev" "$check" "$quoted"
        printf '        will: %s\n' "$action"
        # The item's own command, with its real number substituted. The usage
        # line used to read "--approve [N]" directly above a list labelled
        # "[1]" and "[2]", so both halves of the screen said to type brackets.
        # In bash "[2]" is a glob - a character class - and with no file named
        # "2" to match, it reaches the tool as the literal string "[2]" and is
        # rejected as not a number. The operator did exactly what was printed.
        printf '        approve: sudo '"$qkit"'/sentry.sh --config '"$qconfig"' --approve %s --apply\n' "$i"
        [ "$sev" = RED ] \
          || printf '        note:  AMBER - this may well be yours, so a bulk approve skips it. It needs its own number.\n'
        printf '        more:  playbooks/remediation-cards.md  %s\n\n' "$(card_for "$check")"
      done <"$queue"
    fi

    if [ -f "$findings" ]; then
      while IFS='|' read -r sev check subject desc; do
        [ "${sev:-}" = RED ] || continue
        queue_has "$check" "$subject" && continue
        if [ "$heldred" -eq 0 ]; then
          printf '  RED findings sentry will NOT touch - YOU must decide:\n'
          heldred=1
        fi
        # A label, not a command: %q rendered "/dev/shm/.kworkerd (deleted)"
        # as "\ \(deleted\)". The commands under it are quoted where it matters.
        printf '    %-12s %s\n' "$check" "$subject"
        printf '                 %s\n' "$desc"
        if ! held_reason "$check" "$subject" "$desc"; then
          case "$check" in
            svcshell|admingroup|uid0|emptypw)
              printf '                 held: this account is protected by your config, or the\n'
              printf '                 name is not one this tool will act on. Check it against\n'
              printf '                 CCDC_ALLOWED_USERS before doing anything by hand.\n' ;;
            unit|unittmp|unitdeep)
              printf '                 held: the unit is protected by your config, or the path\n'
              printf '                 is not the one that is live now. Read it first:\n'
              printf '                   sudo systemctl cat %s\n' "$(basename -- "${subject%%::*}")" ;;
            *)
              printf '                 held: there is no automatic action for a %s finding\n' "$check"
              printf '                 and no written reason here yet. That is a gap in this\n'
              printf '                 tool, not a judgement about the finding - treat it by\n'
              printf '                 hand and say so.\n' ;;
          esac
        fi
        printf '                 more:  playbooks/remediation-cards.md  %s\n' \
          "$(card_for "$check")"
        printf '\n'
      done <"$findings"
      [ "$heldred" -eq 1 ] && printf '\n'

      # Anything already carrying its own number above does NOT belong here.
      # Queueing AMBER items made the two sets overlap for the first time, and
      # the operator got the same finding twice: once with an approve command
      # and once, further down, under a heading that says it needs them.
      heldamber=0
      while IFS='|' read -r sev check subject desc; do
        [ "${sev:-}" = AMBER ] || continue
        queue_has "$check" "$subject" && continue
        if [ "$heldamber" -eq 0 ]; then
          printf '  NEEDS YOU - and here is exactly why\n\n'
          heldamber=1
        fi
        # Not %q here: this is a label being read, not a command being pasted,
        # and %q rendered "/dev/shm/.kworkerd (deleted)" as "\ \(deleted\)".
        printf '    %-12s %s\n' "$check" "$subject"
        printf '                 %s\n' "$desc"
        held_reason "$check" "$subject" "$desc" || \
          printf '                 held: no written guidance for a %s finding yet.\n' "$check"
        printf '                 more:  playbooks/remediation-cards.md  %s\n' \
          "$(card_for "$check")"
        printf '\n'
      done <"$findings"
    fi

    if [ "$watch_count" -gt 0 ]; then
      printf '\n  %s unacknowledged change/canary event(s):\n' "$watch_count"
      tail -n 80 "$watch_pending" | sed 's/^/    /'
      printf '\n  After review: sudo '"$qkit"'/sentry.sh --config '"$qconfig"' --ack\n'
    fi
    printf '\n  Full ranked detail: sudo '"$qkit"'/triage.sh --config '"$qconfig"'\n'
    printf '  Verify scored services FROM OFF THE BOX; an on-box probe cannot see scorer reachability.\n'
  } >"$tmp" || { rm -f -- "$tmp"; return 1; }
  mv -f -- "$tmp" "$alerts" || { rm -f -- "$tmp"; return 1; }
}

run_triage() {
  local rc=0 now fresh=no
  rm -f -- "$findings"
  timeout "$triage_timeout" "$SCRIPT_DIR/triage.sh" --config "$config" --quiet \
    >/dev/null 2>>"$log" || rc=$?
  [ -f "$findings" ] && fresh=yes
  if { [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; } || [ "$fresh" != yes ]; then
    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '%s triage failed (exit %s or no fresh findings file); inspect %s\n' "$now" "$rc" "$log" >"$triage_health"
    : >"$queue"
    slog "HEALTH triage failed rc=$rc fresh_findings=$fresh"
    return 4
  fi
  rm -f -- "$triage_health"
  return 0
}

rebuild_queue() {
  local sev check subject desc key new=0 newred=0
  : >"$queue.next"; : >"$seen.next"
  [ -f "$seen" ] || : >"$seen"
  while IFS='|' read -r sev check subject desc; do
    [ -n "${sev:-}" ] || continue
    case "$sev" in RED|AMBER) ;; *) continue ;; esac
    key="$check|$subject"
    printf '%s\n' "$key" >>"$seen.next"
    if ! grep -qxF -- "$key" "$seen" 2>/dev/null; then
      new=$((new + 1)); [ "$sev" = RED ] && newred=$((newred + 1))
      slog "new sev=$sev check=$check subject=$subject"
    fi
    # The queue used to be RED-only, which quietly meant that every finding
    # about a listening port or a socket-holding process - all of them AMBER,
    # because all of them might be yours - could be detected, described, and
    # never offered. That is the finish line the operator kept falling off.
    # AMBER items are queued and numbered like anything else; what they do NOT
    # get is the bulk sweep. See do_approve.
    if { [ "$sev" = RED ] || offerable_at_amber "$check"; } \
      && can_automate "$check" "$subject"; then
      printf '%s|%s|%s\n' "$sev" "$check" "$subject" >>"$queue.next"
    fi
  done <"$findings"
  mv -f -- "$queue.next" "$queue"
  mv -f -- "$seen.next" "$seen"
  if [ "$newred" -gt 0 ] && [ "$bell" -eq 1 ] && [ -t 1 ]; then printf '\a' || true; fi
  printf '%s|%s\n' "$new" "$newred"
}

# How stale is a health failure, and when does the next attempt land? A bare
# timestamp cannot answer either, and the two cases it conflates - "failed once
# and is about to retry" versus "has been failing for twenty minutes" - want
# opposite reactions from the operator.
health_age() {
  local hfile=$1 lastfile=$2 every=$3 label=$4 stamp now age last due
  [ -s "$hfile" ] || return 0
  stamp=$(awk '{print $1; exit}' "$hfile" 2>/dev/null)
  now=$(date +%s)
  age=$(date -d "$stamp" +%s 2>/dev/null) || return 0
  age=$((now - age))
  printf '      that was %ss ago.' "$age"
  if [ -f "$lastfile" ]; then
    read -r last <"$lastfile" 2>/dev/null || last=0
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    due=$((last + every - now))
    if [ "$due" -gt 0 ]; then
      printf ' Next %s attempt in %ss.\n' "$label" "$due"
    else
      printf ' The next %s attempt is overdue - the loop may be stuck.\n' "$label"
    fi
  else
    printf '\n'
  fi
  if [ "$age" -gt $((every * 3)) ]; then
    printf '      It has not recovered across %s attempts. Treat detection as DOWN:\n' "$((age / every))"
    printf '        sudo systemctl status %s.service --no-pager -l\n' "${CCDC_SENTRY_NAME:-ccdc-sentry}"
    printf '        sudo %s/sentry.sh --config %s --once\n' "$qkit" "$qconfig"
  fi
}

run_watch_if_due() {
  local now previous=0 rc=0 key=''
  now=$(date +%s)
  [ -f "$watch_last" ] && read -r previous <"$watch_last" || true
  case "$previous" in ''|*[!0-9]*) previous=0 ;; esac
  [ $((now - previous)) -ge "$watch_interval" ] || return 0
  printf '%s\n' "$now" >"$watch_last"
  timeout "$watch_timeout" "$SCRIPT_DIR/watch.sh" --config "$config" \
    --interval "$watch_interval" --once >"$watch_last.tmp" 2>&1 || rc=$?
  mv -f -- "$watch_last.tmp" "$watch_last.output"
  case "$rc" in
    0) rm -f -- "$watch_health"; return 0 ;;
    3)
      key=$(grep -E 'CANARY|BOX CHANGED|TRIPPED|AUDIT|HINT|^[[:space:]]+---|^[[:space:]]+[<>]' "$watch_last.output" 2>/dev/null \
        | cksum | awk '{print $1":"$2}')
      if [ -n "$key" ] && { [ ! -f "$watch_pending_key" ] || ! grep -qxF -- "$key" "$watch_pending_key"; }; then
        {
          printf '===== watch event %s =====\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
          cat "$watch_last.output"
          printf '\n'
        } >>"$watch_pending"
        printf '%s\n' "$key" >>"$watch_pending_key"
        tail -n 600 "$watch_pending" >"$watch_pending.tmp" && mv -f -- "$watch_pending.tmp" "$watch_pending"
      fi
      rm -f -- "$watch_health"
      return 0
      ;;
    *)
      printf '%s watch.sh failed (exit %s); inspect %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$rc" "$watch_last.output" >"$watch_health"
      slog "HEALTH watch failed rc=$rc"
      return 4
      ;;
  esac
}

run_pass_locked() {
  local counts='0|0' queued_count triage_rc=0 watch_rc=0
  if ! run_triage; then
    triage_rc=4
  else
    counts=$(rebuild_queue)
  fi
  # Triage and the broader canary/change sweep are independent detection
  # layers. A wedged or broken triage pass must not suppress the canary path.
  run_watch_if_due || watch_rc=$?
  printf '%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$last_pass"
  write_alerts
  queued_count=$(wc -l <"$queue" 2>/dev/null || true)
  slog "pass new=${counts%%|*} new_red=${counts#*|} queued=$queued_count"
  [ "$triage_rc" -eq 0 ] && [ "$watch_rc" -eq 0 ] || return 4
  return 0
}

run_pass() {
  local rc
  if ! acquire_lock; then
    slog "pass skipped: another sentry command holds the lock"
    return 0
  fi
  run_pass_locked; rc=$?
  release_lock
  return "$rc"
}

new_evidence_case() {
  local check=$1
  artifact_seq=$((artifact_seq + 1))
  evidence_case="$state_dir/removed/$(ccdc_now)-$$-$artifact_seq-$check"
  [ ! -L "$state_dir/removed" ] || return 1
  mkdir -p -- "$evidence_case" || return 1
  chmod 0700 "$evidence_case" 2>/dev/null || true
  evidence_copy_seq=0
  evidence_last=''
}

preserve_into_case() {
  local path=$1 destination
  evidence_last=''
  [ -e "$path" ] || [ -L "$path" ] || return 0
  evidence_copy_seq=$((evidence_copy_seq + 1))
  destination="$evidence_case/$evidence_copy_seq-$(basename -- "$path")"
  cp -a -- "$path" "$destination" || return 1
  evidence_last=$destination
}

# Put a preserved copy back where it came from.
#
# Every caller is a rollback after a scored service stopped answering, which is
# the one moment where silently doing nothing is worst - so this says whether
# it worked instead of discarding the error.
#
# It exists because two rollbacks reconstructed the saved path by hand, as
# "$evidence_case/$(basename -- "$path")", and preserve_into_case writes
# "$evidence_case/1-$(basename ...)" - the sequence number is what keeps two
# files with the same name apart. Neither cp could ever find its source, and
# both sent the error to /dev/null. Measured on the lab VM: a rogue unit that
# held a scored port was removed, the scored check correctly failed, the report
# correctly said FAILED - and the unit file was gone, the service not-found,
# the port dead, under a line promising it would be put back.
restore_from_case() {
  local saved=$1 dest=$2
  if [ -z "$saved" ] || [ ! -e "$saved" ]; then
    slog "CANNOT ROLL BACK $dest: no preserved copy in ${evidence_case:-<no case>}"
    return 1
  fi
  if ! cp -a -- "$saved" "$dest"; then
    slog "CANNOT ROLL BACK $dest: restoring it from $saved failed"
    return 1
  fi
  return 0
}

action_uid0() {
  local user=$1 record uid auth_file
  record=$(getent passwd "$user") || return 1
  uid=$(printf '%s\n' "$record" | cut -d: -f3)
  [ "$uid" = 0 ] && [ "$user" != root ] || return 1
  new_evidence_case uid0 || return 1
  for auth_file in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do preserve_into_case "$auth_file" || return 1; done
  printf '%s\n' "$record" >"$evidence_case/account.record"
  passwd -l "$user" || return 1
  usermod -s /usr/sbin/nologin "$user" || return 1
  # Never recursively remove a UID-0 alias's home: it may deliberately point at
  # /root or at scored content. The account is removed; its files remain for
  # deliberate review/restoration.
  userdel -f "$user"
}

action_emptypw() {
  local user=$1 auth_file
  new_evidence_case emptypw || return 1
  for auth_file in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do preserve_into_case "$auth_file" || return 1; done
  passwd -l "$user" && usermod -s /usr/sbin/nologin "$user"
}

action_svcshell() {
  local user=$1 uid auth_file
  uid=$(id -u "$user" 2>/dev/null) || return 1
  [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ] || return 1
  new_evidence_case svcshell || return 1
  for auth_file in /etc/passwd /etc/shadow; do preserve_into_case "$auth_file" || return 1; done
  usermod -s /usr/sbin/nologin "$user" || return 1
  pkill -u "$user" 2>/dev/null || true
  return 0
}

action_admingroup() {
  local user=${1%%/*} group=${1#*/} auth_file
  new_evidence_case admingroup || return 1
  for auth_file in /etc/group /etc/gshadow; do preserve_into_case "$auth_file" || return 1; done
  gpasswd -d "$user" "$group"
}

action_cron() {
  local source=$1
  new_evidence_case cron || return 1
  preserve_into_case "$source" || return 1
  rm -f -- "$source"
}

action_crondeep() {
  local source=${1%%::*} target=${1#*::} tmp rc=0
  new_evidence_case crondeep || return 1
  preserve_into_case "$source" && preserve_into_case "$target" || return 1
  tmp="$evidence_case/cron.cleaned"
  grep -vF -- "$target" "$source" >"$tmp" || rc=$?
  [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ] || return 1
  cat "$tmp" >"$source" || return 1
  rm -f -- "$target"
}

# The scored re-check belongs here too, not only in action_rogueunit.
#
# protected_unit only knows the names in the packet. A unit the scored service
# quietly depends on - or, as measured on the lab VM, one holding a port the
# watchdog probes - passes that check and is removed with nothing watching.
# The same unit reported as `rogueunit` got a re-check and a rollback; reported
# as `unit` it did not, so the same file had two different safety levels
# depending on which detector named it first.
action_unit() {
  local unit=$1 base saved_unit saved_dropins
  base=$(basename -- "$unit")
  new_evidence_case unit || return 1
  preserve_into_case "$unit" || return 1
  saved_unit=$evidence_last
  preserve_into_case "$unit.d" || return 1
  saved_dropins=$evidence_last
  systemctl disable --now "$base" >/dev/null 2>&1 || slog "warning: could not disable $base before removal"
  rm -f -- "$unit" || return 1
  [ ! -e "$unit.d" ] || rm -rf -- "$unit.d" || return 1
  systemctl daemon-reload && systemctl reset-failed >/dev/null 2>&1
  if ! scored_still_answering; then
    slog "warning: a scored service stopped answering after removing $unit; restoring"
    restore_from_case "$saved_unit" "$unit" || return 1
    [ -z "$saved_dropins" ] || cp -a -- "$saved_dropins" "$unit.d" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now "$base" >/dev/null 2>&1
    if scored_still_answering; then
      slog "rolled back $unit; scored services are answering again"
    else
      slog "ROLLED BACK $unit and a scored service is STILL not answering - look now"
    fi
    return 1
  fi
  return 0
}

action_unitdeep() {
  local unit=${1%%::*} target=${1#*::} base stem timer
  local saved_unit saved_dropins saved_timer
  base=$(basename -- "$unit"); stem=${base%.service}; timer="$(dirname -- "$unit")/$stem.timer"
  new_evidence_case unitdeep || return 1
  preserve_into_case "$unit" || return 1;    saved_unit=$evidence_last
  preserve_into_case "$unit.d" || return 1;  saved_dropins=$evidence_last
  preserve_into_case "$timer" || return 1;   saved_timer=$evidence_last
  preserve_into_case "$target" || return 1
  systemctl disable --now "$base" "$stem.timer" >/dev/null 2>&1 \
    || slog "warning: could not disable $base/$stem.timer before removal"
  rm -f -- "$unit" "$timer" "$target" || return 1
  [ ! -e "$unit.d" ] || rm -rf -- "$unit.d" || return 1
  systemctl daemon-reload && systemctl reset-failed >/dev/null 2>&1
  if ! scored_still_answering; then
    # The unit and its timer go back. The payload does NOT: this finding exists
    # because a unit launches a file that reads as a reverse shell, and putting
    # that file back to keep a service green is not a trade anyone should make
    # silently. Say so instead, and say the unit will fail to start without it.
    slog "warning: a scored service stopped answering after removing $unit; restoring the unit, NOT the payload"
    restore_from_case "$saved_unit" "$unit" || return 1
    [ -z "$saved_dropins" ] || cp -a -- "$saved_dropins" "$unit.d" 2>/dev/null || true
    [ -z "$saved_timer" ] || cp -a -- "$saved_timer" "$timer" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now "$base" >/dev/null 2>&1
    slog "the payload $target was left deleted on purpose; $base will fail to start if it needed it, and a copy is in $evidence_case"
    return 1
  fi
  return 0
}

action_suid() {
  local path=$1
  new_evidence_case suid || return 1
  preserve_into_case "$path" || return 1
  chmod u-s -- "$path"
}

action_rcdeep() {
  local target=${1#*::}
  new_evidence_case rcdeep || return 1
  preserve_into_case "$target" || return 1
  rm -f -- "$target"
}

action_rcfile() {
  local source=$1 lines tmp rc=0
  new_evidence_case rcfile || return 1
  preserve_into_case "$source" || return 1
  lines="$evidence_case/offending.lines"; tmp="$evidence_case/cleaned"
  grep -IhE "$rc_patterns" "$source" >"$lines" 2>/dev/null || return 1
  [ -s "$lines" ] || return 1
  grep -vxFf "$lines" "$source" >"$tmp" || rc=$?
  [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ] || return 1
  cat "$tmp" >"$source"
}

# --- the actions that were "simply unwritten" ---------------------------------
#
# Each of these was detected and then not offered, which is where the operator
# fell off: thorough detection, silence at the finish line. Every one captures
# evidence first, acts, and where it can take a scored service down, checks the
# service afterwards.

# A sudoers drop-in written AFTER the box was built. Never /etc/sudoers itself,
# and never a file that predates the box - that one is probably the image's or
# yours. visudo -c decides whether it worked, because a sudoers file that no
# longer parses locks every account out of root.
action_nopasswd() {
  local path=$1 saved
  new_evidence_case nopasswd || return 1
  preserve_into_case "$path" || return 1
  saved=$evidence_last
  rm -f -- "$path" || return 1
  if ! visudo -c >/dev/null 2>&1; then
    slog "warning: visudo -c FAILED after removing $path; restoring it"
    restore_from_case "$saved" "$path" || return 1
    if visudo -c >/dev/null 2>&1; then
      slog "restored $path; the sudoers ruleset parses again"
    else
      slog "RESTORED $path and sudoers STILL does not parse - keep a root shell open"
    fi
    return 1
  fi
  return 0
}

# Setuid root and owned by no package. Clear the bit first so the escalation is
# dead even if the removal fails, then remove the file.
action_suidunpackaged() {
  local path=$1
  new_evidence_case suidunpackaged || return 1
  preserve_into_case "$path" || return 1
  chmod u-s,g-s -- "$path" || return 1
  rm -f -- "$path"
}

# An enabled unit nothing accounts for. Same shape as action_unit, plus the
# scored check - removing a unit something scored quietly pulls in takes the
# scored service with it, and that is worth finding out in five seconds rather
# than at the next scoring round.
action_rogueunit() {
  local unit=$1 base saved
  base=$(basename -- "$unit")
  new_evidence_case rogueunit || return 1
  preserve_into_case "$unit" || return 1
  saved=$evidence_last
  systemctl disable --now "$base" >/dev/null 2>&1 \
    || slog "warning: could not disable $base before removal"
  rm -f -- "$unit" || return 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl reset-failed >/dev/null 2>&1
  if ! scored_still_answering; then
    slog "warning: a scored service stopped answering after removing $unit; restoring"
    restore_from_case "$saved" "$unit" || return 1
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now "$base" >/dev/null 2>&1
    if scored_still_answering; then
      slog "rolled back $unit; scored services are answering again"
    else
      slog "ROLLED BACK $unit and a scored service is STILL not answering - look now"
    fi
    return 1
  fi
  return 0
}

# A live process. Capture BEFORE the kill or the socket, the parent and an
# unlinked executable all cease to exist - and refuse to kill what could not be
# captured, because a kill with no capture destroys the only evidence there was.
action_live_process() {
  local subject=$1 kind=$2 pid path
  pid=$(subject_pid "$subject") \
    || { slog "warning: $subject is no longer running"; return 1; }
  path=$(pid_exe "$pid" 2>/dev/null)
  [ -n "$path" ] || path=$(printf '%s' "$subject" | sed 's/^pid[0-9]*://; s/ (deleted)$//')
  # Asked again here, a second time, immediately before anything irreversible.
  # can_automate cleared this pid when the queue was built, which can be a
  # minute ago, and pids are recycled: the number that named a dropper then can
  # name the scored service now. A kill cannot be taken back.
  if pid_is_protected "$pid" "$(protection_mode_for "$kind")"; then
    slog "warning: pid $pid is now ours, the system's or a scored service's; NOT killed"
    return 1
  fi
  new_evidence_case "$kind" || return 1
  if ! "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" --freeze --apply \
       >/dev/null 2>&1; then
    # preserve refuses to SIGSTOP anything inside a scored unit's cgroup, which
    # is correct. Capture it running instead - everything except the
    # frozen-process guarantee - and only give up if that fails too.
    "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" >/dev/null 2>&1 || {
      slog "warning: could not capture pid $pid, so it was NOT killed"
      return 1
    }
  fi
  kill -9 "$pid" 2>/dev/null || true
  # Killing the process and deleting its executable are two different
  # decisions, and only the second one is about provenance.
  #
  # Measured on the lab VM, and it is the worst thing this kit has done to a
  # box: approving a netprocsvc finding for a python web shell deleted
  # /usr/bin/python3.12 - the interpreter the SCORED service runs on. The
  # running service kept serving, because its binary was already mapped, so
  # nothing looked wrong; the next restart would have failed, and every python
  # on the box was gone, with /usr/bin/python3 left as a dangling symlink.
  #
  # A dropper in /dev/shm is owned by nothing and should go. A shared,
  # package-owned interpreter is not the attacker's file - the attacker's file
  # is the script it was told to run, and that is a different finding.
  if [ -f "$path" ]; then
    if exe_is_unpackaged "$path"; then
      preserve_into_case "$path" || return 1
      rm -f -- "$path"
    else
      slog "killed pid $pid but LEFT $path in place: a package owns it and the rest of the box shares it"
    fi
  fi
  return 0
}

action_tmpproc() { action_live_process "$1" tmpproc; }
action_netproc() { action_live_process "$1" netproc; }

# An unpackaged binary that is talking on the network, and an interpreter
# holding a socket that no unit owns. Both are the live-process shape: the
# thing that makes each of them decidable was asked in can_automate, and what
# is left to do is identical - capture, then kill, then delete the file.
action_netunpackaged() { action_live_process "$1" netunpackaged; }
action_netprocsvc()    { action_live_process "$1" netprocsvc; }

# A listening port the packet does not account for.
#
# There is no such thing as removing a port, so the real subject is whatever
# holds it, and there are two quite different cases. A unit holding it can be
# stopped and disabled, and put straight back if a scored service notices -
# that is a reversible action and it is preferred. A bare process holding it
# can only be captured and killed, and a kill does not come back, which is why
# can_automate refuses every pid that could be ours, the system's or a scored
# service's before this function is ever reached.
action_port_common() {
  local netid=$1 port=$2 kind=$3 pid unit exe
  pid=$(holder_of_port "$netid" "$port")
  [ -n "$pid" ] || { slog "warning: nothing holds $netid port $port any more"; return 1; }
  if pid_is_protected "$pid" "$(protection_mode_for "$kind")"; then
    slog "warning: $netid port $port is now held by a protected process (pid $pid); NOT touched"
    return 1
  fi
  unit=$(pid_service "$pid" 2>/dev/null) || unit=''
  exe=$(pid_exe "$pid" 2>/dev/null) || exe=''
  new_evidence_case "$kind" || return 1
  {
    printf '%s port %s\n' "$netid" "$port"
    printf 'pid   %s\n' "$pid"
    printf 'unit  %s\n' "${unit:-none}"
    printf 'exe   %s\n' "${exe:-unknown}"
    ss -H -lnp "sport = :$port" 2>/dev/null
    ps -o pid,ppid,user,lstart,cmd -p "$pid" 2>/dev/null
  } >"$evidence_case/holder.txt" 2>/dev/null || true

  if [ -n "$unit" ]; then
    systemctl stop "$unit" >/dev/null 2>&1 || slog "warning: could not stop $unit"
    systemctl disable "$unit" >/dev/null 2>&1 || true
    if ! scored_still_answering; then
      slog "warning: a scored service stopped answering after stopping $unit for $netid port $port; starting it again"
      systemctl enable --now "$unit" >/dev/null 2>&1
      return 1
    fi
    return 0
  fi

  if ! "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" --freeze --apply \
       >/dev/null 2>&1; then
    "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" >/dev/null 2>&1 || {
      slog "warning: could not capture pid $pid holding $netid port $port, so it was NOT killed"
      return 1
    }
  fi
  [ -n "$exe" ] && [ -f "$exe" ] && preserve_into_case "$exe"
  kill -9 "$pid" 2>/dev/null || true
  if ! scored_still_answering; then
    slog "warning: a scored service stopped answering after killing pid $pid on $netid port $port - a kill cannot be undone; evidence is in $evidence_case"
    return 1
  fi
  return 0
}

action_port()    { action_port_common tcp "$1" port; }
action_udpport() { action_port_common udp "$1" udpport; }

# netproc's subject is an executable path, not a pid. Find the live pid for it.
resolve_pid_for_exe() {
  local want=$1 p exe
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
    exe=${exe% (deleted)}
    [ "$exe" = "$want" ] || continue
    printf '%s' "$p"
    return 0
  done
  return 1
}

# Are the scored services still answering? Used after anything that could take
# one down, so a wrong call reverses itself in seconds rather than at the next
# scoring round.
scored_still_answering() {
  local u name host port svc url waited ok
  for u in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-}; do
    u=${u##*/}
    case "$u" in *.service|*.socket) ;; *) u="$u.service" ;; esac
    systemctl list-unit-files "$u" >/dev/null 2>&1 || continue
    waited=0
    while [ "$waited" -lt 20 ]; do
      systemctl is-active --quiet "$u" 2>/dev/null && break
      sleep 0.5; waited=$((waited + 1))
    done
    systemctl is-active --quiet "$u" 2>/dev/null || return 1
  done
  while IFS='|' read -r name host port svc; do
    [ -n "${port:-}" ] || continue
    ccdc_have nc || continue
    ok=0; waited=0
    while [ "$waited" -lt 20 ]; do
      nc -z -w 2 "$host" "$port" >/dev/null 2>&1 && { ok=1; break; }
      sleep 0.5; waited=$((waited + 1))
    done
    [ "$ok" -eq 1 ] || return 1
  done < <(ccdc_tcp_checks 2>/dev/null)
  # The HTTP checks are the ones that actually say a web service is serving.
  # A port can be open while the service behind it returns 500, and scored-web
  # is graded on the response, not the handshake - so a rollback decision that
  # only looked at TCP would call a broken service healthy.
  while IFS='|' read -r name url svc; do
    [ -n "${url:-}" ] || continue
    ccdc_have curl || continue
    ok=0; waited=0
    while [ "$waited" -lt 20 ]; do
      curl -fsS -o /dev/null --max-time 3 -- "$url" >/dev/null 2>&1 && { ok=1; break; }
      sleep 0.5; waited=$((waited + 1))
    done
    [ "$ok" -eq 1 ] || return 1
  done < <(ccdc_http_checks 2>/dev/null)
  return 0
}

# A malicious drop-in leaves the unit file byte-identical while adding an
# ExecStartPost= that runs as root on next start. can_automate already accepted
# these, but execute_action had no branch for them, so the operator could sign
# off on removing a drop-in attack and get "FAILED - partial changes may have
# occurred" while the drop-in stayed. Remove only the offending fragment - the
# unit itself is legitimate and may well be scored.
action_unitdropin() {
  local owner=${1%%::*} dropin=${1#*::} parent
  new_evidence_case unitdropin || return 1
  preserve_into_case "$dropin" || return 1
  rm -f -- "$dropin" || return 1
  parent=$(dirname -- "$dropin")
  rmdir -- "$parent" 2>/dev/null || true      # only if now empty
  systemctl daemon-reload || return 1
  # Restart so the merged-in command stops being part of the running unit.
  systemctl try-restart "$owner" >/dev/null 2>&1 || slog "warning: could not restart $owner after removing $dropin"
  systemctl reset-failed >/dev/null 2>&1 || true
}

action_unitdropindeep() {
  local owner=${1%%::*} rest=${1#*::} dropin target parent
  dropin=${rest%%::*}; target=${rest#*::}
  new_evidence_case unitdropindeep || return 1
  preserve_into_case "$dropin" && preserve_into_case "$target" || return 1
  rm -f -- "$dropin" "$target" || return 1
  parent=$(dirname -- "$dropin")
  rmdir -- "$parent" 2>/dev/null || true
  systemctl daemon-reload || return 1
  systemctl try-restart "$owner" >/dev/null 2>&1 || slog "warning: could not restart $owner after removing $dropin"
  systemctl reset-failed >/dev/null 2>&1 || true
}

execute_action() {
  local check=$1 subject=$2
  evidence_case=''; evidence_last=''
  case "$check" in
    uid0) action_uid0 "$subject" ;;
    emptypw) action_emptypw "$subject" ;;
    svcshell) action_svcshell "$subject" ;;
    admingroup) action_admingroup "$subject" ;;
    cron) action_cron "$subject" ;;
    crondeep) action_crondeep "$subject" ;;
    unit|unittmp) action_unit "$subject" ;;
    unitdeep) action_unitdeep "$subject" ;;
    unitdropin) action_unitdropin "$subject" ;;
    unitdropindeep) action_unitdropindeep "$subject" ;;
    suid) action_suid "$subject" ;;
    nopasswd) action_nopasswd "$subject" ;;
    suidunpackaged) action_suidunpackaged "$subject" ;;
    rogueunit) action_rogueunit "$subject" ;;
    tmpproc) action_tmpproc "$subject" ;;
    netproc) action_netproc "$subject" ;;
    netunpackaged) action_netunpackaged "$subject" ;;
    netprocsvc) action_netprocsvc "$subject" ;;
    port) action_port "$subject" ;;
    udpport) action_udpport "$subject" ;;
    rcdeep) action_rcdeep "$subject" ;;
    rcfile) action_rcfile "$subject" ;;
    *) return 1 ;;
  esac
}

finding_present() {
  local want_sev=$1 want_check=$2 want_subject=$3 sev check subject desc
  while IFS='|' read -r sev check subject desc; do
    [ "$sev" = "$want_sev" ] && [ "$check" = "$want_check" ] \
      && [ "$subject" = "$want_subject" ] && return 0
  done <"$findings"
  return 1
}

do_status() {
  local now mtime age stale_after
  # The item numbers the operator sees must name the same records at approval
  # time even if the live queue changes in between. Publish a private immutable
  # snapshot under the same lock used by the loop and approval path.
  ensure_state
  acquire_lock || ccdc_die "another sentry command is running; retry status in a moment so the reviewed queue can be frozen"
  # Re-render from the queue under that lock as well. A prior process may have
  # been interrupted after publishing queue but before publishing ALERTS; in
  # that state copying queue and displaying the old ALERTS would recreate the
  # exact item-number mismatch this snapshot is meant to prevent.
  write_alerts || ccdc_die "could not refresh the status report from the current queue"
  publish_review_snapshot || ccdc_die "could not freeze the reviewed approval queue"
  release_lock
  if [ -f "$alerts" ]; then
    if ccdc_have systemctl \
      && { [ -e "$unit_path" ] || [ -L "$unit_path" ] || [ -f "$owner_marker" ]; } \
      && ! systemctl is-active --quiet "$unit_name" 2>/dev/null; then
      printf 'WARNING: %s is installed but not active; the report below may be stale.\n\n' "$unit_name"
    fi
    if [ ! -f "$last_pass" ]; then
      printf 'WARNING: no completed sentry pass timestamp exists; the report below may be stale.\n\n'
    else
      mtime=$(stat -c '%Y' -- "$last_pass" 2>/dev/null || stat -f '%m' "$last_pass" 2>/dev/null || printf 0)
      case "$mtime" in ''|*[!0-9]*) mtime=0 ;; esac
      now=$(date +%s)
      age=$((now - mtime))
      # A worst-case healthy cycle can spend both detector deadlines plus one
      # sleep interval before publishing again. Add a small scheduling margin.
      stale_after=$((interval + triage_timeout + watch_timeout + 15))
      if [ "$age" -gt "$stale_after" ]; then
        printf 'WARNING: last sentry pass is %ss old (stale after %ss); check %s.\n\n' \
          "$age" "$stale_after" "$unit_name"
      fi
    fi
    cat "$alerts" 2>/dev/null || ccdc_die "cannot read $alerts (run status with sudo)"
    if [ -s "$reviewed" ]; then
      printf '\nReviewed approval snapshot frozen. Item numbers above now remain stable until the next --status.\n'
    fi
  else
    printf 'sentry has not completed a pass yet.\n'
  fi
}

do_approve() {
  local sev check subject i=0 done_n=0 failed_n=0 selected=0 amber_n=0 action
  ccdc_require_root
  ensure_state
  ccdc_have timeout || ccdc_die "timeout is required so a wedged detector cannot freeze approval-time triage"
  acquire_lock || ccdc_die "another sentry command is running; retry in a moment"
  [ -s "$reviewed" ] \
    || ccdc_die "no reviewed approval snapshot; run --status immediately before --approve"
  if ! run_triage; then
    write_alerts
    ccdc_die "fresh triage failed; stale queued actions were discarded"
  fi
  rebuild_queue >/dev/null
  packet_entered || ccdc_die "refusing to act: fill both CCDC_ALLOWED_USERS and CCDC_SYSTEMD_SERVICES from the packet first"

  # Select from the snapshot the operator actually reviewed, then require that
  # exact identity to still be present and automatable in the refreshed queue.
  # Newly inserted findings therefore cannot steal an old numeric item.
  while IFS='|' read -r sev check subject; do
    [ -n "${sev:-}" ] || continue
    i=$((i + 1))
    [ -z "$item" ] || [ "$item" = "$i" ] || continue
    selected=$((selected + 1)); action=$(render_action "$check" "$subject")
    printf '\n[%s] %s %s  %s\n    %s\n' "$i" "$sev" "$check" "$subject" "$action"
    # A bulk --approve with no number is for the unambiguous ones. AMBER means
    # "this may well be yours", and the whole class of AMBER actions here stops
    # a port or kills a process - so a sweep that took them would be the
    # self-inflicted outage this kit exists to prevent. Named by number, they
    # apply like anything else.
    if [ -z "$item" ] && [ "$sev" != RED ]; then
      amber_n=$((amber_n + 1))
      printf '    NOT APPLIED by a bulk approve: AMBER means this may be yours.\n'
      printf '    Look, then approve this one by number:\n'
      printf '      sudo %s/sentry.sh --config %s --approve %s --apply\n' "$qkit" "$qconfig" "$i"
      continue
    fi
    if ! queue_has "$check" "$subject" \
      || ! finding_present "$sev" "$check" "$subject" \
      || ! can_automate "$check" "$subject"; then
      printf '    SKIPPED: no longer current or now protected.\n'
      slog "skipped stale/protected check=$check subject=$subject"
      continue
    fi
    if ccdc_is_dry_run; then
      printf '    [dry-run] not executed. Re-run with --apply.\n'
      continue
    fi
    if execute_action "$check" "$subject" >>"$log" 2>&1; then
      printf '    done; evidence: %s\n' "$evidence_case"
      printf '%s|%s|%s|%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$check" "$subject" "$evidence_case" >>"$undo"
      slog "applied check=$check subject=$subject evidence=$evidence_case"
      done_n=$((done_n + 1))
    else
      printf '    FAILED - see %s; partial changes may have occurred.\n' "$log"
      slog "FAILED check=$check subject=$subject evidence=${evidence_case:-none}"
      failed_n=$((failed_n + 1))
    fi
  done <"$reviewed"
  [ "$selected" -gt 0 ] || ccdc_die "approval item $item does not exist in the reviewed snapshot; run --status again"

  if [ "$apply" -eq 1 ]; then
    run_triage && rebuild_queue >/dev/null || true
    run_watch_if_due || true
    write_alerts
    printf '\n%s action(s) applied, %s failed. Verify scored services FROM OFF THE BOX.\n' "$done_n" "$failed_n"
    [ "$amber_n" -eq 0 ] \
      || printf '%s AMBER action(s) were left for you to approve one at a time, by number.\n' "$amber_n"
    [ "$failed_n" -eq 0 ] || return 1
  else
    write_alerts
    printf '\nDry run only; %s current action(s) selected. Add --apply to sign off.\n' "$selected"
  fi
}

do_ack() {
  ccdc_require_root
  ensure_state
  acquire_lock || ccdc_die "another sentry command is running; retry in a moment"
  rm -f -- "$watch_pending" "$watch_pending_key"
  write_alerts
  release_lock
  ccdc_info "change/canary event summaries acknowledged; underlying evidence was retained"
}

do_revert() {
  printf 'sentry actions, newest first:\n\n'
  [ -s "$undo" ] || { printf '  (nothing)\n'; return 0; }
  tac "$undo" 2>/dev/null || cat "$undo"
  printf '\nThere is no blind automatic undo for account or persistence removal.\n'
  printf 'Each record names its evidence directory; restore deliberately, then verify off-box.\n'
}

managed_name=${CCDC_SENTRY_NAME:-ccdc-sentry}
install_dir=${CCDC_SENTRY_DIR:-/usr/local/lib/$managed_name}
unit_name="$managed_name.service"
unit_path="/etc/systemd/system/$unit_name"
installed_config="$install_dir/sentry.env"
owner_marker="$install_dir/.ccdc-sentry-owned"

validate_install_layout() {
  local probe parent
  case "$managed_name" in ''|*[!A-Za-z0-9_-]*) ccdc_die "CCDC_SENTRY_NAME must contain only letters, digits, underscore, and hyphen" ;; esac
  case "$install_dir" in
    /usr/local/lib/?*|/opt/?*|/var/lib/?*) ;;
    *) ccdc_die "CCDC_SENTRY_DIR must be a dedicated leaf below /usr/local/lib, /opt, or /var/lib: $install_dir" ;;
  esac
  case "$install_dir" in
    *' '*|*'|'*|*':'*|*'//'*) ccdc_die "CCDC_SENTRY_DIR contains characters unsupported in a systemd ExecStart: $install_dir" ;;
    */./*|*/.|*/../*|*/..) ccdc_die "CCDC_SENTRY_DIR contains path traversal: $install_dir" ;;
  esac
  probe=$install_dir
  while [ "$probe" != / ]; do
    [ ! -L "$probe" ] || ccdc_die "CCDC_SENTRY_DIR contains a symlink component: $probe"
    parent=$(dirname -- "$probe")
    [ "$parent" != "$probe" ] || break
    probe=$parent
  done
}

known_unit_collision() {
  local candidate
  for candidate in "$unit_path" "/run/systemd/system/$unit_name" \
      "/usr/local/lib/systemd/system/$unit_name" "/usr/lib/systemd/system/$unit_name" "/lib/systemd/system/$unit_name"; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    [ "$candidate" = "$unit_path" ] && [ -f "$owner_marker" ] && return 1
    return 0
  done
  if ccdc_have systemctl; then
    [ "$(systemctl show -p LoadState --value "$unit_name" 2>/dev/null)" != loaded ] || return 0
  fi
  return 1
}

do_install() {
  local tmp
  validate_install_layout
  if [ "$apply" -ne 1 ]; then
    printf '[dry-run] would install a private copy of linux/ at %s\n' "$install_dir"
    printf '[dry-run] would install and start %s (triage %ss, full sweep %ss)\n' "$unit_path" "$interval" "$watch_interval"
    return 0
  fi
  ccdc_require_root; ensure_state
  ccdc_have timeout || ccdc_die "timeout is required so a wedged detector cannot freeze sentry"
  if [ -d "$install_dir" ] && [ ! -f "$owner_marker" ]; then
    ccdc_die "install directory exists without this tool's ownership marker: $install_dir"
  fi
  if [ -f "$owner_marker" ] && [ "$(cat "$owner_marker" 2>/dev/null)" != "$managed_name" ]; then
    ccdc_die "ownership marker does not match CCDC_SENTRY_NAME; uninstall with the old config first"
  fi
  if [ ! -f "$owner_marker" ] && known_unit_collision; then
    ccdc_die "systemd unit name already exists and is not owned by this install: $unit_name"
  fi
  ccdc_have systemctl || ccdc_die "systemctl is required to install supervised sentry"
  mkdir -p -- "$install_dir" || ccdc_die "cannot create $install_dir"
  if [ "$SCRIPT_DIR" != "$install_dir" ]; then
    cp -a -- "$SCRIPT_DIR/." "$install_dir/" || ccdc_die "could not install sentry tool copy"
  fi
  if [ "$config" != "$installed_config" ]; then
    cp -- "$config" "$installed_config" || ccdc_die "could not install sentry config"
  fi
  printf '%s\n' "$managed_name" >"$owner_marker"
  chown -R 0:0 "$install_dir" || ccdc_die "could not make the installed sentry root-owned"
  chmod -R go-w "$install_dir" || ccdc_die "could not secure $install_dir"
  chmod 0600 "$installed_config" "$owner_marker" || ccdc_die "could not secure installed sentry config"

  tmp="$unit_path.tmp.$$"
  {
    printf '[Unit]\nDescription=CCDC supervised detection and approval queue\nAfter=local-fs.target\n\n'
    printf '[Service]\nType=simple\nExecStart=%s/sentry.sh --config %s --interval %s --watch-interval %s --triage-timeout %s --watch-timeout %s --loop --no-bell\n' \
      "$install_dir" "$installed_config" "$interval" "$watch_interval" "$triage_timeout" "$watch_timeout"
    printf 'Restart=always\nRestartSec=5s\nNice=10\nIOSchedulingClass=idle\nUMask=0077\n\n'
    printf '[Install]\nWantedBy=multi-user.target\n'
  } >"$tmp" || ccdc_die "cannot stage $unit_path"
  install -m 0644 "$tmp" "$unit_path" || ccdc_die "cannot install $unit_path"
  rm -f -- "$tmp"
  systemctl daemon-reload || ccdc_die "systemd daemon-reload failed"
  systemctl enable --now "$unit_name" || ccdc_die "could not enable/start $unit_name"
  systemctl is-active --quiet "$unit_name" || ccdc_die "$unit_name did not remain active"
  ccdc_info "installed and started $unit_name; terminal is free"
}

do_uninstall() {
  validate_install_layout
  if [ "$apply" -ne 1 ]; then
    printf '[dry-run] would stop/remove %s and owned directory %s\n' "$unit_name" "$install_dir"
    return 0
  fi
  ccdc_require_root
  [ -f "$owner_marker" ] || ccdc_die "refusing uninstall: ownership marker missing at $owner_marker"
  [ "$(cat "$owner_marker" 2>/dev/null)" = "$managed_name" ] \
    || ccdc_die "refusing uninstall: ownership marker does not match $managed_name"
  systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  rm -f -- "$unit_path" || ccdc_die "cannot remove $unit_path"
  rm -rf -- "$install_dir" || ccdc_die "cannot remove $install_dir"
  systemctl daemon-reload || ccdc_die "systemd daemon-reload failed"
  systemctl reset-failed "$unit_name" >/dev/null 2>&1 || systemctl reset-failed >/dev/null 2>&1 || true
  ccdc_info "removed supervised sentry; evidence and approval history remain in $state_dir"
}

case "$mode" in
  status) do_status ;;
  approve) do_approve ;;
  ack) do_ack ;;
  revert) do_revert ;;
  once)
    ccdc_require_root; ensure_state
    ccdc_have timeout || ccdc_die "timeout is required so a wedged detector cannot freeze sentry"
    run_pass || true
    do_status
    ;;
  loop)
    ccdc_require_root; ensure_state
    ccdc_have timeout || ccdc_die "timeout is required so a wedged detector cannot freeze sentry"
    packet_entered || ccdc_warn "packet protection lists are incomplete; detection runs, but approval is blocked"
    printf 'sentry: supervised loop; triage every %ss, full sweep every %ss.\n' "$interval" "$watch_interval"
    while :; do
      run_pass || true
      sleep "$interval"
    done
    ;;
  install) do_install ;;
  uninstall) do_uninstall ;;
  *) ccdc_die "internal mode error: $mode" ;;
esac
