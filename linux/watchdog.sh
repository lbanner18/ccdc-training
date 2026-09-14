#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
apply=0
once=0
interval=60
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --once) once=1; shift ;;
    --interval) interval=${2:?missing interval}; shift 2 ;;
    -h|--help) printf 'usage: %s --config FILE [--once] [--interval SECONDS] [--apply|--dry-run]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
case "$interval" in ''|*[!0-9]*) ccdc_die "--interval must be a whole number of seconds" ;; esac
# Floor of 2s, and it must stay in step with guardian.sh's CCDC_WATCHDOG_INTERVAL
# floor -- guardian writes this value straight into the unit's ExecStart, so a
# stricter floor here means a unit that installs cleanly and then dies on every
# start. The old floor was 5s "to avoid a restart storm", but the storm is
# already prevented structurally: one restart per service per pass, and a settle
# deadline after each restart before anything else may act. A pass is a curl and
# a couple of systemctl calls, so the real cost of a short interval was log
# volume, and state-change logging below removes that.
[ "$interval" -ge 2 ] || ccdc_die "--interval below 2s leaves no room for a check to finish: $interval"

log_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
if ! mkdir -p "$log_dir" 2>/dev/null || [ ! -w "$log_dir" ]; then
  log_dir="${TMPDIR:-/tmp}/ccdc-evidence"
fi
mkdir -p "$log_dir" || ccdc_die "cannot create watchdog state directory: $log_dir"
if [ "$apply" -eq 1 ]; then
  chmod 0700 "$log_dir" 2>/dev/null || ccdc_die "cannot secure watchdog state directory: $log_dir"
else
  chmod 0700 "$log_dir" 2>/dev/null || true
fi
log="$log_dir/watchdog.log"
hash_state="$log_dir/watchdog.sha256"
watchdog_lock="$log_dir/watchdog.lock"
watchdog_lock_owner="$watchdog_lock/owner"
watchdog_lock_token=''
watchdog_lock_holder=''
watchdog_staged=''

# How often a watchdog that lost the singleton lock re-tries for it. This is the
# failover window: kill the active watchdog and a standby one picks up your
# services this many seconds later, at worst. Kept short because idling is free
# -- a failed mkdir is the entire cost of a standby pass.
standby_interval=${CCDC_WATCHDOG_STANDBY_SECONDS:-5}
case "$standby_interval" in
  ''|*[!0-9]*) ccdc_die "CCDC_WATCHDOG_STANDBY_SECONDS must be a whole number of seconds: $standby_interval" ;;
esac
[ "$standby_interval" -ge 1 ] || ccdc_die "CCDC_WATCHDOG_STANDBY_SECONDS must be at least 1: $standby_interval"

watchdog_process_start() {
  awk '{print $22}' "/proc/$1/stat" 2>/dev/null || printf 'unknown'
}

release_watchdog_lock() {
  local current
  [ -n "$watchdog_staged" ] && rm -f -- "$watchdog_staged" 2>/dev/null || true
  [ -n "$watchdog_lock_token" ] || return 0
  current=$(cat "$watchdog_lock_owner" 2>/dev/null || printf '')
  if [ "$current" = "$watchdog_lock_token" ]; then
    rm -f "$watchdog_lock_owner" 2>/dev/null || true
    rmdir "$watchdog_lock" 2>/dev/null || true
  fi
}

acquire_watchdog_lock() {
  local owner pid expected_start live_start
  if mkdir "$watchdog_lock" 2>/dev/null; then
    watchdog_lock_token="$$:$(watchdog_process_start $$)"
    printf '%s\n' "$watchdog_lock_token" >"$watchdog_lock_owner" \
      || { rmdir "$watchdog_lock" 2>/dev/null || true; return 1; }
    return 0
  fi
  owner=$(cat "$watchdog_lock_owner" 2>/dev/null || printf '')
  pid=${owner%%:*}
  expected_start=${owner#*:}
  live_start=''
  case "$pid" in
    ''|*[!0-9]*) ;;
    *) kill -0 "$pid" 2>/dev/null && live_start=$(watchdog_process_start "$pid") ;;
  esac
  if [ -n "$live_start" ] && [ "$live_start" = "$expected_start" ]; then
    # Silent: in standby this is retried every few seconds, and a warning per
    # attempt would fill watchdog.err with the one thing that is working.
    # Callers log the transition instead.
    watchdog_lock_holder=$pid
    return 1
  fi
  rm -f "$watchdog_lock_owner" 2>/dev/null || return 1
  rmdir "$watchdog_lock" 2>/dev/null || return 1
  mkdir "$watchdog_lock" 2>/dev/null || return 1
  watchdog_lock_token="$$:$(watchdog_process_start $$)"
  printf '%s\n' "$watchdog_lock_token" >"$watchdog_lock_owner" \
    || { rmdir "$watchdog_lock" 2>/dev/null || true; return 1; }
}

trap release_watchdog_lock EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

check_tcp() {
  local name=$1 host=$2 port=$3
  if ccdc_have nc; then
    nc -z -w 3 "$host" "$port" >/dev/null 2>&1
  elif (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
    exec 3>&-
    exec 3<&-
    return 0
  else
    return 1
  fi
}

check_http() {
  local url=$1
  if ccdc_have curl; then
    curl --fail --silent --max-time 5 --output /dev/null "$url"
  elif ccdc_have wget; then
    wget -q --timeout=5 --spider "$url"
  else
    return 2
  fi
}

check_service() {
  local service=$1
  if ccdc_have systemctl; then
    systemctl is-active --quiet "$service"
  else
    service "$service" status >/dev/null 2>&1
  fi
}

# Services already restarted during the current pass. Two different checks
# (HTTP and systemd) can both fail for the same unit; restarting it twice
# kills a slow service while it is still starting.
restarted_this_pass=''

# systemctl reports a Type=simple unit "active" as soon as it forks, which is
# before the socket is bound. Measured on the lab box: restart returned in 29ms
# with state=active, but the service did not answer until 277ms. Real services
# (Apache, MySQL, a Java app) take seconds. Verify with the same probe the
# scorer would use, and escalate in the log when recovery never happens.
verify_recovery() {
  local service=$1 kind=$2 arg=$3
  local limit=${CCDC_RESTART_SETTLE_SECONDS:-15}
  case "$limit" in ''|*[!0-9]*) ccdc_append_log "$log" "invalid_restart_settle_seconds value=$limit"; return 1 ;; esac
  [ "$limit" -ge 2 ] || { ccdc_append_log "$log" "invalid_restart_settle_seconds value=$limit"; return 1; }
  # Measure the real deadline. Counting loop iterations undercounts badly: each
  # curl probe can burn its full --max-time before the loop even sleeps, so 15
  # "iterations" measured 95 seconds of wall clock on the lab box. A watchdog
  # blocked that long is not checking the other scored services.
  local started waited=0 deadline
  started=$(date +%s)
  deadline=$((started + limit))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    waited=$(( $(date +%s) - started ))
    case "$kind" in
      http)
        if check_http "$arg"; then
          ccdc_append_log "$log" "restart_recovered service=$service check=http after=${waited}s"
          return 0
        fi
        ;;
      tcp)
        if check_tcp "$service" "${arg%%:*}" "${arg##*:}"; then
          ccdc_append_log "$log" "restart_recovered service=$service check=tcp after=${waited}s"
          return 0
        fi
        ;;
      *)
        # No endpoint probe configured. is-active is all we have, so require it
        # to hold for two consecutive seconds to catch a crash loop.
        if check_service "$service"; then
          sleep 1
          if check_service "$service"; then
            ccdc_append_log "$log" "restart_recovered service=$service check=systemd after=${waited}s"
            return 0
          fi
          ccdc_append_log "$log" "restart_flapping service=$service"
        fi
        ;;
    esac
    sleep 1
  done
  waited=$(( $(date +%s) - started ))
  ccdc_append_log "$log" "ESCALATE restart_did_not_recover service=$service waited=${waited}s check=$kind"
  return 1
}

restart_service() {
  local service=$1
  local verify_kind=${2:-systemd} verify_arg=${3:-}
  if ccdc_list_contains "$service" "$restarted_this_pass"; then
    ccdc_append_log "$log" "restart_skipped reason=already_restarted_this_pass service=$service"
    return 0
  fi
  restarted_this_pass="$restarted_this_pass $service"
  if [ "$apply" -ne 1 ]; then
    ccdc_append_log "$log" "dry_run would_restart service=$service verify=$verify_kind"
    return 0
  fi
  ccdc_append_log "$log" "restarting unhealthy service=$service"
  if ccdc_have systemctl; then
    systemctl restart "$service" >>"$log" 2>&1 || ccdc_append_log "$log" "restart_failed service=$service"
  else
    service "$service" restart >>"$log" 2>&1 || ccdc_append_log "$log" "restart_failed service=$service"
  fi
  verify_recovery "$service" "$verify_kind" "$verify_arg"
}

check_hashes() {
  local path current previous
  local next_state="${hash_state}.next.$$"
  watchdog_staged=$next_state
  : >"$next_state" || { ccdc_append_log "$log" "hash_state_write_failed path=$next_state"; return 1; }
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ ! -f "$path" ]; then
      log_state "hash:$path" missing "hash_missing path=$path"
      # Carry the last known hash forward. Without this the entry drops out of
      # the state file, so when the file reappears there is nothing to compare
      # against and it logs as a fresh "hash_baseline" -- meaning delete-then-
      # recreate, which is how you would edit sshd_config without tripping a
      # content check, reads as routine. Keeping the old hash turns that back
      # into the config_changed it actually is.
      previous=$(awk -v p="$path" '$2 == p {print $1}' "$hash_state" 2>/dev/null || true)
      [ -n "$previous" ] && printf '%s %s\n' "$previous" "$path" >>"$next_state"
      continue
    fi
    if ccdc_have sha256sum; then
      current=$(sha256sum "$path" | awk '{print $1}')
    elif ccdc_have shasum; then
      current=$(shasum -a 256 "$path" | awk '{print $1}')
    else
      log_state "hash:$path" skip "hash_skipped reason=no-sha256-tool path=$path"
      continue
    fi
    previous=$(awk -v p="$path" '$2 == p {print $1}' "$hash_state" 2>/dev/null || true)
    if [ -z "$previous" ]; then
      ccdc_append_log "$log" "hash_baseline path=$path sha256=$current"
    elif [ "$previous" != "$current" ]; then
      ccdc_append_log "$log" "config_changed path=$path previous=$previous current=$current"
    fi
    # Put the key back to ok, or a file that vanished once would stay latched at
    # "missing" for the life of the process and its SECOND disappearance would
    # log nothing. Only the missing->ok edge prints, because that edge is news;
    # the first-ever observation is already covered by hash_baseline above.
    if [ "${ccdc_state[hash:$path]:-ok}" != ok ]; then
      log_state "hash:$path" ok "hash_restored path=$path"
    else
      ccdc_state[hash:$path]=ok
    fi
    printf '%s %s\n' "$current" "$path" >>"$next_state"
  done <<EOF
${CCDC_HASH_FILES:-}
EOF
  mv "$next_state" "$hash_state" \
    || { ccdc_append_log "$log" "hash_state_install_failed path=$hash_state"; return 1; }
  watchdog_staged=''
}

# Log state CHANGES, not every poll.
#
# At a 5s interval the old per-poll logging produced ~84 lines a minute, about
# 30,000 over a six-hour event - and watchdog.log is a file you READ when you
# are trying to reconstruct what happened. Thirty thousand lines of "service_ok"
# is a haystack you built for yourself. Recovery speed and a readable log were
# in direct conflict only because every poll wrote a line.
#
# Now a check logs when it ENTERS a state and when it LEAVES it, so an incident
# is two lines however long it lasted, and a quiet hour is silent. A periodic
# heartbeat keeps "still alive, still fine" visible without the volume.
# Associative arrays need bash 4 (2009). Fail loudly rather than limping: with
# `set -u` and no associative array, every log_state call below would expand
# $key as an arithmetic index and the watchdog would die mid-pass with a much
# less obvious error than this one.
#
# The `=()` is load-bearing, not style. A bare `declare -A ccdc_state` DECLARES
# the array without SETTING it, and under `set -u` the first `${#ccdc_state[@]}`
# then aborts the shell with "unbound variable" -- which only happens while the
# array is still empty, i.e. only on a box whose config has hash files but no
# tcp/http/service checks. On every config we had tested, the first pass filled
# the array before the heartbeat read it, so the crash stayed invisible.
declare -A ccdc_state=() 2>/dev/null \
  || ccdc_die "this watchdog needs bash 4+ for state-change logging (found ${BASH_VERSION:-unknown})"
last_heartbeat=0
heartbeat_every=${CCDC_WATCHDOG_HEARTBEAT_SECONDS:-300}

log_state() {
  local key=$1 state=$2 message=$3 previous
  previous=${ccdc_state[$key]:-}
  if [ "$previous" != "$state" ]; then
    ccdc_state[$key]=$state
    if [ -n "$previous" ]; then
      ccdc_append_log "$log" "$message"
    else
      # First observation of this check. Record it so the log opens with what
      # normal looked like, rather than starting mid-story.
      ccdc_append_log "$log" "baseline $message"
    fi
  fi
}

heartbeat() {
  local now healthy key
  now=$(date +%s)
  [ $((now - last_heartbeat)) -ge "$heartbeat_every" ] || return 0
  last_heartbeat=$now
  healthy=0
  for key in "${!ccdc_state[@]}"; do
    [ "${ccdc_state[$key]}" = ok ] && healthy=$((healthy + 1))
  done
  ccdc_append_log "$log" "heartbeat checks=${#ccdc_state[@]} healthy=$healthy"
}

run_once() {
  local name host port url service status
  restarted_this_pass=''
  # check_start/check_end per pass was two lines every interval and told you
  # nothing; the heartbeat below carries "still running" instead.
  while IFS='|' read -r name host port; do
    [ -n "${name:-}" ] || continue
    if check_tcp "$name" "$host" "$port"; then
      log_state "tcp:$name" ok "tcp_ok name=$name host=$host port=$port"
    else
      log_state "tcp:$name" bad "tcp_unhealthy name=$name host=$host port=$port"
    fi
  done <<EOF
${CCDC_TCP_CHECKS:-}
EOF

  while IFS='|' read -r name url service; do
    [ -n "${name:-}" ] || continue
    status=0
    check_http "$url" || status=$?
    if [ "$status" -eq 0 ]; then
      log_state "http:$name" ok "http_ok name=$name url=$url"
    elif [ "$status" -eq 2 ]; then
      log_state "http:$name" skip "http_skipped reason=no-curl-or-wget name=$name url=$url"
    else
      log_state "http:$name" bad "http_unhealthy name=$name url=$url"
      [ -n "${service:-}" ] && restart_service "$service" http "$url"
    fi
  done <<EOF
${CCDC_HTTP_CHECKS:-}
EOF

  for service in ${CCDC_SYSTEMD_SERVICES:-}; do
    # Already restarted and verified above via its endpoint check.
    ccdc_list_contains "$service" "$restarted_this_pass" && continue
    if check_service "$service"; then
      log_state "svc:$service" ok "service_ok service=$service"
    else
      log_state "svc:$service" bad "service_unhealthy service=$service"
      restart_service "$service"
    fi
  done
  check_hashes
  heartbeat
}

[ "$apply" -eq 1 ] && ccdc_require_root

# Do we still hold the lock we think we hold?
#
# The EXIT trap releases the lock on a clean stop, but the whole point of this
# tool is that someone is trying to kill it, and `kill -9` runs no traps. It can
# also lose the lock without dying: `rm -rf` on the evidence directory takes the
# lock directory with it, and then a second watchdog is free to create it. So
# ownership is re-checked every pass rather than assumed from start-up.
holds_watchdog_lock() {
  [ -n "$watchdog_lock_token" ] || return 1
  [ "$(cat "$watchdog_lock_owner" 2>/dev/null || printf '')" = "$watchdog_lock_token" ]
}

if [ "$once" -eq 1 ]; then
  acquire_watchdog_lock || ccdc_die "watchdog singleton lock is unavailable; refusing a duplicate recovery loop"
  run_once
  exit 0
fi

# The loop, with the singleton lock as a hot-standby handoff.
#
# Running several independent guardian chains means several watchdog units, and
# two watchdogs restarting the same service is not redundancy -- the second
# restart is an outage you inflicted on yourself, during an incident, while
# reading a log that now has two writers. So only the lock holder acts.
#
# The losers do NOT exit. A watchdog that exits on a lost lock leaves its unit
# to be restarted by systemd every RestartSec forever, and worse, nothing is
# watching your services the moment the holder dies until some other layer
# notices. Instead they idle here re-trying the lock, so when the holder is
# killed -- which is the scenario this is for -- the next chain picks up the
# services within one standby interval, with no coordination between the chains
# and nothing designated as primary.
standby_logged=0
active_logged=0
while :; do
  if ! holds_watchdog_lock; then
    watchdog_lock_token=''
    if acquire_watchdog_lock; then
      standby_logged=0
      if [ "$active_logged" -eq 0 ]; then
        ccdc_append_log "$log" "watchdog_active pid=$$ interval=${interval}s"
        active_logged=1
      fi
      # A new holder inherits nothing from the old one's memory, so let the
      # first pass re-log its baseline instead of reporting a silent "no change"
      # against states it never observed.
      ccdc_state=()
    else
      active_logged=0
      if [ "$standby_logged" -eq 0 ]; then
        ccdc_append_log "$log" "watchdog_standby pid=$$ holder=${watchdog_lock_holder:-unknown}"
        # Also to stderr, once: if you ran this by hand you are staring at a
        # terminal that is doing nothing, and "it is idle on purpose" is the
        # only thing you need to know.
        ccdc_warn "another watchdog (pid ${watchdog_lock_holder:-?}) is active; standing by to take over if it dies"
        standby_logged=1
      fi
      sleep "$standby_interval"
      continue
    fi
  fi
  run_once
  sleep "$interval"
done
