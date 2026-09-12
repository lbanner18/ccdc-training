#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

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

log_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
mkdir -p "$log_dir" 2>/dev/null || log_dir="${TMPDIR:-/tmp}/ccdc-evidence"
mkdir -p "$log_dir"
log="$log_dir/watchdog.log"
hash_state="$log_dir/watchdog.sha256"

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
  local next_state="${hash_state}.next"
  : >"$next_state"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ ! -f "$path" ]; then
      ccdc_append_log "$log" "hash_missing path=$path"
      continue
    fi
    if ccdc_have sha256sum; then
      current=$(sha256sum "$path" | awk '{print $1}')
    elif ccdc_have shasum; then
      current=$(shasum -a 256 "$path" | awk '{print $1}')
    else
      ccdc_append_log "$log" "hash_skipped reason=no-sha256-tool path=$path"
      continue
    fi
    previous=$(awk -v p="$path" '$2 == p {print $1}' "$hash_state" 2>/dev/null || true)
    if [ -z "$previous" ]; then
      ccdc_append_log "$log" "hash_baseline path=$path sha256=$current"
    elif [ "$previous" != "$current" ]; then
      ccdc_append_log "$log" "config_changed path=$path previous=$previous current=$current"
    fi
    printf '%s %s\n' "$current" "$path" >>"$next_state"
  done <<EOF
${CCDC_HASH_FILES:-}
EOF
  mv "$next_state" "$hash_state"
}

run_once() {
  local name host port url service status
  restarted_this_pass=''
  ccdc_append_log "$log" "check_start box=${CCDC_BOX_NAME:-unknown}"
  while IFS='|' read -r name host port; do
    [ -n "${name:-}" ] || continue
    if check_tcp "$name" "$host" "$port"; then
      ccdc_append_log "$log" "tcp_ok name=$name host=$host port=$port"
    else
      ccdc_append_log "$log" "tcp_unhealthy name=$name host=$host port=$port"
    fi
  done <<EOF
${CCDC_TCP_CHECKS:-}
EOF

  while IFS='|' read -r name url service; do
    [ -n "${name:-}" ] || continue
    status=0
    check_http "$url" || status=$?
    if [ "$status" -eq 0 ]; then
      ccdc_append_log "$log" "http_ok name=$name url=$url"
    elif [ "$status" -eq 2 ]; then
      ccdc_append_log "$log" "http_skipped reason=no-curl-or-wget name=$name url=$url"
    else
      ccdc_append_log "$log" "http_unhealthy name=$name url=$url"
      [ -n "${service:-}" ] && restart_service "$service" http "$url"
    fi
  done <<EOF
${CCDC_HTTP_CHECKS:-}
EOF

  for service in ${CCDC_SYSTEMD_SERVICES:-}; do
    # Already restarted and verified above via its endpoint check.
    ccdc_list_contains "$service" "$restarted_this_pass" && continue
    if check_service "$service"; then
      ccdc_append_log "$log" "service_ok service=$service"
    else
      ccdc_append_log "$log" "service_unhealthy service=$service"
      restart_service "$service"
    fi
  done
  check_hashes
  ccdc_append_log "$log" "check_end"
}

[ "$apply" -eq 1 ] && ccdc_require_root
if [ "$once" -eq 1 ]; then
  run_once
else
  while :; do
    run_once
    sleep "$interval"
  done
fi
