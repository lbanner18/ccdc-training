#!/usr/bin/env bash
set -u

# guardian.sh - keep the service watchdog alive even when someone with root is
# actively trying to kill it. The defense is redundancy, not stealth: three
# independent mechanisms that each restart the watchdog AND rebuild each other,
# so an attacker has to find and remove all of them inside one interval.
#
#   sudo ./guardian.sh --config FILE --install     arm all layers
#   sudo ./guardian.sh --config FILE --status      show which layers are live
#   sudo ./guardian.sh --config FILE --uninstall   remove every layer (uses the manifest)
#   sudo ./guardian.sh --config FILE --tick        one reconcile pass (what the layers call)
#   add --dry-run to print actions without making changes (this is the default)
#
# Naming: the installed unit name comes from CCDC_GUARDIAN_NAME (default
# "node-health"). Pick something plausible for the box, NOT something that
# screams "defense" - but always keep the manifest so you can tell your own
# footholds from the red team's. Stealth buys minutes; the manifest is what
# actually keeps you in control.
#
# --- what gets installed -----------------------------------------------------
#
#   target   <name>-watch.service    runs watchdog.sh, Restart=always
#   layer 1  <name>.service          Restart=always, runs tick.sh (a sleep loop)
#   layer 2  <name>-reconcile.timer  fires the same tick every interval
#   layer 3  /etc/cron.d/<name>      fires the same tick every ceil(interval/60) min
#
# All three layers run the identical reconcile pass (--tick), which:
#   1. self-removes if the disarm sentinel is present (see below),
#   2. makes sure the watchdog is running, and
#   3. recreates any of the three layers that has gone missing.
#
# Because every layer rebuilds every other layer, killing one is pointless and
# killing two is temporary. Removing all three inside one interval works, and
# that is the documented limit, not a bug - there is no such thing as
# unkillable, only expensive to kill.
#
# --- the payload is copied, on purpose ---------------------------------------
#
# Install copies guardian.sh, watchdog.sh, lib/common.sh and your config into
# CCDC_GUARDIAN_DIR, and every layer references the copies. The guardian must
# not die because someone deleted your home directory or your /tmp config, and
# the running defense should not change under you when you edit the checkout
# mid-competition.
#
# --- the disarm sentinel -----------------------------------------------------
#
# --uninstall writes a sentinel file FIRST, then tears the layers down. Any tick
# that fires during or after the teardown sees the sentinel and removes its own
# layer instead of rebuilding the others, so a scheduler that was mid-flight
# cannot resurrect what you just removed. Same trick fw.sh uses when it deletes
# the snapshot to disarm a pending rollback. The sentinel is left behind after
# an uninstall (it is what makes the removal stick); --install deletes it.
#
# --- scope -------------------------------------------------------------------
#
# Defensive only, and local only: no network callbacks, no beacons, no remote
# anything (NCCDC rule 5.6 bars external callbacks in team tooling). Everything
# it writes is listed in the manifest and removable with --uninstall. Run it on
# boxes you are authorized to defend.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
mode=''
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --install) mode=install; shift ;;
    --status) mode=status; shift ;;
    --uninstall) mode=uninstall; shift ;;
    --tick) mode=tick; shift ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE --install|--status|--uninstall|--tick [--apply|--dry-run]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$mode" ] || ccdc_die "choose one of --install --status --uninstall --tick"
ccdc_load_config "$config"

name=${CCDC_GUARDIAN_NAME:-node-health}
interval=${CCDC_GUARDIAN_INTERVAL:-60}
guardian_dir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/$name}

# The name becomes a systemd unit name and a cron.d filename. cron ignores any
# file in /etc/cron.d whose name has a character outside [A-Za-z0-9_-], which
# would silently cost you a whole layer - so reject it here instead.
case "$name" in
  ''|*[!A-Za-z0-9_-]*) ccdc_die "CCDC_GUARDIAN_NAME must be [A-Za-z0-9_-] only: $name" ;;
esac
case "$interval" in
  ''|*[!0-9]*) ccdc_die "CCDC_GUARDIAN_INTERVAL must be a whole number of seconds: $interval" ;;
esac
[ "$interval" -ge 10 ] || ccdc_die "CCDC_GUARDIAN_INTERVAL below 10s just burns CPU: $interval"

# State lives with the evidence, next to the watchdog and canary logs, so one
# directory is the whole story when you write the incident report.
state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
mkdir -p "$state_dir" 2>/dev/null || state_dir="${TMPDIR:-/tmp}/ccdc-evidence"
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create state directory"
manifest="$state_dir/guardian.manifest"   # kind|path|sha256-at-write
sentinel="$state_dir/guardian.disarmed"
log="$state_dir/guardian.log"
pid_file="$state_dir/guardian-watchdog.pid"
lock_dir="$state_dir/guardian.lock"

# Payload copies (what the layers actually execute).
guardian_copy="$guardian_dir/guardian.sh"
watchdog_copy="$guardian_dir/watchdog.sh"
common_copy="$guardian_dir/lib/common.sh"
env_copy="$guardian_dir/guardian.env"
tick_script="$guardian_dir/tick.sh"

unit_dir=/etc/systemd/system
svc_watch="$unit_dir/$name-watch.service"
svc_ticker="$unit_dir/$name.service"
svc_reconcile="$unit_dir/$name-reconcile.service"
tmr_reconcile="$unit_dir/$name-reconcile.timer"
cron_file="/etc/cron.d/$name"

created=''          # paths written during this run (their hashes get refreshed)
need_daemon_reload=0

# --- capability detection ----------------------------------------------------
# Degrade honestly. A box with no systemd gets the cron layer only, and says so;
# it does not pretend to three layers it cannot build.

have_systemd() { ccdc_have systemctl && [ -d /run/systemd/system ]; }
have_crond() { [ -d /etc/cron.d ]; }

# --- helpers -----------------------------------------------------------------

glog() { ccdc_append_log "$log" "$@"; }

# Write one artifact, content on stdin. Honors CCDC_DRY_RUN like ccdc_action,
# which cannot be used here because the content is a heredoc, not an argv.
write_artifact() {
  local kind=$1 path=$2 mode_bits=$3 content
  content=$(cat)
  if ccdc_is_dry_run; then
    printf '[dry-run] would write %s (%s, mode %s)\n' "$path" "$kind" "$mode_bits"
    return 0
  fi
  mkdir -p "$(dirname -- "$path")" 2>/dev/null || true
  # Write-then-rename, never truncate in place. tick.sh is being executed by a
  # running bash process (layer 1's service); bash reads a script incrementally
  # by file offset, so overwriting one in place makes the running shell resume
  # mid-file and misparse whatever now sits at that byte. A rename swaps the
  # directory entry and leaves the running process on its original inode, which
  # it finishes cleanly before the next loop picks up the new file.
  local staged="${path}.new.$$"
  printf '%s\n' "$content" >"$staged" || { ccdc_warn "cannot write $path"; return 1; }
  chmod "$mode_bits" "$staged" 2>/dev/null || true
  mv -f "$staged" "$path" || { ccdc_warn "cannot install $path"; rm -f "$staged"; return 1; }
  created="$created $path"
  glog "wrote kind=$kind path=$path"
}

file_hash() { ccdc_hash_file "$1" 2>/dev/null | awk '{print $1}'; }

recorded_hash() {
  [ -f "$manifest" ] || return 0
  awk -F'|' -v p="$1" '$2 == p {print $3; exit}' "$manifest" 2>/dev/null
}

# Keep the tampered copy before overwriting it. The edit is evidence - it shows
# what the attacker wanted the box to run - and an inject will ask for exactly
# that. Deleting it to restore service would throw away the only artifact.
quarantine() {
  local path=$1 dest
  if ccdc_is_dry_run; then
    printf '[dry-run] would preserve tampered %s and rewrite it\n' "$path"
    return 0
  fi
  dest="$state_dir/guardian.tampered"
  mkdir -p "$dest" 2>/dev/null || { ccdc_warn "cannot create $dest"; return 0; }
  cp -f "$path" "$dest/$(basename -- "$path").$(ccdc_now)" 2>/dev/null \
    || ccdc_warn "could not preserve tampered $path"
  ccdc_warn "TAMPERED: $path does not match the manifest; copy kept in $dest, rewriting from source"
  glog "TAMPER path=$path action=quarantined_and_rewritten"
}

# True when an artifact is missing OR has been edited since we wrote it.
#
# Repairing a modified artifact matters as much as replacing a deleted one: an
# attacker who appends an ExecStartPost to your unit has turned your own
# keep-alive into their persistence, and a guardian that only notices missing
# files would rebuild nothing and report itself healthy forever.
needs_rebuild() {
  local path=$1 old new
  [ -f "$path" ] || return 0
  old=$(recorded_hash "$path")
  { [ -n "$old" ] && [ "$old" != absent ]; } || return 1
  new=$(file_hash "$path")
  { [ -n "$new" ] && [ "$old" != "$new" ]; } || return 1
  quarantine "$path"
  return 0
}

# Every artifact this box should have, given what it can actually run.
expected_artifacts() {
  printf 'payload|%s\n' "$guardian_copy"
  printf 'payload|%s\n' "$watchdog_copy"
  printf 'payload|%s\n' "$common_copy"
  printf 'payload|%s\n' "$env_copy"
  if have_systemd; then
    printf 'payload|%s\n' "$tick_script"
    printf 'target|%s\n' "$svc_watch"
    printf 'layer1|%s\n' "$svc_ticker"
    printf 'layer2|%s\n' "$svc_reconcile"
    printf 'layer2|%s\n' "$tmr_reconcile"
  fi
  have_crond && printf 'layer3|%s\n' "$cron_file"
}

# Rebuild the manifest from what is on disk now.
#
# Hashes are only refreshed for files this run actually wrote. Re-hashing
# everything each tick would quietly launder a red-team edit of your own unit
# file into the "expected" value, which is the one thing the manifest exists to
# catch.
record_manifest() {
  ccdc_is_dry_run && return 0
  local kind path old new tmp
  # Per-process temp name. A fixed "${manifest}.next" is shared state: an
  # --install racing a scheduled tick had both processes truncating and
  # appending to the same file, and the manifest that survived was missing five
  # entries. Found on the lab VM; a sandbox with no schedulers running cannot
  # produce it.
  tmp="${manifest}.next.$$"
  : >"$tmp" || { ccdc_warn "cannot write manifest"; return 0; }
  while IFS='|' read -r kind path; do
    [ -n "${path:-}" ] || continue
    if [ ! -e "$path" ]; then
      printf '%s|%s|absent\n' "$kind" "$path" >>"$tmp"
      continue
    fi
    old=$(recorded_hash "$path")
    if ccdc_list_contains "$path" "$created" || [ -z "$old" ] || [ "$old" = absent ]; then
      new=$(file_hash "$path")
    else
      new=$old
    fi
    printf '%s|%s|%s\n' "$kind" "$path" "$new" >>"$tmp"
  done <<EOF
$(expected_artifacts)
EOF
  mv "$tmp" "$manifest"
}

# One tick at a time. Two schedulers firing in the same second would otherwise
# both decide a layer is missing and both write it.
# acquire_lock [seconds-to-wait]
#
# A tick takes it with no wait and simply skips if another tick holds it.
# --install and --uninstall wait for it instead: they are operator-initiated
# and authoritative, and must not quietly do half their work alongside a
# reconcile that is writing the same files.
acquire_lock() {
  ccdc_is_dry_run && return 0
  local wait_for=${1:-0} deadline stamp now age
  deadline=$(( $(date +%s) + wait_for ))
  while :; do
    if mkdir "$lock_dir" 2>/dev/null; then
      trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT
      return 0
    fi
    # A tick that died holding the lock must not wedge the guardian permanently.
    stamp=$(stat -c '%Y' "$lock_dir" 2>/dev/null || stat -f '%m' "$lock_dir" 2>/dev/null || printf '0')
    now=$(date +%s)
    age=$((now - stamp))
    if [ "$age" -gt $((interval * 5)) ]; then
      glog "breaking stale tick lock age=${age}s"
      rmdir "$lock_dir" 2>/dev/null || true
      continue
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 1
  done
  glog "lock_unavailable another_pass_is_running"
  return 1
}

# --- artifact bodies ---------------------------------------------------------

copy_payload_file() {
  local src=$1 dest=$2
  [ -f "$src" ] || { ccdc_warn "payload source missing: $src"; return 0; }
  [ "$src" = "$dest" ] && return 0
  # Same write-then-rename rule as write_artifact: watchdog.sh is running under
  # the watch service while we repair it, and cp truncates in place.
  local staged="${dest}.new.$$"
  cp -f "$src" "$staged" 2>/dev/null || { ccdc_warn "cannot copy $src to $dest"; return 0; }
  chmod --reference="$src" "$staged" 2>/dev/null || chmod 0700 "$staged" 2>/dev/null || true
  mv -f "$staged" "$dest" 2>/dev/null || { ccdc_warn "cannot install $dest"; rm -f "$staged"; return 0; }
  created="$created $dest"
}

write_payload() {
  local force=${1:-0}
  # A rewritten watchdog.sh copy is the best target on the box - it runs as root
  # every interval - so the payload is hash-checked exactly like the units.
  #
  # One honest limit: if guardian.sh's own installed copy is the thing that was
  # edited, the tick executing it is already the attacker's code and cannot be
  # trusted to notice. A tick run from the checkout (or a fresh --install) heals
  # it; a tick run from the tampered copy will not.
  if [ "$force" -eq 1 ] \
    || needs_rebuild "$guardian_copy" \
    || needs_rebuild "$watchdog_copy" \
    || needs_rebuild "$common_copy"; then
    if ccdc_is_dry_run; then
      printf '[dry-run] would copy guardian.sh, watchdog.sh and lib/common.sh into %s\n' "$guardian_dir"
    else
      mkdir -p "$guardian_dir/lib" 2>/dev/null || ccdc_warn "cannot create $guardian_dir/lib"
      # Copy from whichever tree this invocation is running out of: on a
      # reconcile tick that is the installed copy, which makes the guardian
      # able to heal its own payload after a partial delete. When source and
      # destination are the same file that is exactly the healthy case, so skip
      # it silently rather than letting cp complain once per tick forever.
      copy_payload_file "$SCRIPT_DIR/watchdog.sh" "$watchdog_copy"
      copy_payload_file "$SCRIPT_DIR/lib/common.sh" "$common_copy"
      copy_payload_file "$SCRIPT_DIR/guardian.sh" "$guardian_copy"
      chmod 0700 "$guardian_dir" 2>/dev/null || true
      chmod 0700 "$guardian_copy" "$watchdog_copy" 2>/dev/null || true
      glog "payload_refreshed dir=$guardian_dir"
    fi
  fi
  # The config goes with it. A guardian pointing at /tmp/ccdc-linux.env is one
  # tmpfiles cleanup away from restarting nothing.
  if [ -n "$config" ] && { [ "$force" -eq 1 ] || needs_rebuild "$env_copy"; }; then
    if ccdc_is_dry_run; then
      printf '[dry-run] would copy %s to %s (0600)\n' "$config" "$env_copy"
    else
      cp -f "$config" "$env_copy" 2>/dev/null || ccdc_warn "cannot copy config to $env_copy"
      chmod 0600 "$env_copy" 2>/dev/null || true
      created="$created $env_copy"
    fi
  fi
}

write_tick_script() {
  write_artifact payload "$tick_script" 0700 <<SCRIPT
#!/bin/bash
# Generated by guardian.sh. Layer 1: a supervised sleep loop that runs the same
# reconcile pass as the timer and the cron entry.
while :; do
  [ -f "$sentinel" ] && exit 0
  /bin/bash "$guardian_copy" --config "$env_copy" --tick --apply >/dev/null 2>&1
  sleep $interval
done
SCRIPT
}

write_svc_watch() {
  write_artifact target "$svc_watch" 0644 <<UNIT
[Unit]
Description=Node health monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $watchdog_copy --config $env_copy --apply --interval $interval
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  need_daemon_reload=1
}

write_svc_ticker() {
  write_artifact layer1 "$svc_ticker" 0644 <<UNIT
[Unit]
Description=Node health supervisor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $tick_script
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  need_daemon_reload=1
}

write_svc_reconcile() {
  write_artifact layer2 "$svc_reconcile" 0644 <<UNIT
[Unit]
Description=Node health reconcile

[Service]
Type=oneshot
ExecStart=/bin/bash $guardian_copy --config $env_copy --tick --apply
UNIT
  need_daemon_reload=1
}

write_tmr_reconcile() {
  # AccuracySec defaults to a minute, which would make a 60s interval fire
  # anywhere inside a two-minute window. Pin it so the interval means something.
  write_artifact layer2 "$tmr_reconcile" 0644 <<UNIT
[Unit]
Description=Node health reconcile timer

[Timer]
OnBootSec=${interval}s
OnUnitActiveSec=${interval}s
AccuracySec=1s
Unit=$name-reconcile.service

[Install]
WantedBy=timers.target
UNIT
  need_daemon_reload=1
}

write_cron() {
  local minutes spec
  minutes=$(( (interval + 59) / 60 ))
  [ "$minutes" -lt 1 ] && minutes=1
  if [ "$minutes" -ge 60 ]; then
    # */60 is not valid in a cron minute field.
    spec='0 * * * *'
  else
    spec="*/$minutes * * * *"
  fi
  write_artifact layer3 "$cron_file" 0644 <<CRON
# Generated by guardian.sh. Layer 3: the scheduler that survives a systemd purge.
# Removable with: guardian.sh --config <cfg> --uninstall --apply
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$spec root /bin/bash $guardian_copy --config $env_copy --tick --apply >/dev/null 2>&1
CRON
}

# --- reconcile ---------------------------------------------------------------

watchdog_running_pidfile() {
  local pid
  pid=$(cat "$pid_file" 2>/dev/null || printf '')
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  # PIDs get reused. Confirm it is still our process before believing the file.
  if [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q 'watchdog.sh' || return 1
  fi
  return 0
}

ensure_watchdog() {
  local force=${1:-0}
  if have_systemd; then
    if [ "$force" -eq 1 ]; then
      write_svc_watch
    elif needs_rebuild "$svc_watch"; then
      ccdc_info "watchdog unit missing or edited; rebuilding"
      write_svc_watch
      # The old unit may still be loaded in memory with the attacker's edit.
      ccdc_is_dry_run || systemctl stop "$name-watch.service" >>"$log" 2>&1 || true
    fi
    reload_if_needed
    if ccdc_is_dry_run; then
      systemctl is-active --quiet "$name-watch.service" 2>/dev/null \
        || printf '[dry-run] would start %s-watch.service\n' "$name"
      return 0
    fi
    if ! systemctl is-active --quiet "$name-watch.service" 2>/dev/null; then
      glog "watchdog_down restarting unit=$name-watch.service"
      systemctl enable --now "$name-watch.service" >>"$log" 2>&1 \
        || ccdc_warn "could not start $name-watch.service"
    elif ! systemctl is-enabled --quiet "$name-watch.service" 2>/dev/null; then
      # Active but not enabled survives until the next reboot and no longer.
      systemctl enable "$name-watch.service" >>"$log" 2>&1 || true
    fi
    return 0
  fi

  # No systemd: supervise it ourselves through a pidfile.
  if watchdog_running_pidfile; then
    return 0
  fi
  if ccdc_is_dry_run; then
    printf '[dry-run] would start a detached watchdog loop (no systemd on this box)\n'
    return 0
  fi
  glog "watchdog_down starting detached loop"
  setsid /bin/bash "$watchdog_copy" --config "$env_copy" --apply --interval "$interval" \
    </dev/null >>"$state_dir/watchdog.err" 2>&1 &
  printf '%s\n' "$!" >"$pid_file"
}

reload_if_needed() {
  [ "$need_daemon_reload" -eq 1 ] || return 0
  need_daemon_reload=0
  have_systemd || return 0
  ccdc_action systemctl daemon-reload
}

ensure_unit_enabled() {
  local unit=$1
  ccdc_is_dry_run && { printf '[dry-run] would ensure %s is enabled and running\n' "$unit"; return 0; }
  if ! systemctl is-active --quiet "$unit" 2>/dev/null; then
    glog "layer_down restarting unit=$unit"
    systemctl enable --now "$unit" >>"$log" 2>&1 || ccdc_warn "could not start $unit"
  elif ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    systemctl enable "$unit" >>"$log" 2>&1 || true
  fi
}

ensure_layers() {
  local force=${1:-0}
  local built=0

  if have_systemd; then
    # Spelled out rather than `[ force ] || [ ! -f x ] && write`: that chain
    # parses as (A || B) && C, which is right by accident and unreadable on
    # hour six.
    if [ "$force" -eq 1 ] || needs_rebuild "$tick_script"; then write_tick_script; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$svc_ticker"; then write_svc_ticker; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$svc_reconcile"; then write_svc_reconcile; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$tmr_reconcile"; then write_tmr_reconcile; fi
    reload_if_needed
    ensure_unit_enabled "$name.service"
    ensure_unit_enabled "$name-reconcile.timer"
    built=$((built + 2))
  else
    ccdc_warn "no systemd on this box: layers 1 and 2 are unavailable, cron is the only layer"
  fi

  if have_crond; then
    if [ "$force" -eq 1 ] || needs_rebuild "$cron_file"; then
      write_cron
    fi
    built=$((built + 1))
  else
    # Alpine and other busybox/OpenRC systems have no /etc/cron.d: busybox crond
    # reads whole crontabs out of /etc/crontabs instead, and OpenRC has no
    # equivalent of a systemd timer. Neither is wired up here. On such a box,
    # install nothing and run watchdog.sh under your init supervisor by hand.
    ccdc_warn "no /etc/cron.d on this box (Alpine/OpenRC?): layer 3 unavailable and not emulated"
  fi

  [ "$built" -gt 0 ] || ccdc_warn "no scheduling layer could be built; the watchdog is NOT being kept alive"
}

# --- disarm ------------------------------------------------------------------

remove_artifact() {
  local path=$1
  [ -n "$path" ] || return 0
  [ -e "$path" ] || return 0
  ccdc_action rm -f "$path"
}

stop_units() {
  have_systemd || return 0
  local unit
  for unit in "$name.service" "$name-reconcile.timer" "$name-reconcile.service" "$name-watch.service"; do
    ccdc_action systemctl disable --now "$unit"
  done
}

# Tear down everything, whether called by --uninstall or by a tick that found
# the sentinel. Authoritative list is the manifest; the expected list is the
# fallback so a deleted manifest cannot strand a foothold on the box.
remove_all() {
  stop_units

  local kind path
  if [ -f "$manifest" ]; then
    while IFS='|' read -r kind path; do
      [ -n "${path:-}" ] || continue
      remove_artifact "$path"
    done <"$manifest"
  fi
  while IFS='|' read -r kind path; do
    [ -n "${path:-}" ] || continue
    remove_artifact "$path"
  done <<EOF
$(expected_artifacts)
EOF

  # The detached watchdog, if this box had no systemd to own it.
  if ! have_systemd; then
    local pid
    pid=$(cat "$pid_file" 2>/dev/null || printf '')
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      ccdc_action kill "$pid"
    fi
  fi
  remove_artifact "$pid_file"

  # rmdir, never rm -rf: if anything unexpected is in there, leaving it for the
  # operator to look at beats deleting a directory tree by name.
  if [ -d "$guardian_dir" ]; then
    ccdc_action rmdir "$guardian_dir/lib"
    ccdc_action rmdir "$guardian_dir"
  fi

  need_daemon_reload=1
  reload_if_needed
}

# --- modes -------------------------------------------------------------------

do_install() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  [ -n "$config" ] || ccdc_die "--install needs --config FILE: the layers run unattended and cannot guess it"
  [ -f "$SCRIPT_DIR/watchdog.sh" ] || ccdc_die "watchdog.sh not found next to guardian.sh"
  acquire_lock $((interval * 2)) \
    || ccdc_warn "proceeding without the tick lock; a reconcile pass may be running"

  # A leftover sentinel from a previous uninstall would make every layer remove
  # itself on its first tick.
  if [ -f "$sentinel" ]; then
    ccdc_action rm -f "$sentinel"
    ccdc_info "cleared the disarm sentinel from a previous uninstall"
  fi

  write_payload 1
  ensure_watchdog 1
  ensure_layers 1
  record_manifest

  if ccdc_is_dry_run; then
    ccdc_info "dry run only; nothing installed. Re-run with --apply to arm."
  else
    glog "installed name=$name dir=$guardian_dir interval=${interval}s"
    ccdc_info "guardian armed as '$name'; manifest at $manifest"
    printf '\n'
    do_status
  fi
}

do_tick() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  acquire_lock || return 0

  if [ -f "$sentinel" ]; then
    ccdc_info "disarm sentinel present ($sentinel): removing this layer instead of reconciling"
    glog "disarm_seen removing_layers"
    remove_all
    return 0
  fi

  write_payload 0
  ensure_watchdog 0
  ensure_layers 0
  record_manifest
}

layer_line() {
  local label=$1 path=$2 unit=${3:-}
  local state='MISSING' extra=''
  if [ -e "$path" ]; then
    state='present'
    local old new
    old=$(recorded_hash "$path")
    new=$(file_hash "$path")
    if [ -n "$old" ] && [ "$old" != absent ] && [ -n "$new" ] && [ "$old" != "$new" ]; then
      state='MODIFIED'
      extra=' <- does not match the manifest; someone edited it'
    fi
  fi
  if [ -n "$unit" ] && have_systemd; then
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      extra="$extra (active)"
    else
      extra="$extra (NOT ACTIVE)"
    fi
  fi
  printf '  %-9s %-9s %s%s\n' "$label" "$state" "$path" "$extra"
}

do_status() {
  printf 'guardian: %s\n' "$name"
  printf 'payload:  %s\n' "$guardian_dir"
  printf 'interval: %ss\n' "$interval"
  printf 'manifest: %s\n' "$manifest"
  if [ -f "$sentinel" ]; then
    printf 'state:    DISARMED (sentinel present: %s)\n' "$sentinel"
  else
    printf 'state:    armed\n'
  fi
  printf '\nlayers:\n'
  if have_systemd; then
    layer_line target "$svc_watch" "$name-watch.service"
    layer_line layer1 "$svc_ticker" "$name.service"
    layer_line layer2 "$tmr_reconcile" "$name-reconcile.timer"
  else
    printf '  target    n/a       no systemd: watchdog supervised by pidfile %s\n' "$pid_file"
    printf '  layer1    n/a       no systemd\n'
    printf '  layer2    n/a       no systemd\n'
  fi
  if have_crond; then
    layer_line layer3 "$cron_file"
  else
    printf '  layer3    n/a       no /etc/cron.d on this box\n'
  fi

  printf '\nwatchdog: '
  if have_systemd; then
    if systemctl is-active --quiet "$name-watch.service" 2>/dev/null; then
      printf 'running (%s-watch.service)\n' "$name"
    else
      printf 'NOT RUNNING\n'
    fi
  elif watchdog_running_pidfile; then
    printf 'running (pid %s)\n' "$(cat "$pid_file" 2>/dev/null)"
  else
    printf 'NOT RUNNING\n'
  fi

  if [ -f "$manifest" ]; then
    printf '\nmanifest (%s artifacts):\n' "$(wc -l <"$manifest" | tr -d ' ')"
    sed 's/^/  /' "$manifest"
  else
    printf '\nno manifest: guardian has not been installed from this box\n'
  fi
  [ -f "$log" ] && { printf '\nrecent guardian log:\n'; tail -n 10 "$log" | sed 's/^/  /'; }
  return 0
}

do_uninstall() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  acquire_lock $((interval * 2)) \
    || ccdc_warn "proceeding without the tick lock; the sentinel still stops any late rebuild"

  # Sentinel first, teardown second. A tick that fires in the middle of the
  # teardown must find the sentinel already there, or it will helpfully rebuild
  # everything you are in the middle of removing.
  if ccdc_is_dry_run; then
    printf '[dry-run] would write the disarm sentinel %s first, then remove every artifact\n' "$sentinel"
  else
    printf 'guardian disarmed %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$sentinel"
    glog "uninstall_started sentinel=$sentinel"
  fi

  remove_all

  if ccdc_is_dry_run; then
    ccdc_info "dry run only; nothing removed"
    return 0
  fi

  rm -f "$manifest"
  glog "uninstall_complete"
  ccdc_info "guardian removed; sentinel left at $sentinel so any late tick disarms itself"
  ccdc_info "verify with --status, then delete the sentinel by hand once nothing fires"
}

case "$mode" in
  install) do_install ;;
  status) do_status ;;
  uninstall) do_uninstall ;;
  tick) do_tick ;;
esac
