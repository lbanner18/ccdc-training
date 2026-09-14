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
# Naming: every layer derives from CCDC_GUARDIAN_NAME (default "node-health"),
# but each can be named independently:
#
#   CCDC_GUARDIAN_WATCH_NAME       the watchdog unit
#   CCDC_GUARDIAN_TICKER_NAME      layer 1
#   CCDC_GUARDIAN_RECONCILE_NAME   layer 2 (service + timer)
#   CCDC_GUARDIAN_CRON_NAME        layer 3
#
# Set them to unrelated names and the defence stops being enumerable in one
# command. With a shared prefix, `systemctl list-units | grep node-health` finds
# every layer and `rm /etc/systemd/system/node-health*` removes every layer, so
# the "attacker must find all three" property is worth exactly one grep. With
# unrelated names they have to discover four separate things.
#
# You lose nothing by doing this: the manifest at $CCDC_EVIDENCE_DIR is what
# keeps your own footholds legible to you, not the shared prefix. Pick names
# that are plausible for the box, NOT ones that scream "defense".
#
# Know the limit, because it is easy to oversell this. Every layer executes the
# same payload, so every unit's ExecStart names CCDC_GUARDIAN_DIR:
#
#   grep -rl "$CCDC_GUARDIAN_DIR" /etc/systemd/system /etc/cron.d
#
# finds all of them again. Independent names defeat a COLD grep -- someone
# sweeping for obviously-named defence tooling comes up empty -- but they do not
# defeat an attacker who has already found one layer and read it. Set
# CCDC_GUARDIAN_DIR to something unrelated too and the cold sweep gets harder
# still, but the pivot from any single discovered layer remains. Removing that
# would mean a separate payload copy per layer, which is a lot of machinery for
# a modest gain; the redundancy, not the concealment, is what this design is
# actually built on.
#
# --- what gets installed -----------------------------------------------------
#
#   target   <watch>.service       runs watchdog.sh, Restart=always
#   layer 1  <ticker>.service      Restart=always, runs tick.sh (a sleep loop)
#   layer 2  <reconcile>.timer     fires the same tick every interval
#   layer 3  /etc/cron.d/<cron>    fires the same tick every ceil(interval/60) min
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

umask 077

config=''
fallback_config=''
config_sha256=''
mode=''
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --fallback-config) fallback_config=${2:?missing fallback config path}; shift 2 ;;
    --config-sha256) config_sha256=${2:?missing config SHA-256}; shift 2 ;;
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

# Installed layers pin the repair configuration's digest and provide the live
# copy as a fallback. Validate before sourcing shell syntax: otherwise a single
# edit to guardian.env could redirect the manifest/name/paths and then be
# accepted before reconciliation ever had a chance to inspect it.
if [ -n "$config_sha256" ]; then
  actual_config_sha256=$(ccdc_hash_file "$config" 2>/dev/null | awk '{print $1}')
  if [ "$actual_config_sha256" != "$config_sha256" ]; then
    fallback_sha256=$(ccdc_hash_file "$fallback_config" 2>/dev/null | awk '{print $1}')
    if [ -n "$fallback_config" ] && [ "$fallback_sha256" = "$config_sha256" ]; then
      ccdc_warn "repair configuration failed its pinned hash; using the matching live fallback"
      config=$fallback_config
    else
      ccdc_die "neither installed configuration matches the pinned SHA-256; refusing to source either"
    fi
  fi
fi
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

# One knob used to drive two unrelated things, and they want different numbers:
#
#   reconcile interval - how fast a REMOVED LAYER gets rebuilt. An attacker has
#     to delete all layers inside this window, so shorter is more resilient, but
#     every tick re-hashes the whole manifest. 30-60s is plenty.
#   watchdog interval  - how fast a DEAD SERVICE is noticed. This one converts
#     directly into scored downtime: your mean outage is roughly half of it.
#     Measured on the lab box, a 60s interval produced a 57s outage.
#
# So the watchdog gets its own knob and a much lower floor. A pass is a curl and
# a couple of systemctl calls - sub-second - and watchdog.sh already guards
# against thrash with one-restart-per-pass and a settle deadline after each
# restart, so a short interval does not turn into a restart storm.
watchdog_interval=${CCDC_WATCHDOG_INTERVAL:-$interval}
case "$watchdog_interval" in
  ''|*[!0-9]*) ccdc_die "CCDC_WATCHDOG_INTERVAL must be a whole number of seconds: $watchdog_interval" ;;
esac
[ "$watchdog_interval" -ge 2 ] || ccdc_die "CCDC_WATCHDOG_INTERVAL below 2s leaves no room for a check to finish: $watchdog_interval"
case "$guardian_dir" in
  /*) ;;
  *) ccdc_die "CCDC_GUARDIAN_DIR must be an absolute path: $guardian_dir" ;;
esac
case "$guardian_dir" in
  *[!A-Za-z0-9_./-]*) ccdc_die "CCDC_GUARDIAN_DIR contains unsupported whitespace/shell characters: $guardian_dir" ;;
esac

# Per-layer names. CCDC_GUARDIAN_NAME stays the base and every layer derives
# from it by default, so nothing changes unless you ask for it. Override them
# individually and the layers stop sharing a prefix.
#
# Why bother: with one shared name, `systemctl list-units | grep node-health`
# and `rm /etc/systemd/system/node-health*` each find and remove the WHOLE
# defence in one command. Independent names mean an attacker has to discover
# four unrelated things instead of one pattern. The manifest is what keeps it
# legible to you, so you lose nothing by making them unrelated to each other.
watch_name=${CCDC_GUARDIAN_WATCH_NAME:-$name-watch}
ticker_name=${CCDC_GUARDIAN_TICKER_NAME:-$name}
reconcile_name=${CCDC_GUARDIAN_RECONCILE_NAME:-$name-reconcile}
cron_name=${CCDC_GUARDIAN_CRON_NAME:-$name}

for _n in "$watch_name" "$ticker_name" "$reconcile_name" "$cron_name"; do
  case "$_n" in
    ''|*[!A-Za-z0-9_-]*) ccdc_die "guardian layer names must be [A-Za-z0-9_-] only: $_n" ;;
  esac
done
# Two layers sharing a name would mean two layers sharing one unit file: the
# second write silently replaces the first and you are down a layer without
# being told.
if [ "$(printf '%s\n' "$watch_name" "$ticker_name" "$reconcile_name" | sort -u | wc -l)" -ne 3 ]; then
  ccdc_die "watch/ticker/reconcile names must differ from each other"
fi

unit_watch="$watch_name.service"
unit_ticker="$ticker_name.service"
unit_reconcile="$reconcile_name.service"
unit_timer="$reconcile_name.timer"

# A description shared across layers is just the shared name again in another
# field, greppable with `systemctl list-units`. Derive each from its own name.
describe() { printf '%s' "$1" | tr '_-' '  '; }

# State lives with the evidence by default, next to the watchdog and canary
# logs, so one directory is the whole story when you write the incident report.
#
# Override it to run SEVERAL INDEPENDENT CHAINS. Each chain needs its own
# manifest, sentinel, lock and pidfile, or the second install overwrites the
# first one's manifest and then "uninstall" tears down a set of artifacts that
# is no longer the set that exists. With a state dir per chain you get N fully
# separate keep-alives that share nothing but the box:
#
#   CCDC_GUARDIAN_STATE_DIR=/var/lib/misc/.netmon   ...chain A's own names
#   CCDC_GUARDIAN_STATE_DIR=/var/cache/man/.sync    ...chain B's own names
#
# Deliberately NOT split: CCDC_EVIDENCE_DIR. Every chain still writes evidence
# and the watchdog's singleton lock to one shared place, and the shared lock is
# exactly what stops two chains from restarting the same service twice. Split
# the evidence dir as well and you get the double restart back.
state_dir=${CCDC_GUARDIAN_STATE_DIR:-${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}}
case "$state_dir" in
  /*) ;;
  *) ccdc_die "CCDC_GUARDIAN_STATE_DIR must be an absolute path: $state_dir" ;;
esac
mkdir -p "$state_dir" 2>/dev/null || state_dir="${TMPDIR:-/tmp}/ccdc-evidence"
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create state directory"
if [ "$apply" -eq 1 ]; then
  chmod 0700 "$state_dir" 2>/dev/null || ccdc_die "cannot secure state directory: $state_dir"
else
  chmod 0700 "$state_dir" 2>/dev/null || true
fi
manifest="$state_dir/guardian.manifest"   # kind|path|sha256-at-write
sentinel="$state_dir/guardian.disarmed"
log="$state_dir/guardian.log"
pid_file="$state_dir/guardian-watchdog.pid"
lock_dir="$state_dir/guardian.lock"
lock_owner="$lock_dir/owner"
lock_token=''
staged_paths=''

# Payload copies (what the layers actually execute).
#
# Named after this chain's own layers, NOT after the kit. The unit names, the
# payload directory and the state directory can all be made unrelated between
# chains, and a red-team test still found every chain on the box in one command:
#
#     ps -eo args | grep watchdog.sh
#
# because every chain executed a file called watchdog.sh. `ps` is a namespace no
# amount of renaming elsewhere can hide from -- the running process has to say
# what it is running. So the file itself takes the layer's name, and a chain
# whose watch layer is "systemd-netmon" runs /usr/local/lib/netmon/systemd-netmon.sh.
# There is then no string shared between two chains for one grep to find.
#
# This is defence in depth against a hurried attacker, not concealment: the
# manifest still lists every artifact by real path, --status prints them, and
# anyone who reads a unit file learns everything. Rule 5.6 tooling stays public
# and unmodified; what changes is only the filename we copy it to.
watchdog_basename=${CCDC_GUARDIAN_WATCHDOG_FILE:-$watch_name.sh}
self_basename=${CCDC_GUARDIAN_SELF_FILE:-$reconcile_name.sh}
case "$watchdog_basename$self_basename" in
  */*) ccdc_die "CCDC_GUARDIAN_WATCHDOG_FILE and CCDC_GUARDIAN_SELF_FILE are filenames, not paths" ;;
esac
guardian_copy="$guardian_dir/$self_basename"
watchdog_copy="$guardian_dir/$watchdog_basename"
common_copy="$guardian_dir/lib/common.sh"
env_copy="$guardian_dir/guardian.env"
# Same reasoning as the payload names above: tick.sh is named in the ticker
# unit's ExecStart, so leaving it fixed put the shared thread straight back --
# `grep -rl tick.sh /etc/systemd/system` would find every chain at once.
tick_basename=${CCDC_GUARDIAN_TICK_FILE:-$ticker_name.sh}
case "$tick_basename" in
  */*) ccdc_die "CCDC_GUARDIAN_TICK_FILE is a filename, not a path: $tick_basename" ;;
esac
tick_script="$guardian_dir/$tick_basename"

# These three share a directory, so identical names would silently overwrite one
# another and the chain would execute the wrong script. Easy to do by hand when
# the layer names are chosen to look plausible rather than to be distinct.
if [ "$tick_basename" = "$watchdog_basename" ] \
  || [ "$tick_basename" = "$self_basename" ] \
  || [ "$watchdog_basename" = "$self_basename" ]; then
  ccdc_die "payload filenames collide in $guardian_dir: $self_basename / $watchdog_basename / $tick_basename (give the watch, ticker and reconcile layers different names)"
fi

# Reconciliation must copy from an independent source. The files in .repair
# are never referenced by a service ExecStart; they are the clean source used
# to replace a deleted or edited live payload. Root can still destroy every
# copy at once, which is the documented limit, but editing one live file no
# longer causes a source==destination no-op followed by manifest laundering.
repair_dir="$guardian_dir/.repair"
repair_guardian="$repair_dir/$self_basename"
repair_watchdog="$repair_dir/$watchdog_basename"
repair_common="$repair_dir/lib/common.sh"
repair_env="$repair_dir/guardian.env"

unit_dir=/etc/systemd/system
svc_watch="$unit_dir/$unit_watch"
svc_ticker="$unit_dir/$unit_ticker"
svc_reconcile="$unit_dir/$unit_reconcile"
tmr_reconcile="$unit_dir/$unit_timer"
cron_file="/etc/cron.d/$cron_name"

created=''          # paths written during this run (their hashes get refreshed)
need_daemon_reload=0
pinned_env_hash=''
units_needing_restart=''

# --- capability detection ----------------------------------------------------
# Degrade honestly. A box with no systemd gets the cron layer only, and says so;
# it does not pretend to three layers it cannot build.

have_systemd() { ccdc_have systemctl && [ -d /run/systemd/system ]; }

have_crond() {
  [ -d /etc/cron.d ] || return 1
  { ccdc_have cron || ccdc_have crond; } || return 1
  if ccdc_have pgrep; then
    pgrep -x cron >/dev/null 2>&1 || pgrep -x crond >/dev/null 2>&1 || return 1
  elif have_systemd; then
    systemctl is-active --quiet cron.service 2>/dev/null \
      || systemctl is-active --quiet crond.service 2>/dev/null \
      || systemctl is-active --quiet cronie.service 2>/dev/null \
      || return 1
  else
    return 1
  fi
}

run_systemctl() {
  if ccdc_have timeout; then
    timeout 15 systemctl "$@"
  else
    systemctl "$@"
  fi
}

# --- helpers -----------------------------------------------------------------

glog() { ccdc_append_log "$log" "$@"; }

release_lock() {
  [ -n "$lock_token" ] || return 0
  local current
  current=$(cat "$lock_owner" 2>/dev/null || printf '')
  if [ "$current" = "$lock_token" ]; then
    rm -f "$lock_owner" 2>/dev/null || true
    rmdir "$lock_dir" 2>/dev/null || true
  fi
  lock_token=''
}

cleanup_staged() {
  local path
  for path in $staged_paths; do
    rm -f -- "$path" 2>/dev/null || true
  done
  release_lock
}

trap cleanup_staged EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Write one artifact, content on stdin. Honors CCDC_DRY_RUN like ccdc_action,
# which cannot be used here because the content is a heredoc, not an argv.
write_artifact() {
  local kind=$1 path=$2 mode_bits=$3 content
  content=$(cat)
  if ccdc_is_dry_run; then
    printf '[dry-run] would write %s (%s, mode %s)\n' "$path" "$kind" "$mode_bits"
    return 0
  fi
  mkdir -p "$(dirname -- "$path")" 2>/dev/null \
    || { ccdc_warn "cannot create parent for $path"; return 1; }
  # Write-then-rename, never truncate in place. tick.sh is being executed by a
  # running bash process (layer 1's service); bash reads a script incrementally
  # by file offset, so overwriting one in place makes the running shell resume
  # mid-file and misparse whatever now sits at that byte. A rename swaps the
  # directory entry and leaves the running process on its original inode, which
  # it finishes cleanly before the next loop picks up the new file.
  local staged="${path}.new.$$"
  staged_paths="$staged_paths $staged"
  printf '%s\n' "$content" >"$staged" || { ccdc_warn "cannot write $path"; return 1; }
  chmod "$mode_bits" "$staged" 2>/dev/null || { ccdc_warn "cannot chmod $path"; return 1; }
  mv -f "$staged" "$path" || { ccdc_warn "cannot install $path"; rm -f "$staged"; return 1; }
  created="$created $path"
  glog "wrote kind=$kind path=$path"
  return 0
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

unit_override_paths() {
  local unit
  for unit in "$unit_watch" "$unit_ticker" "$unit_reconcile" "$unit_timer"; do
    printf '%s\n' \
      "/etc/systemd/system/$unit.d" \
      "/run/systemd/system/$unit.d" \
      "/etc/systemd/system.control/$unit.d" \
      "/run/systemd/system.control/$unit.d" \
      "/run/systemd/system/$unit" \
      "/run/systemd/transient/$unit"
  done
}

preserve_override() {
  local path=$1 dest label
  label=$(printf '%s' "$path" | tr '/' '_')
  dest="$state_dir/guardian.tampered/${label}.$(ccdc_now).$$"
  if ccdc_is_dry_run; then
    printf '[dry-run] would quarantine systemd override %s as %s\n' "$path" "$dest"
    return 0
  fi
  mkdir -p "$state_dir/guardian.tampered" 2>/dev/null \
    || { ccdc_warn "cannot create guardian tamper evidence directory"; return 1; }
  mv -- "$path" "$dest" 2>/dev/null \
    || { ccdc_warn "cannot quarantine systemd override: $path"; return 1; }
  ccdc_warn "TAMPERED: quarantined systemd override $path"
  glog "TAMPER path=$path action=override_quarantined evidence=$dest"
}

override_unit_for_path() {
  case "$1" in
    */"$unit_watch"|*/"$unit_watch.d") printf '%s\n' "$unit_watch" ;;
    */"$unit_ticker"|*/"$unit_ticker.d") printf '%s\n' "$unit_ticker" ;;
    */"$unit_reconcile"|*/"$unit_reconcile.d") printf '%s\n' "$unit_reconcile" ;;
    */"$unit_timer"|*/"$unit_timer.d") printf '%s\n' "$unit_timer" ;;
  esac
}

ensure_no_unit_overrides() {
  have_systemd || return 0
  local path changed=0 affected_unit
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ] || [ -L "$path" ]; then
      preserve_override "$path" || return 1
      affected_unit=$(override_unit_for_path "$path")
      if [ -n "$affected_unit" ] \
        && ! ccdc_list_contains "$affected_unit" "$units_needing_restart"; then
        units_needing_restart="$units_needing_restart $affected_unit"
      fi
      changed=1
    fi
  done <<EOF
$(unit_override_paths)
EOF
  [ "$changed" -eq 0 ] || need_daemon_reload=1
}

restart_repaired_units() {
  local blocking=${1:-0} unit
  [ -n "$units_needing_restart" ] || return 0
  reload_if_needed || return 1
  for unit in $units_needing_restart; do
    if ccdc_is_dry_run; then
      printf '[dry-run] would restart repaired effective unit %s\n' "$unit"
    elif [ "$blocking" -eq 1 ]; then
      run_systemctl restart "$unit" >>"$log" 2>&1 \
        || { ccdc_warn "could not restart repaired unit $unit"; return 1; }
    else
      # A reconcile oneshot may be repairing its own override. Queueing the
      # restart lets this pass finish its writes before systemd terminates it.
      run_systemctl --no-block restart "$unit" >>"$log" 2>&1 \
        || { ccdc_warn "could not queue restart for repaired unit $unit"; return 1; }
    fi
  done
  units_needing_restart=''
}

new_install_has_override() {
  local path
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ] || [ -L "$path" ]; then
      ccdc_warn "guardian unit name collides with pre-existing override: $path"
      return 0
    fi
  done <<EOF
$(unit_override_paths)
EOF
  return 1
}

unit_effective_matches() {
  local unit=$1 fragment=$2 executable=${3:-} actual dropins
  actual=$(run_systemctl show -p FragmentPath --value "$unit" 2>/dev/null || printf '')
  [ "$actual" = "$fragment" ] || return 1
  dropins=$(run_systemctl show -p DropInPaths --value "$unit" 2>/dev/null || printf '')
  printf '%s\n' "$dropins" | tr ' ' '\n' | grep -F "/$unit.d/" >/dev/null && return 1
  if [ -n "$executable" ]; then
    run_systemctl show -p ExecStart "$unit" 2>/dev/null \
      | grep -F -- "$executable" >/dev/null || return 1
  fi
  return 0
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
  printf 'repair|%s\n' "$repair_guardian"
  printf 'repair|%s\n' "$repair_watchdog"
  printf 'repair|%s\n' "$repair_common"
  printf 'repair|%s\n' "$repair_env"
  if have_systemd; then
    printf 'payload|%s\n' "$tick_script"
    printf 'target|%s\n' "$svc_watch"
    printf 'layer1|%s\n' "$svc_ticker"
    printf 'layer2|%s\n' "$svc_reconcile"
    printf 'layer2|%s\n' "$tmr_reconcile"
  fi
  have_crond && printf 'layer3|%s\n' "$cron_file"
}

# Removal cannot depend on what init system happens to be running now. A rescue
# shell or chroot may have no /run/systemd/system even though unit files were
# installed for the next boot.
removal_artifacts() {
  printf 'payload|%s\n' "$guardian_copy"
  printf 'payload|%s\n' "$watchdog_copy"
  printf 'payload|%s\n' "$common_copy"
  printf 'payload|%s\n' "$env_copy"
  printf 'repair|%s\n' "$repair_guardian"
  printf 'repair|%s\n' "$repair_watchdog"
  printf 'repair|%s\n' "$repair_common"
  printf 'repair|%s\n' "$repair_env"
  printf 'payload|%s\n' "$tick_script"
  printf 'target|%s\n' "$svc_watch"
  printf 'layer1|%s\n' "$svc_ticker"
  printf 'layer2|%s\n' "$svc_reconcile"
  printf 'layer2|%s\n' "$tmr_reconcile"
  printf 'layer3|%s\n' "$cron_file"
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
  staged_paths="$staged_paths $tmp"
  : >"$tmp" || { ccdc_warn "cannot write manifest"; return 1; }
  while IFS='|' read -r kind path; do
    [ -n "${path:-}" ] || continue
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
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
  mv "$tmp" "$manifest" || { ccdc_warn "cannot install manifest"; return 1; }
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
  local wait_for=${1:-0} deadline stamp now age owner owner_pid owner_start live_start
  deadline=$(( $(date +%s) + wait_for ))
  while :; do
    if mkdir "$lock_dir" 2>/dev/null; then
      owner_start=$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null || printf 'unknown')
      lock_token="$$:$owner_start"
      if ! printf '%s\n' "$lock_token" >"$lock_owner"; then
        lock_token=''
        rmdir "$lock_dir" 2>/dev/null || true
        glog "lock_failed cannot_write_owner"
        return 1
      fi
      return 0
    fi

    # Break a lock immediately only when its recorded owner is demonstrably
    # gone. Age alone is not proof: a slow systemctl call can legitimately run
    # longer than several intervals. An ownerless empty directory is eligible
    # only after the old age threshold.
    owner=$(cat "$lock_owner" 2>/dev/null || printf '')
    owner_pid=${owner%%:*}
    owner_start=${owner#*:}
    live_start=''
    case "$owner_pid" in
      ''|*[!0-9]*) ;;
      *)
        if kill -0 "$owner_pid" 2>/dev/null; then
          live_start=$(awk '{print $22}' "/proc/$owner_pid/stat" 2>/dev/null || printf '')
        fi
        ;;
    esac
    if [ -n "$owner" ] && { [ -z "$live_start" ] || [ "$live_start" != "$owner_start" ]; }; then
      glog "breaking dead tick lock owner=$owner"
      rm -f "$lock_owner" 2>/dev/null || true
      if rmdir "$lock_dir" 2>/dev/null; then
        continue
      fi
      glog "lock_not_empty refusing_to_break path=$lock_dir"
    fi

    stamp=$(stat -c '%Y' "$lock_dir" 2>/dev/null || stat -f '%m' "$lock_dir" 2>/dev/null || printf '0')
    now=$(date +%s)
    age=$((now - stamp))
    if [ -z "$owner" ] && [ "$age" -gt $((interval * 5)) ]; then
      if rmdir "$lock_dir" 2>/dev/null; then
        glog "broke ownerless stale tick lock age=${age}s"
        continue
      fi
      glog "ownerless_lock_not_empty refusing_to_break age=${age}s path=$lock_dir"
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 1
  done
  glog "lock_unavailable another_pass_is_running"
  return 1
}

# --- artifact bodies ---------------------------------------------------------

copy_payload_file() {
  local src=$1 dest=$2 mode_bits=${3:-} staged
  [ -f "$src" ] || { ccdc_warn "payload source missing: $src"; return 1; }
  [ "$src" != "$dest" ] || { ccdc_warn "refusing self-copy for payload: $src"; return 1; }
  mkdir -p "$(dirname -- "$dest")" 2>/dev/null \
    || { ccdc_warn "cannot create payload parent for $dest"; return 1; }
  # Same write-then-rename rule as write_artifact: watchdog.sh is running under
  # the watch service while we repair it, and cp truncates in place.
  staged="${dest}.new.$$"
  staged_paths="$staged_paths $staged"
  cp -f "$src" "$staged" 2>/dev/null || { ccdc_warn "cannot copy $src to $dest"; return 1; }
  if [ -n "$mode_bits" ]; then
    chmod "$mode_bits" "$staged" 2>/dev/null \
      || { ccdc_warn "cannot chmod $dest"; return 1; }
  else
    chmod --reference="$src" "$staged" 2>/dev/null \
      || chmod 0700 "$staged" 2>/dev/null \
      || { ccdc_warn "cannot chmod $dest"; return 1; }
  fi
  mv -f "$staged" "$dest" 2>/dev/null || { ccdc_warn "cannot install $dest"; rm -f "$staged"; return 1; }
  created="$created $dest"
  return 0
}

matches_manifest() {
  local path=$1 expected actual
  [ -f "$path" ] || return 1
  expected=$(recorded_hash "$path")
  [ -n "$expected" ] && [ "$expected" != absent ] || return 1
  actual=$(file_hash "$path")
  [ -n "$actual" ] && [ "$actual" = "$expected" ]
}

repair_pair() {
  local live=$1 repair=$2 mode_bits=$3
  if matches_manifest "$repair"; then
    if ! matches_manifest "$live"; then
      if [ -e "$live" ] || [ -L "$live" ]; then quarantine "$live"; fi
      copy_payload_file "$repair" "$live" "$mode_bits" || return 1
      glog "payload_repaired live=$live source=$repair"
    fi
    return 0
  fi
  if matches_manifest "$live"; then
    if [ -e "$repair" ] || [ -L "$repair" ]; then quarantine "$repair"; fi
    copy_payload_file "$live" "$repair" "$mode_bits" || return 1
    glog "repair_source_rebuilt repair=$repair source=$live"
    return 0
  fi
  ccdc_warn "neither payload copy matches the manifest: $live and $repair"
  glog "payload_unrecoverable live=$live repair=$repair"
  return 1
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
  if ccdc_is_dry_run; then
    printf '[dry-run] would install/repair live and independent repair payloads in %s\n' "$guardian_dir"
    pinned_env_hash=$(file_hash "$config")
    [ -n "$pinned_env_hash" ] || pinned_env_hash=DRY_RUN_SHA256
    return 0
  fi

  mkdir -p "$guardian_dir/lib" "$repair_dir/lib" 2>/dev/null \
    || { ccdc_warn "cannot create payload directories under $guardian_dir"; return 1; }
  chmod 0700 "$guardian_dir" "$guardian_dir/lib" "$repair_dir" "$repair_dir/lib" 2>/dev/null \
    || { ccdc_warn "cannot secure payload directories under $guardian_dir"; return 1; }

  if [ "$force" -eq 1 ]; then
    # A fresh install must be launched from the checkout. Reinstalling from the
    # live copy would bless that copy as its own clean repair source.
    [ "$SCRIPT_DIR" != "$guardian_dir" ] \
      || { ccdc_warn "run --install from the kit checkout, not the installed copy"; return 1; }
    copy_payload_file "$SCRIPT_DIR/guardian.sh" "$repair_guardian" 0700 || return 1
    copy_payload_file "$SCRIPT_DIR/watchdog.sh" "$repair_watchdog" 0700 || return 1
    copy_payload_file "$SCRIPT_DIR/lib/common.sh" "$repair_common" 0600 || return 1
    [ -n "$config" ] || { ccdc_warn "no configuration source for repair payload"; return 1; }
    copy_payload_file "$config" "$repair_env" 0600 || return 1

    copy_payload_file "$repair_guardian" "$guardian_copy" 0700 || return 1
    copy_payload_file "$repair_watchdog" "$watchdog_copy" 0700 || return 1
    copy_payload_file "$repair_common" "$common_copy" 0600 || return 1
    copy_payload_file "$repair_env" "$env_copy" 0600 || return 1
    pinned_env_hash=$(file_hash "$repair_env")
    [ -n "$pinned_env_hash" ] || return 1
    glog "payload_installed live=$guardian_dir repair=$repair_dir"
    return 0
  fi

  repair_pair "$guardian_copy" "$repair_guardian" 0700 || return 1
  repair_pair "$watchdog_copy" "$repair_watchdog" 0700 || return 1
  repair_pair "$common_copy" "$repair_common" 0600 || return 1
  repair_pair "$env_copy" "$repair_env" 0600 || return 1
  pinned_env_hash=$(file_hash "$repair_env")
  [ -n "$pinned_env_hash" ] || return 1
  return 0
}

write_tick_script() {
  write_artifact payload "$tick_script" 0700 <<SCRIPT
#!/bin/bash
# Authorised blue-team service keep-alive, layer 1 of 3: a supervised sleep loop
# that runs the same reconcile pass as the timer and the cron entry.
while :; do
  [ -f "$sentinel" ] && exit 0
  /bin/bash "$guardian_copy" --config "$repair_env" --fallback-config "$env_copy" --config-sha256 "$pinned_env_hash" --tick --apply >/dev/null 2>&1
  sleep $interval
done
SCRIPT
}

write_svc_watch() {
  write_artifact target "$svc_watch" 0644 <<UNIT
[Unit]
Description=$(describe "$watch_name") monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $watchdog_copy --config $env_copy --apply --interval $watchdog_interval
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  [ "$?" -eq 0 ] || return 1
  need_daemon_reload=1
}

write_svc_ticker() {
  write_artifact layer1 "$svc_ticker" 0644 <<UNIT
[Unit]
Description=$(describe "$ticker_name") supervisor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $tick_script
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  [ "$?" -eq 0 ] || return 1
  need_daemon_reload=1
}

write_svc_reconcile() {
  write_artifact layer2 "$svc_reconcile" 0644 <<UNIT
[Unit]
Description=$(describe "$reconcile_name")

[Service]
Type=oneshot
ExecStart=/bin/bash $guardian_copy --config $repair_env --fallback-config $env_copy --config-sha256 $pinned_env_hash --tick --apply
UNIT
  [ "$?" -eq 0 ] || return 1
  need_daemon_reload=1
}

write_tmr_reconcile() {
  # AccuracySec defaults to a minute, which would make a 60s interval fire
  # anywhere inside a two-minute window. Pin it so the interval means something.
  write_artifact layer2 "$tmr_reconcile" 0644 <<UNIT
[Unit]
Description=$(describe "$reconcile_name") timer

[Timer]
OnBootSec=${interval}s
OnUnitActiveSec=${interval}s
AccuracySec=1s
Unit=$unit_reconcile

[Install]
WantedBy=timers.target
UNIT
  [ "$?" -eq 0 ] || return 1
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
# Authorised blue-team service keep-alive, layer 3 of 3: the scheduler that
# survives a systemd purge. This is defensive tooling, not an implant.
# Remove with: $guardian_copy --config <cfg> --uninstall --apply
#
# The label names THIS chain's own payload rather than the kit, because a fixed
# string here is a join key: one `grep -rl` across /etc/cron.d would otherwise
# link every independent chain on the box. The path below is already on the
# ExecStart line underneath, so nothing is hidden that was not already visible.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$spec root /bin/bash $guardian_copy --config $repair_env --fallback-config $env_copy --config-sha256 $pinned_env_hash --tick --apply >/dev/null 2>&1
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
    # Match this chain's own payload path, not the literal "watchdog.sh": the
    # copy is named after the chain now, and matching the kit's filename would
    # make this always false (guardian would respawn a watchdog it already has,
    # every tick) and would also match ANOTHER chain's watchdog.
    tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF "$watchdog_copy" || return 1
  fi
  return 0
}

ensure_watchdog() {
  local force=${1:-0}
  if have_systemd; then
    if [ "$force" -eq 1 ]; then
      write_svc_watch || return 1
    elif needs_rebuild "$svc_watch"; then
      ccdc_info "watchdog unit missing or edited; rebuilding"
      write_svc_watch || return 1
      # The old unit may still be loaded in memory with the attacker's edit.
      ccdc_is_dry_run || run_systemctl stop "$unit_watch" >>"$log" 2>&1 || true
    fi
    reload_if_needed || return 1
    if ! ccdc_is_dry_run \
      && ! unit_effective_matches "$unit_watch" "$svc_watch" "$watchdog_copy"; then
      ccdc_warn "effective systemd watchdog unit differs from the installed unit"
      return 1
    fi
    if ccdc_is_dry_run; then
      run_systemctl is-active --quiet "$unit_watch" 2>/dev/null \
        || printf '[dry-run] would start %s-watch.service\n' "$name"
      return 0
    fi
    if ! run_systemctl is-active --quiet "$unit_watch" 2>/dev/null; then
      glog "watchdog_down restarting unit=$unit_watch"
      run_systemctl enable --now "$unit_watch" >>"$log" 2>&1 \
        || { ccdc_warn "could not start $unit_watch"; return 1; }
    elif ! run_systemctl is-enabled --quiet "$unit_watch" 2>/dev/null; then
      # Active but not enabled survives until the next reboot and no longer.
      run_systemctl enable "$unit_watch" >>"$log" 2>&1 \
        || { ccdc_warn "could not enable $unit_watch"; return 1; }
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
  setsid /bin/bash "$watchdog_copy" --config "$env_copy" --apply --interval "$watchdog_interval" \
    </dev/null >>"$state_dir/watchdog.err" 2>&1 &
  local watchdog_pid=$!
  kill -0 "$watchdog_pid" 2>/dev/null \
    || { ccdc_warn "detached watchdog failed to start"; return 1; }
  printf '%s\n' "$watchdog_pid" >"$pid_file" \
    || { kill "$watchdog_pid" 2>/dev/null || true; ccdc_warn "cannot record watchdog pid"; return 1; }
}

reload_if_needed() {
  [ "$need_daemon_reload" -eq 1 ] || return 0
  have_systemd || return 0
  if ccdc_is_dry_run; then
    printf '[dry-run] would run systemctl daemon-reload\n'
    need_daemon_reload=0
    return 0
  fi
  run_systemctl daemon-reload >>"$log" 2>&1 \
    || { ccdc_warn "systemctl daemon-reload failed"; return 1; }
  need_daemon_reload=0
}

ensure_unit_enabled() {
  local unit=$1
  ccdc_is_dry_run && { printf '[dry-run] would ensure %s is enabled and running\n' "$unit"; return 0; }
  if ! run_systemctl is-active --quiet "$unit" 2>/dev/null; then
    glog "layer_down restarting unit=$unit"
    run_systemctl enable --now "$unit" >>"$log" 2>&1 \
      || { ccdc_warn "could not start $unit"; return 1; }
  elif ! run_systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    run_systemctl enable "$unit" >>"$log" 2>&1 \
      || { ccdc_warn "could not enable $unit"; return 1; }
  fi
}

ensure_layers() {
  local force=${1:-0}
  local built=0

  if have_systemd; then
    # Spelled out rather than `[ force ] || [ ! -f x ] && write`: that chain
    # parses as (A || B) && C, which is right by accident and unreadable on
    # hour six.
    if [ "$force" -eq 1 ] || needs_rebuild "$tick_script"; then write_tick_script || return 1; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$svc_ticker"; then write_svc_ticker || return 1; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$svc_reconcile"; then write_svc_reconcile || return 1; fi
    if [ "$force" -eq 1 ] || needs_rebuild "$tmr_reconcile"; then write_tmr_reconcile || return 1; fi
    reload_if_needed || return 1
    if ! ccdc_is_dry_run; then
      unit_effective_matches "$unit_ticker" "$svc_ticker" "$tick_script" \
        || { ccdc_warn "effective ticker unit differs from the installed unit"; return 1; }
      unit_effective_matches "$unit_reconcile" "$svc_reconcile" "$guardian_copy" \
        || { ccdc_warn "effective reconcile unit differs from the installed unit"; return 1; }
      unit_effective_matches "$unit_timer" "$tmr_reconcile" \
        || { ccdc_warn "effective reconcile timer differs from the installed unit"; return 1; }
    fi
    ensure_unit_enabled "$unit_ticker" || return 1
    ensure_unit_enabled "$unit_timer" || return 1
    built=$((built + 2))
  else
    ccdc_warn "no systemd on this box: layers 1 and 2 are unavailable, cron is the only layer"
  fi

  if have_crond; then
    if [ "$force" -eq 1 ] || needs_rebuild "$cron_file"; then
      write_cron || return 1
    fi
    built=$((built + 1))
  else
    # Alpine and other busybox/OpenRC systems have no /etc/cron.d: busybox crond
    # reads whole crontabs out of /etc/crontabs instead, and OpenRC has no
    # equivalent of a systemd timer. Neither is wired up here. On such a box,
    # install nothing and run watchdog.sh under your init supervisor by hand.
    ccdc_warn "no /etc/cron.d on this box (Alpine/OpenRC?): layer 3 unavailable and not emulated"
  fi

  if [ "$built" -eq 0 ]; then
    ccdc_warn "no scheduling layer could be built; the watchdog is NOT being kept alive"
    return 1
  fi
  return 0
}

# --- disarm ------------------------------------------------------------------

remove_artifact() {
  local path=$1
  [ -n "$path" ] || return 0
  [ -e "$path" ] || [ -L "$path" ] || return 0
  ccdc_action rm -f "$path"
}

remove_exact_tree() {
  local path=$1
  [ -e "$path" ] || [ -L "$path" ] || return 0
  if ccdc_is_dry_run; then
    printf '[dry-run] would remove exact guardian-owned tree %s\n' "$path"
  elif [ -d "$path" ] && [ ! -L "$path" ]; then
    find "$path" -depth -delete 2>/dev/null \
      || { ccdc_warn "could not completely remove $path"; return 1; }
  else
    rm -f -- "$path" || { ccdc_warn "could not remove $path"; return 1; }
  fi
}

remove_staging_for() {
  local path=$1 parent base
  parent=$(dirname -- "$path")
  base=$(basename -- "$path")
  [ -d "$parent" ] || return 0
  if ccdc_is_dry_run; then
    find "$parent" -maxdepth 1 -type f -name "${base}.new.[0-9]*" -print 2>/dev/null \
      | sed 's/^/[dry-run] would remove stale staging file /'
  else
    find "$parent" -maxdepth 1 -type f -name "${base}.new.[0-9]*" -delete 2>/dev/null || true
  fi
}

stop_units() {
  have_systemd || return 0
  local unit
  for unit in "$unit_ticker" "$unit_timer" "$unit_reconcile" "$unit_watch"; do
    if ccdc_is_dry_run; then
      printf '[dry-run] would disable and stop %s\n' "$unit"
    else
      run_systemctl disable --now "$unit" >>"$log" 2>&1 || true
    fi
  done
}

# Once a unit has entered a failed state, systemd keeps it in its own list even
# after the unit file is deleted and the daemon is reloaded: it shows in
# `systemctl list-units --all` and `systemctl --failed` as "not-found failed",
# indefinitely. That is a phantom of your own tooling sitting in the exact place
# you look first during an incident, and it outlives an uninstall that otherwise
# left zero artifacts on disk. Found by the drill's post-uninstall assertion.
reset_failed_units() {
  have_systemd || return 0
  local unit
  for unit in "$unit_ticker" "$unit_timer" "$unit_reconcile" "$unit_watch"; do
    if ccdc_is_dry_run; then
      printf '[dry-run] would clear any failed state for %s\n' "$unit"
    else
      run_systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    fi
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
$(removal_artifacts)
EOF

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    remove_exact_tree "$path" || true
  done <<EOF
$(unit_override_paths)
EOF

  while IFS='|' read -r kind path; do
    [ -n "$path" ] || continue
    remove_staging_for "$path"
  done <<EOF
$(removal_artifacts)
EOF
  if ccdc_is_dry_run; then
    [ -f "${manifest}.next.$$" ] && printf '[dry-run] would remove %s\n' "${manifest}.next.$$"
  else
    find "$state_dir" -maxdepth 1 -type f -name 'guardian.manifest.next.[0-9]*' -delete 2>/dev/null || true
  fi

  # A detached watchdog can remain after the host changes init systems or after
  # a partial install, so do not condition cleanup on current capabilities.
  local pid
  pid=$(cat "$pid_file" 2>/dev/null || printf '')
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    if [ -r "/proc/$pid/cmdline" ] \
      && tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -F "$watchdog_copy" >/dev/null; then
      ccdc_action kill "$pid"
    else
      ccdc_warn "refusing to kill reused/unrecognized pid $pid from $pid_file"
    fi
  fi
  remove_artifact "$pid_file"

  # rmdir, never rm -rf: if anything unexpected is in there, leaving it for the
  # operator to look at beats deleting a directory tree by name.
  if [ -d "$guardian_dir" ]; then
    ccdc_action rmdir "$repair_dir/lib"
    ccdc_action rmdir "$repair_dir"
    ccdc_action rmdir "$guardian_dir/lib"
    ccdc_action rmdir "$guardian_dir"
  fi

  need_daemon_reload=1
  reload_if_needed
  # After the reload, so systemd has already dropped the unit files; this clears
  # what the reload cannot.
  reset_failed_units
}

new_install_has_collision() {
  local kind path
  if [ -e "$guardian_dir" ] || [ -L "$guardian_dir" ]; then
    ccdc_warn "guardian install directory already exists without this manifest: $guardian_dir"
    return 0
  fi
  while IFS='|' read -r kind path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ] || [ -L "$path" ]; then
      ccdc_warn "guardian install target already exists without this manifest: $path"
      return 0
    fi
  done <<EOF
$(removal_artifacts)
EOF
  new_install_has_override
}

manifest_matches_disk() {
  local kind path expected actual
  [ -f "$manifest" ] || return 1
  while IFS='|' read -r kind path; do
    [ -n "$path" ] || continue
    expected=$(recorded_hash "$path")
    [ -n "$expected" ] && [ "$expected" != absent ] || return 1
    [ -f "$path" ] || return 1
    actual=$(file_hash "$path")
    [ -n "$actual" ] && [ "$actual" = "$expected" ] || return 1
  done <<EOF
$(expected_artifacts)
EOF
  return 0
}

verify_installation() {
  local schedulers=0
  manifest_matches_disk || { ccdc_warn "one or more installed artifacts do not match the manifest"; return 1; }
  if have_systemd; then
    unit_effective_matches "$unit_watch" "$svc_watch" "$watchdog_copy" || return 1
    unit_effective_matches "$unit_ticker" "$svc_ticker" "$tick_script" || return 1
    unit_effective_matches "$unit_reconcile" "$svc_reconcile" "$guardian_copy" || return 1
    unit_effective_matches "$unit_timer" "$tmr_reconcile" || return 1
    run_systemctl is-active --quiet "$unit_watch" 2>/dev/null || return 1
    run_systemctl is-enabled --quiet "$unit_watch" 2>/dev/null || return 1
    run_systemctl is-active --quiet "$unit_ticker" 2>/dev/null || return 1
    run_systemctl is-enabled --quiet "$unit_ticker" 2>/dev/null || return 1
    run_systemctl is-active --quiet "$unit_timer" 2>/dev/null || return 1
    run_systemctl is-enabled --quiet "$unit_timer" 2>/dev/null || return 1
    schedulers=$((schedulers + 2))
  else
    watchdog_running_pidfile || return 1
  fi
  if have_crond; then
    [ -f "$cron_file" ] || return 1
    schedulers=$((schedulers + 1))
  fi
  [ "$schedulers" -gt 0 ]
}

removal_is_clean() {
  local kind path
  while IFS='|' read -r kind path; do
    [ -n "$path" ] || continue
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  done <<EOF
$(removal_artifacts)
EOF
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  done <<EOF
$(unit_override_paths)
EOF
  [ ! -d "$guardian_dir" ]
}

# --- modes -------------------------------------------------------------------

do_install() {
  local fresh=0
  [ "$apply" -eq 1 ] && ccdc_require_root
  [ -n "$config" ] || ccdc_die "--install needs --config FILE: the layers run unattended and cannot guess it"
  [ -f "$SCRIPT_DIR/watchdog.sh" ] || ccdc_die "watchdog.sh not found next to guardian.sh"
  { have_systemd || have_crond; } \
    || ccdc_die "no verified systemd or cron scheduler is running; nothing was installed"
  if [ ! -f "$manifest" ]; then
    fresh=1
    new_install_has_collision \
      && ccdc_die "refusing to overwrite an unowned guardian target; choose another CCDC_GUARDIAN_NAME/DIR"
  fi
  acquire_lock $((interval * 2)) \
    || ccdc_die "could not obtain the guardian lock; no install changes were made"

  if [ "$fresh" -eq 0 ]; then
    ensure_no_unit_overrides || ccdc_die "could not quarantine a systemd override; install aborted"
  fi

  # A leftover sentinel from a previous uninstall would make every layer remove
  # itself on its first tick.
  if [ -f "$sentinel" ]; then
    ccdc_action rm -f "$sentinel"
    ccdc_info "cleared the disarm sentinel from a previous uninstall"
  fi

  if ! write_payload 1 \
    || ! ensure_watchdog 1 \
    || ! ensure_layers 1 \
    || ! restart_repaired_units 1 \
    || ! record_manifest; then
    if [ "$fresh" -eq 1 ]; then
      ccdc_warn "fresh install failed; removing its partial artifacts"
      remove_all || true
    fi
    ccdc_die "guardian install failed; existing installations were left for inspection"
  fi

  if ! ccdc_is_dry_run && ! verify_installation; then
    if [ "$fresh" -eq 1 ]; then
      ccdc_warn "fresh install verification failed; removing its partial artifacts"
      remove_all || true
    fi
    ccdc_die "guardian did not become fully operational; not claiming it is armed"
  fi

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

  ensure_no_unit_overrides \
    || { glog "reconcile_failed phase=systemd_overrides"; return 1; }
  [ ! -f "$sentinel" ] || { remove_all; return 0; }
  write_payload 0 \
    || { glog "reconcile_failed phase=payload"; return 1; }
  [ ! -f "$sentinel" ] || { remove_all; return 0; }
  ensure_watchdog 0 \
    || { glog "reconcile_failed phase=watchdog"; return 1; }
  [ ! -f "$sentinel" ] || { remove_all; return 0; }
  ensure_layers 0 \
    || { glog "reconcile_failed phase=layers"; return 1; }
  record_manifest \
    || { glog "reconcile_failed phase=manifest"; return 1; }
  restart_repaired_units 0 \
    || { glog "reconcile_failed phase=effective_restart"; return 1; }
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
    if run_systemctl is-active --quiet "$unit" 2>/dev/null; then
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
  printf 'interval: %ss reconcile / %ss watchdog\n' "$interval" "$watchdog_interval"
  printf 'statedir: %s\n' "$state_dir"
  printf 'manifest: %s\n' "$manifest"
  if [ -f "$sentinel" ]; then
    printf 'state:    DISARMED (sentinel present: %s)\n' "$sentinel"
  elif verify_installation 2>/dev/null; then
    printf 'state:    armed (verified)\n'
  else
    printf 'state:    DEGRADED (one or more artifacts/layers failed verification)\n'
  fi
  printf '\nlayers:\n'
  if have_systemd; then
    layer_line target "$svc_watch" "$unit_watch"
    layer_line layer1 "$svc_ticker" "$unit_ticker"
    layer_line layer2 "$tmr_reconcile" "$unit_timer"
  else
    printf '  target    n/a       no systemd: watchdog supervised by pidfile %s\n' "$pid_file"
    printf '  layer1    n/a       no systemd\n'
    printf '  layer2    n/a       no systemd\n'
  fi
  if have_crond; then
    layer_line layer3 "$cron_file"
  else
    printf '  layer3    n/a       no verified running cron daemon with /etc/cron.d support\n'
  fi

  printf '\nrepair sources:\n'
  layer_line repair "$repair_guardian"
  layer_line repair "$repair_watchdog"
  layer_line repair "$repair_common"
  layer_line repair "$repair_env"

  if have_systemd; then
    override_found=0
    while IFS= read -r override_path; do
      [ -n "$override_path" ] || continue
      if [ -e "$override_path" ] || [ -L "$override_path" ]; then
        [ "$override_found" -eq 1 ] || printf '\nSYSTEMD OVERRIDES (guardian is not healthy):\n'
        printf '  %s\n' "$override_path"
        override_found=1
      fi
    done <<EOF
$(unit_override_paths)
EOF
  fi

  printf '\nwatchdog: '
  if have_systemd; then
    if run_systemctl is-active --quiet "$unit_watch" 2>/dev/null; then
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
    || ccdc_die "could not obtain the guardian lock; uninstall made no changes"

  # Sentinel first, teardown second. A tick that fires in the middle of the
  # teardown must find the sentinel already there, or it will helpfully rebuild
  # everything you are in the middle of removing.
  if ccdc_is_dry_run; then
    printf '[dry-run] would write the disarm sentinel %s first, then remove every artifact\n' "$sentinel"
  else
    sentinel_staged="${sentinel}.new.$$"
    staged_paths="$staged_paths $sentinel_staged"
    printf 'guardian disarmed %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$sentinel_staged" \
      && chmod 0600 "$sentinel_staged" \
      && mv -f "$sentinel_staged" "$sentinel" \
      || ccdc_die "could not write disarm sentinel; uninstall made no changes"
    glog "uninstall_started sentinel=$sentinel"
  fi

  remove_all

  if ccdc_is_dry_run; then
    ccdc_info "dry run only; nothing removed"
    return 0
  fi

  if ! removal_is_clean; then
    ccdc_die "uninstall left one or more guardian artifacts; manifest retained for retry"
  fi
  rm -f "$manifest" || ccdc_die "artifacts are gone but manifest could not be removed: $manifest"
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
