#!/usr/bin/env bash
set -u

# watch.sh - the detection loop. Runs the cheap checks often and tells you only
# what CHANGED.
#
# The kit collects well and alerts not at all: canary.sh writes trips to a log
# nobody reads, and hunt.sh produces a 124K report you cannot re-read every few
# minutes. This closes that gap. Measured on the lab box: canary --check is
# instant and a full hunt is ~3s, and two back-to-back hunts on a quiet box
# differ by zero lines - so running them often is cheap and the diff is quiet.
# The binding constraint was never the machine, it was your attention.
#
#   ./watch.sh --config FILE                  loop, default 300s
#   ./watch.sh --config FILE --interval 120   loop faster
#   ./watch.sh --config FILE --once           one pass and exit
#
# DETECTION-ONLY. It never changes system configuration, but it does write and
# rotate evidence snapshots under CCDC_EVIDENCE_DIR.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
interval=300
once=0
keep=12
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --interval) interval=${2:?missing interval}; shift 2 ;;
    --once) once=1; shift ;;
    --keep) keep=${2:?missing count}; shift 2 ;;
    -h|--help)
      printf 'usage: %s --config FILE [--interval SECONDS] [--once] [--keep N]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
case "$interval" in ''|*[!0-9]*) ccdc_die "--interval must be a whole number of seconds" ;; esac
[ "$interval" -ge 30 ] || ccdc_die "--interval below 30s is churn, not vigilance: $interval"
ccdc_load_config "$config"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
if [ -e "$state_dir" ] && [ ! -w "$state_dir" ]; then
  ccdc_die "evidence dir not writable by $(id -un): $state_dir (sudo chown -R $(id -un) $state_dir)"
fi
watch_dir="$state_dir/watch"
mkdir -p "$watch_dir" || ccdc_die "cannot create $watch_dir"
log="$state_dir/watch.log"

# Files worth diffing, from BOTH sweeps. hunt.sh covers persistence; recon.sh
# covers accounts, keys, sudo and listeners -- and a new user is a primary
# red-team move that hunt alone cannot see. Running both was free: recon is
# ~0.15s against hunt's ~3s.
watch_files='hunt/persistence.txt
hunt/extra-persistence.txt
hunt/suid-capabilities.txt
hunt/web-files.txt
hunt/binary-integrity.txt
hunt/process-anomalies.txt
recon/accounts.txt
recon/ssh.txt
recon/sudoers.txt
recon/listening.txt
recon/firewall.txt'

# Three things change on their own every pass and will bury the one line that
# matters if they are not filtered out. Both were found by running this loop for
# real rather than by reading it:
#
#   1. Our own evidence. hunt.sh walks /tmp, /var/tmp and /dev/shm looking for
#      dropped payloads, and that is exactly where we write. The loop observes
#      itself and reports its own files as new every single pass.
#   2. systemd timer schedules. `systemctl list-timers` prints next/last elapsed
#      as relative times ("6s ago", "3min 27s"), so those lines differ every
#      time you look, whether or not anything happened.
#
# Filter both before diffing. Everything else is left alone, because a filter
# that hides too much is worse than noise: it makes the loop look calm while
# someone is working.
#   3. This loop's own processes. hunt.sh greps ps for anything running out of
#      /tmp, and the config lives in /tmp, so watch.sh and its children match
#      their own search every pass with fresh PIDs each time.
normalise() {
  # Matched by basename, not full path: ps shows whatever the operator typed,
  # usually the relative "./linux/watch.sh", so filtering the absolute path
  # misses it. The tradeoff is that an implant literally named hunt.sh would be
  # hidden from THIS view -- it would still show up in cron, units, SUID and
  # listeners, which is where it has to live to be persistence at all.
  grep -v -F -- "$state_dir" "$1" 2>/dev/null \
    | grep -vE '(sentry|watch|hunt|recon|canary)\.sh( |$)' \
    | grep -vE '^[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2}.*\.(timer|service)[[:space:]]*$' \
    | grep -vE '^[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2}.*(ago|left)[[:space:]]' \
    | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g'
}

stamp() { date -u '+%H:%M:%SZ'; }
alert() {
  printf '\n*** %s  %s\n' "$(stamp)" "$1"
  ccdc_append_log "$log" "ALERT $1"
}
quiet() { printf '%s  %s\n' "$(stamp)" "$1"; }

# Audit health is a STATE, not an event, and this loop reports changes.
#
# "auditd is not installed" is true on some boxes forever. Alerting on it every
# pass would put a permanent block of red in front of the one line that means
# something happened, and the operator would start skipping the section that
# also contains "the rules were just dropped from the kernel". So the finding
# text is fingerprinted, and only a DIFFERENT set of findings is an alert.
#
# Returns 0 when it alerted (the caller then prints the detail), 1 when this is
# the same condition as last pass and was deliberately kept quiet.
audit_state="$watch_dir/audit.state"
audit_report() {
  local headline=$1 body=$2 signature previous=''
  signature=$(printf '%s' "$body" | cksum | awk '{print $1":"$2}')
  [ -f "$audit_state" ] && read -r previous <"$audit_state" 2>/dev/null
  if [ "$signature" = "$previous" ]; then
    return 1
  fi
  printf '%s\n' "$signature" >"$audit_state" 2>/dev/null || true
  alert "$headline"
  return 0
}

# Pick up the newest previous pass from disk, not just from this process. Without
# this, every `--once` invocation would report "baseline captured" and never
# diff anything -- which is exactly how you would use it from cron or between
# other work.
prev_dir=$(ls -dt "$watch_dir"/pass-* 2>/dev/null | head -1 || true)

one_pass() {
  local changed=0 trips=0 failed=0 rc=0 f added removed this_dir prior_dir d canary_out
  local audit_rc=0 audit_out degraded=0

  # 1. canary first: it is instant and it is the highest-confidence signal on
  # the box. A moved decoy is not an anomaly to weigh, it is someone in.
  canary_out=$("$SCRIPT_DIR/canary.sh" --config "$config" --check 2>&1) || rc=$?
  if [ "${rc:-0}" -eq 3 ]; then
    trips=1
    alert "CANARY TRIPPED"
    printf '%s\n' "$canary_out" | grep -E 'TRIPPED|AUDIT|HINT' | sed 's/^/      /'
  elif [ "${rc:-0}" -ne 0 ]; then
    failed=1
    alert "canary.sh failed this pass (exit $rc)"
    printf '%s\n' "$canary_out" | tail -n 8 | sed 's/^/      /'
  fi

  # 1b. Can this box still prove what happened to it?
  #
  # Every check in this loop is downstream of the box still recording events. An
  # attacker who restarts auditd drops every runtime watch, and an attacker who
  # truncates the logs removes the record of everything before now - and both
  # leave a box that passes every other check in this file.
  #
  # Read-only here, deliberately: watch.sh never changes system configuration.
  # Repairing the rules is guardian's job, because guardian is the layer that is
  # allowed to restore our own tooling without asking. This one only tells you.
  if [ ! -x "$SCRIPT_DIR/audit.sh" ]; then
    # Worth saying out loud - a missing audit.sh means nothing is putting the
    # watches back - but not worth declaring the whole detector unhealthy over.
    # The distinction matters: exit 4 says "this loop cannot be trusted", and a
    # kit deployed without one optional tool is not that.
    audit_report "AUDIT check unavailable: $SCRIPT_DIR/audit.sh is missing" "missing" \
      && degraded=1
  else
    audit_out=$("$SCRIPT_DIR/audit.sh" --config "$config" --check 2>&1) || audit_rc=$?
    if [ "$audit_rc" -eq 3 ]; then
      if audit_report "AUDIT/LOGGING DEGRADED" "$(printf '%s\n' "$audit_out" | grep -E '^  AUDIT')"; then
        degraded=1
        printf '%s\n' "$audit_out" | grep -E 'AUDIT|SHRANK|REPLACED|NOT LOADED' | sed 's/^/      /'
      fi
    elif [ "$audit_rc" -ne 0 ]; then
      failed=1
      alert "audit.sh failed this pass (exit $audit_rc)"
      printf '%s\n' "$audit_out" | tail -n 8 | sed 's/^/      /'
    else
      # Recovery is a change too, and it is the one that tells you a repair
      # worked without going to look.
      if [ -s "$audit_state" ]; then
        alert "AUDIT/LOGGING RECOVERED - the previous finding is gone"
        : >"$audit_state"
      fi
    fi
  fi

  # 2. full sweep into its own directory, then diff against the last one.
  this_dir="$watch_dir/pass-$(ccdc_now)-$$"
  if ! "$SCRIPT_DIR/hunt.sh" --config "$config" --output-dir "$this_dir/hunt" >/dev/null 2>&1; then
    alert "hunt.sh failed this pass"
    rm -rf -- "$this_dir"
    return 4
  fi
  if ! "$SCRIPT_DIR/recon.sh" --config "$config" --output-dir "$this_dir/recon" >/dev/null 2>&1; then
    alert "recon.sh failed this pass"
    rm -rf -- "$this_dir"
    return 4
  fi

  prior_dir=$prev_dir
  if [ -n "$prev_dir" ] && [ -d "$prev_dir" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      [ -f "$this_dir/$f" ] && [ -f "$prev_dir/$f" ] || continue
      d=$(diff <(normalise "$prev_dir/$f") <(normalise "$this_dir/$f") 2>/dev/null | grep '^[<>]' || true)
      added=$(printf '%s' "$d" | grep -c '^>' || true)
      removed=$(printf '%s' "$d" | grep -c '^<' || true)
      [ -n "$added" ] || added=0
      [ -n "$removed" ] || removed=0
      if [ "$added" -gt 0 ] || [ "$removed" -gt 0 ]; then
        [ "$changed" -eq 0 ] && alert "BOX CHANGED since the last pass"
        changed=1
        printf '      --- %s  (+%s / -%s)\n' "$f" "$added" "$removed"
        printf '%s\n' "$d" | head -12 | sed 's/^/        /'
      fi
    done <<EOF
$watch_files
EOF
  else
    if [ "$failed" -eq 0 ]; then
      quiet "baseline captured ($(basename "$this_dir")) - changes reported from the next pass"
    else
      printf '%s  evidence baseline captured (%s); detector health is degraded\n' \
        "$(stamp)" "$(basename "$this_dir")"
    fi
  fi

  prev_dir="$this_dir"

  # Keep the last N passes so the directory cannot grow without bound over a
  # six-hour event, but keep enough to look backwards after an incident.
  ls -dt "$watch_dir"/pass-* 2>/dev/null | tail -n +$((keep + 1)) | while IFS= read -r old; do
    [ -n "$old" ] && rm -rf -- "$old"
  done

  if [ "$changed" -eq 0 ] && [ "$trips" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$degraded" -eq 0 ]; then
    quiet "quiet - no persistence/privilege changes, no canary trips, audit intact"
  else
    # Both of these get pasted, so both carry sudo and an absolute path. The
    # evidence directory is 0700 root; "./linux/diff-evidence.sh" only resolves
    # if you happen to be standing in the kit, and without sudo it cannot read
    # either directory it was handed.
    printf '\n    evidence: sudo ls -la %q\n' "$this_dir"
    [ -n "$prior_dir" ] && printf '    compare:  sudo %q/diff-evidence.sh %q %q\n' \
      "$SCRIPT_DIR" "$prior_dir" "$this_dir"
    printf '\n'
  fi
  [ "$failed" -eq 0 ] || return 4
  [ "$changed" -eq 0 ] && [ "$trips" -eq 0 ] && [ "$degraded" -eq 0 ] || return 3
  return 0
}

printf 'watch.sh: detection-only loop, every %ss. Ctrl-C to stop.\n' "$interval"
printf '  watching: canary trips + persistence/privilege changes + audit/log health\n'
printf '  NOT watching: whether the scorer can reach your service. Check that\n'
printf '  from OFF the box yourself - nothing here can see it.\n\n'

if [ "$once" -eq 1 ]; then
  one_pass
  exit $?
fi
while :; do
  one_pass || rc=$?
  sleep "$interval"
done
