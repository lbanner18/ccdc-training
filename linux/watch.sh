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
# READ-ONLY. It never mutates anything, so it is safe to leave running and safe
# to start when you are already panicking.

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
recon/listening.txt'

# Two things change on their own every pass and will bury the one line that
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
    | grep -vE '(watch|hunt|recon|canary)\.sh( |$)' \
    | grep -vE '^[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2}.*\.(timer|service)[[:space:]]*$' \
    | grep -vE '^[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2}.*(ago|left)[[:space:]]'
}

stamp() { date -u '+%H:%M:%SZ'; }
alert() {
  printf '\n*** %s  %s\n' "$(stamp)" "$1"
  ccdc_append_log "$log" "ALERT $1"
}
quiet() { printf '%s  %s\n' "$(stamp)" "$1"; }

# Pick up the newest previous pass from disk, not just from this process. Without
# this, every `--once` invocation would report "baseline captured" and never
# diff anything -- which is exactly how you would use it from cron or between
# other work.
prev_dir=$(ls -dt "$watch_dir"/pass-* 2>/dev/null | head -1 || true)

one_pass() {
  local changed=0 trips=0 rc=0 f added removed this_dir

  # 1. canary first: it is instant and it is the highest-confidence signal on
  # the box. A moved decoy is not an anomaly to weigh, it is someone in.
  canary_out=$("$SCRIPT_DIR/canary.sh" --config "$config" --check 2>&1) || rc=$?
  if [ "${rc:-0}" -eq 3 ]; then
    trips=1
    alert "CANARY TRIPPED"
    printf '%s\n' "$canary_out" | grep -E 'TRIPPED|AUDIT|HINT' | sed 's/^/      /'
  fi

  # 2. full sweep into its own directory, then diff against the last one.
  this_dir="$watch_dir/pass-$(ccdc_now)-$$"
  if ! "$SCRIPT_DIR/hunt.sh" --config "$config" --output-dir "$this_dir/hunt" >/dev/null 2>&1; then
    alert "hunt.sh failed this pass"
    return 0
  fi
  if ! "$SCRIPT_DIR/recon.sh" --config "$config" --output-dir "$this_dir/recon" >/dev/null 2>&1; then
    alert "recon.sh failed this pass"
    return 0
  fi

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
    quiet "baseline captured ($(basename "$this_dir")) - changes reported from the next pass"
  fi

  prev_dir="$this_dir"

  # Keep the last N passes so the directory cannot grow without bound over a
  # six-hour event, but keep enough to look backwards after an incident.
  ls -dt "$watch_dir"/pass-* 2>/dev/null | tail -n +$((keep + 1)) | while IFS= read -r old; do
    [ -n "$old" ] && rm -rf -- "$old"
  done

  if [ "$changed" -eq 0 ] && [ "$trips" -eq 0 ]; then
    quiet "quiet - no persistence/privilege changes, no canary trips"
  else
    printf '\n    evidence: %s\n' "$this_dir"
    [ -n "$prev_dir" ] && printf '    compare:  ./linux/diff-evidence.sh <prev> %s\n' "$this_dir"
    printf '\n'
  fi
}

printf 'watch.sh: read-only detection loop, every %ss. Ctrl-C to stop.\n' "$interval"
printf '  watching: canary trips + persistence/privilege changes\n'
printf '  NOT watching: whether the scorer can reach your service. Check that\n'
printf '  from OFF the box yourself - nothing here can see it.\n\n'

if [ "$once" -eq 1 ]; then
  one_pass
  exit 0
fi
while :; do
  one_pass
  sleep "$interval"
done
