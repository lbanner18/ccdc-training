#!/usr/bin/env bash
set -u

# atomic.sh - run Atomic Red Team's Linux atomics at this box and score what the
#             kit noticed.
#
# LAB ONLY. This EXECUTES adversary technique implementations as root. It will
# create backdoor accounts, write cron and systemd persistence, load kernel
# modules, and open sockets. Never point it at anything you are not willing to
# revert from a snapshot.
#
# What it is FOR, and what it is not:
#
# ART is the adversary here, not the denominator. There is no knowable total
# number of ways into a Linux box, so "we pass N of 434" is not a coverage
# figure and must never be read as one. What a maintained corpus is good for is
# naming mechanisms nobody on this side thought of - the exec_trigger_dirs list
# in baseline.sh grew by eight directories from exactly this exercise, including
# /etc/init.d, which ART targets thirteen times and which was simply absent.
#
# So the useful output is the MISSED column. A caught atomic tells you nothing
# you did not already believe. A missed one is a mechanism the kit cannot see,
# and it is worth more than the rest of the run put together.
#
#   ./atomic.sh --config F --corpus DIR --list
#   ./atomic.sh --config F --corpus DIR --list T1053.003
#   sudo ./atomic.sh --config F --corpus DIR --run 42 --apply
#   sudo ./atomic.sh --config F --corpus DIR --sweep persistence --apply
#   ./atomic.sh --config F --scorecard
#
# Each run is: snapshot the detectors' findings, execute the atomic, ask the
# detectors again, run the atomic's own cleanup, and record whether anything
# new appeared. Cleanup runs even when the atomic fails.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KIT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../linux" && pwd)
. "$KIT_DIR/lib/common.sh"

umask 077

config=''
corpus=''
mode='list'
target=''
sweep=''
apply=0
force=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)  config=${2:?missing config path}; shift 2 ;;
    --corpus)  corpus=${2:?missing corpus path}; shift 2 ;;
    --list)    mode='list'
               case "${2:-}" in ''|--*) shift ;; *) target=$2; shift 2 ;; esac ;;
    --run)     mode='run'; target=${2:?missing atomic number}; shift 2 ;;
    --sweep)   mode='sweep'; sweep=${2:?missing sweep name}; shift 2 ;;
    --scorecard) mode='scorecard'; shift ;;
    --apply)   apply=1; shift ;;
    --i-accept-this-box-is-disposable) force=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE --corpus DIR [--list [TECHNIQUE]|--run N|--sweep NAME|--scorecard] [--apply]\n' "$0"
      printf '\n'
      printf '  LAB ONLY - this executes adversary techniques as root.\n'
      printf '\n'
      printf '  --list [T]   the Linux atomics, numbered. With a technique ID, just that one\n'
      printf '  --run N      run atomic N, ask the detectors, then clean up\n'
      printf '  --sweep NAME persistence | evasion | accounts | all-safe\n'
      printf '  --scorecard  what has been caught and what got through\n'
      printf '  --apply      actually execute. Without it, nothing runs.\n'
      printf '\n'
      printf '  --i-accept-this-box-is-disposable   required, together with\n'
      printf '                CCDC_ATOMIC_LAB=1 set ON THE SUDO COMMAND LINE\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
atomic_dir="$state_dir/atomic"
ledger="$atomic_dir/ledger"
manifest="$atomic_dir/manifest"

printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/atomic.sh"

# --- the interlock ------------------------------------------------------------
#
# Two independent confirmations, because the failure mode here is not a wrong
# answer, it is a backdoor account on a box somebody is being scored on. A flag
# alone is one typo; an environment variable alone is one exported shell.
require_lab_box() {
  [ "${CCDC_ATOMIC_LAB:-0}" = 1 ] || ccdc_die "refusing to execute adversary techniques.

  This tool creates real backdoors. It runs only on a box that has said, twice,
  that it is disposable:

      sudo CCDC_ATOMIC_LAB=1 $qself --config $qconfig --corpus DIR \\
           --run N --apply --i-accept-this-box-is-disposable

  Set it on the sudo command line rather than exporting it. Ubuntu's sudoers
  has `Defaults env_reset`, so whether an exported variable reaches root
  depends on that host's sudoers; naming it on the command line does not.

  Take a snapshot first. Several atomics do not clean up completely even when
  their own cleanup succeeds."
  [ "$force" -eq 1 ] || ccdc_die "add --i-accept-this-box-is-disposable to confirm this is a lab box.
  CCDC_ATOMIC_LAB is set, which is one of the two confirmations needed."
  ccdc_require_root
}

# Techniques that destroy the box rather than persist on it. Running these
# teaches nothing about detection and ends the session.
DENY='T1485 T1486 T1490 T1491 T1495 T1529 T1561 T1565 T1499 T1499.001 T1499.002
      T1489 T1531 T1070.004'

# --- reading the corpus -------------------------------------------------------
#
# Emits one line per Linux atomic: N|technique|name|elevation|command|cleanup
# with newlines escaped, so the rest of this is ordinary shell.
build_manifest() {
  [ -n "$corpus" ] || ccdc_die "--corpus is required: the path to atomic-red-team/atomics"
  [ -d "$corpus" ] || ccdc_die "no such corpus directory: $corpus"
  mkdir -p "$atomic_dir" 2>/dev/null; chmod 700 "$atomic_dir" 2>/dev/null
  python3 - "$corpus" "$DENY" >"$manifest" <<'PY'
import glob, os, sys, json
try:
    import yaml
except ImportError:
    sys.stderr.write("atomic.sh needs python3 pyyaml: apt-get install python3-yaml\n")
    sys.exit(1)

corpus, deny = sys.argv[1], set(sys.argv[2].split())

def esc(s):
    return (s or '').replace('\\', '\\\\').replace('\n', '\\n').replace('|', '\\x7c')

def fill(cmd, args):
    # Atomics carry #{name} placeholders with defaults. Substituting the
    # defaults is what the official runner does; an unsubstituted atomic just
    # fails in a way that looks like a detection miss, which is the one wrong
    # answer this harness must not produce.
    for k, v in (args or {}).items():
        d = v.get('default')
        if d is None:
            continue
        cmd = cmd.replace('#{%s}' % k, str(d))
    return cmd

n = 0
for f in sorted(glob.glob(os.path.join(corpus, 'T*', 'T*.yaml'))):
    try:
        doc = yaml.safe_load(open(f, encoding='utf-8', errors='replace'))
    except Exception:
        continue
    if not doc:
        continue
    tech = doc.get('attack_technique', os.path.basename(os.path.dirname(f)))
    for t in doc.get('atomic_tests', []) or []:
        if 'linux' not in (t.get('supported_platforms') or []):
            continue
        ex = t.get('executor') or {}
        if ex.get('name') == 'manual':
            continue
        cmd = ex.get('command')
        if not cmd:
            continue
        args = t.get('input_arguments')
        n += 1
        blocked = 'DESTRUCTIVE' if tech in deny else ''
        print('%d|%s|%s|%s|%s|%s|%s' % (
            n, tech, esc(t.get('name', '')),
            'root' if ex.get('elevation_required') else 'user',
            blocked,
            esc(fill(cmd, args)),
            esc(fill(ex.get('cleanup_command') or '', args))))
PY
  [ -s "$manifest" ] || ccdc_die "no Linux atomics found under $corpus"
  chmod 600 "$manifest"
}

unesc() { printf '%s' "$1" | sed 's/\\x7c/|/g; s/\\n/\n/g; s/\\\\/\\/g'; }

# --- what do the detectors say right now? -------------------------------------
#
# Two of them, because they answer different questions and an atomic that only
# one sees is exactly the result worth writing down. baseline.sh reports what
# nothing explains; triage.sh reports what is wrong regardless of when it
# started.
# Did the atomic change anything at all?
#
# Some atomics are no-ops on a given box. T1098.004 "Modify SSH Authorized Keys"
# reads authorized_keys and writes the identical bytes back; nothing changes, so
# nothing can be detected, and scoring that as MISSED sends you hunting a gap
# that does not exist. A false miss is worse than a false catch here - it is the
# one result that costs you hours.
#
# Deliberately independent of the kit: if this used the kit's own enumeration it
# would agree with the kit by construction, which is the opposite of what a test
# harness is for.
state_fingerprint() {
  {
    cat /etc/passwd /etc/group /etc/sudoers 2>/dev/null
    cat /etc/sudoers.d/* 2>/dev/null
    find /etc /root /home /usr/local /var/spool/cron /srv /opt -xdev \
         \( -type f -o -type l \) -printf '%p %T@ %s %m\n' 2>/dev/null | sort
    systemctl list-units --all --no-legend --plain 2>/dev/null | awk '{print $1, $3, $4}'
    systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1, $2}'
    ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort
    lsmod 2>/dev/null | awk '{print $1}' | sort
  } 2>/dev/null | sha256sum | awk '{print $1}'
}

detector_state() {
  local b t
  b=$("$KIT_DIR/baseline.sh" --config "$config" --status 2>/dev/null \
      | grep -cE '^  \[[0-9]+\]' ) || b=0
  t=$("$KIT_DIR/triage.sh" --config "$config" 2>/dev/null \
      | grep -cE 'CARD [0-9]+\]' ) || t=0
  printf '%s %s' "${b:-0}" "${t:-0}"
}

# --- sweeps -------------------------------------------------------------------
#
# Named sets, chosen to match what this kit CLAIMS to do. A sweep that wanders
# into credential dumping measures nothing about a tool that never claimed to
# watch for it, and a scorecard full of misses nobody intended to cover is a
# scorecard that gets ignored.
sweep_techniques() {
  case "$1" in
    persistence) printf '%s' '
      T1053.003 T1053.006 T1543.002 T1546.004 T1546.005 T1547.006 T1547.013
      T1037.004 T1098.004 T1136.001 T1574.006' ;;
    evasion)     printf '%s' '
      T1070.003 T1070.006 T1222.002 T1564.001 T1027.001 T1036.003 T1014' ;;
    accounts)    printf '%s' '
      T1136.001 T1098.004 T1548.003 T1078.003 T1552.003 T1552.004' ;;
    all-safe)    printf '%s' 'ALL' ;;
    *) return 1 ;;
  esac
}

print_list() {
  local n tech name elev blocked cmd shown=0
  printf '\nAtomic Red Team - Linux atomics in %s\n\n' "$corpus"
  while IFS='|' read -r n tech name elev blocked cmd _cleanup; do
    [ -n "${n:-}" ] || continue
    if [ -n "$target" ]; then
      case "$tech" in "$target"|"$target".*) ;; *) continue ;; esac
    fi
    shown=$((shown + 1))
    if [ -n "$blocked" ]; then
      printf '  [%-3s] %-12s %-5s %s\n' "$n" "$tech" "SKIP" "$(unesc "$name")"
      printf '        refused: this technique destroys the box rather than persisting on it\n'
    else
      printf '  [%-3s] %-12s %-5s %s\n' "$n" "$tech" "$elev" "$(unesc "$name")"
    fi
  done <"$manifest"
  printf '\n  %s atomic(s).\n' "$shown"
  printf '\n  run one:    sudo -E %s --config %s --corpus %s --run N --apply \\\n' \
    "$qself" "$qconfig" "$corpus"
  printf '                   --i-accept-this-box-is-disposable\n'
  printf '  a whole set: --sweep persistence | evasion | accounts | all-safe\n\n'
}

# --- running one --------------------------------------------------------------
run_one() {
  local want=$1 line n tech name elev blocked cmd cleanup
  local before after b0 t0 b1 t1 verdict

  line=$(awk -F'|' -v w="$want" '$1 == w {print; exit}' "$manifest")
  [ -n "$line" ] || { ccdc_warn "no atomic $want in the manifest"; return 1; }
  IFS='|' read -r n tech name elev blocked cmd cleanup <<EOF
$line
EOF
  if [ -n "$blocked" ]; then
    printf '  [%s] %s  SKIPPED - destroys the box rather than persisting on it\n' "$n" "$tech"
    return 0
  fi

  printf '\n  [%s] %s  %s\n' "$n" "$tech" "$(unesc "$name")"

  local fp0 fp1
  fp0=$(state_fingerprint)
  before=$(detector_state); b0=${before%% *}; t0=${before##* }
  printf '      before: baseline %s finding(s), triage %s\n' "$b0" "$t0"

  # The atomic itself. It is allowed to fail - a technique that does not work on
  # this image is not a detection result, and recording it as one would be the
  # harness lying in the direction that flatters the kit.
  if ! unesc "$cmd" | bash >"$atomic_dir/last.out" 2>&1; then
    printf '      the atomic did not run cleanly on this box:\n'
    sed 's/^/        /' "$atomic_dir/last.out" | head -4
    verdict='ERROR'
  else
    sleep 2
    fp1=$(state_fingerprint)
    after=$(detector_state); b1=${after%% *}; t1=${after##* }
    printf '      after:  baseline %s finding(s), triage %s\n' "$b1" "$t1"
    if [ "$fp0" = "$fp1" ] && [ "$b1" -le "$b0" ] && [ "$t1" -le "$t0" ]; then
      verdict='NOOP'
      printf '      NO-OP - this atomic changed nothing on this box, so there was\n'
      printf '      nothing to detect. Not a miss.\n'
    elif [ "$b1" -gt "$b0" ] || [ "$t1" -gt "$t0" ]; then
      verdict='CAUGHT'
      printf '      CAUGHT'
      [ "$b1" -gt "$b0" ] && printf ' by baseline'
      [ "$t1" -gt "$t0" ] && printf ' by triage'
      printf '\n'
    else
      verdict='MISSED'
      printf '      MISSED - nothing in the kit noticed this\n'
    fi
  fi

  # Cleanup always, including after a failure: a half-applied atomic left on the
  # box makes every later result in the sweep meaningless.
  if [ -n "$cleanup" ]; then
    unesc "$cleanup" | bash >/dev/null 2>&1 || \
      ccdc_warn "cleanup for $tech did not run cleanly - check the box by hand"
  fi

  mkdir -p "$atomic_dir" 2>/dev/null
  printf '%s|%s|%s|%s|%s\n' "$(ccdc_now)" "$n" "$tech" "$verdict" "$(unesc "$name")" \
    >>"$ledger"
  chmod 600 "$ledger" 2>/dev/null
  [ "$verdict" != 'MISSED' ]
}

run_sweep() {
  local set techs n tech blocked line want
  techs=$(sweep_techniques "$sweep") \
    || ccdc_die "unknown sweep: $sweep (persistence, evasion, accounts, all-safe)"
  while IFS='|' read -r n tech _name _elev blocked _cmd _cleanup; do
    [ -n "${n:-}" ] || continue
    [ -n "$blocked" ] && continue
    if [ "$techs" != 'ALL' ]; then
      ccdc_list_contains "$tech" "$techs" || continue
    fi
    run_one "$n" || true
  done <"$manifest"
  printf '\n'
  print_scorecard
}

print_scorecard() {
  local total caught missed err noop
  [ -s "$ledger" ] || { printf '  Nothing has been run yet.\n'; return 0; }
  total=$(grep -c . "$ledger")
  caught=$(grep -c '|CAUGHT|' "$ledger" || true)
  missed=$(grep -c '|MISSED|' "$ledger" || true)
  err=$(grep -c '|ERROR|' "$ledger" || true)
  noop=$(grep -c '|NOOP|' "$ledger" || true)
  printf '  ATOMIC SCORECARD\n\n'
  printf '    %s run: %s caught, %s MISSED, %s did not execute here,\n' \
    "$total" "$caught" "$missed" "$err"
  printf '    %s changed nothing on this box\n\n' "$noop"
  if [ "$missed" -gt 0 ]; then
    printf '  These got through. Each one is a mechanism the kit cannot see,\n'
    printf '  and is worth more than the rest of this run put together:\n\n'
    awk -F'|' '$4 == "MISSED" {printf "    %-12s %s\n", $3, $5}' "$ledger" \
      | sort -u
    printf '\n'
  fi
  printf '  This is NOT a coverage percentage. There is no knowable total number\n'
  printf '  of ways into a Linux box, so the denominator here is "what this\n'
  printf '  corpus happens to contain", which is not the same question.\n\n'
}

# --- main ---------------------------------------------------------------------
case "$mode" in
  scorecard) print_scorecard ;;
  list)      build_manifest; print_list ;;
  run|sweep)
    build_manifest
    if [ "$apply" -eq 0 ]; then
      printf '\nDry run: nothing will be executed. Add --apply to mean it.\n'
      [ "$mode" = 'run' ] && target=$target
      print_list
      exit 0
    fi
    require_lab_box
    printf '\n  Running against %s. Revert from a snapshot when you are done.\n' "$(hostname)"
    if [ "$mode" = 'run' ]; then run_one "$target"; else run_sweep; fi ;;
esac
