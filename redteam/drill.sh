#!/usr/bin/env bash
#
# Automated regression run of playbooks/simulation-runbook.md: arm the defenses,
# let redteam/plant.sh land, detect, eradicate, then put guardian.sh through six
# attacks and prove --uninstall is exact. Prints PASS/FAIL per assertion.
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
SCORE_URL=${CCDC_DRILL_SCORE_URL:-http://127.0.0.1:8080/}
SCORED_UNIT=${CCDC_DRILL_SERVICE:-scored-web}
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$
DRILL_TMP=$(mktemp -d /tmp/ccdc-drill.XXXXXX) || exit 1
monitor_pid=''

cleanup_drill() {
  [ -z "$monitor_pid" ] || kill "$monitor_pid" >/dev/null 2>&1 || true
  [ -z "$monitor_pid" ] || wait "$monitor_pid" 2>/dev/null || true
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
./linux/guardian.sh --config "$CFG" --install --apply >"$DRILL_TMP/ginstall.out" 2>&1
sed 's/^/      /' "$DRILL_TMP/ginstall.out" | head -20

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

printf '\n  -- ATTACK 6: remove ALL THREE layers inside one interval --\n'
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
