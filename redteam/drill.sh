#!/usr/bin/env bash
#
# Automated regression run of playbooks/simulation-runbook.md: arm the defenses,
# let redteam/plant.sh land, detect, eradicate, then put guardian.sh through five
# attacks and prove --uninstall is exact. Prints PASS/FAIL per assertion.
#
# LAB VM ONLY, as root. It plants real footholds and installs real persistence.
# Snapshot first; revert after.
#
#   sudo bash drill.sh          (expects the kit at $KIT and a filled config at $CFG)
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
[ "$(id -u)" -eq 0 ] || { printf 'run as root on a disposable lab VM\n' >&2; exit 1; }
[ -r "$CFG" ] || { printf 'drill config is not readable: %s\n' "$CFG" >&2; exit 1; }

EV=$(/bin/bash -c '. "$1"; printf "%s" "${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}"' ccdc-drill "$CFG")
GUARD_NAME=$(/bin/bash -c '. "$1"; printf "%s" "${CCDC_GUARDIAN_NAME:-node-health}"' ccdc-drill "$CFG")
GUARD_DIR=$(/bin/bash -c '. "$1"; n=${CCDC_GUARDIAN_NAME:-node-health}; printf "%s" "${CCDC_GUARDIAN_DIR:-/usr/local/lib/$n}"' ccdc-drill "$CFG")
INT=$(/bin/bash -c '. "$1"; printf "%s" "${CCDC_GUARDIAN_INTERVAL:-60}"' ccdc-drill "$CFG")
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

tampered_count() { find "$EV/guardian.tampered" -type f 2>/dev/null | wc -l; }

for u in "$GUARD_NAME-watch.service" "$GUARD_NAME.service" "$GUARD_NAME-reconcile.timer"; do
  systemctl is-active --quiet "$u" && ok "unit active: $u" || no "unit NOT active: $u"
done
[ -f "/etc/cron.d/$GUARD_NAME" ] && ok "layer 3 cron entry installed" || no "layer 3 cron entry missing"
mcount=$(wc -l < "$EV/guardian.manifest" 2>/dev/null || echo 0)
[ "$mcount" -ge 9 ] && ok "manifest records $mcount artifacts" || no "manifest only has $mcount lines"
# Every path the manifest claims must actually exist. A manifest that lists an
# artifact which is not on disk is the failure mode that would let an operator
# believe a foothold was theirs and removable when it is neither.
missing_manifest=0
while IFS='|' read -r _kind mpath _hash; do
  [ -n "${mpath:-}" ] || continue
  [ -e "$mpath" ] || { missing_manifest=$((missing_manifest + 1)); note "manifest lists a missing path: $mpath"; }
done < "$EV/guardian.manifest"
[ "$missing_manifest" -eq 0 ] && ok "every manifest entry exists on disk" \
  || no "$missing_manifest manifest entries do not exist"

printf '\n  -- ATTACK 1: kill the watchdog process --\n'
pkill -f 'watchdog.sh' ; wait_s 15
systemctl is-active --quiet "$GUARD_NAME-watch.service" \
  && ok "watchdog came back (Restart=always)" || no "watchdog stayed dead"
pgrep -f watchdog.sh >/dev/null && ok "watchdog process is running again" || no "no watchdog process"

printf '\n  -- ATTACK 2: stop the scored service --\n'
systemctl stop "$SCORED_UNIT"; scored_up && no "service did not actually stop" || note "service stopped"
wait_s $((INT + 45))
scored_up && ok "watchdog restarted the scored service" || no "watchdog did NOT restore the service"

printf '\n  -- ATTACK 3: delete layer 2 and layer 3 --\n'
rm -f "/etc/systemd/system/$GUARD_NAME-reconcile.timer" "/etc/cron.d/$GUARD_NAME"
systemctl stop "$GUARD_NAME-reconcile.timer" >/dev/null 2>&1
note "deleted the timer unit and the cron entry"
wait_s $((INT + 45))
unit_file "$GUARD_NAME-reconcile.timer" && ok "layer 2 rebuilt by a surviving layer" || no "layer 2 NOT rebuilt"
[ -f "/etc/cron.d/$GUARD_NAME" ] && ok "layer 3 rebuilt by a surviving layer" || no "layer 3 NOT rebuilt"

printf '\n  -- ATTACK 4: backdoor a unit file instead of deleting it --\n'
tampered_before=$(tampered_count)
echo "ExecStartPost=/bin/sh -c 'id > /tmp/pwned-unit'" >> "/etc/systemd/system/$GUARD_NAME.service"
wait_s $((INT + 45))
grep -q 'pwned-unit' "/etc/systemd/system/$GUARD_NAME.service" \
  && no "backdoor line still in the live unit" || ok "backdoored unit repaired from source"
[ "$(tampered_count)" -gt "$tampered_before" ] \
  && ok "tampered unit preserved as evidence" || no "no tampered copy was preserved"
[ -e /tmp/pwned-unit ] && no "the injected ExecStartPost RAN as root" \
                       || ok "injected command never executed"

printf '\n  -- ATTACK 5: systemd drop-in override (never touches the unit file) --\n'
# The nastiest version of attack 4: the unit file stays byte-identical, so a
# hash check of the fragment sees nothing wrong, while systemd merges the
# drop-in and runs the attacker's command as root on the next start.
dropin_dir="/etc/systemd/system/$GUARD_NAME.service.d"
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
systemctl is-active --quiet "$GUARD_NAME.service" \
  && ok "layer 1 still active after the drop-in was stripped" \
  || no "layer 1 is down after the drop-in repair"

printf '\n  -- ATTACK 6: remove ALL THREE layers inside one interval --\n'
systemctl disable --now "$GUARD_NAME.service" "$GUARD_NAME-reconcile.timer" >/dev/null 2>&1
pkill -f "$GUARD_DIR/tick.sh"
rm -f "/etc/systemd/system/$GUARD_NAME.service" \
      "/etc/systemd/system/$GUARD_NAME-reconcile.timer" \
      "/etc/systemd/system/$GUARD_NAME-reconcile.service" \
      "/etc/cron.d/$GUARD_NAME"
systemctl daemon-reload
wait_s $((INT + 60))
if unit_file "$GUARD_NAME.service" || [ -f "/etc/cron.d/$GUARD_NAME" ]; then
  no "something rebuilt a layer after all three were removed (unexpected)"
else
  ok "stays down once all three are gone - the documented limit holds"
fi

# ---------------------------------------------------------------- phase 4b
hdr "PHASE 4b - reinstall, then prove --uninstall is exact"
./linux/guardian.sh --config "$CFG" --install --apply >"$DRILL_TMP/greinstall.out" 2>&1
systemctl is-active --quiet "$GUARD_NAME.service" && ok "reinstall from scratch works" || no "reinstall failed"

./linux/guardian.sh --config "$CFG" --uninstall --apply >"$DRILL_TMP/guninstall.out" 2>&1
sed 's/^/      /' "$DRILL_TMP/guninstall.out" | tail -5
leftover=0
for p in "/etc/systemd/system/$GUARD_NAME-watch.service" "/etc/systemd/system/$GUARD_NAME.service" \
         "/etc/systemd/system/$GUARD_NAME-reconcile.service" "/etc/systemd/system/$GUARD_NAME-reconcile.timer" \
         "/etc/systemd/system/$GUARD_NAME.service.d" "/etc/systemd/system/$GUARD_NAME-watch.service.d" \
         "/etc/cron.d/$GUARD_NAME" "$GUARD_DIR"; do
  [ -e "$p" ] && { leftover=$((leftover+1)); note "LEFT BEHIND: $p"; }
done
[ "$leftover" -eq 0 ] && ok "uninstall left zero artifacts" || no "$leftover artifacts survived uninstall"
# The repair tree is the copy an operator is least likely to remember exists.
[ -e "$GUARD_DIR/.repair" ] && no "the .repair source tree survived uninstall" \
                            || ok "repair tree removed with the payload"
pgrep -f watchdog.sh >/dev/null && no "a watchdog process is still running after uninstall" \
                                || ok "no stray watchdog process"
pgrep -f "$GUARD_DIR/tick.sh" >/dev/null && no "a layer-1 tick loop is still running after uninstall" \
                                         || ok "no stray tick loop"
systemctl list-units --all 2>/dev/null | grep -q "$GUARD_NAME" \
  && no "systemd still knows about a $GUARD_NAME unit" || ok "systemd has no $GUARD_NAME units left"
scored_up && ok "scored service is still up at the end of the drill" \
          || no "scored service is down at the end of the drill"

hdr "RESULT"
printf '  passed: %s\n  failed: %s\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && printf '  ALL ASSERTIONS PASSED\n' || printf '  %s ASSERTION(S) FAILED - see above\n' "$fail"
exit 0
