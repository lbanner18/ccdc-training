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
EV=/var/tmp/ccdc-evidence
GUARD_NAME=node-health
INT=30

pass=0; fail=0
ok()  { printf '  [PASS] %s\n' "$1"; pass=$((pass+1)); }
no()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail+1)); }
hdr() { printf '\n========== %s ==========\n' "$1"; }
note(){ printf '  ...   %s\n' "$1"; }

scored_up() { curl -fsS --max-time 4 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; }
unit_file() { [ -f "/etc/systemd/system/$1" ]; }
wait_s()    { note "waiting ${1}s"; sleep "$1"; }

cd "$KIT" || exit 1

# ---------------------------------------------------------------- phase 0
hdr "PHASE 0 - arm the defenses"
scored_up && ok "scored service answering on :8080 before we start" \
          || no "scored service is ALREADY down before the drill"

./linux/recon.sh --config "$CFG" >/dev/null 2>&1
BASELINE=$(ls -dt "$EV"/*/ 2>/dev/null | head -1)
[ -n "$BASELINE" ] && ok "recon baseline captured ($(basename "$BASELINE"))" \
                   || no "recon produced no evidence directory"

./linux/canary.sh --config "$CFG" --deploy --apply >/dev/null 2>&1
laid=$(wc -l < "$EV/canary.manifest" 2>/dev/null || echo 0)
[ "$laid" -ge 5 ] && ok "canary decoys laid ($laid)" || no "canary deployed only $laid decoys"

# ---------------------------------------------------------------- phase 1
hdr "PHASE 1 - the red team lands"
./redteam/plant.sh >/tmp/plant.out 2>&1
planted=$(wc -l < /root/.rt_manifest 2>/dev/null || echo 0)
[ "$planted" -ge 10 ] && ok "plant.sh landed $planted footholds" \
                      || no "plant.sh landed only $planted footholds"
sed 's/^/      /' /root/.rt_manifest 2>/dev/null

# ---------------------------------------------------------------- phase 2
hdr "PHASE 2 - detect it"
# Capture each run's directory by name as it is produced. Selecting them with
# `find -newermt` looked equivalent and was not: phases 0-2 complete inside ~4
# seconds, `-newermt` is strictly-newer, and same-second evidence silently fell
# out of the blob -- which read as two detection failures that were really
# harness failures. Never infer which output you just produced; record it.
latest_ev() { ls -dt "$EV"/*/ 2>/dev/null | grep -v 'guardian\.' | head -1; }
./linux/recon.sh --config "$CFG" >/dev/null 2>&1; RECON_DIR=$(latest_ev)
./linux/hunt.sh  --config "$CFG" >/dev/null 2>&1; HUNT_DIR=$(latest_ev)
note "recon evidence: $(basename "$RECON_DIR")"
note "hunt evidence:  $(basename "$HUNT_DIR")"

# The rogue user shows up in recon and the cron implant in hunt, so score the
# union rather than score.sh's single newest directory.
BLOB=$(cat "$RECON_DIR"/*.txt "$HUNT_DIR"/*.txt 2>/dev/null)

detect() {
  local label=$1 pattern=$2
  printf '%s' "$BLOB" | grep -qiE "$pattern" && ok "detected: $label" || no "MISSED: $label"
}
detect "rogue user rtsvc"          'rtsvc'
detect "sudoers NOPASSWD backdoor" 'rtsvc.*NOPASSWD|NOPASSWD.*rtsvc'
detect "extra root SSH key"        'LABPLANT'
detect "cron.d implant"            'rt-cron|rt-implant'
detect "systemd timer backdoor"    'rt-backdoor|System Logging Helper'
detect "implant binary"            'rt-implant'
detect "profile.d hook"            'rt-profile'
detect "root .bashrc hook"         'RT_LAB_PLANT.*bashrc|bashrc.*RT_LAB_PLANT|lab bashrc hook'
detect "SUID root shell"           'rootbash'
detect "/dev/shm payload"          '/dev/shm/\.rt'

printf '\n  -- score.sh native output --\n'
./redteam/score.sh "$EV" 2>&1 | sed 's/^/    /'

printf '\n  -- canary check --\n'
./linux/canary.sh --config "$CFG" --check 2>&1 | sed 's/^/    /'

# ---------------------------------------------------------------- phase 3
hdr "PHASE 3 - eradicate (contain, remove, verify)"
cp /etc/sudoers /root/sudoers.drillbak
passwd -l rtsvc >/dev/null 2>&1
sed -i '/rtsvc/d' /etc/sudoers
if visudo -c >/dev/null 2>&1; then
  ok "sudoers backdoor removed and file still valid"
else
  cp /root/sudoers.drillbak /etc/sudoers
  no "sudoers edit was invalid - restored the backup"
fi
userdel -r rtsvc >/dev/null 2>&1
id rtsvc >/dev/null 2>&1 && no "rogue user rtsvc still exists" || ok "rogue user removed"

sed -i '/RT_LAB_PLANT/d' /root/.ssh/authorized_keys 2>/dev/null
grep -q LABPLANT /root/.ssh/authorized_keys 2>/dev/null \
  && no "attacker SSH key still present" || ok "attacker SSH key removed"

rm -f /etc/cron.d/rt-cron
crontab -l 2>/dev/null | grep -v RT_LAB_PLANT | crontab - 2>/dev/null
systemctl disable --now rt-backdoor.timer >/dev/null 2>&1
rm -f /etc/systemd/system/rt-backdoor.service /etc/systemd/system/rt-backdoor.timer
systemctl daemon-reload
rm -f /usr/local/bin/rt-implant /usr/local/bin/rootbash /dev/shm/.rt /etc/profile.d/rt-profile.sh
sed -i '/RT_LAB_PLANT/d' /root/.bashrc 2>/dev/null

left=0
for p in /etc/cron.d/rt-cron /etc/systemd/system/rt-backdoor.timer /usr/local/bin/rt-implant \
         /usr/local/bin/rootbash /dev/shm/.rt /etc/profile.d/rt-profile.sh; do
  [ -e "$p" ] && { left=$((left+1)); note "still present: $p"; }
done
[ "$left" -eq 0 ] && ok "all file-based footholds removed" || no "$left footholds survived"

./linux/hunt.sh --config "$CFG" >/dev/null 2>&1
CLEAN=$(ls -dt "$EV"/*/ | head -1)
if cat "$CLEAN"/*.txt 2>/dev/null | grep -qiE 'rt-implant|rt-backdoor|rootbash|rt-profile'; then
  no "re-hunt still finds red-team artifacts"
else
  ok "re-hunt is clean"
fi
scored_up && ok "scored service SURVIVED eradication" || no "scored service went down during eradication"

# ---------------------------------------------------------------- phase 4
hdr "PHASE 4 - guardian survival (the unproven paths)"
./linux/guardian.sh --config "$CFG" --install --apply >/tmp/ginstall.out 2>&1
sed 's/^/      /' /tmp/ginstall.out | head -20

for u in "$GUARD_NAME-watch.service" "$GUARD_NAME.service" "$GUARD_NAME-reconcile.timer"; do
  systemctl is-active --quiet "$u" && ok "unit active: $u" || no "unit NOT active: $u"
done
[ -f "/etc/cron.d/$GUARD_NAME" ] && ok "layer 3 cron entry installed" || no "layer 3 cron entry missing"
mcount=$(wc -l < "$EV/guardian.manifest" 2>/dev/null || echo 0)
[ "$mcount" -ge 9 ] && ok "manifest records $mcount artifacts" || no "manifest only has $mcount lines"

printf '\n  -- ATTACK 1: kill the watchdog process --\n'
pkill -f 'watchdog.sh' ; wait_s 15
systemctl is-active --quiet "$GUARD_NAME-watch.service" \
  && ok "watchdog came back (Restart=always)" || no "watchdog stayed dead"
pgrep -f watchdog.sh >/dev/null && ok "watchdog process is running again" || no "no watchdog process"

printf '\n  -- ATTACK 2: stop the scored service --\n'
systemctl stop scored-web; scored_up && no "service did not actually stop" || note "service stopped"
wait_s $((INT + 45))
scored_up && ok "watchdog restarted the scored service" || no "watchdog did NOT restore the service"

printf '\n  -- ATTACK 3: delete layer 2 and layer 3 --\n'
rm -f "/etc/systemd/system/$GUARD_NAME-reconcile.timer" "/etc/cron.d/$GUARD_NAME"
systemctl stop "$GUARD_NAME-reconcile.timer" >/dev/null 2>&1
note "deleted the timer unit and the cron entry"
wait_s $((INT + 45))
unit_file "$GUARD_NAME-reconcile.timer" && ok "layer 2 rebuilt by a surviving layer" || no "layer 2 NOT rebuilt"
[ -f "/etc/cron.d/$GUARD_NAME" ] && ok "layer 3 rebuilt by a surviving layer" || no "layer 3 NOT rebuilt"

printf '\n  -- ATTACK 4: backdoor a unit instead of deleting it --\n'
echo "ExecStartPost=/bin/sh -c 'id > /tmp/pwned'" >> "/etc/systemd/system/$GUARD_NAME.service"
wait_s $((INT + 45))
grep -q 'tmp/pwned' "/etc/systemd/system/$GUARD_NAME.service" \
  && no "backdoor line still in the live unit" || ok "backdoored unit repaired from source"
ls "$EV"/guardian.tampered/ >/dev/null 2>&1 \
  && ok "tampered copy preserved as evidence ($(ls "$EV"/guardian.tampered/ | wc -l) file)" \
  || no "no tampered copy was preserved"

printf '\n  -- ATTACK 5: remove ALL THREE layers inside one interval --\n'
systemctl disable --now "$GUARD_NAME.service" "$GUARD_NAME-reconcile.timer" >/dev/null 2>&1
pkill -f "$GUARD_NAME/tick.sh"
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
./linux/guardian.sh --config "$CFG" --install --apply >/dev/null 2>&1
systemctl is-active --quiet "$GUARD_NAME.service" && ok "reinstall from scratch works" || no "reinstall failed"

./linux/guardian.sh --config "$CFG" --uninstall --apply >/tmp/guninstall.out 2>&1
sed 's/^/      /' /tmp/guninstall.out | tail -5
leftover=0
for p in "/etc/systemd/system/$GUARD_NAME-watch.service" "/etc/systemd/system/$GUARD_NAME.service" \
         "/etc/systemd/system/$GUARD_NAME-reconcile.service" "/etc/systemd/system/$GUARD_NAME-reconcile.timer" \
         "/etc/cron.d/$GUARD_NAME" "/usr/local/lib/$GUARD_NAME"; do
  [ -e "$p" ] && { leftover=$((leftover+1)); note "LEFT BEHIND: $p"; }
done
[ "$leftover" -eq 0 ] && ok "uninstall left zero artifacts" || no "$leftover artifacts survived uninstall"
pgrep -f watchdog.sh >/dev/null && no "a watchdog process is still running after uninstall" \
                                || ok "no stray watchdog process"
systemctl list-units --all 2>/dev/null | grep -q "$GUARD_NAME" \
  && no "systemd still knows about a $GUARD_NAME unit" || ok "systemd has no $GUARD_NAME units left"

hdr "RESULT"
printf '  passed: %s\n  failed: %s\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && printf '  ALL ASSERTIONS PASSED\n' || printf '  %s ASSERTION(S) FAILED - see above\n' "$fail"
exit 0
