#!/usr/bin/env bash
# Score hunt.sh + recon.sh evidence against the plant.sh ground truth.
#
#   ./score.sh DIR [DIR...]   score these evidence directories together
#   ./score.sh BASE           legacy: score the newest subdirectory of BASE
#
# Exits 0 only when every applicable technique was caught, so a caller can
# assert on it. A missed technique exits 1; no usable evidence exits 2.
#
# Every check is a FIXED STRING against a path or an exact signature, not a
# loose regex. The old version checked /dev/shm with the alternative "\.rt",
# which also matches /root/.rt_manifest -- so it scored CAUGHT whenever the
# ground-truth file itself appeared in the evidence. A scorer that says CAUGHT
# when the tool found nothing is worse than no scorer.
set -u

[ "$#" -gt 0 ] || set -- /var/tmp/ccdc-evidence

dirs=''
for arg in "$@"; do
  if ls "$arg"/*.txt >/dev/null 2>&1; then
    dirs="$dirs $arg"
  else
    # Legacy form: a base directory. Take its newest evidence subdirectory,
    # skipping guardian.* state directories, which are not evidence runs.
    latest=$(ls -dt "$arg"/*/ 2>/dev/null | grep -v '/guardian\.' | head -1)
    [ -n "$latest" ] && dirs="$dirs $latest"
  fi
done
[ -n "$dirs" ] || { echo "no usable evidence in: $*" >&2; exit 2; }

blob=''
for d in $dirs; do
  echo "scoring against: $d"
  blob="$blob
$(cat "$d"/*.txt 2>/dev/null)"
done

# Ground truth, when the lab manifest is readable: only score what was actually
# planted. The web foothold is skipped on a box with no /var/www/html.
manifest=/root/.rt_manifest
planted() {
  [ -r "$manifest" ] || return 0          # no manifest: assume everything applies
  grep -Fq -- "$1" "$manifest"
}

missed=0
check() {
  local label=$1 needle=$2
  if printf '%s' "$blob" | grep -Fq -- "$needle"; then
    printf '  [CAUGHT ] %s\n' "$label"
  else
    printf '  [MISSED ] %s\n' "$label"
    missed=$((missed + 1))
  fi
}

echo "--- persistence detection ---"
check "rogue user rtsvc"              'rtsvc:'
check "sudoers drop-in"               '/etc/sudoers.d/rt-lab'
check "service-home SSH key"          '/var/lib/rtsvc/.ssh/authorized_keys'
check "attacker key body"             'LABPLANTdummykeyforhuntdetection'
check "implant binary"                '/usr/local/bin/rt-implant'
check "cron.d implant"                '/etc/cron.d/rt-cron'
check "root crontab implant"          '*/10 * * * * /usr/local/bin/rt-implant'
check "systemd timer backdoor"        '/etc/systemd/system/rt-backdoor.timer'
check "keyword-light profile hook"    '/etc/profile.d/rt-profile.sh'
check "first-line bashrc hook"        'RT_LAB_PLANT lab bashrc hook'
check "SUID root shell"               '/usr/local/bin/rootbash'
check "/dev/shm payload"              '/dev/shm/.rt'
if planted 'web-file:'; then
  check "non-PHP web foothold"        '/var/www/html/.rt-health.jsp'
else
  printf '  [SKIP   ] non-PHP web foothold (not planted on this box)\n'
fi

echo
if [ "$missed" -eq 0 ]; then
  echo "all applicable techniques caught"
  exit 0
fi
echo "$missed technique(s) missed"
exit 1
