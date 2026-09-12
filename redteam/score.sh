#!/usr/bin/env bash
# Score hunt.sh + recon.sh evidence against the plant.sh ground truth.
# Reads the newest evidence folder and greps for each planted artifact's
# signature, so we know what the defensive sweep would and would not surface.
#   ./score.sh /var/tmp/ccdc-evidence
set -u
base=${1:-/var/tmp/ccdc-evidence}
latest=$(ls -dt "$base"/*/ 2>/dev/null | head -1)
[ -n "$latest" ] || { echo "no evidence under $base"; exit 1; }
echo "scoring against: $latest"
blob=$(cat "$latest"/*.txt 2>/dev/null)

check() {
  local label=$1 pattern=$2
  if printf '%s' "$blob" | grep -qiE "$pattern"; then
    printf '  [CAUGHT ] %s\n' "$label"
  else
    printf '  [MISSED ] %s\n' "$label"
  fi
}

echo "--- persistence detection ---"
check "rogue user rtsvc"              'rtsvc'
check "sudoers NOPASSWD backdoor"     'rtsvc.*NOPASSWD|NOPASSWD.*rtsvc'
check "extra root SSH key"            'LABPLANT|authorized_keys'
check "cron.d implant"                'rt-cron|rt-implant'
check "root crontab implant"          'rt-implant'
check "systemd timer backdoor"        'rt-backdoor|System Logging Helper'
check "implant binary"                'rt-implant'
check "profile.d hook"                'rt-profile'
check "SUID root shell"               'rootbash'
check "/dev/shm payload"              '/dev/shm/\.rt|\.rt'
