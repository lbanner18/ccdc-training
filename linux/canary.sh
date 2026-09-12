#!/usr/bin/env bash
set -u

# canary.sh - lay tripwires and detect when they are touched.
#
# This is detection, not persistence and not offense. It deploys decoy files in
# tempting locations, records a baseline (hash + inode + access time), and asks
# auditd to log any access to them and to the real sensitive files. --check
# reports which tripwires moved. Run --check from the watchdog loop or a manual
# pass; nothing here installs its own scheduler.
#
#   canary.sh --config FILE --deploy   [--apply|--dry-run]   lay the tripwires
#   canary.sh --config FILE --check                          report trips (ro)
#   canary.sh --config FILE --status                         show what is laid
#   canary.sh --config FILE --remove   [--apply|--dry-run]   pick them back up
#
# --check is read-only and never mutates, so it is safe to run every interval.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
mode=''
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --deploy) mode=deploy; shift ;;
    --check) mode=check; shift ;;
    --status) mode=status; shift ;;
    --remove) mode=remove; shift ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE --deploy|--check|--status|--remove [--apply|--dry-run]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$mode" ] || ccdc_die "choose one of --deploy --check --status --remove"
ccdc_load_config "$config"

# State lives with the evidence, not with the canaries. If it sat next to a
# decoy, an attacker reading the decoy's directory would find the list of every
# other decoy - which defeats the point.
state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
mkdir -p "$state_dir" 2>/dev/null || state_dir="${TMPDIR:-/tmp}/ccdc-evidence"
mkdir -p "$state_dir"
manifest="$state_dir/canary.manifest"     # path|sha256|inode  - one decoy per line
baseline="$state_dir/canary.baseline"     # path|atime         - for the touch check
alertlog="$state_dir/canary.alerts.log"

# Decoy paths. Override in the config with CCDC_CANARY_FILES (one path per
# line). These defaults are the files an attacker greps for first; each is a
# plausible name in a plausible place, and each is fake.
default_canaries='/root/.ssh/id_rsa.bak
/root/passwords.txt
/root/backup/db_root_credentials.txt
/home/backup.sh.orig
/var/www/html/wp-config.php.bak
/etc/.pgpass.save'

canary_list() {
  if [ -n "${CCDC_CANARY_FILES:-}" ]; then
    printf '%s\n' "$CCDC_CANARY_FILES"
  else
    printf '%s\n' "$default_canaries"
  fi
}

# Files that are real and must never change quietly. Access to these is the
# highest-value signal on the box: a read of /etc/shadow or a write to
# authorized_keys is almost always the red team.
sensitive_list() {
  printf '%s\n' "${CCDC_CANARY_WATCH_PATHS:-/etc/passwd
/etc/shadow
/etc/sudoers
/etc/crontab
/etc/cron.d
/root/.ssh/authorized_keys}"
}

fake_contents() {
  # Deliberately tempting, entirely fake, and marked so a teammate (or you, at
  # hour six) does not mistake it for a real secret and act on it.
  cat <<'FAKE'
# CANARY - not a real credential. Access to this file is logged and alerted.
# If you are reading this and you are not on the blue team, you have tripped an
# alarm.
db_user=admin
db_pass=S3ason@l-Rotation-2026
api_token=ckey_9f2b7a1c4e6d8039bica11ryde90c0de
FAKE
}

path_atime() { stat -c '%X' "$1" 2>/dev/null || stat -f '%a' "$1" 2>/dev/null || printf '0'; }
path_inode() { stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1" 2>/dev/null || printf '0'; }
path_hash()  { ccdc_hash_file "$1" 2>/dev/null | awk '{print $1}'; }

# --- auditd wiring -------------------------------------------------------
# auditd is the only mechanism here that catches a READ. A hash check catches a
# modified or deleted decoy, but an attacker who merely opens and copies it
# leaves the file byte-identical. auditd records the open with the pid, uid,
# and command, which is exactly the evidence an inject asks for. If auditd is
# not installed we fall back to atime, and say so, rather than pretending.
audit_available() { ccdc_have auditctl; }

install_audit_rule() {
  local path=$1 key=$2
  audit_available || return 0
  # -p rwa: read, write, attribute change. -k tags the events so ausearch -k
  # pulls exactly our hits out of a noisy log.
  ccdc_action auditctl -w "$path" -p rwa -k "$key"
}

deploy() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  : >"${manifest}.next"
  : >"${baseline}.next"
  canary_list | while IFS= read -r path; do
    [ -n "$path" ] || continue
    dir=$(dirname -- "$path")
    if [ "$apply" -eq 1 ]; then
      mkdir -p "$dir" 2>/dev/null || ccdc_warn "cannot create $dir for decoy"
      fake_contents >"$path" 2>/dev/null || { ccdc_warn "cannot write decoy $path"; continue; }
      # 0600 and root-owned: a decoy that is world-readable looks like a decoy.
      # Real secrets are locked down, so ours must be too.
      chmod 0600 "$path" 2>/dev/null || true
      printf '%s|%s|%s\n' "$path" "$(path_hash "$path")" "$(path_inode "$path")" >>"${manifest}.next"
      printf '%s|%s\n' "$path" "$(path_atime "$path")" >>"${baseline}.next"
      install_audit_rule "$path" ccdc-canary
      ccdc_append_log "$alertlog" "deployed decoy path=$path"
    else
      printf '[dry-run] would write decoy %s (0600 root) and audit-watch it\n' "$path"
    fi
  done
  # Watch the real sensitive files too.
  sensitive_list | while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ]; then
      if [ "$apply" -eq 1 ]; then
        install_audit_rule "$path" ccdc-sensitive
      else
        printf '[dry-run] would audit-watch sensitive path %s\n' "$path"
      fi
    fi
  done
  if [ "$apply" -eq 1 ]; then
    mv "${manifest}.next" "$manifest"
    mv "${baseline}.next" "$baseline"
    audit_available || ccdc_warn "auditd not present: only modify/delete is detectable, not reads. Install audit for read detection."
    ccdc_info "canaries deployed; manifest at $manifest"
  else
    rm -f "${manifest}.next" "${baseline}.next"
    ccdc_info "dry run only; no decoys written"
  fi
}

check() {
  local tripped=0
  # 1. Decoys modified or removed (hash/inode drift).
  if [ -f "$manifest" ]; then
    while IFS='|' read -r path old_hash old_inode; do
      [ -n "${path:-}" ] || continue
      if [ ! -e "$path" ]; then
        printf 'TRIPPED (deleted): %s\n' "$path"
        ccdc_append_log "$alertlog" "TRIP kind=deleted path=$path"
        tripped=1
        continue
      fi
      new_hash=$(path_hash "$path")
      new_inode=$(path_inode "$path")
      if [ "$new_hash" != "$old_hash" ]; then
        printf 'TRIPPED (modified): %s\n' "$path"
        ccdc_append_log "$alertlog" "TRIP kind=modified path=$path old=$old_hash new=$new_hash"
        tripped=1
      elif [ "$new_inode" != "$old_inode" ]; then
        printf 'TRIPPED (replaced): %s\n' "$path"
        ccdc_append_log "$alertlog" "TRIP kind=replaced path=$path old_inode=$old_inode new_inode=$new_inode"
        tripped=1
      fi
    done <"$manifest"
  else
    ccdc_warn "no canary manifest; run --deploy first"
  fi

  # 2. Decoys read but not changed (atime moved). Weaker than auditd: atime can
  # be off (relatime/noatime) and a careful attacker resets it. Reported as a
  # hint, not proof.
  if [ -f "$baseline" ]; then
    while IFS='|' read -r path old_atime; do
      [ -n "${path:-}" ] || continue
      [ -e "$path" ] || continue
      new_atime=$(path_atime "$path")
      if [ "$new_atime" != "$old_atime" ] && [ "$old_atime" != "0" ]; then
        printf 'HINT (atime moved, possible read): %s\n' "$path"
        ccdc_append_log "$alertlog" "HINT kind=atime path=$path old=$old_atime new=$new_atime"
      fi
    done <"$baseline"
  fi

  # 3. auditd hits against decoys or sensitive files - the real signal.
  if ccdc_have ausearch; then
    hits=$(ausearch -k ccdc-canary -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)
    shits=$(ausearch -k ccdc-sensitive -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)
    [ "${hits:-0}" -gt 0 ] && { printf 'AUDIT: %s recent access event(s) on decoy files\n' "$hits"; tripped=1; }
    [ "${shits:-0}" -gt 0 ] && printf 'AUDIT: %s recent access event(s) on sensitive files\n' "$shits"
    if [ "${hits:-0}" -gt 0 ] || [ "${shits:-0}" -gt 0 ]; then
      printf 'run: ausearch -k ccdc-canary -i   (and -k ccdc-sensitive) for the who/what/when\n'
    fi
  else
    ccdc_warn "ausearch not present: cannot report read events; relying on hash/atime only"
  fi

  if [ "$tripped" -eq 1 ]; then
    ccdc_warn "one or more canaries TRIPPED - investigate now; alerts in $alertlog"
    return 3
  fi
  ccdc_info "no canary trips detected"
  return 0
}

status() {
  printf 'manifest: %s\n' "$manifest"
  if [ -f "$manifest" ]; then
    printf 'decoys laid: %s\n' "$(wc -l <"$manifest")"
    sed 's/|.*//' "$manifest" | sed 's/^/  /'
  else
    printf 'no decoys laid\n'
  fi
  if audit_available; then
    printf 'audit rules:\n'
    auditctl -l 2>/dev/null | grep -E 'ccdc-(canary|sensitive)' | sed 's/^/  /' || printf '  (none loaded)\n'
  else
    printf 'auditd: not installed (read detection unavailable)\n'
  fi
  [ -f "$alertlog" ] && { printf 'recent alerts:\n'; tail -n 10 "$alertlog" | sed 's/^/  /'; }
}

remove() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  if [ -f "$manifest" ]; then
    while IFS='|' read -r path _rest; do
      [ -n "${path:-}" ] || continue
      ccdc_action rm -f "$path"
    done <"$manifest"
  fi
  if audit_available && [ "$apply" -eq 1 ]; then
    auditctl -D -k ccdc-canary >/dev/null 2>&1 || true
    # -D clears all rules; re-listing and deleting by key is version-specific,
    # so warn rather than silently wiping every audit rule on the box.
    ccdc_warn "auditd rules by key cannot be removed individually on all versions; review 'auditctl -l'"
  fi
  if [ "$apply" -eq 1 ]; then
    rm -f "$manifest" "$baseline"
    ccdc_info "canaries removed"
  else
    ccdc_info "dry run only; decoys left in place"
  fi
}

case "$mode" in
  deploy) deploy ;;
  check) check ;;
  status) status ;;
  remove) remove ;;
esac
