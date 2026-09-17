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
# --check never changes a canary or system configuration. It only appends local
# alert evidence, so it is safe to run every interval.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

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
      printf '\n'
      printf '  Decoy files that nobody has any business reading, plus auditd watches\n'
      printf '  on them and on the real sensitive files. If one is touched, someone is\n'
      printf '  looking around.\n'
      printf '\n'
      printf '  --deploy --apply   lay the decoys and load the watches.\n'
      printf '  --check     has anything been touched. Read-only and loopable; this is\n'
      printf '              what sentry runs.\n'
      printf '  --status    what is currently laid.\n'
      printf '  --remove --apply   take them away again.\n'
      printf '\n'
      printf '  Manifest-tracked, so --remove takes away exactly what --deploy laid and\n'
      printf '  nothing else. The auditd rules it loads at runtime are cleared by a\n'
      printf '  restart of auditd - audit.sh makes them persistent.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$mode" ] || ccdc_die "choose one of --deploy --check --status --remove"
ccdc_load_config "$config"
# Config is shell syntax, but it must not be able to override the explicit CLI
# safety choice made above.
if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi

# State lives with the evidence, not with the canaries. If it sat next to a
# decoy, an attacker reading the decoy's directory would find the list of every
# other decoy - which defeats the point.
state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
if [ "$apply" -eq 1 ]; then
  ccdc_secure_state_dir "$state_dir" "canary state directory"
fi
manifest="$state_dir/canary.manifest"     # path|sha256|inode  - one decoy per line
baseline="$state_dir/canary.baseline"     # path|atime         - for the touch check
alertlog="$state_dir/canary.alerts.log"
pending="$state_dir/canary.pending"       # path|expected-hash - interruption journal
audit_marker="$state_dir/canary.audit-active"
canary_staged=''

cleanup_canary_staged() {
  local staged
  for staged in $canary_staged; do rm -f -- "$staged" 2>/dev/null || true; done
}
trap cleanup_canary_staged EXIT

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

# Files that are real and must never change quietly. These get write/attribute
# watches only. The kit's own recon and triage passes legitimately read files
# such as /etc/passwd and /etc/shadow; auditing those reads would make the
# detector alert on itself. Read watches are reserved for the decoys below.
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

manifest_hash() {
  [ -f "$manifest" ] || return 0
  awk -F'|' -v p="$1" '$1 == p {print $2; exit}' "$manifest" 2>/dev/null
}

managed_decoy_is_intact() {
  local path=$1 expected actual
  [ -f "$path" ] && [ ! -L "$path" ] || return 1
  expected=$(manifest_hash "$path")
  [ -n "$expected" ] || return 1
  actual=$(path_hash "$path")
  [ -n "$actual" ] && [ "$actual" = "$expected" ]
}

# --- auditd wiring -------------------------------------------------------
# auditd is the only mechanism here that catches a READ. A hash check catches a
# modified or deleted decoy, but an attacker who merely opens and copies it
# leaves the file byte-identical. auditd records the open with the pid, uid,
# and command, which is exactly the evidence an inject asks for. If auditd is
# not installed we fall back to atime, and say so, rather than pretending.
audit_available() { ccdc_have auditctl; }

install_audit_rule() {
  local path=$1 permissions=$2 key=$3
  audit_available || return 1
  # -k tags the events so ausearch can pull our hits out of a noisy log.
  ccdc_action auditctl -w "$path" -p "$permissions" -k "$key"
}

clear_runtime_audit_rules() {
  local failed=0
  audit_available || return 0
  auditctl -D -k ccdc-canary >/dev/null 2>&1 || failed=1
  auditctl -D -k ccdc-sensitive >/dev/null 2>&1 || failed=1
  [ "$failed" -eq 0 ]
}

audit_rule_present() {
  local rules=$1 path=$2 permissions=$3 key=$4
  printf '%s\n' "$rules" | awk -v wanted_path="$path" -v wanted_permissions="$permissions" -v wanted_key="$key" '
    {
      path = permissions = key = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "-w" && i < NF) path = $(i + 1)
        if ($i == "-p" && i < NF) permissions = $(i + 1)
        if ($i == "-k" && i < NF) key = $(i + 1)
        if ($i ~ /^key=/) { key = $i; sub(/^key=/, "", key) }
      }
      if (path == wanted_path && permissions == wanted_permissions && key == wanted_key) found = 1
    }
    END { exit(found ? 0 : 1) }
  '
}

audit_sensitive_read_rule_present() {
  local rules=$1 path=$2
  printf '%s\n' "$rules" | awk -v wanted_path="$path" '
    {
      path = permissions = key = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "-w" && i < NF) path = $(i + 1)
        if ($i == "-p" && i < NF) permissions = $(i + 1)
        if ($i == "-k" && i < NF) key = $(i + 1)
        if ($i ~ /^key=/) { key = $i; sub(/^key=/, "", key) }
      }
      if (path == wanted_path && key == "ccdc-sensitive" && permissions ~ /r/) found = 1
    }
    END { exit(found ? 0 : 1) }
  '
}

verify_runtime_audit_rules() {
  local rules path failed=0
  audit_available || {
    ccdc_warn "audit marker exists but auditctl is unavailable; read monitoring is not verifiable"
    return 1
  }
  if ! rules=$(auditctl -l 2>/dev/null); then
    ccdc_warn "audit marker exists but loaded rules cannot be inspected (run the check as root)"
    return 1
  fi

  while IFS='|' read -r path _hash _inode; do
    [ -n "${path:-}" ] || continue
    if ! audit_rule_present "$rules" "$path" rwa ccdc-canary; then
      ccdc_warn "runtime decoy read watch is missing or misconfigured: $path"
      failed=1
    fi
  done <"$manifest"

  while IFS= read -r path; do
    [ -n "$path" ] && [ -e "$path" ] || continue
    if ! audit_rule_present "$rules" "$path" wa ccdc-sensitive; then
      ccdc_warn "runtime sensitive-path write watch is missing or misconfigured: $path"
      failed=1
    fi
    if audit_sensitive_read_rule_present "$rules" "$path"; then
      ccdc_warn "runtime sensitive-path rule still audits reads and will create monitor noise: $path"
      failed=1
    fi
  done <<EOF
$(sensitive_list)
EOF

  [ "$failed" -eq 0 ]
}

deploy() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  if [ "$apply" -ne 1 ]; then
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      printf '[dry-run] would create new decoy %s (0600 root) and audit-watch it with permissions rwa\n' "$path"
    done <<EOF
$(canary_list)
EOF
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      [ -e "$path" ] && printf '[dry-run] would audit-watch sensitive path %s with permissions wa\n' "$path"
    done <<EOF
$(sensitive_list)
EOF
    ccdc_info "dry run only; no decoys or state files written"
    return 0
  fi

  [ ! -f "$manifest" ] && [ ! -f "$pending" ] \
    || ccdc_die "canaries are already deployed or a deployment was interrupted; run --status/--remove first"

  collision=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ] || [ -L "$path" ]; then
      ccdc_warn "refusing to overwrite existing path with a decoy: $path"
      collision=1
    fi
  done <<EOF
$(canary_list)
EOF
  [ "$collision" -eq 0 ] || ccdc_die "one or more canary paths already exist; no files were changed"

  if ccdc_have sha256sum; then
    fake_hash=$(fake_contents | sha256sum | awk '{print $1}')
  elif ccdc_have shasum; then
    fake_hash=$(fake_contents | shasum -a 256 | awk '{print $1}')
  else
    ccdc_die "no SHA-256 utility available; no files were changed"
  fi
  [ -n "$fake_hash" ] || ccdc_die "could not hash canary contents; no files were changed"

  pending_staged="${pending}.new.$$"
  manifest_staged="${manifest}.next.$$"
  baseline_staged="${baseline}.next.$$"
  canary_staged="$canary_staged $pending_staged $manifest_staged $baseline_staged"
  : >"$pending_staged" && : >"$manifest_staged" && : >"$baseline_staged" \
    || ccdc_die "cannot prepare canary state; no decoys were written"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf '%s|%s\n' "$path" "$fake_hash" >>"$pending_staged" \
      || ccdc_die "cannot journal planned decoy $path; no decoys were written"
  done <<EOF
$(canary_list)
EOF
  chmod 0600 "$pending_staged" "$manifest_staged" "$baseline_staged" \
    && mv -f "$pending_staged" "$pending" \
    || ccdc_die "cannot install canary interruption journal; no decoys were written"

  deploy_failed=0
  audit_ok=0
  audit_cleanup_failed=0
  if audit_available; then
    if clear_runtime_audit_rules; then
      audit_ok=1
    else
      audit_cleanup_failed=1
      ccdc_warn "could not clear old CCDC audit rules; refusing to layer new watches over unknown permissions"
    fi
  fi

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    dir=$(dirname -- "$path")
    staged="${path}.ccdc-canary.new.$$"
    canary_staged="$canary_staged $staged"
    if ! mkdir -p "$dir" 2>/dev/null \
      || [ -e "$path" ] || [ -L "$path" ] \
      || ! fake_contents >"$staged" 2>/dev/null \
      || ! chmod 0600 "$staged" \
      || ! ln -- "$staged" "$path" 2>/dev/null \
      || ! rm -f "$staged"; then
      ccdc_warn "cannot safely create decoy $path"
      deploy_failed=1
      continue
    fi
    actual_hash=$(path_hash "$path")
    [ "$actual_hash" = "$fake_hash" ] \
      || { ccdc_warn "decoy verification failed: $path"; deploy_failed=1; continue; }
    printf '%s|%s|%s\n' "$path" "$actual_hash" "$(path_inode "$path")" >>"$manifest_staged" \
      || { ccdc_warn "cannot record decoy $path"; deploy_failed=1; continue; }
    printf '%s|%s\n' "$path" "$(path_atime "$path")" >>"$baseline_staged" \
      || { ccdc_warn "cannot baseline decoy $path"; deploy_failed=1; continue; }
    if audit_available && [ "$audit_cleanup_failed" -eq 0 ] \
      && ! install_audit_rule "$path" rwa ccdc-canary; then
      ccdc_warn "could not install read watch for $path"
      audit_ok=0
    fi
    ccdc_append_log "$alertlog" "deployed decoy path=$path"
  done <<EOF
$(canary_list)
EOF

  if [ "$deploy_failed" -eq 1 ]; then
    ccdc_die "canary deployment was incomplete; journal retained for safe --remove"
  fi

  # Real files are write/attribute-only. Reads are routine blue-team activity;
  # write or metadata changes are the useful signal here.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -e "$path" ] && audit_available && [ "$audit_cleanup_failed" -eq 0 ]; then
      if ! install_audit_rule "$path" wa ccdc-sensitive; then
        ccdc_warn "could not install write watch for sensitive path $path"
        audit_ok=0
      fi
    fi
  done <<EOF
$(sensitive_list)
EOF

  mv -f "$manifest_staged" "$manifest" \
    && mv -f "$baseline_staged" "$baseline" \
    || ccdc_die "could not finalize canary manifests; journal retained for safe --remove"
  rm -f "$pending"
  if [ "$audit_ok" -eq 1 ]; then
    if ! printf 'decoy=rwa sensitive=wa\n' >"$audit_marker" \
      || ! chmod 0600 "$audit_marker"; then
      ccdc_warn "could not record audit state; removing runtime watches before using hash fallback"
      audit_ok=0
    fi
  fi
  if [ "$audit_ok" -ne 1 ]; then
    if clear_runtime_audit_rules; then
      rm -f "$audit_marker"
      ccdc_warn "audit watches are not fully active: using hash/inode/atime fallback"
    else
      printf 'degraded: runtime rules could not be removed\n' >"$audit_marker" 2>/dev/null || true
      chmod 0600 "$audit_marker" 2>/dev/null || true
      ccdc_die "canaries were laid, but partial/old audit rules remain; --check will health-fail until rules are repaired"
    fi
  fi
  ccdc_info "canaries deployed; manifest at $manifest"
}

check() {
  local tripped=0 audit_mode=0 health_failed=0

  if [ -e "$pending" ] || [ -L "$pending" ]; then
    ccdc_warn "interrupted deployment journal present: $pending; monitoring state is incomplete"
    health_failed=1
  fi
  if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    ccdc_warn "no trustworthy canary manifest; run --deploy first"
    return 4
  fi

  if [ -e "$audit_marker" ] || [ -L "$audit_marker" ]; then
    # Once deployment records audit mode, never silently trust that disk marker:
    # auditd loses runtime watches across some restarts and immutable/rules-file
    # policies can reject reloads. A stale marker is a detector health failure.
    audit_mode=1
    if [ ! -f "$audit_marker" ] || [ -L "$audit_marker" ]; then
      ccdc_warn "audit marker is not a trustworthy regular file: $audit_marker"
      health_failed=1
    elif ! verify_runtime_audit_rules; then
      health_failed=1
    fi
  fi

  # 1. Decoys modified or removed (hash/inode drift).
  while IFS='|' read -r path old_hash old_inode; do
    [ -n "${path:-}" ] || continue
    if [ ! -e "$path" ]; then
      printf 'TRIPPED (deleted): %s\n' "$path"
      ccdc_append_log "$alertlog" "TRIP kind=deleted path=$path"
      tripped=1
      continue
    fi
    if [ "$audit_mode" -eq 0 ]; then
      new_inode=$(path_inode "$path")
      new_hash=$(path_hash "$path")
      if [ "$new_hash" != "$old_hash" ]; then
        printf 'TRIPPED (modified): %s\n' "$path"
        ccdc_append_log "$alertlog" "TRIP kind=modified path=$path old=$old_hash new=$new_hash"
        tripped=1
      elif [ "$new_inode" != "$old_inode" ]; then
        printf 'TRIPPED (replaced): %s\n' "$path"
        ccdc_append_log "$alertlog" "TRIP kind=replaced path=$path old_inode=$old_inode new_inode=$new_inode"
        tripped=1
      fi
    fi
  done <"$manifest"

  # 2. Decoys read but not changed (atime moved). Weaker than auditd: atime can
  # be off (relatime/noatime) and a careful attacker resets it. Reported as a
  # hint, not proof.
  if [ "$audit_mode" -eq 0 ] && [ -f "$baseline" ]; then
    while IFS='|' read -r path old_atime; do
      [ -n "${path:-}" ] || continue
      [ -e "$path" ] || continue
      new_atime=$(path_atime "$path")
      if [ "$new_atime" != "$old_atime" ] && [ "$old_atime" != "0" ]; then
        printf 'HINT (atime moved, possible read): %s\n' "$path"
        ccdc_append_log "$alertlog" "HINT kind=atime path=$path old=$old_atime new=$new_atime"
        # A fallback read hint is weaker than an audit event, but it still has
        # to propagate to watch/sentry. Returning success hid the only read
        # signal available on boxes without auditd.
        tripped=1
      fi
    done <"$baseline"
  fi

  # 3. auditd hits against decoys or sensitive files - the real signal.
  #
  # Bounded, because ausearch can block indefinitely. On the lab box a
  # `ausearch -k ccdc-canary -ts recent` sat for minutes against a log grown
  # large by repeated drills, and because canary.sh is the FIRST thing
  # watch.sh runs each pass, the whole detection loop stopped with it. A
  # detector that hangs looks exactly like a detector that has nothing to
  # report, which is the most dangerous way for this to fail.
  #
  # A timeout here degrades to "could not read the audit log this pass" and
  # says so, which is a state the operator can see and act on.
  if ccdc_have ausearch; then
    ausearch_bounded() {
      if ccdc_have timeout; then
        timeout "${CCDC_AUSEARCH_TIMEOUT:-20}" ausearch -k "$1" -ts recent 2>/dev/null
      else
        ausearch -k "$1" -ts recent 2>/dev/null
      fi
    }
    # Capture the output first, THEN count it. `x=$(cmd | grep -c ...); rc=$?`
    # reads grep's exit status, not the command's - so a timeout would have
    # reported cleanly as zero events every time. This kit has shipped that
    # mistake before with `head`.
    canary_raw=$(ausearch_bounded ccdc-canary); ausearch_rc=$?
    sens_raw=$(ausearch_bounded ccdc-sensitive); sens_rc=$?
    hits=$(printf '%s\n' "$canary_raw" | grep -c 'type=SYSCALL' || true)
    shits=$(printf '%s\n' "$sens_raw" | grep -c 'type=SYSCALL' || true)
    if [ "${ausearch_rc:-0}" -eq 124 ] || [ "${sens_rc:-0}" -eq 124 ]; then
      ccdc_warn "ausearch timed out: the audit log could not be read this pass.
  This is NOT 'no events' - it is 'no answer'. Check the log size and the daemon:
    sudo ls -lh /var/log/audit/audit.log
    sudo systemctl status auditd
  Raise the limit with CCDC_AUSEARCH_TIMEOUT if the box is just slow."
      health_failed=1
    fi
    [ "${hits:-0}" -gt 0 ] && { printf 'AUDIT: %s recent access event(s) on decoy files\n' "$hits"; ccdc_append_log "$alertlog" "TRIP kind=audit_decoy events=$hits"; tripped=1; }
    [ "${shits:-0}" -gt 0 ] && { printf 'AUDIT: %s recent access event(s) on sensitive files\n' "$shits"; ccdc_append_log "$alertlog" "TRIP kind=audit_sensitive events=$shits"; tripped=1; }
    if [ "${hits:-0}" -gt 0 ] || [ "${shits:-0}" -gt 0 ]; then
      printf 'run: ausearch -k ccdc-canary -i   (and -k ccdc-sensitive) for the who/what/when\n'
    fi
  elif [ "$audit_mode" -eq 0 ]; then
    ccdc_warn "ausearch not present: cannot report read events; relying on hash/atime only"
  fi

  if [ "$health_failed" -eq 1 ]; then
    ccdc_warn "canary detector health failure - repair or redeploy audit watches before trusting a clean result"
    return 4
  fi
  if [ "$tripped" -eq 1 ]; then
    # Naming the log is not telling anyone how to read it. The state directory
    # is 0700 root because it holds captured evidence, so an operator's own
    # shell cannot cd into it, cannot tab-complete inside it, and cannot expand
    # a glob against it - and `sudo cd` is not a thing, because cd is a shell
    # builtin. Print the command that works.
    ccdc_warn "one or more canaries TRIPPED - investigate now"
    printf '  read the alerts:  sudo tail -n 40 %q\n' "$alertlog" >&2
    return 3
  fi
  ccdc_info "no canary trips detected"
  return 0
}

status() {
  local health_failed=0
  printf 'manifest: %s\n' "$manifest"
  if [ -e "$pending" ] || [ -L "$pending" ]; then
    printf 'WARNING: interrupted deployment journal present: %s\n' "$pending"
    health_failed=1
  fi
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
  if [ -e "$audit_marker" ] || [ -L "$audit_marker" ]; then
    if [ ! -f "$manifest" ] || [ -L "$manifest" ] \
      || [ ! -f "$audit_marker" ] || [ -L "$audit_marker" ] \
      || ! verify_runtime_audit_rules; then
      printf 'audit health: DEGRADED (runtime rules do not match deployed state)\n'
      health_failed=1
    else
      printf 'audit health: verified\n'
    fi
  else
    printf 'audit health: hash/inode/atime fallback (no active marker)\n'
  fi
  [ -f "$alertlog" ] && { printf 'recent alerts:\n'; tail -n 10 "$alertlog" | sed 's/^/  /'; }
  [ "$health_failed" -eq 0 ] || return 4
}

remove() {
  [ "$apply" -eq 1 ] && ccdc_require_root
  if audit_available && [ "$apply" -eq 1 ]; then
    auditctl -D -k ccdc-canary >/dev/null 2>&1 \
      || ccdc_warn "could not remove ccdc-canary audit rules; review 'auditctl -l'"
    auditctl -D -k ccdc-sensitive >/dev/null 2>&1 \
      || ccdc_warn "could not remove ccdc-sensitive audit rules; review 'auditctl -l'"
  fi

  remove_failed=0
  for state_file in "$manifest" "$pending"; do
    [ -f "$state_file" ] || continue
    while IFS='|' read -r path expected _rest; do
      [ -n "${path:-}" ] || continue
      if [ "$apply" -ne 1 ]; then
        printf '[dry-run] would remove managed decoy %s if its hash still matches\n' "$path"
        continue
      fi
      [ -e "$path" ] || [ -L "$path" ] || continue
      if [ -f "$path" ] && [ ! -L "$path" ] && [ "$(path_hash "$path")" = "$expected" ]; then
        rm -f -- "$path" || { ccdc_warn "could not remove decoy $path"; remove_failed=1; }
      else
        ccdc_warn "leaving changed/replaced canary for investigation: $path"
        remove_failed=1
      fi
    done <"$state_file"
  done

  # A signal between writing and linking can leave only the same-directory
  # staging inode. Remove it only when it still has the known fake-content hash.
  if [ -f "$pending" ] && [ "$apply" -eq 1 ]; then
    while IFS='|' read -r path expected; do
      [ -n "${path:-}" ] || continue
      parent=$(dirname -- "$path")
      base=$(basename -- "$path")
      [ -d "$parent" ] || continue
      find "$parent" -maxdepth 1 -type f -name "${base}.ccdc-canary.new.[0-9]*" -print 2>/dev/null \
        | while IFS= read -r staged; do
            [ "$(path_hash "$staged")" = "$expected" ] && rm -f -- "$staged"
          done
    done <"$pending"
  fi

  if [ "$apply" -eq 1 ]; then
    if [ "$remove_failed" -eq 0 ]; then
      rm -f "$manifest" "$baseline" "$pending"
      if audit_available \
        && auditctl -l 2>/dev/null | grep -qE 'ccdc-(canary|sensitive)'; then
        ccdc_warn "one or more CCDC audit rules remain loaded; retaining $audit_marker"
      else
        rm -f "$audit_marker"
      fi
      ccdc_info "managed canaries removed"
    else
      ccdc_die "one or more changed canaries were retained; manifests remain for investigation"
    fi
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
