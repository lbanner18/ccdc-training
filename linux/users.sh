#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
apply=0
admin_user=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --create-admin) admin_user=${2:?missing admin username}; shift 2 ;;
    -h|--help) printf 'usage: %s --config FILE [--dry-run|--apply] [--create-admin USER]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
[ "$apply" -eq 1 ] && ccdc_require_root

evidence=$(ccdc_timestamp_dir)
mkdir -p "$evidence"
umask 077
ccdc_record_shell "$evidence/access-audit.txt" 'printf "%s\n" "--- root accounts ---"; awk -F: '\''$3 == 0 {print}'\'' /etc/passwd; printf "%s\n" "--- interactive accounts ---"; awk -F: '\''$7 !~ /(nologin|false)$/ {print $1":"$3":"$6":"$7}'\'' /etc/passwd; printf "%s\n" "--- sudoers ---"; for f in /etc/sudoers /etc/sudoers.d/*; do [ -r "$f" ] && { echo "--- $f"; sed -n "1,240p" "$f"; }; done; printf "%s\n" "--- key metadata ---"; find /root /home -type f -name authorized_keys -readable -exec ls -l {} \; 2>/dev/null || true'

protected="${CCDC_ALLOWED_USERS:-root} ${SUDO_USER:-} ${USER:-}"
for user in ${CCDC_MANAGED_USERS:-}; do
  if ccdc_list_contains "$user" "$protected"; then
    ccdc_append_log "$evidence/actions.log" "protected_skip user=$user"
    continue
  fi
  if ! id "$user" >/dev/null 2>&1; then
    ccdc_warn "configured user does not exist: $user"
    continue
  fi
  printf 'candidate: %s\n' "$user"
  if ccdc_list_contains "$user" "${CCDC_ROTATE_USERS:-}"; then
    if [ "$apply" -eq 1 ]; then
      password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n') || ccdc_die "cannot generate password"
      printf '%s:%s\n' "$user" "$password" | chpasswd
      unset password
      ccdc_append_log "$evidence/actions.log" "password_rotated user=$user"
    else
      printf '[dry-run] would rotate password for %s (secret not generated)\n' "$user"
    fi
  else
    if [ "$apply" -eq 1 ]; then
      usermod --expiredate 1 --shell "$(command -v nologin 2>/dev/null || printf /usr/sbin/nologin)" "$user"
      passwd -l "$user" >/dev/null 2>&1 || true
      pkill -KILL -u "$user" >/dev/null 2>&1 || true
      ccdc_append_log "$evidence/actions.log" "account_disabled user=$user"
    else
      printf '[dry-run] would disable account %s, expire it, set nologin, and end sessions\n' "$user"
    fi
  fi
done

if [ -n "$admin_user" ]; then
  case "$admin_user" in *[!a-zA-Z0-9._-]*|'') ccdc_die "admin username must contain only letters, digits, dot, underscore, or dash" ;; esac
  if id "$admin_user" >/dev/null 2>&1; then
    ccdc_die "admin user already exists: $admin_user"
  fi
  if [ "$apply" -eq 1 ]; then
    useradd --create-home --shell "$(command -v bash 2>/dev/null || printf /bin/sh)" "$admin_user"
    printf 'Set a password for backup admin %s now. Do not paste it into chat or commit it.\n' "$admin_user" >&2
    passwd "$admin_user"
    ccdc_append_log "$evidence/actions.log" "backup_admin_created user=$admin_user"
  else
    printf '[dry-run] would create backup admin %s; password would be entered interactively\n' "$admin_user"
  fi
fi

find "$evidence" -type f -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "access audit saved to $evidence"

