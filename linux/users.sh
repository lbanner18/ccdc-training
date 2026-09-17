#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

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

# See recon.sh: ccdc_die inside $( ) exits the subshell only.
evidence=$(ccdc_timestamp_dir)
[ -n "$evidence" ] || ccdc_die "no usable evidence directory; see the error above (usually: re-run with sudo)"
mkdir -p "$evidence"
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
      printf 'Set a known password for managed account %s now. Do not paste it into chat or commit it.\n' "$user" >&2
      passwd "$user" || ccdc_die "password rotation failed for $user; the old credential may still work"
      ccdc_append_log "$evidence/actions.log" "password_rotated user=$user"
    else
      printf '[dry-run] would interactively rotate password for %s\n' "$user"
    fi
  else
    if [ "$apply" -eq 1 ]; then
      usermod --expiredate 1 --shell "$(command -v nologin 2>/dev/null || printf /usr/sbin/nologin)" "$user" \
        || ccdc_die "could not expire/disable $user"
      passwd -l "$user" >/dev/null 2>&1 || ccdc_die "could not lock password for $user"
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
    if ! passwd "$admin_user"; then
      passwd -l "$admin_user" >/dev/null 2>&1 || true
      ccdc_die "password setup failed; $admin_user was created but left locked"
    fi
    ccdc_append_log "$evidence/actions.log" "backup_admin_created user=$admin_user"
  else
    printf '[dry-run] would create backup admin %s; password would be entered interactively\n' "$admin_user"
  fi
fi

find "$evidence" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "access audit saved to $evidence"
printf '  list it:  sudo ls -la %q\n' "$evidence"
