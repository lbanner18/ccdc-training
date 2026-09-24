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
    -h|--help)
      printf 'usage: %s --config FILE [--dry-run|--apply] [--create-admin USER]\n' "$0"
      printf '\n'
      printf '  Account audit and guarded password rotation. It acts ONLY on the\n'
      printf '  accounts named in CCDC_USER_TARGETS - never on an account it\n'
      printf '  merely found, because the account you did not mean to lock is\n'
      printf '  usually the scored one.\n'
      printf '\n'
      printf '  --dry-run        show what would change. The default.\n'
      printf '  --apply          make the changes.\n'
      printf '  --create-admin USER  add a second administrator with sudo, so\n'
      printf '              losing one account does not lose you the box.\n'
      printf '\n'
      printf '  Rotating a password the scoring engine uses will cost you that\n'
      printf '  service. Check the packet before you rotate anything.\n'
      exit 0 ;;
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

# The backup admin must (1) actually be able to sudo and (2) be in the packet
# list. Found 2026-09-23 while proving the Windows twin live: this created the
# account and set its password but granted nothing, so the "second way in"
# could not administer anything - and, not being in CCDC_ALLOWED_USERS, triage
# would have reported it as an unapproved admin the moment it could.
register_backup_admin() {
  local line last
  [ -n "$config" ] || { ccdc_warn "no --config: add $admin_user to CCDC_ALLOWED_USERS by hand"; return 0; }
  if ccdc_list_contains "$admin_user" "${CCDC_ALLOWED_USERS:-}"; then
    printf '%s is already in CCDC_ALLOWED_USERS\n' "$admin_user"
    return 0
  fi
  # Edit only the LAST definition (the one sourcing keeps), and only when it is
  # a plain one-line quoted value. Anything cleverer is left to the operator.
  last=$(grep -n '^[[:space:]]*CCDC_ALLOWED_USERS=' "$config" | tail -1 | cut -d: -f1)
  line=$(grep -n '^[[:space:]]*CCDC_ALLOWED_USERS="[^"]*"[[:space:]]*$' "$config" | tail -1 | cut -d: -f1)
  if [ -n "$last" ] && [ "$last" = "$line" ] &&
     sed -i "${line}s/^\([[:space:]]*CCDC_ALLOWED_USERS=\"\)\([^\"]*\)\"/\1\2 $admin_user\"/" "$config"; then
    printf 'added %s to CCDC_ALLOWED_USERS in %s, so triage treats it as yours\n' "$admin_user" "$config"
    ccdc_append_log "$evidence/actions.log" "backup_admin_registered user=$admin_user config=$config"
  else
    ccdc_warn "ADD $admin_user TO CCDC_ALLOWED_USERS in $config BY HAND - until then triage reports it as an unapproved admin"
  fi
}

if [ -n "$admin_user" ]; then
  case "$admin_user" in *[!a-zA-Z0-9._-]*|'') ccdc_die "admin username must contain only letters, digits, dot, underscore, or dash" ;; esac
  if id "$admin_user" >/dev/null 2>&1; then
    ccdc_die "admin user already exists: $admin_user"
  fi
  # Debian/Ubuntu grant root through `sudo`, the Red Hat family through `wheel`.
  admin_group=''
  for g in sudo wheel; do
    if getent group "$g" >/dev/null 2>&1; then admin_group=$g; break; fi
  done
  [ -n "$admin_group" ] || ccdc_die "neither a sudo nor a wheel group exists on this box; grant $admin_user in /etc/sudoers.d by hand (visudo -f)"
  if [ "$apply" -eq 1 ]; then
    useradd --create-home --shell "$(command -v bash 2>/dev/null || printf /bin/sh)" "$admin_user"
    printf 'Set a password for backup admin %s now. Do not paste it into chat or commit it.\n' "$admin_user" >&2
    if ! passwd "$admin_user"; then
      passwd -l "$admin_user" >/dev/null 2>&1 || true
      ccdc_die "password setup failed; $admin_user was created but left locked"
    fi
    usermod -aG "$admin_group" "$admin_user" || ccdc_die "could not add $admin_user to $admin_group; it exists but cannot sudo"
    ccdc_append_log "$evidence/actions.log" "backup_admin_created user=$admin_user group=$admin_group"
    # Prove it rather than assume the group is wired to sudoers on this box.
    if sudo -l -U "$admin_user" 2>/dev/null | grep -q '(ALL'; then
      printf 'backup admin %s created, in %s, and sudo confirms it may run commands as root\n' "$admin_user" "$admin_group"
    else
      ccdc_warn "$admin_user is in $admin_group but sudo does not grant it root here; check /etc/sudoers for %$admin_group"
    fi
    register_backup_admin
  else
    printf '[dry-run] would create backup admin %s, add it to %s, and add it to CCDC_ALLOWED_USERS in %s; password entered interactively\n' \
      "$admin_user" "$admin_group" "${config:-(no --config given)}"
  fi
fi

find "$evidence" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "access audit saved to $evidence"
printf '  list it:  sudo ls -la %q\n' "$evidence"
