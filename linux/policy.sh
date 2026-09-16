#!/usr/bin/env bash
set -u

# policy.sh - what this box actually requires of a password, and who is exempt.
#
# users.sh can lock an account and rotate a credential. Nothing in the kit could
# answer the question the password-policy inject asks in its first paragraph:
# what ARE the current rules, on this host, right now. That answer is spread
# across login.defs, a pwquality file, two or three PAM stacks, the hash format
# in /etc/shadow, and the aging fields of every account - and the inject wants it
# as a table.
#
# THIS TOOL HAS NO --apply, AND THAT IS DELIBERATE.
#
# Automating PAM is how you lock everyone out of a box, including yourself, with
# no way back in short of single-user mode - and single-user mode is a reboot,
# which is scored downtime. A misordered line in common-password or a faillock
# deny=3 applied while the scoring engine is authenticating costs more than the
# finding was worth. So this reports, prints the exact edit, and stops.
#
#   ./policy.sh --config FILE           the audit
#   ./policy.sh --config FILE --table   the markdown table the inject asks for
#
# Exit: 0 nothing flagged, 3 findings.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=audit
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --table) mode=table; shift ;;
    --audit) mode=audit; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--audit|--table]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

findings=0
red()     { findings=$((findings + 1)); printf '\n  \033[1;31mRED\033[0m    %s\n' "$1"; }
amber()   { findings=$((findings + 1)); printf '\n  \033[1;33mAMBER\033[0m  %s\n' "$1"; }
note()    { printf '\n  note   %s\n' "$1"; }
detail()  { printf '         %s\n' "$1"; }
fixline() { printf '           %s\n' "$1"; }
okline()  { printf '  ok     %s\n' "$1"; }
fixhdr()  { printf '         ---- the edit (READ IT FIRST, do not paste blind) ----\n'; }

login_defs=${CCDC_LOGIN_DEFS:-/etc/login.defs}
pwquality_conf=/etc/security/pwquality.conf
faillock_conf=/etc/security/faillock.conf

# PAM's password stack has two names depending on the distro family, and the
# file that is NOT there is not a finding.
pam_password_files() {
  local f
  for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}
pam_auth_files() {
  local f
  for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}

defs_value() {
  local key=$1 value
  [ -r "$login_defs" ] || return 1
  # The exit status has to come from the assignment, not from a pipeline: with
  # `awk ... | tail -1` the status is tail's, which is always 0, so an UNSET
  # key looked set and the audit printed "minimum length: " with nothing after
  # it. A blank where a number belongs is worse than a missing line - in an
  # inject table it reads as a researched answer.
  value=$(awk -v k="$key" '$1 == k { v=$2 } END { if (v != "") print v }' "$login_defs" 2>/dev/null)
  [ -n "$value" ] || return 1
  printf '%s\n' "$value"
}

# A pwquality setting can be in pwquality.conf, in a conf.d file, or passed as
# an argument to pam_pwquality in the PAM stack. The PAM argument wins, and it
# is the one people forget to look at.
pwquality_value() {
  local key=$1 value='' file
  if [ -r "$pwquality_conf" ]; then
    value=$(awk -F= -v k="$key" '
      /^[[:space:]]*#/ { next }
      { gsub(/[[:space:]]/, "") }
      $1 == k { print $2 }
    ' "$pwquality_conf" 2>/dev/null | tail -1)
  fi
  for file in /etc/security/pwquality.conf.d/*.conf; do
    [ -r "$file" ] || continue
    local extra
    extra=$(awk -F= -v k="$key" '
      /^[[:space:]]*#/ { next }
      { gsub(/[[:space:]]/, "") }
      $1 == k { print $2 }
    ' "$file" 2>/dev/null | tail -1)
    [ -n "$extra" ] && value=$extra
  done
  while IFS= read -r file; do
    local pam_value
    pam_value=$(grep -E '^[^#]*pam_(pwquality|cracklib)\.so' "$file" 2>/dev/null \
      | grep -oE "(^|[[:space:]])$key=[^[:space:]]+" | tail -1 | cut -d= -f2)
    [ -n "$pam_value" ] && value=$pam_value
  done <<EOF
$(pam_password_files)
EOF
  [ -n "$value" ] || return 1
  printf '%s\n' "$value"
}

faillock_value() {
  local key=$1 value='' file pam_value
  if [ -r "$faillock_conf" ]; then
    value=$(awk -F= -v k="$key" '
      /^[[:space:]]*#/ { next }
      { gsub(/[[:space:]]/, "") }
      $1 == k { print $2 }
    ' "$faillock_conf" 2>/dev/null | tail -1)
    # A bare key with no "=" (for example "even_deny_root") counts as set.
    if [ -z "$value" ] && grep -qE "^[[:space:]]*$key[[:space:]]*$" "$faillock_conf" 2>/dev/null; then
      value=set
    fi
  fi
  while IFS= read -r file; do
    pam_value=$(grep -E '^[^#]*pam_(faillock|tally2)\.so' "$file" 2>/dev/null \
      | grep -oE "(^|[[:space:]])$key=[^[:space:]]+" | tail -1 | cut -d= -f2)
    [ -n "$pam_value" ] && value=$pam_value
  done <<EOF
$(pam_auth_files)
EOF
  [ -n "$value" ] || return 1
  printf '%s\n' "$value"
}

lockout_module() {
  local file
  while IFS= read -r file; do
    grep -qE '^[^#]*pam_faillock\.so' "$file" 2>/dev/null && { printf 'pam_faillock\n'; return 0; }
    grep -qE '^[^#]*pam_tally2\.so' "$file" 2>/dev/null && { printf 'pam_tally2\n'; return 0; }
  done <<EOF
$(pam_auth_files)
EOF
  return 1
}

quality_module() {
  local file
  while IFS= read -r file; do
    grep -qE '^[^#]*pam_pwquality\.so' "$file" 2>/dev/null && { printf 'pam_pwquality\n'; return 0; }
    grep -qE '^[^#]*pam_cracklib\.so' "$file" 2>/dev/null && { printf 'pam_cracklib\n'; return 0; }
  done <<EOF
$(pam_auth_files)
$(pam_password_files)
EOF
  return 1
}

# Human accounts: the ones a password policy is actually about.
human_accounts() {
  awk -F: -v min="${CCDC_POLICY_MIN_UID:-1000}" '
    $3 >= min && $3 < 65534 && $7 !~ /(nologin|false|sync)$/ { print $1 }
  ' /etc/passwd 2>/dev/null
}

hash_scheme() {
  local field=$1
  case "$field" in
    '') printf 'EMPTY' ;;
    '!'*|'*'*) printf 'locked' ;;
    '$6$'*) printf 'sha512' ;;
    '$y$'*) printf 'yescrypt' ;;
    '$7$'*) printf 'scrypt' ;;
    '$5$'*) printf 'sha256' ;;
    '$2'*) printf 'bcrypt' ;;
    '$1$'*) printf 'MD5' ;;
    *) printf 'DES-or-unknown' ;;
  esac
}

# Effective minimum length. pwquality's minlen is the real control on a modern
# box; login.defs PASS_MIN_LEN is ignored when pwquality is in the stack, which
# is exactly the kind of detail that makes a wrong number end up in an inject.
effective_minlen() {
  local minlen
  if minlen=$(pwquality_value minlen); then
    printf '%s\n' "$minlen"
    return 0
  fi
  if defs_value PASS_MIN_LEN >/dev/null 2>&1; then
    printf '%s (login.defs PASS_MIN_LEN)\n' "$(defs_value PASS_MIN_LEN)"
    return 0
  fi
  printf 'none\n'
}

complexity_summary() {
  local parts='' key value
  for key in dcredit ucredit lcredit ocredit minclass; do
    value=$(pwquality_value "$key") || continue
    parts="$parts $key=$value"
  done
  [ -n "$parts" ] && printf '%s\n' "${parts# }" || printf 'none\n'
}

lockout_summary() {
  local module deny unlock
  module=$(lockout_module) || { printf 'NONE\n'; return 0; }
  deny=$(faillock_value deny) || deny='?'
  unlock=$(faillock_value unlock_time) || unlock='?'
  printf '%s deny=%s unlock_time=%s\n' "$module" "$deny" "$unlock"
}

do_audit() {
  local value module user shadow_field scheme weak='' never_expires='' aging

  # --- 1. the quality rules -------------------------------------------------
  if module=$(quality_module); then
    okline "password quality is enforced by $module"
  else
    red "NO password quality module in the PAM stack"
    detail "any user can set their password to 'a'. This is the finding the"
    detail "password-policy inject is really asking about."
    detail "checked: $(pam_password_files | tr '\n' ' ')"
    fixhdr
    fixline "sudo apt-get install -y libpam-pwquality     # Debian/Ubuntu"
    fixline "sudo dnf install -y libpwquality             # RHEL/Rocky"
    fixline "# then add to /etc/security/pwquality.conf:  minlen = 15"
    detail "edit the PAM stack BY HAND and keep a root shell open while you do."
  fi

  value=$(effective_minlen)
  case "$value" in
    none)
      red "no minimum password length is enforced anywhere"
      fixhdr
      fixline "# /etc/security/pwquality.conf"
      fixline "minlen = 15"
      ;;
    *)
      case "$value" in
        *' '*) okline "minimum length: $value" ;;
        *)
          if [ "$value" -lt 12 ] 2>/dev/null; then
            amber "minimum password length is $value - below the 12 the policy memo commits to"
            fixline "# /etc/security/pwquality.conf -> minlen = 15"
          else
            okline "minimum password length: $value"
          fi
          ;;
      esac
      ;;
  esac

  # --- 2. lockout -----------------------------------------------------------
  # Reported, never set. A deny=3 applied while the scoring engine is
  # authenticating locks out the scorer, and the outage is yours.
  if module=$(lockout_module); then
    value=$(faillock_value deny) || value=''
    if [ -n "$value" ] && [ "$value" -le 3 ] 2>/dev/null; then
      amber "$module locks accounts after only $value failures"
      detail "on a scored box that is a self-inflicted outage waiting to happen:"
      detail "anything that authenticates repeatedly - including the scoring"
      detail "engine - trips it. Consider 5-10 with a short unlock_time."
    else
      okline "account lockout: $(lockout_summary)"
    fi
    if faillock_value even_deny_root >/dev/null 2>&1; then
      amber "lockout applies to root as well (even_deny_root)"
      detail "an attacker can lock YOU out of root by failing logins on purpose"
    fi
  else
    amber "no account lockout is configured (no pam_faillock/pam_tally2)"
    detail "password guessing against this box is unlimited and silent"
    fixhdr
    fixline "# /etc/security/faillock.conf"
    fixline "deny = 10"
    fixline "unlock_time = 900"
    detail "then add pam_faillock to the auth stack BY HAND, with a root shell open."
  fi

  # --- 3. how the passwords are stored --------------------------------------
  if [ -r /etc/shadow ]; then
    while IFS=: read -r user shadow_field _; do
      [ -n "$user" ] || continue
      scheme=$(hash_scheme "$shadow_field")
      case "$scheme" in
        MD5|DES-or-unknown) weak="$weak $user($scheme)" ;;
      esac
    done </etc/shadow
    if [ -n "$weak" ]; then
      red "account(s) whose password is stored with an obsolete hash:$weak"
      detail "MD5 and DES crypt are crackable offline in minutes from a stolen"
      detail "/etc/shadow. The hash only changes when the password is changed."
      fixhdr
      fixline "grep ENCRYPT_METHOD $login_defs      # should be SHA512 or YESCRYPT"
      fixline "sudo passwd <user>                   # re-hashes on change"
    else
      okline "no obsolete password hashes in /etc/shadow"
    fi
    value=$(defs_value ENCRYPT_METHOD) || value='(unset)'
    okline "login.defs ENCRYPT_METHOD: $value"
  else
    detail "/etc/shadow unreadable - re-run with sudo for the hash and aging checks"
  fi

  # --- 4. aging, per account -------------------------------------------------
  if [ -r /etc/shadow ]; then
    while IFS= read -r user; do
      [ -n "$user" ] || continue
      aging=$(awk -F: -v u="$user" '$1 == u { print $5 }' /etc/shadow 2>/dev/null)
      case "$aging" in
        ''|99999) never_expires="$never_expires $user" ;;
      esac
    done <<EOF
$(human_accounts)
EOF
    if [ -n "$never_expires" ]; then
      # Informational on purpose: NIST SP 800-63B-4 actively recommends AGAINST
      # routine expiry, and the policy memo in injects/responses cites it. An
      # auditor's checklist and the standard the memo commits to disagree here,
      # and the memo is the one being graded.
      note "account(s) whose password never expires:$never_expires"
      detail "NOT flagged as a finding: NIST SP 800-63B-4 recommends against"
      detail "routine expiry, and injects/responses/password-policy.md commits"
      detail "to that standard. Expire a credential when it is COMPROMISED."
      detail "If the packet demands expiry, this is the command:"
      fixline "sudo chage -M 90 <user>"
    fi
  fi

  # --- 5. credentials sitting in files --------------------------------------
  # Locations only. This prints no values: the report is evidence, it gets
  # pasted into an inject, and a report that leaks the credential it found is a
  # second incident.
  local cred_hits='' f
  for f in /var/www/html/wp-config.php /var/www/wp-config.php \
           /etc/tomcat*/tomcat-users.xml /opt/tomcat/conf/tomcat-users.xml \
           /root/.my.cnf /root/.pgpass /etc/mysql/debian.cnf; do
    [ -f "$f" ] || continue
    cred_hits="$cred_hits $f"
  done
  if [ -n "$cred_hits" ]; then
    amber "application credential file(s) present:$cred_hits"
    detail "the inject asks about application passwords as well as accounts."
    detail "check each for a DEFAULT credential; values are not printed here."
    for f in $cred_hits; do
      detail "$(ls -l -- "$f" 2>/dev/null | cut -c1-90)"
      case "$(stat -c '%a' "$f" 2>/dev/null)" in
        *[4-7]) red "  and it is WORLD-READABLE: $f"
                fixline "sudo chmod 640 -- $(printf '%q' "$f")" ;;
      esac
    done
  fi

  # --- 6. the standard the memo cites ---------------------------------------
  value=$(pwquality_value dcredit)
  if [ -n "$value" ] && [ "$value" != 0 ] 2>/dev/null; then
    note "character-class rules are enforced (complexity: $(complexity_summary))"
    detail "NIST SP 800-63B-4 recommends against mandated composition rules;"
    detail "length is the control that matters. Harmless to leave, but the memo"
    detail "should say which you chose and why, because the inject asks."
  fi
}

do_table() {
  local host minlen complexity expiry lockout other=''
  host=${CCDC_BOX_NAME:-$(hostname 2>/dev/null || printf 'this host')}
  minlen=$(effective_minlen)
  complexity=$(complexity_summary)
  lockout=$(lockout_summary)
  expiry=$(defs_value PASS_MAX_DAYS) || expiry='unset'
  [ "$expiry" = 99999 ] && expiry='none (99999)'

  quality_module >/dev/null 2>&1 || other="no password quality module; "
  [ -r /etc/shadow ] && grep -q '^[^:]*::' /etc/shadow 2>/dev/null \
    && other="${other}EMPTY PASSWORD accounts present; "
  [ -f /var/www/html/wp-config.php ] && other="${other}application credentials in wp-config.php; "
  [ -n "$other" ] || other='none found by this audit'

  printf '| System | Minimum length | Complexity required | Forced expiry | Lockout | Other findings |\n'
  printf '|--------|----------------|--------------------|--------------|---------|----------------|\n'
  printf '| %s | %s | %s | %s | %s | %s |\n' \
    "$host" "$minlen" "$complexity" "$expiry" "$lockout" "${other%; }"
  printf '\nRow generated by linux/policy.sh --table on %s.\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Paste it into the table in injects/responses/password-policy.md, one row\n'
  printf 'per host. Run it on each box: the columns differ per host, and a table\n'
  printf 'that claims otherwise is the kind of detail a grader checks.\n'
}

case "$mode" in
  table) do_table ;;
  audit)
    printf 'policy.sh - what this box requires of a password\n'
    printf 'read-only, and there is no --apply. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    do_audit
    printf '\n'
    if [ "$findings" -eq 0 ]; then
      printf '  Nothing flagged in the password policy.\n'
    else
      printf '  %s password-policy finding(s) above.\n' "$findings"
      printf '\n  Every fix here is a HAND edit to PAM or login.defs. Before you make one:\n'
      printf '    1. keep a second root shell open, and do not close it\n'
      printf '    2. change ONE thing\n'
      printf '    3. test a login in a third session before moving on\n'
      printf '  A broken PAM stack locks out every account at once, including root,\n'
      printf '  and the way back is single-user mode - which is a reboot, which is\n'
      printf '  scored downtime.\n'
    fi
    printf '\n  The inject table: ./linux/policy.sh --config <cfg> --table\n'
    [ "$findings" -gt 0 ] && exit 3
    ;;
esac
exit 0
