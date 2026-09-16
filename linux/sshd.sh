#!/usr/bin/env bash
set -u

# sshd.sh - the config that lets you in is the config that lets them in.
#
# recon.sh records `sshd -T` and nothing acts on it. That is the safe half of a
# job with two halves: reading the effective config catches a bad setting, and
# nothing in the kit could change one without an operator hand-editing a file on
# a box where a typo in that file ends the event.
#
# Two things make SSH different from every other config on the box:
#
#   1. The mistake is unrecoverable from where you are sitting. A bad firewall
#      rule and a bad sshd_config both lock you out; only one of them is the
#      thing you are logged in through.
#   2. The important settings are not in the file you would look at. An attacker
#      who writes /etc/ssh/sshd_config.d/99-tuning.conf gets root logins back
#      with the main config byte-identical, and every "diff sshd_config against
#      the backup" check passes. So does reading the file with your own eyes.
#
# So: the audit reads what sshd will ACTUALLY do (`sshd -T`, which resolves
# every Include) and names the file that set each value; and every change is
# made behind a dead man's switch, exactly like fw.sh, because the connection
# you are about to break is this one.
#
#   ./sshd.sh --config FILE                 audit, read-only (default)
#   sudo ./sshd.sh --config FILE --apply    apply policy with a timed rollback
#   sudo ./sshd.sh --config FILE --confirm  keep it (cancels the rollback)
#   sudo ./sshd.sh --config FILE --rollback revert now
#   ./sshd.sh --config FILE --status        is a rollback pending?
#
# Exit: 0 clean, 3 findings, 4 the audit could not run.
#
# What it will NOT do:
#   - remove an AuthorizedKeysCommand, a CA key, or a Match block. Those are
#     reported loudly and left alone: each one can be load-bearing for a scored
#     login, and deleting the wrong one is an outage you caused.
#   - change PasswordAuthentication unless you configure it explicitly. The
#     scoring engine may well log in with a password.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=audit
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --audit) mode=audit; shift ;;
    --apply) mode=apply; apply=1; shift ;;
    --dry-run) mode=apply; apply=0; shift ;;
    --confirm) mode=confirm; shift ;;
    --rollback) mode=rollback; shift ;;
    --status) mode=status; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--audit|--apply|--dry-run|--confirm|--rollback|--status]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Set before any helper can read it: `set -u` turns an unset global into a hard
# error, and it would surface in whichever code path nobody exercised before the
# competition.
EFFECTIVE=''

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create $state_dir"

case "$mode" in
  apply) [ "$apply" -eq 0 ] || ccdc_require_root ;;
  confirm|rollback) ccdc_require_root ;;
esac

log="$state_dir/sshd.log"
snapshot_dir="$state_dir/sshd-snapshot"
pid_file="$state_dir/sshd-rollback.handle"
rollback_script="$state_dir/sshd-rollback.sh"
rollback_unit=ccdc-sshd-rollback

sshd_config_file=${CCDC_SSHD_CONFIG:-/etc/ssh/sshd_config}
dropin_dir=${CCDC_SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}

# Validate both before anything uses them, because restore runs
#     rm -f -- "$dropin_dir"/*.conf
# and an empty or careless CCDC_SSHD_DROPIN_DIR turns that into `rm -f /*.conf`.
# The same reasoning as ccdc_validate_state_dir in lib/common.sh: a config typo
# must never become a destructive glob. These are paths to an SSH configuration,
# so they are also required to look like one.
validate_ssh_path() {
  local path=${1:-} label=$2
  [ -n "$path" ] || ccdc_die "$label is empty"
  case "$path" in
    /*) ;;
    *) ccdc_die "$label must be absolute: $path" ;;
  esac
  case "$path" in
    */) ccdc_die "$label must not end in a slash: $path" ;;
    *'//'*) ccdc_die "$label contains an empty path component: $path" ;;
    */./*|*/.|*/../*|*/..) ccdc_die "$label contains path traversal: $path" ;;
    *[!A-Za-z0-9_./@+-]*) ccdc_die "$label contains unsupported characters: $path" ;;
  esac
  # Require at least two components, so no value can ever name a top-level
  # directory and have a glob expanded against the root of the filesystem.
  case "${path#/}" in
    */*) ;;
    *) ccdc_die "$label must be nested at least two levels deep: $path" ;;
  esac
}
validate_ssh_path "$sshd_config_file" "CCDC_SSHD_CONFIG"
validate_ssh_path "$dropin_dir" "CCDC_SSHD_DROPIN_DIR"

dropin_file="$dropin_dir/99-ccdc-hardening.conf"
rollback_seconds=${CCDC_SSH_ROLLBACK_SECONDS:-120}
case "$rollback_seconds" in
  ''|*[!0-9]*) ccdc_die "CCDC_SSH_ROLLBACK_SECONDS must be a whole number: $rollback_seconds" ;;
esac
# Long enough to open a second terminal and actually try a login. A window you
# cannot finish the test inside is a window that reverts a good change.
[ "$rollback_seconds" -ge 60 ] || ccdc_die "CCDC_SSH_ROLLBACK_SECONDS below 60 is not enough time to test a login: $rollback_seconds"

findings=0
red()     { findings=$((findings + 1)); printf '\n  \033[1;31mRED\033[0m    %s\n' "$1"; }
amber()   { findings=$((findings + 1)); printf '\n  \033[1;33mAMBER\033[0m  %s\n' "$1"; }
detail()  { printf '         %s\n' "$1"; }
fixline() { printf '           %s\n' "$1"; }
okline()  { printf '  ok     %s\n' "$1"; }
fixhdr()  { printf '         ---- run this ----------------------------------------\n'; }

have_sshd() { ccdc_have sshd || [ -x /usr/sbin/sshd ]; }
sshd_bin() { command -v sshd 2>/dev/null || printf '/usr/sbin/sshd\n'; }

# The effective configuration, with every Include and default resolved. This is
# the only source of truth: the file says what someone wrote, this says what the
# daemon will do.
effective_config() {
  local bin
  bin=$(sshd_bin)
  [ -x "$bin" ] || return 1
  "$bin" -T 2>/dev/null
}

effective_value() {
  local key=$1
  printf '%s\n' "$EFFECTIVE" | awk -v k="$key" 'tolower($1) == k { $1=""; sub(/^ /, ""); print; exit }'
}

# Which file actually set a directive - the question the drill scenario turns
# on. `grep PermitRootLogin /etc/ssh/sshd_config` says "no" while the daemon
# says "yes", because a drop-in three directories away won.
setting_sources() {
  local key=$1 file
  {
    printf '%s\n' "$sshd_config_file"
    [ -d "$dropin_dir" ] && ls "$dropin_dir"/*.conf 2>/dev/null
  } | while IFS= read -r file; do
    [ -n "$file" ] && [ -r "$file" ] || continue
    grep -inE "^[[:space:]]*$key[[:space:]]" "$file" 2>/dev/null \
      | while IFS= read -r hit; do printf '%s:%s\n' "$file" "$hit"; done
  done
}

# Directives that decide whether someone can log in, and what they can do when
# they have. Anything that can hand out access belongs here.
policy_check() {
  local key=$1 want=$2 severity=$3 message=$4 actual sources
  actual=$(effective_value "$key")
  [ -n "$actual" ] || return 0
  if [ "$actual" = "$want" ]; then
    okline "$key = $actual"
    return 0
  fi
  if [ "$severity" = RED ]; then
    red "$key is \"$actual\" - $message"
  else
    amber "$key is \"$actual\" - $message"
  fi
  sources=$(setting_sources "$key")
  if [ -n "$sources" ]; then
    detail "set in:"
    printf '%s\n' "$sources" | sed 's/^/           /'
  else
    detail "not set in any config file - this is the compiled-in default"
  fi
  return 0
}

do_audit() {
  local value sources match_files match_body dropin count started conf_mtime

  if ! have_sshd; then
    printf '  sshd is not installed on this box; nothing to audit.\n'
    return 0
  fi

  EFFECTIVE=$(effective_config) || EFFECTIVE=''
  if [ -z "$EFFECTIVE" ]; then
    if [ "$(id -u)" -ne 0 ]; then
      amber "cannot read the effective config as $(id -un) - re-run with sudo"
      detail "sshd -T needs root, and without it this audit reads files only,"
      detail "which is exactly what a drop-in override defeats"
    else
      red "sshd -T FAILED - the config is not loadable"
      detail "sshd will refuse to start on its next restart, and the scored"
      detail "service goes down with it"
      fixhdr
      fixline "sudo $(sshd_bin) -t"
    fi
  fi

  # 1. Is what is on disk even valid? A config that fails -t is a service that
  # dies on the next restart - including a restart a watchdog or the scoring
  # engine provokes.
  if [ "$(id -u)" -eq 0 ]; then
    if "$(sshd_bin)" -t 2>"$state_dir/.sshd-t.err"; then
      okline "sshd -t: the configuration is valid"
    else
      red "the sshd configuration is INVALID - the next restart kills the service"
      sed 's/^/         /' "$state_dir/.sshd-t.err" 2>/dev/null | head -5
      fixhdr
      fixline "sudo $(sshd_bin) -t          # fix what it names before anything else"
    fi
    rm -f "$state_dir/.sshd-t.err"
  fi

  if [ -n "$EFFECTIVE" ]; then
    # 2. The settings that hand out access.
    policy_check permitrootlogin no RED \
      "root can log in over SSH directly"
    policy_check permitemptypasswords no RED \
      "an account with no password can log in over the network"
    policy_check permituserenvironment no RED \
      "a key file can set environment variables - that is code execution at login"
    policy_check x11forwarding no AMBER \
      "X11 forwarding is rarely needed on a server"
    policy_check permittunnel no AMBER \
      "tunnelling turns an SSH session into a network path into the box"
    policy_check gatewayports no AMBER \
      "forwarded ports are reachable from outside this box"

    value=$(effective_value maxauthtries)
    if [ -n "$value" ] && [ "$value" -gt 6 ] 2>/dev/null; then
      amber "maxauthtries is $value - that is a generous number of guesses per connection"
    elif [ -n "$value" ]; then
      okline "maxauthtries = $value"
    fi

    value=$(effective_value passwordauthentication)
    if [ "$value" = yes ]; then
      # Deliberately not a finding on its own. On a scored box the engine may
      # log in with a password, and "hardening" that away is an outage.
      detail "passwordauthentication = yes (not flagged: the scorer may need it)"
      detail "  if the packet says key-only, set CCDC_SSH_PASSWORD_AUTH=no and --apply"
    fi

    # 3. Alternate key sources. Every check anyone runs looks at
    # authorized_keys; none of these are authorized_keys, and all of them let
    # someone log in.
    value=$(effective_value authorizedkeyscommand)
    if [ -n "$value" ] && [ "$value" != none ]; then
      red "AuthorizedKeysCommand is set: $value"
      detail "sshd asks this program for a user's keys on every login attempt."
      detail "Whatever it prints IS an authorized key. It does not appear in any"
      detail "authorized_keys file, so every key audit in this kit misses it."
      detail "run as: $(effective_value authorizedkeyscommanduser)"
      fixhdr
      fixline "sudo ls -l -- $(printf '%q' "${value%% *}")"
      fixline "sudo cat -- $(printf '%q' "${value%% *}")"
      fixline "# if you did not put it there: comment the directive out, then"
      fixline "sudo $(sshd_bin) -t && sudo systemctl reload sshd"
    else
      okline "no AuthorizedKeysCommand"
    fi

    value=$(effective_value trustedusercakeys)
    if [ -n "$value" ] && [ "$value" != none ]; then
      red "TrustedUserCAKeys is set: $value"
      detail "any key signed by that CA can log in, and new ones can be minted"
      detail "forever without ever touching this box again"
      fixhdr
      fixline "sudo cat -- $(printf '%q' "$value")"
    else
      okline "no TrustedUserCAKeys"
    fi

    value=$(effective_value authorizedprincipalscommand)
    [ -n "$value" ] && [ "$value" != none ] && {
      red "AuthorizedPrincipalsCommand is set: $value"
      detail "same problem as AuthorizedKeysCommand, for certificate logins"
    }

    value=$(effective_value authorizedkeysfile)
    case "$value" in
      ''|'.ssh/authorized_keys .ssh/authorized_keys2'|'.ssh/authorized_keys')
        okline "authorizedkeysfile is the default" ;;
      *)
        amber "AuthorizedKeysFile is non-default: $value"
        detail "keys may live somewhere your authorized_keys checks never look"
        detail "an absolute path here means ONE file can grant access to every account"
        ;;
    esac
  fi

  # 4. Drop-ins. The scenario this tool was written for: the main file is
  # untouched and the daemon's behaviour is not what it says.
  if [ -d "$dropin_dir" ]; then
    count=0
    for dropin in "$dropin_dir"/*.conf; do
      [ -f "$dropin" ] || continue
      count=$((count + 1))
    done
    if [ "$count" -gt 0 ]; then
      amber "$count SSH drop-in file(s) in $dropin_dir - these OVERRIDE the main config"
      detail "recognise every one. A drop-in is how you re-enable root logins"
      detail "while sshd_config still says PermitRootLogin no."
      for dropin in "$dropin_dir"/*.conf; do
        [ -f "$dropin" ] || continue
        detail "$(ls -l -- "$dropin" 2>/dev/null | cut -c1-100)"
        grep -inE '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AuthorizedKeysCommand|AuthorizedKeysFile|TrustedUserCAKeys|Match|AllowUsers|DenyUsers|PermitUserEnvironment)' \
          "$dropin" 2>/dev/null | sed 's/^/             /'
      done
      fixhdr
      fixline "sudo $(sshd_bin) -T | grep -E 'permitrootlogin|passwordauth'   # what WINS"
      fixline "ls -lt -- $(printf '%q' "$dropin_dir")                    # newest first: recent = suspicious"
    else
      okline "no SSH drop-in files"
    fi
  fi

  # 5. Match blocks. sshd -T without -C does not evaluate them, so a Match
  # block is invisible to the effective config above - and it is a completely
  # ordinary way to say "these rules do not apply to this address".
  match_files=''
  for dropin in "$sshd_config_file" "$dropin_dir"/*.conf; do
    [ -f "$dropin" ] || continue
    grep -qiE '^[[:space:]]*Match[[:space:]]' "$dropin" 2>/dev/null || continue
    match_files="$match_files $dropin"
  done
  if [ -n "$match_files" ]; then
    amber "Match block(s) present - these are NOT shown by sshd -T above"
    detail "a Match block applies different rules to a user, group, or address."
    detail "Everything the audit said above can be reversed inside one."
    for dropin in $match_files; do
      detail "$dropin:"
      awk '
        /^[[:space:]]*[Mm]atch[[:space:]]/ { inmatch = 1 }
        inmatch { print "             " $0 }
      ' "$dropin" 2>/dev/null | head -20
    done
    fixhdr
    fixline "sudo $(sshd_bin) -T -C user=root,host=localhost,addr=127.0.0.1 | grep permitrootlogin"
    fixline "# repeat with the addresses in the Match block to see what THEY get"
  else
    okline "no Match blocks"
  fi

  # 6. A config edited after sshd started has not taken effect yet - and will,
  # the moment anything restarts the service. That includes our own watchdog.
  if ccdc_have systemctl && [ -f "$sshd_config_file" ]; then
    started=$(systemctl show -p ActiveEnterTimestamp --value ssh.service 2>/dev/null)
    [ -n "$started" ] || started=$(systemctl show -p ActiveEnterTimestamp --value sshd.service 2>/dev/null)
    if [ -n "$started" ]; then
      started=$(date -d "$started" +%s 2>/dev/null || printf '')
      conf_mtime=$(stat -c '%Y' "$sshd_config_file" 2>/dev/null || printf '')
      for dropin in "$dropin_dir"/*.conf; do
        [ -f "$dropin" ] || continue
        value=$(stat -c '%Y' "$dropin" 2>/dev/null || printf 0)
        [ "$value" -gt "${conf_mtime:-0}" ] 2>/dev/null && conf_mtime=$value
      done
      if [ -n "$started" ] && [ -n "$conf_mtime" ] && [ "$conf_mtime" -gt "$started" ] 2>/dev/null; then
        amber "the SSH config changed AFTER sshd started - the change is pending"
        detail "the running daemon is not using it yet; the next reload or restart will."
        detail "if you did not make that change, it is a booby trap set for the restart."
        fixhdr
        fixline "sudo $(sshd_bin) -T | grep -E 'permitrootlogin|passwordauthentication'"
        fixline "ls -lt -- $(printf '%q' "$sshd_config_file") $(printf '%q' "$dropin_dir")/*.conf 2>/dev/null"
      fi
    fi
  fi

  # 7. Permissions. A group-writable sshd_config is a config anybody in that
  # group can rewrite before the next restart.
  if [ -f "$sshd_config_file" ]; then
    value=$(stat -c '%a %U %G' "$sshd_config_file" 2>/dev/null)
    case "$value" in
      6[0-4][0-4]*|[0-4][0-4][0-4]*) okline "sshd_config permissions: $value" ;;
      *) red "sshd_config is writable beyond root: $value"
         fixhdr
         fixline "sudo chown root:root $sshd_config_file && sudo chmod 0600 $sshd_config_file" ;;
    esac
  fi
}

# --- applying policy ----------------------------------------------------------

# Only directives the operator configured explicitly are written. An unset
# variable means "leave whatever the box already does alone", which is the only
# safe default for a file that decides whether you can log in.
policy_lines() {
  local v
  printf '# Managed by ccdc sshd.sh. Written with a timed rollback armed.\n'
  printf '# Remove this file and reload sshd to undo it by hand.\n'
  [ -n "${CCDC_SSH_PERMIT_ROOT_LOGIN:-}" ] && printf 'PermitRootLogin %s\n' "$CCDC_SSH_PERMIT_ROOT_LOGIN"
  [ -n "${CCDC_SSH_PASSWORD_AUTH:-}" ] && printf 'PasswordAuthentication %s\n' "$CCDC_SSH_PASSWORD_AUTH"
  [ -n "${CCDC_SSH_PERMIT_EMPTY_PASSWORDS:-}" ] && printf 'PermitEmptyPasswords %s\n' "$CCDC_SSH_PERMIT_EMPTY_PASSWORDS"
  [ -n "${CCDC_SSH_PERMIT_USER_ENV:-}" ] && printf 'PermitUserEnvironment %s\n' "$CCDC_SSH_PERMIT_USER_ENV"
  [ -n "${CCDC_SSH_MAX_AUTH_TRIES:-}" ] && printf 'MaxAuthTries %s\n' "$CCDC_SSH_MAX_AUTH_TRIES"
  [ -n "${CCDC_SSH_LOGIN_GRACE:-}" ] && printf 'LoginGraceTime %s\n' "$CCDC_SSH_LOGIN_GRACE"
  [ -n "${CCDC_SSH_X11_FORWARDING:-}" ] && printf 'X11Forwarding %s\n' "$CCDC_SSH_X11_FORWARDING"
  [ -n "${CCDC_SSH_ALLOW_TCP_FORWARDING:-}" ] && printf 'AllowTcpForwarding %s\n' "$CCDC_SSH_ALLOW_TCP_FORWARDING"
  [ -n "${CCDC_SSH_CLIENT_ALIVE_INTERVAL:-}" ] && printf 'ClientAliveInterval %s\n' "$CCDC_SSH_CLIENT_ALIVE_INTERVAL"
  [ -n "${CCDC_SSH_ALLOW_USERS:-}" ] && printf 'AllowUsers %s\n' "$CCDC_SSH_ALLOW_USERS"
  # The login-banner inject's other half. banner.sh writes the file; the
  # directive that makes sshd serve it belongs here, behind the same rollback
  # as every other change to this daemon.
  [ -n "${CCDC_SSH_BANNER:-}" ] && printf 'Banner %s\n' "$CCDC_SSH_BANNER"
  return 0
}

validate_policy_values() {
  local name value
  for name in CCDC_SSH_PERMIT_ROOT_LOGIN CCDC_SSH_PASSWORD_AUTH \
              CCDC_SSH_PERMIT_EMPTY_PASSWORDS CCDC_SSH_PERMIT_USER_ENV \
              CCDC_SSH_X11_FORWARDING CCDC_SSH_ALLOW_TCP_FORWARDING \
              CCDC_SSH_MAX_AUTH_TRIES CCDC_SSH_LOGIN_GRACE \
              CCDC_SSH_CLIENT_ALIVE_INTERVAL CCDC_SSH_ALLOW_USERS; do
    eval "value=\${$name:-}"
    [ -n "$value" ] || continue
    # These values are written verbatim into a config file sshd parses. A
    # newline here would let a config variable append a directive nobody
    # reviewed - including one that undoes everything above it.
    case "$value" in
      *[!A-Za-z0-9_@.:-\ ]*|*$'\n'*)
        ccdc_die "$name contains unsupported characters: $value" ;;
    esac
  done
  case "${CCDC_SSH_PERMIT_ROOT_LOGIN:-}" in
    ''|yes|no|prohibit-password|forced-commands-only) ;;
    *) ccdc_die "CCDC_SSH_PERMIT_ROOT_LOGIN must be yes/no/prohibit-password/forced-commands-only" ;;
  esac
  # The banner is a PATH, so it needs the slash the loop above rejects - and it
  # needs a different check: sshd fails to start if Banner names a file that
  # does not exist, which would take the scored service down for a cosmetic
  # inject.
  if [ -n "${CCDC_SSH_BANNER:-}" ]; then
    case "$CCDC_SSH_BANNER" in
      none) ;;
      /*)
        case "$CCDC_SSH_BANNER" in
          *[!A-Za-z0-9_/.@+-]*) ccdc_die "CCDC_SSH_BANNER contains unsupported characters: $CCDC_SSH_BANNER" ;;
        esac
        [ -f "$CCDC_SSH_BANNER" ] \
          || ccdc_die "CCDC_SSH_BANNER names a file that does not exist: $CCDC_SSH_BANNER
  sshd will refuse to start with a Banner it cannot read. Create it first:
      sudo ./linux/banner.sh --config <cfg> --apply"
        ;;
      *) ccdc_die "CCDC_SSH_BANNER must be an absolute path or \"none\": $CCDC_SSH_BANNER" ;;
    esac
  fi
  for name in CCDC_SSH_PASSWORD_AUTH CCDC_SSH_PERMIT_EMPTY_PASSWORDS \
              CCDC_SSH_PERMIT_USER_ENV CCDC_SSH_X11_FORWARDING CCDC_SSH_ALLOW_TCP_FORWARDING; do
    eval "value=\${$name:-}"
    case "$value" in ''|yes|no) ;; *) ccdc_die "$name must be yes or no: $value" ;; esac
  done
}

# The account this operator is logged in as, when that is knowable. Used only to
# refuse changes that would lock THIS session out.
current_login_user() {
  local who_user
  who_user=${SUDO_USER:-}
  [ -n "$who_user" ] || who_user=$(logname 2>/dev/null || printf '')
  [ -n "$who_user" ] || who_user=$(id -un)
  printf '%s\n' "$who_user"
}

user_has_authorized_key() {
  local user=$1 home keyfile
  home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
  [ -n "$home" ] || return 1
  for keyfile in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -f "$keyfile" ] || continue
    grep -qE '^[[:space:]]*[^#[:space:]]' "$keyfile" 2>/dev/null && return 0
  done
  return 1
}

# The check that exists because the alternative is explaining to your team why
# nobody can log in. Refuses, rather than warns: a warning printed above a
# hundred lines of output is a warning nobody read.
refuse_certain_lockout() {
  local user keyless='' u
  user=$(current_login_user)

  if [ "${CCDC_SSH_PASSWORD_AUTH:-}" = no ]; then
    for u in $user ${CCDC_ALLOWED_USERS:-}; do
      [ "$u" = root ] && continue
      user_has_authorized_key "$u" && return 0
      keyless="$keyless $u"
    done
    # Name an account the operator could actually copy a key to. Suggesting
    # "root@" when root is exactly the account this check skipped is advice
    # that does not work.
    set -- $keyless
    ccdc_die "refusing: PasswordAuthentication=no would leave no way in.
  No authorized_keys found for:$keyless
  Add your public key first, verify it works in a SECOND session, then re-run:
      ssh-copy-id ${1:-$user}@<this box>
  Or leave CCDC_SSH_PASSWORD_AUTH empty to keep password logins as they are."
  fi

  if [ -n "${CCDC_SSH_ALLOW_USERS:-}" ]; then
    case " ${CCDC_SSH_ALLOW_USERS} " in
      *" $user "*) ;;
      *)
        ccdc_die "refusing: AllowUsers is \"$CCDC_SSH_ALLOW_USERS\" and does not include $user.
  Applying this would lock out the account you are using right now.
  Add $user to CCDC_SSH_ALLOW_USERS, or clear it." ;;
    esac
  fi
  return 0
}

take_snapshot() {
  rm -rf -- "$snapshot_dir" 2>/dev/null || true
  mkdir -p "$snapshot_dir" || return 1
  chmod 0700 "$snapshot_dir" || return 1
  [ ! -f "$sshd_config_file" ] || cp -p -- "$sshd_config_file" "$snapshot_dir/sshd_config" || return 1
  if [ -d "$dropin_dir" ]; then
    mkdir -p "$snapshot_dir/dropins" || return 1
    # A snapshot of the whole directory, not of the files we are about to edit:
    # restoring has to REMOVE a drop-in we added as well as put back one we
    # changed, and it cannot do that from a list of files it knew about.
    cp -p -- "$dropin_dir"/*.conf "$snapshot_dir/dropins/" 2>/dev/null || true
  fi
  printf '%s\n' "$dropin_dir" >"$snapshot_dir/dropin_dir"
  return 0
}

restart_cmd() {
  # Debian calls it ssh.service, RHEL calls it sshd.service, and reload keeps
  # existing sessions alive where restart does not. Reload is what we want:
  # the session running this command is one of the ones restart would drop.
  if ccdc_have systemctl; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
      printf 'systemctl reload sshd\n'; return 0
    fi
    printf 'systemctl reload ssh\n'; return 0
  fi
  printf 'kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -o sshd)\n'
}

cancel_pending_rollback() {
  local handle
  [ -f "$pid_file" ] || return 0
  handle=$(cat "$pid_file" 2>/dev/null || printf '')
  case "$handle" in
    systemd:*)
      systemctl stop "${handle#systemd:}.timer" "${handle#systemd:}.service" >/dev/null 2>&1 || true
      systemctl reset-failed "${handle#systemd:}.service" >/dev/null 2>&1 || true
      ;;
    pid:*) kill "${handle#pid:}" >/dev/null 2>&1 || true ;;
  esac
  rm -f "$pid_file"
}

rollback_armed() {
  local handle pid
  [ -f "$pid_file" ] || return 1
  handle=$(cat "$pid_file" 2>/dev/null || printf '')
  case "$handle" in
    systemd:*)
      systemctl is-active --quiet "${handle#systemd:}.timer" 2>/dev/null || return 1
      ;;
    pid:*)
      pid=${handle#pid:}
      case "$pid" in ''|*[!0-9]*) return 1 ;; esac
      kill -0 "$pid" 2>/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
}

restore_snapshot() {
  [ -d "$snapshot_dir" ] || return 1
  [ -f "$snapshot_dir/sshd_config" ] && cp -p -- "$snapshot_dir/sshd_config" "$sshd_config_file"
  if [ -d "$dropin_dir" ]; then
    rm -f -- "$dropin_dir"/*.conf 2>/dev/null || true
    if [ -d "$snapshot_dir/dropins" ]; then
      cp -p -- "$snapshot_dir/dropins"/*.conf "$dropin_dir/" 2>/dev/null || true
    fi
  fi
  return 0
}

do_apply() {
  local reload preview before_root before_pw

  have_sshd || ccdc_die "sshd is not installed on this box"
  validate_policy_values

  if [ -z "$(policy_lines | grep -v '^#')" ]; then
    ccdc_die "no SSH policy is configured - set at least one CCDC_SSH_* value in the config.
  This tool deliberately writes nothing by default: an unset value means
  \"leave what the box already does alone\"."
  fi

  if [ "$apply" -eq 0 ]; then
    printf 'sshd.sh dry run - this would:\n\n'
    printf '  write %s:\n' "$dropin_file"
    policy_lines | sed 's/^/      /'
    printf '\n  validate with: %s -t\n' "$(sshd_bin)"
    printf '  arm a %ss rollback, then: %s\n' "$rollback_seconds" "$(restart_cmd)"
    printf '\n  Nothing has changed. Re-run with --apply.\n'
    return 0
  fi

  refuse_certain_lockout

  EFFECTIVE=$(effective_config) || EFFECTIVE=''
  before_root=$(effective_value permitrootlogin)
  before_pw=$(effective_value passwordauthentication)

  [ -f "$pid_file" ] && ccdc_die "an SSH rollback is already pending; run --confirm or --rollback first"

  take_snapshot || ccdc_die "could not snapshot the current SSH config; nothing was changed"

  # The drop-in only works if the main config includes the directory. On a box
  # without an Include line, writing there changes nothing at all - which would
  # be the worst possible outcome: a tool that reports success and does nothing.
  if ! grep -qiE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$sshd_config_file" 2>/dev/null; then
    ccdc_die "$sshd_config_file has no Include for $dropin_dir, so a drop-in would be ignored.
  Add this as the FIRST line of $sshd_config_file, then re-run:
      Include $dropin_dir/*.conf
  (Doing that by hand is deliberate: it is a change to the main file, and you
  should see exactly what it is.)"
  fi

  mkdir -p "$dropin_dir" || ccdc_die "cannot create $dropin_dir"
  policy_lines >"$dropin_file.new.$$" || ccdc_die "cannot stage the drop-in"
  chmod 0600 "$dropin_file.new.$$"
  mv -f -- "$dropin_file.new.$$" "$dropin_file" || ccdc_die "cannot write $dropin_file"

  # Validate BEFORE anything is reloaded. This is the step that turns a typo
  # from an outage into an error message.
  if ! "$(sshd_bin)" -t 2>"$state_dir/.sshd-apply.err"; then
    ccdc_warn "the new configuration failed sshd -t; restoring and aborting"
    sed 's/^/  /' "$state_dir/.sshd-apply.err" >&2 2>/dev/null || true
    restore_snapshot
    rm -f "$state_dir/.sshd-apply.err"
    ccdc_die "SSH config was NOT changed (the staged policy was invalid)"
  fi
  rm -f "$state_dir/.sshd-apply.err"

  # Arm the switch before reloading, exactly as fw.sh does. Scheduling second
  # would leave a window where a bad reload has happened and nothing will undo
  # it - which is the whole failure this design exists to prevent.
  cat >"$rollback_script.new.$$" <<SCRIPT
#!/bin/sh
# Generated by sshd.sh. Restores the pre-change SSH config unless --confirm ran.
[ -d "$snapshot_dir" ] || exit 0
[ -f "$snapshot_dir/sshd_config" ] && cp -p -- "$snapshot_dir/sshd_config" "$sshd_config_file"
if [ -d "$dropin_dir" ]; then
  rm -f -- "$dropin_dir"/*.conf 2>/dev/null
  [ -d "$snapshot_dir/dropins" ] && cp -p -- "$snapshot_dir/dropins"/*.conf "$dropin_dir/" 2>/dev/null
fi
# Only reload a config that parses. Reloading a broken one would turn a
# recoverable mistake into a dead sshd.
if $(sshd_bin) -t 2>/dev/null; then
  $(restart_cmd) >/dev/null 2>&1
fi
rm -f "$pid_file" "$rollback_script"
exit 0
SCRIPT
  chmod 0700 "$rollback_script.new.$$" \
    && mv -f -- "$rollback_script.new.$$" "$rollback_script" \
    || { rm -f "$rollback_script.new.$$"; restore_snapshot; ccdc_die "cannot create the rollback script; config restored"; }

  if ccdc_have systemd-run; then
    if systemd_error=$(systemd-run --collect --quiet --unit="$rollback_unit" \
         --on-active="${rollback_seconds}s" /bin/sh "$rollback_script" 2>&1); then
      printf 'systemd:%s\n' "$rollback_unit" >"$pid_file"
    else
      ccdc_warn "systemd-run failed: $systemd_error"
      ccdc_warn "falling back to a detached shell"
      if ccdc_have setsid; then
        setsid /bin/sh -c 'sleep "$1"; exec /bin/sh "$2"' ccdc-sshd "$rollback_seconds" "$rollback_script" \
          </dev/null >>"$state_dir/sshd-rollback.err" 2>&1 &
        printf 'pid:%s\n' "$!" >"$pid_file"
      else
        restore_snapshot
        ccdc_die "could not arm any rollback; SSH config restored and unchanged"
      fi
    fi
  else
    if ccdc_have setsid; then
      setsid /bin/sh -c 'sleep "$1"; exec /bin/sh "$2"' ccdc-sshd "$rollback_seconds" "$rollback_script" \
        </dev/null >>"$state_dir/sshd-rollback.err" 2>&1 &
      printf 'pid:%s\n' "$!" >"$pid_file"
    else
      restore_snapshot
      ccdc_die "could not arm any rollback; SSH config restored and unchanged"
    fi
  fi
  rollback_armed || { restore_snapshot; rm -f "$pid_file"; ccdc_die "the rollback did not arm; SSH config restored"; }

  reload=$(restart_cmd)
  if ! eval "$reload" >/dev/null 2>&1; then
    ccdc_warn "reload command failed: $reload"
    ccdc_warn "the rollback is armed and will restore the previous config"
  fi

  EFFECTIVE=$(effective_config) || EFFECTIVE=''
  ccdc_append_log "$log" "APPLY dropin=$dropin_file rollback=${rollback_seconds}s"

  printf '\n  SSH policy applied, and a rollback is armed for %s seconds.\n\n' "$rollback_seconds"
  printf '  changed:\n'
  printf '    PermitRootLogin         %s -> %s\n' "${before_root:-?}" "$(effective_value permitrootlogin)"
  printf '    PasswordAuthentication  %s -> %s\n' "${before_pw:-?}" "$(effective_value passwordauthentication)"
  printf '\n  NOW, BEFORE THE TIMER RUNS OUT:\n\n'
  printf '      open a SECOND terminal and log in again\n'
  printf '          ssh %s@%s\n\n' "$(current_login_user)" "$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '  Do not skip it and do not test it in THIS session - this one is already\n'
  printf '  authenticated, and it will keep working no matter how broken the config is.\n\n'
  printf '  it worked:      sudo %s --config <cfg> --confirm\n' "$0"
  printf '  it did not:     do nothing. The config restores itself in %ss.\n' "$rollback_seconds"
  printf '  undo it now:    sudo %s --config <cfg> --rollback\n' "$0"
}

do_status() {
  if [ -f "$pid_file" ]; then
    if rollback_armed; then
      printf 'SSH rollback PENDING via %s\n' "$(cat "$pid_file")"
      printf 'snapshot: %s\n' "$snapshot_dir"
      printf 'run --confirm to keep the current config, or --rollback to revert now\n'
    else
      printf 'SSH rollback BROKEN via %s - restore by hand NOW:\n' "$(cat "$pid_file")"
      printf '  sudo %s --config <cfg> --rollback\n' "$0"
    fi
  else
    printf 'no SSH rollback pending\n'
  fi
  [ -f "$dropin_file" ] && { printf '\nmanaged drop-in %s:\n' "$dropin_file"; sed 's/^/  /' "$dropin_file"; }
  return 0
}

case "$mode" in
  audit)
    printf 'sshd.sh - what this box will ACTUALLY do at the next login\n'
    printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    do_audit
    printf '\n'
    if [ "$findings" -eq 0 ]; then
      printf '  Nothing flagged in the SSH configuration.\n'
      exit 0
    fi
    printf '  %s SSH finding(s) above.\n' "$findings"
    printf '  Work the RED ones first, and read every drop-in and Match block by\n'
    printf '  hand before changing anything: one of them may be why a scored login\n'
    printf '  still works.\n'
    exit 3
    ;;
  apply) do_apply ;;
  confirm)
    cancel_pending_rollback
    rm -rf -- "$snapshot_dir"
    rm -f -- "$rollback_script"
    ccdc_append_log "$log" "CONFIRM dropin=$dropin_file"
    ccdc_info "SSH rollback cancelled; the new configuration is kept"
    ;;
  rollback)
    cancel_pending_rollback
    restore_snapshot || ccdc_die "rollback failed; restore from $snapshot_dir by hand from the console"
    if "$(sshd_bin)" -t 2>/dev/null; then
      eval "$(restart_cmd)" >/dev/null 2>&1 || ccdc_warn "restored the config but could not reload sshd"
    else
      ccdc_warn "restored config does not pass sshd -t; NOT reloading"
    fi
    rm -rf -- "$snapshot_dir"
    rm -f -- "$rollback_script" "$pid_file"
    ccdc_append_log "$log" "ROLLBACK restored"
    ccdc_info "previous SSH configuration restored"
    ;;
  status) do_status ;;
esac
exit 0
