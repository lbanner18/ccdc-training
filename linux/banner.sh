#!/usr/bin/env bash
set -u

# banner.sh - the login banner inject, done in two minutes instead of twenty.
#
# Low defensive value and worth saying so: a banner stops nobody. It is here
# because it is a known inject with a fixed answer, the answer is three files
# and one sshd directive, and doing it by hand at hour four means hunting for
# the difference between /etc/issue and /etc/issue.net while something else
# needs attention.
#
#   ./banner.sh --config FILE              what the box shows now
#   sudo ./banner.sh --config FILE --apply install the banner
#   sudo ./banner.sh --config FILE --revert --apply   put the old ones back
#
# Every file it replaces is backed up first and restored exactly by --revert.
#
# It does NOT edit sshd_config. The directive that makes SSH serve the banner
# belongs with every other sshd change, behind the rollback in sshd.sh - a tool
# that edits sshd_config without a dead man's switch is a tool that can end the
# event for a cosmetic inject.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 022   # banners are world-readable by design; they are shown pre-login

config=''
mode=show
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) mode=${mode_override:-install}; apply=1; shift ;;
    --revert) mode_override=revert; mode=revert; shift ;;
    --show) mode=show; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--show|--apply|--revert --apply]\n' "$0"
      printf '\n'
      printf '  The login-banner inject. Writes /etc/issue (console) and\n'
      printf '  /etc/issue.net (network).\n'
      printf '\n'
      printf '  --show      what this box currently serves. Read-only, the default.\n'
      printf '  --apply     install the banner.\n'
      printf '  --revert --apply   put the previous one back.\n'
      printf '\n'
      printf '  Setting the files is only half of it: sshd does not show a banner\n'
      printf '  unless it is told to. Set CCDC_SSH_BANNER=/etc/issue.net and run\n'
      printf '  sshd.sh --apply, or you will pass a look at the console and fail the\n'
      printf '  inject, because the grader connects over SSH.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error, which is exactly what
# an operator hit on the lab box. Paths are absolute so they work from any cwd.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/banner.sh"

[ "$apply" -eq 1 ] && ccdc_require_root

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create $state_dir"
backup_dir="$state_dir/banner-backup"
log="$state_dir/banner.log"

targets='/etc/issue
/etc/issue.net'

# The wording matters more than the mechanism, and this is the part the inject
# is actually grading. Two things it must NOT say:
#
#   "Welcome"  - a welcome message has been argued in court to be an invitation,
#                which is the opposite of the notice's purpose.
#   any specific system name, version, or owner - that is free reconnaissance
#   printed before authentication.
#
# What it must say: unauthorized use is prohibited, use is monitored, and
# continuing means consent. Keep it short enough to be read.
default_banner() {
  cat <<'BANNER'
******************************************************************************
                            AUTHORIZED USE ONLY

This system is the property of its owner and is for authorized use only.
Unauthorized or improper use of this system may result in disciplinary action,
and civil and criminal penalties.

By continuing to use this system you indicate your awareness of and consent to
these terms. Activity on this system is monitored and recorded. Anyone using
this system expressly consents to such monitoring, and is advised that evidence
of possible criminal activity may be provided to law enforcement officials.

LOG OFF IMMEDIATELY if you do not agree to these terms.
******************************************************************************
BANNER
}

banner_text() {
  if [ -n "${CCDC_BANNER_FILE:-}" ]; then
    [ -r "$CCDC_BANNER_FILE" ] || ccdc_die "CCDC_BANNER_FILE is not readable: $CCDC_BANNER_FILE"
    cat -- "$CCDC_BANNER_FILE"
    return 0
  fi
  default_banner
}

sshd_serves_banner() {
  local value
  if ccdc_have sshd || [ -x /usr/sbin/sshd ]; then
    value=$("$(command -v sshd 2>/dev/null || printf /usr/sbin/sshd)" -T 2>/dev/null \
      | awk 'tolower($1) == "banner" { print $2; exit }')
    case "$value" in
      ''|none) return 1 ;;
      *) printf '%s\n' "$value"; return 0 ;;
    esac
  fi
  grep -iE '^[[:space:]]*Banner[[:space:]]' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1
}

do_show() {
  local f value
  for f in $targets; do
    printf '  %s: ' "$f"
    if [ -f "$f" ]; then
      if [ -s "$f" ]; then
        printf '%s bytes\n' "$(wc -c <"$f" | tr -d ' ')"
        sed 's/^/      /' "$f" | head -6
        [ "$(wc -l <"$f")" -gt 6 ] && printf '      ...\n'
      else
        printf 'empty\n'
      fi
    else
      printf 'missing\n'
    fi
  done

  printf '\n  SSH pre-login banner: '
  if value=$(sshd_serves_banner) && [ -n "$value" ]; then
    printf '%s\n' "$value"
    printf '  SSH will show a banner BEFORE authentication, which is what the\n'
    printf '  inject means by a login banner.\n'
  else
    printf 'NOT CONFIGURED\n'
    printf '  /etc/issue.net exists but sshd is not serving it, so an SSH user\n'
    printf '  sees nothing before the password prompt. The directive belongs in\n'
    printf '  the SSH policy, behind its rollback:\n'
    printf '      CCDC_SSH_BANNER="/etc/issue.net"   in your config, then\n'
    printf '      sudo ./linux/sshd.sh --config '"$qconfig"' --apply\n'
  fi
  printf '\n  /etc/issue is the CONSOLE banner; /etc/issue.net is the network one.\n'
  printf '  A box that sets only the first passes a visual check and fails the\n'
  printf '  inject, because the grader connects over SSH.\n'
}

do_install() {
  local f staged
  mkdir -p "$backup_dir" || ccdc_die "cannot create $backup_dir"
  chmod 0700 "$backup_dir" 2>/dev/null || true
  staged="$state_dir/.banner-staged.$$"
  trap 'rm -f -- "$staged" 2>/dev/null || true' EXIT INT TERM HUP
  for f in $targets; do
    if [ -f "$f" ] && [ ! -f "$backup_dir/$(basename -- "$f")" ]; then
      cp -p -- "$f" "$backup_dir/$(basename -- "$f")" \
        || ccdc_die "cannot back up $f; nothing was changed"
    fi
    # Staged in our own state directory, never beside the target, and then
    # written THROUGH the path rather than renamed over it. Three reasons, all
    # of them things that actually happen:
    #   - /etc/issue is frequently a bind mount (every container runtime) or a
    #     symlink a package owns; rename over a bind mount fails with EBUSY and
    #     rename over a symlink silently replaces the link.
    #   - /etc is read-only on some hardened images, so a temp file beside the
    #     target cannot even be created.
    #   - a temp file in /etc is debris if this is interrupted, and the debris
    #     is a file called issue.ccdc-new.1234 that nobody will recognise later.
    # A banner is read at login and a torn write is cosmetic, so the atomicity
    # a rename would buy is worth less than any of the above.
    banner_text >"$staged" || ccdc_die "cannot stage the banner text"
    cat -- "$staged" >"$f" || ccdc_die "cannot write $f"
    chmod 0644 "$f" 2>/dev/null || true
    printf '  wrote %s\n' "$f"
  done
  ccdc_append_log "$log" "INSTALL targets=$(printf '%s' "$targets" | tr '\n' ' ')"

  printf '\n  Console and network banner files are in place.\n'
  if sshd_serves_banner >/dev/null; then
    printf '  sshd already serves a banner - nothing further to do.\n'
  else
    printf '\n  SSH is NOT serving it yet, and SSH is what the grader connects with.\n'
    printf '  Add this to your config and apply it through sshd.sh, which validates\n'
    printf '  and arms a rollback before touching the daemon:\n\n'
    printf '      CCDC_SSH_BANNER="/etc/issue.net"\n'
    printf '      sudo ./linux/sshd.sh --config '"$qconfig"' --apply\n'
  fi
  printf '\n  Evidence for the inject response:\n'
  printf '      cat /etc/issue.net\n'
  printf '      ssh USER@%s      # from another machine: the banner shows first\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
}

do_revert() {
  local f base restored=0
  [ -d "$backup_dir" ] || ccdc_die "no banner backup to restore from: $backup_dir"
  for f in $targets; do
    base=$(basename -- "$f")
    if [ -f "$backup_dir/$base" ]; then
      # cp writes through the path rather than replacing it, so this restores
      # correctly over a bind mount or symlink for the same reason as above.
      cp -- "$backup_dir/$base" "$f" && { printf '  restored %s\n' "$f"; restored=1; }
    else
      # No backup means the file did not exist before we made it.
      [ -f "$f" ] && rm -f -- "$f" && printf '  removed %s (it did not exist before)\n' "$f"
      restored=1
    fi
  done
  [ "$restored" -eq 1 ] || ccdc_die "nothing was restored"
  rm -rf -- "$backup_dir"
  ccdc_append_log "$log" "REVERT"
  printf '\n  Banner files are back as they were. If you set CCDC_SSH_BANNER,\n'
  printf '  remove it and re-run sshd.sh to stop SSH serving one.\n'
}

printf 'banner.sh - what this box shows before a login\n'
printf '%s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
case "$mode" in
  show) do_show ;;
  install)
    if [ "$apply" -eq 0 ]; then
      printf '  dry run. This would write:\n\n'
      banner_text | sed 's/^/      /'
      printf '\n  to: %s\n' "$(printf '%s' "$targets" | tr '\n' ' ')"
      printf '  backing up anything already there to %s\n' "$backup_dir"
    else
      do_install
    fi
    ;;
  revert)
    [ "$apply" -eq 1 ] || { printf '  --revert needs --apply\n'; exit 0; }
    do_revert
    ;;
esac
exit 0
