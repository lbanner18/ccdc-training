#!/usr/bin/env bash
set -u

# prompt.sh - opt-in Bash indicator for pending sentry AMBER approvals.
# Sentry writes only epoch|count|stale-after in a root-owned public file under /run.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
mode=status
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --status) mode=status; shift ;;
    --install) mode=install; shift ;;
    --uninstall) mode=uninstall; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--status|--install|--uninstall] [--apply|--dry-run]\n' "$0"
      printf '\nShows [!N] for pending sentry AMBER approvals. RED uses sentry/wall alerting.\n'
      printf '[!?] means the public count is missing, malformed, or stale; it never means clear.\n\n'
      printf 'Install is opt-in and writes only owned files in /usr/local/lib/ccdc-prompt and /etc/profile.d.\n'
      printf 'It refuses unowned files; --install and --uninstall are dry-run by default.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

snapshot='/run/ccdc-sentry-prompt'
hook_dir='/usr/local/lib/ccdc-prompt'
hook_path="$hook_dir/prompt-hook.sh"
profile_path='/etc/profile.d/99-ccdc-prompt.sh'
marker='# CCDC_PROMPT_HOOK v1'

prompt_state() {
  local stamp count ttl now age
  [ -f "$snapshot" ] && [ ! -L "$snapshot" ] && [ -r "$snapshot" ] || {
    printf 'unknown (sentry has not published a prompt snapshot yet)\n'; return 0
  }
  IFS='|' read -r stamp count ttl <"$snapshot" || true
  case "$stamp" in ''|*[!0-9]*) printf 'unknown (malformed prompt snapshot)\n'; return 0 ;; esac
  case "$count" in '?') printf 'unknown (sentry triage failed)\n'; return 0 ;; ''|*[!0-9]*) printf 'unknown (malformed prompt snapshot)\n'; return 0 ;; esac
  case "$ttl" in ''|*[!0-9]*) printf 'unknown (malformed prompt snapshot)\n'; return 0 ;; esac
  [ "$ttl" -gt 0 ] || { printf 'unknown (malformed prompt snapshot)\n'; return 0; }
  now=$(date +%s) || { printf 'unknown (clock unavailable)\n'; return 0; }
  age=$((now - stamp))
  if [ "$age" -lt 0 ] || [ "$age" -gt "$ttl" ]; then
    printf 'unknown (snapshot is %ss old; sentry may be down)\n' "$age"
  elif [ "$count" -eq 0 ]; then
    printf 'clear (no pending AMBER approvals; snapshot %ss old)\n' "$age"
  else
    printf 'pending: [!%s] (%ss old)\n' "$count" "$age"
  fi
}

owned_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && head -n 1 -- "$1" 2>/dev/null | grep -qxF -- "$marker"
}

do_status() {
  prompt_state
  printf 'RED is not counted here: it has sentry/wall alerting. Run:\n'
  printf '  sudo %q/sentry.sh --config %q --status\n' "$SCRIPT_DIR" "$config"
}

do_install() {
  if [ "$apply" -ne 1 ]; then
    printf '[dry-run] would install the owned Bash hook at %s and %s\n' "$hook_path" "$profile_path"
    return 0
  fi
  ccdc_require_root
  if { [ -e "$hook_path" ] || [ -L "$hook_path" ]; } && ! owned_file "$hook_path"; then
    ccdc_die "refusing to overwrite unowned hook: $hook_path"
  fi
  if { [ -e "$profile_path" ] || [ -L "$profile_path" ]; } && ! owned_file "$profile_path"; then
    ccdc_die "refusing to overwrite unowned profile file: $profile_path"
  fi
  [ ! -L "$hook_dir" ] || ccdc_die "refusing symlink hook directory: $hook_dir"
  mkdir -p -- "$hook_dir" || ccdc_die "cannot create $hook_dir"
  chmod 0755 -- "$hook_dir" || ccdc_die "cannot secure $hook_dir"
  local hook_tmp profile_tmp
  hook_tmp=$(mktemp "$hook_dir/.prompt-hook.XXXXXX") || ccdc_die "cannot stage hook"
  profile_tmp=$(mktemp /etc/profile.d/.99-ccdc-prompt.XXXXXX) || { rm -f -- "$hook_tmp"; ccdc_die "cannot stage profile hook"; }
  {
    printf '%s\n' "$marker"
    cat <<'HOOK'
# Keep this hook tiny: it runs before every interactive Bash prompt.
case "$-" in *i*) ;; *) return 0 ;; esac
[ "${CCDC_PROMPT_HOOK:-}" = 1 ] && return 0
CCDC_PROMPT_HOOK=1
_ccdc_prompt_indicator() {
  local stamp count ttl now age
  [ -r /run/ccdc-sentry-prompt ] && [ ! -L /run/ccdc-sentry-prompt ] || return 0
  IFS='|' read -r stamp count ttl </run/ccdc-sentry-prompt || return 0
  case "$stamp" in ''|*[!0-9]*) printf '[!?] '; return 0 ;; esac
  case "$count" in '?'|''|*[!0-9]*) printf '[!?] '; return 0 ;; esac
  case "$ttl" in ''|*[!0-9]*) printf '[!?] '; return 0 ;; esac
  [ "$ttl" -gt 0 ] || { printf '[!?] '; return 0; }
  now=$(command date +%s 2>/dev/null) || return 0
  age=$((now - stamp))
  if [ "$age" -lt 0 ] || [ "$age" -gt "$ttl" ]; then
    printf '[!?] '
  elif [ "$count" -gt 0 ]; then
    printf '[!%s] ' "$count"
  fi
}
PS1='$(_ccdc_prompt_indicator)'${PS1:-'\u@\h:\w\$ '}
HOOK
  } >"$hook_tmp" || { rm -f -- "$hook_tmp" "$profile_tmp"; ccdc_die "cannot write hook"; }
  {
    printf '%s\n' "$marker"
    printf '[ -r %q ] && . %q\n' "$hook_path" "$hook_path"
  } >"$profile_tmp" || { rm -f -- "$hook_tmp" "$profile_tmp"; ccdc_die "cannot write profile hook"; }
  install -o root -g root -m 0644 -- "$hook_tmp" "$hook_path" || { rm -f -- "$hook_tmp" "$profile_tmp"; ccdc_die "cannot install hook"; }
  install -o root -g root -m 0644 -- "$profile_tmp" "$profile_path" || { rm -f -- "$hook_tmp" "$profile_tmp"; ccdc_die "cannot install profile hook"; }
  rm -f -- "$hook_tmp" "$profile_tmp"
  printf 'Installed. Open a new Bash login shell; [!N] is pending AMBER approvals, [!?] is stale/unknown.\n'
  printf 'This /etc/profile.d change appears in baseline provenance. Review then bless it; do not use broad --allow.\n'
}

do_uninstall() {
  if [ "$apply" -ne 1 ]; then
    printf '[dry-run] would remove owned prompt files %s and %s\n' "$profile_path" "$hook_path"
    return 0
  fi
  ccdc_require_root
  owned_file "$hook_path" || ccdc_die "refusing uninstall: owned hook marker missing at $hook_path"
  owned_file "$profile_path" || ccdc_die "refusing uninstall: owned profile marker missing at $profile_path"
  rm -f -- "$profile_path" "$hook_path" || ccdc_die "could not remove owned prompt files"
  rmdir -- "$hook_dir" 2>/dev/null || true
  printf 'Removed the owned prompt hook. Existing shells keep their current prompt until restarted.\n'
}

case "$mode" in
  status) do_status ;;
  install) do_install ;;
  uninstall) do_uninstall ;;
  *) ccdc_die "internal mode error: $mode" ;;
esac
