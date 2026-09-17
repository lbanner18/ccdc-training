#!/usr/bin/env bash

# Shared helpers. Keep this file dependency-free: the target may not have
# curl, Python, ss, jq, or GNU-specific extensions.

ccdc_die() {
  printf 'ccdc: error: %s\n' "$*" >&2
  exit 1
}

ccdc_warn() {
  printf 'ccdc: warning: %s\n' "$*" >&2
}

ccdc_info() {
  printf 'ccdc: %s\n' "$*" >&2
}

ccdc_now() {
  date -u '+%Y%m%dT%H%M%SZ'
}

ccdc_have() {
  command -v "$1" >/dev/null 2>&1
}

ccdc_load_config() {
  local config=${1:-}
  [ -n "$config" ] || return 0
  [ -e "$config" ] || ccdc_die "config does not exist: $config"
  if [ -d "$config" ]; then
    ccdc_die "config is a directory, not a file: $config
  --config takes the env FILE, e.g. $config/config/example.env"
  fi
  [ -f "$config" ] || ccdc_die "config is not a regular file: $config"
  [ -r "$config" ] || ccdc_die "config is not readable: $config (try sudo)"
  # The example config is shell syntax, but never execute an implicit default
  # path. The caller chooses the file explicitly.
  #
  # And the sourcing itself must be checked. `.` returns non-zero on a syntax
  # error or an unreadable file, and without this the tool runs on with an
  # empty or half-loaded environment - which looks exactly like a successful
  # run against a config that happens to say nothing.
  set -a
  # shellcheck disable=SC1090
  if ! . "$config"; then
    set +a
    ccdc_die "config failed to load: $config
  Nothing was applied. Fix the file and re-run - a partially sourced config
  would leave this tool acting on defaults you did not choose."
  fi
  set +a
}

ccdc_timestamp_dir() {
  local base=${1:-/var/tmp/ccdc-evidence}
  local stamp
  stamp=$(ccdc_now)
  ccdc_validate_state_dir "$base" "evidence directory"
  # "Can I create it" is not the same question as "can I write to it". Run any
  # tool as root once and the evidence directory is left root-owned 0700; every
  # later non-root run then fails at the first mkdir, because mkdir -p on an
  # existing directory succeeds and the old test never noticed. That looked like
  # the read-only tools being broken. Check both.
  mkdir -p "$base" 2>/dev/null \
    || ccdc_die "cannot create evidence directory: $base (run with sudo or fix its ownership)"
  [ -w "$base" ] \
    || ccdc_die "evidence directory is not writable by $(id -un): $base (run with sudo; refusing to split evidence into a fallback)"
  # Include the process ID so recon and hunt launched back-to-back cannot
  # accidentally merge their evidence when they share the same second.
  printf '%s/%s-%s-%s\n' "$base" "${CCDC_BOX_NAME:-box}" "$stamp" "$$"
}

ccdc_record() {
  local output=$1
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$output" 2>&1 || {
    printf '\n[command exited non-zero]\n' >>"$output"
    return 0
  }
}

ccdc_record_shell() {
  local output=$1
  local command_text=$2
  {
    printf '$ %s\n\n' "$command_text"
    # This is used only with internally generated, read-only probes.
    sh -c "$command_text"
  } >"$output" 2>&1 || {
    printf '\n[command exited non-zero]\n' >>"$output"
    return 0
  }
}

ccdc_append_log() {
  local log=$1
  shift
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >>"$log"
}

ccdc_list_contains() {
  local needle=$1
  local list=${2:-}
  local item
  for item in $list; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

ccdc_require_root() {
  [ "$(id -u)" -eq 0 ] || ccdc_die "run as root (or through sudo) for this operation"
}

# State directories are chmod'd and populated by several root-run tools.  A
# typo such as CCDC_EVIDENCE_DIR=/var must never turn into `chmod 0700 /var`.
# Keep writable state beneath a conventional state root, require a leaf below
# that root, reject traversal, and refuse to follow an existing symlink in any
# component.  This is deliberately stricter than "is absolute": state can be
# relocated, but it cannot be pointed at an arbitrary part of the target.
ccdc_validate_state_dir() {
  local path=${1:-} label=${2:-state directory} probe parent
  [ -n "$path" ] || ccdc_die "$label is empty"
  case "$path" in
    /*) ;;
    *) ccdc_die "$label must be absolute: $path" ;;
  esac
  case "$path" in
    *'//'*) ccdc_die "$label contains an empty path component: $path" ;;
    */./*|*/.|*/../*|*/..) ccdc_die "$label contains path traversal: $path" ;;
    *[!A-Za-z0-9_./@+-]*) ccdc_die "$label contains unsupported whitespace or control characters: $path" ;;
  esac
  case "$path" in
    /var/tmp/?*|/var/lib/?*|/run/?*|/tmp/?*|/root/?*|/home/?*/?*) ;;
    *)
      ccdc_die "$label must be a dedicated leaf below /var/tmp, /var/lib, /run, /tmp, /root, or a user home: $path"
      ;;
  esac

  probe=$path
  while [ "$probe" != / ]; do
    [ ! -L "$probe" ] || ccdc_die "$label contains a symlink component: $probe"
    parent=$(dirname -- "$probe")
    [ "$parent" != "$probe" ] || break
    probe=$parent
  done
}

# Claim a dedicated state tree before a root service trusts predictable file
# names inside it. Recon is commonly run as the operator before arm.sh, so the
# directory may legitimately begin user-owned. Chown the directory itself
# first (closing writes), reject top-level symlink traps, then migrate the
# existing evidence to root ownership. Nested evidence may intentionally
# preserve symlinks as forensic artifacts; control files are all top-level.
ccdc_secure_state_dir() {
  local path=$1 label=${2:-state directory} trap_path
  ccdc_require_root
  ccdc_validate_state_dir "$path" "$label"
  mkdir -p -- "$path" || ccdc_die "cannot create $label: $path"
  [ -d "$path" ] && [ ! -L "$path" ] || ccdc_die "$label is not a real directory: $path"
  chown 0:0 "$path" || ccdc_die "cannot claim $label as root-owned: $path"
  chmod 0700 "$path" || ccdc_die "cannot secure $label: $path"
  trap_path=$(find "$path" -mindepth 1 -maxdepth 1 -type l -print -quit 2>/dev/null)
  [ -z "$trap_path" ] || ccdc_die "$label contains a top-level symlink trap: $trap_path (move it aside and retry)"
  chown -R 0:0 -- "$path" || ccdc_die "cannot make existing $label evidence root-owned: $path"
  chmod -R go-rwx -- "$path" || ccdc_die "cannot remove group/world access from $label: $path"
}

ccdc_is_dry_run() {
  [ "${CCDC_DRY_RUN:-1}" -eq 1 ]
}

ccdc_action() {
  if ccdc_is_dry_run; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

ccdc_hash_file() {
  local path=$1
  if ccdc_have sha256sum; then
    sha256sum "$path"
  elif ccdc_have shasum; then
    shasum -a 256 "$path"
  else
    ccdc_warn "no SHA-256 utility available for $path"
  fi
}

# Is an installed private copy of the kit behind the tree it was copied from?
#
# sentry.sh and guardian.sh deliberately run from their OWN copies, so that an
# attacker who edits the operator's working tree cannot get a root supervision
# loop to execute it. That is the right call, and it has a consequence nobody
# was told about: fixes to the kit never reach the running supervisor.
#
# On 2026-09-17 the installed sentry was a snapshot from before an evening of
# work. It was still printing an --approve command that bash mangles, it had
# none of the new notifications, and it did not contain baseline.sh at all -
# while the operator read its output and reasonably assumed it was current.
#
# Prints one line per file that differs or is missing. Silence means in sync.
ccdc_tree_drift() {
  local src=$1 dst=$2 f base
  [ -d "$src" ] && [ -d "$dst" ] || return 0
  # Only compare a directory that IS a copy of the kit. guardian's install
  # directory holds its own payload scripts rather than a copy of linux/, so
  # comparing the two reported twenty-six files as "missing" and told the
  # operator their guardian was catastrophically out of date when it was fine.
  # A drift warning that fires on a healthy install is how a drift warning
  # stops being read.
  [ -f "$dst/triage.sh" ] && [ -f "$dst/lib/common.sh" ] || return 0
  for f in "$src"/*.sh "$src"/lib/*.sh; do
    [ -f "$f" ] || continue
    base=${f#"$src"/}
    if [ ! -f "$dst/$base" ]; then
      printf 'missing  %s\n' "$base"
    elif ! cmp -s -- "$f" "$dst/$base"; then
      printf 'differs  %s\n' "$base"
    fi
  done
}

# Emit CCDC_TCP_CHECKS as normalised name|host|port|service lines.
#
# The documented format is name|host|port|systemd-service and arm.sh's preflight
# checks for it. The common way to get it wrong is "127.0.0.1:8080 127.0.0.1:22",
# and that spelling used to read as a single field that matched no service - so
# every consumer silently skipped every port check while still reporting that a
# service was "answering". baseline.sh said a scored web server "is back and
# answering" on a box where the port had never been probed.
#
# So: accept both spellings rather than be right and useless. A check that
# cannot run at all warns instead of disappearing.
ccdc_tcp_checks() {
  local line name host port svc tok
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    if [ "${line#*|}" != "$line" ]; then
      IFS='|' read -r name host port svc extra <<INNER
$line
INNER
      if [ -n "${extra:-}" ]; then
        ccdc_warn "CCDC_TCP_CHECKS: too many fields in '$line' (want name|host|port|service)"
        continue
      fi
      if [ -z "${port:-}" ]; then
        ccdc_warn "CCDC_TCP_CHECKS: no port in '$line' (want name|host|port|service)"
        continue
      fi
      case "$port" in
        ''|*[!0-9]*) ccdc_warn "CCDC_TCP_CHECKS: '$port' is not a port number in '$line'"; continue ;;
      esac
      printf '%s|%s|%s|%s\n' "${name:-$host:$port}" "$host" "$port" "${svc:-}"
    else
      for tok in $line; do
        case "$tok" in
          *:*)
            case "${tok##*:}" in
              ''|*[!0-9]*) ccdc_warn "CCDC_TCP_CHECKS: '$tok' has no port number" ;;
              *) printf '%s|%s|%s|\n' "$tok" "${tok%:*}" "${tok##*:}" ;;
            esac ;;
          *) ccdc_warn "CCDC_TCP_CHECKS: cannot read '$tok' as host:port or name|host|port|service" ;;
        esac
      done
    fi
  done <<OUTER
${CCDC_TCP_CHECKS:-}
OUTER
}

# Emit CCDC_HTTP_CHECKS as normalised name|url|service lines.
#
# Same deal as ccdc_tcp_checks: the documented form is name|url|systemd-service
# and the common way to write it is a bare URL. Accept both rather than be right
# and useless, and warn on anything that is neither.
ccdc_http_checks() {
  local line name url svc tok
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    if [ "${line#*|}" != "$line" ]; then
      IFS='|' read -r name url svc extra <<INNER
$line
INNER
      if [ -n "${extra:-}" ]; then
        ccdc_warn "CCDC_HTTP_CHECKS: too many fields in '$line' (want name|url|service)"
        continue
      fi
      if [ -z "${url:-}" ]; then
        ccdc_warn "CCDC_HTTP_CHECKS: no URL in '$line' (want name|url|service)"
        continue
      fi
      case "$url" in
        http://*|https://*) ;;
        *) ccdc_warn "CCDC_HTTP_CHECKS: '$url' is not an http:// or https:// URL in '$line'"; continue ;;
      esac
      printf '%s|%s|%s\n' "${name:-$url}" "$url" "${svc:-}"
    else
      for tok in $line; do
        case "$tok" in
          http://*|https://*) printf '%s|%s|\n' "$tok" "$tok" ;;
          *) ccdc_warn "CCDC_HTTP_CHECKS: cannot read '$tok' as a URL or name|url|service" ;;
        esac
      done
    fi
  done <<OUTER
${CCDC_HTTP_CHECKS:-}
OUTER
}


# --- standing exceptions for triage findings ---------------------------------
#
# "That one is mine, stop asking." There was no way to say it. The tool's answer
# to "that is my service" was to report it again on the next pass, and the pass
# after that, for the rest of the event - and an operator who cannot silence a
# known finding learns to skim the list it is in, which is the only list that
# must not be skimmed.
#
# Deliberately NOT a config variable. A config edit is invisible afterwards; a
# muted finding carries who recorded it, when, and why, and the reason is also a
# line that can be pasted into the inject response that asked for it.

ccdc_mute_file() {
  printf '%s/muted' "${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}"
}

# check|subject, with any pid stripped off the front of the subject.
#
# A live-process finding's subject carries the pid it was found under -
# pid1234:/usr/bin/python3.12 - and that number changes every restart. Muting
# the literal string would silence it until the service next restarts and no
# longer, which is worse than not offering the option: it looks like it worked.
ccdc_mute_key() {
  local check=$1 subject=$2 rest
  rest=${subject#pid}
  if [ "$rest" != "$subject" ]; then
    case "$rest" in
      [0-9]*:*) subject=${rest#*:} ;;
    esac
  fi
  printf '%s|%s' "$check" "$subject"
}

ccdc_is_muted() {
  local key f mcheck msubject rest
  key=$(ccdc_mute_key "$1" "$2")
  f=$(ccdc_mute_file)
  [ -r "$f" ] || return 1
  while IFS='|' read -r mcheck msubject rest; do
    case "$mcheck" in ''|\#*) continue ;; esac
    [ "$mcheck|$msubject" = "$key" ] && return 0
  done <"$f"
  return 1
}

ccdc_mute_count() {
  local f n
  f=$(ccdc_mute_file)
  [ -r "$f" ] || { printf '0'; return 0; }
  n=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null) || n=0
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  printf '%s' "$n"
}
