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
