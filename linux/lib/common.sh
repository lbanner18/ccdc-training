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
  [ -r "$config" ] || ccdc_die "config is not readable: $config"
  # The example config is shell syntax, but never execute an implicit default
  # path. The caller chooses the file explicitly.
  set -a
  # shellcheck disable=SC1090
  . "$config"
  set +a
}

ccdc_timestamp_dir() {
  local base=${1:-/var/tmp/ccdc-evidence}
  local stamp
  stamp=$(ccdc_now)
  # "Can I create it" is not the same question as "can I write to it". Run any
  # tool as root once and the evidence directory is left root-owned 0700; every
  # later non-root run then fails at the first mkdir, because mkdir -p on an
  # existing directory succeeds and the old test never noticed. That looked like
  # the read-only tools being broken. Check both.
  if ! mkdir -p "$base" 2>/dev/null || [ ! -w "$base" ]; then
    ccdc_warn "evidence directory is not writable by $(id -un): $base"
    ccdc_warn "falling back to a private directory; evidence will be SPLIT across two places"
    ccdc_warn "to keep it in one place: sudo chown -R $(id -un) $base   (or run every tool with sudo)"
    base="${TMPDIR:-/tmp}/ccdc-evidence-$(id -un)"
    mkdir -p "$base" || ccdc_die "cannot create evidence directory"
  fi
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
