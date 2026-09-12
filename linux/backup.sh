#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
apply=0
mode=backup
source_path=''
restore_path=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --diff) mode=diff; restore_path=${2:?missing backup file}; shift 2 ;;
    --restore) mode=restore; restore_path=${2:?missing backup file}; shift 2 ;;
    --service-path) source_path=${2:?missing source path}; shift 2 ;;
    -h|--help) printf 'usage: %s --config FILE [--dry-run|--apply] [--service-path PATH] [--diff|--restore BACKUP]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
[ "$apply" -eq 1 ] && ccdc_require_root

backup_dir=${CCDC_BACKUP_DIR:-/var/backups/ccdc}/$(ccdc_now)
if [ "$mode" = backup ]; then
  if [ "$apply" -eq 1 ]; then
    mkdir -p "$backup_dir" 2>/dev/null || backup_dir="${TMPDIR:-/tmp}/ccdc-backups/$(ccdc_now)"
    mkdir -p "$backup_dir" || ccdc_die "cannot create backup directory"
  fi
  manifest="$backup_dir/MANIFEST"
  [ "$apply" -eq 1 ] && : >"$manifest"
  paths=${source_path:-${CCDC_BACKUP_PATHS:-}}
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || { ccdc_warn "missing backup path: $path"; continue; }
    relative=${path#/}
    destination="$backup_dir/$relative"
    [ "$apply" -eq 1 ] && printf '%s\n' "$path" >>"$manifest"
    if [ "$apply" -eq 1 ]; then
      mkdir -p "$(dirname "$destination")"
      cp -a "$path" "$destination"
    else
      printf '[dry-run] would copy %s -> %s\n' "$path" "$destination"
    fi
  done <<EOF
${paths}
EOF
  if [ "$apply" -eq 1 ]; then
    find "$backup_dir" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$backup_dir/SHA256SUMS"
    chmod -R go-rwx "$backup_dir"
  fi
  ccdc_info "backup directory: $backup_dir"
elif [ "$mode" = diff ]; then
  [ -n "$restore_path" ] || ccdc_die "diff requires a backup file"
  [ -n "$source_path" ] || ccdc_die "diff requires --service-path CURRENT_PATH"
  [ -f "$restore_path" ] || ccdc_die "backup file not found: $restore_path"
  [ -e "$source_path" ] || ccdc_die "current path not found: $source_path"
  if command -v diff >/dev/null 2>&1; then
    diff -u "$restore_path" "$source_path" || true
  elif cmp -s "$restore_path" "$source_path"; then
    printf 'no differences: %s and %s\n' "$restore_path" "$source_path"
  else
    printf 'files differ: %s and %s\n' "$restore_path" "$source_path"
    exit 1
  fi
elif [ "$mode" = restore ]; then
  [ -n "$restore_path" ] || ccdc_die "restore requires a backup file"
  [ -f "$restore_path" ] || ccdc_die "backup file not found: $restore_path"
  destination=${source_path:-}
  [ -n "$destination" ] || ccdc_die "restore requires --service-path DESTINATION"
  if [ "$apply" -eq 1 ]; then
    mkdir -p "$(dirname "$destination")"
    cp -a "$restore_path" "$destination"
    ccdc_info "restored $restore_path to $destination"
  else
    printf '[dry-run] would restore %s -> %s\n' "$restore_path" "$destination"
  fi
fi
