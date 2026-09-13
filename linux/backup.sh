#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

restore_staged=''
cleanup_restore_staged() {
  [ -z "$restore_staged" ] || rm -f -- "$restore_staged" 2>/dev/null || true
}
trap cleanup_restore_staged EXIT

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

backup_dir=${CCDC_BACKUP_DIR:-/var/backups/ccdc}/$(ccdc_now)-$$
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
    if [ "$apply" -eq 1 ]; then
      mkdir -p "$(dirname "$destination")" \
        || ccdc_die "cannot create backup parent for $path"
      cp -a -- "$path" "$destination" \
        || ccdc_die "backup copy failed for $path; incomplete backup retained at $backup_dir"
      printf '%s\n' "$path" >>"$manifest" \
        || ccdc_die "cannot update backup manifest at $manifest"
    else
      printf '[dry-run] would copy %s -> %s\n' "$path" "$destination"
    fi
  done <<EOF
${paths}
EOF
  if [ "$apply" -eq 1 ]; then
    find "$backup_dir" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$backup_dir/SHA256SUMS" \
      || ccdc_die "could not hash backup; do not restore from $backup_dir"
    chmod -R go-rwx "$backup_dir" || ccdc_die "could not secure backup directory: $backup_dir"
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
    [ ! -L "$destination" ] || ccdc_die "refusing to restore through destination symlink: $destination"
    [ ! -d "$destination" ] || ccdc_die "file restore does not overwrite directories: $destination"

    checksum_dir=$(dirname -- "$restore_path")
    checksum_file=''
    while [ "$checksum_dir" != / ]; do
      if [ -f "$checksum_dir/SHA256SUMS" ]; then
        checksum_file="$checksum_dir/SHA256SUMS"
        break
      fi
      checksum_dir=$(dirname -- "$checksum_dir")
    done
    [ -n "$checksum_file" ] \
      || ccdc_die "no SHA256SUMS found above $restore_path; refusing an unverified restore"
    expected_hash=$(awk -v p="$restore_path" '$2 == p {print $1; exit}' "$checksum_file" 2>/dev/null)
    [ -n "$expected_hash" ] \
      || ccdc_die "backup file is not recorded in $checksum_file: $restore_path"
    actual_hash=$(ccdc_hash_file "$restore_path" 2>/dev/null | awk '{print $1}')
    [ -n "$actual_hash" ] && [ "$actual_hash" = "$expected_hash" ] \
      || ccdc_die "backup integrity check failed for $restore_path"

    destination_parent=$(dirname -- "$destination")
    destination_base=$(basename -- "$destination")
    mkdir -p "$destination_parent" || ccdc_die "cannot create restore destination directory"
    restore_staged="$destination_parent/.${destination_base}.ccdc-restore.$$"
    [ ! -e "$restore_staged" ] && [ ! -L "$restore_staged" ] \
      || ccdc_die "restore staging path already exists: $restore_staged"
    cp -a -- "$restore_path" "$restore_staged" \
      || ccdc_die "could not stage restore beside $destination"
    staged_hash=$(ccdc_hash_file "$restore_staged" 2>/dev/null | awk '{print $1}')
    [ "$staged_hash" = "$expected_hash" ] \
      || ccdc_die "staged restore failed verification: $restore_staged"

    rollback_copy=''
    if [ -e "$destination" ]; then
      rollback_copy="${destination}.ccdc-pre-restore.$(ccdc_now)"
      [ ! -e "$rollback_copy" ] && [ ! -L "$rollback_copy" ] \
        || ccdc_die "pre-restore safety copy already exists: $rollback_copy"
      cp -a -- "$destination" "$rollback_copy" \
        || ccdc_die "could not preserve current destination before restore"
    fi
    mv -f -- "$restore_staged" "$destination" \
      || ccdc_die "could not atomically install staged restore"
    restore_staged=''
    if [ -n "$rollback_copy" ]; then
      ccdc_info "restored $restore_path to $destination; previous file retained at $rollback_copy"
    else
      ccdc_info "restored $restore_path to $destination"
    fi
  else
    printf '[dry-run] would restore %s -> %s\n' "$restore_path" "$destination"
  fi
fi
