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
    --list) mode=list; shift ;;
    --diff) mode=diff; restore_path=${2:?missing backup file}; shift 2 ;;
    --restore) mode=restore; restore_path=${2:?missing backup file}; shift 2 ;;
    --service-path) source_path=${2:?missing source path}; shift 2 ;;
    -h|--help)
      printf 'usage: %s --config FILE [--dry-run|--apply] [--service-path PATH] [--list|--diff|--restore BACKUP]\n' "$0"
      printf '\n'
      printf '  Restore points for the files you name in CCDC_BACKUP_PATHS, with a\n'
      printf '  checksum taken at the time so you can tell a restore from a reinfection.\n'
      printf '\n'
      printf '  --dry-run   what would be backed up. The default.\n'
      printf '  --apply     take the backup.\n'
      printf '  --list      what restore points exist, and what is in each. Run this\n'
      printf '              before --restore: you cannot name a file you have not seen.\n'
      printf '  --diff PATH  what changed between the backup and the box right now.\n'
      printf '  --restore PATH --apply   put the saved copy back.\n'
      printf '\n'
      printf '  Take one BEFORE you change anything. A backup taken after the intrusion\n'
      printf '  preserves the intrusion.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
[ "$apply" -eq 1 ] && ccdc_require_root

validate_backup_path() {
  local path=${1:-} label=${2:-path}
  [ -n "$path" ] || ccdc_die "$label is empty"
  case "$path" in
    /*) ;;
    *) ccdc_die "$label must be absolute: $path" ;;
  esac
  [ "$path" != / ] || ccdc_die "$label must not be the filesystem root"
  case "$path" in
    */) ccdc_die "$label must not end with a slash: $path" ;;
    *'//'*) ccdc_die "$label contains an empty path component: $path" ;;
    */./*|*/.|*/../*|*/..) ccdc_die "$label contains path traversal: $path" ;;
    *'|'*|*[[:space:]]*|*[[:cntrl:]]*)
      ccdc_die "$label contains whitespace, a control character, or a manifest delimiter: $path"
      ;;
  esac
}

reject_symlink_components() {
  local path=$1 label=$2 probe=$1 parent
  while [ "$probe" != / ]; do
    [ ! -L "$probe" ] || ccdc_die "$label contains a symlink component: $probe"
    parent=$(dirname -- "$probe")
    [ "$parent" != "$probe" ] || break
    probe=$parent
  done
}

# The backup base is trusted to contain root restore material.  Do not use a
# directory another account can replace or populate, and do not silently fall
# back to a predictable path in /tmp when the requested destination is broken.
validate_secure_backup_base() {
  local base=$1 probe owner mode
  reject_symlink_components "$base" "backup base"
  probe=$base
  while [ ! -e "$probe" ]; do
    probe=$(dirname -- "$probe")
  done
  while [ "$probe" != / ]; do
    [ -d "$probe" ] || ccdc_die "backup base component is not a directory: $probe"
    owner=$(stat -Lc '%u' -- "$probe" 2>/dev/null) \
      || ccdc_die "cannot inspect backup base ownership: $probe"
    mode=$(stat -Lc '%a' -- "$probe" 2>/dev/null) \
      || ccdc_die "cannot inspect backup base permissions: $probe"
    [ "$owner" -eq 0 ] \
      || ccdc_die "backup base component is not root-owned: $probe"
    [ $((8#$mode & 0022)) -eq 0 ] \
      || ccdc_die "backup base component is group/world writable: $probe"
    probe=$(dirname -- "$probe")
  done
}

backup_base=${CCDC_BACKUP_DIR:-/var/backups/ccdc}
validate_backup_path "$backup_base" "CCDC_BACKUP_DIR"
reject_symlink_components "$backup_base" "CCDC_BACKUP_DIR"
backup_dir="$backup_base/ccdc-backup.$(ccdc_now).XXXXXX"
if [ "$mode" = backup ]; then
  requested=0
  copied=0
  missing=0
  paths=${source_path:-${CCDC_BACKUP_PATHS:-}}

  # Validate the entire request before creating an output tree.  A later
  # relative/traversal entry must not leave behind an apparently valid partial
  # backup from the entries that preceded it.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    validate_backup_path "$path" "backup source path"
    reject_symlink_components "$path" "backup source path"
    requested=$((requested + 1))
  done <<EOF
${paths}
EOF
  [ "$requested" -gt 0 ] || ccdc_die "no backup paths configured"

  if [ "$apply" -eq 1 ]; then
    validate_secure_backup_base "$backup_base"
    mkdir -p -- "$backup_base" || ccdc_die "cannot create backup base: $backup_base"
    reject_symlink_components "$backup_base" "backup base"
    validate_secure_backup_base "$backup_base"
    backup_dir=$(mktemp -d "$backup_dir") \
      || ccdc_die "cannot create a unique backup directory below $backup_base"
    [ -d "$backup_dir" ] && [ ! -L "$backup_dir" ] \
      || ccdc_die "backup leaf is not a real directory: $backup_dir"
    chown 0:0 -- "$backup_dir" && chmod 0700 -- "$backup_dir" \
      || ccdc_die "cannot secure backup directory: $backup_dir"
  fi
  manifest="$backup_dir/MANIFEST"
  [ "$apply" -eq 1 ] && : >"$manifest" \
    || [ "$apply" -ne 1 ] \
    || ccdc_die "cannot create backup manifest: $manifest"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || { ccdc_warn "missing backup path: $path"; missing=$((missing + 1)); continue; }
    relative=${path#/}
    destination="$backup_dir/$relative"
    if [ "$apply" -eq 1 ]; then
      mkdir -p "$(dirname "$destination")" \
        || ccdc_die "cannot create backup parent for $path"
      cp -a -- "$path" "$destination" \
        || ccdc_die "backup copy failed for $path; incomplete backup retained at $backup_dir"
      printf '%s\n' "$path" >>"$manifest" \
        || ccdc_die "cannot update backup manifest at $manifest"
      copied=$((copied + 1))
    else
      printf '[dry-run] would copy %s -> %s\n' "$path" "$destination"
    fi
  done <<EOF
${paths}
EOF
  if [ "$apply" -eq 1 ]; then
    [ "$copied" -gt 0 ] || ccdc_die "none of the $requested configured backup paths existed; empty backup retained at $backup_dir"
    find "$backup_dir" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$backup_dir/SHA256SUMS" \
      || ccdc_die "could not hash backup; do not restore from $backup_dir"
    chmod -R go-rwx "$backup_dir" || ccdc_die "could not secure backup directory: $backup_dir"
    [ "$missing" -eq 0 ] \
      || ccdc_die "$missing of $requested configured paths were missing; partial backup retained at $backup_dir"
  fi
  ccdc_info "backup directory: $backup_dir"
elif [ "$mode" = list ]; then
  # CARD 9 has told the operator to run this since it was written, and the flag
  # did not exist. It is the step before --restore, and --restore is useless
  # without it: you cannot name a backup file you have not been shown.
  if [ ! -d "$backup_base" ]; then
    printf 'No backups yet. %s does not exist.\n\n' "$backup_base"
    printf 'Make one now, before you need it:\n'
    printf '  sudo %s --config %s --apply\n' "$0" "$config"
    exit 0
  fi
  found=0
  for d in "$backup_base"/ccdc-backup.*; do
    [ -d "$d" ] || continue
    found=$((found + 1))
    printf '%s   (%s, %s file(s))\n' "$d" \
      "$(date -u -d "@$(stat -c '%Y' "$d")" '+%Y-%m-%d %H:%M:%SZ' 2>/dev/null)" \
      "$(find "$d" -type f ! -name MANIFEST ! -name SHA256SUMS 2>/dev/null | wc -l)"
    find "$d" -type f ! -name MANIFEST ! -name SHA256SUMS 2>/dev/null \
      | sed "s|^$d||" | sort | sed 's/^/      /'
  done
  if [ "$found" -eq 0 ]; then
    printf 'No backups in %s yet.\n\n' "$backup_base"
    printf 'Make one now, before you need it:\n'
    printf '  sudo %s --config %s --apply\n' "$0" "$config"
    exit 0
  fi
  printf '\nRestore one of the paths listed above - the path as it appears on the\n'
  printf 'box, not the path inside the backup:\n'
  printf '  sudo %s --config %s --diff /etc/ssh/sshd_config\n' "$0" "$config"
  printf '  sudo %s --config %s --restore /etc/ssh/sshd_config --apply\n' "$0" "$config"

elif [ "$mode" = diff ]; then
  [ -n "$restore_path" ] || ccdc_die "diff requires a backup file"
  [ -n "$source_path" ] || ccdc_die "diff requires --service-path CURRENT_PATH"
  validate_backup_path "$restore_path" "backup file"
  validate_backup_path "$source_path" "current path"
  reject_symlink_components "$restore_path" "backup file"
  reject_symlink_components "$source_path" "current path"
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
  validate_backup_path "$restore_path" "backup file"
  reject_symlink_components "$restore_path" "backup file"
  [ -f "$restore_path" ] || ccdc_die "backup file not found: $restore_path"
  destination=${source_path:-}
  [ -n "$destination" ] || ccdc_die "restore requires --service-path DESTINATION"
  validate_backup_path "$destination" "restore destination"
  reject_symlink_components "$destination" "restore destination"
  if [ "$apply" -eq 1 ]; then
    validate_secure_backup_base "$backup_base"
    case "$restore_path" in
      "$backup_base"/*) ;;
      *) ccdc_die "backup file is outside CCDC_BACKUP_DIR: $restore_path" ;;
    esac
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
    reject_symlink_components "$destination_parent" "restore destination parent"
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
