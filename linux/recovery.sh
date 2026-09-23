#!/usr/bin/env bash
set -u

# recovery.sh - make and verify an offline-on-the-box recovery copy of this kit.
#
# This is deliberately recovery, not stealth. Guardian repairs the running
# payload while it is alive; this bundle is for the different failure case where
# the checkout or all running payloads were deleted. Install also places this
# small root-owned helper beside the bundle, so the restore command survives a
# deleted checkout. It never overwrites a working directory: restore always
# extracts into a new, empty destination.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
mode='status'
destination=''
apply=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --install) mode=install; shift ;;
    --status) mode=status; shift ;;
    --restore) mode=restore; destination=${2:?missing restore destination}; shift 2 ;;
    --restore-baseline) mode=restorebaseline; destination=${2:?missing evidence state directory}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    -h|--help)
      cat <<'EOF'
usage: recovery.sh --config FILE [--install|--status|--restore DIRECTORY] [--apply]

  --install              create a root-owned, checksummed copy of linux/,
                         playbooks/, and the selected config outside the checkout
  --status               list recovery bundles and verify their checksums
  --restore DIRECTORY    verify the newest bundle and extract it into a NEW,
                         empty directory; never overwrites an existing kit
  --restore-baseline DIR verify the newest bundle and restore its blessed
                         baseline into the dedicated evidence state directory
  --apply                required for --install and either restore operation
  --dry-run              show an install or restore action without changing files

Examples:
  sudo ./linux/recovery.sh --config /tmp/ccdc-linux.env --install --apply
  sudo ./linux/recovery.sh --config /tmp/ccdc-linux.env --restore /root/ccdc-recovered --apply
  sudo /var/backups/ccdc/ccdc-kit-recover.sh --restore-baseline /var/tmp/ccdc-evidence --apply
EOF
      exit 0 ;;
    *) ccdc_die "unknown option: $1" ;;
  esac
done

[ -n "$config" ] && ccdc_load_config "$config"

# The installed helper has no config file to read: the config was inside the
# checkout that may have just been deleted. When invoked from the dedicated
# recovery directory, use that directory as its safe default. The source copy
# still defaults to /var/backups/ccdc unless its config says otherwise.
default_base=/var/backups/ccdc
if [ "$(basename -- "$0")" = ccdc-kit-recover.sh ]; then
  default_base=$SCRIPT_DIR
fi
base=${CCDC_RECOVERY_DIR:-${CCDC_BACKUP_DIR:-$default_base}}
case "$base" in /*) ;; *) ccdc_die "CCDC_RECOVERY_DIR must be an absolute path: $base" ;; esac
case "$base" in *'//'*|*/./*|*/../*|*/.|*/..) ccdc_die "CCDC_RECOVERY_DIR contains unsafe path components: $base" ;; esac

secure_base() {
  local probe owner mode
  mkdir -p -- "$base" || return 1
  probe=$base
  while [ "$probe" != / ]; do
    [ ! -L "$probe" ] || return 1
    owner=$(stat -Lc '%u' -- "$probe" 2>/dev/null) || return 1
    mode=$(stat -Lc '%a' -- "$probe" 2>/dev/null) || return 1
    [ "$owner" -eq 0 ] && [ $((8#$mode & 0022)) -eq 0 ] || return 1
    probe=$(dirname -- "$probe")
  done
  return 0
}

newest_bundle() {
  find "$base" -maxdepth 1 -type f -name 'ccdc-kit-*.tar.gz' -print 2>/dev/null | LC_ALL=C sort | tail -n 1
}

verify_bundle() {
  local archive=$1 sums expected actual
  sums="${archive%.tar.gz}.SHA256SUMS"
  [ -f "$archive" ] && [ -f "$sums" ] || return 1
  expected=$(awk -v b="$(basename -- "$archive")" '$2 == b { print $1; exit }' "$sums" 2>/dev/null)
  actual=$(sha256sum -- "$archive" 2>/dev/null | awk '{print $1}')
  [ -n "$expected" ] && [ "$expected" = "$actual" ]
}

case "$mode" in
  install)
    [ "$apply" -eq 1 ] || { printf '[dry-run] would create a recovery bundle below %s\n' "$base"; exit 0; }
    [ -n "$config" ] || ccdc_die "--install needs --config FILE so the bundle includes the config you used"
    ccdc_require_root
    secure_base || ccdc_die "CCDC_RECOVERY_DIR must be root-owned, not group/world writable, and free of symlink components: $base"
    repo_root=$(dirname -- "$SCRIPT_DIR")
    [ -d "$repo_root/linux" ] && [ -d "$repo_root/playbooks" ] || ccdc_die "run recovery.sh from a complete kit checkout"
    # Keep the restoration tool outside the checkout. It needs no config for
    # --status or --restore because those operations use this directory by
    # default. Root ownership prevents a normal user from replacing it.
    mkdir -p "$base/lib" || ccdc_die "cannot prepare recovery helper directory"
    cp -- "$SCRIPT_DIR/recovery.sh" "$base/ccdc-kit-recover.sh" \
      && cp -- "$SCRIPT_DIR/lib/common.sh" "$base/lib/common.sh" \
      && chown 0:0 "$base/ccdc-kit-recover.sh" "$base/lib/common.sh" \
      && chmod 0700 "$base/ccdc-kit-recover.sh" \
      && chmod 0600 "$base/lib/common.sh" \
      || ccdc_die "could not install recovery helper beside the bundle"
    stamp=$(ccdc_now)
    stage=$(mktemp -d "$base/.ccdc-recovery-stage.XXXXXX") || ccdc_die "cannot create recovery staging directory"
    trap 'rm -rf -- "$stage"' EXIT
    mkdir -p "$stage/kit" || ccdc_die "cannot prepare recovery staging directory"
    cp -a -- "$repo_root/linux" "$repo_root/playbooks" "$stage/kit/" || ccdc_die "could not copy kit into recovery bundle"
    cp -- "$config" "$stage/kit/ccdc.env" || ccdc_die "could not copy selected config into recovery bundle"
    # A recovery bundle made after blessing also carries the small baseline
    # authority files. This is separate from the live evidence directory, so a
    # deleted state tree does not erase the answer to "what was known-good?"
    state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
    if [ -f "$state_dir/baseline/inventory" ]; then
      mkdir -p "$stage/kit/baseline-state" || ccdc_die "could not stage blessed baseline"
      cp -- "$state_dir/baseline/inventory" "$stage/kit/baseline-state/inventory" \
        || ccdc_die "could not copy blessed baseline"
      if [ -f "$state_dir/baseline/exceptions" ]; then
        cp -- "$state_dir/baseline/exceptions" "$stage/kit/baseline-state/exceptions" \
          || ccdc_die "could not copy baseline exceptions"
      else
        : >"$stage/kit/baseline-state/NO-EXCEPTIONS"
      fi
      if [ -f "$state_dir/baseline/bless.log" ]; then
        cp -- "$state_dir/baseline/bless.log" "$stage/kit/baseline-state/bless.log" \
          || ccdc_die "could not copy baseline blessing log"
      fi
    fi
    archive="$base/ccdc-kit-$stamp.tar.gz"
    tar -C "$stage" -czf "$archive" kit || ccdc_die "could not create recovery archive"
    printf '%s  %s\n' "$(sha256sum -- "$archive" | awk '{print $1}')" "$(basename -- "$archive")" >"${archive%.tar.gz}.SHA256SUMS" || ccdc_die "could not write recovery checksum"
    chown 0:0 -- "$archive" "${archive%.tar.gz}.SHA256SUMS" && chmod 0600 -- "$archive" "${archive%.tar.gz}.SHA256SUMS" || ccdc_die "could not secure recovery bundle"
    ccdc_info "recovery bundle: $archive"
    ;;
  status)
    [ -d "$base" ] || { printf 'No recovery bundles yet: %s does not exist.\n' "$base"; exit 0; }
    found=0
    for archive in "$base"/ccdc-kit-*.tar.gz; do
      [ -f "$archive" ] || continue
      found=1
      if verify_bundle "$archive"; then printf 'OK       %s\n' "$archive"; else printf 'BAD HASH %s\n' "$archive"; fi
    done
    [ "$found" -eq 1 ] || printf 'No recovery bundles yet. Create one with --install --apply.\n'
    ;;
  restore)
    [ "$apply" -eq 1 ] || { printf '[dry-run] would verify the newest bundle and extract it to %s\n' "$destination"; exit 0; }
    ccdc_require_root
    secure_base || ccdc_die "recovery directory is not secure: $base"
    archive=$(newest_bundle)
    [ -n "$archive" ] && verify_bundle "$archive" || ccdc_die "no verified recovery bundle is available"
    case "$destination" in /*) ;; *) ccdc_die "restore destination must be an absolute path" ;; esac
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || ccdc_die "restore destination already exists; choose a new empty directory"
    mkdir -p -- "$destination" || ccdc_die "cannot create restore destination"
    tar -C "$destination" -xzf "$archive" || ccdc_die "could not extract verified recovery bundle"
    [ -f "$destination/kit/linux/recovery.sh" ] || ccdc_die "verified archive did not contain the expected kit layout"
    ccdc_info "recovered kit: $destination/kit"
    printf 'Next: inspect the recovered files, then run its scripts from %s/kit.\n' "$destination"
    ;;
  restorebaseline)
    [ "$apply" -eq 1 ] || { printf '[dry-run] would restore the newest bundled baseline into %s\n' "$destination"; exit 0; }
    ccdc_require_root
    secure_base || ccdc_die "recovery directory is not secure: $base"
    ccdc_validate_state_dir "$destination" "baseline restore directory"
    archive=$(newest_bundle)
    [ -n "$archive" ] && verify_bundle "$archive" || ccdc_die "no verified recovery bundle is available"
    stage=$(mktemp -d "$base/.ccdc-baseline-restore.XXXXXX") || ccdc_die "could not make baseline restore staging directory"
    trap 'rm -rf -- "$stage"' EXIT
    tar -C "$stage" -xzf "$archive" kit/baseline-state 2>/dev/null \
      || ccdc_die "the newest recovery bundle contains no blessed baseline; re-run arm after blessing"
    source="$stage/kit/baseline-state"
    [ -f "$source/inventory" ] || ccdc_die "baseline recovery copy has no inventory"
    ccdc_secure_state_dir "$destination" "baseline restore directory"
    mkdir -p "$destination/baseline" || ccdc_die "could not create baseline directory"
    if [ -f "$destination/baseline/inventory" ]; then
      cp -p -- "$destination/baseline/inventory" "$destination/baseline/inventory.before-recovery.$(ccdc_now)" \
        || ccdc_die "could not preserve current baseline before recovery"
    fi
    cp -- "$source/inventory" "$destination/baseline/inventory.tmp.$$" \
      && chown 0:0 "$destination/baseline/inventory.tmp.$$" \
      && chmod 0600 "$destination/baseline/inventory.tmp.$$" \
      && mv -- "$destination/baseline/inventory.tmp.$$" "$destination/baseline/inventory" \
      || ccdc_die "could not restore blessed inventory"
    if [ -f "$source/exceptions" ]; then
      cp -- "$source/exceptions" "$destination/baseline/exceptions.tmp.$$" \
        && chown 0:0 "$destination/baseline/exceptions.tmp.$$" \
        && chmod 0600 "$destination/baseline/exceptions.tmp.$$" \
        && mv -- "$destination/baseline/exceptions.tmp.$$" "$destination/baseline/exceptions" \
        || ccdc_die "could not restore baseline exceptions"
    elif [ -f "$source/NO-EXCEPTIONS" ]; then
      rm -f -- "$destination/baseline/exceptions"
    fi
    if [ -f "$source/bless.log" ]; then
      cp -- "$source/bless.log" "$destination/baseline/bless.log" \
        || ccdc_die "could not restore baseline blessing log"
    fi
    ccdc_info "restored bundled baseline to $destination/baseline/inventory"
    ccdc_info "verify it with: sudo <kit>/linux/baseline.sh --config <config> --status"
    ;;
esac
