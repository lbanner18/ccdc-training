#!/usr/bin/env bash
set -u

# inventory-compare.sh - compare recon's detailed before-picture with its
# canonical execution inventory. This is a migration cross-check, not a threat
# detector: the two views intentionally have different detail and scopes.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

recon_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --recon-dir) recon_dir=${2:?missing recon evidence directory}; shift 2 ;;
    -h|--help)
      printf 'usage: %s --recon-dir EVIDENCE_DIR\n' "$0"
      printf '\n'
      printf 'Reads recon.sh execution-inventory.txt and reports which absolute-path\n'
      printf 'records are also named in recon’s detailed evidence. This is a scope\n'
      printf 'cross-check for the shared-inventory migration, not a security verdict.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$recon_dir" ] || ccdc_die "--recon-dir is required"
[ -d "$recon_dir" ] && [ ! -L "$recon_dir" ] \
  || ccdc_die "recon evidence directory is unavailable: $recon_dir"

inventory="$recon_dir/execution-inventory.txt"
[ -f "$inventory" ] && [ ! -L "$inventory" ] && [ -r "$inventory" ] \
  || ccdc_die "canonical inventory is unavailable: $inventory
  Run recon.sh with --config first; it records execution-inventory.txt."
[ ! -s "$inventory" ] && ccdc_die "canonical inventory is empty: $inventory
  Re-run recon.sh and inspect its command result before comparing coverage."
if grep -qF '[command exited non-zero]' "$inventory"; then
  ccdc_die "canonical inventory command failed inside recon evidence: $inventory
  Re-run recon.sh with sudo if the evidence directory became root-owned, then inspect:
    sudo less $inventory"
fi

detail_files=()
while IFS= read -r -d '' f; do
  case "${f##*/}" in execution-inventory.txt|SHA256SUMS) continue ;; esac
  detail_files+=("$f")
done < <(find "$recon_dir" -maxdepth 1 -type f ! -type l -print0 2>/dev/null)

path_records=0
named_records=0
canonical_only=0
other_records=0
printf 'shared-inventory cross-check: %s\n\n' "$recon_dir"
while IFS='|' read -r kind subject detail; do
  [ -n "${kind:-}" ] || continue
  case "$kind" in '$ '*|ccdc:*) continue ;; esac
  case "$subject" in
    /*)
      path_records=$((path_records + 1))
      named=0
      for f in "${detail_files[@]}"; do
        grep -Fq -- "$subject" "$f" 2>/dev/null && { named=1; break; }
      done
      if [ "$named" -eq 1 ]; then
        named_records=$((named_records + 1))
      else
        canonical_only=$((canonical_only + 1))
        printf '  canonical-only  %-12s %q\n' "$kind" "$subject"
      fi
      ;;
    *) other_records=$((other_records + 1)) ;;
  esac
done <"$inventory"

printf '\n'
printf '  absolute-path records: %s\n' "$path_records"
printf '  also named in recon:   %s\n' "$named_records"
printf '  canonical-only:        %s\n' "$canonical_only"
printf '  semantic/process rows: %s (not compared by path)\n' "$other_records"
printf '\n'
printf 'Canonical-only is not automatically a gap: recon is a detailed human\n'
printf 'before-picture, while baseline inventory includes broader trigger and\n'
printf 'semantic surfaces. Use this list to decide what needs parity proof before\n'
printf 'a report consumes the shared feed.\n'
