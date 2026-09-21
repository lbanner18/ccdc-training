#!/usr/bin/env bash
#
# Generate a persistence-drill plan from baseline.sh's declared execution
# mechanisms. This intentionally does NOT plant every row: writing a syntactic
# PAM rule, a sudoers file, or an executable systemd generator just to test a
# detector can lock a lab box out or change how it boots. The plan gives the
# operator a rotating, reviewable set; the existing lab-only plant/drill tools
# remain the only mutators.
#
#   ./redteam/mechanism-drill.sh --plan
#   ./redteam/mechanism-drill.sh --plan --count 8
#   ./redteam/mechanism-drill.sh --self-test
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE="$ROOT/linux/baseline.sh"
count=6
mode=plan

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) mode=plan; shift ;;
    --count) count=${2:?missing count}; shift 2 ;;
    --self-test) mode=selftest; shift ;;
    -h|--help)
      printf 'usage: %s [--plan] [--count N] [--self-test]\n' "$0"
      printf '\n'
      printf '  --plan       print a rotating LAB-ONLY drill plan generated from\n'
      printf '               baseline.sh --mechanisms; does not change the box\n'
      printf '  --count N    number of present mechanisms to select (default 6)\n'
      printf '  --self-test  verify the generator consumes the baseline inventory\n'
      exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

case "$count" in ''|*[!0-9]*|0) printf '--count must be a positive integer\n' >&2; exit 2 ;; esac

plan() {
  local total present selected=0 kind path here
  # --mechanisms needs no configuration state, but baseline currently loads a
  # config before dispatch. Supply a blank, ephemeral config rather than parse
  # source code or duplicate its list here.
  here=$(mktemp -d /tmp/ccdc-mechanism-plan.XXXXXX) || exit 1
  trap 'rm -rf -- "$here"' EXIT INT TERM HUP
  printf 'CCDC_EVIDENCE_DIR=%q\n' "$here/state" >"$here/blank.env"
  "$BASE" --config "$here/blank.env" --mechanisms >"$here/mechanisms"
  total=$(awk 'NR>1 {n++} END {print n+0}' "$here/mechanisms")
  present=$(awk -F '\t' 'NR>1 && $3 == "yes" {n++} END {print n+0}' "$here/mechanisms")

  printf 'Mechanism drill plan — generated from baseline.sh, not memory\n'
  printf 'Known mechanisms: %s; present on this image: %s. Selecting up to %s.\n\n' "$total" "$present" "$count"
  printf 'LAB ONLY. Snapshot first. For each selected mechanism, create one harmless,\n'
  printf 'clearly named fixture, confirm baseline reports it, then remove it and prove\n'
  printf 'the report is clean. Do not make PAM/sudoers/generator fixtures executable.\n\n'

  # Sort by a hash-like stable key (cksum), then rotate by the day. The source
  # list is authoritative; a newly added mechanism participates immediately.
  while IFS=$'\t' read -r kind path state; do
    [ "$state" = yes ] || continue
    printf '%s\t%s\n' "$kind" "$path"
  done < <(tail -n +2 "$here/mechanisms") \
    | while IFS=$'\t' read -r kind path; do
        printf '%s\t%s\t%s\n' "$(printf '%s-%s-%s' "$(date -u +%j)" "$kind" "$path" | cksum | awk '{print $1}')" "$kind" "$path"
      done \
    | sort -n \
    | head -n "$count" \
    | while IFS=$'\t' read -r _ kind path; do
        selected=$((selected + 1))
        printf '  %s. %-9s %s\n' "$selected" "$kind" "$path"
        printf '     fixture name: ccdc-drill-<date>; preserve -> baseline --status -> remove -> baseline --status\n'
      done
  printf '\nThis plan is coverage of the declared mechanism inventory, not exploit coverage.\n'
}

selftest() {
  tmp=$(mktemp -d /tmp/ccdc-mechanism-selftest.XXXXXX) || exit 1
  trap 'rm -rf -- "$tmp"' EXIT INT TERM HUP
  printf 'CCDC_EVIDENCE_DIR=%q\n' "$tmp/state" >"$tmp/blank.env"
  if "$BASE" --config "$tmp/blank.env" --mechanisms >"$tmp/out" &&
     grep -q '^directory[[:space:]]/etc/cron.d[[:space:]]' "$tmp/out" &&
     grep -q '^file[[:space:]]/etc/ld.so.preload[[:space:]]' "$tmp/out"; then
    printf 'mechanism drill self-test: PASS (uses baseline mechanism inventory)\n'
  else
    printf 'mechanism drill self-test: FAIL\n' >&2
    exit 1
  fi
}

case "$mode" in plan) plan ;; selftest) selftest ;; esac
