#!/usr/bin/env bash
set -u

# fix.sh - the one command for the rest of the day. Shows what is wrong on this
# box, numbered, and fixes what you pick. Run it whenever a popup fires or you
# come back to this box:
#
#   sudo ~/ccdc-training/linux/fix.sh
#
#   --config FILE   a config other than /tmp/ccdc-linux.env
#   --wrong-only    skip part 2 (what changed since the freeze); the runner uses this

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CFG=/tmp/ccdc-linux.env
wrong_only=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) CFG=${2:?missing config path}; shift 2 ;;
    --wrong-only) wrong_only=1; shift ;;
    -h|--help) sed -n '4,11p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

ok()   { printf '  \033[32m%s\033[0m\n' "$*"; }
warn() { printf '  \033[31m%s\033[0m\n' "$*"; }
note() { printf '  \033[33m%s\033[0m\n' "$*"; }
hdr()  { printf '\n\033[36m%s\n  %s\n%s\033[0m\n' "$(printf '=%.0s' {1..76})" "$1" "$(printf '=%.0s' {1..76})"; }
run()  { printf '  \033[90m> %s\033[0m\n' "$(basename "$1") ${*:2}"; "$@"; }

[ "$(id -u)" -eq 0 ] || { warn "run it with sudo:  sudo $SCRIPT_DIR/fix.sh"; exit 1; }
[ -f "$CFG" ] || { warn "no $CFG - run Phase 1 first:  sudo $SCRIPT_DIR/first15.sh --phase 1"; exit 1; }

sentry=("$SCRIPT_DIR/sentry.sh" --config "$CFG")
baseline=("$SCRIPT_DIR/baseline.sh" --config "$CFG")

# ---- part 1: what is wrong right now --------------------------------------
hdr '1 of 2  WHAT IS WRONG - fix by number'
run "${sentry[@]}" --status
while :; do
  printf '\n  \033[1ma\033[0m = fix every RED   \033[1mNUMBERS\033[0m = fix those, e.g. 2 4 5 (read each first)   \033[1mr\033[0m = re-list   \033[1mEnter\033[0m = next: '
  read -r ans || ans=''
  case "$ans" in
    '') break ;;
    r|R) run "${sentry[@]}" --status ;;
    a|A) run "${sentry[@]}" --approve --apply ;;
    *)
      nums=$(printf '%s' "$ans" | tr ',' ' ')
      case "$nums" in *[!0-9\ ]*) note 'type a, one or more numbers, r, or just Enter'; continue ;; esac
      for n in $nums; do run "${sentry[@]}" --approve "$n" --apply; done ;;
  esac
done

# ---- part 2: what changed since the box was frozen ------------------------
evid=$(set -a; . "$CFG" >/dev/null 2>&1; printf '%s' "${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}")
if [ "$wrong_only" -eq 1 ]; then
  :
elif [ ! -s "$evid/baseline/inventory" ]; then
  note '(part 2 - what changed since the freeze - starts once you bless the baseline in Phase 2)'
else
  hdr '2 of 2  WHAT CHANGED since you froze this box - fix by number'
  run "${baseline[@]}"
  while :; do
    printf '\n  \033[1mg\033[0m = fix everything marked safe   \033[1mNUMBERS\033[0m = fix those, e.g. 2 4 5   \033[1me NUMBER\033[0m = explain it first   \033[1mr\033[0m = re-list   \033[1mEnter\033[0m = done: '
    read -r ans || ans=''
    case "$ans" in
      '') break ;;
      r|R) run "${baseline[@]}" ;;
      g|G) run "${baseline[@]}" --approve all-green --apply ;;
      e\ *|E\ *) n=${ans#* }; case "$n" in ''|*[!0-9]*) note 'e then a number, e.g.  e 3' ;; *) run "${baseline[@]}" --explain "$n" ;; esac ;;
      *)
        # baseline.sh takes a comma list itself: "2 4 5" -> "2,4,5"
        nums=$(printf '%s' "$ans" | tr ' ' ',' | tr -s ',' | sed 's/^,//; s/,$//')
        case "$nums" in ''|*[!0-9,]*) note 'type g, one or more numbers, e NUMBER, r, or just Enter'; continue ;; esac
        run "${baseline[@]}" --approve "$nums" --apply ;;
    esac
  done
fi

# ---- what is left -----------------------------------------------------------
hdr 'WHAT IS LEFT'
left=$("$SCRIPT_DIR/triage.sh" --config "$CFG" --quiet 2>/dev/null \
  | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^  RED ')
reds=0
[ -z "$left" ] || reds=$(printf '%s\n' "$left" | wc -l)
if [ "$reds" -eq 0 ]; then
  ok '0 RED.'
else
  printf '%s\n' "$left" | sed $'s/^  RED /  \033[1;31mRED\033[0m /'
  warn "$reds RED left - the kit cannot fix these by number. Each one, with its exact fix:"
  printf '     sudo %s/triage.sh --config %s\n' "$SCRIPT_DIR" "$CFG"
fi
printf '\n  Run this again any time - a popup, or you come back to this box:\n'
printf '     \033[1msudo %s/fix.sh\033[0m\n\n' "$SCRIPT_DIR"
[ "$reds" -le 100 ] || reds=100
exit "$reds"
